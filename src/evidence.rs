//! Stable evidence envelope shared by CLI JSON output and integrations.
//!
//! Plugin-specific report structures intentionally remain in [`EvidenceEnvelope::data`].  This
//! keeps the forensic contract stable while plugins evolve independently.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::image::{ImageFormat, MemoryImage};
use crate::profile::KernelProfile;

/// Version of the standalone JSON evidence contract.
pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// Stable identifier for StarMem's bounded source sampling algorithm.
pub const SOURCE_SAMPLE_DIGEST_ALGORITHM: &str = "sha256-starmem-sample-v1";

const SAMPLE_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineIdentity {
    pub version: String,
    pub build_id: String,
    pub integration_api_version: u32,
}

impl EngineIdentity {
    pub fn new(
        version: impl Into<String>,
        build_id: impl Into<String>,
        integration_api_version: u32,
    ) -> Self {
        Self {
            version: version.into(),
            build_id: build_id.into(),
            integration_api_version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestReference {
    pub algorithm: String,
    pub value: String,
}

impl DigestReference {
    pub fn new(algorithm: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            algorithm: algorithm.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceModifiedTime {
    /// Decimal nanoseconds since the Unix epoch. A string avoids lossy JSON number conversions.
    pub unix_nanos: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SymbolIdentity {
    /// Symbol family, for example `windows_pdb` or `linux_isf`.
    pub kind: String,
    /// Provider-stable identity that must not contain a machine-local absolute path.
    pub key: String,
    /// Optional digest of the symbol material actually consumed.
    pub digest: Option<DigestReference>,
    #[serde(default)]
    pub details: BTreeMap<String, Value>,
}

impl SymbolIdentity {
    pub fn new(kind: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            key: key.into(),
            digest: None,
            details: BTreeMap::new(),
        }
    }
}

/// Build the path-free identity of the exact Windows kernel profile consumed by a session.
///
/// The PDB GUID/age remains the human- and tool-comparable key.  The digest covers the complete
/// normalized profile used by StarMem, so compatible-symbol fallbacks and locally generated
/// profiles cannot silently share an identity merely because their source filenames differ.
pub fn windows_symbol_identity(profile: &KernelProfile) -> Result<Option<SymbolIdentity>> {
    let guid = profile
        .pdb_guid
        .trim()
        .trim_matches(['{', '}'])
        .replace('-', "")
        .to_ascii_uppercase();
    if guid.is_empty() {
        return Ok(None);
    }
    let profile_bytes = serde_json::to_vec(profile)?;
    let profile_sha256 = hex::encode(Sha256::digest(profile_bytes));
    let mut identity = SymbolIdentity::new("windows_pdb", format!("{guid}{:X}", profile.pdb_age));
    identity.digest = Some(DigestReference::new(
        "sha256-starmem-kernel-profile-v1",
        profile_sha256,
    ));
    identity.details.insert(
        "pdb_guid".to_owned(),
        Value::String(profile.pdb_guid.clone()),
    );
    identity.details.insert(
        "pdb_age".to_owned(),
        Value::Number(serde_json::Number::from(profile.pdb_age)),
    );
    identity.details.insert(
        "profile_schema_version".to_owned(),
        Value::Number(serde_json::Number::from(profile.schema_version)),
    );
    Ok(Some(identity))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub format: String,
    pub size: u64,
    pub mtime: Option<SourceModifiedTime>,
    pub sample_digest: DigestReference,
    pub symbol_identity: Option<SymbolIdentity>,
    /// Primary and sidecar identities. Names are basenames only; absolute host paths are excluded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<SourceComponentIdentity>,
    /// Deterministic identity of physical mappings, missing bytes and MMIO exclusions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_layout: Option<PhysicalLayoutIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceComponentIdentity {
    pub index: usize,
    pub role: String,
    pub name: String,
    pub size: u64,
    pub mtime: Option<SourceModifiedTime>,
    pub sample_digest: DigestReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalLayoutIdentity {
    pub mapping_count: usize,
    pub mapped_bytes: u64,
    pub digest: DigestReference,
    #[serde(default)]
    pub missing_ranges: Vec<MissingRange>,
    #[serde(default)]
    pub excluded_ranges: Vec<MissingRange>,
}

impl SourceIdentity {
    /// Builds a bounded, reproducible identity without hashing the complete source image.
    ///
    /// The digest covers the file length plus up to three 1 MiB regions at the start, middle and
    /// end. Full-image SHA-256 remains the responsibility of the corpus/release manifest.
    pub fn from_path(path: &Path, format: impl Into<String>) -> Result<Self> {
        let mut file = File::open(path)
            .with_context(|| format!("无法打开证据源以计算身份 {}", path.display()))?;
        let before = file
            .metadata()
            .with_context(|| format!("无法读取证据源元数据 {}", path.display()))?;
        ensure!(before.is_file(), "证据源不是普通文件: {}", path.display());

        let size = before.len();
        let sample_digest = sample_digest(&mut file, size)
            .with_context(|| format!("无法计算证据源采样摘要 {}", path.display()))?;
        let after = file
            .metadata()
            .with_context(|| format!("无法重新读取证据源元数据 {}", path.display()))?;
        ensure!(
            after.len() == size && after.modified().ok() == before.modified().ok(),
            "计算采样摘要期间证据源发生变化: {}",
            path.display()
        );

        let mtime = before
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| SourceModifiedTime {
                unix_nanos: duration.as_nanos().to_string(),
            });

        Ok(Self {
            format: format.into(),
            size,
            mtime,
            sample_digest: DigestReference::new(SOURCE_SAMPLE_DIGEST_ALGORITHM, sample_digest),
            symbol_identity: None,
            components: Vec::new(),
            physical_layout: None,
        })
    }

    pub fn with_symbol_identity(mut self, symbol_identity: SymbolIdentity) -> Self {
        self.symbol_identity = Some(symbol_identity);
        self
    }
}

/// Build the portable identity of a decoded memory source, including sidecars, physical mappings,
/// missing bytes and MMIO exclusions. Absolute host paths are intentionally excluded.
pub fn source_identity_for_memory_image(
    primary_path: &Path,
    image: &MemoryImage,
) -> Result<SourceIdentity> {
    let format = serde_json::to_value(image.format())
        .ok()
        .and_then(|value| value.get("kind").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| format!("{:?}", image.format()));
    let mut identity = SourceIdentity::from_path(primary_path, format)?;
    identity.components = image
        .sources()
        .map(|source| -> Result<SourceComponentIdentity> {
            let sampled = SourceIdentity::from_path(&source.path, "image_component")?;
            Ok(SourceComponentIdentity {
                index: source.index,
                role: serde_json::to_value(source.role)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("{:?}", source.role).to_ascii_lowercase()),
                name: source
                    .path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "unnamed-source".to_owned()),
                size: source.container_len,
                mtime: sampled.mtime,
                sample_digest: sampled.sample_digest,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let missing_ranges = image
        .missing_ranges()
        .iter()
        .map(|range| MissingRange {
            address_space: "physical".to_owned(),
            start: range.start,
            length: range.length,
            source: range.source.clone(),
        })
        .collect::<Vec<_>>();
    let excluded_ranges = match image.format() {
        ImageFormat::VmwareVmem {
            pci_hole_start,
            pci_hole_size,
            ..
        } if *pci_hole_size > 0 => vec![MissingRange {
            address_space: "physical".to_owned(),
            start: *pci_hole_start,
            length: *pci_hole_size,
            source: "vmware_pci_mmio_exclusion".to_owned(),
        }],
        ImageFormat::QevmV3 {
            pci_hole_start,
            pci_hole_size,
            ..
        } if *pci_hole_size > 0 => vec![MissingRange {
            address_space: "physical".to_owned(),
            start: *pci_hole_start,
            length: *pci_hole_size,
            source: "qevm_explicit_pci_mmio_exclusion".to_owned(),
        }],
        _ => Vec::new(),
    };
    let layout_sources = image
        .sources()
        .map(|source| {
            serde_json::json!({
                "index": source.index,
                "role": source.role,
                "container_len": source.container_len,
            })
        })
        .collect::<Vec<_>>();
    let layout_bytes = serde_json::to_vec(&serde_json::json!({
        "sources": layout_sources,
        "spans": image.spans(),
        "missing_ranges": &missing_ranges,
        "excluded_ranges": &excluded_ranges,
    }))?;
    identity.physical_layout = Some(PhysicalLayoutIdentity {
        mapping_count: image.spans().len(),
        mapped_bytes: image.mapped_bytes(),
        digest: DigestReference::new(
            "sha256-starmem-physical-layout-v1",
            hex::encode(Sha256::digest(layout_bytes)),
        ),
        missing_ranges,
        excluded_ranges,
    });
    Ok(identity)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceScope {
    /// Stable scope name, for example `physical_memory` or `process`.
    pub kind: String,
    pub description: Option<String>,
    #[serde(default)]
    pub constraints: BTreeMap<String, Value>,
}

impl EvidenceScope {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            description: None,
            constraints: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceWarningSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceWarning {
    pub code: String,
    pub severity: EvidenceWarningSeverity,
    pub message: String,
    pub source: String,
    #[serde(default)]
    pub context: BTreeMap<String, Value>,
}

impl EvidenceWarning {
    pub fn new(
        code: impl Into<String>,
        severity: EvidenceWarningSeverity,
        message: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            severity,
            message: message.into(),
            source: source.into(),
            context: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceLimitKind {
    SourceScan,
    Output,
    Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLimit {
    pub name: String,
    pub kind: EvidenceLimitKind,
    pub configured: Option<u64>,
    pub observed: Option<u64>,
    /// `None` means the plugin cannot prove whether the limit was reached.
    pub reached: Option<bool>,
}

impl EvidenceLimit {
    pub fn new(name: impl Into<String>, kind: EvidenceLimitKind) -> Self {
        Self {
            name: name.into(),
            kind,
            configured: None,
            observed: None,
            reached: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingRange {
    pub address_space: String,
    pub start: u64,
    pub length: u64,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawEvidenceStorage {
    None,
    Inline,
    Jsonl,
    Sqlite,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEvidenceReference {
    pub path: Option<String>,
    pub hash: Option<DigestReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEvidenceSummary {
    pub count: u64,
    pub storage: RawEvidenceStorage,
    #[serde(default)]
    pub references: Vec<RawEvidenceReference>,
}

impl Default for RawEvidenceSummary {
    fn default() -> Self {
        Self {
            count: 0,
            storage: RawEvidenceStorage::None,
            references: Vec::new(),
        }
    }
}

/// Versioned, command-independent wrapper for every standalone JSON report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEnvelope<T> {
    pub schema_version: u32,
    pub command: String,
    pub engine_identity: EngineIdentity,
    pub source_identity: SourceIdentity,
    pub available: bool,
    pub complete: bool,
    pub scope: EvidenceScope,
    pub warnings: Vec<EvidenceWarning>,
    pub limits: Vec<EvidenceLimit>,
    pub missing_ranges: Vec<MissingRange>,
    pub raw_evidence: RawEvidenceSummary,
    pub data: T,
}

impl<T> EvidenceEnvelope<T> {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        command: impl Into<String>,
        engine_identity: EngineIdentity,
        source_identity: SourceIdentity,
        available: bool,
        complete: bool,
        scope: EvidenceScope,
        warnings: Vec<EvidenceWarning>,
        limits: Vec<EvidenceLimit>,
        missing_ranges: Vec<MissingRange>,
        raw_evidence: RawEvidenceSummary,
        data: T,
    ) -> Result<Self> {
        let envelope = Self {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            command: command.into(),
            engine_identity,
            source_identity,
            available,
            complete,
            scope,
            warnings,
            limits,
            missing_ranges,
            raw_evidence,
            data,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Checks semantic constraints that JSON Schema cannot express clearly.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == EVIDENCE_SCHEMA_VERSION,
            "不支持的 Evidence schema 版本 {}",
            self.schema_version
        );
        ensure!(
            is_stable_identifier(&self.command),
            "command 不是稳定命令 ID: {}",
            self.command
        );
        ensure!(
            !self.engine_identity.version.trim().is_empty(),
            "engine_identity.version 不能为空"
        );
        ensure!(
            !self.engine_identity.build_id.trim().is_empty(),
            "engine_identity.build_id 不能为空"
        );
        ensure!(
            self.engine_identity.integration_api_version > 0,
            "engine_identity.integration_api_version 必须大于 0"
        );
        ensure!(
            !self.source_identity.format.trim().is_empty(),
            "source_identity.format 不能为空"
        );
        validate_digest(
            &self.source_identity.sample_digest,
            "source_identity.sample_digest",
        )?;
        if let Some(symbol) = &self.source_identity.symbol_identity {
            ensure!(
                !symbol.kind.trim().is_empty(),
                "symbol_identity.kind 不能为空"
            );
            ensure!(
                !symbol.key.trim().is_empty(),
                "symbol_identity.key 不能为空"
            );
            ensure!(
                !looks_like_absolute_path(&symbol.key),
                "symbol_identity.key 不得包含本机绝对路径"
            );
            ensure!(
                !value_contains_absolute_path(&Value::Object(
                    symbol.details.clone().into_iter().collect()
                )),
                "symbol_identity.details 不得包含本机绝对路径"
            );
            if let Some(digest) = &symbol.digest {
                validate_digest(digest, "symbol_identity.digest")?;
            }
        }
        ensure!(!self.scope.kind.trim().is_empty(), "scope.kind 不能为空");
        ensure!(
            self.available || !self.complete,
            "available=false 时 complete 不能为 true"
        );

        for warning in &self.warnings {
            ensure!(
                is_stable_identifier(&warning.code),
                "warning code 不是稳定标识符: {}",
                warning.code
            );
            ensure!(
                !warning.message.trim().is_empty(),
                "warning message 不能为空"
            );
            ensure!(!warning.source.trim().is_empty(), "warning source 不能为空");
        }
        for limit in &self.limits {
            ensure!(!limit.name.trim().is_empty(), "limit name 不能为空");
        }
        for missing in &self.missing_ranges {
            ensure!(
                !missing.address_space.trim().is_empty(),
                "missing range address_space 不能为空"
            );
            ensure!(missing.length > 0, "missing range length 必须大于 0");
            ensure!(
                !missing.source.trim().is_empty(),
                "missing range source 不能为空"
            );
        }
        match self.raw_evidence.storage {
            RawEvidenceStorage::None => ensure!(
                self.raw_evidence.count == 0 && self.raw_evidence.references.is_empty(),
                "raw_evidence storage=none 时 count 和 references 必须为空"
            ),
            _ => ensure!(
                self.raw_evidence.count > 0 || !self.raw_evidence.references.is_empty(),
                "raw_evidence 存在存储类型时必须提供 count 或 reference"
            ),
        }
        for (index, reference) in self.raw_evidence.references.iter().enumerate() {
            ensure!(
                reference
                    .path
                    .as_deref()
                    .is_some_and(|path| !path.is_empty())
                    || reference.hash.is_some(),
                "raw_evidence reference[{index}] 必须包含 path 或 hash"
            );
            if let Some(digest) = &reference.hash {
                validate_digest(digest, &format!("raw_evidence.references[{index}].hash"))?;
            }
        }
        Ok(())
    }
}

/// Strongly typed adapter contract for reports that natively expose evidence metadata.
pub trait EvidenceReport: Serialize {
    fn evidence_available(&self) -> bool;
    fn evidence_complete(&self) -> bool;
    fn evidence_scope(&self) -> EvidenceScope;

    fn evidence_warnings(&self) -> Vec<EvidenceWarning> {
        Vec::new()
    }

    fn evidence_limits(&self) -> Vec<EvidenceLimit> {
        Vec::new()
    }

    fn evidence_missing_ranges(&self) -> Vec<MissingRange> {
        Vec::new()
    }

    fn raw_evidence(&self) -> RawEvidenceSummary {
        RawEvidenceSummary::default()
    }
}

impl<T: EvidenceReport> EvidenceEnvelope<T> {
    pub fn from_report(
        command: impl Into<String>,
        engine_identity: EngineIdentity,
        source_identity: SourceIdentity,
        report: T,
    ) -> Result<Self> {
        let available = report.evidence_available();
        let complete = report.evidence_complete();
        let scope = report.evidence_scope();
        let warnings = report.evidence_warnings();
        let limits = report.evidence_limits();
        let missing_ranges = report.evidence_missing_ranges();
        let raw_evidence = report.raw_evidence();
        Self::from_parts(
            command,
            engine_identity,
            source_identity,
            available,
            complete,
            scope,
            warnings,
            limits,
            missing_ranges,
            raw_evidence,
            report,
        )
    }
}

/// Explicit hints used while migrating legacy plugin reports.
///
/// A missing `available` or `complete` flag is never guessed. The adapter first checks an explicit
/// hint, then a top-level legacy boolean, and otherwise returns an error.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyReportAdapter {
    pub available: Option<bool>,
    pub complete: Option<bool>,
    pub scope: EvidenceScope,
    pub warnings: Option<Vec<EvidenceWarning>>,
    pub limits: Vec<EvidenceLimit>,
    pub missing_ranges: Vec<MissingRange>,
    pub raw_evidence: RawEvidenceSummary,
}

impl LegacyReportAdapter {
    pub fn new(scope: EvidenceScope) -> Self {
        Self {
            available: None,
            complete: None,
            scope,
            warnings: None,
            limits: Vec::new(),
            missing_ranges: Vec::new(),
            raw_evidence: RawEvidenceSummary::default(),
        }
    }

    pub fn with_status(mut self, available: bool, complete: bool) -> Self {
        self.available = Some(available);
        self.complete = Some(complete);
        self
    }

    pub fn adapt<T: Serialize>(
        self,
        command: impl Into<String>,
        engine_identity: EngineIdentity,
        source_identity: SourceIdentity,
        report: T,
    ) -> Result<EvidenceEnvelope<T>> {
        let command = command.into();
        let legacy = serde_json::to_value(&report).context("无法序列化旧版插件报告")?;
        let root = legacy
            .as_object()
            .context("旧版插件报告必须序列化为 JSON object")?;
        let available = required_legacy_boolean(self.available, root, "available", &command)?;
        let complete = required_legacy_boolean(self.complete, root, "complete", &command)?;
        let warnings = match self.warnings {
            Some(warnings) => warnings,
            None => normalize_legacy_warnings(root.get("warnings"), &command)?,
        };

        EvidenceEnvelope::from_parts(
            command,
            engine_identity,
            source_identity,
            available,
            complete,
            self.scope,
            warnings,
            self.limits,
            self.missing_ranges,
            self.raw_evidence,
            report,
        )
    }
}

fn required_legacy_boolean(
    explicit: Option<bool>,
    root: &Map<String, Value>,
    field: &str,
    command: &str,
) -> Result<bool> {
    if let Some(value) = explicit {
        return Ok(value);
    }
    match root.get(field) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => bail!("命令 {command} 的旧报告字段 {field} 不是布尔值"),
        None => bail!("命令 {command} 的旧报告缺少 {field}；适配器必须显式提供"),
    }
}

/// Converts legacy warnings into the v1 structured form without leaking strings into the top-level
/// warning array.
pub fn normalize_legacy_warnings(
    warnings: Option<&Value>,
    default_source: &str,
) -> Result<Vec<EvidenceWarning>> {
    let Some(warnings) = warnings else {
        return Ok(Vec::new());
    };
    let array = warnings
        .as_array()
        .context("旧版 warnings 字段必须是数组")?;
    array
        .iter()
        .map(|warning| normalize_legacy_warning(warning, default_source))
        .collect()
}

fn normalize_legacy_warning(warning: &Value, default_source: &str) -> Result<EvidenceWarning> {
    match warning {
        Value::String(message) => Ok(EvidenceWarning::new(
            "legacy.unclassified",
            EvidenceWarningSeverity::Warning,
            message,
            default_source,
        )),
        Value::Object(object) => {
            let code = object
                .get("code")
                .and_then(Value::as_str)
                .filter(|code| is_stable_identifier(code))
                .map(str::to_owned)
                .or_else(|| {
                    object
                        .get("kind")
                        .and_then(Value::as_str)
                        .map(normalize_warning_code)
                })
                .unwrap_or_else(|| "legacy.unclassified".to_owned());
            let message = object
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("legacy warning did not provide a message")
                .to_owned();
            let severity = object
                .get("severity")
                .and_then(Value::as_str)
                .map(parse_warning_severity)
                .unwrap_or(EvidenceWarningSeverity::Warning);
            let source = object
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or(default_source)
                .to_owned();
            let context = object
                .iter()
                .filter(|(key, _)| {
                    !matches!(
                        key.as_str(),
                        "code" | "kind" | "severity" | "message" | "source"
                    )
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            Ok(EvidenceWarning {
                code,
                severity,
                message,
                source,
                context,
            })
        }
        _ => {
            let mut normalized = EvidenceWarning::new(
                "legacy.invalid_warning",
                EvidenceWarningSeverity::Warning,
                "legacy warning used an unsupported JSON representation",
                default_source,
            );
            normalized
                .context
                .insert("value".to_owned(), warning.clone());
            Ok(normalized)
        }
    }
}

fn parse_warning_severity(value: &str) -> EvidenceWarningSeverity {
    match value.to_ascii_lowercase().as_str() {
        "info" => EvidenceWarningSeverity::Info,
        "error" | "critical" | "fatal" => EvidenceWarningSeverity::Error,
        _ => EvidenceWarningSeverity::Warning,
    }
}

fn normalize_warning_code(kind: &str) -> String {
    let mut normalized = String::with_capacity(kind.len());
    let mut separator = false;
    for character in kind.chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !normalized.is_empty() {
                normalized.push('_');
            }
            normalized.push(character.to_ascii_lowercase());
            separator = false;
        } else {
            separator = true;
        }
    }
    while normalized.ends_with('_') {
        normalized.pop();
    }
    if normalized.is_empty() {
        "legacy.unclassified".to_owned()
    } else if normalized
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_lowercase)
    {
        normalized
    } else {
        format!("warning.{normalized}")
    }
}

fn is_stable_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || !bytes[0].is_ascii_lowercase()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
    {
        return false;
    }
    let mut segment_start = false;
    for byte in bytes {
        if *byte == b'.' {
            if segment_start {
                return false;
            }
            segment_start = true;
        } else {
            if segment_start && !byte.is_ascii_lowercase() && !byte.is_ascii_digit() {
                return false;
            }
            segment_start = false;
            if !byte.is_ascii_lowercase()
                && !byte.is_ascii_digit()
                && *byte != b'-'
                && *byte != b'_'
            {
                return false;
            }
        }
    }
    true
}

fn looks_like_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with('\\')
        || value
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
}

fn value_contains_absolute_path(value: &Value) -> bool {
    match value {
        Value::String(value) => looks_like_absolute_path(value),
        Value::Array(values) => values.iter().any(value_contains_absolute_path),
        Value::Object(values) => values.values().any(value_contains_absolute_path),
        _ => false,
    }
}

fn validate_digest(digest: &DigestReference, path: &str) -> Result<()> {
    ensure!(
        !digest.algorithm.trim().is_empty(),
        "{path}.algorithm 不能为空"
    );
    ensure!(!digest.value.trim().is_empty(), "{path}.value 不能为空");
    Ok(())
}

fn sample_digest(file: &mut File, size: u64) -> Result<String> {
    let chunk_len = size.min(SAMPLE_CHUNK_BYTES as u64);
    let mut offsets = BTreeSet::new();
    offsets.insert(0_u64);
    if chunk_len > 0 {
        offsets.insert((size.saturating_sub(chunk_len)) / 2);
        offsets.insert(size.saturating_sub(chunk_len));
    }

    let mut hasher = Sha256::new();
    hasher.update(b"starmem-source-sample-v1\0");
    hasher.update(size.to_le_bytes());
    let mut buffer = vec![0_u8; usize::try_from(chunk_len).unwrap_or(SAMPLE_CHUNK_BYTES)];
    for offset in offsets {
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buffer)?;
        hasher.update(offset.to_le_bytes());
        hasher.update(chunk_len.to_le_bytes());
        hasher.update(&buffer);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn source_identity() -> SourceIdentity {
        SourceIdentity {
            format: "raw".to_owned(),
            size: 4096,
            mtime: None,
            sample_digest: DigestReference::new("sha256-starmem-sample-v1", "00"),
            symbol_identity: None,
            components: Vec::new(),
            physical_layout: None,
        }
    }

    fn engine_identity() -> EngineIdentity {
        EngineIdentity::new("0.2.0", "test-build", 3)
    }

    #[test]
    fn envelope_serialization_always_contains_required_contract_fields() {
        let envelope = EvidenceEnvelope::from_parts(
            "windows.pslist",
            engine_identity(),
            source_identity(),
            true,
            false,
            EvidenceScope::new("active_process_list"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            RawEvidenceSummary::default(),
            json!({"processes": []}),
        )
        .unwrap();
        let object = serde_json::to_value(envelope).unwrap();
        let object = object.as_object().unwrap();
        for field in [
            "schema_version",
            "command",
            "engine_identity",
            "source_identity",
            "available",
            "complete",
            "scope",
            "warnings",
            "limits",
            "missing_ranges",
            "raw_evidence",
            "data",
        ] {
            assert!(object.contains_key(field), "missing field {field}");
        }
        assert!(object["available"].is_boolean());
        assert!(object["complete"].is_boolean());
    }

    #[test]
    fn unavailable_evidence_cannot_claim_completeness() {
        let result = EvidenceEnvelope::from_parts(
            "linux.kmsg",
            engine_identity(),
            source_identity(),
            false,
            true,
            EvidenceScope::new("kernel_log"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            RawEvidenceSummary::default(),
            json!({}),
        );
        assert!(result.is_err());
    }

    #[test]
    fn legacy_adapter_requires_explicit_missing_status() {
        let report = json!({"warnings": []});
        let result = LegacyReportAdapter::new(EvidenceScope::new("physical_memory")).adapt(
            "windows.filescan",
            engine_identity(),
            source_identity(),
            report,
        );
        assert!(result.unwrap_err().to_string().contains("available"));
    }

    #[test]
    fn legacy_warning_shapes_are_normalized() {
        let report = json!({
            "complete": false,
            "warnings": [
                "plain warning",
                {"kind": "Head Blink Mismatch", "message": "bad backlink", "list_entry": 42},
                {"code": "already.stable", "severity": "error", "message": "failed", "source": "task_ring"}
            ]
        });
        let envelope = LegacyReportAdapter::new(EvidenceScope::new("active_process_list"))
            .with_status(true, false)
            .adapt(
                "windows.pslist",
                engine_identity(),
                source_identity(),
                report,
            )
            .unwrap();
        assert_eq!(envelope.warnings[0].code, "legacy.unclassified");
        assert_eq!(envelope.warnings[0].message, "plain warning");
        assert_eq!(envelope.warnings[1].code, "head_blink_mismatch");
        assert_eq!(envelope.warnings[1].context["list_entry"], 42);
        assert_eq!(envelope.warnings[2].code, "already.stable");
        assert_eq!(
            envelope.warnings[2].severity,
            EvidenceWarningSeverity::Error
        );
    }

    #[test]
    fn null_limit_reached_is_preserved() {
        let envelope = EvidenceEnvelope::from_parts(
            "linux.info",
            engine_identity(),
            source_identity(),
            true,
            false,
            EvidenceScope::new("physical_memory"),
            Vec::new(),
            vec![EvidenceLimit::new(
                "scan_bytes",
                EvidenceLimitKind::SourceScan,
            )],
            Vec::new(),
            RawEvidenceSummary::default(),
            json!({}),
        )
        .unwrap();
        let value = serde_json::to_value(envelope).unwrap();
        assert!(value["limits"][0]["reached"].is_null());
    }

    #[test]
    fn identifier_validation_matches_schema_segment_rules() {
        assert!(is_stable_identifier("symbols.id"));
        assert!(is_stable_identifier("windows.recent-files"));
        assert!(!is_stable_identifier("symbols.-id"));
        assert!(!is_stable_identifier("Symbols.id"));
    }

    #[test]
    fn symbol_identity_rejects_machine_local_paths() {
        let result = EvidenceEnvelope::from_parts(
            "linux.lsmod",
            engine_identity(),
            source_identity().with_symbol_identity(SymbolIdentity::new(
                "linux_isf",
                "/Users/example/.cache/symbol.json",
            )),
            true,
            false,
            EvidenceScope::new("kernel_modules"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            RawEvidenceSummary::default(),
            json!({}),
        );
        assert!(result.unwrap_err().to_string().contains("绝对路径"));

        let mut symbol = SymbolIdentity::new("linux_isf", "stable-key");
        symbol.details.insert(
            "candidate".to_owned(),
            Value::String("C:\\Users\\example\\symbol.json".to_owned()),
        );
        let result = EvidenceEnvelope::from_parts(
            "linux.lsmod",
            engine_identity(),
            source_identity().with_symbol_identity(symbol),
            true,
            false,
            EvidenceScope::new("kernel_modules"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            RawEvidenceSummary::default(),
            json!({}),
        );
        assert!(result.unwrap_err().to_string().contains("details"));
    }

    #[test]
    fn windows_profile_identity_is_stable_and_path_free() {
        let profile = KernelProfile {
            schema_version: 2,
            pdb_guid: "{7427da99-c3d7-3720-2bfb-359c2b0e1a5e}".to_owned(),
            pdb_age: 1,
            type_name: "_EPROCESS".to_owned(),
            type_size: 0x4d0,
            fields: BTreeMap::new(),
            types: BTreeMap::new(),
            symbols: BTreeMap::new(),
        };
        let first = windows_symbol_identity(&profile).unwrap().unwrap();
        let second = windows_symbol_identity(&profile).unwrap().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.kind, "windows_pdb");
        assert_eq!(first.key, "7427DA99C3D737202BFB359C2B0E1A5E1");
        assert_eq!(first.digest.as_ref().unwrap().value.len(), 64);
        let serialized = serde_json::to_string(&first).unwrap();
        assert!(!serialized.contains("/Users/"));
        assert!(!serialized.contains("C:\\"));
    }
}
