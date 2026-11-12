use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::session::AnalysisSession;
use crate::windows::files::{DumpSource, FileScanRecord};
use crate::windows::plugins::HiveRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSelection {
    Registry,
    EventLogs,
    All,
}

#[derive(Debug, Clone)]
pub struct ArtifactExportOptions {
    pub selection: ArtifactSelection,
    pub file_scan_limit: usize,
    pub artifact_limit: usize,
    pub max_file_size: u64,
    pub force: bool,
}

impl Default for ArtifactExportOptions {
    fn default() -> Self {
        Self {
            selection: ArtifactSelection::All,
            file_scan_limit: 1_000_000,
            artifact_limit: 100_000,
            max_file_size: 4 * 1024 * 1024 * 1024,
            force: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ArtifactExportRecord {
    pub kind: ArtifactKind,
    pub cmhive: Option<u64>,
    pub cmhive_hex: Option<String>,
    pub file_object: u64,
    pub file_object_hex: String,
    pub physical_address: u64,
    pub physical_address_hex: String,
    pub original_path: String,
    pub output_path: Option<String>,
    pub recoverable_sources: Vec<String>,
    pub attempted: bool,
    pub success: bool,
    pub source: Option<DumpSource>,
    pub logical_size: Option<u64>,
    pub output_size: Option<u64>,
    pub recovered_bytes: Option<u64>,
    pub missing_bytes: Option<u64>,
    pub complete: Option<bool>,
    /// Expected on-disk signature when the artifact format has a stable magic.
    pub signature_expected: Option<String>,
    /// `None` means that this artifact type has no reliable signature check yet.
    pub signature_valid: Option<bool>,
    pub signature_observed_hex: Option<String>,
    /// Page reconstruction provenance for an exported live registry hive.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub compressed_pages: Vec<crate::windows::compressed_store::CompressedPageEvidence>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Registry,
    EventLog,
}

#[derive(Debug, Serialize)]
pub struct ArtifactExportReport {
    pub selection: ArtifactSelection,
    pub output_directory: String,
    pub file_scan_complete: bool,
    pub file_scan_records: usize,
    pub loaded_hive_candidates: usize,
    pub loaded_hives_attempted: usize,
    pub loaded_hives_recovered: usize,
    pub candidates: usize,
    pub attempted: usize,
    pub recovered: usize,
    pub complete_files: usize,
    pub partial_files: usize,
    pub signature_valid_files: usize,
    pub signature_invalid_files: usize,
    pub signature_unchecked_files: usize,
    pub unavailable: usize,
    pub failed: usize,
    pub truncated: bool,
    pub warnings: Vec<String>,
    pub records: Vec<ArtifactExportRecord>,
}

pub fn export_artifacts(
    session: &AnalysisSession,
    output_directory: impl AsRef<Path>,
    options: &ArtifactExportOptions,
) -> Result<ArtifactExportReport> {
    ensure!(
        options.file_scan_limit > 0,
        "file scan limit must be greater than zero"
    );
    ensure!(
        options.artifact_limit > 0,
        "artifact limit must be greater than zero"
    );
    ensure!(
        options.max_file_size > 0,
        "maximum file size must be greater than zero"
    );

    let output_directory = output_directory.as_ref();
    let mut output_policy = OutputPolicy::new(options.force);
    for source in session.image().sources() {
        output_policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    output_policy.output(
        OutputTarget::directory("artifact_export", output_directory)
            .with_owned_file("export-report.json"),
    );
    output_policy.prepare_directories().with_context(|| {
        format!(
            "cannot prepare artifact output directory {}",
            output_directory.display()
        )
    })?;

    let mut report_warnings = Vec::new();
    let mut loaded_hives = Vec::new();
    let mut registry_process_dtb = None;
    if matches!(
        options.selection,
        ArtifactSelection::Registry | ArtifactSelection::All
    ) {
        let hive_report = session.hives(65_536)?;
        report_warnings.extend(hive_report.warnings);
        loaded_hives = hive_report.records;
        loaded_hives.sort_by(|left, right| {
            hive_priority(left)
                .cmp(&hive_priority(right))
                .then_with(|| hive_original_path(left).cmp(&hive_original_path(right)))
                .then_with(|| left.cmhive.cmp(&right.cmhive))
        });

        let process_report = session.processes(65_536)?;
        registry_process_dtb = crate::system::registry::registry_process_dtb(&process_report);
        report_warnings.extend(
            process_report
                .warnings
                .into_iter()
                .map(|warning| format!("pslist/{}: {}", warning.kind, warning.message)),
        );
        if registry_process_dtb.is_none() {
            report_warnings.push(
                "Registry process DTB was not recovered; user-mapped hive pages may be partial"
                    .to_owned(),
            );
        }
    }

    let file_report = session.files(options.file_scan_limit)?;
    report_warnings.extend(file_report.warnings.iter().cloned());
    let direct_hives_available = !loaded_hives.is_empty();
    let mut candidates = file_report
        .records
        .iter()
        .filter_map(|record| {
            classify_record(record, options.selection).and_then(|kind| {
                (!(direct_hives_available
                    && kind == ArtifactKind::Registry
                    && is_primary_registry_file(record)))
                .then_some((record, kind))
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|(left, left_kind), (right, right_kind)| {
        usize::from(has_recovery_source(right))
            .cmp(&usize::from(has_recovery_source(left)))
            .then_with(|| artifact_rank(*left_kind).cmp(&artifact_rank(*right_kind)))
            .then_with(|| {
                artifact_priority(left, *left_kind).cmp(&artifact_priority(right, *right_kind))
            })
            .then_with(|| {
                left.name
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .cmp(&right.name.as_deref().unwrap_or("").to_ascii_lowercase())
            })
            .then_with(|| left.file_object.cmp(&right.file_object))
    });

    let loaded_hive_candidates = loaded_hives.len();
    let candidate_count = loaded_hive_candidates + candidates.len();
    let truncated = candidate_count > options.artifact_limit;
    loaded_hives.truncate(options.artifact_limit);
    let remaining = options.artifact_limit.saturating_sub(loaded_hives.len());
    candidates.truncate(remaining);
    let mut used_paths = HashSet::new();
    let mut records = Vec::with_capacity(loaded_hives.len() + candidates.len());

    for hive in loaded_hives {
        let original_path = hive_original_path(&hive);
        let relative_source = format!("loaded-hives\\{original_path}");
        let relative = unique_relative_path(
            &relative_source,
            hive.cmhive,
            ArtifactKind::Registry,
            &mut used_paths,
        );
        let output_path = output_directory.join(relative);
        match session.recover_hive(
            hive.cmhive,
            registry_process_dtb,
            &output_path,
            options.max_file_size,
            options.force,
        ) {
            Ok(recovery) => {
                let signature = inspect_artifact_signature(
                    ArtifactKind::Registry,
                    &original_path,
                    &output_path,
                );
                let mut warnings = recovery.warnings;
                if let Some(warning) = signature.warning {
                    warnings.push(warning);
                }
                let success = recovery.recovered_bytes > 0 && signature.valid != Some(false);
                let error = (signature.valid == Some(false)).then(|| {
                    "direct hive output does not begin with a valid regf signature".to_owned()
                });
                records.push(ArtifactExportRecord {
                    kind: ArtifactKind::Registry,
                    cmhive: Some(hive.cmhive),
                    cmhive_hex: Some(format!("{:#018x}", hive.cmhive)),
                    file_object: 0,
                    file_object_hex: format!("{:#018x}", 0),
                    physical_address: 0,
                    physical_address_hex: format!("{:#018x}", 0),
                    original_path,
                    output_path: Some(output_path.display().to_string()),
                    recoverable_sources: vec!["hive_memory".to_owned()],
                    attempted: true,
                    success,
                    source: Some(recovery.source),
                    logical_size: Some(recovery.logical_size),
                    output_size: Some(recovery.output_size),
                    recovered_bytes: Some(recovery.recovered_bytes),
                    missing_bytes: Some(recovery.missing_bytes),
                    complete: Some(recovery.complete),
                    signature_expected: signature.expected,
                    signature_valid: signature.valid,
                    signature_observed_hex: signature.observed_hex,
                    compressed_pages: recovery.compressed_pages,
                    warnings,
                    error,
                });
            }
            Err(error) => records.push(ArtifactExportRecord {
                kind: ArtifactKind::Registry,
                cmhive: Some(hive.cmhive),
                cmhive_hex: Some(format!("{:#018x}", hive.cmhive)),
                file_object: 0,
                file_object_hex: format!("{:#018x}", 0),
                physical_address: 0,
                physical_address_hex: format!("{:#018x}", 0),
                original_path,
                output_path: Some(output_path.display().to_string()),
                recoverable_sources: vec!["hive_memory".to_owned()],
                attempted: true,
                success: false,
                source: None,
                logical_size: None,
                output_size: None,
                recovered_bytes: None,
                missing_bytes: None,
                complete: None,
                signature_expected: Some("regf".to_owned()),
                signature_valid: None,
                signature_observed_hex: None,
                compressed_pages: Vec::new(),
                warnings: Vec::new(),
                error: Some(format!("{error:#}")),
            }),
        }
    }

    for (record, kind) in candidates {
        let original_path = record.name.clone().unwrap_or_default();
        let sources = recoverable_sources(record);
        if sources.is_empty() {
            let signature_expected =
                signature_spec(kind, &original_path).map(|spec| spec.expected.to_owned());
            records.push(ArtifactExportRecord {
                kind,
                cmhive: None,
                cmhive_hex: None,
                file_object: record.file_object,
                file_object_hex: format!("{:#018x}", record.file_object),
                physical_address: record.physical_address,
                physical_address_hex: format!("{:#018x}", record.physical_address),
                original_path,
                output_path: None,
                recoverable_sources: sources,
                attempted: false,
                success: false,
                source: None,
                logical_size: None,
                output_size: None,
                recovered_bytes: None,
                missing_bytes: None,
                complete: None,
                signature_expected,
                signature_valid: None,
                signature_observed_hex: None,
                warnings: Vec::new(),
                error: Some("no resident Cache/Data/Image recovery source".to_owned()),
                compressed_pages: Vec::new(),
            });
            continue;
        }

        let relative =
            unique_relative_path(&original_path, record.file_object, kind, &mut used_paths);
        let output_path = output_directory.join(relative);
        match session.recover_file(
            record.file_object,
            &output_path,
            DumpSource::Auto,
            options.max_file_size,
            options.force,
        ) {
            Ok(recovery) => {
                let signature = if recovery.recovered_bytes > 0 {
                    inspect_artifact_signature(kind, &original_path, &output_path)
                } else {
                    SignatureCheck {
                        expected: signature_spec(kind, &original_path)
                            .map(|spec| spec.expected.to_owned()),
                        valid: None,
                        observed_hex: None,
                        warning: None,
                    }
                };
                let mut warnings = recovery.warnings;
                if let Some(warning) = signature.warning {
                    warnings.push(warning);
                }
                let success = recovery.recovered_bytes > 0 && signature.valid != Some(false);
                let error = (signature.valid == Some(false)).then(|| {
                    format!(
                        "recovered output does not begin with the expected {} signature",
                        signature.expected.as_deref().unwrap_or("artifact")
                    )
                });
                records.push(ArtifactExportRecord {
                    kind,
                    cmhive: None,
                    cmhive_hex: None,
                    file_object: record.file_object,
                    file_object_hex: format!("{:#018x}", record.file_object),
                    physical_address: record.physical_address,
                    physical_address_hex: format!("{:#018x}", record.physical_address),
                    original_path,
                    output_path: Some(output_path.display().to_string()),
                    recoverable_sources: sources,
                    attempted: true,
                    success,
                    source: Some(recovery.source),
                    logical_size: Some(recovery.logical_size),
                    output_size: Some(recovery.output_size),
                    recovered_bytes: Some(recovery.recovered_bytes),
                    missing_bytes: Some(recovery.missing_bytes),
                    complete: Some(recovery.complete),
                    signature_expected: signature.expected,
                    signature_valid: signature.valid,
                    signature_observed_hex: signature.observed_hex,
                    compressed_pages: recovery.compressed_pages,
                    warnings,
                    error,
                });
            }
            Err(error) => {
                let signature_expected =
                    signature_spec(kind, &original_path).map(|spec| spec.expected.to_owned());
                records.push(ArtifactExportRecord {
                    kind,
                    cmhive: None,
                    cmhive_hex: None,
                    file_object: record.file_object,
                    file_object_hex: format!("{:#018x}", record.file_object),
                    physical_address: record.physical_address,
                    physical_address_hex: format!("{:#018x}", record.physical_address),
                    original_path,
                    output_path: Some(output_path.display().to_string()),
                    recoverable_sources: sources,
                    attempted: true,
                    success: false,
                    source: None,
                    logical_size: None,
                    output_size: None,
                    recovered_bytes: None,
                    missing_bytes: None,
                    complete: None,
                    signature_expected,
                    signature_valid: None,
                    signature_observed_hex: None,
                    warnings: Vec::new(),
                    error: Some(format!("{error:#}")),
                    compressed_pages: Vec::new(),
                });
            }
        }
    }

    let attempted = records.iter().filter(|record| record.attempted).count();
    let recovered = records.iter().filter(|record| record.success).count();
    let complete_files = records
        .iter()
        .filter(|record| record.success && record.complete == Some(true))
        .count();
    let partial_files = records
        .iter()
        .filter(|record| record.success && record.complete == Some(false))
        .count();
    let signature_valid_files = records
        .iter()
        .filter(|record| record.signature_valid == Some(true))
        .count();
    let signature_invalid_files = records
        .iter()
        .filter(|record| record.signature_valid == Some(false))
        .count();
    let signature_unchecked_files = records
        .iter()
        .filter(|record| {
            record.attempted
                && record.recovered_bytes.unwrap_or(0) > 0
                && record.signature_valid.is_none()
        })
        .count();
    let unavailable = records.iter().filter(|record| !record.attempted).count();
    let failed = records
        .iter()
        .filter(|record| record.attempted && !record.success)
        .count();
    let loaded_hives_attempted = records
        .iter()
        .filter(|record| record.cmhive.is_some() && record.attempted)
        .count();
    let loaded_hives_recovered = records
        .iter()
        .filter(|record| record.cmhive.is_some() && record.success)
        .count();
    let report = ArtifactExportReport {
        selection: options.selection,
        output_directory: output_directory.display().to_string(),
        file_scan_complete: file_report.complete,
        file_scan_records: file_report.records.len(),
        loaded_hive_candidates,
        loaded_hives_attempted,
        loaded_hives_recovered,
        candidates: candidate_count,
        attempted,
        recovered,
        complete_files,
        partial_files,
        signature_valid_files,
        signature_invalid_files,
        signature_unchecked_files,
        unavailable,
        failed,
        truncated,
        warnings: report_warnings,
        records,
    };
    write_manifest(&output_policy, output_directory, &report)?;
    Ok(report)
}

fn classify_record(record: &FileScanRecord, selection: ArtifactSelection) -> Option<ArtifactKind> {
    let path = record.name.as_deref()?.replace('/', "\\");
    let normalized = path.to_ascii_lowercase();
    if matches!(
        selection,
        ArtifactSelection::Registry | ArtifactSelection::All
    ) && is_registry_artifact(&normalized)
    {
        return Some(ArtifactKind::Registry);
    }
    if matches!(
        selection,
        ArtifactSelection::EventLogs | ArtifactSelection::All
    ) && is_event_log(&normalized)
    {
        return Some(ArtifactKind::EventLog);
    }
    None
}

fn is_registry_artifact(path: &str) -> bool {
    let filename = path.rsplit('\\').next().unwrap_or(path);
    let system_hive = path.contains("\\windows\\system32\\config\\")
        && matches!(
            base_registry_name(filename),
            "system"
                | "software"
                | "sam"
                | "security"
                | "default"
                | "components"
                | "drivers"
                | "elam"
                | "bbihive"
                | "bcd-template"
        );
    let user_hive = filename.starts_with("ntuser.dat") || filename.starts_with("usrclass.dat");
    let application_hive = filename.starts_with("amcache.hve")
        || filename.starts_with("syscache.hve")
        || filename.starts_with("recentfilecache.bcf");
    let boot_configuration = filename == "bcd" && path.contains("\\boot\\");
    system_hive || user_hive || application_hive || boot_configuration
}

fn is_primary_registry_file(record: &FileScanRecord) -> bool {
    let path = record
        .name
        .as_deref()
        .unwrap_or("")
        .replace('/', "\\")
        .to_ascii_lowercase();
    let filename = path.rsplit('\\').next().unwrap_or(&path);
    is_registry_artifact(&path)
        && !filename.ends_with(".log1")
        && !filename.ends_with(".log2")
        && !filename.ends_with(".log")
        && !filename.ends_with(".blf")
        && !filename.contains(".regtrans-ms")
        && !filename.ends_with(".tm")
        && filename != "recentfilecache.bcf"
}

fn base_registry_name(filename: &str) -> &str {
    filename
        .strip_suffix(".log1")
        .or_else(|| filename.strip_suffix(".log2"))
        .or_else(|| filename.strip_suffix(".log"))
        .or_else(|| filename.strip_suffix(".blf"))
        .or_else(|| filename.split_once(".regtrans-ms").map(|(base, _)| base))
        .unwrap_or(filename)
}

fn is_event_log(path: &str) -> bool {
    let filename = path.rsplit('\\').next().unwrap_or(path);
    filename.ends_with(".evtx") || filename.ends_with(".evt") || filename.ends_with(".etl")
}

fn recoverable_sources(record: &FileScanRecord) -> Vec<String> {
    let mut sources = Vec::with_capacity(3);
    if record.shared_cache_map != 0 {
        sources.push("cache".to_owned());
    }
    if record.data_section_object != 0 {
        sources.push("data".to_owned());
    }
    if record.image_section_object != 0 {
        sources.push("image".to_owned());
    }
    sources
}

fn unique_relative_path(
    original_path: &str,
    file_object: u64,
    kind: ArtifactKind,
    used_paths: &mut HashSet<String>,
) -> PathBuf {
    let category = match kind {
        ArtifactKind::Registry => "registry",
        ArtifactKind::EventLog => "event-logs",
    };
    let mut relative = PathBuf::from(category);
    let components = original_path
        .replace('/', "\\")
        .split('\\')
        .filter(|component| !component.is_empty() && *component != "." && *component != "..")
        .map(sanitize_component)
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    if components.is_empty() {
        relative.push(format!("artifact_{file_object:016x}.bin"));
    } else {
        for component in components {
            relative.push(component);
        }
    }

    let key = relative.to_string_lossy().to_ascii_lowercase();
    if used_paths.insert(key) {
        return relative;
    }
    let stem = relative
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact");
    let extension = relative.extension().and_then(|value| value.to_str());
    let name = match extension {
        Some(extension) => format!("{stem}_{file_object:016x}.{extension}"),
        None => format!("{stem}_{file_object:016x}"),
    };
    relative.set_file_name(name);
    used_paths.insert(relative.to_string_lossy().to_ascii_lowercase());
    relative
}

fn sanitize_component(component: &str) -> String {
    let sanitized = component
        .chars()
        .map(|character| match character {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\0' => '_',
            character if character.is_control() => '_',
            character => character,
        })
        .collect::<String>();
    sanitized.trim().trim_end_matches('.').to_owned()
}

fn hive_original_path(hive: &HiveRecord) -> String {
    [&hive.file_path, &hive.user_name, &hive.root_path]
        .into_iter()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| format!("unnamed\\hive_{:016x}.hive", hive.cmhive))
}

fn hive_priority(hive: &HiveRecord) -> u8 {
    let evidence =
        format!("{}\\{}\\{}", hive.file_path, hive.user_name, hive.root_path).to_ascii_lowercase();
    if evidence.ends_with("\\system") || evidence.contains("\\machine\\system") {
        0
    } else if evidence.ends_with("\\software") || evidence.contains("\\machine\\software") {
        1
    } else if evidence.ends_with("\\sam") || evidence.contains("\\machine\\sam") {
        2
    } else if evidence.ends_with("\\security") || evidence.contains("\\machine\\security") {
        3
    } else if evidence.ends_with("\\default") || evidence.contains("\\user\\.default") {
        4
    } else if evidence.ends_with("\\bcd") || evidence.contains("\\bcd00000000") {
        5
    } else if evidence.contains("ntuser.dat") || evidence.contains("usrclass.dat") {
        6
    } else if evidence.contains("amcache.hve") {
        7
    } else {
        8
    }
}

fn artifact_rank(kind: ArtifactKind) -> u8 {
    match kind {
        ArtifactKind::Registry => 0,
        ArtifactKind::EventLog => 1,
    }
}

fn has_recovery_source(record: &FileScanRecord) -> bool {
    record.shared_cache_map != 0
        || record.data_section_object != 0
        || record.image_section_object != 0
}

fn artifact_priority(record: &FileScanRecord, kind: ArtifactKind) -> u8 {
    let path = record
        .name
        .as_deref()
        .unwrap_or("")
        .replace('/', "\\")
        .to_ascii_lowercase();
    let filename = path.rsplit('\\').next().unwrap_or(&path);
    match kind {
        ArtifactKind::Registry
            if matches!(
                filename,
                "system" | "software" | "sam" | "security" | "default"
            ) =>
        {
            0
        }
        ArtifactKind::Registry if matches!(filename, "ntuser.dat" | "usrclass.dat") => 1,
        ArtifactKind::Registry => 2,
        ArtifactKind::EventLog
            if matches!(
                filename,
                "system.evtx" | "security.evtx" | "application.evtx" | "setup.evtx"
            ) =>
        {
            0
        }
        ArtifactKind::EventLog if filename.ends_with(".evtx") => 1,
        ArtifactKind::EventLog => 2,
    }
}

#[derive(Debug, Clone, Copy)]
struct SignatureSpec {
    expected: &'static str,
    offset: usize,
    accepted: &'static [&'static [u8]],
}

#[derive(Debug)]
struct SignatureCheck {
    expected: Option<String>,
    valid: Option<bool>,
    observed_hex: Option<String>,
    warning: Option<String>,
}

const REGF_SIGNATURES: &[&[u8]] = &[b"regf"];
const HIVE_LOG_SIGNATURES: &[&[u8]] = &[b"HvLE", b"regf"];
const EVTX_SIGNATURES: &[&[u8]] = &[b"ElfFile\0"];
const EVT_SIGNATURES: &[&[u8]] = &[b"LfLe"];

fn signature_spec(kind: ArtifactKind, original_path: &str) -> Option<SignatureSpec> {
    let normalized = original_path.replace('/', "\\").to_ascii_lowercase();
    let filename = normalized.rsplit('\\').next().unwrap_or(&normalized);
    match kind {
        ArtifactKind::Registry
            if filename.ends_with(".log1")
                || filename.ends_with(".log2")
                || filename.ends_with(".log") =>
        {
            Some(SignatureSpec {
                expected: "HvLE/regf",
                offset: 0,
                accepted: HIVE_LOG_SIGNATURES,
            })
        }
        ArtifactKind::Registry
            if filename.ends_with(".blf")
                || filename.contains(".regtrans-ms")
                || filename.ends_with(".tm")
                || filename == "recentfilecache.bcf" =>
        {
            None
        }
        ArtifactKind::Registry => Some(SignatureSpec {
            expected: "regf",
            offset: 0,
            accepted: REGF_SIGNATURES,
        }),
        ArtifactKind::EventLog if filename.ends_with(".evtx") => Some(SignatureSpec {
            expected: "ElfFile\\0",
            offset: 0,
            accepted: EVTX_SIGNATURES,
        }),
        // Legacy EVT files store their stable LfLe marker after HeaderSize.
        ArtifactKind::EventLog if filename.ends_with(".evt") => Some(SignatureSpec {
            expected: "LfLe@+4",
            offset: 4,
            accepted: EVT_SIGNATURES,
        }),
        // ETL headers depend on the ETW logging mode and do not have a single
        // reliable file magic, so retain them without pretending to validate.
        ArtifactKind::EventLog => None,
    }
}

fn inspect_artifact_signature(
    kind: ArtifactKind,
    original_path: &str,
    output_path: &Path,
) -> SignatureCheck {
    let Some(spec) = signature_spec(kind, original_path) else {
        return SignatureCheck {
            expected: None,
            valid: None,
            observed_hex: None,
            warning: None,
        };
    };
    let expected = Some(spec.expected.to_owned());
    let required = spec.offset
        + spec
            .accepted
            .iter()
            .map(|signature| signature.len())
            .max()
            .unwrap_or(0);
    let mut header = Vec::new();
    let read_result = File::open(output_path)
        .and_then(|file| file.take(required.max(16) as u64).read_to_end(&mut header));
    if let Err(error) = read_result {
        return SignatureCheck {
            expected,
            valid: Some(false),
            observed_hex: None,
            warning: Some(format!(
                "cannot inspect recovered artifact signature: {error}"
            )),
        };
    }

    let valid = signature_matches(spec, &header);
    SignatureCheck {
        expected,
        valid: Some(valid),
        observed_hex: (!header.is_empty()).then(|| hex::encode_upper(&header)),
        warning: (!valid).then(|| {
            format!(
                "invalid {} signature; observed header {}",
                spec.expected,
                if header.is_empty() {
                    "<empty>".to_owned()
                } else {
                    hex::encode_upper(&header)
                }
            )
        }),
    }
}

fn signature_matches(spec: SignatureSpec, bytes: &[u8]) -> bool {
    spec.accepted.iter().any(|signature| {
        bytes
            .get(spec.offset..spec.offset + signature.len())
            .is_some_and(|observed| observed == *signature)
    })
}

fn write_manifest(
    policy: &OutputPolicy,
    output_directory: &Path,
    report: &ArtifactExportReport,
) -> Result<()> {
    let path = output_directory.join("export-report.json");
    policy.write_file_atomic(&path, |output| {
        serde_json::to_writer_pretty(output, report)
            .with_context(|| format!("cannot write {}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_registry_hives_and_transaction_files() {
        assert!(is_registry_artifact(
            r"\device\harddiskvolume3\windows\system32\config\system"
        ));
        assert!(is_registry_artifact(
            r"\device\harddiskvolume3\users\alice\ntuser.dat.log1"
        ));
        assert!(is_registry_artifact(
            r"\device\harddiskvolume3\users\alice\appdata\local\microsoft\windows\usrclass.dat"
        ));
        assert!(!is_registry_artifact(
            r"\device\harddiskvolume3\windows\system32\config\notes.txt"
        ));
    }

    #[test]
    fn classifies_windows_event_logs() {
        assert!(is_event_log(r"\windows\system32\winevt\logs\security.evtx"));
        assert!(is_event_log(r"\windows\system32\wdi\bootckcl.etl"));
        assert!(!is_event_log(r"\windows\windowsupdate.log"));
    }

    #[test]
    fn output_path_cannot_escape_export_root() {
        let mut used = HashSet::new();
        let path = unique_relative_path(
            r"..\..\Windows\System32\config\SYSTEM",
            0x1234,
            ArtifactKind::Registry,
            &mut used,
        );
        assert!(path.starts_with("registry"));
        assert!(!path.to_string_lossy().contains(".."));
    }

    #[test]
    fn validates_stable_registry_and_event_log_signatures() {
        let hive = signature_spec(ArtifactKind::Registry, r"C:\Windows\System32\config\SYSTEM")
            .expect("main hive signature");
        assert!(signature_matches(hive, b"regf\x01\x00\x00\x00"));
        assert!(!signature_matches(hive, b"not-a-hive"));

        let evtx = signature_spec(
            ArtifactKind::EventLog,
            r"C:\Windows\System32\winevt\Logs\System.evtx",
        )
        .expect("EVTX signature");
        assert!(signature_matches(evtx, b"ElfFile\0more"));

        let evt = signature_spec(ArtifactKind::EventLog, r"C:\Windows\system32\legacy.evt")
            .expect("EVT signature");
        assert!(signature_matches(evt, b"\x30\x00\x00\x00LfLe"));
    }

    #[test]
    fn leaves_etl_and_clfs_transactions_unchecked() {
        assert!(signature_spec(ArtifactKind::EventLog, "trace.etl").is_none());
        assert!(signature_spec(ArtifactKind::Registry, "SYSTEM.blf").is_none());
        assert!(signature_spec(ArtifactKind::Registry, "SYSTEM.regtrans-ms").is_none());
    }
}
