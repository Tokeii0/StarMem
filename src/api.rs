//! Stable, synchronous host API for GUI integrations such as LovelyMem.
//!
//! StarMem intentionally does not depend on Tauri or an async runtime. Hosts
//! should keep [`Session`] in their own session manager and call [`Session::open`]
//! and [`Session::run`] from a blocking worker. The rest of the crate remains
//! public for existing Rust users, but only this module's DTO and runner
//! contract is covered by `INTEGRATION_API_VERSION` compatibility guarantees.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result as AnyResult, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::cancellation::{CancellationToken, is_cancellation_error};
use crate::collection::{
    DatabaseCollectionOptions, ReadablePluginPlatform, readable_plugin_catalog,
    run_readable_plugin_cancellable,
};
use crate::command_registry::{CommandRegistry, EMBEDDED_LEAF_COMMAND_COUNT};
use crate::evidence::{
    EngineIdentity, EvidenceEnvelope, EvidenceLimit, EvidenceLimitKind, EvidenceScope,
    EvidenceWarning, EvidenceWarningSeverity, MissingRange, RawEvidenceSummary, SourceIdentity,
    normalize_legacy_warnings, source_identity_for_memory_image, windows_symbol_identity,
};
use crate::image::{ImageOpenOptions, QevmPhysicalLayout};
use crate::session::{AnalysisSession, SessionOptions, SymbolLayoutExactness};
use crate::symbols::{SymbolStore, default_symbol_cache};
use crate::windows::process_string::{
    DEFAULT_PROCESS_STRING_REVERSE_ALIAS_LIMIT, DEFAULT_PROCESS_STRING_REVERSE_ENTRY_LIMIT,
    MAX_PROCESS_STRING_REVERSE_ALIAS_LIMIT, MAX_PROCESS_STRING_REVERSE_ENTRY_LIMIT,
    ProcessStringEncodingSelection, ProcessStringOptions,
};

/// Schema version for the serializable request, response, error and progress DTOs in this module.
pub const HOST_API_SCHEMA_VERSION: u32 = 1;

pub const ERROR_API_VERSION_MISMATCH: &str = "api.version-mismatch";
pub const ERROR_REQUEST_INVALID: &str = "request.invalid";
pub const ERROR_COMMAND_UNKNOWN: &str = "command.unknown";
pub const ERROR_COMMAND_UNSUPPORTED: &str = "command.unsupported";
pub const ERROR_PLATFORM_MISMATCH: &str = "platform.mismatch";
pub const ERROR_SESSION_OPEN_FAILED: &str = "session.open-failed";
pub const ERROR_TASK_CANCELLED: &str = "task.cancelled";
pub const ERROR_ANALYSIS_FAILED: &str = "analysis.failed";

const DEFAULT_DECODE_CACHE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_RESULT_LIMIT: usize = 65_536;
const DEFAULT_FILE_SCAN_LIMIT: usize = 1_000_000;
const DEFAULT_PROCESS_SPACE_LIMIT: usize = 256;
const DEFAULT_MAX_DATA_SIZE: usize = 256 * 1024 * 1024;
const DEFAULT_PROCESS_STRING_SCAN_HIT_LIMIT: usize = 1_000_000;
const DEFAULT_PROCESS_STRING_RESULT_LIMIT: usize = 10_000;
const DEFAULT_PROCESS_STRING_PROCESS_LIMIT: usize = 65_536;
const DEFAULT_PROCESS_STRING_MAPPING_LIMIT: usize = 64;
const DEFAULT_PROCESS_STRING_CHUNK_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_PROCESS_STRING_CONTEXT_BYTES: usize = 32;

/// Static compatibility and capability information used during host startup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiCapabilities {
    pub host_api_schema_version: u32,
    pub integration_api_version: u32,
    pub evidence_schema_version: u32,
    pub raw_object_schema_version: u32,
    pub command_registry_schema_version: u32,
    pub sqlite_schema_version: i64,
    pub version: String,
    pub build_id: String,
    pub registered_command_count: usize,
    pub supported_platforms: Vec<ApiPlatform>,
    pub runnable_command_ids: Vec<String>,
}

/// Returns a deterministic compatibility handshake without opening evidence or touching the network.
pub fn capabilities() -> ApiCapabilities {
    let mut runnable_command_ids = readable_plugin_catalog()
        .into_iter()
        .filter(|descriptor| descriptor.platform == ReadablePluginPlatform::Windows)
        .map(|descriptor| descriptor.name.to_owned())
        .collect::<Vec<_>>();
    runnable_command_ids.push("windows.process-string".to_owned());
    runnable_command_ids.sort();
    runnable_command_ids.dedup();
    ApiCapabilities {
        host_api_schema_version: HOST_API_SCHEMA_VERSION,
        integration_api_version: crate::INTEGRATION_API_VERSION,
        evidence_schema_version: crate::EVIDENCE_SCHEMA_VERSION,
        raw_object_schema_version: crate::RAW_OBJECT_SCHEMA_VERSION,
        command_registry_schema_version: crate::command_registry::COMMAND_REGISTRY_SCHEMA_VERSION,
        sqlite_schema_version: crate::database::DATABASE_SCHEMA_VERSION,
        version: crate::VERSION.to_owned(),
        build_id: crate::BUILD_ID.to_owned(),
        registered_command_count: EMBEDDED_LEAF_COMMAND_COUNT,
        supported_platforms: vec![ApiPlatform::Windows],
        runnable_command_ids,
    }
}

/// Returns the same versioned command contracts used by the CLI and `collect`.
pub fn command_catalog() -> ApiResult<CommandRegistry> {
    CommandRegistry::load_embedded().map_err(|error| {
        ApiError::new(
            ERROR_ANALYSIS_FAILED,
            format!("embedded command registry is invalid: {error}"),
        )
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformHint {
    #[default]
    Auto,
    Windows,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiPlatform {
    Windows,
    Linux,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostQevmPhysicalLayout {
    pub ram_block: String,
    pub below_4g_length: u64,
    pub above_4g_physical_base: u64,
}

impl From<HostQevmPhysicalLayout> for QevmPhysicalLayout {
    fn from(value: HostQevmPhysicalLayout) -> Self {
        Self {
            ram_block: value.ram_block,
            below_4g_length: value.below_4g_length,
            above_4g_physical_base: value.above_4g_physical_base,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostImageOptions {
    pub metadata_path: Option<PathBuf>,
    pub auto_discover_sidecars: bool,
    pub decode_cache_bytes: usize,
    pub qevm_layout: Option<HostQevmPhysicalLayout>,
}

impl Default for HostImageOptions {
    fn default() -> Self {
        Self {
            metadata_path: None,
            auto_discover_sidecars: true,
            decode_cache_bytes: DEFAULT_DECODE_CACHE_BYTES,
            qevm_layout: None,
        }
    }
}

/// Explicit symbol inputs for one host-owned session.
///
/// Automatic exact-symbol resolution retains the engine's existing behavior.
/// Supplying `profile_path` or `pdb_path` makes the session independent of a
/// symbol download; `search_roots` never relies on LovelyMem process globals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostSymbolOptions {
    pub profile_path: Option<PathBuf>,
    pub pdb_path: Option<PathBuf>,
    pub cache_root: Option<PathBuf>,
    pub search_roots: Vec<PathBuf>,
    pub allow_compatible_local_symbols: bool,
}

impl Default for HostSymbolOptions {
    fn default() -> Self {
        Self {
            profile_path: None,
            pdb_path: None,
            cache_root: None,
            search_roots: Vec::new(),
            allow_compatible_local_symbols: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenSessionRequest {
    pub integration_api_version: u32,
    pub request_id: String,
    pub image_path: PathBuf,
    #[serde(default)]
    pub platform: PlatformHint,
    #[serde(default)]
    pub image: HostImageOptions,
    #[serde(default)]
    pub symbols: HostSymbolOptions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenSessionResponse {
    pub host_api_schema_version: u32,
    pub integration_api_version: u32,
    pub platform: ApiPlatform,
    pub source_identity: SourceIdentity,
    pub warnings: Vec<EvidenceWarning>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    pub integration_api_version: u32,
    pub request_id: String,
    pub command_id: String,
    #[serde(default)]
    pub arguments: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    pub role: String,
    pub path: PathBuf,
    pub media_type: Option<String>,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunResponse {
    pub host_api_schema_version: u32,
    pub integration_api_version: u32,
    pub request_id: String,
    pub command_id: String,
    pub envelope: EvidenceEnvelope<Value>,
    pub artifacts: Vec<ArtifactReference>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReadableCommandArguments {
    pub result_limit: usize,
    pub file_scan_limit: usize,
    pub process_space_limit: usize,
    pub max_data_size: usize,
}

impl Default for ReadableCommandArguments {
    fn default() -> Self {
        Self {
            result_limit: DEFAULT_RESULT_LIMIT,
            file_scan_limit: DEFAULT_FILE_SCAN_LIMIT,
            process_space_limit: DEFAULT_PROCESS_SPACE_LIMIT,
            max_data_size: DEFAULT_MAX_DATA_SIZE,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStringEncoding {
    #[default]
    Both,
    Utf8,
    Utf16le,
}

impl From<ProcessStringEncoding> for ProcessStringEncodingSelection {
    fn from(value: ProcessStringEncoding) -> Self {
        match value {
            ProcessStringEncoding::Both => Self::Both,
            ProcessStringEncoding::Utf8 => Self::Utf8,
            ProcessStringEncoding::Utf16le => Self::Utf16Le,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStringArguments {
    pub text: String,
    #[serde(default)]
    pub encoding: ProcessStringEncoding,
    #[serde(default = "default_process_string_scan_hit_limit")]
    pub scan_hit_limit: usize,
    #[serde(default = "default_process_string_result_limit")]
    pub limit: usize,
    #[serde(default = "default_process_string_process_limit")]
    pub process_limit: usize,
    #[serde(default = "default_process_string_mapping_limit")]
    pub mapping_limit: usize,
    #[serde(default = "default_process_string_reverse_entry_limit")]
    pub reverse_entry_limit: usize,
    #[serde(default = "default_process_string_reverse_alias_limit")]
    pub reverse_alias_limit: usize,
    #[serde(default = "default_process_string_chunk_bytes")]
    pub chunk_bytes: usize,
    #[serde(default = "default_process_string_context_bytes")]
    pub context_bytes: usize,
}

impl ProcessStringArguments {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            encoding: ProcessStringEncoding::Both,
            scan_hit_limit: default_process_string_scan_hit_limit(),
            limit: default_process_string_result_limit(),
            process_limit: default_process_string_process_limit(),
            mapping_limit: default_process_string_mapping_limit(),
            reverse_entry_limit: default_process_string_reverse_entry_limit(),
            reverse_alias_limit: default_process_string_reverse_alias_limit(),
            chunk_bytes: default_process_string_chunk_bytes(),
            context_bytes: default_process_string_context_bytes(),
        }
    }
}

fn default_process_string_scan_hit_limit() -> usize {
    DEFAULT_PROCESS_STRING_SCAN_HIT_LIMIT
}

fn default_process_string_result_limit() -> usize {
    DEFAULT_PROCESS_STRING_RESULT_LIMIT
}

fn default_process_string_process_limit() -> usize {
    DEFAULT_PROCESS_STRING_PROCESS_LIMIT
}

fn default_process_string_mapping_limit() -> usize {
    DEFAULT_PROCESS_STRING_MAPPING_LIMIT
}

fn default_process_string_reverse_entry_limit() -> usize {
    DEFAULT_PROCESS_STRING_REVERSE_ENTRY_LIMIT
}

fn default_process_string_reverse_alias_limit() -> usize {
    DEFAULT_PROCESS_STRING_REVERSE_ALIAS_LIMIT
}

fn default_process_string_chunk_bytes() -> usize {
    DEFAULT_PROCESS_STRING_CHUNK_BYTES
}

fn default_process_string_context_bytes() -> usize {
    DEFAULT_PROCESS_STRING_CONTEXT_BYTES
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub host_api_schema_version: u32,
    pub integration_api_version: u32,
    pub request_id: Option<String>,
    pub command_id: Option<String>,
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[serde(default)]
    pub context: Box<BTreeMap<String, Value>>,
}

impl ApiError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            host_api_schema_version: HOST_API_SCHEMA_VERSION,
            integration_api_version: crate::INTEGRATION_API_VERSION,
            request_id: None,
            command_id: None,
            code: code.into(),
            message: message.into(),
            retryable: false,
            context: Box::default(),
        }
    }

    fn for_request(mut self, request_id: &str, command_id: Option<&str>) -> Self {
        self.request_id = Some(request_id.to_owned());
        self.command_id = command_id.map(str::to_owned);
        self
    }

    fn from_engine(
        error: anyhow::Error,
        fallback_code: &'static str,
        request_id: &str,
        command_id: Option<&str>,
    ) -> Self {
        let cancelled = is_cancellation_error(&error);
        let mut api_error = Self::new(
            if cancelled {
                ERROR_TASK_CANCELLED
            } else {
                fallback_code
            },
            format!("{error:#}"),
        )
        .for_request(request_id, command_id);
        api_error.retryable = cancelled;
        api_error
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressState {
    Started,
    Running,
    Completed,
    Cancelled,
    Failed,
}

impl ProgressState {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressUnit {
    Stages,
    Items,
    Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressEvent {
    pub host_api_schema_version: u32,
    pub integration_api_version: u32,
    pub request_id: String,
    pub command_id: String,
    pub phase: String,
    pub unit: ProgressUnit,
    pub current: u64,
    pub total: Option<u64>,
    pub state: ProgressState,
}

pub trait ProgressSink: Send + Sync + 'static {
    fn emit(&self, event: ProgressEvent);
}

impl<F> ProgressSink for F
where
    F: Fn(ProgressEvent) + Send + Sync + 'static,
{
    fn emit(&self, event: ProgressEvent) {
        self(event);
    }
}

/// Per-request execution resources. Unlike the legacy CLI observer, this sink
/// is not process-global and can safely carry multiple LovelyMem request IDs.
#[derive(Clone, Default)]
pub struct ExecutionContext {
    cancellation: CancellationToken,
    progress: Option<Arc<dyn ProgressSink>>,
}

impl ExecutionContext {
    pub fn new(cancellation: CancellationToken) -> Self {
        Self {
            cancellation,
            progress: None,
        }
    }

    pub fn with_progress(mut self, progress: Arc<dyn ProgressSink>) -> Self {
        self.progress = Some(progress);
        self
    }

    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    fn emit(&self, event: ProgressEvent) {
        if let Some(progress) = &self.progress {
            progress.emit(event);
        }
    }
}

struct RequestProgress {
    context: ExecutionContext,
    request_id: String,
    command_id: String,
    terminal: bool,
}

impl RequestProgress {
    fn start(context: &ExecutionContext, request_id: &str, command_id: &str, total: u64) -> Self {
        let progress = Self {
            context: context.clone(),
            request_id: request_id.to_owned(),
            command_id: command_id.to_owned(),
            terminal: false,
        };
        progress.emit("starting", 0, Some(total), ProgressState::Started);
        progress
    }

    fn running(&self, phase: &str, current: u64, total: u64) {
        self.emit(phase, current, Some(total), ProgressState::Running);
    }

    fn finish(mut self, phase: &str, current: u64, total: u64, state: ProgressState) {
        debug_assert!(state.is_terminal());
        // Mark the request terminal before calling host code. If a sink panics,
        // Drop must not attempt a second callback while unwinding.
        self.terminal = true;
        self.emit(phase, current, Some(total), state);
    }

    fn emit(&self, phase: &str, current: u64, total: Option<u64>, state: ProgressState) {
        self.context.emit(ProgressEvent {
            host_api_schema_version: HOST_API_SCHEMA_VERSION,
            integration_api_version: crate::INTEGRATION_API_VERSION,
            request_id: self.request_id.clone(),
            command_id: self.command_id.clone(),
            phase: phase.to_owned(),
            unit: ProgressUnit::Stages,
            current,
            total,
            state,
        });
    }
}

impl Drop for RequestProgress {
    fn drop(&mut self) {
        if !self.terminal {
            self.emit("aborted", 0, None, ProgressState::Failed);
            self.terminal = true;
        }
    }
}

/// Reusable Windows analysis session owned by a host application.
pub struct Session {
    inner: AnalysisSession,
    source_identity: SourceIdentity,
}

impl Session {
    pub fn open(
        request: OpenSessionRequest,
        context: &ExecutionContext,
    ) -> ApiResult<(Self, OpenSessionResponse)> {
        validate_api_version(
            request.integration_api_version,
            Some(&request.request_id),
            None,
        )?;
        validate_request_id(&request.request_id, None)?;
        if request.platform == PlatformHint::Linux {
            return Err(ApiError::new(
                ERROR_PLATFORM_MISMATCH,
                "host API v1 opens Windows sessions; Linux host sessions are not yet exposed",
            )
            .for_request(&request.request_id, Some("session.open")));
        }
        if request.symbols.profile_path.is_some() && request.symbols.pdb_path.is_some() {
            return Err(ApiError::new(
                ERROR_REQUEST_INVALID,
                "profile_path and pdb_path cannot be supplied together",
            )
            .for_request(&request.request_id, Some("session.open")));
        }
        if request.image.decode_cache_bytes == 0 {
            return Err(ApiError::new(
                ERROR_REQUEST_INVALID,
                "image.decode_cache_bytes must be greater than zero",
            )
            .for_request(&request.request_id, Some("session.open")));
        }

        let progress = RequestProgress::start(context, &request.request_id, "session.open", 3);
        let result = open_windows_session(&request, context, &progress);
        match result {
            Ok((session, response)) => {
                progress.finish("completed", 3, 3, ProgressState::Completed);
                Ok((session, response))
            }
            Err(error) => {
                let api_error = ApiError::from_engine(
                    error,
                    ERROR_SESSION_OPEN_FAILED,
                    &request.request_id,
                    Some("session.open"),
                );
                let state = if api_error.code == ERROR_TASK_CANCELLED {
                    ProgressState::Cancelled
                } else {
                    ProgressState::Failed
                };
                progress.finish("failed", 0, 3, state);
                Err(api_error)
            }
        }
    }

    pub fn run(&self, request: RunRequest, context: &ExecutionContext) -> ApiResult<RunResponse> {
        validate_api_version(
            request.integration_api_version,
            Some(&request.request_id),
            Some(&request.command_id),
        )?;
        validate_request_id(&request.request_id, Some(&request.command_id))?;
        let command = classify_host_command(&request.command_id, &request.request_id)?;
        validate_host_arguments(command, &request.arguments).map_err(|error| {
            ApiError::new(
                ERROR_REQUEST_INVALID,
                format!("invalid arguments for {}: {error:#}", request.command_id),
            )
            .for_request(&request.request_id, Some(&request.command_id))
        })?;
        let progress = RequestProgress::start(context, &request.request_id, &request.command_id, 2);
        let result = self.run_inner(&request, command, context, &progress);
        match result {
            Ok(response) => {
                progress.finish("completed", 2, 2, ProgressState::Completed);
                Ok(response)
            }
            Err(error) => {
                let api_error = ApiError::from_engine(
                    error,
                    ERROR_ANALYSIS_FAILED,
                    &request.request_id,
                    Some(&request.command_id),
                );
                let state = if api_error.code == ERROR_TASK_CANCELLED {
                    ProgressState::Cancelled
                } else {
                    ProgressState::Failed
                };
                progress.finish("failed", 0, 2, state);
                Err(api_error)
            }
        }
    }

    pub fn platform(&self) -> ApiPlatform {
        ApiPlatform::Windows
    }

    pub fn source_identity(&self) -> &SourceIdentity {
        &self.source_identity
    }

    fn run_inner(
        &self,
        request: &RunRequest,
        command: HostCommand,
        context: &ExecutionContext,
        progress: &RequestProgress,
    ) -> AnyResult<RunResponse> {
        context.cancellation.check_cancelled()?;
        progress.running("analysis", 0, 2);
        let (report, configured_limits) = match command {
            HostCommand::ProcessString => {
                let arguments = serde_json::from_value::<ProcessStringArguments>(Value::Object(
                    request.arguments.clone(),
                ))
                .context("invalid windows.process-string arguments")?;
                let options = ProcessStringOptions {
                    query: arguments.text,
                    encoding: arguments.encoding.into(),
                    scan_hit_limit: arguments.scan_hit_limit,
                    limit: arguments.limit,
                    process_limit: arguments.process_limit,
                    mapping_limit: arguments.mapping_limit,
                    reverse_entry_limit: arguments.reverse_entry_limit,
                    reverse_alias_limit: arguments.reverse_alias_limit,
                    chunk_size: arguments.chunk_bytes,
                    context_bytes: arguments.context_bytes,
                };
                let report = serde_json::to_value(
                    self.inner
                        .process_string_cancellable(&options, &context.cancellation)?,
                )?;
                (report, Vec::new())
            }
            HostCommand::Readable => {
                let arguments = serde_json::from_value::<ReadableCommandArguments>(Value::Object(
                    request.arguments.clone(),
                ))
                .context("invalid readable-plugin arguments")?;
                validate_readable_arguments(&arguments)?;
                let options = DatabaseCollectionOptions {
                    database: PathBuf::new(),
                    session: SessionOptions::default(),
                    result_limit: arguments.result_limit,
                    file_scan_limit: arguments.file_scan_limit,
                    process_space_limit: arguments.process_space_limit,
                    max_data_size: arguments.max_data_size,
                };
                let configured_limits = readable_configured_limits(&arguments);
                let report = run_readable_plugin_cancellable(
                    &self.inner,
                    &options,
                    &request.command_id,
                    &context.cancellation,
                )?
                .value;
                (report, configured_limits)
            }
        };
        context.cancellation.check_cancelled()?;
        progress.running("evidence_envelope", 1, 2);
        let envelope = envelope_from_value(
            &request.command_id,
            self.source_identity.clone(),
            report,
            configured_limits,
        )?;
        context.cancellation.check_cancelled()?;
        Ok(RunResponse {
            host_api_schema_version: HOST_API_SCHEMA_VERSION,
            integration_api_version: crate::INTEGRATION_API_VERSION,
            request_id: request.request_id.clone(),
            command_id: request.command_id.clone(),
            envelope,
            artifacts: Vec::new(),
        })
    }
}

fn open_windows_session(
    request: &OpenSessionRequest,
    context: &ExecutionContext,
    progress: &RequestProgress,
) -> AnyResult<(Session, OpenSessionResponse)> {
    context.cancellation.check_cancelled()?;
    let cache_root = request
        .symbols
        .cache_root
        .clone()
        .unwrap_or_else(default_symbol_cache);
    let mut symbol_store = SymbolStore::new(cache_root);
    for root in &request.symbols.search_roots {
        symbol_store.add_search_root(root.clone());
    }
    let options = SessionOptions {
        image_options: ImageOpenOptions {
            metadata_path: request.image.metadata_path.clone(),
            auto_discover_sidecars: request.image.auto_discover_sidecars,
            decode_cache_bytes: request.image.decode_cache_bytes,
            qevm_layout: request.image.qevm_layout.clone().map(Into::into),
        },
        profile: request.symbols.profile_path.clone(),
        pdb: request.symbols.pdb_path.clone(),
        symbol_store,
        allow_compatible_local_symbols: request.symbols.allow_compatible_local_symbols,
    };
    progress.running("session_bootstrap", 1, 3);
    let inner =
        AnalysisSession::open_cancellable(&request.image_path, options, &context.cancellation)?;
    progress.running("source_identity", 2, 3);
    let mut source_identity =
        source_identity_for_memory_image(inner.image().path(), inner.image())?;
    if let Some(mut symbol_identity) = windows_symbol_identity(inner.profile())? {
        symbol_identity.details.insert(
            "layout_exactness".to_owned(),
            Value::String(
                match inner.symbol_layout_exactness() {
                    SymbolLayoutExactness::Exact => "exact",
                    SymbolLayoutExactness::CompatibleLocal => "compatible_local",
                }
                .to_owned(),
            ),
        );
        source_identity.symbol_identity = Some(symbol_identity);
    }
    context.cancellation.check_cancelled()?;
    let warnings = inner
        .warnings()
        .iter()
        .map(|message| {
            EvidenceWarning::new(
                "session.warning",
                EvidenceWarningSeverity::Warning,
                message.clone(),
                "session.open",
            )
        })
        .collect::<Vec<_>>();
    let response = OpenSessionResponse {
        host_api_schema_version: HOST_API_SCHEMA_VERSION,
        integration_api_version: crate::INTEGRATION_API_VERSION,
        platform: ApiPlatform::Windows,
        source_identity: source_identity.clone(),
        warnings,
    };
    Ok((
        Session {
            inner,
            source_identity,
        },
        response,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostCommand {
    Readable,
    ProcessString,
}

fn classify_host_command(command_id: &str, request_id: &str) -> ApiResult<HostCommand> {
    let registry = command_catalog()?;
    if registry.by_id(command_id).is_none() {
        return Err(ApiError::new(
            ERROR_COMMAND_UNKNOWN,
            format!("unknown stable command ID: {command_id}"),
        )
        .for_request(request_id, Some(command_id)));
    }
    if command_id == "windows.process-string" {
        return Ok(HostCommand::ProcessString);
    }
    match readable_plugin_catalog()
        .into_iter()
        .find(|descriptor| descriptor.name == command_id)
    {
        Some(descriptor) if descriptor.platform == ReadablePluginPlatform::Windows => {
            Ok(HostCommand::Readable)
        }
        Some(_) => Err(ApiError::new(
            ERROR_PLATFORM_MISMATCH,
            format!("command {command_id} requires a non-Windows session"),
        )
        .for_request(request_id, Some(command_id))),
        None => Err(ApiError::new(
            ERROR_COMMAND_UNSUPPORTED,
            format!("command {command_id} has no host runner in API schema v1"),
        )
        .for_request(request_id, Some(command_id))),
    }
}

fn validate_api_version(
    actual: u32,
    request_id: Option<&str>,
    command_id: Option<&str>,
) -> ApiResult<()> {
    if actual == crate::INTEGRATION_API_VERSION {
        return Ok(());
    }
    let mut error = ApiError::new(
        ERROR_API_VERSION_MISMATCH,
        format!(
            "integration API version {actual} is incompatible with engine version {}",
            crate::INTEGRATION_API_VERSION
        ),
    );
    error.request_id = request_id.map(str::to_owned);
    error.command_id = command_id.map(str::to_owned);
    error.context.insert(
        "expected".to_owned(),
        Value::from(crate::INTEGRATION_API_VERSION),
    );
    error
        .context
        .insert("actual".to_owned(), Value::from(actual));
    Err(error)
}

fn validate_request_id(request_id: &str, command_id: Option<&str>) -> ApiResult<()> {
    if !request_id.trim().is_empty() && request_id.chars().count() <= 256 {
        return Ok(());
    }
    Err(ApiError::new(
        ERROR_REQUEST_INVALID,
        "request_id must contain 1 to 256 Unicode characters",
    )
    .for_request(request_id, command_id))
}

fn validate_readable_arguments(arguments: &ReadableCommandArguments) -> AnyResult<()> {
    if arguments.result_limit == 0
        || arguments.file_scan_limit == 0
        || arguments.process_space_limit == 0
        || arguments.max_data_size == 0
    {
        bail!("all readable-plugin limits must be greater than zero");
    }
    Ok(())
}

fn readable_configured_limits(arguments: &ReadableCommandArguments) -> Vec<EvidenceLimit> {
    [
        ("limit", EvidenceLimitKind::Output, arguments.result_limit),
        (
            "file_scan_limit",
            EvidenceLimitKind::SourceScan,
            arguments.file_scan_limit,
        ),
        (
            "process_space_limit",
            EvidenceLimitKind::SourceScan,
            arguments.process_space_limit,
        ),
        (
            "max_data_size",
            EvidenceLimitKind::Bytes,
            arguments.max_data_size,
        ),
    ]
    .into_iter()
    .map(|(name, kind, configured)| EvidenceLimit {
        name: name.to_owned(),
        kind,
        configured: u64::try_from(configured).ok(),
        observed: None,
        reached: None,
    })
    .collect()
}

fn validate_host_arguments(command: HostCommand, arguments: &Map<String, Value>) -> AnyResult<()> {
    match command {
        HostCommand::Readable => {
            validate_readable_arguments(&serde_json::from_value::<ReadableCommandArguments>(
                Value::Object(arguments.clone()),
            )?)
        }
        HostCommand::ProcessString => {
            let arguments =
                serde_json::from_value::<ProcessStringArguments>(Value::Object(arguments.clone()))?;
            if arguments.text.is_empty() {
                bail!("text must not be empty");
            }
            if arguments.text.len() > 1024 * 1024 {
                bail!("text exceeds the 1 MiB UTF-8 limit");
            }
            if arguments.scan_hit_limit == 0
                || arguments.limit == 0
                || arguments.process_limit == 0
                || arguments.mapping_limit == 0
                || arguments.reverse_entry_limit == 0
                || arguments.reverse_alias_limit == 0
            {
                bail!("all process-string limits must be greater than zero");
            }
            if arguments.reverse_entry_limit > MAX_PROCESS_STRING_REVERSE_ENTRY_LIMIT {
                bail!("reverse_entry_limit exceeds {MAX_PROCESS_STRING_REVERSE_ENTRY_LIMIT}");
            }
            if arguments.reverse_alias_limit > MAX_PROCESS_STRING_REVERSE_ALIAS_LIMIT {
                bail!("reverse_alias_limit exceeds {MAX_PROCESS_STRING_REVERSE_ALIAS_LIMIT}");
            }
            if arguments.context_bytes > 4096 {
                bail!("context_bytes exceeds 4096");
            }
            let longest = arguments
                .text
                .encode_utf16()
                .count()
                .checked_mul(2)
                .context("UTF-16LE query length overflow")?
                .max(arguments.text.len());
            if arguments.chunk_bytes < longest {
                bail!("chunk_bytes is smaller than the encoded query");
            }
            Ok(())
        }
    }
}

fn envelope_from_value(
    command_id: &str,
    source_identity: SourceIdentity,
    report: Value,
    mut configured_limits: Vec<EvidenceLimit>,
) -> AnyResult<EvidenceEnvelope<Value>> {
    let root = report
        .as_object()
        .context("plugin report must serialize as a JSON object")?;
    let available = optional_boolean(root, "available")?.unwrap_or(true);
    let declared_complete = optional_boolean(root, "complete")?;
    let complete = available && declared_complete.unwrap_or(false);
    let mut warnings = normalize_legacy_warnings(root.get("warnings"), command_id)?;
    if declared_complete.is_none() {
        warnings.push(EvidenceWarning::new(
            "contract.completeness_unknown",
            EvidenceWarningSeverity::Warning,
            "plugin report did not declare search-universe completeness; host API uses complete=false",
            command_id,
        ));
    }
    let scope = deserialize_optional(root, "scope")?.unwrap_or_else(|| {
        let mut scope = EvidenceScope::new("memory_image");
        scope.constraints.insert(
            "command_id".to_owned(),
            Value::String(command_id.to_owned()),
        );
        scope
    });
    let reported_limits =
        deserialize_optional::<Vec<EvidenceLimit>>(root, "limits")?.unwrap_or_default();
    for mut reported in reported_limits {
        if let Some(existing) = configured_limits
            .iter_mut()
            .find(|limit| limit.name == reported.name && limit.kind == reported.kind)
        {
            if reported.configured.is_none() {
                reported.configured = existing.configured;
            }
            *existing = reported;
        } else {
            configured_limits.push(reported);
        }
    }
    configured_limits.sort_by(|left, right| {
        left.name.cmp(&right.name).then_with(|| {
            evidence_limit_kind_rank(left.kind).cmp(&evidence_limit_kind_rank(right.kind))
        })
    });
    let missing_ranges =
        deserialize_optional::<Vec<MissingRange>>(root, "missing_ranges")?.unwrap_or_default();
    let raw_evidence =
        deserialize_optional::<RawEvidenceSummary>(root, "raw_evidence")?.unwrap_or_default();
    EvidenceEnvelope::from_parts(
        command_id,
        EngineIdentity::new(
            crate::VERSION,
            crate::BUILD_ID,
            crate::INTEGRATION_API_VERSION,
        ),
        source_identity,
        available,
        complete,
        scope,
        warnings,
        configured_limits,
        missing_ranges,
        raw_evidence,
        report,
    )
}

fn evidence_limit_kind_rank(kind: EvidenceLimitKind) -> u8 {
    match kind {
        EvidenceLimitKind::SourceScan => 0,
        EvidenceLimitKind::Output => 1,
        EvidenceLimitKind::Bytes => 2,
    }
}

fn optional_boolean(root: &Map<String, Value>, field: &str) -> AnyResult<Option<bool>> {
    match root.get(field) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => bail!("plugin report field {field} must be boolean"),
    }
}

fn deserialize_optional<T>(root: &Map<String, Value>, field: &str) -> AnyResult<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    root.get(field)
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .with_context(|| format!("plugin report field {field} has an invalid shape"))
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::sync::Mutex;

    use serde::de::DeserializeOwned;
    use serde_json::json;

    use super::*;
    use crate::evidence::{DigestReference, RawEvidenceStorage};

    fn synthetic_source() -> SourceIdentity {
        SourceIdentity {
            format: "synthetic".to_owned(),
            size: 0,
            mtime: None,
            sample_digest: DigestReference::new("sha256", "00"),
            symbol_identity: None,
            components: Vec::new(),
            physical_layout: None,
        }
    }

    fn assert_json_round_trip<T>(value: T)
    where
        T: Clone + Debug + PartialEq + Serialize + DeserializeOwned,
    {
        let encoded = serde_json::to_vec(&value).unwrap();
        assert_eq!(serde_json::from_slice::<T>(&encoded).unwrap(), value);
    }

    #[test]
    fn capabilities_are_a_no_io_compatibility_handshake() {
        let capabilities = capabilities();
        assert_eq!(capabilities.host_api_schema_version, 1);
        assert_eq!(
            capabilities.integration_api_version,
            crate::INTEGRATION_API_VERSION
        );
        assert_eq!(
            capabilities.registered_command_count,
            command_catalog().unwrap().len()
        );
        assert!(
            capabilities
                .runnable_command_ids
                .contains(&"pslist".to_owned())
        );
        assert!(
            capabilities
                .runnable_command_ids
                .contains(&"windows.process-string".to_owned())
        );
    }

    #[test]
    fn open_request_round_trips_and_rejects_unknown_fields() {
        let request = OpenSessionRequest {
            integration_api_version: crate::INTEGRATION_API_VERSION,
            request_id: "open-1".to_owned(),
            image_path: PathBuf::from("memory.raw"),
            platform: PlatformHint::Windows,
            image: HostImageOptions::default(),
            symbols: HostSymbolOptions::default(),
        };
        let encoded = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<OpenSessionRequest>(&encoded).unwrap(),
            request
        );
        let invalid = json!({
            "integration_api_version": crate::INTEGRATION_API_VERSION,
            "request_id": "open-1",
            "image_path": "memory.raw",
            "unexpected": true
        });
        assert!(serde_json::from_value::<OpenSessionRequest>(invalid).is_err());
        assert!(validate_request_id(&"测".repeat(256), None).is_ok());
        assert!(validate_request_id(&"测".repeat(257), None).is_err());
    }

    #[test]
    fn every_host_message_dto_round_trips_as_json() {
        assert_json_round_trip(capabilities());
        assert_json_round_trip(OpenSessionResponse {
            host_api_schema_version: HOST_API_SCHEMA_VERSION,
            integration_api_version: crate::INTEGRATION_API_VERSION,
            platform: ApiPlatform::Windows,
            source_identity: synthetic_source(),
            warnings: Vec::new(),
        });
        let run_request = RunRequest {
            integration_api_version: crate::INTEGRATION_API_VERSION,
            request_id: "run-round-trip".to_owned(),
            command_id: "pslist".to_owned(),
            arguments: Map::new(),
        };
        assert_json_round_trip(run_request.clone());
        let envelope = envelope_from_value(
            "pslist",
            synthetic_source(),
            json!({"available": true, "complete": true, "warnings": []}),
            Vec::new(),
        )
        .unwrap();
        assert_json_round_trip(RunResponse {
            host_api_schema_version: HOST_API_SCHEMA_VERSION,
            integration_api_version: crate::INTEGRATION_API_VERSION,
            request_id: run_request.request_id,
            command_id: run_request.command_id,
            envelope,
            artifacts: vec![ArtifactReference {
                role: "report".to_owned(),
                path: PathBuf::from("report.json"),
                media_type: Some("application/json".to_owned()),
                size: Some(1),
                sha256: Some("0".repeat(64)),
                partial: false,
            }],
        });
        assert_json_round_trip(ApiError::new(ERROR_ANALYSIS_FAILED, "synthetic failure"));
        assert_json_round_trip(ProgressEvent {
            host_api_schema_version: HOST_API_SCHEMA_VERSION,
            integration_api_version: crate::INTEGRATION_API_VERSION,
            request_id: "progress-round-trip".to_owned(),
            command_id: "pslist".to_owned(),
            phase: "analysis".to_owned(),
            unit: ProgressUnit::Items,
            current: 1,
            total: Some(2),
            state: ProgressState::Running,
        });
    }

    #[test]
    fn version_mismatch_fails_before_path_io_or_progress() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let context = ExecutionContext::default().with_progress(Arc::new(move |event| {
            captured.lock().unwrap().push(event);
        }));
        let request = OpenSessionRequest {
            integration_api_version: crate::INTEGRATION_API_VERSION + 1,
            request_id: "wrong-version".to_owned(),
            image_path: PathBuf::from("this-file-must-not-be-opened.mem"),
            platform: PlatformHint::Auto,
            image: HostImageOptions::default(),
            symbols: HostSymbolOptions::default(),
        };
        let error = match Session::open(request, &context) {
            Ok(_) => panic!("version mismatch must fail before opening a session"),
            Err(error) => error,
        };
        assert_eq!(error.code, ERROR_API_VERSION_MISMATCH);
        assert!(events.lock().unwrap().is_empty());
    }

    #[test]
    fn command_classification_distinguishes_unknown_and_unsupported() {
        let unknown = classify_host_command("not-a-command", "r1").unwrap_err();
        assert_eq!(unknown.code, ERROR_COMMAND_UNKNOWN);
        let unsupported = classify_host_command("dumpfile", "r2").unwrap_err();
        assert_eq!(unsupported.code, ERROR_COMMAND_UNSUPPORTED);
    }

    #[test]
    fn unavailable_evidence_is_a_successful_envelope_state() {
        let envelope = envelope_from_value(
            "pslist",
            synthetic_source(),
            json!({
                "available": false,
                "complete": false,
                "scope": {"kind": "active_process_list", "description": null, "constraints": {}},
                "warnings": [],
                "limits": [{
                    "name": "limit",
                    "kind": "output",
                    "configured": null,
                    "observed": 0,
                    "reached": false
                }],
                "missing_ranges": []
            }),
            readable_configured_limits(&ReadableCommandArguments::default()),
        )
        .unwrap();
        assert!(!envelope.available);
        assert!(!envelope.complete);
        assert_eq!(envelope.raw_evidence.storage, RawEvidenceStorage::None);
        let limit = envelope
            .limits
            .iter()
            .find(|limit| limit.name == "limit")
            .unwrap();
        assert_eq!(limit.configured, Some(DEFAULT_RESULT_LIMIT as u64));
        assert_eq!(limit.observed, Some(0));
        assert_eq!(limit.reached, Some(false));
        envelope.validate().unwrap();
    }

    #[test]
    fn progress_is_request_scoped_and_has_one_terminal_event() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);
        let context = ExecutionContext::default().with_progress(Arc::new(move |event| {
            captured.lock().unwrap().push(event);
        }));
        let first = RequestProgress::start(&context, "request-a", "pslist", 2);
        first.running("analysis", 1, 2);
        first.finish("completed", 2, 2, ProgressState::Completed);
        let second = RequestProgress::start(&context, "request-b", "windows.process-string", 2);
        second.finish("cancelled", 0, 2, ProgressState::Cancelled);

        let events = events.lock().unwrap();
        for request_id in ["request-a", "request-b"] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.request_id == request_id && event.state.is_terminal())
                    .count(),
                1
            );
        }
        assert!(events.iter().all(|event| {
            (event.request_id == "request-a" && event.command_id == "pslist")
                || (event.request_id == "request-b" && event.command_id == "windows.process-string")
        }));
    }

    #[test]
    fn host_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Session>();
        assert_send_sync::<ExecutionContext>();
        assert_send_sync::<CancellationToken>();
    }
}
