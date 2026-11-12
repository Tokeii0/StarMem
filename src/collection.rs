use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::{Value, json, to_value};

use crate::acquisition::{AcquisitionInfoOptions, analyze_acquisition_info};
use crate::browser_artifacts::{
    BrowserArtifactOptions, parse_browser_history_artifacts_from_file_scan,
};
use crate::browser_session::BrowserSessionOptions;
use crate::cancellation::{CancellationToken, is_cancellation_error};
use crate::clipboard::{ClipboardScanOptions, ResidualScanOptions};
use crate::cobaltstrike::CobaltStrikeScanOptions;
use crate::command_registry::{CollectDisposition, CommandRegistry};
use crate::cookies::CookieScanOptions;
use crate::database::{
    AnalysisIdentity, DatabaseCollectionReport, PluginOutcome, SqliteReportStore,
};
use crate::dns_scan::DnsScanOptions;
use crate::downloads::scan_download_traces;
use crate::evidence::{
    DigestReference, EngineIdentity, EvidenceEnvelope, EvidenceLimit, EvidenceLimitKind,
    EvidenceScope, EvidenceWarning, EvidenceWarningSeverity, MissingRange, RawEvidenceReference,
    RawEvidenceStorage, RawEvidenceSummary, SourceIdentity, SymbolIdentity,
    normalize_legacy_warnings, source_identity_for_memory_image, windows_symbol_identity,
};
use crate::image::{ImageFormat, MemoryImage};
use crate::linux::{
    LinuxKernelSessionOptions, OpenedLinuxKernelSession, discover_linux_banners,
    open_linux_kernel_session,
};
use crate::linux_kernel_plugins::{
    LinuxCheckSyscallOptions, LinuxKernelSession, LinuxKmsgOptions, LinuxMountInfoOptions,
    linux_check_syscall, linux_kallsyms, linux_kmsg, linux_lsmod, linux_modxview, linux_mountinfo,
};
use crate::linux_symbols::{LinuxSymbolFeature, LinuxSymbolIdentity};
use crate::output_policy::ProtectedInput;
use crate::packet_scan::PacketScanOptions;
use crate::raw_objects::extract_raw_objects;
use crate::session::{AnalysisSession, SessionOptions};
use crate::system::registry::analyze_registry_with_system_hive;
use crate::system::{analyze_system_artifacts, analyze_system_info_quick};
use crate::terminal_history::TerminalHistoryOptions;
use crate::wechat::WechatScanOptions;
use crate::windows::autorun_plugins::AutorunOptions;
use crate::windows::check_pslist::CheckPslistOptions;
use crate::windows::disk_plugins::MftView;
use crate::windows::injected_regions::InjectedRegionOptions;
use crate::windows::mailslot_plugins::MailslotOptions;
use crate::windows::malware_plugins::ProcessImageView;
use crate::windows::open_files::{OpenFileOptions, scan_open_files};
use crate::windows::pe_plugins::PeSymbolSource;
use crate::windows::pipe_plugins::PipeScanOptions;
use crate::windows::prefetch_plugins::PrefetchScanOptions;
use crate::windows::service_plugins::ServiceView;
use crate::windows::syscall_plugins::SyscallView;
use crate::windows::usb_history::{
    USB_HISTORY_WARNING_LIMIT, UsbHistoryOptions, analyze_usb_history,
};
use crate::windows_execution::{WindowsExecutionOptions, analyze_windows_execution};
use crate::windows_recent_files::{WindowsRecentFilesOptions, analyze_windows_recent_files};
use crate::windows_timeline::{WindowsTimelineOptions, analyze_windows_timeline};

type WindowsPluginRunner = fn(&AnalysisSession, &DatabaseCollectionOptions) -> Result<Value>;
type LinuxPluginRunner = fn(&LinuxKernelSession, &DatabaseCollectionOptions) -> Result<Value>;

#[derive(Clone, Copy)]
enum PluginRunner {
    Windows(WindowsPluginRunner),
    Linux(LinuxPluginRunner),
}

#[derive(Debug, Clone)]
pub struct DatabaseCollectionOptions {
    pub database: PathBuf,
    pub session: SessionOptions,
    pub result_limit: usize,
    pub file_scan_limit: usize,
    pub process_space_limit: usize,
    pub max_data_size: usize,
}

#[derive(Debug, Clone)]
pub enum DatabaseCollectionEvent {
    Opening,
    Started {
        index: usize,
        total: usize,
        plugin: &'static str,
        display_name: &'static str,
    },
    Finished {
        index: usize,
        total: usize,
        plugin: &'static str,
        display_name: &'static str,
        outcome: PluginOutcome,
    },
}

#[derive(Clone, Copy)]
struct PluginSpec {
    name: &'static str,
    display_name: &'static str,
    category: &'static str,
    runner: PluginRunner,
}

enum CollectionRuntime {
    Windows(Box<AnalysisSession>),
    Linux {
        opened: Option<Box<OpenedLinuxKernelSession>>,
        open_error: Option<String>,
    },
}

/// 命令在无参数 SQLite 自动采集中的处理方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionPluginDisposition {
    Runnable,
    Skipped,
}

/// `collect` 对一个 CLI 取证命令的完整目录记录。
#[derive(Debug, Clone, Copy, Serialize)]
pub struct CollectionPluginDescriptor {
    pub name: &'static str,
    pub display_name: &'static str,
    pub category: &'static str,
    pub disposition: CollectionPluginDisposition,
    pub reason: Option<&'static str>,
}

/// LovelyMem.Luxe 等宿主可以复用的只读插件描述。
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ReadablePluginDescriptor {
    pub name: &'static str,
    pub display_name: &'static str,
    pub category: &'static str,
    pub platform: ReadablePluginPlatform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadablePluginPlatform {
    Windows,
    Linux,
}

/// 需要额外输入或输出目标的 StarMem 命令描述。它们不能加入 `--db` 的无参数收集，
/// 但宿主可以用同一份目录在界面中渲染参数框并调用对应入口。
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ParameterizedPluginDescriptor {
    pub name: &'static str,
    pub display_name: &'static str,
    pub category: &'static str,
    pub reason: &'static str,
}

/// 单个只读插件执行结果。
#[derive(Debug)]
pub struct ReadablePluginReport {
    pub descriptor: ReadablePluginDescriptor,
    pub value: Value,
}

#[derive(Clone, Copy)]
struct SkippedPlugin {
    name: &'static str,
    display_name: &'static str,
    category: &'static str,
    reason: &'static str,
}

pub fn collect_to_sqlite<F>(
    image_path: &Path,
    options: &DatabaseCollectionOptions,
    progress: F,
) -> Result<DatabaseCollectionReport>
where
    F: FnMut(DatabaseCollectionEvent),
{
    collect_to_sqlite_cancellable(image_path, options, &CancellationToken::new(), progress)
}

/// Collects the complete readable-plugin catalog while honoring a host-owned
/// cooperative cancellation token. Completed plugin rows remain committed;
/// the analysis row is finalized with status `cancelled` before this function
/// returns [`crate::cancellation::CancellationError`].
pub fn collect_to_sqlite_cancellable<F>(
    image_path: &Path,
    options: &DatabaseCollectionOptions,
    cancellation: &CancellationToken,
    mut progress: F,
) -> Result<DatabaseCollectionReport>
where
    F: FnMut(DatabaseCollectionEvent),
{
    cancellation.check_cancelled()?;
    progress(DatabaseCollectionEvent::Opening);
    cancellation.check_cancelled()?;
    let image = MemoryImage::open_with_options(image_path, options.session.image_options.clone())?;
    cancellation.check_cancelled()?;
    let runnable = runnable_plugins();
    let skipped = skipped_plugins();
    let total = runnable.len() + skipped.len();
    let image_format = serde_json::to_string(image.format())?;
    let mut source_identity = source_identity_for_memory_image(image_path, &image)?;
    let linux_candidate = has_linux_collection_evidence(&image);
    let runtime = if linux_candidate {
        let opened = open_linux_kernel_session(
            image.clone(),
            &options.session.symbol_store,
            [
                LinuxSymbolFeature::Modules,
                LinuxSymbolFeature::Mount,
                LinuxSymbolFeature::Kallsyms,
                LinuxSymbolFeature::Kmsg,
                LinuxSymbolFeature::Hooks,
            ],
            LinuxKernelSessionOptions::default(),
        );
        match opened {
            Ok(opened) => {
                source_identity.symbol_identity = Some(linux_collection_symbol_identity(
                    &opened.evidence.symbol_identity,
                ));
                CollectionRuntime::Linux {
                    opened: Some(Box::new(opened)),
                    open_error: None,
                }
            }
            Err(linux_error) if !matches!(image.format(), ImageFormat::Lime { .. }) => {
                // A complete Linux banner is strong triage evidence, but it can occur as a
                // resident string inside an otherwise valid Windows RAW/VMEM capture.  When the
                // Linux kernel-global bootstrap does not validate, a successfully validated
                // Windows kernel wins.  If neither bootstrap validates, retain the positive
                // Linux banner as an unavailable Linux evidence source instead of reporting a
                // misleading Windows initialization error.
                match AnalysisSession::from_image_cancellable(
                    image.clone(),
                    options.session.clone(),
                    cancellation,
                ) {
                    Ok(session) => {
                        source_identity.symbol_identity =
                            windows_symbol_identity(session.profile())?;
                        CollectionRuntime::Windows(Box::new(session))
                    }
                    Err(windows_error) => CollectionRuntime::Linux {
                        opened: None,
                        open_error: Some(format!(
                            "Linux kernel-global 验证失败：{linux_error:#}；Windows 内核验证也失败：{windows_error:#}"
                        )),
                    },
                }
            }
            Err(error) => CollectionRuntime::Linux {
                opened: None,
                open_error: Some(format!("{error:#}")),
            },
        }
    } else {
        let session = AnalysisSession::from_image_cancellable(
            image.clone(),
            options.session.clone(),
            cancellation,
        )?;
        source_identity.symbol_identity = windows_symbol_identity(session.profile())?;
        CollectionRuntime::Windows(Box::new(session))
    };
    cancellation.check_cancelled()?;
    let identity = AnalysisIdentity::current(
        image_path,
        serde_json::to_string(&json!({
            "result_limit": options.result_limit,
            "file_scan_limit": options.file_scan_limit,
            "process_space_limit": options.process_space_limit,
            "max_data_size": options.max_data_size,
            "plugins_total": total,
        }))?,
    )?;
    let mut protected_inputs = image
        .sources()
        .enumerate()
        .map(|(index, source)| {
            ProtectedInput::file(format!("memory_image.source[{index}]"), source.path.clone())
        })
        .collect::<Vec<_>>();
    if let Some(profile) = &options.session.profile {
        protected_inputs.push(ProtectedInput::file("profile", profile.clone()));
    }
    if let Some(pdb) = &options.session.pdb {
        protected_inputs.push(ProtectedInput::file("pdb", pdb.clone()));
    }
    protected_inputs.extend(
        options
            .session
            .symbol_store
            .search_roots()
            .iter()
            .enumerate()
            .map(|(index, root)| {
                ProtectedInput::directory(format!("symbol_root[{index}]"), root.clone())
            }),
    );
    let mut store = SqliteReportStore::create_with_identity_and_inputs(
        &options.database,
        image_path,
        &image_format,
        image.file_len(),
        image.mapped_bytes(),
        &identity,
        &source_identity,
        total,
        &protected_inputs,
    )?;
    check_collection_cancellation(cancellation, &mut store)?;

    let mut index = 0usize;
    for plugin in runnable {
        check_collection_cancellation(cancellation, &mut store)?;
        index += 1;
        progress(DatabaseCollectionEvent::Started {
            index,
            total,
            plugin: plugin.name,
            display_name: plugin.display_name,
        });
        check_collection_cancellation(cancellation, &mut store)?;
        let started = Instant::now();
        let action = collection_plugin_action(&runtime, plugin, options, cancellation);
        let outcome = match action {
            CollectionPluginAction::Skipped(reason) => {
                store.record_skipped(plugin.name, plugin.display_name, plugin.category, reason)?
            }
            CollectionPluginAction::Run(result) => match result {
                Ok(report) => {
                    let envelope =
                        collection_evidence_envelope(plugin, report, &source_identity, options)?;
                    store.store_value(
                        plugin.name,
                        plugin.display_name,
                        plugin.category,
                        &envelope,
                        started.elapsed().as_secs_f64(),
                    )?
                }
                Err(error) if is_cancellation_error(&error) => {
                    check_collection_cancellation(cancellation, &mut store)?;
                    return Err(error);
                }
                Err(error) => store.record_failure(
                    plugin.name,
                    plugin.display_name,
                    plugin.category,
                    started.elapsed().as_secs_f64(),
                    &format!("{error:#}"),
                )?,
            },
        };
        progress(DatabaseCollectionEvent::Finished {
            index,
            total,
            plugin: plugin.name,
            display_name: plugin.display_name,
            outcome,
        });
        check_collection_cancellation(cancellation, &mut store)?;
    }

    for plugin in skipped {
        check_collection_cancellation(cancellation, &mut store)?;
        index += 1;
        progress(DatabaseCollectionEvent::Started {
            index,
            total,
            plugin: plugin.name,
            display_name: plugin.display_name,
        });
        check_collection_cancellation(cancellation, &mut store)?;
        let outcome = store.record_skipped(
            plugin.name,
            plugin.display_name,
            plugin.category,
            plugin.reason,
        )?;
        progress(DatabaseCollectionEvent::Finished {
            index,
            total,
            plugin: plugin.name,
            display_name: plugin.display_name,
            outcome,
        });
        check_collection_cancellation(cancellation, &mut store)?;
    }
    store.finish()
}

enum CollectionPluginAction {
    Run(Result<Value>),
    Skipped(&'static str),
}

fn has_linux_collection_evidence(image: &MemoryImage) -> bool {
    if matches!(image.format(), ImageFormat::Lime { .. }) {
        return true;
    }
    discover_linux_banners(image).is_ok()
}

fn linux_collection_symbol_identity(identity: &LinuxSymbolIdentity) -> SymbolIdentity {
    let mut converted = SymbolIdentity::new("linux_isf", identity.canonical_sha256.clone());
    converted.digest = Some(DigestReference::new("sha256", identity.isf_sha256.clone()));
    converted.details.insert(
        "schema_version".to_owned(),
        Value::from(identity.schema_version),
    );
    converted.details.insert(
        "provider".to_owned(),
        Value::String(identity.provider.clone()),
    );
    converted
        .details
        .insert("format".to_owned(), Value::String(identity.format.clone()));
    if let Some(producer) = &identity.producer {
        converted
            .details
            .insert("producer".to_owned(), Value::String(producer.clone()));
    }
    converted.details.insert(
        "banner_sha256".to_owned(),
        Value::String(identity.banner_sha256.clone()),
    );
    converted
        .details
        .insert("vmlinux_sha256".to_owned(), json!(identity.vmlinux_sha256));
    converted
        .details
        .insert("features".to_owned(), json!(identity.features));
    converted
}

fn collection_plugin_action(
    runtime: &CollectionRuntime,
    plugin: PluginSpec,
    options: &DatabaseCollectionOptions,
    cancellation: &CancellationToken,
) -> CollectionPluginAction {
    match (runtime, plugin.runner) {
        (CollectionRuntime::Windows(session), PluginRunner::Windows(_))
            if plugin.name == "crashinfo"
                && !matches!(session.image().format(), ImageFormat::WindowsCrashDump64(_)) =>
        {
            CollectionPluginAction::Skipped("当前镜像不是 Windows 崩溃转储")
        }
        (CollectionRuntime::Windows(session), PluginRunner::Windows(_)) => {
            CollectionPluginAction::Run(run_plugin_cancellable(
                plugin,
                session,
                options,
                cancellation,
            ))
        }
        (CollectionRuntime::Windows(_), PluginRunner::Linux(_)) => {
            CollectionPluginAction::Skipped("当前镜像已验证为 Windows，Linux 插件不适用")
        }
        (CollectionRuntime::Linux { .. }, PluginRunner::Windows(_)) => {
            CollectionPluginAction::Skipped("当前镜像已验证为 Linux，Windows 插件不适用")
        }
        (
            CollectionRuntime::Linux {
                opened: Some(opened),
                ..
            },
            PluginRunner::Linux(runner),
        ) => {
            let value = cancellation.check_cancelled().and_then(|()| {
                let mut value = runner(&opened.session, options)?;
                if let Some(root) = value.as_object_mut() {
                    root.insert(
                        "kernel_session".to_owned(),
                        serde_json::to_value(&opened.evidence)?,
                    );
                }
                cancellation.check_cancelled()?;
                Ok(value)
            });
            CollectionPluginAction::Run(value)
        }
        (
            CollectionRuntime::Linux {
                opened: None,
                open_error,
            },
            PluginRunner::Linux(_),
        ) => CollectionPluginAction::Run(Ok(linux_kernel_session_unavailable_report(
            plugin.name,
            open_error.as_deref().unwrap_or("未知 Linux 内核会话错误"),
        ))),
    }
}

fn linux_kernel_session_unavailable_report(plugin: &str, error: &str) -> Value {
    json!({
        "available": false,
        "complete": false,
        "scope": EvidenceScope::new("linux_kernel"),
        "warnings": [EvidenceWarning::new(
            "linux.kernel_session_unavailable",
            EvidenceWarningSeverity::Warning,
            format!("Linux kernel-global 会话不可用：{error}"),
            plugin,
        )],
        "limits": [],
        "missing_ranges": [],
        "records": [],
    })
}

fn check_collection_cancellation(
    cancellation: &CancellationToken,
    store: &mut SqliteReportStore,
) -> Result<()> {
    if let Err(error) = cancellation.check_cancelled() {
        if let Err(persist_error) = store.mark_cancelled() {
            return Err(error.context(format!(
                "无法把已取消的 StarMem 全量采集标记写入数据库：{persist_error:#}"
            )));
        }
        return Err(error);
    }
    Ok(())
}

fn collection_evidence_envelope(
    plugin: PluginSpec,
    report: Value,
    source_identity: &SourceIdentity,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    let root = report.as_object();
    let available = root
        .and_then(|object| object.get("available"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let declared_complete = root
        .and_then(|object| object.get("complete"))
        .and_then(Value::as_bool);
    let complete = available && declared_complete.unwrap_or(false);
    let mut warnings =
        normalize_legacy_warnings(root.and_then(|object| object.get("warnings")), plugin.name)?;
    if declared_complete.is_none() {
        warnings.push(EvidenceWarning::new(
            "contract.completeness_unknown",
            EvidenceWarningSeverity::Warning,
            "插件报告未声明搜索宇宙完整性，collect 按 complete=false 保存",
            plugin.name,
        ));
    }
    let missing_ranges = root
        .and_then(|object| object.get("missing_ranges"))
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<MissingRange>>(value).ok())
        .unwrap_or_default();
    let mut raw_evidence = root
        .and_then(|object| object.get("raw_evidence"))
        .cloned()
        .and_then(|value| serde_json::from_value::<RawEvidenceSummary>(value).ok())
        .unwrap_or_default();
    if matches!(raw_evidence.storage, RawEvidenceStorage::None) {
        let bundle = extract_raw_objects(plugin.name, source_identity, &report)?;
        raw_evidence = RawEvidenceSummary {
            count: bundle.objects.len() as u64,
            storage: RawEvidenceStorage::Sqlite,
            references: vec![RawEvidenceReference {
                path: Some(options.database.display().to_string()),
                hash: None,
            }],
        };
    }
    let mut scope = root
        .and_then(|object| object.get("scope"))
        .cloned()
        .and_then(|value| serde_json::from_value::<EvidenceScope>(value).ok())
        .unwrap_or_else(|| EvidenceScope::new("memory_image"));
    scope.constraints.insert(
        "category".to_owned(),
        Value::String(plugin.category.to_owned()),
    );
    let configured_limits = [
        (
            "limit",
            EvidenceLimitKind::Output,
            options.result_limit as u64,
        ),
        (
            "file_scan_limit",
            EvidenceLimitKind::SourceScan,
            options.file_scan_limit as u64,
        ),
        (
            "process_space_limit",
            EvidenceLimitKind::SourceScan,
            options.process_space_limit as u64,
        ),
        (
            "max_data_size",
            EvidenceLimitKind::Bytes,
            options.max_data_size as u64,
        ),
    ]
    .into_iter()
    .map(|(name, kind, configured)| {
        let mut limit = EvidenceLimit::new(name, kind);
        limit.configured = Some(configured);
        limit
    })
    .collect::<Vec<_>>();
    let reported_limits = root
        .and_then(|object| object.get("limits"))
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<EvidenceLimit>>(value).ok())
        .unwrap_or_default();
    let limits = merge_collection_limits(configured_limits, reported_limits);
    let envelope = EvidenceEnvelope::from_parts(
        plugin.name,
        EngineIdentity::new(
            crate::VERSION,
            crate::BUILD_ID,
            crate::INTEGRATION_API_VERSION,
        ),
        source_identity.clone(),
        available,
        complete,
        scope,
        warnings,
        limits,
        missing_ranges,
        raw_evidence,
        report,
    )?;
    serde_json::to_value(envelope).context("无法序列化 collect Evidence Envelope")
}

fn merge_collection_limits(
    mut configured: Vec<EvidenceLimit>,
    reported: Vec<EvidenceLimit>,
) -> Vec<EvidenceLimit> {
    for mut plugin_limit in reported {
        if let Some(existing) = configured.iter_mut().find(|candidate| {
            candidate.name == plugin_limit.name && candidate.kind == plugin_limit.kind
        }) {
            if plugin_limit.configured.is_none() {
                plugin_limit.configured = existing.configured;
            }
            *existing = plugin_limit;
        } else {
            configured.push(plugin_limit);
        }
    }
    configured.sort_by(|left, right| {
        left.name.cmp(&right.name).then_with(|| {
            collection_limit_kind_rank(left.kind).cmp(&collection_limit_kind_rank(right.kind))
        })
    });
    configured
}

fn collection_limit_kind_rank(kind: EvidenceLimitKind) -> u8 {
    match kind {
        EvidenceLimitKind::SourceScan => 0,
        EvidenceLimitKind::Output => 1,
        EvidenceLimitKind::Bytes => 2,
    }
}

/// 返回所有无需额外输入、不会直接写出外部取证文件的只读插件。
///
/// 该目录与 `--db` 的可读收集集合保持一致，宿主不应再复制一份插件清单。
pub fn readable_plugin_catalog() -> Vec<ReadablePluginDescriptor> {
    runnable_plugins()
        .into_iter()
        .map(|plugin| ReadablePluginDescriptor {
            name: plugin.name,
            display_name: plugin.display_name,
            category: plugin.category,
            platform: plugin_platform(plugin),
        })
        .collect()
}

/// 返回 `collect` 已知的完整命令目录，包括可运行项和带原因的明确跳过项。
///
/// 除 `collect` 自身外，CLI 顶层命令不应静默缺席于此目录。
pub fn collection_plugin_catalog() -> Vec<CollectionPluginDescriptor> {
    runnable_plugins()
        .into_iter()
        .map(|plugin| CollectionPluginDescriptor {
            name: plugin.name,
            display_name: plugin.display_name,
            category: plugin.category,
            disposition: CollectionPluginDisposition::Runnable,
            reason: None,
        })
        .chain(
            skipped_plugins()
                .into_iter()
                .map(|plugin| CollectionPluginDescriptor {
                    name: plugin.name,
                    display_name: plugin.display_name,
                    category: plugin.category,
                    disposition: CollectionPluginDisposition::Skipped,
                    reason: Some(plugin.reason),
                }),
        )
        .collect()
}

/// 返回所有需要用户参数或文件输出目录的取证命令。
pub fn parameterized_plugin_catalog() -> Vec<ParameterizedPluginDescriptor> {
    let registry = CommandRegistry::load_embedded()
        .expect("embedded leaf-command registry must validate before catalog use");
    skipped_plugins()
        .into_iter()
        .filter(|plugin| {
            registry
                .by_id(plugin.name)
                .is_some_and(|contract| contract.collect_parameterized)
        })
        .map(|plugin| ParameterizedPluginDescriptor {
            name: plugin.name,
            display_name: plugin.display_name,
            category: plugin.category,
            reason: plugin.reason,
        })
        .collect()
}

/// 按短插件名运行一个只读插件并返回结构化 JSON 值。
pub fn run_readable_plugin(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
    name: &str,
) -> Result<ReadablePluginReport> {
    run_readable_plugin_cancellable(session, options, name, &CancellationToken::new())
}

/// Cancellable host entry point for one catalog plugin.
pub fn run_readable_plugin_cancellable(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
    name: &str,
    cancellation: &CancellationToken,
) -> Result<ReadablePluginReport> {
    cancellation.check_cancelled()?;
    let plugin = runnable_plugins()
        .into_iter()
        .find(|plugin| plugin.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| anyhow::anyhow!("未找到可读 StarMem 插件：{name}"))?;
    if plugin.name == "crashinfo"
        && !matches!(session.image().format(), ImageFormat::WindowsCrashDump64(_))
    {
        bail!("当前镜像不是 Windows 崩溃转储，无法运行 crashinfo");
    }
    let value = run_plugin_cancellable(plugin, session, options, cancellation)
        .with_context(|| format!("StarMem 插件 {} 执行失败", plugin.name))?;
    Ok(ReadablePluginReport {
        descriptor: ReadablePluginDescriptor {
            name: plugin.name,
            display_name: plugin.display_name,
            category: plugin.category,
            platform: plugin_platform(plugin),
        },
        value,
    })
}

/// 按短插件名运行一个 Linux kernel-global 只读插件。
pub fn run_readable_linux_plugin(
    session: &LinuxKernelSession,
    options: &DatabaseCollectionOptions,
    name: &str,
) -> Result<ReadablePluginReport> {
    run_readable_linux_plugin_cancellable(session, options, name, &CancellationToken::new())
}

/// 可取消的 Linux kernel-global 单插件宿主入口。
pub fn run_readable_linux_plugin_cancellable(
    session: &LinuxKernelSession,
    options: &DatabaseCollectionOptions,
    name: &str,
    cancellation: &CancellationToken,
) -> Result<ReadablePluginReport> {
    cancellation.check_cancelled()?;
    let (plugin, runner) = resolve_readable_linux_plugin(name)?;
    let value = runner(session, options)
        .with_context(|| format!("StarMem Linux 插件 {} 执行失败", plugin.name))?;
    cancellation.check_cancelled()?;
    Ok(ReadablePluginReport {
        descriptor: ReadablePluginDescriptor {
            name: plugin.name,
            display_name: plugin.display_name,
            category: plugin.category,
            platform: ReadablePluginPlatform::Linux,
        },
        value,
    })
}

fn resolve_readable_linux_plugin(name: &str) -> Result<(PluginSpec, LinuxPluginRunner)> {
    let plugin = runnable_plugins()
        .into_iter()
        .find(|plugin| plugin.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| anyhow::anyhow!("未找到可读 StarMem 插件：{name}"))?;
    let PluginRunner::Linux(runner) = plugin.runner else {
        bail!("插件 {} 需要 Windows AnalysisSession", plugin.name);
    };
    Ok((plugin, runner))
}

fn plugin_platform(plugin: PluginSpec) -> ReadablePluginPlatform {
    match plugin.runner {
        PluginRunner::Windows(_) => ReadablePluginPlatform::Windows,
        PluginRunner::Linux(_) => ReadablePluginPlatform::Linux,
    }
}

fn run_plugin_cancellable(
    plugin: PluginSpec,
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
    cancellation: &CancellationToken,
) -> Result<Value> {
    cancellation.check_cancelled()?;
    let PluginRunner::Windows(runner) = plugin.runner else {
        bail!(
            "插件 {} 需要 LinuxKernelSession，不能使用 Windows AnalysisSession 运行",
            plugin.name
        );
    };
    let value = match plugin.name {
        "clipboardscan" => serialize(session.clipboard_scan_cancellable(
            &ClipboardScanOptions {
                limit: options.result_limit,
                max_data_size: options.max_data_size,
            },
            cancellation,
            |_| {},
        )?),
        "cmdscan" => {
            serialize(session.command_histories_cancellable(options.result_limit, cancellation)?)
        }
        "consoles" => serialize(session.consoles_cancellable(options.result_limit, cancellation)?),
        "mouse-history" => serialize(crate::mouse_history::analyze_mouse_history(
            session,
            options.result_limit,
            cancellation,
        )?),
        "mailslots" => {
            serialize(session.mailslots(&collection_mailslot_options(options), cancellation)?)
        }
        "pslist" => serialize(session.processes_cancellable(options.result_limit, cancellation)?),
        "psscan" => {
            serialize(session.process_scan_cancellable(options.result_limit, cancellation)?)
        }
        "netscan" => serialize(session.network_cancellable(options.result_limit, cancellation)?),
        "screen-resolution" => {
            serialize(session.screen_resolutions_cancellable(options.result_limit, cancellation)?)
        }
        "filescan" => serialize(session.files_cancellable(options.file_scan_limit, cancellation)?),
        "mftscan" => {
            serialize(session.mft_cancellable(MftView::All, options.result_limit, cancellation)?)
        }
        "mft-ads" => serialize(session.mft_cancellable(
            MftView::AlternateDataStreams,
            options.result_limit,
            cancellation,
        )?),
        "mft-resident-data" => serialize(session.mft_cancellable(
            MftView::ResidentData,
            options.result_limit,
            cancellation,
        )?),
        "injected-regions" => serialize(session.injected_regions_cancellable(
            &InjectedRegionOptions {
                limit: options.result_limit,
                ..InjectedRegionOptions::default()
            },
            cancellation,
        )?),
        "cobaltstrikescan" => serialize(session.cobaltstrikescan_cancellable(
            &CobaltStrikeScanOptions {
                result_limit: options.result_limit,
                ..CobaltStrikeScanOptions::default()
            },
            cancellation,
        )?),
        _ => runner(session, options),
    }?;
    cancellation.check_cancelled()?;
    Ok(value)
}

fn verified_plugin_partitions() -> &'static (Vec<PluginSpec>, Vec<SkippedPlugin>) {
    static PARTITIONS: OnceLock<(Vec<PluginSpec>, Vec<SkippedPlugin>)> = OnceLock::new();
    PARTITIONS.get_or_init(|| {
        let registry = CommandRegistry::load_embedded()
            .expect("embedded leaf-command registry must validate before collect catalog use");
        let runner_declarations = runnable_plugin_declarations();
        let mut runners = BTreeMap::new();
        for plugin in &runner_declarations {
            assert!(
                runners.insert(plugin.name, *plugin).is_none(),
                "duplicate collect runner declaration: {}",
                plugin.name
            );
        }
        let skip_declarations = skipped_plugin_declarations();
        let mut skips = BTreeMap::new();
        for plugin in &skip_declarations {
            assert!(
                skips.insert(plugin.name, *plugin).is_none(),
                "duplicate collect skip declaration: {}",
                plugin.name
            );
        }

        for contract in registry
            .commands
            .values()
            .filter(|contract| contract.command_id != "collect")
        {
            match contract.collect_disposition {
                CollectDisposition::Runnable => {
                    runners
                        .remove(contract.command_id.as_str())
                        .unwrap_or_else(|| {
                            panic!(
                                "leaf manifest marks {} runnable but no collect runner is declared",
                                contract.command_id
                            )
                        });
                    assert!(
                        !skips.contains_key(contract.command_id.as_str()),
                        "{} has both collect runner and skip declarations",
                        contract.command_id
                    );
                }
                CollectDisposition::Skipped => {
                    skips
                        .remove(contract.command_id.as_str())
                        .unwrap_or_else(|| {
                            panic!(
                                "leaf manifest marks {} skipped but no collect reason is declared",
                                contract.command_id
                            )
                        });
                    assert!(
                        !runners.contains_key(contract.command_id.as_str()),
                        "{} has both collect runner and skip declarations",
                        contract.command_id
                    );
                }
                CollectDisposition::Conditional
                | CollectDisposition::Unsupported
                | CollectDisposition::Unknown => panic!(
                    "leaf manifest disposition {:?} is not executable by collect for {}",
                    contract.collect_disposition, contract.command_id
                ),
            }
        }
        assert!(
            runners.is_empty(),
            "collect runners are absent from the leaf manifest: {:?}",
            runners.keys().collect::<Vec<_>>()
        );
        assert!(
            skips.is_empty(),
            "collect skip declarations are absent from the leaf manifest: {:?}",
            skips.keys().collect::<Vec<_>>()
        );
        (runner_declarations, skip_declarations)
    })
}

fn runnable_plugins() -> Vec<PluginSpec> {
    verified_plugin_partitions().0.clone()
}

fn skipped_plugins() -> Vec<SkippedPlugin> {
    verified_plugin_partitions().1.clone()
}

fn runnable_plugin_declarations() -> Vec<PluginSpec> {
    vec![
        plugin("info", "镜像信息", "系统与内存", |session, _| {
            Ok(json!({
                "path": session.image().path().display().to_string(),
                "file_size": session.image().file_len(),
                "logical_size": session.image().logical_len(),
                "mapped_bytes": session.image().mapped_bytes(),
                "format": session.image().format(),
                "physical_spans": session.image().spans(),
                "complete": true,
                "warnings": session.warnings(),
            }))
        }),
        plugin(
            "windows-info",
            "Windows 内核信息",
            "系统与内存",
            |session, _| serialize(session.kernel()),
        ),
        plugin(
            "system-info",
            "系统取证概况",
            "系统与内存",
            |session, options| serialize(analyze_system_info_quick(session, options.result_limit)?),
        ),
        plugin(
            "system-artifacts",
            "系统配置与历史证据",
            "系统与内存",
            |session, _| serialize(analyze_system_artifacts(session)?),
        ),
        plugin(
            "screen-resolution",
            "屏幕分辨率",
            "系统与内存",
            |session, options| serialize(session.screen_resolutions(options.result_limit)?),
        ),
        plugin(
            "crashinfo",
            "崩溃转储信息",
            "系统与内存",
            |session, _| serialize(session.crash_info()?),
        ),
        plugin(
            "kpcrs",
            "处理器控制区",
            "系统与内存",
            |session, options| serialize(session.kpcrs(options.result_limit)?),
        ),
        plugin(
            "debugregisters",
            "硬件调试寄存器",
            "系统与内存",
            |session, options| serialize(session.kpcrs(options.result_limit)?),
        ),
        plugin(
            "virtmap",
            "内核虚拟地址映射",
            "系统与内存",
            |session, options| serialize(session.kernel_virtmap(options.result_limit)?),
        ),
        plugin(
            "memmap",
            "全部进程内存映射",
            "系统与内存",
            collect_process_memmaps,
        ),
        plugin(
            "statistics",
            "内存统计",
            "系统与内存",
            |session, options| serialize(session.memory_statistics(options.result_limit)?),
        ),
        plugin(
            "bigpools",
            "大页池",
            "系统与内存",
            |session, options| serialize(session.big_pools(&[], false, options.result_limit)?),
        ),
        plugin(
            "poolscanner",
            "内核池扫描",
            "系统与内存",
            |session, options| {
                serialize(session.pool_scan(&crate::scan::COMMON_POOL_TAGS, options.result_limit)?)
            },
        ),
        plugin(
            "downloadscan",
            "下载痕迹",
            "网络与应用",
            |session, options| {
                serialize(scan_download_traces(session.image(), options.result_limit)?)
            },
        ),
        plugin(
            "cookiescan",
            "浏览器 Cookie",
            "网络与应用",
            |session, options| serialize(session.cookie_scan(&cookie_options(options), |_| {})?),
        ),
        plugin(
            "clipboardscan",
            "剪贴板与历史",
            "命令与交互",
            |session, options| {
                serialize(session.clipboard_scan(
                    &ClipboardScanOptions {
                        limit: options.result_limit,
                        max_data_size: options.max_data_size,
                    },
                    |_| {},
                )?)
            },
        ),
        plugin(
            "residualscan",
            "进程文本残留",
            "命令与交互",
            |session, options| {
                serialize(session.residual_scan(
                    &ResidualScanOptions {
                        limit: options.result_limit,
                        process_space_limit: options.process_space_limit,
                        search_texts: Vec::new(),
                    },
                    |_| {},
                )?)
            },
        ),
        plugin(
            "wechatscan",
            "微信密钥",
            "网络与应用",
            |session, options| {
                serialize(session.wechat_scan(
                    &WechatScanOptions {
                        pid: None,
                        include_helpers: true,
                        limit: options.result_limit,
                        anchor_limit: 1_000_000,
                        process_space_limit: options.process_space_limit,
                        verification_roots: Vec::new(),
                        verification_file_limit: 10_000,
                    },
                    |_| {},
                )?)
            },
        ),
        plugin(
            "browser-session",
            "浏览器会话",
            "网络与应用",
            |session, options| {
                serialize(session.browser_sessions(
                    &BrowserSessionOptions {
                        session_limit: options.result_limit,
                        download_limit: options.result_limit,
                        cookie: cookie_options(options),
                    },
                    |_| {},
                )?)
            },
        ),
        plugin(
            "browser-history",
            "浏览器访问历史",
            "网络与应用",
            |session, options| {
                let files = session.files(options.file_scan_limit)?;
                let report = parse_browser_history_artifacts_from_file_scan(
                    session.image(),
                    session.kernel(),
                    session.profile(),
                    files,
                    &BrowserArtifactOptions {
                        result_limit: options.result_limit,
                        database_limit: 256,
                        max_database_size: options.max_data_size as u64,
                    },
                    None,
                )?;
                Ok(json!({
                    "records": report.visit_history,
                    "visit_events": report.visit_events,
                    "download_history": report.download_history,
                    "database_sources": report.database_sources,
                    "page_candidates": report.page_candidates,
                    "artifact_files_found": report.artifact_files_found,
                    "databases_parsed": report.databases_parsed,
                    "complete": report.complete,
                    "warnings": report.warnings,
                    "parse_seconds": report.parse_seconds,
                }))
            },
        ),
        plugin(
            "dnsscan",
            "DNS 与域名证据",
            "网络与应用",
            |session, options| {
                serialize(session.dns_scan(
                    &DnsScanOptions {
                        limit: options.result_limit,
                        browser: BrowserSessionOptions {
                            session_limit: options.result_limit,
                            download_limit: options.result_limit,
                            cookie: cookie_options(options),
                        },
                    },
                    |_| {},
                )?)
            },
        ),
        plugin(
            "accountscan",
            "账户操作",
            "进程与账户",
            |session, options| serialize(session.account_scan(options.result_limit)?),
        ),
        plugin(
            "pslist",
            "活动进程",
            "进程与线程",
            |session, options| serialize(session.processes(options.result_limit)?),
        ),
        plugin(
            "psscan",
            "进程池扫描",
            "进程与线程",
            |session, options| serialize(session.process_scan(options.result_limit)?),
        ),
        plugin(
            "pstree",
            "进程树",
            "进程与线程",
            |session, options| serialize(session.process_tree(options.result_limit)?),
        ),
        plugin(
            "check-pslist",
            "进程父链审计",
            "进程与线程",
            |session, options| {
                serialize(session.check_pslist(&CheckPslistOptions {
                    result_limit: options.result_limit,
                    ..CheckPslistOptions::default()
                })?)
            },
        ),
        plugin(
            "psxview",
            "进程交叉视图",
            "进程与线程",
            |session, options| serialize(session.psxview(options.result_limit)?),
        ),
        plugin(
            "threads",
            "线程",
            "进程与线程",
            |session, options| serialize(session.threads(options.result_limit)?),
        ),
        plugin(
            "thrdscan",
            "线程池扫描",
            "进程与线程",
            |session, options| serialize(session.thread_scan(options.result_limit)?),
        ),
        plugin(
            "suspended-threads",
            "挂起线程",
            "进程与线程",
            |session, options| {
                let mut report = session.threads(options.result_limit)?;
                report.records.retain(|thread| {
                    thread.suspend_count.unwrap_or(0) > 0
                        || thread.freeze_count.unwrap_or(0) > 0
                        || matches!(thread.wait_reason, Some(5 | 12))
                });
                serialize(report)
            },
        ),
        plugin(
            "suspicious-threads",
            "可疑线程",
            "进程与线程",
            |session, options| {
                let mut report = session.threads(options.result_limit)?;
                report
                    .records
                    .retain(|thread| !thread.suspicious_reasons.is_empty());
                serialize(report)
            },
        ),
        plugin(
            "orphan-kernel-threads",
            "孤立内核线程",
            "进程与线程",
            |session, options| {
                let mut report = session.threads(options.result_limit)?;
                report.records.retain(|thread| {
                    thread
                        .suspicious_reasons
                        .iter()
                        .any(|reason| reason == "kernel start address is outside loaded modules")
                });
                serialize(report)
            },
        ),
        plugin(
            "sessions",
            "进程会话分组",
            "进程与账户",
            |session, options| serialize(session.process_sessions(options.result_limit)?),
        ),
        plugin(
            "logonsessions",
            "安全登录会话",
            "进程与账户",
            |session, options| {
                serialize(session.logon_sessions(
                    &crate::windows::logon_plugins::LogonSessionOptions {
                        process_limit: 65_536,
                        limit: options.result_limit,
                    },
                )?)
            },
        ),
        plugin(
            "token-anomalies",
            "令牌异常",
            "进程与账户",
            |session, options| {
                serialize(session.token_anomalies(
                    &crate::windows::token_plugins::TokenAnomalyOptions {
                        process_limit: 65_536,
                        limit: options.result_limit,
                        ..Default::default()
                    },
                )?)
            },
        ),
        plugin(
            "joblinks",
            "进程 Job 关系",
            "进程与线程",
            |session, options| serialize(session.job_links(options.result_limit)?),
        ),
        plugin(
            "cmdline",
            "进程命令行",
            "命令与交互",
            |session, options| serialize(session.command_lines(options.result_limit)?),
        ),
        plugin(
            "envars",
            "进程环境变量",
            "命令与交互",
            |session, options| serialize(session.environment_variables(options.result_limit)?),
        ),
        plugin(
            "terminal-history",
            "终端历史",
            "命令与交互",
            |session, options| {
                serialize(session.terminal_history(
                    &TerminalHistoryOptions {
                        limit: options.result_limit,
                        file_scan_limit: options.file_scan_limit,
                        history_file_limit: 256,
                        max_history_file_size: options.max_data_size as u64,
                    },
                    |_| {},
                )?)
            },
        ),
        plugin(
            "cmdscan",
            "控制台命令历史",
            "命令与交互",
            |session, options| serialize(session.command_histories(options.result_limit)?),
        ),
        plugin(
            "consoles",
            "控制台内容",
            "命令与交互",
            |session, options| serialize(session.consoles(options.result_limit)?),
        ),
        plugin(
            "windowstations",
            "窗口站",
            "命令与交互",
            |session, options| serialize(session.window_stations(options.result_limit)?),
        ),
        plugin(
            "desktops",
            "桌面对象",
            "命令与交互",
            |session, options| serialize(session.desktops(options.result_limit, false)?),
        ),
        plugin(
            "deskscan",
            "桌面池扫描",
            "命令与交互",
            |session, options| serialize(session.desktops(options.result_limit, true)?),
        ),
        plugin(
            "gui-windows",
            "GUI 窗口",
            "命令与交互",
            |session, options| serialize(session.windows(options.result_limit)?),
        ),
        plugin(
            "windowtitles",
            "窗口标题",
            "命令与交互",
            |session, options| serialize(session.window_titles(options.result_limit)?),
        ),
        plugin(
            "privileges",
            "令牌权限",
            "进程与账户",
            |session, options| serialize(session.process_privileges(options.result_limit)?),
        ),
        plugin(
            "getsids",
            "进程 SID",
            "进程与账户",
            |session, options| serialize(session.process_sids(None, options.result_limit)?),
        ),
        plugin(
            "getservicesids",
            "服务 SID",
            "进程与账户",
            |session, options| serialize(session.service_sids(options.result_limit)?),
        ),
        plugin(
            "drivers",
            "内核模块和驱动",
            "驱动与内核",
            |session, options| serialize(session.drivers(options.result_limit)?),
        ),
        plugin(
            "modscan",
            "内核模块池扫描",
            "驱动与内核",
            |session, options| serialize(session.module_scan(options.result_limit)?),
        ),
        plugin(
            "driverscan",
            "驱动对象扫描",
            "驱动与内核",
            |session, options| serialize(session.driver_scan(options.result_limit)?),
        ),
        plugin(
            "drivermodule",
            "驱动模块关联",
            "驱动与内核",
            |session, options| serialize(session.driver_modules(options.result_limit)?),
        ),
        plugin(
            "driverirp",
            "驱动 IRP",
            "驱动与内核",
            |session, options| serialize(session.driver_irps(options.result_limit)?),
        ),
        plugin(
            "driver-inspect",
            "驱动对象综合视图",
            "驱动与内核",
            |session, options| {
                serialize(session.driver_inspect(None, None, options.result_limit)?)
            },
        ),
        plugin(
            "devicetree",
            "驱动设备树",
            "驱动与内核",
            |session, options| serialize(session.device_tree(options.result_limit)?),
        ),
        plugin(
            "callbacks",
            "内核回调",
            "驱动与内核",
            |session, options| serialize(session.callbacks(options.result_limit)?),
        ),
        plugin(
            "ssdt",
            "系统服务表",
            "驱动与内核",
            |session, options| serialize(session.ssdt(options.result_limit)?),
        ),
        plugin(
            "unloadedmodules",
            "已卸载模块",
            "驱动与内核",
            |session, options| serialize(session.unloaded_modules(options.result_limit)?),
        ),
        plugin(
            "mutantscan",
            "互斥体",
            "内核对象",
            |session, options| serialize(session.mutants(options.result_limit)?),
        ),
        plugin(
            "symlinkscan",
            "符号链接对象",
            "内核对象",
            |session, options| serialize(session.symbolic_links(options.result_limit)?),
        ),
        plugin(
            "handles",
            "全部进程句柄",
            "内核对象",
            |session, options| {
                collect_process_records(session, options, |session, pid, limit| {
                    serialize(session.handles(pid, limit)?)
                })
            },
        ),
        plugin(
            "timers",
            "内核定时器",
            "内核对象",
            |session, options| serialize(session.timers(options.result_limit)?),
        ),
        plugin(
            "dlllist",
            "进程 DLL",
            "进程内存",
            |session, options| serialize(session.dlls(None, options.result_limit)?),
        ),
        plugin(
            "ldrmodules",
            "加载器模块交叉检查",
            "进程内存",
            |session, options| serialize(session.ldr_modules(None, options.result_limit)?),
        ),
        plugin(
            "iat",
            "导入地址表",
            "进程内存",
            |session, options| serialize(session.iat(None, options.result_limit)?),
        ),
        plugin(
            "vad",
            "全部进程 VAD",
            "进程内存",
            |session, options| {
                collect_process_records(session, options, |session, pid, limit| {
                    serialize(session.vads(pid, limit)?)
                })
            },
        ),
        plugin(
            "pe-symbols",
            "内核与进程 PE 符号",
            "进程内存",
            collect_pe_symbols,
        ),
        plugin(
            "hivelist",
            "已加载注册表 Hive",
            "注册表",
            |session, options| serialize(session.hives(options.result_limit)?),
        ),
        plugin(
            "hivescan",
            "注册表 Hive 扫描",
            "注册表",
            |session, options| serialize(session.hive_scan(options.result_limit)?),
        ),
        plugin(
            "getcellroutine",
            "注册表 GetCellRoutine",
            "注册表",
            |session, options| serialize(session.get_cell_routines(options.result_limit)?),
        ),
        plugin(
            "hashdump",
            "本地账户密码哈希",
            "注册表与凭据",
            |session, options| serialize(session.hashdump(options.result_limit)?),
        ),
        plugin(
            "cachedump",
            "域缓存登录哈希",
            "注册表与凭据",
            |session, options| serialize(session.cachedump(options.result_limit)?),
        ),
        plugin(
            "lsadump",
            "LSA Secrets",
            "注册表与凭据",
            |session, options| serialize(session.lsadump(options.result_limit)?),
        ),
        plugin(
            "svcscan",
            "服务扫描",
            "服务与持久化",
            |session, options| {
                serialize(session.services(ServiceView::Scan, options.result_limit, true)?)
            },
        ),
        plugin(
            "svclist",
            "服务链表",
            "服务与持久化",
            |session, options| {
                serialize(session.services(ServiceView::List, options.result_limit, true)?)
            },
        ),
        plugin(
            "svcdiff",
            "隐藏服务差异",
            "服务与持久化",
            |session, options| {
                serialize(session.services(ServiceView::Difference, options.result_limit, true)?)
            },
        ),
        plugin(
            "scheduled-tasks",
            "计划任务",
            "服务与持久化",
            |session, options| serialize(session.scheduled_tasks(options.result_limit)?),
        ),
        plugin(
            "autoruns",
            "自启动与持久化配置",
            "服务与持久化",
            |session, options| {
                serialize(session.autoruns(&AutorunOptions {
                    limit: options.result_limit,
                    ..AutorunOptions::default()
                })?)
            },
        ),
        plugin(
            "userassist",
            "UserAssist",
            "注册表",
            |session, options| serialize(session.userassist(options.result_limit)?),
        ),
        plugin("amcache", "Amcache", "注册表", |session, options| {
            serialize(session.amcache(options.result_limit)?)
        }),
        plugin(
            "shimcachemem",
            "Shimcache",
            "注册表",
            |session, options| serialize(session.shimcache(options.result_limit)?),
        ),
        plugin(
            "netscan",
            "网络端点扫描",
            "网络与应用",
            |session, options| serialize(session.network(options.result_limit)?),
        ),
        plugin(
            "netstat",
            "活动网络连接",
            "网络与应用",
            |session, options| serialize(session.netstat(options.result_limit)?),
        ),
        plugin(
            "packetscan",
            "内存数据包",
            "网络与应用",
            |session, options| {
                let artifacts = session.packet_scan(
                    &PacketScanOptions {
                        limit: options.result_limit,
                        ..PacketScanOptions::default()
                    },
                    |_| {},
                )?;
                serialize(artifacts.report)
            },
        ),
        plugin(
            "filescan",
            "文件对象扫描",
            "文件与磁盘",
            |session, options| serialize(session.files(options.file_scan_limit)?),
        ),
        plugin(
            "mftscan",
            "MFT 记录",
            "文件与磁盘",
            |session, options| serialize(session.mft(MftView::All, options.result_limit)?),
        ),
        plugin(
            "mft-ads",
            "MFT 备用数据流",
            "文件与磁盘",
            |session, options| {
                serialize(session.mft(MftView::AlternateDataStreams, options.result_limit)?)
            },
        ),
        plugin(
            "mft-resident-data",
            "MFT 常驻数据",
            "文件与磁盘",
            |session, options| serialize(session.mft(MftView::ResidentData, options.result_limit)?),
        ),
        plugin(
            "mbrscan",
            "主引导记录",
            "文件与磁盘",
            |session, options| serialize(session.mbrs(options.result_limit)?),
        ),
        plugin(
            "malfind",
            "可执行 VAD 异常",
            "恶意代码",
            |session, options| serialize(session.malfind(None, options.result_limit)?),
        ),
        plugin(
            "injected-regions",
            "保护位不一致的注入区间",
            "恶意代码",
            |session, options| {
                serialize(session.injected_regions(&InjectedRegionOptions {
                    limit: options.result_limit,
                    ..InjectedRegionOptions::default()
                })?)
            },
        ),
        plugin(
            "cobaltstrikescan",
            "Cobalt Strike Beacon 配置",
            "恶意代码",
            |session, options| {
                serialize(session.cobaltstrikescan(&CobaltStrikeScanOptions {
                    result_limit: options.result_limit,
                    ..CobaltStrikeScanOptions::default()
                })?)
            },
        ),
        plugin(
            "hollowprocesses",
            "进程空洞化",
            "恶意代码",
            |session, options| {
                serialize(
                    session.process_image_anomalies(
                        ProcessImageView::Hollowing,
                        options.result_limit,
                    )?,
                )
            },
        ),
        plugin(
            "processghosting",
            "进程幽灵化",
            "恶意代码",
            |session, options| {
                serialize(
                    session.process_image_anomalies(
                        ProcessImageView::Ghosting,
                        options.result_limit,
                    )?,
                )
            },
        ),
        plugin(
            "pebmasquerade",
            "PEB 伪装",
            "恶意代码",
            |session, options| {
                serialize(session.process_image_anomalies(
                    ProcessImageView::PebMasquerade,
                    options.result_limit,
                )?)
            },
        ),
        plugin(
            "direct-system-calls",
            "直接系统调用",
            "恶意代码",
            |session, options| {
                serialize(session.system_calls(SyscallView::Direct, options.result_limit)?)
            },
        ),
        plugin(
            "indirect-system-calls",
            "间接系统调用",
            "恶意代码",
            |session, options| {
                serialize(session.system_calls(SyscallView::Indirect, options.result_limit)?)
            },
        ),
        plugin(
            "unhooked-system-calls",
            "异常系统调用桩",
            "恶意代码",
            |session, options| serialize(session.unhooked_system_calls(options.result_limit)?),
        ),
        plugin(
            "etwpatch",
            "ETW 补丁",
            "恶意代码",
            |session, options| serialize(session.etw_patches(options.result_limit)?),
        ),
        plugin(
            "skeleton-key-check",
            "Skeleton Key",
            "恶意代码",
            |session, options| serialize(session.skeleton_key(options.result_limit)?),
        ),
        plugin(
            "acquisition-info",
            "内存采集信息",
            "系统与内存",
            collect_acquisition_info,
        ),
        plugin(
            "windows.open-files",
            "Windows 打开文件",
            "文件与对象",
            collect_windows_open_files,
        ),
        plugin("pipescan", "命名管道", "文件与对象", collect_pipes),
        plugin(
            "mailslots",
            "Mailslot 邮槽与消息",
            "文件与对象",
            collect_mailslots,
        ),
        plugin(
            "mouse-history",
            "鼠标最近轨迹",
            "用户交互",
            collect_mouse_history,
        ),
        plugin(
            "prefetchscan",
            "Prefetch 执行记录",
            "执行与时间线",
            collect_prefetch,
        ),
        plugin(
            "windows.timeline",
            "Windows 统一时间线",
            "执行与时间线",
            collect_windows_timeline,
        ),
        plugin(
            "windows.execution",
            "Windows 执行证据",
            "执行与时间线",
            collect_windows_execution,
        ),
        plugin(
            "windows.recent-files",
            "Windows 最近文件",
            "执行与时间线",
            collect_windows_recent_files,
        ),
        plugin(
            "usb-history",
            "USB 连接历史",
            "系统与内存",
            collect_usb_history,
        ),
        linux_plugin(
            "linux.lsmod",
            "Linux 内核模块链",
            "Linux",
            collect_linux_lsmod,
        ),
        linux_plugin(
            "linux.mountinfo",
            "Linux 挂载命名空间",
            "Linux",
            collect_linux_mountinfo,
        ),
        linux_plugin(
            "linux.kallsyms",
            "Linux kallsyms",
            "Linux",
            collect_linux_kallsyms,
        ),
        linux_plugin("linux.kmsg", "Linux 内核日志", "Linux", collect_linux_kmsg),
        linux_plugin(
            "linux.modxview",
            "Linux 内核模块交叉视图",
            "Linux",
            collect_linux_modxview,
        ),
        linux_plugin(
            "linux.check-syscall",
            "Linux syscall hook 检查",
            "Linux",
            collect_linux_check_syscall,
        ),
    ]
}

fn collect_linux_lsmod(
    session: &LinuxKernelSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    serialize(linux_lsmod(session, options.result_limit))
}

fn collect_linux_mountinfo(
    session: &LinuxKernelSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    serialize(linux_mountinfo(
        session,
        &LinuxMountInfoOptions {
            limit: options.result_limit,
            ..LinuxMountInfoOptions::default()
        },
    ))
}

fn collect_linux_kallsyms(
    session: &LinuxKernelSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    serialize(linux_kallsyms(session, options.result_limit))
}

fn collect_linux_kmsg(
    session: &LinuxKernelSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    serialize(linux_kmsg(
        session,
        &LinuxKmsgOptions {
            limit: options.result_limit,
            boot_time_unix_ns: None,
        },
    ))
}

fn collect_linux_modxview(
    session: &LinuxKernelSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    serialize(linux_modxview(session, options.result_limit))
}

fn collect_linux_check_syscall(
    session: &LinuxKernelSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    serialize(linux_check_syscall(
        session,
        &LinuxCheckSyscallOptions {
            entries: options.result_limit,
            ..LinuxCheckSyscallOptions::default()
        },
    ))
}

fn collect_acquisition_info(
    session: &AnalysisSession,
    _options: &DatabaseCollectionOptions,
) -> Result<Value> {
    serialize(analyze_acquisition_info(
        session,
        &AcquisitionInfoOptions::default(),
    )?)
}

fn collect_pe_symbols(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    let kernel = session.pe_symbols(
        PeSymbolSource::Kernel,
        None,
        None,
        None,
        options.result_limit,
    );
    let processes = session.pe_symbols(
        PeSymbolSource::Processes,
        None,
        None,
        None,
        options.result_limit,
    );
    let mut report = match (kernel, processes) {
        (Ok(mut kernel), Ok(processes)) => {
            kernel.records.extend(processes.records);
            kernel.modules_examined += processes.modules_examined;
            kernel.complete &= processes.complete;
            kernel.warnings.extend(
                processes
                    .warnings
                    .into_iter()
                    .map(|warning| format!("进程模块：{warning}")),
            );
            kernel
        }
        (Ok(mut kernel), Err(error)) => {
            kernel.complete = false;
            kernel
                .warnings
                .push(format!("进程模块 PE 符号恢复失败：{error:#}"));
            kernel
        }
        (Err(error), Ok(mut processes)) => {
            processes.complete = false;
            processes
                .warnings
                .push(format!("内核模块 PE 符号恢复失败：{error:#}"));
            processes
        }
        (Err(kernel_error), Err(process_error)) => {
            bail!("内核与进程 PE 符号恢复均失败：内核={kernel_error:#}；进程={process_error:#}")
        }
    };
    truncate_collection_records(
        &mut report.records,
        &mut report.complete,
        &mut report.warnings,
        options.result_limit,
        "内核与进程 PE 符号",
    );
    serialize(report)
}

fn collect_windows_open_files(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    let open_files = collection_open_file_options(options);
    serialize(scan_open_files(session, &open_files)?)
}

fn collect_pipes(session: &AnalysisSession, options: &DatabaseCollectionOptions) -> Result<Value> {
    let pipes = collection_pipe_options(options);
    serialize(session.pipes(&pipes)?)
}

fn collect_mailslots(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    serialize(session.mailslots(
        &collection_mailslot_options(options),
        &CancellationToken::new(),
    )?)
}

fn collect_mouse_history(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    serialize(crate::mouse_history::analyze_mouse_history(
        session,
        options.result_limit,
        &CancellationToken::new(),
    )?)
}

fn collection_mailslot_options(options: &DatabaseCollectionOptions) -> MailslotOptions {
    MailslotOptions {
        file_limit: options.file_scan_limit,
        limit: options.result_limit,
        ..MailslotOptions::default()
    }
}

fn collect_prefetch(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    let prefetch = collection_prefetch_options(options);
    let mut report = session.prefetch(&prefetch)?;
    truncate_collection_records(
        &mut report.records,
        &mut report.complete,
        &mut report.warnings,
        options.result_limit,
        "Prefetch",
    );
    serialize(report)
}

fn collect_windows_timeline(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    let timeline = collection_timeline_options(options);
    serialize(analyze_windows_timeline(session, &timeline, |_| {})?)
}

fn collect_windows_execution(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    let execution = collection_execution_options(options);
    serialize(analyze_windows_execution(session, &execution, |_| {})?)
}

fn collect_windows_recent_files(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    let recent_files = collection_recent_file_options(options);
    serialize(analyze_windows_recent_files(
        session,
        &recent_files,
        |_| {},
    )?)
}

fn collect_usb_history(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    let processes = session.processes(65_536)?;
    let process_complete = processes.complete;
    let process_warnings = processes
        .warnings
        .iter()
        .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
        .collect::<Vec<_>>();
    let (registry, system_hive) = analyze_registry_with_system_hive(session, &processes);
    let usb = UsbHistoryOptions {
        limit: options.result_limit,
        ..UsbHistoryOptions::default()
    };
    let mut report = analyze_usb_history(&registry, system_hive.as_ref(), &usb)?;
    report.complete &= process_complete;
    for warning in process_warnings {
        if report.warnings.len() < USB_HISTORY_WARNING_LIMIT {
            report.warnings.push(warning);
        } else if report.warnings.len() == USB_HISTORY_WARNING_LIMIT {
            report.warnings.push(format!(
                "USB history warnings reached {USB_HISTORY_WARNING_LIMIT}; additional warnings were suppressed"
            ));
        }
    }
    report.warnings_truncated = report.warnings.len() > USB_HISTORY_WARNING_LIMIT;
    serialize(report)
}

fn collection_open_file_options(options: &DatabaseCollectionOptions) -> OpenFileOptions {
    OpenFileOptions {
        file_scan_limit: options.file_scan_limit,
        result_limit: options.result_limit,
        ..OpenFileOptions::default()
    }
}

fn collection_pipe_options(options: &DatabaseCollectionOptions) -> PipeScanOptions {
    PipeScanOptions {
        file_limit: options.file_scan_limit,
        limit: options.result_limit,
        ..PipeScanOptions::default()
    }
}

fn collection_prefetch_options(options: &DatabaseCollectionOptions) -> PrefetchScanOptions {
    PrefetchScanOptions {
        file_scan_limit: options.file_scan_limit,
        ..PrefetchScanOptions::default()
    }
}

fn collection_timeline_options(options: &DatabaseCollectionOptions) -> WindowsTimelineOptions {
    WindowsTimelineOptions {
        event_limit: options.result_limit,
        ..WindowsTimelineOptions::default()
    }
}

fn collection_execution_options(options: &DatabaseCollectionOptions) -> WindowsExecutionOptions {
    WindowsExecutionOptions {
        file_scan_limit: options.file_scan_limit,
        event_limit: options.result_limit,
        ..WindowsExecutionOptions::default()
    }
}

fn collection_recent_file_options(
    options: &DatabaseCollectionOptions,
) -> WindowsRecentFilesOptions {
    WindowsRecentFilesOptions {
        record_limit: options.result_limit,
        ..WindowsRecentFilesOptions::default()
    }
}

fn truncate_collection_records<T>(
    records: &mut Vec<T>,
    complete: &mut bool,
    warnings: &mut Vec<String>,
    limit: usize,
    label: &str,
) {
    if records.len() <= limit {
        return;
    }
    let recovered = records.len();
    records.truncate(limit);
    *complete = false;
    warnings.push(format!(
        "{label} 恢复 {recovered} 条，按 collect --limit 仅保留 {limit} 条"
    ));
}

fn skipped_plugin_declarations() -> Vec<SkippedPlugin> {
    vec![
        skipped(
            "windows.phys2file",
            "物理页文件反查",
            "文件系统",
            "需要显式物理地址；按 PFN、原型 PTE 与数据节双向归属核对文件对象，不推定已移除的文件名",
        ),
        skipped(
            "macos.ir",
            "macOS 系统、进程与文件",
            "macOS",
            "需要显式转换的 macOS 符号；只分析驻留活动对象链，不进入自动采集",
        ),
        skipped(
            "macos.dumpfile",
            "macOS 驻留文件恢复",
            "macOS",
            "需要显式 macOS 符号与 vnode；缺页产物使用 .partial 并保留恢复范围",
        ),
        skipped(
            "symbolless.registry",
            "无符号注册表",
            "无符号基础分析",
            "需要显式选择 Hive 文件对象与配对；仅解析已恢复稳定数据",
        ),
        skipped(
            "symbolless.system-info",
            "无符号系统信息",
            "无符号基础分析",
            "仅手动读取目标导出和共享页，保留字段缺失、冲突及估算说明",
        ),
        skipped(
            "symbolless.process-context",
            "无符号进程上下文",
            "无符号基础分析",
            "手动恢复经归属核验的原生 AMD64 PEB 参数与环境块，缺页及截断分别报告",
        ),
        skipped(
            "symbolless.process-modules",
            "无符号进程 DLL",
            "无符号基础分析",
            "手动恢复原生 AMD64 加载器链，未覆盖 WOW64、VAD 对照和隐藏模块",
        ),
        skipped(
            "symbolless.pslist",
            "无符号进程分析",
            "无符号基础分析",
            "实验性独立模式，仅手动执行，不进入符号会话或自动采集",
        ),
        skipped(
            "symbolless.filescan",
            "无符号文件扫描",
            "无符号基础分析",
            "实验性文件对象扫描，仅手动执行，保留布局先验和覆盖限制",
        ),
        skipped(
            "symbolless.dumpfile",
            "无符号文件恢复",
            "无符号基础分析",
            "需要指定 FILE_OBJECT，仅恢复可验证范围并保存来源说明",
        ),
        skipped(
            "browser-pages",
            "浏览器页面与标签页",
            "浏览器",
            "手动关联窗口、驻留 URL 与 Session 片段，保留独立进程读取预算",
        ),
        skipped(
            "bitlocker",
            "BitLocker 检测",
            "应用痕迹",
            "加密组件与驻留配置检测仅手动执行，不推定卷状态",
        ),
        skipped(
            "veracrypt",
            "VeraCrypt 分析",
            "应用痕迹",
            "容器与配置候选分析仅手动执行，保留独立恢复预算",
        ),
        skipped(
            "sunlogin",
            "向日葵远程分析",
            "应用痕迹",
            "远控配置与日志仅手动执行，保留独立恢复预算",
        ),
        skipped(
            "anydesk",
            "AnyDesk 分析",
            "应用痕迹",
            "远控配置与日志仅手动执行，保留独立恢复预算",
        ),
        skipped(
            "wps",
            "WPS 分析",
            "应用痕迹",
            "办公配置与最近文档仅手动执行，保留独立恢复预算",
        ),
        skipped(
            "huorong",
            "火绒报毒分析",
            "应用痕迹",
            "手动解析报毒日志、WAL 和进程内存",
        ),
        skipped(
            "ai-chat",
            "AI 软件与本地对话",
            "应用痕迹",
            "手动解析会话存储与进程内存，不推定完整历史",
        ),
        skipped(
            "qqscan",
            "QQNT 内存取证",
            "进程",
            "QQNT 驻留结构恢复仅手动执行，保留独立进程、解析和读取预算",
        ),
        skipped(
            "wechat-chat",
            "微信聊天取证",
            "进程",
            "微信 WCDB 驻留缓存恢复仅手动执行，保留独立缓存归属及缺页限制",
        ),
        skipped(
            "windows.interaction",
            "Windows 交互痕迹",
            "用户交互",
            "版本相关的交互恢复仅手动执行，避免自动下载额外模块符号和重复扫描",
        ),
        skipped("build-info", "构建身份", "工具", "构建身份不读取内存镜像"),
        skipped("scan", "精确字节扫描", "搜索", "必须提供 --text 或 --hex"),
        skipped(
            "strings",
            "字符串偏移映射",
            "搜索",
            "必须提供 strings 偏移文件",
        ),
        skipped(
            "windows.process-string",
            "Windows 字符串进程定位",
            "搜索",
            "必须显式提供 --text 字符串",
        ),
        skipped(
            "virt2phys",
            "虚拟地址转换",
            "系统与内存",
            "必须提供虚拟地址",
        ),
        skipped(
            "vadregexscan",
            "VAD 正则扫描",
            "进程内存",
            "必须提供正则表达式",
        ),
        skipped(
            "vadyarascan",
            "VAD YARA 扫描",
            "进程内存",
            "必须提供 YARA 规则",
        ),
        skipped(
            "registry-printkey",
            "注册表键输出",
            "注册表",
            "必须提供 Hive 和键路径",
        ),
        skipped("pedump", "PE 导出", "导出", "会写外部文件且必须提供地址"),
        skipped(
            "vaddump",
            "VAD 区间导出",
            "导出",
            "会写外部目录且必须提供 PID 与输出目录",
        ),
        skipped(
            "gdi-bitmap",
            "GDI 位图恢复",
            "命令与交互",
            "会写外部 BMP 文件，可按 PID 限定进程",
        ),
        skipped(
            "desktop-reconstruct",
            "桌面状态重建",
            "命令与交互",
            "会写外部 SVG 画布，且可按会话或桌面限定范围",
        ),
        skipped(
            "mftdump",
            "MFT 数据导出",
            "导出",
            "会写外部文件且必须提供记录地址",
        ),
        skipped(
            "dumpfile",
            "文件导出",
            "导出",
            "会写外部文件且必须提供 FILE_OBJECT",
        ),
        skipped("dump-registry", "注册表导出", "导出", "会写外部文件"),
        skipped("dump-logs", "日志导出", "导出", "会写外部文件"),
        skipped(
            "event-timeline",
            "事件时间线",
            "日志",
            "输入是已导出的日志目录，不是内存插件",
        ),
        skipped(
            "sqlite-recover",
            "SQLite 恢复",
            "导出",
            "会写恢复文件和页级清单，必须提供输出目录",
        ),
        skipped(
            "linux.info",
            "Linux 系统信息",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.ir",
            "Linux 应急响应",
            "Linux",
            "按需选择进程/文件应急响应模块；宿主使用 linux_ir::run_task",
        ),
        skipped(
            "linux.ir-kernel",
            "Linux 内核应急响应",
            "Linux",
            "按需选择内核应急响应模块；宿主使用 linux_ir::run_kernel",
        ),
        skipped(
            "linux.kaslr",
            "Linux KASLR",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.cmdline",
            "Linux 命令行",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.psaux",
            "Linux 进程与命令行",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.envars",
            "Linux 环境变量",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.lsof",
            "Linux 打开文件",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.sockstat",
            "Linux Socket",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.proc.maps",
            "Linux 进程内存映射",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.proc.dump",
            "Linux 进程内存导出",
            "Linux",
            "会写外部文件，必须显式提供 PID 和输出目录",
        ),
        skipped(
            "linux.proc.strings",
            "Linux 进程堆栈字符串",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.bash",
            "Linux Bash 历史",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.pstree",
            "Linux 进程树",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.passwd",
            "Linux passwd 恢复",
            "Linux",
            "collect 尚未接入 Linux task-ring session；请定向运行 Linux 命令",
        ),
        skipped(
            "linux.module-extract",
            "Linux 内核模块导出",
            "Linux",
            "必须提供互斥的 --name/--base selector、--output 与 --max-bytes，且会写出 ELF 与 manifest",
        ),
        skipped("symbols.id", "符号身份", "工具", "符号诊断不是自动镜像插件"),
        skipped(
            "symbols.fetch",
            "符号下载",
            "工具",
            "需要显式授权网络和缓存写入",
        ),
        skipped(
            "symbols.search",
            "PDB 搜索",
            "工具",
            "输入是 PDB 文件而不是内存镜像",
        ),
        skipped(
            "symbols.module",
            "模块符号",
            "工具",
            "需要显式模块基址和可选缓存写入",
        ),
        skipped(
            "symbols.linux",
            "Linux ISF 诊断",
            "工具",
            "需要 Linux 镜像和显式 feature/action 参数",
        ),
        skipped("profile", "配置生成", "工具", "配置生成会写外部文件"),
    ]
}

fn collect_process_records<F>(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
    runner: F,
) -> Result<Value>
where
    F: Fn(&AnalysisSession, u64, usize) -> Result<Value>,
{
    let processes = session.processes(65_536)?;
    let process_count = processes.processes.len();
    let budget = options.result_limit.max(process_count);
    let per_process_limit = (budget / process_count.max(1)).max(1);
    let mut complete = processes.complete;
    let mut warnings = to_value(&processes.warnings)?
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut records = Vec::new();
    let mut processes_examined = 0usize;
    for process in &processes.processes {
        processes_examined += 1;
        match runner(session, process.pid, per_process_limit) {
            Ok(mut report) => {
                let Some(object) = report.as_object_mut() else {
                    complete = false;
                    warnings.push(json!({
                        "pid": process.pid,
                        "process": process.name,
                        "error": "进程插件报告不是对象",
                    }));
                    continue;
                };
                complete &= object
                    .get("complete")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                if let Some(Value::Array(plugin_warnings)) = object.remove("warnings") {
                    warnings.extend(plugin_warnings);
                }
                if let Some(Value::Array(mut plugin_records)) = object.remove("records") {
                    records.append(&mut plugin_records);
                }
            }
            Err(error) => {
                complete = false;
                warnings.push(json!({
                    "pid": process.pid,
                    "process": process.name,
                    "error": format!("{error:#}"),
                }));
            }
        }
    }
    Ok(json!({
        "records": records,
        "processes_examined": processes_examined,
        "per_process_limit": per_process_limit,
        "complete": complete,
        "warnings": warnings,
    }))
}

fn collect_process_memmaps(
    session: &AnalysisSession,
    options: &DatabaseCollectionOptions,
) -> Result<Value> {
    let process_report = session.processes(65_536)?;
    let process_count = process_report.processes.len();
    let budget = options.result_limit.max(process_count);
    let per_process_limit = (budget / process_count.max(1)).max(1);
    let mut complete = process_report.complete;
    let mut warnings = to_value(&process_report.warnings)?
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut processes = Vec::new();
    for process in &process_report.processes {
        match session.process_memmap(process.pid, per_process_limit) {
            Ok(report) => {
                let report = to_value(report)?;
                if report
                    .pointer("/mappings/truncated")
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    complete = false;
                }
                processes.push(report);
            }
            Err(error) => {
                complete = false;
                warnings.push(json!({
                    "pid": process.pid,
                    "process": process.name,
                    "error": format!("{error:#}"),
                }));
            }
        }
    }
    Ok(json!({
        "processes": processes,
        "processes_examined": process_count,
        "per_process_limit": per_process_limit,
        "complete": complete,
        "warnings": warnings,
    }))
}

fn plugin(
    name: &'static str,
    display_name: &'static str,
    category: &'static str,
    runner: WindowsPluginRunner,
) -> PluginSpec {
    PluginSpec {
        name,
        display_name,
        category,
        runner: PluginRunner::Windows(runner),
    }
}

fn linux_plugin(
    name: &'static str,
    display_name: &'static str,
    category: &'static str,
    runner: LinuxPluginRunner,
) -> PluginSpec {
    PluginSpec {
        name,
        display_name,
        category,
        runner: PluginRunner::Linux(runner),
    }
}

fn skipped(
    name: &'static str,
    display_name: &'static str,
    category: &'static str,
    reason: &'static str,
) -> SkippedPlugin {
    SkippedPlugin {
        name,
        display_name,
        category,
        reason,
    }
}

fn cookie_options(options: &DatabaseCollectionOptions) -> CookieScanOptions {
    CookieScanOptions {
        limit: options.result_limit,
        database_limit: 256,
        file_scan_limit: options.file_scan_limit,
        max_database_size: options.max_data_size as u64,
        process_space_limit: options.process_space_limit,
    }
}

fn serialize(value: impl Serialize) -> Result<Value> {
    to_value(value).context("无法把插件报告转换为数据库中间结构")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::cancellation::{CancellationHandle, is_cancellation_error};

    use super::*;

    #[test]
    fn catalog_covers_readable_and_explicitly_skipped_commands() {
        let runnable = runnable_plugins();
        let skipped = skipped_plugins();
        assert!(runnable.len() >= 80);
        assert!(runnable.iter().any(|plugin| plugin.name == "clipboardscan"));
        assert!(runnable.iter().any(|plugin| plugin.name == "residualscan"));
        assert!(runnable.iter().any(|plugin| plugin.name == "packetscan"));
        assert!(runnable.iter().any(|plugin| plugin.name == "logonsessions"));
        assert!(
            runnable
                .iter()
                .any(|plugin| plugin.name == "token-anomalies")
        );
        assert!(runnable.iter().any(|plugin| plugin.name == "autoruns"));
        assert!(
            runnable
                .iter()
                .any(|plugin| plugin.name == "screen-resolution")
        );
        for name in [
            "acquisition-info",
            "windows.open-files",
            "pipescan",
            "prefetchscan",
            "windows.timeline",
            "windows.execution",
            "windows.recent-files",
            "usb-history",
            "linux.lsmod",
            "linux.mountinfo",
            "linux.kallsyms",
            "linux.kmsg",
            "linux.modxview",
            "linux.check-syscall",
        ] {
            assert!(
                runnable.iter().any(|plugin| plugin.name == name),
                "missing runnable collection plugin {name}"
            );
        }
        assert!(skipped.iter().any(|plugin| plugin.name == "dumpfile"));
        assert!(skipped.iter().any(|plugin| plugin.name == "pedump"));
        for name in [
            "sqlite-recover",
            "linux.info",
            "linux.kaslr",
            "linux.cmdline",
            "linux.psaux",
            "linux.envars",
            "linux.lsof",
            "linux.sockstat",
            "linux.proc.maps",
            "linux.proc.dump",
            "linux.proc.strings",
            "linux.bash",
            "linux.pstree",
            "linux.passwd",
            "linux.module-extract",
        ] {
            assert!(
                skipped.iter().any(|plugin| plugin.name == name),
                "missing explicit collection skip for {name}"
            );
        }
        let mut names = runnable
            .iter()
            .map(|plugin| plugin.name)
            .chain(skipped.iter().map(|plugin| plugin.name))
            .collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), runnable.len() + skipped.len());

        let complete_catalog = collection_plugin_catalog();
        assert_eq!(complete_catalog.len(), runnable.len() + skipped.len());
        assert!(complete_catalog.iter().all(|plugin| {
            matches!(
                (plugin.disposition, plugin.reason),
                (CollectionPluginDisposition::Runnable, None)
                    | (CollectionPluginDisposition::Skipped, Some(_))
            )
        }));
        let registry = CommandRegistry::load_embedded().unwrap();
        for plugin in &complete_catalog {
            let declared = &registry.by_id(plugin.name).unwrap().collect_disposition;
            assert!(
                matches!(
                    (declared, plugin.disposition),
                    (
                        CollectDisposition::Runnable,
                        CollectionPluginDisposition::Runnable
                    ) | (
                        CollectDisposition::Skipped,
                        CollectionPluginDisposition::Skipped
                    )
                ),
                "collect disposition drift for {}",
                plugin.name
            );
        }

        let public_catalog = readable_plugin_catalog();
        assert_eq!(public_catalog.len(), runnable.len());
        assert!(
            public_catalog
                .iter()
                .any(|plugin| plugin.name == "cookiescan")
        );
        assert!(
            public_catalog
                .iter()
                .any(|plugin| plugin.name == "browser-session")
        );
        assert!(
            public_catalog
                .iter()
                .any(|plugin| plugin.name == "browser-history")
        );
        assert!(
            public_catalog
                .iter()
                .any(|plugin| plugin.name == "cobaltstrikescan")
        );

        let parameterized = parameterized_plugin_catalog();
        assert!(parameterized.iter().any(|plugin| plugin.name == "scan"));
        assert!(parameterized.iter().any(|plugin| plugin.name == "dumpfile"));
        assert!(
            parameterized
                .iter()
                .any(|plugin| plugin.name == "event-timeline")
        );
        assert!(!parameterized.iter().any(|plugin| plugin.name == "symbols"));
        assert!(!parameterized.iter().any(|plugin| plugin.name == "profile"));
        assert!(
            !parameterized
                .iter()
                .any(|plugin| plugin.name == "build-info")
        );
        assert!(
            !parameterized
                .iter()
                .any(|plugin| plugin.name == "linux.info")
        );
        assert!(
            !parameterized
                .iter()
                .any(|plugin| plugin.name == "linux.passwd")
        );
        assert!(
            parameterized
                .iter()
                .any(|plugin| plugin.name == "linux.proc.dump")
        );
        assert!(
            parameterized
                .iter()
                .any(|plugin| plugin.name == "linux.module-extract")
        );
        let actual_parameterized = parameterized
            .iter()
            .map(|plugin| plugin.name)
            .collect::<std::collections::BTreeSet<_>>();
        let declared_parameterized = registry
            .commands
            .values()
            .filter(|contract| contract.command_id != "collect")
            .filter(|contract| contract.collect_parameterized)
            .map(|contract| contract.command_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual_parameterized, declared_parameterized);
    }

    #[test]
    fn collection_result_limit_does_not_replace_source_scan_budgets() {
        let options = DatabaseCollectionOptions {
            database: PathBuf::from("unused.sqlite"),
            session: SessionOptions::default(),
            result_limit: 17,
            file_scan_limit: 23,
            process_space_limit: 5,
            max_data_size: 1024,
        };

        let open_files = collection_open_file_options(&options);
        assert_eq!(open_files.file_scan_limit, 23);
        assert_eq!(open_files.result_limit, 17);
        assert_eq!(
            open_files.process_limit,
            OpenFileOptions::default().process_limit
        );

        let pipes = collection_pipe_options(&options);
        assert_eq!(pipes.file_limit, 23);
        assert_eq!(pipes.limit, 17);
        assert_eq!(
            pipes.process_limit,
            PipeScanOptions::default().process_limit
        );

        let prefetch = collection_prefetch_options(&options);
        assert_eq!(prefetch.file_scan_limit, 23);
        assert_eq!(
            prefetch.file_limit,
            PrefetchScanOptions::default().file_limit,
            "collect --limit must not amplify the Prefetch recovery budget"
        );

        let timeline = collection_timeline_options(&options);
        assert_eq!(timeline.event_limit, 17);
        assert_eq!(
            timeline.process_limit,
            WindowsTimelineOptions::default().process_limit
        );
        assert_eq!(
            timeline.mft_limit,
            WindowsTimelineOptions::default().mft_limit
        );

        let execution = collection_execution_options(&options);
        assert_eq!(execution.file_scan_limit, 23);
        assert_eq!(execution.event_limit, 17);
        assert_eq!(
            execution.prefetch_file_limit,
            WindowsExecutionOptions::default().prefetch_file_limit
        );

        let recent = collection_recent_file_options(&options);
        assert_eq!(recent.record_limit, 17);
        assert_eq!(
            recent.registry_limit,
            WindowsRecentFilesOptions::default().registry_limit
        );
    }

    #[test]
    fn collection_envelope_preserves_plugin_scope_and_observed_limits() {
        let options = DatabaseCollectionOptions {
            database: PathBuf::from("evidence.sqlite"),
            session: SessionOptions::default(),
            result_limit: 17,
            file_scan_limit: 23,
            process_space_limit: 5,
            max_data_size: 1024,
        };
        let source = SourceIdentity {
            format: "lime".to_owned(),
            size: 4096,
            mtime: None,
            sample_digest: DigestReference::new("test", "source"),
            symbol_identity: None,
            components: Vec::new(),
            physical_layout: None,
        };
        let plugin = linux_plugin(
            "linux.lsmod",
            "Linux 内核模块链",
            "Linux",
            |_, _| unreachable!(),
        );
        let report = json!({
            "available": true,
            "complete": false,
            "scope": EvidenceScope::new("linux_kernel_modules_list"),
            "warnings": [],
            "limits": [{
                "name": "modules",
                "kind": "output",
                "configured": 17,
                "observed": 17,
                "reached": true
            }],
            "missing_ranges": [],
            "modules": []
        });
        let envelope = collection_evidence_envelope(plugin, report, &source, &options).unwrap();
        assert_eq!(envelope["scope"]["kind"], "linux_kernel_modules_list");
        assert_eq!(envelope["scope"]["constraints"]["category"], "Linux");
        let modules = envelope["limits"]
            .as_array()
            .unwrap()
            .iter()
            .find(|limit| limit["name"] == "modules")
            .unwrap();
        assert_eq!(modules["observed"], 17);
        assert_eq!(modules["reached"], true);
    }

    #[test]
    fn unavailable_linux_runtime_returns_evidence_instead_of_opening_windows() {
        let options = DatabaseCollectionOptions {
            database: PathBuf::from("evidence.sqlite"),
            session: SessionOptions::default(),
            result_limit: 17,
            file_scan_limit: 23,
            process_space_limit: 5,
            max_data_size: 1024,
        };
        let runtime = CollectionRuntime::Linux {
            opened: None,
            open_error: Some("测试 ISF 不可用".to_owned()),
        };
        let plugin = linux_plugin(
            "linux.kmsg",
            "Linux 内核日志",
            "Linux",
            |_, _| unreachable!(),
        );
        let CollectionPluginAction::Run(Ok(report)) =
            collection_plugin_action(&runtime, plugin, &options, &CancellationToken::new())
        else {
            panic!("Linux 会话不可用应保存 available=false 证据")
        };
        assert_eq!(report["available"], false);
        assert_eq!(report["complete"], false);
        assert_eq!(
            report["warnings"][0]["code"],
            "linux.kernel_session_unavailable"
        );
    }

    #[test]
    fn lime_is_classified_as_linux_without_task_or_symbol_evidence() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-collect-linux-platform-{}-{nonce}.lime",
            std::process::id()
        ));
        let mut bytes = Vec::with_capacity(32 + 4096);
        bytes.extend_from_slice(&0x4c69_4d45_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&0x1000_u64.to_le_bytes());
        bytes.extend_from_slice(&0x1fff_u64.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.resize(32 + 4096, 0);
        fs::write(&path, bytes).unwrap();

        let image = MemoryImage::open(&path).unwrap();
        assert!(matches!(image.format(), ImageFormat::Lime { .. }));
        assert!(has_linux_collection_evidence(&image));
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_without_linux_evidence_routes_to_windows_candidate() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-collect-windows-platform-{}-{nonce}.raw",
            std::process::id()
        ));
        fs::write(&path, [0_u8; 4096]).unwrap();

        let image = MemoryImage::open(&path).unwrap();
        assert!(matches!(image.format(), ImageFormat::Raw));
        assert!(!has_linux_collection_evidence(&image));
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_linux_banner_is_only_a_candidate_until_kernel_validation() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-collect-ambiguous-platform-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0_u8; 4096];
        let banner = b"Linux version 6.8.0-test (builder@example) (gcc) #1 SMP\0";
        bytes[128..128 + banner.len()].copy_from_slice(banner);
        fs::write(&path, bytes).unwrap();

        let image = MemoryImage::open(&path).unwrap();
        assert!(has_linux_collection_evidence(&image));
        // Production routing still requires LinuxKernelSession validation. If that fails and a
        // Windows AnalysisSession validates, Windows wins; the banner alone is never final OS
        // attribution for an ambiguous RAW/VMEM container.
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn readable_catalog_declares_platform_and_linux_runner_route() {
        let catalog = readable_plugin_catalog();
        for name in [
            "linux.lsmod",
            "linux.mountinfo",
            "linux.kallsyms",
            "linux.kmsg",
            "linux.modxview",
            "linux.check-syscall",
        ] {
            let descriptor = catalog
                .iter()
                .find(|descriptor| descriptor.name == name)
                .unwrap();
            assert_eq!(descriptor.platform, ReadablePluginPlatform::Linux);
            assert!(resolve_readable_linux_plugin(name).is_ok());
        }
        let windows = catalog
            .iter()
            .find(|descriptor| descriptor.name == "pslist")
            .unwrap();
        assert_eq!(windows.platform, ReadablePluginPlatform::Windows);
        assert!(resolve_readable_linux_plugin("pslist").is_err());
    }

    #[test]
    fn combined_collection_records_obey_the_total_output_limit() {
        let mut records = vec![1, 2, 3, 4];
        let mut complete = true;
        let mut warnings = Vec::new();
        truncate_collection_records(&mut records, &mut complete, &mut warnings, 2, "PE 符号");
        assert_eq!(records, [1, 2]);
        assert!(!complete);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("恢复 4 条"));

        let mut exact_records = vec![1, 2];
        let mut exact_complete = true;
        let mut exact_warnings = Vec::new();
        truncate_collection_records(
            &mut exact_records,
            &mut exact_complete,
            &mut exact_warnings,
            2,
            "Prefetch",
        );
        assert!(exact_complete);
        assert!(exact_warnings.is_empty());
    }

    #[test]
    fn pre_cancelled_collection_wins_over_image_opening() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let missing_image = std::env::temp_dir().join(format!(
            "starmem-missing-cancelled-image-{}-{nonce}.raw",
            std::process::id()
        ));
        let database = std::env::temp_dir().join(format!(
            "starmem-cancelled-collection-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let options = DatabaseCollectionOptions {
            database: database.clone(),
            session: SessionOptions::default(),
            result_limit: 1,
            file_scan_limit: 1,
            process_space_limit: 1,
            max_data_size: 1,
        };
        let handle = CancellationHandle::new();
        let cancellation = handle.start();
        handle.cancel();

        let error = collect_to_sqlite_cancellable(&missing_image, &options, &cancellation, |_| {})
            .expect_err("pre-cancelled collection must not try to open the image");
        assert!(is_cancellation_error(&error));
        assert!(!database.exists());
    }

    #[test]
    fn collection_cancellation_finalizes_partial_database_state() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let image = std::env::temp_dir().join(format!(
            "starmem-cancel-status-image-{}-{nonce}.raw",
            std::process::id()
        ));
        let database = std::env::temp_dir().join(format!(
            "starmem-cancel-status-{}-{nonce}.sqlite",
            std::process::id()
        ));
        fs::write(&image, [0u8; 16]).unwrap();
        let mut store = SqliteReportStore::create(
            &database,
            &image,
            "raw",
            16,
            16,
            env!("CARGO_PKG_VERSION"),
            90,
        )
        .unwrap();
        let handle = CancellationHandle::new();
        let cancellation = handle.start();
        handle.cancel();

        let error = check_collection_cancellation(&cancellation, &mut store)
            .expect_err("cancelled collection must return a typed error");
        assert!(is_cancellation_error(&error));
        drop(store);

        let connection = rusqlite::Connection::open(&database).unwrap();
        let status: String = connection
            .query_row("SELECT status FROM latest_analysis", [], |row| row.get(0))
            .unwrap();
        assert_eq!(status, "cancelled");
        drop(connection);
        fs::remove_file(database).unwrap();
        fs::remove_file(image).unwrap();
    }
}
