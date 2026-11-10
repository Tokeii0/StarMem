use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::Instant;

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::address::X64AddressSpace;
use crate::cookies::{
    chromium_time, infer_chromium_browser_from_path, infer_chromium_profile_from_path,
    is_chromium_artifact_file_path, parse_sqlite_table, parse_sqlite_table_by_rowids,
    parse_sqlite_table_descending, physical_for_file_offset, recovery_physical_extents, sql_blob,
    sql_integer, sql_text,
};
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::windows::WindowsKernelContext;
use crate::windows::files::{DumpSource, FileScanRecord, FileScanReport, recover_file_bytes};
use crate::windows::plugins::find_handle_owners;

const MAX_WARNING_COUNT: usize = 64;
const MAX_TEXT_LENGTH: usize = 16 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct BrowserArtifactOptions {
    pub result_limit: usize,
    pub database_limit: usize,
    pub max_database_size: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct BrowserArtifactOwnerOptions {
    pub process_limit: usize,
    pub handle_scan_limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserDownloadHistoryRecord {
    pub browser: String,
    pub profile: Option<String>,
    pub download_id: i64,
    pub source_url: Option<String>,
    pub url_chain: Vec<String>,
    pub website: Option<String>,
    pub target_path: Option<String>,
    pub file_name: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub received_bytes: Option<i64>,
    pub total_bytes: Option<i64>,
    pub state: Option<String>,
    pub danger_type: Option<i64>,
    pub interrupt_reason: Option<i64>,
    pub http_method: Option<String>,
    pub referrer: Option<String>,
    pub tab_url: Option<String>,
    pub mime_type: Option<String>,
    pub opened: Option<bool>,
    pub source_file: String,
    pub file_object: u64,
    pub database_rowid: i64,
    pub physical_addresses: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserVisitHistoryRecord {
    pub browser: String,
    pub profile: Option<String>,
    pub url: String,
    pub domain: Option<String>,
    pub title: Option<String>,
    pub url_id: i64,
    /// Legacy Chromium `urls.visit_count` field retained for JSON compatibility.
    pub visit_count: Option<i64>,
    /// Explicit name for Chromium's aggregate count.  This is not the number
    /// of individual `visits` rows StarMem happened to recover, and Chromium
    /// may intentionally apply different accounting rules (for example reloads).
    pub aggregate_visit_count: Option<i64>,
    pub recovered_visit_event_count: usize,
    pub count_status: BrowserVisitCountStatus,
    pub event_recovery_status: BrowserVisitRecoveryStatus,
    pub typed_count: Option<i64>,
    pub last_visit_time: Option<String>,
    pub hidden: Option<bool>,
    pub source_file: String,
    pub file_object: u64,
    pub database_rowid: i64,
    pub physical_addresses: Vec<u64>,
    pub source_database_complete: bool,
    /// PIDs that held this History FILE_OBJECT at capture time.  They are not
    /// automatically promoted to visit actors.
    pub database_handle_owner_pids: Vec<u64>,
    /// Reserved for direct causal attribution.  Handle ownership alone never
    /// populates this field.
    pub visit_actor_pid: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserVisitCountStatus {
    Equal,
    RecoveredBelowAggregate,
    RecoveredAboveAggregate,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserVisitRecoveryStatus {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserSqliteSourceRange {
    pub sqlite_page_number: u32,
    pub file_offset: u64,
    pub length: u64,
    pub physical_address: Option<u64>,
    pub fully_recovered: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserVisitEventRecord {
    pub browser: String,
    pub profile: Option<String>,
    pub visit_id: i64,
    pub url_id: i64,
    pub url: Option<String>,
    pub domain: Option<String>,
    pub title: Option<String>,
    /// Raw Chromium/WebKit microseconds since 1601-01-01 UTC.
    pub visit_time_raw: Option<i64>,
    pub visit_time_utc: Option<String>,
    pub transition_raw: Option<i64>,
    pub transition_core: Option<String>,
    pub transition_qualifiers: Vec<String>,
    pub from_visit_id: Option<i64>,
    pub opener_visit_id: Option<i64>,
    pub visit_duration_microseconds: Option<i64>,
    pub aggregate_visit_count: Option<i64>,
    pub recovered_visit_event_count: usize,
    pub count_status: BrowserVisitCountStatus,
    pub event_recovery_status: BrowserVisitRecoveryStatus,
    pub source_file: String,
    pub file_object: u64,
    pub database_rowid: i64,
    pub sqlite_page_number: u32,
    pub sqlite_page_size: usize,
    pub database_file_offset: u64,
    /// The SQLite record declared a finite payload and its overflow chain was
    /// fully assembled without loops.  This does not by itself prove all bytes
    /// came from resident memory; see `source_bytes_complete`.
    pub parser_payload_complete: bool,
    pub source_bytes_complete: bool,
    pub source_database_complete: bool,
    pub source_ranges: Vec<BrowserSqliteSourceRange>,
    pub physical_addresses: Vec<u64>,
    pub database_handle_owner_pids: Vec<u64>,
    pub visit_actor_pid: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserArtifactOwnerRecord {
    pub artifact_kind: String,
    pub browser: String,
    pub profile: Option<String>,
    pub source_file: String,
    pub file_object: u64,
    pub pid: u64,
    pub process: String,
    pub user_name: Option<String>,
    pub user_sid: Option<String>,
    pub process_create_time: Option<String>,
    pub handle_value: u32,
    pub handle_entry: u64,
    pub object_header: u64,
    pub granted_access: u32,
    pub relationship: String,
    pub observation_time_basis: String,
    pub supports_visit_actor_attribution: bool,
    pub visit_actor_pid: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserArtifactOwnerScan {
    pub complete: bool,
    pub processes_examined: usize,
    pub handle_entries_examined: usize,
    pub targets_examined: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserLoginAccountRecord {
    pub browser: String,
    pub profile: Option<String>,
    pub website: String,
    pub domain: Option<String>,
    pub origin_url: Option<String>,
    pub action_url: Option<String>,
    pub signon_realm: Option<String>,
    pub username: String,
    pub username_kind: String,
    /// 仅表示数据库中存在非空密码密文；绝不导出、解密或序列化密码内容。
    pub password_stored: bool,
    pub date_created: Option<String>,
    pub date_last_used: Option<String>,
    pub times_used: Option<i64>,
    pub confidence: String,
    pub source_file: String,
    pub file_object: u64,
    pub database_rowid: i64,
    pub physical_addresses: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct BrowserArtifactReport {
    pub visit_history: Vec<BrowserVisitHistoryRecord>,
    pub visit_events: Vec<BrowserVisitEventRecord>,
    pub download_history: Vec<BrowserDownloadHistoryRecord>,
    pub login_accounts: Vec<BrowserLoginAccountRecord>,
    pub artifact_owners: Vec<BrowserArtifactOwnerRecord>,
    pub artifact_owner_scan: Option<BrowserArtifactOwnerScan>,
    pub artifact_files_found: usize,
    pub databases_parsed: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
    pub parse_seconds: f64,
}

impl BrowserArtifactReport {
    /// Merge the upstream FILE_OBJECT scan's evidence boundary into this
    /// derived browser report. A complete database parse cannot repair an
    /// incomplete filescan universe, and its warnings remain attributable to
    /// that source.
    pub fn merge_file_scan_status<I>(&mut self, complete: bool, warnings: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.complete &= complete;
        let warning_count = self.warnings.len();
        for warning in warnings {
            push_warning(&mut self.warnings, format!("filescan：{warning}"));
        }
        if !complete && self.warnings.len() == warning_count {
            push_warning(&mut self.warnings, "filescan 报告不完整".to_owned());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ArtifactKind {
    History,
    LoginData,
}

struct ArtifactCandidate {
    kind: ArtifactKind,
    browser: String,
    profile: Option<String>,
    path: String,
    file: FileScanRecord,
}

#[derive(Debug, Clone)]
struct ArtifactIdentity {
    kind: ArtifactKind,
    browser: String,
    profile: Option<String>,
    path: String,
}

pub fn parse_browser_artifacts(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    files: Vec<FileScanRecord>,
    options: &BrowserArtifactOptions,
) -> Result<BrowserArtifactReport> {
    parse_browser_artifacts_with_owners(image, kernel, profile, files, options, None)
}

/// History-only entry point for the `browser-history` command.  Keeping this
/// selection ahead of recovery prevents unrelated Login Data damage and
/// ownership targets from changing a history report's completeness.
pub fn parse_browser_history_artifacts(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    files: Vec<FileScanRecord>,
    options: &BrowserArtifactOptions,
    owner_options: Option<&BrowserArtifactOwnerOptions>,
) -> Result<BrowserArtifactReport> {
    let files = files
        .into_iter()
        .filter(|file| {
            file.name
                .as_deref()
                .map(|path| path.replace('/', "\\"))
                .and_then(|path| path.rsplit('\\').next().map(str::to_owned))
                .is_some_and(|base| base.eq_ignore_ascii_case("history"))
        })
        .collect();
    parse_browser_artifacts_with_owners(image, kernel, profile, files, options, owner_options)
}

/// History-only entry point that consumes the complete filescan report and
/// propagates its completeness/warnings into the derived browser report.
pub fn parse_browser_history_artifacts_from_file_scan(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    files: FileScanReport,
    options: &BrowserArtifactOptions,
    owner_options: Option<&BrowserArtifactOwnerOptions>,
) -> Result<BrowserArtifactReport> {
    let FileScanReport {
        records,
        complete,
        warnings,
        ..
    } = files;
    let mut report =
        parse_browser_history_artifacts(image, kernel, profile, records, options, owner_options)?;
    report.merge_file_scan_status(complete, warnings);
    Ok(report)
}

/// Parse browser databases and, when requested, correlate their exact
/// FILE_OBJECT bodies with active process handle tables.  The original entry
/// point deliberately leaves owner scanning disabled so existing callers keep
/// their cost and output behavior until their CLI/API opts in.
pub fn parse_browser_artifacts_with_owners(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    files: Vec<FileScanRecord>,
    options: &BrowserArtifactOptions,
    owner_options: Option<&BrowserArtifactOwnerOptions>,
) -> Result<BrowserArtifactReport> {
    ensure!(options.result_limit > 0, "浏览器证据结果上限必须大于零");
    ensure!(options.database_limit > 0, "浏览器数据库数量上限必须大于零");
    ensure!(
        options.max_database_size > 0,
        "浏览器数据库最大恢复大小必须大于零"
    );
    if let Some(owner_options) = owner_options {
        ensure!(owner_options.process_limit > 0, "进程扫描上限必须大于零");
        ensure!(
            owner_options.handle_scan_limit > 0,
            "句柄扫描上限必须大于零"
        );
    }
    let started = Instant::now();
    let mut candidates = files
        .into_iter()
        .filter_map(classify_artifact_file)
        .collect::<Vec<_>>();
    candidates.sort_unstable_by(|left, right| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.file.file_object.cmp(&right.file.file_object))
    });
    candidates.dedup_by(|left, right| {
        left.kind == right.kind
            && left.path.eq_ignore_ascii_case(&right.path)
            && left.file.data_section_object == right.file.data_section_object
            && left.file.shared_cache_map == right.file.shared_cache_map
    });
    let artifact_files_found = candidates.len();
    let mut warnings = Vec::new();
    let mut complete = true;
    if candidates.len() > options.database_limit {
        candidates.truncate(options.database_limit);
        complete = false;
        push_warning(
            &mut warnings,
            format!(
                "浏览器 History/Login Data 候选达到 {} 个上限",
                options.database_limit
            ),
        );
    }

    let mut identities_by_object = HashMap::<u64, Vec<ArtifactIdentity>>::new();
    for candidate in &candidates {
        identities_by_object
            .entry(candidate.file.file_object)
            .or_default()
            .push(ArtifactIdentity {
                kind: candidate.kind,
                browser: candidate.browser.clone(),
                profile: candidate.profile.clone(),
                path: candidate.path.clone(),
            });
    }

    let kernel_space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut visit_history = Vec::new();
    let mut visit_events = Vec::new();
    let mut download_history = Vec::new();
    let mut login_accounts = Vec::new();
    let mut databases_parsed = 0usize;
    for candidate in candidates {
        if visit_history.len() >= options.result_limit
            && visit_events.len() >= options.result_limit
            && download_history.len() >= options.result_limit
            && login_accounts.len() >= options.result_limit
        {
            complete = false;
            push_warning(&mut warnings, "浏览器证据结果达到安全上限".to_owned());
            break;
        }
        let recovered = recover_file_bytes(
            image,
            kernel,
            profile,
            candidate.file.file_object,
            DumpSource::Auto,
            options.max_database_size,
        );
        let (dump, bytes) = match recovered {
            Ok(value) => value,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("无法恢复浏览器数据库 {}：{error:#}", candidate.path),
                );
                continue;
            }
        };
        if dump.recovered_bytes == 0 || bytes.is_empty() {
            complete = false;
            push_warning(
                &mut warnings,
                format!("浏览器数据库 {} 没有驻留内容", candidate.path),
            );
            continue;
        }
        if !dump.complete {
            complete = false;
            push_warning(
                &mut warnings,
                format!(
                    "浏览器数据库 {} 仅恢复 {}/{} 字节",
                    candidate.path, dump.recovered_bytes, dump.logical_size
                ),
            );
        }
        let extents = recovery_physical_extents(&dump.extents, &kernel_space);
        let parsed = match candidate.kind {
            ArtifactKind::History => parse_history_database(
                &bytes,
                &candidate,
                &extents,
                dump.complete,
                options.result_limit.saturating_sub(visit_history.len()),
                options.result_limit.saturating_sub(visit_events.len()),
                options.result_limit.saturating_sub(download_history.len()),
            )
            .map(|mut parsed| {
                if !parsed.complete {
                    complete = false;
                }
                for warning in parsed.warnings.drain(..) {
                    push_warning(
                        &mut warnings,
                        format!("浏览器数据库 {}：{warning}", candidate.path),
                    );
                }
                visit_history.append(&mut parsed.visit_history);
                visit_events.append(&mut parsed.visit_events);
                download_history.append(&mut parsed.download_history);
                parsed.damaged_pages
            }),
            ArtifactKind::LoginData => parse_login_database(
                &bytes,
                &candidate,
                &extents,
                options.result_limit.saturating_sub(login_accounts.len()),
            )
            .map(|(mut records, damaged)| {
                login_accounts.append(&mut records);
                damaged
            }),
        };
        match parsed {
            Ok(damaged_pages) => {
                databases_parsed += 1;
                if damaged_pages > 0 {
                    complete = false;
                    push_warning(
                        &mut warnings,
                        format!(
                            "浏览器数据库 {} 有 {damaged_pages} 个 SQLite 页面或单元损坏，已保留其他记录",
                            candidate.path
                        ),
                    );
                }
            }
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("无法解析浏览器数据库 {}：{error:#}", candidate.path),
                );
            }
        }
    }

    visit_history.sort_unstable_by(|left, right| {
        right
            .last_visit_time
            .cmp(&left.last_visit_time)
            .then_with(|| left.browser.cmp(&right.browser))
            .then_with(|| left.url.cmp(&right.url))
    });
    visit_history.dedup_by(|left, right| {
        left.url.eq_ignore_ascii_case(&right.url)
            && left.browser == right.browser
            && left.profile == right.profile
    });
    visit_events.sort_unstable_by(|left, right| {
        right
            .visit_time_raw
            .cmp(&left.visit_time_raw)
            .then_with(|| left.browser.cmp(&right.browser))
            .then_with(|| left.source_file.cmp(&right.source_file))
            .then_with(|| left.visit_id.cmp(&right.visit_id))
    });
    visit_events.dedup_by(|left, right| {
        left.browser == right.browser
            && left.profile == right.profile
            && left.visit_id == right.visit_id
            && left.file_object == right.file_object
            && left.source_file.eq_ignore_ascii_case(&right.source_file)
    });
    download_history.sort_unstable_by(|left, right| {
        right
            .start_time
            .cmp(&left.start_time)
            .then_with(|| left.browser.cmp(&right.browser))
            .then_with(|| left.target_path.cmp(&right.target_path))
    });
    download_history.dedup_by(|left, right| {
        left.browser == right.browser
            && left.profile == right.profile
            && left.download_id == right.download_id
            && left.source_file.eq_ignore_ascii_case(&right.source_file)
    });
    login_accounts.sort_unstable_by(|left, right| {
        left.website
            .cmp(&right.website)
            .then_with(|| left.username.cmp(&right.username))
            .then_with(|| left.browser.cmp(&right.browser))
    });
    login_accounts.dedup_by(|left, right| {
        left.website.eq_ignore_ascii_case(&right.website)
            && left.username.eq_ignore_ascii_case(&right.username)
            && left.browser == right.browser
            && left.profile == right.profile
    });

    let output_truncated = visit_history.len() > options.result_limit
        || visit_events.len() > options.result_limit
        || download_history.len() > options.result_limit
        || login_accounts.len() > options.result_limit;
    if output_truncated {
        complete = false;
        push_warning(&mut warnings, "浏览器证据结果达到安全上限".to_owned());
    }
    visit_history.truncate(options.result_limit);
    visit_events.truncate(options.result_limit);
    download_history.truncate(options.result_limit);
    login_accounts.truncate(options.result_limit);

    let mut artifact_owners = Vec::new();
    let mut artifact_owner_scan = None;
    if let Some(owner_options) = owner_options {
        let targets = identities_by_object.keys().copied().collect::<HashSet<_>>();
        match find_handle_owners(
            image,
            kernel,
            profile,
            &targets,
            owner_options.process_limit,
            owner_options.handle_scan_limit,
        ) {
            Ok(owner_report) => {
                complete &= owner_report.complete;
                for warning in owner_report.warnings.iter() {
                    push_warning(&mut warnings, format!("浏览器数据库句柄归属：{warning}"));
                }
                for owner in &owner_report.records {
                    let Some(identities) = identities_by_object.get(&owner.object) else {
                        continue;
                    };
                    for identity in identities {
                        artifact_owners.push(BrowserArtifactOwnerRecord {
                            artifact_kind: artifact_kind_name(identity.kind).to_owned(),
                            browser: identity.browser.clone(),
                            profile: identity.profile.clone(),
                            source_file: identity.path.clone(),
                            file_object: owner.object,
                            pid: owner.pid,
                            process: owner.process.clone(),
                            user_name: owner.user_name.clone(),
                            user_sid: owner.user_sid.clone(),
                            process_create_time: owner.process_create_time.clone(),
                            handle_value: owner.handle,
                            handle_entry: owner.entry,
                            object_header: owner.object_header,
                            granted_access: owner.granted_access,
                            relationship: "database_handle_owner".to_owned(),
                            observation_time_basis: "memory_capture".to_owned(),
                            supports_visit_actor_attribution: false,
                            visit_actor_pid: None,
                        });
                    }
                }
                artifact_owner_scan = Some(BrowserArtifactOwnerScan {
                    complete: owner_report.complete,
                    processes_examined: owner_report.processes_examined,
                    handle_entries_examined: owner_report.handle_entries_examined,
                    targets_examined: targets.len(),
                });
            }
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("浏览器数据库句柄归属扫描失败：{error:#}"),
                );
                artifact_owner_scan = Some(BrowserArtifactOwnerScan {
                    complete: false,
                    processes_examined: 0,
                    handle_entries_examined: 0,
                    targets_examined: targets.len(),
                });
            }
        }
    }
    artifact_owners.sort_unstable_by(|left, right| {
        left.file_object
            .cmp(&right.file_object)
            .then_with(|| left.pid.cmp(&right.pid))
            .then_with(|| left.handle_value.cmp(&right.handle_value))
            .then_with(|| left.source_file.cmp(&right.source_file))
    });
    artifact_owners.dedup_by(|left, right| {
        left.file_object == right.file_object
            && left.pid == right.pid
            && left.handle_value == right.handle_value
            && left.source_file.eq_ignore_ascii_case(&right.source_file)
    });
    let owner_pids_by_object = artifact_owners.iter().fold(
        HashMap::<u64, BTreeSet<u64>>::new(),
        |mut owners, evidence| {
            owners
                .entry(evidence.file_object)
                .or_default()
                .insert(evidence.pid);
            owners
        },
    );
    for summary in &mut visit_history {
        summary.database_handle_owner_pids = owner_pids_by_object
            .get(&summary.file_object)
            .into_iter()
            .flatten()
            .copied()
            .collect();
    }
    for event in &mut visit_events {
        event.database_handle_owner_pids = owner_pids_by_object
            .get(&event.file_object)
            .into_iter()
            .flatten()
            .copied()
            .collect();
    }
    Ok(BrowserArtifactReport {
        visit_history,
        visit_events,
        download_history,
        login_accounts,
        artifact_owners,
        artifact_owner_scan,
        artifact_files_found,
        databases_parsed,
        complete,
        warnings,
        parse_seconds: started.elapsed().as_secs_f64(),
    })
}

fn classify_artifact_file(file: FileScanRecord) -> Option<ArtifactCandidate> {
    let path = file.name.as_deref()?.replace('/', "\\");
    if !is_chromium_artifact_file_path(&path) {
        return None;
    }
    let kind = match path.rsplit('\\').next()?.to_ascii_lowercase().as_str() {
        "history" => ArtifactKind::History,
        "login data" => ArtifactKind::LoginData,
        _ => return None,
    };
    Some(ArtifactCandidate {
        kind,
        browser: infer_chromium_browser_from_path(&path),
        profile: infer_chromium_profile_from_path(&path),
        path,
        file,
    })
}

struct ParsedHistoryDatabase {
    visit_history: Vec<BrowserVisitHistoryRecord>,
    visit_events: Vec<BrowserVisitEventRecord>,
    download_history: Vec<BrowserDownloadHistoryRecord>,
    damaged_pages: usize,
    complete: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct HistoryUrlDetails {
    url: String,
    domain: Option<String>,
    title: Option<String>,
    aggregate_visit_count: Option<i64>,
}

fn parse_history_database(
    bytes: &[u8],
    candidate: &ArtifactCandidate,
    extents: &[crate::windows::files::RecoveredExtent],
    source_database_complete: bool,
    summary_limit: usize,
    event_limit: usize,
    download_limit: usize,
) -> Result<ParsedHistoryDatabase> {
    let urls = parse_sqlite_table(bytes, &["urls"], summary_limit.max(1));
    // Visit IDs are monotonically allocated by Chromium.  Traverse the table
    // from the largest rowids so a bounded forensic view favors recent events;
    // final presentation is still sorted by the explicit visit timestamp.
    let visits = parse_sqlite_table_descending(bytes, &["visits"], event_limit.max(1));
    let downloads = parse_sqlite_table(bytes, &["downloads"], download_limit.max(1));
    if urls.is_err() && visits.is_err() && downloads.is_err() {
        return Err(anyhow::anyhow!(
            "History 中 urls/visits/downloads 均不可解析：{}",
            urls.as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_else(|| "未知 SQLite 错误".to_owned())
        ));
    }

    let mut damaged_pages = 0usize;
    let mut complete = true;
    let mut warnings = Vec::new();
    let mut visit_history = Vec::new();
    let mut summary_by_url_id = HashMap::<i64, usize>::new();
    let mut url_details_by_id = HashMap::<i64, HistoryUrlDetails>::new();
    if let Ok(urls) = &urls {
        damaged_pages = damaged_pages.saturating_add(urls.damaged_pages);
        if urls.limit_reached {
            complete = false;
            warnings.push(format!("urls 表达到 {summary_limit} 条安全上限"));
        }
        for row in &urls.rows {
            let value = |names: &[&str]| row_value(&row.values, &urls.columns, names);
            let Some(url) = value(&["url"]).and_then(sql_text).and_then(clean_text) else {
                continue;
            };
            let url_id = value(&["id"]).and_then(sql_integer).unwrap_or(row.rowid);
            let aggregate_visit_count = value(&["visit_count"]).and_then(sql_integer);
            let domain = extract_host(&url);
            let title = value(&["title"]).and_then(sql_text).and_then(clean_text);
            summary_by_url_id.insert(url_id, visit_history.len());
            url_details_by_id.insert(
                url_id,
                HistoryUrlDetails {
                    url: url.clone(),
                    domain: domain.clone(),
                    title: title.clone(),
                    aggregate_visit_count,
                },
            );
            visit_history.push(BrowserVisitHistoryRecord {
                browser: candidate.browser.clone(),
                profile: candidate.profile.clone(),
                domain,
                url,
                title,
                url_id,
                visit_count: aggregate_visit_count,
                aggregate_visit_count,
                recovered_visit_event_count: 0,
                count_status: BrowserVisitCountStatus::Unavailable,
                event_recovery_status: BrowserVisitRecoveryStatus::Unavailable,
                typed_count: value(&["typed_count"]).and_then(sql_integer),
                last_visit_time: value(&["last_visit_time"])
                    .and_then(sql_integer)
                    .and_then(chromium_time),
                hidden: value(&["hidden"])
                    .and_then(sql_integer)
                    .map(|value| value != 0),
                source_file: candidate.path.clone(),
                file_object: candidate.file.file_object,
                database_rowid: row.rowid,
                physical_addresses: physical_for_file_offset(extents, row.file_offset)
                    .into_iter()
                    .collect(),
                source_database_complete,
                database_handle_owner_pids: Vec::new(),
                visit_actor_pid: None,
            });
        }
    } else if let Err(error) = &urls {
        complete = false;
        warnings.push(format!("无法解析 urls 表：{error:#}"));
    }

    // The summary and visit views have independent limits and opposite useful
    // traversal order. Resolve only the URL foreign keys referenced by the
    // already bounded visit rows, using direct b-tree rowid lookup rather than
    // retaining the full urls table.
    let required_url_ids = visits
        .as_ref()
        .map(|visits| {
            visits
                .rows
                .iter()
                .filter_map(|row| {
                    row_value(&row.values, &visits.columns, &["url"]).and_then(sql_integer)
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let missing_url_ids = required_url_ids
        .iter()
        .filter(|url_id| !url_details_by_id.contains_key(url_id))
        .copied()
        .collect::<BTreeSet<_>>();
    if !missing_url_ids.is_empty() {
        match parse_sqlite_table_by_rowids(bytes, &["urls"], &missing_url_ids) {
            Ok(lookup) => {
                damaged_pages = damaged_pages.saturating_add(lookup.damaged_pages);
                if lookup.damaged_pages > 0 {
                    complete = false;
                    warnings.push(format!(
                        "urls 外键定向查找遇到 {} 个损坏页面或单元",
                        lookup.damaged_pages
                    ));
                }
                for row in &lookup.rows {
                    let value = |names: &[&str]| row_value(&row.values, &lookup.columns, names);
                    let url_id = value(&["id"]).and_then(sql_integer).unwrap_or(row.rowid);
                    let Some(url) = value(&["url"]).and_then(sql_text).and_then(clean_text) else {
                        continue;
                    };
                    url_details_by_id.insert(
                        url_id,
                        HistoryUrlDetails {
                            domain: extract_host(&url),
                            title: value(&["title"]).and_then(sql_text).and_then(clean_text),
                            aggregate_visit_count: value(&["visit_count"]).and_then(sql_integer),
                            url,
                        },
                    );
                }
                let unresolved = missing_url_ids
                    .iter()
                    .filter(|url_id| !url_details_by_id.contains_key(url_id))
                    .count();
                if unresolved > 0 {
                    complete = false;
                    warnings.push(format!(
                        "visits 表有 {unresolved} 个 url 外键无法从 urls 表定向解析"
                    ));
                }
            }
            Err(error) => {
                complete = false;
                warnings.push(format!("无法定向解析 visits 的 urls 外键：{error:#}"));
            }
        }
    }

    let visits_available = visits.is_ok();
    let visits_complete = visits
        .as_ref()
        .is_ok_and(|table| table.damaged_pages == 0 && !table.limit_reached);
    let mut recovered_by_url_id = HashMap::<i64, usize>::new();
    let mut visit_events = Vec::new();
    match &visits {
        Ok(visits) => {
            damaged_pages = damaged_pages.saturating_add(visits.damaged_pages);
            if visits.limit_reached {
                complete = false;
                warnings.push(format!("visits 表达到 {event_limit} 条安全上限"));
            }
            if visits.damaged_pages > 0 {
                complete = false;
            }
            let mut malformed = 0usize;
            for row in &visits.rows {
                let value = |names: &[&str]| row_value(&row.values, &visits.columns, names);
                let Some(url_id) = value(&["url"]).and_then(sql_integer) else {
                    malformed = malformed.saturating_add(1);
                    continue;
                };
                *recovered_by_url_id.entry(url_id).or_default() += 1;
                let visit_id = value(&["id"]).and_then(sql_integer).unwrap_or(row.rowid);
                let visit_time_raw = value(&["visit_time"]).and_then(sql_integer);
                let transition_raw = value(&["transition"]).and_then(sql_integer);
                let (transition_core, transition_qualifiers) = transition_raw
                    .map(decode_chromium_transition)
                    .map(|(core, qualifiers)| (Some(core), qualifiers))
                    .unwrap_or_else(|| (None, Vec::new()));
                let url_details = url_details_by_id.get(&url_id);
                let source_ranges = browser_source_ranges(extents, &row.source_ranges);
                let source_bytes_complete = !source_ranges.is_empty()
                    && source_ranges.iter().all(|range| range.fully_recovered);
                let physical_addresses = source_ranges
                    .iter()
                    .filter_map(|range| range.physical_address)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                visit_events.push(BrowserVisitEventRecord {
                    browser: candidate.browser.clone(),
                    profile: candidate.profile.clone(),
                    visit_id,
                    url_id,
                    url: url_details.map(|details| details.url.clone()),
                    domain: url_details.and_then(|details| details.domain.clone()),
                    title: url_details.and_then(|details| details.title.clone()),
                    visit_time_raw,
                    visit_time_utc: visit_time_raw.and_then(chromium_time),
                    transition_raw,
                    transition_core,
                    transition_qualifiers,
                    from_visit_id: value(&["from_visit"])
                        .and_then(sql_integer)
                        .filter(|value| *value != 0),
                    opener_visit_id: value(&["opener_visit"])
                        .and_then(sql_integer)
                        .filter(|value| *value != 0),
                    visit_duration_microseconds: value(&["visit_duration"]).and_then(sql_integer),
                    aggregate_visit_count: url_details
                        .and_then(|details| details.aggregate_visit_count),
                    recovered_visit_event_count: 0,
                    count_status: BrowserVisitCountStatus::Unavailable,
                    event_recovery_status: BrowserVisitRecoveryStatus::Unavailable,
                    source_file: candidate.path.clone(),
                    file_object: candidate.file.file_object,
                    database_rowid: row.rowid,
                    sqlite_page_number: row.page_number,
                    sqlite_page_size: visits.page_size,
                    database_file_offset: row.file_offset,
                    parser_payload_complete: true,
                    source_bytes_complete,
                    source_database_complete,
                    source_ranges,
                    physical_addresses,
                    database_handle_owner_pids: Vec::new(),
                    visit_actor_pid: None,
                });
            }
            if malformed > 0 {
                complete = false;
                warnings.push(format!("visits 表有 {malformed} 条记录缺少可用的 url 外键"));
            }
        }
        Err(error) => {
            complete = false;
            warnings.push(format!("无法解析 visits 表：{error:#}"));
        }
    }
    let event_recovery_status = if !visits_available {
        BrowserVisitRecoveryStatus::Unavailable
    } else if visits_complete {
        BrowserVisitRecoveryStatus::Complete
    } else {
        BrowserVisitRecoveryStatus::Partial
    };
    for summary in &mut visit_history {
        let recovered = recovered_by_url_id
            .get(&summary.url_id)
            .copied()
            .unwrap_or(0);
        summary.recovered_visit_event_count = recovered;
        summary.count_status =
            visit_count_status(summary.aggregate_visit_count, recovered, visits_available);
        summary.event_recovery_status = event_recovery_status;
    }
    for event in &mut visit_events {
        let recovered = recovered_by_url_id.get(&event.url_id).copied().unwrap_or(0);
        event.recovered_visit_event_count = recovered;
        event.count_status =
            visit_count_status(event.aggregate_visit_count, recovered, visits_available);
        event.event_recovery_status = if visits_available && event.url.is_none() {
            BrowserVisitRecoveryStatus::Partial
        } else {
            event_recovery_status
        };
    }

    let mut download_history = Vec::new();
    if let Ok(downloads) = &downloads {
        damaged_pages = damaged_pages.saturating_add(downloads.damaged_pages);
        if downloads.limit_reached {
            complete = false;
            warnings.push(format!("downloads 表达到 {download_limit} 条安全上限"));
        }
        let chains = parse_sqlite_table(
            bytes,
            &["downloads_url_chains"],
            download_limit.saturating_mul(8).max(1),
        );
        let mut url_chains = BTreeMap::<i64, Vec<(i64, String)>>::new();
        if let Ok(chains) = chains {
            damaged_pages = damaged_pages.saturating_add(chains.damaged_pages);
            for row in chains.rows {
                let id = row_value(&row.values, &chains.columns, &["id"]).and_then(sql_integer);
                let index = row_value(&row.values, &chains.columns, &["chain_index"])
                    .and_then(sql_integer)
                    .unwrap_or(0);
                let url = row_value(&row.values, &chains.columns, &["url"])
                    .and_then(sql_text)
                    .and_then(clean_text);
                if let (Some(id), Some(url)) = (id, url) {
                    url_chains.entry(id).or_default().push((index, url));
                }
            }
        }
        for chain in url_chains.values_mut() {
            chain.sort_unstable_by_key(|(index, _)| *index);
            chain.dedup_by(|left, right| left.1 == right.1);
        }
        download_history = downloads
            .rows
            .iter()
            .filter_map(|row| {
                let value = |names: &[&str]| row_value(&row.values, &downloads.columns, names);
                let download_id = value(&["id"]).and_then(sql_integer).unwrap_or(row.rowid);
                let chain = url_chains
                    .remove(&download_id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(_, url)| url)
                    .collect::<Vec<_>>();
                let source_url = chain.last().cloned().or_else(|| {
                    value(&["url", "site_url"])
                        .and_then(sql_text)
                        .and_then(clean_text)
                });
                let target_path = value(&["target_path", "current_path", "full_path"])
                    .and_then(sql_text)
                    .and_then(clean_text);
                if source_url.is_none() && target_path.is_none() {
                    return None;
                }
                let website = source_url.as_deref().and_then(extract_host).or_else(|| {
                    value(&["site_url", "tab_url"])
                        .and_then(sql_text)
                        .and_then(extract_host)
                });
                Some(BrowserDownloadHistoryRecord {
                    browser: candidate.browser.clone(),
                    profile: candidate.profile.clone(),
                    download_id,
                    source_url,
                    url_chain: chain,
                    website,
                    file_name: target_path.as_deref().and_then(path_file_name),
                    target_path,
                    start_time: value(&["start_time"])
                        .and_then(sql_integer)
                        .and_then(chromium_time),
                    end_time: value(&["end_time"])
                        .and_then(sql_integer)
                        .and_then(chromium_time),
                    received_bytes: value(&["received_bytes"]).and_then(sql_integer),
                    total_bytes: value(&["total_bytes"]).and_then(sql_integer),
                    state: value(&["state"]).and_then(sql_integer).map(download_state),
                    danger_type: value(&["danger_type"]).and_then(sql_integer),
                    interrupt_reason: value(&["interrupt_reason"]).and_then(sql_integer),
                    http_method: value(&["http_method"])
                        .and_then(sql_text)
                        .and_then(clean_text),
                    referrer: value(&["referrer"]).and_then(sql_text).and_then(clean_text),
                    tab_url: value(&["tab_url"]).and_then(sql_text).and_then(clean_text),
                    mime_type: value(&["mime_type"])
                        .and_then(sql_text)
                        .and_then(clean_text),
                    opened: value(&["opened"])
                        .and_then(sql_integer)
                        .map(|value| value != 0),
                    source_file: candidate.path.clone(),
                    file_object: candidate.file.file_object,
                    database_rowid: row.rowid,
                    physical_addresses: physical_for_file_offset(extents, row.file_offset)
                        .into_iter()
                        .collect(),
                })
            })
            .collect();
    }

    Ok(ParsedHistoryDatabase {
        visit_history,
        visit_events,
        download_history,
        damaged_pages,
        complete,
        warnings,
    })
}

fn artifact_kind_name(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::History => "history",
        ArtifactKind::LoginData => "login_data",
    }
}

fn visit_count_status(
    aggregate: Option<i64>,
    recovered: usize,
    visits_available: bool,
) -> BrowserVisitCountStatus {
    if !visits_available {
        return BrowserVisitCountStatus::Unavailable;
    }
    let Some(aggregate) = aggregate else {
        return BrowserVisitCountStatus::Unavailable;
    };
    let Ok(aggregate) = usize::try_from(aggregate) else {
        return BrowserVisitCountStatus::Unavailable;
    };
    match recovered.cmp(&aggregate) {
        std::cmp::Ordering::Greater => BrowserVisitCountStatus::RecoveredAboveAggregate,
        std::cmp::Ordering::Equal => BrowserVisitCountStatus::Equal,
        std::cmp::Ordering::Less => BrowserVisitCountStatus::RecoveredBelowAggregate,
    }
}

fn browser_source_ranges(
    extents: &[crate::windows::files::RecoveredExtent],
    ranges: &[crate::cookies::SqliteSourceRange],
) -> Vec<BrowserSqliteSourceRange> {
    ranges
        .iter()
        .map(|range| BrowserSqliteSourceRange {
            sqlite_page_number: range.page_number,
            file_offset: range.file_offset,
            length: range.length,
            physical_address: physical_for_file_offset(extents, range.file_offset),
            fully_recovered: file_range_fully_recovered(extents, range.file_offset, range.length),
        })
        .collect()
}

fn file_range_fully_recovered(
    extents: &[crate::windows::files::RecoveredExtent],
    start: u64,
    length: u64,
) -> bool {
    let Some(end) = start.checked_add(length) else {
        return false;
    };
    let mut cursor = start;
    while cursor < end {
        let furthest = extents
            .iter()
            .filter(|extent| extent.memory_kind == "physical" && extent.file_offset <= cursor)
            .filter_map(|extent| extent.file_offset.checked_add(extent.length))
            .filter(|extent_end| *extent_end > cursor)
            .max()
            .unwrap_or(cursor)
            .min(end);
        if furthest == cursor {
            return false;
        }
        cursor = furthest;
    }
    true
}

fn decode_chromium_transition(raw: i64) -> (String, Vec<String>) {
    let raw = raw as u32;
    let core = match raw & 0xff {
        0 => "link",
        1 => "typed",
        2 => "auto_bookmark",
        3 => "auto_subframe",
        4 => "manual_subframe",
        5 => "generated",
        6 => "auto_toplevel",
        7 => "form_submit",
        8 => "reload",
        9 => "keyword",
        10 => "keyword_generated",
        _ => "unknown",
    }
    .to_owned();
    let qualifiers = [
        (0x0080_0000, "blocked"),
        (0x0100_0000, "forward_back"),
        (0x0200_0000, "from_address_bar"),
        (0x0400_0000, "home_page"),
        (0x0800_0000, "from_api"),
        (0x1000_0000, "chain_start"),
        (0x2000_0000, "chain_end"),
        (0x4000_0000, "client_redirect"),
        (0x8000_0000, "server_redirect"),
    ]
    .into_iter()
    .filter(|&(mask, _)| raw & mask != 0)
    .map(|(_, name)| name.to_owned())
    .collect();
    (core, qualifiers)
}

fn parse_login_database(
    bytes: &[u8],
    candidate: &ArtifactCandidate,
    extents: &[crate::windows::files::RecoveredExtent],
    limit: usize,
) -> Result<(Vec<BrowserLoginAccountRecord>, usize)> {
    let logins = parse_sqlite_table(bytes, &["logins"], limit.max(1))?;
    let records = logins
        .rows
        .iter()
        .filter_map(|row| {
            let value = |names: &[&str]| row_value(&row.values, &logins.columns, names);
            if value(&["blacklisted_by_user"])
                .and_then(sql_integer)
                .is_some_and(|value| value != 0)
            {
                return None;
            }
            let username = value(&["username_value"])
                .and_then(sql_text)
                .and_then(clean_username)?;
            let origin_url = value(&["origin_url"])
                .and_then(sql_text)
                .and_then(clean_text);
            let action_url = value(&["action_url"])
                .and_then(sql_text)
                .and_then(clean_text);
            let signon_realm = value(&["signon_realm"])
                .and_then(sql_text)
                .and_then(clean_text);
            let website = signon_realm
                .clone()
                .or_else(|| origin_url.clone())
                .or_else(|| action_url.clone())?;
            let domain = extract_host(&website)
                .or_else(|| origin_url.as_deref().and_then(extract_host))
                .or_else(|| action_url.as_deref().and_then(extract_host));
            Some(BrowserLoginAccountRecord {
                browser: candidate.browser.clone(),
                profile: candidate.profile.clone(),
                website,
                domain,
                origin_url,
                action_url,
                signon_realm,
                username_kind: if username.contains('@') {
                    "email".to_owned()
                } else {
                    "username".to_owned()
                },
                username,
                password_stored: value(&["password_value"])
                    .and_then(sql_blob)
                    .is_some_and(|bytes| !bytes.is_empty()),
                date_created: value(&["date_created"])
                    .and_then(sql_integer)
                    .and_then(chromium_time),
                date_last_used: value(&["date_last_used"])
                    .and_then(sql_integer)
                    .and_then(chromium_time),
                times_used: value(&["times_used"]).and_then(sql_integer),
                confidence: "high".to_owned(),
                source_file: candidate.path.clone(),
                file_object: candidate.file.file_object,
                database_rowid: row.rowid,
                physical_addresses: physical_for_file_offset(extents, row.file_offset)
                    .into_iter()
                    .collect(),
            })
        })
        .collect();
    Ok((records, logins.damaged_pages))
}

fn row_value<'a>(
    values: &'a [crate::cookies::SqlValue],
    columns: &HashMap<String, usize>,
    names: &[&str],
) -> Option<&'a crate::cookies::SqlValue> {
    names
        .iter()
        .find_map(|name| columns.get(*name).and_then(|index| values.get(*index)))
}

fn clean_text(value: &str) -> Option<String> {
    let value =
        value.trim_matches(|character: char| character == '\0' || character.is_whitespace());
    (!value.is_empty() && value.len() <= MAX_TEXT_LENGTH).then(|| value.to_owned())
}

fn clean_username(value: &str) -> Option<String> {
    let value = clean_text(value)?;
    (value.len() <= 4096 && !value.chars().any(char::is_control)).then_some(value)
}

fn extract_host(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let authority = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed)
        .split(['/', '?', '#'])
        .next()?;
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if authority.starts_with('[') {
        authority
            .strip_prefix('[')?
            .split_once(']')
            .map(|(host, _)| host)
            .unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    let host = host.trim_matches('.').to_ascii_lowercase();
    (!host.is_empty() && host.len() <= 255).then_some(host)
}

fn path_file_name(path: &str) -> Option<String> {
    path.rsplit(['\\', '/'])
        .find(|part| !part.is_empty())
        .map(ToOwned::to_owned)
}

fn download_state(value: i64) -> String {
    match value {
        0 => "in_progress",
        1 => "complete",
        2 => "cancelled",
        3 => "interrupted",
        4 => "interrupted",
        _ => "unknown",
    }
    .to_owned()
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNING_COUNT {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::{Connection, params};

    use super::*;

    #[test]
    fn reconstructs_chromium_download_and_login_without_exposing_password() {
        let path = std::env::temp_dir().join(format!(
            "starmem-browser-artifacts-{}-{}.sqlite",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE downloads (
                    id INTEGER PRIMARY KEY, target_path TEXT, start_time INTEGER,
                    received_bytes INTEGER, total_bytes INTEGER, state INTEGER,
                    danger_type INTEGER, interrupt_reason INTEGER, end_time INTEGER,
                    opened INTEGER, referrer TEXT, site_url TEXT, tab_url TEXT,
                    http_method TEXT, mime_type TEXT
                 );
                 CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
                 CREATE TABLE urls (
                    id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
                    typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER
                 );
                 CREATE TABLE logins (
                    origin_url TEXT, action_url TEXT, username_value TEXT,
                    password_value BLOB, signon_realm TEXT, date_created INTEGER,
                    blacklisted_by_user INTEGER, times_used INTEGER, date_last_used INTEGER
                 );",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO urls VALUES (1, ?1, ?2, 5, 2, ?3, 0)",
                params![
                    "https://portal.example.test/dashboard",
                    "Portal Dashboard",
                    13_300_000_030_000_000i64
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO downloads VALUES (1, ?1, ?2, 4096, 4096, 1, 0, 0, ?3, 1, ?4, ?5, ?6, 'GET', 'application/pdf')",
                params![
                    r"C:\Users\Alice\Downloads\report.pdf",
                    13_300_000_000_000_000i64,
                    13_300_000_010_000_000i64,
                    "https://portal.example.test/",
                    "https://portal.example.test/files",
                    "https://portal.example.test/files"
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO downloads_url_chains VALUES (1, 0, 'https://portal.example.test/start')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO downloads_url_chains VALUES (1, 1, 'https://cdn.example.test/report.pdf')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO logins VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 7, ?7)",
                params![
                    "https://portal.example.test/login",
                    "https://portal.example.test/session",
                    "alice@example.test",
                    b"v10\x01\x02\x03".as_slice(),
                    "https://portal.example.test/",
                    13_300_000_000_000_000i64,
                    13_300_000_020_000_000i64
                ],
            )
            .unwrap();
        drop(connection);
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(path).unwrap();
        let history = candidate(ArtifactKind::History, "History");
        let parsed = parse_history_database(&bytes, &history, &[], true, 10, 10, 10).unwrap();
        assert_eq!(parsed.visit_history.len(), 1);
        assert_eq!(
            parsed.visit_history[0].domain.as_deref(),
            Some("portal.example.test")
        );
        assert_eq!(
            parsed.visit_history[0].title.as_deref(),
            Some("Portal Dashboard")
        );
        assert_eq!(parsed.visit_history[0].visit_count, Some(5));
        assert_eq!(parsed.download_history.len(), 1);
        assert_eq!(
            parsed.download_history[0].file_name.as_deref(),
            Some("report.pdf")
        );
        assert_eq!(
            parsed.download_history[0].website.as_deref(),
            Some("cdn.example.test")
        );
        assert_eq!(parsed.download_history[0].url_chain.len(), 2);
        assert_eq!(
            parsed.download_history[0].state.as_deref(),
            Some("complete")
        );

        let login = candidate(ArtifactKind::LoginData, "Login Data");
        let (accounts, _) = parse_login_database(&bytes, &login, &[], 10).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].domain.as_deref(), Some("portal.example.test"));
        assert_eq!(accounts[0].username, "alice@example.test");
        assert!(accounts[0].password_stored);
        let serialized = serde_json::to_string(&accounts[0]).unwrap();
        assert!(!serialized.contains("763130010203"));
        assert!(parsed.visit_events.is_empty());
        assert_eq!(
            parsed.visit_history[0].count_status,
            BrowserVisitCountStatus::Unavailable
        );
        assert!(!parsed.complete);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.contains("visits"))
        );
    }

    #[test]
    fn reconstructs_two_chromium_visit_events_with_exact_count_and_provenance() {
        let path = std::env::temp_dir().join(format!(
            "starmem-browser-visits-{}-{}.sqlite",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE urls (
                    id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
                    typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER
                 );
                 CREATE TABLE visits (
                    id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
                    from_visit INTEGER, transition INTEGER, segment_id INTEGER,
                    visit_duration INTEGER, opener_visit INTEGER
                 );",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO urls VALUES (58, ?1, ?2, 2, 0, ?3, 0)",
                params![
                    "http://vip.licai.com:8083/AdminV9YY/Login",
                    "后台登录-维斯塔斯风力技术（中国）有限公司",
                    13_331_753_817_175_636i64
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO visits VALUES (111, 58, ?1, 0, ?2, 0, 1250000, 0)",
                params![13_331_751_330_689_976i64, 0x1000_0001i64],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO visits VALUES (112, 58, ?1, 111, ?2, 0, 2500000, 0)",
                params![13_331_753_817_175_636i64, 0x0100_0000i64],
            )
            .unwrap();
        drop(connection);
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(path).unwrap();

        let history = candidate(ArtifactKind::History, "History");
        let parsed = parse_history_database(&bytes, &history, &[], true, 100, 100, 100).unwrap();
        assert_eq!(parsed.visit_history.len(), 1);
        assert_eq!(parsed.visit_events.len(), 2);
        assert_eq!(parsed.visit_events[0].visit_id, 112);
        let summary = &parsed.visit_history[0];
        assert_eq!(summary.url_id, 58);
        assert_eq!(summary.visit_count, Some(2));
        assert_eq!(summary.aggregate_visit_count, Some(2));
        assert_eq!(summary.recovered_visit_event_count, 2);
        assert_eq!(summary.count_status, BrowserVisitCountStatus::Equal);
        assert_eq!(
            summary.event_recovery_status,
            BrowserVisitRecoveryStatus::Complete
        );

        let last = parsed
            .visit_events
            .iter()
            .find(|event| event.visit_id == 112)
            .unwrap();
        assert_eq!(last.url_id, 58);
        assert_eq!(
            last.url.as_deref(),
            Some("http://vip.licai.com:8083/AdminV9YY/Login")
        );
        assert_eq!(
            last.title.as_deref(),
            Some("后台登录-维斯塔斯风力技术（中国）有限公司")
        );
        assert_eq!(last.visit_time_raw, Some(13_331_753_817_175_636));
        assert_eq!(
            last.visit_time_utc.as_deref(),
            Some("2023-06-20T16:56:57.175636+00:00")
        );
        assert_eq!(last.from_visit_id, Some(111));
        assert_eq!(last.transition_core.as_deref(), Some("link"));
        assert_eq!(last.transition_qualifiers, vec!["forward_back".to_owned()]);
        assert_eq!(last.visit_duration_microseconds, Some(2_500_000));
        assert_eq!(last.recovered_visit_event_count, 2);
        assert_eq!(last.count_status, BrowserVisitCountStatus::Equal);
        assert!(last.sqlite_page_number > 0);
        assert_eq!(last.sqlite_page_size, 4096);
        assert!(last.database_file_offset < bytes.len() as u64);
        assert!(last.parser_payload_complete);
        assert!(!last.source_bytes_complete);
        assert!(last.source_database_complete);
        assert!(!last.source_ranges.is_empty());
        assert!(last.database_handle_owner_pids.is_empty());
        assert_eq!(last.visit_actor_pid, None);

        let first = parsed
            .visit_events
            .iter()
            .find(|event| event.visit_id == 111)
            .unwrap();
        assert_eq!(first.transition_core.as_deref(), Some("typed"));
        assert_eq!(first.transition_qualifiers, vec!["chain_start".to_owned()]);
    }

    #[test]
    fn bounded_latest_visit_resolves_url_outside_summary_window() {
        let path = std::env::temp_dir().join(format!(
            "starmem-browser-visit-url-lookup-{}-{}.sqlite",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE urls (
                    id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
                    typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER
                 );
                 CREATE TABLE visits (
                    id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
                    from_visit INTEGER, transition INTEGER, segment_id INTEGER,
                    visit_duration INTEGER, opener_visit INTEGER
                 );",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO urls VALUES (1, ?1, ?2, 1, 0, ?3, 0)",
                params![
                    "https://old.example.test/",
                    "Old page",
                    13_331_751_000_000_000i64
                ],
            )
            .unwrap();
        connection.execute_batch("BEGIN").unwrap();
        for url_id in 2..999i64 {
            if url_id == 500 {
                continue;
            }
            connection
                .execute(
                    "INSERT INTO urls VALUES (?1, ?2, ?3, 1, 0, ?4, 0)",
                    params![
                        url_id,
                        format!("https://filler.example.test/page/{url_id:04}"),
                        format!("Filler page {url_id:04}"),
                        13_331_751_000_000_000i64 + url_id
                    ],
                )
                .unwrap();
        }
        connection.execute_batch("COMMIT").unwrap();
        connection
            .execute(
                "INSERT INTO urls VALUES (500, ?1, ?2, 1, 0, ?3, 0)",
                params![
                    "https://latest.example.test/dashboard",
                    "Latest dashboard",
                    13_331_753_817_175_636i64
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO visits VALUES (1, 1, ?1, 0, 0, 0, 0, 0)",
                params![13_331_751_000_000_000i64],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO visits VALUES (2, 500, ?1, 1, 0, 0, 0, 0)",
                params![13_331_753_817_175_636i64],
            )
            .unwrap();
        drop(connection);
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(path).unwrap();

        let history = candidate(ArtifactKind::History, "History");
        let parsed = parse_history_database(&bytes, &history, &[], true, 1, 1, 1).unwrap();

        assert_eq!(parsed.visit_history.len(), 1);
        assert_eq!(parsed.visit_history[0].url_id, 1);
        assert_eq!(parsed.visit_events.len(), 1);
        let latest = &parsed.visit_events[0];
        assert_eq!(latest.visit_id, 2);
        assert_eq!(latest.url_id, 500);
        assert_eq!(
            latest.url.as_deref(),
            Some("https://latest.example.test/dashboard")
        );
        assert_eq!(latest.domain.as_deref(), Some("latest.example.test"));
        assert_eq!(latest.title.as_deref(), Some("Latest dashboard"));
        assert_eq!(latest.aggregate_visit_count, Some(1));
        assert_eq!(latest.recovered_visit_event_count, 1);
        assert_eq!(latest.count_status, BrowserVisitCountStatus::Equal);
        assert_eq!(
            latest.event_recovery_status,
            BrowserVisitRecoveryStatus::Partial
        );
        assert!(!parsed.complete);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.contains("urls 表达到 1 条安全上限"))
        );
        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.contains("visits 表达到 1 条安全上限"))
        );
    }

    #[test]
    fn exact_fit_visit_limit_remains_complete() {
        let path = std::env::temp_dir().join(format!(
            "starmem-browser-visit-exact-fit-{}-{}.sqlite",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE urls (
                    id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
                    typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER
                 );
                 CREATE TABLE visits (
                    id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
                    from_visit INTEGER, transition INTEGER, segment_id INTEGER,
                    visit_duration INTEGER, opener_visit INTEGER
                 );
                 INSERT INTO urls VALUES (
                    7, 'https://one.example.test/', 'One page', 1,
                    0, 13331753817175636, 0
                 );
                 INSERT INTO visits VALUES (
                    9, 7, 13331753817175636, 0, 0, 0, 0, 0
                 );",
            )
            .unwrap();
        drop(connection);
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(path).unwrap();

        let history = candidate(ArtifactKind::History, "History");
        let parsed = parse_history_database(&bytes, &history, &[], true, 1, 1, 1).unwrap();

        assert!(parsed.complete);
        assert_eq!(parsed.visit_history.len(), 1);
        assert_eq!(parsed.visit_events.len(), 1);
        assert_eq!(
            parsed.visit_events[0].event_recovery_status,
            BrowserVisitRecoveryStatus::Complete
        );
        assert!(
            parsed
                .warnings
                .iter()
                .all(|warning| !warning.contains("达到 1 条安全上限"))
        );
    }

    #[test]
    fn merges_incomplete_file_scan_status_into_browser_report() {
        let mut report = BrowserArtifactReport {
            visit_history: Vec::new(),
            visit_events: Vec::new(),
            download_history: Vec::new(),
            login_accounts: Vec::new(),
            artifact_owners: Vec::new(),
            artifact_owner_scan: None,
            artifact_files_found: 0,
            databases_parsed: 0,
            complete: true,
            warnings: Vec::new(),
            parse_seconds: 0.0,
        };

        report.merge_file_scan_status(false, ["达到 FILE_OBJECT 上限".to_owned()]);

        assert!(!report.complete);
        assert_eq!(
            report.warnings,
            vec!["filescan：达到 FILE_OBJECT 上限".to_owned()]
        );
    }

    #[test]
    fn keeps_aggregate_and_recovered_count_semantics_separate() {
        assert_eq!(
            visit_count_status(Some(5), 2, true),
            BrowserVisitCountStatus::RecoveredBelowAggregate
        );
        assert_eq!(
            visit_count_status(Some(2), 3, true),
            BrowserVisitCountStatus::RecoveredAboveAggregate
        );
        assert_eq!(
            visit_count_status(Some(2), 2, true),
            BrowserVisitCountStatus::Equal
        );
        assert_eq!(
            visit_count_status(Some(2), 0, false),
            BrowserVisitCountStatus::Unavailable
        );
    }

    #[test]
    fn filters_empty_and_blacklisted_login_rows() {
        assert_eq!(clean_username("   "), None);
        assert_eq!(clean_username("alice"), Some("alice".to_owned()));
        assert_eq!(
            extract_host("https://User@example.test:443/path"),
            Some("example.test".to_owned())
        );
    }

    fn candidate(kind: ArtifactKind, base: &str) -> ArtifactCandidate {
        ArtifactCandidate {
            kind,
            browser: "Chrome".to_owned(),
            profile: Some("Default".to_owned()),
            path: format!(r"\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\{base}"),
            file: FileScanRecord {
                file_object: 0xffff_8000_0000_1000,
                physical_address: 0x1000,
                object_header: 0xffff_8000_0000_0fd0,
                pool_header_physical: 0xf80,
                pool_allocation_size: 0x150,
                name: None,
                device_object: 0,
                section_object_pointer: 0,
                data_section_object: 0,
                shared_cache_map: 0,
                image_section_object: 0,
                flags: 0,
                delete_pending: false,
                object_type_verified: true,
            },
        }
    }
}
