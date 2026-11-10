use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::Instant;

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::address::{VirtualAddressRegion, X64AddressSpace};
use crate::browser_artifacts::{
    BrowserArtifactOptions, BrowserArtifactOwnerOptions, BrowserArtifactOwnerRecord,
    BrowserArtifactOwnerScan, BrowserDownloadHistoryRecord, BrowserLoginAccountRecord,
    BrowserVisitEventRecord, BrowserVisitHistoryRecord, parse_browser_artifacts_with_owners,
};
use crate::cookies::{
    BrowserCookieRecord, CookieScanOptions, CookieScanStage, infer_browser_from_process_context,
};
use crate::downloads::{DownloadOwner, DownloadTraceRecord, scan_download_traces};
use crate::session::AnalysisSession;

const PROCESS_ENUMERATION_LIMIT: usize = 65_536;
const MAX_DOWNLOAD_OWNERS: usize = 8;
const MAX_WARNING_COUNT: usize = 128;

#[derive(Debug, Clone, Copy)]
pub struct BrowserSessionOptions {
    pub session_limit: usize,
    pub download_limit: usize,
    pub cookie: CookieScanOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserSessionStage {
    CookieRuntimeHeaders,
    CookieFileObjects,
    CookieDatabases,
    CookieOwners,
    BrowserDatabases,
    DownloadTraces,
    DownloadOwners,
    Aggregate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserSessionKind {
    Process,
    Profile,
    Browser,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserProcessRecord {
    pub browser: String,
    pub pid: u64,
    pub ppid: Option<u64>,
    pub process: String,
    pub user_sid: Option<String>,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
    pub configuration_directory: Option<String>,
    pub profile: Option<String>,
    pub process_create_time: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BrowserSessionRecord {
    pub kind: BrowserSessionKind,
    pub browser: String,
    pub profile: Option<String>,
    pub configuration_directory: Option<String>,
    pub pid: Option<u64>,
    pub process: Option<String>,
    pub user_sid: Option<String>,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
    pub process_create_time: Option<String>,
    pub time_basis: String,
    pub confidence: String,
    pub cookie_indices: Vec<usize>,
    pub download_indices: Vec<usize>,
    pub domains: Vec<String>,
    pub evidence_count: usize,
}

#[derive(Debug, Serialize)]
pub struct BrowserDomainRelation {
    pub download_host: String,
    pub cookie_domains: Vec<String>,
    pub cookie_indices: Vec<usize>,
    pub download_indices: Vec<usize>,
    pub session_indices: Vec<usize>,
    pub relation_basis: String,
}

#[derive(Debug, Serialize)]
pub struct BrowserSessionStatistics {
    pub runtime_cookie_header_hits: usize,
    pub cookie_files_found: usize,
    pub cookie_databases_parsed: usize,
    pub cookie_process_address_spaces: usize,
    pub browser_artifact_files_found: usize,
    pub browser_artifact_databases_parsed: usize,
    pub browser_visit_history_records: usize,
    pub browser_visit_event_records: usize,
    pub browser_download_history_records: usize,
    pub browser_login_accounts: usize,
    pub browser_artifact_owner_records: usize,
    pub raw_download_url_hits: usize,
    pub download_process_address_spaces: usize,
    pub bytes_scanned: u64,
}

#[derive(Debug, Serialize)]
pub struct BrowserSessionTiming {
    pub cookie_seconds: f64,
    pub browser_database_seconds: f64,
    pub download_seconds: f64,
    pub download_owner_mapping_seconds: f64,
    pub aggregation_seconds: f64,
    pub total_seconds: f64,
}

#[derive(Debug, Serialize)]
pub struct BrowserSessionReport {
    pub sessions: Vec<BrowserSessionRecord>,
    pub browser_processes: Vec<BrowserProcessRecord>,
    pub cookies: Vec<BrowserCookieRecord>,
    pub downloads: Vec<DownloadTraceRecord>,
    /// Chromium History 数据库中的 URL 访问历史。
    pub visit_history: Vec<BrowserVisitHistoryRecord>,
    /// Chromium `visits` 表中的逐次访问事件；数据库句柄所有者不等于访问者。
    pub visit_events: Vec<BrowserVisitEventRecord>,
    /// Chromium History 数据库中重组出的下载记录及 URL 跳转链。
    pub download_history: Vec<BrowserDownloadHistoryRecord>,
    /// Chromium Login Data 中的站点和明文用户名；不包含密码值或密码密文。
    pub login_accounts: Vec<BrowserLoginAccountRecord>,
    /// 抓取时持有浏览器数据库 FILE_OBJECT 的进程句柄证据。
    pub artifact_owners: Vec<BrowserArtifactOwnerRecord>,
    pub artifact_owner_scan: Option<BrowserArtifactOwnerScan>,
    /// `downloads` 中从零开始的索引；对应记录没有可证明的浏览器进程地址空间归属。
    pub unassigned_downloads: Vec<usize>,
    pub domain_relations: Vec<BrowserDomainRelation>,
    pub complete: bool,
    pub warnings: Vec<String>,
    pub statistics: BrowserSessionStatistics,
    pub timing: BrowserSessionTiming,
}

#[derive(Debug)]
struct AddressSpaceCandidate {
    dtb: u64,
    working_set: u64,
    owners: Vec<DownloadOwner>,
}

#[derive(Debug)]
struct BrowserProcessContext {
    processes: Vec<BrowserProcessRecord>,
    address_spaces: Vec<AddressSpaceCandidate>,
    complete: bool,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct SessionBuilder {
    kind: BrowserSessionKind,
    browser: String,
    profile: Option<String>,
    configuration_directory: Option<String>,
    pid: Option<u64>,
    process: Option<String>,
    user_sid: Option<String>,
    image_path: Option<String>,
    command_line: Option<String>,
    process_create_time: Option<String>,
    time_basis: String,
    confidence: String,
    cookies: BTreeSet<usize>,
    downloads: BTreeSet<usize>,
    domains: BTreeSet<String>,
}

pub fn reconstruct_browser_sessions<F>(
    session: &AnalysisSession,
    options: &BrowserSessionOptions,
    progress: F,
) -> Result<BrowserSessionReport>
where
    F: FnMut(BrowserSessionStage),
{
    reconstruct_browser_sessions_with_artifact_owners(session, options, None, progress)
}

pub fn reconstruct_browser_sessions_with_artifact_owners<F>(
    session: &AnalysisSession,
    options: &BrowserSessionOptions,
    artifact_owner_options: Option<&BrowserArtifactOwnerOptions>,
    mut progress: F,
) -> Result<BrowserSessionReport>
where
    F: FnMut(BrowserSessionStage),
{
    ensure!(
        options.session_limit > 0,
        "浏览器会话结果数量上限必须大于零"
    );
    ensure!(options.download_limit > 0, "下载痕迹结果数量上限必须大于零");
    let started = Instant::now();

    let mut cookie_report = session.cookie_scan(&options.cookie, |stage| {
        progress(match stage {
            CookieScanStage::RuntimeHeaders => BrowserSessionStage::CookieRuntimeHeaders,
            CookieScanStage::FileObjects => BrowserSessionStage::CookieFileObjects,
            CookieScanStage::Databases => BrowserSessionStage::CookieDatabases,
            CookieScanStage::ProcessOwners => BrowserSessionStage::CookieOwners,
        });
    })?;
    let cookie_seconds = cookie_report.scan_seconds;

    progress(BrowserSessionStage::BrowserDatabases);
    let artifact_report = parse_browser_artifacts_with_owners(
        session.image(),
        session.kernel(),
        session.profile(),
        std::mem::take(&mut cookie_report.browser_artifact_files),
        &BrowserArtifactOptions {
            result_limit: options
                .session_limit
                .max(options.download_limit)
                .max(options.cookie.limit),
            database_limit: options.cookie.database_limit,
            max_database_size: options.cookie.max_database_size,
        },
        artifact_owner_options,
    )?;

    progress(BrowserSessionStage::DownloadTraces);
    let download_started = Instant::now();
    let mut download_report = scan_download_traces(session.image(), options.download_limit)?;
    let download_seconds = download_started.elapsed().as_secs_f64();

    progress(BrowserSessionStage::DownloadOwners);
    let mapping_started = Instant::now();
    let process_context = browser_process_context(session)?;
    let mut browser_processes = process_context.processes;
    let mut address_spaces = process_context.address_spaces;
    let (mapping_complete, mapped_address_spaces, mapping_warnings) = map_download_owners(
        session,
        &mut download_report.records,
        &mut address_spaces,
        options.cookie.process_space_limit,
    );
    let download_owner_mapping_seconds = mapping_started.elapsed().as_secs_f64();

    progress(BrowserSessionStage::Aggregate);
    let aggregation_started = Instant::now();
    browser_processes.sort_unstable_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.process.cmp(&right.process))
    });
    let process_by_pid = browser_processes
        .iter()
        .cloned()
        .map(|process| (process.pid, process))
        .collect::<HashMap<_, _>>();
    let (sessions, sessions_truncated, aggregation_warnings) = aggregate_sessions(
        &cookie_report.records,
        &download_report.records,
        &process_by_pid,
        options.session_limit,
    );
    let unassigned_downloads = download_report
        .records
        .iter()
        .enumerate()
        .filter_map(|(index, record)| record.owners.is_empty().then_some(index))
        .collect::<Vec<_>>();
    let domain_relations =
        build_domain_relations(&cookie_report.records, &download_report.records, &sessions);
    let aggregation_seconds = aggregation_started.elapsed().as_secs_f64();

    let complete = cookie_report.complete
        && artifact_report.complete
        && download_report.complete
        && process_context.complete
        && mapping_complete
        && !sessions_truncated;
    let mut warnings = Vec::new();
    extend_warnings(
        &mut warnings,
        cookie_report
            .warnings
            .iter()
            .map(|warning| format!("Cookie 扫描：{warning}")),
    );
    extend_warnings(
        &mut warnings,
        artifact_report
            .warnings
            .iter()
            .map(|warning| format!("浏览器数据库：{warning}")),
    );
    extend_warnings(
        &mut warnings,
        download_report
            .warnings
            .iter()
            .map(|warning| format!("下载扫描：{warning}")),
    );
    extend_warnings(&mut warnings, process_context.warnings);
    extend_warnings(&mut warnings, mapping_warnings);
    extend_warnings(&mut warnings, aggregation_warnings);

    let statistics = BrowserSessionStatistics {
        runtime_cookie_header_hits: cookie_report.runtime_header_hits,
        cookie_files_found: cookie_report.cookie_files_found,
        cookie_databases_parsed: cookie_report.cookie_databases_parsed,
        cookie_process_address_spaces: cookie_report.process_address_spaces,
        browser_artifact_files_found: artifact_report.artifact_files_found,
        browser_artifact_databases_parsed: artifact_report.databases_parsed,
        browser_visit_history_records: artifact_report.visit_history.len(),
        browser_visit_event_records: artifact_report.visit_events.len(),
        browser_download_history_records: artifact_report.download_history.len(),
        browser_login_accounts: artifact_report.login_accounts.len(),
        browser_artifact_owner_records: artifact_report.artifact_owners.len(),
        raw_download_url_hits: download_report.raw_url_hits,
        download_process_address_spaces: mapped_address_spaces,
        bytes_scanned: cookie_report
            .bytes_scanned
            .saturating_add(download_report.bytes_scanned),
    };
    let timing = BrowserSessionTiming {
        cookie_seconds,
        browser_database_seconds: artifact_report.parse_seconds,
        download_seconds,
        download_owner_mapping_seconds,
        aggregation_seconds,
        total_seconds: started.elapsed().as_secs_f64(),
    };

    Ok(BrowserSessionReport {
        sessions,
        browser_processes,
        cookies: cookie_report.records,
        downloads: download_report.records,
        visit_history: artifact_report.visit_history,
        visit_events: artifact_report.visit_events,
        download_history: artifact_report.download_history,
        login_accounts: artifact_report.login_accounts,
        artifact_owners: artifact_report.artifact_owners,
        artifact_owner_scan: artifact_report.artifact_owner_scan,
        unassigned_downloads,
        domain_relations,
        complete,
        warnings,
        statistics,
        timing,
    })
}

fn browser_process_context(session: &AnalysisSession) -> Result<BrowserProcessContext> {
    let report = session.processes(PROCESS_ENUMERATION_LIMIT)?;
    let mut processes = Vec::new();
    let mut spaces = BTreeMap::<u64, AddressSpaceCandidate>::new();
    for process in report.processes {
        let Some(browser) = infer_browser_from_process_context(
            &process.name,
            process.details.image_path.as_deref(),
            process.details.command_line.as_deref(),
        ) else {
            continue;
        };
        let configuration_directory = process
            .details
            .command_line
            .as_deref()
            .and_then(|line| command_line_option(line, "--user-data-dir"));
        let profile = process
            .details
            .command_line
            .as_deref()
            .and_then(|line| command_line_option(line, "--profile-directory"));
        let record = BrowserProcessRecord {
            browser: browser.clone(),
            pid: process.pid,
            ppid: process.ppid,
            process: process.name.clone(),
            user_sid: process.details.user_sid.clone(),
            image_path: process.details.image_path.clone(),
            command_line: process.details.command_line.clone(),
            configuration_directory,
            profile,
            process_create_time: process.details.create_time.clone(),
        };
        if let Some(dtb) = process
            .details
            .user_directory_table_base
            .or(process.details.directory_table_base)
            .map(|value| value & 0x000f_ffff_ffff_f000)
            .filter(|value| *value != 0)
        {
            let owner = DownloadOwner {
                pid: process.pid,
                process: process.name,
                browser,
                virtual_address: 0,
            };
            let entry = spaces.entry(dtb).or_insert_with(|| AddressSpaceCandidate {
                dtb,
                working_set: 0,
                owners: Vec::new(),
            });
            entry.working_set = entry
                .working_set
                .max(process.details.working_set_private_size.unwrap_or(0));
            entry.owners.push(owner);
        }
        processes.push(record);
    }
    let warnings = report
        .warnings
        .into_iter()
        .map(|warning| {
            format!(
                "浏览器进程枚举：{}{}",
                process_warning_name(&warning.kind),
                warning
                    .list_entry
                    .map(|entry| format!("（链表项 {entry:#x}）"))
                    .unwrap_or_default()
            )
        })
        .collect();
    Ok(BrowserProcessContext {
        processes,
        address_spaces: spaces.into_values().collect(),
        complete: report.complete,
        warnings,
    })
}

fn map_download_owners(
    session: &AnalysisSession,
    records: &mut [DownloadTraceRecord],
    address_spaces: &mut Vec<AddressSpaceCandidate>,
    process_space_limit: usize,
) -> (bool, usize, Vec<String>) {
    let mut complete = true;
    let mut warnings = Vec::new();
    let targets = records
        .iter()
        .flat_map(|record| record.physical_addresses.iter())
        .map(|address| address & !0xfff)
        .collect::<HashSet<_>>();
    if targets.is_empty() || address_spaces.is_empty() {
        return (complete, 0, warnings);
    }
    address_spaces.sort_unstable_by(|left, right| {
        right
            .working_set
            .cmp(&left.working_set)
            .then_with(|| left.dtb.cmp(&right.dtb))
    });
    if address_spaces.len() > process_space_limit {
        complete = false;
        warnings.push(format!(
            "发现 {} 个浏览器相关进程地址空间；为保证速度，本次分析前 {process_space_limit} 个",
            address_spaces.len()
        ));
        address_spaces.truncate(process_space_limit);
    }

    let mut records_by_page = HashMap::<u64, Vec<(usize, u64)>>::new();
    for (record_index, record) in records.iter().enumerate() {
        for physical in &record.physical_addresses {
            records_by_page
                .entry(physical & !0xfff)
                .or_default()
                .push((record_index, physical & 0xfff));
        }
    }
    let mut examined = 0usize;
    for candidate in address_spaces {
        examined += 1;
        let reverse = match X64AddressSpace::new(session.image(), candidate.dtb).and_then(|space| {
            space.reverse_translate_pages(&targets, VirtualAddressRegion::User, 4)
        }) {
            Ok(reverse) => reverse,
            Err(error) => {
                complete = false;
                warnings.push(format!(
                    "无法反向映射浏览器进程 DTB {:#x}：{error:#}",
                    candidate.dtb
                ));
                continue;
            }
        };
        for (physical_page, virtual_pages) in reverse {
            let Some(record_refs) = records_by_page.get(&physical_page) else {
                continue;
            };
            for (record_index, delta) in record_refs {
                for owner in &candidate.owners {
                    for virtual_page in &virtual_pages {
                        let mut owner = owner.clone();
                        owner.virtual_address = virtual_page + delta;
                        records[*record_index].owners.push(owner);
                    }
                }
            }
        }
    }
    for record in records {
        record.owners.sort_unstable_by(|left, right| {
            left.pid
                .cmp(&right.pid)
                .then_with(|| left.virtual_address.cmp(&right.virtual_address))
        });
        record
            .owners
            .dedup_by_key(|owner| (owner.pid, owner.virtual_address));
        record.owners.truncate(MAX_DOWNLOAD_OWNERS);
    }
    (complete, examined, warnings)
}

fn aggregate_sessions(
    cookies: &[BrowserCookieRecord],
    downloads: &[DownloadTraceRecord],
    processes: &HashMap<u64, BrowserProcessRecord>,
    limit: usize,
) -> (Vec<BrowserSessionRecord>, bool, Vec<String>) {
    let mut builders = BTreeMap::<String, SessionBuilder>::new();
    for (cookie_index, cookie) in cookies.iter().enumerate() {
        let owner_pids = cookie
            .owners
            .iter()
            .map(|owner| owner.pid)
            .collect::<BTreeSet<_>>();
        if !owner_pids.is_empty() {
            for pid in owner_pids {
                let builder = process_builder(&mut builders, pid, processes, &cookie.browser);
                builder.cookies.insert(cookie_index);
                add_cookie_domain(builder, cookie);
            }
        } else if let Some(profile) = cookie.profile.as_deref() {
            let key = format!("profile\u{1f}{}\u{1f}{profile}", cookie.browser);
            let builder = builders.entry(key).or_insert_with(|| SessionBuilder {
                kind: BrowserSessionKind::Profile,
                browser: cookie.browser.clone(),
                profile: Some(profile.to_owned()),
                configuration_directory: cookie
                    .source_file
                    .as_deref()
                    .and_then(|path| profile_directory_from_cookie_path(path, profile)),
                pid: None,
                process: None,
                user_sid: None,
                image_path: None,
                command_line: None,
                process_create_time: None,
                time_basis: "配置文件证据聚合；未推断真实浏览起止时间".to_owned(),
                confidence: cookie.confidence.clone(),
                cookies: BTreeSet::new(),
                downloads: BTreeSet::new(),
                domains: BTreeSet::new(),
            });
            builder.cookies.insert(cookie_index);
            add_cookie_domain(builder, cookie);
        } else {
            let key = format!("browser\u{1f}{}", cookie.browser);
            let builder = builders.entry(key).or_insert_with(|| SessionBuilder {
                kind: BrowserSessionKind::Browser,
                browser: cookie.browser.clone(),
                profile: None,
                configuration_directory: None,
                pid: None,
                process: None,
                user_sid: None,
                image_path: None,
                command_line: None,
                process_create_time: None,
                time_basis: "浏览器类型证据聚合；未推断真实浏览起止时间".to_owned(),
                confidence: cookie.confidence.clone(),
                cookies: BTreeSet::new(),
                downloads: BTreeSet::new(),
                domains: BTreeSet::new(),
            });
            builder.cookies.insert(cookie_index);
            add_cookie_domain(builder, cookie);
        }
    }

    for (download_index, download) in downloads.iter().enumerate() {
        for pid in download
            .owners
            .iter()
            .map(|owner| owner.pid)
            .collect::<BTreeSet<_>>()
        {
            let browser = download
                .owners
                .iter()
                .find(|owner| owner.pid == pid)
                .map(|owner| owner.browser.as_str())
                .unwrap_or("未知浏览器");
            let builder = process_builder(&mut builders, pid, processes, browser);
            builder.downloads.insert(download_index);
            if let Some(domain) = normalize_domain(&download.host) {
                builder.domains.insert(domain);
            }
        }
    }

    let mut records = builders
        .into_values()
        .map(|builder| {
            let cookie_indices = builder.cookies.into_iter().collect::<Vec<_>>();
            let download_indices = builder.downloads.into_iter().collect::<Vec<_>>();
            let evidence_count = cookie_indices.len() + download_indices.len();
            BrowserSessionRecord {
                kind: builder.kind,
                browser: builder.browser,
                profile: builder.profile,
                configuration_directory: builder.configuration_directory,
                pid: builder.pid,
                process: builder.process,
                user_sid: builder.user_sid,
                image_path: builder.image_path,
                command_line: builder.command_line,
                process_create_time: builder.process_create_time,
                time_basis: builder.time_basis,
                confidence: builder.confidence,
                cookie_indices,
                download_indices,
                domains: builder.domains.into_iter().collect(),
                evidence_count,
            }
        })
        .collect::<Vec<_>>();
    records.sort_unstable_by(|left, right| {
        right
            .evidence_count
            .cmp(&left.evidence_count)
            .then_with(|| session_kind_rank(left.kind).cmp(&session_kind_rank(right.kind)))
            .then_with(|| left.browser.cmp(&right.browser))
            .then_with(|| left.pid.cmp(&right.pid))
            .then_with(|| left.profile.cmp(&right.profile))
    });
    let truncated = records.len() > limit;
    let warnings = truncated
        .then(|| format!("浏览器会话结果达到 {limit} 条上限"))
        .into_iter()
        .collect();
    records.truncate(limit);
    (records, truncated, warnings)
}

fn process_builder<'a>(
    builders: &'a mut BTreeMap<String, SessionBuilder>,
    pid: u64,
    processes: &HashMap<u64, BrowserProcessRecord>,
    fallback_browser: &str,
) -> &'a mut SessionBuilder {
    let key = format!("process\u{1f}{pid}");
    builders.entry(key).or_insert_with(|| {
        let process = processes.get(&pid);
        SessionBuilder {
            kind: BrowserSessionKind::Process,
            browser: process
                .map(|record| record.browser.clone())
                .unwrap_or_else(|| fallback_browser.to_owned()),
            profile: process.and_then(|record| record.profile.clone()),
            configuration_directory: process
                .and_then(|record| record.configuration_directory.clone()),
            pid: Some(pid),
            process: process.map(|record| record.process.clone()),
            user_sid: process.and_then(|record| record.user_sid.clone()),
            image_path: process.and_then(|record| record.image_path.clone()),
            command_line: process.and_then(|record| record.command_line.clone()),
            process_create_time: process.and_then(|record| record.process_create_time.clone()),
            time_basis: "进程创建时间仅表示进程生命周期起点，不等同于浏览开始时间".to_owned(),
            confidence: "high".to_owned(),
            cookies: BTreeSet::new(),
            downloads: BTreeSet::new(),
            domains: BTreeSet::new(),
        }
    })
}

fn add_cookie_domain(builder: &mut SessionBuilder, cookie: &BrowserCookieRecord) {
    if let Some(domain) = cookie.domain.as_deref().and_then(normalize_domain) {
        builder.domains.insert(domain);
    }
}

fn build_domain_relations(
    cookies: &[BrowserCookieRecord],
    downloads: &[DownloadTraceRecord],
    sessions: &[BrowserSessionRecord],
) -> Vec<BrowserDomainRelation> {
    let mut downloads_by_host = BTreeMap::<String, Vec<usize>>::new();
    for (index, download) in downloads.iter().enumerate() {
        if let Some(host) = normalize_domain(&download.host) {
            downloads_by_host.entry(host).or_default().push(index);
        }
    }
    downloads_by_host
        .into_iter()
        .filter_map(|(host, download_indices)| {
            let mut cookie_domains = BTreeSet::new();
            let mut cookie_indices = Vec::new();
            for (index, cookie) in cookies.iter().enumerate() {
                let Some(domain) = cookie.domain.as_deref().and_then(normalize_domain) else {
                    continue;
                };
                if domains_related(&host, &domain) {
                    cookie_domains.insert(domain);
                    cookie_indices.push(index);
                }
            }
            let session_indices: Vec<usize> = sessions
                .iter()
                .enumerate()
                .filter_map(|(index, session)| {
                    (session
                        .download_indices
                        .iter()
                        .any(|item| download_indices.contains(item))
                        || session
                            .domains
                            .iter()
                            .any(|domain| domains_related(&host, domain)))
                    .then_some(index)
                })
                .collect();
            if cookie_indices.is_empty() && session_indices.is_empty() {
                return None;
            }
            let relation_basis = if cookie_indices.is_empty() {
                "下载物理页已映射到浏览器进程；未找到同域或父子域 Cookie".to_owned()
            } else {
                "Cookie 域与下载主机相同或存在父子域关系；该关系不单独证明进程归属".to_owned()
            };
            Some(BrowserDomainRelation {
                download_host: host,
                cookie_domains: cookie_domains.into_iter().collect(),
                cookie_indices,
                download_indices,
                session_indices,
                relation_basis,
            })
        })
        .collect()
}

fn normalize_domain(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('.').trim_end_matches('.');
    if value.is_empty() {
        None
    } else {
        Some(value.to_ascii_lowercase())
    }
}

fn domains_related(left: &str, right: &str) -> bool {
    let Some(left) = normalize_domain(left) else {
        return false;
    };
    let Some(right) = normalize_domain(right) else {
        return false;
    };
    left == right
        || left
            .strip_suffix(&right)
            .is_some_and(|prefix| prefix.ends_with('.'))
        || right
            .strip_suffix(&left)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn command_line_option(command_line: &str, option: &str) -> Option<String> {
    let lower = command_line.to_ascii_lowercase();
    let option = option.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(relative) = lower[search_from..].find(&option) {
        let start = search_from + relative;
        let before = lower[..start].chars().next_back();
        let after = lower[start + option.len()..].chars().next();
        if before.is_none_or(char::is_whitespace)
            && after.is_some_and(|character| character == '=' || character.is_whitespace())
        {
            let mut value = command_line[start + option.len()..].trim_start();
            if let Some(rest) = value.strip_prefix('=') {
                value = rest.trim_start();
            }
            if let Some(rest) = value.strip_prefix('"') {
                return rest
                    .split_once('"')
                    .map(|(value, _)| value.to_owned())
                    .filter(|value| !value.is_empty());
            }
            return value
                .split_whitespace()
                .next()
                .map(str::to_owned)
                .filter(|value| !value.is_empty());
        }
        search_from = start + option.len();
    }
    None
}

fn profile_directory_from_cookie_path(path: &str, profile: &str) -> Option<String> {
    let parts = path.replace('/', "\\");
    let parts = parts.split('\\').collect::<Vec<_>>();
    let profile_index = parts
        .iter()
        .position(|part| part.eq_ignore_ascii_case(profile))?;
    Some(parts[..=profile_index].join("\\"))
}

fn session_kind_rank(kind: BrowserSessionKind) -> u8 {
    match kind {
        BrowserSessionKind::Process => 0,
        BrowserSessionKind::Profile => 1,
        BrowserSessionKind::Browser => 2,
    }
}

fn process_warning_name(kind: &str) -> &'static str {
    match kind {
        "cycle" => "活动进程链表存在循环",
        "invalid_pointer" => "活动进程链表指针无效",
        "invalid_blink" | "blink_mismatch" | "head_blink_mismatch" => "活动进程链表反向链接异常",
        "unreadable_blink" | "unreadable_flink" | "unreadable_entry" => "活动进程链表内容不可读",
        "invalid_process_id" => "进程标识无效",
        _ => "活动进程链表出现未知异常",
    }
}

fn extend_warnings(target: &mut Vec<String>, warnings: impl IntoIterator<Item = String>) {
    for warning in warnings {
        if target.len() >= MAX_WARNING_COUNT {
            break;
        }
        target.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cookies::{CookieEncoding, CookieSource};
    use crate::downloads::DownloadTextEncoding;

    fn cookie(domain: &str, profile: Option<&str>) -> BrowserCookieRecord {
        BrowserCookieRecord {
            browser: "Chrome".to_owned(),
            profile: profile.map(str::to_owned),
            source: CookieSource::ChromiumDatabase,
            encoding: CookieEncoding::Sqlite,
            domain: Some(domain.to_owned()),
            path: Some("/".to_owned()),
            name: "会话".to_owned(),
            value: Some("值".to_owned()),
            encrypted_value_hex: None,
            encrypted: false,
            expires: None,
            secure: Some(true),
            http_only: Some(true),
            same_site: None,
            confidence: "high".to_owned(),
            occurrences: 1,
            physical_addresses: vec![0x1234],
            owners: Vec::new(),
            source_file: Some(
                "\\Users\\Alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"
                    .to_owned(),
            ),
            file_object: Some(0xffff_8000_0000_1000),
            database_rowid: Some(1),
        }
    }

    fn download(host: &str) -> DownloadTraceRecord {
        DownloadTraceRecord {
            url: format!("https://{host}/tool.exe"),
            host: host.to_owned(),
            ip_address: None,
            port: None,
            file_name: Some("tool.exe".to_owned()),
            method: None,
            confidence: "medium".to_owned(),
            encodings: vec![DownloadTextEncoding::Ascii],
            occurrences: 1,
            physical_addresses: vec![0x2000],
            owners: Vec::new(),
            evidence: "浏览器下载证据".to_owned(),
        }
    }

    #[test]
    fn relates_cookie_parent_domains_without_false_suffix_matches() {
        assert!(domains_related("download.example.test", ".example.test"));
        assert!(domains_related("example.test", "example.test"));
        assert!(!domains_related("notexample.test", "example.test"));
        assert!(!domains_related("example.test.invalid", "example.test"));
    }

    #[test]
    fn extracts_quoted_browser_configuration_options() {
        let command =
            r#"chrome.exe --user-data-dir="D:\取证\用户数据" --profile-directory="Profile 2""#;
        assert_eq!(
            command_line_option(command, "--user-data-dir").as_deref(),
            Some(r"D:\取证\用户数据")
        );
        assert_eq!(
            command_line_option(command, "--profile-directory").as_deref(),
            Some("Profile 2")
        );
    }

    #[test]
    fn keeps_unowned_download_separate_but_builds_domain_relation() {
        let cookies = vec![cookie(".example.test", Some("Default"))];
        let downloads = vec![download("download.example.test")];
        let (sessions, truncated, warnings) =
            aggregate_sessions(&cookies, &downloads, &HashMap::new(), 10);
        assert!(!truncated);
        assert!(warnings.is_empty());
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].kind, BrowserSessionKind::Profile);
        assert!(sessions[0].download_indices.is_empty());

        let relations = build_domain_relations(&cookies, &downloads, &sessions);
        assert_eq!(relations.len(), 1);
        assert_eq!(relations[0].cookie_indices, vec![0]);
        assert_eq!(relations[0].download_indices, vec![0]);

        let unrelated =
            build_domain_relations(&cookies, &[download("unrelated.invalid")], &sessions);
        assert!(unrelated.is_empty());
    }

    #[test]
    fn assigns_download_only_when_a_browser_process_owner_exists() {
        let mut download = download("download.example.test");
        download.owners.push(DownloadOwner {
            pid: 4242,
            process: "msedge.exe".to_owned(),
            browser: "Edge".to_owned(),
            virtual_address: 0x7ff6_1234_5000,
        });
        let process = BrowserProcessRecord {
            browser: "Edge".to_owned(),
            pid: 4242,
            ppid: Some(1000),
            process: "msedge.exe".to_owned(),
            user_sid: Some("S-1-5-21-1-2-3-1001".to_owned()),
            image_path: Some("C:\\Program Files\\Microsoft\\Edge\\msedge.exe".to_owned()),
            command_line: None,
            configuration_directory: None,
            profile: Some("Default".to_owned()),
            process_create_time: Some("2026-08-05T00:00:00Z".to_owned()),
        };
        let processes = HashMap::from([(process.pid, process)]);
        let (sessions, truncated, _) = aggregate_sessions(&[], &[download], &processes, 10);
        assert!(!truncated);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].kind, BrowserSessionKind::Process);
        assert_eq!(sessions[0].pid, Some(4242));
        assert_eq!(sessions[0].download_indices, vec![0]);
    }
}
