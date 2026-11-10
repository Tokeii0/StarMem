use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat, Utc};
use serde::Serialize;

use crate::session::AnalysisSession;
use crate::windows::WindowsKernelContext;
use crate::windows::disk_plugins::{MftFileNameRecord, MftRecord, MftView, NtfsTimestamps};

mod registry;

#[derive(Debug, Clone)]
pub struct WindowsTimelineOptions {
    pub include_processes: bool,
    pub include_threads: bool,
    pub include_mft: bool,
    pub include_shimcache: bool,
    pub include_registry: bool,
    pub include_accessed: bool,
    pub process_limit: usize,
    pub thread_limit: usize,
    pub mft_limit: usize,
    pub shimcache_limit: usize,
    pub registry_limit: usize,
    pub event_limit: usize,
    pub pid: Option<u64>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub newest_first: bool,
}

impl Default for WindowsTimelineOptions {
    fn default() -> Self {
        Self {
            include_processes: true,
            include_threads: true,
            include_mft: true,
            include_shimcache: true,
            include_registry: true,
            include_accessed: false,
            process_limit: 65_536,
            thread_limit: 262_144,
            mft_limit: 250_000,
            shimcache_limit: 100_000,
            registry_limit: 100_000,
            event_limit: 1_000_000,
            pid: None,
            from: None,
            to: None,
            newest_first: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsTimelineStage {
    Processes,
    Threads,
    Mft,
    Shimcache,
    Registry,
    Finalize,
}

#[derive(Debug, Serialize)]
pub struct WindowsTimelineReport {
    pub image: String,
    pub kernel: WindowsKernelContext,
    pub filters: WindowsTimelineFilters,
    pub sources: Vec<WindowsTimelineSourceStatus>,
    pub matched_events: usize,
    pub outlier_events_matched: usize,
    pub outlier_events_retained: usize,
    pub events: Vec<WindowsTimelineRecord>,
    pub category_counts: BTreeMap<String, usize>,
    pub action_counts: BTreeMap<String, usize>,
    pub truncated: bool,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct WindowsTimelineFilters {
    pub from: Option<String>,
    pub to: Option<String>,
    pub pid: Option<u64>,
    pub include_accessed: bool,
    pub newest_first: bool,
    pub event_limit: usize,
}

#[derive(Debug, Serialize)]
pub struct WindowsTimelineSourceStatus {
    pub source: String,
    pub records_examined: usize,
    pub events_matched: usize,
    pub duplicate_events_merged: usize,
    pub complete: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowsTimelineRecord {
    pub timestamp: String,
    pub timestamp_unix_ms: i64,
    pub timestamp_quality: String,
    pub category: String,
    pub action: String,
    pub source: String,
    pub description: String,
    pub pid: Option<u64>,
    pub tid: Option<u64>,
    pub process: Option<String>,
    pub path: Option<String>,
    pub object_address: Option<u64>,
    pub physical_address: Option<u64>,
    pub physical_addresses: Vec<u64>,
    pub details: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
struct TimeFilter {
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    pid: Option<u64>,
}

pub fn analyze_windows_timeline<F>(
    session: &AnalysisSession,
    options: &WindowsTimelineOptions,
    mut progress: F,
) -> Result<WindowsTimelineReport>
where
    F: FnMut(WindowsTimelineStage),
{
    validate_options(options)?;
    let from = options
        .from
        .as_deref()
        .map(|value| parse_time_bound(value, false))
        .transpose()?;
    let to = options
        .to
        .as_deref()
        .map(|value| parse_time_bound(value, true))
        .transpose()?;
    if let (Some(from), Some(to)) = (from, to) {
        ensure!(from <= to, "时间范围无效：--from 必须早于或等于 --to");
    }
    let filter = TimeFilter {
        from_ms: from.map(|value| value.timestamp_millis()),
        to_ms: to.map(|value| value.timestamp_millis()),
        pid: options.pid,
    };
    let normalized_from = from.map(format_utc);
    let normalized_to = to.map(format_utc);

    let mut events = Vec::new();
    let mut sources = Vec::new();
    let mut warnings = Vec::new();
    let mut complete = true;

    if options.include_processes && session.kernel().is_x86_pae() {
        progress(WindowsTimelineStage::Processes);
        match session.processes(options.process_limit) {
            Ok(report) => {
                let records_examined = report.processes.len();
                let before = events.len();
                for record in report.processes {
                    let details = BTreeMap::from([
                        ("ppid".to_owned(), optional_number(record.ppid)),
                        ("state".to_owned(), record.details.state.clone()),
                        (
                            "active_threads".to_owned(),
                            optional_number(record.details.active_threads),
                        ),
                        (
                            "directory_table_base".to_owned(),
                            record
                                .details
                                .directory_table_base
                                .map(|value| format!("{value:#x}"))
                                .unwrap_or_default(),
                        ),
                    ]);
                    push_event(
                        &mut events,
                        filter,
                        EventInput {
                            timestamp: record.details.create_time.as_deref(),
                            category: "process",
                            action: "process_create",
                            source: "pslist",
                            description: format!("进程创建：{} (PID {})", record.name, record.pid),
                            pid: Some(record.pid),
                            tid: None,
                            process: Some(record.name.clone()),
                            path: record.details.image_path.clone(),
                            object_address: Some(record.eprocess),
                            physical_address: None,
                            details: details.clone(),
                        },
                    );
                    push_event(
                        &mut events,
                        filter,
                        EventInput {
                            timestamp: record.details.exit_time.as_deref(),
                            category: "process",
                            action: "process_exit",
                            source: "pslist",
                            description: format!("进程退出：{} (PID {})", record.name, record.pid),
                            pid: Some(record.pid),
                            tid: None,
                            process: Some(record.name),
                            path: record.details.image_path,
                            object_address: Some(record.eprocess),
                            physical_address: None,
                            details,
                        },
                    );
                }
                warnings.extend(
                    report
                        .warnings
                        .into_iter()
                        .map(|warning| format!("pslist [{}]：{}", warning.kind, warning.message)),
                );
                warnings.push(
                    "Windows x86 PAE 当前无法从物理池可靠反向映射残留 EPROCESS；进程时间线已回退为活动进程链，不能覆盖已脱链对象"
                        .to_owned(),
                );
                complete = false;
                sources.push(WindowsTimelineSourceStatus {
                    source: "pslist".to_owned(),
                    records_examined,
                    events_matched: events.len() - before,
                    duplicate_events_merged: 0,
                    complete: false,
                    error: None,
                });
            }
            Err(error) => {
                let message = format!("pslist 失败：{error:#}");
                warnings.push(message.clone());
                sources.push(failed_source("pslist", message));
                complete = false;
            }
        }
    }

    if options.include_processes && !session.kernel().is_x86_pae() {
        progress(WindowsTimelineStage::Processes);
        match session.process_scan(options.process_limit) {
            Ok(report) => {
                let records_examined = report.records.len();
                let before = events.len();
                for record in report.records {
                    let mut details = BTreeMap::from([
                        ("ppid".to_owned(), optional_number(record.ppid)),
                        (
                            "in_active_list".to_owned(),
                            record.in_active_list.to_string(),
                        ),
                        (
                            "validation_score".to_owned(),
                            record.validation_score.to_string(),
                        ),
                        (
                            "active_threads".to_owned(),
                            optional_number(record.active_threads),
                        ),
                    ]);
                    if let Some(directory_table_base) = record.directory_table_base {
                        details.insert(
                            "directory_table_base".to_owned(),
                            format!("{directory_table_base:#x}"),
                        );
                    }
                    push_event(
                        &mut events,
                        filter,
                        EventInput {
                            timestamp: record.create_time.as_deref(),
                            category: "process",
                            action: "process_create",
                            source: "psscan",
                            description: format!("进程创建：{} (PID {})", record.name, record.pid),
                            pid: Some(record.pid),
                            tid: None,
                            process: Some(record.name.clone()),
                            path: None,
                            object_address: Some(record.eprocess),
                            physical_address: Some(record.physical_address),
                            details: details.clone(),
                        },
                    );
                    push_event(
                        &mut events,
                        filter,
                        EventInput {
                            timestamp: record.exit_time.as_deref(),
                            category: "process",
                            action: "process_exit",
                            source: "psscan",
                            description: format!("进程退出：{} (PID {})", record.name, record.pid),
                            pid: Some(record.pid),
                            tid: None,
                            process: Some(record.name),
                            path: None,
                            object_address: Some(record.eprocess),
                            physical_address: Some(record.physical_address),
                            details,
                        },
                    );
                }
                append_source_warnings("psscan", report.warnings, &mut warnings);
                complete &= report.complete;
                sources.push(WindowsTimelineSourceStatus {
                    source: "psscan".to_owned(),
                    records_examined,
                    events_matched: events.len() - before,
                    duplicate_events_merged: 0,
                    complete: report.complete,
                    error: None,
                });
            }
            Err(error) => {
                let message = format!("psscan 失败：{error:#}");
                warnings.push(message.clone());
                sources.push(failed_source("psscan", message));
                complete = false;
            }
        }
    }

    if options.include_threads {
        progress(WindowsTimelineStage::Threads);
        match session.thread_scan(options.thread_limit) {
            Ok(report) => {
                let records_examined = report.records.len();
                let before = events.len();
                for record in report.records {
                    let mut details = BTreeMap::from([
                        ("state".to_owned(), record.state_name.clone()),
                        ("pool_scanned".to_owned(), record.pool_scanned.to_string()),
                        (
                            "in_process_thread_list".to_owned(),
                            record.in_process_thread_list.to_string(),
                        ),
                    ]);
                    if let Some(start_address) = record.start_address {
                        details.insert("start_address".to_owned(), format!("{start_address:#x}"));
                    }
                    if let Some(module) = &record.start_module {
                        details.insert("start_module".to_owned(), module.clone());
                    }
                    if !record.suspicious_reasons.is_empty() {
                        details.insert(
                            "suspicious_reasons".to_owned(),
                            record.suspicious_reasons.join("; "),
                        );
                    }
                    push_event(
                        &mut events,
                        filter,
                        EventInput {
                            timestamp: record.create_time.as_deref(),
                            category: "thread",
                            action: "thread_create",
                            source: "thrdscan",
                            description: format!(
                                "线程创建：{} PID {} / TID {}",
                                record.process, record.pid, record.tid
                            ),
                            pid: Some(record.pid),
                            tid: Some(record.tid),
                            process: Some(record.process.clone()),
                            path: None,
                            object_address: Some(record.ethread),
                            physical_address: record.physical_address,
                            details: details.clone(),
                        },
                    );
                    push_event(
                        &mut events,
                        filter,
                        EventInput {
                            timestamp: record.exit_time.as_deref(),
                            category: "thread",
                            action: "thread_exit",
                            source: "thrdscan",
                            description: format!(
                                "线程退出：{} PID {} / TID {}",
                                record.process, record.pid, record.tid
                            ),
                            pid: Some(record.pid),
                            tid: Some(record.tid),
                            process: Some(record.process),
                            path: None,
                            object_address: Some(record.ethread),
                            physical_address: record.physical_address,
                            details,
                        },
                    );
                }
                append_source_warnings("thrdscan", report.warnings, &mut warnings);
                complete &= report.complete;
                sources.push(WindowsTimelineSourceStatus {
                    source: "thrdscan".to_owned(),
                    records_examined,
                    events_matched: events.len() - before,
                    duplicate_events_merged: 0,
                    complete: report.complete,
                    error: None,
                });
            }
            Err(error) => {
                let message = format!("thrdscan 失败：{error:#}");
                warnings.push(message.clone());
                sources.push(failed_source("thrdscan", message));
                complete = false;
            }
        }
    }

    if options.include_mft {
        progress(WindowsTimelineStage::Mft);
        match session.mft(MftView::All, options.mft_limit) {
            Ok(report) => {
                let records_examined = report.records.len();
                let mut source_events = Vec::new();
                let paths = MftPathIndex::new(&report.records);
                for record in &report.records {
                    let path = paths.path_for_record(record);
                    if let Some(timestamps) = &record.standard_information {
                        append_mft_timestamps(
                            &mut source_events,
                            filter,
                            record,
                            timestamps,
                            "mft.standard_information",
                            path.clone(),
                            None,
                            options.include_accessed,
                        );
                    }

                    let mut seen_names = HashSet::new();
                    for name in &record.file_names {
                        let key = (
                            name.parent_record,
                            name.name.to_lowercase(),
                            name.timestamps.created_raw,
                            name.timestamps.modified_raw,
                            name.timestamps.mft_changed_raw,
                            name.timestamps.accessed_raw,
                        );
                        if !seen_names.insert(key) {
                            continue;
                        }
                        append_mft_timestamps(
                            &mut source_events,
                            filter,
                            record,
                            &name.timestamps,
                            "mft.file_name",
                            Some(paths.path_for_name(record, name)),
                            Some(name),
                            options.include_accessed,
                        );
                    }
                }
                let events_before_deduplication = source_events.len();
                source_events = deduplicate_mft_events(source_events);
                let duplicate_events_merged =
                    events_before_deduplication.saturating_sub(source_events.len());
                let events_matched = source_events.len();
                events.extend(source_events);
                append_source_warnings("mftscan", report.warnings, &mut warnings);
                complete &= report.complete;
                sources.push(WindowsTimelineSourceStatus {
                    source: "mftscan".to_owned(),
                    records_examined,
                    events_matched,
                    duplicate_events_merged,
                    complete: report.complete,
                    error: None,
                });
            }
            Err(error) => {
                let message = format!("mftscan 失败：{error:#}");
                warnings.push(message.clone());
                sources.push(failed_source("mftscan", message));
                complete = false;
            }
        }
    }

    if options.include_shimcache {
        progress(WindowsTimelineStage::Shimcache);
        match session.shimcache(options.shimcache_limit) {
            Ok(report) => {
                let records_examined = report.records.len();
                let before = events.len();
                for record in report.records {
                    let mut details = BTreeMap::from([
                        ("order".to_owned(), record.order.to_string()),
                        (
                            "executed".to_owned(),
                            record
                                .executed
                                .map(|value| value.to_string())
                                .unwrap_or_default(),
                        ),
                    ]);
                    if let Some(raw) = record.last_modified_raw {
                        details.insert("last_modified_filetime".to_owned(), raw.to_string());
                    }
                    if let Some(blob_size) = record.blob_size {
                        details.insert("blob_size".to_owned(), blob_size.to_string());
                    }
                    push_event(
                        &mut events,
                        filter,
                        EventInput {
                            timestamp: record.last_modified.as_deref(),
                            category: "execution",
                            action: "shimcache_file_modified",
                            source: "shimcache",
                            description: format!(
                                "Shimcache 记录的文件最后修改时间：{}",
                                record.path
                            ),
                            pid: None,
                            tid: None,
                            process: None,
                            path: Some(record.path),
                            object_address: Some(record.entry),
                            physical_address: None,
                            details,
                        },
                    );
                }
                append_source_warnings("shimcache", report.warnings, &mut warnings);
                complete &= report.complete;
                sources.push(WindowsTimelineSourceStatus {
                    source: "shimcache".to_owned(),
                    records_examined,
                    events_matched: events.len() - before,
                    duplicate_events_merged: 0,
                    complete: report.complete,
                    error: None,
                });
            }
            Err(error) => {
                let message = format!("shimcache 失败：{error:#}");
                warnings.push(message.clone());
                sources.push(failed_source("shimcache", message));
                complete = false;
            }
        }
    }

    if options.include_registry {
        progress(WindowsTimelineStage::Registry);
        registry::append_registry_events(
            session,
            options,
            filter,
            &mut events,
            &mut sources,
            &mut warnings,
            &mut complete,
        );
    }

    progress(WindowsTimelineStage::Finalize);
    sort_timeline_events(&mut events);
    let matched_events = events.len();
    let retained = retain_timeline_events(events, options.event_limit);
    let truncated = retained.truncated;
    let outlier_events_matched = retained.outliers_matched;
    let outlier_events_retained = retained.outliers_retained;
    let normal_events_retained = retained.normal_retained;
    events = retained.events;
    if truncated {
        warnings.push(format!(
            "时间线匹配到 {matched_events} 条事件，达到 {} 条上限；已保留时间上最新的 {normal_events_retained} 条正常事件，并抽样保留 {outlier_events_retained}/{outlier_events_matched} 条异常时间事件",
            options.event_limit,
        ));
        complete = false;
    }
    if options.newest_first {
        events.reverse();
    }

    let mut category_counts = BTreeMap::new();
    let mut action_counts = BTreeMap::new();
    for event in &events {
        *category_counts.entry(event.category.clone()).or_insert(0) += 1;
        *action_counts.entry(event.action.clone()).or_insert(0) += 1;
    }

    Ok(WindowsTimelineReport {
        image: session.image().path().display().to_string(),
        kernel: session.kernel().clone(),
        filters: WindowsTimelineFilters {
            from: normalized_from,
            to: normalized_to,
            pid: options.pid,
            include_accessed: options.include_accessed,
            newest_first: options.newest_first,
            event_limit: options.event_limit,
        },
        sources,
        matched_events,
        outlier_events_matched,
        outlier_events_retained,
        events,
        category_counts,
        action_counts,
        truncated,
        complete,
        warnings,
    })
}

fn validate_options(options: &WindowsTimelineOptions) -> Result<()> {
    ensure!(
        options.include_processes
            || options.include_threads
            || options.include_mft
            || options.include_shimcache
            || options.include_registry,
        "至少选择一个 Windows 时间线来源"
    );
    ensure!(options.event_limit > 0, "时间线事件上限必须大于零");
    if options.include_processes {
        ensure!(options.process_limit > 0, "进程扫描上限必须大于零");
    }
    if options.include_threads {
        ensure!(options.thread_limit > 0, "线程扫描上限必须大于零");
    }
    if options.include_mft {
        ensure!(options.mft_limit > 0, "MFT 扫描上限必须大于零");
    }
    if options.include_shimcache {
        ensure!(options.shimcache_limit > 0, "Shimcache 扫描上限必须大于零");
    }
    if options.include_registry {
        ensure!(options.registry_limit > 0, "注册表结果上限必须大于零");
    }
    Ok(())
}

fn parse_time_bound(value: &str, end_of_day: bool) -> Result<DateTime<Utc>> {
    if let Ok(timestamp) = DateTime::parse_from_rfc3339(value) {
        return Ok(timestamp.with_timezone(&Utc));
    }
    let date = NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .with_context(|| format!("无法解析时间 {value:?}；请使用 RFC3339 或 YYYY-MM-DD"))?;
    let naive = if end_of_day {
        date.and_hms_milli_opt(23, 59, 59, 999)
    } else {
        date.and_hms_opt(0, 0, 0)
    }
    .context("时间超出可表示范围")?;
    Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

fn format_utc(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn append_source_warnings(source: &str, source_warnings: Vec<String>, warnings: &mut Vec<String>) {
    warnings.extend(
        source_warnings
            .into_iter()
            .map(|warning| format!("{source}：{warning}")),
    );
}

fn failed_source(source: &str, error: String) -> WindowsTimelineSourceStatus {
    WindowsTimelineSourceStatus {
        source: source.to_owned(),
        records_examined: 0,
        events_matched: 0,
        duplicate_events_merged: 0,
        complete: false,
        error: Some(error),
    }
}

fn optional_number<T: ToString>(value: Option<T>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

struct EventInput<'a> {
    timestamp: Option<&'a str>,
    category: &'a str,
    action: &'a str,
    source: &'a str,
    description: String,
    pid: Option<u64>,
    tid: Option<u64>,
    process: Option<String>,
    path: Option<String>,
    object_address: Option<u64>,
    physical_address: Option<u64>,
    details: BTreeMap<String, String>,
}

fn push_event(events: &mut Vec<WindowsTimelineRecord>, filter: TimeFilter, input: EventInput<'_>) {
    let Some(timestamp) = input.timestamp else {
        return;
    };
    let Ok(timestamp) = DateTime::parse_from_rfc3339(timestamp) else {
        return;
    };
    let timestamp = timestamp.with_timezone(&Utc);
    let timestamp_unix_ms = timestamp.timestamp_millis();
    if filter.from_ms.is_some_and(|from| timestamp_unix_ms < from)
        || filter.to_ms.is_some_and(|to| timestamp_unix_ms > to)
        || matches!((filter.pid, input.pid), (Some(expected), Some(actual)) if expected != actual)
    {
        return;
    }
    events.push(WindowsTimelineRecord {
        timestamp: format_utc(timestamp),
        timestamp_unix_ms,
        timestamp_quality: timestamp_quality(timestamp),
        category: input.category.to_owned(),
        action: input.action.to_owned(),
        source: input.source.to_owned(),
        description: input.description,
        pid: input.pid,
        tid: input.tid,
        process: input.process,
        path: input.path,
        object_address: input.object_address,
        physical_address: input.physical_address,
        physical_addresses: input.physical_address.into_iter().collect(),
        details: input.details,
    });
}

fn timestamp_quality(timestamp: DateTime<Utc>) -> String {
    if timestamp.year() < 1980 {
        "outlier_before_1980".to_owned()
    } else if timestamp.year() > 2100 {
        "outlier_after_2100".to_owned()
    } else {
        "normal".to_owned()
    }
}

fn sort_timeline_events(events: &mut [WindowsTimelineRecord]) {
    events.sort_by(|left, right| {
        left.timestamp_unix_ms
            .cmp(&right.timestamp_unix_ms)
            .then_with(|| left.category.cmp(&right.category))
            .then_with(|| left.action.cmp(&right.action))
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.object_address.cmp(&right.object_address))
            .then_with(|| left.physical_address.cmp(&right.physical_address))
    });
}

struct TimelineRetention {
    events: Vec<WindowsTimelineRecord>,
    truncated: bool,
    outliers_matched: usize,
    outliers_retained: usize,
    normal_retained: usize,
}

fn retain_timeline_events(events: Vec<WindowsTimelineRecord>, limit: usize) -> TimelineRetention {
    let outliers_matched = events
        .iter()
        .filter(|event| event.timestamp_quality != "normal")
        .count();
    if events.len() <= limit {
        return TimelineRetention {
            normal_retained: events.len().saturating_sub(outliers_matched),
            outliers_retained: outliers_matched,
            events,
            truncated: false,
            outliers_matched,
        };
    }

    let (mut normal, outliers): (Vec<_>, Vec<_>) = events
        .into_iter()
        .partition(|event| event.timestamp_quality == "normal");
    let reserved_outlier_slots = if normal.is_empty() {
        limit
    } else if limit >= 100 {
        (limit / 100).clamp(1, 1_000)
    } else {
        0
    }
    .min(outliers.len());
    let mut normal_to_keep = normal.len().min(limit - reserved_outlier_slots);
    let outliers_to_keep = outliers.len().min(limit - normal_to_keep);
    normal_to_keep += (limit - normal_to_keep - outliers_to_keep)
        .min(normal.len().saturating_sub(normal_to_keep));

    let normal_start = normal.len().saturating_sub(normal_to_keep);
    let mut retained = normal.split_off(normal_start);
    retained.extend(sample_outliers(outliers, outliers_to_keep));
    sort_timeline_events(&mut retained);
    TimelineRetention {
        normal_retained: normal_to_keep,
        outliers_retained: outliers_to_keep,
        events: retained,
        truncated: true,
        outliers_matched,
    }
}

fn sample_outliers(
    outliers: Vec<WindowsTimelineRecord>,
    limit: usize,
) -> Vec<WindowsTimelineRecord> {
    if outliers.len() <= limit {
        return outliers;
    }
    if limit == 0 {
        return Vec::new();
    }
    let head_count = limit / 2;
    let tail_count = limit - head_count;
    let tail_start = outliers.len() - tail_count;
    outliers
        .into_iter()
        .enumerate()
        .filter_map(|(index, event)| (index < head_count || index >= tail_start).then_some(event))
        .collect()
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct MftEventKey {
    timestamp_unix_ms: i64,
    action: String,
    source: String,
    path: Option<String>,
    record_number: String,
    sequence_number: String,
}

fn deduplicate_mft_events(events: Vec<WindowsTimelineRecord>) -> Vec<WindowsTimelineRecord> {
    let mut deduplicated: Vec<WindowsTimelineRecord> = Vec::new();
    let mut indexes: HashMap<MftEventKey, usize> = HashMap::new();
    for event in events {
        let key = MftEventKey {
            timestamp_unix_ms: event.timestamp_unix_ms,
            action: event.action.clone(),
            source: event.source.clone(),
            path: event.path.clone(),
            record_number: event
                .details
                .get("record_number")
                .cloned()
                .unwrap_or_default(),
            sequence_number: event
                .details
                .get("sequence_number")
                .cloned()
                .unwrap_or_default(),
        };
        if let Some(index) = indexes.get(&key).copied() {
            let existing = &mut deduplicated[index];
            for address in event.physical_addresses {
                if !existing.physical_addresses.contains(&address) {
                    existing.physical_addresses.push(address);
                }
            }
            existing.physical_addresses.sort_unstable();
            existing.details.insert(
                "evidence_copy_count".to_owned(),
                existing.physical_addresses.len().to_string(),
            );
        } else {
            indexes.insert(key, deduplicated.len());
            deduplicated.push(event);
        }
    }
    deduplicated
}

#[allow(clippy::too_many_arguments)]
fn append_mft_timestamps(
    events: &mut Vec<WindowsTimelineRecord>,
    filter: TimeFilter,
    record: &MftRecord,
    timestamps: &NtfsTimestamps,
    source: &str,
    path: Option<String>,
    file_name: Option<&MftFileNameRecord>,
    include_accessed: bool,
) {
    let mut details = BTreeMap::from([
        ("record_number".to_owned(), record.record_number.to_string()),
        (
            "sequence_number".to_owned(),
            record.sequence_number.to_string(),
        ),
        ("in_use".to_owned(), record.in_use.to_string()),
        ("directory".to_owned(), record.directory.to_string()),
    ]);
    if let Some(file_name) = file_name {
        details.insert(
            "parent_record".to_owned(),
            file_name.parent_record.to_string(),
        );
        details.insert(
            "parent_sequence".to_owned(),
            file_name.parent_sequence.to_string(),
        );
        details.insert("namespace".to_owned(), file_name.namespace.to_string());
    }

    let label = path
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("MFT #{}", record.record_number));
    let timestamp_values = [
        (
            timestamps.created.as_deref(),
            timestamps.created_raw,
            "file_created",
            "文件创建",
        ),
        (
            timestamps.modified.as_deref(),
            timestamps.modified_raw,
            "file_modified",
            "文件内容修改",
        ),
        (
            timestamps.mft_changed.as_deref(),
            timestamps.mft_changed_raw,
            "file_metadata_changed",
            "MFT 元数据修改",
        ),
        (
            include_accessed
                .then_some(timestamps.accessed.as_deref())
                .flatten(),
            timestamps.accessed_raw,
            "file_accessed",
            "文件访问",
        ),
    ];
    for (timestamp, raw, action, action_label) in timestamp_values {
        let mut event_details = details.clone();
        event_details.insert("filetime".to_owned(), raw.to_string());
        push_event(
            events,
            filter,
            EventInput {
                timestamp,
                category: "file",
                action,
                source,
                description: format!("{action_label}：{label}"),
                pid: None,
                tid: None,
                process: None,
                path: path.clone(),
                object_address: None,
                physical_address: Some(record.physical_address),
                details: event_details,
            },
        );
    }
}

struct MftPathIndex<'a> {
    records: &'a [MftRecord],
    by_number: HashMap<u32, usize>,
}

impl<'a> MftPathIndex<'a> {
    fn new(records: &'a [MftRecord]) -> Self {
        let mut by_number = HashMap::new();
        for (index, record) in records.iter().enumerate() {
            by_number
                .entry(record.record_number)
                .and_modify(|current: &mut usize| {
                    if !records[*current].in_use && record.in_use {
                        *current = index;
                    }
                })
                .or_insert(index);
        }
        Self { records, by_number }
    }

    fn path_for_record(&self, record: &MftRecord) -> Option<String> {
        let name = preferred_name(record)?;
        Some(self.path_for_name(record, name))
    }

    fn path_for_name(&self, record: &MftRecord, name: &MftFileNameRecord) -> String {
        let mut components = Vec::new();
        if !matches!(name.name.as_str(), "." | "\\") {
            components.push(name.name.clone());
        }
        let mut current_record = record.record_number;
        let mut parent_record = name.parent_record;
        let mut parent_sequence = name.parent_sequence;
        let mut visited = HashSet::from([current_record]);
        let mut complete = parent_record == u64::from(current_record);

        for _ in 0..128 {
            if complete {
                break;
            }
            let Ok(parent_number) = u32::try_from(parent_record) else {
                break;
            };
            if !visited.insert(parent_number) {
                break;
            }
            let Some(index) = self.by_number.get(&parent_number).copied() else {
                break;
            };
            let parent = &self.records[index];
            if parent_sequence != 0 && parent.sequence_number != parent_sequence {
                break;
            }
            let Some(parent_name) = preferred_name(parent) else {
                break;
            };
            if !matches!(parent_name.name.as_str(), "." | "\\") {
                components.push(parent_name.name.clone());
            }
            current_record = parent.record_number;
            parent_record = parent_name.parent_record;
            parent_sequence = parent_name.parent_sequence;
            complete = parent_record == u64::from(current_record) || current_record == 5;
        }

        components.reverse();
        let joined = components.join("\\");
        if complete {
            format!("\\{joined}")
        } else if joined.is_empty() {
            format!("[MFT:{parent_record}]")
        } else {
            format!("[MFT:{parent_record}]\\{joined}")
        }
    }
}

fn preferred_name(record: &MftRecord) -> Option<&MftFileNameRecord> {
    record
        .file_names
        .iter()
        .find(|name| name.namespace == 3)
        .or_else(|| record.file_names.iter().find(|name| name.namespace == 1))
        .or_else(|| record.file_names.iter().find(|name| name.namespace == 0))
        .or_else(|| record.file_names.first())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_rfc3339_and_date_only_bounds() {
        let exact = parse_time_bound("2025-04-14T08:30:00+08:00", false).unwrap();
        assert_eq!(format_utc(exact), "2025-04-14T00:30:00.000Z");

        let start = parse_time_bound("2025-04-14", false).unwrap();
        let end = parse_time_bound("2025-04-14", true).unwrap();
        assert_eq!(format_utc(start), "2025-04-14T00:00:00.000Z");
        assert_eq!(format_utc(end), "2025-04-14T23:59:59.999Z");
    }

    #[test]
    fn pid_filter_keeps_uncorrelated_file_events() {
        let filter = TimeFilter {
            from_ms: None,
            to_ms: None,
            pid: Some(42),
        };
        let mut events = Vec::new();
        for pid in [Some(7), Some(42), None] {
            push_event(
                &mut events,
                filter,
                EventInput {
                    timestamp: Some("2025-04-14T00:00:00Z"),
                    category: "test",
                    action: "test",
                    source: "test",
                    description: "test".to_owned(),
                    pid,
                    tid: None,
                    process: None,
                    path: None,
                    object_address: None,
                    physical_address: None,
                    details: BTreeMap::new(),
                },
            );
        }
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].pid, Some(42));
        assert_eq!(events[1].pid, None);
    }

    #[test]
    fn filters_timestamp_range_inclusively() {
        let filter = TimeFilter {
            from_ms: Some(
                parse_time_bound("2025-04-14T00:00:00Z", false)
                    .unwrap()
                    .timestamp_millis(),
            ),
            to_ms: Some(
                parse_time_bound("2025-04-14T23:59:59Z", true)
                    .unwrap()
                    .timestamp_millis(),
            ),
            pid: None,
        };
        let mut events = Vec::new();
        for timestamp in [
            "2025-04-13T23:59:59Z",
            "2025-04-14T00:00:00Z",
            "2025-04-14T23:59:59Z",
            "2025-04-15T00:00:00Z",
        ] {
            push_event(
                &mut events,
                filter,
                EventInput {
                    timestamp: Some(timestamp),
                    category: "test",
                    action: "test",
                    source: "test",
                    description: "test".to_owned(),
                    pid: None,
                    tid: None,
                    process: None,
                    path: None,
                    object_address: None,
                    physical_address: None,
                    details: BTreeMap::new(),
                },
            );
        }
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn merges_duplicate_mft_events_and_preserves_physical_addresses() {
        let make_event = |physical_address| WindowsTimelineRecord {
            timestamp: "2025-04-14T00:00:00.000Z".to_owned(),
            timestamp_unix_ms: 1_744_588_800_000,
            timestamp_quality: "normal".to_owned(),
            category: "file".to_owned(),
            action: "file_modified".to_owned(),
            source: "mft.standard_information".to_owned(),
            description: "文件内容修改：\\evidence.txt".to_owned(),
            pid: None,
            tid: None,
            process: None,
            path: Some("\\evidence.txt".to_owned()),
            object_address: None,
            physical_address: Some(physical_address),
            physical_addresses: vec![physical_address],
            details: BTreeMap::from([
                ("record_number".to_owned(), "42".to_owned()),
                ("sequence_number".to_owned(), "7".to_owned()),
            ]),
        };
        let events = deduplicate_mft_events(vec![make_event(0x1000), make_event(0x2000)]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].physical_addresses, [0x1000, 0x2000]);
        assert_eq!(
            events[0]
                .details
                .get("evidence_copy_count")
                .map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn marks_implausibly_early_and_late_windows_timestamps_as_outliers() {
        let early = parse_time_bound("1700-01-01T00:00:00Z", false).unwrap();
        let normal = parse_time_bound("1980-01-01T00:00:00Z", false).unwrap();
        let future = parse_time_bound("5294-10-23T00:50:28Z", false).unwrap();
        assert_eq!(timestamp_quality(early), "outlier_before_1980");
        assert_eq!(timestamp_quality(normal), "normal");
        assert_eq!(timestamp_quality(future), "outlier_after_2100");
    }

    #[test]
    fn small_limits_prefer_normal_events_over_future_outliers() {
        let event = |timestamp_unix_ms, quality: &str| WindowsTimelineRecord {
            timestamp: String::new(),
            timestamp_unix_ms,
            timestamp_quality: quality.to_owned(),
            category: "test".to_owned(),
            action: "test".to_owned(),
            source: "test".to_owned(),
            description: "test".to_owned(),
            pid: None,
            tid: None,
            process: None,
            path: None,
            object_address: None,
            physical_address: None,
            physical_addresses: Vec::new(),
            details: BTreeMap::new(),
        };
        let retained = retain_timeline_events(
            vec![
                event(1, "normal"),
                event(2, "normal"),
                event(3, "outlier_after_2100"),
            ],
            1,
        );
        assert_eq!(retained.events.len(), 1);
        assert_eq!(retained.events[0].timestamp_unix_ms, 2);
        assert_eq!(retained.outliers_matched, 1);
        assert_eq!(retained.outliers_retained, 0);
    }
}
