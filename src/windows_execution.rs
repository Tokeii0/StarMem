use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat, Utc};
use serde::Serialize;

use crate::session::AnalysisSession;
use crate::windows::WindowsKernelContext;
use crate::windows::prefetch_plugins::PrefetchScanOptions;
use crate::windows_timeline::{
    WindowsTimelineOptions, WindowsTimelineStage, analyze_windows_timeline,
};

#[derive(Debug, Clone)]
pub struct WindowsExecutionOptions {
    pub include_processes: bool,
    pub include_prefetch: bool,
    pub include_bam_dam: bool,
    pub include_userassist: bool,
    pub include_shimcache: bool,
    pub include_amcache: bool,
    pub exact_only: bool,
    pub aggregate: bool,
    pub program: Option<String>,
    pub user: Option<String>,
    pub correlation_window_ms: u64,
    pub latest_per_program: bool,
    pub file_scan_limit: usize,
    pub prefetch_file_limit: usize,
    pub reference_limit: usize,
    pub max_prefetch_file_size: u64,
    pub max_prefetch_uncompressed_size: usize,
    pub registry_limit: usize,
    pub shimcache_limit: usize,
    pub event_limit: usize,
    pub from: Option<String>,
    pub to: Option<String>,
    pub newest_first: bool,
}

impl Default for WindowsExecutionOptions {
    fn default() -> Self {
        Self {
            include_processes: false,
            include_prefetch: true,
            include_bam_dam: true,
            include_userassist: true,
            include_shimcache: true,
            include_amcache: true,
            exact_only: false,
            aggregate: false,
            program: None,
            user: None,
            correlation_window_ms: 2_000,
            latest_per_program: false,
            file_scan_limit: 1_000_000,
            prefetch_file_limit: 4096,
            reference_limit: 1024,
            max_prefetch_file_size: 32 * 1024 * 1024,
            max_prefetch_uncompressed_size: 64 * 1024 * 1024,
            registry_limit: 100_000,
            shimcache_limit: 100_000,
            event_limit: 500_000,
            from: None,
            to: None,
            newest_first: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsExecutionStage {
    Prefetch,
    RegistryAndShimcache,
    Finalize,
}

#[derive(Debug, Serialize)]
pub struct WindowsExecutionReport {
    pub image: String,
    pub kernel: WindowsKernelContext,
    pub filters: WindowsExecutionFilters,
    pub sources: Vec<WindowsExecutionSourceStatus>,
    pub matched_events: usize,
    pub exact_execution_events: usize,
    pub contextual_events: usize,
    pub outlier_events_matched: usize,
    pub events: Vec<WindowsExecutionRecord>,
    pub episodes: Vec<WindowsExecutionEpisode>,
    pub artifact_counts: BTreeMap<String, usize>,
    pub truncated: bool,
    pub complete: bool,
    pub scope: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct WindowsExecutionFilters {
    pub from: Option<String>,
    pub to: Option<String>,
    pub exact_only: bool,
    pub aggregate: bool,
    pub include_processes: bool,
    pub program: Option<String>,
    pub user: Option<String>,
    pub correlation_window_ms: u64,
    pub latest_per_program: bool,
    pub newest_first: bool,
    pub event_limit: usize,
}

#[derive(Debug, Serialize)]
pub struct WindowsExecutionSourceStatus {
    pub source: String,
    pub artifacts_examined: usize,
    pub events_matched: usize,
    pub complete: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowsExecutionRecord {
    pub timestamp: String,
    pub timestamp_unix_ms: i64,
    pub timestamp_quality: String,
    pub artifact: String,
    pub source: String,
    pub executable: String,
    pub path: Option<String>,
    pub user_sid: Option<String>,
    pub run_count: Option<u32>,
    pub execution_supported: bool,
    pub exact_execution_time: bool,
    pub confidence: String,
    pub time_semantics: String,
    pub description: String,
    pub object_address: Option<u64>,
    pub details: BTreeMap<String, String>,
}

/// One execution episode derived from one or more independently retained events.
///
/// `canonical_timestamp` is copied from a real event (preferably EPROCESS
/// CreateTime); timestamps are never averaged or synthesized.
#[derive(Debug, Clone, Serialize)]
pub struct WindowsExecutionEpisode {
    pub program: String,
    pub program_key: String,
    pub canonical_timestamp: String,
    pub canonical_timestamp_unix_ms: i64,
    pub canonical_artifact: String,
    pub canonical_source: String,
    pub canonical_time_semantics: String,
    pub process_start: Option<WindowsExecutionEpisodeEvidence>,
    pub shell_invocation: Option<WindowsExecutionEpisodeEvidence>,
    pub first_evidence_timestamp: String,
    pub first_evidence_unix_ms: i64,
    pub last_evidence_timestamp: String,
    pub last_evidence_unix_ms: i64,
    pub spread_ms: u64,
    pub pid: Option<u64>,
    pub session_id: Option<u32>,
    pub user_sid: Option<String>,
    pub user: Option<String>,
    pub path: Option<String>,
    pub evidence_count: usize,
    pub independent_source_count: usize,
    pub artifacts: Vec<String>,
    pub sources: Vec<String>,
    pub confidence: String,
    pub correlation_reasons: Vec<String>,
    pub evidence: Vec<WindowsExecutionRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowsExecutionEpisodeEvidence {
    pub timestamp: String,
    pub timestamp_unix_ms: i64,
    pub artifact: String,
    pub source: String,
    pub time_semantics: String,
    pub executable: String,
    pub path: Option<String>,
    pub pid: Option<u64>,
    pub object_address: Option<u64>,
}

pub fn analyze_windows_execution<F>(
    session: &AnalysisSession,
    options: &WindowsExecutionOptions,
    mut progress: F,
) -> Result<WindowsExecutionReport>
where
    F: FnMut(WindowsExecutionStage),
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
    let from_ms = from.map(|timestamp| timestamp.timestamp_millis());
    let to_ms = to.map(|timestamp| timestamp.timestamp_millis());
    let mut events = Vec::new();
    let mut sources = Vec::new();
    let mut warnings = Vec::new();
    let mut complete = true;

    if options.include_processes {
        match session.processes(65_536) {
            Ok(report) => {
                let artifacts_examined = report.processes.len();
                let before = events.len();
                let source_complete =
                    process_source_complete(report.complete, !report.warnings.is_empty());
                for record in report.processes {
                    let process = record.details;
                    let Some(timestamp) = process.create_time.as_deref() else {
                        continue;
                    };
                    let Some((unix_ms, quality)) = timestamp_metadata(timestamp) else {
                        continue;
                    };
                    if !within_time_filter(unix_ms, from_ms, to_ms) {
                        continue;
                    }

                    let mut details = BTreeMap::from([
                        ("pid".to_owned(), record.pid.to_string()),
                        (
                            "ppid".to_owned(),
                            record
                                .ppid
                                .map_or_else(String::new, |value| value.to_string()),
                        ),
                        ("state".to_owned(), process.state.clone()),
                        (
                            "create_time_filetime".to_owned(),
                            process
                                .create_time_raw
                                .map_or_else(String::new, |value| value.to_string()),
                        ),
                        (
                            "session_id".to_owned(),
                            process
                                .session_id
                                .map_or_else(String::new, |value| value.to_string()),
                        ),
                        (
                            "token_session_id".to_owned(),
                            process
                                .token_session_id
                                .map_or_else(String::new, |value| value.to_string()),
                        ),
                        (
                            "user_name".to_owned(),
                            process.user_name.clone().unwrap_or_default(),
                        ),
                        (
                            "user_domain".to_owned(),
                            process.user_domain.clone().unwrap_or_default(),
                        ),
                        (
                            "user_name_source".to_owned(),
                            process.user_name_source.clone().unwrap_or_default(),
                        ),
                        (
                            "environment_user_name".to_owned(),
                            process.environment_user_name.clone().unwrap_or_default(),
                        ),
                        (
                            "environment_user_profile".to_owned(),
                            process.environment_user_profile.clone().unwrap_or_default(),
                        ),
                        (
                            "command_line".to_owned(),
                            process.command_line.clone().unwrap_or_default(),
                        ),
                        (
                            "token_authentication_id".to_owned(),
                            process
                                .token_authentication_id
                                .map_or_else(String::new, |value| format!("{value:#x}")),
                        ),
                        (
                            "token_originating_logon_session".to_owned(),
                            process
                                .token_originating_logon_session
                                .map_or_else(String::new, |value| format!("{value:#x}")),
                        ),
                        (
                            "logon_sid".to_owned(),
                            process.logon_sid.clone().unwrap_or_default(),
                        ),
                        (
                            "execution_evidence".to_owned(),
                            "direct_eprocess_create_time".to_owned(),
                        ),
                    ]);
                    if let Some(token) = process.token {
                        details.insert("token".to_owned(), format!("{token:#x}"));
                    }
                    events.push(WindowsExecutionRecord {
                        timestamp: timestamp.to_owned(),
                        timestamp_unix_ms: unix_ms,
                        timestamp_quality: quality,
                        artifact: "process".to_owned(),
                        source: "process.eprocess".to_owned(),
                        executable: record.name.clone(),
                        path: process.image_path.clone(),
                        user_sid: process.user_sid.clone(),
                        run_count: None,
                        execution_supported: true,
                        exact_execution_time: true,
                        confidence: "high".to_owned(),
                        time_semantics: "process_creation_time".to_owned(),
                        description: format!(
                            "EPROCESS CreateTime 记录进程创建：{} (PID {})",
                            record.name, record.pid
                        ),
                        object_address: Some(record.eprocess),
                        details,
                    });
                }
                complete &= source_complete;
                warnings.extend(report.warnings.into_iter().map(|warning| {
                    format!("process.eprocess [{}]：{}", warning.kind, warning.message)
                }));
                sources.push(WindowsExecutionSourceStatus {
                    source: "process.eprocess".to_owned(),
                    artifacts_examined,
                    events_matched: events.len() - before,
                    complete: source_complete,
                    error: None,
                });
            }
            Err(error) => {
                let message = format!("EPROCESS CreateTime 恢复失败：{error:#}");
                warnings.push(message.clone());
                sources.push(failed_source("process.eprocess", message));
                complete = false;
            }
        }
    }

    if options.include_prefetch {
        progress(WindowsExecutionStage::Prefetch);
        match session.prefetch(&PrefetchScanOptions {
            file_scan_limit: options.file_scan_limit,
            file_limit: options.prefetch_file_limit,
            reference_limit: options.reference_limit,
            max_file_size: options.max_prefetch_file_size,
            max_uncompressed_size: options.max_prefetch_uncompressed_size,
        }) {
            Ok(report) => {
                let before = events.len();
                let artifacts_examined = report.files_attempted;
                for record in report.records {
                    let executable_path =
                        executable_path_from_prefetch(&record.executable, &record.referenced_files);
                    for (index, (&raw, timestamp)) in record
                        .last_run_times_raw
                        .iter()
                        .zip(record.last_run_times.iter())
                        .enumerate()
                    {
                        let Some((unix_ms, quality)) = timestamp_metadata(timestamp) else {
                            continue;
                        };
                        if !within_time_filter(unix_ms, from_ms, to_ms) {
                            continue;
                        }
                        let exact = !record.boot_prefetch;
                        if options.exact_only && !exact {
                            continue;
                        }
                        let mut details = BTreeMap::from([
                            ("prefetch_file".to_owned(), record.path.clone()),
                            ("prefetch_version".to_owned(), record.version.to_string()),
                            (
                                "prefetch_hash".to_owned(),
                                format!("{:08X}", record.prefetch_hash),
                            ),
                            ("filetime".to_owned(), raw.to_string()),
                            ("time_index_newest_first".to_owned(), index.to_string()),
                            (
                                "referenced_file_count".to_owned(),
                                record.referenced_file_count.to_string(),
                            ),
                            (
                                "recovery_complete".to_owned(),
                                record.recovery_complete.to_string(),
                            ),
                        ]);
                        if let Some(matches) = record.filename_hash_matches {
                            details.insert("filename_hash_matches".to_owned(), matches.to_string());
                        }
                        events.push(WindowsExecutionRecord {
                            timestamp: timestamp.clone(),
                            timestamp_unix_ms: unix_ms,
                            timestamp_quality: quality,
                            artifact: "prefetch".to_owned(),
                            source: record.container.clone(),
                            executable: record.executable.clone(),
                            path: executable_path.clone(),
                            user_sid: None,
                            run_count: Some(record.run_count),
                            execution_supported: true,
                            exact_execution_time: exact,
                            confidence: if exact { "high" } else { "contextual" }.to_owned(),
                            time_semantics: if exact {
                                "program_execution_time"
                            } else {
                                "system_boot_prefetch_time"
                            }
                            .to_owned(),
                            description: if exact {
                                format!("Prefetch 记录程序运行：{}", record.executable)
                            } else {
                                "NTOSBOOT Prefetch 启动时间证据".to_owned()
                            },
                            object_address: Some(record.file_object),
                            details,
                        });
                    }
                }
                let source_complete = report.complete;
                complete &= source_complete;
                warnings.extend(
                    report
                        .warnings
                        .into_iter()
                        .map(|warning| format!("prefetch：{warning}")),
                );
                sources.push(WindowsExecutionSourceStatus {
                    source: "prefetch".to_owned(),
                    artifacts_examined,
                    events_matched: events.len() - before,
                    complete: source_complete,
                    error: None,
                });
            }
            Err(error) => {
                let message = format!("prefetchscan 失败：{error:#}");
                warnings.push(message.clone());
                sources.push(failed_source("prefetch", message));
                complete = false;
            }
        }
    }

    let include_shimcache = options.include_shimcache && !options.exact_only;
    let include_amcache = options.include_amcache && !options.exact_only;
    let include_registry = options.include_bam_dam || options.include_userassist || include_amcache;
    if include_registry || include_shimcache {
        progress(WindowsExecutionStage::RegistryAndShimcache);
        let timeline_options = WindowsTimelineOptions {
            include_processes: false,
            include_threads: false,
            include_mft: false,
            include_shimcache,
            include_registry,
            include_accessed: false,
            process_limit: 1,
            thread_limit: 1,
            mft_limit: 1,
            shimcache_limit: options.shimcache_limit,
            registry_limit: options.registry_limit,
            event_limit: usize::MAX,
            pid: None,
            from: options.from.clone(),
            to: options.to.clone(),
            newest_first: false,
        };
        match analyze_windows_timeline(
            session,
            &timeline_options,
            |_stage: WindowsTimelineStage| {},
        ) {
            Ok(report) => {
                for status in report.sources {
                    let selected = match status.source.as_str() {
                        "registry.bam_dam" => options.include_bam_dam,
                        "registry.userassist" => options.include_userassist,
                        "registry.amcache" => include_amcache,
                        "shimcache" => include_shimcache,
                        _ => false,
                    };
                    if !selected {
                        continue;
                    }
                    complete &= status.complete;
                    sources.push(WindowsExecutionSourceStatus {
                        source: status.source,
                        artifacts_examined: status.records_examined,
                        events_matched: status.events_matched,
                        complete: status.complete,
                        error: status.error,
                    });
                }
                warnings.extend(report.warnings.into_iter().filter(|warning| {
                    if warning.starts_with("registry.taskcache：") {
                        return false;
                    }
                    if warning.starts_with("registry.userassist：") {
                        return options.include_userassist;
                    }
                    if warning.starts_with("registry.amcache：") {
                        return include_amcache;
                    }
                    if warning.starts_with("shimcache：") {
                        return include_shimcache;
                    }
                    if warning.starts_with("registry.bam_dam：")
                        || warning.starts_with("registry：")
                    {
                        return options.include_bam_dam;
                    }
                    true
                }));
                for event in report.events {
                    let classification = match event.action.as_str() {
                        "bam_dam_execution" if options.include_bam_dam => Some((
                            "bam_dam",
                            true,
                            true,
                            "high",
                            "program_execution_time",
                            "direct_execution_time",
                        )),
                        "userassist_execution" if options.include_userassist => Some((
                            "userassist",
                            true,
                            true,
                            "high",
                            "user_program_execution_time",
                            "direct_execution_time",
                        )),
                        "shimcache_file_modified" if include_shimcache => Some((
                            "shimcache",
                            event
                                .details
                                .get("executed")
                                .is_some_and(|value| value == "true"),
                            false,
                            "contextual",
                            "cached_file_last_modified_time",
                            "execution_cache_context",
                        )),
                        "amcache_key_modified" if include_amcache => Some((
                            "amcache",
                            false,
                            false,
                            "contextual",
                            "inventory_key_last_write_time",
                            "inventory_context",
                        )),
                        _ => None,
                    };
                    let Some((
                        artifact,
                        execution_supported,
                        exact,
                        confidence,
                        semantics,
                        evidence,
                    )) = classification
                    else {
                        continue;
                    };
                    let path = event.path.clone();
                    let executable = path
                        .as_deref()
                        .map(executable_basename)
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| event.description.clone());
                    let mut details = event.details;
                    details.insert("execution_evidence".to_owned(), evidence.to_owned());
                    let user_sid = details
                        .get("sid")
                        .cloned()
                        .filter(|value| !value.is_empty())
                        .or_else(|| {
                            details
                                .get("hive")
                                .and_then(|hive| extract_sid_from_text(hive))
                        });
                    if !details.contains_key("user_name")
                        && let Some(user_name) = details
                            .get("hive")
                            .and_then(|hive| extract_profile_user(hive))
                    {
                        details.insert("user_name".to_owned(), user_name);
                    }
                    let run_count = details
                        .get("run_count")
                        .and_then(|value| value.parse().ok());
                    events.push(WindowsExecutionRecord {
                        timestamp: event.timestamp,
                        timestamp_unix_ms: event.timestamp_unix_ms,
                        timestamp_quality: event.timestamp_quality,
                        artifact: artifact.to_owned(),
                        source: event.source,
                        executable,
                        path,
                        user_sid,
                        run_count,
                        execution_supported,
                        exact_execution_time: exact,
                        confidence: confidence.to_owned(),
                        time_semantics: semantics.to_owned(),
                        description: event.description,
                        object_address: event.object_address,
                        details,
                    });
                }
            }
            Err(error) => {
                let message = format!("注册表/Shimcache 执行证据聚合失败：{error:#}");
                warnings.push(message.clone());
                for (source, enabled) in [
                    ("registry.bam_dam", options.include_bam_dam),
                    ("registry.userassist", options.include_userassist),
                    ("registry.amcache", include_amcache),
                    ("shimcache", include_shimcache),
                ] {
                    if enabled {
                        sources.push(failed_source(source, message.clone()));
                    }
                }
                complete = false;
            }
        }
    }

    progress(WindowsExecutionStage::Finalize);
    events.retain(|event| {
        options
            .program
            .as_deref()
            .is_none_or(|program| event_matches_program(event, program))
            && options
                .user
                .as_deref()
                .is_none_or(|user| event_matches_user(event, user))
    });
    if options.program.is_some() || options.user.is_some() {
        for status in &mut sources {
            status.events_matched = events
                .iter()
                .filter(|event| source_status_matches_event(&status.source, event))
                .count();
        }
    }
    events.sort_unstable_by(|left, right| {
        left.timestamp_unix_ms
            .cmp(&right.timestamp_unix_ms)
            .then_with(|| left.artifact.cmp(&right.artifact))
            .then_with(|| left.executable.cmp(&right.executable))
            .then_with(|| left.object_address.cmp(&right.object_address))
    });
    let matched_events = events.len();
    let outlier_events_matched = events
        .iter()
        .filter(|event| event.timestamp_quality != "normal")
        .count();
    let truncated = events.len() > options.event_limit;
    if truncated {
        let mut normal = events
            .iter()
            .filter(|event| event.timestamp_quality == "normal")
            .cloned()
            .collect::<Vec<_>>();
        let mut outliers = events
            .into_iter()
            .filter(|event| event.timestamp_quality != "normal")
            .collect::<Vec<_>>();
        if normal.len() >= options.event_limit {
            normal.drain(..normal.len() - options.event_limit);
            events = normal;
        } else {
            let remaining = options.event_limit - normal.len();
            if outliers.len() > remaining {
                outliers.drain(..outliers.len() - remaining);
            }
            normal.extend(outliers);
            normal.sort_unstable_by_key(|event| event.timestamp_unix_ms);
            events = normal;
        }
        complete = false;
        warnings.push(format!(
            "执行证据匹配到 {matched_events} 条事件，达到 {} 条上限；优先保留最新正常时间事件",
            options.event_limit
        ));
    }
    let episodes = if options.aggregate {
        aggregate_execution_events(
            &events,
            options.correlation_window_ms,
            options.latest_per_program,
            options.newest_first,
        )
    } else {
        Vec::new()
    };
    if options.newest_first {
        events.reverse();
    }
    let exact_execution_events = events
        .iter()
        .filter(|event| event.exact_execution_time)
        .count();
    let contextual_events = events.len().saturating_sub(exact_execution_events);
    let mut artifact_counts = BTreeMap::new();
    for event in &events {
        *artifact_counts.entry(event.artifact.clone()).or_insert(0) += 1;
    }

    Ok(WindowsExecutionReport {
        image: session.image().path().display().to_string(),
        kernel: session.kernel().clone(),
        filters: WindowsExecutionFilters {
            from: from.map(format_utc),
            to: to.map(format_utc),
            exact_only: options.exact_only,
            aggregate: options.aggregate,
            include_processes: options.include_processes,
            program: options.program.clone(),
            user: options.user.clone(),
            correlation_window_ms: options.correlation_window_ms,
            latest_per_program: options.latest_per_program,
            newest_first: options.newest_first,
            event_limit: options.event_limit,
        },
        sources,
        matched_events,
        exact_execution_events,
        contextual_events,
        outlier_events_matched,
        events,
        episodes,
        artifact_counts,
        truncated,
        complete,
        scope: "活动进程链中的 EPROCESS CreateTime、Prefetch、BAM/DAM 与 UserAssist 的时间作为直接执行时间；EPROCESS 来源不覆盖已退出或已脱链进程。Shimcache 仅保留缓存条目的文件最后修改时间，Amcache 仅保留清单键最后写入时间。episode 按程序、用户、会话、可执行路径与时间窗口关联；canonical 优先选择 EPROCESS CreateTime，从不对时间取平均值。contextual 事件不冒充精确执行时间，--exact-only 可排除它们。".to_owned(),
        warnings,
    })
}

#[derive(Debug)]
struct ExecutionEpisodeBuilder {
    program_key: String,
    evidence: Vec<WindowsExecutionRecord>,
}

impl ExecutionEpisodeBuilder {
    fn correlation_distance(
        &self,
        event: &WindowsExecutionRecord,
        correlation_window_ms: u64,
    ) -> Option<u64> {
        let first = self
            .evidence
            .iter()
            .map(|item| item.timestamp_unix_ms)
            .min()?;
        let last = self
            .evidence
            .iter()
            .map(|item| item.timestamp_unix_ms)
            .max()?;
        let new_first = first.min(event.timestamp_unix_ms);
        let new_last = last.max(event.timestamp_unix_ms);
        if new_last.abs_diff(new_first) > correlation_window_ms {
            return None;
        }

        if !identity_sets_compatible(&episode_user_sids(&self.evidence), &event_user_sids(event))
            || !identity_sets_compatible(
                &episode_user_names(&self.evidence),
                &event_user_names(event),
            )
            || !identity_sets_compatible(
                &episode_session_ids(&self.evidence),
                &event_session_ids(event),
            )
            || !identity_sets_compatible(
                &episode_executable_paths(&self.evidence),
                &event_executable_paths(event),
            )
        {
            return None;
        }

        if event.artifact == "process" {
            let existing_process_pids = self
                .evidence
                .iter()
                .filter(|item| item.artifact == "process")
                .filter_map(event_pid)
                .collect::<BTreeSet<_>>();
            if let Some(pid) = event_pid(event)
                && !existing_process_pids.is_empty()
                && !existing_process_pids.contains(&pid)
            {
                return None;
            }
        }

        self.evidence
            .iter()
            .map(|item| item.timestamp_unix_ms.abs_diff(event.timestamp_unix_ms))
            .min()
    }
}

fn aggregate_execution_events(
    events: &[WindowsExecutionRecord],
    correlation_window_ms: u64,
    latest_per_program: bool,
    newest_first: bool,
) -> Vec<WindowsExecutionEpisode> {
    let mut ordered = events.to_vec();
    ordered.sort_unstable_by(|left, right| {
        left.timestamp_unix_ms
            .cmp(&right.timestamp_unix_ms)
            .then_with(|| left.artifact.cmp(&right.artifact))
            .then_with(|| left.executable.cmp(&right.executable))
    });

    let mut builders: Vec<ExecutionEpisodeBuilder> = Vec::new();
    let mut active_by_program = BTreeMap::<String, Vec<usize>>::new();
    for event in ordered {
        let program_key = event_program_key(&event);
        if program_key.is_empty() {
            continue;
        }
        let active = active_by_program.entry(program_key.clone()).or_default();
        active.retain(|index| {
            builders[*index].evidence.first().is_some_and(|first| {
                event.timestamp_unix_ms.abs_diff(first.timestamp_unix_ms) <= correlation_window_ms
            })
        });
        let candidates = active
            .iter()
            .copied()
            .filter_map(|index| {
                builders[index]
                    .correlation_distance(&event, correlation_window_ms)
                    .map(|distance| (index, distance))
            })
            .collect::<Vec<_>>();
        // If two episodes remain compatible after user/SID/session/path/PID
        // checks, time proximity alone cannot prove which launch owns this
        // artifact. Keep it independent instead of choosing a builder by
        // iteration order or a marginal timestamp difference.
        let candidate = if candidates.len() == 1 {
            candidates.into_iter().next().map(|(index, _)| index)
        } else {
            None
        };
        if let Some(index) = candidate {
            builders[index].evidence.push(event);
        } else {
            let index = builders.len();
            builders.push(ExecutionEpisodeBuilder {
                program_key,
                evidence: vec![event],
            });
            active.push(index);
        }
    }

    let mut episodes = builders
        .into_iter()
        .map(build_execution_episode)
        .collect::<Vec<_>>();
    if latest_per_program {
        let mut latest = BTreeMap::<String, WindowsExecutionEpisode>::new();
        for episode in episodes {
            let replace = latest.get(&episode.program_key).is_none_or(|current| {
                (
                    episode.canonical_timestamp_unix_ms,
                    episode.last_evidence_unix_ms,
                ) > (
                    current.canonical_timestamp_unix_ms,
                    current.last_evidence_unix_ms,
                )
            });
            if replace {
                latest.insert(episode.program_key.clone(), episode);
            }
        }
        episodes = latest.into_values().collect();
    }
    episodes.sort_unstable_by(|left, right| {
        left.canonical_timestamp_unix_ms
            .cmp(&right.canonical_timestamp_unix_ms)
            .then_with(|| left.program_key.cmp(&right.program_key))
            .then_with(|| left.pid.cmp(&right.pid))
    });
    if newest_first {
        episodes.reverse();
    }
    episodes
}

fn build_execution_episode(builder: ExecutionEpisodeBuilder) -> WindowsExecutionEpisode {
    let mut evidence = builder.evidence;
    evidence.sort_unstable_by(|left, right| {
        left.timestamp_unix_ms
            .cmp(&right.timestamp_unix_ms)
            .then_with(|| left.artifact.cmp(&right.artifact))
            .then_with(|| left.executable.cmp(&right.executable))
    });

    let process_index = evidence
        .iter()
        .enumerate()
        .filter(|(_, event)| event.artifact == "process")
        .min_by_key(|(_, event)| event.timestamp_unix_ms)
        .map(|(index, _)| index);
    let shell_index = evidence
        .iter()
        .enumerate()
        .filter(|(_, event)| event.artifact == "userassist")
        .max_by_key(|(_, event)| {
            (
                event.path.as_deref().is_some_and(is_link_path) || is_link_path(&event.executable),
                event.timestamp_unix_ms,
            )
        })
        .map(|(index, _)| index);
    let canonical_index = process_index.or(shell_index).unwrap_or_else(|| {
        evidence
            .iter()
            .enumerate()
            .min_by_key(|(_, event)| (canonical_rank(event), event.timestamp_unix_ms))
            .map(|(index, _)| index)
            .expect("an execution episode always has evidence")
    });

    let canonical = &evidence[canonical_index];
    let first = evidence
        .first()
        .expect("an execution episode always has first evidence");
    let last = evidence
        .last()
        .expect("an execution episode always has last evidence");
    let process_start = process_index.map(|index| episode_marker(&evidence[index]));
    let shell_invocation = shell_index.map(|index| episode_marker(&evidence[index]));
    let artifacts = evidence
        .iter()
        .map(|event| event.artifact.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let sources = evidence
        .iter()
        .map(|event| event.source.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let direct_sources = evidence
        .iter()
        .filter(|event| event.exact_execution_time)
        .map(|event| event.artifact.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let has_process = process_index.is_some();
    let has_independent_invocation = evidence
        .iter()
        .any(|event| event.artifact != "process" && event.exact_execution_time);
    let confidence = if (has_process && has_independent_invocation) || direct_sources >= 2 {
        "high_corroborated"
    } else if has_process {
        "high"
    } else if evidence.iter().any(|event| event.exact_execution_time) {
        "medium"
    } else {
        "contextual"
    }
    .to_owned();
    let pid = process_index
        .and_then(|index| event_pid(&evidence[index]))
        .or_else(|| evidence.iter().find_map(event_pid));
    let session_id = process_index
        .and_then(|index| event_session_ids(&evidence[index]).into_iter().next())
        .or_else(|| {
            evidence
                .iter()
                .find_map(|event| event_session_ids(event).into_iter().next())
        });
    let user_sid = process_index
        .and_then(|index| event_display_sid(&evidence[index]))
        .or_else(|| evidence.iter().find_map(event_display_sid));
    let user = process_index
        .and_then(|index| event_display_user(&evidence[index]))
        .or_else(|| evidence.iter().find_map(event_display_user));
    let path = process_index
        .and_then(|index| evidence[index].path.clone())
        .or_else(|| canonical.path.clone())
        .or_else(|| {
            evidence
                .iter()
                .find_map(|event| event.path.as_ref().cloned())
        });
    let program = process_index
        .map(|index| evidence[index].executable.clone())
        .unwrap_or_else(|| canonical.executable.clone());
    let spread_ms = last.timestamp_unix_ms.abs_diff(first.timestamp_unix_ms);
    let independent_source_count = artifacts.len();
    let mut correlation_reasons = vec![
        format!("normalized_program={}", builder.program_key),
        format!("observed_spread_ms={spread_ms}"),
    ];
    if user_sid.is_some() || user.is_some() {
        correlation_reasons.push("user_identity_consistent".to_owned());
    }
    if session_id.is_some() {
        correlation_reasons.push("session_id_consistent".to_owned());
    }
    if !episode_executable_paths(&evidence).is_empty() {
        correlation_reasons.push("executable_path_consistent".to_owned());
    }
    correlation_reasons.push(
        if has_process {
            "canonical=eprocess_create_time"
        } else if shell_index.is_some() {
            "canonical=userassist_shell_invocation"
        } else {
            "canonical=highest_ranked_observed_event"
        }
        .to_owned(),
    );

    WindowsExecutionEpisode {
        program,
        program_key: builder.program_key,
        canonical_timestamp: canonical.timestamp.clone(),
        canonical_timestamp_unix_ms: canonical.timestamp_unix_ms,
        canonical_artifact: canonical.artifact.clone(),
        canonical_source: canonical.source.clone(),
        canonical_time_semantics: canonical.time_semantics.clone(),
        process_start,
        shell_invocation,
        first_evidence_timestamp: first.timestamp.clone(),
        first_evidence_unix_ms: first.timestamp_unix_ms,
        last_evidence_timestamp: last.timestamp.clone(),
        last_evidence_unix_ms: last.timestamp_unix_ms,
        spread_ms,
        pid,
        session_id,
        user_sid,
        user,
        path,
        evidence_count: evidence.len(),
        independent_source_count,
        artifacts,
        sources,
        confidence,
        correlation_reasons,
        evidence,
    }
}

fn episode_marker(event: &WindowsExecutionRecord) -> WindowsExecutionEpisodeEvidence {
    WindowsExecutionEpisodeEvidence {
        timestamp: event.timestamp.clone(),
        timestamp_unix_ms: event.timestamp_unix_ms,
        artifact: event.artifact.clone(),
        source: event.source.clone(),
        time_semantics: event.time_semantics.clone(),
        executable: event.executable.clone(),
        path: event.path.clone(),
        pid: event_pid(event),
        object_address: event.object_address,
    }
}

fn canonical_rank(event: &WindowsExecutionRecord) -> u8 {
    match event.artifact.as_str() {
        "process" => 0,
        "userassist" => 1,
        "bam_dam" => 2,
        "prefetch" => 3,
        _ if event.exact_execution_time => 4,
        _ => 5,
    }
}

fn event_program_key(event: &WindowsExecutionRecord) -> String {
    let executable = normalize_program_text(&event.executable);
    if !executable.is_empty() {
        return executable;
    }
    event
        .path
        .as_deref()
        .map(normalize_program_text)
        .unwrap_or_default()
}

fn normalize_program_text(value: &str) -> String {
    let trimmed = value.trim().trim_matches(['"', '\'']);
    let basename = executable_basename(trimmed)
        .trim()
        .trim_matches(['"', '\''])
        .to_ascii_lowercase();
    let known_suffixes = [".exe", ".com", ".bat", ".cmd", ".scr", ".lnk"];
    if let Some(suffix) = known_suffixes
        .iter()
        .find(|suffix| basename.ends_with(**suffix))
    {
        return basename[..basename.len() - suffix.len()]
            .trim_matches([' ', '.', '{', '}'])
            .to_owned();
    }
    let normalized = basename.trim_matches([' ', '.', '{', '}']);
    // UserAssist commonly retains VeraCrypt's registered application id while
    // process/prefetch evidence uses VeraCrypt.exe. Keep this alias explicit:
    // stripping every dotted prefix would collapse unrelated identifiers such
    // as VendorA.Agent and VendorB.Agent into one program.
    if normalized.eq_ignore_ascii_case("idrix.veracrypt") {
        "veracrypt".to_owned()
    } else {
        normalized.to_owned()
    }
}

fn event_matches_program(event: &WindowsExecutionRecord, program: &str) -> bool {
    let needle = program.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }
    let key = normalize_program_text(program);
    event_program_key(event) == key
        || event.executable.to_ascii_lowercase().contains(&needle)
        || event
            .path
            .as_deref()
            .is_some_and(|path| path.to_ascii_lowercase().contains(&needle))
}

fn event_matches_user(event: &WindowsExecutionRecord, user: &str) -> bool {
    let needle = user.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }
    if needle.starts_with("s-1-") {
        return event_user_sids(event).contains(&needle);
    }
    let user_name = normalize_user_name(&needle);
    event_user_names(event).contains(&user_name)
}

fn normalize_user_name(value: &str) -> String {
    let value = value.trim().to_ascii_lowercase();
    value
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&value)
        .split('@')
        .next()
        .unwrap_or(&value)
        .trim()
        .to_owned()
}

fn event_user_sids(event: &WindowsExecutionRecord) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    if let Some(sid) = event.user_sid.as_deref().filter(|value| !value.is_empty()) {
        values.insert(sid.to_ascii_lowercase());
    }
    for key in ["sid", "user_sid"] {
        if let Some(sid) = event.details.get(key).filter(|value| !value.is_empty()) {
            values.insert(sid.to_ascii_lowercase());
        }
    }
    values
}

fn event_display_sid(event: &WindowsExecutionRecord) -> Option<String> {
    event
        .user_sid
        .clone()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            ["sid", "user_sid"]
                .into_iter()
                .filter_map(|key| event.details.get(key))
                .find(|value| !value.is_empty())
                .cloned()
        })
}

fn event_user_names(event: &WindowsExecutionRecord) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for key in ["user_name", "environment_user_name", "user"] {
        if let Some(value) = event.details.get(key).filter(|value| !value.is_empty()) {
            values.insert(normalize_user_name(value));
        }
    }
    for key in ["hive", "environment_user_profile"] {
        if let Some(value) = event.details.get(key)
            && let Some(user) = extract_profile_user(value)
        {
            values.insert(normalize_user_name(&user));
        }
    }
    values
}

fn event_display_user(event: &WindowsExecutionRecord) -> Option<String> {
    ["user_name", "environment_user_name", "user"]
        .into_iter()
        .filter_map(|key| event.details.get(key))
        .find(|value| !value.is_empty())
        .cloned()
        .or_else(|| {
            ["hive", "environment_user_profile"]
                .into_iter()
                .filter_map(|key| event.details.get(key))
                .find_map(|value| extract_profile_user(value))
        })
}

fn extract_profile_user(value: &str) -> Option<String> {
    let normalized = value.replace('/', "\\");
    let mut folded = normalized.clone();
    folded.make_ascii_lowercase();
    for marker in ["\\users\\", "\\documents and settings\\"] {
        let Some(index) = folded.find(marker) else {
            continue;
        };
        let rest = &normalized[index + marker.len()..];
        let user = rest.split('\\').next()?.trim();
        if !user.is_empty() {
            return Some(user.to_owned());
        }
    }
    None
}

fn extract_sid_from_text(value: &str) -> Option<String> {
    let mut folded = value.to_owned();
    folded.make_ascii_lowercase();
    let start = folded.find("s-1-")?;
    let sid = value[start..]
        .split(|character: char| !character.is_ascii_digit() && character != '-')
        .next()?
        .trim_end_matches('-');
    (sid.matches('-').count() >= 3).then(|| sid.to_owned())
}

fn event_session_ids(event: &WindowsExecutionRecord) -> BTreeSet<u32> {
    let session_id = event
        .details
        .get("session_id")
        .and_then(|value| value.parse::<u32>().ok())
        .or_else(|| {
            event
                .details
                .get("token_session_id")
                .and_then(|value| value.parse::<u32>().ok())
        });
    session_id.into_iter().collect()
}

fn event_executable_paths(event: &WindowsExecutionRecord) -> BTreeSet<String> {
    event
        .path
        .as_deref()
        .and_then(normalize_concrete_executable_path)
        .into_iter()
        .collect()
}

fn normalize_concrete_executable_path(path: &str) -> Option<String> {
    let path = path.trim().trim_matches(['"', '\'']);
    let mut normalized = path.replace('/', "\\").to_ascii_lowercase();
    while normalized.contains("\\\\") {
        normalized = normalized.replace("\\\\", "\\");
    }
    let is_executable = [".exe", ".com", ".bat", ".cmd", ".scr"]
        .iter()
        .any(|suffix| normalized.ends_with(suffix));
    (is_executable && normalized.contains('\\')).then_some(normalized)
}

fn is_link_path(path: &str) -> bool {
    path.trim()
        .trim_matches(['"', '\''])
        .to_ascii_lowercase()
        .ends_with(".lnk")
}

fn event_pid(event: &WindowsExecutionRecord) -> Option<u64> {
    event.details.get("pid")?.parse().ok()
}

fn episode_user_sids(events: &[WindowsExecutionRecord]) -> BTreeSet<String> {
    events.iter().flat_map(event_user_sids).collect()
}

fn episode_user_names(events: &[WindowsExecutionRecord]) -> BTreeSet<String> {
    events.iter().flat_map(event_user_names).collect()
}

fn episode_session_ids(events: &[WindowsExecutionRecord]) -> BTreeSet<u32> {
    events.iter().flat_map(event_session_ids).collect()
}

fn episode_executable_paths(events: &[WindowsExecutionRecord]) -> BTreeSet<String> {
    events.iter().flat_map(event_executable_paths).collect()
}

fn identity_sets_compatible<T: Ord>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> bool {
    left.is_empty() || right.is_empty() || !left.is_disjoint(right)
}

fn source_status_matches_event(source: &str, event: &WindowsExecutionRecord) -> bool {
    match source {
        "process.eprocess" => event.artifact == "process",
        "prefetch" => event.artifact == "prefetch",
        "registry.bam_dam" => event.artifact == "bam_dam",
        "registry.userassist" => event.artifact == "userassist",
        "registry.amcache" => event.artifact == "amcache",
        "shimcache" => event.artifact == "shimcache",
        source => event.source == source,
    }
}

fn validate_options(options: &WindowsExecutionOptions) -> Result<()> {
    ensure!(
        options.include_processes
            || options.include_prefetch
            || options.include_bam_dam
            || options.include_userassist
            || options.include_shimcache
            || options.include_amcache,
        "至少选择一个 Windows 执行证据来源"
    );
    ensure!(options.event_limit > 0, "执行事件上限必须大于零");
    ensure!(
        options.correlation_window_ms > 0,
        "执行证据关联时间窗口必须大于零"
    );
    ensure!(
        !options.latest_per_program || options.aggregate,
        "--latest-per-program 需要同时启用 --aggregate"
    );
    ensure!(
        options
            .program
            .as_deref()
            .is_none_or(|value| !value.trim().is_empty()),
        "程序筛选值不能为空"
    );
    ensure!(
        options
            .user
            .as_deref()
            .is_none_or(|value| !value.trim().is_empty()),
        "用户筛选值不能为空"
    );
    ensure!(
        !options.exact_only
            || options.include_processes
            || options.include_prefetch
            || options.include_bam_dam
            || options.include_userassist,
        "--exact-only 需要选择 process、prefetch、bam-dam 或 userassist 中至少一个直接执行时间来源"
    );
    ensure!(options.registry_limit > 0, "注册表结果上限必须大于零");
    ensure!(options.shimcache_limit > 0, "Shimcache 结果上限必须大于零");
    Ok(())
}

fn failed_source(source: &str, error: String) -> WindowsExecutionSourceStatus {
    WindowsExecutionSourceStatus {
        source: source.to_owned(),
        artifacts_examined: 0,
        events_matched: 0,
        complete: false,
        error: Some(error),
    }
}

fn process_source_complete(traversal_complete: bool, has_structural_warnings: bool) -> bool {
    traversal_complete && !has_structural_warnings
}

fn executable_path_from_prefetch(executable: &str, references: &[String]) -> Option<String> {
    references
        .iter()
        .find(|path| executable_basename(path).eq_ignore_ascii_case(executable))
        .cloned()
}

fn executable_basename(path: &str) -> String {
    path.trim_end_matches(['\\', '/'])
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_owned()
}

fn timestamp_metadata(timestamp: &str) -> Option<(i64, String)> {
    let parsed = DateTime::parse_from_rfc3339(timestamp)
        .ok()?
        .with_timezone(&Utc);
    let quality = if parsed.year() < 1980 {
        "outlier_before_1980"
    } else if parsed.year() > 2100 {
        "outlier_after_2100"
    } else {
        "normal"
    };
    Some((parsed.timestamp_millis(), quality.to_owned()))
}

fn within_time_filter(timestamp: i64, from: Option<i64>, to: Option<i64>) -> bool {
    from.is_none_or(|from| timestamp >= from) && to.is_none_or(|to| timestamp <= to)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_source_warnings_prevent_a_complete_status() {
        assert!(process_source_complete(true, false));
        assert!(!process_source_complete(true, true));
        assert!(!process_source_complete(false, false));
    }

    fn event(
        timestamp: &str,
        artifact: &str,
        source: &str,
        executable: &str,
        path: Option<&str>,
    ) -> WindowsExecutionRecord {
        let (timestamp_unix_ms, timestamp_quality) = timestamp_metadata(timestamp).unwrap();
        WindowsExecutionRecord {
            timestamp: timestamp.to_owned(),
            timestamp_unix_ms,
            timestamp_quality,
            artifact: artifact.to_owned(),
            source: source.to_owned(),
            executable: executable.to_owned(),
            path: path.map(str::to_owned),
            user_sid: None,
            run_count: None,
            execution_supported: true,
            exact_execution_time: true,
            confidence: "high".to_owned(),
            time_semantics: if artifact == "process" {
                "process_creation_time"
            } else {
                "user_program_execution_time"
            }
            .to_owned(),
            description: executable.to_owned(),
            object_address: None,
            details: BTreeMap::new(),
        }
    }

    fn with_identity(
        mut event: WindowsExecutionRecord,
        user: &str,
        sid: Option<&str>,
        session_id: u32,
    ) -> WindowsExecutionRecord {
        event
            .details
            .insert("user_name".to_owned(), user.to_owned());
        event
            .details
            .insert("session_id".to_owned(), session_id.to_string());
        event.user_sid = sid.map(str::to_owned);
        event
    }

    #[test]
    fn timestamp_quality_and_filters_are_stable() {
        let (normal, quality) = timestamp_metadata("2026-08-26T00:00:00Z").unwrap();
        assert_eq!(quality, "normal");
        assert!(within_time_filter(normal, Some(normal), Some(normal)));
        assert_eq!(
            timestamp_metadata("2200-01-01T00:00:00Z").unwrap().1,
            "outlier_after_2100"
        );
    }

    #[test]
    fn finds_executable_path_in_prefetch_references() {
        let references = vec![
            r"\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\KERNEL32.DLL".to_owned(),
            r"\DEVICE\HARDDISKVOLUME3\TOOLS\RANSOM.EXE".to_owned(),
        ];
        assert_eq!(
            executable_path_from_prefetch("RANSOM.EXE", &references),
            Some(r"\DEVICE\HARDDISKVOLUME3\TOOLS\RANSOM.EXE".to_owned())
        );
    }

    #[test]
    fn veracrypt_process_and_userassist_form_one_non_averaged_episode() {
        let mut process = with_identity(
            event(
                "2025-05-14T13:22:08.324Z",
                "process",
                "process.eprocess",
                "VeraCrypt.exe",
                Some(r"C:\Program Files\VeraCrypt\VeraCrypt.exe"),
            ),
            "testuser",
            Some("S-1-5-21-1000"),
            1,
        );
        process.details.insert("pid".to_owned(), "3416".to_owned());
        let app_id = with_identity(
            event(
                "2025-05-14T13:22:08.324Z",
                "userassist",
                "registry.userassist",
                "IDRIX.VeraCrypt",
                Some("IDRIX.VeraCrypt"),
            ),
            "testuser",
            None,
            1,
        );
        let link = with_identity(
            event(
                "2025-05-14T13:22:08.339Z",
                "userassist",
                "registry.userassist",
                "VeraCrypt.lnk",
                Some(r"C:\Users\testuser\AppData\Roaming\Microsoft\Windows\Recent\VeraCrypt.lnk"),
            ),
            "testuser",
            None,
            1,
        );

        let episodes = aggregate_execution_events(&[link, process, app_id], 2_000, false, false);
        assert_eq!(episodes.len(), 1);
        let episode = &episodes[0];
        assert_eq!(episode.program_key, "veracrypt");
        assert_eq!(episode.pid, Some(3416));
        assert_eq!(episode.evidence_count, 3);
        assert_eq!(episode.spread_ms, 15);
        assert_eq!(episode.canonical_artifact, "process");
        assert_eq!(episode.canonical_timestamp, "2025-05-14T13:22:08.324Z");
        assert_eq!(
            episode.process_start.as_ref().unwrap().timestamp,
            "2025-05-14T13:22:08.324Z"
        );
        assert_eq!(
            episode.shell_invocation.as_ref().unwrap().timestamp,
            "2025-05-14T13:22:08.339Z"
        );
    }

    #[test]
    fn correlation_never_crosses_user_path_or_time_boundaries() {
        let alice = with_identity(
            event(
                "2025-01-01T00:00:00.000Z",
                "userassist",
                "registry.userassist",
                "Tool.lnk",
                Some(r"C:\Users\alice\Recent\Tool.lnk"),
            ),
            "alice",
            None,
            1,
        );
        let bob = with_identity(
            event(
                "2025-01-01T00:00:00.001Z",
                "userassist",
                "registry.userassist",
                "Tool.lnk",
                Some(r"C:\Users\bob\Recent\Tool.lnk"),
            ),
            "bob",
            None,
            1,
        );
        assert_eq!(
            aggregate_execution_events(&[alice, bob], 2_000, false, false).len(),
            2
        );

        let first_path = with_identity(
            event(
                "2025-01-01T00:00:00.000Z",
                "bam_dam",
                "registry.bam_dam",
                "Tool.exe",
                Some(r"C:\Tools\Tool.exe"),
            ),
            "alice",
            None,
            1,
        );
        let second_path = with_identity(
            event(
                "2025-01-01T00:00:00.001Z",
                "bam_dam",
                "registry.bam_dam",
                "Tool.exe",
                Some(r"D:\Tools\Tool.exe"),
            ),
            "alice",
            None,
            1,
        );
        assert_eq!(
            aggregate_execution_events(&[first_path, second_path], 2_000, false, false).len(),
            2
        );

        let early = with_identity(
            event(
                "2025-01-01T00:00:00.000Z",
                "userassist",
                "registry.userassist",
                "Tool.lnk",
                None,
            ),
            "alice",
            None,
            1,
        );
        let late = with_identity(
            event(
                "2025-01-01T00:00:02.001Z",
                "userassist",
                "registry.userassist",
                "Tool.lnk",
                None,
            ),
            "alice",
            None,
            1,
        );
        assert_eq!(
            aggregate_execution_events(&[early, late], 2_000, false, false).len(),
            2
        );
    }

    #[test]
    fn distinct_process_ids_do_not_collapse_inside_the_window() {
        let mut first = with_identity(
            event(
                "2025-01-01T00:00:00.000Z",
                "process",
                "process.eprocess",
                "Tool.exe",
                Some(r"C:\Tools\Tool.exe"),
            ),
            "alice",
            Some("S-1-5-21-1000"),
            1,
        );
        first.details.insert("pid".to_owned(), "100".to_owned());
        let mut second = first.clone();
        second.timestamp = "2025-01-01T00:00:00.010Z".to_owned();
        second.timestamp_unix_ms = timestamp_metadata(&second.timestamp).unwrap().0;
        second.details.insert("pid".to_owned(), "101".to_owned());
        assert_eq!(
            aggregate_execution_events(&[first, second], 2_000, false, false).len(),
            2
        );
    }

    #[test]
    fn dotted_application_ids_are_not_globally_collapsed() {
        assert_eq!(normalize_program_text("IDRIX.VeraCrypt"), "veracrypt");
        assert_eq!(normalize_program_text("VendorA.Agent"), "vendora.agent");
        assert_eq!(normalize_program_text("VendorB.Agent"), "vendorb.agent");
        assert_ne!(
            normalize_program_text("VendorA.Agent"),
            normalize_program_text("VendorB.Agent")
        );
    }

    #[test]
    fn weak_evidence_is_not_arbitrarily_assigned_between_users() {
        let alice = with_identity(
            event(
                "2025-01-01T00:00:00.000Z",
                "process",
                "process.eprocess",
                "Tool.exe",
                Some(r"C:\Tools\Tool.exe"),
            ),
            "alice",
            Some("S-1-5-21-1000"),
            1,
        );
        let bob = with_identity(
            event(
                "2025-01-01T00:00:00.001Z",
                "process",
                "process.eprocess",
                "Tool.exe",
                Some(r"C:\Tools\Tool.exe"),
            ),
            "bob",
            Some("S-1-5-21-1001"),
            2,
        );
        let anonymous = event(
            "2025-01-01T00:00:00.002Z",
            "prefetch",
            "prefetch",
            "Tool.exe",
            Some(r"C:\Tools\Tool.exe"),
        );

        let episodes = aggregate_execution_events(&[alice, bob, anonymous], 2_000, false, false);
        assert_eq!(episodes.len(), 3);
        assert!(episodes.iter().any(|episode| {
            episode.evidence.len() == 1 && episode.evidence[0].artifact == "prefetch"
        }));
    }

    #[test]
    fn latest_per_program_reduces_only_after_episode_construction() {
        let first = event(
            "2025-01-01T00:00:00.000Z",
            "userassist",
            "registry.userassist",
            "Tool.lnk",
            None,
        );
        let second = event(
            "2025-01-01T00:01:00.000Z",
            "userassist",
            "registry.userassist",
            "Tool.lnk",
            None,
        );
        let episodes = aggregate_execution_events(&[first, second], 2_000, true, true);
        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].canonical_timestamp, "2025-01-01T00:01:00.000Z");
    }

    #[test]
    fn filters_use_normalized_program_and_profile_user() {
        let mut userassist = event(
            "2025-01-01T00:00:00.000Z",
            "userassist",
            "registry.userassist",
            "IDRIX.VeraCrypt",
            Some(r"C:\Users\testuser\Recent\VeraCrypt.lnk"),
        );
        userassist.details.insert(
            "hive".to_owned(),
            r"C:\Users\testuser\NTUSER.DAT".to_owned(),
        );
        assert!(event_matches_program(&userassist, "veracrypt"));
        assert!(event_matches_user(&userassist, "TESTUSER"));
        assert!(!event_matches_user(&userassist, "alice"));
    }

    #[test]
    fn defaults_preserve_non_aggregate_legacy_output() {
        let options = WindowsExecutionOptions::default();
        assert!(!options.include_processes);
        assert!(!options.aggregate);
        assert!(!options.latest_per_program);
        assert_eq!(options.correlation_window_ms, 2_000);
    }
}
