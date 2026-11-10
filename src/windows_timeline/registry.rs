use std::collections::BTreeMap;

use crate::session::AnalysisSession;
use crate::system::registry::{
    RegistryHiveStatus, analyze_amcache, analyze_registry, analyze_userassist,
};

use super::{
    EventInput, TimeFilter, WindowsTimelineOptions, WindowsTimelineRecord,
    WindowsTimelineSourceStatus, append_source_warnings, failed_source, optional_number,
    push_event,
};

const PROCESS_LIMIT: usize = 65_536;

pub(super) fn append_registry_events(
    session: &AnalysisSession,
    options: &WindowsTimelineOptions,
    filter: TimeFilter,
    events: &mut Vec<WindowsTimelineRecord>,
    sources: &mut Vec<WindowsTimelineSourceStatus>,
    warnings: &mut Vec<String>,
    complete: &mut bool,
) {
    let processes = match session.processes(PROCESS_LIMIT) {
        Ok(processes) => processes,
        Err(error) => {
            let message = format!("注册表时间线无法枚举活动进程：{error:#}");
            warnings.push(message.clone());
            for source in [
                "registry.bam_dam",
                "registry.taskcache",
                "registry.userassist",
                "registry.amcache",
            ] {
                sources.push(failed_source(source, message.clone()));
            }
            *complete = false;
            return;
        }
    };
    let process_complete = processes.complete;

    let mut registry = analyze_registry(session, &processes);
    let system_complete =
        process_complete && recovered_hive_complete(&registry.hives, "\\REGISTRY\\MACHINE\\SYSTEM");
    let software_complete = process_complete
        && recovered_hive_complete(&registry.hives, "\\REGISTRY\\MACHINE\\SOFTWARE");

    let bam_records_examined = registry.bam_entries.len();
    let bam_truncated = registry.bam_entries.len() > options.registry_limit;
    registry.bam_entries.truncate(options.registry_limit);
    let before = events.len();
    for record in registry.bam_entries {
        let details = BTreeMap::from([
            ("sid".to_owned(), record.sid),
            (
                "last_execution_filetime".to_owned(),
                optional_number(record.last_execution_raw),
            ),
        ]);
        push_event(
            events,
            filter,
            EventInput {
                timestamp: record.last_execution.as_deref(),
                category: "execution",
                action: "bam_dam_execution",
                source: record.source.as_str(),
                description: format!("BAM/DAM 程序执行：{}", record.executable),
                pid: None,
                tid: None,
                process: None,
                path: Some(record.executable),
                object_address: None,
                physical_address: None,
                details,
            },
        );
    }
    let bam_complete = system_complete && !bam_truncated;
    if bam_truncated {
        warnings.push(format!(
            "registry.bam_dam：结果达到 {} 条上限",
            options.registry_limit
        ));
    }
    sources.push(source_status(
        "registry.bam_dam",
        bam_records_examined,
        events.len() - before,
        bam_complete,
    ));
    *complete &= bam_complete;

    let task_records_examined = registry.scheduled_tasks.len();
    let task_truncated = registry.scheduled_tasks.len() > options.registry_limit;
    registry.scheduled_tasks.truncate(options.registry_limit);
    let before = events.len();
    for record in registry.scheduled_tasks {
        let details = BTreeMap::from([
            ("task_id".to_owned(), record.task_id.unwrap_or_default()),
            ("uri".to_owned(), record.uri.unwrap_or_default()),
            ("author".to_owned(), record.author.unwrap_or_default()),
            ("source".to_owned(), record.source.unwrap_or_default()),
            ("index".to_owned(), optional_number(record.index)),
            (
                "actions_size".to_owned(),
                optional_number(record.actions_size),
            ),
            (
                "triggers_size".to_owned(),
                optional_number(record.triggers_size),
            ),
            (
                "key_last_write_filetime".to_owned(),
                record.last_write_raw.to_string(),
            ),
        ]);
        push_event(
            events,
            filter,
            EventInput {
                timestamp: record.last_write.as_deref(),
                category: "persistence",
                action: "scheduled_task_key_modified",
                source: "registry.taskcache",
                description: format!("计划任务注册表键最后写入：{}", record.tree_path),
                pid: None,
                tid: None,
                process: None,
                path: Some(record.tree_path),
                object_address: None,
                physical_address: None,
                details,
            },
        );
    }
    let task_complete = software_complete && !task_truncated;
    if task_truncated {
        warnings.push(format!(
            "registry.taskcache：结果达到 {} 条上限",
            options.registry_limit
        ));
    }
    sources.push(source_status(
        "registry.taskcache",
        task_records_examined,
        events.len() - before,
        task_complete,
    ));
    *complete &= task_complete;
    append_source_warnings("registry", registry.warnings, warnings);

    let userassist = analyze_userassist(session, &processes, options.registry_limit);
    let userassist_records_examined = userassist.records.len();
    let before = events.len();
    for record in userassist.records {
        let details = BTreeMap::from([
            ("hive".to_owned(), record.hive),
            ("guid".to_owned(), record.guid),
            ("encoded_name".to_owned(), record.encoded_name),
            ("session_id".to_owned(), optional_number(record.session_id)),
            ("run_count".to_owned(), optional_number(record.run_count)),
            (
                "focus_count".to_owned(),
                optional_number(record.focus_count),
            ),
            (
                "focus_time_ms".to_owned(),
                optional_number(record.focus_time_ms),
            ),
            (
                "last_execution_filetime".to_owned(),
                optional_number(record.last_execution_raw),
            ),
        ]);
        push_event(
            events,
            filter,
            EventInput {
                timestamp: record.last_execution.as_deref(),
                category: "execution",
                action: "userassist_execution",
                source: "registry.userassist",
                description: format!("UserAssist 程序执行：{}", record.decoded_name),
                pid: None,
                tid: None,
                process: None,
                path: Some(record.decoded_name),
                object_address: None,
                physical_address: None,
                details,
            },
        );
    }
    let userassist_complete = userassist.available && userassist.complete;
    sources.push(source_status(
        "registry.userassist",
        userassist_records_examined,
        events.len() - before,
        userassist_complete,
    ));
    *complete &= userassist_complete;
    append_source_warnings("registry.userassist", userassist.warnings, warnings);

    let amcache = analyze_amcache(session, &processes, options.registry_limit);
    let amcache_records_examined = amcache.records.len();
    let before = events.len();
    for record in amcache.records {
        let path = record.path.clone();
        let label = path
            .as_deref()
            .or(record.product_name.as_deref())
            .unwrap_or(record.key_name.as_str())
            .to_owned();
        let details = BTreeMap::from([
            ("entry_type".to_owned(), record.entry_type),
            ("key_name".to_owned(), record.key_name),
            (
                "program_id".to_owned(),
                record.program_id.unwrap_or_default(),
            ),
            ("sha1".to_owned(), record.sha1.unwrap_or_default()),
            (
                "product_name".to_owned(),
                record.product_name.unwrap_or_default(),
            ),
            (
                "product_version".to_owned(),
                record.product_version.unwrap_or_default(),
            ),
            ("publisher".to_owned(), record.publisher.unwrap_or_default()),
            ("service".to_owned(), record.service.unwrap_or_default()),
            ("link_date".to_owned(), record.link_date.unwrap_or_default()),
            (
                "key_last_write_filetime".to_owned(),
                record.last_write_raw.to_string(),
            ),
        ]);
        push_event(
            events,
            filter,
            EventInput {
                timestamp: record.last_write.as_deref(),
                category: "inventory",
                action: "amcache_key_modified",
                source: "registry.amcache",
                description: format!("Amcache 条目最后写入（非精确执行时间）：{label}"),
                pid: None,
                tid: None,
                process: None,
                path,
                object_address: None,
                physical_address: None,
                details,
            },
        );
    }
    let amcache_complete = amcache.available && amcache.complete;
    sources.push(source_status(
        "registry.amcache",
        amcache_records_examined,
        events.len() - before,
        amcache_complete,
    ));
    *complete &= amcache_complete;
    append_source_warnings("registry.amcache", amcache.warnings, warnings);
}

fn source_status(
    source: &str,
    records_examined: usize,
    events_matched: usize,
    complete: bool,
) -> WindowsTimelineSourceStatus {
    WindowsTimelineSourceStatus {
        source: source.to_owned(),
        records_examined,
        events_matched,
        duplicate_events_merged: 0,
        complete,
        error: None,
    }
}

fn recovered_hive_complete(hives: &[RegistryHiveStatus], root_path: &str) -> bool {
    hives.iter().any(|hive| {
        hive.root_path.eq_ignore_ascii_case(root_path)
            && hive.recovery_attempted
            && hive.parsed
            && hive.complete.unwrap_or(false)
    })
}
