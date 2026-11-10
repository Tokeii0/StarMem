use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use anyhow::{Result, ensure};
use serde::Serialize;

use super::service_plugins::{ServiceRecord, ServiceView, analyze_services};
use crate::session::AnalysisSession;
use crate::system::registry::{
    RegistryAutorun, RegistryHiveStatus, RegistryScheduledTask, RegistryServiceInfo,
    analyze_registry,
};

const MAX_WARNINGS: usize = 128;

#[derive(Debug, Clone)]
pub struct AutorunOptions {
    pub process_limit: usize,
    pub limit: usize,
    pub correlate_service_memory: bool,
    pub service_scan_limit: usize,
    pub include_task_candidates: bool,
}

impl Default for AutorunOptions {
    fn default() -> Self {
        Self {
            process_limit: 65_536,
            limit: 16_384,
            correlate_service_memory: false,
            service_scan_limit: 65_536,
            include_task_candidates: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AutorunReport {
    pub records: Vec<AutorunRecord>,
    pub sources: Vec<AutorunSourceStatus>,
    pub mechanism_counts: BTreeMap<String, usize>,
    pub registry_entries: usize,
    pub registry_services_examined: usize,
    pub automatic_services_included: usize,
    pub manual_services_skipped: usize,
    pub disabled_services_skipped: usize,
    pub disabled_runtime_conflicts: usize,
    pub unknown_start_services_skipped: usize,
    pub scheduled_tasks_examined: usize,
    pub scheduled_task_candidates_requested: bool,
    pub scheduled_task_candidates_included: usize,
    pub service_memory_requested: bool,
    pub service_memory_available: bool,
    pub service_memory_records: usize,
    pub records_detected: usize,
    pub records_emitted: usize,
    pub available: bool,
    pub scope: String,
    pub truncated: bool,
    pub scan_seconds: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AutorunSourceStatus {
    pub name: String,
    pub available: bool,
    pub complete: bool,
    pub hives_examined: usize,
    pub hives_parsed: usize,
    pub missing_bytes: u64,
    pub records: usize,
    pub parse_warnings: usize,
    pub warnings: usize,
}

#[derive(Debug, Serialize)]
pub struct AutorunRecord {
    pub category: String,
    pub mechanism: String,
    pub scope: String,
    pub user_sid: Option<String>,
    pub name: String,
    pub location: String,
    pub command: Option<String>,
    pub secondary_command: Option<String>,
    pub executable: Option<String>,
    pub arguments: Option<String>,
    pub enabled: Option<bool>,
    pub activation_verified: Option<bool>,
    pub activation_status: String,
    pub registration_present: bool,
    pub registry_presence: Option<String>,
    pub source_hive: Option<String>,
    pub source_root: Option<String>,
    pub key_last_write_raw: Option<u64>,
    pub key_last_write: Option<String>,
    pub service_start: Option<u32>,
    pub service_start_name: Option<String>,
    pub service_type: Option<u32>,
    pub task_id: Option<String>,
    pub artifact_sha256: Option<String>,
    pub artifact_strings: Vec<String>,
    pub trigger_sha256: Option<String>,
    pub trigger_strings: Vec<String>,
    pub runtime: Option<AutorunRuntimeEvidence>,
    pub evidence_sources: Vec<String>,
    pub parse_status: String,
    pub triage_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutorunRuntimeEvidence {
    pub address: u64,
    pub pid: Option<u32>,
    pub state: u32,
    pub state_name: String,
    pub binary_path_memory: Option<String>,
    pub found_by_scan: bool,
    pub found_by_list: bool,
    pub adaptive_layout: String,
}

#[derive(Debug, Clone, Copy)]
enum HiveTarget {
    System,
    Software,
    NtUser,
}

pub fn scan_autoruns(session: &AnalysisSession, options: &AutorunOptions) -> Result<AutorunReport> {
    ensure!(options.limit > 0, "自启动结果上限必须大于零");
    ensure!(options.process_limit > 0, "进程结果上限必须大于零");
    if options.correlate_service_memory {
        ensure!(
            options.service_scan_limit > 0,
            "服务内存关联结果上限必须大于零"
        );
    }
    let started = Instant::now();
    let processes = session.processes(options.process_limit)?;
    let mut registry = analyze_registry(session, &processes);
    let registry_entries = registry.autoruns.len();
    let registry_services_examined = registry.services.len();
    let scheduled_tasks_examined = registry.scheduled_tasks.len();
    let system_parse_warnings = registry
        .warnings
        .iter()
        .filter(|warning| warning.starts_with("SYSTEM 持久化："))
        .count();
    let software_parse_warnings = registry
        .warnings
        .iter()
        .filter(|warning| warning.starts_with("SOFTWARE 持久化："))
        .count();
    let user_parse_warnings = registry
        .warnings
        .iter()
        .filter(|warning| warning.to_ascii_lowercase().contains("ntuser.dat 持久化："))
        .count();

    let mut system_source = hive_source_status(
        "SYSTEM",
        HiveTarget::System,
        &registry.hives,
        registry.hive_enumeration_complete && registry.system_persistence_complete,
        system_parse_warnings,
    );
    let mut software_source = hive_source_status(
        "SOFTWARE",
        HiveTarget::Software,
        &registry.hives,
        registry.hive_enumeration_complete && registry.software_persistence_complete,
        software_parse_warnings,
    );
    let mut user_source = hive_source_status(
        "NTUSER",
        HiveTarget::NtUser,
        &registry.hives,
        registry.hive_enumeration_complete && registry.user_persistence_complete,
        user_parse_warnings,
    );

    let system_complete = system_source.available && system_source.complete;
    let service_report = if options.correlate_service_memory {
        Some(analyze_services(
            session.image(),
            session.kernel(),
            session.profile(),
            &processes,
            &registry.services,
            true,
            Vec::new(),
            ServiceView::Scan,
            options.service_scan_limit,
        )?)
    } else {
        None
    };

    let mut warnings = Vec::new();
    warnings.append(&mut registry.warnings);
    append_hive_warnings(&mut warnings, &registry.hives);
    for warning in &processes.warnings {
        push_warning(
            &mut warnings,
            format!("进程枚举/{}：{}", warning.kind, warning.message),
        );
    }

    let mut runtime_records = BTreeMap::<String, Vec<ServiceRecord>>::new();
    let mut service_memory_available = false;
    let mut service_memory_complete = true;
    let mut service_memory_records = 0usize;
    if let Some(report) = service_report {
        service_memory_available = !report.services_pids.is_empty();
        service_memory_complete = report.complete;
        service_memory_records = report.records.len();
        for warning in report.warnings {
            push_warning(&mut warnings, format!("服务内存关联：{warning}"));
        }
        for record in report.records {
            runtime_records
                .entry(record.name.to_ascii_lowercase())
                .or_default()
                .push(record);
        }
    }

    let mut records = Vec::new();
    for entry in std::mem::take(&mut registry.autoruns) {
        records.push(registry_autorun_record(entry));
    }

    let current_control_set = registry.current_control_set.unwrap_or(1);
    let mut registered_service_names = BTreeSet::new();
    let mut manual_services_skipped = 0usize;
    let mut disabled_services_skipped = 0usize;
    let mut disabled_runtime_conflicts = 0usize;
    let mut unknown_start_services_skipped = 0usize;
    let mut automatic_services_included = 0usize;
    for service in std::mem::take(&mut registry.services) {
        let normalized_name = service.name.to_ascii_lowercase();
        registered_service_names.insert(normalized_name.clone());
        let runtime = runtime_records
            .get(&normalized_name)
            .and_then(|records| preferred_runtime_record(records));
        match service.start {
            Some(0..=2) => {
                automatic_services_included += 1;
                records.push(service_autorun_record(
                    service,
                    runtime,
                    current_control_set,
                ));
            }
            Some(3) => manual_services_skipped += 1,
            Some(4) => {
                disabled_services_skipped += 1;
                if runtime.is_some_and(|record| record.found_by_list && record.state != 1) {
                    disabled_runtime_conflicts += 1;
                    records.push(disabled_runtime_service_record(
                        service,
                        runtime.expect("runtime checked"),
                        current_control_set,
                    ));
                }
            }
            _ => unknown_start_services_skipped += 1,
        }
    }

    if options.correlate_service_memory {
        for (name, candidates) in &runtime_records {
            if registered_service_names.contains(name) {
                continue;
            }
            if let Some(runtime) = preferred_runtime_record(candidates)
                && runtime.start <= 2
            {
                records.push(memory_only_service_record(runtime, system_complete));
            }
        }
    }

    let mut scheduled_task_candidates_included = 0usize;
    if options.include_task_candidates {
        for task in std::mem::take(&mut registry.scheduled_tasks) {
            scheduled_task_candidates_included += 1;
            records.push(scheduled_task_record(task));
        }
    }

    records.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then_with(|| left.mechanism.cmp(&right.mechanism))
            .then_with(|| left.scope.cmp(&right.scope))
            .then_with(|| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            })
            .then_with(|| left.location.cmp(&right.location))
            .then_with(|| left.command.cmp(&right.command))
    });
    records.dedup_by(|left, right| {
        left.mechanism == right.mechanism
            && left.scope == right.scope
            && left.user_sid == right.user_sid
            && left.name.eq_ignore_ascii_case(&right.name)
            && left.location.eq_ignore_ascii_case(&right.location)
            && left.command == right.command
    });

    let records_detected = records.len();
    let mut mechanism_counts = BTreeMap::new();
    for record in &records {
        *mechanism_counts
            .entry(record.mechanism.clone())
            .or_insert(0usize) += 1;
    }
    let system_records = records
        .iter()
        .filter(|record| record.source_root.as_deref() == Some("\\REGISTRY\\MACHINE\\SYSTEM"))
        .count();
    let software_records = records
        .iter()
        .filter(|record| record.source_root.as_deref() == Some("\\REGISTRY\\MACHINE\\SOFTWARE"))
        .count();
    let user_records = records
        .iter()
        .filter(|record| record.scope == "user")
        .count();
    system_source.records = system_records;
    software_source.records = software_records;
    user_source.records = user_records;

    let truncated = records.len() > options.limit;
    records.truncate(options.limit);
    if truncated {
        push_warning(
            &mut warnings,
            format!("自启动与持久化配置结果达到 {} 条上限", options.limit),
        );
    }
    if !user_source.available {
        push_warning(
            &mut warnings,
            "未恢复任何 NTUSER.DAT；用户级 Run/Winlogon/Active Setup 范围不可用".to_owned(),
        );
    }
    warnings.truncate(MAX_WARNINGS);

    let mut sources = vec![system_source, software_source, user_source];
    if options.correlate_service_memory {
        sources.push(AutorunSourceStatus {
            name: "SERVICE_MEMORY".to_owned(),
            available: service_memory_available,
            complete: service_memory_complete,
            hives_examined: 0,
            hives_parsed: 0,
            missing_bytes: 0,
            records: service_memory_records,
            parse_warnings: 0,
            warnings: usize::from(!service_memory_complete),
        });
    }
    let available = sources.iter().any(|source| source.available);
    let registry_sources_complete = sources
        .iter()
        .take(3)
        .all(|source| source.available && source.complete);
    let complete = processes.complete
        && registry_sources_complete
        && (!options.correlate_service_memory || service_memory_complete)
        && !truncated;
    let scope = format!(
        "一次性恢复 SYSTEM、SOFTWARE 与全部驻留 NTUSER Hive；输出注册表 ASEP 和 Start=0/1/2 的服务/驱动{}{}。TaskCache 候选不等同已验证的开机/登录触发",
        if options.include_task_candidates {
            "，并附加触发器尚未结构化解码的 TaskCache 持久化候选"
        } else {
            ""
        },
        if options.correlate_service_memory {
            "，同时与 services.exe 内存证据交叉验证"
        } else {
            "；未请求 services.exe 内存关联"
        }
    );
    let records_emitted = records.len();

    Ok(AutorunReport {
        records,
        sources,
        mechanism_counts,
        registry_entries,
        registry_services_examined,
        automatic_services_included,
        manual_services_skipped,
        disabled_services_skipped,
        disabled_runtime_conflicts,
        unknown_start_services_skipped,
        scheduled_tasks_examined,
        scheduled_task_candidates_requested: options.include_task_candidates,
        scheduled_task_candidates_included,
        service_memory_requested: options.correlate_service_memory,
        service_memory_available,
        service_memory_records,
        records_detected,
        records_emitted,
        available,
        scope,
        truncated,
        scan_seconds: started.elapsed().as_secs_f64(),
        complete,
        warnings,
    })
}

fn registry_autorun_record(entry: RegistryAutorun) -> AutorunRecord {
    let (executable, arguments) = split_windows_command(&entry.command);
    let triage_indicators = persistence_triage_indicators(
        &entry.command,
        executable.as_deref(),
        arguments.as_deref(),
        &entry.mechanism,
        false,
        false,
    );
    let activation_status = match entry.enabled {
        Some(true) => "startup_or_logon_registration_enabled",
        Some(false) => "registration_present_but_disabled",
        None => "registration_present_enablement_unknown",
    }
    .to_owned();
    let parse_status = if entry.enabled.is_none() {
        "registry_value_recovered_enablement_unknown"
    } else {
        "registry_value_recovered"
    }
    .to_owned();
    AutorunRecord {
        category: "registry_value".to_owned(),
        mechanism: entry.mechanism,
        scope: entry.scope,
        user_sid: entry.user_sid,
        name: entry.name,
        location: format!(
            "{}\\{}",
            entry.source_root.trim_end_matches('\\'),
            entry.key_path.trim_start_matches('\\')
        ),
        command: Some(entry.command),
        secondary_command: None,
        executable,
        arguments,
        enabled: entry.enabled,
        activation_verified: entry.enabled,
        activation_status,
        registration_present: true,
        registry_presence: Some("present".to_owned()),
        source_hive: Some(entry.source_hive),
        source_root: Some(entry.source_root),
        key_last_write_raw: Some(entry.key_last_write_raw),
        key_last_write: entry.key_last_write,
        service_start: None,
        service_start_name: None,
        service_type: None,
        task_id: None,
        artifact_sha256: None,
        artifact_strings: Vec::new(),
        trigger_sha256: None,
        trigger_strings: Vec::new(),
        runtime: None,
        evidence_sources: vec!["registry".to_owned()],
        parse_status,
        triage_indicators,
    }
}

fn service_autorun_record(
    service: RegistryServiceInfo,
    runtime: Option<&ServiceRecord>,
    control_set: u32,
) -> AutorunRecord {
    let driver = service
        .service_type
        .is_some_and(|service_type| service_type & 0x0f != 0);
    let mechanism = if driver { "driver" } else { "service" };
    let command = service
        .image_path
        .clone()
        .or_else(|| service.service_dll.clone());
    let secondary_command = match (&service.image_path, &service.service_dll) {
        (Some(_), Some(service_dll)) => Some(service_dll.clone()),
        _ => None,
    };
    let (executable, arguments) = command
        .as_deref()
        .map(split_windows_command)
        .unwrap_or((None, None));
    let raw_path_differs = runtime.is_some_and(|runtime| {
        match (
            service.image_path.as_deref(),
            runtime.binary_path_memory.as_deref(),
        ) {
            (Some(registry), Some(memory)) => service_command_text_differs(registry, memory),
            _ => false,
        }
    });
    let mut evidence_sources = vec!["registry_service".to_owned()];
    if let Some(runtime) = runtime {
        evidence_sources.push("service_memory_scan".to_owned());
        if runtime.found_by_list {
            evidence_sources.push("service_memory_list".to_owned());
        }
    }
    let mut triage_indicators: Vec<String> = command
        .as_deref()
        .map(|command| {
            persistence_triage_indicators(
                command,
                executable.as_deref(),
                arguments.as_deref(),
                mechanism,
                driver,
                raw_path_differs,
            )
        })
        .unwrap_or_default();
    if let Some(service_dll) = service.service_dll.as_deref() {
        let (dll_executable, dll_arguments) = split_windows_command(service_dll);
        for indicator in persistence_triage_indicators(
            service_dll,
            dll_executable.as_deref(),
            dll_arguments.as_deref(),
            "service_dll",
            false,
            false,
        ) {
            triage_indicators.push(format!("service_dll_{indicator}"));
        }
        triage_indicators.sort();
        triage_indicators.dedup();
    }
    AutorunRecord {
        category: if driver { "driver" } else { "service" }.to_owned(),
        mechanism: mechanism.to_owned(),
        scope: "machine".to_owned(),
        user_sid: None,
        name: service.name.clone(),
        location: format!(
            "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet{control_set:03}\\Services\\{}",
            service.name
        ),
        command,
        secondary_command,
        executable,
        arguments,
        enabled: Some(true),
        activation_verified: Some(true),
        activation_status: "automatic_service_start_configured".to_owned(),
        registration_present: true,
        registry_presence: Some("present".to_owned()),
        source_hive: Some("SYSTEM".to_owned()),
        source_root: Some("\\REGISTRY\\MACHINE\\SYSTEM".to_owned()),
        key_last_write_raw: Some(service.last_write_raw),
        key_last_write: service.last_write,
        service_start: service.start,
        service_start_name: service.start.map(service_start_name).map(str::to_owned),
        service_type: service.service_type,
        task_id: None,
        artifact_sha256: None,
        artifact_strings: Vec::new(),
        trigger_sha256: None,
        trigger_strings: Vec::new(),
        runtime: runtime.map(runtime_evidence),
        evidence_sources,
        parse_status: if service.image_path.is_some() || service.service_dll.is_some() {
            "registry_path_recovered"
        } else {
            "registration_without_path"
        }
        .to_owned(),
        triage_indicators,
    }
}

fn disabled_runtime_service_record(
    service: RegistryServiceInfo,
    runtime: &ServiceRecord,
    control_set: u32,
) -> AutorunRecord {
    let mut record = service_autorun_record(service, Some(runtime), control_set);
    record.category = "service_state_conflict".to_owned();
    record.mechanism = "disabled_service_runtime".to_owned();
    record.enabled = Some(false);
    record.activation_verified = Some(false);
    record.activation_status = "disabled_configuration_but_runtime_state_non_stopped".to_owned();
    record
        .triage_indicators
        .push("disabled_service_has_non_stopped_runtime_record".to_owned());
    record.triage_indicators.sort();
    record.triage_indicators.dedup();
    record
}

fn memory_only_service_record(
    runtime: &ServiceRecord,
    registry_services_complete: bool,
) -> AutorunRecord {
    let driver = runtime.service_type & 0x0f != 0;
    let command = runtime.binary_path_memory.clone();
    let (executable, arguments) = command
        .as_deref()
        .map(split_windows_command)
        .unwrap_or((None, None));
    let mut triage_indicators = command
        .as_deref()
        .map(|command| {
            persistence_triage_indicators(
                command,
                executable.as_deref(),
                arguments.as_deref(),
                if driver { "driver" } else { "service" },
                driver,
                false,
            )
        })
        .unwrap_or_default();
    triage_indicators.push(
        if registry_services_complete {
            "absent_from_complete_registry_services_tree"
        } else {
            "registry_service_not_observed_source_incomplete"
        }
        .to_owned(),
    );
    if !runtime.found_by_list {
        triage_indicators.push("memory_scan_candidate_not_in_recovered_active_list".to_owned());
    }
    triage_indicators.sort();
    triage_indicators.dedup();
    AutorunRecord {
        category: if driver {
            "driver_memory_evidence"
        } else {
            "service_memory_evidence"
        }
        .to_owned(),
        mechanism: if driver {
            "driver_memory_only"
        } else {
            "service_memory_only"
        }
        .to_owned(),
        scope: "machine".to_owned(),
        user_sid: None,
        name: runtime.name.clone(),
        location: format!("services.exe record {:#x}", runtime.address),
        command,
        secondary_command: None,
        executable,
        arguments,
        enabled: Some(true),
        activation_verified: Some(true),
        activation_status: if runtime.found_by_list {
            "automatic_start_mode_in_recovered_service_list"
        } else {
            "automatic_start_mode_in_memory_scan_candidate"
        }
        .to_owned(),
        registration_present: false,
        registry_presence: Some(
            if registry_services_complete {
                "absent_from_complete_services_tree"
            } else {
                "not_observed_in_incomplete_services_evidence"
            }
            .to_owned(),
        ),
        source_hive: None,
        source_root: None,
        key_last_write_raw: None,
        key_last_write: None,
        service_start: Some(runtime.start),
        service_start_name: Some(runtime.start_name.clone()),
        service_type: Some(runtime.service_type),
        task_id: None,
        artifact_sha256: None,
        artifact_strings: Vec::new(),
        trigger_sha256: None,
        trigger_strings: Vec::new(),
        runtime: Some(runtime_evidence(runtime)),
        evidence_sources: vec!["service_memory_scan".to_owned()],
        parse_status: if registry_services_complete {
            "memory_record_registry_absence_verified"
        } else {
            "memory_record_registry_presence_unresolved"
        }
        .to_owned(),
        triage_indicators,
    }
}

fn scheduled_task_record(task: RegistryScheduledTask) -> AutorunRecord {
    let command = choose_task_command(&task.action_strings);
    let (executable, arguments) = command
        .as_deref()
        .map(split_windows_command)
        .unwrap_or((None, None));
    let mut triage_indicators: Vec<String> = command
        .as_deref()
        .map(|command| {
            persistence_triage_indicators(
                command,
                executable.as_deref(),
                arguments.as_deref(),
                "scheduled_task",
                false,
                false,
            )
            .into_iter()
            .map(|indicator| format!("heuristic_action_{indicator}"))
            .collect()
        })
        .unwrap_or_default();
    if !task.task_key_present {
        triage_indicators.push("taskcache_tree_entry_without_task_record".to_owned());
    }
    if !task.tree_key_present {
        triage_indicators.push("taskcache_task_record_without_tree_entry".to_owned());
    }
    let mut evidence_sources = Vec::new();
    if task.tree_key_present {
        evidence_sources.push("registry_taskcache_tree".to_owned());
    }
    if task.task_key_present {
        evidence_sources.push("registry_taskcache_tasks".to_owned());
    }
    let name = task
        .tree_path
        .rsplit('\\')
        .find(|component| !component.is_empty())
        .unwrap_or(&task.tree_path)
        .to_owned();
    AutorunRecord {
        category: "scheduled_task_registration".to_owned(),
        mechanism: "taskcache_persistence_candidate".to_owned(),
        scope: "machine".to_owned(),
        user_sid: None,
        name,
        location: if task.tree_key_present {
            format!("TaskCache{}", task.tree_path)
        } else {
            format!(
                "TaskCache\\Tasks\\{}",
                task.task_id.as_deref().unwrap_or("<unknown>")
            )
        },
        command,
        secondary_command: None,
        executable,
        arguments,
        enabled: None,
        activation_verified: None,
        activation_status: "taskcache_registration_trigger_not_structurally_decoded".to_owned(),
        registration_present: true,
        registry_presence: Some("present".to_owned()),
        source_hive: Some("SOFTWARE".to_owned()),
        source_root: Some("\\REGISTRY\\MACHINE\\SOFTWARE".to_owned()),
        key_last_write_raw: Some(task.last_write_raw),
        key_last_write: task.last_write,
        service_start: None,
        service_start_name: None,
        service_type: None,
        task_id: task.task_id,
        artifact_sha256: task.actions_sha256,
        artifact_strings: task.action_strings,
        trigger_sha256: task.triggers_sha256,
        trigger_strings: task.trigger_strings,
        runtime: None,
        evidence_sources,
        parse_status: format!(
            "{};{};heuristic_utf16_strings_only;trigger_not_structurally_decoded",
            task.registration_status, task.action_parse_status
        ),
        triage_indicators,
    }
}

fn runtime_evidence(record: &ServiceRecord) -> AutorunRuntimeEvidence {
    AutorunRuntimeEvidence {
        address: record.address,
        pid: record.pid,
        state: record.state,
        state_name: record.state_name.clone(),
        binary_path_memory: record.binary_path_memory.clone(),
        found_by_scan: record.found_by_scan,
        found_by_list: record.found_by_list,
        adaptive_layout: record.adaptive_layout.clone(),
    }
}

fn preferred_runtime_record(records: &[ServiceRecord]) -> Option<&ServiceRecord> {
    records.iter().max_by_key(|record| {
        (
            record.found_by_list,
            record.found_by_scan,
            record.state != 1,
        )
    })
}

fn hive_source_status(
    name: &str,
    target: HiveTarget,
    hives: &[RegistryHiveStatus],
    semantic_complete: bool,
    parse_warnings: usize,
) -> AutorunSourceStatus {
    let matched = hives
        .iter()
        .filter(|status| hive_matches(status, target))
        .collect::<Vec<_>>();
    let available = matched.iter().any(|status| status.parsed);
    let complete = available
        && semantic_complete
        && matched
            .iter()
            .all(|status| status.parsed && status.complete == Some(true) && status.error.is_none());
    AutorunSourceStatus {
        name: name.to_owned(),
        available,
        complete,
        hives_examined: matched.len(),
        hives_parsed: matched.iter().filter(|status| status.parsed).count(),
        missing_bytes: matched
            .iter()
            .filter_map(|status| status.missing_bytes)
            .sum(),
        records: 0,
        parse_warnings,
        warnings: matched
            .iter()
            .map(|status| status.warnings.len() + usize::from(status.error.is_some()))
            .sum::<usize>()
            + parse_warnings,
    }
}

fn hive_matches(status: &RegistryHiveStatus, target: HiveTarget) -> bool {
    if !status.recovery_attempted {
        return false;
    }
    let root = status.root_path.to_ascii_lowercase();
    let file = status.file_path.to_ascii_lowercase();
    let user = status.user_name.to_ascii_lowercase();
    match target {
        HiveTarget::System => {
            root == "\\registry\\machine\\system"
                || file.ends_with("\\system")
                || user.ends_with("\\system")
        }
        HiveTarget::Software => {
            root == "\\registry\\machine\\software"
                || file.ends_with("\\software")
                || user.ends_with("\\software")
        }
        HiveTarget::NtUser => {
            user.ends_with("\\ntuser.dat")
                || file.ends_with("\\ntuser.dat")
                || root.starts_with("\\registry\\user\\")
        }
    }
}

fn append_hive_warnings(warnings: &mut Vec<String>, hives: &[RegistryHiveStatus]) {
    for hive in hives.iter().filter(|hive| hive.recovery_attempted) {
        let source = [&hive.file_path, &hive.user_name, &hive.root_path]
            .into_iter()
            .find(|value| !value.is_empty())
            .map(String::as_str)
            .unwrap_or("unknown hive");
        for warning in &hive.warnings {
            push_warning(warnings, format!("{source}：{warning}"));
        }
        if let Some(error) = &hive.error {
            push_warning(warnings, format!("{source}：{error}"));
        }
    }
}

fn split_windows_command(command: &str) -> (Option<String>, Option<String>) {
    let trimmed = command.trim().trim_matches('\0');
    if trimmed.is_empty() {
        return (None, None);
    }
    if let Some(rest) = trimmed.strip_prefix('"')
        && let Some(end) = rest.find('"')
    {
        let executable = rest[..end].trim();
        let arguments = rest[end + 1..].trim();
        return (
            (!executable.is_empty()).then(|| executable.to_owned()),
            (!arguments.is_empty()).then(|| arguments.to_owned()),
        );
    }
    let lower = trimmed.to_ascii_lowercase();
    let executable_end = [
        ".exe", ".com", ".cmd", ".bat", ".ps1", ".vbs", ".js", ".sys",
    ]
    .iter()
    .filter_map(|extension| lower.find(extension).map(|index| index + extension.len()))
    .min()
    .or_else(|| trimmed.find(char::is_whitespace));
    match executable_end {
        Some(end) => {
            let executable = trimmed[..end].trim();
            let arguments = trimmed[end..].trim();
            (
                (!executable.is_empty()).then(|| executable.to_owned()),
                (!arguments.is_empty()).then(|| arguments.to_owned()),
            )
        }
        None => (Some(trimmed.to_owned()), None),
    }
}

fn choose_task_command(strings: &[String]) -> Option<String> {
    strings
        .iter()
        .find(|value| looks_like_command(value))
        .cloned()
}

fn looks_like_command(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        ".exe",
        ".com",
        ".cmd",
        ".bat",
        ".ps1",
        ".vbs",
        ".js",
        ".dll",
        "%systemroot%",
        "\\windows\\",
        "\\users\\",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn persistence_triage_indicators(
    command: &str,
    executable: Option<&str>,
    arguments: Option<&str>,
    mechanism: &str,
    driver: bool,
    raw_path_differs: bool,
) -> Vec<String> {
    let lower = command.replace('/', "\\").to_ascii_lowercase();
    let mut output = Vec::new();
    let profile_or_temp_path = lower.contains("\\users\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\temp\\")
        || lower.contains("%temp%")
        || lower.contains("%tmp%");
    if profile_or_temp_path {
        output.push(
            if driver {
                "driver_path_contains_user_profile_or_temp"
            } else {
                "path_contains_user_profile_or_temp"
            }
            .to_owned(),
        );
    }
    if executable.is_some_and(|value| value.trim_start().starts_with("\\\\")) {
        output.push("network_path".to_owned());
    }
    let launcher = executable
        .map(|value| value.trim().trim_matches('"').replace('/', "\\"))
        .and_then(|value| value.rsplit('\\').next().map(str::to_ascii_lowercase));
    if launcher.as_deref().is_some_and(|launcher| {
        matches!(
            launcher,
            "powershell"
                | "powershell.exe"
                | "pwsh"
                | "pwsh.exe"
                | "cmd"
                | "cmd.exe"
                | "wscript"
                | "wscript.exe"
                | "cscript"
                | "cscript.exe"
                | "mshta"
                | "mshta.exe"
                | "rundll32"
                | "rundll32.exe"
                | "regsvr32"
                | "regsvr32.exe"
        )
    }) {
        output.push("script_or_dual_use_launcher".to_owned());
    }
    if matches!(
        launcher.as_deref(),
        Some("powershell" | "powershell.exe" | "pwsh" | "pwsh.exe")
    ) && arguments.is_some_and(|arguments| {
        arguments.split_ascii_whitespace().any(|argument| {
            argument.eq_ignore_ascii_case("-enc")
                || argument.eq_ignore_ascii_case("-encodedcommand")
        })
    }) {
        output.push("encoded_script_argument".to_owned());
    }
    if mechanism == "service"
        && !command.trim_start().starts_with('"')
        && executable.is_some_and(|executable| {
            executable.contains(char::is_whitespace)
                && executable.to_ascii_lowercase().ends_with(".exe")
        })
    {
        output.push("unquoted_service_path".to_owned());
    }
    if mechanism == "ifeo_debugger" {
        output.push("image_debugger_redirection".to_owned());
    }
    if raw_path_differs {
        output.push("raw_registry_memory_command_text_differs".to_owned());
    }
    output.sort();
    output.dedup();
    output
}

fn service_command_text_differs(registry: &str, memory: &str) -> bool {
    fn normalize(value: &str) -> (String, String) {
        let (executable, arguments) = split_windows_command(value);
        let executable = executable
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .replace('/', "\\")
            .to_ascii_lowercase()
            .replace("%windir%\\", "\\systemroot\\")
            .replace("%systemroot%\\", "\\systemroot\\")
            .trim_start_matches("\\??\\")
            .trim_start_matches("\\\\?\\")
            .to_owned();
        let arguments = arguments
            .unwrap_or_default()
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        (executable, arguments)
    }
    normalize(registry) != normalize(memory)
}

fn service_start_name(start: u32) -> &'static str {
    match start {
        0 => "boot",
        1 => "system",
        2 => "automatic",
        3 => "demand",
        4 => "disabled",
        _ => "unknown",
    }
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_and_unquoted_windows_commands() {
        assert_eq!(
            split_windows_command(r#""C:\Program Files\Agent\agent.exe" -service"#),
            (
                Some(r"C:\Program Files\Agent\agent.exe".to_owned()),
                Some("-service".to_owned())
            )
        );
        assert_eq!(
            split_windows_command(r"C:\Windows\System32\svchost.exe -k netsvcs"),
            (
                Some(r"C:\Windows\System32\svchost.exe".to_owned()),
                Some("-k netsvcs".to_owned())
            )
        );
    }

    #[test]
    fn triage_labels_are_evidence_not_malware_verdicts() {
        let command = r"C:\Users\alice\AppData\Local\Temp\driver.sys";
        let (executable, arguments) = split_windows_command(command);
        let indicators = persistence_triage_indicators(
            command,
            executable.as_deref(),
            arguments.as_deref(),
            "driver",
            true,
            false,
        );
        assert_eq!(indicators, ["driver_path_contains_user_profile_or_temp"]);
    }

    #[test]
    fn task_command_selection_prefers_executable_strings() {
        let strings = vec!["metadata".to_owned(), r"C:\Tools\job.exe".to_owned()];
        assert_eq!(
            choose_task_command(&strings).as_deref(),
            Some(r"C:\Tools\job.exe")
        );
        assert_eq!(choose_task_command(&["metadata".to_owned()]), None);
    }

    #[test]
    fn service_arguments_do_not_trigger_unquoted_path_indicator() {
        let command = r"C:\Windows\System32\svchost.exe -k netsvcs";
        let (executable, arguments) = split_windows_command(command);
        let indicators = persistence_triage_indicators(
            command,
            executable.as_deref(),
            arguments.as_deref(),
            "service",
            false,
            false,
        );
        assert!(!indicators.contains(&"unquoted_service_path".to_owned()));

        let command = r"C:\Program Files\Agent\agent.exe -service";
        let (executable, arguments) = split_windows_command(command);
        let indicators = persistence_triage_indicators(
            command,
            executable.as_deref(),
            arguments.as_deref(),
            "service",
            false,
            false,
        );
        assert!(indicators.contains(&"unquoted_service_path".to_owned()));
    }
}
