use std::collections::{HashMap, HashSet};

use anyhow::{Result, ensure};
use serde::Serialize;

use super::plugins::{ObjectHandleOwner, ObjectHandleOwnerReport, find_handle_owners};
use super::process_plugins::{ThreadRecord, ThreadReport, list_threads};
use super::{ProcessListReport, ProcessRecord, WindowsKernelContext, list_processes};
use crate::image::MemoryImage;
use crate::profile::KernelProfile;

// A caller must have PROCESS_CREATE_PROCESS on the process selected through
// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.  Retaining that handle alongside the
// handles returned for the child process and its initial thread is therefore
// substantially stronger evidence than any one handle on its own.
const PROCESS_CREATE_PROCESS: u32 = 0x0080;

#[derive(Debug, Clone)]
pub struct CheckPslistOptions {
    pub pid: Option<u64>,
    pub process_limit: usize,
    pub thread_limit: usize,
    pub handle_scan_limit: usize,
    pub result_limit: usize,
}

impl Default for CheckPslistOptions {
    fn default() -> Self {
        Self {
            pid: None,
            process_limit: 65_536,
            thread_limit: 262_144,
            handle_scan_limit: 4_000_000,
            result_limit: 65_536,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CheckPslistReport {
    pub records: Vec<CheckPslistRecord>,
    pub processes_examined: usize,
    pub target_processes: usize,
    pub threads_examined: usize,
    pub handle_entries_examined: usize,
    pub high_confidence_count: usize,
    pub medium_confidence_count: usize,
    pub unassessed_processes: usize,
    pub routine_broker_candidates_ignored: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckPslistRecord {
    pub eprocess: u64,
    pub pid: u64,
    pub process: String,
    pub image_path: Option<String>,
    pub create_time: Option<String>,
    pub reported_ppid: Option<u64>,
    pub reported_parent_eprocess: Option<u64>,
    pub reported_parent: Option<String>,
    pub earliest_active_ethread: u64,
    pub earliest_active_tid: u64,
    pub earliest_active_thread_create_time: Option<String>,
    pub likely_creator_eprocess: u64,
    pub likely_creator_pid: u64,
    pub likely_creator: String,
    pub likely_creator_image_path: Option<String>,
    pub likely_creator_create_time: Option<String>,
    pub creator_to_child_delta_ms: Option<u64>,
    pub same_session: Option<bool>,
    pub same_user_sid: Option<bool>,
    pub verdict: CheckPslistVerdict,
    pub confidence: CheckPslistConfidence,
    pub evidence: CheckPslistEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckPslistVerdict {
    PpidSpoofSuspected,
    AlternativeCreatorObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckPslistConfidence {
    Medium,
    High,
}

#[derive(Debug, Serialize)]
pub struct CheckPslistEvidence {
    pub child_process_handle: HandleEvidence,
    pub earliest_active_thread_handle: HandleEvidence,
    pub reported_parent_process_handle: Option<HandleEvidence>,
    pub reported_parent_has_process_create_process_access: bool,
    pub initial_thread_basis: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct HandleEvidence {
    pub handle: u32,
    pub object: u64,
    pub granted_access: u32,
}

pub fn check_pslist(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &CheckPslistOptions,
) -> Result<CheckPslistReport> {
    validate_options(kernel, options)?;
    let processes = list_processes(image, kernel, profile, options.process_limit)?;
    if let Some(pid) = options.pid {
        ensure!(
            processes.processes.iter().any(|process| process.pid == pid),
            "PsActiveProcessHead 中没有 PID {pid}"
        );
    }
    let threads = list_threads(image, kernel, profile, options.thread_limit)?;
    let earliest_threads = earliest_active_threads(&threads.records);
    let targets = lineage_targets(&processes, &earliest_threads, options.pid);
    let owners = find_handle_owners(
        image,
        kernel,
        profile,
        &targets,
        options.process_limit,
        options.handle_scan_limit,
    )?;
    Ok(correlate_process_lineage(
        &processes, &threads, &owners, options,
    ))
}

fn validate_options(kernel: &WindowsKernelContext, options: &CheckPslistOptions) -> Result<()> {
    ensure!(
        !kernel.is_x86_pae(),
        "check-pslist 当前需要 x64 Windows 句柄表与 ETHREAD 布局"
    );
    ensure!(options.process_limit > 0, "进程扫描上限必须大于零");
    ensure!(options.thread_limit > 0, "线程扫描上限必须大于零");
    ensure!(options.handle_scan_limit > 0, "句柄扫描上限必须大于零");
    ensure!(options.result_limit > 0, "结果上限必须大于零");
    Ok(())
}

fn lineage_targets(
    processes: &ProcessListReport,
    earliest_threads: &HashMap<u64, &ThreadRecord>,
    pid: Option<u64>,
) -> HashSet<u64> {
    let selected = processes
        .processes
        .iter()
        .filter(|process| pid.is_none_or(|pid| process.pid == pid))
        .collect::<Vec<_>>();
    let selected_ppids = selected
        .iter()
        .filter_map(|process| process.ppid)
        .collect::<HashSet<_>>();
    let mut targets = HashSet::new();
    for process in &processes.processes {
        if pid.is_none() || selected.iter().any(|selected| selected.pid == process.pid) {
            targets.insert(process.eprocess);
            if let Some(thread) = earliest_threads.get(&process.eprocess) {
                targets.insert(thread.ethread);
            }
        }
        if selected_ppids.contains(&process.pid) {
            targets.insert(process.eprocess);
        }
    }
    targets
}

fn correlate_process_lineage(
    processes: &ProcessListReport,
    threads: &ThreadReport,
    owners: &ObjectHandleOwnerReport,
    options: &CheckPslistOptions,
) -> CheckPslistReport {
    let by_pid = unique_processes_by_pid(&processes.processes);
    let earliest_threads = earliest_active_threads(&threads.records);
    let owners_by_object = owners_by_object(&owners.records);
    let targets = processes
        .processes
        .iter()
        .filter(|process| options.pid.is_none_or(|pid| process.pid == pid))
        .collect::<Vec<_>>();
    let mut records = Vec::new();
    let mut unassessed_processes = 0usize;
    let mut routine_broker_candidates_ignored = 0usize;

    for child in &targets {
        let Some(initial_thread) = earliest_threads.get(&child.eprocess).copied() else {
            unassessed_processes += 1;
            continue;
        };
        let Some(child_owners) = owners_by_object.get(&child.eprocess) else {
            continue;
        };
        let Some(thread_owners) = owners_by_object.get(&initial_thread.ethread) else {
            continue;
        };
        let reported_parent = child.ppid.and_then(|ppid| by_pid.get(&ppid).copied());

        for child_owner in child_owners {
            if child_owner.pid == child.pid || child.ppid == Some(child_owner.pid) {
                continue;
            }
            let Some(thread_owner) = thread_owners
                .iter()
                .find(|owner| owner.pid == child_owner.pid)
                .copied()
            else {
                continue;
            };
            let Some(candidate) = by_pid.get(&child_owner.pid).copied() else {
                continue;
            };
            if is_routine_process_broker(candidate) {
                routine_broker_candidates_ignored += 1;
                continue;
            }
            if creator_is_newer_than_child(candidate, child) {
                continue;
            }
            let parent_owner = reported_parent.and_then(|parent| {
                owners_by_object
                    .get(&parent.eprocess)
                    .and_then(|owners| owners.iter().find(|owner| owner.pid == candidate.pid))
                    .copied()
            });
            let parent_has_create_access = parent_owner
                .is_some_and(|owner| owner.granted_access & PROCESS_CREATE_PROCESS != 0);
            let same_session =
                equal_if_known(candidate.details.session_id, child.details.session_id);
            let same_user_sid = equal_strings_if_known(
                candidate.details.user_sid.as_deref(),
                child.details.user_sid.as_deref(),
            );
            let identity_correlated = same_session == Some(true) && same_user_sid == Some(true);
            let confidence = if parent_has_create_access && identity_correlated {
                CheckPslistConfidence::High
            } else {
                CheckPslistConfidence::Medium
            };
            let verdict = if confidence == CheckPslistConfidence::High {
                CheckPslistVerdict::PpidSpoofSuspected
            } else {
                CheckPslistVerdict::AlternativeCreatorObserved
            };
            records.push(CheckPslistRecord {
                eprocess: child.eprocess,
                pid: child.pid,
                process: child.name.clone(),
                image_path: child.details.image_path.clone(),
                create_time: child.details.create_time.clone(),
                reported_ppid: child.ppid,
                reported_parent_eprocess: reported_parent.map(|parent| parent.eprocess),
                reported_parent: reported_parent.map(|parent| parent.name.clone()),
                earliest_active_ethread: initial_thread.ethread,
                earliest_active_tid: initial_thread.tid,
                earliest_active_thread_create_time: initial_thread.create_time.clone(),
                likely_creator_eprocess: candidate.eprocess,
                likely_creator_pid: candidate.pid,
                likely_creator: candidate.name.clone(),
                likely_creator_image_path: candidate.details.image_path.clone(),
                likely_creator_create_time: candidate.details.create_time.clone(),
                creator_to_child_delta_ms: creator_to_child_delta_ms(candidate, child),
                same_session,
                same_user_sid,
                verdict,
                confidence,
                evidence: CheckPslistEvidence {
                    child_process_handle: handle_evidence(child_owner),
                    earliest_active_thread_handle: handle_evidence(thread_owner),
                    reported_parent_process_handle: parent_owner.map(handle_evidence),
                    reported_parent_has_process_create_process_access: parent_has_create_access,
                    initial_thread_basis: "earliest_active_ethread_create_time",
                },
            });
        }
    }

    records.sort_unstable_by(|left, right| {
        right
            .confidence
            .cmp(&left.confidence)
            .then_with(|| left.pid.cmp(&right.pid))
            .then_with(|| left.likely_creator_pid.cmp(&right.likely_creator_pid))
            .then_with(|| left.eprocess.cmp(&right.eprocess))
    });
    records.dedup_by_key(|record| (record.eprocess, record.likely_creator_eprocess));
    let recovered_records = records.len();
    records.truncate(options.result_limit);
    let truncated = recovered_records > records.len();
    let high_confidence_count = records
        .iter()
        .filter(|record| record.confidence == CheckPslistConfidence::High)
        .count();
    let medium_confidence_count = records.len() - high_confidence_count;
    let mut warnings = process_warnings(processes);
    warnings.extend(
        threads
            .warnings
            .iter()
            .map(|warning| format!("线程枚举：{warning}")),
    );
    warnings.extend(
        owners
            .warnings
            .iter()
            .map(|warning| format!("句柄关联：{warning}")),
    );
    if truncated {
        warnings.push(format!(
            "check-pslist 恢复 {recovered_records} 条候选关系，按结果上限仅保留 {} 条",
            options.result_limit
        ));
    }

    CheckPslistReport {
        records,
        processes_examined: processes.processes.len(),
        target_processes: targets.len(),
        threads_examined: threads.records.len(),
        handle_entries_examined: owners.handle_entries_examined,
        high_confidence_count,
        medium_confidence_count,
        unassessed_processes,
        routine_broker_candidates_ignored,
        complete: processes.complete && threads.complete && owners.complete && !truncated,
        warnings,
    }
}

fn unique_processes_by_pid(processes: &[ProcessRecord]) -> HashMap<u64, &ProcessRecord> {
    let mut counts = HashMap::<u64, usize>::new();
    for process in processes {
        *counts.entry(process.pid).or_default() += 1;
    }
    processes
        .iter()
        .filter(|process| counts.get(&process.pid) == Some(&1))
        .map(|process| (process.pid, process))
        .collect()
}

fn earliest_active_threads(threads: &[ThreadRecord]) -> HashMap<u64, &ThreadRecord> {
    let mut earliest = HashMap::<u64, &ThreadRecord>::new();
    for thread in threads
        .iter()
        .filter(|thread| thread.in_process_thread_list && thread.exit_time.is_none())
    {
        let Some(owner) = thread.owner_eprocess else {
            continue;
        };
        let replace = earliest
            .get(&owner)
            .is_none_or(|current| thread_time_key(thread) < thread_time_key(current));
        if replace {
            earliest.insert(owner, thread);
        }
    }
    earliest
}

fn thread_time_key(thread: &ThreadRecord) -> (&str, u64, u64) {
    (
        thread.create_time.as_deref().unwrap_or("~"),
        thread.tid,
        thread.ethread,
    )
}

fn owners_by_object(owners: &[ObjectHandleOwner]) -> HashMap<u64, Vec<&ObjectHandleOwner>> {
    let mut by_object = HashMap::<u64, Vec<&ObjectHandleOwner>>::new();
    for owner in owners {
        by_object.entry(owner.object).or_default().push(owner);
    }
    by_object
}

fn creator_is_newer_than_child(candidate: &ProcessRecord, child: &ProcessRecord) -> bool {
    matches!(
        (
            candidate.details.create_time_raw,
            child.details.create_time_raw
        ),
        (Some(candidate), Some(child)) if candidate > child
    )
}

fn is_routine_process_broker(candidate: &ProcessRecord) -> bool {
    // The kernel and CSRSS routinely retain process/thread creation objects.
    // They are useful corroborating witnesses, but treating them as the user-
    // mode creator produces a candidate for nearly every newly created process.
    candidate.pid == 4
        || candidate.name.eq_ignore_ascii_case("System")
        || candidate.name.eq_ignore_ascii_case("csrss.exe")
}

fn creator_to_child_delta_ms(candidate: &ProcessRecord, child: &ProcessRecord) -> Option<u64> {
    child
        .details
        .create_time_raw?
        .checked_sub(candidate.details.create_time_raw?)
        .map(|ticks| ticks / 10_000)
}

fn equal_if_known<T: PartialEq>(left: Option<T>, right: Option<T>) -> Option<bool> {
    Some(left? == right?)
}

fn equal_strings_if_known(left: Option<&str>, right: Option<&str>) -> Option<bool> {
    Some(left?.eq_ignore_ascii_case(right?))
}

fn handle_evidence(owner: &ObjectHandleOwner) -> HandleEvidence {
    HandleEvidence {
        handle: owner.handle,
        object: owner.object,
        granted_access: owner.granted_access,
    }
}

fn process_warnings(report: &ProcessListReport) -> Vec<String> {
    report
        .warnings
        .iter()
        .map(|warning| format!("进程枚举 [{}]：{}", warning.kind, warning.message))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::{ProcessDetails, ProcessListStopReason};

    fn process(
        eprocess: u64,
        pid: u64,
        ppid: Option<u64>,
        name: &str,
        create_time_raw: u64,
    ) -> ProcessRecord {
        ProcessRecord {
            eprocess,
            pid,
            ppid,
            name: name.to_owned(),
            details: ProcessDetails {
                image_path: Some(format!(r"C:\{name}")),
                create_time_raw: Some(create_time_raw),
                create_time: Some(format!("{create_time_raw}")),
                session_id: Some(1),
                user_sid: Some("S-1-5-21-1001".to_owned()),
                ..ProcessDetails::default()
            },
        }
    }

    fn thread(ethread: u64, owner: u64, pid: u64, tid: u64, time: &str) -> ThreadRecord {
        ThreadRecord {
            ethread,
            physical_address: None,
            owner_eprocess: Some(owner),
            pid,
            tid,
            process: String::new(),
            start_address: None,
            win32_start_address: None,
            start_module: None,
            state: None,
            state_name: String::new(),
            wait_reason: None,
            wait_reason_name: None,
            suspend_count: None,
            freeze_count: None,
            previous_mode: None,
            priority: None,
            base_priority: None,
            teb: None,
            kernel_stack: None,
            create_time: Some(time.to_owned()),
            exit_time: None,
            hide_from_debugger: None,
            system_thread: Some(false),
            in_process_thread_list: true,
            pool_scanned: false,
            suspicious_reasons: Vec::new(),
        }
    }

    fn owner(pid: u64, object: u64, handle: u32, granted_access: u32) -> ObjectHandleOwner {
        ObjectHandleOwner {
            pid,
            process: String::new(),
            user_name: None,
            user_sid: None,
            process_create_time: None,
            handle,
            entry: 0,
            object_header: object - 0x30,
            object,
            granted_access,
        }
    }

    fn reports(
        owners: Vec<ObjectHandleOwner>,
    ) -> (ProcessListReport, ThreadReport, ObjectHandleOwnerReport) {
        let processes = ProcessListReport {
            processes: vec![
                process(0x1000, 7656, Some(6684), "chrome.exe", 10_000_000),
                process(0x7000, 816, Some(672), "csrss.exe", 1_000_000),
                process(0x2000, 4376, Some(3272), "QQ.exe", 20_000_000),
                process(0x6000, 5555, Some(3272), "other.exe", 19_000_000),
                process(0x3000, 1356, Some(7656), "notepad.exe", 21_470_000),
            ],
            complete: true,
            stop_reason: ProcessListStopReason::ListHead,
            warnings: Vec::new(),
        };
        let threads = ThreadReport {
            records: vec![
                thread(0x4000, 0x3000, 1356, 10364, "2026-08-30T10:59:10.664Z"),
                thread(0x5000, 0x3000, 1356, 4088, "2026-08-30T10:59:10.699Z"),
            ],
            process_count: 5,
            complete: true,
            warnings: Vec::new(),
        };
        let handles = ObjectHandleOwnerReport {
            records: owners,
            complete: true,
            processes_examined: 5,
            handle_entries_examined: 128,
            warnings: Vec::new(),
        };
        (processes, threads, handles)
    }

    #[test]
    fn reports_high_confidence_spoof_when_creator_owns_parent_child_and_initial_thread() {
        let (processes, threads, handles) = reports(vec![
            owner(4376, 0x1000, 0xcc, 0x1f_ffff),
            owner(4376, 0x4000, 0x100, 0x1f_ffff),
            owner(4376, 0x3000, 0x108, 0x1f_ffff),
        ]);
        let report = correlate_process_lineage(
            &processes,
            &threads,
            &handles,
            &CheckPslistOptions::default(),
        );

        assert!(report.complete);
        assert_eq!(report.records.len(), 1);
        let record = &report.records[0];
        assert_eq!(record.pid, 1356);
        assert_eq!(record.reported_ppid, Some(7656));
        assert_eq!(record.likely_creator_pid, 4376);
        assert_eq!(record.creator_to_child_delta_ms, Some(147));
        assert_eq!(record.confidence, CheckPslistConfidence::High);
        assert_eq!(record.verdict, CheckPslistVerdict::PpidSpoofSuspected);
        assert!(
            record
                .evidence
                .reported_parent_has_process_create_process_access
        );
    }

    #[test]
    fn does_not_treat_a_process_handle_alone_as_creator_evidence() {
        let (processes, threads, handles) = reports(vec![owner(4376, 0x3000, 0x108, 0x1f_ffff)]);
        let report = correlate_process_lineage(
            &processes,
            &threads,
            &handles,
            &CheckPslistOptions::default(),
        );
        assert!(report.records.is_empty());
    }

    #[test]
    fn reports_medium_confidence_without_parent_process_create_access() {
        let (processes, threads, handles) = reports(vec![
            owner(4376, 0x4000, 0x100, 0x1f_ffff),
            owner(4376, 0x3000, 0x108, 0x1f_ffff),
        ]);
        let report = correlate_process_lineage(
            &processes,
            &threads,
            &handles,
            &CheckPslistOptions::default(),
        );
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].confidence, CheckPslistConfidence::Medium);
        assert_eq!(
            report.records[0].verdict,
            CheckPslistVerdict::AlternativeCreatorObserved
        );
    }

    #[test]
    fn identity_mismatch_does_not_receive_high_confidence() {
        let (mut processes, threads, handles) = reports(vec![
            owner(4376, 0x1000, 0xcc, 0x1f_ffff),
            owner(4376, 0x4000, 0x100, 0x1f_ffff),
            owner(4376, 0x3000, 0x108, 0x1f_ffff),
        ]);
        processes
            .processes
            .iter_mut()
            .find(|process| process.pid == 4376)
            .unwrap()
            .details
            .user_sid = Some("S-1-5-18".to_owned());

        let report = correlate_process_lineage(
            &processes,
            &threads,
            &handles,
            &CheckPslistOptions::default(),
        );
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].same_user_sid, Some(false));
        assert_eq!(report.records[0].confidence, CheckPslistConfidence::Medium);
        assert_eq!(
            report.records[0].verdict,
            CheckPslistVerdict::AlternativeCreatorObserved
        );
    }

    #[test]
    fn ignores_the_recorded_parent_as_an_alternative_creator() {
        let (processes, threads, handles) = reports(vec![
            owner(7656, 0x4000, 0x100, 0x1f_ffff),
            owner(7656, 0x3000, 0x108, 0x1f_ffff),
        ]);
        let report = correlate_process_lineage(
            &processes,
            &threads,
            &handles,
            &CheckPslistOptions::default(),
        );
        assert!(report.records.is_empty());
    }

    #[test]
    fn ignores_routine_csrss_process_creation_handles() {
        let (processes, threads, handles) = reports(vec![
            owner(816, 0x1000, 0xcc, 0x1f_ffff),
            owner(816, 0x4000, 0x100, 0x1f_ffff),
            owner(816, 0x3000, 0x108, 0x1f_ffff),
        ]);
        let report = correlate_process_lineage(
            &processes,
            &threads,
            &handles,
            &CheckPslistOptions::default(),
        );
        assert!(report.records.is_empty());
        assert_eq!(report.routine_broker_candidates_ignored, 1);
    }

    #[test]
    fn truncation_is_explicitly_incomplete() {
        let (processes, threads, handles) = reports(vec![
            owner(4376, 0x4000, 0x100, 0x1f_ffff),
            owner(4376, 0x3000, 0x108, 0x1f_ffff),
            owner(5555, 0x4000, 0x110, 0x1f_ffff),
            owner(5555, 0x3000, 0x118, 0x1f_ffff),
        ]);
        let report = correlate_process_lineage(
            &processes,
            &threads,
            &handles,
            &CheckPslistOptions {
                result_limit: 1,
                ..CheckPslistOptions::default()
            },
        );
        assert!(!report.complete);
        assert_eq!(report.records.len(), 1);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("恢复 2 条"))
        );
    }
}
