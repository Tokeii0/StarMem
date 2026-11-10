use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{Result, ensure};
use serde::Serialize;
use sha1::{Digest, Sha1};

use super::plugins::list_drivers;
use super::system_plugins::{
    PoolAllocationRecord, scan_pool_allocations, scan_pool_allocations_cancellable,
};
use super::{
    ProcessRecord, WindowsKernelContext, filetime_to_rfc3339, is_kernel_address, is_kernel_pointer,
    list_processes, read_process_details,
};
use crate::address::X64AddressSpace;
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::profile::{FieldProfile, KernelProfile};

const MAX_ACTIVE_PROCESSES: usize = 65_536;
const MAX_POOL_OBJECTS: usize = 1_000_000;
const PRIVILEGES: &[(u8, &str, &str)] = &[
    (2, "SeCreateTokenPrivilege", "创建令牌对象"),
    (3, "SeAssignPrimaryTokenPrivilege", "替换进程级令牌"),
    (4, "SeLockMemoryPrivilege", "锁定内存页"),
    (5, "SeIncreaseQuotaPrivilege", "增加配额"),
    (6, "SeMachineAccountPrivilege", "将工作站加入域"),
    (7, "SeTcbPrivilege", "作为操作系统的一部分运行"),
    (8, "SeSecurityPrivilege", "管理审核和安全日志"),
    (9, "SeTakeOwnershipPrivilege", "取得对象所有权"),
    (10, "SeLoadDriverPrivilege", "加载和卸载设备驱动"),
    (11, "SeSystemProfilePrivilege", "分析系统性能"),
    (12, "SeSystemtimePrivilege", "更改系统时间"),
    (13, "SeProfileSingleProcessPrivilege", "分析单个进程性能"),
    (14, "SeIncreaseBasePriorityPrivilege", "提高调度优先级"),
    (15, "SeCreatePagefilePrivilege", "创建页面文件"),
    (16, "SeCreatePermanentPrivilege", "创建永久共享对象"),
    (17, "SeBackupPrivilege", "备份文件和目录"),
    (18, "SeRestorePrivilege", "还原文件和目录"),
    (19, "SeShutdownPrivilege", "关闭系统"),
    (20, "SeDebugPrivilege", "调试程序"),
    (21, "SeAuditPrivilege", "生成安全审核"),
    (22, "SeSystemEnvironmentPrivilege", "编辑固件环境变量值"),
    (23, "SeChangeNotifyPrivilege", "绕过遍历检查"),
    (24, "SeRemoteShutdownPrivilege", "强制远程关机"),
    (25, "SeUndockPrivilege", "从扩展坞移除计算机"),
    (26, "SeSyncAgentPrivilege", "同步目录服务数据"),
    (27, "SeEnableDelegationPrivilege", "启用受信任委派"),
    (28, "SeManageVolumePrivilege", "管理卷文件"),
    (29, "SeImpersonatePrivilege", "模拟客户端"),
    (30, "SeCreateGlobalPrivilege", "创建全局对象"),
    (
        31,
        "SeTrustedCredManAccessPrivilege",
        "访问受信任的凭据管理器",
    ),
    (32, "SeRelabelPrivilege", "修改强制完整性级别"),
    (33, "SeIncreaseWorkingSetPrivilege", "增加进程工作集"),
    (34, "SeTimeZonePrivilege", "调整时区"),
    (35, "SeCreateSymbolicLinkPrivilege", "创建符号链接"),
    (
        36,
        "SeDelegateSessionUserImpersonatePrivilege",
        "模拟同一会话中的其他用户",
    ),
];

#[derive(Debug, Serialize)]
pub struct ProcessScanReport {
    pub records: Vec<ScannedProcessRecord>,
    pub active_process_count: usize,
    pub pool_candidates: usize,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScannedProcessRecord {
    pub eprocess: u64,
    pub physical_address: u64,
    pub pool_header: u64,
    pub allocation_size: u64,
    pub pid: u64,
    pub ppid: Option<u64>,
    pub name: String,
    pub directory_table_base: Option<u64>,
    pub create_time: Option<String>,
    pub exit_time: Option<String>,
    pub active_threads: Option<u32>,
    pub in_active_list: bool,
    pub validation_score: u8,
}

#[derive(Debug, Serialize)]
pub struct ProcessTreeReport {
    pub records: Vec<ProcessTreeRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProcessTreeRecord {
    pub depth: usize,
    pub eprocess: u64,
    pub pid: u64,
    pub ppid: Option<u64>,
    pub name: String,
    pub orphan_parent: bool,
    pub parent_cycle: bool,
    pub create_time: Option<String>,
    pub command_line: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadRecord {
    pub ethread: u64,
    pub physical_address: Option<u64>,
    pub owner_eprocess: Option<u64>,
    pub pid: u64,
    pub tid: u64,
    pub process: String,
    pub start_address: Option<u64>,
    pub win32_start_address: Option<u64>,
    pub start_module: Option<String>,
    pub state: Option<u8>,
    pub state_name: String,
    pub wait_reason: Option<u8>,
    pub wait_reason_name: Option<String>,
    pub suspend_count: Option<u8>,
    pub freeze_count: Option<u8>,
    pub previous_mode: Option<u8>,
    pub priority: Option<i8>,
    pub base_priority: Option<i8>,
    pub teb: Option<u64>,
    pub kernel_stack: Option<u64>,
    pub create_time: Option<String>,
    pub exit_time: Option<String>,
    pub hide_from_debugger: Option<bool>,
    pub system_thread: Option<bool>,
    pub in_process_thread_list: bool,
    pub pool_scanned: bool,
    pub suspicious_reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ThreadReport {
    pub records: Vec<ThreadRecord>,
    pub process_count: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ThreadScanReport {
    pub records: Vec<ThreadRecord>,
    pub pool_candidates: usize,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProcessSessionReport {
    pub sessions: Vec<ProcessSessionRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProcessSessionRecord {
    pub session_id: u32,
    pub process_count: usize,
    pub user_sids: Vec<String>,
    pub processes: Vec<SessionProcessRecord>,
}

#[derive(Debug, Serialize)]
pub struct SessionProcessRecord {
    pub pid: u64,
    pub name: String,
    pub eprocess: u64,
    pub user_sid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct JobLinkReport {
    pub records: Vec<JobLinkRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct JobLinkRecord {
    pub pid: u64,
    pub process: String,
    pub eprocess: u64,
    pub job: u64,
    pub job_id: Option<u32>,
    pub session_id: Option<u32>,
    pub total_processes: Option<u32>,
    pub active_processes: Option<u32>,
    pub total_terminated_processes: Option<u32>,
    pub limit_flags: Option<u32>,
    pub parent_job: Option<u64>,
    pub root_job: Option<u64>,
    pub silo: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct PsxviewReport {
    pub records: Vec<PsxviewRecord>,
    pub cid_handles_examined: u32,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PsxviewRecord {
    pub eprocess: u64,
    pub pid: Option<u64>,
    pub name: Option<String>,
    pub active_process_list: bool,
    pub process_pool: bool,
    pub thread_owner: bool,
    pub psp_cid_table: Option<bool>,
    pub evidence_count: u8,
    pub hidden_suspect: bool,
}

#[derive(Debug, Serialize)]
pub struct CommandLineReport {
    pub records: Vec<CommandLineRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CommandLineRecord {
    pub pid: u64,
    pub process: String,
    pub eprocess: u64,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EnvironmentReport {
    pub records: Vec<EnvironmentVariableRecord>,
    pub process_count: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EnvironmentVariableRecord {
    pub pid: u64,
    pub process: String,
    pub variable: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct SidReport {
    pub records: Vec<SidRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SidRecord {
    pub pid: u64,
    pub process: String,
    pub sid: String,
    pub kind: String,
    /// Resolved principal name, when the SID alone decides it.
    pub account: Option<String>,
    /// How `account` was obtained. `None` when the SID stayed unresolved.
    pub account_source: Option<&'static str>,
    pub attributes: Option<u32>,
    pub attribute_names: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PrivilegeReport {
    pub records: Vec<PrivilegeRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PrivilegeRecord {
    pub pid: u64,
    pub process: String,
    pub value: u8,
    pub privilege: String,
    pub description: String,
    pub present: bool,
    pub enabled: bool,
    pub enabled_by_default: bool,
}

#[derive(Debug, Serialize)]
pub struct ServiceSidReport {
    pub records: Vec<ServiceSidRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ServiceSidRecord {
    pub service: String,
    pub sid: String,
}

pub fn scan_processes(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<ProcessScanReport> {
    scan_processes_cancellable(image, kernel, profile, limit, &CancellationToken::new())
}

pub fn scan_processes_cancellable(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
    cancellation: &CancellationToken,
) -> Result<ProcessScanReport> {
    cancellation.check_cancelled()?;
    ensure!(limit > 0, "进程扫描结果上限必须大于零");
    #[cfg(debug_assertions)]
    eprintln!("[starmem-debug][psscan] active-list:start");
    let active = list_processes(image, kernel, profile, MAX_ACTIVE_PROCESSES)?;
    #[cfg(debug_assertions)]
    eprintln!(
        "[starmem-debug][psscan] active-list:done records={} complete={}",
        active.processes.len(),
        active.complete
    );
    cancellation.check_cancelled()?;
    let active_addresses = active
        .processes
        .iter()
        .map(|process| process.eprocess)
        .collect::<HashSet<_>>();
    #[cfg(debug_assertions)]
    eprintln!("[starmem-debug][psscan] pool-scan:start");
    let pool = scan_pool_allocations_cancellable(
        image,
        kernel,
        profile,
        &[*b"Proc"],
        MAX_POOL_OBJECTS,
        cancellation,
    )?;
    #[cfg(debug_assertions)]
    eprintln!(
        "[starmem-debug][psscan] pool-scan:done candidates={} complete={}",
        pool.records.len(),
        pool.complete
    );
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for allocation in &pool.records {
        cancellation.check_cancelled()?;
        let Some(candidate) = find_eprocess_in_allocation(&space, profile, allocation) else {
            continue;
        };
        if !seen.insert(candidate.address) {
            continue;
        }
        let details = read_process_details(image, &space, profile, candidate.address);
        records.push(ScannedProcessRecord {
            eprocess: candidate.address,
            physical_address: allocation
                .physical_address_for(candidate.address)
                .unwrap_or(allocation.physical_body),
            pool_header: candidate.pool_header,
            allocation_size: allocation.allocation_size,
            pid: candidate.pid,
            ppid: candidate.ppid,
            name: candidate.name,
            directory_table_base: details.directory_table_base,
            create_time: details.create_time,
            exit_time: details.exit_time,
            active_threads: details.active_threads,
            in_active_list: active_addresses.contains(&candidate.address),
            validation_score: candidate.score,
        });
    }
    #[cfg(debug_assertions)]
    eprintln!(
        "[starmem-debug][psscan] validate:done records={}",
        records.len()
    );
    records.sort_unstable_by_key(|record| (record.pid, record.eprocess));
    let truncated = records.len() > limit;
    records.truncate(limit);
    let mut warnings = pool.warnings;
    if truncated {
        warnings.push(format!("结构验证后的进程结果达到 {limit} 条上限"));
    }
    for warning in active.warnings {
        warnings.push(format!(
            "活动进程链表 [{}]：{}",
            warning.kind, warning.message
        ));
    }
    Ok(ProcessScanReport {
        records,
        active_process_count: active.processes.len(),
        pool_candidates: pool.records.len(),
        bytes_scanned: pool.bytes_scanned,
        scan_seconds: pool.elapsed_seconds,
        scan_gib_per_second: pool.gib_per_second,
        complete: pool.complete && active.complete && !truncated,
        warnings,
    })
}

pub fn process_tree(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<ProcessTreeReport> {
    let report = list_processes(image, kernel, profile, limit)?;
    let by_pid = report
        .processes
        .iter()
        .map(|process| (process.pid, process))
        .collect::<HashMap<_, _>>();
    let mut children = BTreeMap::<u64, Vec<&ProcessRecord>>::new();
    let mut roots = Vec::new();
    for process in &report.processes {
        if let Some(parent) = process.ppid.filter(|parent| by_pid.contains_key(parent)) {
            children.entry(parent).or_default().push(process);
        } else {
            roots.push(process);
        }
    }
    for values in children.values_mut() {
        values.sort_unstable_by_key(|process| (process.pid, process.eprocess));
    }
    roots.sort_unstable_by_key(|process| (process.pid, process.eprocess));
    let mut records = Vec::with_capacity(report.processes.len());
    let mut emitted = HashSet::new();
    for root in roots {
        append_process_tree(root, 0, &children, &by_pid, &mut emitted, &mut records);
    }
    for process in &report.processes {
        if !emitted.contains(&process.eprocess) {
            append_process_tree(process, 0, &children, &by_pid, &mut emitted, &mut records);
        }
    }
    Ok(ProcessTreeReport {
        records,
        complete: report.complete,
        warnings: report
            .warnings
            .into_iter()
            .map(|warning| format!("[{}] {}", warning.kind, warning.message))
            .collect(),
    })
}

pub fn list_threads(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<ThreadReport> {
    ensure!(limit > 0, "线程结果上限必须大于零");
    let processes = list_processes(image, kernel, profile, MAX_ACTIVE_PROCESSES)?;
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let head_offset = profile.type_field("_EPROCESS", "ThreadListHead")?.offset;
    let link_offset = profile.type_field("_ETHREAD", "ThreadListEntry")?.offset;
    let modules = list_drivers(image, kernel, profile, 65_536)?;
    let mut records = Vec::new();
    let mut warnings = modules.warnings;
    let mut seen = HashSet::new();
    let mut complete = processes.complete && modules.complete;
    for process in &processes.processes {
        if records.len() == limit {
            complete = false;
            warnings.push(format!("线程结果达到 {limit} 条上限"));
            break;
        }
        let head = process.eprocess + head_offset;
        let mut link = match space.read_u64(head) {
            Ok(link) => link,
            Err(error) => {
                push_limited(
                    &mut warnings,
                    format!("PID {} 的线程链表头不可读：{error:#}", process.pid),
                );
                complete = false;
                continue;
            }
        };
        let mut local_seen = HashSet::new();
        while link != head && records.len() < limit {
            if !is_kernel_pointer(link) || link < link_offset || !local_seen.insert(link) {
                complete = false;
                push_limited(
                    &mut warnings,
                    format!("PID {} 的线程链接 {link:#x} 无效或形成循环", process.pid),
                );
                break;
            }
            let ethread = link - link_offset;
            if seen.insert(ethread) {
                if let Some(mut record) = parse_thread(&space, profile, ethread, None) {
                    record.in_process_thread_list = true;
                    attribute_thread(&mut record, &processes.processes, &modules.records);
                    records.push(record);
                } else {
                    complete = false;
                    push_limited(
                        &mut warnings,
                        format!("无法验证 PID {} 的 ETHREAD {ethread:#x}", process.pid),
                    );
                }
            }
            link = match space.read_u64(link) {
                Ok(next) => next,
                Err(error) => {
                    complete = false;
                    push_limited(
                        &mut warnings,
                        format!("无法在 {link:#x} 继续遍历线程链表：{error:#}"),
                    );
                    break;
                }
            };
        }
    }
    for warning in processes.warnings {
        push_limited(
            &mut warnings,
            format!("活动进程链表 [{}]：{}", warning.kind, warning.message),
        );
    }
    records.sort_unstable_by_key(|thread| (thread.pid, thread.tid, thread.ethread));
    Ok(ThreadReport {
        records,
        process_count: processes.processes.len(),
        complete,
        warnings,
    })
}

pub fn scan_threads(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<ThreadScanReport> {
    ensure!(limit > 0, "线程扫描结果上限必须大于零");
    let pool = scan_pool_allocations(image, kernel, profile, &[*b"Thre"], MAX_POOL_OBJECTS)?;
    let active = list_threads(image, kernel, profile, MAX_POOL_OBJECTS)?;
    let active_addresses = active
        .records
        .iter()
        .map(|thread| thread.ethread)
        .collect::<HashSet<_>>();
    let processes = list_processes(image, kernel, profile, MAX_ACTIVE_PROCESSES)?;
    let modules = list_drivers(image, kernel, profile, 65_536)?;
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for allocation in &pool.records {
        let Some((ethread, physical)) = find_ethread_in_allocation(&space, profile, allocation)
        else {
            continue;
        };
        if !seen.insert(ethread) {
            continue;
        }
        if let Some(mut record) = parse_thread(&space, profile, ethread, Some(physical)) {
            record.pool_scanned = true;
            record.in_process_thread_list = active_addresses.contains(&ethread);
            attribute_thread(&mut record, &processes.processes, &modules.records);
            records.push(record);
        }
    }
    records.sort_unstable_by_key(|thread| (thread.pid, thread.tid, thread.ethread));
    let truncated = records.len() > limit;
    records.truncate(limit);
    let mut warnings = pool.warnings;
    warnings.extend(active.warnings);
    warnings.extend(modules.warnings);
    if truncated {
        warnings.push(format!("结构验证后的线程结果达到 {limit} 条上限"));
    }
    Ok(ThreadScanReport {
        records,
        pool_candidates: pool.records.len(),
        bytes_scanned: pool.bytes_scanned,
        scan_seconds: pool.elapsed_seconds,
        scan_gib_per_second: pool.gib_per_second,
        complete: pool.complete && active.complete && processes.complete && !truncated,
        warnings,
    })
}

pub fn process_sessions(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<ProcessSessionReport> {
    let processes = list_processes(image, kernel, profile, limit)?;
    let mut grouped = BTreeMap::<u32, Vec<&ProcessRecord>>::new();
    for process in &processes.processes {
        if let Some(session_id) = process.details.session_id {
            grouped.entry(session_id).or_default().push(process);
        }
    }
    let sessions = grouped
        .into_iter()
        .map(|(session_id, values)| {
            let mut user_sids = values
                .iter()
                .filter_map(|process| process.details.user_sid.clone())
                .collect::<Vec<_>>();
            user_sids.sort();
            user_sids.dedup();
            ProcessSessionRecord {
                session_id,
                process_count: values.len(),
                user_sids,
                processes: values
                    .into_iter()
                    .map(|process| SessionProcessRecord {
                        pid: process.pid,
                        name: process.name.clone(),
                        eprocess: process.eprocess,
                        user_sid: process.details.user_sid.clone(),
                    })
                    .collect(),
            }
        })
        .collect();
    Ok(ProcessSessionReport {
        sessions,
        complete: processes.complete,
        warnings: processes
            .warnings
            .into_iter()
            .map(|warning| format!("[{}] {}", warning.kind, warning.message))
            .collect(),
    })
}

pub fn command_lines(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<CommandLineReport> {
    let processes = list_processes(image, kernel, profile, limit)?;
    let records = processes
        .processes
        .iter()
        .map(|process| CommandLineRecord {
            pid: process.pid,
            process: process.name.clone(),
            eprocess: process.eprocess,
            image_path: process.details.image_path.clone(),
            command_line: process.details.command_line.clone(),
        })
        .collect();
    Ok(CommandLineReport {
        records,
        complete: processes.complete,
        warnings: process_warnings(processes.warnings),
    })
}

pub fn environment_variables(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<EnvironmentReport> {
    let processes = list_processes(image, kernel, profile, MAX_ACTIVE_PROCESSES)?;
    let process_count = processes.processes.len();
    let mut records = Vec::new();
    for process in &processes.processes {
        for (variable, value) in &process.details.environment_variables {
            if records.len() == limit {
                break;
            }
            records.push(EnvironmentVariableRecord {
                pid: process.pid,
                process: process.name.clone(),
                variable: variable.clone(),
                value: value.clone(),
            });
        }
        if records.len() == limit {
            break;
        }
    }
    let truncated = records.len() == limit
        && processes
            .processes
            .iter()
            .map(|process| process.details.environment_variables.len())
            .sum::<usize>()
            > limit;
    let mut warnings = process_warnings(processes.warnings);
    if truncated {
        warnings.push(format!("环境变量结果达到 {limit} 条上限"));
    }
    Ok(EnvironmentReport {
        records,
        process_count,
        complete: processes.complete && !truncated,
        warnings,
    })
}

pub fn process_sids(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid: Option<u64>,
    limit: usize,
) -> Result<SidReport> {
    let processes = list_processes(image, kernel, profile, MAX_ACTIVE_PROCESSES)?;
    let mut matched_requested_pid = pid.is_none();
    let mut records = Vec::new();
    for process in &processes.processes {
        if let Some(pid) = pid {
            if process.pid != pid {
                continue;
            }
            matched_requested_pid = true;
        }
        if let Some(sid) = &process.details.user_sid {
            records.push(SidRecord {
                pid: process.pid,
                process: process.name.clone(),
                sid: sid.clone(),
                kind: "user".to_owned(),
                account: well_known_sid_account(sid),
                account_source: well_known_sid_account(sid).map(|_| "well_known"),
                attributes: None,
                attribute_names: Vec::new(),
            });
        }
        for group in &process.details.token_groups {
            records.push(SidRecord {
                pid: process.pid,
                process: process.name.clone(),
                sid: group.sid.clone(),
                kind: if process.details.integrity_sid.as_ref() == Some(&group.sid) {
                    "integrity".to_owned()
                } else {
                    "group".to_owned()
                },
                account: well_known_sid_account(&group.sid),
                account_source: well_known_sid_account(&group.sid).map(|_| "well_known"),
                attributes: Some(group.attributes),
                attribute_names: group.attribute_names.clone(),
            });
        }
    }
    if let Some(pid) = pid {
        ensure!(
            matched_requested_pid,
            "PsActiveProcessHead 中没有 PID {pid}"
        );
    }
    let truncated = records.len() > limit;
    records.truncate(limit);
    let mut warnings = process_warnings(processes.warnings);
    if truncated {
        warnings.push(format!("SID 结果达到 {limit} 条上限"));
    }
    Ok(SidReport {
        records,
        complete: processes.complete && !truncated,
        warnings,
    })
}

pub fn process_privileges(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<PrivilegeReport> {
    let processes = list_processes(image, kernel, profile, MAX_ACTIVE_PROCESSES)?;
    let mut records = Vec::new();
    for process in &processes.processes {
        let present = process.details.privileges_present.unwrap_or(0);
        let enabled = process.details.privileges_enabled.unwrap_or(0);
        let default = process.details.privileges_enabled_by_default.unwrap_or(0);
        for (value, name, description) in PRIVILEGES {
            let mask = 1u64 << value;
            if present & mask == 0 && enabled & mask == 0 && default & mask == 0 {
                continue;
            }
            records.push(PrivilegeRecord {
                pid: process.pid,
                process: process.name.clone(),
                value: *value,
                privilege: (*name).to_owned(),
                description: (*description).to_owned(),
                present: present & mask != 0,
                enabled: enabled & mask != 0,
                enabled_by_default: default & mask != 0,
            });
        }
    }
    let truncated = records.len() > limit;
    records.truncate(limit);
    let mut warnings = process_warnings(processes.warnings);
    if truncated {
        warnings.push(format!("权限结果达到 {limit} 条上限"));
    }
    Ok(PrivilegeReport {
        records,
        complete: processes.complete && !truncated,
        warnings,
    })
}

pub fn service_sid_report(
    service_names: impl IntoIterator<Item = String>,
    limit: usize,
    mut warnings: Vec<String>,
) -> ServiceSidReport {
    let mut names = service_names.into_iter().collect::<Vec<_>>();
    names.sort_by_key(|name| name.to_ascii_lowercase());
    names.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    let truncated = names.len() > limit;
    names.truncate(limit);
    if truncated {
        warnings.push(format!("服务 SID 结果达到 {limit} 条上限"));
    }
    ServiceSidReport {
        records: names
            .into_iter()
            .map(|service| ServiceSidRecord {
                sid: service_sid(&service),
                service,
            })
            .collect(),
        complete: !truncated,
        warnings,
    }
}

pub fn service_sid(service_name: &str) -> String {
    let uppercase = service_name.to_uppercase();
    let mut bytes = Vec::with_capacity(uppercase.len() * 2);
    for word in uppercase.encode_utf16() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let digest = Sha1::digest(&bytes);
    let authorities = digest
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("SHA-1 DWORD")))
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!("S-1-5-80-{authorities}")
}

pub fn job_links(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<JobLinkReport> {
    let processes = list_processes(image, kernel, profile, limit)?;
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut records = Vec::new();
    let mut warnings = Vec::new();
    for process in &processes.processes {
        let Some(job) = type_u64(&space, profile, "_EPROCESS", process.eprocess, "Job")
            .map(|value| value & !0xf)
            .filter(|value| is_kernel_pointer(*value))
        else {
            continue;
        };
        records.push(JobLinkRecord {
            pid: process.pid,
            process: process.name.clone(),
            eprocess: process.eprocess,
            job,
            job_id: type_u32(&space, profile, "_EJOB", job, "JobId"),
            session_id: type_u32(&space, profile, "_EJOB", job, "SessionId"),
            total_processes: type_u32(&space, profile, "_EJOB", job, "TotalProcesses"),
            active_processes: type_u32(&space, profile, "_EJOB", job, "ActiveProcesses"),
            total_terminated_processes: type_u32(
                &space,
                profile,
                "_EJOB",
                job,
                "TotalTerminatedProcesses",
            ),
            limit_flags: type_u32(&space, profile, "_EJOB", job, "LimitFlags"),
            parent_job: type_kernel_pointer(&space, profile, "_EJOB", job, "ParentJob"),
            root_job: type_kernel_pointer(&space, profile, "_EJOB", job, "RootJob"),
            silo: type_kernel_pointer(&space, profile, "_EJOB", job, "Silo"),
        });
    }
    for warning in processes.warnings {
        warnings.push(format!("[{}] {}", warning.kind, warning.message));
    }
    Ok(JobLinkReport {
        records,
        complete: processes.complete,
        warnings,
    })
}

pub fn psxview(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<PsxviewReport> {
    ensure!(limit > 0, "psxview 结果上限必须大于零");
    let active = list_processes(image, kernel, profile, MAX_ACTIVE_PROCESSES)?;
    let active_threads = list_threads(image, kernel, profile, MAX_POOL_OBJECTS)?;
    let cid = enumerate_psp_cid_table(image, kernel, profile)?;
    let pool = scan_pool_allocations(
        image,
        kernel,
        profile,
        &[*b"Proc", *b"Thre"],
        MAX_POOL_OBJECTS,
    )?;
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut evidence = HashMap::<u64, PsxviewRecord>::new();
    for process in &active.processes {
        evidence.insert(
            process.eprocess,
            PsxviewRecord {
                eprocess: process.eprocess,
                pid: Some(process.pid),
                name: Some(process.name.clone()),
                active_process_list: true,
                process_pool: false,
                thread_owner: false,
                psp_cid_table: Some(false),
                evidence_count: 0,
                hidden_suspect: false,
            },
        );
    }
    for thread in &active_threads.records {
        if let Some(owner) = thread.owner_eprocess {
            evidence
                .entry(owner)
                .or_insert_with(|| PsxviewRecord {
                    eprocess: owner,
                    pid: Some(thread.pid),
                    name: (!thread.process.is_empty()).then(|| thread.process.clone()),
                    active_process_list: false,
                    process_pool: false,
                    thread_owner: false,
                    psp_cid_table: Some(false),
                    evidence_count: 0,
                    hidden_suspect: false,
                })
                .thread_owner = true;
        }
    }
    for allocation in &pool.records {
        match allocation.tag.as_str() {
            "Proc" => {
                if let Some(candidate) = find_eprocess_in_allocation(&space, profile, allocation) {
                    let record = evidence.entry(candidate.address).or_insert(PsxviewRecord {
                        eprocess: candidate.address,
                        pid: Some(candidate.pid),
                        name: Some(candidate.name),
                        active_process_list: false,
                        process_pool: false,
                        thread_owner: false,
                        psp_cid_table: Some(false),
                        evidence_count: 0,
                        hidden_suspect: false,
                    });
                    record.process_pool = true;
                }
            }
            "Thre" => {
                if let Some((ethread, _)) = find_ethread_in_allocation(&space, profile, allocation)
                    && let Some(thread) = parse_thread(&space, profile, ethread, None)
                    && let Some(owner) = thread.owner_eprocess
                {
                    evidence
                        .entry(owner)
                        .or_insert(PsxviewRecord {
                            eprocess: owner,
                            pid: Some(thread.pid),
                            name: None,
                            active_process_list: false,
                            process_pool: false,
                            thread_owner: false,
                            psp_cid_table: Some(false),
                            evidence_count: 0,
                            hidden_suspect: false,
                        })
                        .thread_owner = true;
                }
            }
            _ => {}
        }
    }
    for process in &cid.processes {
        let record = evidence.entry(process.eprocess).or_insert(PsxviewRecord {
            eprocess: process.eprocess,
            pid: Some(process.pid),
            name: Some(process.name.clone()),
            active_process_list: false,
            process_pool: false,
            thread_owner: false,
            psp_cid_table: Some(false),
            evidence_count: 0,
            hidden_suspect: false,
        });
        record.psp_cid_table = Some(true);
    }
    for owner in &cid.thread_owners {
        evidence
            .entry(*owner)
            .or_insert(PsxviewRecord {
                eprocess: *owner,
                pid: None,
                name: None,
                active_process_list: false,
                process_pool: false,
                thread_owner: false,
                psp_cid_table: Some(false),
                evidence_count: 0,
                hidden_suspect: false,
            })
            .thread_owner = true;
    }
    let mut records = evidence.into_values().collect::<Vec<_>>();
    for record in &mut records {
        record.evidence_count = u8::from(record.active_process_list)
            + u8::from(record.process_pool)
            + u8::from(record.thread_owner)
            + u8::from(record.psp_cid_table == Some(true));
        record.hidden_suspect = !record.active_process_list
            && (record.process_pool || record.thread_owner)
            && record.evidence_count >= 2;
    }
    records.sort_unstable_by_key(|record| (record.pid.unwrap_or(u64::MAX), record.eprocess));
    let truncated = records.len() > limit;
    records.truncate(limit);
    let mut warnings = pool.warnings;
    warnings.extend(active_threads.warnings);
    warnings.extend(cid.warnings);
    warnings.extend(
        active
            .warnings
            .into_iter()
            .map(|warning| format!("[{}] {}", warning.kind, warning.message)),
    );
    if truncated {
        warnings.push(format!("psxview 结果达到 {limit} 条上限"));
    }
    Ok(PsxviewReport {
        records,
        cid_handles_examined: cid.handles_examined,
        bytes_scanned: pool.bytes_scanned,
        scan_seconds: pool.elapsed_seconds,
        scan_gib_per_second: pool.gib_per_second,
        complete: pool.complete
            && active.complete
            && active_threads.complete
            && cid.complete
            && !truncated,
        warnings,
    })
}

struct CidProcess {
    eprocess: u64,
    pid: u64,
    name: String,
}

struct CidEvidence {
    processes: Vec<CidProcess>,
    thread_owners: HashSet<u64>,
    handles_examined: u32,
    complete: bool,
    warnings: Vec<String>,
}

fn enumerate_psp_cid_table(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
) -> Result<CidEvidence> {
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let global = kernel.kernel_base + u64::from(profile.symbol_rva("PspCidTable")?);
    let table = space.read_u64(global)?;
    ensure!(is_kernel_pointer(table), "PspCidTable 地址无效：{table:#x}");
    let table_code_offset = profile.type_field("_HANDLE_TABLE", "TableCode")?.offset;
    let next_handle_offset = profile
        .type_field("_HANDLE_TABLE", "NextHandleNeedingPool")?
        .offset;
    let object_body_offset = profile.type_field("_OBJECT_HEADER", "Body")?.offset;
    let compressed = profile
        .type_field("_HANDLE_TABLE_ENTRY", "ObjectPointerBits")
        .is_ok();
    let table_code = space.read_u64(table + table_code_offset)?;
    let reported_next_handle = read_u32(&space, table + next_handle_offset)?;
    let max_handle = reported_next_handle.min(0x0400_0000);
    let pid_offset = profile.type_field("_EPROCESS", "UniqueProcessId")?.offset;
    let name_field = profile.type_field("_EPROCESS", "ImageFileName")?;
    let mut processes = Vec::new();
    let mut process_seen = HashSet::new();
    let mut thread_owners = HashSet::new();
    let mut warnings = Vec::new();
    for handle in (4..max_handle).step_by(4) {
        let Ok(entry) = cid_handle_entry_address(&space, table_code, handle) else {
            continue;
        };
        let Ok(low) = space.read_u64(entry) else {
            continue;
        };
        let object_header = if compressed {
            let bits = (low >> 20) & 0x0000_0fff_ffff_ffff;
            if bits == 0 {
                continue;
            }
            sign_extend_48(bits << 4)
        } else {
            low & !0xf
        };
        if !is_kernel_pointer(object_header) {
            continue;
        }
        let handle_value = u64::from(handle);
        let mut candidates = vec![object_header, object_header + object_body_offset];
        candidates.extend(
            (0x10..=0x80)
                .step_by(0x10)
                .map(|offset| object_header + offset),
        );
        candidates.sort_unstable();
        candidates.dedup();
        let process = candidates.iter().find_map(|object| {
            (space.read_u64(*object + pid_offset).ok() == Some(handle_value))
                .then(|| read_ascii_field(&space, *object + name_field.offset, 15))
                .flatten()
                .map(|name| (*object, name))
        });
        if let Some((object, name)) = process {
            if process_seen.insert(object) {
                processes.push(CidProcess {
                    eprocess: object,
                    pid: handle_value,
                    name,
                });
            }
            continue;
        }
        if let Some(owner) = candidates.iter().find_map(|object| {
            let thread = parse_thread(&space, profile, *object, None)?;
            (thread.tid == handle_value)
                .then_some(thread.owner_eprocess)
                .flatten()
        }) {
            thread_owners.insert(owner);
        }
    }
    if reported_next_handle > max_handle {
        warnings.push(format!(
            "PspCidTable 的 NextHandleNeedingPool {reported_next_handle:#x} 超出安全上限 {max_handle:#x}"
        ));
    }
    Ok(CidEvidence {
        processes,
        thread_owners,
        handles_examined: max_handle / 4,
        complete: reported_next_handle <= max_handle,
        warnings,
    })
}

fn cid_handle_entry_address(
    space: &X64AddressSpace<'_>,
    table_code: u64,
    handle: u32,
) -> Result<u64> {
    let level = table_code & 3;
    let root = table_code & !0xf;
    let index = u64::from(handle >> 2);
    ensure!(root != 0, "CID 句柄表根指针为空");
    match level {
        0 => Ok(root + index * 16),
        1 => {
            let leaf = space.read_u64(root + (index >> 8) * 8)?;
            ensure!(leaf != 0, "CID 一级叶表指针为空");
            Ok(leaf + (index & 0xff) * 16)
        }
        2 => {
            let middle = space.read_u64(root + (index >> 17) * 8)?;
            ensure!(middle != 0, "CID 二级中间表指针为空");
            let leaf = space.read_u64(middle + ((index >> 8) & 0x1ff) * 8)?;
            ensure!(leaf != 0, "CID 二级叶表指针为空");
            Ok(leaf + (index & 0xff) * 16)
        }
        _ => unreachable!("TableCode uses two level bits"),
    }
}

fn sign_extend_48(value: u64) -> u64 {
    if value & (1 << 47) != 0 {
        value | 0xffff_0000_0000_0000
    } else {
        value
    }
}

fn append_process_tree(
    process: &ProcessRecord,
    depth: usize,
    children: &BTreeMap<u64, Vec<&ProcessRecord>>,
    by_pid: &HashMap<u64, &ProcessRecord>,
    emitted: &mut HashSet<u64>,
    output: &mut Vec<ProcessTreeRecord>,
) {
    let parent_cycle = !emitted.insert(process.eprocess);
    if parent_cycle {
        return;
    }
    output.push(ProcessTreeRecord {
        depth,
        eprocess: process.eprocess,
        pid: process.pid,
        ppid: process.ppid,
        name: process.name.clone(),
        orphan_parent: process
            .ppid
            .is_some_and(|parent| !by_pid.contains_key(&parent)),
        parent_cycle,
        create_time: process.details.create_time.clone(),
        command_line: process.details.command_line.clone(),
    });
    if let Some(values) = children.get(&process.pid) {
        for child in values {
            append_process_tree(child, depth + 1, children, by_pid, emitted, output);
        }
    }
}

struct EprocessCandidate {
    address: u64,
    pool_header: u64,
    pid: u64,
    ppid: Option<u64>,
    name: String,
    score: u8,
}

fn find_eprocess_in_allocation(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    allocation: &PoolAllocationRecord,
) -> Option<EprocessCandidate> {
    allocation
        .virtual_headers()
        .filter_map(|header| find_eprocess_at_header(space, profile, allocation, header))
        .max_by_key(|candidate| candidate.score)
}

fn find_eprocess_at_header(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    allocation: &PoolAllocationRecord,
    header: u64,
) -> Option<EprocessCandidate> {
    let type_size = profile.type_layout("_EPROCESS").ok()?.size;
    let start = header.checked_add(16)?;
    let end = header.checked_add(allocation.allocation_size)?;
    let last = end.checked_sub(type_size)?;
    let pid_offset = profile
        .type_field("_EPROCESS", "UniqueProcessId")
        .ok()?
        .offset;
    let ppid_offset = profile
        .type_field("_EPROCESS", "InheritedFromUniqueProcessId")
        .ok()
        .map(|field| field.offset);
    let name_field = profile.type_field("_EPROCESS", "ImageFileName").ok()?;
    let links_offset = profile
        .type_field("_EPROCESS", "ActiveProcessLinks")
        .ok()?
        .offset;
    let threads_offset = profile
        .type_field("_EPROCESS", "ActiveThreads")
        .ok()?
        .offset;
    let pcb_offset = profile.type_field("_EPROCESS", "Pcb").ok()?.offset;
    let dtb_offset = profile
        .type_field("_KPROCESS", "DirectoryTableBase")
        .ok()?
        .offset;
    let create_offset = profile.type_field("_EPROCESS", "CreateTime").ok()?.offset;
    let mut best: Option<EprocessCandidate> = None;
    let mut candidate = (start + 0xf) & !0xf;
    while candidate <= last {
        let Some(pid) = space.read_u64(candidate + pid_offset).ok() else {
            candidate += 16;
            continue;
        };
        if pid > u32::MAX as u64 {
            candidate += 16;
            continue;
        }
        let Some(name) = read_ascii_field(space, candidate + name_field.offset, 15) else {
            candidate += 16;
            continue;
        };
        let mut score = 4u8;
        let flink = space.read_u64(candidate + links_offset).ok();
        let blink = space.read_u64(candidate + links_offset + 8).ok();
        if flink.is_some_and(is_kernel_pointer) && blink.is_some_and(is_kernel_pointer) {
            score += 2;
        } else if flink != Some(0) || blink != Some(0) {
            candidate += 16;
            continue;
        }
        if read_u32(space, candidate + threads_offset)
            .ok()
            .is_some_and(|threads| threads < 0x1_0000)
        {
            score += 1;
        }
        if space
            .read_u64(candidate + pcb_offset + dtb_offset)
            .ok()
            .is_some_and(|dtb| dtb == 0 || dtb & 0xfff == 0)
        {
            score += 1;
        }
        if space
            .read_u64(candidate + create_offset)
            .ok()
            .is_some_and(plausible_filetime)
        {
            score += 1;
        }
        let ppid = ppid_offset
            .and_then(|offset| space.read_u64(candidate + offset).ok())
            .filter(|value| *value <= u32::MAX as u64 && *value != 0);
        let replace = best.as_ref().is_none_or(|current| score > current.score);
        if replace {
            best = Some(EprocessCandidate {
                address: candidate,
                pool_header: header,
                pid,
                ppid,
                name,
                score,
            });
        }
        candidate += 16;
    }
    best.filter(|candidate| candidate.score >= 7)
}

fn find_ethread_in_allocation(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    allocation: &PoolAllocationRecord,
) -> Option<(u64, u64)> {
    let type_size = profile.type_layout("_ETHREAD").ok()?.size;
    let mut best: Option<(u64, u64, u8)> = None;
    for header in allocation.virtual_headers() {
        let start = header.checked_add(16)?;
        let end = header.checked_add(allocation.allocation_size)?;
        let last = end.checked_sub(type_size)?;
        let mut candidate = (start + 0xf) & !0xf;
        while candidate <= last {
            if let Some(record) = parse_thread(space, profile, candidate, None) {
                let score = thread_validation_score(&record);
                if score >= 7 && best.is_none_or(|(_, _, current_score)| score > current_score) {
                    best = Some((candidate, header, score));
                }
            }
            candidate += 16;
        }
    }
    let (ethread, header, _) = best?;
    let physical = allocation.physical_header + ethread.saturating_sub(header);
    Some((ethread, physical))
}

fn parse_thread(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    ethread: u64,
    physical_address: Option<u64>,
) -> Option<ThreadRecord> {
    let tcb_offset = profile.type_field("_ETHREAD", "Tcb").ok()?.offset;
    let kthread = ethread + tcb_offset;
    let cid_offset = profile.type_field("_ETHREAD", "Cid").ok()?.offset;
    let cid = ethread + cid_offset;
    let pid = type_u64(space, profile, "_CLIENT_ID", cid, "UniqueProcess")?;
    let tid = type_u64(space, profile, "_CLIENT_ID", cid, "UniqueThread")?;
    if pid > u32::MAX as u64 || tid == 0 || tid > u32::MAX as u64 {
        return None;
    }
    let owner_eprocess = type_kernel_pointer(space, profile, "_KTHREAD", kthread, "Process");
    let state = type_u8(space, profile, "_KTHREAD", kthread, "State");
    if state.is_some_and(|state| state > 10) {
        return None;
    }
    let start_address = type_u64(space, profile, "_ETHREAD", ethread, "StartAddress")
        .filter(|address| *address != 0);
    if start_address.is_some_and(|address| !is_canonical_address(address)) {
        return None;
    }
    let create_time_raw = type_u64(space, profile, "_ETHREAD", ethread, "CreateTime")
        .filter(|value| plausible_filetime(*value));
    let exit_time_raw = type_u64(space, profile, "_ETHREAD", ethread, "ExitTime")
        .filter(|value| plausible_filetime(*value));
    Some(ThreadRecord {
        ethread,
        physical_address,
        owner_eprocess,
        pid,
        tid,
        process: String::new(),
        start_address,
        win32_start_address: type_u64(space, profile, "_ETHREAD", ethread, "Win32StartAddress")
            .filter(|address| *address != 0),
        start_module: None,
        state,
        state_name: state.map(thread_state_name).unwrap_or("unknown").to_owned(),
        wait_reason: type_u8(space, profile, "_KTHREAD", kthread, "WaitReason"),
        wait_reason_name: type_u8(space, profile, "_KTHREAD", kthread, "WaitReason")
            .map(wait_reason_name)
            .map(str::to_owned),
        suspend_count: type_u8(space, profile, "_KTHREAD", kthread, "SuspendCount"),
        freeze_count: type_u8(space, profile, "_KTHREAD", kthread, "FreezeCount"),
        previous_mode: type_u8(space, profile, "_KTHREAD", kthread, "PreviousMode"),
        priority: type_i8(space, profile, "_KTHREAD", kthread, "Priority"),
        base_priority: type_i8(space, profile, "_KTHREAD", kthread, "BasePriority"),
        teb: type_u64(space, profile, "_KTHREAD", kthread, "Teb").filter(|value| *value != 0),
        kernel_stack: type_u64(space, profile, "_KTHREAD", kthread, "KernelStack")
            .filter(|value| *value != 0),
        create_time: create_time_raw.and_then(filetime_to_rfc3339),
        exit_time: exit_time_raw.and_then(filetime_to_rfc3339),
        hide_from_debugger: type_bitfield_bool(
            space,
            profile,
            "_ETHREAD",
            ethread,
            "HideFromDebugger",
        ),
        system_thread: type_bitfield_bool(space, profile, "_KTHREAD", kthread, "SystemThread"),
        in_process_thread_list: false,
        pool_scanned: false,
        suspicious_reasons: Vec::new(),
    })
}

fn thread_validation_score(thread: &ThreadRecord) -> u8 {
    let mut score = 4;
    if thread.owner_eprocess.is_some() {
        score += 2;
    }
    if thread.start_address.is_some() {
        score += 1;
    }
    if thread.create_time.is_some() {
        score += 1;
    }
    if thread.state.is_some() {
        score += 1;
    }
    score
}

fn attribute_thread(
    thread: &mut ThreadRecord,
    processes: &[ProcessRecord],
    modules: &[super::plugins::DriverRecord],
) {
    let owner = thread
        .owner_eprocess
        .and_then(|owner| processes.iter().find(|process| process.eprocess == owner))
        .or_else(|| processes.iter().find(|process| process.pid == thread.pid));
    if let Some(owner) = owner {
        thread.process = owner.name.clone();
    }
    let module = thread.start_address.and_then(|address| {
        modules.iter().find(|module| {
            address >= module.base && address < module.base.saturating_add(u64::from(module.size))
        })
    });
    thread.start_module = module.map(|module| module.path.clone());
    if thread.start_address.is_some_and(is_kernel_address)
        && thread
            .system_thread
            .unwrap_or(thread.previous_mode == Some(0))
        && module.is_none()
    {
        thread
            .suspicious_reasons
            .push("内核线程起始地址不在已加载模块中".to_owned());
    }
    if thread.win32_start_address.is_some_and(is_kernel_address)
        && !thread.system_thread.unwrap_or(false)
    {
        thread
            .suspicious_reasons
            .push("用户线程具有内核空间 Win32 起始地址".to_owned());
    }
    if thread.hide_from_debugger == Some(true) {
        thread
            .suspicious_reasons
            .push("HideFromDebugger 标志已设置".to_owned());
    }
    if owner.is_none() {
        thread
            .suspicious_reasons
            .push("所属进程不在 PsActiveProcessHead 中".to_owned());
    }
}

fn read_ascii_field(space: &X64AddressSpace<'_>, address: u64, length: usize) -> Option<String> {
    let mut bytes = vec![0u8; length];
    space.read_virtual(address, &mut bytes).ok()?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if end == 0
        || bytes[..end]
            .iter()
            .any(|byte| !byte.is_ascii_graphic() && *byte != b' ')
    {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn plausible_filetime(value: u64) -> bool {
    (116_444_736_000_000_000..=160_000_000_000_000_000).contains(&value)
}

fn field<'a>(
    profile: &'a KernelProfile,
    type_name: &str,
    field_name: &str,
) -> Option<&'a FieldProfile> {
    profile.type_field(type_name, field_name).ok()
}

fn type_u8(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field_name: &str,
) -> Option<u8> {
    let offset = field(profile, type_name, field_name)?.offset;
    let mut bytes = [0u8; 1];
    space.read_virtual(base + offset, &mut bytes).ok()?;
    Some(bytes[0])
}

fn type_i8(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field_name: &str,
) -> Option<i8> {
    type_u8(space, profile, type_name, base, field_name).map(|value| value as i8)
}

fn type_u32(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field_name: &str,
) -> Option<u32> {
    let offset = field(profile, type_name, field_name)?.offset;
    read_u32(space, base + offset).ok()
}

fn type_u64(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field_name: &str,
) -> Option<u64> {
    let offset = field(profile, type_name, field_name)?.offset;
    space.read_u64(base + offset).ok()
}

fn type_kernel_pointer(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field_name: &str,
) -> Option<u64> {
    type_u64(space, profile, type_name, base, field_name).filter(|value| is_kernel_pointer(*value))
}

fn type_bitfield_bool(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field_name: &str,
) -> Option<bool> {
    let field = field(profile, type_name, field_name)?;
    let bit_position = field.bit_position?;
    let bit_length = field.bit_length?;
    let raw = match field.size.unwrap_or(4) {
        1 => u64::from(type_u8(space, profile, type_name, base, field_name)?),
        2 => {
            let mut bytes = [0u8; 2];
            space.read_virtual(base + field.offset, &mut bytes).ok()?;
            u64::from(u16::from_le_bytes(bytes))
        }
        4 => u64::from(read_u32(space, base + field.offset).ok()?),
        _ => space.read_u64(base + field.offset).ok()?,
    };
    let mask = if bit_length == 64 {
        u64::MAX
    } else {
        (1u64 << bit_length) - 1
    };
    Some((raw >> bit_position) & mask != 0)
}

fn thread_state_name(state: u8) -> &'static str {
    match state {
        0 => "已初始化",
        1 => "就绪",
        2 => "运行中",
        3 => "待运行",
        4 => "已终止",
        5 => "等待中",
        6 => "转换中",
        7 => "延迟就绪",
        8 => "门等待",
        9 => "等待进程换入",
        _ => "未知",
    }
}

fn wait_reason_name(reason: u8) -> &'static str {
    const REASONS: [&str; 40] = [
        "执行体",
        "空闲页",
        "页面换入",
        "池分配",
        "延迟执行",
        "已挂起",
        "用户请求",
        "等待执行体",
        "等待空闲页",
        "等待页面换入",
        "等待池分配",
        "等待延迟执行",
        "等待挂起",
        "等待用户请求",
        "等待事件对",
        "等待队列",
        "等待 LPC 接收",
        "等待 LPC 回复",
        "等待虚拟内存",
        "等待页面换出",
        "等待会合",
        "等待键控事件",
        "等待终止",
        "等待进程换入",
        "等待 CPU 速率控制",
        "等待调出栈",
        "等待内核",
        "等待资源",
        "等待推锁",
        "等待互斥体",
        "等待时间片结束",
        "等待调度中断",
        "等待抢占",
        "等待让出执行权",
        "等待快速互斥体",
        "等待受保护互斥体",
        "等待清理",
        "等待线程 ID 警报",
        "等待延迟抢占",
        "等待物理缺页",
    ];
    REASONS.get(reason as usize).copied().unwrap_or("未知")
}

fn read_u32(space: &X64AddressSpace<'_>, address: u64) -> Result<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn is_canonical_address(address: u64) -> bool {
    let upper = address >> 48;
    upper == 0 || upper == 0xffff
}

fn push_limited(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 256 {
        warnings.push(warning);
    }
}

fn process_warnings(warnings: Vec<super::ProcessListWarning>) -> Vec<String> {
    warnings
        .into_iter()
        .map(|warning| format!("[{}] {}", warning.kind, warning.message))
        .collect()
}

/// Resolve the SIDs whose meaning is fixed by the platform rather than by this
/// machine's account database.
///
/// Everything below is decidable from the SID itself. Machine-local accounts
/// (`S-1-5-21-<domain>-<RID>` with RID >= 1000) are deliberately **not**
/// resolved here: their names live in the registry, and inventing one from the
/// token would be a guess. Callers that need those must join the recovered
/// `ProfileList`; the record's `account_source` says which happened.
pub fn well_known_sid_account(sid: &str) -> Option<String> {
    if let Some(rest) = sid.strip_prefix("S-1-16-") {
        return integrity_level_name(rest).map(|name| format!("Mandatory Label\\{name}"));
    }
    if let Some(rid) = sid.strip_prefix("S-1-5-32-") {
        return builtin_alias_name(rid).map(|name| format!("BUILTIN\\{name}"));
    }
    let fixed = match sid {
        "S-1-0-0" => "NULL SID",
        "S-1-1-0" => "Everyone",
        "S-1-2-0" => "LOCAL",
        "S-1-2-1" => "CONSOLE LOGON",
        "S-1-3-0" => "CREATOR OWNER",
        "S-1-3-1" => "CREATOR GROUP",
        "S-1-3-4" => "OWNER RIGHTS",
        "S-1-5-1" => "NT AUTHORITY\\DIALUP",
        "S-1-5-2" => "NT AUTHORITY\\NETWORK",
        "S-1-5-3" => "NT AUTHORITY\\BATCH",
        "S-1-5-4" => "NT AUTHORITY\\INTERACTIVE",
        "S-1-5-6" => "NT AUTHORITY\\SERVICE",
        "S-1-5-7" => "NT AUTHORITY\\ANONYMOUS LOGON",
        "S-1-5-9" => "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS",
        "S-1-5-11" => "NT AUTHORITY\\Authenticated Users",
        "S-1-5-12" => "NT AUTHORITY\\RESTRICTED",
        "S-1-5-13" => "NT AUTHORITY\\TERMINAL SERVER USER",
        "S-1-5-14" => "NT AUTHORITY\\REMOTE INTERACTIVE LOGON",
        "S-1-5-15" => "NT AUTHORITY\\This Organization",
        "S-1-5-17" => "NT AUTHORITY\\IUSR",
        "S-1-5-18" => "NT AUTHORITY\\SYSTEM",
        "S-1-5-19" => "NT AUTHORITY\\LOCAL SERVICE",
        "S-1-5-20" => "NT AUTHORITY\\NETWORK SERVICE",
        "S-1-5-33" => "NT AUTHORITY\\WRITE RESTRICTED",
        "S-1-5-64-10" => "NT AUTHORITY\\NTLM Authentication",
        "S-1-5-64-14" => "NT AUTHORITY\\SChannel Authentication",
        "S-1-5-64-21" => "NT AUTHORITY\\Digest Authentication",
        "S-1-5-65-1" => "NT AUTHORITY\\This Organization Certificate",
        "S-1-5-80-0" => "NT SERVICE\\ALL SERVICES",
        "S-1-5-113" => "NT AUTHORITY\\Local account",
        "S-1-5-114" => "NT AUTHORITY\\Local account and member of Administrators group",
        "S-1-5-1000" => "NT AUTHORITY\\OTHER ORGANIZATION",
        _ => return domain_relative_account(sid),
    };
    Some(fixed.to_owned())
}

fn integrity_level_name(rid: &str) -> Option<&'static str> {
    Some(match rid {
        "0" => "Untrusted Mandatory Level",
        "4096" => "Low Mandatory Level",
        "8192" => "Medium Mandatory Level",
        "8448" => "Medium Plus Mandatory Level",
        "12288" => "High Mandatory Level",
        "16384" => "System Mandatory Level",
        "20480" => "Protected Process Mandatory Level",
        _ => return None,
    })
}

fn builtin_alias_name(rid: &str) -> Option<&'static str> {
    Some(match rid {
        "544" => "Administrators",
        "545" => "Users",
        "546" => "Guests",
        "547" => "Power Users",
        "548" => "Account Operators",
        "549" => "Server Operators",
        "550" => "Print Operators",
        "551" => "Backup Operators",
        "552" => "Replicators",
        "554" => "Pre-Windows 2000 Compatible Access",
        "555" => "Remote Desktop Users",
        "556" => "Network Configuration Operators",
        "558" => "Performance Monitor Users",
        "559" => "Performance Log Users",
        "562" => "Distributed COM Users",
        "568" => "IIS_IUSRS",
        "569" => "Cryptographic Operators",
        "573" => "Event Log Readers",
        "574" => "Certificate Service DCOM Access",
        "578" => "Hyper-V Administrators",
        "580" => "Remote Management Users",
        _ => return None,
    })
}

/// `S-1-5-21-<domain>-<RID>`: only the reserved RIDs below 1000 have a fixed
/// meaning. Anything above that is a machine-local or domain account whose name
/// this function cannot know.
fn domain_relative_account(sid: &str) -> Option<String> {
    let rest = sid.strip_prefix("S-1-5-21-")?;
    let rid = rest.rsplit('-').next()?;
    let name = match rid {
        "500" => "Administrator",
        "501" => "Guest",
        "502" => "KRBTGT",
        "512" => "Domain Admins",
        "513" => "Domain Users",
        "514" => "Domain Guests",
        "515" => "Domain Computers",
        "516" => "Domain Controllers",
        "517" => "Cert Publishers",
        "518" => "Schema Admins",
        "519" => "Enterprise Admins",
        "520" => "Group Policy Creator Owners",
        "553" => "RAS and IAS Servers",
        _ => return None,
    };
    Some(name.to_owned())
}

#[cfg(test)]
mod sid_resolution_tests {
    use super::well_known_sid_account;

    #[test]
    fn fixed_authorities_resolve() {
        assert_eq!(
            well_known_sid_account("S-1-5-18").as_deref(),
            Some(r"NT AUTHORITY\SYSTEM")
        );
        assert_eq!(
            well_known_sid_account("S-1-1-0").as_deref(),
            Some("Everyone")
        );
        assert_eq!(
            well_known_sid_account("S-1-5-32-544").as_deref(),
            Some(r"BUILTIN\Administrators")
        );
        assert_eq!(
            well_known_sid_account("S-1-16-8192").as_deref(),
            Some(r"Mandatory Label\Medium Mandatory Level")
        );
    }

    #[test]
    fn reserved_domain_rids_resolve_but_real_accounts_do_not() {
        let domain = "S-1-5-21-2432978570-3942096864-396630067";
        assert_eq!(
            well_known_sid_account(&format!("{domain}-513")).as_deref(),
            Some("Domain Users")
        );
        assert_eq!(
            well_known_sid_account(&format!("{domain}-500")).as_deref(),
            Some("Administrator")
        );
        // RID 1000+ is a machine-local account. Its name lives in the registry,
        // so the token alone must not produce one.
        assert_eq!(well_known_sid_account(&format!("{domain}-1000")), None);
        assert_eq!(well_known_sid_account(&format!("{domain}-1001")), None);
    }

    #[test]
    fn unknown_shapes_stay_unresolved_instead_of_guessing() {
        assert_eq!(well_known_sid_account("S-1-5-32-9999"), None);
        assert_eq!(well_known_sid_account("S-1-16-1234"), None);
        assert_eq!(well_known_sid_account("S-1-5-5-0-458929"), None);
        assert_eq!(well_known_sid_account("not-a-sid"), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_thread_states_and_wait_reasons() {
        assert_eq!(thread_state_name(2), "运行中");
        assert_eq!(wait_reason_name(12), "等待挂起");
        assert_eq!(wait_reason_name(255), "未知");
    }

    #[test]
    fn computes_windows_service_sid() {
        assert_eq!(
            service_sid("TrustedInstaller"),
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
    }
}
