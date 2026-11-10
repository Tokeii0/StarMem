use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{Result, ensure};
use serde::Serialize;

use super::pe_plugins::read_pe_exports;
use super::plugins::{VadRecord, list_dlls, list_vads};
use super::{ProcessRecord, WindowsKernelContext, list_processes};
use crate::address::{VirtualAddressRegion, VirtualMapping, X64AddressSpace};
use crate::image::MemoryImage;
use crate::profile::KernelProfile;

#[derive(Debug, Clone, Copy)]
pub enum SyscallView {
    Direct,
    Indirect,
}

#[derive(Debug, Serialize)]
pub struct SyscallScanReport {
    pub records: Vec<SyscallScanRecord>,
    pub view: String,
    pub processes_examined: usize,
    pub vads_examined: usize,
    pub bytes_examined: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SyscallScanRecord {
    pub pid: u64,
    pub process: String,
    pub vad: u64,
    pub range: Option<String>,
    pub block_address: u64,
    pub instruction_address: u64,
    pub syscall_number: Option<u32>,
    pub target_address: Option<u64>,
    pub target_range: Option<String>,
    pub evidence: String,
}

#[derive(Debug, Serialize)]
pub struct UnhookedSyscallReport {
    pub records: Vec<UnhookedSyscallRecord>,
    pub processes_examined: usize,
    pub functions_examined: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UnhookedSyscallRecord {
    pub function: String,
    pub implementations: usize,
    pub majority_processes: usize,
    pub outliers: Vec<String>,
    pub anomalous: bool,
}

#[derive(Debug, Serialize)]
pub struct EtwPatchReport {
    pub records: Vec<EtwPatchRecord>,
    pub processes_examined: usize,
    pub functions_examined: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EtwPatchRecord {
    pub pid: u64,
    pub process: String,
    pub dll: String,
    pub function: String,
    pub address: u64,
    pub first_bytes_hex: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SkeletonKeyReport {
    pub records: Vec<SkeletonKeyRecord>,
    pub lsass_processes_examined: usize,
    pub cryptdll_vads_examined: usize,
    pub candidates_examined: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SkeletonKeyRecord {
    pub pid: u64,
    pub process: String,
    pub cryptdll_base: u64,
    pub csystem: u64,
    pub encryption_type: u32,
    pub block_size: u32,
    pub initialize: u64,
    pub encrypt: u64,
    pub decrypt: u64,
    pub finish: u64,
    pub skeleton_key_found: bool,
    pub reasons: Vec<String>,
}

const WATCHED_SYSCALLS: &[&str] = &[
    "NtCreateThread",
    "NtProtectVirtualMemory",
    "NtReadVirtualMemory",
    "NtOpenProcess",
    "NtWriteFile",
    "NtQueryVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtClose",
    "NtCreateFile",
    "NtOpenFile",
    "NtOpenThread",
    "NtWriteVirtualMemory",
    "NtTraceEvent",
    "NtCreateKey",
    "NtCreateSection",
    "NtDeleteKey",
    "NtDeleteValueKey",
    "NtDuplicateObject",
    "NtQueryValueKey",
    "NtSetContextThread",
    "NtSetValueKey",
    "NtSystemDebugControl",
    "NtTerminateProcess",
];

const ETW_FUNCTIONS: &[(&str, &[&str])] = &[
    (
        "ntdll.dll",
        &[
            "EtwEventWrite",
            "EtwEventWriteFull",
            "NtTraceEvent",
            "ZwTraceEvent",
            "NtTraceControl",
            "ZwTraceControl",
            "EtwpEventWriteFull",
        ],
    ),
    ("advapi32.dll", &["EventWrite", "TraceEvent"]),
];

pub fn scan_system_calls(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    view: SyscallView,
    limit: usize,
) -> Result<SyscallScanReport> {
    ensure!(limit > 0, "系统调用结果上限必须大于零");
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut records = Vec::new();
    let mut warnings = processes
        .warnings
        .iter()
        .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
        .collect::<Vec<_>>();
    let mut complete = processes.complete;
    let mut processes_examined = 0usize;
    let mut vads_examined = 0usize;
    let mut bytes_examined = 0u64;
    let mut missing_bytes = 0u64;

    'processes: for process in &processes.processes {
        if process.details.wow64 == Some(true) {
            continue;
        }
        let Some(space) = process_space(image, process) else {
            complete = false;
            continue;
        };
        let vads = match list_vads(image, kernel, profile, process.pid, 1_000_000) {
            Ok(vads) => vads,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("PID {} 的 VAD 遍历失败：{error:#}", process.pid),
                );
                continue;
            }
        };
        let mappings = match space.enumerate_mappings(VirtualAddressRegion::User, 1_000_000) {
            Ok(report) => report.mappings,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("PID {} 的地址映射遍历失败：{error:#}", process.pid),
                );
                continue;
            }
        };
        let legacy_win32_syscalls = process
            .details
            .peb_os_build_number
            .is_some_and(|build| build < 10_240);
        processes_examined += 1;
        for vad in vads.records.iter().filter(|vad| {
            vad.end.saturating_sub(vad.start) < 10_000_000
                && vad.protection_name.contains("EXECUTE")
        }) {
            vads_examined += 1;
            scan_mapped_vad(
                &space,
                vad,
                &mappings,
                64,
                |base, bytes| {
                    bytes_examined += bytes.len() as u64;
                    match view {
                        SyscallView::Direct => scan_direct_chunk(
                            process,
                            vad,
                            base,
                            bytes,
                            legacy_win32_syscalls,
                            &mut records,
                            limit,
                        ),
                        SyscallView::Indirect => scan_indirect_chunk(
                            &space,
                            process,
                            vad,
                            &vads.records,
                            base,
                            bytes,
                            legacy_win32_syscalls,
                            &mut records,
                            limit,
                        ),
                    }
                },
                &mut missing_bytes,
            );
            if records.len() == limit {
                complete = false;
                warnings.push(format!("系统调用结果达到 {limit} 条上限"));
                break 'processes;
            }
        }
    }
    if missing_bytes != 0 {
        complete = false;
        warnings.push(format!(
            "有 {missing_bytes} 个已映射可执行字节不可用，未进行扫描"
        ));
    }
    records.sort_unstable_by_key(|record| (record.pid, record.instruction_address));
    records.dedup_by_key(|record| (record.pid, record.instruction_address));
    Ok(SyscallScanReport {
        records,
        view: match view {
            SyscallView::Direct => "直接",
            SyscallView::Indirect => "间接",
        }
        .to_owned(),
        processes_examined,
        vads_examined,
        bytes_examined,
        missing_bytes,
        complete,
        warnings,
    })
}

fn scan_direct_chunk(
    process: &ProcessRecord,
    vad: &VadRecord,
    base: u64,
    bytes: &[u8],
    legacy_win32_syscalls: bool,
    output: &mut Vec<SyscallScanRecord>,
    limit: usize,
) {
    if is_normal_syscall_module(vad.file.as_deref(), legacy_win32_syscalls) {
        return;
    }
    for index in 0..bytes.len().saturating_sub(1) {
        if output.len() == limit || bytes[index..index + 2] != *b"\x0f\x05" {
            continue;
        }
        let Some((start, syscall_number)) = direct_syscall_stub(bytes, index) else {
            continue;
        };
        let end = (index + 10).min(bytes.len());
        let after = &bytes[index + 2..end];
        if !returns_after_syscall(after) || syscall_number > 0x2000 {
            continue;
        }
        if legacy_win32_syscalls && is_legacy_system_gui_stub(vad.file.as_deref(), syscall_number) {
            continue;
        }
        output.push(SyscallScanRecord {
            pid: process.pid,
            process: process.name.clone(),
            vad: vad.node,
            range: vad.file.clone(),
            block_address: base + start as u64,
            instruction_address: base + index as u64,
            syscall_number: Some(syscall_number),
            target_address: None,
            target_range: None,
            evidence: "在系统调用模块之外发现 mov r10,rcx; mov eax,imm32; syscall; ret".to_owned(),
        });
    }
}

fn direct_syscall_stub(bytes: &[u8], syscall_index: usize) -> Option<(usize, u32)> {
    let start = syscall_index.checked_sub(8)?;
    let prefix = bytes.get(start..syscall_index)?;
    let immediate = if prefix[..4] == *b"\x4c\x8b\xd1\xb8" {
        &prefix[4..8]
    } else if prefix[0] == 0xb8 && prefix[5..8] == *b"\x4c\x8b\xd1" {
        &prefix[1..5]
    } else {
        return None;
    };
    Some((start, u32::from_le_bytes(immediate.try_into().ok()?)))
}

fn returns_after_syscall(bytes: &[u8]) -> bool {
    bytes.iter().copied().take(8).any(|byte| byte == 0xc3)
}

#[allow(clippy::too_many_arguments)]
fn scan_indirect_chunk(
    space: &X64AddressSpace<'_>,
    process: &ProcessRecord,
    vad: &VadRecord,
    all_vads: &[VadRecord],
    base: u64,
    bytes: &[u8],
    legacy_win32_syscalls: bool,
    output: &mut Vec<SyscallScanRecord>,
    limit: usize,
) {
    if is_normal_syscall_module(vad.file.as_deref(), legacy_win32_syscalls) {
        return;
    }
    for index in 0..bytes.len().saturating_sub(5) {
        if output.len() == limit || bytes[index..index + 2] != *b"\xff\x25" {
            continue;
        }
        let displacement = i32::from_le_bytes(bytes[index + 2..index + 6].try_into().unwrap());
        let instruction = base + index as u64;
        let slot = (instruction + 6).wrapping_add_signed(i64::from(displacement));
        let Ok(target) = space.read_u64(slot) else {
            continue;
        };
        let mut syscall = [0u8; 2];
        if space.read_virtual(target, &mut syscall).is_err() || syscall != *b"\x0f\x05" {
            continue;
        }
        let target_vad = all_vads
            .iter()
            .find(|candidate| target >= candidate.start && target <= candidate.end);
        if !is_normal_syscall_module(
            target_vad.and_then(|vad| vad.file.as_deref()),
            legacy_win32_syscalls,
        ) {
            continue;
        }
        let start = index.saturating_sub(32);
        let block = &bytes[start..index];
        if find_subslice(block, b"\x4c\x8b\xd1").is_none()
            || !block.windows(5).any(|window| window[0] == 0xb8)
        {
            continue;
        }
        output.push(SyscallScanRecord {
            pid: process.pid,
            process: process.name.clone(),
            vad: vad.node,
            range: vad.file.clone(),
            block_address: base + start as u64,
            instruction_address: instruction,
            syscall_number: block
                .windows(5)
                .find(|window| window[0] == 0xb8)
                .map(|window| u32::from_le_bytes(window[1..5].try_into().unwrap())),
            target_address: Some(target),
            target_range: target_vad.and_then(|vad| vad.file.clone()),
            evidence: "RIP 相对间接跳转最终进入正常系统调用模块".to_owned(),
        });
    }
}

pub fn compare_ntdll_syscalls(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<UnhookedSyscallReport> {
    ensure!(limit > 0, "系统调用桩对比结果上限必须大于零");
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let dlls = list_dlls(image, kernel, profile, None, 4096)?;
    let process_map = processes
        .processes
        .iter()
        .map(|process| (process.pid, process))
        .collect::<HashMap<_, _>>();
    let mut groups = BTreeMap::<String, HashMap<Vec<u8>, Vec<String>>>::new();
    let mut warnings = dlls.warnings;
    let mut complete = processes.complete && dlls.complete;
    let mut examined_pids = HashSet::new();
    for dll in dlls.records.iter().filter(|dll| {
        dll.name.eq_ignore_ascii_case("ntdll.dll")
            || dll.path.to_ascii_lowercase().ends_with("\\ntdll.dll")
    }) {
        let Some(process) = process_map.get(&dll.pid).copied() else {
            continue;
        };
        let Some(space) = process_space(image, process) else {
            complete = false;
            continue;
        };
        let exports = match read_pe_exports(&space, dll.base) {
            Ok(exports) => exports,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("PID {} 的 ntdll.dll 导出表解析失败：{error:#}", dll.pid),
                );
                continue;
            }
        };
        examined_pids.insert(dll.pid);
        for export in exports {
            let Some(name) = export.name else {
                continue;
            };
            if !WATCHED_SYSCALLS
                .iter()
                .any(|wanted| name.eq_ignore_ascii_case(wanted))
            {
                continue;
            }
            let Some(address) = export.address else {
                continue;
            };
            let mut bytes = vec![0u8; 32];
            if space.read_virtual(address, &mut bytes).is_err() {
                complete = false;
                continue;
            }
            groups
                .entry(name)
                .or_default()
                .entry(bytes)
                .or_default()
                .push(format!("{}:{}", dll.pid, dll.process));
        }
    }
    let mut records = Vec::new();
    for (function, implementations) in groups {
        if records.len() == limit {
            complete = false;
            warnings.push(format!("系统调用桩对比结果达到 {limit} 条上限"));
            break;
        }
        let mut grouped = implementations.into_values().collect::<Vec<_>>();
        grouped.sort_unstable_by_key(|processes| std::cmp::Reverse(processes.len()));
        let implementation_count = grouped.len();
        let majority_processes = grouped.first().map_or(0, Vec::len);
        let outliers = grouped.into_iter().skip(1).flatten().collect::<Vec<_>>();
        records.push(UnhookedSyscallRecord {
            function,
            implementations: implementation_count,
            majority_processes,
            anomalous: !outliers.is_empty(),
            outliers,
        });
    }
    let functions_examined = records.len();
    Ok(UnhookedSyscallReport {
        records,
        processes_examined: examined_pids.len(),
        functions_examined,
        complete,
        warnings,
    })
}

pub fn detect_etw_patches(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<EtwPatchReport> {
    ensure!(limit > 0, "ETW 补丁检测结果上限必须大于零");
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let dlls = list_dlls(image, kernel, profile, None, 4096)?;
    let process_map = processes
        .processes
        .iter()
        .map(|process| (process.pid, process))
        .collect::<HashMap<_, _>>();
    let mut samples = BTreeMap::<(String, String), Vec<(Vec<u8>, u64, String, u64)>>::new();
    let mut warnings = dlls.warnings;
    let mut complete = processes.complete && dlls.complete;
    let mut examined_pids = HashSet::new();
    for dll in &dlls.records {
        let Some((canonical_dll, wanted)) = ETW_FUNCTIONS.iter().find(|(name, _)| {
            dll.name.eq_ignore_ascii_case(name)
                || dll
                    .path
                    .to_ascii_lowercase()
                    .ends_with(&format!("\\{name}"))
        }) else {
            continue;
        };
        let Some(process) = process_map.get(&dll.pid).copied() else {
            continue;
        };
        if process.details.wow64 == Some(true) {
            continue;
        }
        let Some(space) = process_space(image, process) else {
            complete = false;
            continue;
        };
        let exports = match read_pe_exports(&space, dll.base) {
            Ok(exports) => exports,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("PID {} 的 {} 导出表解析失败：{error:#}", dll.pid, dll.name),
                );
                continue;
            }
        };
        examined_pids.insert(dll.pid);
        for export in exports {
            let Some(name) = export.name else {
                continue;
            };
            if !wanted
                .iter()
                .any(|wanted| name.eq_ignore_ascii_case(wanted))
            {
                continue;
            }
            let Some(address) = export.address else {
                continue;
            };
            let mut bytes = vec![0u8; 16];
            if space.read_virtual(address, &mut bytes).is_err() {
                complete = false;
                continue;
            }
            samples
                .entry(((*canonical_dll).to_owned(), name))
                .or_default()
                .push((bytes, dll.pid, dll.process.clone(), address));
        }
    }
    let functions_examined = samples.len();
    let mut records = Vec::new();
    for ((dll, function), function_samples) in samples {
        let mut counts = HashMap::<Vec<u8>, usize>::new();
        for (bytes, _, _, _) in &function_samples {
            *counts.entry(bytes.clone()).or_default() += 1;
        }
        let majority = counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(bytes, _)| bytes);
        for (bytes, pid, process, address) in function_samples {
            let mut reasons = Vec::new();
            match bytes.first().copied() {
                Some(0xc3) => reasons.push("函数以 RET 指令开头".to_owned()),
                Some(0xe9 | 0xeb) => reasons.push("函数以 JMP 指令开头".to_owned()),
                _ => {}
            }
            if majority.as_ref().is_some_and(|majority| *majority != bytes) {
                reasons.push("函数实现与多数进程中的实现不一致".to_owned());
            }
            if reasons.is_empty() {
                continue;
            }
            if records.len() == limit {
                complete = false;
                warnings.push(format!("ETW 补丁检测结果达到 {limit} 条上限"));
                break;
            }
            records.push(EtwPatchRecord {
                pid,
                process,
                dll: dll.clone(),
                function: function.clone(),
                address,
                first_bytes_hex: hex::encode_upper(bytes),
                reasons,
            });
        }
    }
    Ok(EtwPatchReport {
        records,
        processes_examined: examined_pids.len(),
        functions_examined,
        complete,
        warnings,
    })
}

pub fn skeleton_key_check(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<SkeletonKeyReport> {
    ensure!(limit > 0, "Skeleton Key 检测结果上限必须大于零");
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut records = Vec::new();
    let mut warnings = processes
        .warnings
        .iter()
        .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
        .collect::<Vec<_>>();
    let mut complete = processes.complete;
    let mut lsass_processes_examined = 0usize;
    let mut cryptdll_vads_examined = 0usize;
    let mut candidates_examined = 0usize;
    for process in processes
        .processes
        .iter()
        .filter(|process| process.name.eq_ignore_ascii_case("lsass.exe"))
    {
        lsass_processes_examined += 1;
        let Some(space) = process_space(image, process) else {
            complete = false;
            continue;
        };
        let vads = match list_vads(image, kernel, profile, process.pid, 1_000_000) {
            Ok(vads) => vads,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("PID {} 的 VAD 遍历失败：{error:#}", process.pid),
                );
                continue;
            }
        };
        let mappings = space
            .enumerate_mappings(VirtualAddressRegion::User, 1_000_000)?
            .mappings;
        for vad in vads.records.iter().filter(|vad| {
            vad.file
                .as_deref()
                .is_some_and(|path| path.to_ascii_lowercase().ends_with("\\cryptdll.dll"))
        }) {
            cryptdll_vads_examined += 1;
            let mut hits = HashSet::new();
            let mut missing = 0u64;
            scan_mapped_vad(
                &space,
                vad,
                &mappings,
                7,
                |base, bytes| {
                    for index in 0..bytes.len().saturating_sub(7) {
                        if bytes[index..index + 8] == *b"\x17\0\0\0\x01\0\0\0" {
                            hits.insert(base + index as u64);
                        }
                    }
                },
                &mut missing,
            );
            if missing != 0 {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!(
                        "PID {} 的 cryptdll VAD 中有 {missing} 个已映射字节不可用",
                        process.pid
                    ),
                );
            }
            for candidate in hits {
                candidates_examined += 1;
                let Some(block_size) = read_process_u32(&space, candidate + 4) else {
                    continue;
                };
                let (Ok(initialize), Ok(encrypt), Ok(decrypt), Ok(finish)) = (
                    space.read_u64(candidate + 40),
                    space.read_u64(candidate + 48),
                    space.read_u64(candidate + 56),
                    space.read_u64(candidate + 64),
                ) else {
                    complete = false;
                    continue;
                };
                let in_cryptdll = |address| address >= vad.start && address <= vad.end;
                if !in_cryptdll(encrypt) || !in_cryptdll(finish) {
                    continue;
                }
                let mut reasons = Vec::new();
                if !in_cryptdll(initialize) {
                    reasons.push("RC4-HMAC Initialize 指向 cryptdll.dll 之外".to_owned());
                }
                if !in_cryptdll(decrypt) {
                    reasons.push("RC4-HMAC Decrypt 指向 cryptdll.dll 之外".to_owned());
                }
                records.push(SkeletonKeyRecord {
                    pid: process.pid,
                    process: process.name.clone(),
                    cryptdll_base: vad.start,
                    csystem: candidate,
                    encryption_type: 0x17,
                    block_size,
                    initialize,
                    encrypt,
                    decrypt,
                    finish,
                    skeleton_key_found: !reasons.is_empty(),
                    reasons,
                });
                if records.len() == limit {
                    complete = false;
                    warnings.push(format!("Skeleton Key 检测结果达到 {limit} 条上限"));
                    break;
                }
            }
        }
    }
    if cryptdll_vads_examined == 0 {
        complete = false;
        warnings.push("没有恢复出可读的 lsass.exe cryptdll.dll VAD".to_owned());
    }
    Ok(SkeletonKeyReport {
        records,
        lsass_processes_examined,
        cryptdll_vads_examined,
        candidates_examined,
        complete,
        warnings,
    })
}

fn scan_mapped_vad(
    space: &X64AddressSpace<'_>,
    vad: &VadRecord,
    mappings: &[VirtualMapping],
    overlap: usize,
    mut callback: impl FnMut(u64, &[u8]),
    missing: &mut u64,
) {
    let mut tail = Vec::new();
    let mut previous_end = None;
    for mapping in mappings {
        if mapping.virtual_end <= vad.start {
            continue;
        }
        if mapping.virtual_start > vad.end {
            break;
        }
        let mut address = mapping.virtual_start.max(vad.start);
        let end = mapping.virtual_end.min(vad.end.saturating_add(1));
        while address < end {
            let count = (end - address).min(0x1000 - (address & 0xfff)) as usize;
            let mut page = vec![0u8; count];
            if space.read_virtual(address, &mut page).is_ok() {
                if previous_end == Some(address) && !tail.is_empty() {
                    let mut combined = tail.clone();
                    combined.extend_from_slice(&page);
                    callback(address - tail.len() as u64, &combined);
                } else {
                    callback(address, &page);
                }
                let retained = overlap.min(page.len());
                tail.clear();
                tail.extend_from_slice(&page[page.len() - retained..]);
                previous_end = Some(address + count as u64);
            } else {
                *missing += count as u64;
                tail.clear();
                previous_end = None;
            }
            address += count as u64;
        }
    }
}

fn process_space<'a>(
    image: &'a MemoryImage,
    process: &ProcessRecord,
) -> Option<X64AddressSpace<'a>> {
    process
        .details
        .user_directory_table_base
        .or(process.details.directory_table_base)
        .and_then(|dtb| X64AddressSpace::new(image, dtb).ok())
}

fn is_normal_syscall_module(path: Option<&str>, legacy_win32_syscalls: bool) -> bool {
    path.is_some_and(|path| {
        let path = path.to_ascii_lowercase();
        path.ends_with("\\ntdll.dll")
            || path.ends_with("/ntdll.dll")
            || path.ends_with("\\win32u.dll")
            || path.ends_with("/win32u.dll")
            || path.ends_with("\\wow64win.dll")
            || path.ends_with("/wow64win.dll")
            || path.ends_with("\\wow64.dll")
            || path.ends_with("/wow64.dll")
            || path.ends_with("\\wow64cpu.dll")
            || path.ends_with("/wow64cpu.dll")
            || legacy_win32_syscalls
                && (path.ends_with("\\user32.dll")
                    || path.ends_with("/user32.dll")
                    || path.ends_with("\\gdi32.dll")
                    || path.ends_with("/gdi32.dll")
                    || path.ends_with("\\winsrv.dll")
                    || path.ends_with("/winsrv.dll"))
    })
}

fn is_legacy_system_gui_stub(path: Option<&str>, syscall_number: u32) -> bool {
    if !(0x1000..0x2000).contains(&syscall_number) {
        return false;
    }
    path.is_some_and(|path| {
        let path = path.replace('/', "\\").to_ascii_lowercase();
        (path.ends_with(".dll") || path.ends_with(".exe"))
            && (path.starts_with("\\windows\\system32\\")
                || path.contains("\\windows\\system32\\")
                || path.starts_with("\\systemroot\\system32\\"))
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read_process_u32(space: &X64AddressSpace<'_>, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 256 {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_normal_syscall_modules_case_insensitively() {
        assert!(is_normal_syscall_module(
            Some("C:\\Windows\\System32\\NTDLL.DLL"),
            false
        ));
        assert!(is_normal_syscall_module(
            Some("C:\\Windows\\System32\\USER32.DLL"),
            true
        ));
        assert!(is_normal_syscall_module(
            Some("C:\\Windows\\System32\\WINSRV.DLL"),
            true
        ));
        assert!(!is_normal_syscall_module(
            Some("C:\\Windows\\System32\\USER32.DLL"),
            false
        ));
        assert!(!is_normal_syscall_module(
            Some("C:\\Temp\\implant.dll"),
            true
        ));
        assert!(is_legacy_system_gui_stub(
            Some("\\Windows\\System32\\imm32.dll"),
            0x1001
        ));
        assert!(is_legacy_system_gui_stub(
            Some("\\Windows\\System32\\conhost.exe"),
            0x1001
        ));
        assert!(!is_legacy_system_gui_stub(
            Some("C:\\Temp\\implant.dll"),
            0x1001
        ));
        assert!(!is_legacy_system_gui_stub(
            Some("\\Windows\\System32\\kernel32.dll"),
            0x55
        ));

        let canonical = b"\x4c\x8b\xd1\xb8\x55\x00\x00\x00\x0f\x05\xc3";
        assert_eq!(direct_syscall_stub(canonical, 8), Some((0, 0x55)));
        assert!(returns_after_syscall(&canonical[10..]));

        let unrelated = b"\x4c\x8b\xd1\x90\x90\x90\xb8\x01\x00\x00\x00\x90\x0f\x05\xc3";
        assert_eq!(direct_syscall_stub(unrelated, 12), None);
    }
}
