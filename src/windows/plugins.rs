use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, ensure};
use rayon::prelude::*;
use serde::Serialize;

use super::{WindowsKernelContext, list_processes};
use crate::address::X64AddressSpace;
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::scan::scan_exact_4_cancellable;
use crate::windows::system_plugins::{list_big_pools, scan_pool_allocations};

#[derive(Debug, Serialize)]
pub struct PluginReport<T> {
    pub records: Vec<T>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriverRecord {
    pub entry: u64,
    pub base: u64,
    pub size: u32,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct DllRecord {
    pub pid: u64,
    pub process: String,
    pub entry: u64,
    pub base: u64,
    pub size: u32,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct VadRecord {
    pub pid: u64,
    pub process: String,
    pub node: u64,
    pub start: u64,
    pub end: u64,
    pub protection: u8,
    pub protection_name: String,
    pub vad_type: u8,
    pub private_memory: bool,
    pub file: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HiveRecord {
    pub cmhive: u64,
    pub file_path: String,
    pub user_name: String,
    pub root_path: String,
}

#[derive(Debug, Serialize)]
pub struct HiveScanRecord {
    pub cmhive: u64,
    pub allocation_size: u64,
    pub hhive_signature: u32,
    pub file_path: Option<String>,
    pub user_name: Option<String>,
    pub root_path: Option<String>,
    pub active_list: bool,
}

#[derive(Debug, Serialize)]
pub struct GetCellRoutineReport {
    pub records: Vec<GetCellRoutineRecord>,
    pub hives_examined: usize,
    pub suspicious_count: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct GetCellRoutineRecord {
    pub cmhive: u64,
    pub hive_name: String,
    pub handler: u64,
    pub module: Option<String>,
    pub expected_kernel: bool,
    pub suspicious: bool,
}

#[derive(Debug, Serialize)]
pub struct HandleRecord {
    pub pid: u64,
    pub process: String,
    pub handle: u32,
    pub entry: u64,
    pub object_header: u64,
    pub object: u64,
    pub type_index: Option<u8>,
    pub object_type: String,
    pub object_type_source: String,
    pub granted_access: u32,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ObjectHandleOwner {
    pub pid: u64,
    pub process: String,
    pub user_name: Option<String>,
    pub user_sid: Option<String>,
    pub process_create_time: Option<String>,
    pub handle: u32,
    pub entry: u64,
    pub object_header: u64,
    pub object: u64,
    pub granted_access: u32,
}

#[derive(Debug, Serialize)]
pub struct ObjectHandleOwnerReport {
    pub records: Vec<ObjectHandleOwner>,
    pub complete: bool,
    pub processes_examined: usize,
    pub handle_entries_examined: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NetworkRecord {
    pub physical_address: u64,
    pub pool_tag: String,
    pub protocol: String,
    pub address_family: u16,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: Option<u16>,
    pub state: Option<String>,
    pub pid: u64,
    pub process: String,
    pub owner_offset: Option<u64>,
    pub owner_resolution: String,
}

pub fn list_drivers(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<PluginReport<DriverRecord>> {
    ensure!(limit > 0, "驱动结果上限必须大于零");
    let space = kernel.x64_address_space(image)?;
    let module_field = |field_name: &str, stable_x64_offset: u64| {
        profile
            .type_field("_KLDR_DATA_TABLE_ENTRY", field_name)
            .or_else(|_| profile.type_field("_LDR_DATA_TABLE_ENTRY", field_name))
            .map(|field| field.offset)
            .unwrap_or(stable_x64_offset)
    };
    // Older kernels call this structure _LDR_DATA_TABLE_ENTRY and some public
    // PDBs omit both type records. These bootstrap fields have retained their
    // x64 offsets; every parsed entry is still checked through its pointers and
    // UNICODE_STRING descriptors before it is emitted.
    let links = module_field("InLoadOrderLinks", 0x00);
    let dll_base = module_field("DllBase", 0x30);
    let size = module_field("SizeOfImage", 0x40);
    let full_name = module_field("FullDllName", 0x48);
    let base_name = module_field("BaseDllName", 0x58);
    let head = kernel.ps_loaded_module_list;
    let mut link = space.read_u64(head)?;
    let mut visited = HashSet::new();
    let mut records = Vec::new();
    let mut warnings = Vec::new();

    while link != head && records.len() < limit {
        if !visited.insert(link) {
            warnings.push(format!("已加载模块链表在 {link:#x} 处形成循环"));
            break;
        }
        let entry = match link.checked_sub(links) {
            Some(entry) => entry,
            None => {
                warnings.push(format!("模块链表指针 {link:#x} 无效"));
                break;
            }
        };
        let parsed = (|| -> Result<DriverRecord> {
            Ok(DriverRecord {
                entry,
                base: space.read_u64(entry + dll_base)?,
                size: read_u32(&space, entry + size)?,
                name: read_unicode_string(&space, entry + base_name, 4096)?,
                path: read_unicode_string(&space, entry + full_name, 32 * 1024)?,
            })
        })();
        match parsed {
            Ok(record) => records.push(record),
            Err(error) => {
                warnings.push(format!("无法解析模块条目 {entry:#x}：{error:#}"));
                break;
            }
        }
        link = match space.read_u64(link) {
            Ok(next) => next,
            Err(error) => {
                warnings.push(format!("无法继续遍历模块条目 {link:#x}：{error:#}"));
                break;
            }
        };
    }
    let complete = link == head;
    Ok(PluginReport {
        records,
        complete,
        warnings,
    })
}

pub fn list_dlls(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid_filter: Option<u64>,
    per_process_limit: usize,
) -> Result<PluginReport<DllRecord>> {
    ensure!(per_process_limit > 0, "DLL 结果上限必须大于零");
    let processes = list_processes(image, kernel, profile, 65536)?;
    let mut records = Vec::new();
    let mut warnings: Vec<String> = processes
        .warnings
        .iter()
        .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
        .collect();
    for process in processes
        .processes
        .iter()
        .filter(|p| pid_filter.is_none_or(|pid| p.pid == pid))
    {
        let report = list_process_dlls(image, kernel, profile, process, per_process_limit)?;
        records.extend(report.records);
        warnings.extend(report.warnings);
    }
    if let Some(pid) = pid_filter
        && !processes.processes.iter().any(|process| process.pid == pid)
    {
        warnings.push(format!("PsActiveProcessHead 中没有 PID {pid}"));
    }
    Ok(PluginReport {
        records,
        complete: processes.complete && warnings.is_empty(),
        warnings,
    })
}

/// Reuses the same loader walker for an already identified guest process.
/// A live caller validates EPROCESS / PID / CreateTime before and after use.
pub(crate) fn list_process_dlls(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    process: &super::ProcessRecord,
    limit: usize,
) -> Result<PluginReport<DllRecord>> {
    ensure!(limit > 0, "DLL 结果上限必须大于零");
    let kernel_space = kernel.x64_address_space(image)?;
    let pcb = profile.field("Pcb")?.offset;
    let peb = profile.field("Peb")?.offset;
    let directory_table_base = profile
        .type_field("_KPROCESS", "DirectoryTableBase")?
        .offset;
    let user_directory_table_base = profile
        .type_layout("_KPROCESS")?
        .fields
        .get("UserDirectoryTableBase")
        .map(|field| field.offset);
    let mut warnings = Vec::new();
    let result = (|| -> Result<Vec<DllRecord>> {
        let peb_address = kernel_space.read_u64(process.eprocess + peb)?;
        if peb_address == 0 {
            if image.is_live() {
                warnings.push(format!("PID {}：没有可读取的用户态 PEB", process.pid));
            }
            return Ok(Vec::new());
        }
        let kernel_dtb = kernel_space
            .read_u64(process.eprocess + pcb + directory_table_base)
            .unwrap_or(0);
        let user_dtb = user_directory_table_base
            .and_then(|offset| kernel_space.read_u64(process.eprocess + pcb + offset).ok())
            .unwrap_or(0);
        let mut selected_dtb = [user_dtb, kernel_dtb]
            .into_iter()
            .filter(|dtb| *dtb != 0)
            .find(|dtb| {
                X64AddressSpace::new(image, *dtb)
                    .is_ok_and(|space| valid_process_peb(&space, peb_address))
            });
        // A live read must not guess another process's address space by scanning
        // all RAM when the selected EPROCESS no longer maps its PEB.
        if selected_dtb.is_none() && !image.is_live() {
            selected_dtb = discover_process_dtb(image, peb_address);
        }
        let selected_dtb =
            selected_dtb.with_context(|| format!("进程页表均未映射 PEB {peb_address:#x}"))?;
        let space = X64AddressSpace::new(image, selected_dtb)?;
        let (records, warning) =
            walk_process_dlls(&space, process.pid, &process.name, peb_address, limit)?;
        warnings.extend(warning);
        if image.is_live() && process.details.wow64 == Some(true) {
            warnings.push("仅枚举原生 x64 加载器；WOW64 的 32 位模块尚未覆盖".into());
        }
        Ok(records)
    })();
    let records = match result {
        Ok(records) => records,
        Err(error) => {
            warnings.push(format!("PID {}：{error:#}", process.pid));
            Vec::new()
        }
    };
    Ok(PluginReport {
        complete: warnings.is_empty(),
        records,
        warnings,
    })
}

pub(crate) fn walk_process_dlls(
    space: &X64AddressSpace<'_>,
    pid: u64,
    process: &str,
    peb: u64,
    limit: usize,
) -> Result<(Vec<DllRecord>, Option<String>)> {
    const PEB_LDR: u64 = 0x18;
    const LDR_IN_LOAD_ORDER: u64 = 0x10;
    const LDR_DLL_BASE: u64 = 0x30;
    const LDR_SIZE_OF_IMAGE: u64 = 0x40;
    const LDR_FULL_DLL_NAME: u64 = 0x48;
    const LDR_BASE_DLL_NAME: u64 = 0x58;

    let ldr = space.read_u64(peb + PEB_LDR)?;
    ensure!(ldr != 0, "PEB 中没有加载器数据");
    let head = ldr + LDR_IN_LOAD_ORDER;
    let mut link = space.read_u64(head)?;
    let mut visited = HashSet::new();
    let mut records = Vec::new();
    let mut warning = None;
    while link != head && records.len() < limit {
        if !visited.insert(link) {
            warning = Some(format!("PID {pid}：加载器链表在 {link:#x} 处形成循环"));
            break;
        }
        let entry = link;
        records.push(DllRecord {
            pid,
            process: process.to_owned(),
            entry,
            base: space.read_u64(entry + LDR_DLL_BASE)?,
            size: read_u32(space, entry + LDR_SIZE_OF_IMAGE)?,
            name: read_unicode_string(space, entry + LDR_BASE_DLL_NAME, 4096)?,
            path: read_unicode_string(space, entry + LDR_FULL_DLL_NAME, 32 * 1024)?,
        });
        link = space.read_u64(link)?;
    }
    if records.len() == limit && link != head {
        warning = Some(format!("PID {pid}：DLL 结果达到 {limit} 条上限"));
    }
    Ok((records, warning))
}

fn valid_process_peb(space: &X64AddressSpace<'_>, peb: u64) -> bool {
    if peb == 0 || peb >> 48 != 0 {
        return false;
    }
    let Some(ldr) = space.read_u64(peb + 0x18).ok() else {
        return false;
    };
    ldr != 0 && ldr >> 48 == 0 && space.translate(ldr).is_ok() && space.read_u64(ldr + 0x10).is_ok()
}

fn discover_process_dtb(image: &MemoryImage, peb: u64) -> Option<u64> {
    let pml4_index = (peb >> 39) & 0x1ff;
    let pages: Vec<u64> = image
        .spans()
        .iter()
        .flat_map(|span| {
            let first = (span.start + 0xfff) & !0xfff;
            let count = span.end().saturating_sub(first) / 0x1000;
            (0..count).map(move |index| first + index * 0x1000)
        })
        .collect();
    let mut candidates: Vec<u64> = pages
        .par_iter()
        .filter_map(|page| {
            let pml4e = image.read_u64_physical(*page + pml4_index * 8).ok()?;
            if pml4e & 1 == 0 || !image.contains_physical(pml4e & 0x000f_ffff_ffff_f000) {
                return None;
            }
            let space = X64AddressSpace::new(image, *page).ok()?;
            valid_process_peb(&space, peb).then_some(*page)
        })
        .collect();
    candidates.sort_unstable();
    candidates.into_iter().next()
}

#[allow(clippy::too_many_arguments)]
fn discover_vad_root(
    space: &X64AddressSpace<'_>,
    eprocess: u64,
    eprocess_size: u64,
    reported_root: u64,
    left_offset: u64,
    right_offset: u64,
    starting_vpn_offset: u64,
    ending_vpn_offset: u64,
    starting_high_offset: Option<u64>,
    ending_high_offset: Option<u64>,
) -> Option<u64> {
    let score = |root| {
        score_vad_tree(
            space,
            root,
            left_offset,
            right_offset,
            starting_vpn_offset,
            ending_vpn_offset,
            starting_high_offset,
            ending_high_offset,
        )
    };
    let mut best = (score(reported_root), reported_root);
    for offset in (0x300..eprocess_size.min(0x1000)).step_by(8) {
        let Ok(candidate) =
            checked_vad_field(eprocess, offset).and_then(|address| space.read_u64(address))
        else {
            continue;
        };
        if !is_kernel_pointer(candidate) {
            continue;
        }
        let candidate_score = score(candidate & !7);
        if candidate_score > best.0 {
            best = (candidate_score, candidate & !7);
        }
    }
    (best.0 >= 3).then_some(best.1)
}

#[allow(clippy::too_many_arguments)]
fn score_vad_tree(
    space: &X64AddressSpace<'_>,
    root: u64,
    left_offset: u64,
    right_offset: u64,
    starting_vpn_offset: u64,
    ending_vpn_offset: u64,
    starting_high_offset: Option<u64>,
    ending_high_offset: Option<u64>,
) -> usize {
    const MAX_USER_VPN: u64 = 0x7fff_fffff;
    const SCORE_LIMIT: usize = 32;
    if !is_kernel_pointer(root) {
        return 0;
    }
    let mut pending = vec![(root, 0u64, MAX_USER_VPN)];
    let mut visited = HashSet::new();
    let mut score = 0usize;
    while let Some((node, minimum, maximum)) = pending.pop() {
        if score == SCORE_LIMIT || !visited.insert(node) {
            continue;
        }
        let Ok(start) = read_vpn(space, node, starting_vpn_offset, starting_high_offset) else {
            return score;
        };
        let Ok(end) = read_vpn(space, node, ending_vpn_offset, ending_high_offset) else {
            return score;
        };
        if start < minimum || start > maximum || end < start || end > MAX_USER_VPN {
            return score;
        }
        score += 1;
        for (child_offset, child_minimum, child_maximum) in [
            (left_offset, minimum, start.saturating_sub(1)),
            (right_offset, start.saturating_add(1), maximum),
        ] {
            let Ok(child) =
                checked_vad_field(node, child_offset).and_then(|address| space.read_u64(address))
            else {
                return score;
            };
            let child = child & !7;
            if child == 0 {
                continue;
            }
            if !is_kernel_pointer(child) || child_minimum > child_maximum {
                return score;
            }
            pending.push((child, child_minimum, child_maximum));
        }
    }
    score
}

fn read_vpn(
    space: &X64AddressSpace<'_>,
    node: u64,
    low_offset: u64,
    high_offset: Option<u64>,
) -> Result<u64> {
    let low = u64::from(read_u32(space, checked_vad_field(node, low_offset)?)?);
    // A missing high byte is unknown, not zero: guessing it changes the range.
    let high = match high_offset {
        Some(offset) => u64::from(read_u8(space, checked_vad_field(node, offset)?)?) << 32,
        None => 0,
    };
    Ok(low | high)
}

pub fn list_vads(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid: u64,
    limit: usize,
) -> Result<PluginReport<VadRecord>> {
    list_vads_cancellable(
        image,
        kernel,
        profile,
        pid,
        limit,
        &CancellationToken::new(),
    )
}

pub fn list_vads_cancellable(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid: u64,
    limit: usize,
    cancellation: &CancellationToken,
) -> Result<PluginReport<VadRecord>> {
    ensure!(limit > 0, "VAD 结果上限必须大于零");
    cancellation.check_cancelled()?;
    let space = kernel.x64_address_space(image)?;
    let processes = list_processes(image, kernel, profile, 65536)?;
    cancellation.check_cancelled()?;
    let process = processes
        .processes
        .iter()
        .find(|process| process.pid == pid)
        .with_context(|| format!("PsActiveProcessHead 中没有 PID {pid}"))?;
    let vad_root = profile.field("VadRoot")?.offset;
    let modern_vad_node = profile
        .type_layout("_MMVAD_SHORT")?
        .fields
        .get("VadNode")
        .map(|field| field.offset);
    let (root_offset, left, right, node_offset) = if let Some(node_offset) = modern_vad_node {
        (
            profile.type_field("_RTL_AVL_TREE", "Root")?.offset,
            profile.type_field("_RTL_BALANCED_NODE", "Left")?.offset,
            profile.type_field("_RTL_BALANCED_NODE", "Right")?.offset,
            node_offset,
        )
    } else {
        // Windows 7/8 embeds an _MM_AVL_TABLE sentinel in EPROCESS.VadRoot.
        // Its real root is BalancedRoot.RightChild and VADs contain the legacy
        // child links directly instead of an embedded _RTL_BALANCED_NODE.
        let balanced_root = profile
            .type_field("_MM_AVL_TABLE", "BalancedRoot")
            .map(|field| field.offset)
            .unwrap_or(0);
        let root_child = profile
            .type_field("_MMADDRESS_NODE", "RightChild")
            .or_else(|_| profile.type_field("_MMVAD_SHORT", "RightChild"))?
            .offset;
        (
            balanced_root
                .checked_add(root_child)
                .context("VAD 根字段偏移溢出")?,
            profile.type_field("_MMVAD_SHORT", "LeftChild")?.offset,
            profile.type_field("_MMVAD_SHORT", "RightChild")?.offset,
            0,
        )
    };
    let starting_vpn = profile.type_field("_MMVAD_SHORT", "StartingVpn")?.offset;
    let ending_vpn = profile.type_field("_MMVAD_SHORT", "EndingVpn")?.offset;
    let starting_high = profile
        .type_field("_MMVAD_SHORT", "StartingVpnHigh")
        .ok()
        .map(|field| field.offset);
    let ending_high = profile
        .type_field("_MMVAD_SHORT", "EndingVpnHigh")
        .ok()
        .map(|field| field.offset);
    let flags_offset = profile.type_field("_MMVAD_SHORT", "u")?.offset;
    let file_object_offset = profile
        .type_field("_MMVAD", "FileObject")
        .ok()
        .map(|field| field.offset);
    let subsection_path = profile
        .type_field("_MMVAD", "Subsection")
        .ok()
        .and_then(|subsection| {
            let control_area = profile.type_field("_SUBSECTION", "ControlArea").ok()?;
            let file_pointer = profile.type_field("_CONTROL_AREA", "FilePointer").ok()?;
            Some((subsection.offset, control_area.offset, file_pointer.offset))
        });
    let file_name_offset = profile.type_field("_FILE_OBJECT", "FileName")?.offset;
    let (vad_type_position, vad_type_length) = vad_flag_layout(profile, "VadType", 4, 3);
    let (protection_position, protection_length) = vad_flag_layout(profile, "Protection", 7, 5);
    let (private_position, private_length) = vad_flag_layout(profile, "PrivateMemory", 20, 1);
    let root_field = checked_vad_field(process.eprocess, vad_root)?;
    let mut root = space.read_u64(checked_vad_field(root_field, root_offset)?)?;
    if modern_vad_node.is_some() {
        root = discover_vad_root(
            &space,
            process.eprocess,
            profile.type_size,
            root,
            left,
            right,
            starting_vpn,
            ending_vpn,
            starting_high,
            ending_high,
        )
        .context("无法定位结构有效的 VAD 根节点")?;
    }
    let mut stack = Vec::new();
    if root != 0 {
        stack.push(root);
    }
    let mut visited = HashSet::new();
    let mut records = Vec::new();
    let mut warnings = Vec::new();
    while let Some(tree_node) = stack.pop() {
        cancellation.check_cancelled()?;
        if visited.len() == limit {
            push_warning_limited(&mut warnings, format!("VAD 遍历达到 {limit} 个节点上限"));
            break;
        }
        if !visited.insert(tree_node) {
            warnings.push(format!("VAD 树在 {tree_node:#x} 处形成循环"));
            continue;
        }
        let vad = match tree_node.checked_sub(node_offset) {
            Some(vad) => vad,
            None => {
                warnings.push(format!("VAD 节点 {tree_node:#x} 无效"));
                continue;
            }
        };
        let parsed = (|| -> Result<VadRecord> {
            let start_vpn = read_vpn(&space, vad, starting_vpn, starting_high)?;
            let end_vpn = read_vpn(&space, vad, ending_vpn, ending_high)?;
            ensure!(end_vpn >= start_vpn, "VAD 结束地址早于起始地址");
            // _MMVAD_FLAGS is 64-bit on Windows 7 (Protection begins at bit 56)
            // and 32-bit on newer kernels. Reading the containing 64-bit union
            // handles both layouts without hard-coding an OS version.
            let flags = space.read_u64(checked_vad_field(vad, flags_offset)?)?;
            let protection = extract_u64_bits(flags, protection_position, protection_length) as u8;
            let private_memory = extract_u64_bits(flags, private_position, private_length) != 0;
            let file = if private_memory {
                None
            } else {
                match vad_file_name(
                    &space,
                    vad,
                    file_object_offset,
                    subsection_path,
                    file_name_offset,
                ) {
                    Ok(file) => file,
                    Err(error) => {
                        push_warning_limited(
                            &mut warnings,
                            format!(
                                "VAD {vad:#x} 的文件关联无法解析，保留区间且文件未知：{error:#}"
                            ),
                        );
                        None
                    }
                }
            };
            Ok(VadRecord {
                pid,
                process: process.name.clone(),
                node: vad,
                start: start_vpn << 12,
                end: (end_vpn << 12) | 0xfff,
                protection,
                protection_name: protection_name(protection).to_owned(),
                vad_type: extract_u64_bits(flags, vad_type_position, vad_type_length) as u8,
                private_memory,
                file,
            })
        })();
        match parsed {
            Ok(record) => records.push(record),
            Err(error) => warnings.push(format!("无法解析 VAD {vad:#x}：{error:#}")),
        }
        for child_offset in [right, left] {
            match checked_vad_field(tree_node, child_offset)
                .and_then(|address| space.read_u64(address))
            {
                Ok(child) if child != 0 => stack.push(child),
                Ok(_) => {}
                Err(error) => warnings.push(format!(
                    "无法读取 VAD {tree_node:#x} 的子节点字段 +{child_offset:#x}：{error:#}"
                )),
            }
        }
    }
    records.sort_unstable_by_key(|record| record.start);
    Ok(PluginReport {
        records,
        complete: warnings.is_empty(),
        warnings,
    })
}

pub fn list_hives(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<PluginReport<HiveRecord>> {
    ensure!(limit > 0, "Hive 结果上限必须大于零");
    let space = kernel.x64_address_space(image)?;
    let hive_list = profile.type_field("_CMHIVE", "HiveList")?.offset;
    let file_path = profile.type_field("_CMHIVE", "FileFullPath")?.offset;
    let user_name = profile.type_field("_CMHIVE", "FileUserName")?.offset;
    let root_path = profile.type_field("_CMHIVE", "HiveRootPath")?.offset;
    let reported_head = kernel.kernel_base + u64::from(profile.symbol_rva("CmpHiveListHead")?);
    let head = discover_hive_list_head(&space, kernel.kernel_base, reported_head, hive_list)
        .context("无法通过 HHIVE 签名定位 CmpHiveListHead")?;
    let mut link = space.read_u64(head)?;
    let mut visited = HashSet::new();
    let mut records = Vec::new();
    let mut warnings = Vec::new();
    while link != head && records.len() < limit {
        if !visited.insert(link) {
            warnings.push(format!("Hive 链表在 {link:#x} 处形成循环"));
            break;
        }
        let Some(cmhive) = link.checked_sub(hive_list) else {
            warnings.push(format!("Hive 链表条目 {link:#x} 无效"));
            break;
        };
        let mut read_name = |field_address: u64, field_name: &str| match read_unicode_string(
            &space,
            field_address,
            32 * 1024,
        ) {
            Ok(value) => value,
            Err(error) => {
                warnings.push(format!(
                    "无法读取 CMHIVE {cmhive:#x} 的 {field_name}：{error:#}"
                ));
                String::new()
            }
        };
        records.push(HiveRecord {
            cmhive,
            file_path: read_name(cmhive + file_path, "FileFullPath"),
            user_name: read_name(cmhive + user_name, "FileUserName"),
            root_path: read_name(cmhive + root_path, "HiveRootPath"),
        });
        link = match space.read_u64(link) {
            Ok(next) => next,
            Err(error) => {
                warnings.push(format!("无法继续遍历 Hive 条目 {link:#x}：{error:#}"));
                break;
            }
        };
    }
    Ok(PluginReport {
        complete: link == head,
        records,
        warnings,
    })
}

pub fn scan_hives(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<PluginReport<HiveScanRecord>> {
    ensure!(limit > 0, "Hive 扫描结果上限必须大于零");
    let space = kernel.x64_address_space(image)?;
    let big = list_big_pools(
        image,
        kernel,
        profile,
        &["CM10".to_owned()],
        false,
        limit.saturating_mul(4).max(1024),
    );
    let small = scan_pool_allocations(
        image,
        kernel,
        profile,
        &[*b"CM10"],
        limit.saturating_mul(4).max(1024),
    )?;
    let active = list_hives(image, kernel, profile, 65_536);
    let mut warnings = small.warnings;
    let mut complete = small.complete;
    let big_records = match big {
        Ok(report) => {
            complete &= report.complete;
            warnings.extend(report.warnings);
            report.records
        }
        Err(error) => {
            warnings.push(format!(
                "Big Pool Hive 枚举不可用，已继续使用小池扫描：{error:#}"
            ));
            Vec::new()
        }
    };
    let active_addresses = match active {
        Ok(report) => {
            complete &= report.complete;
            warnings.extend(report.warnings);
            report
                .records
                .into_iter()
                .map(|hive| hive.cmhive)
                .collect::<HashSet<_>>()
        }
        Err(error) => {
            complete = false;
            warnings.push(format!("Hive 活动链表交叉检查失败：{error:#}"));
            HashSet::new()
        }
    };
    let hive_offset = profile.type_field("_CMHIVE", "Hive")?.offset;
    let signature_offset = profile.type_field("_HHIVE", "Signature")?.offset;
    let file_path = profile.type_field("_CMHIVE", "FileFullPath")?.offset;
    let user_name = profile.type_field("_CMHIVE", "FileUserName")?.offset;
    let root_path = profile.type_field("_CMHIVE", "HiveRootPath")?.offset;
    let cmhive_size = profile.type_layout("_CMHIVE")?.size;
    let mut candidates = big_records
        .into_iter()
        .map(|allocation| (allocation.virtual_address, allocation.number_of_bytes))
        .collect::<Vec<_>>();
    for allocation in &small.records {
        for header in allocation.virtual_headers() {
            let start = (header + 16 + 0xf) & !0xf;
            let Some(last) = header
                .checked_add(allocation.allocation_size)
                .and_then(|end| end.checked_sub(cmhive_size))
            else {
                continue;
            };
            let mut cmhive = start;
            while cmhive <= last {
                if read_u32(&space, cmhive + hive_offset + signature_offset).ok()
                    == Some(0xbee0_bee0)
                {
                    candidates.push((cmhive, allocation.allocation_size));
                }
                cmhive += 16;
            }
        }
    }
    candidates.sort_unstable();
    candidates.dedup_by_key(|candidate| candidate.0);
    let mut records = Vec::new();
    for (cmhive, allocation_size) in candidates {
        if records.len() == limit {
            complete = false;
            warnings.push(format!("Hive 扫描结果达到 {limit} 条上限"));
            break;
        }
        let signature = match read_u32(&space, cmhive + hive_offset + signature_offset) {
            Ok(0xbee0_bee0) => 0xbee0_bee0,
            Ok(_) | Err(_) => continue,
        };
        records.push(HiveScanRecord {
            cmhive,
            allocation_size,
            hhive_signature: signature,
            file_path: read_unicode_string(&space, cmhive + file_path, 32 * 1024).ok(),
            user_name: read_unicode_string(&space, cmhive + user_name, 32 * 1024).ok(),
            root_path: read_unicode_string(&space, cmhive + root_path, 32 * 1024).ok(),
            active_list: active_addresses.contains(&cmhive),
        });
    }
    records.sort_unstable_by_key(|record| record.cmhive);
    Ok(PluginReport {
        records,
        complete,
        warnings,
    })
}

pub fn check_get_cell_routines(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<GetCellRoutineReport> {
    ensure!(limit > 0, "GetCellRoutine 结果上限必须大于零");
    let space = kernel.x64_address_space(image)?;
    let hives = list_hives(image, kernel, profile, 65_536)?;
    let modules = list_drivers(image, kernel, profile, 65_536)?;
    let hive_offset = profile.type_field("_CMHIVE", "Hive")?.offset;
    let routine_offset = profile.type_field("_HHIVE", "GetCellRoutine")?.offset;
    let mut records = Vec::new();
    let mut suspicious_count = 0usize;
    let mut complete = hives.complete && modules.complete;
    let mut warnings = hives.warnings;
    warnings.extend(modules.warnings);
    for hive in &hives.records {
        if records.len() == limit {
            complete = false;
            warnings.push(format!("GetCellRoutine 结果达到 {limit} 条上限"));
            break;
        }
        let handler = match space.read_u64(hive.cmhive + hive_offset + routine_offset) {
            Ok(value) => value,
            Err(error) => {
                complete = false;
                warnings.push(format!(
                    "无法读取 CMHIVE {:#x} 的 GetCellRoutine：{error:#}",
                    hive.cmhive
                ));
                continue;
            }
        };
        let module = modules
            .records
            .iter()
            .find(|module| {
                handler >= module.base
                    && handler < module.base.saturating_add(u64::from(module.size))
            })
            .map(|module| module.name.clone());
        let expected_kernel = modules.records.iter().any(|module| {
            module.base == kernel.kernel_base
                && handler >= module.base
                && handler < module.base.saturating_add(u64::from(module.size))
        });
        let suspicious = !expected_kernel;
        suspicious_count += usize::from(suspicious);
        records.push(GetCellRoutineRecord {
            cmhive: hive.cmhive,
            hive_name: [&hive.file_path, &hive.user_name, &hive.root_path]
                .into_iter()
                .find(|name| !name.is_empty())
                .cloned()
                .unwrap_or_default(),
            handler,
            module,
            expected_kernel,
            suspicious,
        });
    }
    Ok(GetCellRoutineReport {
        records,
        hives_examined: hives.records.len(),
        suspicious_count,
        complete,
        warnings,
    })
}

fn discover_hive_list_head(
    space: &X64AddressSpace<'_>,
    kernel_base: u64,
    reported_head: u64,
    hive_list_offset: u64,
) -> Option<u64> {
    if valid_hive_list_head(space, reported_head, hive_list_offset) {
        return Some(reported_head);
    }
    let image_size = virtual_pe_image_size(space, kernel_base)
        .unwrap_or(0x0200_0000)
        .min(0x0400_0000);
    let mut page = vec![0u8; 0x1000];
    for rva in (0..image_size).step_by(0x1000) {
        let page_va = kernel_base + rva;
        if space.read_virtual(page_va, &mut page).is_err() {
            continue;
        }
        for offset in (0..=0xff0).step_by(8) {
            let flink = u64::from_le_bytes(page[offset..offset + 8].try_into().unwrap());
            let blink = u64::from_le_bytes(page[offset + 8..offset + 16].try_into().unwrap());
            if !is_kernel_pointer(flink) || !is_kernel_pointer(blink) {
                continue;
            }
            let candidate = page_va + offset as u64;
            if valid_hive_list_head(space, candidate, hive_list_offset) {
                return Some(candidate);
            }
        }
    }
    None
}

fn valid_hive_list_head(space: &X64AddressSpace<'_>, head: u64, hive_list_offset: u64) -> bool {
    let Some(flink) = space.read_u64(head).ok() else {
        return false;
    };
    let Some(blink) = space.read_u64(head + 8).ok() else {
        return false;
    };
    if !is_kernel_pointer(flink)
        || !is_kernel_pointer(blink)
        || flink < hive_list_offset
        || space.read_u64(flink + 8).ok() != Some(head)
    {
        return false;
    }
    // Some acquisitions omit the page containing the tail entry while the
    // list head and forward chain remain resident. A readable tail must still
    // point back to the head; an absent tail page does not invalidate the
    // independently verified forward link and HHIVE signature.
    if let Ok(tail_flink) = space.read_u64(blink)
        && tail_flink != head
    {
        return false;
    }
    read_u32(space, flink - hive_list_offset).ok() == Some(0xbee0_bee0)
}

fn virtual_pe_image_size(space: &X64AddressSpace<'_>, image_base: u64) -> Option<u64> {
    let mut dos = [0u8; 64];
    space.read_virtual(image_base, &mut dos).ok()?;
    if !dos.starts_with(b"MZ") {
        return None;
    }
    let pe_offset = u64::from(u32::from_le_bytes(dos[0x3c..0x40].try_into().ok()?));
    let mut headers = [0u8; 0x100];
    space
        .read_virtual(image_base + pe_offset, &mut headers)
        .ok()?;
    if !headers.starts_with(b"PE\0\0") {
        return None;
    }
    Some(u64::from(u32::from_le_bytes(
        headers[24 + 56..24 + 60].try_into().ok()?,
    )))
}

pub fn list_handles(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid: u64,
    limit: usize,
) -> Result<PluginReport<HandleRecord>> {
    ensure!(limit > 0, "句柄结果上限必须大于零");
    let space = kernel.x64_address_space(image)?;
    let processes = list_processes(image, kernel, profile, 65536)?;
    let process = processes
        .processes
        .iter()
        .find(|process| process.pid == pid)
        .with_context(|| format!("PsActiveProcessHead 中没有 PID {pid}"))?;
    let object_table_offset = profile.field("ObjectTable")?.offset;
    let table_code_offset = profile.type_field("_HANDLE_TABLE", "TableCode")?.offset;
    let next_handle_offset = profile
        .type_field("_HANDLE_TABLE", "NextHandleNeedingPool")?
        .offset;
    let type_index_offset = profile.type_field("_OBJECT_HEADER", "TypeIndex")?.offset;
    let body_offset = profile.type_field("_OBJECT_HEADER", "Body")?.offset;
    let object_type_name = profile.type_field("_OBJECT_TYPE", "Name")?.offset;
    let reported_type_table =
        kernel.kernel_base + u64::from(profile.symbol_rva("ObTypeIndexTable")?);
    let encoded_headers = profile.symbols.contains_key("ObHeaderCookie");
    let reported_cookie = profile
        .symbols
        .get("ObHeaderCookie")
        .and_then(|rva| read_u8(&space, kernel.kernel_base + u64::from(*rva)).ok());
    let granted_access_offset = profile
        .type_field("_HANDLE_TABLE_ENTRY", "GrantedAccess")
        .or_else(|_| profile.type_field("_HANDLE_TABLE_ENTRY", "GrantedAccessBits"))
        .map(|field| field.offset)
        .unwrap_or(8);
    let table = space.read_u64(process.eprocess + object_table_offset)?;
    ensure!(table != 0, "PID {pid} 没有句柄表");
    let table_code = space.read_u64(table + table_code_offset)?;
    let next_handle = read_u32(&space, table + next_handle_offset)?;
    let max_handle = next_handle.min(0x0400_0000);
    let sample_headers =
        sample_handle_object_headers(&space, table_code, max_handle, encoded_headers, 64);
    let resolved_type_table = discover_object_type_table(
        &space,
        kernel.kernel_base,
        reported_type_table,
        object_type_name,
    );
    let cookie = if encoded_headers {
        resolved_type_table
            .and_then(|(type_table, resolved_type_name_offset)| {
                discover_object_header_cookie(
                    &space,
                    type_table,
                    type_index_offset,
                    resolved_type_name_offset,
                    &sample_headers,
                )
            })
            .or_else(|| resolved_type_table.and(reported_cookie))
    } else {
        None
    };
    let mut records = Vec::new();
    let mut warnings: Vec<String> = processes
        .warnings
        .iter()
        .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
        .collect();
    if resolved_type_table.is_none() || (encoded_headers && cookie.is_none()) {
        warnings.push(
            "无法验证 ObTypeIndexTable/ObHeaderCookie；未经验证的数字对象类型将显示为“未知”"
                .to_owned(),
        );
    }

    for handle in (4..max_handle).step_by(4) {
        if records.len() == limit {
            push_warning_limited(&mut warnings, format!("句柄结果达到 {limit} 条上限"));
            break;
        }
        let entry = match handle_entry_address(&space, table_code, handle) {
            Ok(entry) => entry,
            Err(error) => {
                push_warning_limited(
                    &mut warnings,
                    format!("句柄 {handle:#x}：无法解析表项：{error:#}"),
                );
                continue;
            }
        };
        let low = match space.read_u64(entry) {
            Ok(low) => low,
            Err(_) => continue,
        };
        let object_header = if encoded_headers {
            let object_bits = (low >> 20) & 0x0000_0fff_ffff_ffff;
            if object_bits == 0 {
                continue;
            }
            sign_extend_48(object_bits << 4)
        } else {
            // Before handle-entry pointer compression, Object was an
            // _EX_FAST_REF whose low attribute bits must simply be cleared.
            low & !0xf
        };
        if object_header >> 48 != 0xffff {
            continue;
        }
        let raw_type_index = match read_u8(&space, object_header + type_index_offset) {
            Ok(index) => index,
            Err(_) => continue,
        };
        let decoded_type = resolved_type_table.and_then(|(type_table, type_name_offset)| {
            let type_index = if encoded_headers {
                let cookie = cookie?;
                raw_type_index ^ cookie ^ ((object_header >> 8) as u8)
            } else {
                raw_type_index
            };
            let object_type_pointer = space
                .read_u64(type_table + u64::from(type_index) * 8)
                .ok()?;
            let object_type =
                read_unicode_string(&space, object_type_pointer + type_name_offset, 4096)
                    .ok()
                    .filter(|name| is_known_object_type(name))?;
            Some((type_index, object_type))
        });
        let object = object_header + body_offset;
        let (type_index, object_type, object_type_source) = if let Some((index, name)) =
            decoded_type
        {
            (Some(index), name, "type_table".to_owned())
        } else if let Some(name) = infer_handle_object_type(&space, profile, object, &processes) {
            (None, name, "structure".to_owned())
        } else {
            (None, "未知".to_owned(), "未经验证".to_owned())
        };
        let granted_access = if encoded_headers {
            (space.read_u64(entry + 8).unwrap_or(0) & 0x01ff_ffff) as u32
        } else {
            read_u32(&space, entry + granted_access_offset).unwrap_or(0) & 0x01ff_ffff
        };
        let name = object_display_name(&space, profile, object, &object_type)
            .ok()
            .flatten();
        records.push(HandleRecord {
            pid,
            process: process.name.clone(),
            handle,
            entry,
            object_header,
            object,
            type_index,
            object_type,
            object_type_source,
            granted_access,
            name,
        });
    }

    Ok(PluginReport {
        complete: warnings.is_empty(),
        records,
        warnings,
    })
}

/// Walk every active process handle table once and retain only handles whose
/// object body is in `targets`.  Pool-scanning plugins use this to correlate
/// recovered objects without repeatedly enumerating the same process list and
/// handle tables.
pub fn find_handle_owners(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    targets: &HashSet<u64>,
    process_limit: usize,
    handle_scan_limit: usize,
) -> Result<ObjectHandleOwnerReport> {
    ensure!(process_limit > 0, "进程扫描上限必须大于零");
    ensure!(handle_scan_limit > 0, "句柄扫描上限必须大于零");
    if targets.is_empty() {
        return Ok(ObjectHandleOwnerReport {
            records: Vec::new(),
            complete: true,
            processes_examined: 0,
            handle_entries_examined: 0,
            warnings: Vec::new(),
        });
    }

    let space = kernel.x64_address_space(image)?;
    let processes = list_processes(image, kernel, profile, process_limit)?;
    let object_table_offset = profile.field("ObjectTable")?.offset;
    let table_code_offset = profile.type_field("_HANDLE_TABLE", "TableCode")?.offset;
    let next_handle_offset = profile
        .type_field("_HANDLE_TABLE", "NextHandleNeedingPool")?
        .offset;
    let body_offset = profile.type_field("_OBJECT_HEADER", "Body")?.offset;
    let encoded_headers = profile.symbols.contains_key("ObHeaderCookie");
    let granted_access_offset = profile
        .type_field("_HANDLE_TABLE_ENTRY", "GrantedAccess")
        .or_else(|_| profile.type_field("_HANDLE_TABLE_ENTRY", "GrantedAccessBits"))
        .map(|field| field.offset)
        .unwrap_or(8);
    let mut records = Vec::new();
    let mut warnings: Vec<String> = processes
        .warnings
        .iter()
        .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
        .collect();
    let mut complete =
        handle_owner_process_source_complete(processes.complete, processes.warnings.len());
    let mut handle_entries_examined = 0usize;
    let mut processes_examined = 0usize;

    'processes: for process in &processes.processes {
        processes_examined += 1;
        let table = match space.read_u64(process.eprocess + object_table_offset) {
            Ok(0) => continue,
            Ok(table) if is_kernel_pointer(table) => table,
            Ok(table) => {
                complete = false;
                push_warning_limited(
                    &mut warnings,
                    format!("PID {} 的句柄表指针 {table:#x} 无效", process.pid),
                );
                continue;
            }
            Err(error) => {
                complete = false;
                push_warning_limited(
                    &mut warnings,
                    format!("无法读取 PID {} 的句柄表指针：{error:#}", process.pid),
                );
                continue;
            }
        };
        let Ok(table_code) = space.read_u64(table + table_code_offset) else {
            complete = false;
            push_warning_limited(
                &mut warnings,
                format!("无法读取 PID {} 的句柄表根", process.pid),
            );
            continue;
        };
        let Ok(next_handle) = read_u32(&space, table + next_handle_offset) else {
            complete = false;
            push_warning_limited(
                &mut warnings,
                format!("无法读取 PID {} 的句柄表边界", process.pid),
            );
            continue;
        };
        // A smeared NextHandleNeedingPool can otherwise make one damaged
        // process consume the entire global budget.  One million bytes of
        // handle value cover 262,143 entries for a process; clipping is
        // reported as incomplete instead of silently trusting the boundary.
        const MAX_HANDLE_VALUE_PER_PROCESS: u32 = 0x0010_0000;
        let max_handle = next_handle.min(MAX_HANDLE_VALUE_PER_PROCESS);
        if next_handle > max_handle {
            complete = false;
            push_warning_limited(
                &mut warnings,
                format!(
                    "PID {} 的句柄表边界 {next_handle:#x} 超过安全上限 {max_handle:#x}",
                    process.pid
                ),
            );
        }

        for handle in (4..max_handle).step_by(4) {
            if handle_entries_examined == handle_scan_limit {
                complete = false;
                push_warning_limited(
                    &mut warnings,
                    format!("句柄表扫描达到 {handle_scan_limit} 个表项上限"),
                );
                break 'processes;
            }
            handle_entries_examined += 1;
            let Ok(entry) = handle_entry_address(&space, table_code, handle) else {
                continue;
            };
            let Ok(low) = space.read_u64(entry) else {
                continue;
            };
            let object_header = if encoded_headers {
                let object_bits = (low >> 20) & 0x0000_0fff_ffff_ffff;
                if object_bits == 0 {
                    continue;
                }
                sign_extend_48(object_bits << 4)
            } else {
                low & !0xf
            };
            if !is_kernel_pointer(object_header) {
                continue;
            }
            let Some(object) = object_header.checked_add(body_offset) else {
                continue;
            };
            if !targets.contains(&object) {
                continue;
            }
            let granted_access = if encoded_headers {
                (space.read_u64(entry + 8).unwrap_or(0) & 0x01ff_ffff) as u32
            } else {
                read_u32(&space, entry + granted_access_offset).unwrap_or(0) & 0x01ff_ffff
            };
            records.push(ObjectHandleOwner {
                pid: process.pid,
                process: process.name.clone(),
                user_name: process.details.user_name.clone(),
                user_sid: process.details.user_sid.clone(),
                process_create_time: process.details.create_time.clone(),
                handle,
                entry,
                object_header,
                object,
                granted_access,
            });
        }
    }

    records.sort_unstable_by_key(|record| (record.object, record.pid, record.handle));
    Ok(ObjectHandleOwnerReport {
        records,
        complete,
        processes_examined,
        handle_entries_examined,
        warnings,
    })
}

fn handle_owner_process_source_complete(complete: bool, warning_count: usize) -> bool {
    complete && warning_count == 0
}

/// Resolve one exact handle from PID 4 without walking the whole handle table.
/// Registry hives store their primary backing file as an encoded System-process
/// handle, and callers still validate the returned object as a FILE_OBJECT.
pub(crate) fn resolve_system_handle_object(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    handle: u32,
) -> Result<u64> {
    ensure!(
        handle >= 4 && handle.is_multiple_of(4),
        "System 句柄值 {handle:#x} 无效"
    );
    let space = kernel.x64_address_space(image)?;
    let system_process_pointer = kernel
        .kernel_base
        .checked_add(u64::from(profile.symbol_rva("PsInitialSystemProcess")?))
        .context("PsInitialSystemProcess 地址溢出")?;
    let system_process = space
        .read_u64(system_process_pointer)
        .ok()
        .filter(|process| is_kernel_pointer(*process))
        .or_else(|| {
            list_processes(image, kernel, profile, 65_536)
                .ok()?
                .processes
                .into_iter()
                .find(|process| process.pid == 4)
                .map(|process| process.eprocess)
                .filter(|process| is_kernel_pointer(*process))
        })
        .context("PsInitialSystemProcess 无效，活动进程链中也没有可用的 PID 4 EPROCESS")?;
    let object_table_offset = profile.field("ObjectTable")?.offset;
    let table_code_offset = profile.type_field("_HANDLE_TABLE", "TableCode")?.offset;
    let table = space.read_u64(system_process + object_table_offset)?;
    ensure!(is_kernel_pointer(table), "System 进程没有有效的句柄表");
    let table_code = space.read_u64(table + table_code_offset)?;
    let entry = handle_entry_address(&space, table_code, handle)?;
    let low = space.read_u64(entry)?;
    let object_header = if profile.symbols.contains_key("ObHeaderCookie") {
        let object_bits = (low >> 20) & 0x0000_0fff_ffff_ffff;
        ensure!(object_bits != 0, "System 句柄 {handle:#x} 的对象指针为空");
        sign_extend_48(object_bits << 4)
    } else {
        low & !0xf
    };
    ensure!(is_kernel_pointer(object_header), "System 句柄对象头无效");
    let body_offset = profile.type_field("_OBJECT_HEADER", "Body")?.offset;
    object_header
        .checked_add(body_offset)
        .context("System 句柄对象正文地址溢出")
}

pub fn scan_network(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<PluginReport<NetworkRecord>> {
    scan_network_cancellable(image, kernel, profile, limit, &CancellationToken::new())
}

pub fn scan_network_cancellable(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
    cancellation: &CancellationToken,
) -> Result<PluginReport<NetworkRecord>> {
    cancellation.check_cancelled()?;
    ensure!(limit > 0, "网络结果上限必须大于零");
    let space = kernel.x64_address_space(image)?;
    let processes = list_processes(image, kernel, profile, 65536)?;
    cancellation.check_cancelled()?;
    let owners: HashMap<u64, _> = processes
        .processes
        .iter()
        .map(|process| (process.eprocess, process))
        .collect();
    let mut records = Vec::new();
    let mut warnings: Vec<String> = processes
        .warnings
        .iter()
        .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
        .collect();

    const TAGS: [[u8; 4]; 4] = [*b"TcpE", *b"TTcb", *b"TcpL", *b"UdpA"];
    let scan = scan_exact_4_cancellable(image, &TAGS, 65_536, 64 * 1024 * 1024, cancellation)?;
    if scan.truncated {
        push_warning_limited(
            &mut warnings,
            "一个或多个网络池标签超过候选数量上限".to_owned(),
        );
    }
    for hit in scan.hits {
        cancellation.check_cancelled()?;
        if records.len() == limit {
            push_warning_limited(&mut warnings, format!("网络结果已达到数量上限 {limit}"));
            break;
        }
        let tag = &TAGS[hit.pattern_index];
        let Some((object_physical, pool_size)) = network_pool_object(image, &hit, tag) else {
            continue;
        };
        let object_length = usize::try_from((pool_size - 16).min(4096))?;
        let mut bytes = vec![0u8; object_length];
        if image.read_physical(object_physical, &mut bytes).is_err() {
            continue;
        }
        let owner = find_network_owner(&space, &bytes, &owners);
        let classic_owner_offset = owner.as_ref().map(|owner| owner.object_offset);
        let decoded = match tag {
            b"TcpE" => decode_tcp_endpoint(&space, &bytes, pool_size, classic_owner_offset),
            b"TTcb" => decode_ttcb_endpoint(&space, &bytes),
            b"TcpL" => decode_tcp_listener(&space, &bytes, pool_size, classic_owner_offset),
            b"UdpA" => decode_udp_endpoint(&space, &bytes, pool_size, classic_owner_offset),
            _ => unreachable!(),
        };
        let Some((family, parsed)) = decoded else {
            continue;
        };
        let (local_address, local_port, remote_address, remote_port, state) = parsed;
        if local_port == 0 {
            continue;
        }
        let (pid, process, owner_offset, owner_resolution) = owner.map_or_else(
            || (0, String::new(), None, "未知".to_owned()),
            |owner| {
                (
                    owner.process.pid,
                    owner.process.name.clone(),
                    Some(owner.object_offset),
                    owner.resolution.to_owned(),
                )
            },
        );
        records.push(NetworkRecord {
            physical_address: object_physical,
            pool_tag: String::from_utf8_lossy(tag).into_owned(),
            protocol: if tag == b"UdpA" { "UDP" } else { "TCP" }.to_owned(),
            address_family: family,
            local_address,
            local_port,
            remote_address,
            remote_port,
            state,
            pid,
            process,
            owner_offset,
            owner_resolution,
        });
    }

    // Some kernels expose both a complete connection and a compact TcpE
    // companion that only retains owner/state/local-port data. Merge the weak
    // companion only when a complete endpoint in the same process and port
    // group proves that it is redundant. A lone compact endpoint is retained.
    let merged_companions = merge_weak_tcp_companions(&mut records);
    if merged_companions != 0 {
        push_warning_limited(
            &mut warnings,
            format!("已合并 {merged_companions} 个缺少远端地址的 TcpE 伴生记录"),
        );
    }

    let unknown_owners = records.iter().filter(|record| record.pid == 0).count();
    if unknown_owners != 0 {
        push_warning_limited(
            &mut warnings,
            format!("已保留 {unknown_owners} 个尚未验证所属进程的网络端点"),
        );
    }
    let compact_tcp = records
        .iter()
        .filter(|record| record.pool_tag == "TcpE" && record.remote_port.is_none())
        .count();
    if compact_tcp != 0 {
        push_warning_limited(
            &mut warnings,
            format!(
                "{compact_tcp} 个紧凑型 TcpE 端点因私有地址包装结构缺少符号，地址按未指定值保守显示"
            ),
        );
    }
    records.sort_unstable_by_key(|record| (record.pid, record.local_port));
    Ok(PluginReport {
        complete: !scan.truncated && records.len() < limit,
        records,
        warnings,
    })
}

fn merge_weak_tcp_companions(records: &mut Vec<NetworkRecord>) -> usize {
    let complete_groups = records
        .iter()
        .filter(|record| {
            record.remote_port.is_some_and(|port| port != 0)
                && record
                    .remote_address
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| !address.is_unspecified())
        })
        .map(|record| (record.pid, record.protocol.clone(), record.local_port))
        .collect::<HashSet<_>>();

    let original_len = records.len();
    records.retain(|record| {
        let weak_companion = record.pool_tag == "TcpE"
            && record.remote_port.is_none_or(|port| port == 0)
            && record
                .remote_address
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_unspecified());
        !weak_companion
            || !complete_groups.contains(&(record.pid, record.protocol.clone(), record.local_port))
    });
    original_len - records.len()
}

struct NetworkOwner<'a> {
    object_offset: u64,
    process: &'a super::ProcessRecord,
    resolution: &'static str,
}

fn find_network_owner<'a>(
    space: &X64AddressSpace<'_>,
    bytes: &[u8],
    owners: &HashMap<u64, &'a super::ProcessRecord>,
) -> Option<NetworkOwner<'a>> {
    if let Some(owner) = (0x10..bytes.len().min(0x400))
        .step_by(8)
        .find_map(|offset| {
            let pointer = buffer_u64(bytes, offset)?;
            owners.get(&pointer).copied().map(|process| NetworkOwner {
                object_offset: offset as u64,
                process,
                resolution: "直接",
            })
        })
    {
        return Some(owner);
    }

    let mut pointee = [0u8; 512];
    for object_offset in (0x10..bytes.len().min(0x200)).step_by(8) {
        let Some(pointer) =
            buffer_u64(bytes, object_offset).filter(|value| is_kernel_pointer(*value))
        else {
            continue;
        };
        if space.read_virtual(pointer, &mut pointee).is_err() {
            continue;
        }
        if let Some(process) = pointee.chunks_exact(8).find_map(|raw| {
            let candidate = u64::from_le_bytes(raw.try_into().ok()?);
            owners.get(&candidate).copied()
        }) {
            return Some(NetworkOwner {
                object_offset: object_offset as u64,
                process,
                resolution: "间接",
            });
        }
    }
    None
}

fn network_pool_object(
    image: &MemoryImage,
    hit: &crate::scan::MultiScanHit,
    tag: &[u8; 4],
) -> Option<(u64, u64)> {
    if hit.physical_address & 0xf != 4 {
        return None;
    }
    let pool_header = hit.physical_address.checked_sub(4)?;
    let mut header = [0u8; 16];
    image.read_physical(pool_header, &mut header).ok()?;
    if &header[4..8] != tag {
        return None;
    }
    let pool_size = u64::from(header[2]) * 16;
    (pool_size >= 0x80).then_some((pool_header + 16, pool_size))
}

fn valid_address_family(family: u16) -> Option<u16> {
    matches!(family, 2 | 0x17).then_some(family)
}

fn inetaf_family(space: &X64AddressSpace<'_>, pointer: u64) -> Option<u16> {
    if !is_kernel_pointer(pointer) {
        return None;
    }
    [0x14u64, 0x18, 0x74].into_iter().find_map(|offset| {
        read_u16(space, pointer + offset)
            .ok()
            .and_then(valid_address_family)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TcpEndpointLayout {
    inetaf: usize,
    addrinfo: usize,
    state: usize,
    local_port: usize,
    remote_port: usize,
}

// tcpip.sys uses private endpoint structures whose offsets vary by Windows
// generation.  Layout selection is intentionally independent from the Owner
// field: an endpoint may store EPROCESS directly near the end of the object or
// expose it through an intermediate structure much earlier in the allocation.
// Every candidate must pass pointer, address-family, state and port validation
// before it is accepted.
const TCP_ENDPOINT_LAYOUTS: &[TcpEndpointLayout] = &[
    // Windows 7 / Server 2008 R2 x64 (_TCP_ENDPOINT size 0x240).
    TcpEndpointLayout {
        inetaf: 0x18,
        addrinfo: 0x20,
        state: 0x68,
        local_port: 0x6c,
        remote_port: 0x6e,
    },
    TcpEndpointLayout {
        inetaf: 0x10,
        addrinfo: 0x18,
        state: 0x68,
        local_port: 0x6c,
        remote_port: 0x6e,
    },
    TcpEndpointLayout {
        inetaf: 0x10,
        addrinfo: 0x18,
        state: 0x6c,
        local_port: 0x70,
        remote_port: 0x72,
    },
    TcpEndpointLayout {
        inetaf: 0x18,
        addrinfo: 0x20,
        state: 0x50,
        local_port: 0x54,
        remote_port: 0x56,
    },
];

#[derive(Debug, Eq, PartialEq)]
struct TcpEndpointFields {
    inetaf: u64,
    addrinfo: u64,
    state: u8,
    local_port: u16,
    remote_port: Option<u16>,
}

#[derive(Debug, Eq, PartialEq)]
struct TtcbEndpointFields {
    inetaf: u64,
    address_pair: u64,
    state: u8,
    local_port: u16,
    remote_port: Option<u16>,
}

fn tcp_endpoint_fields(bytes: &[u8], layout: TcpEndpointLayout) -> Option<TcpEndpointFields> {
    let inetaf = buffer_u64(bytes, layout.inetaf).filter(|value| is_kernel_pointer(*value))?;
    let addrinfo = buffer_u64(bytes, layout.addrinfo).filter(|value| is_kernel_pointer(*value))?;
    let state = buffer_u32(bytes, layout.state).filter(|state| *state <= 13)? as u8;
    let local_port = buffer_be_u16(bytes, layout.local_port).filter(|port| *port != 0)?;
    let remote_port = buffer_be_u16(bytes, layout.remote_port).filter(|port| *port != 0);
    Some(TcpEndpointFields {
        inetaf,
        addrinfo,
        state,
        local_port,
        remote_port,
    })
}

fn ttcb_endpoint_fields(bytes: &[u8]) -> Option<TtcbEndpointFields> {
    let inetaf = buffer_u64(bytes, 0x18).filter(|value| is_kernel_pointer(*value))?;
    let address_pair = buffer_u64(bytes, 0x20).filter(|value| is_kernel_pointer(*value))?;
    let state = buffer_u32(bytes, 0x70).filter(|state| *state <= 13)? as u8;
    let local_port = buffer_be_u16(bytes, 0x74).filter(|port| *port != 0)?;
    let remote_port = buffer_be_u16(bytes, 0x76).filter(|port| *port != 0);
    Some(TtcbEndpointFields {
        inetaf,
        address_pair,
        state,
        local_port,
        remote_port,
    })
}

fn decode_ttcb_endpoint(space: &X64AddressSpace<'_>, bytes: &[u8]) -> Option<(u16, ParsedNetwork)> {
    let fields = ttcb_endpoint_fields(bytes)?;
    let family = inetaf_family(space, fields.inetaf)?;

    // Build 26200 and newer store a pointer to an Ippa address-pair object at
    // +0x20.  Its first pointer identifies the Ipla local-address object;
    // both tags are checked before fixed private offsets are trusted.
    let local_holder = space.read_u64(fields.address_pair).ok()?;
    if !is_kernel_pointer(local_holder)
        || read_u32(space, fields.address_pair + 0x64).ok()? != u32::from_le_bytes(*b"Ippa")
        || read_u32(space, local_holder).ok()? != u32::from_le_bytes(*b"Ipla")
    {
        return None;
    }
    let local_address = read_ip(space, local_holder + 0xf0, family).ok()?;
    let remote_address = read_ip(space, fields.address_pair + 0xd8, family).ok()?;
    Some((
        family,
        (
            local_address,
            fields.local_port,
            remote_address,
            fields.remote_port,
            Some(tcp_state_name(fields.state).to_owned()),
        ),
    ))
}

fn decode_tcp_endpoint(
    space: &X64AddressSpace<'_>,
    bytes: &[u8],
    pool_size: u64,
    owner_offset: Option<u64>,
) -> Option<(u16, ParsedNetwork)> {
    for layout in TCP_ENDPOINT_LAYOUTS.iter().copied() {
        let Some(fields) = tcp_endpoint_fields(bytes, layout) else {
            continue;
        };
        let Some(family) = inetaf_family(space, fields.inetaf) else {
            continue;
        };
        let Ok(parsed) = parse_tcp_endpoint(space, fields, family) else {
            continue;
        };
        return Some((family, parsed));
    }

    let compact_family = buffer_le_u16(bytes, 0x68).and_then(valid_address_family);
    if pool_size <= 0x180
        && let Some(family) = compact_family
    {
        let local_port = buffer_be_u16(bytes, 0x6a)?;
        let state = buffer_u32(bytes, 0x80)
            .filter(|state| *state <= 13)
            .map(|state| tcp_state_name(state as u8).to_owned());
        return Some((
            family,
            (
                unspecified_address(family),
                local_port,
                unspecified_address(family),
                None,
                state,
            ),
        ));
    }
    let owner_offset = owner_offset?;
    let inetaf_offset = owner_offset.checked_sub(0x10)?;
    let inetaf = buffer_u64(bytes, inetaf_offset as usize)?;
    let family = buffer_le_u16(bytes, (owner_offset + 0x48) as usize)
        .and_then(valid_address_family)
        .or_else(|| inetaf_family(space, inetaf))?;
    parse_legacy_tcp_endpoint(space, bytes, owner_offset, family)
        .ok()
        .map(|parsed| (family, parsed))
}

fn decode_tcp_listener(
    space: &X64AddressSpace<'_>,
    bytes: &[u8],
    pool_size: u64,
    owner_offset: Option<u64>,
) -> Option<(u16, ParsedNetwork)> {
    // Windows 7 / Server 2008 R2 keeps InetAF and Owner near the start of the
    // allocation, while the port follows the inline address-family field.
    // Select this layout from validated structural invariants instead of the
    // OS build number so that compatible server and backported kernels work.
    if owner_offset == Some(0x28) {
        let inetaf = buffer_u64(bytes, 0x18)?;
        let family = buffer_le_u16(bytes, 0x68)
            .and_then(valid_address_family)
            .or_else(|| inetaf_family(space, inetaf))?;
        let local_pointer = buffer_u64(bytes, 0x60).unwrap_or(0);
        let local_address = read_local_address(space, local_pointer, family, true)
            .unwrap_or_else(|_| unspecified_address(family));
        let local_port = buffer_be_u16(bytes, 0x6a).filter(|port| *port != 0)?;
        return Some((
            family,
            (
                local_address,
                local_port,
                unspecified_address(family),
                None,
                Some("LISTENING".to_owned()),
            ),
        ));
    }
    let compact_family = buffer_le_u16(bytes, 0x70).and_then(valid_address_family);
    if pool_size <= 0x200
        && let Some(family) = compact_family
    {
        return parse_tcp_listener(space, bytes, 0x30, family)
            .ok()
            .map(|parsed| (family, parsed));
    }
    let owner_offset = owner_offset?;
    let inetaf_offset = owner_offset.checked_sub(0x10)?;
    let inetaf = buffer_u64(bytes, inetaf_offset as usize)?;
    let family = buffer_le_u16(bytes, (owner_offset + 0x40) as usize)
        .and_then(valid_address_family)
        .or_else(|| inetaf_family(space, inetaf))?;
    parse_tcp_listener(space, bytes, owner_offset, family)
        .ok()
        .map(|parsed| (family, parsed))
}

fn decode_udp_endpoint(
    space: &X64AddressSpace<'_>,
    bytes: &[u8],
    pool_size: u64,
    owner_offset: Option<u64>,
) -> Option<(u16, ParsedNetwork)> {
    // The legacy full UDP endpoint has a self-consistent InetAF/Owner/local
    // tuple and stores the network-order port at +0x80.  Owner validation is
    // important here: without it, unrelated pointers in reclaimed pool data
    // can make the modern fallback appear superficially valid.
    if pool_size >= 0x150 && owner_offset == Some(0x28) {
        let local_pointer = buffer_u64(bytes, 0x20).unwrap_or(0);
        let family = inetaf_family(space, buffer_u64(bytes, 0x18)?)
            .or_else(|| inetaf_family(space, local_pointer))
            .or_else(|| buffer_le_u16(bytes, 0x70).and_then(valid_address_family))?;
        let local_address = read_local_address(space, local_pointer, family, true)
            .unwrap_or_else(|_| unspecified_address(family));
        return Some((
            family,
            (
                local_address,
                buffer_be_u16(bytes, 0x80)?,
                unspecified_address(family),
                None,
                None,
            ),
        ));
    }
    if pool_size <= 0x220 {
        let family = buffer_le_u16(bytes, 0xa6)
            .and_then(valid_address_family)
            .or_else(|| inetaf_family(space, buffer_u64(bytes, 0x20)?))?;
        let local = buffer_u64(bytes, 0xa8).unwrap_or(0);
        let local_address = read_compact_local_address(space, local, family)
            .unwrap_or_else(|_| unspecified_address(family));
        return Some((
            family,
            (
                local_address,
                buffer_be_u16(bytes, 0xa0)?,
                unspecified_address(family),
                None,
                None,
            ),
        ));
    }
    let owner_offset = owner_offset?;
    let inetaf_offset = owner_offset.checked_sub(0x10)?;
    let family = inetaf_family(space, buffer_u64(bytes, inetaf_offset as usize)?)?;
    parse_udp_endpoint(space, bytes, owner_offset, family)
        .ok()
        .map(|parsed| (family, parsed))
}

type ParsedNetwork = (String, u16, String, Option<u16>, Option<String>);

fn parse_tcp_endpoint(
    space: &X64AddressSpace<'_>,
    fields: TcpEndpointFields,
    family: u16,
) -> Result<ParsedNetwork> {
    let local = space.read_u64(fields.addrinfo)?;
    let remote = space.read_u64(fields.addrinfo + 0x10)?;
    let local_address = read_local_address(space, local, family, true)
        .unwrap_or_else(|_| unspecified_address(family));
    let remote_address =
        read_ip(space, remote, family).unwrap_or_else(|_| unspecified_address(family));
    Ok((
        local_address,
        fields.local_port,
        remote_address,
        fields.remote_port,
        Some(tcp_state_name(fields.state).to_owned()),
    ))
}

fn parse_legacy_tcp_endpoint(
    space: &X64AddressSpace<'_>,
    bytes: &[u8],
    owner_offset: u64,
    family: u16,
) -> Result<ParsedNetwork> {
    let addrinfo = buffer_u64(bytes, (owner_offset - 8) as usize).context("缺少 AddrInfo")?;
    let local = space.read_u64(addrinfo).unwrap_or(0);
    let remote = space.read_u64(addrinfo + 0x10).unwrap_or(0);
    let local_address = read_local_address(space, local, family, true)
        .unwrap_or_else(|_| unspecified_address(family));
    let remote_address = if owner_offset <= 0x40 {
        unspecified_address(family)
    } else {
        read_ip(space, remote, family).unwrap_or_else(|_| unspecified_address(family))
    };
    let (local_port_offset, remote_port_offset, state) = if owner_offset <= 0x40 {
        let state = bytes
            .get(0xc5)
            .copied()
            .filter(|state| *state <= 13)
            .map(tcp_state_name)
            .map(str::to_owned);
        (owner_offset + 0x4a, None, state)
    } else {
        let state_value = buffer_u32(bytes, 0x6c).unwrap_or(u32::MAX);
        let state = (state_value <= 13).then(|| tcp_state_name(state_value as u8).to_owned());
        (0x70, Some(0x72), state)
    };
    let local_port = buffer_be_u16(bytes, local_port_offset as usize).unwrap_or(0);
    let remote_port = remote_port_offset
        .and_then(|offset| buffer_be_u16(bytes, offset))
        .filter(|port| *port != 0);
    Ok((
        local_address,
        local_port,
        remote_address,
        remote_port,
        state,
    ))
}

fn parse_tcp_listener(
    space: &X64AddressSpace<'_>,
    bytes: &[u8],
    owner_offset: u64,
    family: u16,
) -> Result<ParsedNetwork> {
    let local_pointer = buffer_u64(bytes, 0x60).unwrap_or(0);
    let local_address = read_local_address(space, local_pointer, family, true)
        .unwrap_or_else(|_| unspecified_address(family));
    let port_offset = usize::try_from(owner_offset + 0x42)?;
    Ok((
        local_address,
        buffer_be_u16(bytes, port_offset).unwrap_or(0),
        unspecified_address(family),
        None,
        Some("LISTENING".to_owned()),
    ))
}

fn parse_udp_endpoint(
    space: &X64AddressSpace<'_>,
    bytes: &[u8],
    owner_offset: u64,
    family: u16,
) -> Result<ParsedNetwork> {
    let modern = owner_offset == 0x30;
    let port_offset = if modern { 0xa8 } else { 0xa0 };
    let address_offset = if modern { 0xb0 } else { 0xa8 };
    let local_pointer = buffer_u64(bytes, address_offset).unwrap_or(0);
    let local_address = read_local_address(space, local_pointer, family, !modern)
        .unwrap_or_else(|_| unspecified_address(family));
    Ok((
        local_address,
        buffer_be_u16(bytes, port_offset).unwrap_or(0),
        unspecified_address(family),
        None,
        None,
    ))
}

fn read_local_address(
    space: &X64AddressSpace<'_>,
    local: u64,
    family: u16,
    pointer_to_pointer: bool,
) -> Result<String> {
    ensure!(local != 0, "本地地址指针为空");
    let data = space.read_u64(local + 0x10)?;
    ensure!(data != 0, "本地地址数据为空");
    let inaddr = if pointer_to_pointer {
        space.read_u64(data)?
    } else {
        data
    };
    read_ip(space, inaddr, family)
}

fn read_compact_local_address(
    space: &X64AddressSpace<'_>,
    local: u64,
    family: u16,
) -> Result<String> {
    ensure!(is_kernel_pointer(local), "本地地址包装结构无效");
    read_ip(space, local + 0x28, family)
}

fn read_ip(space: &X64AddressSpace<'_>, address: u64, family: u16) -> Result<String> {
    ensure!(address != 0, "IP 地址指针为空");
    match family {
        2 => {
            let mut bytes = [0u8; 4];
            space.read_virtual(address, &mut bytes)?;
            Ok(Ipv4Addr::from(bytes).to_string())
        }
        0x17 => {
            let mut bytes = [0u8; 16];
            space.read_virtual(address, &mut bytes)?;
            Ok(Ipv6Addr::from(bytes).to_string())
        }
        _ => unreachable!(),
    }
}

fn unspecified_address(family: u16) -> String {
    if family == 2 {
        Ipv4Addr::UNSPECIFIED.to_string()
    } else {
        Ipv6Addr::UNSPECIFIED.to_string()
    }
}

fn tcp_state_name(state: u8) -> &'static str {
    const STATES: [&str; 14] = [
        "CLOSED",
        "LISTENING",
        "SYN_SENT",
        "SYN_RECEIVED",
        "ESTABLISHED",
        "FIN_WAIT_1",
        "FIN_WAIT_2",
        "CLOSE_WAIT",
        "CLOSING",
        "LAST_ACK",
        "DELETE_TCB",
        "TIME_WAIT",
        "UNKNOWN_12",
        "UNKNOWN_13",
    ];
    STATES[usize::from(state)]
}

fn buffer_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn buffer_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn buffer_be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn buffer_le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn vad_flag_layout(
    profile: &KernelProfile,
    field_name: &str,
    fallback_position: u8,
    fallback_length: u8,
) -> (u8, u8) {
    ["_MMVAD_FLAGS", "_MMVAD_FLAGS1", "_MMVAD_FLAGS2"]
        .into_iter()
        .find_map(|type_name| {
            let field = profile.type_field(type_name, field_name).ok()?;
            Some((field.bit_position?, field.bit_length?))
        })
        .unwrap_or((fallback_position, fallback_length))
}

fn extract_u64_bits(value: u64, position: u8, length: u8) -> u64 {
    if length == 0 || position >= 64 {
        return 0;
    }
    let available = 64 - u32::from(position);
    let width = u32::from(length).min(available);
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    (value >> position) & mask
}

fn checked_vad_field(object: u64, offset: u64) -> Result<u64> {
    ensure!(
        object >= 0xffff_8000_0000_0000 && object & 7 == 0,
        "VAD 关联中存在无效内核指针 {object:#x}"
    );
    object
        .checked_add(offset)
        .with_context(|| format!("VAD 关联字段地址溢出：{object:#x} + {offset:#x}"))
}

fn vad_file_name(
    space: &X64AddressSpace<'_>,
    vad: u64,
    direct_file_object: Option<u64>,
    subsection_path: Option<(u64, u64, u64)>,
    file_name_offset: u64,
) -> Result<Option<String>> {
    let mut candidates = Vec::with_capacity(2);
    if let Some(offset) = direct_file_object {
        candidates.push(checked_vad_field(vad, offset).and_then(|address| space.read_u64(address)));
    }
    if let Some((subsection_offset, control_area_offset, file_pointer_offset)) = subsection_path {
        candidates.push((|| -> Result<u64> {
            let subsection = space.read_u64(checked_vad_field(vad, subsection_offset)?)?;
            if subsection == 0 {
                return Ok(0);
            }
            // Subsection and ControlArea are ordinary pointers, not EX_FAST_REFs.
            // Do not round an eight-byte-aligned pointer down to another object.
            let control_area =
                space.read_u64(checked_vad_field(subsection, control_area_offset)?)?;
            if control_area == 0 {
                return Ok(0);
            }
            space.read_u64(checked_vad_field(control_area, file_pointer_offset)?)
        })());
    }
    ensure!(!candidates.is_empty(), "符号中缺少 VAD 文件关联字段");
    let mut first_error = None;
    for candidate in candidates {
        let result = candidate.and_then(|reference| {
            // _CONTROL_AREA.FilePointer is an _EX_FAST_REF. Only the file
            // reference has four low reference-count bits to remove.
            if reference == 0 {
                return Ok(None);
            }
            let file_object = reference & !0xf;
            let descriptor = checked_vad_field(file_object, file_name_offset)?;
            let name = read_unicode_string(space, descriptor, 32 * 1024)?;
            Ok((!name.is_empty()).then_some(name))
        });
        match result {
            Ok(Some(name)) => return Ok(Some(name)),
            Ok(None) => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

fn handle_entry_address(space: &X64AddressSpace<'_>, table_code: u64, handle: u32) -> Result<u64> {
    let level = table_code & 3;
    let root = table_code & !0xf;
    let index = u64::from(handle >> 2);
    ensure!(root != 0, "句柄表根指针为空");
    match level {
        0 => Ok(root + index * 16),
        1 => {
            let leaf = space.read_u64(root + (index >> 8) * 8)?;
            ensure!(leaf != 0, "一级叶表指针为空");
            Ok(leaf + (index & 0xff) * 16)
        }
        2 => {
            let middle = space.read_u64(root + (index >> 17) * 8)?;
            ensure!(middle != 0, "二级中间表指针为空");
            let leaf = space.read_u64(middle + ((index >> 8) & 0x1ff) * 8)?;
            ensure!(leaf != 0, "二级叶表指针为空");
            Ok(leaf + (index & 0xff) * 16)
        }
        _ => unreachable!("TableCode uses two level bits"),
    }
}

fn sample_handle_object_headers(
    space: &X64AddressSpace<'_>,
    table_code: u64,
    max_handle: u32,
    compressed: bool,
    limit: usize,
) -> Vec<u64> {
    let mut headers = Vec::new();
    for handle in (4..max_handle).step_by(4).take(65_536) {
        if headers.len() == limit {
            break;
        }
        let Ok(entry) = handle_entry_address(space, table_code, handle) else {
            continue;
        };
        let Ok(low) = space.read_u64(entry) else {
            continue;
        };
        let header = if compressed {
            let bits = (low >> 20) & 0x0000_0fff_ffff_ffff;
            sign_extend_48(bits << 4)
        } else {
            low & !0xf
        };
        if is_kernel_pointer(header) && space.translate(header).is_ok() {
            headers.push(header);
        }
    }
    headers.sort_unstable();
    headers.dedup();
    headers
}

fn discover_object_type_table(
    space: &X64AddressSpace<'_>,
    kernel_base: u64,
    reported_table: u64,
    name_offset: u64,
) -> Option<(u64, u64)> {
    let reported_score = score_object_type_table(space, reported_table, name_offset);
    if reported_score >= 5 {
        return Some((reported_table, name_offset));
    }
    let image_size = virtual_pe_image_size(space, kernel_base)
        .unwrap_or(0x0200_0000)
        .min(0x0400_0000);
    let mut page = vec![0u8; 0x1000];
    let mut best = (0usize, 0u64, name_offset);
    for rva in (0..image_size).step_by(0x1000) {
        let page_va = kernel_base + rva;
        if space.read_virtual(page_va, &mut page).is_err() {
            continue;
        }
        for offset in (0..=0xff8).step_by(8) {
            let pointer = u64::from_le_bytes(page[offset..offset + 8].try_into().unwrap());
            if !is_kernel_pointer(pointer) {
                continue;
            }
            let Some((name, discovered_name_offset)) =
                find_object_type_name(space, pointer, name_offset)
            else {
                continue;
            };
            if name != "Type" {
                continue;
            }
            // Object type index 2 is the meta-type "Type" on x64 Windows.
            let Some(candidate) = (page_va + offset as u64).checked_sub(16) else {
                continue;
            };
            let score = score_object_type_table(space, candidate, discovered_name_offset);
            if score > best.0 {
                best = (score, candidate, discovered_name_offset);
            }
        }
    }
    (best.0 >= 5).then_some((best.1, best.2))
}

fn find_object_type_name(
    space: &X64AddressSpace<'_>,
    object_type: u64,
    preferred_offset: u64,
) -> Option<(String, u64)> {
    std::iter::once(preferred_offset)
        .chain(
            (0..=0x100)
                .step_by(8)
                .filter(|offset| *offset != preferred_offset),
        )
        .find_map(|offset| {
            let name = read_object_type_name(space, object_type, offset)?;
            is_known_object_type(&name).then_some((name, offset))
        })
}

fn score_object_type_table(space: &X64AddressSpace<'_>, table: u64, name_offset: u64) -> usize {
    (2..=96u64)
        .filter(|index| {
            let pointer = space.read_u64(table + index * 8).unwrap_or(0);
            read_object_type_name(space, pointer, name_offset)
                .is_some_and(|name| is_known_object_type(&name))
        })
        .count()
}

fn discover_object_header_cookie(
    space: &X64AddressSpace<'_>,
    type_table: u64,
    type_index_offset: u64,
    type_name_offset: u64,
    object_headers: &[u64],
) -> Option<u8> {
    if object_headers.is_empty() {
        return None;
    }
    let mut best = (0usize, 0u8);
    for cookie in 0..=u8::MAX {
        let score = object_headers
            .iter()
            .filter(|header| {
                let raw = read_u8(space, **header + type_index_offset).unwrap_or(0);
                let index = raw ^ cookie ^ ((**header >> 8) as u8);
                let pointer = space
                    .read_u64(type_table + u64::from(index) * 8)
                    .unwrap_or(0);
                read_object_type_name(space, pointer, type_name_offset)
                    .is_some_and(|name| is_known_object_type(&name))
            })
            .count();
        if score > best.0 {
            best = (score, cookie);
        }
    }
    (best.0 >= 3 && best.0 * 2 >= object_headers.len()).then_some(best.1)
}

fn read_object_type_name(
    space: &X64AddressSpace<'_>,
    object_type: u64,
    name_offset: u64,
) -> Option<String> {
    if !is_kernel_pointer(object_type) {
        return None;
    }
    read_unicode_string(space, object_type + name_offset, 256)
        .ok()
        .filter(|name| !name.is_empty() && name.chars().all(|character| !character.is_control()))
}

fn is_known_object_type(name: &str) -> bool {
    matches!(
        name,
        "Type"
            | "Directory"
            | "SymbolicLink"
            | "Token"
            | "Process"
            | "Thread"
            | "Job"
            | "Event"
            | "Mutant"
            | "Callback"
            | "Semaphore"
            | "Timer"
            | "IRTimer"
            | "Profile"
            | "KeyedEvent"
            | "WindowStation"
            | "Desktop"
            | "Composition"
            | "RawInputManager"
            | "CoreMessaging"
            | "ActivationObject"
            | "TpWorkerFactory"
            | "Adapter"
            | "Controller"
            | "Device"
            | "Driver"
            | "IoCompletion"
            | "WaitCompletionPacket"
            | "File"
            | "TmTm"
            | "TmTx"
            | "TmRm"
            | "TmEn"
            | "Section"
            | "Session"
            | "Key"
            | "ALPC Port"
            | "EnergyTracker"
            | "PowerRequest"
            | "WmiGuid"
            | "EtwRegistration"
            | "EtwConsumer"
            | "FilterConnectionPort"
            | "FilterCommunicationPort"
            | "PcwObject"
    )
}

fn object_display_name(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    object: u64,
    object_type: &str,
) -> Result<Option<String>> {
    match object_type {
        "File" => {
            let offset = profile.type_field("_FILE_OBJECT", "FileName")?.offset;
            Ok(Some(read_unicode_string(
                space,
                object + offset,
                32 * 1024,
            )?))
        }
        "Process" => {
            let offset = profile.field("ImageFileName")?.offset;
            let length = profile.field("ImageFileName")?.size.unwrap_or(15) as usize;
            let mut bytes = vec![0u8; length];
            space.read_virtual(object + offset, &mut bytes)?;
            let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(length);
            Ok(Some(String::from_utf8_lossy(&bytes[..end]).into_owned()))
        }
        _ => Ok(None),
    }
}

fn infer_handle_object_type(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    object: u64,
    processes: &super::ProcessListReport,
) -> Option<String> {
    if processes
        .processes
        .iter()
        .any(|process| process.eprocess == object)
    {
        return Some("Process".to_owned());
    }

    let expected_size = profile.type_layout("_FILE_OBJECT").ok()?.size;
    let type_offset = profile.type_field("_FILE_OBJECT", "Type").ok()?.offset;
    let size_offset = profile.type_field("_FILE_OBJECT", "Size").ok()?.offset;
    let device_offset = profile
        .type_field("_FILE_OBJECT", "DeviceObject")
        .ok()?
        .offset;
    let section_offset = profile
        .type_field("_FILE_OBJECT", "SectionObjectPointer")
        .ok()?
        .offset;
    let name_offset = profile.type_field("_FILE_OBJECT", "FileName").ok()?.offset;
    if read_u16(space, object + type_offset).ok() != Some(5) {
        return None;
    }
    let actual_size = u64::from(read_u16(space, object + size_offset).ok()?);
    if actual_size < expected_size || actual_size > expected_size.saturating_add(0x100) {
        return None;
    }
    let valid_pointer = |pointer: u64| pointer == 0 || is_kernel_pointer(pointer);
    if !valid_pointer(space.read_u64(object + device_offset).ok()?)
        || !valid_pointer(space.read_u64(object + section_offset).ok()?)
        || read_unicode_string(space, object + name_offset, 32 * 1024).is_err()
    {
        return None;
    }
    Some("File".to_owned())
}

fn sign_extend_48(address: u64) -> u64 {
    if address & (1 << 47) != 0 {
        address | 0xffff_0000_0000_0000
    } else {
        address
    }
}

fn is_kernel_pointer(address: u64) -> bool {
    address >> 48 == 0xffff && address & 7 == 0
}

fn push_warning_limited(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 64 {
        warnings.push(warning);
    }
}

fn read_u8(space: &X64AddressSpace<'_>, address: u64) -> Result<u8> {
    let mut bytes = [0u8; 1];
    space.read_virtual(address, &mut bytes)?;
    Ok(bytes[0])
}

fn read_u16(space: &X64AddressSpace<'_>, address: u64) -> Result<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(space: &X64AddressSpace<'_>, address: u64) -> Result<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_unicode_string(
    space: &X64AddressSpace<'_>,
    descriptor: u64,
    max_bytes: usize,
) -> Result<String> {
    let mut header = [0u8; 16];
    space.read_virtual(descriptor, &mut header)?;
    let length = usize::from(u16::from_le_bytes([header[0], header[1]]));
    let maximum = usize::from(u16::from_le_bytes([header[2], header[3]]));
    ensure!(length <= maximum, "UNICODE_STRING 长度超过 MaximumLength");
    ensure!(length <= max_bytes, "UNICODE_STRING 长度超过安全上限");
    ensure!(length.is_multiple_of(2), "UNICODE_STRING 的字节长度为奇数");
    if length == 0 {
        return Ok(String::new());
    }
    let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap());
    ensure!(buffer != 0, "UNICODE_STRING 的缓冲区指针为空");
    let mut bytes = vec![0u8; length];
    space.read_virtual(buffer, &mut bytes)?;
    let utf16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&utf16))
}

fn protection_name(protection: u8) -> &'static str {
    const BASE: [&str; 8] = [
        "NOACCESS",
        "READONLY",
        "EXECUTE",
        "EXECUTE_READ",
        "READWRITE",
        "WRITECOPY",
        "EXECUTE_READWRITE",
        "EXECUTE_WRITECOPY",
    ];
    BASE[usize::from(protection & 7)]
}

#[cfg(test)]
#[path = "plugins/vad_tests.rs"]
mod vad_tests;

#[cfg(test)]
mod handle_owner_tests {
    use super::handle_owner_process_source_complete;

    #[test]
    fn process_enumeration_warning_makes_owner_universe_incomplete() {
        assert!(handle_owner_process_source_complete(true, 0));
        assert!(!handle_owner_process_source_complete(true, 1));
        assert!(!handle_owner_process_source_complete(false, 0));
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;

    fn network_record(
        pool_tag: &str,
        pid: u64,
        protocol: &str,
        local_port: u16,
        remote_address: &str,
        remote_port: Option<u16>,
    ) -> NetworkRecord {
        NetworkRecord {
            physical_address: 0,
            pool_tag: pool_tag.to_owned(),
            protocol: protocol.to_owned(),
            address_family: 2,
            local_address: "192.168.60.150".to_owned(),
            local_port,
            remote_address: remote_address.to_owned(),
            remote_port,
            state: Some("ESTABLISHED".to_owned()),
            pid,
            process: "spoolsv.exe".to_owned(),
            owner_offset: None,
            owner_resolution: "测试".to_owned(),
        }
    }

    const WIN7_TCP_ENDPOINT: TcpEndpointLayout = TcpEndpointLayout {
        inetaf: 0x18,
        addrinfo: 0x20,
        state: 0x68,
        local_port: 0x6c,
        remote_port: 0x6e,
    };

    #[test]
    fn parses_win7_tcp_endpoint_fields_without_using_owner_offset() {
        let mut bytes = [0u8; 0x240];
        bytes[0x18..0x20].copy_from_slice(&0xffff_fa80_1900_9370u64.to_le_bytes());
        bytes[0x20..0x28].copy_from_slice(&0xffff_fa80_1ad3_bd80u64.to_le_bytes());
        bytes[0x68..0x6c].copy_from_slice(&4u32.to_le_bytes());
        bytes[0x6c..0x6e].copy_from_slice(&49_257u16.to_be_bytes());
        bytes[0x6e..0x70].copy_from_slice(&4_444u16.to_be_bytes());
        // The owning EPROCESS is deliberately far from the decoded fields.
        bytes[0x238..0x240].copy_from_slice(&0xffff_fa80_1a65_1b30u64.to_le_bytes());

        assert_eq!(
            tcp_endpoint_fields(&bytes, WIN7_TCP_ENDPOINT),
            Some(TcpEndpointFields {
                inetaf: 0xffff_fa80_1900_9370,
                addrinfo: 0xffff_fa80_1ad3_bd80,
                state: 4,
                local_port: 49_257,
                remote_port: Some(4_444),
            })
        );
    }

    #[test]
    fn rejects_invalid_tcp_endpoint_state() {
        let mut bytes = [0u8; 0x240];
        bytes[0x18..0x20].copy_from_slice(&0xffff_fa80_1900_9370u64.to_le_bytes());
        bytes[0x20..0x28].copy_from_slice(&0xffff_fa80_1ad3_bd80u64.to_le_bytes());
        bytes[0x68..0x6c].copy_from_slice(&99u32.to_le_bytes());
        bytes[0x6c..0x6e].copy_from_slice(&49_257u16.to_be_bytes());

        assert_eq!(tcp_endpoint_fields(&bytes, WIN7_TCP_ENDPOINT), None);
    }

    #[test]
    fn parses_build_26200_ttcb_fields() {
        let mut bytes = [0u8; 0x250];
        bytes[0x18..0x20].copy_from_slice(&0xffff_a98c_e61e_c280u64.to_le_bytes());
        bytes[0x20..0x28].copy_from_slice(&0xffff_a98c_f3a8_7740u64.to_le_bytes());
        bytes[0x70..0x74].copy_from_slice(&7u32.to_le_bytes());
        bytes[0x74..0x76].copy_from_slice(&10_549u16.to_be_bytes());
        bytes[0x76..0x78].copy_from_slice(&443u16.to_be_bytes());

        assert_eq!(
            ttcb_endpoint_fields(&bytes),
            Some(TtcbEndpointFields {
                inetaf: 0xffff_a98c_e61e_c280,
                address_pair: 0xffff_a98c_f3a8_7740,
                state: 7,
                local_port: 10_549,
                remote_port: Some(443),
            })
        );
    }

    #[test]
    fn merges_weak_tcp_companion_when_complete_endpoint_exists() {
        let mut records = vec![
            network_record("TcpE", 828, "TCP", 49_257, "0.0.0.0", None),
            network_record("TcpE", 828, "TCP", 49_257, "192.168.60.169", Some(4_444)),
        ];

        assert_eq!(merge_weak_tcp_companions(&mut records), 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].remote_address, "192.168.60.169");
        assert_eq!(records[0].remote_port, Some(4_444));
    }

    #[test]
    fn retains_lone_weak_tcp_endpoint() {
        let mut records = vec![network_record("TcpE", 828, "TCP", 49_257, "0.0.0.0", None)];

        assert_eq!(merge_weak_tcp_companions(&mut records), 0);
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn retains_listener_and_unrelated_process_records() {
        let mut listener = network_record("TcpL", 828, "TCP", 49_257, "0.0.0.0", None);
        listener.state = Some("LISTENING".to_owned());
        let mut records = vec![
            listener,
            network_record("TcpE", 900, "TCP", 49_257, "0.0.0.0", None),
            network_record("TcpE", 828, "TCP", 49_257, "192.168.60.169", Some(4_444)),
        ];

        assert_eq!(merge_weak_tcp_companions(&mut records), 0);
        assert_eq!(records.len(), 3);
    }
}
