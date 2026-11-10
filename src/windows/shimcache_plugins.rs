use std::collections::{HashMap, HashSet};

use anyhow::{Result, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use super::WindowsKernelContext;
use super::plugins::list_drivers;
use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;

const AVL_TABLE_SIZE: u64 = 104;
const MAX_HANDLES: usize = 256;
const MAX_ENTRIES: usize = 1_000_000;

#[derive(Debug, Serialize)]
pub struct ShimcacheReport {
    pub records: Vec<ShimcacheRecord>,
    pub module_base: u64,
    pub module_size: u32,
    pub handle_candidates: usize,
    pub pointer_candidates: usize,
    pub readable_handle_pairs: usize,
    pub avl_root_matches: usize,
    pub routine_range_matches: usize,
    pub structural_handles: Vec<ShimHandleEvidence>,
    pub selected_handle: Option<u64>,
    pub selected_avl_table: Option<u64>,
    pub declared_elements: Option<u32>,
    pub bytes_examined: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShimcacheRecord {
    pub order: usize,
    pub entry: u64,
    pub path: String,
    pub last_modified_raw: Option<u64>,
    pub last_modified: Option<String>,
    pub executed: Option<bool>,
    pub blob_size: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ShimHandleEvidence {
    pub handle: u64,
    pub avl: u64,
    pub declared: Option<u32>,
    pub depth: Option<u32>,
    pub head: u64,
    pub first: Option<u64>,
    pub last: Option<u64>,
    pub first_flink: Option<u64>,
    pub first_blink: Option<u64>,
    pub first_path_length: Option<u16>,
    pub first_path_buffer: Option<u64>,
    pub first_path: Option<String>,
}

struct HandleCandidate {
    handle: u64,
    avl: u64,
    declared: u32,
    records: Vec<ShimcacheRecord>,
    complete: bool,
}

pub fn shimcache_memory(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<ShimcacheReport> {
    ensure!(limit > 0, "Shimcache 结果上限必须大于零");
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let modules = list_drivers(image, kernel, profile, 65_536)?;
    let modern_module = modules
        .records
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case("ahcache.sys"));
    let Some(module) = modern_module else {
        let kernel_module = modules.records.iter().find(|module| {
            [
                "ntoskrnl.exe",
                "ntkrnlpa.exe",
                "ntkrnlmp.exe",
                "ntkrpamp.exe",
            ]
            .iter()
            .any(|name| module.name.eq_ignore_ascii_case(name))
        });
        let Some(kernel_module) = kernel_module else {
            return Ok(empty_report(
                modules.warnings,
                "模块列表中既没有 ahcache.sys，也没有可识别的 NT 内核映像，无法定位内存 Shimcache"
                    .to_owned(),
            ));
        };
        return scan_legacy_kernel_cache(
            &space,
            kernel_module.base,
            kernel_module.size,
            modules.complete,
            modules.warnings,
            limit,
        );
    };
    let module_end = module.base.saturating_add(u64::from(module.size));
    let mut bytes_examined = 0u64;
    let mut missing_bytes = 0u64;
    let mut handle_addresses = HashSet::new();
    let mut address = module.base;
    while address < module_end {
        let count = (module_end - address).min(0x1000 - (address & 0xfff)) as usize;
        let mut page = [0u8; 0x1000];
        if space.read_virtual(address, &mut page[..count]).is_ok() {
            bytes_examined += count as u64;
            let alignment = (8 - (address & 7)) & 7;
            for offset in (alignment as usize..count.saturating_sub(7)).step_by(8) {
                let pointer = u64::from_le_bytes(page[offset..offset + 8].try_into().unwrap());
                if is_kernel_pointer(pointer) {
                    handle_addresses.insert(pointer);
                }
            }
        } else {
            missing_bytes += count as u64;
        }
        address += count as u64;
    }

    let mut candidates = HashMap::<u64, HandleCandidate>::new();
    let pointer_candidates = handle_addresses.len();
    let mut readable_handle_pairs = 0usize;
    let mut avl_root_matches = 0usize;
    let mut routine_range_matches = 0usize;
    let mut structural_handles = Vec::new();
    for handle in handle_addresses.into_iter().take(2_000_000) {
        if candidates.len() == MAX_HANDLES {
            break;
        }
        let (Ok(resource), Ok(avl)) = (space.read_u64(handle), space.read_u64(handle + 8)) else {
            continue;
        };
        if !is_kernel_pointer(resource) || !is_kernel_pointer(avl) {
            continue;
        }
        readable_handle_pairs += 1;
        if space.read_u64(avl).ok() != Some(avl) {
            continue;
        }
        avl_root_matches += 1;
        let head = avl + AVL_TABLE_SIZE;
        let first = space.read_u64(head).ok();
        structural_handles.push(ShimHandleEvidence {
            handle,
            avl,
            declared: read_u32(&space, avl + 44),
            depth: read_u32(&space, avl + 48),
            head,
            first,
            last: space.read_u64(head + 8).ok(),
            first_flink: first.and_then(|first| space.read_u64(first).ok()),
            first_blink: first.and_then(|first| space.read_u64(first + 8).ok()),
            first_path_length: first.and_then(|first| read_u16(&space, first + 24)),
            first_path_buffer: first.and_then(|first| space.read_u64(first + 32).ok()),
            first_path: first.and_then(|first| read_unicode_string(&space, first + 24, 32 * 1024)),
        });
        let routines = [72u64, 80, 88]
            .into_iter()
            .filter_map(|offset| space.read_u64(avl + offset).ok())
            .collect::<Vec<_>>();
        if routines.len() == 3
            && routines
                .iter()
                .all(|routine| in_module(*routine, module.base, module_end))
        {
            routine_range_matches += 1;
        }
        let Some(candidate) = parse_handle(&space, handle, module.base, module_end, limit) else {
            continue;
        };
        candidates.entry(candidate.avl).or_insert(candidate);
    }
    let handle_candidates = candidates.len();
    let selected = candidates.into_values().max_by(|left, right| {
        left.records
            .len()
            .cmp(&right.records.len())
            .then_with(|| left.declared.cmp(&right.declared))
    });
    let mut warnings = modules.warnings;
    let mut complete = modules.complete && missing_bytes == 0;
    if missing_bytes != 0 {
        warnings.push(format!(
            "定位 SHIM_CACHE_HANDLE 指针时，ahcache.sys 中有 {missing_bytes} 字节不可用"
        ));
    }
    let (records, selected_handle, selected_avl_table, declared_elements) = if let Some(selected) =
        selected
    {
        complete &= selected.complete;
        (
            selected.records,
            Some(selected.handle),
            Some(selected.avl),
            Some(selected.declared),
        )
    } else {
        complete = false;
        warnings.push("没有从 ahcache.sys 恢复出结构有效的 SHIM_CACHE_HANDLE/AVL 链表".to_owned());
        (Vec::new(), None, None, None)
    };
    Ok(ShimcacheReport {
        records,
        module_base: module.base,
        module_size: module.size,
        handle_candidates,
        pointer_candidates,
        readable_handle_pairs,
        avl_root_matches,
        routine_range_matches,
        structural_handles,
        selected_handle,
        selected_avl_table,
        declared_elements,
        bytes_examined,
        missing_bytes,
        complete,
        warnings,
    })
}

fn scan_legacy_kernel_cache(
    space: &X64AddressSpace<'_>,
    module_base: u64,
    module_size: u32,
    modules_complete: bool,
    mut warnings: Vec<String>,
    limit: usize,
) -> Result<ShimcacheReport> {
    let module_end = module_base.saturating_add(u64::from(module_size));
    let data = pe_section_range(space, module_base, module_end, b".data");
    let page = pe_section_range(space, module_base, module_end, b"PAGE");
    let (Some((data_start, data_end)), Some((page_start, page_end))) = (data, page) else {
        warnings.push(
            "NT 内核映像缺少可验证的 .data 或 PAGE 节，无法定位旧式内存 Shimcache".to_owned(),
        );
        return Ok(ShimcacheReport {
            records: Vec::new(),
            module_base,
            module_size,
            handle_candidates: 0,
            pointer_candidates: 0,
            readable_handle_pairs: 0,
            avl_root_matches: 0,
            routine_range_matches: 0,
            structural_handles: Vec::new(),
            selected_handle: None,
            selected_avl_table: None,
            declared_elements: None,
            bytes_examined: 0,
            missing_bytes: 0,
            complete: false,
            warnings,
        });
    };

    let mut candidates = Vec::new();
    let mut structural_handles = Vec::new();
    let mut avl_root_matches = 0usize;
    let mut routine_range_matches = 0usize;
    let mut missing_bytes = 0u64;
    let first = (data_start + 7) & !7;
    for avl in (first..data_end.saturating_sub(AVL_TABLE_SIZE)).step_by(8) {
        let Ok(root_parent) = space.read_u64(avl) else {
            missing_bytes = missing_bytes.saturating_add(8);
            continue;
        };
        if root_parent != avl {
            continue;
        }
        avl_root_matches += 1;
        let routines = [72u64, 80, 88]
            .into_iter()
            .filter_map(|offset| space.read_u64(avl + offset).ok())
            .collect::<Vec<_>>();
        if routines.len() != 3
            || !routines
                .iter()
                .all(|routine| in_module(*routine, page_start, page_end))
            || routines[0] == routines[1]
            || routines[0] == routines[2]
            || routines[1] == routines[2]
        {
            continue;
        }
        routine_range_matches += 1;
        let Some(candidate) = parse_legacy_avl(space, avl, limit) else {
            continue;
        };
        let head = avl + AVL_TABLE_SIZE;
        let first = space.read_u64(head).ok();
        structural_handles.push(ShimHandleEvidence {
            handle: avl,
            avl,
            declared: Some(candidate.declared),
            depth: read_u32(space, avl + 48),
            head,
            first,
            last: space.read_u64(head + 8).ok(),
            first_flink: first.and_then(|entry| space.read_u64(entry).ok()),
            first_blink: first.and_then(|entry| space.read_u64(entry + 8).ok()),
            first_path_length: first.and_then(|entry| read_u16(space, entry + 16)),
            first_path_buffer: first.and_then(|entry| space.read_u64(entry + 24).ok()),
            first_path: first.and_then(|entry| read_unicode_string(space, entry + 16, 32 * 1024)),
        });
        candidates.push(candidate);
    }

    let selected = candidates.into_iter().max_by(|left, right| {
        left.records
            .len()
            .cmp(&right.records.len())
            .then_with(|| left.declared.cmp(&right.declared))
    });
    let handle_candidates = structural_handles.len();
    let mut complete = modules_complete && missing_bytes == 0;
    if missing_bytes != 0 {
        warnings.push(format!(
            "扫描 NT 内核 .data 节时有 {missing_bytes} 字节不可用"
        ));
    }
    let (records, selected_avl_table, declared_elements) = if let Some(selected) = selected {
        complete &= selected.complete;
        (
            selected.records,
            Some(selected.avl),
            Some(selected.declared),
        )
    } else {
        complete = false;
        warnings
            .push("没有从 NT 内核 .data 节恢复出结构有效的旧式 Shimcache AVL/LRU 链表".to_owned());
        (Vec::new(), None, None)
    };

    Ok(ShimcacheReport {
        records,
        module_base,
        module_size,
        handle_candidates,
        pointer_candidates: 0,
        readable_handle_pairs: 0,
        avl_root_matches,
        routine_range_matches,
        structural_handles,
        selected_handle: None,
        selected_avl_table,
        declared_elements,
        bytes_examined: data_end.saturating_sub(data_start),
        missing_bytes,
        complete,
        warnings,
    })
}

fn parse_legacy_avl(
    space: &X64AddressSpace<'_>,
    avl: u64,
    limit: usize,
) -> Option<HandleCandidate> {
    let declared = read_u32(space, avl + 44)?;
    let depth = read_u32(space, avl + 48)?;
    if declared > MAX_ENTRIES as u32 || depth > 64 {
        return None;
    }
    let head = avl + AVL_TABLE_SIZE;
    let mut current = space.read_u64(head).ok()?;
    let head_blink = space.read_u64(head + 8).ok()?;
    if !is_kernel_pointer(current) || !is_kernel_pointer(head_blink) {
        return None;
    }
    let mut previous = head;
    let mut visited = HashSet::new();
    let mut records = Vec::new();
    let mut complete = true;
    while current != head && records.len() < limit {
        if !is_kernel_pointer(current) || !visited.insert(current) {
            complete = false;
            break;
        }
        let next = space.read_u64(current).ok()?;
        let blink = space.read_u64(current + 8).ok()?;
        if blink != previous || !is_kernel_pointer(next) {
            return None;
        }
        let path = read_unicode_string(space, current + 16, 32 * 1024)?;
        if !plausible_path(&path) {
            return None;
        }
        let last_modified_raw = space
            .read_u64(current + 32)
            .ok()
            .filter(|value| *value != 0);
        let insert_flags = read_u32(space, current + 40);
        let blob_size = space
            .read_u64(current + 48)
            .ok()
            .and_then(|value| u32::try_from(value).ok());
        records.push(ShimcacheRecord {
            order: records.len(),
            entry: current,
            path,
            last_modified_raw,
            last_modified: last_modified_raw.and_then(filetime_to_rfc3339),
            executed: insert_flags.map(|flags| flags & 2 != 0),
            blob_size,
        });
        previous = current;
        current = next;
        if records.len() > declared as usize + 1024 {
            complete = false;
            break;
        }
    }
    if current != head {
        complete = false;
    } else if head_blink != previous {
        return None;
    }
    if records.is_empty() || (declared != 0 && records.len().abs_diff(declared as usize) > 1024) {
        return None;
    }
    Some(HandleCandidate {
        handle: avl,
        avl,
        declared,
        records,
        complete,
    })
}

fn pe_section_range(
    space: &X64AddressSpace<'_>,
    module_base: u64,
    module_end: u64,
    wanted: &[u8],
) -> Option<(u64, u64)> {
    let mut dos = [0u8; 0x40];
    space.read_virtual(module_base, &mut dos).ok()?;
    if &dos[..2] != b"MZ" {
        return None;
    }
    let pe_offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().ok()?) as u64;
    if pe_offset > 0x1000 {
        return None;
    }
    let mut file_header = [0u8; 24];
    space
        .read_virtual(module_base + pe_offset, &mut file_header)
        .ok()?;
    if &file_header[..4] != b"PE\0\0" {
        return None;
    }
    let section_count = u16::from_le_bytes(file_header[6..8].try_into().ok()?) as usize;
    let optional_size = u16::from_le_bytes(file_header[20..22].try_into().ok()?) as u64;
    if !(1..=96).contains(&section_count) || !(64..=0x1000).contains(&optional_size) {
        return None;
    }
    let section_table = module_base + pe_offset + 24 + optional_size;
    for index in 0..section_count {
        let mut section = [0u8; 40];
        space
            .read_virtual(section_table + index as u64 * 40, &mut section)
            .ok()?;
        let name_end = section[..8].iter().position(|byte| *byte == 0).unwrap_or(8);
        if &section[..name_end] != wanted {
            continue;
        }
        let virtual_size = u32::from_le_bytes(section[8..12].try_into().ok()?) as u64;
        let virtual_address = u32::from_le_bytes(section[12..16].try_into().ok()?) as u64;
        let raw_size = u32::from_le_bytes(section[16..20].try_into().ok()?) as u64;
        let start = module_base.checked_add(virtual_address)?;
        let end = start
            .checked_add(virtual_size.max(raw_size))?
            .min(module_end);
        if start < end && start >= module_base {
            return Some((start, end));
        }
    }
    None
}

fn empty_report(mut warnings: Vec<String>, warning: String) -> ShimcacheReport {
    warnings.push(warning);
    ShimcacheReport {
        records: Vec::new(),
        module_base: 0,
        module_size: 0,
        handle_candidates: 0,
        pointer_candidates: 0,
        readable_handle_pairs: 0,
        avl_root_matches: 0,
        routine_range_matches: 0,
        structural_handles: Vec::new(),
        selected_handle: None,
        selected_avl_table: None,
        declared_elements: None,
        bytes_examined: 0,
        missing_bytes: 0,
        complete: false,
        warnings,
    }
}

fn parse_handle(
    space: &X64AddressSpace<'_>,
    handle: u64,
    module_start: u64,
    module_end: u64,
    limit: usize,
) -> Option<HandleCandidate> {
    let resource = space.read_u64(handle).ok()?;
    let avl = space.read_u64(handle + 8).ok()?;
    if !is_kernel_pointer(resource) || !is_kernel_pointer(avl) {
        return None;
    }
    let root_parent = space.read_u64(avl).ok()?;
    let declared = read_u32(space, avl + 44)?;
    let depth = read_u32(space, avl + 48)?;
    let compare = space.read_u64(avl + 72).ok()?;
    let allocate = space.read_u64(avl + 80).ok()?;
    let free = space.read_u64(avl + 88).ok()?;
    if root_parent != avl
        || declared > MAX_ENTRIES as u32
        || depth > 64
        || !in_module(compare, module_start, module_end)
        || !in_module(allocate, module_start, module_end)
        || !in_module(free, module_start, module_end)
        || compare == allocate
        || compare == free
        || allocate == free
    {
        return None;
    }
    let head = avl + AVL_TABLE_SIZE;
    let mut current = space.read_u64(head).ok()?;
    let head_blink = space.read_u64(head + 8).ok()?;
    if !is_kernel_pointer(current) || !is_kernel_pointer(head_blink) {
        return None;
    }
    let mut previous = head;
    let mut visited = HashSet::new();
    let mut records = Vec::new();
    let mut complete = true;
    while current != head && records.len() < limit {
        if !is_kernel_pointer(current) || !visited.insert(current) {
            complete = false;
            break;
        }
        let next = match space.read_u64(current) {
            Ok(next) => next,
            Err(_) => {
                complete = false;
                break;
            }
        };
        let blink = space.read_u64(current + 8).ok()?;
        if blink != previous || !is_kernel_pointer(next) {
            complete = false;
            break;
        }
        let Some(path) = read_unicode_string(space, current + 24, 32 * 1024) else {
            complete = false;
            break;
        };
        if !plausible_path(&path) {
            complete = false;
            break;
        }
        let detail = space.read_u64(current + 40).ok();
        let last_modified_raw = detail
            .filter(|detail| is_kernel_pointer(*detail))
            .and_then(|detail| space.read_u64(detail + 8).ok())
            .filter(|value| *value != 0);
        let blob_size = detail.and_then(|detail| read_u32(space, detail + 16));
        let executed = detail.and_then(|detail| {
            let size = read_u32(space, detail + 16)?;
            let buffer = space.read_u64(detail + 24).ok()?;
            if !(4..=1024).contains(&size) || !is_kernel_pointer(buffer) {
                return None;
            }
            read_u32(space, buffer).map(|flag| flag != 0)
        });
        records.push(ShimcacheRecord {
            order: records.len(),
            entry: current,
            path,
            last_modified_raw,
            last_modified: last_modified_raw.and_then(filetime_to_rfc3339),
            executed,
            blob_size,
        });
        previous = current;
        current = next;
        if records.len() > declared as usize + 1024 {
            complete = false;
            break;
        }
    }
    if current == head && space.read_u64(head + 8).ok() != Some(previous) {
        complete = false;
    }
    if records.is_empty() || (declared != 0 && records.len().abs_diff(declared as usize) > 1024) {
        return None;
    }
    Some(HandleCandidate {
        handle,
        avl,
        declared,
        records,
        complete,
    })
}

fn read_unicode_string(
    space: &X64AddressSpace<'_>,
    address: u64,
    max_length: usize,
) -> Option<String> {
    let length = usize::from(read_u16(space, address)?);
    if length == 0 || length > max_length || length & 1 != 0 {
        return None;
    }
    let buffer = space.read_u64(address + 8).ok()?;
    if !is_kernel_pointer(buffer) {
        return None;
    }
    let mut bytes = vec![0u8; length];
    space.read_virtual(buffer, &mut bytes).ok()?;
    Some(String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    ))
}

fn plausible_path(path: &str) -> bool {
    let path = path.trim();
    !path.is_empty()
        && path.len() <= 16 * 1024
        && path.chars().all(|character| !character.is_control())
        && path.chars().any(|character| character.is_alphanumeric())
}

fn read_u16(space: &X64AddressSpace<'_>, address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(space: &X64AddressSpace<'_>, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn is_kernel_pointer(address: u64) -> bool {
    address >> 48 == 0xffff && address & 7 == 0
}

fn in_module(address: u64, start: u64, end: u64) -> bool {
    address >= start && address < end
}

fn filetime_to_rfc3339(value: u64) -> Option<String> {
    const WINDOWS_TO_UNIX_SECONDS: i128 = 11_644_473_600;
    let seconds = i128::from(value / 10_000_000) - WINDOWS_TO_UNIX_SECONDS;
    let nanos = u32::try_from((value % 10_000_000) * 100).ok()?;
    let seconds = i64::try_from(seconds).ok()?;
    DateTime::<Utc>::from_timestamp(seconds, nanos)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_full_paths_and_basenames() {
        assert!(plausible_path("\\??\\C:\\Windows\\notepad.exe"));
        assert!(plausible_path("notepad.exe"));
        assert!(!plausible_path("\t\t"));
    }
}
