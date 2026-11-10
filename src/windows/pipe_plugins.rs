use std::collections::{HashMap, HashSet};
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::WindowsKernelContext;
use super::files::scan_files;
use super::plugins::find_handle_owners;
use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;

#[derive(Debug, Clone)]
pub struct PipeScanOptions {
    pub file_limit: usize,
    pub process_limit: usize,
    pub handle_scan_limit: usize,
    pub limit: usize,
}

impl Default for PipeScanOptions {
    fn default() -> Self {
        Self {
            file_limit: 1_000_000,
            process_limit: 65_536,
            handle_scan_limit: 4_000_000,
            limit: 100_000,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PipeOwnerRecord {
    pub pid: u64,
    pub process: String,
    pub handle: u32,
    pub handle_table_entry: u64,
    pub object_header: u64,
    pub granted_access: u32,
}

#[derive(Debug, Serialize)]
pub struct PipeScanRecord {
    pub file_object: u64,
    pub physical_address: u64,
    pub object_header: u64,
    pub raw_name: String,
    pub name: String,
    pub full_name: String,
    pub device_object: u64,
    pub driver_object: u64,
    pub driver_name: String,
    pub flags: u32,
    pub delete_pending: bool,
    pub object_type_verified: bool,
    pub endpoint_state: String,
    pub owners: Vec<PipeOwnerRecord>,
}

#[derive(Debug, Serialize)]
pub struct PipeScanReport {
    pub records: Vec<PipeScanRecord>,
    pub complete: bool,
    pub file_objects_examined: usize,
    pub device_objects_examined: usize,
    pub named_pipe_objects_found: usize,
    pub active_endpoint_count: usize,
    pub residual_endpoint_count: usize,
    pub processes_examined: usize,
    pub handle_entries_examined: usize,
    pub correlated_handle_count: usize,
    pub file_pool_tag_hits: usize,
    pub scan_seconds: f64,
    pub scope: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct NpfsDeviceEvidence {
    driver_object: u64,
    driver_name: String,
}

pub fn scan_pipes(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &PipeScanOptions,
) -> Result<PipeScanReport> {
    ensure!(
        !kernel.is_x86_pae(),
        "pipescan 当前需要 64 位 Windows 内存镜像"
    );
    ensure!(options.file_limit > 0, "FILE_OBJECT 扫描上限必须大于零");
    ensure!(options.process_limit > 0, "进程扫描上限必须大于零");
    ensure!(options.handle_scan_limit > 0, "句柄扫描上限必须大于零");
    ensure!(options.limit > 0, "命名管道结果上限必须大于零");

    // Resolve all required fields before starting the expensive physical scan,
    // so an incompatible profile fails immediately and explicitly.
    profile.type_layout("_DEVICE_OBJECT")?;
    profile.type_field("_DEVICE_OBJECT", "Type")?;
    profile.type_field("_DEVICE_OBJECT", "Size")?;
    profile.type_field("_DEVICE_OBJECT", "DriverObject")?;
    profile.type_layout("_DRIVER_OBJECT")?;
    profile.type_field("_DRIVER_OBJECT", "Type")?;
    profile.type_field("_DRIVER_OBJECT", "Size")?;
    profile.type_field("_DRIVER_OBJECT", "DriverName")?;

    let started = Instant::now();
    let file_report = scan_files(image, kernel, profile, options.file_limit)?;
    let file_objects_examined = file_report.records.len();
    let file_pool_tag_hits = file_report.pool_tag_hits;
    let mut complete = file_report.complete;
    let mut warnings = file_report
        .warnings
        .into_iter()
        .map(|warning| format!("FILE_OBJECT 扫描：{warning}"))
        .collect::<Vec<_>>();
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut device_cache: HashMap<u64, Option<NpfsDeviceEvidence>> = HashMap::new();
    let mut records = Vec::new();

    for file in file_report.records {
        let Some(raw_name) = file.name.filter(|name| !name.trim_matches('\0').is_empty()) else {
            continue;
        };
        let evidence = device_cache
            .entry(file.device_object)
            .or_insert_with(|| validate_npfs_device(&space, profile, file.device_object));
        let Some(evidence) = evidence.clone() else {
            continue;
        };
        let Some((name, full_name)) = normalize_pipe_name(&raw_name) else {
            continue;
        };
        records.push(PipeScanRecord {
            file_object: file.file_object,
            physical_address: file.physical_address,
            object_header: file.object_header,
            raw_name,
            name,
            full_name,
            device_object: file.device_object,
            driver_object: evidence.driver_object,
            driver_name: evidence.driver_name,
            flags: file.flags,
            delete_pending: file.delete_pending,
            object_type_verified: file.object_type_verified,
            endpoint_state: "residual_pool_object".to_owned(),
            owners: Vec::new(),
        });
    }

    let named_pipe_objects_found = records.len();
    let targets = records
        .iter()
        .map(|record| record.file_object)
        .collect::<HashSet<_>>();
    let owner_report = find_handle_owners(
        image,
        kernel,
        profile,
        &targets,
        options.process_limit,
        options.handle_scan_limit,
    )?;
    complete &= owner_report.complete;
    warnings.extend(
        owner_report
            .warnings
            .iter()
            .map(|warning| format!("句柄关联：{warning}")),
    );
    let processes_examined = owner_report.processes_examined;
    let handle_entries_examined = owner_report.handle_entries_examined;
    let correlated_handle_count = owner_report.records.len();
    let mut owners_by_object: HashMap<u64, Vec<PipeOwnerRecord>> = HashMap::new();
    for owner in owner_report.records {
        owners_by_object
            .entry(owner.object)
            .or_default()
            .push(PipeOwnerRecord {
                pid: owner.pid,
                process: owner.process,
                handle: owner.handle,
                handle_table_entry: owner.entry,
                object_header: owner.object_header,
                granted_access: owner.granted_access,
            });
    }
    for record in &mut records {
        if let Some(owners) = owners_by_object.remove(&record.file_object) {
            record.endpoint_state = "active_handle".to_owned();
            record.owners = owners;
        }
    }
    records.sort_unstable_by(|left, right| {
        left.full_name
            .to_ascii_lowercase()
            .cmp(&right.full_name.to_ascii_lowercase())
            .then_with(|| left.file_object.cmp(&right.file_object))
    });
    let active_endpoint_count = records
        .iter()
        .filter(|record| !record.owners.is_empty())
        .count();
    let residual_endpoint_count = records.len().saturating_sub(active_endpoint_count);
    if records.len() > options.limit {
        records.truncate(options.limit);
        complete = false;
        warnings.push(format!(
            "命名管道结果达到 {} 条上限；统计值仍对应截断前结果",
            options.limit
        ));
    }

    Ok(PipeScanReport {
        records,
        complete,
        file_objects_examined,
        device_objects_examined: device_cache.len(),
        named_pipe_objects_found,
        active_endpoint_count,
        residual_endpoint_count,
        processes_examined,
        handle_entries_examined,
        correlated_handle_count,
        file_pool_tag_hits,
        scan_seconds: started.elapsed().as_secs_f64(),
        scope: "仅报告由 FILE_OBJECT.DeviceObject → DEVICE_OBJECT.DriverObject → \\FileSystem\\Npfs 结构链验证的命名管道；active_handle 表示仍被活动进程句柄引用，residual_pool_object 仅表示池中残留，不能据此认定仍活动。".to_owned(),
        warnings,
    })
}

fn validate_npfs_device(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    device_object: u64,
) -> Option<NpfsDeviceEvidence> {
    if !is_kernel_pointer(device_object) {
        return None;
    }
    let device_size = profile.type_layout("_DEVICE_OBJECT").ok()?.size;
    if type_u16(space, profile, "_DEVICE_OBJECT", device_object, "Type") != Some(3)
        || type_u16(space, profile, "_DEVICE_OBJECT", device_object, "Size")
            .is_none_or(|size| u64::from(size) < device_size)
    {
        return None;
    }
    let driver_object = type_u64(
        space,
        profile,
        "_DEVICE_OBJECT",
        device_object,
        "DriverObject",
    )?;
    if !is_kernel_pointer(driver_object) {
        return None;
    }
    let driver_size = profile.type_layout("_DRIVER_OBJECT").ok()?.size;
    if type_u16(space, profile, "_DRIVER_OBJECT", driver_object, "Type") != Some(4)
        || type_u16(space, profile, "_DRIVER_OBJECT", driver_object, "Size")
            .is_none_or(|size| u64::from(size) < driver_size)
    {
        return None;
    }
    let name_field = profile
        .type_field("_DRIVER_OBJECT", "DriverName")
        .ok()?
        .offset;
    let driver_name = read_unicode_string(space, driver_object + name_field, 4096).ok()?;
    if !is_npfs_driver_name(&driver_name) {
        return None;
    }
    Some(NpfsDeviceEvidence {
        driver_object,
        driver_name,
    })
}

fn normalize_pipe_name(raw_name: &str) -> Option<(String, String)> {
    let raw_name = raw_name.trim_matches('\0').trim();
    if raw_name.is_empty() {
        return None;
    }
    let lower = raw_name.to_ascii_lowercase();
    let name = if lower == r"\device\namedpipe" || lower == r"\namedpipe" {
        return None;
    } else if lower.starts_with(r"\device\namedpipe\") {
        raw_name[r"\Device\NamedPipe\".len()..].to_owned()
    } else if lower.starts_with(r"\namedpipe\") {
        raw_name[r"\NamedPipe\".len()..].to_owned()
    } else {
        raw_name.trim_start_matches('\\').to_owned()
    };
    (!name.is_empty()).then(|| {
        let full_name = format!(r"\Device\NamedPipe\{name}");
        (name, full_name)
    })
}

fn is_npfs_driver_name(name: &str) -> bool {
    name.rsplit(['\\', '/'])
        .find(|component| !component.is_empty())
        .is_some_and(|component| component.eq_ignore_ascii_case("npfs"))
}

fn type_u16(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    address: u64,
    field_name: &str,
) -> Option<u16> {
    let offset = profile.type_field(type_name, field_name).ok()?.offset;
    read_u16(space, address.checked_add(offset)?)
}

fn type_u64(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    address: u64,
    field_name: &str,
) -> Option<u64> {
    let offset = profile.type_field(type_name, field_name).ok()?.offset;
    space.read_u64(address.checked_add(offset)?).ok()
}

fn read_u16(space: &X64AddressSpace<'_>, address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u16::from_le_bytes(bytes))
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
    ensure!(length.is_multiple_of(2), "UNICODE_STRING 字节长度为奇数");
    if length == 0 {
        return Ok(String::new());
    }
    let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap());
    ensure!(
        is_kernel_pointer(buffer),
        "UNICODE_STRING 缓冲区不是内核指针"
    );
    let mut bytes = vec![0u8; length];
    space
        .read_virtual(buffer, &mut bytes)
        .context("无法读取 UNICODE_STRING 缓冲区")?;
    let utf16 = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    Ok(String::from_utf16_lossy(&utf16))
}

fn is_kernel_pointer(address: u64) -> bool {
    address >> 48 == 0xffff && address & 7 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_only_npfs_driver_basename() {
        assert!(is_npfs_driver_name(r"\FileSystem\Npfs"));
        assert!(is_npfs_driver_name("NPFS"));
        assert!(!is_npfs_driver_name(r"\Driver\Npf"));
        assert!(!is_npfs_driver_name(r"\FileSystem\NpfsExtra"));
    }

    #[test]
    fn normalizes_relative_and_device_pipe_names() {
        assert_eq!(
            normalize_pipe_name(r"\wkssvc"),
            Some(("wkssvc".to_owned(), r"\Device\NamedPipe\wkssvc".to_owned()))
        );
        assert_eq!(
            normalize_pipe_name(r"\Device\NamedPipe\srvsvc"),
            Some(("srvsvc".to_owned(), r"\Device\NamedPipe\srvsvc".to_owned()))
        );
        assert_eq!(normalize_pipe_name(r"\Device\NamedPipe"), None);
    }
}
