use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{Result, ensure};
use serde::Serialize;

use super::plugins::{DriverRecord, list_drivers};
use super::system_plugins::{PoolAllocationRecord, scan_pool_allocations};
use super::{
    WindowsKernelContext, is_kernel_address, is_kernel_pointer, list_processes, read_unicode_string,
};
use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;

const MAX_POOL_OBJECTS: usize = 1_000_000;
const MAX_CALLBACK_CHAIN: usize = 65_536;

#[derive(Debug, Serialize)]
pub struct ModuleScanReport {
    pub records: Vec<ScannedModuleRecord>,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScannedModuleRecord {
    pub entry: u64,
    pub physical_address: u64,
    pub base: u64,
    pub size: u32,
    pub name: String,
    pub path: String,
    pub in_loaded_module_list: bool,
}

#[derive(Debug, Serialize)]
pub struct DriverScanReport {
    pub records: Vec<DriverObjectRecord>,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriverObjectRecord {
    pub driver_object: u64,
    pub physical_address: u64,
    pub name: String,
    pub driver_start: u64,
    pub driver_size: u32,
    pub driver_section: Option<u64>,
    pub device_object: Option<u64>,
    pub driver_extension: Option<u64>,
    pub driver_init: Option<u64>,
    pub driver_start_io: Option<u64>,
    pub driver_unload: Option<u64>,
    pub fast_io_dispatch: Option<u64>,
    pub major_functions: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct DriverModuleReport {
    pub records: Vec<DriverModuleRecord>,
    pub loaded_module_count: usize,
    pub driver_object_count: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriverModuleRecord {
    pub driver_object: u64,
    pub driver_name: String,
    pub driver_start: u64,
    pub driver_size: u32,
    pub module_entry: Option<u64>,
    pub module_name: Option<String>,
    pub module_path: Option<String>,
    pub exact_base_match: bool,
    pub suspicious_unbacked: bool,
}

#[derive(Debug, Serialize)]
pub struct DriverIrpReport {
    pub records: Vec<DriverIrpRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriverIrpRecord {
    pub driver_object: u64,
    pub driver_name: String,
    pub major_index: u8,
    pub major_name: String,
    pub routine: u64,
    pub module: Option<String>,
    pub inside_driver_image: bool,
    pub suspicious: bool,
}

#[derive(Debug, Serialize)]
pub struct DriverInspectReport {
    pub drivers: Vec<DriverInspectRecord>,
    pub devices: Vec<DeviceObjectRecord>,
    pub irp_dispatch: Vec<DriverIrpRecord>,
    pub fast_io_dispatch: Vec<DriverFastIoRecord>,
    pub loaded_module_count: usize,
    pub driver_object_count: usize,
    pub matched_driver_count: usize,
    pub attention_driver_count: usize,
    pub suspicious_driver_count: usize,
    pub fast_io_available: bool,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriverInspectRecord {
    pub driver_object: u64,
    pub physical_address: u64,
    pub name: String,
    pub driver_start: u64,
    pub driver_size: u32,
    pub module_entry: Option<u64>,
    pub module_name: Option<String>,
    pub module_path: Option<String>,
    pub module_status: String,
    pub path_status: String,
    /// A memory image cannot prove the current on-disk file or its signature.
    pub file_status: String,
    pub triage_attention: bool,
    pub triage_reasons: Vec<String>,
    pub exact_base_match: bool,
    pub suspicious_unbacked: bool,
    pub device_count: usize,
    pub distinct_irp_routine_count: usize,
    pub suspicious_irp_count: usize,
    pub fast_io_dispatch: Option<u64>,
    pub fast_io_implemented_count: usize,
    pub suspicious_fast_io_count: usize,
}

#[derive(Debug, Serialize)]
pub struct DriverFastIoRecord {
    pub driver_object: u64,
    pub driver_name: String,
    pub dispatch_table: u64,
    pub function_name: String,
    pub routine: u64,
    pub implemented: bool,
    pub module: Option<String>,
    pub inside_driver_image: bool,
    pub suspicious: bool,
}

#[derive(Debug, Serialize)]
pub struct DeviceTreeReport {
    pub records: Vec<DeviceObjectRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceObjectRecord {
    pub driver_object: u64,
    pub driver_name: String,
    pub device_object: u64,
    pub next_device: Option<u64>,
    pub attached_device: Option<u64>,
    pub device_type: Option<u32>,
    pub flags: Option<u32>,
    pub characteristics: Option<u32>,
    pub stack_size: Option<u8>,
    pub device_extension: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct CallbackReport {
    pub records: Vec<CallbackRecord>,
    pub sources: Vec<CallbackSourceStatus>,
    pub evidence_observations: usize,
    pub unique_callback_count: usize,
    pub unique_registration_count: usize,
    pub pool_only_candidate_count: usize,
    pub records_retained: usize,
    pub duplicate_evidence_merged: usize,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub pool_candidates: usize,
    pub missing_pages: usize,
    pub missing_bytes: u64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CallbackRecord {
    pub kind: String,
    pub index: u32,
    pub callback_block: u64,
    pub routine: u64,
    pub context: Option<u64>,
    pub detail: Option<String>,
    pub source: String,
    pub evidence_sources: Vec<String>,
    pub evidence_kinds: Vec<String>,
    pub pool_tag: Option<String>,
    pub pool_tags: Vec<String>,
    pub corroborated_by_pool: bool,
    pub registration_status: String,
    pub layout: String,
    pub module: Option<String>,
    pub routine_unbacked_by_loaded_module: bool,
    pub suspicious_unbacked: bool,
}

#[derive(Debug, Serialize)]
pub struct CallbackSourceStatus {
    pub name: String,
    pub available: bool,
    pub recovered: usize,
    pub malformed: usize,
    pub complete: bool,
    pub helper_counts: BTreeMap<String, u32>,
}

#[derive(Debug, Serialize)]
pub struct SsdtReport {
    pub records: Vec<SsdtRecord>,
    pub descriptors: Vec<SsdtDescriptorRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SsdtDescriptorRecord {
    pub name: String,
    pub descriptor: u64,
    pub service_table: u64,
    pub number_of_services: u32,
    pub address_space_dtb: u64,
}

#[derive(Debug, Serialize)]
pub struct SsdtRecord {
    pub table: String,
    pub index: u32,
    pub encoded_entry: i32,
    pub routine: u64,
    pub argument_count: u8,
    pub module: Option<String>,
    pub suspicious_unbacked: bool,
}

#[derive(Debug, Serialize)]
pub struct UnloadedModuleReport {
    pub records: Vec<UnloadedModuleRecord>,
    pub last_index: u32,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UnloadedModuleRecord {
    pub slot: u32,
    pub name: String,
    pub start_address: u64,
    pub end_address: u64,
    pub current_time_raw: u64,
    pub time_interpretation: String,
    pub unload_time: Option<String>,
    pub unload_uptime_seconds: Option<f64>,
}

pub fn scan_modules(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<ModuleScanReport> {
    ensure!(limit > 0, "模块扫描结果上限必须大于零");
    let loaded = list_drivers(image, kernel, profile, 65_536)?;
    let loaded_entries = loaded
        .records
        .iter()
        .map(|module| module.entry)
        .collect::<HashSet<_>>();
    let pool = scan_pool_allocations(image, kernel, profile, &[*b"MmLd"], MAX_POOL_OBJECTS)?;
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for allocation in &pool.records {
        let Some((entry, physical_address, base, size, name, path)) =
            find_module_in_allocation(&space, profile, allocation)
        else {
            continue;
        };
        if !seen.insert(entry) {
            continue;
        }
        records.push(ScannedModuleRecord {
            entry,
            physical_address,
            base,
            size,
            name,
            path,
            in_loaded_module_list: loaded_entries.contains(&entry),
        });
    }
    records.sort_unstable_by_key(|record| (record.base, record.entry));
    let truncated = records.len() > limit;
    records.truncate(limit);
    let mut warnings = pool.warnings;
    warnings.extend(loaded.warnings);
    if truncated {
        warnings.push(format!("模块扫描结果达到 {limit} 条上限"));
    }
    Ok(ModuleScanReport {
        records,
        bytes_scanned: pool.bytes_scanned,
        scan_seconds: pool.elapsed_seconds,
        scan_gib_per_second: pool.gib_per_second,
        complete: pool.complete && loaded.complete && !truncated,
        warnings,
    })
}

pub fn scan_driver_objects(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<DriverScanReport> {
    ensure!(limit > 0, "驱动扫描结果上限必须大于零");
    let pool = scan_pool_allocations(image, kernel, profile, &[*b"Driv"], MAX_POOL_OBJECTS)?;
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for allocation in &pool.records {
        let Some(driver) = find_driver_in_allocation(&space, profile, allocation) else {
            continue;
        };
        if !seen.insert(driver.driver_object) {
            continue;
        }
        records.push(driver);
    }
    records.sort_unstable_by_key(|record| (record.driver_start, record.driver_object));
    let truncated = records.len() > limit;
    records.truncate(limit);
    let mut warnings = pool.warnings;
    if truncated {
        warnings.push(format!("驱动扫描结果达到 {limit} 条上限"));
    }
    Ok(DriverScanReport {
        records,
        bytes_scanned: pool.bytes_scanned,
        scan_seconds: pool.elapsed_seconds,
        scan_gib_per_second: pool.gib_per_second,
        complete: pool.complete && !truncated,
        warnings,
    })
}

pub fn correlate_drivers(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<DriverModuleReport> {
    let modules = list_drivers(image, kernel, profile, 65_536)?;
    let drivers = scan_driver_objects(image, kernel, profile, limit)?;
    let records = drivers
        .records
        .iter()
        .map(|driver| {
            let module = module_for_address(&modules.records, driver.driver_start);
            DriverModuleRecord {
                driver_object: driver.driver_object,
                driver_name: driver.name.clone(),
                driver_start: driver.driver_start,
                driver_size: driver.driver_size,
                module_entry: module.map(|module| module.entry),
                module_name: module.map(|module| module.name.clone()),
                module_path: module.map(|module| module.path.clone()),
                exact_base_match: module.is_some_and(|module| module.base == driver.driver_start),
                suspicious_unbacked: module.is_none(),
            }
        })
        .collect();
    let mut warnings = drivers.warnings;
    warnings.extend(modules.warnings);
    Ok(DriverModuleReport {
        records,
        loaded_module_count: modules.records.len(),
        driver_object_count: drivers.records.len(),
        complete: drivers.complete && modules.complete,
        warnings,
    })
}

pub fn driver_irps(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<DriverIrpReport> {
    let modules = list_drivers(image, kernel, profile, 65_536)?;
    let drivers = scan_driver_objects(image, kernel, profile, limit)?;
    let records = irp_dispatch_records(&modules.records, &drivers.records);
    let mut warnings = drivers.warnings;
    warnings.extend(modules.warnings);
    Ok(DriverIrpReport {
        records,
        complete: drivers.complete && modules.complete,
        warnings,
    })
}

pub fn device_tree(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<DeviceTreeReport> {
    ensure!(limit > 0, "设备结果上限必须大于零");
    let drivers = scan_driver_objects(image, kernel, profile, 65_536)?;
    let mut report = device_tree_from_drivers(image, kernel, profile, &drivers.records, limit)?;
    report.complete &= drivers.complete;
    let mut warnings = drivers.warnings;
    warnings.extend(report.warnings);
    report.warnings = warnings;
    Ok(report)
}

pub fn inspect_drivers(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    name_filter: Option<&str>,
    address_filter: Option<u64>,
    limit: usize,
) -> Result<DriverInspectReport> {
    ensure!(limit > 0, "驱动检查结果上限必须大于零");
    let modules = list_drivers(image, kernel, profile, 65_536)?;
    let mut scanned = scan_driver_objects(image, kernel, profile, 65_536)?;
    let driver_object_count = scanned.records.len();
    scanned.records.retain(|driver| {
        name_filter.is_none_or(|name| driver.name.eq_ignore_ascii_case(name))
            && address_filter.is_none_or(|address| driver.driver_object == address)
    });
    let truncated = scanned.records.len() > limit;
    scanned.records.truncate(limit);
    if truncated {
        scanned.complete = false;
        scanned
            .warnings
            .push(format!("驱动检查结果达到 {limit} 条上限"));
    }
    let devices = device_tree_from_drivers(image, kernel, profile, &scanned.records, 1_000_000)?;
    let irp_dispatch = irp_dispatch_records(&modules.records, &scanned.records);
    let fast_io =
        fast_io_dispatch_records(image, kernel, profile, &modules.records, &scanned.records)?;

    let mut device_counts = HashMap::new();
    for device in &devices.records {
        *device_counts.entry(device.driver_object).or_insert(0usize) += 1;
    }
    let mut suspicious_irp_counts = HashMap::new();
    for dispatch in &irp_dispatch {
        if dispatch.suspicious {
            *suspicious_irp_counts
                .entry(dispatch.driver_object)
                .or_insert(0usize) += 1;
        }
    }
    let mut fast_io_implemented_counts = HashMap::new();
    let mut suspicious_fast_io_counts = HashMap::new();
    for dispatch in &fast_io.records {
        if dispatch.implemented {
            *fast_io_implemented_counts
                .entry(dispatch.driver_object)
                .or_insert(0usize) += 1;
        }
        if dispatch.suspicious {
            *suspicious_fast_io_counts
                .entry(dispatch.driver_object)
                .or_insert(0usize) += 1;
        }
    }

    let drivers = scanned
        .records
        .iter()
        .map(|driver| {
            let module = module_for_address(&modules.records, driver.driver_start);
            let exact_base_match = module.is_some_and(|module| module.base == driver.driver_start);
            let module_status = match module {
                Some(_) if exact_base_match => "loaded_module_exact",
                Some(_) => "loaded_module_contains_address",
                None => "unbacked_by_loaded_module",
            };
            let path_status = classify_driver_path(module.map(|module| module.path.as_str()));
            let handles_directory_control = driver.major_functions.get(12).is_some_and(|routine| {
                *routine >= driver.driver_start
                    && *routine
                        < driver
                            .driver_start
                            .saturating_add(u64::from(driver.driver_size))
            });
            let mut triage_reasons = Vec::new();
            if path_status == "user_profile" {
                triage_reasons.push("module_loaded_from_user_profile".to_owned());
            }
            if handles_directory_control {
                triage_reasons.push("handles_irp_mj_directory_control".to_owned());
            }
            if driver.fast_io_dispatch.is_some() {
                triage_reasons.push("fast_io_dispatch_present".to_owned());
            }
            if module.is_none() {
                triage_reasons.push("unbacked_by_loaded_module".to_owned());
            }
            let suspicious_irp_count = suspicious_irp_counts
                .get(&driver.driver_object)
                .copied()
                .unwrap_or(0);
            let suspicious_fast_io_count = suspicious_fast_io_counts
                .get(&driver.driver_object)
                .copied()
                .unwrap_or(0);
            let triage_attention = path_status == "user_profile"
                || module.is_none()
                || suspicious_irp_count > 0
                || suspicious_fast_io_count > 0;
            DriverInspectRecord {
                driver_object: driver.driver_object,
                physical_address: driver.physical_address,
                name: driver.name.clone(),
                driver_start: driver.driver_start,
                driver_size: driver.driver_size,
                module_entry: module.map(|module| module.entry),
                module_name: module.map(|module| module.name.clone()),
                module_path: module.map(|module| module.path.clone()),
                module_status: module_status.to_owned(),
                path_status: path_status.to_owned(),
                file_status: "not_examined_from_memory_image".to_owned(),
                triage_attention,
                triage_reasons,
                exact_base_match,
                suspicious_unbacked: module.is_none(),
                device_count: device_counts
                    .get(&driver.driver_object)
                    .copied()
                    .unwrap_or(0),
                distinct_irp_routine_count: driver
                    .major_functions
                    .iter()
                    .copied()
                    .collect::<HashSet<_>>()
                    .len(),
                suspicious_irp_count,
                fast_io_dispatch: driver.fast_io_dispatch,
                fast_io_implemented_count: fast_io_implemented_counts
                    .get(&driver.driver_object)
                    .copied()
                    .unwrap_or(0),
                suspicious_fast_io_count,
            }
        })
        .collect::<Vec<_>>();
    let suspicious_driver_count = drivers
        .iter()
        .filter(|driver| {
            driver.suspicious_unbacked
                || driver.suspicious_irp_count > 0
                || driver.suspicious_fast_io_count > 0
        })
        .count();
    let attention_driver_count = drivers
        .iter()
        .filter(|driver| driver.triage_attention)
        .count();

    let mut warnings = scanned.warnings;
    warnings.extend(modules.warnings);
    warnings.extend(devices.warnings);
    warnings.extend(fast_io.warnings);
    Ok(DriverInspectReport {
        loaded_module_count: modules.records.len(),
        driver_object_count,
        matched_driver_count: drivers.len(),
        attention_driver_count,
        suspicious_driver_count,
        drivers,
        devices: devices.records,
        irp_dispatch,
        fast_io_dispatch: fast_io.records,
        fast_io_available: fast_io.available,
        complete: scanned.complete && modules.complete && devices.complete && fast_io.complete,
        warnings,
    })
}

fn device_tree_from_drivers(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    drivers: &[DriverObjectRecord],
    limit: usize,
) -> Result<DeviceTreeReport> {
    ensure!(limit > 0, "设备结果上限必须大于零");
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    let mut complete = true;
    let mut warnings = Vec::new();
    for driver in drivers {
        let mut device = driver.device_object;
        let mut per_driver = 0usize;
        while let Some(address) = device {
            if records.len() == limit {
                complete = false;
                warnings.push(format!("设备结果达到 {limit} 条上限"));
                break;
            }
            if !seen.insert(address) || per_driver == 4096 {
                complete = false;
                warnings.push(format!(
                    "驱动 {} 的设备链在 {address:#x} 处出现循环或长度超限",
                    driver.name
                ));
                break;
            }
            per_driver += 1;
            let object_type = type_u16(&space, profile, "_DEVICE_OBJECT", address, "Type");
            let object_size = type_u16(&space, profile, "_DEVICE_OBJECT", address, "Size");
            if object_type != Some(3)
                || object_size
                    .is_none_or(|size| u64::from(size) < profile.types["_DEVICE_OBJECT"].size)
            {
                complete = false;
                warnings.push(format!("DEVICE_OBJECT {address:#x} 的结构无效"));
                break;
            }
            let next_device =
                type_pointer(&space, profile, "_DEVICE_OBJECT", address, "NextDevice");
            records.push(DeviceObjectRecord {
                driver_object: driver.driver_object,
                driver_name: driver.name.clone(),
                device_object: address,
                next_device,
                attached_device: type_pointer(
                    &space,
                    profile,
                    "_DEVICE_OBJECT",
                    address,
                    "AttachedDevice",
                ),
                device_type: type_u32(&space, profile, "_DEVICE_OBJECT", address, "DeviceType"),
                flags: type_u32(&space, profile, "_DEVICE_OBJECT", address, "Flags"),
                characteristics: type_u32(
                    &space,
                    profile,
                    "_DEVICE_OBJECT",
                    address,
                    "Characteristics",
                ),
                stack_size: type_u8(&space, profile, "_DEVICE_OBJECT", address, "StackSize"),
                device_extension: type_pointer(
                    &space,
                    profile,
                    "_DEVICE_OBJECT",
                    address,
                    "DeviceExtension",
                ),
            });
            device = next_device;
        }
        if records.len() == limit {
            break;
        }
    }
    records.sort_unstable_by_key(|record| (record.driver_name.clone(), record.device_object));
    Ok(DeviceTreeReport {
        records,
        complete,
        warnings,
    })
}

fn irp_dispatch_records(
    modules: &[DriverRecord],
    drivers: &[DriverObjectRecord],
) -> Vec<DriverIrpRecord> {
    let mut records = Vec::new();
    for driver in drivers {
        for (index, routine) in driver.major_functions.iter().copied().enumerate() {
            let module = module_for_address(modules, routine);
            let inside_driver_image = routine >= driver.driver_start
                && routine
                    < driver
                        .driver_start
                        .saturating_add(u64::from(driver.driver_size));
            records.push(DriverIrpRecord {
                driver_object: driver.driver_object,
                driver_name: driver.name.clone(),
                major_index: index as u8,
                major_name: irp_major_name(index as u8).to_owned(),
                routine,
                module: module.map(|module| module.path.clone()),
                inside_driver_image,
                suspicious: routine == 0 || module.is_none(),
            });
        }
    }
    records
}

struct FastIoExtraction {
    records: Vec<DriverFastIoRecord>,
    available: bool,
    complete: bool,
    warnings: Vec<String>,
}

const FAST_IO_FUNCTION_NAMES: [&str; 27] = [
    "FastIoCheckIfPossible",
    "FastIoRead",
    "FastIoWrite",
    "FastIoQueryBasicInfo",
    "FastIoQueryStandardInfo",
    "FastIoLock",
    "FastIoUnlockSingle",
    "FastIoUnlockAll",
    "FastIoUnlockAllByKey",
    "FastIoDeviceControl",
    "AcquireFileForNtCreateSection",
    "ReleaseFileForNtCreateSection",
    "FastIoDetachDevice",
    "FastIoQueryNetworkOpenInfo",
    "AcquireForModWrite",
    "MdlRead",
    "MdlReadComplete",
    "PrepareMdlWrite",
    "MdlWriteComplete",
    "FastIoReadCompressed",
    "FastIoWriteCompressed",
    "MdlReadCompleteCompressed",
    "MdlWriteCompleteCompressed",
    "FastIoQueryOpen",
    "ReleaseForModWrite",
    "AcquireForCcFlush",
    "ReleaseForCcFlush",
];

fn fast_io_dispatch_records(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    modules: &[DriverRecord],
    drivers: &[DriverObjectRecord],
) -> Result<FastIoExtraction> {
    if profile
        .type_field("_DRIVER_OBJECT", "FastIoDispatch")
        .is_err()
        || profile.type_layout("_FAST_IO_DISPATCH").is_err()
    {
        return Ok(FastIoExtraction {
            records: Vec::new(),
            available: false,
            complete: false,
            warnings: vec![
                "精确符号配置缺少 _DRIVER_OBJECT.FastIoDispatch 或 _FAST_IO_DISPATCH；Fast I/O 分发表不可用"
                    .to_owned(),
            ],
        });
    }
    let layout = profile.type_layout("_FAST_IO_DISPATCH")?;
    let field_offsets = FAST_IO_FUNCTION_NAMES
        .iter()
        .filter_map(|name| {
            layout
                .fields
                .get(*name)
                .map(|field| ((*name).to_owned(), field.offset))
        })
        .collect::<Vec<_>>();
    if field_offsets.is_empty() {
        return Ok(FastIoExtraction {
            records: Vec::new(),
            available: false,
            complete: false,
            warnings: vec!["精确 _FAST_IO_DISPATCH 类型未公开任何已知函数指针字段".to_owned()],
        });
    }

    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut records = Vec::new();
    let mut warnings = Vec::new();
    let mut complete = true;
    for driver in drivers {
        let Some(dispatch_table) = driver.fast_io_dispatch else {
            continue;
        };
        let Some(declared_size) = read_u32_at(&space, dispatch_table) else {
            complete = false;
            warnings.push(format!(
                "驱动 {} 的 FAST_IO_DISPATCH {dispatch_table:#x} 无法读取 SizeOfFastIoDispatch",
                driver.name
            ));
            continue;
        };
        let declared_size = u64::from(declared_size);
        if declared_size < 4 || declared_size > layout.size || declared_size > 0x1000 {
            complete = false;
            warnings.push(format!(
                "驱动 {} 的 FAST_IO_DISPATCH {dispatch_table:#x} 大小 {declared_size:#x} 无效（精确类型大小 {:#x}）",
                driver.name, layout.size
            ));
            continue;
        }
        for (function_name, offset) in &field_offsets {
            if offset.saturating_add(8) > declared_size {
                continue;
            }
            let routine = match space.read_u64(dispatch_table + offset) {
                Ok(routine) => routine,
                Err(error) => {
                    complete = false;
                    warnings.push(format!(
                        "驱动 {} 的 Fast I/O 字段 {} 无法读取：{error:#}",
                        driver.name, function_name
                    ));
                    continue;
                }
            };
            let implemented = routine != 0;
            let module = implemented
                .then(|| module_for_address(modules, routine))
                .flatten();
            let inside_driver_image = implemented
                && routine >= driver.driver_start
                && routine
                    < driver
                        .driver_start
                        .saturating_add(u64::from(driver.driver_size));
            records.push(DriverFastIoRecord {
                driver_object: driver.driver_object,
                driver_name: driver.name.clone(),
                dispatch_table,
                function_name: function_name.clone(),
                routine,
                implemented,
                module: module.map(|module| module.path.clone()),
                inside_driver_image,
                suspicious: implemented && module.is_none(),
            });
        }
    }
    Ok(FastIoExtraction {
        records,
        available: true,
        complete,
        warnings,
    })
}

fn classify_driver_path(path: Option<&str>) -> &'static str {
    let Some(path) = path else {
        return "unknown";
    };
    let path = path.to_ascii_lowercase();
    if path.starts_with("\\systemroot\\") {
        "system_root"
    } else if path.starts_with("\\??\\c:\\users\\") {
        "user_profile"
    } else if path.starts_with("\\??\\c:\\program files\\")
        || path.starts_with("\\??\\c:\\program files (x86)\\")
    {
        "program_files"
    } else if path.starts_with("\\??\\c:\\windows\\") {
        "windows_directory"
    } else {
        "other"
    }
}

pub fn callbacks(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<CallbackReport> {
    ensure!(limit > 0, "回调结果上限必须大于零");
    ensure!(
        !kernel.is_x86_pae(),
        "callbacks 暂不支持 Windows x86 PAE 内核回调结构"
    );
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let modules = list_drivers(image, kernel, profile, 65_536)?;
    const POOL_TAGS: [[u8; 4]; 7] = [
        *b"IoFs", *b"IoSh", *b"Cbrb", *b"DbCb", *b"Pnp9", *b"PnpD", *b"PnpC",
    ];
    // All seven signatures share scan_exact_4 and one reverse-translation
    // pass.  This is the expensive part of callbacks and must never degrade
    // into one physical scan per callback class.
    let pool = scan_pool_allocations(image, kernel, profile, &POOL_TAGS, MAX_POOL_OBJECTS)?;
    let arrays: [(&str, &[&str]); 3] = [
        (
            "PspCreateProcessNotifyRoutine",
            &[
                "PspCreateProcessNotifyRoutineCount",
                "PspCreateProcessNotifyRoutineExCount",
            ],
        ),
        (
            "PspCreateThreadNotifyRoutine",
            &[
                "PspCreateThreadNotifyRoutineCount",
                "PspCreateThreadNotifyRoutineNonSystemCount",
            ],
        ),
        (
            "PspLoadImageNotifyRoutine",
            &["PspLoadImageNotifyRoutineCount"],
        ),
    ];
    let mut records = Vec::new();
    let mut seen = HashMap::new();
    let mut sources = Vec::new();
    let mut stats = CallbackCollectionStats::default();
    let mut missing = MissingPageTracker::default();
    let mut warnings = modules.warnings;
    let mut complete = modules.complete;

    for (array_symbol, count_symbols) in arrays {
        let mut status = CallbackSourceStatus {
            name: array_symbol.to_owned(),
            available: false,
            recovered: 0,
            malformed: 0,
            complete: true,
            helper_counts: BTreeMap::new(),
        };
        let Ok(array_rva) = profile.symbol_rva(array_symbol) else {
            complete = false;
            status.complete = false;
            warnings.push(format!("符号配置中不包含 {array_symbol}"));
            sources.push(status);
            continue;
        };
        status.available = true;
        for count_symbol in count_symbols {
            let Some(rva) = profile.symbols.get(*count_symbol) else {
                continue;
            };
            match tracked_read_u32(&space, kernel.kernel_base + u64::from(*rva), &mut missing) {
                Some(count) if count <= 64 => {
                    status
                        .helper_counts
                        .insert((*count_symbol).to_owned(), count);
                }
                Some(count) => warnings.push(format!(
                    "{count_symbol} 的辅助计数 {count} 超出 64 槽数组范围；不将其作为完整性真值"
                )),
                None => status.complete = false,
            }
        }
        let array = kernel.kernel_base + u64::from(array_rva);
        for index in 0..64u32 {
            let Some(value) = tracked_read_u64(&space, array + u64::from(index) * 8, &mut missing)
            else {
                complete = false;
                status.complete = false;
                continue;
            };
            if value == 0 {
                continue;
            }
            let block = value & !0xf;
            if !is_kernel_pointer(block) {
                complete = false;
                status.complete = false;
                status.malformed += 1;
                warnings.push(format!(
                    "{array_symbol}[{index}] 的非零 fast-ref 未指向有效内核回调块：{value:#x}"
                ));
                continue;
            }
            let Some(routine) = tracked_read_u64(&space, block + 8, &mut missing) else {
                complete = false;
                status.complete = false;
                status.malformed += 1;
                continue;
            };
            if !is_kernel_address(routine) {
                complete = false;
                status.complete = false;
                status.malformed += 1;
                warnings.push(format!(
                    "{array_symbol}[{index}] 的回调块 {block:#x} 包含无效例程 {routine:#x}"
                ));
                continue;
            }
            status.recovered += 1;
            let candidate = CallbackCandidate {
                kind: array_symbol.to_owned(),
                index,
                callback_block: block,
                routine,
                context: tracked_read_u64(&space, block + 16, &mut missing)
                    .filter(|context| *context != 0),
                detail: None,
                source: "global_array".to_owned(),
                pool_tag: None,
                layout: "nt!_EX_CALLBACK_ROUTINE_BLOCK(Function@0x8,Context@0x10)".to_owned(),
            };
            push_callback_record(
                &mut records,
                &mut seen,
                &mut stats,
                &modules.records,
                candidate,
                limit,
            );
        }
        sources.push(status);
    }

    for symbol in [
        "KeBugCheckCallbackListHead",
        "KeBugCheckReasonCallbackListHead",
    ] {
        let mut status = CallbackSourceStatus {
            name: symbol.to_owned(),
            available: false,
            recovered: 0,
            malformed: 0,
            complete: true,
            helper_counts: BTreeMap::new(),
        };
        let (record_type, routine_fallback, component_fallback) = bugcheck_layout(symbol);
        let routine_offset = profile
            .type_field(record_type, "CallbackRoutine")
            .map(|field| field.offset)
            .unwrap_or(routine_fallback);
        let component_offset = profile
            .type_field(record_type, "Component")
            .map(|field| field.offset)
            .unwrap_or(component_fallback);
        let Ok(rva) = profile.symbol_rva(symbol) else {
            complete = false;
            status.complete = false;
            warnings.push(format!("符号配置中不包含 {symbol}"));
            sources.push(status);
            continue;
        };
        status.available = true;
        let head = kernel.kernel_base + u64::from(rva);
        let Some(mut link) = tracked_read_u64(&space, head, &mut missing) else {
            complete = false;
            status.complete = false;
            warnings.push(format!("{symbol} 链表头不可用"));
            sources.push(status);
            continue;
        };
        let mut previous = head;
        let mut visited = HashSet::new();
        let mut index = 0u32;
        while link != head {
            if index as usize == MAX_CALLBACK_CHAIN {
                complete = false;
                status.complete = false;
                status.malformed += 1;
                warnings.push(format!("{symbol} 达到 {MAX_CALLBACK_CHAIN} 个节点安全上限"));
                break;
            }
            if !is_kernel_pointer(link) || !visited.insert(link) {
                complete = false;
                status.complete = false;
                status.malformed += 1;
                warnings.push(format!("{symbol} 回调链表在 {link:#x} 处无效"));
                break;
            }
            let Some(next) = tracked_read_u64(&space, link, &mut missing) else {
                complete = false;
                status.complete = false;
                status.malformed += 1;
                warnings.push(format!("{symbol} 在 {link:#x} 处的下一链接不可用"));
                break;
            };
            let Some(blink) = tracked_read_u64(&space, link + 8, &mut missing) else {
                complete = false;
                status.complete = false;
                status.malformed += 1;
                warnings.push(format!("{symbol} 在 {link:#x} 处的反向链接不可用"));
                break;
            };
            if blink != previous || !is_kernel_pointer(next) {
                complete = false;
                status.complete = false;
                status.malformed += 1;
                warnings.push(format!("{symbol} 回调链表在 {link:#x} 处的反向链接不一致"));
                break;
            }
            let routine =
                tracked_read_u64(&space, link + routine_offset, &mut missing).unwrap_or(0);
            if is_kernel_address(routine) {
                let component_pointer =
                    tracked_read_u64(&space, link + component_offset, &mut missing).unwrap_or(0);
                let candidate = CallbackCandidate {
                    kind: symbol.to_owned(),
                    index,
                    callback_block: link,
                    routine,
                    context: None,
                    detail: read_ascii_z(&space, component_pointer, 64),
                    source: "linked_list".to_owned(),
                    pool_tag: None,
                    layout: if symbol == "KeBugCheckCallbackListHead" {
                        "callbacks-x64!_KBUGCHECK_CALLBACK_RECORD".to_owned()
                    } else {
                        "callbacks-x64!_KBUGCHECK_REASON_CALLBACK_RECORD".to_owned()
                    },
                };
                status.recovered += 1;
                push_callback_record(
                    &mut records,
                    &mut seen,
                    &mut stats,
                    &modules.records,
                    candidate,
                    limit,
                );
            } else {
                complete = false;
                status.complete = false;
                status.malformed += 1;
                warnings.push(format!(
                    "{symbol}[{index}] 的节点 {link:#x} 包含无效回调例程 {routine:#x}"
                ));
            }
            index += 1;
            previous = link;
            link = next;
        }
        if link == head && tracked_read_u64(&space, head + 8, &mut missing) != Some(previous) {
            complete = false;
            status.complete = false;
            status.malformed += 1;
            warnings.push(format!("{symbol} 回调链表头的反向链接不一致"));
        }
        sources.push(status);
    }

    let registry_available = [
        "CallbackListHead",
        "CmCallbackListHead",
        "CmpCallBackVector",
    ]
    .iter()
    .any(|symbol| profile.symbols.contains_key(*symbol));
    let registry_before = stats.evidence_observations;
    let registry_complete = enumerate_registry_callbacks(
        &space,
        kernel,
        profile,
        &modules.records,
        &mut records,
        &mut seen,
        &mut stats,
        &mut missing,
        &mut warnings,
        limit,
    );
    sources.push(CallbackSourceStatus {
        name: "RegistryCallbacks".to_owned(),
        available: registry_available,
        recovered: stats.evidence_observations - registry_before,
        malformed: usize::from(!registry_complete),
        complete: registry_complete,
        helper_counts: BTreeMap::new(),
    });
    if !registry_complete {
        complete = false;
    }

    let mut pool_indexes = HashMap::<String, u32>::new();
    let pool_candidates =
        pool_callback_candidates(&space, profile, &modules.records, &pool.records);
    let pool_recovered = pool_candidates.len();
    for candidate in pool_candidates {
        let index = pool_indexes.entry(candidate.kind.clone()).or_default();
        let mut candidate = candidate;
        candidate.index = *index;
        *index += 1;
        push_callback_record(
            &mut records,
            &mut seen,
            &mut stats,
            &modules.records,
            candidate,
            limit,
        );
    }
    sources.push(CallbackSourceStatus {
        name: "CallbackPoolScan".to_owned(),
        available: true,
        recovered: pool_recovered,
        malformed: 0,
        complete: pool.complete,
        helper_counts: BTreeMap::new(),
    });

    warnings.extend(pool.warnings);
    if stats.truncated {
        complete = false;
        warnings.push(format!("回调结果达到 {limit} 条上限"));
    }
    if !pool.complete {
        complete = false;
    }
    let missing_pages = missing.pages.len();
    let missing_bytes = missing_pages as u64 * 0x1000;
    if missing_pages != 0 {
        complete = false;
        warnings.push(format!(
            "沿已验证指针遍历时，有 {missing_pages} 个回调结构页（{missing_bytes} 字节）不可用"
        ));
    }
    records.sort_unstable_by_key(|record| (record.kind.clone(), record.index));
    let unique_callback_count = stats.unique_callbacks.len();
    let unique_registration_count = stats.active_registrations.len();
    let pool_only_candidate_count = unique_callback_count.saturating_sub(unique_registration_count);
    let records_retained = records.len();
    Ok(CallbackReport {
        records,
        sources,
        evidence_observations: stats.evidence_observations,
        unique_callback_count,
        unique_registration_count,
        pool_only_candidate_count,
        records_retained,
        duplicate_evidence_merged: stats.duplicate_evidence_merged,
        bytes_scanned: pool.bytes_scanned,
        scan_seconds: pool.elapsed_seconds,
        scan_gib_per_second: pool.gib_per_second,
        pool_candidates: pool.records.len(),
        missing_pages,
        missing_bytes,
        complete: complete && !stats.truncated && missing_pages == 0,
        warnings,
    })
}

#[derive(Debug)]
struct CallbackCandidate {
    kind: String,
    index: u32,
    callback_block: u64,
    routine: u64,
    context: Option<u64>,
    detail: Option<String>,
    source: String,
    pool_tag: Option<String>,
    layout: String,
}

fn bugcheck_layout(symbol: &str) -> (&'static str, u64, u64) {
    if symbol == "KeBugCheckCallbackListHead" {
        // x64 KBUGCHECK_CALLBACK_RECORD: Entry@0x0,
        // CallbackRoutine@0x10, Component@0x28.
        ("_KBUGCHECK_CALLBACK_RECORD", 0x10, 0x28)
    } else {
        ("_KBUGCHECK_REASON_CALLBACK_RECORD", 0x10, 0x18)
    }
}

#[derive(Debug, Default)]
struct CallbackCollectionStats {
    evidence_observations: usize,
    duplicate_evidence_merged: usize,
    unique_callbacks: HashSet<(u64, u64)>,
    active_registrations: HashSet<(u64, u64)>,
    truncated: bool,
}

fn push_callback_record(
    records: &mut Vec<CallbackRecord>,
    seen: &mut HashMap<(u64, u64), usize>,
    stats: &mut CallbackCollectionStats,
    modules: &[DriverRecord],
    candidate: CallbackCandidate,
    limit: usize,
) {
    stats.evidence_observations += 1;
    let key = (candidate.callback_block, candidate.routine);
    let active_evidence = candidate.source != "pool_scan";
    if active_evidence {
        stats.active_registrations.insert(key);
    }
    if !stats.unique_callbacks.insert(key) {
        if let Some(record_index) = seen.get(&key).copied() {
            let record = &mut records[record_index];
            push_unique(&mut record.evidence_sources, candidate.source.clone());
            push_unique(&mut record.evidence_kinds, candidate.kind.clone());
            if let Some(pool_tag) = candidate.pool_tag.as_ref() {
                push_unique(&mut record.pool_tags, pool_tag.clone());
            }
            record.corroborated_by_pool = record
                .evidence_sources
                .iter()
                .any(|source| source == "pool_scan")
                && record
                    .evidence_sources
                    .iter()
                    .any(|source| source != "pool_scan");
            if record
                .evidence_sources
                .iter()
                .any(|source| source != "pool_scan")
            {
                record.registration_status = "active_registration".to_owned();
                record.suspicious_unbacked = record.routine_unbacked_by_loaded_module;
            }
        }
        stats.duplicate_evidence_merged += 1;
        return;
    }
    if records.len() == limit {
        stats.truncated = true;
        return;
    }
    let module = module_for_address(modules, candidate.routine);
    let evidence_sources = vec![candidate.source.clone()];
    let evidence_kinds = vec![candidate.kind.clone()];
    let pool_tags = candidate.pool_tag.iter().cloned().collect::<Vec<_>>();
    let registration_status = if evidence_sources.iter().any(|source| source != "pool_scan") {
        "active_registration".to_owned()
    } else {
        "pool_candidate".to_owned()
    };
    let routine_unbacked_by_loaded_module = module.is_none();
    let record_index = records.len();
    records.push(CallbackRecord {
        kind: candidate.kind,
        index: candidate.index,
        callback_block: candidate.callback_block,
        routine: candidate.routine,
        context: candidate.context,
        detail: candidate.detail,
        source: candidate.source,
        evidence_sources,
        evidence_kinds,
        pool_tag: candidate.pool_tag,
        pool_tags,
        corroborated_by_pool: false,
        registration_status,
        layout: candidate.layout,
        module: module.map(|module| module.path.clone()),
        routine_unbacked_by_loaded_module,
        suspicious_unbacked: routine_unbacked_by_loaded_module && active_evidence,
    });
    seen.insert(key, record_index);
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

#[derive(Default)]
struct MissingPageTracker {
    pages: HashSet<u64>,
}

impl MissingPageTracker {
    fn record(&mut self, address: u64, length: u64) {
        let first = address & !0xfff;
        let last = address
            .saturating_add(length.saturating_sub(1))
            .saturating_add(0xfff)
            & !0xfff;
        for page in (first..last).step_by(0x1000) {
            self.pages.insert(page);
        }
    }
}

fn tracked_read_u64(
    space: &X64AddressSpace<'_>,
    address: u64,
    missing: &mut MissingPageTracker,
) -> Option<u64> {
    match space.read_u64(address) {
        Ok(value) => Some(value),
        Err(_) => {
            missing.record(address, 8);
            None
        }
    }
}

fn tracked_read_u32(
    space: &X64AddressSpace<'_>,
    address: u64,
    missing: &mut MissingPageTracker,
) -> Option<u32> {
    let mut bytes = [0u8; 4];
    match space.read_virtual(address, &mut bytes) {
        Ok(()) => Some(u32::from_le_bytes(bytes)),
        Err(_) => {
            missing.record(address, 4);
            None
        }
    }
}

#[derive(Debug)]
struct RegistryEntryCandidate {
    block: u64,
    routine: u64,
    altitude: Option<String>,
    layout: &'static str,
    score: i32,
}

#[derive(Debug)]
struct RegistryListCandidate {
    symbol: &'static str,
    entries: Vec<RegistryEntryCandidate>,
    score: i32,
}

#[allow(clippy::too_many_arguments)]
fn enumerate_registry_callbacks(
    space: &X64AddressSpace<'_>,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    modules: &[DriverRecord],
    records: &mut Vec<CallbackRecord>,
    seen: &mut HashMap<(u64, u64), usize>,
    stats: &mut CallbackCollectionStats,
    missing: &mut MissingPageTracker,
    warnings: &mut Vec<String>,
    limit: usize,
) -> bool {
    let expected = profile
        .symbols
        .get("CmpCallBackCount")
        .and_then(|rva| tracked_read_u32(space, kernel.kernel_base + u64::from(*rva), missing));
    let expected = match expected {
        Some(count) if count <= 4096 => Some(count),
        Some(count) => {
            warnings.push(format!(
                "CmpCallBackCount 的值 {count} 不合理；将以链表结构关系为准"
            ));
            None
        }
        None => None,
    };

    let mut list_candidates = ["CallbackListHead", "CmCallbackListHead"]
        .into_iter()
        .filter_map(|symbol| {
            let rva = profile.symbols.get(symbol)?;
            score_registry_list(
                space,
                profile,
                modules,
                symbol,
                kernel.kernel_base + u64::from(*rva),
                expected,
            )
        })
        .collect::<Vec<_>>();
    list_candidates.sort_unstable_by_key(|candidate| std::cmp::Reverse(candidate.score));

    if let Some(selected) = list_candidates.into_iter().next() {
        if let Some(expected) = expected
            && selected.entries.len() != expected as usize
        {
            warnings.push(format!(
                "{} 恢复出 {} 个已验证注册表回调，但 CmpCallBackCount 为 {expected}",
                selected.symbol,
                selected.entries.len()
            ));
        }
        for (index, entry) in selected.entries.into_iter().enumerate() {
            let candidate = CallbackCandidate {
                kind: "CmRegisterCallbackEx".to_owned(),
                index: index as u32,
                callback_block: entry.block,
                routine: entry.routine,
                context: None,
                detail: entry
                    .altitude
                    .map(|altitude| format!("Altitude: {altitude}")),
                source: "linked_list".to_owned(),
                pool_tag: None,
                layout: entry.layout.to_owned(),
            };
            push_callback_record(records, seen, stats, modules, candidate, limit);
        }
        return true;
    }

    // NT 5.x used a fast-ref vector rather than the altitude-ordered list.
    if let (Some(vector_rva), Some(count)) = (profile.symbols.get("CmpCallBackVector"), expected) {
        let vector = kernel.kernel_base + u64::from(*vector_rva);
        for index in 0..count {
            let Some(fast_ref) = tracked_read_u64(space, vector + u64::from(index) * 8, missing)
            else {
                continue;
            };
            let block = fast_ref & !0xf;
            if !is_kernel_pointer(block) {
                continue;
            }
            let Some(routine) = tracked_read_u64(space, block + 8, missing) else {
                continue;
            };
            if !is_kernel_address(routine) {
                continue;
            }
            let candidate = CallbackCandidate {
                kind: "CmRegisterCallback".to_owned(),
                index,
                callback_block: block,
                routine,
                context: None,
                detail: None,
                source: "global_array".to_owned(),
                pool_tag: None,
                layout: "callbacks-x64!_EX_CALLBACK_ROUTINE_BLOCK(Function@0x8)".to_owned(),
            };
            push_callback_record(records, seen, stats, modules, candidate, limit);
        }
        return true;
    }

    for symbol in ["CallbackListHead", "CmCallbackListHead"] {
        if let Some(rva) = profile.symbols.get(symbol) {
            let head = kernel.kernel_base + u64::from(*rva);
            let _ = tracked_read_u64(space, head, missing);
            let _ = tracked_read_u64(space, head + 8, missing);
        }
    }
    warnings.push("无法从精确 PDB 全局变量恢复出自洽的注册表回调链表或向量".to_owned());
    false
}

fn score_registry_list(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    modules: &[DriverRecord],
    symbol: &'static str,
    head: u64,
    expected: Option<u32>,
) -> Option<RegistryListCandidate> {
    let mut link = space.read_u64(head).ok()?;
    let head_blink = space.read_u64(head + 8).ok()?;
    if link == head {
        return (head_blink == head).then_some(RegistryListCandidate {
            symbol,
            entries: Vec::new(),
            score: if expected == Some(0) { 100 } else { 0 },
        });
    }
    if !is_kernel_pointer(link) || !is_kernel_pointer(head_blink) {
        return None;
    }
    let mut previous = head;
    let mut visited = HashSet::new();
    let mut entries = Vec::new();
    let mut score = 0i32;
    while link != head && entries.len() < 4096 {
        if !is_kernel_pointer(link) || !visited.insert(link) {
            return None;
        }
        let next = space.read_u64(link).ok()?;
        let blink = space.read_u64(link + 8).ok()?;
        if blink != previous || !is_kernel_pointer(next) {
            return None;
        }
        let entry = select_registry_entry_layout(space, profile, modules, link)?;
        score += entry.score + 8;
        entries.push(entry);
        previous = link;
        link = next;
    }
    if link != head || head_blink != previous {
        return None;
    }
    if expected == Some(entries.len() as u32) {
        score += 100;
    } else if let Some(expected) = expected {
        score -= (i64::from(expected) - entries.len() as i64)
            .unsigned_abs()
            .min(50) as i32;
    }
    Some(RegistryListCandidate {
        symbol,
        entries,
        score,
    })
}

fn select_registry_entry_layout(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    modules: &[DriverRecord],
    block: u64,
) -> Option<RegistryEntryCandidate> {
    // The first entry is the callbacks-x64 overlay.  The remaining candidates
    // cover field movement without consulting the Windows build number.  A
    // candidate wins only through live list, module and UNICODE_STRING
    // relationships; the overlay gets a small tie-break prior, not authority.
    const LAYOUTS: [(&str, u64, u64); 4] = [
        (
            "callbacks-x64!_CM_CALLBACK_ENTRY(Function@0x28,Altitude@0x30)",
            0x28,
            0x30,
        ),
        ("field-scored(Function@0x20,Altitude@0x28)", 0x20, 0x28),
        ("field-scored(Function@0x30,Altitude@0x38)", 0x30, 0x38),
        ("field-scored(Function@0x18,Altitude@0x20)", 0x18, 0x20),
    ];
    let cookie = space.read_u64(block + 0x18).unwrap_or(0);
    LAYOUTS
        .into_iter()
        .filter_map(|(layout, function_offset, altitude_offset)| {
            let routine = space.read_u64(block + function_offset).ok()?;
            if !is_kernel_address(routine) {
                return None;
            }
            let altitude = read_unicode_string(space, profile, block + altitude_offset, 1024)
                .filter(|value| plausible_altitude(value));
            let module_backed = module_for_address(modules, routine).is_some();
            let mut score = if function_offset == 0x28 { 4 } else { 0 };
            if module_backed {
                score += 6;
            }
            if altitude.is_some() {
                score += 5;
            }
            if cookie != 0 {
                score += 1;
            }
            // The preferred overlay is only a tie-breaker. It must not pass on
            // the hard-coded offset alone: require either a loaded-module
            // routine or a plausible altitude recovered from the target.
            (module_backed || altitude.is_some()).then_some(RegistryEntryCandidate {
                block,
                routine,
                altitude,
                layout,
                score,
            })
        })
        .max_by_key(|candidate| candidate.score)
}

fn plausible_altitude(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | ' ')
        })
}

#[derive(Debug)]
struct ValidatedDriver {
    name: String,
    shutdown_routine: u64,
}

fn validate_driver_object(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    modules: &[DriverRecord],
    address: u64,
) -> Option<ValidatedDriver> {
    if !is_kernel_pointer(address) {
        return None;
    }
    let size = profile.type_layout("_DRIVER_OBJECT").ok()?.size;
    if type_u16(space, profile, "_DRIVER_OBJECT", address, "Type") != Some(4)
        || type_u16(space, profile, "_DRIVER_OBJECT", address, "Size")
            .is_none_or(|value| u64::from(value) < size)
    {
        return None;
    }
    let start = type_u64(space, profile, "_DRIVER_OBJECT", address, "DriverStart")?;
    let image_size = type_u32(space, profile, "_DRIVER_OBJECT", address, "DriverSize")?;
    if !is_kernel_pointer(start)
        || !start.is_multiple_of(0x1000)
        || !(0x1000..=0x8000_0000).contains(&image_size)
        || module_for_address(modules, start).is_none()
    {
        return None;
    }
    let major = profile
        .type_field("_DRIVER_OBJECT", "MajorFunction")
        .ok()?
        .offset;
    let shutdown_routine = space.read_u64(address + major + 0x10 * 8).ok()?;
    let name = type_unicode(space, profile, "_DRIVER_OBJECT", address, "DriverName")
        .unwrap_or_else(|| format!("DRIVER_OBJECT {address:#x}"));
    Some(ValidatedDriver {
        name,
        shutdown_routine,
    })
}

fn validate_device_object(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    modules: &[DriverRecord],
    address: u64,
) -> Option<ValidatedDriver> {
    if !is_kernel_pointer(address) {
        return None;
    }
    let size = profile.type_layout("_DEVICE_OBJECT").ok()?.size;
    if type_u16(space, profile, "_DEVICE_OBJECT", address, "Type") != Some(3)
        || type_u16(space, profile, "_DEVICE_OBJECT", address, "Size")
            .is_none_or(|value| u64::from(value) < size)
    {
        return None;
    }
    let driver = type_u64(space, profile, "_DEVICE_OBJECT", address, "DriverObject")?;
    validate_driver_object(space, profile, modules, driver)
}

fn pool_callback_candidates(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    modules: &[DriverRecord],
    allocations: &[PoolAllocationRecord],
) -> Vec<CallbackCandidate> {
    let mut candidates = Vec::new();
    for allocation in allocations {
        for header in allocation.virtual_headers() {
            let Some(end) = header.checked_add(allocation.allocation_size) else {
                continue;
            };
            let body = header + 16;
            let field = |offset: u64| -> Option<u64> {
                (body.checked_add(offset)?.checked_add(8)? <= end)
                    .then(|| space.read_u64(body + offset).ok())?
            };
            let list_score = || score_list_entry(space, body);
            let module_score = |routine| {
                if module_for_address(modules, routine).is_some() {
                    3
                } else {
                    0
                }
            };
            let candidate = (|| -> Option<CallbackCandidate> {
                match allocation.tag.as_str() {
                    "IoFs" => {
                        let driver_address = field(0x10)?;
                        let routine = field(0x18)?;
                        let links = list_score()?;
                        let driver =
                            validate_driver_object(space, profile, modules, driver_address)?;
                        let score = links + 6 + 2 + module_score(routine);
                        (is_kernel_address(routine) && score >= 10).then_some(CallbackCandidate {
                            kind: "IoRegisterFsRegistrationChange".to_owned(),
                            index: 0,
                            callback_block: body,
                            routine,
                            context: Some(driver_address),
                            detail: Some(format!("驱动：{}", driver.name)),
                            source: "pool_scan".to_owned(),
                            pool_tag: Some(allocation.tag.clone()),
                            layout: "callbacks-x64!_NOTIFICATION_PACKET".to_owned(),
                        })
                    }
                    "IoSh" if allocation.pool_index == 0 => {
                        let device = field(0x10)?;
                        let links = list_score()?;
                        let driver = validate_device_object(space, profile, modules, device)?;
                        let routine = driver.shutdown_routine;
                        let score = links + 10 + 2 + module_score(routine);
                        (is_kernel_address(routine) && score >= 14).then_some(CallbackCandidate {
                            kind: "IoRegisterShutdownNotification".to_owned(),
                            index: 0,
                            callback_block: body,
                            routine,
                            context: Some(device),
                            detail: Some(format!("设备对象：{device:#x}；驱动：{}", driver.name)),
                            source: "pool_scan".to_owned(),
                            pool_tag: Some(allocation.tag.clone()),
                            layout: "callbacks-x64!_SHUTDOWN_PACKET".to_owned(),
                        })
                    }
                    "Cbrb" => {
                        let routine = field(0x08)?;
                        let associated = field(0x10)?;
                        let associated_valid = associated == 0 || is_canonical_pointer(associated);
                        let score = 2 + i32::from(associated_valid) * 2 + module_score(routine);
                        (is_kernel_address(routine) && associated_valid && score >= 4).then_some(
                            CallbackCandidate {
                                kind: "ExCallbackRoutineBlockPoolCandidate".to_owned(),
                                index: 0,
                                callback_block: body,
                                routine,
                                context: (associated != 0).then_some(associated),
                                detail: None,
                                source: "pool_scan".to_owned(),
                                pool_tag: Some(allocation.tag.clone()),
                                layout: "callbacks-x64!_GENERIC_CALLBACK".to_owned(),
                            },
                        )
                    }
                    "DbCb" if allocation.allocation_size <= 0x40 => {
                        let routine = field(0x10)?;
                        let score = 3 + module_score(routine);
                        (is_kernel_address(routine) && score >= 3).then_some(CallbackCandidate {
                            kind: "DbgSetDebugPrintCallback".to_owned(),
                            index: 0,
                            callback_block: body,
                            routine,
                            context: None,
                            detail: None,
                            source: "pool_scan".to_owned(),
                            pool_tag: Some(allocation.tag.clone()),
                            layout: "callbacks-x64!_DBGPRINT_CALLBACK".to_owned(),
                        })
                    }
                    "Pnp9" | "PnpD" | "PnpC" if allocation.pool_index == 1 => {
                        let category = field_u32_in_allocation(space, body, end, 0x10)?;
                        let routine = field(0x20)?;
                        let driver_address = field(0x30)?;
                        let links = list_score()?;
                        let driver =
                            validate_driver_object(space, profile, modules, driver_address)?;
                        let score =
                            links + i32::from(category <= 4) * 3 + 6 + 2 + module_score(routine);
                        (category <= 4 && is_kernel_address(routine) && score >= 13).then_some(
                            CallbackCandidate {
                                kind: event_category_name(category).to_owned(),
                                index: 0,
                                callback_block: body,
                                routine,
                                context: Some(driver_address),
                                detail: Some(format!(
                                    "池标签：{}；驱动：{}",
                                    allocation.tag, driver.name
                                )),
                                source: "pool_scan".to_owned(),
                                pool_tag: Some(allocation.tag.clone()),
                                layout: "callbacks-x64!_NOTIFY_ENTRY_HEADER".to_owned(),
                            },
                        )
                    }
                    _ => None,
                }
            })();
            if let Some(candidate) = candidate {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

fn field_u32_in_allocation(
    space: &X64AddressSpace<'_>,
    body: u64,
    end: u64,
    offset: u64,
) -> Option<u32> {
    let address = body.checked_add(offset)?;
    if address.checked_add(4)? > end {
        return None;
    }
    read_u32_at(space, address)
}

fn score_list_entry(space: &X64AddressSpace<'_>, address: u64) -> Option<i32> {
    let flink = space.read_u64(address).ok()?;
    let blink = space.read_u64(address + 8).ok()?;
    if !is_kernel_pointer(flink) || !is_kernel_pointer(blink) {
        return None;
    }
    let mut score = 2;
    if space.read_u64(flink + 8).ok() == Some(address) {
        score += 2;
    }
    if space.read_u64(blink).ok() == Some(address) {
        score += 2;
    }
    Some(score)
}

fn is_canonical_pointer(pointer: u64) -> bool {
    pointer >> 48 == 0 || pointer >> 48 == 0xffff
}

fn event_category_name(category: u32) -> &'static str {
    match category {
        0 => "EventCategoryReserved",
        1 => "EventCategoryHardwareProfileChange",
        2 => "EventCategoryDeviceInterfaceChange",
        3 => "EventCategoryTargetDeviceChange",
        4 => "EventCategoryKernelSoftRestart",
        _ => "EventCategoryInvalid",
    }
}

fn read_ascii_z(space: &X64AddressSpace<'_>, address: u64, max_length: usize) -> Option<String> {
    if !is_kernel_address(address) {
        return None;
    }
    let mut bytes = Vec::new();
    for index in 0..max_length {
        let mut byte = [0u8; 1];
        space.read_virtual(address + index as u64, &mut byte).ok()?;
        if byte[0] == 0 {
            break;
        }
        if !byte[0].is_ascii_graphic() && byte[0] != b' ' {
            return None;
        }
        bytes.push(byte[0]);
    }
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

pub fn ssdt(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<SsdtReport> {
    ensure!(limit > 0, "SSDT 结果上限必须大于零");
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let modules = list_drivers(image, kernel, profile, 65_536)?;
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut candidate_dtbs = vec![kernel.directory_table_base];
    for process in &processes.processes {
        if let Some(dtb) = process
            .details
            .user_directory_table_base
            .or(process.details.directory_table_base)
            .filter(|dtb| *dtb != 0)
            && !candidate_dtbs.contains(&dtb)
        {
            candidate_dtbs.push(dtb);
        }
    }
    let mut descriptor_candidates = Vec::new();
    if let Ok(rva) = profile.symbol_rva("KeServiceDescriptorTable") {
        descriptor_candidates.push(("nt".to_owned(), kernel.kernel_base + u64::from(rva)));
    }
    if let Ok(rva) = profile.symbol_rva("KeServiceDescriptorTableShadow") {
        let shadow = kernel.kernel_base + u64::from(rva);
        descriptor_candidates.push(("shadow_nt".to_owned(), shadow));
        descriptor_candidates.push(("shadow_win32k".to_owned(), shadow + 0x20));
    }
    let mut seen_tables = HashSet::new();
    let mut descriptors = Vec::new();
    let mut records = Vec::new();
    let mut warnings = modules.warnings;
    for warning in &processes.warnings {
        warnings.push(format!("进程枚举/{}：{}", warning.kind, warning.message));
    }
    let mut complete = modules.complete && processes.complete;
    for (name, descriptor) in descriptor_candidates {
        let service_table = space.read_u64(descriptor).unwrap_or(0);
        let number_of_services = space
            .read_u64(descriptor + 0x10)
            .ok()
            .and_then(|value| u32::try_from(value).ok())
            .or_else(|| read_u32_at(&space, descriptor + 0x10))
            .unwrap_or(0);
        if !is_kernel_pointer(service_table)
            || !(1..=16_384).contains(&number_of_services)
            || !seen_tables.insert(service_table)
        {
            continue;
        }
        let Some(table_dtb) =
            select_service_table_dtb(image, &candidate_dtbs, service_table, number_of_services)
        else {
            complete = false;
            warnings.push(format!(
                "服务表 {name}（{service_table:#x}）在内核及已恢复进程会话页表中均不可读"
            ));
            descriptors.push(SsdtDescriptorRecord {
                name,
                descriptor,
                service_table,
                number_of_services,
                address_space_dtb: 0,
            });
            continue;
        };
        let table_space = X64AddressSpace::new(image, table_dtb)?;
        descriptors.push(SsdtDescriptorRecord {
            name: name.clone(),
            descriptor,
            service_table,
            number_of_services,
            address_space_dtb: table_dtb,
        });
        let mut missing_entries = 0u32;
        for index in 0..number_of_services {
            if records.len() == limit {
                complete = false;
                warnings.push(format!("SSDT 结果达到 {limit} 条上限"));
                break;
            }
            let Some(encoded_entry) =
                read_i32_at(&table_space, service_table + u64::from(index) * 4)
            else {
                complete = false;
                missing_entries += 1;
                continue;
            };
            let routine = service_table.wrapping_add_signed(i64::from(encoded_entry >> 4));
            let module = module_for_address(&modules.records, routine);
            records.push(SsdtRecord {
                table: name.clone(),
                index,
                encoded_entry,
                routine,
                argument_count: (encoded_entry & 0xf) as u8,
                module: module.map(|module| module.path.clone()),
                suspicious_unbacked: module.is_none(),
            });
        }
        if missing_entries != 0 {
            warnings.push(format!(
                "服务表 {name} 有 {missing_entries}/{number_of_services} 个表项不可读"
            ));
        }
        if records.len() == limit {
            break;
        }
    }
    if descriptors.is_empty() {
        complete = false;
        warnings.push("没有恢复出结构有效的系统服务表描述符".to_owned());
    }
    Ok(SsdtReport {
        records,
        descriptors,
        complete,
        warnings,
    })
}

fn select_service_table_dtb(
    image: &MemoryImage,
    candidate_dtbs: &[u64],
    service_table: u64,
    number_of_services: u32,
) -> Option<u64> {
    let mut samples = vec![0u32, number_of_services / 2, number_of_services - 1];
    samples.sort_unstable();
    samples.dedup();
    candidate_dtbs.iter().copied().find(|dtb| {
        let Ok(space) = X64AddressSpace::new(image, *dtb) else {
            return false;
        };
        samples.iter().all(|index| {
            read_i32_at(&space, service_table + u64::from(*index) * 4)
                .map(|entry| service_table.wrapping_add_signed(i64::from(entry >> 4)))
                .is_some_and(|routine| routine >> 48 == 0xffff)
        })
    })
}

pub fn unloaded_modules(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<UnloadedModuleReport> {
    ensure!(limit > 0, "已卸载模块结果上限必须大于零");
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let array_global = kernel.kernel_base + u64::from(profile.symbol_rva("MmUnloadedDrivers")?);
    let index_global = kernel.kernel_base + u64::from(profile.symbol_rva("MmLastUnloadedDriver")?);
    let array = space.read_u64(array_global)?;
    let last_index = read_u32_at(&space, index_global).unwrap_or(0);
    ensure!(
        is_kernel_pointer(array),
        "MmUnloadedDrivers 地址无效：{array:#x}"
    );
    const ENTRY_SIZE: u64 = 0x28;
    const SLOT_COUNT: u32 = 50;
    let mut records = Vec::new();
    for slot in 0..SLOT_COUNT {
        let entry = array + u64::from(slot) * ENTRY_SIZE;
        let Some(name) =
            read_unicode_string(&space, profile, entry, 4096).filter(|name| !name.is_empty())
        else {
            continue;
        };
        let start_address = space.read_u64(entry + 0x10).unwrap_or(0);
        let end_address = space.read_u64(entry + 0x18).unwrap_or(0);
        let current_time_raw = space.read_u64(entry + 0x20).unwrap_or(0);
        if !is_kernel_pointer(start_address) || end_address <= start_address {
            continue;
        }
        records.push(UnloadedModuleRecord {
            slot,
            name,
            start_address,
            end_address,
            current_time_raw,
            time_interpretation: if plausible_filetime(current_time_raw) {
                "filetime_utc".to_owned()
            } else {
                "uptime_100ns".to_owned()
            },
            unload_time: plausible_filetime(current_time_raw)
                .then(|| super::filetime_to_rfc3339(current_time_raw))
                .flatten(),
            unload_uptime_seconds: (!plausible_filetime(current_time_raw))
                .then_some(current_time_raw as f64 / 10_000_000.0),
        });
    }
    records.sort_unstable_by_key(|record| (record.current_time_raw, record.slot));
    let truncated = records.len() > limit;
    records.truncate(limit);
    let warnings = if truncated {
        vec![format!("已卸载模块结果达到 {limit} 条上限")]
    } else {
        Vec::new()
    };
    Ok(UnloadedModuleReport {
        records,
        last_index,
        complete: !truncated,
        warnings,
    })
}

fn find_module_in_allocation(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    allocation: &PoolAllocationRecord,
) -> Option<(u64, u64, u64, u32, String, String)> {
    let type_name = ["_KLDR_DATA_TABLE_ENTRY", "_LDR_DATA_TABLE_ENTRY"]
        .into_iter()
        .find(|name| {
            profile.type_layout(name).is_ok()
                && profile.type_field(name, "DllBase").is_ok()
                && profile.type_field(name, "SizeOfImage").is_ok()
        })?;
    let type_size = profile.type_layout(type_name).ok()?.size;
    for header in allocation.virtual_headers() {
        let end = header.checked_add(allocation.allocation_size)?;
        let last = end.checked_sub(type_size)?;
        let mut candidate = (header + 16 + 0xf) & !0xf;
        while candidate <= last {
            let base = type_u64(space, profile, type_name, candidate, "DllBase").unwrap_or(0);
            let size = type_u32(space, profile, type_name, candidate, "SizeOfImage").unwrap_or(0);
            if is_kernel_pointer(base) && (0x1000..=0x8000_0000).contains(&size) {
                let mut magic = [0u8; 2];
                if space.read_virtual(base, &mut magic).is_ok() && magic == *b"MZ" {
                    let name = type_unicode(space, profile, type_name, candidate, "BaseDllName")
                        .unwrap_or_default();
                    let path = type_unicode(space, profile, type_name, candidate, "FullDllName")
                        .unwrap_or_else(|| name.clone());
                    if !name.is_empty() || !path.is_empty() {
                        let physical =
                            allocation.physical_header + candidate.saturating_sub(header);
                        return Some((candidate, physical, base, size, name, path));
                    }
                }
            }
            candidate += 16;
        }
    }
    None
}

fn find_driver_in_allocation(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    allocation: &PoolAllocationRecord,
) -> Option<DriverObjectRecord> {
    let type_name = "_DRIVER_OBJECT";
    let type_size = profile.type_layout(type_name).ok()?.size;
    for header in allocation.virtual_headers() {
        let end = header.checked_add(allocation.allocation_size)?;
        let last = end.checked_sub(type_size)?;
        let mut candidate = (header + 16 + 0xf) & !0xf;
        while candidate <= last {
            let object_type = type_u16(space, profile, type_name, candidate, "Type");
            let object_size = type_u16(space, profile, type_name, candidate, "Size");
            let start = type_u64(space, profile, type_name, candidate, "DriverStart").unwrap_or(0);
            let size = type_u32(space, profile, type_name, candidate, "DriverSize").unwrap_or(0);
            if object_type == Some(4)
                && object_size.is_some_and(|size| u64::from(size) >= type_size)
                && is_kernel_pointer(start)
                && (0x1000..=0x8000_0000).contains(&size)
            {
                let name = type_unicode(space, profile, type_name, candidate, "DriverName")
                    .unwrap_or_default();
                if name.is_empty() {
                    candidate += 16;
                    continue;
                }
                let major_offset = profile.type_field(type_name, "MajorFunction").ok()?.offset;
                let major_functions = (0..28u64)
                    .map(|index| {
                        space
                            .read_u64(candidate + major_offset + index * 8)
                            .unwrap_or(0)
                    })
                    .collect();
                return Some(DriverObjectRecord {
                    driver_object: candidate,
                    physical_address: allocation.physical_header + candidate.saturating_sub(header),
                    name,
                    driver_start: start,
                    driver_size: size,
                    driver_section: type_pointer(
                        space,
                        profile,
                        type_name,
                        candidate,
                        "DriverSection",
                    ),
                    device_object: type_pointer(
                        space,
                        profile,
                        type_name,
                        candidate,
                        "DeviceObject",
                    ),
                    driver_extension: type_pointer(
                        space,
                        profile,
                        type_name,
                        candidate,
                        "DriverExtension",
                    ),
                    driver_init: type_pointer(space, profile, type_name, candidate, "DriverInit"),
                    driver_start_io: type_pointer(
                        space,
                        profile,
                        type_name,
                        candidate,
                        "DriverStartIo",
                    ),
                    driver_unload: type_pointer(
                        space,
                        profile,
                        type_name,
                        candidate,
                        "DriverUnload",
                    ),
                    fast_io_dispatch: type_pointer(
                        space,
                        profile,
                        type_name,
                        candidate,
                        "FastIoDispatch",
                    ),
                    major_functions,
                });
            }
            candidate += 16;
        }
    }
    None
}

fn module_for_address(modules: &[DriverRecord], address: u64) -> Option<&DriverRecord> {
    modules.iter().find(|module| {
        address >= module.base && address < module.base.saturating_add(u64::from(module.size))
    })
}

fn type_unicode(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<String> {
    let offset = profile.type_field(type_name, field).ok()?.offset;
    read_unicode_string(space, profile, base + offset, 64 * 1024).filter(|value| !value.is_empty())
}

fn type_u8(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u8> {
    let offset = profile.type_field(type_name, field).ok()?.offset;
    let mut bytes = [0u8; 1];
    space.read_virtual(base + offset, &mut bytes).ok()?;
    Some(bytes[0])
}

fn type_u16(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u16> {
    let offset = profile.type_field(type_name, field).ok()?.offset;
    let mut bytes = [0u8; 2];
    space.read_virtual(base + offset, &mut bytes).ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn type_u32(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u32> {
    let offset = profile.type_field(type_name, field).ok()?.offset;
    let mut bytes = [0u8; 4];
    space.read_virtual(base + offset, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn type_u64(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u64> {
    let offset = profile.type_field(type_name, field).ok()?.offset;
    space.read_u64(base + offset).ok()
}

fn read_u32_at(space: &X64AddressSpace<'_>, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_i32_at(space: &X64AddressSpace<'_>, address: u64) -> Option<i32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(i32::from_le_bytes(bytes))
}

fn type_pointer(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u64> {
    type_u64(space, profile, type_name, base, field).filter(|value| is_kernel_pointer(*value))
}

fn irp_major_name(index: u8) -> &'static str {
    const NAMES: [&str; 28] = [
        "CREATE",
        "CREATE_NAMED_PIPE",
        "CLOSE",
        "READ",
        "WRITE",
        "QUERY_INFORMATION",
        "SET_INFORMATION",
        "QUERY_EA",
        "SET_EA",
        "FLUSH_BUFFERS",
        "QUERY_VOLUME_INFORMATION",
        "SET_VOLUME_INFORMATION",
        "DIRECTORY_CONTROL",
        "FILE_SYSTEM_CONTROL",
        "DEVICE_CONTROL",
        "INTERNAL_DEVICE_CONTROL",
        "SHUTDOWN",
        "LOCK_CONTROL",
        "CLEANUP",
        "CREATE_MAILSLOT",
        "QUERY_SECURITY",
        "SET_SECURITY",
        "POWER",
        "SYSTEM_CONTROL",
        "DEVICE_CHANGE",
        "QUERY_QUOTA",
        "SET_QUOTA",
        "PNP",
    ];
    NAMES.get(index as usize).copied().unwrap_or("UNKNOWN")
}

fn plausible_filetime(value: u64) -> bool {
    (116_444_736_000_000_000..=160_000_000_000_000_000).contains(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_all_irp_major_functions() {
        assert_eq!(irp_major_name(0), "CREATE");
        assert_eq!(irp_major_name(27), "PNP");
    }

    #[test]
    fn names_the_complete_fast_io_dispatch_surface() {
        assert_eq!(FAST_IO_FUNCTION_NAMES.len(), 27);
        assert_eq!(FAST_IO_FUNCTION_NAMES[0], "FastIoCheckIfPossible");
        assert_eq!(FAST_IO_FUNCTION_NAMES[26], "ReleaseForCcFlush");
    }

    #[test]
    fn classifies_driver_paths_without_claiming_signature_status() {
        assert_eq!(
            classify_driver_path(Some(r"\SystemRoot\System32\drivers\disk.sys")),
            "system_root"
        );
        assert_eq!(
            classify_driver_path(Some(r"\??\C:\Users\Analyst\Desktop\rootkit.sys")),
            "user_profile"
        );
        assert_eq!(
            classify_driver_path(Some(r"\??\C:\Program Files\Vendor\driver.sys")),
            "program_files"
        );
        assert_eq!(classify_driver_path(None), "unknown");
    }

    #[test]
    fn bugcheck_fallback_layouts_match_x64_records() {
        assert_eq!(
            bugcheck_layout("KeBugCheckCallbackListHead"),
            ("_KBUGCHECK_CALLBACK_RECORD", 0x10, 0x28)
        );
        assert_eq!(
            bugcheck_layout("KeBugCheckReasonCallbackListHead"),
            ("_KBUGCHECK_REASON_CALLBACK_RECORD", 0x10, 0x18)
        );
    }

    #[test]
    fn callback_evidence_lists_are_deduplicated() {
        let mut values = vec!["global_array".to_owned()];
        push_unique(&mut values, "pool_scan".to_owned());
        push_unique(&mut values, "pool_scan".to_owned());
        assert_eq!(values, ["global_array", "pool_scan"]);
    }

    fn callback_candidate(block: u64, routine: u64, source: &str) -> CallbackCandidate {
        CallbackCandidate {
            kind: "test".to_owned(),
            index: 0,
            callback_block: block,
            routine,
            context: None,
            detail: None,
            source: source.to_owned(),
            pool_tag: (source == "pool_scan").then(|| "Cbrb".to_owned()),
            layout: "test".to_owned(),
        }
    }

    #[test]
    fn callback_limit_does_not_stop_evidence_accounting() {
        let mut records = Vec::new();
        let mut seen = HashMap::new();
        let mut stats = CallbackCollectionStats::default();
        push_callback_record(
            &mut records,
            &mut seen,
            &mut stats,
            &[],
            callback_candidate(0xffff_8000_0000_1000, 0xffff_8000_0000_2004, "global_array"),
            1,
        );
        push_callback_record(
            &mut records,
            &mut seen,
            &mut stats,
            &[],
            callback_candidate(0xffff_8000_0000_3000, 0xffff_8000_0000_4004, "linked_list"),
            1,
        );
        push_callback_record(
            &mut records,
            &mut seen,
            &mut stats,
            &[],
            callback_candidate(0xffff_8000_0000_3000, 0xffff_8000_0000_4004, "pool_scan"),
            1,
        );
        assert_eq!(records.len(), 1);
        assert_eq!(stats.evidence_observations, 3);
        assert_eq!(stats.unique_callbacks.len(), 2);
        assert_eq!(stats.active_registrations.len(), 2);
        assert_eq!(stats.duplicate_evidence_merged, 1);
        assert!(stats.truncated);
    }

    #[test]
    fn pool_only_unbacked_callback_is_context_not_active_alert() {
        let mut records = Vec::new();
        let mut seen = HashMap::new();
        let mut stats = CallbackCollectionStats::default();
        push_callback_record(
            &mut records,
            &mut seen,
            &mut stats,
            &[],
            callback_candidate(0xffff_8000_0000_1000, 0xffff_8000_0000_2004, "pool_scan"),
            8,
        );
        assert!(records[0].routine_unbacked_by_loaded_module);
        assert!(!records[0].suspicious_unbacked);
        assert_eq!(records[0].registration_status, "pool_candidate");
    }
}
