use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use super::{WindowsKernelContext, list_processes};
use crate::address::{VirtualAddressRegion, VirtualMappingReport, X64AddressSpace};
use crate::cancellation::CancellationToken;
use crate::image::{MemoryImage, PhysicalSpan, WindowsDump64};
use crate::profile::KernelProfile;
use crate::scan::scan_exact_4_cancellable;

#[derive(Debug, Serialize)]
pub struct CrashInfoReport {
    pub image: String,
    pub signature: String,
    pub dump_type: u32,
    pub dump_type_name: String,
    pub major_version: u32,
    pub minor_version: u32,
    pub machine_type: u32,
    pub machine_type_name: String,
    pub number_processors: u32,
    pub directory_table_base: u64,
    pub pfn_database: u64,
    pub ps_loaded_module_list: u64,
    pub ps_active_process_head: u64,
    pub kd_debugger_data_block: u64,
    pub bug_check_code: u32,
    pub bug_check_parameters: [u64; 4],
    pub required_dump_space: u64,
    pub system_time_raw: u64,
    pub system_time: Option<String>,
    pub system_uptime_100ns: u64,
    pub system_uptime_seconds: f64,
    pub comment: String,
    pub mini_dump_fields: u32,
    pub secondary_data_state: u32,
    pub product_type: u32,
    pub suite_mask: u32,
    pub writer_status: u32,
    pub number_of_runs: u32,
    pub number_of_pages: u64,
    pub physical_spans: Vec<PhysicalSpan>,
}

#[derive(Debug, Serialize)]
pub struct KpcrReport {
    pub processor_count_reported: u32,
    pub records: Vec<KpcrRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct KpcrRecord {
    pub processor_index: u32,
    pub kpcr: u64,
    pub prcb: u64,
    pub self_pointer: Option<u64>,
    pub current_prcb: Option<u64>,
    pub processor_number: Option<u32>,
    pub group: Option<u16>,
    pub group_index: Option<u8>,
    pub mhz: Option<u32>,
    pub vendor: Option<String>,
    pub current_thread: Option<u64>,
    pub next_thread: Option<u64>,
    pub idle_thread: Option<u64>,
    pub gdt_base: Option<u64>,
    pub idt_base: Option<u64>,
    pub cr0: Option<u64>,
    pub cr2: Option<u64>,
    pub cr3: Option<u64>,
    pub cr4: Option<u64>,
    pub cr8: Option<u64>,
    pub dr0: Option<u64>,
    pub dr1: Option<u64>,
    pub dr2: Option<u64>,
    pub dr3: Option<u64>,
    pub dr6: Option<u64>,
    pub dr7: Option<u64>,
    pub hardware_breakpoints_active: bool,
}

#[derive(Debug, Serialize)]
pub struct PhysicalMemoryRunRecord {
    pub base_page: u64,
    pub page_count: u64,
    pub physical_start: u64,
    pub length: u64,
}

#[derive(Debug, Serialize)]
pub struct MemoryStatisticsReport {
    pub image: String,
    pub image_format: String,
    pub file_size: u64,
    pub logical_size: u64,
    pub acquired_physical_bytes: u64,
    pub physical_span_count: usize,
    pub highest_acquired_physical_address: Option<u64>,
    pub kernel_directory_table_base: u64,
    pub kernel_mapped_bytes: u64,
    pub kernel_mapping_count: usize,
    pub kernel_page_table_pages_read: u64,
    pub kernel_4k_mapping_count: usize,
    pub kernel_2m_mapping_count: usize,
    pub kernel_1g_mapping_count: usize,
    pub kernel_writable_executable_bytes: u64,
    pub physical_memory_descriptor_pages: Option<u64>,
    pub physical_memory_runs: Vec<PhysicalMemoryRunRecord>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BigPoolReport {
    pub table: u64,
    pub declared_entries: u64,
    pub records: Vec<BigPoolRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BigPoolRecord {
    pub entry: u64,
    pub virtual_address: u64,
    pub tag: String,
    pub key_raw: u32,
    pub number_of_bytes: u64,
    pub pool_flags: u32,
    pub process_billed: Option<u64>,
    pub free: bool,
}

#[derive(Debug, Serialize)]
pub struct PoolScanReport {
    pub tags: Vec<String>,
    pub bytes_scanned: u64,
    pub elapsed_seconds: f64,
    pub gib_per_second: f64,
    pub records: Vec<PoolAllocationRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PoolAllocationRecord {
    pub physical_header: u64,
    pub physical_body: u64,
    pub kernel_virtual_header: Option<u64>,
    pub kernel_virtual_body: Option<u64>,
    /// 此物理池页在内核页表中的全部候选虚拟映射。
    ///
    /// 旧版 Windows 经常同时保留直接映射、会话映射或其他别名；只取
    /// 第一个映射会让上层结构验证在错误别名上静默失败。
    pub kernel_virtual_headers: Vec<u64>,
    pub tag: String,
    pub previous_size: u16,
    pub block_size: u16,
    pub allocation_size: u64,
    pub pool_index: u8,
    pub pool_type: u8,
}

impl PoolAllocationRecord {
    pub fn virtual_headers(&self) -> impl Iterator<Item = u64> + '_ {
        self.kernel_virtual_headers.iter().copied()
    }

    pub fn physical_address_for(&self, virtual_address: u64) -> Option<u64> {
        self.virtual_headers().find_map(|header| {
            let offset = virtual_address.checked_sub(header)?;
            (offset < self.allocation_size).then(|| self.physical_header + offset)
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ProcessMemmapReport {
    pub pid: u64,
    pub process: String,
    pub eprocess: u64,
    pub directory_table_base: u64,
    pub mappings: VirtualMappingReport,
}

#[derive(Debug, Clone, Copy)]
pub enum StringOffsetKind {
    Physical,
    File,
}

#[derive(Debug, Serialize)]
pub struct StringsMapReport {
    pub records: Vec<StringMappingRecord>,
    pub input_records: usize,
    pub mapped_records: usize,
    pub malformed_lines: usize,
    pub process_address_spaces: usize,
    pub truncated: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StringMappingRecord {
    pub source_offset: u64,
    pub physical_address: u64,
    pub text: String,
    pub owners: Vec<StringMappingOwner>,
}

#[derive(Debug, Serialize)]
pub struct StringMappingOwner {
    pub pid: Option<u64>,
    pub process: String,
    pub virtual_address: u64,
    pub address_space: String,
}

pub fn crash_info(image: &MemoryImage) -> Result<CrashInfoReport> {
    let dump = image
        .dump64()
        .context("crashinfo 需要 64 位 Windows 崩溃转储")?;
    Ok(CrashInfoReport {
        image: image.path().display().to_string(),
        signature: "PAGEDU64".to_owned(),
        dump_type: dump.dump_type,
        dump_type_name: dump_type_name(dump.dump_type).to_owned(),
        major_version: dump.major_version,
        minor_version: dump.minor_version,
        machine_type: dump.machine_type,
        machine_type_name: machine_type_name(dump.machine_type).to_owned(),
        number_processors: dump.number_processors,
        directory_table_base: dump.directory_table_base,
        pfn_database: dump.pfn_database,
        ps_loaded_module_list: dump.ps_loaded_module_list,
        ps_active_process_head: dump.ps_active_process_head,
        kd_debugger_data_block: dump.kd_debugger_data_block,
        bug_check_code: dump.bug_check_code,
        bug_check_parameters: dump.bug_check_parameters,
        required_dump_space: dump.required_dump_space,
        system_time_raw: dump.system_time_raw,
        system_time: windows_filetime_to_rfc3339(dump.system_time_raw),
        system_uptime_100ns: dump.system_uptime_100ns,
        system_uptime_seconds: dump.system_uptime_100ns as f64 / 10_000_000.0,
        comment: dump.comment.clone(),
        mini_dump_fields: dump.mini_dump_fields,
        secondary_data_state: dump.secondary_data_state,
        product_type: dump.product_type,
        suite_mask: dump.suite_mask,
        writer_status: dump.writer_status,
        number_of_runs: dump.number_of_runs,
        number_of_pages: dump.number_of_pages,
        physical_spans: image.spans().to_vec(),
    })
}

pub fn list_kpcrs(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<KpcrReport> {
    ensure!(limit > 0, "KPCR 结果上限必须大于零");
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let processor_count_reported = processor_count(image.dump64(), &space, kernel, profile);
    let count = processor_count_reported.min(limit as u32);
    let processor_block = symbol_address(kernel, profile, "KiProcessorBlock")?;
    let prcb_offset = profile.type_field("_KPCR", "Prcb")?.offset;
    let mut records = Vec::new();
    let mut warnings = Vec::new();
    for processor_index in 0..count {
        let pointer_address = processor_block + u64::from(processor_index) * 8;
        let prcb = match space.read_u64(pointer_address) {
            Ok(value) if is_kernel_pointer(value) => value,
            Ok(value) => {
                warnings.push(format!(
                    "KiProcessorBlock[{processor_index}] 包含无效的 KPRCB {value:#x}"
                ));
                continue;
            }
            Err(error) => {
                warnings.push(format!(
                    "无法读取 KiProcessorBlock[{processor_index}]：{error:#}"
                ));
                continue;
            }
        };
        let Some(kpcr) = prcb.checked_sub(prcb_offset) else {
            continue;
        };
        let processor_state =
            field_offset(profile, "_KPRCB", "ProcessorState").map(|offset| prcb + offset);
        let special = processor_state.and_then(|state| {
            field_offset(profile, "_KPROCESSOR_STATE", "SpecialRegisters")
                .map(|offset| state + offset)
        });
        let special_u64 = |name: &str| {
            special.and_then(|base| type_u64(&space, profile, "_KSPECIAL_REGISTERS", base, name))
        };
        let dr0 = special_u64("KernelDr0");
        let dr1 = special_u64("KernelDr1");
        let dr2 = special_u64("KernelDr2");
        let dr3 = special_u64("KernelDr3");
        let dr6 = special_u64("KernelDr6");
        let dr7 = special_u64("KernelDr7");
        let hardware_breakpoints_active = [dr0, dr1, dr2, dr3]
            .into_iter()
            .flatten()
            .any(|value| value != 0)
            || dr7.is_some_and(|value| value & 0xff != 0);
        records.push(KpcrRecord {
            processor_index,
            kpcr,
            prcb,
            self_pointer: type_u64(&space, profile, "_KPCR", kpcr, "Self"),
            current_prcb: type_u64(&space, profile, "_KPCR", kpcr, "CurrentPrcb"),
            processor_number: type_u32(&space, profile, "_KPRCB", prcb, "Number"),
            group: type_u16(&space, profile, "_KPRCB", prcb, "Group"),
            group_index: type_u8(&space, profile, "_KPRCB", prcb, "GroupIndex"),
            mhz: type_u32(&space, profile, "_KPRCB", prcb, "MHz"),
            vendor: read_fixed_ascii_field(&space, profile, "_KPRCB", prcb, "VendorString", 32),
            current_thread: type_kernel_pointer(&space, profile, "_KPRCB", prcb, "CurrentThread"),
            next_thread: type_kernel_pointer(&space, profile, "_KPRCB", prcb, "NextThread"),
            idle_thread: type_kernel_pointer(&space, profile, "_KPRCB", prcb, "IdleThread"),
            gdt_base: type_u64(&space, profile, "_KPCR", kpcr, "GdtBase"),
            idt_base: type_u64(&space, profile, "_KPCR", kpcr, "IdtBase"),
            cr0: special_u64("Cr0"),
            cr2: special_u64("Cr2"),
            cr3: special_u64("Cr3"),
            cr4: special_u64("Cr4"),
            cr8: special_u64("Cr8"),
            dr0,
            dr1,
            dr2,
            dr3,
            dr6,
            dr7,
            hardware_breakpoints_active,
        });
    }
    Ok(KpcrReport {
        processor_count_reported,
        complete: count == processor_count_reported
            && records.len() == count as usize
            && warnings.is_empty(),
        records,
        warnings,
    })
}

pub fn kernel_virtmap(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    limit: usize,
) -> Result<VirtualMappingReport> {
    X64AddressSpace::new(image, kernel.directory_table_base)?
        .enumerate_mappings(VirtualAddressRegion::Kernel, limit)
}

pub fn process_memmap(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid: u64,
    limit: usize,
) -> Result<ProcessMemmapReport> {
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let process = processes
        .processes
        .iter()
        .find(|process| process.pid == pid)
        .with_context(|| format!("PsActiveProcessHead 中没有 PID {pid}"))?;
    let directory_table_base = process
        .details
        .user_directory_table_base
        .or(process.details.directory_table_base)
        .context("进程没有可恢复的页表根")?;
    let mappings = X64AddressSpace::new(image, directory_table_base)?
        .enumerate_mappings(VirtualAddressRegion::User, limit)?;
    Ok(ProcessMemmapReport {
        pid,
        process: process.name.clone(),
        eprocess: process.eprocess,
        directory_table_base,
        mappings,
    })
}

pub fn map_strings(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    strings_file: &Path,
    offset_kind: StringOffsetKind,
    limit: usize,
) -> Result<StringsMapReport> {
    ensure!(limit > 0, "字符串映射结果上限必须大于零");
    let input = File::open(strings_file)
        .with_context(|| format!("无法打开字符串文件 {}", strings_file.display()))?;
    let mut parsed = Vec::new();
    let mut malformed_lines = 0usize;
    let mut truncated = false;
    for line in BufReader::new(input).lines() {
        let line = line?;
        let Some((source_offset, text)) = parse_strings_line(&line) else {
            malformed_lines += 1;
            continue;
        };
        let physical_address = match offset_kind {
            StringOffsetKind::Physical => Some(source_offset),
            StringOffsetKind::File => file_offset_to_physical(image, source_offset),
        };
        let Some(physical_address) = physical_address else {
            continue;
        };
        if parsed.len() == limit {
            truncated = true;
            break;
        }
        parsed.push((source_offset, physical_address, text));
    }
    let targets = parsed
        .iter()
        .map(|(_, physical, _)| physical & !0xfff)
        .collect::<HashSet<_>>();
    let kernel_space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let kernel_reverse = kernel_space.reverse_translate_kernel_pages(&targets, 16)?;
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut address_spaces = BTreeMap::<u64, Vec<(u64, String)>>::new();
    for process in &processes.processes {
        if let Some(dtb) = process
            .details
            .user_directory_table_base
            .or(process.details.directory_table_base)
        {
            address_spaces
                .entry(dtb & 0x000f_ffff_ffff_f000)
                .or_default()
                .push((process.pid, process.name.clone()));
        }
    }
    let mut process_reverse = Vec::new();
    let mut warnings = processes
        .warnings
        .into_iter()
        .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
        .collect::<Vec<_>>();
    for (dtb, owners) in &address_spaces {
        match X64AddressSpace::new(image, *dtb).and_then(|space| {
            space.reverse_translate_pages(&targets, VirtualAddressRegion::User, 16)
        }) {
            Ok(reverse) => process_reverse.push((owners, reverse)),
            Err(error) => push_limited(
                &mut warnings,
                format!("无法反向映射进程 DTB {dtb:#x}：{error:#}"),
            ),
        }
    }
    let mut records = Vec::with_capacity(parsed.len());
    for (source_offset, physical_address, text) in parsed {
        let page = physical_address & !0xfff;
        let delta = physical_address & 0xfff;
        let mut owners = Vec::new();
        if let Some(addresses) = kernel_reverse.get(&page) {
            owners.extend(addresses.iter().map(|address| StringMappingOwner {
                pid: None,
                process: "内核".to_owned(),
                virtual_address: address + delta,
                address_space: "内核空间".to_owned(),
            }));
        }
        for (processes, reverse) in &process_reverse {
            let Some(addresses) = reverse.get(&page) else {
                continue;
            };
            for (pid, process) in processes.iter() {
                owners.extend(addresses.iter().map(|address| StringMappingOwner {
                    pid: Some(*pid),
                    process: process.clone(),
                    virtual_address: address + delta,
                    address_space: "用户空间".to_owned(),
                }));
            }
        }
        owners.sort_unstable_by_key(|owner| (owner.pid.unwrap_or(0), owner.virtual_address));
        owners.dedup_by_key(|owner| (owner.pid, owner.virtual_address));
        records.push(StringMappingRecord {
            source_offset,
            physical_address,
            text,
            owners,
        });
    }
    let mapped_records = records
        .iter()
        .filter(|record| !record.owners.is_empty())
        .count();
    if truncated {
        warnings.push(format!("字符串输入达到 {limit} 条上限"));
    }
    Ok(StringsMapReport {
        input_records: records.len(),
        mapped_records,
        malformed_lines,
        process_address_spaces: address_spaces.len(),
        records,
        truncated,
        warnings,
    })
}

pub fn memory_statistics(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    mapping_limit: usize,
) -> Result<MemoryStatisticsReport> {
    let mapping_report = kernel_virtmap(image, kernel, mapping_limit)?;
    let mut warnings = mapping_report.warnings.clone();
    if mapping_report.truncated {
        warnings.push(format!(
            "内核映射报告达到 {mapping_limit} 条上限；字节总数仅覆盖保留的映射"
        ));
    }
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let (descriptor_pages, physical_memory_runs) =
        physical_memory_descriptor(&space, kernel, profile).unwrap_or_else(|error| {
            warnings.push(format!("无法读取 MmPhysicalMemoryBlock：{error:#}"));
            (None, Vec::new())
        });
    let kernel_4k_mapping_count = mapping_report
        .mappings
        .iter()
        .filter(|mapping| mapping.source_page_size == 0x1000)
        .count();
    let kernel_2m_mapping_count = mapping_report
        .mappings
        .iter()
        .filter(|mapping| mapping.source_page_size == 0x20_0000)
        .count();
    let kernel_1g_mapping_count = mapping_report
        .mappings
        .iter()
        .filter(|mapping| mapping.source_page_size == 0x4000_0000)
        .count();
    let kernel_writable_executable_bytes = mapping_report
        .mappings
        .iter()
        .filter(|mapping| mapping.writable && mapping.executable)
        .fold(0u64, |total, mapping| total.saturating_add(mapping.length));
    Ok(MemoryStatisticsReport {
        image: image.path().display().to_string(),
        image_format: format!("{:?}", image.format()),
        file_size: image.file_len(),
        logical_size: image.logical_len(),
        acquired_physical_bytes: image.mapped_bytes(),
        physical_span_count: image.spans().len(),
        highest_acquired_physical_address: image.spans().iter().map(PhysicalSpan::end).max(),
        kernel_directory_table_base: kernel.directory_table_base,
        kernel_mapped_bytes: mapping_report.mapped_bytes,
        kernel_mapping_count: mapping_report.mapping_count,
        kernel_page_table_pages_read: mapping_report.page_table_pages_read,
        kernel_4k_mapping_count,
        kernel_2m_mapping_count,
        kernel_1g_mapping_count,
        kernel_writable_executable_bytes,
        physical_memory_descriptor_pages: descriptor_pages,
        physical_memory_runs,
        warnings,
    })
}

pub fn list_big_pools(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    tags: &[String],
    show_free: bool,
    limit: usize,
) -> Result<BigPoolReport> {
    ensure!(limit > 0, "大页池结果上限必须大于零");
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let table_global = symbol_address(kernel, profile, "PoolBigPageTable")?;
    let size_global = symbol_address(kernel, profile, "PoolBigPageTableSize")?;
    let table = space.read_u64(table_global)?;
    let declared_entries = u64::from(read_u32(&space, size_global)?);
    ensure!(
        is_kernel_pointer(table),
        "PoolBigPageTable 地址无效：{table:#x}"
    );
    ensure!(
        declared_entries <= 16 * 1024 * 1024,
        "大页池表大小 {declared_entries} 不合理"
    );
    let layout = profile.type_layout("_POOL_TRACKER_BIG_PAGES")?;
    let entry_size = layout.size;
    ensure!(entry_size >= 0x18, "大页池条目布局过小");
    let va_offset = profile.type_field("_POOL_TRACKER_BIG_PAGES", "Va")?.offset;
    let key_offset = profile.type_field("_POOL_TRACKER_BIG_PAGES", "Key")?.offset;
    let flags_offset = profile
        .type_field("_POOL_TRACKER_BIG_PAGES", "PoolFlags")
        .or_else(|_| profile.type_field("_POOL_TRACKER_BIG_PAGES", "Pattern"))
        .or_else(|_| profile.type_field("_POOL_TRACKER_BIG_PAGES", "PoolType"))?
        .offset;
    let bytes_offset = profile
        .type_field("_POOL_TRACKER_BIG_PAGES", "NumberOfBytes")?
        .offset;
    let billed_offset = profile
        .type_field("_POOL_TRACKER_BIG_PAGES", "ProcessBilled")
        .ok()
        .map(|field| field.offset);
    let tag_filter = tags
        .iter()
        .map(|tag| tag.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mut records = Vec::new();
    let mut warnings = Vec::new();
    for index in 0..declared_entries {
        if records.len() == limit {
            warnings.push(format!("大页池结果达到 {limit} 条上限"));
            break;
        }
        let entry = table + index * entry_size;
        let va = match space.read_u64(entry + va_offset) {
            Ok(value) => value,
            Err(error) => {
                push_limited(
                    &mut warnings,
                    format!("无法读取大页池条目 {entry:#x}：{error:#}"),
                );
                continue;
            }
        };
        let key_raw = match read_u32(&space, entry + key_offset) {
            Ok(value) if value != 0 => value,
            _ => continue,
        };
        let tag = pool_tag(key_raw);
        if !tag_filter.is_empty() && !tag_filter.contains(&tag.to_ascii_lowercase()) {
            continue;
        }
        let free = va & 1 != 0;
        if free && !show_free {
            continue;
        }
        let number_of_bytes = space.read_u64(entry + bytes_offset).unwrap_or(0);
        if number_of_bytes == 0 {
            continue;
        }
        records.push(BigPoolRecord {
            entry,
            virtual_address: va & !1,
            tag,
            key_raw,
            number_of_bytes,
            pool_flags: read_u32(&space, entry + flags_offset).unwrap_or(0),
            process_billed: billed_offset
                .and_then(|offset| space.read_u64(entry + offset).ok())
                .filter(|value| *value != 0),
            free,
        });
    }
    records.sort_unstable_by_key(|record| record.virtual_address);
    Ok(BigPoolReport {
        table,
        declared_entries,
        complete: records.len() < limit && warnings.is_empty(),
        records,
        warnings,
    })
}

pub fn scan_pool_allocations(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    tags: &[[u8; 4]],
    limit_per_tag: usize,
) -> Result<PoolScanReport> {
    scan_pool_allocations_cancellable(
        image,
        kernel,
        profile,
        tags,
        limit_per_tag,
        &CancellationToken::new(),
    )
}

pub fn scan_pool_allocations_cancellable(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    tags: &[[u8; 4]],
    limit_per_tag: usize,
    cancellation: &CancellationToken,
) -> Result<PoolScanReport> {
    cancellation.check_cancelled()?;
    ensure!(!tags.is_empty(), "请至少提供一个四字节池标签");
    ensure!(limit_per_tag > 0, "内存池结果上限必须大于零");
    // This limit applies only to raw string hits and is deliberately much
    // larger than the requested result limit. Result limiting happens after
    // pool-header, type-size, pool-kind, and kernel-mapping validation.
    const RAW_HIT_LIMIT_PER_TAG: usize = 4_000_000;
    let (scan_tags, pattern_to_tag) = pool_tag_patterns(tags);
    #[cfg(debug_assertions)]
    eprintln!(
        "[starmem-debug][poolscan] tag-scan:start tags={} threads={}",
        tags.len(),
        rayon::current_num_threads()
    );
    let scan = scan_exact_4_cancellable(
        image,
        &scan_tags,
        RAW_HIT_LIMIT_PER_TAG,
        64 * 1024 * 1024,
        cancellation,
    )?;
    #[cfg(debug_assertions)]
    eprintln!(
        "[starmem-debug][poolscan] tag-scan:done hits={} bytes={}",
        scan.hits.len(),
        scan.bytes_scanned
    );
    let mut provisional = Vec::new();
    let mut target_pages = HashSet::new();
    for hit in &scan.hits {
        cancellation.check_cancelled()?;
        if hit.physical_address & 0xf != 4 {
            continue;
        }
        let Some(physical_header) = hit.physical_address.checked_sub(4) else {
            continue;
        };
        let mut header = [0u8; 16];
        let observed_tag = scan_tags[hit.pattern_index];
        let canonical_index = pattern_to_tag[hit.pattern_index];
        let canonical_tag = tags[canonical_index];
        if image.read_physical(physical_header, &mut header).is_err()
            || header[4..8] != observed_tag
        {
            continue;
        }
        let previous_size = u16::from(header[0]);
        let pool_index = header[1];
        let block_size = u16::from(header[2]);
        let pool_type = header[3];
        let allocation_size = u64::from(block_size) * 16;
        if block_size == 0 || allocation_size > 0x10_0000 {
            continue;
        }
        let constraint = pool_constraint(&canonical_tag, profile);
        if allocation_size < constraint.minimum_size || !constraint.pool_kind.accepts(pool_type) {
            continue;
        }
        target_pages.insert(physical_header & !0xfff);
        provisional.push((
            physical_header,
            canonical_index,
            String::from_utf8_lossy(&canonical_tag).into_owned(),
            previous_size,
            block_size,
            allocation_size,
            pool_index,
            pool_type,
        ));
    }
    #[cfg(debug_assertions)]
    eprintln!(
        "[starmem-debug][poolscan] reverse-map:start provisional={} pages={}",
        provisional.len(),
        target_pages.len()
    );
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    cancellation.check_cancelled()?;
    let reverse = space.reverse_translate_kernel_pages(&target_pages, 64)?;
    #[cfg(debug_assertions)]
    eprintln!(
        "[starmem-debug][poolscan] reverse-map:done mapped_pages={}",
        reverse.len()
    );
    cancellation.check_cancelled()?;
    let mut retained_per_tag = vec![0usize; tags.len()];
    let mut validated_per_tag = vec![0usize; tags.len()];
    let mut records: Vec<PoolAllocationRecord> = provisional
        .into_iter()
        .filter_map(
            |(
                physical_header,
                pattern_index,
                tag,
                previous_size,
                block_size,
                allocation_size,
                pool_index,
                pool_type,
            )| {
                let mut kernel_virtual_headers = reverse
                    .get(&(physical_header & !0xfff))
                    .into_iter()
                    .flatten()
                    .map(|page| page + (physical_header & 0xfff))
                    .collect::<Vec<_>>();
                kernel_virtual_headers.sort_unstable();
                kernel_virtual_headers.dedup();
                let kernel_virtual_header = kernel_virtual_headers.first().copied()?;
                validated_per_tag[pattern_index] += 1;
                if retained_per_tag[pattern_index] == limit_per_tag {
                    return None;
                }
                retained_per_tag[pattern_index] += 1;
                Some(PoolAllocationRecord {
                    physical_header,
                    physical_body: physical_header + 16,
                    kernel_virtual_header: Some(kernel_virtual_header),
                    kernel_virtual_body: Some(kernel_virtual_header + 16),
                    kernel_virtual_headers,
                    tag,
                    previous_size,
                    block_size,
                    allocation_size,
                    pool_index,
                    pool_type,
                })
            },
        )
        .collect();
    cancellation.check_cancelled()?;
    records.sort_unstable_by_key(|record| {
        (
            record.kernel_virtual_header.unwrap_or(u64::MAX),
            record.physical_header,
        )
    });
    let mut warnings = Vec::new();
    if scan.truncated {
        warnings.push(format!(
            "一个或多个池标签的原始命中数超过安全上限 {RAW_HIT_LIMIT_PER_TAG}"
        ));
    }
    if validated_per_tag.iter().any(|count| *count > limit_per_tag) {
        warnings.push(format!(
            "一个或多个已验证池标签的结果达到 {limit_per_tag} 条上限"
        ));
    }
    Ok(PoolScanReport {
        tags: tags
            .iter()
            .map(|tag| String::from_utf8_lossy(tag).into_owned())
            .collect(),
        bytes_scanned: scan.bytes_scanned,
        elapsed_seconds: scan.elapsed_seconds,
        gib_per_second: scan.gib_per_second,
        complete: !scan.truncated
            && validated_per_tag
                .iter()
                .all(|count| *count <= limit_per_tag),
        records,
        warnings,
    })
}

fn pool_tag_patterns(tags: &[[u8; 4]]) -> (Vec<[u8; 4]>, Vec<usize>) {
    let mut patterns = Vec::with_capacity(tags.len() * 2);
    let mut owners = Vec::with_capacity(tags.len() * 2);
    for (index, tag) in tags.iter().copied().enumerate() {
        patterns.push(tag);
        owners.push(index);
        if tag[3] & 0x80 == 0 {
            let mut protected = tag;
            protected[3] |= 0x80;
            patterns.push(protected);
            owners.push(index);
        }
    }
    (patterns, owners)
}

#[derive(Clone, Copy)]
enum PoolKindConstraint {
    Any,
    NonPagedOrFree,
    PagedOrFree,
}

impl PoolKindConstraint {
    fn accepts(self, pool_type: u8) -> bool {
        match self {
            Self::Any => true,
            Self::NonPagedOrFree => pool_type == 0 || pool_type.is_multiple_of(2),
            Self::PagedOrFree => pool_type == 0 || !pool_type.is_multiple_of(2),
        }
    }
}

struct PoolConstraint {
    minimum_size: u64,
    pool_kind: PoolKindConstraint,
}

fn pool_constraint(tag: &[u8; 4], profile: &KernelProfile) -> PoolConstraint {
    let (type_name, fallback_size, pool_kind) = match tag {
        b"Proc" => (Some("_EPROCESS"), 600, PoolKindConstraint::NonPagedOrFree),
        b"Thre" => (Some("_ETHREAD"), 600, PoolKindConstraint::NonPagedOrFree),
        b"File" => (
            Some("_FILE_OBJECT"),
            150,
            PoolKindConstraint::NonPagedOrFree,
        ),
        b"Muta" => (Some("_KMUTANT"), 64, PoolKindConstraint::NonPagedOrFree),
        b"Driv" => (
            Some("_DRIVER_OBJECT"),
            248,
            PoolKindConstraint::NonPagedOrFree,
        ),
        b"MmLd" => (
            ["_KLDR_DATA_TABLE_ENTRY", "_LDR_DATA_TABLE_ENTRY"]
                .into_iter()
                .find(|name| profile.type_layout(name).is_ok()),
            76,
            PoolKindConstraint::NonPagedOrFree,
        ),
        b"Symb" => (
            Some("_OBJECT_SYMBOLIC_LINK"),
            72,
            PoolKindConstraint::PagedOrFree,
        ),
        b"CM10" => (Some("_CMHIVE"), 800, PoolKindConstraint::PagedOrFree),
        b"AtmT" => (Some("_RTL_ATOM_TABLE"), 200, PoolKindConstraint::Any),
        // Private callback structures are described by the callbacks-x64
        // layout data rather than public kernel PDB types.  These
        // are whole-allocation lower bounds, followed by stricter structure
        // and relationship validation in callbacks.
        b"IoFs" => (None, 0x30, PoolKindConstraint::Any),
        b"IoSh" => (None, 0x18, PoolKindConstraint::Any),
        b"Cbrb" => (None, 0x18, PoolKindConstraint::Any),
        b"DbCb" => (None, 0x20, PoolKindConstraint::Any),
        b"Pnp9" => (None, 0x30, PoolKindConstraint::Any),
        b"PnpD" => (None, 0x40, PoolKindConstraint::Any),
        b"PnpC" => (None, 0x38, PoolKindConstraint::Any),
        _ => (None, 16, PoolKindConstraint::Any),
    };
    let minimum_size = type_name
        .and_then(|name| profile.type_layout(name).ok())
        // Pool constraints describe the whole allocation, while PDB sizes only
        // describe the object body. Never weaken the proven per-tag minimum.
        .map(|layout| layout.size.max(fallback_size))
        .unwrap_or(fallback_size);
    PoolConstraint {
        minimum_size,
        pool_kind,
    }
}

fn physical_memory_descriptor(
    space: &X64AddressSpace<'_>,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
) -> Result<(Option<u64>, Vec<PhysicalMemoryRunRecord>)> {
    let global = symbol_address(kernel, profile, "MmPhysicalMemoryBlock")?;
    let descriptor = space.read_u64(global)?;
    ensure!(
        is_kernel_pointer(descriptor),
        "物理内存描述符地址无效：{descriptor:#x}"
    );
    let number_of_runs_offset =
        field_offset(profile, "_PHYSICAL_MEMORY_DESCRIPTOR", "NumberOfRuns").unwrap_or(0);
    let number_of_pages_offset =
        field_offset(profile, "_PHYSICAL_MEMORY_DESCRIPTOR", "NumberOfPages").unwrap_or(8);
    let run_offset = field_offset(profile, "_PHYSICAL_MEMORY_DESCRIPTOR", "Run").unwrap_or(0x10);
    let run_size = profile
        .type_layout("_PHYSICAL_MEMORY_RUN")
        .map(|layout| layout.size)
        .unwrap_or(0x10);
    let base_page_offset = field_offset(profile, "_PHYSICAL_MEMORY_RUN", "BasePage").unwrap_or(0);
    let page_count_offset = field_offset(profile, "_PHYSICAL_MEMORY_RUN", "PageCount").unwrap_or(8);
    let number_of_runs = u64::from(read_u32(space, descriptor + number_of_runs_offset)?);
    ensure!(
        number_of_runs <= 4096,
        "物理内存区间数量 {number_of_runs} 不合理"
    );
    let number_of_pages = space.read_u64(descriptor + number_of_pages_offset).ok();
    let mut runs = Vec::with_capacity(number_of_runs as usize);
    for index in 0..number_of_runs {
        let entry = descriptor + run_offset + index * run_size;
        let base_page = space.read_u64(entry + base_page_offset)?;
        let page_count = space.read_u64(entry + page_count_offset)?;
        if page_count == 0 {
            continue;
        }
        runs.push(PhysicalMemoryRunRecord {
            base_page,
            page_count,
            physical_start: base_page.saturating_mul(0x1000),
            length: page_count.saturating_mul(0x1000),
        });
    }
    Ok((number_of_pages, runs))
}

fn parse_strings_line(line: &str) -> Option<(u64, String)> {
    let line = line.trim_start();
    let separator = line
        .char_indices()
        .find(|(_, character)| character.is_ascii_whitespace() || *character == ':')?
        .0;
    let offset_text = &line[..separator];
    let text = line[separator..]
        .trim_start_matches(|character: char| character.is_ascii_whitespace() || character == ':');
    if text.is_empty() {
        return None;
    }
    let source_offset = if let Some(hex) = offset_text
        .strip_prefix("0x")
        .or_else(|| offset_text.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        offset_text.parse().ok()?
    };
    Some((source_offset, text.to_owned()))
}

fn file_offset_to_physical(image: &MemoryImage, file_offset: u64) -> Option<u64> {
    image.file_offset_to_physical(file_offset)
}

fn processor_count(
    dump: Option<&WindowsDump64>,
    space: &X64AddressSpace<'_>,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
) -> u32 {
    dump.map(|dump| dump.number_processors)
        .filter(|count| (1..=4096).contains(count))
        .or_else(|| {
            let address = symbol_address(kernel, profile, "KeNumberProcessors").ok()?;
            read_u32(space, address)
                .ok()
                .filter(|count| (1..=4096).contains(count))
                .or_else(|| read_u8(space, address).ok().map(u32::from))
        })
        .unwrap_or(1)
}

fn symbol_address(
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    name: &str,
) -> Result<u64> {
    Ok(kernel.kernel_base + u64::from(profile.symbol_rva(name)?))
}

fn field_offset(profile: &KernelProfile, type_name: &str, field: &str) -> Option<u64> {
    profile
        .type_field(type_name, field)
        .ok()
        .map(|field| field.offset)
}

fn type_u8(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u8> {
    field_offset(profile, type_name, field).and_then(|offset| read_u8(space, base + offset).ok())
}

fn type_u16(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u16> {
    field_offset(profile, type_name, field).and_then(|offset| read_u16(space, base + offset).ok())
}

fn type_u32(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u32> {
    field_offset(profile, type_name, field).and_then(|offset| read_u32(space, base + offset).ok())
}

fn type_u64(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u64> {
    field_offset(profile, type_name, field).and_then(|offset| space.read_u64(base + offset).ok())
}

fn type_kernel_pointer(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u64> {
    type_u64(space, profile, type_name, base, field).filter(|value| is_kernel_pointer(*value))
}

fn read_fixed_ascii_field(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
    maximum: usize,
) -> Option<String> {
    let layout = profile.type_field(type_name, field).ok()?;
    let length = usize::try_from(layout.size.unwrap_or(maximum as u64))
        .ok()?
        .min(maximum);
    let mut bytes = vec![0u8; length];
    space.read_virtual(base + layout.offset, &mut bytes).ok()?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value = String::from_utf8_lossy(&bytes[..end]).trim().to_owned();
    (!value.is_empty()).then_some(value)
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

fn is_kernel_pointer(value: u64) -> bool {
    value >> 48 == 0xffff && value & 7 == 0
}

fn pool_tag(key: u32) -> String {
    key.to_le_bytes()
        .into_iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || byte == b' ' {
                char::from(byte)
            } else {
                '.'
            }
        })
        .collect()
}

fn dump_type_name(dump_type: u32) -> &'static str {
    match dump_type {
        1 => "完整转储",
        2 => "内核转储",
        3 => "小型转储",
        4 => "分类转储",
        5 => "位图转储",
        6 => "自动转储",
        _ => "未知",
    }
}

fn machine_type_name(machine_type: u32) -> &'static str {
    match machine_type {
        0x014c => "x86",
        0x8664 => "x86_64",
        0xaa64 => "arm64",
        _ => "未知",
    }
}

fn windows_filetime_to_rfc3339(value: u64) -> Option<String> {
    const WINDOWS_EPOCH_SECONDS: i128 = 11_644_473_600;
    const TICKS_PER_SECOND: i128 = 10_000_000;
    let ticks = i128::from(value).checked_sub(WINDOWS_EPOCH_SECONDS * TICKS_PER_SECOND)?;
    let seconds = i64::try_from(ticks.div_euclid(TICKS_PER_SECOND)).ok()?;
    let nanoseconds = u32::try_from(ticks.rem_euclid(TICKS_PER_SECOND) * 100).ok()?;
    DateTime::<Utc>::from_timestamp(seconds, nanoseconds)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn push_limited(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 128 {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_pool_tags_without_control_characters() {
        assert_eq!(pool_tag(u32::from_le_bytes(*b"Proc")), "Proc");
        assert_eq!(pool_tag(u32::from_le_bytes([b'A', 0, b'B', b' '])), "A.B ");
    }

    #[test]
    fn pool_scan_includes_protected_tag_variants() {
        let (patterns, owners) = pool_tag_patterns(&[*b"Proc", *b"File"]);
        assert_eq!(
            patterns,
            vec![
                *b"Proc",
                [b'P', b'r', b'o', b'c' | 0x80],
                *b"File",
                [b'F', b'i', b'l', b'e' | 0x80]
            ]
        );
        assert_eq!(owners, vec![0, 0, 1, 1]);
    }

    #[test]
    fn parses_decimal_and_hex_strings_offsets() {
        assert_eq!(
            parse_strings_line("  4096 hello world"),
            Some((4096, "hello world".to_owned()))
        );
        assert_eq!(
            parse_strings_line("0x20:kernel"),
            Some((32, "kernel".to_owned()))
        );
    }
}
