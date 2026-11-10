use std::collections::HashSet;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::plugins::{DriverRecord, list_drivers};
use super::system_plugins::{PoolAllocationRecord, list_kpcrs, scan_pool_allocations};
use super::{WindowsKernelContext, filetime_to_rfc3339, is_kernel_pointer, read_unicode_string};
use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;

const MAX_POOL_OBJECTS: usize = 1_000_000;
const MAX_TIMER_CHAIN: usize = 1_000_000;

#[derive(Debug, Serialize)]
pub struct NamedObjectScanReport {
    pub mutants: Vec<MutantRecord>,
    pub symbolic_links: Vec<SymbolicLinkRecord>,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MutantScanReport {
    pub records: Vec<MutantRecord>,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SymbolicLinkScanReport {
    pub records: Vec<SymbolicLinkRecord>,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

impl NamedObjectScanReport {
    pub fn into_mutants(self) -> MutantScanReport {
        MutantScanReport {
            records: self.mutants,
            bytes_scanned: self.bytes_scanned,
            scan_seconds: self.scan_seconds,
            scan_gib_per_second: self.scan_gib_per_second,
            complete: self.complete,
            warnings: self.warnings,
        }
    }

    pub fn into_symbolic_links(self) -> SymbolicLinkScanReport {
        SymbolicLinkScanReport {
            records: self.symbolic_links,
            bytes_scanned: self.bytes_scanned,
            scan_seconds: self.scan_seconds,
            scan_gib_per_second: self.scan_gib_per_second,
            complete: self.complete,
            warnings: self.warnings,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MutantRecord {
    pub mutant: u64,
    pub object_header: u64,
    pub physical_address: u64,
    pub name: Option<String>,
    pub signal_state: i32,
    pub owner_thread: Option<u64>,
    pub abandoned: bool,
    pub apc_disable: i8,
    pub pool_type: u8,
}

#[derive(Debug, Serialize)]
pub struct SymbolicLinkRecord {
    pub symbolic_link: u64,
    pub object_header: u64,
    pub physical_address: u64,
    pub creation_time_raw: u64,
    pub creation_time: Option<String>,
    pub name: Option<String>,
    pub target: String,
    pub flags: Option<u32>,
    pub pool_type: u8,
}

#[derive(Debug, Serialize)]
pub struct TimerReport {
    pub records: Vec<TimerRecord>,
    pub processors_examined: usize,
    pub timer_buckets_examined: usize,
    pub backlink_mismatches: usize,
    pub invalid_or_cyclic_links: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TimerRecord {
    pub processor_index: u32,
    pub timer: u64,
    pub timer_type: u8,
    pub due_time_raw: i64,
    pub due_time_hex: String,
    pub period_ms: i32,
    pub signaled: bool,
    pub dpc: Option<u64>,
    pub deferred_routine: Option<u64>,
    pub module: Option<String>,
    pub suspicious_unbacked: bool,
}

/// Scans both executive-object tags in one physical-memory pass.  LovelyMemLuxe
/// can project either vector without starting a second 8+ GiB scan.
pub fn scan_named_objects(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit_per_kind: usize,
) -> Result<NamedObjectScanReport> {
    ensure!(limit_per_kind > 0, "命名对象结果上限必须大于零");
    let pool = scan_pool_allocations(
        image,
        kernel,
        profile,
        &[*b"Muta", *b"Symb"],
        MAX_POOL_OBJECTS,
    )?;
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let decoder = ObjectHeaderDecoder::new(&space, kernel, profile)?;
    let mut mutants = Vec::new();
    let mut symbolic_links = Vec::new();
    let mut seen_mutants = HashSet::new();
    let mut seen_links = HashSet::new();

    for allocation in &pool.records {
        match allocation.tag.as_str() {
            "Muta" => {
                let Some((header, mutant)) =
                    find_typed_object(&space, profile, &decoder, allocation, "Mutant", "_KMUTANT")
                else {
                    continue;
                };
                if !seen_mutants.insert(mutant)
                    || dispatcher_type(&space, profile, "_KMUTANT", mutant) != Some(2)
                {
                    continue;
                }
                let owner_thread = type_u64(&space, profile, "_KMUTANT", mutant, "OwnerThread")
                    .map(|value| value & !0x7)
                    .filter(|value| is_kernel_pointer(*value));
                mutants.push(MutantRecord {
                    mutant,
                    object_header: header,
                    physical_address: allocation_physical_address(allocation, mutant),
                    name: decoder.object_name(&space, kernel, profile, header),
                    signal_state: dispatcher_signal_state(&space, profile, "_KMUTANT", mutant)
                        .unwrap_or(0),
                    owner_thread,
                    abandoned: type_u8(&space, profile, "_KMUTANT", mutant, "MutantFlags")
                        .is_some_and(|flags| flags & 1 != 0),
                    apc_disable: type_u8(&space, profile, "_KMUTANT", mutant, "ApcDisable")
                        .unwrap_or(0) as i8,
                    pool_type: allocation.pool_type,
                });
            }
            "Symb" => {
                let Some((header, link)) = find_typed_object(
                    &space,
                    profile,
                    &decoder,
                    allocation,
                    "SymbolicLink",
                    "_OBJECT_SYMBOLIC_LINK",
                ) else {
                    continue;
                };
                if !seen_links.insert(link) {
                    continue;
                }
                let Some(target) =
                    type_unicode(&space, profile, "_OBJECT_SYMBOLIC_LINK", link, "LinkTarget")
                        .filter(|target| !target.is_empty() && sane_text(target))
                else {
                    continue;
                };
                let creation_time_raw = type_u64(
                    &space,
                    profile,
                    "_OBJECT_SYMBOLIC_LINK",
                    link,
                    "CreationTime",
                )
                .unwrap_or(0);
                symbolic_links.push(SymbolicLinkRecord {
                    symbolic_link: link,
                    object_header: header,
                    physical_address: allocation_physical_address(allocation, link),
                    creation_time_raw,
                    creation_time: filetime_to_rfc3339(creation_time_raw),
                    name: decoder.object_name(&space, kernel, profile, header),
                    target,
                    flags: type_u32(&space, profile, "_OBJECT_SYMBOLIC_LINK", link, "Flags"),
                    pool_type: allocation.pool_type,
                });
            }
            _ => {}
        }
    }

    mutants.sort_unstable_by_key(|record| record.mutant);
    symbolic_links.sort_unstable_by_key(|record| record.symbolic_link);
    let mutant_truncated = mutants.len() > limit_per_kind;
    let link_truncated = symbolic_links.len() > limit_per_kind;
    mutants.truncate(limit_per_kind);
    symbolic_links.truncate(limit_per_kind);
    let mut warnings = pool.warnings;
    if mutant_truncated {
        warnings.push(format!("互斥体结果达到 {limit_per_kind} 条上限"));
    }
    if link_truncated {
        warnings.push(format!("符号链接结果达到 {limit_per_kind} 条上限"));
    }
    Ok(NamedObjectScanReport {
        mutants,
        symbolic_links,
        bytes_scanned: pool.bytes_scanned,
        scan_seconds: pool.elapsed_seconds,
        scan_gib_per_second: pool.gib_per_second,
        complete: pool.complete && !mutant_truncated && !link_truncated,
        warnings,
    })
}

/// Walks the live per-processor timer tables. This avoids scanning arbitrary
/// bytes for timer-shaped data and validates every LIST_ENTRY backlink before
/// accepting a timer.
pub fn list_timers(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<TimerReport> {
    ensure!(limit > 0, "定时器结果上限必须大于零");
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let kpcrs = list_kpcrs(image, kernel, profile, 65_536)?;
    let modules = list_drivers(image, kernel, profile, 65_536)?;
    let timer_table_offset = profile.type_field("_KPRCB", "TimerTable")?.offset;
    let entries = profile.type_field("_KTIMER_TABLE", "TimerEntries")?;
    let entry_size = profile.type_layout("_KTIMER_TABLE_ENTRY")?.size;
    let entry_list_offset = profile.type_field("_KTIMER_TABLE_ENTRY", "Entry")?.offset;
    let entries_size = entries
        .size
        .context("PDB 未描述 _KTIMER_TABLE.TimerEntries 的数组大小")?;
    ensure!(entry_size >= 16, "_KTIMER_TABLE_ENTRY 大小无效");
    ensure!(
        entries_size >= entry_size && entries_size.is_multiple_of(entry_size),
        "定时器表数组维度无效"
    );
    let bucket_count = entries_size / entry_size;
    ensure!(
        (1..=4096).contains(&bucket_count),
        "定时器桶数量 {bucket_count} 不合理"
    );
    let timer_list_offset = profile.type_field("_KTIMER", "TimerListEntry")?.offset;
    let mut records = Vec::new();
    let mut seen_timers = HashSet::new();
    let mut warnings = kpcrs.warnings;
    warnings.extend(modules.warnings.clone());
    let mut complete = kpcrs.complete && modules.complete;
    let mut buckets_examined = 0usize;
    let mut backlink_mismatches = 0usize;
    let mut invalid_or_cyclic_links = 0usize;

    'processors: for processor in &kpcrs.records {
        let table = processor.prcb + timer_table_offset + entries.offset;
        for bucket in 0..bucket_count {
            buckets_examined += 1;
            let head = table + bucket * entry_size + entry_list_offset;
            let mut current = match space.read_u64(head) {
                Ok(value) => value,
                Err(_) => {
                    complete = false;
                    push_warning_limited(
                        &mut warnings,
                        format!(
                            "CPU {} 的定时器桶 {} 不可读",
                            processor.processor_index, bucket
                        ),
                    );
                    continue;
                }
            };
            if current == head {
                continue;
            }
            let mut previous = head;
            let mut chain_seen = HashSet::new();
            for _ in 0..MAX_TIMER_CHAIN {
                if current == head {
                    break;
                }
                if !is_kernel_pointer(current) || !chain_seen.insert(current) {
                    complete = false;
                    invalid_or_cyclic_links += 1;
                    break;
                }
                let next = match space.read_u64(current) {
                    Ok(value) => value,
                    Err(_) => {
                        complete = false;
                        break;
                    }
                };
                let backlink = space.read_u64(current + 8).unwrap_or(0);
                let backlink_valid = backlink == previous;
                if !backlink_valid {
                    complete = false;
                    backlink_mismatches += 1;
                    // The timer may have migrated between buckets while the dump was
                    // acquired. Do not follow a chain anchored in another bucket.
                    break;
                }
                let Some(timer) = current.checked_sub(timer_list_offset) else {
                    complete = false;
                    break;
                };
                if let Some(timer_type @ (8 | 9)) =
                    dispatcher_type(&space, profile, "_KTIMER", timer)
                    && seen_timers.insert(timer)
                {
                    if records.len() == limit {
                        complete = false;
                        warnings.push(format!("定时器结果达到 {limit} 条上限"));
                        break 'processors;
                    }
                    records.push(read_timer_record(
                        &space,
                        kernel,
                        profile,
                        &modules.records,
                        processor.processor_index,
                        timer,
                        timer_type,
                    ));
                }
                previous = current;
                current = next;
            }
        }
    }
    records.sort_unstable_by_key(|record| (record.processor_index, record.timer));
    if backlink_mismatches != 0 {
        warnings.push(format!(
            "发现 {backlink_mismatches} 处定时器 LIST_ENTRY 反向链接不一致；未继续跟随外来或陈旧的正向链"
        ));
    }
    if invalid_or_cyclic_links != 0 {
        warnings.push(format!(
            "有 {invalid_or_cyclic_links} 个定时器桶以无效或循环的正向链接结束"
        ));
    }
    Ok(TimerReport {
        records,
        processors_examined: kpcrs.records.len(),
        timer_buckets_examined: buckets_examined,
        backlink_mismatches,
        invalid_or_cyclic_links,
        complete,
        warnings,
    })
}

pub(super) struct ObjectHeaderDecoder {
    cookie: Option<u8>,
    type_table: u64,
    type_index_offset: u64,
    info_mask_offset: u64,
    body_offset: u64,
    type_name_offset: u64,
}

impl ObjectHeaderDecoder {
    pub(super) fn new(
        space: &X64AddressSpace<'_>,
        kernel: &WindowsKernelContext,
        profile: &KernelProfile,
    ) -> Result<Self> {
        Ok(Self {
            cookie: profile
                .symbol_rva("ObHeaderCookie")
                .ok()
                .and_then(|rva| read_u8_at(space, kernel.kernel_base + u64::from(rva))),
            type_table: kernel.kernel_base + u64::from(profile.symbol_rva("ObTypeIndexTable")?),
            type_index_offset: profile.type_field("_OBJECT_HEADER", "TypeIndex")?.offset,
            info_mask_offset: profile.type_field("_OBJECT_HEADER", "InfoMask")?.offset,
            body_offset: profile.type_field("_OBJECT_HEADER", "Body")?.offset,
            type_name_offset: profile.type_field("_OBJECT_TYPE", "Name")?.offset,
        })
    }

    fn type_name(
        &self,
        space: &X64AddressSpace<'_>,
        profile: &KernelProfile,
        header: u64,
    ) -> Option<String> {
        let raw = read_u8_at(space, header + self.type_index_offset)?;
        let index = self
            .cookie
            .map(|cookie| raw ^ cookie ^ ((header >> 8) as u8))
            .unwrap_or(raw);
        let object_type = space
            .read_u64(self.type_table + u64::from(index) * 8)
            .ok()?;
        if !is_kernel_pointer(object_type) {
            return None;
        }
        read_unicode_string(space, profile, object_type + self.type_name_offset, 256)
            .filter(|name| sane_text(name))
    }

    /// Resolve an executive object's type from its body address. Callers must
    /// first establish that the profile belongs to the target kernel before
    /// relying on profile RVAs such as ObTypeIndexTable and ObHeaderCookie.
    pub(super) fn body_type_name(
        &self,
        space: &X64AddressSpace<'_>,
        profile: &KernelProfile,
        body: u64,
    ) -> Option<String> {
        let header = body.checked_sub(self.body_offset)?;
        self.type_name(space, profile, header)
    }

    fn object_name(
        &self,
        space: &X64AddressSpace<'_>,
        kernel: &WindowsKernelContext,
        profile: &KernelProfile,
        header: u64,
    ) -> Option<String> {
        let info_mask = read_u8_at(space, header + self.info_mask_offset)?;
        const NAME_INFO_BIT: u8 = 0x2;
        let index = info_mask & (NAME_INFO_BIT | (NAME_INFO_BIT - 1));
        let table = kernel.kernel_base + u64::from(profile.symbol_rva("ObpInfoMaskToOffset").ok()?);
        let header_offset = read_u8_at(space, table + u64::from(index))?;
        if header_offset == 0 {
            return None;
        }
        let name_offset = profile
            .type_field("_OBJECT_HEADER_NAME_INFO", "Name")
            .ok()?
            .offset;
        let name_info = header.checked_sub(u64::from(header_offset))?;
        read_unicode_string(space, profile, name_info + name_offset, 32 * 1024)
            .filter(|name| !name.is_empty() && sane_text(name))
    }
}

fn find_typed_object(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    decoder: &ObjectHeaderDecoder,
    allocation: &PoolAllocationRecord,
    expected_object_type: &str,
    body_type: &str,
) -> Option<(u64, u64)> {
    let body_size = profile.type_layout(body_type).ok()?.size;
    for pool_header in allocation.virtual_headers() {
        let end = pool_header.checked_add(allocation.allocation_size)?;
        let last = end.checked_sub(decoder.body_offset.checked_add(body_size)?)?;
        let mut header = (pool_header + 16 + 7) & !7;
        while header <= last {
            if decoder.type_name(space, profile, header).as_deref() == Some(expected_object_type) {
                return Some((header, header + decoder.body_offset));
            }
            header += 8;
        }
    }
    None
}

fn read_timer_record(
    space: &X64AddressSpace<'_>,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    modules: &[DriverRecord],
    processor_index: u32,
    timer: u64,
    timer_type: u8,
) -> TimerRecord {
    let due_time_raw = type_u64(space, profile, "_KTIMER", timer, "DueTime")
        .map(|value| value as i64)
        .unwrap_or(0);
    let raw_dpc = type_u64(space, profile, "_KTIMER", timer, "Dpc").unwrap_or(0);
    let dpc = decode_timer_dpc(space, kernel, profile, timer, raw_dpc)
        .filter(|value| is_kernel_pointer(*value));
    let deferred_routine = dpc.and_then(|address| {
        type_u64(space, profile, "_KDPC", address, "DeferredRoutine")
            .filter(|value| is_kernel_pointer(*value))
    });
    let module = deferred_routine
        .and_then(|routine| module_for_address(modules, routine))
        .map(|module| module.path.clone());
    TimerRecord {
        processor_index,
        timer,
        timer_type,
        due_time_raw,
        due_time_hex: format!(
            "{:#010x}:{:#010x}",
            (due_time_raw as u64) >> 32,
            due_time_raw as u32
        ),
        period_ms: type_u32(space, profile, "_KTIMER", timer, "Period")
            .map(|value| value as i32)
            .unwrap_or(0),
        signaled: dispatcher_signal_state(space, profile, "_KTIMER", timer)
            .is_some_and(|value| value != 0),
        dpc,
        deferred_routine,
        suspicious_unbacked: deferred_routine.is_some() && module.is_none(),
        module,
    }
}

fn decode_timer_dpc(
    space: &X64AddressSpace<'_>,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    timer: u64,
    raw: u64,
) -> Option<u64> {
    let wait_never = profile
        .symbols
        .get("KiWaitNever")
        .and_then(|rva| space.read_u64(kernel.kernel_base + u64::from(*rva)).ok());
    let wait_always = profile
        .symbols
        .get("KiWaitAlways")
        .and_then(|rva| space.read_u64(kernel.kernel_base + u64::from(*rva)).ok());
    match (wait_never, wait_always) {
        (Some(never), Some(always)) => {
            let rotated = (raw ^ never).rotate_left((never & 0xff) as u32);
            Some((rotated ^ timer).swap_bytes() ^ always)
        }
        _ => (raw != 0).then_some(raw),
    }
}

fn dispatcher_type(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    object_type: &str,
    object: u64,
) -> Option<u8> {
    let header = profile.type_field(object_type, "Header").ok()?.offset;
    let kind = profile
        .type_field("_DISPATCHER_HEADER", "Type")
        .ok()?
        .offset;
    read_u8_at(space, object + header + kind)
}

fn dispatcher_signal_state(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    object_type: &str,
    object: u64,
) -> Option<i32> {
    let header = profile.type_field(object_type, "Header").ok()?.offset;
    let state = profile
        .type_field("_DISPATCHER_HEADER", "SignalState")
        .ok()?
        .offset;
    read_u32_at(space, object + header + state).map(|value| value as i32)
}

fn allocation_physical_address(allocation: &PoolAllocationRecord, virtual_address: u64) -> u64 {
    allocation
        .physical_address_for(virtual_address)
        .unwrap_or(allocation.physical_header)
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
    read_unicode_string(space, profile, base + offset, 64 * 1024)
}

fn type_u8(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u8> {
    let offset = profile.type_field(type_name, field).ok()?.offset;
    read_u8_at(space, base + offset)
}

fn type_u32(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field: &str,
) -> Option<u32> {
    let offset = profile.type_field(type_name, field).ok()?.offset;
    read_u32_at(space, base + offset)
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

fn read_u8_at(space: &X64AddressSpace<'_>, address: u64) -> Option<u8> {
    let mut bytes = [0u8; 1];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(bytes[0])
}

fn read_u32_at(space: &X64AddressSpace<'_>, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn sane_text(value: &str) -> bool {
    value.chars().all(|character| {
        !character.is_control() || character == '\t' || character == '\r' || character == '\n'
    })
}

fn push_warning_limited(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 256 {
        warnings.push(warning);
    }
}
