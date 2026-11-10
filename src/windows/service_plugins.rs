use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use anyhow::{Result, ensure};
use serde::Serialize;

use super::plugins::{VadRecord, list_vads};
use super::{ProcessListReport, ProcessRecord, WindowsKernelContext};
use crate::address::{VirtualAddressRegion, VirtualMapping, X64AddressSpace};
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::system::registry::RegistryServiceInfo;

const SERVICE_HEADER_RECORD_OFFSET: u64 = 0x10;
const MAX_CHAIN_RECORDS: usize = 65_536;
const MAX_UTF16_UNITS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceView {
    Scan,
    List,
    Difference,
}

#[derive(Debug, Serialize)]
pub struct ServiceReport {
    pub records: Vec<ServiceRecord>,
    pub view: String,
    pub services_pids: Vec<u64>,
    pub registry_services: usize,
    pub vads_examined: usize,
    pub bytes_examined: u64,
    pub missing_bytes: u64,
    pub unmapped_vad_bytes: u64,
    pub scan_header_candidates: usize,
    pub list_anchor_candidates: usize,
    pub structurally_valid_scan_records: usize,
    pub structurally_valid_list_records: usize,
    pub list_recovery: String,
    pub elapsed_seconds: f64,
    pub gib_per_second: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceRecord {
    pub address: u64,
    pub order: u32,
    pub pid: Option<u32>,
    pub start: u32,
    pub start_name: String,
    pub state: u32,
    pub state_name: String,
    pub service_type: u32,
    pub type_names: Vec<String>,
    pub name: String,
    pub display_name: Option<String>,
    pub binary_path_memory: Option<String>,
    pub binary_path_registry: Option<String>,
    pub service_dll_registry: Option<String>,
    pub registry_present: bool,
    pub found_by_scan: bool,
    pub found_by_list: bool,
    pub adaptive_layout: String,
}

#[derive(Debug, Clone, Copy)]
struct ServiceSchema {
    label: &'static str,
    prev: u64,
    order: u64,
    start: u64,
    service_name: u64,
    display_name: u64,
    service_type: u64,
    state: u64,
    service_union: u64,
    binary_path: u64,
    process_id: u64,
}

// These are structural shapes, not build-number selections.  Every candidate
// is tried against captured memory and scored using enum ranges, pointers,
// strings, list links, and registry service names.  This avoids trusting a
// potentially spoofed or unavailable Windows version while retaining support
// for the known x64 service-record shapes.
const SERVICE_SCHEMAS: &[ServiceSchema] = &[
    ServiceSchema {
        label: "name38/type50/process150",
        prev: 0x10,
        order: 0x20,
        start: 0x24,
        service_name: 0x38,
        display_name: 0x40,
        service_type: 0x50,
        state: 0x54,
        service_union: 0x150,
        binary_path: 0x18,
        process_id: 0x28,
    },
    ServiceSchema {
        label: "name38/type48/process128",
        prev: 0x10,
        order: 0x20,
        start: 0x24,
        service_name: 0x38,
        display_name: 0x40,
        service_type: 0x48,
        state: 0x4c,
        service_union: 0x128,
        binary_path: 0x18,
        process_id: 0x28,
    },
    ServiceSchema {
        label: "name38/type48/process0f0",
        prev: 0x10,
        order: 0x20,
        start: 0x24,
        service_name: 0x38,
        display_name: 0x40,
        service_type: 0x48,
        state: 0x4c,
        service_union: 0xf0,
        binary_path: 0x18,
        process_id: 0x28,
    },
    ServiceSchema {
        label: "name38/type48/process0e8-pid28",
        prev: 0x10,
        order: 0x20,
        start: 0x24,
        service_name: 0x38,
        display_name: 0x40,
        service_type: 0x48,
        state: 0x4c,
        service_union: 0xe8,
        binary_path: 0x18,
        process_id: 0x28,
    },
    ServiceSchema {
        label: "name38/type48/process0e8-pid20",
        prev: 0x10,
        order: 0x20,
        start: 0x24,
        service_name: 0x38,
        display_name: 0x40,
        service_type: 0x48,
        state: 0x4c,
        service_union: 0xe8,
        binary_path: 0x18,
        process_id: 0x20,
    },
    ServiceSchema {
        label: "name10/type40/process38",
        prev: 0x08,
        order: 0x20,
        start: 0x5c,
        service_name: 0x10,
        display_name: 0x18,
        service_type: 0x40,
        state: 0x44,
        service_union: 0x38,
        binary_path: 0x18,
        process_id: 0x20,
    },
    ServiceSchema {
        label: "name08/type30/process28",
        prev: 0,
        order: 0x18,
        start: 0x4c,
        service_name: 0x08,
        display_name: 0x10,
        service_type: 0x30,
        state: 0x34,
        service_union: 0x28,
        binary_path: 0x10,
        process_id: 0x18,
    },
];

#[derive(Debug, Clone)]
struct ParsedService {
    record: ServiceRecord,
    previous: Option<u64>,
    schema_index: usize,
    score: u32,
}

#[derive(Default)]
struct VadScanStats {
    vads: usize,
    bytes: u64,
    missing: u64,
    unmapped: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn analyze_services(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    processes: &ProcessListReport,
    registry_services: &[RegistryServiceInfo],
    registry_available: bool,
    mut warnings: Vec<String>,
    view: ServiceView,
    limit: usize,
) -> Result<ServiceReport> {
    ensure!(limit > 0, "服务结果上限必须大于零");
    let started = Instant::now();
    let registry = registry_services
        .iter()
        .map(|service| (service.name.to_lowercase(), service))
        .collect::<HashMap<_, _>>();
    let mut scan_records = BTreeMap::<u64, ParsedService>::new();
    let mut list_records = BTreeMap::<u64, ParsedService>::new();
    let mut scan_headers = HashSet::new();
    let mut list_anchors = HashSet::new();
    let mut stats = VadScanStats::default();
    let mut services_pids = Vec::new();
    let mut complete = processes.complete && registry_available;
    let mut list_recovery = "映像锚点".to_owned();

    for warning in &processes.warnings {
        push_warning_limited(
            &mut warnings,
            format!("进程枚举/{}：{}", warning.kind, warning.message),
        );
    }
    if !registry_available {
        push_warning_limited(
            &mut warnings,
            "注册表服务证据不完整；仍显示结构有效的内存记录，但可能缺少注册表关联信息".to_owned(),
        );
    }

    for process in processes
        .processes
        .iter()
        .filter(|process| process.name.eq_ignore_ascii_case("services.exe"))
    {
        services_pids.push(process.pid);
        let Some(space) = process_address_space(image, process) else {
            complete = false;
            push_warning_limited(
                &mut warnings,
                format!("services.exe PID {} 没有可读的进程页表", process.pid),
            );
            continue;
        };
        let vads = match list_vads(image, kernel, profile, process.pid, 1_000_000) {
            Ok(report) => report,
            Err(error) => {
                complete = false;
                push_warning_limited(
                    &mut warnings,
                    format!(
                        "services.exe PID {} 的 VAD 遍历失败：{error:#}",
                        process.pid
                    ),
                );
                continue;
            }
        };
        complete &= vads.complete;
        for warning in vads.warnings {
            push_warning_limited(
                &mut warnings,
                format!("services.exe PID {} 的 VAD：{warning}", process.pid),
            );
        }
        let mappings = match space.enumerate_mappings(VirtualAddressRegion::User, 1_000_000) {
            Ok(report) => {
                if report.truncated {
                    complete = false;
                    push_warning_limited(
                        &mut warnings,
                        "services.exe 用户地址映射枚举已达到上限".to_owned(),
                    );
                }
                for warning in report.warnings {
                    complete = false;
                    push_warning_limited(&mut warnings, format!("services.exe 页表：{warning}"));
                }
                report.mappings
            }
            Err(error) => {
                complete = false;
                push_warning_limited(
                    &mut warnings,
                    format!(
                        "services.exe PID {} 的地址映射枚举失败：{error:#}",
                        process.pid
                    ),
                );
                continue;
            }
        };
        scan_service_vads(
            &space,
            &vads.records,
            &mappings,
            &mut scan_headers,
            &mut list_anchors,
            &mut stats,
        );

        for header in scan_headers.iter().copied().collect::<Vec<_>>() {
            collect_header_chain(&space, header, &registry, &mut scan_records);
        }
        for anchor in list_anchors.iter().copied().collect::<Vec<_>>() {
            collect_header_chain(&space, anchor, &registry, &mut list_records);
        }
    }

    if services_pids.is_empty() {
        complete = false;
        push_warning_limited(&mut warnings, "活动进程列表中没有 services.exe".to_owned());
    }
    if stats.missing != 0 {
        complete = false;
        push_warning_limited(
            &mut warnings,
            format!(
                "services.exe 的 VAD 中有 {} 字节不可用；程序没有用零值代替这些证据",
                stats.missing
            ),
        );
    }
    if stats.unmapped != 0 {
        push_warning_limited(
            &mut warnings,
            format!(
                "services.exe 的 VAD 中有 {} 字节属于保留区或非驻留区，没有有效页表映射，已跳过",
                stats.unmapped
            ),
        );
    }
    if scan_headers.is_empty() {
        complete = false;
        push_warning_limited(
            &mut warnings,
            "没有恢复出按 8 字节对齐且结构有效的 serH 服务头".to_owned(),
        );
    }

    // Sc27 only exists in newer service-controller images.  Older systems still
    // retain a strong invariant: active records form a long, order-decreasing
    // chain through their predecessor pointers.  Recover that chain from the
    // already validated scan records instead of selecting by Windows build.
    if list_records.is_empty() {
        let inferred = infer_active_service_chain(&scan_records);
        if !inferred.is_empty() {
            list_records = inferred;
            list_recovery = "结构化前驱链".to_owned();
        }
    }
    if list_records.is_empty() {
        complete = false;
        push_warning_limited(
            &mut warnings,
            "既未从 services.exe 映像恢复出有效的 Sc27 服务链锚点，也无法从服务记录前驱关系重建活动链表".to_owned(),
        );
    }

    let list_names = list_records
        .values()
        .map(|record| record.record.name.to_lowercase())
        .collect::<HashSet<_>>();
    let mut merged = BTreeMap::<u64, ServiceRecord>::new();
    for (address, parsed) in &scan_records {
        let mut record = parsed.record.clone();
        record.found_by_scan = true;
        record.found_by_list =
            list_records.contains_key(address) || list_names.contains(&record.name.to_lowercase());
        merged.insert(*address, record);
    }
    for (address, parsed) in &list_records {
        let record = merged
            .entry(*address)
            .or_insert_with(|| parsed.record.clone());
        record.found_by_list = true;
        if scan_records.contains_key(address) {
            record.found_by_scan = true;
        }
    }

    let mut records = merged
        .into_values()
        .filter(|record| match view {
            ServiceView::Scan => record.found_by_scan,
            ServiceView::List => record.found_by_list,
            ServiceView::Difference => record.found_by_scan && !record.found_by_list,
        })
        .collect::<Vec<_>>();
    records.sort_unstable_by(|left, right| {
        left.order
            .cmp(&right.order)
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            .then_with(|| left.address.cmp(&right.address))
    });
    if records.len() > limit {
        records.truncate(limit);
        complete = false;
        push_warning_limited(
            &mut warnings,
            format!("结构验证后的服务结果达到 {limit} 条上限"),
        );
    }

    let elapsed_seconds = started.elapsed().as_secs_f64();
    let gib_per_second = if elapsed_seconds == 0.0 {
        0.0
    } else {
        stats.bytes as f64 / (1024.0 * 1024.0 * 1024.0) / elapsed_seconds
    };
    Ok(ServiceReport {
        records,
        view: match view {
            ServiceView::Scan => "scan",
            ServiceView::List => "list",
            ServiceView::Difference => "difference",
        }
        .to_owned(),
        services_pids,
        registry_services: registry_services.len(),
        vads_examined: stats.vads,
        bytes_examined: stats.bytes,
        missing_bytes: stats.missing,
        unmapped_vad_bytes: stats.unmapped,
        scan_header_candidates: scan_headers.len(),
        list_anchor_candidates: list_anchors.len(),
        structurally_valid_scan_records: scan_records.len(),
        structurally_valid_list_records: list_records.len(),
        list_recovery,
        elapsed_seconds,
        gib_per_second,
        complete,
        warnings,
    })
}

fn infer_active_service_chain(
    scan_records: &BTreeMap<u64, ParsedService>,
) -> BTreeMap<u64, ParsedService> {
    let mut best_addresses = Vec::new();
    let mut best_score = 0u64;

    for start in scan_records.keys().copied() {
        let mut addresses = Vec::new();
        let mut visited = HashSet::new();
        let mut score = 0u64;
        let mut current = start;

        while let Some(record) = scan_records.get(&current) {
            if !visited.insert(current) {
                break;
            }
            addresses.push(current);
            score = score.saturating_add(record.score as u64);

            let Some(previous_address) = record.previous else {
                break;
            };
            let Some(previous) = scan_records.get(&previous_address) else {
                break;
            };
            if previous.schema_index != record.schema_index
                || previous.record.order >= record.record.order
            {
                break;
            }
            current = previous_address;
        }

        if addresses.len() > best_addresses.len()
            || (addresses.len() == best_addresses.len() && score > best_score)
        {
            best_addresses = addresses;
            best_score = score;
        }
    }

    // A pair can occur by chance in stale pool memory.  Three independently
    // validated records and two coherent links make accidental recovery
    // negligible while still allowing useful results from damaged captures.
    if best_addresses.len() < 3 {
        return BTreeMap::new();
    }

    best_addresses
        .into_iter()
        .filter_map(|address| {
            let mut parsed = scan_records.get(&address)?.clone();
            parsed.record.adaptive_layout =
                format!("{}/结构化前驱链", parsed.record.adaptive_layout);
            Some((address, parsed))
        })
        .collect()
}

fn scan_service_vads(
    space: &X64AddressSpace<'_>,
    vads: &[VadRecord],
    mappings: &[VirtualMapping],
    scan_headers: &mut HashSet<u64>,
    list_anchors: &mut HashSet<u64>,
    stats: &mut VadScanStats,
) {
    for vad in vads {
        stats.vads += 1;
        let image_vad = vad.file.as_ref().is_some_and(|path| {
            path.replace('/', "\\")
                .to_ascii_lowercase()
                .ends_with("\\services.exe")
        });
        let mut previous_tail = Vec::<u8>::new();
        let mut previous_end = None;
        let mut mapped = 0u64;
        for mapping in mappings {
            if mapping.virtual_end <= vad.start {
                continue;
            }
            if mapping.virtual_start > vad.end {
                break;
            }
            let mut address = mapping.virtual_start.max(vad.start);
            let end = mapping.virtual_end.min(vad.end.saturating_add(1));
            mapped = mapped.saturating_add(end.saturating_sub(address));
            while address < end {
                let count = (end - address).min(0x1000 - (address & 0xfff)) as usize;
                let mut page = [0u8; 0x1000];
                if space.read_virtual(address, &mut page[..count]).is_ok() {
                    stats.bytes += count as u64;
                    if previous_end == Some(address) && !previous_tail.is_empty() {
                        let mut boundary = previous_tail.clone();
                        boundary.extend_from_slice(&page[..count.min(3)]);
                        let boundary_base = address - previous_tail.len() as u64;
                        find_service_needles(
                            &boundary,
                            boundary_base,
                            image_vad,
                            scan_headers,
                            list_anchors,
                        );
                    }
                    find_service_needles(
                        &page[..count],
                        address,
                        image_vad,
                        scan_headers,
                        list_anchors,
                    );
                    let retained = count.min(3);
                    previous_tail.clear();
                    previous_tail.extend_from_slice(&page[count - retained..count]);
                    previous_end = Some(address + count as u64);
                } else {
                    stats.missing = stats.missing.saturating_add(count as u64);
                    previous_tail.clear();
                    previous_end = None;
                }
                address = address.saturating_add(count as u64);
                if address == 0 {
                    break;
                }
            }
        }
        let vad_size = vad.end.saturating_sub(vad.start).saturating_add(1);
        stats.unmapped = stats
            .unmapped
            .saturating_add(vad_size.saturating_sub(mapped.min(vad_size)));
    }
}

fn find_service_needles(
    bytes: &[u8],
    base: u64,
    image_vad: bool,
    scan_headers: &mut HashSet<u64>,
    list_anchors: &mut HashSet<u64>,
) {
    for (index, window) in bytes.windows(4).enumerate() {
        let address = base + index as u64;
        if address & 7 != 0 {
            continue;
        }
        if window == b"serH" {
            scan_headers.insert(address);
        }
        if image_vad && window == b"Sc27" {
            list_anchors.insert(address);
        }
    }
}

fn collect_header_chain(
    space: &X64AddressSpace<'_>,
    header: u64,
    registry: &HashMap<String, &RegistryServiceInfo>,
    output: &mut BTreeMap<u64, ParsedService>,
) {
    let Ok(root) = space.read_u64(header + SERVICE_HEADER_RECORD_OFFSET) else {
        return;
    };
    if !is_user_pointer(root) {
        return;
    }
    let Some(first) = parse_best_service(space, root, registry) else {
        return;
    };
    let schema_index = first.schema_index;
    let mut current = Some(first);
    let mut visited = HashSet::new();
    for _ in 0..MAX_CHAIN_RECORDS {
        let Some(parsed) = current else {
            break;
        };
        if !visited.insert(parsed.record.address) {
            break;
        }
        let previous = parsed.previous;
        merge_parsed(output, parsed);
        let Some(previous) = previous else {
            break;
        };
        current = parse_service(space, previous, schema_index, registry);
    }
}

fn merge_parsed(output: &mut BTreeMap<u64, ParsedService>, parsed: ParsedService) {
    match output.get(&parsed.record.address) {
        Some(existing) if existing.score >= parsed.score => {}
        _ => {
            output.insert(parsed.record.address, parsed);
        }
    }
}

fn parse_best_service(
    space: &X64AddressSpace<'_>,
    address: u64,
    registry: &HashMap<String, &RegistryServiceInfo>,
) -> Option<ParsedService> {
    SERVICE_SCHEMAS
        .iter()
        .enumerate()
        .filter_map(|(index, _)| parse_service(space, address, index, registry))
        .max_by_key(|parsed| parsed.score)
}

fn parse_service(
    space: &X64AddressSpace<'_>,
    address: u64,
    schema_index: usize,
    registry: &HashMap<String, &RegistryServiceInfo>,
) -> Option<ParsedService> {
    if !is_user_pointer(address) {
        return None;
    }
    let schema = *SERVICE_SCHEMAS.get(schema_index)?;
    let order = read_u32(space, address + schema.order)?;
    let start = read_u32(space, address + schema.start)?;
    let state = read_u32(space, address + schema.state)?;
    let service_type = read_u32(space, address + schema.service_type)?;
    if order > 0xffff || start > 4 || !(1..=7).contains(&state) || !valid_service_type(service_type)
    {
        return None;
    }
    let name_pointer = space.read_u64(address + schema.service_name).ok()?;
    let name = read_utf16_z(space, name_pointer, MAX_UTF16_UNITS)?;
    if !plausible_service_name(&name) {
        return None;
    }
    let registry_record = registry.get(&name.to_lowercase()).copied();
    let mut score = 30u32;
    if registry_record.is_some() {
        score += 100;
    }

    let display_pointer = space.read_u64(address + schema.display_name).ok();
    let display_name = display_pointer
        .filter(|pointer| is_user_pointer(*pointer))
        .and_then(|pointer| read_utf16_z(space, pointer, MAX_UTF16_UNITS))
        .filter(|value| plausible_display_name(value));
    if display_name.is_some() {
        score += 5;
    }

    let previous = space
        .read_u64(address + schema.prev)
        .ok()
        .and_then(|value| {
            if value == 0 {
                None
            } else if is_user_pointer(value) && value != address {
                score += 4;
                Some(value)
            } else {
                None
            }
        });
    if space
        .read_u64(address + schema.prev)
        .ok()
        .is_some_and(|value| value != 0 && (!is_user_pointer(value) || value == address))
    {
        return None;
    }

    let mut pid = None;
    let mut binary_path_memory = None;
    let process_type = service_type & (0x10 | 0x20 | 0x40 | 0x80) != 0;
    if let Ok(union_pointer) = space.read_u64(address + schema.service_union)
        && is_user_pointer(union_pointer)
    {
        if process_type {
            if state == 4 {
                pid = read_u32(space, union_pointer + schema.process_id).filter(|pid| *pid != 0);
            }
            binary_path_memory = space
                .read_u64(union_pointer + schema.binary_path)
                .ok()
                .filter(|pointer| is_user_pointer(*pointer))
                .and_then(|pointer| read_utf16_z(space, pointer, MAX_UTF16_UNITS))
                .filter(|value| plausible_path(value));
        } else {
            binary_path_memory = read_utf16_z(space, union_pointer, MAX_UTF16_UNITS)
                .filter(|value| plausible_path(value));
        }
    }
    if binary_path_memory.is_some() {
        score += 5;
    }
    if pid.is_some() {
        score += 3;
    }

    let registry_present = registry_record.is_some();
    Some(ParsedService {
        record: ServiceRecord {
            address,
            order,
            pid,
            start,
            start_name: service_start_name(start).to_owned(),
            state,
            state_name: service_state_name(state).to_owned(),
            service_type,
            type_names: service_type_names(service_type),
            name,
            display_name,
            binary_path_memory,
            binary_path_registry: registry_record.and_then(|service| service.image_path.clone()),
            service_dll_registry: registry_record.and_then(|service| service.service_dll.clone()),
            registry_present,
            found_by_scan: false,
            found_by_list: false,
            adaptive_layout: schema.label.to_owned(),
        },
        previous,
        schema_index,
        score,
    })
}

fn process_address_space<'a>(
    image: &'a MemoryImage,
    process: &ProcessRecord,
) -> Option<X64AddressSpace<'a>> {
    process
        .details
        .user_directory_table_base
        .or(process.details.directory_table_base)
        .and_then(|dtb| X64AddressSpace::new(image, dtb).ok())
}

fn read_u32(space: &X64AddressSpace<'_>, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_utf16_z(space: &X64AddressSpace<'_>, address: u64, max_units: usize) -> Option<String> {
    if !is_user_pointer(address) {
        return None;
    }
    let mut words = Vec::new();
    for index in 0..max_units {
        let mut bytes = [0u8; 2];
        space
            .read_virtual(address + (index * 2) as u64, &mut bytes)
            .ok()?;
        let word = u16::from_le_bytes(bytes);
        if word == 0 {
            return String::from_utf16(&words).ok();
        }
        words.push(word);
    }
    None
}

fn is_user_pointer(address: u64) -> bool {
    (0x1_0000..0x0000_8000_0000_0000).contains(&address) && address & 1 == 0
}

fn valid_service_type(value: u32) -> bool {
    value != 0 && value & !0x3ff == 0
}

fn plausible_service_name(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 256
        && !value.contains(['\\', '/', ':'])
        && value.chars().all(|character| !character.is_control())
}

fn plausible_display_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 1024
        && value.chars().all(|character| !character.is_control())
}

fn plausible_path(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 2048
        && value.chars().all(|character| !character.is_control())
}

fn service_start_name(value: u32) -> &'static str {
    match value {
        0 => "SERVICE_BOOT_START",
        1 => "SERVICE_SYSTEM_START",
        2 => "SERVICE_AUTO_START",
        3 => "SERVICE_DEMAND_START",
        4 => "SERVICE_DISABLED",
        _ => "UNKNOWN",
    }
}

fn service_state_name(value: u32) -> &'static str {
    match value {
        1 => "SERVICE_STOPPED",
        2 => "SERVICE_START_PENDING",
        3 => "SERVICE_STOP_PENDING",
        4 => "SERVICE_RUNNING",
        5 => "SERVICE_CONTINUE_PENDING",
        6 => "SERVICE_PAUSE_PENDING",
        7 => "SERVICE_PAUSED",
        _ => "UNKNOWN",
    }
}

fn service_type_names(value: u32) -> Vec<String> {
    const FLAGS: &[(u32, &str)] = &[
        (0x001, "SERVICE_KERNEL_DRIVER"),
        (0x002, "SERVICE_FILE_SYSTEM_DRIVER"),
        (0x004, "SERVICE_ADAPTER"),
        (0x008, "SERVICE_RECOGNIZER_DRIVER"),
        (0x010, "SERVICE_WIN32_OWN_PROCESS"),
        (0x020, "SERVICE_WIN32_SHARE_PROCESS"),
        (0x040, "SERVICE_USER_SERVICE"),
        (0x080, "SERVICE_USERSERVICE_INSTANCE"),
        (0x100, "SERVICE_INTERACTIVE_PROCESS"),
        (0x200, "SERVICE_PKG_SERVICE"),
    ];
    FLAGS
        .iter()
        .filter(|(flag, _)| value & flag != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect()
}

fn push_warning_limited(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 256 {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_service(address: u64, order: u32, previous: Option<u64>) -> ParsedService {
        ParsedService {
            record: ServiceRecord {
                address,
                order,
                pid: None,
                start: 2,
                start_name: "SERVICE_AUTO_START".to_owned(),
                state: 4,
                state_name: "SERVICE_RUNNING".to_owned(),
                service_type: 0x10,
                type_names: vec!["SERVICE_WIN32_OWN_PROCESS".to_owned()],
                name: format!("Svc{order}"),
                display_name: None,
                binary_path_memory: None,
                binary_path_registry: None,
                service_dll_registry: None,
                registry_present: false,
                found_by_scan: true,
                found_by_list: false,
                adaptive_layout: "test".to_owned(),
            },
            previous,
            schema_index: 0,
            score: 30,
        }
    }

    #[test]
    fn validates_service_names_without_accepting_paths() {
        assert!(plausible_service_name("WinDefend"));
        assert!(plausible_service_name("User Data Access_12345"));
        assert!(!plausible_service_name("C:\\Windows\\service.exe"));
        assert!(!plausible_service_name(""));
    }

    #[test]
    fn decodes_combined_service_types() {
        assert_eq!(
            service_type_names(0x110),
            ["SERVICE_WIN32_OWN_PROCESS", "SERVICE_INTERACTIVE_PROCESS"]
        );
    }

    #[test]
    fn infers_the_longest_ordered_predecessor_chain() {
        let records = BTreeMap::from([
            (0x1000, parsed_service(0x1000, 1, None)),
            (0x2000, parsed_service(0x2000, 2, Some(0x1000))),
            (0x3000, parsed_service(0x3000, 3, Some(0x2000))),
            (0x4000, parsed_service(0x4000, 4, Some(0x3000))),
            (0x9000, parsed_service(0x9000, 99, None)),
        ]);
        let inferred = infer_active_service_chain(&records);
        assert_eq!(inferred.len(), 4);
        assert!(inferred.contains_key(&0x1000));
        assert!(inferred.contains_key(&0x4000));
        assert!(!inferred.contains_key(&0x9000));
    }
}
