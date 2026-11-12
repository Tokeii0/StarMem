use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::plugins::{DriverRecord, list_drivers};
use super::{ProcessRecord, WindowsKernelContext, list_processes};
use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::profile::{KernelProfile, read_pdb_symbol_rvas};
use crate::symbols::{SymbolStore, codeview_from_virtual_pe};

#[derive(Debug, Serialize)]
pub struct NetstatReport {
    pub records: Vec<NetstatRecord>,
    pub tcpip_base: u64,
    pub tcpip_pdb_key: String,
    pub tcp_partitions_examined: usize,
    pub tcp_entries_declared: usize,
    pub tcp_endpoints_recovered: usize,
    pub bitmap_ports_examined: usize,
    /// Bitmap-asserted ports that actually produced an endpoint record.  Read
    /// together with `bitmap_ports_examined`: a gap is an enumeration miss.
    pub bitmap_ports_resolved: usize,
    pub missing_bytes: u64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NetstatRecord {
    pub virtual_address: u64,
    pub physical_address: Option<u64>,
    pub source: String,
    pub protocol: String,
    pub address_family: u16,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: Option<u16>,
    pub state: Option<String>,
    pub pid: u64,
    pub process: String,
    pub owner_resolution: String,
}

#[derive(Clone, Copy)]
struct HashTable {
    address: u64,
    table_size: u32,
    num_entries: u32,
    directory: u64,
}

#[derive(Clone, Copy)]
struct PortPoolLayout {
    bitmap: u64,
    assignments: u64,
}

#[derive(Clone, Copy)]
struct SocketLayout {
    next: u64,
    inetaf: u64,
    port: u64,
    local: u64,
}

#[derive(Clone, Copy)]
struct TcpLayout {
    inetaf: u64,
    addrinfo: u64,
    state: u64,
    local_port: u64,
    remote_port: u64,
}

const TCP_LAYOUTS: &[TcpLayout] = &[
    // Windows 7 / Server 2008 R2 TcpE layout.  The owning EPROCESS is much
    // later in the object, so AF/address/state fields must not be inferred
    // relative to the owner pointer.
    TcpLayout {
        inetaf: 0x18,
        addrinfo: 0x20,
        state: 0x68,
        local_port: 0x6c,
        remote_port: 0x6e,
    },
    TcpLayout {
        inetaf: 0x10,
        addrinfo: 0x18,
        state: 0x68,
        local_port: 0x6c,
        remote_port: 0x6e,
    },
    TcpLayout {
        inetaf: 0x10,
        addrinfo: 0x18,
        state: 0x6c,
        local_port: 0x70,
        remote_port: 0x72,
    },
    TcpLayout {
        inetaf: 0x18,
        addrinfo: 0x20,
        state: 0x50,
        local_port: 0x54,
        remote_port: 0x56,
    },
];

// These are layout candidates, not build selections.  Every candidate is
// scored against the captured bitmap, pointers, address family, port and
// EPROCESS owner before it is accepted.
const PORT_POOL_LAYOUTS: &[PortPoolLayout] = &[
    PortPoolLayout {
        bitmap: 0xd0,
        assignments: 0xe0,
    },
    PortPoolLayout {
        bitmap: 0xd8,
        assignments: 0xe8,
    },
    PortPoolLayout {
        bitmap: 0xc8,
        assignments: 0xd8,
    },
    PortPoolLayout {
        bitmap: 0xa0,
        assignments: 0xb0,
    },
    PortPoolLayout {
        bitmap: 0x90,
        assignments: 0xa0,
    },
];

const TCP_LISTENER_LAYOUTS: &[SocketLayout] = &[
    SocketLayout {
        next: 0x78,
        inetaf: 0x28,
        port: 0x72,
        local: 0x60,
    },
    SocketLayout {
        next: 0x70,
        inetaf: 0x20,
        port: 0x6a,
        local: 0x58,
    },
];

const UDP_LAYOUTS: &[SocketLayout] = &[
    SocketLayout {
        next: 0x70,
        inetaf: 0x20,
        port: 0xa0,
        local: 0xa8,
    },
    SocketLayout {
        next: 0x70,
        inetaf: 0x20,
        port: 0x80,
        local: 0x88,
    },
    SocketLayout {
        next: 0x70,
        inetaf: 0x20,
        port: 0x78,
        local: 0x80,
    },
    SocketLayout {
        next: 0x80,
        inetaf: 0x20,
        port: 0x80,
        local: 0x60,
    },
    SocketLayout {
        next: 0x88,
        inetaf: 0x20,
        port: 0x80,
        local: 0x60,
    },
];

pub fn netstat(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    symbol_store: &SymbolStore,
    limit: usize,
) -> Result<NetstatReport> {
    ensure!(limit > 0, "netstat 结果上限必须大于零");
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let modules = list_drivers(image, kernel, profile, 65_536)?;
    let tcpip = modules
        .records
        .iter()
        .find(|module| module.name.eq_ignore_ascii_case("tcpip.sys"))
        .context("PsLoadedModuleList 中没有 tcpip.sys")?;
    let codeview = codeview_from_virtual_pe(image, kernel.directory_table_base, tcpip.base)
        .context("无法从捕获页面恢复 tcpip.sys 的 CodeView 标识")?;
    ensure!(
        codeview.pdb_name.eq_ignore_ascii_case("tcpip.pdb"),
        "tcpip.sys 声明了非预期的 PDB {}",
        codeview.pdb_name
    );
    let pdb = symbol_store
        .resolve(&codeview)
        .with_context(|| format!("无法解析精确的 tcpip PDB {}", codeview.symbol_key))?;
    if image.is_live() {
        let mut symbols = pdb::PDB::open(std::fs::File::open(&pdb)?)?;
        let guid = symbols.pdb_information()?.guid.to_string();
        let age = symbols
            .debug_information()?
            .age()
            .context("tcpip PDB 缺少 DBI age")?;
        ensure!(
            guid.eq_ignore_ascii_case(&codeview.guid) && age == codeview.age,
            "tcpip PDB 与实时模块 CodeView 不匹配"
        );
    }
    let globals = read_pdb_symbol_rvas(
        &pdb,
        &[
            "PartitionTable",
            "PartitionCount",
            "UdpCompartmentSet",
            "TcpCompartmentSet",
            "UdpPortPool",
            "TcpPortPool",
        ],
    )?;

    let processes = list_processes(image, kernel, profile, 65_536)?;
    let owners: HashMap<u64, &ProcessRecord> = processes
        .processes
        .iter()
        .map(|process| (process.eprocess, process))
        .collect();
    let mut warnings: Vec<String> = modules.warnings;
    warnings.extend(
        processes
            .warnings
            .iter()
            .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message)),
    );
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    let mut missing_bytes = 0u64;

    let (partition_count, partition_tables, partition_entries, tcp_decoded) =
        enumerate_tcp_partitions(
            &space,
            tcpip,
            &globals,
            &owners,
            &mut records,
            &mut seen,
            limit,
            &mut missing_bytes,
            &mut warnings,
        );

    let mut bitmap_ports_examined = 0usize;
    let mut bitmap_ports_resolved = 0usize;
    for (protocol, modern_global, legacy_global, layouts) in [
        (
            "TCP",
            "TcpCompartmentSet",
            "TcpPortPool",
            TCP_LISTENER_LAYOUTS,
        ),
        ("UDP", "UdpCompartmentSet", "UdpPortPool", UDP_LAYOUTS),
    ] {
        if records.len() == limit {
            break;
        }
        let pool = resolve_port_pool(&space, tcpip.base, &globals, modern_global, legacy_global);
        let Some(pool) = pool else {
            warnings.push(format!("无法通过精确 tcpip 全局变量验证 {protocol} 端口池"));
            continue;
        };
        let Some(layout) = select_port_pool_layout(&space, pool) else {
            warnings.push(format!("{protocol} 端口池位图或分配布局未通过结构验证"));
            continue;
        };
        let sweep = enumerate_port_pool(
            &space,
            pool,
            layout,
            protocol,
            layouts,
            &owners,
            &mut records,
            &mut seen,
            limit,
            &mut missing_bytes,
        );
        bitmap_ports_examined += sweep.ports_examined;
        bitmap_ports_resolved += sweep.ports_resolved;
        if sweep.ports_examined > sweep.ports_resolved {
            warnings.push(format!(
                "{protocol} 端口池位图断言 {} 个端口，仅 {} 个解析出端点；{} 个已枚举但未恢复",
                sweep.ports_examined,
                sweep.ports_resolved,
                sweep.ports_examined - sweep.ports_resolved
            ));
        }
    }

    if records.len() == limit {
        warnings.push(format!("netstat 结果达到 {limit} 条上限"));
    }
    if missing_bytes != 0 {
        warnings.push(format!(
            "已验证 tcpip 表中有 {missing_bytes} 字节不可用，未进行枚举"
        ));
    }
    records.sort_unstable_by_key(|record| (record.pid, record.local_port, record.virtual_address));
    let tables_complete = partition_tables != 0
        && (partition_entries == 0 || tcp_decoded != 0)
        && !warnings.iter().any(|warning| {
            warning.contains("无法通过精确 tcpip 全局变量验证")
                || warning.contains("未通过结构验证")
        });
    // Recovering everything that was *declared* is not the same as enumerating
    // everything that *exists*.  A bitmap-asserted port that produced no
    // endpoint is a known miss, so it must clear `complete` — otherwise the
    // report claims coverage it does not have and the analyst stops looking.
    let enumeration_complete = bitmap_ports_examined == bitmap_ports_resolved;
    let complete = tables_complete
        && enumeration_complete
        && missing_bytes == 0
        && processes.complete
        && records.len() < limit;
    Ok(NetstatReport {
        records,
        tcpip_base: tcpip.base,
        tcpip_pdb_key: codeview.symbol_key,
        tcp_partitions_examined: partition_count,
        tcp_entries_declared: partition_entries,
        tcp_endpoints_recovered: tcp_decoded,
        bitmap_ports_examined,
        bitmap_ports_resolved,
        missing_bytes,
        complete,
        warnings,
    })
}

#[allow(clippy::too_many_arguments)]
fn enumerate_tcp_partitions(
    space: &X64AddressSpace<'_>,
    tcpip: &DriverRecord,
    globals: &std::collections::BTreeMap<String, u32>,
    owners: &HashMap<u64, &ProcessRecord>,
    records: &mut Vec<NetstatRecord>,
    seen: &mut HashSet<u64>,
    limit: usize,
    missing_bytes: &mut u64,
    warnings: &mut Vec<String>,
) -> (usize, usize, usize, usize) {
    let Some(table_rva) = globals.get("PartitionTable").copied() else {
        warnings.push("精确 tcpip PDB 中缺少 PartitionTable".to_owned());
        return (0, 0, 0, 0);
    };
    let Some(count_rva) = globals.get("PartitionCount").copied() else {
        warnings.push("精确 tcpip PDB 中缺少 PartitionCount".to_owned());
        return (0, 0, 0, 0);
    };
    let table = match space.read_u64(tcpip.base + u64::from(table_rva)) {
        Ok(value) if is_kernel_pointer(value) => value,
        _ => {
            warnings.push("PartitionTable 指针不可用或无效".to_owned());
            return (0, 0, 0, 0);
        }
    };
    let count = read_u8(space, tcpip.base + u64::from(count_rva))
        .filter(|count| (1..=255).contains(count))
        .map(usize::from)
        .unwrap_or(0);
    if count == 0 {
        warnings.push("PartitionCount 不可用或不在 1..255 范围内".to_owned());
        return (0, 0, 0, 0);
    }

    let mut candidates = [0xc0u64, 0x80]
        .into_iter()
        .map(|stride| {
            let tables = (0..count)
                .filter_map(|index| {
                    let pointer = space.read_u64(table + index as u64 * stride + 8).ok()?;
                    validate_hash_table(space, pointer)
                })
                .collect::<Vec<_>>();
            (stride, tables)
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|(_, tables)| std::cmp::Reverse(tables.len()));
    let Some((stride, tables)) = candidates.into_iter().next() else {
        warnings.push("没有可读的 TCP 分区布局候选".to_owned());
        return (count, 0, 0, 0);
    };
    if tables.is_empty() {
        warnings.push(format!(
            "PartitionTable {table:#x} 声明了 {count} 个分区，但两个已验证的 x64 步长都未解析出动态哈希表"
        ));
        return (count, 0, 0, 0);
    }
    if tables.len() != count {
        warnings.push(format!(
            "TCP 分区步长 {stride:#x} 验证了 {}/{} 个动态哈希表",
            tables.len(),
            count
        ));
    }
    let declared_entries = tables.iter().fold(0usize, |total, table| {
        total.saturating_add(table.num_entries as usize)
    });
    let before = records.len();
    let mut diagnostic = None;
    for hash in &tables {
        let current =
            enumerate_hash_table(space, *hash, owners, records, seen, limit, missing_bytes);
        if diagnostic.is_none() {
            diagnostic = current;
        }
        if records.len() == limit {
            break;
        }
    }
    let decoded = records.len().saturating_sub(before);
    if declared_entries != 0 && decoded < declared_entries {
        warnings.push(format!(
            "{} 个已验证 TCP 哈希表声明了 {declared_entries} 个条目；完整桶链遍历恢复出 {decoded} 个唯一端点（动态哈希表切换期间，参考计数可能不同）",
            tables.len(),
        ));
        if let Some(diagnostic) = diagnostic {
            warnings.push(diagnostic);
        }
    }
    (count, tables.len(), declared_entries, decoded)
}

fn validate_hash_table(space: &X64AddressSpace<'_>, address: u64) -> Option<HashTable> {
    if !is_kernel_pointer(address) {
        return None;
    }
    let table_size = read_u32(space, address + 8).ok()?;
    let num_entries = read_u32(space, address + 0x14).ok()?;
    let directory = space.read_u64(address + 0x20).ok()?;
    if table_size == 0
        || table_size > 4096
        || num_entries > 1_000_000
        || !is_kernel_pointer(directory)
        || space.read_u64(directory).is_err()
    {
        return None;
    }
    Some(HashTable {
        address,
        table_size,
        num_entries,
        directory,
    })
}

#[allow(clippy::too_many_arguments)]
fn enumerate_hash_table(
    space: &X64AddressSpace<'_>,
    table: HashTable,
    owners: &HashMap<u64, &ProcessRecord>,
    records: &mut Vec<NetstatRecord>,
    seen: &mut HashSet<u64>,
    limit: usize,
    missing_bytes: &mut u64,
) -> Option<String> {
    let per_table_limit = usize::try_from(table.num_entries)
        .unwrap_or(65_536)
        .saturating_add(usize::try_from(table.table_size).unwrap_or(4096))
        .max(64);
    let mut walked = 0usize;
    let mut diagnostic = None;
    for bucket in 0..table.table_size {
        if records.len() == limit || walked >= per_table_limit {
            break;
        }
        let head = table.directory + u64::from(bucket) * 0x10;
        let mut link = match space.read_u64(head) {
            Ok(value) => value & !3,
            Err(_) => {
                *missing_bytes += 8;
                continue;
            }
        };
        let mut bucket_seen = HashSet::new();
        while is_kernel_pointer(link)
            && link != head
            && bucket_seen.insert(link)
            && walked < per_table_limit
            && records.len() < limit
        {
            walked += 1;
            if let Some(object) = link.checked_sub(0x28) {
                if seen.insert(object)
                    && let Some(record) = decode_tcp_endpoint(space, object, owners)
                {
                    records.push(record);
                } else if diagnostic.is_none() {
                    diagnostic = diagnose_hash_link(space, link, owners);
                }
            }
            link = match space.read_u64(link) {
                Ok(value) => value & !3,
                Err(_) => {
                    *missing_bytes += 8;
                    break;
                }
            };
        }
    }
    let _ = table.address;
    diagnostic
}

fn diagnose_hash_link(
    space: &X64AddressSpace<'_>,
    link: u64,
    owners: &HashMap<u64, &ProcessRecord>,
) -> Option<String> {
    let start = link.checked_sub(0x400)?;
    let mut bytes = vec![0u8; 0x800];
    space.read_virtual(start, &mut bytes).ok()?;
    let hits = (0..bytes.len().saturating_sub(7))
        .step_by(8)
        .filter_map(|offset| {
            let pointer = buffer_u64(&bytes, offset)?;
            let owner = owners.get(&pointer)?;
            let field = start + offset as u64;
            let relative = if field >= link {
                format!("+{:#x}", field - link)
            } else {
                format!("-{:#x}", link - field)
            };
            Some(format!("{relative}=PID{}:{}", owner.pid, owner.name))
        })
        .take(8)
        .collect::<Vec<_>>();
    let object = link.saturating_sub(0x28);
    let object_offset = usize::try_from(object.saturating_sub(start)).ok()?;
    let object_bytes = bytes.get(object_offset..)?;
    let inetaf_hits = (0..object_bytes.len().saturating_sub(7).min(0x380))
        .step_by(8)
        .filter_map(|offset| {
            let pointer = buffer_u64(object_bytes, offset)?;
            inetaf_family(space, pointer).map(|family| format!("{offset:#x}=AF{family}"))
        })
        .take(8)
        .collect::<Vec<_>>();
    let state_6c = buffer_u32(object_bytes, 0x6c);
    let ports_70 = (
        buffer_be_u16(object_bytes, 0x70),
        buffer_be_u16(object_bytes, 0x72),
    );
    let state_80 = buffer_u32(object_bytes, 0x80);
    let state_port_hits = (0..object_bytes.len().saturating_sub(8).min(0x380))
        .step_by(4)
        .filter_map(|offset| {
            let state = buffer_u32(object_bytes, offset)?;
            let local = buffer_be_u16(object_bytes, offset + 4)?;
            let remote = buffer_be_u16(object_bytes, offset + 6)?;
            (state <= 13 && (local != 0 || remote != 0))
                .then(|| format!("{offset:#x}:{state}/{local}/{remote}"))
        })
        .take(16)
        .collect::<Vec<_>>();
    Some(format!(
        "首个未匹配 TCP 哈希链接 {link:#x}（物理地址 {:?}）；附近 EPROCESS 指针相对链接的偏移：[{}]；相对 link-0x28 的 InetAF 候选：[{}]；state@6c={state_6c:?} ports@70={ports_70:?} state@80={state_80:?}；状态/本地/远端候选：[{}]",
        space.translate(link).ok(),
        hits.join(", "),
        inetaf_hits.join(", "),
        state_port_hits.join(", ")
    ))
}

fn decode_tcp_endpoint(
    space: &X64AddressSpace<'_>,
    object: u64,
    owners: &HashMap<u64, &ProcessRecord>,
) -> Option<NetstatRecord> {
    let mut bytes = vec![0u8; 0x400];
    space.read_virtual(object, &mut bytes).ok()?;
    let owner = find_owner(&bytes, owners);
    // Current kernels use a compact endpoint in which AF/port/state are
    // embedded rather than reached through the older private wrappers.
    if owner.is_some_and(|(_, offset)| offset <= 0x40)
        && let Some(family) = buffer_le_u16(&bytes, 0x68).filter(valid_family)
        && let Some(local_port) = buffer_be_u16(&bytes, 0x6a).filter(|port| *port != 0)
        && let Some(state) = buffer_u32(&bytes, 0x80).filter(|state| *state <= 13)
    {
        let (pid, process, owner_resolution) = owner_identity(owner);
        return Some(NetstatRecord {
            virtual_address: object,
            physical_address: space.translate(object).ok(),
            source: "PartitionTable".to_owned(),
            protocol: if family == 2 { "TCPv4" } else { "TCPv6" }.to_owned(),
            address_family: family,
            local_address: unspecified(family),
            local_port,
            remote_address: unspecified(family),
            remote_port: None,
            state: Some(tcp_state_name(state).to_owned()),
            pid,
            process,
            owner_resolution,
        });
    }
    // Layout candidates are scored instead of accepted on first match.  The
    // hard gates below (family, state range, non-zero local port, kernel
    // addrinfo pointer) are satisfied by more than one candidate on several
    // builds.  On Server 2016 14393 the Windows 7 candidate reads a constant
    // field as the local port and an adjacent zero as the remote port, which
    // passes every gate and is returned first, shadowing the candidate that
    // resolves the real endpoint.  Scoring lets the coherent decode win
    // regardless of table order.
    let mut best: Option<(u32, NetstatRecord)> = None;
    for layout in TCP_LAYOUTS {
        let Some(inetaf) = buffer_u64(&bytes, layout.inetaf as usize) else {
            continue;
        };
        let family = inetaf_family(space, inetaf).or_else(|| {
            let (_, owner_offset) = owner?;
            buffer_le_u16(&bytes, owner_offset + 0x48).filter(valid_family)
        });
        let Some(family) = family else {
            continue;
        };
        let Some(state) = buffer_u32(&bytes, layout.state as usize) else {
            continue;
        };
        if state > 13 {
            continue;
        }
        let Some(local_port) = buffer_be_u16(&bytes, layout.local_port as usize) else {
            continue;
        };
        let Some(remote_port) = buffer_be_u16(&bytes, layout.remote_port as usize) else {
            continue;
        };
        if local_port == 0 {
            continue;
        }
        let Some(addrinfo) = buffer_u64(&bytes, layout.addrinfo as usize) else {
            continue;
        };
        if !is_kernel_pointer(addrinfo) {
            continue;
        }
        let local = space.read_u64(addrinfo).unwrap_or(0);
        let remote = space.read_u64(addrinfo + 0x10).unwrap_or(0);
        let local_address = read_standard_local_ip(space, local, family);
        let remote_address = read_ip_candidates(space, remote, family);

        let score = score_layout_candidate(
            local_address.is_some(),
            remote_address.is_some(),
            remote_port,
            state,
        );

        let (pid, process, owner_resolution) = owner_identity(owner);
        let record = NetstatRecord {
            virtual_address: object,
            physical_address: space.translate(object).ok(),
            source: "PartitionTable".to_owned(),
            protocol: if family == 2 { "TCPv4" } else { "TCPv6" }.to_owned(),
            address_family: family,
            local_address: local_address.unwrap_or_else(|| unspecified(family)),
            local_port,
            remote_address: remote_address.unwrap_or_else(|| unspecified(family)),
            remote_port: (remote_port != 0).then_some(remote_port),
            state: Some(tcp_state_name(state).to_owned()),
            pid,
            process,
            owner_resolution,
        };
        if best.as_ref().is_none_or(|(current, _)| score > *current) {
            best = Some((score, record));
        }
    }
    best.map(|(_, record)| record)
}

fn resolve_port_pool(
    space: &X64AddressSpace<'_>,
    module_base: u64,
    globals: &std::collections::BTreeMap<String, u32>,
    compartment_name: &str,
    legacy_name: &str,
) -> Option<u64> {
    if let Some(rva) = globals.get(compartment_name) {
        let set = space.read_u64(module_base + u64::from(*rva)).ok()?;
        let compartment = space.read_u64(set + 0x148).ok()?;
        let protocol = space.read_u64(compartment + 0x20).ok()?;
        let pool = space.read_u64(protocol).ok()?;
        if is_kernel_pointer(pool) {
            return Some(pool);
        }
    }
    globals.get(legacy_name).and_then(|rva| {
        let pool = space.read_u64(module_base + u64::from(*rva)).ok()?;
        is_kernel_pointer(pool).then_some(pool)
    })
}

fn select_port_pool_layout(space: &X64AddressSpace<'_>, pool: u64) -> Option<PortPoolLayout> {
    PORT_POOL_LAYOUTS
        .iter()
        .copied()
        .filter_map(|layout| {
            let bits = read_u32(space, pool + layout.bitmap).ok()?;
            let buffer = space.read_u64(pool + layout.bitmap + 8).ok()?;
            if !(256..=65_536).contains(&bits)
                || bits % 8 != 0
                || !is_kernel_pointer(buffer)
                || space.read_u64(buffer).is_err()
            {
                return None;
            }
            let readable_assignments = (0..256u64)
                .step_by(17)
                .filter(|index| {
                    space
                        .read_u64(pool + layout.assignments + index * 8)
                        .is_ok_and(|pointer| pointer == 0 || is_kernel_pointer(pointer))
                })
                .count();
            Some((readable_assignments, layout))
        })
        .max_by_key(|(score, _)| *score)
        .map(|(_, layout)| layout)
}

#[allow(clippy::too_many_arguments)]
fn enumerate_port_pool(
    space: &X64AddressSpace<'_>,
    pool: u64,
    pool_layout: PortPoolLayout,
    protocol: &str,
    socket_layouts: &[SocketLayout],
    owners: &HashMap<u64, &ProcessRecord>,
    records: &mut Vec<NetstatRecord>,
    seen: &mut HashSet<u64>,
    limit: usize,
    missing_bytes: &mut u64,
) -> PortPoolSweep {
    let bits = read_u32(space, pool + pool_layout.bitmap)
        .unwrap_or(0)
        .min(65_536);
    let buffer = space.read_u64(pool + pool_layout.bitmap + 8).unwrap_or(0);
    let byte_count = usize::try_from(bits.div_ceil(8)).unwrap_or(0);
    let mut bitmap = vec![0u8; byte_count];
    read_virtual_partial(space, buffer, &mut bitmap, missing_bytes);
    let ports = bitmap
        .iter()
        .enumerate()
        .flat_map(|(index, byte)| {
            (0..8)
                .filter_map(move |bit| (byte & (1 << bit) != 0).then_some((index * 8 + bit) as u16))
        })
        .filter(|port| *port != 0 && u32::from(*port) < bits)
        .collect::<Vec<_>>();

    // A port present in the verified bitmap is an endpoint the kernel says
    // exists.  Every `continue` below drops one without emitting a record, so
    // the two counts must be reported separately: `examined` alone reads as
    // coverage it does not provide.
    let mut ports_resolved = 0usize;
    for port in ports.iter().copied() {
        if records.len() == limit {
            break;
        }
        let emitted_before = records.len();
        let group = match space.read_u64(pool + pool_layout.assignments + u64::from(port >> 8) * 8)
        {
            Ok(value) if is_kernel_pointer(value) => value,
            Ok(_) => continue,
            Err(_) => {
                *missing_bytes += 8;
                continue;
            }
        };
        let assignment_list = match space.read_u64(group + 0x18) {
            Ok(value) if is_kernel_pointer(value) => value,
            Ok(_) => continue,
            Err(_) => {
                *missing_bytes += 8;
                continue;
            }
        };
        let inside = match space.read_u64(assignment_list + u64::from(port & 0xff) * 0x20 + 0x10) {
            Ok(value) => value & !3,
            Err(_) => {
                *missing_bytes += 8;
                continue;
            }
        };
        if !is_kernel_pointer(inside) {
            continue;
        }
        let Some((layout, mut object)) = socket_layouts.iter().find_map(|layout| {
            let object = inside.checked_sub(layout.next)?;
            socket_matches(space, object, port, *layout, owners).then_some((*layout, object))
        }) else {
            continue;
        };

        let mut chain = HashSet::new();
        while is_kernel_pointer(object) && chain.insert(object) && records.len() < limit {
            if seen.insert(object)
                && let Some(record) =
                    decode_bound_socket(space, object, port, protocol, layout, owners)
            {
                records.push(record);
            }
            let next_inside = match space.read_u64(object + layout.next) {
                Ok(value) => value & !3,
                Err(_) => {
                    *missing_bytes += 8;
                    break;
                }
            };
            if next_inside == 0 {
                break;
            }
            let Some(next) = next_inside.checked_sub(layout.next) else {
                break;
            };
            object = next;
        }
        if records.len() > emitted_before {
            ports_resolved += 1;
        }
    }
    PortPoolSweep {
        ports_examined: ports.len(),
        ports_resolved,
    }
}

/// Outcome of one port-pool sweep.  `ports_examined` counts bitmap-asserted
/// ports; `ports_resolved` counts those that actually produced an endpoint.
/// A wide gap means the sweep walked the pool but could not decode it, which
/// is an enumeration failure rather than an empty system.
#[derive(Clone, Copy, Default)]
struct PortPoolSweep {
    ports_examined: usize,
    ports_resolved: usize,
}

fn socket_matches(
    space: &X64AddressSpace<'_>,
    object: u64,
    port: u16,
    layout: SocketLayout,
    owners: &HashMap<u64, &ProcessRecord>,
) -> bool {
    let mut bytes = [0u8; 0x200];
    space.read_virtual(object, &mut bytes).is_ok()
        && buffer_be_u16(&bytes, layout.port as usize) == Some(port)
        && buffer_u64(&bytes, layout.inetaf as usize)
            .and_then(|pointer| inetaf_family(space, pointer))
            .is_some()
        && find_owner(&bytes, owners).is_some()
}

fn decode_bound_socket(
    space: &X64AddressSpace<'_>,
    object: u64,
    expected_port: u16,
    protocol: &str,
    layout: SocketLayout,
    owners: &HashMap<u64, &ProcessRecord>,
) -> Option<NetstatRecord> {
    let mut bytes = [0u8; 0x200];
    space.read_virtual(object, &mut bytes).ok()?;
    let port = buffer_be_u16(&bytes, layout.port as usize)?;
    if port != expected_port {
        return None;
    }
    let family = inetaf_family(space, buffer_u64(&bytes, layout.inetaf as usize)?)?;
    let (owner, owner_offset) = find_owner(&bytes, owners)?;
    let local_pointer = buffer_u64(&bytes, layout.local as usize).unwrap_or(0);
    let local_address = if protocol == "TCP" {
        read_standard_local_ip(space, local_pointer, family)
    } else {
        read_udp_local_ip(space, local_pointer, family)
    }
    .unwrap_or_else(|| unspecified(family));
    Some(NetstatRecord {
        virtual_address: object,
        physical_address: space.translate(object).ok(),
        source: if protocol == "TCP" {
            "TcpPortPool"
        } else {
            "UdpPortPool"
        }
        .to_owned(),
        protocol: format!("{}v{}", protocol, if family == 2 { 4 } else { 6 }),
        address_family: family,
        local_address,
        local_port: port,
        remote_address: "*".to_owned(),
        remote_port: None,
        state: (protocol == "TCP").then(|| "LISTENING".to_owned()),
        pid: owner.pid,
        process: owner.name.clone(),
        owner_resolution: format!("EPROCESS@{owner_offset:#x}"),
    })
}

fn find_owner<'a>(
    bytes: &[u8],
    owners: &HashMap<u64, &'a ProcessRecord>,
) -> Option<(&'a ProcessRecord, usize)> {
    (0x10..bytes.len().saturating_sub(7))
        .step_by(8)
        .find_map(|offset| {
            let pointer = buffer_u64(bytes, offset)?;
            owners.get(&pointer).copied().map(|owner| (owner, offset))
        })
}

fn owner_identity(owner: Option<(&ProcessRecord, usize)>) -> (u64, String, String) {
    owner.map_or_else(
        || (0, String::new(), "未解析".to_owned()),
        |(process, offset)| {
            (
                process.pid,
                process.name.clone(),
                format!("EPROCESS@{offset:#x}"),
            )
        },
    )
}

fn inetaf_family(space: &X64AddressSpace<'_>, inetaf: u64) -> Option<u16> {
    if !is_kernel_pointer(inetaf) {
        return None;
    }
    [0x14u64, 0x18, 0x74]
        .into_iter()
        .find_map(|offset| read_u16(space, inetaf + offset).ok().filter(valid_family))
}

fn read_standard_local_ip(
    space: &X64AddressSpace<'_>,
    wrapper: u64,
    family: u16,
) -> Option<String> {
    let data = space.read_u64(wrapper + 0x10).ok()?;
    let address = space.read_u64(data).ok()?;
    read_ip(space, address, family)
}

fn read_udp_local_ip(space: &X64AddressSpace<'_>, wrapper: u64, family: u16) -> Option<String> {
    let address = space.read_u64(wrapper).ok()?;
    read_ip(space, address, family)
}

fn read_ip_candidates(space: &X64AddressSpace<'_>, pointer: u64, family: u16) -> Option<String> {
    if !is_kernel_pointer(pointer) {
        return None;
    }
    read_ip(space, pointer, family).or_else(|| {
        let indirect = space.read_u64(pointer).ok()?;
        read_ip(space, indirect, family)
    })
}

fn read_ip(space: &X64AddressSpace<'_>, address: u64, family: u16) -> Option<String> {
    match family {
        2 => {
            let mut bytes = [0u8; 4];
            space.read_virtual(address, &mut bytes).ok()?;
            Some(Ipv4Addr::from(bytes).to_string())
        }
        0x17 => {
            let mut bytes = [0u8; 16];
            space.read_virtual(address, &mut bytes).ok()?;
            Some(Ipv6Addr::from(bytes).to_string())
        }
        _ => None,
    }
}

fn read_virtual_partial(
    space: &X64AddressSpace<'_>,
    mut address: u64,
    mut output: &mut [u8],
    missing_bytes: &mut u64,
) {
    while !output.is_empty() {
        let take = (0x1000 - (address & 0xfff)).min(output.len() as u64) as usize;
        if space.read_virtual(address, &mut output[..take]).is_err() {
            *missing_bytes += take as u64;
        }
        address += take as u64;
        output = &mut output[take..];
    }
}

fn read_u8(space: &X64AddressSpace<'_>, address: u64) -> Option<u8> {
    let mut bytes = [0u8; 1];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(bytes[0])
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

fn buffer_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn buffer_le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
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

fn valid_family(value: &u16) -> bool {
    matches!(*value, 2 | 0x17)
}

fn is_kernel_pointer(value: u64) -> bool {
    value >= 0xffff_8000_0000_0000 && value & 7 == 0
}

fn unspecified(family: u16) -> String {
    if family == 2 {
        Ipv4Addr::UNSPECIFIED.to_string()
    } else {
        Ipv6Addr::UNSPECIFIED.to_string()
    }
}

/// Rank one TcpE layout candidate that already cleared the hard gates.
///
/// Every input is resolved through pointers the candidate itself supplies, so
/// a candidate aimed at unrelated fields cannot manufacture a high score: it
/// would have to make an unrelated qword dereference to a valid address
/// structure *and* an adjacent halfword read as a coherent peer port.
fn score_layout_candidate(
    local_resolved: bool,
    remote_resolved: bool,
    remote_port: u16,
    state: u32,
) -> u32 {
    let mut score = 1u32;
    if local_resolved {
        score += 2;
    }
    if remote_resolved {
        score += 2;
    }
    // A connected state with no peer port is self-contradictory; a listening
    // or closed endpoint without one is expected, so only the former is
    // penalised.
    let connected = matches!(state, 2..=9 | 11 | 12);
    if remote_port != 0 {
        score += 2;
        if connected {
            score += 1;
        }
    } else if connected {
        score = score.saturating_sub(1);
    }
    score
}

fn tcp_state_name(state: u32) -> &'static str {
    match state {
        0 => "CLOSED",
        1 => "LISTENING",
        2 => "SYN_SENT",
        3 => "SYN_RECEIVED",
        4 => "ESTABLISHED",
        5 => "FIN_WAIT_1",
        6 => "FIN_WAIT_2",
        7 => "CLOSE_WAIT",
        8 => "CLOSING",
        9 => "LAST_ACK",
        10 => "DELETE_TCB",
        11 => "TIME_WAIT",
        12 => "TIME_WAIT",
        13 => "DELETE_TCB",
        _ => "未知",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_network_port_byte_order() {
        assert_eq!(buffer_be_u16(&[0x01, 0xbb], 0), Some(443));
    }

    #[test]
    fn accepts_only_inet_families() {
        assert!(valid_family(&2));
        assert!(valid_family(&0x17));
        assert!(!valid_family(&0));
    }

    /// Regression for Server 2016 14393: the Windows 7 candidate clears every
    /// hard gate on a connected TcpE by reading a constant field as the local
    /// port and an adjacent zero as the peer port.  Being first in the table,
    /// it used to win and report an ESTABLISHED session as SYN_SENT with no
    /// peer port.  The coherent candidate must now outrank it.
    #[test]
    fn coherent_candidate_outranks_shadowing_one() {
        // Wrong offsets: no address resolves, peer port reads as zero, and the
        // state field lands on a connected value.
        let shadowing = score_layout_candidate(false, false, 0, 3);
        // Correct offsets: both addresses resolve and the peer port is real.
        let coherent = score_layout_candidate(true, true, 8000, 4);
        assert!(
            coherent > shadowing,
            "coherent={coherent} must outrank shadowing={shadowing}"
        );
    }

    #[test]
    fn listener_without_peer_port_is_not_penalised() {
        // A listener legitimately has no peer port, so it must not lose the
        // point a closed-but-connected endpoint would.
        let listener = score_layout_candidate(true, false, 0, 1);
        let connected_without_peer = score_layout_candidate(true, false, 0, 4);
        assert!(listener > connected_without_peer);
    }

    #[test]
    fn port_pool_sweep_reports_unresolved_ports() {
        let sweep = PortPoolSweep {
            ports_examined: 25,
            ports_resolved: 3,
        };
        // The gap is what makes `complete` false; examined alone would read as
        // coverage the sweep never provided.
        assert_ne!(sweep.ports_examined, sweep.ports_resolved);
    }
}
