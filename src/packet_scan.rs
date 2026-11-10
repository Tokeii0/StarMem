use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::profile::{TypeLayout, read_pdb_symbol_rvas, read_pdb_type_layouts};
use crate::session::AnalysisSession;
use crate::symbols::codeview_from_virtual_pe;
use crate::windows::netstat_plugins::NetstatRecord;

const MAX_EVIDENCE_ADDRESSES: usize = 64;
const MAX_PACKET_OWNERS: usize = 8;
const MAX_WARNINGS: usize = 64;
const RAW_CANDIDATE_MULTIPLIER: usize = 64;
const LINKTYPE_RAW: u16 = 101;
const NDIS_TRIAGE_SIGNATURE: u32 = 0xbece_dafa;
const MAX_NDIS_POOLS: usize = 65_536;
const MAX_NDIS_NET_BUFFERS: usize = 1_000_000;
const MAX_NDIS_CHAIN_NODES: usize = 4_096;
const MAX_MDL_CHAIN_NODES: usize = 256;
const MAX_MDL_PAGES: usize = 16_384;

#[derive(Debug, Clone, Copy)]
pub struct PacketScanOptions {
    pub limit: usize,
    pub endpoint_limit: usize,
    pub max_packet_size: usize,
    pub max_occurrences: usize,
    pub chunk_size: usize,
}

impl Default for PacketScanOptions {
    fn default() -> Self {
        Self {
            limit: 100_000,
            endpoint_limit: 1_000_000,
            max_packet_size: 65_535,
            max_occurrences: 16,
            chunk_size: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketScanStage {
    NdisStructures,
    PhysicalMemory,
    EndpointTables,
    Correlate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InternetProtocol {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketOwner {
    pub pid: u64,
    pub process: String,
    pub direction: String,
    pub match_basis: String,
    pub confidence: String,
    pub endpoint_address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NdisPacketEvidence {
    pub pool: u64,
    pub allocation: u64,
    pub net_buffer_list: u64,
    pub net_buffer: u64,
    pub mdl_chain: u64,
    pub current_mdl: u64,
    pub data_length: u32,
    pub frame_offset: usize,
    pub mdl_addresses: Vec<u64>,
    pub page_frame_numbers: Vec<u64>,
    pub crosses_physical_pages: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketRecord {
    pub index: usize,
    pub source: String,
    pub internet_protocol: InternetProtocol,
    pub transport_protocol: TransportProtocol,
    pub source_address: String,
    pub source_port: u16,
    pub destination_address: String,
    pub destination_port: u16,
    pub packet_length: usize,
    pub payload_length: usize,
    pub tcp_sequence: Option<u32>,
    pub tcp_acknowledgment: Option<u32>,
    pub tcp_flags: Option<String>,
    pub ip_checksum: String,
    pub transport_checksum: String,
    pub confidence: String,
    pub sha256: String,
    pub payload_preview_hex: String,
    pub occurrences: usize,
    pub physical_addresses: Vec<u64>,
    pub file_offsets: Vec<u64>,
    pub recovery_sources: Vec<String>,
    pub ndis_evidence: Vec<NdisPacketEvidence>,
    pub owners: Vec<PacketOwner>,
    pub timestamp: Option<String>,
    pub timestamp_basis: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcapngExportReport {
    pub output_path: String,
    pub packet_count: usize,
    pub output_bytes: u64,
    pub sha256: String,
    pub link_type: String,
    pub timestamp_policy: String,
}

#[derive(Debug, Serialize)]
pub struct PacketScanStatistics {
    pub header_candidates: u64,
    pub rejected_offload_candidates: usize,
    pub rejected_offload_occurrences: usize,
    pub validated_occurrences: usize,
    pub unique_packets: usize,
    pub duplicate_occurrences: usize,
    pub endpoint_records: usize,
    pub owner_associations: usize,
    pub bytes_scanned: u64,
    pub ndis_pools_examined: usize,
    pub ndis_allocations_examined: usize,
    pub ndis_net_buffers_examined: usize,
    pub ndis_packet_occurrences: usize,
    pub ndis_cross_page_occurrences: usize,
    pub ndis_only_packets: usize,
    pub ndis_rejections: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct PacketScanTiming {
    pub ndis_scan_seconds: f64,
    pub packet_scan_seconds: f64,
    pub endpoint_seconds: f64,
    pub correlation_seconds: f64,
    pub total_seconds: f64,
    pub scan_gib_per_second: f64,
}

#[derive(Debug, Serialize)]
pub struct PacketScanReport {
    pub records: Vec<PacketRecord>,
    pub export: Option<PcapngExportReport>,
    pub ndis_pdb_key: Option<String>,
    pub complete: bool,
    pub ndis_structure_complete: bool,
    pub endpoint_correlation_complete: bool,
    pub warnings: Vec<String>,
    pub statistics: PacketScanStatistics,
    pub timing: PacketScanTiming,
}

pub struct PacketScanArtifacts {
    pub report: PacketScanReport,
    packets: Vec<Vec<u8>>,
    source_images: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct RawPacket {
    bytes: Vec<u8>,
    physical_address: u64,
    /// Exact offset in a directly-backed source. Decoded/synthetic mappings have no file offset.
    file_offset: Option<u64>,
    parsed: ParsedPacket,
    source: PacketSource,
    ndis_evidence: Option<NdisPacketEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketSource {
    PhysicalCarving,
    NdisStructure,
}

#[derive(Debug, Clone)]
struct ParsedPacket {
    internet_protocol: InternetProtocol,
    transport_protocol: TransportProtocol,
    source_address: IpAddr,
    source_port: u16,
    destination_address: IpAddr,
    destination_port: u16,
    payload_offset: usize,
    tcp_sequence: Option<u32>,
    tcp_acknowledgment: Option<u32>,
    tcp_flags: Option<String>,
    ip_checksum: ChecksumState,
    transport_checksum: ChecksumState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChecksumState {
    Valid,
    ZeroOffload,
    InvalidOffload,
    NotApplicable,
}

#[derive(Debug, Clone)]
struct PacketChunk {
    physical_start: u64,
    file_start: Option<usize>,
    core_len: usize,
    scan_len: usize,
}

pub fn scan_memory_packets<F>(
    session: &AnalysisSession,
    options: &PacketScanOptions,
    mut progress: F,
) -> Result<PacketScanArtifacts>
where
    F: FnMut(PacketScanStage),
{
    validate_options(options)?;
    let started = Instant::now();
    let raw_limit = options
        .limit
        .saturating_mul(RAW_CANDIDATE_MULTIPLIER)
        .min(1_000_000)
        .max(options.limit);

    progress(PacketScanStage::NdisStructures);
    let ndis_started = Instant::now();
    let mut warnings = Vec::new();
    let (mut ndis, ndis_structure_complete) = match scan_ndis_packets(session, options, raw_limit) {
        Ok(scan) => {
            for warning in &scan.warnings {
                push_warning(&mut warnings, format!("NDIS 结构恢复：{warning}"));
            }
            let complete = scan.complete;
            (scan, complete)
        }
        Err(error) => {
            push_warning(
                &mut warnings,
                format!("NDIS 结构恢复不可用，继续执行物理雕刻：{error:#}"),
            );
            (NdisScanResult::default(), false)
        }
    };
    let ndis_scan_seconds = ndis_started.elapsed().as_secs_f64();

    progress(PacketScanStage::PhysicalMemory);
    let scan_started = Instant::now();
    let scan = scan_raw_packets(session.image(), options, raw_limit)?;
    let packet_scan_seconds = scan_started.elapsed().as_secs_f64();

    let mut candidates = std::mem::take(&mut ndis.packets);
    candidates.extend(scan.packets);
    let (mut records, mut packets, unique_truncated) =
        merge_raw_packets(candidates, options.limit, options.max_occurrences);
    if scan.raw_truncated {
        push_warning(
            &mut warnings,
            format!("原始有效包候选达到 {raw_limit} 条安全上限"),
        );
    }
    if unique_truncated {
        push_warning(
            &mut warnings,
            format!("唯一数据包结果达到 {} 条上限", options.limit),
        );
    }
    push_warning(
        &mut warnings,
        "当前版本组合 NDIS NBL/NB/MDL/PFN 结构恢复与物理雕刻；不支持 IP 分片、IPv6 扩展头和巨型载荷".to_owned(),
    );
    push_warning(
        &mut warnings,
        "物理雕刻会排除非零校验失败数据；由 NBL/NB/MDL/PFN 完整证明的数据允许保留硬件卸载尚未完成的校验和，其他零校验候选仍需精确五元组证明".to_owned(),
    );

    progress(PacketScanStage::EndpointTables);
    let endpoint_started = Instant::now();
    let mut endpoint_correlation_complete = true;
    let endpoints = if records.is_empty() {
        Vec::new()
    } else {
        match session.netstat(options.endpoint_limit) {
            Ok(report) => {
                endpoint_correlation_complete = report.complete;
                for warning in report.warnings {
                    push_warning(&mut warnings, format!("端点关联：{warning}"));
                }
                report.records
            }
            Err(error) => {
                endpoint_correlation_complete = false;
                push_warning(
                    &mut warnings,
                    format!("端点关联不可用，数据包仍保留：{error:#}"),
                );
                Vec::new()
            }
        }
    };
    let endpoint_seconds = endpoint_started.elapsed().as_secs_f64();

    progress(PacketScanStage::Correlate);
    let correlation_started = Instant::now();
    correlate_packet_owners(&mut records, &endpoints);
    let (
        filtered_records,
        filtered_packets,
        rejected_offload_candidates,
        rejected_offload_occurrences,
    ) = retain_proven_packets(records, packets);
    records = filtered_records;
    packets = filtered_packets;
    let owner_associations = records.iter().map(|record| record.owners.len()).sum();
    let ndis_only_packets = records
        .iter()
        .filter(|record| {
            record.recovery_sources.len() == 1
                && record.recovery_sources[0] == "ndis_nbl_nb_mdl_pfn"
        })
        .count();
    let correlation_seconds = correlation_started.elapsed().as_secs_f64();
    let validated_occurrences: usize = records.iter().map(|record| record.occurrences).sum();
    let duplicate_occurrences = validated_occurrences.saturating_sub(records.len());
    let bytes_scanned = scan.bytes_scanned;
    let total_seconds = started.elapsed().as_secs_f64();
    let scan_gib_per_second =
        bytes_scanned as f64 / 1024f64.powi(3) / packet_scan_seconds.max(f64::EPSILON);
    let complete = !scan.raw_truncated && !unique_truncated && ndis_structure_complete;
    for (index, record) in records.iter_mut().enumerate() {
        record.index = index + 1;
    }
    debug_assert_eq!(records.len(), packets.len());
    Ok(PacketScanArtifacts {
        report: PacketScanReport {
            statistics: PacketScanStatistics {
                header_candidates: scan.header_candidates,
                rejected_offload_candidates,
                rejected_offload_occurrences,
                validated_occurrences,
                unique_packets: records.len(),
                duplicate_occurrences,
                endpoint_records: endpoints.len(),
                owner_associations,
                bytes_scanned,
                ndis_pools_examined: ndis.pools_examined,
                ndis_allocations_examined: ndis.allocations_examined,
                ndis_net_buffers_examined: ndis.net_buffers_examined,
                ndis_packet_occurrences: ndis.packet_occurrences,
                ndis_cross_page_occurrences: ndis.cross_page_occurrences,
                ndis_only_packets,
                ndis_rejections: ndis.rejections,
            },
            timing: PacketScanTiming {
                ndis_scan_seconds,
                packet_scan_seconds,
                endpoint_seconds,
                correlation_seconds,
                total_seconds,
                scan_gib_per_second,
            },
            records,
            export: None,
            ndis_pdb_key: ndis.pdb_key,
            complete,
            ndis_structure_complete,
            endpoint_correlation_complete,
            warnings,
        },
        packets: std::mem::take(&mut packets),
        source_images: session
            .image()
            .sources()
            .map(|source| source.path.clone())
            .collect(),
    })
}

impl PacketScanArtifacts {
    pub fn export_pcapng(
        &mut self,
        output_path: &Path,
        force: bool,
    ) -> Result<&PcapngExportReport> {
        ensure!(
            self.packets.len() == self.report.records.len(),
            "数据包字节与报告记录数量不一致"
        );
        let mut policy = OutputPolicy::new(force);
        for source in &self.source_images {
            policy.protect_file("memory_image_or_sidecar", source);
        }
        policy.output(OutputTarget::file("packets.pcapng", output_path));
        policy.preflight()?;
        let mut export = None;
        policy.write_file_atomic(output_path, |file| {
            let mut writer = HashingWriter::new(BufWriter::new(file));
            write_pcapng(&mut writer, &self.packets, &self.report.records)?;
            let (mut output, output_bytes, sha256) = writer.finish()?;
            output.flush()?;
            export = Some((output_bytes, sha256));
            Ok(())
        })?;
        let (output_bytes, sha256) = export.context("PCAPNG 写出未生成摘要")?;
        let report = PcapngExportReport {
            output_path: output_path.display().to_string(),
            packet_count: self.packets.len(),
            output_bytes,
            sha256,
            link_type: "LINKTYPE_RAW (101)".to_owned(),
            timestamp_policy: "镜像中没有可靠逐包时间戳；PCAPNG 时间戳字段写为零".to_owned(),
        };
        self.report.export = Some(report);
        Ok(self.report.export.as_ref().unwrap())
    }
}

struct RawScanResult {
    packets: Vec<RawPacket>,
    bytes_scanned: u64,
    header_candidates: u64,
    raw_truncated: bool,
}

#[derive(Default)]
struct NdisScanResult {
    packets: Vec<RawPacket>,
    pdb_key: Option<String>,
    pools_examined: usize,
    allocations_examined: usize,
    net_buffers_examined: usize,
    packet_occurrences: usize,
    cross_page_occurrences: usize,
    rejections: BTreeMap<String, usize>,
    complete: bool,
    warnings: Vec<String>,
}

#[derive(Clone, Copy)]
struct NdisLayouts {
    nbl_first_net_buffer: u64,
    nbl_source_handle: u64,
    nbl_size: u64,
    nb_next: u64,
    nb_current_mdl: u64,
    nb_current_mdl_offset: u64,
    nb_data_length: u64,
    nb_mdl_chain: u64,
    nb_data_offset: u64,
    mdl_next: u64,
    mdl_size_field: u64,
    mdl_start_va: u64,
    mdl_byte_count: u64,
    mdl_byte_offset: u64,
    mdl_header_size: u64,
}

#[derive(Clone, Copy)]
struct NdisTriage {
    pool_list_offset: u64,
    allocated_list_offset: u64,
    entry_linkage_offset: u64,
    entry_header_size: u64,
    nbl_size: u64,
    source_handle_offset: u64,
    global_pool_list: u64,
}

#[derive(Clone, Copy)]
struct NdisTriageOffsets {
    signature: usize,
    revision: usize,
    size: usize,
    pool_list_offset: usize,
    allocated_list_offset: usize,
    entry_linkage_offset: usize,
    entry_header_size: usize,
    nbl_size: usize,
    source_handle_offset: usize,
    global_pool_list: usize,
}

struct MdlDescriptor {
    next: u64,
    byte_count: usize,
    byte_offset: usize,
    pfns: Vec<u64>,
}

struct MdlRecovery {
    bytes: Vec<u8>,
    physical_segments: Vec<(usize, u64, usize)>,
    mdl_addresses: Vec<u64>,
    pfns: Vec<u64>,
}

fn scan_ndis_packets(
    session: &AnalysisSession,
    options: &PacketScanOptions,
    packet_limit: usize,
) -> Result<NdisScanResult> {
    let drivers = session.drivers(65_536)?;
    let ndis = drivers
        .records
        .iter()
        .find(|driver| driver.name.eq_ignore_ascii_case("ndis.sys"))
        .context("已加载模块链中没有 ndis.sys")?;
    let codeview = codeview_from_virtual_pe(
        session.image(),
        session.kernel().directory_table_base,
        ndis.base,
    )
    .context("无法从捕获的 ndis.sys 恢复 CodeView 标识")?;
    ensure!(
        codeview.pdb_name.eq_ignore_ascii_case("ndis.pdb"),
        "ndis.sys 声明了非预期的 PDB {}",
        codeview.pdb_name
    );
    let protected_sources = session
        .image()
        .sources()
        .map(|source| ("memory_image_or_sidecar", source.path.as_path()))
        .collect::<Vec<_>>();
    let pdb = session
        .symbol_store()
        .resolve_protecting(&codeview, &protected_sources)
        .with_context(|| format!("无法解析精确的 NDIS PDB {}", codeview.symbol_key))?;
    let symbols = read_pdb_symbol_rvas(
        &pdb,
        &["ndisGlobalTriageBlock", "ndisGlobalNetBufferListPoolList"],
    )?;
    let types = read_pdb_type_layouts(
        &pdb,
        &[
            "_NET_BUFFER_LIST",
            "_NET_BUFFER",
            "_MDL",
            "_NDIS_GLOBAL_TRIAGE_BLOCK",
        ],
    )?;
    let layouts = ndis_layouts(&types)?;
    let triage_rva = symbols
        .get("ndisGlobalTriageBlock")
        .copied()
        .context("精确 NDIS PDB 中没有 ndisGlobalTriageBlock")?;
    let space = X64AddressSpace::new(session.image(), session.kernel().directory_table_base)?;
    let triage_address = ndis
        .base
        .checked_add(u64::from(triage_rva))
        .context("NDIS triage block 地址溢出")?;
    let triage = read_ndis_triage(
        &space,
        triage_address,
        layouts,
        types.get("_NDIS_GLOBAL_TRIAGE_BLOCK"),
    )?;
    if let Some(global_rva) = symbols.get("ndisGlobalNetBufferListPoolList") {
        let symbol_address = ndis.base + u64::from(*global_rva);
        ensure!(
            symbol_address == triage.global_pool_list,
            "NDIS triage block 的 NBL pool 链表 {:#x} 与 PDB 全局符号 {symbol_address:#x} 不一致",
            triage.global_pool_list
        );
    }

    let mut result = NdisScanResult {
        pdb_key: Some(codeview.symbol_key),
        complete: drivers.complete,
        ..NdisScanResult::default()
    };
    for warning in drivers.warnings {
        push_warning(&mut result.warnings, format!("驱动枚举：{warning}"));
    }
    enumerate_ndis_pools(
        session.image(),
        &space,
        layouts,
        triage,
        options,
        packet_limit,
        &mut result,
    )?;
    Ok(result)
}

fn ndis_layouts(types: &BTreeMap<String, TypeLayout>) -> Result<NdisLayouts> {
    let nbl = types
        .get("_NET_BUFFER_LIST")
        .context("NDIS PDB 中没有完整的 _NET_BUFFER_LIST")?;
    let nb = types
        .get("_NET_BUFFER")
        .context("NDIS PDB 中没有完整的 _NET_BUFFER")?;
    let mdl = types.get("_MDL").context("NDIS PDB 中没有完整的 _MDL")?;
    Ok(NdisLayouts {
        nbl_first_net_buffer: type_field_offset(nbl, "_NET_BUFFER_LIST", "FirstNetBuffer")?,
        nbl_source_handle: type_field_offset(nbl, "_NET_BUFFER_LIST", "SourceHandle")?,
        nbl_size: nbl.size,
        nb_next: type_field_offset(nb, "_NET_BUFFER", "Next")?,
        nb_current_mdl: type_field_offset(nb, "_NET_BUFFER", "CurrentMdl")?,
        nb_current_mdl_offset: type_field_offset(nb, "_NET_BUFFER", "CurrentMdlOffset")?,
        nb_data_length: type_field_offset(nb, "_NET_BUFFER", "DataLength")?,
        nb_mdl_chain: type_field_offset(nb, "_NET_BUFFER", "MdlChain")?,
        nb_data_offset: type_field_offset(nb, "_NET_BUFFER", "DataOffset")?,
        mdl_next: type_field_offset(mdl, "_MDL", "Next")?,
        mdl_size_field: type_field_offset(mdl, "_MDL", "Size")?,
        mdl_start_va: type_field_offset(mdl, "_MDL", "StartVa")?,
        mdl_byte_count: type_field_offset(mdl, "_MDL", "ByteCount")?,
        mdl_byte_offset: type_field_offset(mdl, "_MDL", "ByteOffset")?,
        mdl_header_size: mdl.size,
    })
}

fn type_field_offset(layout: &TypeLayout, type_name: &str, field_name: &str) -> Result<u64> {
    layout
        .fields
        .get(field_name)
        .map(|field| field.offset)
        .with_context(|| format!("NDIS PDB 中没有 {type_name}.{field_name}"))
}

fn read_ndis_triage(
    space: &X64AddressSpace<'_>,
    address: u64,
    layouts: NdisLayouts,
    triage_layout: Option<&TypeLayout>,
) -> Result<NdisTriage> {
    let offsets = ndis_triage_offsets(triage_layout)?;
    let read_length = offsets
        .global_pool_list
        .checked_add(8)
        .context("NDIS triage block 读取长度溢出")?;
    ensure!(read_length <= 0x1000, "NDIS triage block 字段范围不合理");
    let mut bytes = vec![0u8; read_length];
    space
        .read_virtual(address, &mut bytes)
        .with_context(|| format!("无法读取 NDIS triage block {address:#x}"))?;
    ensure!(
        read_le_u32(&bytes, offsets.signature)? == NDIS_TRIAGE_SIGNATURE,
        "NDIS triage block 签名无效"
    );
    let revision = read_le_u16(&bytes, offsets.revision)?;
    let size = read_le_u16(&bytes, offsets.size)?;
    ensure!(
        revision != 0 && usize::from(size) >= read_length,
        "NDIS triage block 版本或大小无效"
    );
    let triage = NdisTriage {
        pool_list_offset: u64::from(read_le_u16(&bytes, offsets.pool_list_offset)?),
        allocated_list_offset: u64::from(read_le_u16(&bytes, offsets.allocated_list_offset)?),
        entry_linkage_offset: u64::from(read_le_u16(&bytes, offsets.entry_linkage_offset)?),
        entry_header_size: u64::from(read_le_u16(&bytes, offsets.entry_header_size)?),
        nbl_size: u64::from(read_le_u16(&bytes, offsets.nbl_size)?),
        source_handle_offset: u64::from(read_le_u16(&bytes, offsets.source_handle_offset)?),
        global_pool_list: read_le_u64(&bytes, offsets.global_pool_list)?,
    };
    ensure!(
        triage.pool_list_offset < 0x1000
            && triage.allocated_list_offset < 0x1000
            && triage.entry_linkage_offset < triage.entry_header_size
            && triage.entry_header_size <= 0x1000
            && triage.pool_list_offset.is_multiple_of(8)
            && triage.allocated_list_offset.is_multiple_of(8)
            && triage.entry_linkage_offset.is_multiple_of(8)
            && triage.entry_header_size.is_multiple_of(8),
        "NDIS triage block 的 pool/分配偏移不合理"
    );
    ensure!(
        triage.nbl_size == layouts.nbl_size,
        "NDIS triage NBL 大小 {} 与精确 PDB 大小 {} 不一致",
        triage.nbl_size,
        layouts.nbl_size
    );
    ensure!(
        triage.source_handle_offset == layouts.nbl_source_handle,
        "NDIS triage SourceHandle 偏移 {} 与精确 PDB 偏移 {} 不一致",
        triage.source_handle_offset,
        layouts.nbl_source_handle
    );
    ensure!(
        is_kernel_pointer(triage.global_pool_list) && triage.global_pool_list.is_multiple_of(8),
        "NDIS triage block 的全局 NBL pool 链表指针无效"
    );
    Ok(triage)
}

fn ndis_triage_offsets(layout: Option<&TypeLayout>) -> Result<NdisTriageOffsets> {
    let Some(layout) = layout else {
        // Older public NDIS PDBs omit this type. These positions are accepted
        // only after signature, size, NBL layout and SourceHandle cross-checks.
        return Ok(NdisTriageOffsets {
            signature: 0,
            revision: 4,
            size: 6,
            pool_list_offset: 0x44,
            allocated_list_offset: 0x46,
            entry_linkage_offset: 0x4c,
            entry_header_size: 0x4e,
            nbl_size: 0x56,
            source_handle_offset: 0x5a,
            global_pool_list: 0x68,
        });
    };
    let field = |name: &str| -> Result<usize> {
        usize::try_from(type_field_offset(
            layout,
            "_NDIS_GLOBAL_TRIAGE_BLOCK",
            name,
        )?)
        .context("NDIS triage block 字段偏移超出平台范围")
    };
    Ok(NdisTriageOffsets {
        signature: field("Signature")?,
        revision: field("Revision")?,
        size: field("Size")?,
        pool_list_offset: field("NBLPoolListOffset")?,
        allocated_list_offset: field("AllocatedListOffset")?,
        entry_linkage_offset: field("EntryLinkageOffset")?,
        entry_header_size: field("EntryHeaderSize")?,
        nbl_size: field("NblSize")?,
        source_handle_offset: field("SourceHandleOffset")?,
        global_pool_list: field("GlobalNetBufferListPoolList")?,
    })
}

fn enumerate_ndis_pools(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    layouts: NdisLayouts,
    triage: NdisTriage,
    options: &PacketScanOptions,
    packet_limit: usize,
    result: &mut NdisScanResult,
) -> Result<()> {
    let head = triage.global_pool_list;
    let (mut link, head_blink) = read_list_entry(space, head)
        .with_context(|| format!("无法读取 NDIS 全局 NBL pool 链表头 {head:#x}"))?;
    let mut previous = head;
    let mut visited = HashSet::new();
    while link != head {
        if result.pools_examined == MAX_NDIS_POOLS {
            result.complete = false;
            push_warning(&mut result.warnings, "NBL pool 数量达到安全上限".to_owned());
            break;
        }
        if !is_kernel_pointer(link) || link % 8 != 0 || !visited.insert(link) {
            result.complete = false;
            push_warning(
                &mut result.warnings,
                format!("NBL pool 链表在 {link:#x} 处出现无效指针或环"),
            );
            break;
        }
        let (next, blink) = match read_list_entry(space, link) {
            Ok(entry) => entry,
            Err(error) => {
                result.complete = false;
                push_warning(
                    &mut result.warnings,
                    format!("无法读取 NBL pool 链表节点 {link:#x}：{error:#}"),
                );
                break;
            }
        };
        if blink != previous {
            result.complete = false;
            push_warning(
                &mut result.warnings,
                format!("NBL pool 链表节点 {link:#x} 的反向指针不一致"),
            );
            break;
        }
        let Some(pool) = link.checked_sub(triage.pool_list_offset) else {
            result.complete = false;
            break;
        };
        result.pools_examined += 1;
        enumerate_ndis_allocations(
            image,
            space,
            layouts,
            triage,
            pool,
            options,
            packet_limit,
            result,
        );
        if result.packets.len() == packet_limit {
            result.complete = false;
            push_warning(
                &mut result.warnings,
                format!("NDIS 结构包候选达到 {packet_limit} 条安全上限"),
            );
            break;
        }
        previous = link;
        link = next;
    }
    if link == head && head_blink != previous {
        result.complete = false;
        push_warning(
            &mut result.warnings,
            "NBL pool 链表头的反向指针与末节点不一致".to_owned(),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn enumerate_ndis_allocations(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    layouts: NdisLayouts,
    triage: NdisTriage,
    pool: u64,
    options: &PacketScanOptions,
    packet_limit: usize,
    result: &mut NdisScanResult,
) {
    let Some(head) = pool.checked_add(triage.allocated_list_offset) else {
        result.complete = false;
        return;
    };
    let Ok((mut link, head_blink)) = read_list_entry(space, head) else {
        result.complete = false;
        push_warning(
            &mut result.warnings,
            format!("无法读取 NBL pool {pool:#x} 的分配链表头"),
        );
        return;
    };
    let mut previous = head;
    let mut visited = HashSet::new();
    while link != head {
        if result.allocations_examined == MAX_NDIS_NET_BUFFERS {
            result.complete = false;
            push_warning(&mut result.warnings, "NBL 分配数量达到安全上限".to_owned());
            return;
        }
        if !is_kernel_pointer(link) || link % 8 != 0 || !visited.insert(link) {
            result.complete = false;
            push_warning(
                &mut result.warnings,
                format!("NBL pool {pool:#x} 的分配链在 {link:#x} 处损坏"),
            );
            return;
        }
        let Ok((next, blink)) = read_list_entry(space, link) else {
            result.complete = false;
            return;
        };
        if blink != previous {
            result.complete = false;
            push_warning(
                &mut result.warnings,
                format!("NBL 分配节点 {link:#x} 的反向指针不一致"),
            );
            return;
        }
        result.allocations_examined += 1;
        if let Some(allocation) = link.checked_sub(triage.entry_linkage_offset)
            && let Some(nbl) = allocation.checked_add(triage.entry_header_size)
        {
            enumerate_nbl_net_buffers(
                image,
                space,
                layouts,
                pool,
                allocation,
                nbl,
                options,
                packet_limit,
                result,
            );
        }
        if result.packets.len() == packet_limit {
            return;
        }
        previous = link;
        link = next;
    }
    if head_blink != previous {
        result.complete = false;
        push_warning(
            &mut result.warnings,
            format!("NBL pool {pool:#x} 分配链表头的反向指针不一致"),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn enumerate_nbl_net_buffers(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    layouts: NdisLayouts,
    pool: u64,
    allocation: u64,
    nbl: u64,
    options: &PacketScanOptions,
    packet_limit: usize,
    result: &mut NdisScanResult,
) {
    let Ok(mut net_buffer) = space.read_u64(nbl + layouts.nbl_first_net_buffer) else {
        return;
    };
    if net_buffer == 0 {
        return;
    }
    let source_handle = space
        .read_u64(nbl + layouts.nbl_source_handle)
        .unwrap_or_default();
    if source_handle != 0 && !is_kernel_pointer(source_handle) {
        return;
    }
    let mut visited = HashSet::new();
    for _ in 0..MAX_NDIS_CHAIN_NODES {
        if result.packets.len() == packet_limit
            || !is_kernel_pointer(net_buffer)
            || net_buffer % 8 != 0
            || !visited.insert(net_buffer)
        {
            return;
        }
        result.net_buffers_examined += 1;
        if let Some(packet) = recover_ndis_net_buffer(
            image,
            space,
            layouts,
            pool,
            allocation,
            nbl,
            net_buffer,
            options.max_packet_size,
            &mut result.rejections,
        ) {
            result.packet_occurrences += 1;
            if packet
                .ndis_evidence
                .as_ref()
                .is_some_and(|evidence| evidence.crosses_physical_pages)
            {
                result.cross_page_occurrences += 1;
            }
            result.packets.push(packet);
        }
        let Ok(next) = space.read_u64(net_buffer + layouts.nb_next) else {
            return;
        };
        if next == 0 {
            return;
        }
        net_buffer = next;
    }
    result.complete = false;
    push_warning(
        &mut result.warnings,
        format!("NBL {nbl:#x} 的 NET_BUFFER 链达到安全上限"),
    );
}

#[allow(clippy::too_many_arguments)]
fn recover_ndis_net_buffer(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    layouts: NdisLayouts,
    pool: u64,
    allocation: u64,
    nbl: u64,
    net_buffer: u64,
    max_packet_size: usize,
    rejections: &mut BTreeMap<String, usize>,
) -> Option<RawPacket> {
    let Some((current_mdl, current_mdl_offset, data_length, mdl_chain, data_offset)) = (|| {
        Some((
            space.read_u64(net_buffer + layouts.nb_current_mdl).ok()?,
            usize::try_from(
                read_virtual_u32(space, net_buffer + layouts.nb_current_mdl_offset).ok()?,
            )
            .ok()?,
            read_virtual_u32(space, net_buffer + layouts.nb_data_length).ok()?,
            space.read_u64(net_buffer + layouts.nb_mdl_chain).ok()?,
            usize::try_from(read_virtual_u32(space, net_buffer + layouts.nb_data_offset).ok()?)
                .ok()?,
        ))
    })() else {
        increment_ndis_rejection(rejections, "net_buffer_fields_unreadable");
        return None;
    };
    let Ok(data_length_usize) = usize::try_from(data_length) else {
        increment_ndis_rejection(rejections, "net_buffer_fields_invalid");
        return None;
    };
    if data_length_usize < 28 || data_length_usize > max_packet_size.saturating_add(64) {
        increment_ndis_rejection(rejections, "net_buffer_data_length_invalid");
        return None;
    }
    if !is_kernel_pointer(current_mdl) || !is_kernel_pointer(mdl_chain) {
        increment_ndis_rejection(rejections, "net_buffer_mdl_pointer_invalid");
        return None;
    }
    if !validate_net_buffer_position(
        space,
        layouts,
        mdl_chain,
        current_mdl,
        current_mdl_offset,
        data_offset,
    ) {
        increment_ndis_rejection(rejections, "net_buffer_data_position_invalid");
        return None;
    }
    let recovery = recover_mdl_bytes(
        image,
        space,
        layouts,
        current_mdl,
        current_mdl_offset,
        data_length_usize,
        rejections,
    )?;
    let Some((parsed, packet_length, frame_offset)) =
        parse_ndis_frame(&recovery.bytes, max_packet_size)
    else {
        increment_ndis_rejection(rejections, classify_unsupported_frame(&recovery.bytes));
        return None;
    };
    let Some(packet_bytes) = recovery
        .bytes
        .get(frame_offset..frame_offset + packet_length)
    else {
        increment_ndis_rejection(rejections, "network_packet_range_invalid");
        return None;
    };
    let bytes = packet_bytes.to_vec();
    let Some(physical_address) =
        physical_address_for_logical_offset(&recovery.physical_segments, frame_offset)
    else {
        increment_ndis_rejection(rejections, "packet_physical_address_unavailable");
        return None;
    };
    let file_offset = image.physical_to_file_offset(physical_address);
    let crosses_physical_pages = recovery.pfns.len() > 1 || recovery.mdl_addresses.len() > 1;
    Some(RawPacket {
        bytes,
        physical_address,
        file_offset,
        parsed,
        source: PacketSource::NdisStructure,
        ndis_evidence: Some(NdisPacketEvidence {
            pool,
            allocation,
            net_buffer_list: nbl,
            net_buffer,
            mdl_chain,
            current_mdl,
            data_length,
            frame_offset,
            mdl_addresses: recovery.mdl_addresses,
            page_frame_numbers: recovery.pfns,
            crosses_physical_pages,
        }),
    })
}

fn increment_ndis_rejection(rejections: &mut BTreeMap<String, usize>, reason: &str) {
    *rejections.entry(reason.to_owned()).or_default() += 1;
}

fn validate_net_buffer_position(
    space: &X64AddressSpace<'_>,
    layouts: NdisLayouts,
    mdl_chain: u64,
    current_mdl: u64,
    current_mdl_offset: usize,
    data_offset: usize,
) -> bool {
    let mut mdl = mdl_chain;
    let mut preceding_bytes = 0usize;
    let mut visited = HashSet::new();
    for _ in 0..MAX_MDL_CHAIN_NODES {
        if !is_kernel_pointer(mdl) || !visited.insert(mdl) {
            return false;
        }
        let Ok(byte_count) = read_virtual_u32(space, mdl + layouts.mdl_byte_count) else {
            return false;
        };
        if mdl == current_mdl {
            return current_mdl_offset <= byte_count as usize
                && preceding_bytes.checked_add(current_mdl_offset) == Some(data_offset);
        }
        preceding_bytes = match preceding_bytes.checked_add(byte_count as usize) {
            Some(value) if value <= 16 * 1024 * 1024 => value,
            _ => return false,
        };
        let Ok(next) = space.read_u64(mdl + layouts.mdl_next) else {
            return false;
        };
        if next == 0 {
            return false;
        }
        mdl = next;
    }
    false
}

fn recover_mdl_bytes(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    layouts: NdisLayouts,
    mut mdl: u64,
    mut skip: usize,
    wanted: usize,
    rejections: &mut BTreeMap<String, usize>,
) -> Option<MdlRecovery> {
    let mut bytes = Vec::with_capacity(wanted);
    let mut physical_segments = Vec::new();
    let mut mdl_addresses = Vec::new();
    let mut pfns = Vec::new();
    let mut visited = HashSet::new();
    for _ in 0..MAX_MDL_CHAIN_NODES {
        if bytes.len() == wanted {
            return Some(MdlRecovery {
                bytes,
                physical_segments,
                mdl_addresses,
                pfns,
            });
        }
        if !is_kernel_pointer(mdl) || !visited.insert(mdl) {
            increment_ndis_rejection(rejections, "mdl_pointer_invalid_or_cycle");
            return None;
        }
        let descriptor = read_mdl_descriptor(space, layouts, mdl, rejections)?;
        if skip > descriptor.byte_count {
            increment_ndis_rejection(rejections, "mdl_current_offset_out_of_range");
            return None;
        }
        mdl_addresses.push(mdl);
        let available = descriptor.byte_count - skip;
        let take = available.min(wanted - bytes.len());
        let mut mdl_data_offset = descriptor.byte_offset.checked_add(skip)?;
        let end = mdl_data_offset.checked_add(take)?;
        while mdl_data_offset < end {
            let page_index = mdl_data_offset / 0x1000;
            let page_offset = mdl_data_offset & 0xfff;
            let pfn = *descriptor.pfns.get(page_index)?;
            if !pfns.contains(&pfn) {
                pfns.push(pfn);
            }
            let physical = pfn.checked_mul(0x1000)?.checked_add(page_offset as u64)?;
            let chunk = (0x1000 - page_offset).min(end - mdl_data_offset);
            if !image.contains_physical(physical) {
                increment_ndis_rejection(rejections, "mdl_pfn_page_missing");
                return None;
            }
            let logical_start = bytes.len();
            let mut buffer = vec![0u8; chunk];
            if image.read_physical(physical, &mut buffer).is_err() {
                increment_ndis_rejection(rejections, "mdl_pfn_page_unreadable");
                return None;
            }
            bytes.extend_from_slice(&buffer);
            physical_segments.push((logical_start, physical, chunk));
            mdl_data_offset += chunk;
        }
        skip = 0;
        if bytes.len() == wanted {
            continue;
        }
        if descriptor.next == 0 {
            increment_ndis_rejection(rejections, "mdl_chain_shorter_than_data_length");
            return None;
        }
        mdl = descriptor.next;
    }
    None
}

fn read_mdl_descriptor(
    space: &X64AddressSpace<'_>,
    layouts: NdisLayouts,
    mdl: u64,
    rejections: &mut BTreeMap<String, usize>,
) -> Option<MdlDescriptor> {
    let header_size = usize::try_from(layouts.mdl_header_size).ok()?;
    if !(0x20..=0x100).contains(&header_size) {
        increment_ndis_rejection(rejections, "mdl_pdb_header_size_invalid");
        return None;
    }
    let mut header = vec![0u8; header_size];
    if space.read_virtual(mdl, &mut header).is_err() {
        increment_ndis_rejection(rejections, "mdl_header_unreadable");
        return None;
    }
    let next = read_le_u64(&header, usize::try_from(layouts.mdl_next).ok()?).ok()?;
    let declared_size =
        usize::from(read_le_u16(&header, usize::try_from(layouts.mdl_size_field).ok()?).ok()?);
    let start_va = read_le_u64(&header, usize::try_from(layouts.mdl_start_va).ok()?).ok()?;
    let byte_count =
        usize::try_from(read_le_u32(&header, usize::try_from(layouts.mdl_byte_count).ok()?).ok()?)
            .ok()?;
    let byte_offset =
        usize::try_from(read_le_u32(&header, usize::try_from(layouts.mdl_byte_offset).ok()?).ok()?)
            .ok()?;
    if byte_count == 0
        || byte_offset >= 0x1000
        || start_va == 0
        || start_va & 0xfff != 0
        || !is_canonical_pointer(start_va)
    {
        increment_ndis_rejection(rejections, "mdl_geometry_invalid");
        return None;
    }
    let page_count = byte_offset.checked_add(byte_count)?.div_ceil(0x1000);
    if page_count == 0 || page_count > MAX_MDL_PAGES {
        increment_ndis_rejection(rejections, "mdl_page_count_invalid");
        return None;
    }
    let expected_size = header_size.checked_add(page_count.checked_mul(8)?)?;
    if declared_size != expected_size {
        increment_ndis_rejection(rejections, "mdl_declared_size_mismatch");
        return None;
    }
    let mut pfn_bytes = vec![0u8; page_count * 8];
    if space
        .read_virtual(mdl + layouts.mdl_header_size, &mut pfn_bytes)
        .is_err()
    {
        increment_ndis_rejection(rejections, "mdl_pfn_array_unreadable");
        return None;
    }
    let mut pfns = Vec::with_capacity(page_count);
    for chunk in pfn_bytes.chunks_exact(8) {
        let pfn = u64::from_le_bytes(chunk.try_into().ok()?);
        if pfn == 0 || pfn > 0x000f_ffff_ffff {
            increment_ndis_rejection(rejections, "mdl_pfn_value_invalid");
            return None;
        }
        pfns.push(pfn);
    }
    Some(MdlDescriptor {
        next,
        byte_count,
        byte_offset,
        pfns,
    })
}

fn parse_ndis_frame(bytes: &[u8], max_packet_size: usize) -> Option<(ParsedPacket, usize, usize)> {
    let mut candidates = Vec::with_capacity(4);
    if bytes.first().is_some_and(|byte| matches!(byte >> 4, 4 | 6)) {
        candidates.push(0usize);
    }
    if let Some(ether_type) = read_be_u16(bytes, 12) {
        match ether_type {
            0x0800 | 0x86dd => candidates.push(14),
            0x8100 | 0x88a8 | 0x9100 => {
                if matches!(read_be_u16(bytes, 16), Some(0x0800 | 0x86dd)) {
                    candidates.push(18);
                } else if matches!(read_be_u16(bytes, 16), Some(0x8100 | 0x88a8 | 0x9100))
                    && matches!(read_be_u16(bytes, 20), Some(0x0800 | 0x86dd))
                {
                    candidates.push(22);
                }
            }
            _ => {}
        }
    }
    for offset in candidates {
        let payload = bytes.get(offset..)?;
        let parsed = match payload.first()? >> 4 {
            4 => parse_ipv4_packet_with_policy(payload, max_packet_size, true),
            6 => parse_ipv6_packet_with_policy(payload, max_packet_size, true),
            _ => None,
        };
        if let Some((parsed, length)) = parsed {
            return Some((parsed, length, offset));
        }
    }
    None
}

fn classify_unsupported_frame(bytes: &[u8]) -> &'static str {
    if bytes.first().is_some_and(|byte| matches!(byte >> 4, 4 | 6)) {
        return "network_raw_ip_header_invalid";
    }
    match read_be_u16(bytes, 12) {
        Some(0x0800 | 0x86dd) => "network_ethernet_ip_header_invalid",
        Some(0x8100 | 0x88a8 | 0x9100)
            if matches!(
                read_be_u16(bytes, 16),
                Some(0x0800 | 0x86dd | 0x8100 | 0x88a8 | 0x9100)
            ) =>
        {
            "network_vlan_ip_header_invalid"
        }
        _ => "network_non_ip_or_unsupported_link_type",
    }
}

fn physical_address_for_logical_offset(
    segments: &[(usize, u64, usize)],
    offset: usize,
) -> Option<u64> {
    segments.iter().find_map(|(logical, physical, length)| {
        (offset >= *logical && offset < logical.checked_add(*length)?)
            .then(|| physical + (offset - logical) as u64)
    })
}

fn read_list_entry(space: &X64AddressSpace<'_>, address: u64) -> Result<(u64, u64)> {
    let mut bytes = [0u8; 16];
    space.read_virtual(address, &mut bytes)?;
    Ok((read_le_u64(&bytes, 0)?, read_le_u64(&bytes, 8)?))
}

fn read_virtual_u32(space: &X64AddressSpace<'_>, address: u64) -> Result<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .context("读取 u16 时缓冲区被截断")?;
    Ok(u16::from_le_bytes(value.try_into().unwrap()))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .context("读取 u32 时缓冲区被截断")?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes
        .get(offset..offset + 8)
        .context("读取 u64 时缓冲区被截断")?;
    Ok(u64::from_le_bytes(value.try_into().unwrap()))
}

fn read_be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset + 2)?;
    Some(u16::from_be_bytes(value.try_into().ok()?))
}

fn is_kernel_pointer(value: u64) -> bool {
    value >= 0xffff_8000_0000_0000 && is_canonical_pointer(value)
}

fn is_canonical_pointer(value: u64) -> bool {
    let upper = value >> 48;
    upper == 0 || upper == 0xffff
}

fn validate_options(options: &PacketScanOptions) -> Result<()> {
    ensure!(options.limit > 0, "数据包结果数量上限必须大于零");
    ensure!(
        options.limit <= 1_000_000,
        "数据包结果数量上限不能超过 1000000"
    );
    ensure!(options.endpoint_limit > 0, "端点结果数量上限必须大于零");
    ensure!(
        (40..=65_575).contains(&options.max_packet_size),
        "最大数据包大小必须在 40..65575 字节范围内"
    );
    ensure!(
        options.max_occurrences > 0,
        "每个数据包保留的证据地址数量必须大于零"
    );
    ensure!(
        options.chunk_size >= options.max_packet_size,
        "扫描块必须大于或等于最大数据包大小"
    );
    Ok(())
}

fn scan_raw_packets(
    image: &MemoryImage,
    options: &PacketScanOptions,
    raw_limit: usize,
) -> Result<RawScanResult> {
    let chunks = packet_chunks(image, options.chunk_size, options.max_packet_size)?;
    let retained = AtomicUsize::new(0);
    let bytes_scanned = AtomicU64::new(0);
    let header_candidates = AtomicU64::new(0);
    let raw_truncated = AtomicBool::new(false);
    let direct = image.direct_bytes();
    let chunk_packets = chunks
        .par_iter()
        .map(|chunk| -> Result<Vec<RawPacket>> {
            let mut buffered = Vec::new();
            let bytes = if let (Some(direct), Some(file_start)) = (direct, chunk.file_start) {
                direct
                    .get(file_start..file_start + chunk.scan_len)
                    .context("数据包扫描块超出镜像映射")?
            } else {
                buffered.resize(chunk.scan_len, 0);
                image.read_physical(chunk.physical_start, &mut buffered)?;
                &buffered
            };
            bytes_scanned.fetch_add(chunk.core_len as u64, Ordering::Relaxed);
            let protocol_scan_end = (chunk.core_len + 40).min(bytes.len());
            let mut output = Vec::new();
            for protocol_offset in memchr::memchr2_iter(6, 17, &bytes[..protocol_scan_end]) {
                let candidate = if protocol_offset >= 9
                    && bytes[protocol_offset - 9] >> 4 == 4
                    && protocol_offset - 9 < chunk.core_len
                {
                    let start = protocol_offset - 9;
                    parse_ipv4_packet(&bytes[start..], options.max_packet_size)
                        .map(|(parsed, length)| (start, parsed, length))
                } else if protocol_offset >= 6
                    && bytes[protocol_offset - 6] >> 4 == 6
                    && protocol_offset - 6 < chunk.core_len
                {
                    let start = protocol_offset - 6;
                    parse_ipv6_packet(&bytes[start..], options.max_packet_size)
                        .map(|(parsed, length)| (start, parsed, length))
                } else {
                    None
                };
                let Some((start, parsed, length)) = candidate else {
                    continue;
                };
                header_candidates.fetch_add(1, Ordering::Relaxed);
                let slot = retained.fetch_add(1, Ordering::Relaxed);
                if slot >= raw_limit {
                    raw_truncated.store(true, Ordering::Relaxed);
                    continue;
                }
                output.push(RawPacket {
                    bytes: bytes[start..start + length].to_vec(),
                    physical_address: chunk.physical_start + start as u64,
                    file_offset: chunk
                        .file_start
                        .map(|file_start| file_start as u64 + start as u64),
                    parsed,
                    source: PacketSource::PhysicalCarving,
                    ndis_evidence: None,
                });
            }
            Ok(output)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut packets = chunk_packets.into_iter().flatten().collect::<Vec<_>>();
    packets.sort_unstable_by_key(|packet| packet.physical_address);
    Ok(RawScanResult {
        packets,
        bytes_scanned: bytes_scanned.load(Ordering::Relaxed),
        header_candidates: header_candidates.load(Ordering::Relaxed),
        raw_truncated: raw_truncated.load(Ordering::Relaxed),
    })
}

fn packet_chunks(
    image: &MemoryImage,
    chunk_size: usize,
    max_packet_size: usize,
) -> Result<Vec<PacketChunk>> {
    let mut chunks = Vec::new();
    for span in image.spans() {
        let mut consumed = 0u64;
        while consumed < span.length {
            let core_len = usize::try_from((span.length - consumed).min(chunk_size as u64))?;
            let remaining = usize::try_from(span.length - consumed - core_len as u64)?;
            let overlap = max_packet_size.saturating_sub(1).min(remaining);
            chunks.push(PacketChunk {
                physical_start: span.start + consumed,
                file_start: matches!(span.encoding, crate::image::MappingEncoding::Direct)
                    .then(|| usize::try_from(span.file_offset + consumed))
                    .transpose()?,
                core_len,
                scan_len: core_len + overlap,
            });
            consumed += core_len as u64;
        }
    }
    Ok(chunks)
}

fn parse_ipv4_packet(bytes: &[u8], max_packet_size: usize) -> Option<(ParsedPacket, usize)> {
    parse_ipv4_packet_with_policy(bytes, max_packet_size, false)
}

fn parse_ipv4_packet_with_policy(
    bytes: &[u8],
    max_packet_size: usize,
    allow_incomplete_checksum: bool,
) -> Option<(ParsedPacket, usize)> {
    if bytes.len() < 28 || bytes[0] >> 4 != 4 {
        return None;
    }
    let header_length = usize::from(bytes[0] & 0x0f) * 4;
    if !(20..=60).contains(&header_length) || bytes.len() < header_length {
        return None;
    }
    let total_length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total_length < header_length + 8
        || total_length > max_packet_size
        || total_length > bytes.len()
        || bytes[8] == 0
    {
        return None;
    }
    let fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }
    let ip_checksum =
        checksum_state_with_policy(&bytes[..header_length], 10, allow_incomplete_checksum)?;
    let transport_protocol = match bytes[9] {
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        _ => return None,
    };
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    if source.is_unspecified() && destination.is_unspecified() {
        return None;
    }
    let segment = &bytes[header_length..total_length];
    let pseudo = [
        &bytes[12..16],
        &bytes[16..20],
        &[0, bytes[9]],
        &(segment.len() as u16).to_be_bytes(),
    ];
    parse_transport(
        segment,
        transport_protocol,
        InternetProtocol::Ipv4,
        IpAddr::V4(source),
        IpAddr::V4(destination),
        header_length,
        &pseudo,
        allow_incomplete_checksum,
    )
    .map(|mut parsed| {
        parsed.ip_checksum = ip_checksum;
        (parsed, total_length)
    })
}

fn parse_ipv6_packet(bytes: &[u8], max_packet_size: usize) -> Option<(ParsedPacket, usize)> {
    parse_ipv6_packet_with_policy(bytes, max_packet_size, false)
}

fn parse_ipv6_packet_with_policy(
    bytes: &[u8],
    max_packet_size: usize,
    allow_incomplete_checksum: bool,
) -> Option<(ParsedPacket, usize)> {
    if bytes.len() < 48 || bytes[0] >> 4 != 6 || bytes[7] == 0 {
        return None;
    }
    let payload_length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    let total_length = 40usize.checked_add(payload_length)?;
    if payload_length < 8 || total_length > max_packet_size || total_length > bytes.len() {
        return None;
    }
    let transport_protocol = match bytes[6] {
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        _ => return None,
    };
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?);
    if source.is_unspecified() && destination.is_unspecified() {
        return None;
    }
    let segment = &bytes[40..total_length];
    let payload_length_bytes = (segment.len() as u32).to_be_bytes();
    let next_header = [0, 0, 0, bytes[6]];
    let pseudo = [
        &bytes[8..24],
        &bytes[24..40],
        payload_length_bytes.as_slice(),
        next_header.as_slice(),
    ];
    parse_transport(
        segment,
        transport_protocol,
        InternetProtocol::Ipv6,
        IpAddr::V6(source),
        IpAddr::V6(destination),
        40,
        &pseudo,
        allow_incomplete_checksum,
    )
    .map(|parsed| (parsed, total_length))
}

#[allow(clippy::too_many_arguments)]
fn parse_transport(
    segment: &[u8],
    transport_protocol: TransportProtocol,
    internet_protocol: InternetProtocol,
    source_address: IpAddr,
    destination_address: IpAddr,
    ip_header_length: usize,
    pseudo_header: &[&[u8]],
    allow_incomplete_checksum: bool,
) -> Option<ParsedPacket> {
    let (source_port, destination_port) = (
        u16::from_be_bytes([*segment.first()?, *segment.get(1)?]),
        u16::from_be_bytes([*segment.get(2)?, *segment.get(3)?]),
    );
    if source_port == 0 || destination_port == 0 {
        return None;
    }
    match transport_protocol {
        TransportProtocol::Tcp => {
            if segment.len() < 20 {
                return None;
            }
            let header_length = usize::from(segment[12] >> 4) * 4;
            if !(20..=60).contains(&header_length)
                || header_length > segment.len()
                || segment[12] & 0x0e != 0
                || !valid_tcp_control_fields(segment)
                || !valid_tcp_options(&segment[20..header_length])
            {
                return None;
            }
            let transport_checksum =
                transport_checksum_state(segment, 16, pseudo_header, allow_incomplete_checksum)?;
            Some(ParsedPacket {
                internet_protocol,
                transport_protocol,
                source_address,
                source_port,
                destination_address,
                destination_port,
                payload_offset: ip_header_length + header_length,
                tcp_sequence: Some(u32::from_be_bytes(segment[4..8].try_into().ok()?)),
                tcp_acknowledgment: Some(u32::from_be_bytes(segment[8..12].try_into().ok()?)),
                tcp_flags: Some(format_tcp_flags(segment[12] & 1, segment[13])),
                ip_checksum: ChecksumState::NotApplicable,
                transport_checksum,
            })
        }
        TransportProtocol::Udp => {
            if segment.len() < 8 {
                return None;
            }
            let udp_length = usize::from(u16::from_be_bytes([segment[4], segment[5]]));
            if udp_length < 8 || udp_length != segment.len() {
                return None;
            }
            let transport_checksum =
                transport_checksum_state(segment, 6, pseudo_header, allow_incomplete_checksum)?;
            Some(ParsedPacket {
                internet_protocol,
                transport_protocol,
                source_address,
                source_port,
                destination_address,
                destination_port,
                payload_offset: ip_header_length + 8,
                tcp_sequence: None,
                tcp_acknowledgment: None,
                tcp_flags: None,
                ip_checksum: ChecksumState::NotApplicable,
                transport_checksum,
            })
        }
    }
}

fn valid_tcp_control_fields(segment: &[u8]) -> bool {
    let flags = segment[13];
    let syn = flags & 0x02 != 0;
    let rst = flags & 0x04 != 0;
    let fin = flags & 0x01 != 0;
    if flags == 0 || (syn && fin) || (syn && rst) || (fin && rst) {
        return false;
    }
    let acknowledgment = u32::from_be_bytes(segment[8..12].try_into().unwrap());
    flags & 0x10 != 0 || acknowledgment == 0
}

fn valid_tcp_options(options: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < options.len() {
        match options[offset] {
            0 => {
                return options[offset + 1..]
                    .iter()
                    .all(|byte| matches!(byte, 0 | 1));
            }
            1 => offset += 1,
            _ => {
                let Some(&length) = options.get(offset + 1) else {
                    return false;
                };
                let length = usize::from(length);
                if length < 2 || offset + length > options.len() {
                    return false;
                }
                offset += length;
            }
        }
    }
    true
}

fn checksum_state_with_policy(
    bytes: &[u8],
    checksum_offset: usize,
    allow_incomplete: bool,
) -> Option<ChecksumState> {
    let field = u16::from_be_bytes([
        *bytes.get(checksum_offset)?,
        *bytes.get(checksum_offset + 1)?,
    ]);
    if field == 0 {
        Some(ChecksumState::ZeroOffload)
    } else if checksum_valid(&[bytes]) {
        Some(ChecksumState::Valid)
    } else if allow_incomplete {
        Some(ChecksumState::InvalidOffload)
    } else {
        None
    }
}

fn transport_checksum_state(
    segment: &[u8],
    checksum_offset: usize,
    pseudo_header: &[&[u8]],
    allow_incomplete: bool,
) -> Option<ChecksumState> {
    let field = u16::from_be_bytes([
        *segment.get(checksum_offset)?,
        *segment.get(checksum_offset + 1)?,
    ]);
    if field == 0 {
        return Some(ChecksumState::ZeroOffload);
    }
    let mut parts = pseudo_header.to_vec();
    parts.push(segment);
    if checksum_valid(&parts) {
        Some(ChecksumState::Valid)
    } else if allow_incomplete {
        Some(ChecksumState::InvalidOffload)
    } else {
        None
    }
}

fn checksum_valid(parts: &[&[u8]]) -> bool {
    let mut sum = 0u64;
    let mut pending = None;
    for part in parts {
        for byte in *part {
            if let Some(high) = pending.take() {
                sum += u64::from(u16::from_be_bytes([high, *byte]));
            } else {
                pending = Some(*byte);
            }
        }
    }
    if let Some(high) = pending {
        sum += u64::from(u16::from_be_bytes([high, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}

fn format_tcp_flags(ns: u8, flags: u8) -> String {
    let mut names = Vec::new();
    if ns != 0 {
        names.push("NS");
    }
    for (mask, name) in [
        (0x80, "CWR"),
        (0x40, "ECE"),
        (0x20, "URG"),
        (0x10, "ACK"),
        (0x08, "PSH"),
        (0x04, "RST"),
        (0x02, "SYN"),
        (0x01, "FIN"),
    ] {
        if flags & mask != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        "NONE".to_owned()
    } else {
        names.join("|")
    }
}

fn merge_raw_packets(
    raw_packets: Vec<RawPacket>,
    limit: usize,
    max_occurrences: usize,
) -> (Vec<PacketRecord>, Vec<Vec<u8>>, bool) {
    let mut records = Vec::<PacketRecord>::new();
    let mut packets = Vec::<Vec<u8>>::new();
    let mut occurrence_addresses = Vec::<HashSet<u64>>::new();
    let mut by_hash = HashMap::<[u8; 32], Vec<usize>>::new();
    let mut truncated = false;
    for packet in raw_packets {
        let digest: [u8; 32] = Sha256::digest(&packet.bytes).into();
        let existing = by_hash.get(&digest).and_then(|indices| {
            indices
                .iter()
                .copied()
                .find(|index| packets[*index] == packet.bytes)
        });
        if let Some(index) = existing {
            let record = &mut records[index];
            let new_physical_occurrence =
                occurrence_addresses[index].insert(packet.physical_address);
            if new_physical_occurrence {
                record.occurrences += 1;
            }
            let source = packet_source_name(packet.source);
            if !record
                .recovery_sources
                .iter()
                .any(|existing| existing == source)
            {
                record.recovery_sources.push(source.to_owned());
                record.source = record.recovery_sources.join("+");
            }
            if let Some(evidence) = packet.ndis_evidence
                && record.ndis_evidence.len() < max_occurrences.min(MAX_EVIDENCE_ADDRESSES)
            {
                record.ndis_evidence.push(evidence);
            }
            if new_physical_occurrence
                && record.physical_addresses.len() < max_occurrences.min(MAX_EVIDENCE_ADDRESSES)
            {
                record.physical_addresses.push(packet.physical_address);
                if let Some(file_offset) = packet.file_offset {
                    record.file_offsets.push(file_offset);
                }
            }
            continue;
        }
        if records.len() == limit {
            truncated = true;
            continue;
        }
        let payload = packet
            .bytes
            .get(packet.parsed.payload_offset..)
            .unwrap_or_default();
        let confidence = if packet.parsed.ip_checksum != ChecksumState::ZeroOffload
            && packet.parsed.transport_checksum == ChecksumState::Valid
        {
            "high"
        } else {
            "medium"
        };
        let index = records.len();
        let source = packet_source_name(packet.source).to_owned();
        let ndis_evidence = packet.ndis_evidence.into_iter().collect();
        records.push(PacketRecord {
            index: index + 1,
            source: source.clone(),
            internet_protocol: packet.parsed.internet_protocol,
            transport_protocol: packet.parsed.transport_protocol,
            source_address: packet.parsed.source_address.to_string(),
            source_port: packet.parsed.source_port,
            destination_address: packet.parsed.destination_address.to_string(),
            destination_port: packet.parsed.destination_port,
            packet_length: packet.bytes.len(),
            payload_length: payload.len(),
            tcp_sequence: packet.parsed.tcp_sequence,
            tcp_acknowledgment: packet.parsed.tcp_acknowledgment,
            tcp_flags: packet.parsed.tcp_flags,
            ip_checksum: checksum_state_name(packet.parsed.ip_checksum).to_owned(),
            transport_checksum: checksum_state_name(packet.parsed.transport_checksum).to_owned(),
            confidence: confidence.to_owned(),
            sha256: hex::encode(digest),
            payload_preview_hex: hex::encode(&payload[..payload.len().min(64)]),
            occurrences: 1,
            physical_addresses: vec![packet.physical_address],
            file_offsets: packet.file_offset.into_iter().collect(),
            recovery_sources: vec![source],
            ndis_evidence,
            owners: Vec::new(),
            timestamp: None,
            timestamp_basis: "内存中没有可靠逐包时间戳".to_owned(),
        });
        packets.push(packet.bytes);
        occurrence_addresses.push(HashSet::from([packet.physical_address]));
        by_hash.entry(digest).or_default().push(index);
    }
    (records, packets, truncated)
}

fn packet_source_name(source: PacketSource) -> &'static str {
    match source {
        PacketSource::PhysicalCarving => "validated_raw_ip_bytes",
        PacketSource::NdisStructure => "ndis_nbl_nb_mdl_pfn",
    }
}

fn checksum_state_name(state: ChecksumState) -> &'static str {
    match state {
        ChecksumState::Valid => "valid",
        ChecksumState::ZeroOffload => "zero_or_offloaded",
        ChecksumState::InvalidOffload => "invalid_or_offloaded",
        ChecksumState::NotApplicable => "not_applicable",
    }
}

fn retain_proven_packets(
    records: Vec<PacketRecord>,
    packets: Vec<Vec<u8>>,
) -> (Vec<PacketRecord>, Vec<Vec<u8>>, usize, usize) {
    debug_assert_eq!(records.len(), packets.len());
    let mut retained_records = Vec::with_capacity(records.len());
    let mut retained_packets = Vec::with_capacity(packets.len());
    let mut rejected_candidates = 0usize;
    let mut rejected_occurrences = 0usize;
    for (record, packet) in records.into_iter().zip(packets) {
        let checksums_proven = record.transport_checksum == "valid"
            && matches!(record.ip_checksum.as_str(), "valid" | "not_applicable");
        let ipv4_udp_without_checksum = record.internet_protocol == InternetProtocol::Ipv4
            && record.transport_protocol == TransportProtocol::Udp
            && record.ip_checksum == "valid"
            && record.transport_checksum == "zero_or_offloaded";
        let exact_endpoint_proves_offload = record
            .owners
            .iter()
            .any(|owner| owner.match_basis == "exact_five_tuple" && owner.confidence == "high");
        let ndis_structure_proves_offload = !record.ndis_evidence.is_empty();
        if checksums_proven
            || ipv4_udp_without_checksum
            || exact_endpoint_proves_offload
            || ndis_structure_proves_offload
        {
            retained_records.push(record);
            retained_packets.push(packet);
        } else {
            rejected_candidates += 1;
            rejected_occurrences += record.occurrences;
        }
    }
    for (index, record) in retained_records.iter_mut().enumerate() {
        record.index = index + 1;
    }
    (
        retained_records,
        retained_packets,
        rejected_candidates,
        rejected_occurrences,
    )
}

fn correlate_packet_owners(records: &mut [PacketRecord], endpoints: &[NetstatRecord]) -> usize {
    let mut total = 0usize;
    for packet in records {
        let Ok(source) = packet.source_address.parse::<IpAddr>() else {
            continue;
        };
        let Ok(destination) = packet.destination_address.parse::<IpAddr>() else {
            continue;
        };
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            if endpoint.pid == 0 || !protocol_matches(packet.transport_protocol, &endpoint.protocol)
            {
                continue;
            }
            let Some((direction, basis, confidence)) = endpoint_packet_match(
                endpoint,
                source,
                packet.source_port,
                destination,
                packet.destination_port,
                packet.transport_protocol,
            ) else {
                continue;
            };
            if !seen.insert((endpoint.pid, direction)) {
                continue;
            }
            packet.owners.push(PacketOwner {
                pid: endpoint.pid,
                process: endpoint.process.clone(),
                direction: direction.to_owned(),
                match_basis: basis.to_owned(),
                confidence: confidence.to_owned(),
                endpoint_address: endpoint.virtual_address,
            });
            total += 1;
            if packet.owners.len() == MAX_PACKET_OWNERS {
                break;
            }
        }
    }
    total
}

fn protocol_matches(protocol: TransportProtocol, endpoint: &str) -> bool {
    match protocol {
        TransportProtocol::Tcp => endpoint.to_ascii_lowercase().starts_with("tcp"),
        TransportProtocol::Udp => endpoint.to_ascii_lowercase().starts_with("udp"),
    }
}

fn endpoint_packet_match(
    endpoint: &NetstatRecord,
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
    transport: TransportProtocol,
) -> Option<(&'static str, &'static str, &'static str)> {
    let local = endpoint.local_address.parse::<IpAddr>().ok()?;
    let remote = endpoint.remote_address.parse::<IpAddr>().ok()?;
    let local_matches_source = address_matches(local, source) && endpoint.local_port == source_port;
    let local_matches_destination =
        address_matches(local, destination) && endpoint.local_port == destination_port;
    let remote_out =
        endpoint.remote_port == Some(destination_port) && address_matches(remote, destination);
    let remote_in = endpoint.remote_port == Some(source_port) && address_matches(remote, source);
    if local_matches_source && remote_out {
        let exact = !local.is_unspecified() && !remote.is_unspecified();
        return Some((
            "outbound",
            if exact {
                "exact_five_tuple"
            } else {
                "wildcard_endpoint"
            },
            if exact { "high" } else { "medium" },
        ));
    }
    if local_matches_destination && remote_in {
        let exact = !local.is_unspecified() && !remote.is_unspecified();
        return Some((
            "inbound",
            if exact {
                "exact_five_tuple"
            } else {
                "wildcard_endpoint"
            },
            if exact { "high" } else { "medium" },
        ));
    }
    let wildcard_remote = remote.is_unspecified() || endpoint.remote_port.is_none();
    if wildcard_remote
        && (transport == TransportProtocol::Udp
            || endpoint
                .state
                .as_deref()
                .is_some_and(|state| state.eq_ignore_ascii_case("LISTENING")))
    {
        if local_matches_source {
            return Some(("outbound", "local_port_wildcard", "medium"));
        }
        if local_matches_destination {
            return Some(("inbound", "local_port_wildcard", "medium"));
        }
    }
    None
}

fn address_matches(endpoint: IpAddr, packet: IpAddr) -> bool {
    endpoint.is_unspecified() || endpoint == packet
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    bytes: u64,
}

impl<W> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }
}

impl<W: Write> HashingWriter<W> {
    fn finish(mut self) -> Result<(W, u64, String)> {
        self.inner.flush()?;
        Ok((self.inner, self.bytes, hex::encode(self.hasher.finalize())))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn write_pcapng<W: Write>(
    output: &mut W,
    packets: &[Vec<u8>],
    records: &[PacketRecord],
) -> Result<()> {
    let mut section = Vec::new();
    section.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
    section.extend_from_slice(&1u16.to_le_bytes());
    section.extend_from_slice(&0u16.to_le_bytes());
    section.extend_from_slice(&(-1i64).to_le_bytes());
    append_option(
        &mut section,
        1,
        "StarMem 内存包恢复；逐包时间戳不可用，所有时间戳字段为零".as_bytes(),
    )?;
    finish_options(&mut section);
    write_pcapng_block(output, 0x0a0d_0d0a, &section)?;

    let snaplen = packets
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or(65_535)
        .min(u32::MAX as usize) as u32;
    let mut interface = Vec::new();
    interface.extend_from_slice(&LINKTYPE_RAW.to_le_bytes());
    interface.extend_from_slice(&0u16.to_le_bytes());
    interface.extend_from_slice(&snaplen.to_le_bytes());
    append_option(&mut interface, 2, b"StarMem RAW IP")?;
    append_option(
        &mut interface,
        3,
        b"Validated IPv4/IPv6 bytes recovered from physical memory",
    )?;
    append_option(&mut interface, 9, &[6])?;
    finish_options(&mut interface);
    write_pcapng_block(output, 1, &interface)?;

    for (packet, record) in packets.iter().zip(records) {
        let captured = u32::try_from(packet.len()).context("数据包长度超过 PCAPNG 限制")?;
        let mut body = Vec::with_capacity(packet.len() + 256);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&captured.to_le_bytes());
        body.extend_from_slice(&captured.to_le_bytes());
        body.extend_from_slice(packet);
        pad32(&mut body);
        let owners = record
            .owners
            .iter()
            .map(|owner| format!("{}({})/{}", owner.process, owner.pid, owner.direction))
            .collect::<Vec<_>>()
            .join(",");
        let comment = format!(
            "StarMem; timestamp=unavailable; PA={}; occurrences={}; SHA256={}; owners={}",
            record
                .physical_addresses
                .first()
                .map(|address| format!("{address:#x}"))
                .unwrap_or_else(|| "unknown".to_owned()),
            record.occurrences,
            record.sha256,
            if owners.is_empty() {
                "unproven"
            } else {
                &owners
            },
        );
        append_option(&mut body, 1, comment.as_bytes())?;
        finish_options(&mut body);
        write_pcapng_block(output, 6, &body)?;
    }
    Ok(())
}

fn write_pcapng_block<W: Write>(output: &mut W, block_type: u32, body: &[u8]) -> Result<()> {
    ensure!(body.len().is_multiple_of(4), "PCAPNG 块体没有按四字节对齐");
    let total = u32::try_from(body.len() + 12).context("PCAPNG 块长度溢出")?;
    output.write_all(&block_type.to_le_bytes())?;
    output.write_all(&total.to_le_bytes())?;
    output.write_all(body)?;
    output.write_all(&total.to_le_bytes())?;
    Ok(())
}

fn append_option(body: &mut Vec<u8>, code: u16, value: &[u8]) -> Result<()> {
    let length = u16::try_from(value.len()).context("PCAPNG 选项过长")?;
    body.extend_from_slice(&code.to_le_bytes());
    body.extend_from_slice(&length.to_le_bytes());
    body.extend_from_slice(value);
    pad32(body);
    Ok(())
}

fn finish_options(body: &mut Vec<u8>) {
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
}

fn pad32(bytes: &mut Vec<u8>) {
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNINGS && !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn checksum(bytes: &mut [u8], offset: usize, pseudo: &[&[u8]]) {
        bytes[offset] = 0;
        bytes[offset + 1] = 0;
        let mut parts = pseudo.to_vec();
        parts.push(bytes);
        let mut sum = 0u64;
        let mut pending = None;
        for part in parts {
            for byte in part {
                if let Some(high) = pending.take() {
                    sum += u64::from(u16::from_be_bytes([high, *byte]));
                } else {
                    pending = Some(*byte);
                }
            }
        }
        if let Some(high) = pending {
            sum += u64::from(u16::from_be_bytes([high, 0]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let value = !(sum as u16);
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn ipv4_tcp_packet(payload: &[u8]) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 168, 1, 10]);
        packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
        packet[20..22].copy_from_slice(&49_152u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..28].copy_from_slice(&1u32.to_be_bytes());
        packet[28..32].copy_from_slice(&2u32.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x18;
        packet[34..36].copy_from_slice(&65_535u16.to_be_bytes());
        packet[40..].copy_from_slice(payload);
        let segment_length = packet.len() - 20;
        let pseudo = [
            packet[12..16].to_vec(),
            packet[16..20].to_vec(),
            vec![0, 6],
            (segment_length as u16).to_be_bytes().to_vec(),
        ];
        let pseudo_refs = pseudo.iter().map(Vec::as_slice).collect::<Vec<_>>();
        checksum(&mut packet[20..], 16, &pseudo_refs);
        checksum(&mut packet[..20], 10, &[]);
        packet
    }

    #[test]
    fn reconstructs_mdl_data_across_two_physical_pages() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-packet-mdl-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut image_bytes = vec![0u8; 0x8000];
        put_test_u64(&mut image_bytes, 0x1000 + 256 * 8, 0x2003);
        put_test_u64(&mut image_bytes, 0x2000, 0x3003);
        put_test_u64(&mut image_bytes, 0x3000, 0x4003);
        put_test_u64(&mut image_bytes, 0x4000, 0x5003);
        image_bytes[0x5008..0x500a].copy_from_slice(&64u16.to_le_bytes());
        put_test_u64(&mut image_bytes, 0x5020, 0xffff_9000_0000_0000);
        image_bytes[0x5028..0x502c].copy_from_slice(&32u32.to_le_bytes());
        image_bytes[0x502c..0x5030].copy_from_slice(&0xff0u32.to_le_bytes());
        put_test_u64(&mut image_bytes, 0x5030, 6);
        put_test_u64(&mut image_bytes, 0x5038, 7);
        image_bytes[0x6ff0..0x7000].copy_from_slice(b"0123456789abcdef");
        image_bytes[0x7000..0x7010].copy_from_slice(b"FEDCBA9876543210");
        fs::write(&path, image_bytes).unwrap();

        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 0x1000).unwrap();
        let layouts = NdisLayouts {
            nbl_first_net_buffer: 0,
            nbl_source_handle: 0,
            nbl_size: 0,
            nb_next: 0,
            nb_current_mdl: 0,
            nb_current_mdl_offset: 0,
            nb_data_length: 0,
            nb_mdl_chain: 0,
            nb_data_offset: 0,
            mdl_next: 0,
            mdl_size_field: 8,
            mdl_start_va: 32,
            mdl_byte_count: 40,
            mdl_byte_offset: 44,
            mdl_header_size: 48,
        };
        let mut rejections = BTreeMap::new();
        let recovered = recover_mdl_bytes(
            &image,
            &space,
            layouts,
            0xffff_8000_0000_0000,
            0,
            32,
            &mut rejections,
        )
        .unwrap();
        assert_eq!(recovered.bytes, b"0123456789abcdefFEDCBA9876543210");
        assert_eq!(recovered.pfns, [6, 7]);
        assert_eq!(recovered.physical_segments.len(), 2);
        assert!(rejections.is_empty());
        drop(image);
        fs::remove_file(path).unwrap();
    }

    fn put_test_u64(output: &mut [u8], offset: usize, value: u64) {
        output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parses_valid_ipv4_tcp_and_rejects_corruption() {
        let packet = ipv4_tcp_packet(b"GET / HTTP/1.1\r\n\r\n");
        let (parsed, length) = parse_ipv4_packet(&packet, 65_535).unwrap();
        assert_eq!(length, packet.len());
        assert_eq!(parsed.transport_protocol, TransportProtocol::Tcp);
        assert_eq!(parsed.source_port, 49_152);
        assert_eq!(parsed.destination_port, 443);
        assert_eq!(parsed.transport_checksum, ChecksumState::Valid);
        let mut corrupted = packet;
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(parse_ipv4_packet(&corrupted, 65_535).is_none());
        let (offloaded, _) = parse_ipv4_packet_with_policy(&corrupted, 65_535, true).unwrap();
        assert_eq!(offloaded.transport_checksum, ChecksumState::InvalidOffload);
    }

    #[test]
    fn parses_ethernet_and_vlan_ndis_frames_without_fabricating_headers() {
        let packet = ipv4_tcp_packet(b"hello");
        let mut ethernet = vec![0u8; 14];
        ethernet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        ethernet.extend_from_slice(&packet);
        let (_, length, offset) = parse_ndis_frame(&ethernet, 65_535).unwrap();
        assert_eq!((length, offset), (packet.len(), 14));

        let mut vlan = vec![0u8; 18];
        vlan[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        vlan[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        vlan.extend_from_slice(&packet);
        let (_, length, offset) = parse_ndis_frame(&vlan, 65_535).unwrap();
        assert_eq!((length, offset), (packet.len(), 18));
    }

    #[test]
    fn merges_identical_packet_occurrences() {
        let bytes = ipv4_tcp_packet(b"hello");
        let (parsed, _) = parse_ipv4_packet(&bytes, 65_535).unwrap();
        let packets = vec![
            RawPacket {
                bytes: bytes.clone(),
                physical_address: 0x1000,
                file_offset: Some(0x1000),
                parsed: parsed.clone(),
                source: PacketSource::PhysicalCarving,
                ndis_evidence: None,
            },
            RawPacket {
                bytes: bytes.clone(),
                physical_address: 0x2000,
                file_offset: Some(0x2000),
                parsed,
                source: PacketSource::PhysicalCarving,
                ndis_evidence: None,
            },
        ];
        let (records, stored, truncated) = merge_raw_packets(packets, 10, 8);
        assert!(!truncated);
        assert_eq!(records.len(), 1);
        assert_eq!(stored.len(), 1);
        assert_eq!(records[0].occurrences, 2);
        assert_eq!(records[0].physical_addresses, [0x1000, 0x2000]);
    }

    #[test]
    fn keeps_zero_checksums_only_with_exact_endpoint_evidence() {
        let bytes = ipv4_tcp_packet(b"hello");
        let (parsed, _) = parse_ipv4_packet(&bytes, 65_535).unwrap();
        let (mut records, packets, _) = merge_raw_packets(
            vec![RawPacket {
                bytes,
                physical_address: 0x1000,
                file_offset: Some(0x1000),
                parsed,
                source: PacketSource::PhysicalCarving,
                ndis_evidence: None,
            }],
            10,
            8,
        );
        records[0].ip_checksum = "zero_or_offloaded".to_owned();
        records[0].transport_checksum = "zero_or_offloaded".to_owned();
        let (rejected, _, rejected_candidates, rejected_occurrences) =
            retain_proven_packets(records.clone(), packets.clone());
        assert!(rejected.is_empty());
        assert_eq!(rejected_candidates, 1);
        assert_eq!(rejected_occurrences, 1);

        records[0].owners.push(PacketOwner {
            pid: 42,
            process: "browser.exe".to_owned(),
            direction: "outbound".to_owned(),
            match_basis: "exact_five_tuple".to_owned(),
            confidence: "high".to_owned(),
            endpoint_address: 0xffff_8000_0000_1000,
        });
        let (retained, retained_bytes, rejected_candidates, _) =
            retain_proven_packets(records, packets);
        assert_eq!(retained.len(), 1);
        assert_eq!(retained_bytes.len(), 1);
        assert_eq!(rejected_candidates, 0);
    }

    #[test]
    fn rejects_zero_ports_and_impossible_tcp_flags() {
        let mut zero_port = ipv4_tcp_packet(b"hello");
        zero_port[20..22].copy_from_slice(&0u16.to_be_bytes());
        let pseudo = [
            zero_port[12..16].to_vec(),
            zero_port[16..20].to_vec(),
            vec![0, 6],
            ((zero_port.len() - 20) as u16).to_be_bytes().to_vec(),
        ];
        let pseudo_refs = pseudo.iter().map(Vec::as_slice).collect::<Vec<_>>();
        checksum(&mut zero_port[20..], 16, &pseudo_refs);
        assert!(parse_ipv4_packet(&zero_port, 65_535).is_none());

        let mut syn_fin = ipv4_tcp_packet(b"hello");
        syn_fin[33] = 0x03;
        let pseudo = [
            syn_fin[12..16].to_vec(),
            syn_fin[16..20].to_vec(),
            vec![0, 6],
            ((syn_fin.len() - 20) as u16).to_be_bytes().to_vec(),
        ];
        let pseudo_refs = pseudo.iter().map(Vec::as_slice).collect::<Vec<_>>();
        checksum(&mut syn_fin[20..], 16, &pseudo_refs);
        assert!(parse_ipv4_packet(&syn_fin, 65_535).is_none());

        let mut malformed_options = ipv4_tcp_packet(b"hello");
        malformed_options[32] = 0x60;
        malformed_options.splice(40..40, [101, 46, 0, 0]);
        let total = malformed_options.len();
        malformed_options[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        let pseudo = [
            malformed_options[12..16].to_vec(),
            malformed_options[16..20].to_vec(),
            vec![0, 6],
            ((malformed_options.len() - 20) as u16)
                .to_be_bytes()
                .to_vec(),
        ];
        let pseudo_refs = pseudo.iter().map(Vec::as_slice).collect::<Vec<_>>();
        checksum(&mut malformed_options[20..], 16, &pseudo_refs);
        checksum(&mut malformed_options[..20], 10, &[]);
        assert!(parse_ipv4_packet(&malformed_options, 65_535).is_none());
    }

    #[test]
    fn writes_openable_pcapng_block_lengths() {
        let bytes = ipv4_tcp_packet(b"hello");
        let (parsed, _) = parse_ipv4_packet(&bytes, 65_535).unwrap();
        let (records, packets, _) = merge_raw_packets(
            vec![RawPacket {
                bytes,
                physical_address: 0x1234,
                file_offset: Some(0x1234),
                parsed,
                source: PacketSource::PhysicalCarving,
                ndis_evidence: None,
            }],
            10,
            8,
        );
        let mut output = Vec::new();
        write_pcapng(&mut output, &packets, &records).unwrap();
        assert_eq!(&output[..4], &0x0a0d_0d0au32.to_le_bytes());
        let mut offset = 0usize;
        let mut blocks = 0usize;
        while offset < output.len() {
            let length =
                u32::from_le_bytes(output[offset + 4..offset + 8].try_into().unwrap()) as usize;
            assert!(length >= 12 && length.is_multiple_of(4));
            assert_eq!(
                &output[offset + length - 4..offset + length],
                &(length as u32).to_le_bytes()
            );
            offset += length;
            blocks += 1;
        }
        assert_eq!(offset, output.len());
        assert_eq!(blocks, 3);
    }
}
