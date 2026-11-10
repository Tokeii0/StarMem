//! Cobalt Strike Beacon configuration recovery from Windows process VADs.
//!
//! The detection format is based on Kevin Breen's MIT-licensed Volatility
//! plugin in Immersive Labs' `volatility_plugins` repository.  This is a
//! native, bounded-memory implementation with strict TLV validation,
//! cancellation, evidence addresses and duplicate suppression.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;

use anyhow::{Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::address::{VirtualAddressRegion, VirtualMapping, X64AddressSpace};
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::windows::plugins::{VadRecord, list_vads};
use crate::windows::{ProcessRecord, WindowsKernelContext, list_processes};

const PAGE_SIZE: u64 = 0x1000;
const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
const CONFIG_WINDOW_SIZE: usize = 4096;
const CONFIG_OVERLAP: usize = CONFIG_WINDOW_SIZE * 2;
const MAX_FIELDS: usize = 128;
const MAX_WARNING_COUNT: usize = 256;
const MAX_DUPLICATE_ADDRESSES: usize = 64;
const MAX_X64_USER_ADDRESS: u64 = 0x0000_7fff_ffff_ffff;

#[derive(Debug, Clone)]
pub struct CobaltStrikeScanOptions {
    pub pid: Option<u64>,
    pub result_limit: usize,
    pub chunk_size: usize,
}

impl Default for CobaltStrikeScanOptions {
    fn default() -> Self {
        Self {
            pid: None,
            result_limit: 4096,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CobaltStrikeScanReport {
    pub records: Vec<CobaltStrikeConfigRecord>,
    pub processes_examined: usize,
    pub vads_examined: usize,
    pub invalid_vads_skipped: usize,
    pub page_table_warning_count: usize,
    pub chunks_scanned: usize,
    pub bytes_examined: u64,
    pub missing_bytes: u64,
    pub candidates_examined: usize,
    pub rejected_candidates: usize,
    pub rejected_by_reason: BTreeMap<String, usize>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CobaltStrikeConfigRecord {
    pub pid: u64,
    pub process: String,
    pub ppid: Option<u64>,
    pub process_state: String,
    pub process_image_path: Option<String>,
    pub process_command_line: Option<String>,
    pub process_user: Option<String>,
    pub process_session_id: Option<u32>,
    pub process_create_time: Option<String>,
    pub eprocess: u64,
    pub vad: u64,
    pub vad_start: u64,
    pub vad_end: u64,
    pub vad_size: u64,
    pub vad_protection: String,
    pub vad_private_memory: bool,
    pub vad_file: Option<String>,
    pub config_address: u64,
    pub duplicate_addresses: Vec<u64>,
    pub copy_count: usize,
    pub xor_key: u8,
    pub decoded_size: usize,
    pub config_sha256: String,
    pub field_count: usize,
    pub recognized_field_count: usize,
    pub max_setting_id: u16,
    pub version_hint: String,
    pub complete: bool,
    pub confidence: String,
    pub payload_dns: bool,
    pub payload_ssl: bool,
    pub protocols: Vec<String>,
    pub port: Option<u64>,
    pub sleep_time_ms: Option<u64>,
    pub jitter_percent: Option<u64>,
    pub server_get_uri: Option<String>,
    pub user_agent: Option<String>,
    pub post_uri: Option<String>,
    pub spawn_to_x86: Option<String>,
    pub spawn_to_x64: Option<String>,
    pub pipe_name: Option<String>,
    pub license_id: Option<u64>,
    pub host_header: Option<String>,
    pub c2_endpoints: Vec<CobaltStrikeEndpoint>,
    pub http_profile: CobaltStrikeHttpProfile,
    pub dns_profile: CobaltStrikeDnsProfile,
    pub proxy_profile: CobaltStrikeProxyProfile,
    pub process_injection: CobaltStrikeProcessInjectionProfile,
    pub stage_profile: CobaltStrikeStageProfile,
    pub configuration_highlights: Vec<String>,
    pub profile_preview: Vec<String>,
    pub settings: Vec<CobaltStrikeConfigField>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CobaltStrikeEndpoint {
    pub domain: String,
    pub get_uri: String,
    pub scheme: String,
    pub port: Option<u64>,
    pub url: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CobaltStrikeHttpProfile {
    pub get_verb: Option<String>,
    pub post_verb: Option<String>,
    pub submit_uri: Option<String>,
    pub user_agent: Option<String>,
    pub host_header: Option<String>,
    pub get_headers: Vec<String>,
    pub post_headers: Vec<String>,
    pub server_output_transform: Vec<String>,
    pub client_metadata_transform: Vec<String>,
    pub client_output_transform: Vec<String>,
    pub uses_cookies: Option<bool>,
    pub data_required: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CobaltStrikeDnsProfile {
    pub idle_ipv4: Option<String>,
    pub sleep_ms: Option<u64>,
    pub resolver: Option<String>,
    pub beacon: Option<String>,
    pub get_a: Option<String>,
    pub get_aaaa: Option<String>,
    pub get_txt: Option<String>,
    pub put_metadata: Option<String>,
    pub put_output: Option<String>,
    pub strategy: Option<String>,
    pub rotate_seconds: Option<u64>,
    pub fail_x: Option<u64>,
    pub fail_seconds: Option<u64>,
    pub retry_attempts: Option<u64>,
    pub retry_increase: Option<u64>,
    pub retry_duration: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CobaltStrikeProxyProfile {
    pub server: Option<String>,
    pub username: Option<String>,
    pub password_present: bool,
    pub behavior: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CobaltStrikeProcessInjectionProfile {
    pub start_rwx: Option<bool>,
    pub use_rwx: Option<bool>,
    pub minimum_allocation: Option<u64>,
    pub allocator: Option<String>,
    pub execute_methods: Vec<String>,
    pub transform_x86: Vec<String>,
    pub transform_x64: Vec<String>,
    pub bof_allocator: Option<String>,
    pub bof_reuse_memory: Option<bool>,
    pub syscall_method: Option<String>,
    pub stub_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CobaltStrikeStageProfile {
    pub kill_date: Option<String>,
    pub cleanup: Option<bool>,
    pub cfg_caution: Option<bool>,
    pub public_key_sha256: Option<String>,
    pub crypto_scheme: Option<String>,
    pub sleep_mask_sections: Vec<String>,
    pub obfuscate_sections: bool,
    pub watermark: Option<u64>,
    pub watermark_hash: Option<String>,
    pub masked_watermark: Option<String>,
    pub data_store_size: Option<u64>,
    pub beacon_gate_apis: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CobaltStrikeConfigField {
    pub id: u16,
    pub name: String,
    pub value_type: String,
    pub length: usize,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_hex: Option<String>,
}

#[derive(Default)]
struct ScanCounters {
    processes: usize,
    vads: usize,
    invalid_vads: usize,
    page_table_warnings: usize,
    chunks: usize,
    bytes: u64,
    missing: u64,
    candidates: usize,
    rejected: usize,
    rejected_by_reason: BTreeMap<String, usize>,
}

struct ParsedConfig {
    fields: Vec<CobaltStrikeConfigField>,
    numeric: BTreeMap<u16, u64>,
    text: BTreeMap<u16, String>,
    binary: BTreeMap<u16, Vec<u8>>,
    consumed: usize,
    recognized: usize,
    complete: bool,
}

/// Scans all selected process VADs for encoded Cobalt Strike Beacon settings.
pub fn scan_cobaltstrike_configs(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &CobaltStrikeScanOptions,
    cancellation: &CancellationToken,
) -> Result<CobaltStrikeScanReport> {
    validate_options(options)?;
    cancellation.check_cancelled()?;

    let processes = list_processes(image, kernel, profile, 65_536)?;
    cancellation.check_cancelled()?;
    let mut warnings: Vec<String> = processes
        .warnings
        .iter()
        .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
        .collect();
    let mut complete = processes.complete;
    let mut counters = ScanCounters::default();
    let mut records = Vec::new();
    let mut dedup: HashMap<(u64, String), usize> = HashMap::new();

    'processes: for process in processes
        .processes
        .iter()
        .filter(|process| options.pid.is_none_or(|pid| process.pid == pid))
    {
        cancellation.check_cancelled()?;
        counters.processes += 1;
        let Some(space) = process_address_space(image, process) else {
            complete = false;
            push_warning(
                &mut warnings,
                format!("PID {} 没有可读取的用户页表，已跳过", process.pid),
            );
            continue;
        };
        let mappings = match space.enumerate_mappings(VirtualAddressRegion::User, 2_000_000) {
            Ok(report) => {
                complete &= !report.truncated;
                if report.truncated {
                    push_warning(
                        &mut warnings,
                        format!("PID {} 的用户页表映射达到结果上限", process.pid),
                    );
                }
                if !report.warnings.is_empty() {
                    complete = false;
                    counters.page_table_warnings = counters
                        .page_table_warnings
                        .saturating_add(report.warnings.len());
                    let examples = report
                        .warnings
                        .iter()
                        .take(3)
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join("；");
                    push_warning(
                        &mut warnings,
                        format!(
                            "PID {} 的用户页表有 {} 项读取警告，示例：{}",
                            process.pid,
                            report.warnings.len(),
                            examples
                        ),
                    );
                }
                report.mappings
            }
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("PID {} 的用户页表遍历失败：{error:#}", process.pid),
                );
                continue;
            }
        };
        cancellation.check_cancelled()?;
        let vads = match list_vads(image, kernel, profile, process.pid, 1_000_000) {
            Ok(report) => report,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("PID {} 的 VAD 遍历失败：{error:#}", process.pid),
                );
                continue;
            }
        };
        cancellation.check_cancelled()?;
        counters.vads += vads.records.len();
        complete &= vads.complete;
        for vad in &vads.records {
            cancellation.check_cancelled()?;
            if !valid_user_vad_range(vad.start, vad.end) {
                complete = false;
                counters.invalid_vads = counters.invalid_vads.saturating_add(1);
                if counters.invalid_vads <= 8 {
                    push_warning(
                        &mut warnings,
                        format!(
                            "PID {} 的 VAD 范围无效，已跳过：{:#x}-{:#x}",
                            process.pid, vad.start, vad.end
                        ),
                    );
                }
                continue;
            }
            let outcome = scan_vad(
                image,
                &mappings,
                process,
                vad,
                options,
                cancellation,
                &mut records,
                &mut dedup,
                &mut counters,
            )?;
            counters.chunks += outcome.chunks;
            counters.bytes += outcome.bytes;
            counters.missing += outcome.missing;
            if outcome.missing != 0 {
                complete = false;
            }
            if records.len() == options.result_limit {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!(
                        "Cobalt Strike 配置结果达到 {} 条上限，剩余 VAD 未扫描",
                        options.result_limit
                    ),
                );
                break 'processes;
            }
        }
    }

    if options.pid.is_some() && counters.processes == 0 {
        complete = false;
        push_warning(
            &mut warnings,
            format!("活动进程列表中没有 PID {}", options.pid.unwrap_or_default()),
        );
    }
    if counters.missing != 0 {
        push_warning(
            &mut warnings,
            format!(
                "页表缺失导致 {} 字节的 VAD 内容不可读取；阴性结果不能排除 Beacon",
                counters.missing
            ),
        );
    }

    Ok(CobaltStrikeScanReport {
        records,
        processes_examined: counters.processes,
        vads_examined: counters.vads,
        invalid_vads_skipped: counters.invalid_vads,
        page_table_warning_count: counters.page_table_warnings,
        chunks_scanned: counters.chunks,
        bytes_examined: counters.bytes,
        missing_bytes: counters.missing,
        candidates_examined: counters.candidates,
        rejected_candidates: counters.rejected,
        rejected_by_reason: counters.rejected_by_reason,
        complete,
        warnings,
    })
}

struct VadScanOutcome {
    chunks: usize,
    bytes: u64,
    missing: u64,
}

#[allow(clippy::too_many_arguments)]
fn scan_vad(
    image: &MemoryImage,
    mappings: &[VirtualMapping],
    process: &ProcessRecord,
    vad: &VadRecord,
    options: &CobaltStrikeScanOptions,
    cancellation: &CancellationToken,
    records: &mut Vec<CobaltStrikeConfigRecord>,
    dedup: &mut HashMap<(u64, String), usize>,
    counters: &mut ScanCounters,
) -> Result<VadScanOutcome> {
    let mut chunks = 0usize;
    let mut bytes_examined = 0u64;
    let mut missing = 0u64;
    let mut buffer = Vec::with_capacity(options.chunk_size + PAGE_SIZE as usize);
    let mut buffer_base = vad.start;
    let mut next_virtual = vad.start;
    let first_mapping = mappings.partition_point(|mapping| mapping.virtual_end < vad.start);

    for mapping in mappings[first_mapping..]
        .iter()
        .take_while(|mapping| mapping.virtual_start <= vad.end)
    {
        cancellation.check_cancelled()?;
        let range_start = mapping.virtual_start.max(vad.start);
        let range_end = mapping.virtual_end.min(vad.end);
        if range_start > range_end {
            continue;
        }
        if range_start > next_virtual {
            // A VAD may contain demand-zero, swapped, or otherwise nonresident
            // pages.  Those gaps are not bytes that failed to read from the
            // captured image, so do not inflate `missing_bytes`; only break the
            // stream to avoid joining non-contiguous virtual ranges.
            flush_buffer(
                process,
                vad,
                &mut buffer_base,
                &mut buffer,
                options,
                records,
                dedup,
                counters,
                &mut chunks,
            );
        }

        let mut virtual_address = range_start;
        let mut physical_address = mapping
            .physical_start
            .saturating_add(range_start - mapping.virtual_start);
        while virtual_address <= range_end {
            cancellation.check_cancelled()?;
            let count = (range_end - virtual_address + 1).min(64 * 1024) as usize;
            let mut bytes = vec![0u8; count];
            if image.read_physical(physical_address, &mut bytes).is_ok() {
                bytes_examined += count as u64;
                if buffer.is_empty() {
                    buffer_base = virtual_address;
                }
                append_stream_bytes(
                    process,
                    vad,
                    virtual_address,
                    &bytes,
                    options,
                    records,
                    dedup,
                    counters,
                    &mut chunks,
                    &mut buffer_base,
                    &mut buffer,
                );
            } else {
                missing = missing.saturating_add(count as u64);
                flush_buffer(
                    process,
                    vad,
                    &mut buffer_base,
                    &mut buffer,
                    options,
                    records,
                    dedup,
                    counters,
                    &mut chunks,
                );
            }
            if records.len() == options.result_limit {
                break;
            }
            virtual_address = virtual_address.saturating_add(count as u64);
            physical_address = physical_address.saturating_add(count as u64);
            if virtual_address == 0 {
                break;
            }
        }
        next_virtual = range_end.saturating_add(1);
        if records.len() == options.result_limit || next_virtual == 0 {
            break;
        }
    }
    if !buffer.is_empty() && records.len() < options.result_limit {
        scan_buffer(
            process,
            vad,
            buffer_base,
            &buffer,
            None,
            options,
            records,
            dedup,
            counters,
        );
        chunks += 1;
    }
    Ok(VadScanOutcome {
        chunks,
        bytes: bytes_examined,
        missing,
    })
}

#[allow(clippy::too_many_arguments)]
fn append_stream_bytes(
    process: &ProcessRecord,
    vad: &VadRecord,
    virtual_address: u64,
    bytes: &[u8],
    options: &CobaltStrikeScanOptions,
    records: &mut Vec<CobaltStrikeConfigRecord>,
    dedup: &mut HashMap<(u64, String), usize>,
    counters: &mut ScanCounters,
    chunks: &mut usize,
    buffer_base: &mut u64,
    buffer: &mut Vec<u8>,
) {
    if buffer.len() + bytes.len() > options.chunk_size && !buffer.is_empty() {
        let safe_start_end = buffer.len().saturating_sub(CONFIG_OVERLAP);
        scan_buffer(
            process,
            vad,
            *buffer_base,
            buffer,
            Some(safe_start_end),
            options,
            records,
            dedup,
            counters,
        );
        *chunks += 1;
        let retained = CONFIG_OVERLAP.min(buffer.len());
        *buffer = buffer.split_off(buffer.len() - retained);
        *buffer_base = virtual_address.saturating_sub(retained as u64);
    }
    buffer.extend_from_slice(bytes);
}

#[allow(clippy::too_many_arguments)]
fn flush_buffer(
    process: &ProcessRecord,
    vad: &VadRecord,
    buffer_base: &mut u64,
    buffer: &mut Vec<u8>,
    options: &CobaltStrikeScanOptions,
    records: &mut Vec<CobaltStrikeConfigRecord>,
    dedup: &mut HashMap<(u64, String), usize>,
    counters: &mut ScanCounters,
    chunks: &mut usize,
) {
    if buffer.is_empty() {
        return;
    }
    scan_buffer(
        process,
        vad,
        *buffer_base,
        buffer,
        None,
        options,
        records,
        dedup,
        counters,
    );
    *chunks += 1;
    buffer.clear();
}

#[allow(clippy::too_many_arguments)]
fn scan_buffer(
    process: &ProcessRecord,
    vad: &VadRecord,
    base: u64,
    bytes: &[u8],
    safe_start_end: Option<usize>,
    options: &CobaltStrikeScanOptions,
    records: &mut Vec<CobaltStrikeConfigRecord>,
    dedup: &mut HashMap<(u64, String), usize>,
    counters: &mut ScanCounters,
) {
    if bytes.len() < 14 {
        return;
    }
    let last_start = safe_start_end
        .unwrap_or(bytes.len().saturating_sub(13))
        .min(bytes.len().saturating_sub(13));
    for offset in 0..last_start {
        if records.len() == options.result_limit {
            break;
        }
        if !is_encoded_config_header(&bytes[offset..]) {
            continue;
        }
        counters.candidates += 1;
        let key = bytes[offset];
        let end = (offset + CONFIG_WINDOW_SIZE).min(bytes.len());
        let parsed = match parse_encoded_config(&bytes[offset..end], key) {
            Ok(parsed) => parsed,
            Err(reason) => {
                counters.rejected += 1;
                *counters
                    .rejected_by_reason
                    .entry(reason.to_owned())
                    .or_default() += 1;
                continue;
            }
        };
        let decoded: Vec<u8> = bytes[offset..offset + parsed.consumed]
            .iter()
            .map(|byte| byte ^ key)
            .collect();
        let digest = hex::encode(Sha256::digest(&decoded));
        let address = base.saturating_add(offset as u64);
        if let Some(index) = dedup.get(&(process.pid, digest.clone())).copied() {
            let existing = &mut records[index];
            existing.copy_count += 1;
            if existing.duplicate_addresses.len() < MAX_DUPLICATE_ADDRESSES
                && !existing.duplicate_addresses.contains(&address)
            {
                existing.duplicate_addresses.push(address);
            }
            continue;
        }
        let payload = parsed.numeric.get(&1).copied().unwrap_or(0);
        let port = parsed.numeric.get(&2).copied();
        let protocols = protocol_names(payload);
        let c2_endpoints = build_c2_endpoints(&parsed, payload, port);
        let http_profile = build_http_profile(&parsed);
        let dns_profile = build_dns_profile(&parsed);
        let proxy_profile = build_proxy_profile(&parsed);
        let process_injection = build_process_injection_profile(&parsed);
        let stage_profile = build_stage_profile(&parsed);
        let max_setting_id = parsed
            .fields
            .iter()
            .map(|field| field.id)
            .max()
            .unwrap_or(0);
        let version_hint = version_hint(max_setting_id).to_owned();
        let configuration_highlights = build_configuration_highlights(
            &parsed,
            vad,
            &protocols,
            &c2_endpoints,
            &process_injection,
            &stage_profile,
        );
        let profile_preview = build_profile_preview(
            &parsed,
            &protocols,
            &c2_endpoints,
            &http_profile,
            &dns_profile,
            &process_injection,
            &stage_profile,
        );
        let process_user = process.details.user_name.as_ref().map(|name| {
            match process.details.user_domain.as_deref() {
                Some(domain) if !domain.is_empty() => format!("{domain}\\{name}"),
                _ => name.clone(),
            }
        });
        let record = CobaltStrikeConfigRecord {
            pid: process.pid,
            process: process.name.clone(),
            ppid: process.ppid,
            process_state: process.details.state.clone(),
            process_image_path: process.details.image_path.clone(),
            process_command_line: process.details.command_line.clone(),
            process_user,
            process_session_id: process.details.session_id,
            process_create_time: process.details.create_time.clone(),
            eprocess: process.eprocess,
            vad: vad.node,
            vad_start: vad.start,
            vad_end: vad.end,
            vad_size: vad.end.saturating_sub(vad.start).saturating_add(1),
            vad_protection: vad.protection_name.clone(),
            vad_private_memory: vad.private_memory,
            vad_file: vad.file.clone(),
            config_address: address,
            duplicate_addresses: Vec::new(),
            copy_count: 1,
            xor_key: key,
            decoded_size: parsed.consumed,
            config_sha256: digest.clone(),
            field_count: parsed.fields.len(),
            recognized_field_count: parsed.recognized,
            max_setting_id,
            version_hint,
            complete: parsed.complete,
            confidence: if parsed.complete && parsed.recognized >= 8 {
                "high".to_owned()
            } else {
                "medium".to_owned()
            },
            payload_dns: payload & 1 != 0,
            payload_ssl: payload & 8 != 0,
            protocols,
            port,
            sleep_time_ms: parsed.numeric.get(&3).copied(),
            jitter_percent: parsed.numeric.get(&5).copied(),
            server_get_uri: parsed.text.get(&8).cloned(),
            user_agent: parsed.text.get(&9).cloned(),
            post_uri: parsed.text.get(&10).cloned(),
            spawn_to_x86: parsed.text.get(&29).cloned(),
            spawn_to_x64: parsed.text.get(&30).cloned(),
            pipe_name: parsed.text.get(&15).cloned(),
            license_id: parsed.numeric.get(&37).copied(),
            host_header: parsed.text.get(&54).cloned(),
            c2_endpoints,
            http_profile,
            dns_profile,
            proxy_profile,
            process_injection,
            stage_profile,
            configuration_highlights,
            profile_preview,
            settings: parsed.fields,
        };
        let index = records.len();
        records.push(record);
        dedup.insert((process.pid, digest), index);
    }
}

fn is_encoded_config_header(bytes: &[u8]) -> bool {
    if bytes.len() < 14 {
        return false;
    }
    let key = bytes[0];
    bytes[1] == key ^ 1
        && bytes[2] == key
        && bytes[3] == key ^ 1
        && bytes[4] == key
        && bytes[5] == key ^ 2
        && bytes[8] == key
        && bytes[9] == key ^ 2
        && bytes[10] == key
        && bytes[11] == key ^ 1
        && bytes[12] == key
        && bytes[13] == key ^ 2
}

fn parse_encoded_config(encoded: &[u8], key: u8) -> Result<ParsedConfig, &'static str> {
    let decoded: Vec<u8> = encoded.iter().map(|byte| byte ^ key).collect();
    let parsed = parse_decoded_config(&decoded)?;
    if matches!(key, 0x2e | 0x69) {
        return Ok(parsed);
    }

    // The public plugin documents 0x2e and 0x69.  Other one-byte XOR
    // variants are accepted only when a complete, richly populated Beacon
    // config is present; this rejects common short plaintext TLV structures.
    let strong_fields = parsed
        .fields
        .iter()
        .filter(|field| matches!(field.id, 3 | 8 | 9 | 10 | 15 | 29 | 30 | 37 | 54))
        .count();
    if parsed.complete
        && parsed.recognized >= 8
        && strong_fields >= 3
        && parsed.numeric.contains_key(&3)
        && (parsed.text.contains_key(&8)
            || parsed.text.contains_key(&15)
            || parsed.numeric.contains_key(&37))
    {
        Ok(parsed)
    } else {
        Err("非标准 XOR 配置的强语义字段不足")
    }
}

fn parse_decoded_config(decoded: &[u8]) -> Result<ParsedConfig, &'static str> {
    let mut offset = 0usize;
    let mut fields = Vec::new();
    let mut numeric = BTreeMap::new();
    let mut text = BTreeMap::new();
    let mut binary = BTreeMap::new();
    let mut recognized = 0usize;
    let mut complete = false;

    while offset + 2 <= decoded.len() && fields.len() < MAX_FIELDS {
        if decoded[offset..offset + 2] == [0, 0] {
            offset += 2;
            complete = true;
            break;
        }
        if offset + 6 > decoded.len() {
            return Err("配置字段头被截断");
        }
        let id = u16::from_be_bytes([decoded[offset], decoded[offset + 1]]);
        let value_type = u16::from_be_bytes([decoded[offset + 2], decoded[offset + 3]]);
        let length = usize::from(u16::from_be_bytes([
            decoded[offset + 4],
            decoded[offset + 5],
        ]));
        if id == 0 || value_type == 0 || value_type > 3 {
            return Err("配置字段编号或类型无效");
        }
        if (value_type == 1 && length != 2) || (value_type == 2 && length != 4) {
            return Err("数值字段长度无效");
        }
        let value_start = offset + 6;
        let value_end = value_start.checked_add(length).ok_or("配置字段长度溢出")?;
        if value_end > decoded.len() {
            return Err("配置字段值被截断");
        }
        let raw = &decoded[value_start..value_end];
        let (kind, value, raw_hex) = match value_type {
            1 => {
                let number = u64::from(u16::from_be_bytes([raw[0], raw[1]]));
                numeric.insert(id, number);
                ("u16", number.to_string(), None)
            }
            2 => {
                let number = u64::from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]));
                numeric.insert(id, number);
                ("u32", number.to_string(), None)
            }
            3 => {
                binary.insert(id, raw.to_vec());
                let display = display_bytes(raw);
                text.insert(id, display.clone());
                let raw_hex = (!looks_textual(raw)).then(|| hex::encode(raw));
                ("bytes", display, raw_hex)
            }
            _ => unreachable!(),
        };
        let name = setting_name(id).map_or_else(|| format!("unknown_{id:#06x}"), str::to_owned);
        if setting_name(id).is_some() {
            recognized += 1;
        }
        fields.push(CobaltStrikeConfigField {
            id,
            name,
            value_type: kind.to_owned(),
            length,
            value,
            raw_hex,
        });
        offset = value_end;
    }

    let first = fields.first().ok_or("配置没有字段")?;
    let second = fields.get(1).ok_or("配置字段数量不足")?;
    let has_operational_field = fields
        .iter()
        .any(|field| matches!(field.id, 2 | 3 | 8 | 15 | 29 | 30 | 37));
    if first.id != 1 || first.value_type != "u16" || second.id != 2 || second.value_type != "u16" {
        return Err("配置起始字段不符合 Beacon TLV");
    }
    if recognized < 3 {
        return Err("已识别配置字段不足");
    }
    if !has_operational_field {
        return Err("配置缺少运行字段");
    }
    Ok(ParsedConfig {
        fields,
        numeric,
        text,
        binary,
        consumed: offset,
        recognized,
        complete,
    })
}

fn protocol_names(payload: u64) -> Vec<String> {
    if payload == 0 {
        return vec!["http".to_owned()];
    }
    let mut protocols = Vec::new();
    for (flag, name) in [
        (1, "dns"),
        (2, "smb"),
        (4, "tcp"),
        (8, "https"),
        (16, "bind_tcp"),
    ] {
        if payload & flag != 0 {
            protocols.push(name.to_owned());
        }
    }
    if protocols.is_empty() {
        protocols.push(format!("unknown_{payload:#x}"));
    }
    protocols
}

fn build_c2_endpoints(
    parsed: &ParsedConfig,
    payload: u64,
    port: Option<u64>,
) -> Vec<CobaltStrikeEndpoint> {
    let Some(domains) = parsed.text.get(&8) else {
        return Vec::new();
    };
    let parts: Vec<&str> = domains
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    let scheme = if payload & 8 != 0 { "https" } else { "http" };
    let mut endpoints = Vec::new();
    for pair in parts.chunks(2) {
        let domain = pair[0].trim_matches('/');
        if domain.is_empty() {
            continue;
        }
        let get_uri = pair.get(1).copied().unwrap_or("").trim().to_owned();
        let port_suffix = match (scheme, port) {
            ("http", Some(80)) | ("https", Some(443)) | (_, None) => String::new(),
            (_, Some(port)) => format!(":{port}"),
        };
        let uri = if get_uri.is_empty() {
            "/".to_owned()
        } else if get_uri.starts_with('/') {
            get_uri.clone()
        } else {
            format!("/{get_uri}")
        };
        let endpoint = CobaltStrikeEndpoint {
            domain: domain.to_owned(),
            get_uri,
            scheme: scheme.to_owned(),
            port,
            url: format!("{scheme}://{domain}{port_suffix}{uri}"),
        };
        if !endpoints
            .iter()
            .any(|existing: &CobaltStrikeEndpoint| existing.url == endpoint.url)
        {
            endpoints.push(endpoint);
        }
    }
    endpoints
}

fn build_http_profile(parsed: &ParsedConfig) -> CobaltStrikeHttpProfile {
    let client_metadata_transform = parsed
        .binary
        .get(&12)
        .map_or_else(Vec::new, |data| parse_request_transform(data, "metadata"));
    let client_output_transform = parsed
        .binary
        .get(&13)
        .map_or_else(Vec::new, |data| parse_request_transform(data, "id"));
    let get_headers = client_metadata_transform
        .iter()
        .filter(|step| step.starts_with("header:") || step.starts_with("host_header:"))
        .cloned()
        .collect();
    let post_headers = client_output_transform
        .iter()
        .filter(|step| step.starts_with("header:") || step.starts_with("host_header:"))
        .cloned()
        .collect();
    CobaltStrikeHttpProfile {
        get_verb: parsed.text.get(&26).cloned(),
        post_verb: parsed.text.get(&27).cloned(),
        submit_uri: parsed.text.get(&10).cloned(),
        user_agent: parsed.text.get(&9).cloned(),
        host_header: parsed.text.get(&54).cloned(),
        get_headers,
        post_headers,
        server_output_transform: parsed
            .binary
            .get(&11)
            .map_or_else(Vec::new, |data| parse_recover_transform(data)),
        client_metadata_transform,
        client_output_transform,
        // Modern documentation names setting 50 HTTP_NO_COOKIES.
        uses_cookies: parsed.numeric.get(&50).map(|value| *value == 0),
        data_required: parsed.numeric.get(&77).map(|value| *value != 0),
    }
}

fn build_dns_profile(parsed: &ParsedConfig) -> CobaltStrikeDnsProfile {
    let idle_ipv4 = parsed.binary.get(&19).and_then(|raw| {
        (raw.len() >= 4).then(|| Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string())
    });
    CobaltStrikeDnsProfile {
        idle_ipv4,
        sleep_ms: parsed.numeric.get(&20).copied(),
        resolver: parsed.text.get(&66).cloned(),
        beacon: parsed.text.get(&60).cloned(),
        get_a: parsed.text.get(&61).cloned(),
        get_aaaa: parsed.text.get(&62).cloned(),
        get_txt: parsed.text.get(&63).cloned(),
        put_metadata: parsed.text.get(&64).cloned(),
        put_output: parsed.text.get(&65).cloned(),
        strategy: parsed
            .numeric
            .get(&67)
            .map(|value| format!("strategy_{value}")),
        rotate_seconds: parsed.numeric.get(&68).copied(),
        fail_x: parsed.numeric.get(&69).copied(),
        fail_seconds: parsed.numeric.get(&70).copied(),
        retry_attempts: parsed.numeric.get(&71).copied(),
        retry_increase: parsed.numeric.get(&72).copied(),
        retry_duration: parsed.numeric.get(&73).copied(),
    }
}

fn build_proxy_profile(parsed: &ParsedConfig) -> CobaltStrikeProxyProfile {
    let behavior = parsed.numeric.get(&35).map(|value| match *value {
        0 => "manual",
        1 => "direct",
        2 => "system_preconfigured",
        4 => "manual_credentials",
        _ => "unknown",
    });
    CobaltStrikeProxyProfile {
        server: parsed.text.get(&32).cloned(),
        username: parsed.text.get(&33).cloned(),
        password_present: parsed
            .binary
            .get(&34)
            .is_some_and(|value| value.iter().any(|byte| *byte != 0)),
        behavior: behavior.map(str::to_owned),
    }
}

fn build_process_injection_profile(parsed: &ParsedConfig) -> CobaltStrikeProcessInjectionProfile {
    let max_setting = parsed
        .fields
        .iter()
        .map(|field| field.id)
        .max()
        .unwrap_or(0);
    let modern_bof = max_setting >= 74;
    CobaltStrikeProcessInjectionProfile {
        start_rwx: parsed.numeric.get(&43).map(|value| *value != 0),
        use_rwx: parsed.numeric.get(&44).map(|value| *value != 0),
        minimum_allocation: parsed.numeric.get(&45).copied(),
        allocator: parsed.numeric.get(&52).map(|value| {
            match *value {
                0 => "VirtualAllocEx",
                1 => "NtMapViewOfSection",
                _ => "unknown",
            }
            .to_owned()
        }),
        execute_methods: parsed
            .binary
            .get(&51)
            .map_or_else(Vec::new, |data| parse_execute_methods(data)),
        transform_x86: parsed
            .binary
            .get(&46)
            .map_or_else(Vec::new, |data| parse_injection_transform(data)),
        transform_x64: parsed
            .binary
            .get(&47)
            .map_or_else(Vec::new, |data| parse_injection_transform(data)),
        bof_allocator: (modern_bof)
            .then(|| parsed.numeric.get(&16).copied())
            .flatten()
            .map(|value| {
                match value {
                    0 => "VirtualAlloc",
                    1 => "MapViewOfFile",
                    2 => "HeapAlloc",
                    _ => "unknown",
                }
                .to_owned()
            }),
        bof_reuse_memory: (modern_bof)
            .then(|| parsed.numeric.get(&48).map(|value| *value != 0))
            .flatten(),
        syscall_method: parsed
            .numeric
            .get(&17)
            .and_then(|value| (*value <= 10).then(|| format!("method_{value}"))),
        stub_sha256: parsed
            .binary
            .get(&53)
            .map(|data| hex::encode(Sha256::digest(trim_trailing_zeroes(data)))),
    }
}

fn build_stage_profile(parsed: &ParsedConfig) -> CobaltStrikeStageProfile {
    let public_key_sha256 = parsed
        .binary
        .get(&7)
        .map(|data| hex::encode(Sha256::digest(trim_trailing_zeroes(data))));
    let kill_date = normalized_kill_date(parsed);
    CobaltStrikeStageProfile {
        kill_date,
        cleanup: parsed.numeric.get(&38).map(|value| *value != 0),
        cfg_caution: parsed.numeric.get(&39).map(|value| *value != 0),
        public_key_sha256,
        crypto_scheme: parsed.numeric.get(&31).map(|value| {
            match *value {
                0 => "licensed_product",
                1 => "trial_product",
                _ => "unknown",
            }
            .to_owned()
        }),
        sleep_mask_sections: parsed
            .binary
            .get(&42)
            .map_or_else(Vec::new, |data| parse_sleep_mask_sections(data)),
        obfuscate_sections: parsed
            .binary
            .get(&42)
            .is_some_and(|data| data.iter().any(|byte| *byte != 0)),
        watermark: parsed.numeric.get(&37).copied(),
        watermark_hash: parsed.text.get(&36).cloned(),
        masked_watermark: parsed.binary.get(&74).map(hex::encode),
        data_store_size: parsed.numeric.get(&76).copied(),
        beacon_gate_apis: parsed
            .binary
            .get(&78)
            .map_or_else(Vec::new, |data| parse_beacon_gate(data)),
    }
}

fn build_configuration_highlights(
    parsed: &ParsedConfig,
    vad: &VadRecord,
    protocols: &[String],
    endpoints: &[CobaltStrikeEndpoint],
    injection: &CobaltStrikeProcessInjectionProfile,
    stage: &CobaltStrikeStageProfile,
) -> Vec<String> {
    let mut highlights = vec![format!(
        "恢复 {}/{} 个已识别设置，版本范围提示 {}",
        parsed.recognized,
        parsed.fields.len(),
        version_hint(
            parsed
                .fields
                .iter()
                .map(|field| field.id)
                .max()
                .unwrap_or(0)
        )
    )];
    highlights.push(format!("通信协议：{}", protocols.join(" + ")));
    if !endpoints.is_empty() {
        highlights.push(format!(
            "C2 端点：{}",
            endpoints
                .iter()
                .map(|endpoint| endpoint.url.as_str())
                .collect::<Vec<_>>()
                .join("；")
        ));
    }
    if vad.private_memory {
        highlights.push(format!("配置位于私有 VAD（{}）", vad.protection_name));
    }
    if injection.start_rwx == Some(true) || injection.use_rwx == Some(true) {
        highlights.push("进程注入配置允许 RWX 内存".to_owned());
    }
    if let Some(kill_date) = &stage.kill_date {
        highlights.push(format!("Kill Date：{kill_date}"));
    }
    if let Some(watermark) = stage.watermark {
        highlights.push(format!("Watermark / License ID：{watermark}"));
    }
    if !stage.beacon_gate_apis.is_empty() {
        highlights.push(format!(
            "BeaconGate 代理 API：{}",
            stage.beacon_gate_apis.join(", ")
        ));
    }
    highlights
}

#[allow(clippy::too_many_arguments)]
fn build_profile_preview(
    parsed: &ParsedConfig,
    protocols: &[String],
    endpoints: &[CobaltStrikeEndpoint],
    http: &CobaltStrikeHttpProfile,
    dns: &CobaltStrikeDnsProfile,
    injection: &CobaltStrikeProcessInjectionProfile,
    stage: &CobaltStrikeStageProfile,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!("# protocol {}", protocols.join("+")));
    if let Some(value) = parsed.numeric.get(&3) {
        lines.push(format!("set sleeptime \"{value}\";"));
    }
    if let Some(value) = parsed.numeric.get(&5) {
        lines.push(format!("set jitter \"{value}\";"));
    }
    if let Some(value) = stage.watermark {
        lines.push(format!("set watermark \"{value}\";"));
    }
    for endpoint in endpoints {
        lines.push(format!(
            "# http-get {} {}",
            endpoint.domain, endpoint.get_uri
        ));
    }
    if let Some(uri) = &http.submit_uri {
        lines.push(format!("# http-post submit-uri {uri}"));
    }
    if let Some(user_agent) = &http.user_agent {
        lines.push(format!("set useragent \"{}\";", escape_preview(user_agent)));
    }
    if let Some(pipe) = parsed.text.get(&15) {
        lines.push(format!("set pipename \"{}\";", escape_preview(pipe)));
    }
    if let Some(resolver) = &dns.resolver {
        lines.push(format!(
            "set dns_resolver \"{}\";",
            escape_preview(resolver)
        ));
    }
    if let Some(allocator) = &injection.allocator {
        lines.push(format!("# process-inject allocator {allocator}"));
    }
    if !injection.execute_methods.is_empty() {
        lines.push(format!(
            "# process-inject execute {}",
            injection.execute_methods.join(", ")
        ));
    }
    if let Some(kill_date) = &stage.kill_date {
        lines.push(format!("set killdate \"{}\";", kill_date.replace('-', "")));
    }
    lines
}

fn parse_recover_transform(data: &[u8]) -> Vec<String> {
    let mut offset = 0usize;
    let mut steps = Vec::new();
    while let Some(step) = take_be_u32(data, &mut offset) {
        match step {
            0 => break,
            1 | 2 => {
                let Some(length) = take_be_u32(data, &mut offset) else {
                    steps.push("truncated".to_owned());
                    break;
                };
                steps.push(if step == 1 {
                    format!("append:{length}")
                } else {
                    format!("prepend:{length}")
                });
            }
            3 => steps.push("base64".to_owned()),
            4 => steps.push("print".to_owned()),
            8 => steps.push("netbios".to_owned()),
            11 => steps.push("netbiosu".to_owned()),
            13 => steps.push("base64url".to_owned()),
            15 => steps.push("mask".to_owned()),
            other => {
                steps.push(format!("unknown_{other}"));
                break;
            }
        }
    }
    steps
}

fn parse_request_transform(data: &[u8], default_build: &str) -> Vec<String> {
    let mut offset = 0usize;
    let mut steps = Vec::new();
    while let Some(step) = take_be_u32(data, &mut offset) {
        if step == 0 {
            break;
        }
        match step {
            3 => steps.push("base64".to_owned()),
            4 => steps.push("print".to_owned()),
            8 => steps.push("netbios".to_owned()),
            11 => steps.push("netbiosu".to_owned()),
            12 => steps.push("uri_append".to_owned()),
            13 => steps.push("base64url".to_owned()),
            15 => steps.push("mask".to_owned()),
            7 => {
                let Some(kind) = take_be_u32(data, &mut offset) else {
                    steps.push("build:truncated".to_owned());
                    break;
                };
                let kind = match kind {
                    0 => default_build,
                    1 => "output",
                    _ => "unknown",
                };
                steps.push(format!("build:{kind}"));
            }
            1 | 2 | 5 | 6 | 9 | 10 | 16 => {
                let Some(length) = take_be_u32(data, &mut offset).map(|value| value as usize)
                else {
                    steps.push("argument:truncated".to_owned());
                    break;
                };
                let Some(value) = take_bytes(data, &mut offset, length) else {
                    steps.push("argument:truncated".to_owned());
                    break;
                };
                let name = match step {
                    1 => "append",
                    2 => "prepend",
                    5 => "parameter",
                    6 => "header",
                    9 => "parameter_remove",
                    10 => "header_remove",
                    16 => "host_header",
                    _ => unreachable!(),
                };
                steps.push(format!("{name}:{}", display_transform_argument(value)));
            }
            other => {
                steps.push(format!("unknown_{other}"));
                break;
            }
        }
    }
    steps
}

fn parse_execute_methods(data: &[u8]) -> Vec<String> {
    let mut offset = 0usize;
    let mut methods = Vec::new();
    while offset < data.len() {
        let method = data[offset];
        offset += 1;
        if method == 0 {
            break;
        }
        let name = match method {
            1 => "CreateThread",
            2 => "SetThreadContext",
            3 => "CreateRemoteThread",
            4 => "RtlCreateUserThread",
            5 => "NtQueueApcThread",
            6 | 7 => {
                let base = if method == 6 {
                    "CreateThread"
                } else {
                    "CreateRemoteThread"
                };
                let Some(displacement) = take_be_u16(data, &mut offset) else {
                    methods.push(format!("{base}:truncated"));
                    break;
                };
                let Some(module) = take_length_prefixed(data, &mut offset) else {
                    methods.push(format!("{base}:truncated"));
                    break;
                };
                let Some(function) = take_length_prefixed(data, &mut offset) else {
                    methods.push(format!("{base}:truncated"));
                    break;
                };
                methods.push(format!(
                    "{base}:{}!{}+{displacement:#x}",
                    display_transform_argument(module),
                    display_transform_argument(function)
                ));
                continue;
            }
            8 => "NtQueueApcThread_s",
            _ => {
                methods.push(format!("unknown_{method}"));
                continue;
            }
        };
        methods.push(name.to_owned());
    }
    methods
}

fn parse_injection_transform(data: &[u8]) -> Vec<String> {
    let mut offset = 0usize;
    let mut steps = Vec::new();
    for name in ["append", "prepend"] {
        let Some(length) = take_be_u32(data, &mut offset).map(|value| value as usize) else {
            break;
        };
        if length == 0 {
            continue;
        }
        let Some(value) = take_bytes(data, &mut offset, length) else {
            steps.push(format!("{name}:truncated"));
            break;
        };
        steps.push(format!("{name}:{}", hex_preview(value, 64)));
    }
    steps
}

fn parse_sleep_mask_sections(data: &[u8]) -> Vec<String> {
    let mut sections = Vec::new();
    for pair in data.chunks_exact(8) {
        let start = u32::from_le_bytes(pair[..4].try_into().unwrap());
        let end = u32::from_le_bytes(pair[4..].try_into().unwrap());
        if start != 0 || end != 0 {
            sections.push(format!("{start:#x}-{end:#x}"));
        }
    }
    sections
}

fn parse_beacon_gate(data: &[u8]) -> Vec<String> {
    const APIS: &[&str] = &[
        "InternetOpenA",
        "InternetConnectA",
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "VirtualFree",
        "GetThreadContext",
        "SetThreadContext",
        "ResumeThread",
        "CreateThread",
        "CreateRemoteThread",
        "OpenProcess",
        "OpenThread",
        "CloseHandle",
        "CreateFileMappingA",
        "MapViewOfFile",
        "UnmapViewOfFile",
        "VirtualQuery",
        "DuplicateHandle",
        "ReadProcessMemory",
        "WriteProcessMemory",
        "ExitThread",
    ];
    APIS.iter()
        .zip(data)
        .filter(|(_, enabled)| **enabled != 0)
        .map(|(name, _)| (*name).to_owned())
        .collect()
}

fn normalized_kill_date(parsed: &ParsedConfig) -> Option<String> {
    if let Some(value) = parsed.numeric.get(&40).copied().filter(|value| *value != 0) {
        let value = format!("{value:08}");
        return Some(format!("{}-{}-{}", &value[..4], &value[4..6], &value[6..8]));
    }
    let year = parsed.numeric.get(&16).copied()?;
    let month = parsed.numeric.get(&17).copied()?;
    let day = parsed.numeric.get(&18).copied()?;
    (year >= 2000 && (1..=12).contains(&month) && (1..=31).contains(&day))
        .then(|| format!("{year:04}-{month:02}-{day:02}"))
}

fn version_hint(max_setting_id: u16) -> &'static str {
    match max_setting_id {
        78.. => "Cobalt Strike 4.10+",
        77 => "Cobalt Strike 4.10+",
        76 => "Cobalt Strike 4.9+",
        74..=75 => "Cobalt Strike 4.7+",
        71..=73 => "Cobalt Strike 4.5+",
        67..=70 => "Cobalt Strike 4.3+",
        60..=66 => "Cobalt Strike 4.3+",
        59 => "Cobalt Strike 4.2+",
        56..=58 => "Cobalt Strike 4.1+",
        54..=55 => "Cobalt Strike 4.0+",
        50..=53 => "Cobalt Strike 3.14+",
        49 => "Cobalt Strike 3.13+",
        43..=48 => "Cobalt Strike 3.12+",
        40..=42 => "Cobalt Strike 3.12+",
        38..=39 => "Cobalt Strike 3.11+",
        37 => "Cobalt Strike 3.9+",
        32..=36 => "Cobalt Strike 3.7+",
        31 => "Cobalt Strike 3.6+",
        15..=30 => "Cobalt Strike 3.4+",
        _ => "早期或定制 Beacon",
    }
}

fn take_be_u16(data: &[u8], offset: &mut usize) -> Option<u16> {
    let bytes = take_bytes(data, offset, 2)?;
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

fn take_be_u32(data: &[u8], offset: &mut usize) -> Option<u32> {
    let bytes = take_bytes(data, offset, 4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn take_bytes<'a>(data: &'a [u8], offset: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = (*offset).checked_add(length)?;
    let bytes = data.get(*offset..end)?;
    *offset = end;
    Some(bytes)
}

fn take_length_prefixed<'a>(data: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let length = take_be_u32(data, offset)? as usize;
    take_bytes(data, offset, length)
}

fn trim_trailing_zeroes(data: &[u8]) -> &[u8] {
    let length = data
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    &data[..length]
}

fn display_transform_argument(data: &[u8]) -> String {
    let data = trim_trailing_zeroes(data);
    if looks_textual(data) {
        String::from_utf8_lossy(data).into_owned()
    } else {
        hex_preview(data, 64)
    }
}

fn hex_preview(data: &[u8], max: usize) -> String {
    let shown = data.len().min(max);
    let suffix = if shown < data.len() { "…" } else { "" };
    format!("hex:{}{suffix}", hex::encode(&data[..shown]))
}

fn escape_preview(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn display_bytes(raw: &[u8]) -> String {
    let trimmed = raw
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(&[][..], |end| &raw[..=end]);
    if looks_textual(trimmed) {
        String::from_utf8_lossy(trimmed)
            .replace('\0', " | ")
            .trim()
            .to_owned()
    } else {
        format!("hex:{}", hex::encode(trimmed))
    }
}

fn looks_textual(raw: &[u8]) -> bool {
    !raw.is_empty()
        && raw
            .iter()
            .all(|byte| *byte == 0 || *byte == b'\t' || (0x20..=0x7e).contains(byte))
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

fn validate_options(options: &CobaltStrikeScanOptions) -> Result<()> {
    ensure!(options.result_limit > 0, "Cobalt Strike 结果上限必须大于零");
    ensure!(
        (64 * 1024..=32 * 1024 * 1024).contains(&options.chunk_size),
        "Cobalt Strike VAD 分块大小必须在 64 KiB 到 32 MiB 之间"
    );
    ensure!(
        options.chunk_size > CONFIG_OVERLAP,
        "Cobalt Strike VAD 分块必须大于配置重叠窗口"
    );
    Ok(())
}

fn valid_user_vad_range(start: u64, end: u64) -> bool {
    start <= end && end <= MAX_X64_USER_ADDRESS
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNING_COUNT {
        warnings.push(warning);
    }
}

fn setting_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0001 => "payload_type",
        0x0002 => "port",
        0x0003 => "sleep_time_ms",
        0x0004 => "max_get_size",
        0x0005 => "jitter_percent",
        0x0006 => "max_dns",
        0x0007 => "public_key",
        0x0008 => "server_get_uri",
        0x0009 => "user_agent",
        0x000a => "post_uri",
        0x000b => "malleable_c2_instructions",
        0x000c => "http_get_header",
        0x000d => "http_post_header",
        0x000e => "spawn_to",
        0x000f => "pipe_name",
        0x0010 => "kill_date_year_or_bof_allocator",
        0x0011 => "kill_date_month_or_syscall_method",
        0x0012 => "kill_date_day",
        0x0013 => "dns_idle",
        0x0014 => "dns_sleep",
        0x0015 => "ssh_host",
        0x0016 => "ssh_port",
        0x0017 => "ssh_username",
        0x0018 => "ssh_password",
        0x0019 => "ssh_public_key",
        0x001a => "get_verb",
        0x001b => "post_verb",
        0x001c => "http_post_chunk",
        0x001d => "spawn_to_x86",
        0x001e => "spawn_to_x64",
        0x001f => "crypto_scheme",
        0x0020 => "proxy",
        0x0021 => "proxy_username",
        0x0022 => "proxy_password",
        0x0023 => "proxy_type",
        0x0024 => "watermark_hash_or_deprecated_inject_options",
        0x0025 => "license_id",
        0x0026 => "stage_cleanup",
        0x0027 => "cfg_caution",
        0x0028 => "kill_date",
        0x0029 => "text_section_end",
        0x002a => "obfuscate_sections_info",
        0x002b => "process_inject_start_rwx",
        0x002c => "process_inject_use_rwx",
        0x002d => "process_inject_min_alloc",
        0x002e => "process_inject_transform_x86",
        0x002f => "process_inject_transform_x64",
        0x0030 => "process_inject_allowed_or_bof_reuse_memory",
        0x0031 => "bind_host",
        0x0032 => "http_no_cookies",
        0x0033 => "process_inject_execute",
        0x0034 => "process_inject_allocation_method",
        0x0035 => "process_inject_stub",
        0x0036 => "host_header",
        0x0037 => "exit_function",
        0x0038 => "ssh_banner",
        0x0039 => "smb_frame_header",
        0x003a => "tcp_frame_header",
        0x003b => "headers_to_remove",
        0x003c => "dns_beacon",
        0x003d => "dns_a",
        0x003e => "dns_aaaa",
        0x003f => "dns_txt",
        0x0040 => "dns_metadata",
        0x0041 => "dns_output",
        0x0042 => "dns_resolver",
        0x0043 => "dns_strategy",
        0x0044 => "dns_strategy_rotate_seconds",
        0x0045 => "dns_strategy_fail_x",
        0x0046 => "dns_strategy_fail_seconds",
        0x0047 => "dns_strategy_max_retry_attempts",
        0x0048 => "dns_strategy_retry_increase",
        0x0049 => "dns_strategy_retry_duration",
        0x004a => "masked_watermark",
        0x004b => "reserved_0x4b",
        0x004c => "data_store_size",
        0x004d => "http_data_required",
        0x004e => "beacon_gate",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(id: u16, value_type: u16, value: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&value_type.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
    }

    fn sample_config() -> Vec<u8> {
        let mut decoded = Vec::new();
        field(1, 1, &9u16.to_be_bytes(), &mut decoded);
        field(2, 1, &443u16.to_be_bytes(), &mut decoded);
        field(3, 2, &60_000u32.to_be_bytes(), &mut decoded);
        field(5, 1, &20u16.to_be_bytes(), &mut decoded);
        field(8, 3, b"c2.example,/submit\0", &mut decoded);
        field(15, 3, b"beacon_pipe\0", &mut decoded);
        field(29, 3, b"%windir%\\syswow64\\rundll32.exe\0", &mut decoded);
        field(30, 3, b"%windir%\\sysnative\\rundll32.exe\0", &mut decoded);
        field(37, 2, &123_456u32.to_be_bytes(), &mut decoded);
        field(54, 3, b"Host: example.org\0", &mut decoded);
        decoded.extend_from_slice(&[0, 0]);
        decoded
    }

    #[test]
    fn decodes_known_and_generic_xor_keys() {
        let decoded = sample_config();
        for key in [0x2e, 0x69, 0x55, 0x00] {
            let encoded: Vec<u8> = decoded.iter().map(|byte| byte ^ key).collect();
            assert!(is_encoded_config_header(&encoded));
            let parsed = parse_encoded_config(&encoded, key).expect("valid config");
            assert!(parsed.complete);
            assert_eq!(parsed.numeric.get(&2), Some(&443));
            assert_eq!(parsed.numeric.get(&3), Some(&60_000));
            assert_eq!(
                parsed.text.get(&15).map(String::as_str),
                Some("beacon_pipe")
            );
            assert!(parsed.recognized >= 8);
        }
    }

    #[test]
    fn rejects_lookalike_with_invalid_tlv_length() {
        let mut decoded = sample_config();
        // Keep the two-field detection header valid, but make the third u32
        // field claim an invalid two-byte value.
        decoded[20..22].copy_from_slice(&2u16.to_be_bytes());
        let encoded: Vec<u8> = decoded.iter().map(|byte| byte ^ 0x2e).collect();
        assert!(is_encoded_config_header(&encoded));
        assert!(parse_encoded_config(&encoded, 0x2e).is_err());
    }

    #[test]
    fn preserves_partial_but_structurally_valid_config() {
        let mut decoded = sample_config();
        decoded.truncate(decoded.len() - 2);
        let parsed = parse_decoded_config(&decoded).expect("valid partial config");
        assert!(!parsed.complete);
        assert!(parsed.recognized >= 8);
    }

    #[test]
    fn rejects_short_plaintext_tlv_lookalike() {
        let mut decoded = Vec::new();
        field(1, 1, &1u16.to_be_bytes(), &mut decoded);
        field(2, 1, &1u16.to_be_bytes(), &mut decoded);
        field(4, 2, &4096u32.to_be_bytes(), &mut decoded);
        decoded.extend_from_slice(&[0, 0]);
        assert!(is_encoded_config_header(&decoded));
        assert!(parse_encoded_config(&decoded, 0).is_err());
    }

    #[test]
    fn decodes_modern_profiles_and_version_hint() {
        let mut decoded = sample_config();
        decoded.truncate(decoded.len() - 2);
        field(26, 3, b"GET\0", &mut decoded);
        field(27, 3, b"POST\0", &mut decoded);
        field(50, 1, &0u16.to_be_bytes(), &mut decoded);
        field(52, 1, &1u16.to_be_bytes(), &mut decoded);
        field(66, 3, b"8.8.8.8\0", &mut decoded);
        field(71, 2, &5u32.to_be_bytes(), &mut decoded);
        field(76, 2, &1_048_576u32.to_be_bytes(), &mut decoded);
        field(77, 1, &1u16.to_be_bytes(), &mut decoded);
        let mut gate = vec![0u8; 23];
        gate[0] = 1;
        gate[20] = 1;
        field(78, 3, &gate, &mut decoded);
        decoded.extend_from_slice(&[0, 0]);

        let parsed = parse_decoded_config(&decoded).expect("modern config");
        let http = build_http_profile(&parsed);
        let dns = build_dns_profile(&parsed);
        let injection = build_process_injection_profile(&parsed);
        let stage = build_stage_profile(&parsed);

        assert_eq!(version_hint(78), "Cobalt Strike 4.10+");
        assert_eq!(version_hint(70), "Cobalt Strike 4.3+");
        assert_eq!(version_hint(56), "Cobalt Strike 4.1+");
        assert_eq!(version_hint(50), "Cobalt Strike 3.14+");
        assert_eq!(http.get_verb.as_deref(), Some("GET"));
        assert_eq!(http.post_verb.as_deref(), Some("POST"));
        assert_eq!(http.uses_cookies, Some(true));
        assert_eq!(http.data_required, Some(true));
        assert_eq!(dns.resolver.as_deref(), Some("8.8.8.8"));
        assert_eq!(dns.retry_attempts, Some(5));
        assert_eq!(injection.allocator.as_deref(), Some("NtMapViewOfSection"));
        assert_eq!(stage.data_store_size, Some(1_048_576));
        assert_eq!(
            stage.beacon_gate_apis,
            vec!["InternetOpenA".to_owned(), "ReadProcessMemory".to_owned()]
        );
    }

    #[test]
    fn reconstructs_all_c2_domain_uri_pairs() {
        let mut decoded = sample_config();
        decoded.truncate(decoded.len() - 2);
        field(8, 3, b"one.example,/a,two.example,/b\0", &mut decoded);
        decoded.extend_from_slice(&[0, 0]);
        let parsed = parse_decoded_config(&decoded).expect("paired c2 config");
        let endpoints = build_c2_endpoints(&parsed, 8, Some(443));
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].url, "https://one.example/a");
        assert_eq!(endpoints[1].url, "https://two.example/b");
    }

    #[test]
    fn rejects_noncanonical_or_reversed_user_vads() {
        assert!(valid_user_vad_range(0x1000, 0x7fff_ffff));
        assert!(!valid_user_vad_range(0x2000, 0x1000));
        assert!(!valid_user_vad_range(
            0x1000,
            MAX_X64_USER_ADDRESS.saturating_add(1)
        ));
    }
}
