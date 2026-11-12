use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Result, ensure};
use memchr::{memchr_iter, memmem};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::address::{VirtualAddressRegion, X64AddressSpace};
use crate::cancellation::CancellationToken;
use crate::evidence::EvidenceLimit;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::windows::gui_plugins::{WindowStationRecord, window_stations};
use crate::windows::{ProcessRecord, WindowsKernelContext, list_processes};

mod history;
mod history_layout;
pub use history::{ClipboardHistoryCheck, ClipboardHistoryRecord, HistoryChain, HistoryRange};

const SCAN_CHUNK_SIZE: usize = 64 * 1024 * 1024;
const SCAN_OVERLAP: usize = 512;
const MAX_TEXT_ADDRESSES: usize = 32;
const MAX_OWNERS: usize = 16;
const MAX_WARNINGS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardScanStage {
    Structures,
    PhysicalScan,
    DataRecovery,
    HistoryRecovery,
}

#[derive(Debug, Clone)]
pub struct ClipboardScanOptions {
    pub limit: usize,
    pub max_data_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidualScanStage {
    PhysicalScan,
    ProcessOwners,
    Classification,
}

#[derive(Debug, Clone)]
pub struct ResidualScanOptions {
    pub limit: usize,
    pub process_space_limit: usize,
    pub search_texts: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardTextEncoding {
    Ascii,
    Utf8,
    Utf16Le,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardResidualKind {
    Email,
    Url,
    Ipv4,
    WindowsPath,
    Command,
    ExactText,
}

impl ClipboardResidualKind {
    fn label(self) -> &'static str {
        match self {
            Self::Email => "邮箱地址",
            Self::Url => "URL",
            Self::Ipv4 => "IPv4 地址",
            Self::WindowsPath => "Windows 路径",
            Self::Command => "命令行",
            Self::ExactText => "精确文本",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ClipboardOwner {
    pub pid: u64,
    pub process: String,
    pub virtual_address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClipboardFormatRecord {
    pub session_id: u32,
    pub window_station: String,
    pub window_station_address: u64,
    pub clip_base: u64,
    pub clip_base_field_offset: u64,
    pub entry_layout: String,
    pub format_id: u32,
    pub format_name: String,
    pub handle: u64,
    pub global_handle: u32,
    pub delayed_render: bool,
    pub data_object: Option<u64>,
    pub data_physical_address: Option<u64>,
    pub data_size: Option<u32>,
    pub recovered_size: usize,
    pub data_complete: bool,
    pub content_type: String,
    pub content: Option<String>,
    pub sha256: Option<String>,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClipboardTextRecord {
    pub content: String,
    pub kind: ClipboardResidualKind,
    pub content_type: String,
    pub evidence_kind: String,
    pub confidence: String,
    pub occurrences: usize,
    pub encodings: Vec<ClipboardTextEncoding>,
    pub physical_addresses: Vec<u64>,
    pub owners: Vec<ClipboardOwner>,
    pub evidence_note: String,
}

#[derive(Debug, Serialize)]
pub struct ClipboardScanReport {
    pub formats: Vec<ClipboardFormatRecord>,
    pub history: Vec<ClipboardHistoryRecord>,
    pub history_checks: Vec<ClipboardHistoryCheck>,
    pub history_scope: &'static str,
    pub history_complete: bool,
    pub history_seconds: f64,
    pub limits: Vec<EvidenceLimit>,
    pub window_stations_examined: usize,
    pub clip_arrays_validated: usize,
    pub structured_data_blocks: usize,
    pub raw_pool_tag_hits: usize,
    pub bytes_scanned: u64,
    pub structure_seconds: f64,
    pub physical_scan_seconds: f64,
    pub total_seconds: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ResidualScanReport {
    pub records: Vec<ClipboardTextRecord>,
    pub raw_email_candidates: usize,
    pub raw_residual_candidates: usize,
    pub candidate_types: BTreeMap<String, usize>,
    pub custom_searches: usize,
    pub process_address_spaces: usize,
    pub bytes_scanned: u64,
    pub physical_scan_seconds: f64,
    pub owner_mapping_seconds: f64,
    pub total_seconds: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone)]
struct SessionSpace {
    session_id: u32,
    dtb: u64,
}

#[derive(Clone, Copy)]
struct ClipArrayLayout {
    pointer: u64,
    field_offset: u64,
    stride: usize,
}

type RawClipboardEntry = (u32, u64, u32);
type ClipArrayMatch = (ClipArrayLayout, Vec<RawClipboardEntry>);
type ScoredClipArray = (usize, ClipArrayLayout, Vec<RawClipboardEntry>);

#[derive(Clone)]
struct StructuredEntry {
    station: WindowStationRecord,
    array: ClipArrayLayout,
    format_id: u32,
    handle: u64,
    global_handle: u32,
}

#[derive(Clone)]
struct ClipboardDataBlock {
    object: Option<u64>,
    physical_object: u64,
    declared_size: u32,
    data: Vec<u8>,
    complete: bool,
}

struct TextAggregate {
    content: String,
    kind: ClipboardResidualKind,
    occurrences: usize,
    ascii: bool,
    utf8: bool,
    utf16: bool,
    physical_addresses: Vec<u64>,
}

type ResidualKey = (ClipboardResidualKind, String);
type ResidualMap = HashMap<ResidualKey, TextAggregate>;
type PhysicalScanPartial = (Vec<u64>, ResidualMap);

struct PhysicalScanResult {
    pool_tags: Vec<u64>,
    residuals: Vec<TextAggregate>,
    bytes_scanned: u64,
    elapsed_seconds: f64,
}

#[derive(Clone, Copy)]
struct ScanWork {
    physical_start: u64,
    file_start: u64,
    prefix: usize,
    core_len: usize,
    scan_len: usize,
}

struct ExactTextPattern {
    content: String,
    utf8: Vec<u8>,
    utf16: Vec<u8>,
    utf8_encoding: ClipboardTextEncoding,
}

#[derive(Clone, Copy)]
enum PatternAction {
    Url(ClipboardTextEncoding),
    Command(ClipboardTextEncoding),
    Exact(usize, ClipboardTextEncoding),
}

struct PatternScanner {
    matcher: AhoCorasick,
    actions: Vec<Vec<PatternAction>>,
}

#[derive(Clone, Copy)]
struct PhysicalScanMode {
    pool_tags: bool,
    residual_text: bool,
}

pub fn scan_clipboard<F>(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &ClipboardScanOptions,
    progress: F,
) -> Result<ClipboardScanReport>
where
    F: FnMut(ClipboardScanStage),
{
    scan_clipboard_cancellable(
        image,
        kernel,
        profile,
        options,
        &CancellationToken::new(),
        progress,
    )
}

pub fn scan_clipboard_cancellable<F>(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &ClipboardScanOptions,
    cancellation: &CancellationToken,
    mut progress: F,
) -> Result<ClipboardScanReport>
where
    F: FnMut(ClipboardScanStage),
{
    cancellation.check_cancelled()?;
    ensure!(options.limit > 0, "剪切板结果上限必须大于零");
    ensure!(options.max_data_size > 0, "剪切板数据恢复上限必须大于零");

    let total_started = Instant::now();
    let mut warnings = Vec::new();
    let mut complete = true;

    progress(ClipboardScanStage::Structures);
    let structure_started = Instant::now();
    // User-mode history remains recoverable when the kernel clipboard source is unavailable.
    let stations = match window_stations(image, kernel, profile, 4096) {
        Ok(report) => {
            complete &= report.complete;
            warnings.extend(
                report
                    .warnings
                    .into_iter()
                    .map(|warning| format!("窗口站：{warning}")),
            );
            report.records
        }
        Err(error) => {
            complete = false;
            warnings.push(format!("活动剪贴板窗口站不可用：{error:#}"));
            Vec::new()
        }
    };
    cancellation.check_cancelled()?;
    let processes = list_processes(image, kernel, profile, 65_536)?;
    complete &= processes.complete;
    warnings.extend(
        processes
            .warnings
            .iter()
            .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message)),
    );
    let sessions = select_session_spaces(&processes.processes);
    let mut structured = Vec::new();
    let mut clip_arrays_validated = 0usize;
    for station in &stations {
        cancellation.check_cancelled()?;
        let Some(session) = sessions
            .iter()
            .find(|session| session.session_id == station.session_id)
        else {
            push_warning(
                &mut warnings,
                format!(
                    "窗口站 {}（会话 {}）没有可用的会话页表",
                    station.name, station.session_id
                ),
            );
            complete = false;
            continue;
        };
        let space = match X64AddressSpace::new(image, session.dtb) {
            Ok(space) => space,
            Err(error) => {
                push_warning(
                    &mut warnings,
                    format!("无法打开会话 {} 的页表：{error:#}", session.session_id),
                );
                complete = false;
                continue;
            }
        };
        let Some((layout, entries)) = find_clip_array(&space, station) else {
            continue;
        };
        clip_arrays_validated += 1;
        structured.extend(
            entries
                .into_iter()
                .map(|(format_id, handle, global_handle)| StructuredEntry {
                    station: station.clone(),
                    array: layout,
                    format_id,
                    handle,
                    global_handle,
                }),
        );
    }
    let structure_seconds = structure_started.elapsed().as_secs_f64();

    progress(ClipboardScanStage::PhysicalScan);
    let physical = scan_physical_candidates(
        image,
        &[],
        PhysicalScanMode {
            pool_tags: true,
            residual_text: false,
        },
        cancellation,
    )?;
    let raw_pool_tag_hits = physical.pool_tags.len();

    progress(ClipboardScanStage::DataRecovery);
    let referenced_handles = structured
        .iter()
        .map(|entry| entry.handle)
        .filter(|handle| *handle != 0)
        .collect::<HashSet<_>>();
    let blocks = recover_data_blocks(
        image,
        &sessions,
        &physical.pool_tags,
        &referenced_handles,
        options.max_data_size,
    );
    cancellation.check_cancelled()?;
    let structured_data_blocks = blocks.len();
    let mut formats = structured
        .into_iter()
        .map(|entry| {
            let handle = entry.handle;
            format_record(entry, blocks.get(&handle))
        })
        .collect::<Vec<_>>();
    formats.sort_unstable_by(|left, right| {
        left.session_id
            .cmp(&right.session_id)
            .then_with(|| left.window_station.cmp(&right.window_station))
            .then_with(|| left.format_id.cmp(&right.format_id))
    });
    if formats.len() > options.limit {
        formats.truncate(options.limit);
        complete = false;
        push_warning(
            &mut warnings,
            format!("结构化剪切板格式达到 {} 条结果上限", options.limit),
        );
    }

    progress(ClipboardScanStage::HistoryRecovery);
    let history_started = Instant::now();
    let history = history::scan_history(
        image,
        kernel,
        profile,
        &processes.processes,
        options,
        cancellation,
    )?;
    complete &= history.complete;
    for check in &history.checks {
        if !check.complete {
            push_warning(
                &mut warnings,
                format!(
                    "TextInputHost 历史 PID {}：{}（详见历史来源检查）",
                    check
                        .pid
                        .map_or_else(|| "—".to_owned(), |pid| pid.to_string()),
                    check.warnings.join("；")
                ),
            );
        }
    }
    Ok(ClipboardScanReport {
        formats,
        history: history.items,
        history_checks: history.checks,
        history_scope: history::HISTORY_SCOPE,
        history_complete: history.complete && processes.complete,
        history_seconds: history_started.elapsed().as_secs_f64(),
        limits: history.limits,
        window_stations_examined: stations.len(),
        clip_arrays_validated,
        structured_data_blocks,
        raw_pool_tag_hits,
        bytes_scanned: physical.bytes_scanned,
        structure_seconds,
        physical_scan_seconds: physical.elapsed_seconds,
        total_seconds: total_started.elapsed().as_secs_f64(),
        complete,
        warnings,
    })
}

pub fn scan_residual_text<F>(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &ResidualScanOptions,
    mut progress: F,
) -> Result<ResidualScanReport>
where
    F: FnMut(ResidualScanStage),
{
    ensure!(options.limit > 0, "文本残留结果上限必须大于零");
    ensure!(
        options.process_space_limit > 0,
        "进程地址空间数量上限必须大于零"
    );
    ensure!(
        options.search_texts.len() <= 64,
        "精确搜索文本最多允许指定 64 条"
    );
    let exact_patterns = prepare_exact_text_patterns(&options.search_texts)?;
    let total_started = Instant::now();
    let mut warnings = Vec::new();
    let mut complete = true;

    progress(ResidualScanStage::PhysicalScan);
    let physical = scan_physical_candidates(
        image,
        &exact_patterns,
        PhysicalScanMode {
            pool_tags: false,
            residual_text: true,
        },
        &CancellationToken::new(),
    )?;
    let raw_email_candidates = physical
        .residuals
        .iter()
        .filter(|candidate| candidate.kind == ClipboardResidualKind::Email)
        .count();
    let raw_residual_candidates = physical.residuals.len();
    let mut candidate_types = BTreeMap::<String, usize>::new();
    for candidate in &physical.residuals {
        *candidate_types
            .entry(candidate.kind.label().to_owned())
            .or_default() += 1;
    }
    let residual_limit = options.limit.saturating_mul(16).clamp(512, 16_384);
    let mut records = physical
        .residuals
        .into_iter()
        .map(|candidate| {
            let encodings = text_encodings(&candidate);
            ClipboardTextRecord {
                content: candidate.content,
                kind: candidate.kind,
                content_type: candidate.kind.label().to_owned(),
                evidence_kind: "进程文本残留".to_owned(),
                confidence: "低".to_owned(),
                occurrences: candidate.occurrences,
                encodings,
                physical_addresses: candidate.physical_addresses,
                owners: Vec::new(),
                evidence_note: "文本已从物理内存恢复；该证据不表示文本曾进入剪切板".to_owned(),
            }
        })
        .collect::<Vec<_>>();
    records.sort_unstable_by(|left, right| {
        pre_mapping_score(right)
            .cmp(&pre_mapping_score(left))
            .then_with(|| left.content.cmp(&right.content))
    });
    if balance_pre_mapping_candidates(&mut records, residual_limit) {
        complete = false;
        push_warning(
            &mut warnings,
            format!("进程文本残留候选达到 {residual_limit} 条关联上限"),
        );
    }

    progress(ResidualScanStage::ProcessOwners);
    let owner_started = Instant::now();
    let processes = list_processes(image, kernel, profile, 65_536)?;
    complete &= processes.complete;
    warnings.extend(
        processes
            .warnings
            .iter()
            .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message)),
    );
    let process_address_spaces = associate_text_owners(
        image,
        &processes.processes,
        &mut records,
        options.process_space_limit,
        &mut warnings,
        &mut complete,
    )?;
    let owner_mapping_seconds = owner_started.elapsed().as_secs_f64();

    progress(ResidualScanStage::Classification);
    records.retain(|record| {
        record.kind == ClipboardResidualKind::ExactText
            || !record.owners.is_empty()
            || record.occurrences >= 4
    });
    for record in &mut records {
        classify_residual_confidence(record);
    }
    records.sort_unstable_by(|left, right| {
        residual_score(right)
            .cmp(&residual_score(left))
            .then_with(|| right.occurrences.cmp(&left.occurrences))
            .then_with(|| left.content.cmp(&right.content))
    });
    if balance_final_candidates(&mut records, options.limit) {
        complete = false;
        push_warning(
            &mut warnings,
            format!("文本残留达到 {} 条结果上限", options.limit),
        );
    }

    Ok(ResidualScanReport {
        records,
        raw_email_candidates,
        raw_residual_candidates,
        candidate_types,
        custom_searches: exact_patterns.len(),
        process_address_spaces,
        bytes_scanned: physical.bytes_scanned,
        physical_scan_seconds: physical.elapsed_seconds,
        owner_mapping_seconds,
        total_seconds: total_started.elapsed().as_secs_f64(),
        complete,
        warnings,
    })
}

fn select_session_spaces(processes: &[ProcessRecord]) -> Vec<SessionSpace> {
    fn priority(name: &str) -> u8 {
        if name.eq_ignore_ascii_case("csrss.exe") {
            6
        } else if name.eq_ignore_ascii_case("winlogon.exe") {
            5
        } else if name.eq_ignore_ascii_case("dwm.exe") {
            4
        } else if name.eq_ignore_ascii_case("explorer.exe") {
            3
        } else {
            1
        }
    }
    let mut selected = BTreeMap::<u32, (u8, SessionSpace)>::new();
    for process in processes {
        let Some(session_id) = process
            .details
            .session_id
            .or(process.details.token_session_id)
        else {
            continue;
        };
        let Some(dtb) = process
            .details
            .directory_table_base
            .or(process.details.user_directory_table_base)
            .map(|value| value & 0x000f_ffff_ffff_f000)
            .filter(|value| *value != 0)
        else {
            continue;
        };
        let rank = priority(&process.name);
        if selected
            .get(&session_id)
            .is_none_or(|(current, _)| rank > *current)
        {
            selected.insert(session_id, (rank, SessionSpace { session_id, dtb }));
        }
    }
    selected.into_values().map(|(_, session)| session).collect()
}

fn find_clip_array(
    space: &X64AddressSpace<'_>,
    station: &WindowStationRecord,
) -> Option<ClipArrayMatch> {
    let mut best: Option<ScoredClipArray> = None;
    for field_offset in (0..=0x3e8u64).step_by(8) {
        let Ok(pointer) = space.read_u64(station.address + field_offset) else {
            continue;
        };
        if !is_kernel_pointer(pointer) {
            continue;
        }
        let Some(count) = read_u32(space, station.address + field_offset + 8) else {
            continue;
        };
        let count = count as usize;
        if !(1..=104).contains(&count) {
            continue;
        }
        for stride in [0x20usize, 0x18usize] {
            let mut bytes = vec![0u8; count.checked_mul(stride)?];
            if space.read_virtual(pointer, &mut bytes).is_err() {
                continue;
            }
            let mut entries = Vec::with_capacity(count);
            let mut valid = 0usize;
            let mut standard = 0usize;
            let mut rendered = 0usize;
            for chunk in bytes.chunks_exact(stride) {
                let format_id = u32::from_le_bytes(chunk[0..4].try_into().ok()?);
                let handle = u64::from_le_bytes(chunk[8..16].try_into().ok()?);
                let global_handle = u32::from_le_bytes(chunk[16..20].try_into().ok()?);
                if valid_format(format_id) {
                    valid += 1;
                }
                if standard_format_name(format_id).is_some() {
                    standard += 1;
                }
                if handle != 0 {
                    rendered += 1;
                }
                entries.push((format_id, handle, global_handle));
            }
            if valid < count.saturating_mul(3).div_ceil(4) {
                continue;
            }
            let score = valid * 8 + standard * 3 + rendered + usize::from(stride == 0x20);
            let layout = ClipArrayLayout {
                pointer,
                field_offset,
                stride,
            };
            if best
                .as_ref()
                .is_none_or(|(current_score, ..)| score > *current_score)
            {
                best = Some((score, layout, entries));
            }
        }
    }
    best.map(|(_, layout, entries)| (layout, entries))
}

fn valid_format(format_id: u32) -> bool {
    (1..=17).contains(&format_id) || (0xc000..=0xffff).contains(&format_id)
}

fn standard_format_name(format_id: u32) -> Option<&'static str> {
    Some(match format_id {
        1 => "CF_TEXT",
        2 => "CF_BITMAP",
        3 => "CF_METAFILEPICT",
        4 => "CF_SYLK",
        5 => "CF_DIF",
        6 => "CF_TIFF",
        7 => "CF_OEMTEXT",
        8 => "CF_DIB",
        9 => "CF_PALETTE",
        10 => "CF_PENDATA",
        11 => "CF_RIFF",
        12 => "CF_WAVE",
        13 => "CF_UNICODETEXT",
        14 => "CF_ENHMETAFILE",
        15 => "CF_HDROP",
        16 => "CF_LOCALE",
        17 => "CF_DIBV5",
        _ => return None,
    })
}

fn recover_data_blocks(
    image: &MemoryImage,
    sessions: &[SessionSpace],
    pool_tags: &[u64],
    handles: &HashSet<u64>,
    max_data_size: usize,
) -> HashMap<u64, ClipboardDataBlock> {
    let candidates = pool_tags
        .iter()
        .filter(|tag| **tag & 0xf == 4)
        .filter_map(|tag| {
            let object = tag.checked_add(0x0c)?;
            let mut head = [0u8; 0x14];
            image.read_physical(object, &mut head).ok()?;
            let handle = u64::from_le_bytes(head[0..8].try_into().ok()?);
            let declared = u32::from_le_bytes(head[0x10..0x14].try_into().ok()?);
            (handles.contains(&handle) && declared > 0 && declared <= 64 * 1024 * 1024)
                .then_some((*tag, handle, declared))
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return HashMap::new();
    }
    let targets = candidates
        .iter()
        .map(|(tag, ..)| tag & !0xfff)
        .collect::<HashSet<_>>();
    let mut blocks = HashMap::new();
    for session in sessions {
        let Ok(space) = X64AddressSpace::new(image, session.dtb) else {
            continue;
        };
        let Ok(reverse) = space.reverse_translate_pages(&targets, VirtualAddressRegion::Kernel, 8)
        else {
            continue;
        };
        for (tag, expected_handle, expected_size) in &candidates {
            let Some(virtual_pages) = reverse.get(&(tag & !0xfff)) else {
                continue;
            };
            for page in virtual_pages {
                let object = page + (tag & 0xfff) + 0x0c;
                let Ok(handle) = space.read_u64(object) else {
                    continue;
                };
                let Some(declared) = read_u32(&space, object + 0x10) else {
                    continue;
                };
                if handle != *expected_handle || declared != *expected_size {
                    continue;
                }
                let take = usize::try_from(declared)
                    .unwrap_or(usize::MAX)
                    .min(max_data_size);
                let mut data = vec![0u8; take];
                if space.read_virtual(object + 0x14, &mut data).is_err() {
                    continue;
                }
                blocks.entry(handle).or_insert(ClipboardDataBlock {
                    object: Some(object),
                    physical_object: tag + 0x0c,
                    declared_size: declared,
                    data,
                    complete: take == declared as usize,
                });
            }
        }
    }
    for (tag, handle, declared) in candidates {
        if blocks.contains_key(&handle) {
            continue;
        }
        let take = usize::try_from(declared)
            .unwrap_or(usize::MAX)
            .min(max_data_size);
        let mut data = vec![0u8; take];
        if image.read_physical(tag + 0x20, &mut data).is_ok() {
            blocks.insert(
                handle,
                ClipboardDataBlock {
                    object: None,
                    physical_object: tag + 0x0c,
                    declared_size: declared,
                    data,
                    complete: take == declared as usize,
                },
            );
        }
    }
    blocks
}

fn format_record(
    entry: StructuredEntry,
    block: Option<&ClipboardDataBlock>,
) -> ClipboardFormatRecord {
    let format_name = standard_format_name(entry.format_id)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("已注册格式 {:#06x}", entry.format_id));
    let (content_type, content) = block
        .map(|block| decode_clipboard_content(entry.format_id, &block.data))
        .unwrap_or_else(|| ("无驻留数据".to_owned(), None));
    let sha256 = block.map(|block| hex::encode(Sha256::digest(&block.data)));
    ClipboardFormatRecord {
        session_id: entry.station.session_id,
        window_station: entry.station.name,
        window_station_address: entry.station.address,
        clip_base: entry.array.pointer,
        clip_base_field_offset: entry.array.field_offset,
        entry_layout: format!("{} 字节", entry.array.stride),
        format_id: entry.format_id,
        format_name,
        handle: entry.handle,
        global_handle: entry.global_handle,
        delayed_render: entry.handle == 0,
        data_object: block.and_then(|block| block.object),
        data_physical_address: block.map(|block| block.physical_object),
        data_size: block.map(|block| block.declared_size),
        recovered_size: block.map_or(0, |block| block.data.len()),
        data_complete: block.is_some_and(|block| block.complete),
        content_type,
        content,
        sha256,
        confidence: if block.is_some() {
            "高".to_owned()
        } else {
            "中".to_owned()
        },
    }
}

fn decode_clipboard_content(format_id: u32, data: &[u8]) -> (String, Option<String>) {
    if format_id == 13 {
        return (
            "Unicode 文本".to_owned(),
            decode_utf16_text(data).map(|value| truncate_text(&value, 4096)),
        );
    }
    if format_id == 1 || format_id == 7 {
        return (
            "文本".to_owned(),
            decode_ascii_text(data).map(|value| truncate_text(&value, 4096)),
        );
    }
    if format_id == 15
        && let Some(paths) = decode_hdrop(data)
    {
        return ("文件列表".to_owned(), Some(truncate_text(&paths, 4096)));
    }
    if data.starts_with(b"{\\rtf") {
        return (
            "RTF".to_owned(),
            Some(truncate_text(&String::from_utf8_lossy(data), 4096)),
        );
    }
    if data.starts_with(b"Version:") || memmem::find(data, b"StartHTML:").is_some() {
        return (
            "HTML".to_owned(),
            Some(truncate_text(&String::from_utf8_lossy(data), 4096)),
        );
    }
    if let Some(text) = decode_utf16_text(data)
        && printable_ratio(&text) >= 0.85
    {
        return ("Unicode 文本".to_owned(), Some(truncate_text(&text, 4096)));
    }
    if let Some(text) = decode_ascii_text(data)
        && printable_ratio(&text) >= 0.85
    {
        return ("文本".to_owned(), Some(truncate_text(&text, 4096)));
    }
    let preview = data
        .iter()
        .take(128)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    (
        "二进制".to_owned(),
        (!preview.is_empty()).then_some(preview),
    )
}

fn decode_hdrop(data: &[u8]) -> Option<String> {
    let offset = usize::try_from(u32::from_le_bytes(data.get(0..4)?.try_into().ok()?)).ok()?;
    let wide = *data.get(16)? != 0;
    let payload = data.get(offset..)?;
    let values = if wide {
        let units = payload
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        units
            .split(|unit| *unit == 0)
            .take_while(|value| !value.is_empty())
            .map(String::from_utf16_lossy)
            .collect::<Vec<_>>()
    } else {
        payload
            .split(|byte| *byte == 0)
            .take_while(|value| !value.is_empty())
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .collect::<Vec<_>>()
    };
    (!values.is_empty()).then(|| values.join("\n"))
}

fn decode_utf16_text(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    let units = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .take(65_536)
        .collect::<Vec<_>>();
    if units.len() < 2 {
        return None;
    }
    String::from_utf16(&units).ok()
}

fn decode_ascii_text(data: &[u8]) -> Option<String> {
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    let bytes = data.get(..end)?;
    if bytes.len() < 2 {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn printable_ratio(value: &str) -> f64 {
    let total = value.chars().count();
    if total == 0 {
        return 0.0;
    }
    let printable = value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\r' | '\n' | '\t'))
        .count();
    printable as f64 / total as f64
}

fn truncate_text(value: &str, limit: usize) -> String {
    let mut output = value.chars().take(limit).collect::<String>();
    if value.chars().count() > limit {
        output.push_str("...");
    }
    output
}

fn scan_physical_candidates(
    image: &MemoryImage,
    exact_patterns: &[ExactTextPattern],
    mode: PhysicalScanMode,
    cancellation: &CancellationToken,
) -> Result<PhysicalScanResult> {
    cancellation.check_cancelled()?;
    let work = scan_work(image)?;
    // Scanning a RAW image through the persistent mmap faults the whole image
    // into the host working set. A large clipboard scan then trips Lovelymem's
    // memory guard even though the returned evidence is tiny. Uscb scanning
    // uses bounded reads (positional file reads on Windows) instead.
    let direct = if mode.pool_tags {
        None
    } else {
        image.direct_bytes()
    };
    let pattern_scanner = mode
        .residual_text
        .then(|| prepare_pattern_scanner(exact_patterns))
        .transpose()?;
    let started = Instant::now();
    let partial = work
        .par_iter()
        .map(|work| -> Result<PhysicalScanPartial> {
            cancellation.check_cancelled()?;
            let mut buffered = Vec::new();
            let bytes = if let Some(direct) = direct {
                let start = usize::try_from(work.file_start)?;
                direct.get(start..start + work.scan_len).ok_or_else(|| {
                    anyhow::anyhow!("镜像扫描块在文件偏移 {:#x} 处被截断", work.file_start)
                })?
            } else {
                buffered.resize(work.scan_len, 0);
                image.read_physical(work.physical_start, &mut buffered)?;
                &buffered
            };
            let core_start = work.prefix;
            let core_end = core_start + work.core_len;
            let mut tags = Vec::new();
            if mode.pool_tags {
                for relative in memchr_iter(b'U', bytes) {
                    if relative < core_start || relative >= core_end {
                        continue;
                    }
                    if bytes.get(relative..relative + 4) == Some(b"Uscb") {
                        tags.push(work.physical_start + relative as u64);
                    }
                }
            }
            let mut candidates = ResidualMap::new();
            if let Some(pattern_scanner) = &pattern_scanner {
                for at in memchr_iter(b'@', bytes) {
                    if at < core_start || at >= core_end {
                        continue;
                    }
                    if let Some((start, end, content)) = extract_ascii_email(bytes, at) {
                        record_text(
                            &mut candidates,
                            ClipboardResidualKind::Email,
                            content,
                            work.physical_start + start as u64,
                            ClipboardTextEncoding::Ascii,
                        );
                        debug_assert!(end > start);
                    }
                    if let Some((start, end, content)) = extract_utf16_email(bytes, at) {
                        record_text(
                            &mut candidates,
                            ClipboardResidualKind::Email,
                            content,
                            work.physical_start + start as u64,
                            ClipboardTextEncoding::Utf16Le,
                        );
                        debug_assert!(end > start);
                    }
                }
                scan_pattern_candidates(
                    bytes,
                    core_start,
                    core_end,
                    work.physical_start,
                    pattern_scanner,
                    exact_patterns,
                    &mut candidates,
                );
                scan_ipv4_addresses(
                    bytes,
                    core_start,
                    core_end,
                    work.physical_start,
                    &mut candidates,
                );
                scan_windows_paths(
                    bytes,
                    core_start,
                    core_end,
                    work.physical_start,
                    &mut candidates,
                );
            }
            cancellation.check_cancelled()?;
            Ok((tags, candidates))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut pool_tags = Vec::new();
    let mut merged = ResidualMap::new();
    for (mut tags, candidates) in partial {
        pool_tags.append(&mut tags);
        for (key, mut candidate) in candidates {
            let entry = merged.entry(key).or_insert_with(|| TextAggregate {
                content: candidate.content.clone(),
                kind: candidate.kind,
                occurrences: 0,
                ascii: false,
                utf8: false,
                utf16: false,
                physical_addresses: Vec::new(),
            });
            entry.occurrences += candidate.occurrences;
            entry.ascii |= candidate.ascii;
            entry.utf8 |= candidate.utf8;
            entry.utf16 |= candidate.utf16;
            entry
                .physical_addresses
                .append(&mut candidate.physical_addresses);
            entry.physical_addresses.sort_unstable();
            entry.physical_addresses.dedup();
            entry.physical_addresses.truncate(MAX_TEXT_ADDRESSES);
        }
    }
    pool_tags.sort_unstable();
    pool_tags.dedup();
    let mut residuals = merged.into_values().collect::<Vec<_>>();
    residuals.sort_unstable_by(|left, right| {
        right
            .occurrences
            .cmp(&left.occurrences)
            .then_with(|| left.kind.label().cmp(right.kind.label()))
            .then_with(|| left.content.cmp(&right.content))
    });
    Ok(PhysicalScanResult {
        pool_tags,
        residuals,
        bytes_scanned: work.iter().map(|work| work.core_len as u64).sum(),
        elapsed_seconds: started.elapsed().as_secs_f64(),
    })
}

fn scan_work(image: &MemoryImage) -> Result<Vec<ScanWork>> {
    let mut work = Vec::new();
    for span in image.spans() {
        let mut core_offset = 0u64;
        while core_offset < span.length {
            let core_len =
                usize::try_from((span.length - core_offset).min(SCAN_CHUNK_SIZE as u64))?;
            let prefix = usize::try_from(core_offset.min(SCAN_OVERLAP as u64))?;
            let suffix = usize::try_from(
                (span.length - core_offset - core_len as u64).min(SCAN_OVERLAP as u64),
            )?;
            work.push(ScanWork {
                physical_start: span.start + core_offset - prefix as u64,
                file_start: span.file_offset + core_offset - prefix as u64,
                prefix,
                core_len,
                scan_len: prefix + core_len + suffix,
            });
            core_offset += core_len as u64;
        }
    }
    Ok(work)
}

fn prepare_exact_text_patterns(values: &[String]) -> Result<Vec<ExactTextPattern>> {
    let mut seen = HashSet::new();
    let mut patterns = Vec::new();
    for value in values {
        ensure!(value.chars().count() >= 2, "精确搜索文本至少需要 2 个字符");
        ensure!(
            value.chars().count() <= 512,
            "单条精确搜索文本最多允许 512 个字符"
        );
        if !seen.insert(value.clone()) {
            continue;
        }
        patterns.push(ExactTextPattern {
            content: value.clone(),
            utf8: value.as_bytes().to_vec(),
            utf16: value.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            utf8_encoding: if value.is_ascii() {
                ClipboardTextEncoding::Ascii
            } else {
                ClipboardTextEncoding::Utf8
            },
        });
    }
    Ok(patterns)
}

fn prepare_pattern_scanner(exact_patterns: &[ExactTextPattern]) -> Result<PatternScanner> {
    let mut patterns = Vec::<Vec<u8>>::new();
    let mut actions = Vec::<Vec<PatternAction>>::new();
    let mut indices = HashMap::<Vec<u8>, usize>::new();
    let mut add = |pattern: Vec<u8>, action: PatternAction| {
        if let Some(index) = indices.get(&pattern).copied() {
            actions[index].push(action);
        } else {
            let index = patterns.len();
            indices.insert(pattern.clone(), index);
            patterns.push(pattern);
            actions.push(vec![action]);
        }
    };
    for prefix in ["https://", "http://", "ftp://"] {
        add(
            prefix.as_bytes().to_vec(),
            PatternAction::Url(ClipboardTextEncoding::Ascii),
        );
        add(
            prefix.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            PatternAction::Url(ClipboardTextEncoding::Utf16Le),
        );
    }
    for prefix in command_prefixes() {
        add(
            prefix.as_bytes().to_vec(),
            PatternAction::Command(ClipboardTextEncoding::Ascii),
        );
        add(
            prefix.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            PatternAction::Command(ClipboardTextEncoding::Utf16Le),
        );
    }
    for (index, pattern) in exact_patterns.iter().enumerate() {
        add(
            pattern.utf8.clone(),
            PatternAction::Exact(index, pattern.utf8_encoding),
        );
        add(
            pattern.utf16.clone(),
            PatternAction::Exact(index, ClipboardTextEncoding::Utf16Le),
        );
    }
    let matcher = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .build(patterns.iter())?;
    Ok(PatternScanner { matcher, actions })
}

fn scan_pattern_candidates(
    bytes: &[u8],
    core_start: usize,
    core_end: usize,
    physical_start: u64,
    scanner: &PatternScanner,
    exact_patterns: &[ExactTextPattern],
    candidates: &mut ResidualMap,
) {
    for matched in scanner.matcher.find_overlapping_iter(bytes) {
        let start = matched.start();
        if !in_core(start, core_start, core_end) {
            continue;
        }
        for action in &scanner.actions[matched.pattern().as_usize()] {
            let recovered = match action {
                PatternAction::Url(ClipboardTextEncoding::Ascii) => extract_ascii_url(bytes, start),
                PatternAction::Url(ClipboardTextEncoding::Utf16Le) => {
                    extract_utf16_url(bytes, start)
                }
                PatternAction::Command(ClipboardTextEncoding::Ascii) => {
                    extract_ascii_command(bytes, start)
                }
                PatternAction::Command(ClipboardTextEncoding::Utf16Le) => {
                    extract_utf16_command(bytes, start)
                }
                PatternAction::Exact(index, encoding) => {
                    let pattern = &exact_patterns[*index];
                    record_text(
                        candidates,
                        ClipboardResidualKind::ExactText,
                        pattern.content.clone(),
                        physical_start + start as u64,
                        *encoding,
                    );
                    None
                }
                PatternAction::Url(ClipboardTextEncoding::Utf8)
                | PatternAction::Command(ClipboardTextEncoding::Utf8) => None,
            };
            let Some((end, content)) = recovered else {
                continue;
            };
            let (kind, encoding) = match action {
                PatternAction::Url(encoding) => (ClipboardResidualKind::Url, *encoding),
                PatternAction::Command(encoding) => (ClipboardResidualKind::Command, *encoding),
                PatternAction::Exact(..) => continue,
            };
            record_text(
                candidates,
                kind,
                content,
                physical_start + start as u64,
                encoding,
            );
            debug_assert!(end > start);
        }
    }
}

fn extract_ascii_url(bytes: &[u8], start: usize) -> Option<(usize, String)> {
    let mut end = start;
    while end < bytes.len() && end - start < 2048 && is_url_byte(bytes[end]) {
        end += 1;
    }
    while end > start && matches!(bytes[end - 1], b'.' | b',' | b';' | b')' | b']' | b'}') {
        end -= 1;
    }
    let value = std::str::from_utf8(bytes.get(start..end)?).ok()?;
    validate_url(value)?;
    Some((end, value.to_owned()))
}

fn extract_utf16_url(bytes: &[u8], start: usize) -> Option<(usize, String)> {
    let mut units = Vec::new();
    let mut end = start;
    while end + 1 < bytes.len() && units.len() < 2048 {
        let unit = u16::from_le_bytes([bytes[end], bytes[end + 1]]);
        if unit > 0x7f || !is_url_byte(unit as u8) {
            break;
        }
        units.push(unit);
        end += 2;
    }
    while matches!(units.last(), Some(unit) if matches!(*unit as u8, b'.' | b',' | b';' | b')' | b']' | b'}'))
    {
        units.pop();
        end -= 2;
    }
    let value = String::from_utf16(&units).ok()?;
    validate_url(&value)?;
    Some((end, value))
}

fn is_url_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\'' | b'<' | b'>' | b'{' | b'}' | b'\\')
}

fn validate_url(value: &str) -> Option<()> {
    let (_, rest) = value.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split_once(']')?.0
    } else {
        authority.split(':').next()?
    };
    if host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok() {
        return Some(());
    }
    let labels = host.split('.').collect::<Vec<_>>();
    let tld = labels.last()?;
    if labels.len() < 2
        || !(2..=63).contains(&tld.len())
        || !tld.bytes().all(|byte| byte.is_ascii_alphabetic())
        || labels.iter().any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(())
}

fn scan_ipv4_addresses(
    bytes: &[u8],
    core_start: usize,
    core_end: usize,
    physical_start: u64,
    candidates: &mut ResidualMap,
) {
    for dot in memchr_iter(b'.', bytes) {
        if let Some((start, end, content)) = extract_ascii_ipv4(bytes, dot)
            && in_core(start, core_start, core_end)
        {
            record_text(
                candidates,
                ClipboardResidualKind::Ipv4,
                content,
                physical_start + start as u64,
                ClipboardTextEncoding::Ascii,
            );
            debug_assert!(end > start);
        }
        if let Some((start, end, content)) = extract_utf16_ipv4(bytes, dot)
            && in_core(start, core_start, core_end)
        {
            record_text(
                candidates,
                ClipboardResidualKind::Ipv4,
                content,
                physical_start + start as u64,
                ClipboardTextEncoding::Utf16Le,
            );
            debug_assert!(end > start);
        }
    }
}

fn extract_ascii_ipv4(bytes: &[u8], first_dot: usize) -> Option<(usize, usize, String)> {
    let mut start = first_dot;
    while start > 0 && first_dot - start < 3 && bytes[start - 1].is_ascii_digit() {
        start -= 1;
    }
    if start == first_dot
        || start
            .checked_sub(1)
            .and_then(|index| bytes.get(index))
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'.')
    {
        return None;
    }
    let mut end = first_dot + 1;
    while end < bytes.len()
        && end - start <= 15
        && (bytes[end].is_ascii_digit() || bytes[end] == b'.')
    {
        end += 1;
    }
    if bytes
        .get(end)
        .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'.')
    {
        return None;
    }
    let value = std::str::from_utf8(bytes.get(start..end)?).ok()?;
    validate_ipv4(value)?;
    Some((start, end, value.to_owned()))
}

fn extract_utf16_ipv4(bytes: &[u8], dot: usize) -> Option<(usize, usize, String)> {
    if bytes.get(dot + 1) != Some(&0) {
        return None;
    }
    let mut start = dot;
    while start >= 2
        && dot - start < 30
        && bytes[start - 1] == 0
        && (bytes[start - 2].is_ascii_digit() || bytes[start - 2] == b'.')
    {
        start -= 2;
    }
    let mut end = dot;
    while end + 1 < bytes.len()
        && end - start < 30
        && bytes[end + 1] == 0
        && (bytes[end].is_ascii_digit() || bytes[end] == b'.')
    {
        end += 2;
    }
    let compact = bytes[start..end]
        .chunks_exact(2)
        .map(|pair| pair[0])
        .collect::<Vec<_>>();
    if compact.iter().position(|byte| *byte == b'.')? * 2 + start != dot {
        return None;
    }
    let value = String::from_utf8(compact).ok()?;
    validate_ipv4(&value)?;
    Some((start, end, value))
}

fn validate_ipv4(value: &str) -> Option<()> {
    let octets = value
        .split('.')
        .map(|part| {
            if part.is_empty() || part.len() > 3 || (part.len() > 1 && part.starts_with('0')) {
                return None;
            }
            part.parse::<u8>().ok()
        })
        .collect::<Option<Vec<_>>>()?;
    if octets.len() != 4
        || octets == [0, 0, 0, 0]
        || octets == [255, 255, 255, 255]
        || octets.get(1..) == Some([0, 0, 0].as_slice())
        || octets.get(..2) == Some([2, 5].as_slice())
    {
        return None;
    }
    Some(())
}

fn scan_windows_paths(
    bytes: &[u8],
    core_start: usize,
    core_end: usize,
    physical_start: u64,
    candidates: &mut ResidualMap,
) {
    for colon in memchr_iter(b':', bytes) {
        if let Some((start, end, content)) = extract_ascii_windows_path(bytes, colon)
            && in_core(start, core_start, core_end)
        {
            record_text(
                candidates,
                ClipboardResidualKind::WindowsPath,
                content,
                physical_start + start as u64,
                ClipboardTextEncoding::Ascii,
            );
            debug_assert!(end > start);
        }
        if let Some((start, end, content)) = extract_utf16_windows_path(bytes, colon)
            && in_core(start, core_start, core_end)
        {
            record_text(
                candidates,
                ClipboardResidualKind::WindowsPath,
                content,
                physical_start + start as u64,
                ClipboardTextEncoding::Utf16Le,
            );
            debug_assert!(end > start);
        }
    }
}

fn extract_ascii_windows_path(bytes: &[u8], colon: usize) -> Option<(usize, usize, String)> {
    let start = colon.checked_sub(1)?;
    if !bytes[start].is_ascii_alphabetic()
        || !matches!(bytes.get(colon + 1), Some(b'\\' | b'/'))
        || start
            .checked_sub(1)
            .and_then(|index| bytes.get(index))
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return None;
    }
    let mut end = colon + 2;
    while end < bytes.len() && end - start < 512 && is_ascii_path_byte(bytes[end]) {
        end += 1;
    }
    while end > colon + 2 && matches!(bytes[end - 1], b' ' | b'.' | b',' | b';' | b')' | b']') {
        end -= 1;
    }
    if end <= colon + 2 || end - start < 6 {
        return None;
    }
    let value = std::str::from_utf8(bytes.get(start..end)?).ok()?.to_owned();
    validate_windows_path(&value)?;
    Some((start, end, value))
}

fn extract_utf16_windows_path(bytes: &[u8], colon: usize) -> Option<(usize, usize, String)> {
    let start = colon.checked_sub(2)?;
    if bytes.get(colon + 1) != Some(&0)
        || bytes.get(start + 1) != Some(&0)
        || !bytes[start].is_ascii_alphabetic()
        || bytes.get(colon + 3) != Some(&0)
        || !matches!(bytes.get(colon + 2), Some(b'\\' | b'/'))
        || (start >= 2 && bytes[start - 1] == 0 && bytes[start - 2].is_ascii_alphanumeric())
    {
        return None;
    }
    let mut units = Vec::new();
    let mut end = start;
    while end + 1 < bytes.len() && units.len() < 512 {
        let unit = u16::from_le_bytes([bytes[end], bytes[end + 1]]);
        if !is_utf16_path_unit(unit) {
            break;
        }
        units.push(unit);
        end += 2;
    }
    while matches!(units.last(), Some(unit) if matches!(*unit, 0x20 | 0x2e | 0x2c | 0x3b | 0x29 | 0x5d))
    {
        units.pop();
        end -= 2;
    }
    if units.len() < 6 {
        return None;
    }
    let value = String::from_utf16(&units).ok()?;
    validate_windows_path(&value)?;
    Some((start, end, value))
}

fn validate_windows_path(value: &str) -> Option<()> {
    if value
        .split(['\\', '/'])
        .any(|segment| segment.chars().count() > 255)
        || value
            .bytes()
            .filter(|byte| matches!(byte, b'=' | b'@'))
            .count()
            >= 2
    {
        return None;
    }
    Some(())
}

fn is_ascii_path_byte(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e)
        && !matches!(byte, b'"' | b'<' | b'>' | b'|' | b'\r' | b'\n' | b'\t')
}

fn is_utf16_path_unit(unit: u16) -> bool {
    unit >= 0x20 && !matches!(unit, 0x22 | 0x3c | 0x3e | 0x7c | 0x7f)
}

fn command_prefixes() -> &'static [&'static str] {
    &[
        "powershell ",
        "powershell.exe ",
        "PowerShell ",
        "pwsh ",
        "cmd.exe ",
        "cmd /c ",
        "net user ",
        "net localgroup ",
        "whoami ",
        "ipconfig ",
        "systeminfo ",
        "schtasks ",
        "reg add ",
        "certutil ",
        "bitsadmin ",
        "curl ",
        "wget ",
        "Invoke-WebRequest ",
        "invoke-webrequest ",
        "iwr ",
        "wmic ",
    ]
}

fn extract_ascii_command(bytes: &[u8], start: usize) -> Option<(usize, String)> {
    if start
        .checked_sub(1)
        .and_then(|index| bytes.get(index))
        .is_some_and(u8::is_ascii_alphanumeric)
    {
        return None;
    }
    let mut end = start;
    while end < bytes.len()
        && end - start < 512
        && matches!(bytes[end], 0x20..=0x7e | b'\t')
        && !matches!(bytes[end], b'\r' | b'\n' | 0)
    {
        end += 1;
    }
    let value = std::str::from_utf8(bytes.get(start..end)?).ok()?.trim_end();
    validate_command(value)?;
    Some((start + value.len(), value.to_owned()))
}

fn extract_utf16_command(bytes: &[u8], start: usize) -> Option<(usize, String)> {
    if start >= 2 && bytes[start - 1] == 0 && bytes[start - 2].is_ascii_alphanumeric() {
        return None;
    }
    let mut units = Vec::new();
    let mut end = start;
    while end + 1 < bytes.len() && units.len() < 512 {
        let unit = u16::from_le_bytes([bytes[end], bytes[end + 1]]);
        if unit == 0 || matches!(unit, 0x0a | 0x0d) || (unit < 0x20 && unit != 0x09) {
            break;
        }
        units.push(unit);
        end += 2;
    }
    while matches!(units.last(), Some(0x20 | 0x09)) {
        units.pop();
        end -= 2;
    }
    let value = String::from_utf16(&units).ok()?;
    validate_command(&value)?;
    Some((end, value))
}

fn validate_command(value: &str) -> Option<()> {
    let lower = value.to_ascii_lowercase();
    if value.len() < 5
        || value.len() > 512
        || matches!(
            lower.as_str(),
            "powershell" | "powershell.exe" | "pwsh" | "cmd" | "cmd.exe"
        )
        || lower.contains("for new features and improvements")
        || lower.contains("usage:")
        || lower.contains("example:")
        || lower.contains("documentation")
        || lower.contains("engine core assembly")
        || lower.contains("console file")
        || lower.contains("cmdlets that")
        || lower.contains("object.defineproperty")
        || lower.contains("function(")
        || lower.contains("=>")
        || lower.ends_with(".lnk")
    {
        return None;
    }
    if let Some(arguments) = lower
        .strip_prefix("powershell.exe ")
        .or_else(|| lower.strip_prefix("powershell "))
        .or_else(|| lower.strip_prefix("pwsh "))
        && !matches!(arguments.as_bytes().first(), Some(b'-' | b'/'))
    {
        return None;
    }
    if let Some(arguments) = lower
        .strip_prefix("cmd.exe ")
        .or_else(|| lower.strip_prefix("cmd "))
        && !["/c ", "/k ", "/s "]
            .iter()
            .any(|prefix| arguments.starts_with(prefix))
    {
        return None;
    }
    Some(())
}

fn in_core(start: usize, core_start: usize, core_end: usize) -> bool {
    (core_start..core_end).contains(&start)
}

fn extract_ascii_email(bytes: &[u8], at: usize) -> Option<(usize, usize, String)> {
    if at == 0 || !is_domain_byte(*bytes.get(at + 1)?) {
        return None;
    }
    let mut start = at;
    while start > 0 && at - start < 64 && is_local_byte(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = at + 1;
    while end < bytes.len() && end - at <= 255 && is_domain_byte(bytes[end]) {
        end += 1;
    }
    validate_email_bytes(bytes.get(start..end)?)?;
    let value = std::str::from_utf8(bytes.get(start..end)?).ok()?.to_owned();
    Some((start, end, value))
}

fn extract_utf16_email(bytes: &[u8], at: usize) -> Option<(usize, usize, String)> {
    if at + 3 >= bytes.len() || bytes[at + 1] != 0 || !is_domain_byte(bytes[at + 2]) {
        return None;
    }
    let mut start = at;
    while start >= 2
        && (at - start) / 2 < 64
        && bytes[start - 1] == 0
        && is_local_byte(bytes[start - 2])
    {
        start -= 2;
    }
    let mut end = at + 2;
    while end + 1 < bytes.len()
        && (end - at) / 2 <= 255
        && bytes[end + 1] == 0
        && is_domain_byte(bytes[end])
    {
        end += 2;
    }
    let compact = bytes[start..end]
        .chunks_exact(2)
        .map(|pair| pair[0])
        .collect::<Vec<_>>();
    validate_email_bytes(&compact)?;
    let value = String::from_utf8(compact).ok()?;
    Some((start, end, value))
}

fn validate_email_bytes(value: &[u8]) -> Option<()> {
    let at = value.iter().position(|byte| *byte == b'@')?;
    let local = value.get(..at)?;
    let domain = value.get(at + 1..)?;
    if local.is_empty()
        || domain.len() < 4
        || local.first() == Some(&b'.')
        || local.last() == Some(&b'.')
        || domain.first() == Some(&b'.')
        || domain.last() == Some(&b'.')
        || local.windows(2).any(|pair| pair == b"..")
        || domain.windows(2).any(|pair| pair == b"..")
    {
        return None;
    }
    let dot = domain.iter().rposition(|byte| *byte == b'.')?;
    let tld = domain.get(dot + 1..)?;
    if !(2..=24).contains(&tld.len())
        || !tld.iter().all(u8::is_ascii_lowercase)
        || matches!(
            tld.to_ascii_lowercase().as_slice(),
            b"css"
                | b"dll"
                | b"exe"
                | b"gif"
                | b"htm"
                | b"html"
                | b"jpeg"
                | b"jpg"
                | b"js"
                | b"json"
                | b"png"
                | b"svg"
                | b"sys"
                | b"txt"
                | b"xml"
                | b"xpi"
        )
    {
        return None;
    }
    if domain.split(|byte| *byte == b'.').any(|label| {
        label.is_empty() || label.first() == Some(&b'-') || label.last() == Some(&b'-')
    }) {
        return None;
    }
    Some(())
}

fn is_local_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_domain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

fn record_text(
    candidates: &mut ResidualMap,
    kind: ClipboardResidualKind,
    content: String,
    physical_address: u64,
    encoding: ClipboardTextEncoding,
) {
    let normalized = if kind == ClipboardResidualKind::ExactText {
        content.clone()
    } else {
        content.to_ascii_lowercase()
    };
    let entry = candidates
        .entry((kind, normalized))
        .or_insert_with(|| TextAggregate {
            content,
            kind,
            occurrences: 0,
            ascii: false,
            utf8: false,
            utf16: false,
            physical_addresses: Vec::new(),
        });
    entry.occurrences += 1;
    match encoding {
        ClipboardTextEncoding::Ascii => entry.ascii = true,
        ClipboardTextEncoding::Utf8 => entry.utf8 = true,
        ClipboardTextEncoding::Utf16Le => entry.utf16 = true,
    }
    if entry.physical_addresses.len() < MAX_TEXT_ADDRESSES
        && !entry.physical_addresses.contains(&physical_address)
    {
        entry.physical_addresses.push(physical_address);
    }
}

fn text_encodings(candidate: &TextAggregate) -> Vec<ClipboardTextEncoding> {
    let mut encodings = Vec::new();
    if candidate.ascii {
        encodings.push(ClipboardTextEncoding::Ascii);
    }
    if candidate.utf8 {
        encodings.push(ClipboardTextEncoding::Utf8);
    }
    if candidate.utf16 {
        encodings.push(ClipboardTextEncoding::Utf16Le);
    }
    encodings
}

fn associate_text_owners(
    image: &MemoryImage,
    processes: &[ProcessRecord],
    records: &mut [ClipboardTextRecord],
    process_space_limit: usize,
    warnings: &mut Vec<String>,
    complete: &mut bool,
) -> Result<usize> {
    let targets = records
        .iter()
        .flat_map(|record| record.physical_addresses.iter())
        .map(|address| address & !0xfff)
        .collect::<HashSet<_>>();
    if targets.is_empty() {
        return Ok(0);
    }
    let mut spaces = HashMap::<u64, Vec<(u64, String, u8)>>::new();
    for process in processes {
        let Some(dtb) = process
            .details
            .user_directory_table_base
            .or(process.details.directory_table_base)
            .map(|value| value & 0x000f_ffff_ffff_f000)
            .filter(|value| *value != 0)
        else {
            continue;
        };
        spaces.entry(dtb).or_default().push((
            process.pid,
            process.name.clone(),
            owner_process_priority(&process.name),
        ));
    }
    let mut spaces = spaces.into_iter().collect::<Vec<_>>();
    spaces.sort_unstable_by(|(left_dtb, left), (right_dtb, right)| {
        right
            .iter()
            .map(|owner| owner.2)
            .max()
            .cmp(&left.iter().map(|owner| owner.2).max())
            .then_with(|| left_dtb.cmp(right_dtb))
    });
    if spaces.len() > process_space_limit {
        *complete = false;
        push_warning(
            warnings,
            format!(
                "发现 {} 个进程地址空间；按交互相关性分析前 {process_space_limit} 个",
                spaces.len()
            ),
        );
        spaces.truncate(process_space_limit);
    }
    let mut records_by_page = HashMap::<u64, Vec<(usize, u64)>>::new();
    for (record_index, record) in records.iter().enumerate() {
        for address in &record.physical_addresses {
            records_by_page
                .entry(address & !0xfff)
                .or_default()
                .push((record_index, address & 0xfff));
        }
    }
    let mut examined = 0usize;
    for (dtb, owners) in &spaces {
        examined += 1;
        let reverse = match X64AddressSpace::new(image, *dtb).and_then(|space| {
            space.reverse_translate_pages(&targets, VirtualAddressRegion::User, 8)
        }) {
            Ok(reverse) => reverse,
            Err(error) => {
                *complete = false;
                push_warning(
                    warnings,
                    format!("无法反向映射进程 DTB {dtb:#x}：{error:#}"),
                );
                continue;
            }
        };
        for (physical_page, virtual_pages) in reverse {
            let Some(record_refs) = records_by_page.get(&physical_page) else {
                continue;
            };
            for (record_index, delta) in record_refs {
                for (pid, process, _) in owners {
                    for virtual_page in &virtual_pages {
                        records[*record_index].owners.push(ClipboardOwner {
                            pid: *pid,
                            process: process.clone(),
                            virtual_address: virtual_page + *delta,
                        });
                    }
                }
            }
        }
    }
    for record in records {
        record
            .owners
            .sort_unstable_by_key(|owner| (owner.pid, owner.virtual_address));
        record
            .owners
            .dedup_by_key(|owner| (owner.pid, owner.virtual_address));
        record.owners.truncate(MAX_OWNERS);
    }
    Ok(examined)
}

fn owner_process_priority(name: &str) -> u8 {
    let name = name.to_ascii_lowercase();
    if ["mail", "outlook", "thunderbird", "proton"]
        .iter()
        .any(|needle| name.contains(needle))
    {
        8
    } else if [
        "chrome",
        "edge",
        "firefox",
        "brave",
        "opera",
        "wechat",
        "weixin",
        "qq",
        "telegram",
        "powershell",
        "pwsh",
        "cmd.exe",
        "conhost",
        "openconsole",
        "windowsterminal",
    ]
    .iter()
    .any(|needle| name.contains(needle))
    {
        7
    } else if ["explorer", "textinput", "rdpclip", "notepad"]
        .iter()
        .any(|needle| name.contains(needle))
    {
        6
    } else {
        1
    }
}

fn pre_mapping_score(record: &ClipboardTextRecord) -> usize {
    let kind = match record.kind {
        ClipboardResidualKind::ExactText => 6_000_000,
        ClipboardResidualKind::Command => 5_000_000,
        ClipboardResidualKind::Url => 4_000_000,
        ClipboardResidualKind::WindowsPath => 3_000_000,
        ClipboardResidualKind::Email => 2_000_000,
        ClipboardResidualKind::Ipv4 => 1_000_000,
    };
    let occurrence = match record.kind {
        ClipboardResidualKind::Email | ClipboardResidualKind::ExactText => {
            record.occurrences.min(999_999)
        }
        _ => match record.occurrences {
            2..=64 => 999_999 - record.occurrences,
            1 => 900_000,
            65..=256 => 700_000 - record.occurrences,
            _ => 0,
        },
    };
    kind + occurrence
}

fn balance_pre_mapping_candidates(records: &mut Vec<ClipboardTextRecord>, limit: usize) -> bool {
    if records.len() <= limit {
        return false;
    }
    let per_kind = (limit / 6).max(1);
    let mut counts = [0usize; 6];
    let mut selected = Vec::with_capacity(limit);
    let mut overflow = Vec::new();
    for record in records.drain(..) {
        let index = residual_kind_index(record.kind);
        if counts[index] < per_kind {
            counts[index] += 1;
            selected.push(record);
        } else {
            overflow.push(record);
        }
    }
    let remaining = limit.saturating_sub(selected.len());
    selected.extend(overflow.into_iter().take(remaining));
    *records = selected;
    true
}

fn balance_final_candidates(records: &mut Vec<ClipboardTextRecord>, limit: usize) -> bool {
    if records.len() <= limit {
        return false;
    }
    let per_kind = (limit / 20).clamp(1, 64);
    let mut counts = [0usize; 6];
    let mut selected = Vec::with_capacity(limit);
    let mut overflow = Vec::new();
    for record in records.drain(..) {
        let index = residual_kind_index(record.kind);
        if counts[index] < per_kind {
            counts[index] += 1;
            selected.push(record);
        } else {
            overflow.push(record);
        }
    }
    let remaining = limit.saturating_sub(selected.len());
    selected.extend(overflow.into_iter().take(remaining));
    selected.sort_unstable_by(|left, right| {
        residual_score(right)
            .cmp(&residual_score(left))
            .then_with(|| right.occurrences.cmp(&left.occurrences))
            .then_with(|| left.content.cmp(&right.content))
    });
    *records = selected;
    true
}

fn residual_kind_index(kind: ClipboardResidualKind) -> usize {
    match kind {
        ClipboardResidualKind::Email => 0,
        ClipboardResidualKind::Url => 1,
        ClipboardResidualKind::Ipv4 => 2,
        ClipboardResidualKind::WindowsPath => 3,
        ClipboardResidualKind::Command => 4,
        ClipboardResidualKind::ExactText => 5,
    }
}

fn classify_residual_confidence(record: &mut ClipboardTextRecord) {
    if record.kind != ClipboardResidualKind::Email {
        classify_generic_residual(record);
        return;
    }
    let (local, domain) = record
        .content
        .split_once('@')
        .map(|(local, domain)| (local.to_ascii_lowercase(), domain.to_ascii_lowercase()))
        .unwrap_or_default();
    let provider_owner = plausible_login_local(&local)
        && record
            .owners
            .iter()
            .any(|owner| mail_service_owner_match(&domain, &owner.process));
    let interactive_owner = record
        .owners
        .iter()
        .any(|owner| owner_process_priority(&owner.process) >= 6);
    if provider_owner && record.occurrences >= 2 {
        record.confidence = "高".to_owned();
        record.evidence_note =
            "多个物理副本映射到对应邮箱服务的客户端进程；属于强登录残留候选，不证明剪切板行为"
                .to_owned();
    } else if interactive_owner && record.occurrences <= 256 {
        record.confidence = "中".to_owned();
        record.evidence_note =
            "文本页映射到交互式应用进程；仅证明内存残留和进程归属，需结合题目语境复核".to_owned();
    } else if !record.owners.is_empty() {
        record.confidence = "低".to_owned();
        record.evidence_note =
            "文本页存在进程归属，但进程语义与邮箱服务不匹配，可能是聊天、缓存或样本字符串"
                .to_owned();
    }
}

fn classify_generic_residual(record: &mut ClipboardTextRecord) {
    let interactive_owner = record
        .owners
        .iter()
        .any(|owner| owner_process_priority(&owner.process) >= 6);
    if record.kind == ClipboardResidualKind::ExactText
        && (interactive_owner || record.occurrences >= 2)
    {
        record.confidence = "高".to_owned();
        record.evidence_note =
            "与用户指定文本精确匹配，并具有进程归属或多个物理副本；属于文本残留证据，不证明剪切板行为"
                .to_owned();
    } else if interactive_owner && record.occurrences <= 256 {
        record.confidence = "中".to_owned();
        record.evidence_note = format!(
            "{}页映射到交互式应用进程；属于应用内容或缓存残留，需结合上下文复核",
            record.kind.label()
        );
    } else if !record.owners.is_empty() || record.occurrences >= 2 {
        record.confidence = "低".to_owned();
        record.evidence_note = if record.occurrences > 256 {
            format!(
                "{}在镜像中高频重复，更可能是应用资源或程序常量；不证明剪切板行为",
                record.kind.label()
            )
        } else {
            format!(
                "恢复到{}及物理/进程证据；只证明文本残留，不证明剪切板行为",
                record.kind.label()
            )
        };
    }
}

fn plausible_login_local(local: &str) -> bool {
    if !(3..=64).contains(&local.len()) {
        return false;
    }
    !matches!(
        local,
        "admin"
            | "contact"
            | "context"
            | "help"
            | "info"
            | "no-reply"
            | "noreply"
            | "postmaster"
            | "privacy"
            | "sales"
            | "salt"
            | "security"
            | "support"
    )
}

fn mail_service_owner_match(domain: &str, process: &str) -> bool {
    let process = process.to_ascii_lowercase();
    match domain {
        "proton.me" | "protonmail.com" | "proton.ch" => process.contains("proton"),
        "outlook.com" | "hotmail.com" | "live.com" => process.contains("outlook"),
        "icloud.com" | "me.com" | "mac.com" => process.contains("icloud"),
        "yahoo.com" => process.contains("yahoo"),
        _ => false,
    }
}

fn residual_score(record: &ClipboardTextRecord) -> usize {
    let confidence = match record.confidence.as_str() {
        "高" => 1_000_000,
        "中" => 100_000,
        _ => 0,
    };
    let kind = match record.kind {
        ClipboardResidualKind::ExactText => 90_000,
        ClipboardResidualKind::Email => 80_000,
        ClipboardResidualKind::Command => 70_000,
        ClipboardResidualKind::Url => 60_000,
        ClipboardResidualKind::WindowsPath => 50_000,
        ClipboardResidualKind::Ipv4 => 40_000,
    };
    confidence + kind + record.occurrences.min(9_999)
}

fn read_u32(space: &X64AddressSpace<'_>, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn is_kernel_pointer(address: u64) -> bool {
    address >> 48 == 0xffff && address != u64::MAX
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNINGS && !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ascii_and_utf16_emails() {
        let ascii = b"xx <Fixture.user01@proton.me> yy";
        let at = ascii.iter().position(|byte| *byte == b'@').unwrap();
        let (_, _, value) = extract_ascii_email(ascii, at).unwrap();
        assert_eq!(value, "Fixture.user01@proton.me");

        let utf16 = "账号 fixture.user02@proton.me 完成"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let at = utf16.iter().position(|byte| *byte == b'@').unwrap();
        let (_, _, value) = extract_utf16_email(&utf16, at).unwrap();
        assert_eq!(value, "fixture.user02@proton.me");
    }

    #[test]
    fn rejects_malformed_email_boundaries() {
        for value in [
            b".bad@example.com".as_slice(),
            b"a@bad..com",
            b"a@-bad.com",
            b"addon@mozilla.org.xpi",
            b"icon@2x.png",
        ] {
            let at = value.iter().position(|byte| *byte == b'@').unwrap();
            assert!(extract_ascii_email(value, at).is_none());
        }
    }

    #[test]
    fn decodes_unicode_clipboard_text() {
        let bytes = "中文剪切板"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let (kind, text) = decode_clipboard_content(13, &bytes);
        assert_eq!(kind, "Unicode 文本");
        assert_eq!(text.as_deref(), Some("中文剪切板"));
    }

    #[test]
    fn extracts_urls_ipv4_paths_and_commands_in_both_encodings() {
        let ascii_url = b"<https://example.com/a?q=1>";
        let (_, url) = extract_ascii_url(ascii_url, 1).unwrap();
        assert_eq!(url, "https://example.com/a?q=1");
        assert!(validate_url("http://.css").is_none());
        assert!(validate_url("http://ator").is_none());

        let utf16_url = "https://example.org/path\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let (_, url) = extract_utf16_url(&utf16_url, 0).unwrap();
        assert_eq!(url, "https://example.org/path");

        let ipv4 = b"remote=192.168.60.169:4444";
        let dot = ipv4.iter().position(|byte| *byte == b'.').unwrap();
        assert_eq!(extract_ascii_ipv4(ipv4, dot).unwrap().2, "192.168.60.169");
        assert!(validate_ipv4("10.0.19045.1").is_none());
        assert!(validate_ipv4("0.0.0.0").is_none());
        assert!(validate_ipv4("192.168.001.1").is_none());
        assert!(validate_ipv4("2.5.29.15").is_none());
        assert!(validate_ipv4("2.5.4.3").is_none());
        assert!(validate_ipv4("6.0.0.0").is_none());

        let ascii_path = br#"open C:\Users\Alice\Desktop\pass.txt"#;
        let colon = ascii_path.iter().position(|byte| *byte == b':').unwrap();
        assert_eq!(
            extract_ascii_windows_path(ascii_path, colon).unwrap().2,
            r"C:\Users\Alice\Desktop\pass.txt"
        );

        let utf16_path = "D:\\证据\\密码.txt\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let colon = utf16_path.iter().position(|byte| *byte == b':').unwrap();
        assert_eq!(
            extract_utf16_windows_path(&utf16_path, colon).unwrap().2,
            r"D:\证据\密码.txt"
        );
        assert!(validate_windows_path(r"A:\RANDOM=VALUE\OTHER@VALUE").is_none());

        let command = b"net user attacker Password1! /add\0noise";
        assert_eq!(
            extract_ascii_command(command, 0).unwrap().1,
            "net user attacker Password1! /add"
        );
        assert!(extract_ascii_command(b"PowerShell documentation or type\0", 0).is_none());
        assert!(extract_ascii_command(b"PowerShell -Command whoami\0", 0).is_some());
        assert!(
            extract_ascii_command(
                b"cmd.exe /c Object.defineProperty(x);function(a){return a=>a}\0",
                0,
            )
            .is_none()
        );
    }

    #[test]
    fn one_automaton_recovers_custom_text_and_automatic_types() {
        let exact = prepare_exact_text_patterns(&["复制的中文内容".to_owned()]).unwrap();
        let scanner = prepare_pattern_scanner(&exact).unwrap();
        let mut bytes = b"https://example.com/file cmd /c whoami\0".to_vec();
        bytes.extend("复制的中文内容".encode_utf16().flat_map(u16::to_le_bytes));
        let mut candidates = HashMap::new();
        scan_pattern_candidates(
            &bytes,
            0,
            bytes.len(),
            0x1000,
            &scanner,
            &exact,
            &mut candidates,
        );
        assert!(
            candidates
                .values()
                .any(|candidate| candidate.kind == ClipboardResidualKind::Url)
        );
        assert!(
            candidates
                .values()
                .any(|candidate| candidate.kind == ClipboardResidualKind::Command)
        );
        let custom = candidates
            .values()
            .find(|candidate| candidate.kind == ClipboardResidualKind::ExactText)
            .unwrap();
        assert_eq!(custom.content, "复制的中文内容");
        assert!(custom.utf16);
    }

    #[test]
    fn final_limit_preserves_multiple_candidate_types() {
        let record = |kind, index| ClipboardTextRecord {
            content: format!("candidate-{index}"),
            kind,
            content_type: kind.label().to_owned(),
            evidence_kind: "进程残留候选".to_owned(),
            confidence: "中".to_owned(),
            occurrences: 100usize.saturating_sub(index),
            encodings: vec![ClipboardTextEncoding::Ascii],
            physical_addresses: vec![index as u64],
            owners: Vec::new(),
            evidence_note: String::new(),
        };
        let mut records = (0..100)
            .map(|index| record(ClipboardResidualKind::Email, index))
            .chain((0..20).map(|index| record(ClipboardResidualKind::Url, index)))
            .collect::<Vec<_>>();
        records.sort_unstable_by_key(|record| std::cmp::Reverse(residual_score(record)));
        assert!(balance_final_candidates(&mut records, 20));
        assert_eq!(records.len(), 20);
        assert!(
            records
                .iter()
                .any(|record| record.kind == ClipboardResidualKind::Url)
        );
    }

    #[test]
    fn raises_only_plausible_accounts_in_matching_mail_clients() {
        let classify = |content: &str, process: &str| {
            let mut record = ClipboardTextRecord {
                content: content.to_owned(),
                kind: ClipboardResidualKind::Email,
                content_type: "邮箱地址".to_owned(),
                evidence_kind: "进程残留候选".to_owned(),
                confidence: "低".to_owned(),
                occurrences: 2,
                encodings: vec![ClipboardTextEncoding::Ascii],
                physical_addresses: vec![0x1000, 0x2000],
                owners: vec![ClipboardOwner {
                    pid: 1,
                    process: process.to_owned(),
                    virtual_address: 0x7ff0_0000,
                }],
                evidence_note: String::new(),
            };
            classify_residual_confidence(&mut record);
            record.confidence
        };

        assert_eq!(classify("fixture.user02@proton.me", "Proton Mail.ex"), "高");
        assert_eq!(classify("contact@proton.ch", "Proton Mail.ex"), "中");
        assert_eq!(classify("fixture.user04@proton.me", "Weixin.exe"), "中");
        assert_eq!(classify("fixture.user05@wps.cn", "wps.exe"), "低");
    }
}
