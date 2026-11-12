//! Resident TextInputHost clipboard history, independent of the active win32k clipboard.

use std::collections::HashSet;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Datelike, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::ClipboardScanOptions;
use super::history_layout::{self, CodeCheck, HistoryLayout};
use crate::address::{VirtualAddressRegion, VirtualMapping, X64AddressSpace};
use crate::cancellation::{CancellationToken, is_cancellation_error};
use crate::evidence::{EvidenceLimit, EvidenceLimitKind};
use crate::image::{MemoryImage, SourceLocation};
use crate::profile::KernelProfile;
use crate::symbols::{CodeViewRecord, codeview_from_virtual_pe};
use crate::windows::plugins::{DllRecord, VadRecord, list_vads_cancellable, walk_process_dlls};
use crate::windows::{ProcessRecord, WindowsKernelContext};

const MAX_PROCESSES: usize = 16;
const MAX_MAPPINGS: usize = 131_072;
const MAX_CONTROLS: usize = 256;
const MAX_VECTOR_ITEMS: usize = 4096;
const MAX_ITEMS: usize = 256;
const MAX_SCAN_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_STRING_UNITS: usize = 16_384;
pub const HISTORY_SCOPE: &str = "TextInputHost 驻留私有页中的 ClipboardControl → Model → Vector → ClipboardViewItem；仅覆盖可验证的内存历史列表，不代表全部历史或当前活动剪贴板。";
pub const HISTORY_NOTE: &str =
    "历史项时间来自对象的 UniversalTimestamp；不能据此确认复制来源应用、输入、粘贴或发送行为。";

#[derive(Debug, Clone, Serialize)]
pub struct HistoryRange {
    pub role: String,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub length: usize,
    pub source_location: SourceLocation,
    pub sha256: String,
    pub bytes_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryChain {
    pub control_address: u64,
    pub model_address: u64,
    pub vector_address: u64,
    pub vector_interface_address: u64,
    pub storage_address: u64,
    pub array_begin: u64,
    pub array_end: u64,
    pub array_capacity: u64,
    pub item_count: usize,
    pub sources: Vec<HistoryRange>,
}

#[derive(Debug, Serialize)]
pub struct ClipboardHistoryRecord {
    pub pid: u64,
    pub process: String,
    pub eprocess: u64,
    pub directory_table_base: Option<u64>,
    pub session_id: Option<u32>,
    pub module_base: u64,
    pub layout: String,
    pub pdb_key: String,
    pub evidence_kind: &'static str,
    pub evidence_note: &'static str,
    pub chain: HistoryChain,
    pub item_index: usize,
    pub item_address: u64,
    pub item_id: String,
    pub item_type_raw: u32,
    pub timestamp_raw: u64,
    pub timestamp_utc: Option<String>,
    pub hstring_address: u64,
    pub text_virtual_address: Option<u64>,
    pub text_utf16_units: Option<usize>,
    pub text: Option<String>,
    pub text_status: &'static str,
    pub text_error: Option<String>,
    pub sources: Vec<HistoryRange>,
}

#[derive(Debug, Serialize)]
pub struct ClipboardHistoryCheck {
    pub pid: Option<u64>,
    pub process: String,
    pub eprocess: Option<u64>,
    pub image_path: Option<String>,
    pub status: &'static str,
    pub complete: bool,
    pub textinput_pdb: Option<CodeViewRecord>,
    pub combase_pdb: Option<CodeViewRecord>,
    pub layout: Option<String>,
    pub scanned_bytes: u64,
    pub unreadable_pages: usize,
    pub control_candidates: usize,
    pub verified_controls: usize,
    pub rejected_controls: usize,
    pub recovered_items: usize,
    pub code_sources: Vec<HistoryRange>,
    pub warnings: Vec<String>,
}

impl ClipboardHistoryCheck {
    fn new(process: Option<&ProcessRecord>) -> Self {
        Self {
            pid: process.map(|p| p.pid),
            process: process.map_or("TextInputHost", |p| &p.name).to_owned(),
            eprocess: process.map(|p| p.eprocess),
            image_path: process.and_then(|p| p.details.image_path.clone()),
            status: "not_found",
            complete: true,
            textinput_pdb: None,
            combase_pdb: None,
            layout: None,
            scanned_bytes: 0,
            unreadable_pages: 0,
            control_candidates: 0,
            verified_controls: 0,
            rejected_controls: 0,
            recovered_items: 0,
            code_sources: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn warn(&mut self, message: String) {
        self.complete = false;
        if self.warnings.len() < 16 && !self.warnings.contains(&message) {
            self.warnings.push(message);
        }
    }
}

pub(super) struct HistoryReport {
    pub items: Vec<ClipboardHistoryRecord>,
    pub checks: Vec<ClipboardHistoryCheck>,
    pub complete: bool,
    pub limits: Vec<EvidenceLimit>,
}

struct Budget {
    scan_bytes: u64,
    text_bytes: usize,
    items: usize,
    item_attempts: usize,
    item_limit: usize,
    scan_limited: bool,
    text_limited: bool,
    items_limited: bool,
    attempts_limited: bool,
}

pub(super) fn scan_history(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    processes: &[ProcessRecord],
    options: &ClipboardScanOptions,
    token: &CancellationToken,
) -> Result<HistoryReport> {
    token.check_cancelled()?;
    let targets = processes
        .iter()
        .filter(|p| is_target(p))
        .collect::<Vec<_>>();
    let mut result = HistoryReport {
        items: Vec::new(),
        checks: Vec::new(),
        complete: true,
        limits: Vec::new(),
    };
    let mut budget = Budget {
        scan_bytes: 0,
        text_bytes: 0,
        items: 0,
        item_attempts: 0,
        item_limit: options.limit.min(MAX_ITEMS),
        scan_limited: false,
        text_limited: false,
        items_limited: false,
        attempts_limited: false,
    };
    for process in targets.iter().take(MAX_PROCESSES) {
        token.check_cancelled()?;
        let mut check = ClipboardHistoryCheck::new(Some(process));
        let start = result.items.len();
        if let Err(error) = scan_process(
            image,
            kernel,
            profile,
            process,
            options,
            token,
            &mut budget,
            &mut check,
            &mut result.items,
        ) {
            if is_cancellation_error(&error) {
                return Err(error);
            }
            if check.status != "unsupported_layout" {
                check.status = "unavailable";
            }
            check.warn(format!("{error:#}"));
        }
        check.recovered_items = result.items.len() - start;
        result.complete &= check.complete;
        result.checks.push(check);
    }
    if targets.is_empty() {
        let mut check = ClipboardHistoryCheck::new(None);
        check
            .warnings
            .push("活动进程链中未发现 TextInputHost；未扫描已退出进程或磁盘历史库。".to_owned());
        result.checks.push(check);
    }
    if targets.len() > MAX_PROCESSES {
        let mut check = ClipboardHistoryCheck::new(None);
        check.status = "limited";
        check.warn(format!(
            "目标进程数 {} 超过 {} 个上限",
            targets.len(),
            MAX_PROCESSES
        ));
        result.checks.push(check);
        result.complete = false;
    }
    result.limits = [
        (
            "clipboard_history_processes",
            EvidenceLimitKind::SourceScan,
            MAX_PROCESSES as u64,
            targets.len() as u64,
            targets.len() > MAX_PROCESSES,
        ),
        (
            "clipboard_history_scan_bytes",
            EvidenceLimitKind::Bytes,
            MAX_SCAN_BYTES,
            budget.scan_bytes,
            budget.scan_limited,
        ),
        (
            "clipboard_history_text_bytes",
            EvidenceLimitKind::Bytes,
            MAX_TEXT_BYTES as u64,
            budget.text_bytes as u64,
            budget.text_limited,
        ),
        (
            "clipboard_history_items",
            EvidenceLimitKind::Output,
            budget.item_limit as u64,
            budget.items as u64,
            budget.items_limited,
        ),
        (
            "clipboard_history_item_attempts",
            EvidenceLimitKind::SourceScan,
            MAX_VECTOR_ITEMS as u64,
            budget.item_attempts as u64,
            budget.attempts_limited,
        ),
    ]
    .into_iter()
    .map(
        |(name, kind, configured, observed, reached)| EvidenceLimit {
            name: name.to_owned(),
            kind,
            configured: Some(configured),
            observed: Some(observed),
            reached: Some(reached),
        },
    )
    .collect();
    token.check_cancelled()?;
    Ok(result)
}

fn is_target(process: &ProcessRecord) -> bool {
    [
        Some(process.name.as_str()),
        process.details.image_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|name| {
        let leaf = name.rsplit(['\\', '/']).next().unwrap_or(name);
        leaf.eq_ignore_ascii_case("TextInputHost.exe")
            || leaf.eq_ignore_ascii_case("TextInputHost.")
    })
}

#[allow(clippy::too_many_arguments)]
fn scan_process(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    process: &ProcessRecord,
    options: &ClipboardScanOptions,
    token: &CancellationToken,
    budget: &mut Budget,
    check: &mut ClipboardHistoryCheck,
    items: &mut Vec<ClipboardHistoryRecord>,
) -> Result<()> {
    ensure!(!kernel.is_x86_pae(), "TextInputHost 历史解析目前仅支持 x64");
    // Try only this EPROCESS's own user/kernel DTBs. The general DLL helper may
    // discover another DTB by scanning RAM; that is inappropriate for this bounded source.
    let peb = process.details.peb.context("进程 PEB 不可用")?;
    let mut loaded = None;
    let mut failures = Vec::new();
    for dtb in [
        process.details.user_directory_table_base,
        process.details.directory_table_base,
    ]
    .into_iter()
    .flatten()
    .filter(|dtb| *dtb != 0)
    {
        token.check_cancelled()?;
        match X64AddressSpace::new(image, dtb).and_then(|space| {
            walk_process_dlls(&space, process.pid, &process.name, peb, 2048)
                .map(|(modules, warning)| (space, modules, warning))
        }) {
            Ok(value) => {
                loaded = Some(value);
                break;
            }
            Err(error) => failures.push(format!("DTB {dtb:#x}：{error:#}")),
        }
    }
    let (space, modules, warning) =
        loaded.with_context(|| format!("所属进程页表无法读取加载器：{}", failures.join("；")))?;
    let dtb = space.directory_table_base();
    let reader = Reader {
        image,
        space,
        token,
    };
    if let Some(warning) = warning {
        check.warn(format!("模块枚举：{warning}"));
    }
    let module = |name: &str| -> Result<&DllRecord> {
        modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
            .with_context(|| format!("未找到 {name} 的加载器记录"))
    };
    let textinput = module("TextInput.dll")?;
    let combase = module("combase.dll")?;
    check.textinput_pdb = Some(
        codeview_from_virtual_pe(image, dtb, textinput.base)
            .context("TextInput.dll RSDS 不可读")?,
    );
    check.combase_pdb = Some(
        codeview_from_virtual_pe(image, dtb, combase.base).context("combase.dll RSDS 不可读")?,
    );
    let layout = match check
        .textinput_pdb
        .as_ref()
        .zip(check.combase_pdb.as_ref())
        .and_then(|(a, b)| history_layout::select(a, b))
    {
        Some(layout) => layout,
        None => {
            check.status = "unsupported_layout";
            anyhow::bail!(
                "模块 PDB 身份尚未适配，未套用其他版本的对象偏移；请查看本进程的 TextInput/combase 符号身份"
            );
        }
    };
    check.layout = Some(layout.id.to_owned());
    validate_code(
        &reader,
        textinput,
        layout.textinput_code,
        &mut check.code_sources,
    )?;
    validate_code(
        &reader,
        combase,
        layout.combase_code,
        &mut check.code_sources,
    )?;
    // The IObservableVector Size slot and native Size slot must lead to the audited thunks.
    let vector_table = textinput.base + layout.vector_vtables[1];
    for (offset, expected) in [(7 * 8, 0xb1950), (0x90, 0xb29b0)] {
        let bytes = reader.capture(
            vector_table + offset,
            8,
            "Vector.Size.vtable_slot",
            &mut check.code_sources,
        )?;
        ensure!(
            u64_at(&bytes, 0)? == textinput.base + expected,
            "Vector.Size 虚表槽与已验证布局不符"
        );
    }
    token.check_cancelled()?;
    let vads = list_vads_cancellable(image, kernel, profile, process.pid, 65_536, token)?;
    if !vads.complete {
        for warning in vads.warnings {
            check.warn(format!("VAD：{warning}"));
        }
    }
    let mappings = reader.space.enumerate_mappings_cancellable(
        VirtualAddressRegion::User,
        MAX_MAPPINGS,
        token,
    )?;
    if mappings.truncated {
        check.warn(format!("驻留映射达到 {MAX_MAPPINGS} 页表叶项上限"));
    }
    for warning in mappings.warnings {
        check.warn(format!("页表：{warning}"));
    }
    let controls = find_controls(
        &reader,
        &mappings.mappings,
        &vads.records,
        textinput.base + layout.control_vtables[0],
        budget,
        check,
    )?;
    for control in controls {
        token.check_cancelled()?;
        match read_chain(&reader, textinput.base, layout, control) {
            Ok(chain) => {
                check.verified_controls += 1;
                for index in 0..chain.item_count {
                    token.check_cancelled()?;
                    if budget.items >= budget.item_limit {
                        budget.items_limited = true;
                        check.warn(format!("历史项达到 {} 条输出上限", budget.item_limit));
                        break;
                    }
                    if budget.item_attempts >= MAX_VECTOR_ITEMS {
                        budget.attempts_limited = true;
                        check.warn(format!(
                            "历史对象累计读取达到 {MAX_VECTOR_ITEMS} 次上限（含无效对象）"
                        ));
                        break;
                    }
                    budget.item_attempts += 1;
                    match read_item(
                        &reader,
                        process,
                        textinput.base,
                        layout,
                        &chain,
                        index,
                        options.max_data_size,
                        budget,
                    ) {
                        Ok(item) => {
                            if item.text_status != "verified" {
                                check.warn(format!(
                                    "历史项 {:#x} 文本未恢复：{}",
                                    item.item_address,
                                    item.text_error.as_deref().unwrap_or("未知原因")
                                ));
                            }
                            items.push(item);
                            budget.items += 1;
                        }
                        Err(error) => {
                            if is_cancellation_error(&error) {
                                return Err(error);
                            }
                            check.warn(format!(
                                "Control {control:#x} 的第 {index} 项无法验证：{error:#}"
                            ));
                        }
                    }
                }
            }
            Err(error) => {
                if is_cancellation_error(&error) {
                    return Err(error);
                }
                check.rejected_controls += 1;
                check.warn(format!("Control {control:#x} 对象链不可验证：{error:#}"));
            }
        }
    }
    check.status = if !check.complete {
        "partial"
    } else if check.verified_controls == 0 {
        "not_found"
    } else {
        "verified"
    };
    Ok(())
}

struct Reader<'a> {
    image: &'a MemoryImage,
    space: X64AddressSpace<'a>,
    token: &'a CancellationToken,
}

impl Reader<'_> {
    fn read(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        self.token.check_cancelled()?;
        ensure!(
            valid_range(address, length),
            "无效的用户空间区间 {address:#x}+{length:#x}"
        );
        let mut bytes = vec![0; length];
        self.space
            .read_virtual(address, &mut bytes)
            .with_context(|| format!("驻留页不完整 {address:#x}+{length:#x}"))?;
        Ok(bytes)
    }

    fn capture(
        &self,
        address: u64,
        length: usize,
        role: &str,
        sources: &mut Vec<HistoryRange>,
    ) -> Result<Vec<u8>> {
        let bytes = self.read(address, length)?;
        let mut offset = 0;
        while offset < bytes.len() {
            self.token.check_cancelled()?;
            let va = address + offset as u64;
            let pa = self.space.translate(va)?;
            let span = self
                .image
                .spans()
                .iter()
                .find(|s| pa >= s.start && pa < s.end())
                .context("物理来源区间缺失")?;
            let take = (bytes.len() - offset)
                .min(0x1000 - (va as usize & 0xfff))
                .min((span.end() - pa) as usize);
            ensure!(take > 0, "物理来源区间为空");
            let data = &bytes[offset..offset + take];
            sources.push(HistoryRange {
                role: role.to_owned(),
                virtual_address: va,
                physical_address: pa,
                length: take,
                source_location: self
                    .image
                    .source_location(pa)
                    .context("物理来源映射不可用")?,
                sha256: hex::encode(Sha256::digest(data)),
                bytes_hex: hex::encode(data),
            });
            offset += take;
        }
        Ok(bytes)
    }
}

fn valid_range(address: u64, length: usize) -> bool {
    address >= 0x10000
        && address
            .checked_add(length as u64)
            .is_some_and(|end| end <= 0x0000_8000_0000_0000)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .context("指针字段截断")?
            .try_into()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("整数字段截断")?
            .try_into()?,
    ))
}

fn validate_code(
    reader: &Reader<'_>,
    module: &DllRecord,
    checks: &[CodeCheck],
    sources: &mut Vec<HistoryRange>,
) -> Result<()> {
    for check in checks {
        ensure!(
            check.rva + check.bytes.len() as u64 <= module.size as u64,
            "{} 超出模块范围",
            check.name
        );
        let bytes = reader.capture(
            module.base + check.rva,
            check.bytes.len(),
            check.name,
            sources,
        )?;
        ensure!(
            bytes == check.bytes,
            "{} 访问指令与 PDB 布局不符，停止解释对象",
            check.name
        );
    }
    Ok(())
}

fn find_controls(
    reader: &Reader<'_>,
    mappings: &[VirtualMapping],
    vads: &[VadRecord],
    vtable: u64,
    budget: &mut Budget,
    check: &mut ClipboardHistoryCheck,
) -> Result<Vec<u64>> {
    let needle = vtable.to_le_bytes();
    let mut controls = Vec::new();
    let mut seen = HashSet::new();
    let mut private = vads
        .iter()
        .filter(|v| v.private_memory && !v.protection_name.contains("NOACCESS") && v.start <= v.end)
        .map(|v| (v.start, v.end.saturating_add(1)))
        .collect::<Vec<_>>();
    private.sort_unstable();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for (start, end) in private {
        if let Some(last) = ranges.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            ranges.push((start, end));
        }
    }
    // Intersect resident mappings with private VADs. Never read the logical length
    // of a reserved 4 GiB/2 TiB VAD or allocate a process-sized buffer.
    for mapping in mappings.iter().filter(|m| m.user_accessible) {
        reader.token.check_cancelled()?;
        let map_end = mapping.virtual_start.saturating_add(mapping.length);
        let first = ranges.partition_point(|range| range.1 <= mapping.virtual_start);
        for &(vad_start, vad_end) in ranges[first..].iter().take_while(|range| range.0 < map_end) {
            let mut cursor = mapping.virtual_start.max(vad_start);
            let end = map_end.min(vad_end);
            while cursor < end {
                reader.token.check_cancelled()?;
                let take = (end - cursor).min(0x1000 - (cursor & 0xfff)) as usize;
                if budget.scan_bytes + take as u64 > MAX_SCAN_BYTES {
                    budget.scan_limited = true;
                    check.warn(format!("历史扫描达到 {MAX_SCAN_BYTES} 字节驻留页预算"));
                    return Ok(controls);
                }
                budget.scan_bytes += take as u64;
                check.scanned_bytes += take as u64;
                match reader.read(cursor, take) {
                    Ok(bytes) => {
                        for at in memchr::memmem::find_iter(&bytes, &needle) {
                            let address = cursor + at as u64;
                            if address & 7 != 0 || !seen.insert(address) {
                                continue;
                            }
                            if controls.len() == MAX_CONTROLS {
                                check.warn(format!("Control 候选达到 {MAX_CONTROLS} 个上限"));
                                return Ok(controls);
                            }
                            controls.push(address);
                            check.control_candidates += 1;
                        }
                    }
                    Err(error) => {
                        if is_cancellation_error(&error) {
                            return Err(error);
                        }
                        check.unreadable_pages += 1;
                    }
                }
                cursor += take as u64;
            }
        }
    }
    if check.unreadable_pages > 0 {
        check.warn(format!(
            "{} 个映射页无法完整读取，未以补零内容参与匹配",
            check.unreadable_pages
        ));
    }
    controls.sort_unstable();
    Ok(controls)
}

fn validate_vtables(bytes: &[u8], base: u64, tables: &[u64]) -> Result<()> {
    for (index, rva) in tables.iter().enumerate() {
        ensure!(
            u64_at(bytes, index * 8)? == base + rva,
            "对象接口虚表 {index} 不匹配"
        );
    }
    Ok(())
}

fn vector_count(begin: u64, end: u64, capacity: u64) -> Result<usize> {
    ensure!(
        begin <= end && end <= capacity,
        "Vector begin/end/capacity 顺序无效"
    );
    ensure!(
        begin & 7 == 0 && (end - begin) & 7 == 0 && (capacity - begin) & 7 == 0,
        "Vector 元素未按指针对齐"
    );
    ensure!(
        (capacity - begin) / 8 <= MAX_VECTOR_ITEMS as u64,
        "Vector 容量超过 {MAX_VECTOR_ITEMS} 项"
    );
    ensure!(
        begin == 0 && capacity == 0 || valid_range(begin, (capacity - begin) as usize),
        "Vector 地址区间无效"
    );
    Ok(((end - begin) / 8) as usize)
}

fn read_chain(
    reader: &Reader<'_>,
    base: u64,
    layout: &HistoryLayout,
    control: u64,
) -> Result<HistoryChain> {
    let mut sources = Vec::new();
    let head = reader.capture(
        control,
        layout.control_model + 8,
        "ClipboardControl",
        &mut sources,
    )?;
    validate_vtables(&head, base, layout.control_vtables)?;
    let model = u64_at(&head, layout.control_model)?;
    let head = reader.capture(
        model,
        layout.model_items + 8,
        "ClipboardControlModel",
        &mut sources,
    )?;
    validate_vtables(&head, base, layout.model_vtables)?;
    let interface = u64_at(&head, layout.model_items)?;
    let vector = interface.checked_sub(8).context("Vector 接口地址下溢")?;
    let head = reader.capture(
        vector,
        layout.vector_storage + 8,
        "ClipboardItems.Vector",
        &mut sources,
    )?;
    validate_vtables(&head, base, layout.vector_vtables)?;
    let storage = u64_at(&head, layout.vector_storage)?;
    let head = reader.capture(storage, 24, "ClipboardItems.storage", &mut sources)?;
    let (begin, end, capacity) = (u64_at(&head, 0)?, u64_at(&head, 8)?, u64_at(&head, 16)?);
    let item_count = vector_count(begin, end, capacity)?;
    Ok(HistoryChain {
        control_address: control,
        model_address: model,
        vector_address: vector,
        vector_interface_address: interface,
        storage_address: storage,
        array_begin: begin,
        array_end: end,
        array_capacity: capacity,
        item_count,
        sources,
    })
}

struct HistoryText {
    text: String,
    buffer: Option<u64>,
    units: usize,
}

fn read_hstring(
    reader: &Reader<'_>,
    address: u64,
    max_data_size: usize,
    budget: &mut Budget,
    sources: &mut Vec<HistoryRange>,
) -> Result<HistoryText> {
    if address == 0 {
        return Ok(HistoryText {
            text: String::new(),
            buffer: None,
            units: 0,
        });
    }
    let head = reader.capture(address, 28, "HSTRING.header", sources)?;
    let flags = u32_at(&head, 0)?;
    let units = u32_at(&head, 4)? as usize;
    let buffer = u64_at(&head, 16)?;
    let refs = u32_at(&head, 24)?;
    ensure!(
        flags == 0 && buffer == address + 28 && (1..1_000_000).contains(&refs),
        "HSTRING 不是已验证的普通持有字符串（引用字符串、复用对象或未知标志未解析）"
    );
    ensure!(
        units <= MAX_STRING_UNITS,
        "HSTRING 长度超过 {MAX_STRING_UNITS} 个 UTF-16 单元"
    );
    let bytes = units * 2 + 2;
    ensure!(
        bytes <= max_data_size,
        "HSTRING 超过单条数据读取上限 {max_data_size} 字节"
    );
    if budget.text_bytes + bytes > MAX_TEXT_BYTES {
        budget.text_limited = true;
        anyhow::bail!("历史文本达到 {MAX_TEXT_BYTES} 字节总读取预算");
    }
    budget.text_bytes += bytes;
    let data = reader.capture(buffer, bytes, "HSTRING.utf16le_with_terminator", sources)?;
    ensure!(data.ends_with(&[0, 0]), "HSTRING 终止符缺失");
    let utf16 = data[..data.len() - 2]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect::<Vec<_>>();
    Ok(HistoryText {
        text: String::from_utf16(&utf16).context("HSTRING 包含无效 UTF-16，未进行有损替换")?,
        buffer: Some(buffer),
        units,
    })
}

#[allow(clippy::too_many_arguments)]
fn read_item(
    reader: &Reader<'_>,
    process: &ProcessRecord,
    base: u64,
    layout: &HistoryLayout,
    chain: &HistoryChain,
    index: usize,
    max_data_size: usize,
    budget: &mut Budget,
) -> Result<ClipboardHistoryRecord> {
    let mut sources = Vec::new();
    let pointer = reader.capture(
        chain.array_begin + index as u64 * 8,
        8,
        "ClipboardItems.element",
        &mut sources,
    )?;
    let address = u64_at(&pointer, 0)?;
    let head = reader.capture(
        address,
        layout.item_timestamp + 8,
        "ClipboardViewItem",
        &mut sources,
    )?;
    validate_vtables(&head, base, layout.item_vtables)?;
    let timestamp_raw = u64_at(&head, layout.item_timestamp)?;
    let hstring = u64_at(&head, layout.item_text)?;
    let mut record = ClipboardHistoryRecord {
        pid: process.pid,
        process: process.name.clone(),
        eprocess: process.eprocess,
        directory_table_base: Some(reader.space.directory_table_base()),
        session_id: process.details.session_id,
        module_base: base,
        layout: layout.id.to_owned(),
        pdb_key: layout.textinput_key.to_owned(),
        evidence_kind: "textinputhost_clipboard_history",
        evidence_note: HISTORY_NOTE,
        chain: chain.clone(),
        item_index: index,
        item_address: address,
        item_id: guid_text(
            head.get(layout.item_id..layout.item_id + 16)
                .context("历史项 ID 截断")?,
        ),
        item_type_raw: u32_at(&head, layout.item_type)?,
        timestamp_raw,
        timestamp_utc: history_time(timestamp_raw),
        hstring_address: hstring,
        text_virtual_address: None,
        text_utf16_units: None,
        text: None,
        text_status: "unavailable",
        text_error: None,
        sources,
    };
    match read_hstring(reader, hstring, max_data_size, budget, &mut record.sources) {
        Ok(text) => {
            record.text = Some(text.text);
            record.text_virtual_address = text.buffer;
            record.text_utf16_units = Some(text.units);
            record.text_status = "verified";
        }
        Err(error) => {
            if is_cancellation_error(&error) {
                return Err(error);
            }
            record.text_error = Some(format!("{error:#}"));
        }
    }
    Ok(record)
}

fn guid_text(bytes: &[u8]) -> String {
    // Caller has already checked the fixed width. GUID's first three fields are little endian.
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
        bytes[3],
        bytes[2],
        bytes[1],
        bytes[0],
        bytes[5],
        bytes[4],
        bytes[7],
        bytes[6],
        bytes[8],
        bytes[9],
        hex::encode(&bytes[10..])
    )
}

fn history_time(ticks: u64) -> Option<String> {
    if ticks == 0 {
        return None;
    }
    let seconds = i64::try_from(ticks / 10_000_000)
        .ok()?
        .checked_sub(11_644_473_600)?;
    let time = DateTime::<Utc>::from_timestamp(seconds, 0)?;
    (1601..=9999).contains(&time.year()).then(|| {
        format!(
            "{}.{:07}Z",
            time.format("%Y-%m-%dT%H:%M:%S"),
            ticks % 10_000_000
        )
    })
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
