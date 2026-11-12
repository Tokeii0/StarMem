//! 从 Linux 进程的堆、栈（以及可选的匿名可写映射）中提取可读字符串。
//!
//! 只读取经复验的 VMA 中驻留的页面；缺页不参与提取，并在区域摘要中给出缺页范围，
//! 因此"没有找到"不能被解读为"内存中不存在"。

use anyhow::{Result, ensure};
use serde::Serialize;

use super::{
    LinuxProcessArtifactWarning, LinuxProcessMapRecord, LinuxProcessProfileEvidence,
    LinuxVirtualMissingRange, PAGE_SIZE, collect_maps_for_process, exact_profile,
    process_list_warnings, push_missing_range, selected_processes,
};
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::linux::{LinuxKernelContext, LinuxProcessListReport, LinuxX64AddressSpace};

/// 要扫描的进程内存区域类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxStringRegion {
    /// brk 堆（`[heap]`）。
    Heap,
    /// 主线程栈（`[stack]`）。
    Stack,
    /// 无文件映射的可写区域：glibc mmap 分配、线程栈、.bss 之后的匿名段等。
    Anonymous,
}

impl LinuxStringRegion {
    fn classify(record: &LinuxProcessMapRecord) -> Option<Self> {
        match record.path.as_deref() {
            Some("[heap]") => Some(Self::Heap),
            Some("[stack]") => Some(Self::Stack),
            None if record.permissions.contains('w') => Some(Self::Anonymous),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxStringEncoding {
    Utf8,
    Utf16le,
}

#[derive(Debug, Clone)]
pub struct LinuxProcStringsOptions {
    pub pid: Option<i32>,
    pub process_limit: usize,
    pub map_limit: usize,
    pub regions: Vec<LinuxStringRegion>,
    /// 最少字符数（按 Unicode 标量计）。
    pub min_length: usize,
    pub utf8: bool,
    pub utf16le: bool,
    /// 大小写不敏感的子串过滤；为空时保留全部字符串。
    pub grep: Option<String>,
    /// 单条字符串保留的最大字符数，超出部分截断并标记。
    pub max_string_chars: usize,
    pub limit: usize,
    pub max_region_size: u64,
}

impl Default for LinuxProcStringsOptions {
    fn default() -> Self {
        Self {
            pid: None,
            process_limit: 65_536,
            map_limit: 1_000_000,
            regions: vec![LinuxStringRegion::Heap, LinuxStringRegion::Stack],
            min_length: 4,
            utf8: true,
            utf16le: true,
            grep: None,
            max_string_chars: 4096,
            limit: 100_000,
            max_region_size: 256 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxProcessStringRecord {
    pub pid: i32,
    pub process_name: String,
    pub region: LinuxStringRegion,
    pub region_start_hex: String,
    pub address: u64,
    pub address_hex: String,
    pub encoding: LinuxStringEncoding,
    pub byte_length: usize,
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxProcessStringRegionSummary {
    pub pid: i32,
    pub process_name: String,
    pub region: LinuxStringRegion,
    pub start: u64,
    pub start_hex: String,
    pub end: u64,
    pub end_hex: String,
    pub permissions: String,
    pub logical_size: u64,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
    pub strings_found: usize,
    pub strings_kept: usize,
    pub skipped: bool,
    pub skip_reason: Option<String>,
    pub missing_ranges: Vec<LinuxVirtualMissingRange>,
}

#[derive(Debug, Serialize)]
pub struct LinuxProcStringsReport {
    pub source: String,
    pub kernel: LinuxKernelContext,
    pub profile: LinuxProcessProfileEvidence,
    pub regions_requested: Vec<LinuxStringRegion>,
    pub min_length: usize,
    pub grep: Option<String>,
    pub processes_considered: usize,
    pub processes_recovered: usize,
    pub regions: Vec<LinuxProcessStringRegionSummary>,
    pub records: Vec<LinuxProcessStringRecord>,
    pub record_count: usize,
    pub limit: usize,
    pub limit_reached: bool,
    pub process_list_complete: bool,
    pub complete: bool,
    pub scope: String,
    pub warnings: Vec<LinuxProcessArtifactWarning>,
}

pub fn analyze_proc_strings(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    processes: &LinuxProcessListReport,
    options: &LinuxProcStringsOptions,
    cancellation: &CancellationToken,
) -> Result<LinuxProcStringsReport> {
    ensure!(options.map_limit > 0, "VMA 结果上限必须大于零");
    ensure!(options.limit > 0, "字符串结果上限必须大于零");
    ensure!(options.min_length > 0, "最少字符数必须大于零");
    ensure!(options.max_string_chars > 0, "单条字符串字符上限必须大于零");
    ensure!(
        options.utf8 || options.utf16le,
        "至少需要启用一种字符串编码"
    );
    ensure!(!options.regions.is_empty(), "至少需要选择一种内存区域");
    let grep = options
        .grep
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_lowercase);
    let profile = exact_profile(kernel)?;
    let selected = selected_processes(processes, options.pid, true)?;
    let kernel_space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut warnings = process_list_warnings(processes);
    let mut complete = processes.complete;
    let mut processes_recovered = 0usize;
    let mut regions = Vec::new();
    let mut records = Vec::new();
    let mut limit_reached = false;
    for process in &selected {
        cancellation.check_cancelled()?;
        let collected = match collect_maps_for_process(
            image,
            &kernel_space,
            profile,
            process,
            options.map_limit,
            &mut warnings,
        ) {
            Ok(collected) => collected,
            Err(error) => {
                complete = false;
                warnings.push(LinuxProcessArtifactWarning::new(
                    "maps_unrecoverable",
                    format!("PID {} VMA 恢复失败：{error:#}", process.pid),
                    Some(process.pid),
                    process.mm,
                ));
                continue;
            }
        };
        processes_recovered += 1;
        complete &= collected.summary.complete;
        for mapping in &collected.records {
            let Some(kind) = LinuxStringRegion::classify(mapping) else {
                continue;
            };
            if !options.regions.contains(&kind) {
                continue;
            }
            cancellation.check_cancelled()?;
            let mut summary = LinuxProcessStringRegionSummary {
                pid: process.pid,
                process_name: process.name.clone(),
                region: kind,
                start: mapping.start,
                start_hex: mapping.start_hex.clone(),
                end: mapping.end,
                end_hex: mapping.end_hex.clone(),
                permissions: mapping.permissions.clone(),
                logical_size: mapping.length,
                recovered_bytes: 0,
                missing_bytes: mapping.length,
                strings_found: 0,
                strings_kept: 0,
                skipped: false,
                skip_reason: None,
                missing_ranges: Vec::new(),
            };
            if mapping.length > options.max_region_size {
                summary.skipped = true;
                summary.skip_reason = Some(format!(
                    "区域长度 {} 超过单区上限 {}",
                    mapping.length, options.max_region_size
                ));
                complete = false;
                regions.push(summary);
                continue;
            }
            let (bytes, present) = read_region(
                &collected.context.space,
                mapping.start,
                mapping.end,
                &mut summary,
                cancellation,
            )?;
            complete &= summary.missing_ranges.is_empty();
            let mut found = extract_strings(
                &bytes,
                &present,
                options.min_length,
                options.utf8,
                options.utf16le,
            );
            found.sort_by_key(|item| (item.offset, item.encoding as u8));
            summary.strings_found = found.len();
            for item in found {
                if let Some(grep) = &grep
                    && !item.text.to_lowercase().contains(grep)
                {
                    continue;
                }
                if records.len() >= options.limit {
                    limit_reached = true;
                    break;
                }
                let address = mapping.start + item.offset as u64;
                let (text, truncated) = truncate_chars(item.text, options.max_string_chars);
                records.push(LinuxProcessStringRecord {
                    pid: process.pid,
                    process_name: process.name.clone(),
                    region: kind,
                    region_start_hex: mapping.start_hex.clone(),
                    address,
                    address_hex: format!("{address:#x}"),
                    encoding: item.encoding,
                    byte_length: item.byte_length,
                    text,
                    truncated,
                });
                summary.strings_kept += 1;
            }
            regions.push(summary);
            if limit_reached {
                break;
            }
        }
        if limit_reached {
            warnings.push(LinuxProcessArtifactWarning::new(
                "limit_reached",
                format!("字符串结果达到上限 {}，后续区域未继续输出", options.limit),
                Some(process.pid),
                None,
            ));
            break;
        }
    }
    complete &= !limit_reached && processes_recovered == selected.len();
    let mut regions_requested = Vec::new();
    for region in &options.regions {
        if !regions_requested.contains(region) {
            regions_requested.push(*region);
        }
    }
    Ok(LinuxProcStringsReport {
        source: "linux.process.present_pages.string_scan".to_owned(),
        kernel: kernel.clone(),
        profile: profile.evidence(kernel),
        regions_requested,
        min_length: options.min_length,
        grep: options.grep.clone(),
        processes_considered: selected.len(),
        processes_recovered,
        record_count: records.len(),
        regions,
        records,
        limit: options.limit,
        limit_reached,
        process_list_complete: processes.complete,
        complete,
        scope: "validated heap/stack/anonymous writable VMAs of active thread-group leaders; resident present pages only; strings never span a missing page".to_owned(),
        warnings,
    })
}

/// 读取整个区域；缺页以 0 填充并在 `present` 中标记为 false。
fn read_region(
    space: &LinuxX64AddressSpace<'_>,
    start: u64,
    end: u64,
    summary: &mut LinuxProcessStringRegionSummary,
    cancellation: &CancellationToken,
) -> Result<(Vec<u8>, Vec<bool>)> {
    let length = usize::try_from(end - start)?;
    let mut bytes = vec![0u8; length];
    let mut present = Vec::with_capacity(length.div_ceil(PAGE_SIZE as usize));
    let mut address = start;
    while address < end {
        if present.len() % 256 == 0 {
            cancellation.check_cancelled()?;
        }
        let offset = usize::try_from(address - start)?;
        let take = usize::try_from((end - address).min(PAGE_SIZE))?;
        let ok = space
            .read_virtual(address, &mut bytes[offset..offset + take])
            .is_ok();
        if ok {
            summary.recovered_bytes += take as u64;
        } else {
            bytes[offset..offset + take].fill(0);
            push_missing_range(
                &mut summary.missing_ranges,
                address,
                offset as u64,
                take as u64,
            );
        }
        present.push(ok);
        address += take as u64;
    }
    summary.missing_bytes = summary.logical_size - summary.recovered_bytes;
    Ok((bytes, present))
}

/// UTF-8 通道总会运行，用于剔除落在 UTF-8 字符串内部的 UTF-16 误读
/// （例如 `— classified` 的字节被错位解读为 CJK）；只有启用时才输出 UTF-8 结果。
fn extract_strings(
    bytes: &[u8],
    present: &[bool],
    min_length: usize,
    utf8: bool,
    utf16le: bool,
) -> Vec<FoundString> {
    let mut utf8_found = Vec::new();
    extract_utf8(bytes, present, min_length, &mut utf8_found);
    let mut output = Vec::new();
    if utf16le {
        let mut wide = Vec::new();
        extract_utf16le(bytes, present, min_length, &mut wide);
        // utf8_found 按偏移递增且互不重叠，取起点不大于候选起点的最后一条判断包含关系。
        output.extend(wide.into_iter().filter(|candidate| {
            let index = utf8_found.partition_point(|item| item.offset <= candidate.offset);
            !index.checked_sub(1).is_some_and(|index| {
                let item = &utf8_found[index];
                candidate.offset + candidate.byte_length <= item.offset + item.byte_length
            })
        }));
    }
    if utf8 {
        output.extend(utf8_found);
    }
    output
}

struct FoundString {
    offset: usize,
    byte_length: usize,
    encoding: LinuxStringEncoding,
    text: String,
}

fn page_present(present: &[bool], offset: usize) -> bool {
    present
        .get(offset / PAGE_SIZE as usize)
        .copied()
        .unwrap_or(false)
}

fn is_text_char(ch: char) -> bool {
    ch == '\t' || !ch.is_control()
}

/// 提取 UTF-8 字符串：可打印 ASCII 与合法的非控制多字节字符连续出现。
fn extract_utf8(bytes: &[u8], present: &[bool], min_length: usize, out: &mut Vec<FoundString>) {
    let mut index = 0usize;
    while index < bytes.len() {
        let start = index;
        let mut chars = 0usize;
        while index < bytes.len() && page_present(present, index) {
            let width = match bytes[index] {
                0x20..=0x7e | b'\t' => 1,
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => 0,
            };
            if width == 0 || index + width > bytes.len() {
                break;
            }
            // 多字节字符不能跨越缺页边界。
            if !page_present(present, index + width - 1) {
                break;
            }
            let Ok(text) = std::str::from_utf8(&bytes[index..index + width]) else {
                break;
            };
            if !text.chars().all(is_text_char) {
                break;
            }
            index += width;
            chars += 1;
        }
        if chars >= min_length {
            out.push(FoundString {
                offset: start,
                byte_length: index - start,
                encoding: LinuxStringEncoding::Utf8,
                text: String::from_utf8_lossy(&bytes[start..index]).into_owned(),
            });
        }
        if index == start {
            index += 1;
        }
    }
}

/// UTF-16LE 只接受可打印 ASCII 与常用 CJK 区段，避免把任意二进制误报为宽字符串。
/// 低字节为 0 的 CJK 码点几乎总是错位读取 ASCII 宽字符串（`l\0` -> U+6C00）的产物，一并排除。
fn is_utf16_text_unit(unit: u16) -> bool {
    match unit {
        0x20..=0x7e | 0x09 => true,
        0x3000..=0x303f | 0x4e00..=0x9fff | 0xff00..=0xffef => unit & 0xff != 0,
        _ => false,
    }
}

fn extract_utf16le(bytes: &[u8], present: &[bool], min_length: usize, out: &mut Vec<FoundString>) {
    for parity in 0..2usize {
        let mut index = parity;
        while index + 1 < bytes.len() {
            let start = index;
            let mut units = Vec::new();
            while index + 1 < bytes.len()
                && page_present(present, index)
                && page_present(present, index + 1)
            {
                let unit = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
                if !is_utf16_text_unit(unit) {
                    break;
                }
                units.push(unit);
                index += 2;
            }
            // 普通 ASCII 文本按 UTF-16LE 解读会落入 CJK 区（如 "ab" -> U+6261）；
            // 字节全为可打印 ASCII 的序列已由 UTF-8 通道给出，这里丢弃以免重复误报。
            // 判据：序列中存在 CJK 码点，且每个 CJK 码点的两个字节都是可打印 ASCII。
            let ascii_pair = |unit: &u16| {
                let [low, high] = unit.to_le_bytes();
                (0x20..=0x7e).contains(&low) && (0x20..=0x7e).contains(&high)
            };
            let mut wide = units.iter().filter(|unit| **unit > 0x7e).peekable();
            let ascii_misread = wide.peek().is_some() && wide.all(ascii_pair);
            if units.len() >= min_length && !ascii_misread {
                out.push(FoundString {
                    offset: start,
                    byte_length: index - start,
                    encoding: LinuxStringEncoding::Utf16le,
                    text: String::from_utf16_lossy(&units),
                });
            }
            if index == start {
                index += 2;
            }
        }
    }
}

fn truncate_chars(text: String, max_chars: usize) -> (String, bool) {
    match text.char_indices().nth(max_chars) {
        Some((cut, _)) => (text[..cut].to_owned(), true),
        None => (text, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_present(bytes: &[u8]) -> Vec<bool> {
        vec![true; bytes.len().div_ceil(PAGE_SIZE as usize)]
    }

    #[test]
    fn utf8_extracts_ascii_and_multibyte_runs() {
        let bytes = "\0\0SSS{m3m0ry}\0ab\0classified — 机密\x01".as_bytes();
        let mut found = Vec::new();
        extract_utf8(bytes, &all_present(bytes), 4, &mut found);
        let texts: Vec<_> = found.iter().map(|item| item.text.as_str()).collect();
        assert_eq!(texts, ["SSS{m3m0ry}", "classified — 机密"]);
        assert_eq!(found[0].offset, 2);
    }

    #[test]
    fn utf16le_extracts_wide_strings_on_both_parities() {
        let mut bytes = vec![0u8];
        for unit in "flag测试".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        let mut found = Vec::new();
        extract_utf16le(&bytes, &all_present(&bytes), 4, &mut found);
        let texts: Vec<_> = found
            .iter()
            .map(|item| (item.text.as_str(), item.offset))
            .collect();
        // 只有正确对齐的一条；错位读取不能产生额外的伪 CJK 串。
        assert_eq!(texts, [("flag测试", 1)]);
    }

    #[test]
    fn utf16le_does_not_misread_plain_ascii_as_cjk() {
        let bytes = b"\0abcdefgh\0";
        let mut found = Vec::new();
        extract_utf16le(bytes, &all_present(bytes), 2, &mut found);
        assert!(
            found.is_empty(),
            "{:?}",
            found.iter().map(|item| &item.text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn utf16le_inside_utf8_text_is_not_reported() {
        let bytes = "\0started — classified data\0".as_bytes();
        for utf8 in [true, false] {
            let found = extract_strings(bytes, &all_present(bytes), 4, utf8, true);
            assert!(
                found
                    .iter()
                    .all(|item| item.encoding == LinuxStringEncoding::Utf8),
                "{:?}",
                found.iter().map(|item| &item.text).collect::<Vec<_>>()
            );
        }
        // 真正的宽字符串不受影响。
        let mut wide = vec![0u8];
        for unit in "机密文件".encode_utf16() {
            wide.extend_from_slice(&unit.to_le_bytes());
        }
        wide.extend_from_slice(&[0, 0]);
        let found = extract_strings(&wide, &all_present(&wide), 4, true, true);
        assert!(found.iter().any(|item| item.text == "机密文件"));
    }

    #[test]
    fn strings_never_span_missing_pages() {
        let page = PAGE_SIZE as usize;
        let mut bytes = vec![0u8; page * 2];
        bytes[page - 3..page].copy_from_slice(b"abc");
        bytes[page..page + 3].copy_from_slice(b"def");
        let mut found = Vec::new();
        extract_utf8(&bytes, &[true, false], 3, &mut found);
        let texts: Vec<_> = found.iter().map(|item| item.text.as_str()).collect();
        assert_eq!(texts, ["abc"]);
    }

    #[test]
    fn truncation_is_char_boundary_safe() {
        assert_eq!(
            truncate_chars("机密文件".to_owned(), 2),
            ("机密".to_owned(), true)
        );
        assert_eq!(truncate_chars("ab".to_owned(), 2), ("ab".to_owned(), false));
    }
}
