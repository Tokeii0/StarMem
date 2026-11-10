//! Recover timestamp-linked GNU Bash `HIST_ENTRY` objects from process heaps.
//!
//! A record is emitted only when a heap pointer links a plausible `HIST_ENTRY.timestamp`
//! field to a `#<epoch>` string and the adjacent line pointer resolves to terminated text.
//! This intentionally excludes un-timestamped history and arbitrary printable remnants.

use std::collections::HashSet;

use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::image::MemoryImage;
use crate::linux::{LinuxKernelContext, LinuxProcessListReport};
use crate::linux_process::{
    LinuxProcessArtifactWarning, LinuxProcessProfileEvidence, LinuxVirtualMissingRange,
    bash_process_memory, process_profile_evidence, read_process_c_string,
    read_process_range_for_bash,
};

#[derive(Debug, Clone, Serialize)]
pub struct LinuxBashScanRegion {
    pub pid: i32,
    pub process_name: String,
    pub start: u64,
    pub start_hex: String,
    pub end: u64,
    pub end_hex: String,
    pub path: Option<String>,
    pub requested_bytes: u64,
    pub scanned_bytes: u64,
    pub recovered_bytes: u64,
    pub complete: bool,
    pub truncated: bool,
    pub missing_ranges: Vec<LinuxVirtualMissingRange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxBashHistoryRecord {
    pub task: u64,
    pub task_hex: String,
    pub pid: i32,
    pub process_name: String,
    pub hist_entry: u64,
    pub hist_entry_hex: String,
    pub line_address: u64,
    pub line_address_hex: String,
    pub timestamp_address: u64,
    pub timestamp_address_hex: String,
    pub timestamp_raw: String,
    pub timestamp_epoch: u64,
    pub timestamp_utc: Option<String>,
    pub command: String,
    pub entry_backreference_found: bool,
    pub confidence: String,
}

#[derive(Debug, Serialize)]
pub struct LinuxBashReport {
    pub source: String,
    pub kernel: LinuxKernelContext,
    pub profile: LinuxProcessProfileEvidence,
    pub scan_regions: Vec<LinuxBashScanRegion>,
    pub records: Vec<LinuxBashHistoryRecord>,
    pub bash_processes: usize,
    pub scan_region_count: usize,
    pub record_count: usize,
    pub total_scanned_bytes: u64,
    pub total_recovered_bytes: u64,
    pub process_list_complete: bool,
    pub complete: bool,
    pub map_limit: usize,
    pub max_scan_bytes: u64,
    pub max_command_bytes: usize,
    pub scope: String,
    pub limitations: Vec<String>,
    pub warnings: Vec<LinuxProcessArtifactWarning>,
}

struct MemorySegment {
    start: u64,
    bytes: Vec<u8>,
}

pub fn analyze_bash_history(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    processes: &LinuxProcessListReport,
    pid: Option<i32>,
    map_limit: usize,
    max_scan_bytes: u64,
    max_command_bytes: usize,
) -> Result<LinuxBashReport> {
    ensure!(map_limit > 0, "Bash VMA 结果上限必须大于零");
    ensure!(max_scan_bytes > 0, "Bash 扫描字节上限必须大于零");
    ensure!(max_command_bytes > 0, "Bash 命令长度上限必须大于零");
    let mut warnings = processes
        .warnings
        .iter()
        .map(|warning| {
            LinuxProcessArtifactWarning::new(
                format!("pslist.{}", warning.kind),
                warning.message.clone(),
                None,
                warning.list_entry,
            )
        })
        .collect::<Vec<_>>();
    let memories = bash_process_memory(image, kernel, processes, pid, map_limit, &mut warnings)?;
    if pid.is_some() {
        ensure!(!memories.is_empty(), "指定 PID 不是活动 Bash 进程");
    }
    let bash_processes = memories.len();
    let mut scan_regions = Vec::new();
    let mut records = Vec::new();
    let mut remaining = max_scan_bytes;
    let mut complete = processes.complete;
    for memory in memories {
        if remaining == 0 {
            complete = false;
            warnings.push(LinuxProcessArtifactWarning::new(
                "bash_scan_limit",
                "达到 Bash 扫描总字节上限，未扫描其余候选 VMA",
                Some(memory.process.pid),
                None,
            ));
            break;
        }
        let mut segments = Vec::new();
        let candidates = memory
            .maps
            .iter()
            .filter(|mapping| mapping.vm_flags & 0x2 != 0)
            .filter(|mapping| mapping.path.as_deref() == Some("[heap]") || mapping.path.is_none());
        for mapping in candidates {
            if remaining == 0 {
                complete = false;
                break;
            }
            let allowed = mapping.length.min(remaining);
            let end = mapping.start + allowed;
            let (bytes, recovered_bytes, missing_ranges, range_truncated) =
                read_process_range_for_bash(&memory.space, mapping.start, end, allowed)?;
            let truncated = range_truncated || allowed < mapping.length;
            let region_complete = missing_ranges.is_empty() && !truncated;
            complete &= region_complete;
            remaining -= allowed;
            scan_regions.push(LinuxBashScanRegion {
                pid: memory.process.pid,
                process_name: memory.process.name.clone(),
                start: mapping.start,
                start_hex: format_address(mapping.start),
                end: mapping.end,
                end_hex: format_address(mapping.end),
                path: mapping.path.clone(),
                requested_bytes: mapping.length,
                scanned_bytes: allowed,
                recovered_bytes,
                complete: region_complete,
                truncated,
                missing_ranges,
            });
            segments.push(MemorySegment {
                start: mapping.start,
                bytes,
            });
        }
        let timestamps = find_timestamps(&segments);
        let mut seen_records = HashSet::new();
        for (timestamp_address, timestamp_raw, timestamp_epoch) in timestamps {
            for pointer_field in find_pointer_references(&segments, timestamp_address) {
                if pointer_field < 8 {
                    continue;
                }
                let hist_entry = pointer_field - 8;
                let Ok(line_address) = memory.space.read_u64(hist_entry) else {
                    continue;
                };
                let Ok(command) =
                    read_process_c_string(&memory.space, line_address, max_command_bytes)
                else {
                    continue;
                };
                if !seen_records.insert((hist_entry, line_address, timestamp_address)) {
                    continue;
                }
                let entry_backreference_found = contains_pointer_reference(&segments, hist_entry);
                let timestamp_utc = i64::try_from(timestamp_epoch)
                    .ok()
                    .and_then(|epoch| DateTime::<Utc>::from_timestamp(epoch, 0))
                    .map(|value| value.to_rfc3339());
                records.push(LinuxBashHistoryRecord {
                    task: memory.process.task,
                    task_hex: format_address(memory.process.task),
                    pid: memory.process.pid,
                    process_name: memory.process.name.clone(),
                    hist_entry,
                    hist_entry_hex: format_address(hist_entry),
                    line_address,
                    line_address_hex: format_address(line_address),
                    timestamp_address,
                    timestamp_address_hex: format_address(timestamp_address),
                    timestamp_raw: timestamp_raw.clone(),
                    timestamp_epoch,
                    timestamp_utc,
                    command,
                    entry_backreference_found,
                    confidence: if entry_backreference_found {
                        "validated_hist_entry_with_array_backreference"
                    } else {
                        "timestamp_linked_hist_entry"
                    }
                    .to_owned(),
                });
            }
        }
    }
    records.sort_by_key(|record| (record.pid, record.timestamp_epoch, record.hist_entry));
    let total_scanned_bytes = scan_regions.iter().map(|region| region.scanned_bytes).sum();
    let total_recovered_bytes = scan_regions
        .iter()
        .map(|region| region.recovered_bytes)
        .sum();
    Ok(LinuxBashReport {
        source: "linux.bash.timestamp_linked_hist_entry".to_owned(),
        kernel: kernel.clone(),
        profile: process_profile_evidence(kernel)?,
        bash_processes,
        scan_region_count: scan_regions.len(),
        record_count: records.len(),
        total_scanned_bytes,
        total_recovered_bytes,
        process_list_complete: processes.complete,
        complete,
        map_limit,
        max_scan_bytes,
        max_command_bytes,
        scope: "writable anonymous/heap VMAs of active Bash thread-group leaders; #epoch timestamp strings linked through HIST_ENTRY.timestamp and adjacent line pointers".to_owned(),
        limitations: vec![
            "未带时间戳、已退出 Bash、未驻留页及不符合 HIST_ENTRY 指针关系的命令不会被恢复".to_owned(),
            "complete 仅表示声明扫描范围无缺页/截断，不表示 Bash 历史在语义上穷尽".to_owned(),
        ],
        scan_regions,
        records,
        warnings,
    })
}

fn find_timestamps(segments: &[MemorySegment]) -> Vec<(u64, String, u64)> {
    let mut output = Vec::new();
    for segment in segments {
        let bytes = &segment.bytes;
        let mut index = 0usize;
        while index < bytes.len() {
            if bytes[index] != b'#' {
                index += 1;
                continue;
            }
            let mut end = index + 1;
            while end < bytes.len() && bytes[end].is_ascii_digit() && end - index <= 13 {
                end += 1;
            }
            let digits = end.saturating_sub(index + 1);
            if (9..=12).contains(&digits)
                && end < bytes.len()
                && bytes[end] == 0
                && let Ok(text) = std::str::from_utf8(&bytes[index..end])
                && let Ok(epoch) = text[1..].parse::<u64>()
            {
                output.push((segment.start + index as u64, text.to_owned(), epoch));
            }
            index = end.max(index + 1);
        }
    }
    output
}

fn find_pointer_references(segments: &[MemorySegment], target: u64) -> Vec<u64> {
    let needle = target.to_le_bytes();
    let mut output = Vec::new();
    for segment in segments {
        let alignment = usize::try_from((8 - (segment.start & 7)) & 7).unwrap_or(0);
        let mut offset = alignment;
        while offset + 8 <= segment.bytes.len() {
            if segment.bytes[offset..offset + 8] == needle {
                output.push(segment.start + offset as u64);
            }
            offset += 8;
        }
    }
    output
}

fn contains_pointer_reference(segments: &[MemorySegment], target: u64) -> bool {
    !find_pointer_references(segments, target).is_empty()
}

fn format_address(address: u64) -> String {
    format!("0x{address:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_epoch_timestamps_and_aligned_pointer_references() {
        let timestamp_address = 0x4010u64;
        let mut bytes = vec![0u8; 64];
        bytes[16..28].copy_from_slice(b"#1646000000\0");
        bytes[40..48].copy_from_slice(&timestamp_address.to_le_bytes());
        let segments = [MemorySegment {
            start: 0x4000,
            bytes,
        }];
        let timestamps = find_timestamps(&segments);
        assert_eq!(timestamps[0].0, timestamp_address);
        assert_eq!(timestamps[0].2, 1_646_000_000);
        assert_eq!(
            find_pointer_references(&segments, timestamp_address),
            [0x4028]
        );
    }

    #[test]
    fn rejects_non_epoch_hash_strings() {
        let segments = [MemorySegment {
            start: 0x1000,
            bytes: b"#abc\0#123\0".to_vec(),
        }];
        assert!(find_timestamps(&segments).is_empty());
    }
}
