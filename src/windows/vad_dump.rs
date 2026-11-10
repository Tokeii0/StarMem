//! Export a Windows process' VAD ranges to one reviewable file per region.
//!
//! `vad` proves which ranges a process declares; it cannot hand the analyst the
//! bytes. Carving those bytes out of the image by physical offset is possible
//! but not reproducible: the offset is only meaningful for one acquisition, so
//! a write-up built on it cannot be re-run by a reader. This command publishes
//! the same ranges as named files keyed by the process virtual address, which
//! is stable across every tool that can walk the same page tables.
//!
//! The publication rule is the one `linux.proc.dump` already established: a
//! region whose pages are all resident is published as `.dmp`; a region with
//! any missing page keeps the layout by zero-filling the hole but is published
//! as `.dmp.partial`. Zero-filled bytes are never counted as recovered, and the
//! suffix - not a footnote in a report - is what tells the analyst which is
//! which.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::address::X64AddressSpace;
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::profile::KernelProfile;
use crate::windows::plugins::{VadRecord, list_vads};
use crate::windows::{WindowsKernelContext, list_processes};

const PAGE_SIZE: u64 = 4096;
const MANIFEST_NAME: &str = "vad-dump-report.json";

#[derive(Debug, Clone)]
pub struct VadDumpOptions {
    pub pid: u64,
    pub output: PathBuf,
    pub limit: usize,
    pub max_region_size: u64,
    pub max_total_size: u64,
    pub force: bool,
}

/// One contiguous span of a VAD whose pages could not be translated.
#[derive(Debug, Clone, Serialize)]
pub struct VadMissingRange {
    pub virtual_start: u64,
    pub file_offset: u64,
    pub length: u64,
}

#[derive(Debug, Serialize)]
pub struct VadDumpRegion {
    pub index: usize,
    pub node: u64,
    pub start: u64,
    pub end: u64,
    pub protection: u8,
    pub protection_name: String,
    pub vad_type: u8,
    pub private_memory: bool,
    pub file: Option<String>,
    pub output_path: Option<String>,
    pub logical_size: u64,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
    /// True only when every page of the region was translated and read.
    pub complete: bool,
    pub skipped: bool,
    pub skip_reason: Option<String>,
    /// SHA-256 over the published bytes, zero fill included.
    pub logical_sha256: Option<String>,
    /// SHA-256 over the recovered bytes only; differs from `logical_sha256`
    /// exactly when the region has holes.
    pub recovered_sha256: Option<String>,
    pub missing_ranges: Vec<VadMissingRange>,
}

#[derive(Debug, Serialize)]
pub struct VadDumpReport {
    pub pid: u64,
    pub process: String,
    pub directory_table_base: u64,
    pub output_directory: String,
    pub manifest: PathBuf,
    pub regions: Vec<VadDumpRegion>,
    pub vad_count: usize,
    pub regions_written: usize,
    pub regions_complete: usize,
    pub regions_partial: usize,
    pub regions_skipped: usize,
    pub total_logical_bytes: u64,
    pub total_recovered_bytes: u64,
    pub total_missing_bytes: u64,
    pub complete: bool,
    pub max_region_size: u64,
    pub max_total_size: u64,
    pub scope: String,
    pub warnings: Vec<String>,
}

pub fn dump_vads(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &VadDumpOptions,
    cancellation: &CancellationToken,
) -> Result<VadDumpReport> {
    validate_options(options)?;
    cancellation.check_cancelled()?;

    let processes = list_processes(image, kernel, profile, 65_536)?;
    let process = processes
        .processes
        .iter()
        .find(|process| process.pid == options.pid)
        .with_context(|| format!("PsActiveProcessHead 中没有 PID {}", options.pid))?;
    let directory_table_base = process
        .details
        .user_directory_table_base
        .or(process.details.directory_table_base)
        .with_context(|| format!("PID {} 没有可用的 DTB，无法翻译用户地址", options.pid))?;
    let space = X64AddressSpace::new(image, directory_table_base)?;

    let vads = list_vads(image, kernel, profile, options.pid, options.limit)?;
    let mut warnings = processes
        .warnings
        .iter()
        .map(|warning| format!("pslist/{}: {}", warning.kind, warning.message))
        .collect::<Vec<_>>();
    warnings.extend(vads.warnings.iter().cloned());

    let mut output_policy = OutputPolicy::new(options.force);
    for source in image.sources() {
        output_policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    let mut directory_target =
        OutputTarget::directory("vaddump", &options.output).with_owned_file(MANIFEST_NAME);
    for (index, vad) in vads.records.iter().enumerate() {
        let basename = region_basename(index, vad);
        directory_target = directory_target
            .with_owned_file(&basename)
            .with_owned_file(format!("{basename}.partial"));
    }
    output_policy.output(directory_target);
    output_policy.prepare_directories()?;

    let mut regions = Vec::with_capacity(vads.records.len());
    let mut total_logical_bytes = 0u64;
    let mut total_recovered_bytes = 0u64;
    let mut total_missing_bytes = 0u64;

    for (index, vad) in vads.records.iter().enumerate() {
        cancellation.check_cancelled()?;
        // `end` is the last addressable byte of the VAD, not one past it.
        let length = vad
            .end
            .checked_sub(vad.start)
            .and_then(|span| span.checked_add(1))
            .with_context(|| format!("VAD {:#x} 的区间长度非法", vad.node))?;

        if let Some(reason) = skip_reason(options, length, total_logical_bytes) {
            regions.push(skipped_region(index, vad, length, reason));
            total_missing_bytes = total_missing_bytes.saturating_add(length);
            continue;
        }

        total_logical_bytes += length;
        let exclusive_end = vad.start + length;
        let basename = region_basename(index, vad);
        let final_path = options.output.join(&basename);
        let partial_path = options.output.join(format!("{basename}.partial"));
        let expected_complete =
            virtual_region_is_fully_mapped(image, &space, vad.start, exclusive_end);
        let selected_path = if expected_complete {
            &final_path
        } else {
            &partial_path
        };

        let mut dumped = None;
        output_policy.write_file_atomic(selected_path, |output| {
            let result = dump_virtual_region(&space, vad.start, exclusive_end, output)?;
            // The suffix is evidence. If residency changed between the
            // pre-flight check and the write, publishing under the pre-flight
            // suffix would label a holed file as complete.
            ensure!(
                result.complete == expected_complete,
                "VAD 页映射在预检与发布之间发生变化；拒绝发布后缀语义不正确的输出"
            );
            dumped = Some(result);
            Ok(())
        })?;
        let dumped = dumped.context("VAD 导出未生成结果")?;

        if options.force {
            let stale_path = if dumped.complete {
                &partial_path
            } else {
                &final_path
            };
            output_policy.remove_owned_file(stale_path)?;
        }

        let missing = length.saturating_sub(dumped.recovered_bytes);
        total_recovered_bytes += dumped.recovered_bytes;
        total_missing_bytes = total_missing_bytes.saturating_add(missing);
        regions.push(VadDumpRegion {
            index,
            node: vad.node,
            start: vad.start,
            end: vad.end,
            protection: vad.protection,
            protection_name: vad.protection_name.clone(),
            vad_type: vad.vad_type,
            private_memory: vad.private_memory,
            file: vad.file.clone(),
            output_path: Some(selected_path.display().to_string()),
            logical_size: length,
            recovered_bytes: dumped.recovered_bytes,
            missing_bytes: missing,
            complete: dumped.complete,
            skipped: false,
            skip_reason: None,
            logical_sha256: Some(dumped.logical_sha256),
            recovered_sha256: Some(dumped.recovered_sha256),
            missing_ranges: dumped.missing_ranges,
        });
    }

    let regions_written = regions.iter().filter(|region| !region.skipped).count();
    let regions_complete = regions.iter().filter(|region| region.complete).count();
    let regions_partial = regions
        .iter()
        .filter(|region| !region.skipped && !region.complete)
        .count();
    let regions_skipped = regions.iter().filter(|region| region.skipped).count();
    let complete = vads.complete
        && processes.complete
        && regions_partial == 0
        && regions_skipped == 0
        && warnings.is_empty();

    let manifest = options.output.join(MANIFEST_NAME);
    let report = VadDumpReport {
        pid: options.pid,
        process: process.name.clone(),
        directory_table_base,
        output_directory: options.output.display().to_string(),
        manifest: manifest.clone(),
        vad_count: vads.records.len(),
        regions,
        regions_written,
        regions_complete,
        regions_partial,
        regions_skipped,
        total_logical_bytes,
        total_recovered_bytes,
        total_missing_bytes,
        complete,
        max_region_size: options.max_region_size,
        max_total_size: options.max_total_size,
        scope: "one file per VAD of a single active process; present pages copied, \
                missing pages zero-filled and retained only in .partial outputs"
            .to_owned(),
        warnings,
    };
    output_policy.write_file_atomic(&manifest, |file| {
        serde_json::to_writer_pretty(BufWriter::new(file), &report)?;
        Ok(())
    })?;
    Ok(report)
}

fn validate_options(options: &VadDumpOptions) -> Result<()> {
    ensure!(options.limit > 0, "VAD 结果上限必须大于零");
    ensure!(options.max_region_size > 0, "单个 VAD 导出上限必须大于零");
    ensure!(options.max_total_size > 0, "VAD 导出总上限必须大于零");
    Ok(())
}

fn skip_reason(options: &VadDumpOptions, length: u64, accumulated: u64) -> Option<String> {
    if length > options.max_region_size {
        return Some(format!(
            "VAD 长度 {length} 超过单区上限 {}",
            options.max_region_size
        ));
    }
    if accumulated
        .checked_add(length)
        .is_none_or(|total| total > options.max_total_size)
    {
        return Some(format!(
            "加入该 VAD 后超过总上限 {}",
            options.max_total_size
        ));
    }
    None
}

fn skipped_region(index: usize, vad: &VadRecord, length: u64, reason: String) -> VadDumpRegion {
    VadDumpRegion {
        index,
        node: vad.node,
        start: vad.start,
        end: vad.end,
        protection: vad.protection,
        protection_name: vad.protection_name.clone(),
        vad_type: vad.vad_type,
        private_memory: vad.private_memory,
        file: vad.file.clone(),
        output_path: None,
        logical_size: length,
        recovered_bytes: 0,
        missing_bytes: length,
        complete: false,
        skipped: true,
        skip_reason: Some(reason),
        logical_sha256: None,
        recovered_sha256: None,
        missing_ranges: Vec::new(),
    }
}

/// Name a region by its process virtual address so the same VAD gets the same
/// file name from any tool that walks the same page tables.
fn region_basename(index: usize, vad: &VadRecord) -> String {
    format!(
        "{index:04}_{:016x}-{:016x}_{}.dmp",
        vad.start,
        vad.end,
        sanitize_protection(&vad.protection_name)
    )
}

fn sanitize_protection(protection: &str) -> String {
    let cleaned: String = protection
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "UNKNOWN".to_owned()
    } else {
        cleaned
    }
}

struct DumpedRegion {
    recovered_bytes: u64,
    complete: bool,
    logical_sha256: String,
    recovered_sha256: String,
    missing_ranges: Vec<VadMissingRange>,
}

fn dump_virtual_region(
    space: &X64AddressSpace<'_>,
    start: u64,
    end: u64,
    output: &mut File,
) -> Result<DumpedRegion> {
    ensure!(start < end, "导出 VAD 范围为空");
    let mut writer = BufWriter::new(output);
    let mut logical_hasher = Sha256::new();
    let mut recovered_hasher = Sha256::new();
    let zero_page = [0u8; PAGE_SIZE as usize];
    let mut buffer = [0u8; PAGE_SIZE as usize];
    let mut address = start;
    let mut recovered_bytes = 0u64;
    let mut missing_ranges: Vec<VadMissingRange> = Vec::new();
    while address < end {
        let take = usize::try_from((end - address).min(PAGE_SIZE))?;
        let file_offset = address - start;
        if space.read_virtual(address, &mut buffer[..take]).is_ok() {
            writer.write_all(&buffer[..take])?;
            logical_hasher.update(&buffer[..take]);
            recovered_hasher.update(&buffer[..take]);
            recovered_bytes += take as u64;
        } else {
            writer.write_all(&zero_page[..take])?;
            logical_hasher.update(&zero_page[..take]);
            push_missing_range(&mut missing_ranges, address, file_offset, take as u64);
        }
        address += take as u64;
    }
    writer.flush()?;
    Ok(DumpedRegion {
        recovered_bytes,
        complete: missing_ranges.is_empty(),
        logical_sha256: hex::encode(logical_hasher.finalize()),
        recovered_sha256: hex::encode(recovered_hasher.finalize()),
        missing_ranges,
    })
}

fn push_missing_range(
    ranges: &mut Vec<VadMissingRange>,
    virtual_start: u64,
    file_offset: u64,
    length: u64,
) {
    if let Some(last) = ranges.last_mut()
        && last.virtual_start + last.length == virtual_start
        && last.file_offset + last.length == file_offset
    {
        last.length += length;
        return;
    }
    ranges.push(VadMissingRange {
        virtual_start,
        file_offset,
        length,
    });
}

fn virtual_region_is_fully_mapped(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    start: u64,
    end: u64,
) -> bool {
    let mut address = start;
    while address < end {
        let take = (end - address).min(PAGE_SIZE);
        let Ok(physical) = space.translate(address) else {
            return false;
        };
        let Some(last_physical) = physical.checked_add(take - 1) else {
            return false;
        };
        if !image.contains_physical(physical) || !image.contains_physical(last_physical) {
            return false;
        }
        address += take;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(start: u64, end: u64, protection: &str) -> VadRecord {
        VadRecord {
            pid: 4,
            process: "test.exe".to_owned(),
            node: 0xdead_beef,
            start,
            end,
            protection: 4,
            protection_name: protection.to_owned(),
            vad_type: 0,
            private_memory: true,
            file: None,
        }
    }

    #[test]
    fn basename_is_keyed_by_virtual_address() {
        let name = region_basename(7, &record(0x60000, 0x60fff, "READWRITE"));
        assert_eq!(name, "0007_0000000000060000-0000000000060fff_READWRITE.dmp");
    }

    #[test]
    fn protection_characters_unsafe_for_paths_are_replaced() {
        assert_eq!(
            sanitize_protection("EXECUTE/WRITE COPY"),
            "EXECUTE_WRITE_COPY"
        );
        assert_eq!(sanitize_protection(""), "UNKNOWN");
    }

    #[test]
    fn oversized_region_is_skipped_rather_than_truncated() {
        let options = VadDumpOptions {
            pid: 4,
            output: PathBuf::from("out"),
            limit: 16,
            max_region_size: 4096,
            max_total_size: 1 << 20,
            force: false,
        };
        let reason = skip_reason(&options, 8192, 0).expect("oversized region must be skipped");
        assert!(reason.contains("超过单区上限"));
    }

    #[test]
    fn total_budget_stops_before_overrunning() {
        let options = VadDumpOptions {
            pid: 4,
            output: PathBuf::from("out"),
            limit: 16,
            max_region_size: 1 << 20,
            max_total_size: 8192,
            force: false,
        };
        assert!(skip_reason(&options, 4096, 0).is_none());
        let reason = skip_reason(&options, 4096, 8192).expect("budget must stop the walk");
        assert!(reason.contains("超过总上限"));
    }

    #[test]
    fn adjacent_missing_pages_merge_into_one_range() {
        let mut ranges = Vec::new();
        push_missing_range(&mut ranges, 0x1000, 0, 4096);
        push_missing_range(&mut ranges, 0x2000, 4096, 4096);
        push_missing_range(&mut ranges, 0x9000, 0x8000, 4096);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].length, 8192);
        assert_eq!(ranges[1].virtual_start, 0x9000);
    }

    #[test]
    fn skipped_region_never_claims_recovered_bytes() {
        let region = skipped_region(0, &record(0, 0xfff, "READONLY"), 4096, "too big".to_owned());
        assert!(region.skipped);
        assert!(!region.complete);
        assert_eq!(region.recovered_bytes, 0);
        assert_eq!(region.missing_bytes, 4096);
        assert!(region.output_path.is_none());
        assert!(region.logical_sha256.is_none());
    }
}
