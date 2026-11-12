//! Find process memory that was written and then had its protection revoked.
//!
//! `malfind` answers "which private memory is executable". That question misses
//! a whole injection style: allocate `PAGE_READWRITE`, `WriteProcessMemory` a
//! payload in, then `VirtualProtectEx` the pages down to `PAGE_READONLY`. The
//! result is never executable, so every executable-page heuristic reports
//! nothing, while the payload sits in the victim process in plain sight.
//!
//! The tell is that Windows keeps two records of the protection and they stop
//! agreeing. The VAD stores the protection the range was *created* with;
//! the PTEs carry what it is *now*. `VirtualProtectEx` rewrites the PTEs and
//! leaves the VAD alone, so a private, committed range whose VAD says writable
//! and whose resident pages are all read-only is a range that someone wrote to
//! and then closed off. Ordinary allocations do not produce that shape.
//!
//! This plugin reports that disagreement, plus the reverse (a VAD that never
//! asked for execute backing pages that carry it), and annotates each candidate
//! with the cheap triage facts that decide whether it is worth dumping: how much
//! of it is resident, its Shannon entropy, and its first printable run.
//!
//! Evidence rules: a page that cannot be translated proves nothing about the
//! protection of that page. Regions with missing pages keep their findings but
//! report `pages_missing`, and any such region clears `complete` for the whole
//! report - the search universe was not fully observable.

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::address::{VirtualAddressRegion, VirtualMapping, X64AddressSpace};
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::windows::plugins::{VadRecord, list_vads_cancellable};
use crate::windows::{WindowsKernelContext, list_processes};

const PAGE_SIZE: u64 = 4096;
const MAX_ACTIVE_PROCESSES: usize = 65_536;
const MAX_MAPPINGS_PER_PROCESS: usize = 1_048_576;
/// Bytes read per region for the entropy/printable summary. The summary is
/// triage, not evidence, so it is capped rather than allowed to read GiB.
const TRIAGE_SAMPLE_BYTES: usize = 64 * 1024;
const PRINTABLE_RUN_MIN: usize = 8;
const PRINTABLE_PREVIEW_MAX: usize = 96;

#[derive(Debug, Clone)]
pub struct InjectedRegionOptions {
    pub pid: Option<u64>,
    /// Also report private+executable regions. Off by default because
    /// `malfind` already owns that question; on when a single sweep is wanted.
    pub include_executable: bool,
    /// Report protection disagreements in regions that are not fully resident.
    /// Off by default: if some pages could not be observed, "every page is
    /// read-only" is not something the image proves.
    pub include_partial: bool,
    pub vad_limit: usize,
    pub limit: usize,
}

impl Default for InjectedRegionOptions {
    fn default() -> Self {
        Self {
            pid: None,
            include_executable: false,
            include_partial: false,
            vad_limit: 1_000_000,
            limit: 65_536,
        }
    }
}

/// Why a region was reported. Each variant is a statement about observed
/// structure, not a verdict about intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionSignal {
    /// VAD was created writable; every resident page is now read-only.
    WriteRevoked,
    /// VAD never asked for execute; resident pages carry it.
    ExecuteAdded,
    /// Private, committed and executable - the classic `malfind` shape.
    PrivateExecutable,
}

impl InjectionSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WriteRevoked => "write_revoked",
            Self::ExecuteAdded => "execute_added",
            Self::PrivateExecutable => "private_executable",
        }
    }

    pub fn explanation(self) -> &'static str {
        match self {
            Self::WriteRevoked => {
                "VAD 声明可写，但全部驻留页的 PTE 均为只读：写入后调用 VirtualProtectEx 撤销写权限的典型形状"
            }
            Self::ExecuteAdded => "VAD 未声明可执行，驻留页却带执行位",
            Self::PrivateExecutable => "私有已提交且可执行（malfind 同款判据）",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct InjectedRegionRecord {
    pub pid: u64,
    pub process: String,
    pub node: u64,
    pub start: u64,
    pub end: u64,
    pub length: u64,
    pub vad_protection: u8,
    pub vad_protection_name: String,
    pub vad_writable: bool,
    pub vad_executable: bool,
    pub private_memory: bool,
    pub file: Option<String>,
    pub pages_total: u64,
    pub pages_resident: u64,
    pub pages_missing: u64,
    pub pages_writable: u64,
    pub pages_executable: u64,
    pub signals: Vec<InjectionSignal>,
    pub signal_names: Vec<&'static str>,
    pub explanations: Vec<&'static str>,
    /// Shannon entropy over the sampled resident bytes, 0.0-8.0.
    pub entropy: Option<f64>,
    pub sampled_bytes: u64,
    /// First printable ASCII run of at least eight characters.
    pub first_printable: Option<String>,
    /// True only when every page of the region was translated.
    pub complete: bool,
}

#[derive(Debug, Serialize)]
pub struct InjectedRegionReport {
    pub records: Vec<InjectedRegionRecord>,
    pub processes_examined: usize,
    pub vads_examined: usize,
    pub candidate_vads: usize,
    pub regions_with_missing_pages: usize,
    pub include_executable: bool,
    pub include_partial: bool,
    pub complete: bool,
    pub scope: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectedRegionStage {
    Processes,
    VadTree,
    PageTables,
    Regions,
}

#[derive(Debug, Clone, Copy)]
pub struct InjectedRegionProgress {
    pub stage: InjectedRegionStage,
    pub pid: Option<u64>,
    pub process_index: usize,
    pub process_total: usize,
}

pub fn find_injected_regions(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &InjectedRegionOptions,
    cancellation: &CancellationToken,
) -> Result<InjectedRegionReport> {
    find_injected_regions_with_progress(image, kernel, profile, options, cancellation, |_| {})
}

pub fn find_injected_regions_with_progress(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &InjectedRegionOptions,
    cancellation: &CancellationToken,
    mut progress: impl FnMut(InjectedRegionProgress),
) -> Result<InjectedRegionReport> {
    ensure!(options.limit > 0, "注入区间结果上限必须大于零");
    ensure!(options.vad_limit > 0, "VAD 遍历上限必须大于零");
    cancellation.check_cancelled()?;

    progress(InjectedRegionProgress {
        stage: InjectedRegionStage::Processes,
        pid: None,
        process_index: 0,
        process_total: 0,
    });
    let processes = list_processes(image, kernel, profile, MAX_ACTIVE_PROCESSES)?;
    let mut warnings = processes
        .warnings
        .iter()
        .map(|warning| format!("pslist/{}: {}", warning.kind, warning.message))
        .collect::<Vec<_>>();
    let mut complete = processes.complete;
    let mut matched_requested_pid = options.pid.is_none();

    let mut records = Vec::new();
    let mut processes_examined = 0usize;
    let mut vads_examined = 0usize;
    let mut candidate_vads = 0usize;
    let mut truncated = false;

    let selected_processes = processes
        .processes
        .iter()
        .filter(|process| options.pid.is_none_or(|pid| process.pid == pid))
        .collect::<Vec<_>>();
    for (process_index, process) in selected_processes.iter().enumerate() {
        cancellation.check_cancelled()?;
        if let Some(pid) = options.pid {
            if process.pid != pid {
                continue;
            }
            matched_requested_pid = true;
        }
        let Some(dtb) = process
            .details
            .user_directory_table_base
            .or(process.details.directory_table_base)
        else {
            warnings.push(format!("PID {} 没有可用的 DTB，已跳过", process.pid));
            complete = false;
            continue;
        };
        let Ok(space) = X64AddressSpace::new(image, dtb) else {
            warnings.push(format!("PID {} 的页表根不可读，已跳过", process.pid));
            complete = false;
            continue;
        };
        let mut process_progress = InjectedRegionProgress {
            stage: InjectedRegionStage::VadTree,
            pid: Some(process.pid),
            process_index: process_index + 1,
            process_total: selected_processes.len(),
        };
        progress(process_progress);
        let vads = match list_vads_cancellable(
            image,
            kernel,
            profile,
            process.pid,
            options.vad_limit,
            cancellation,
        ) {
            Ok(vads) => vads,
            Err(error) => {
                cancellation.check_cancelled()?;
                warnings.push(format!("PID {} 的 VAD 遍历失败：{error:#}", process.pid));
                complete = false;
                continue;
            }
        };
        if !vads.complete {
            complete = false;
        }
        warnings.extend(
            vads.warnings
                .iter()
                .map(|warning| format!("PID {}: {warning}", process.pid)),
        );

        processes_examined += 1;
        vads_examined += vads.records.len();
        if !vads.records.iter().any(is_candidate) {
            continue;
        }
        process_progress.stage = InjectedRegionStage::PageTables;
        progress(process_progress);
        let mappings = match space.enumerate_mappings_cancellable(
            VirtualAddressRegion::User,
            MAX_MAPPINGS_PER_PROCESS,
            cancellation,
        ) {
            Ok(report) => report,
            Err(error) => {
                cancellation.check_cancelled()?;
                warnings.push(format!("PID {} 的用户页表遍历失败：{error:#}", process.pid));
                complete = false;
                continue;
            }
        };
        if mappings.truncated {
            warnings.push(format!(
                "PID {} 的用户映射达到 {MAX_MAPPINGS_PER_PROCESS} 条上限",
                process.pid
            ));
            complete = false;
        }
        if !mappings.warnings.is_empty() {
            complete = false;
            warnings.extend(
                mappings
                    .warnings
                    .iter()
                    .map(|warning| format!("PID {}: {warning}", process.pid)),
            );
        }
        process_progress.stage = InjectedRegionStage::Regions;
        progress(process_progress);

        for vad in &vads.records {
            cancellation.check_cancelled()?;
            if !is_candidate(vad) {
                continue;
            }
            candidate_vads += 1;
            let Some(record) = evaluate_region(
                &space,
                process.pid,
                &process.name,
                vad,
                &mappings.mappings,
                options,
                cancellation,
            )?
            else {
                continue;
            };
            if !record.complete {
                complete = false;
            }
            if records.len() >= options.limit {
                truncated = true;
                break;
            }
            records.push(record);
        }
        if truncated {
            break;
        }
    }

    if let Some(pid) = options.pid {
        ensure!(
            matched_requested_pid,
            "PsActiveProcessHead 中没有 PID {pid}"
        );
    }
    if truncated {
        warnings.push(format!("注入区间结果达到 {} 条上限", options.limit));
        complete = false;
    }

    let regions_with_missing_pages = records.iter().filter(|r| r.pages_missing > 0).count();
    Ok(InjectedRegionReport {
        processes_examined,
        vads_examined,
        candidate_vads,
        regions_with_missing_pages,
        include_executable: options.include_executable,
        include_partial: options.include_partial,
        complete,
        scope: "fully resident private committed user VADs whose PTE-effective \
                protection disagrees with the protection recorded in the VAD"
            .to_owned(),
        warnings,
        records,
    })
}

/// Only private, committed, user-space ranges are in scope. File-backed
/// sections legitimately carry protections that differ from the VAD.
fn is_candidate(vad: &VadRecord) -> bool {
    vad.private_memory && vad.file.is_none() && vad.end > vad.start
}

/// enumerate_mappings returns sorted, disjoint ranges. Keep those ranges compact:
/// a sparse multi-TiB VAD must not become billions of absent-page lookups, and a
/// large-page mapping must not allocate a HashMap entry for every 4 KiB page.
fn overlapping_mappings(mappings: &[VirtualMapping], start: u64, end: u64) -> &[VirtualMapping] {
    let first = mappings.partition_point(|mapping| mapping.virtual_end <= start);
    let count = mappings[first..].partition_point(|mapping| mapping.virtual_start < end);
    &mappings[first..first + count]
}

fn mapped_page_counts(
    mappings: &[VirtualMapping],
    start: u64,
    end: u64,
    cancellation: &CancellationToken,
) -> Result<(u64, u64, u64)> {
    cancellation.check_cancelled()?;
    let mut counts = (0, 0, 0);
    for mapping in overlapping_mappings(mappings, start, end) {
        cancellation.check_cancelled()?;
        let overlap_start = start.max(mapping.virtual_start);
        let overlap_end = end.min(mapping.virtual_end);
        let pages = (overlap_end - 1) / PAGE_SIZE - overlap_start / PAGE_SIZE + 1;
        counts.0 += pages;
        if mapping.writable {
            counts.1 += pages;
        }
        if mapping.executable {
            counts.2 += pages;
        }
    }
    Ok(counts)
}

fn evaluate_region(
    space: &X64AddressSpace<'_>,
    pid: u64,
    process: &str,
    vad: &VadRecord,
    mappings: &[VirtualMapping],
    options: &InjectedRegionOptions,
    cancellation: &CancellationToken,
) -> Result<Option<InjectedRegionRecord>> {
    let length = vad
        .end
        .checked_sub(vad.start)
        .and_then(|span| span.checked_add(1))
        .with_context(|| format!("VAD {:#x} 的区间长度非法", vad.node))?;
    let region_end = vad
        .end
        .checked_add(1)
        .with_context(|| format!("VAD {:#x} 的结束地址溢出", vad.node))?;
    let pages_total = vad.end / PAGE_SIZE - vad.start / PAGE_SIZE + 1;
    let (pages_resident, pages_writable, pages_executable) =
        mapped_page_counts(mappings, vad.start, region_end, cancellation)?;
    let pages_missing = pages_total.saturating_sub(pages_resident);

    let vad_writable = protection_is_writable(vad.protection, &vad.protection_name);
    let vad_executable = protection_is_executable(vad.protection, &vad.protection_name);

    let observation = PageObservation {
        pages_resident,
        pages_missing,
        pages_writable,
        pages_executable,
        vad_writable,
        vad_executable,
    };
    let signals = decide_signals(&observation, options);
    if signals.is_empty() {
        return Ok(None);
    }

    let (entropy, sampled_bytes, first_printable) =
        triage_sample(space, mappings, vad.start, region_end, cancellation)?;

    Ok(Some(InjectedRegionRecord {
        pid,
        process: process.to_owned(),
        node: vad.node,
        start: vad.start,
        end: vad.end,
        length,
        vad_protection: vad.protection,
        vad_protection_name: vad.protection_name.clone(),
        vad_writable,
        vad_executable,
        private_memory: vad.private_memory,
        file: vad.file.clone(),
        pages_total,
        pages_resident,
        pages_missing,
        pages_writable,
        pages_executable,
        signal_names: signals.iter().map(|signal| signal.as_str()).collect(),
        explanations: signals.iter().map(|signal| signal.explanation()).collect(),
        signals,
        entropy,
        sampled_bytes,
        first_printable,
        complete: pages_missing == 0,
    }))
}

// `_MMVAD_FLAGS.Protection` low three bits, from the MM_* protection table:
//   0 NOACCESS   1 READONLY          2 EXECUTE            3 EXECUTE_READ
//   4 READWRITE  5 WRITECOPY         6 EXECUTE_READWRITE  7 EXECUTE_WRITECOPY
const MM_PROTECTION_MASK: u8 = 0x7;
const MM_READWRITE: u8 = 4;
const MM_WRITECOPY: u8 = 5;
const MM_EXECUTE: u8 = 2;
const MM_EXECUTE_READ: u8 = 3;
const MM_EXECUTE_READWRITE: u8 = 6;
const MM_EXECUTE_WRITECOPY: u8 = 7;

/// The decoded name is authoritative when the profile produced one; the numeric
/// value is the fallback for builds whose bitfield decode yielded no name.
fn protection_is_writable(protection: u8, name: &str) -> bool {
    if name.contains("WRITE") {
        return true;
    }
    matches!(
        protection & MM_PROTECTION_MASK,
        MM_READWRITE | MM_WRITECOPY | MM_EXECUTE_READWRITE | MM_EXECUTE_WRITECOPY
    )
}

fn protection_is_executable(protection: u8, name: &str) -> bool {
    if name.contains("EXECUTE") {
        return true;
    }
    matches!(
        protection & MM_PROTECTION_MASK,
        MM_EXECUTE | MM_EXECUTE_READ | MM_EXECUTE_READWRITE | MM_EXECUTE_WRITECOPY
    )
}

fn triage_sample(
    space: &X64AddressSpace<'_>,
    mappings: &[VirtualMapping],
    start: u64,
    end: u64,
    cancellation: &CancellationToken,
) -> Result<(Option<f64>, u64, Option<String>)> {
    let span = end.saturating_sub(start);
    let want = span.min(TRIAGE_SAMPLE_BYTES as u64) as usize;
    if want == 0 {
        return Ok((None, 0, None));
    }
    let mut sample = Vec::with_capacity(want);
    let mut buffer = [0u8; PAGE_SIZE as usize];
    let mut attempted = 0;
    let mut contiguous = Vec::new();
    let mut previous_end = None;
    let mut printable = None;
    for mapping in overlapping_mappings(mappings, start, end) {
        let mut address = start.max(mapping.virtual_start);
        let mapping_end = end.min(mapping.virtual_end);
        while attempted < want && address < mapping_end {
            cancellation.check_cancelled()?;
            let take = ((mapping_end - address).min(PAGE_SIZE - address % PAGE_SIZE) as usize)
                .min(want - attempted);
            attempted += take; // Unreadable physical backing must also consume the sample budget.
            if previous_end != Some(address) {
                printable = printable.or_else(|| first_printable_run(&contiguous));
                contiguous.clear();
            }
            if space.read_virtual(address, &mut buffer[..take]).is_ok() {
                sample.extend_from_slice(&buffer[..take]);
                contiguous.extend_from_slice(&buffer[..take]);
                previous_end = Some(address + take as u64);
            } else {
                printable = printable.or_else(|| first_printable_run(&contiguous));
                contiguous.clear();
                previous_end = None;
            }
            address += take as u64;
        }
        if attempted >= want {
            break;
        }
    }
    if sample.is_empty() {
        return Ok((None, 0, None));
    }
    let entropy = shannon_entropy(&sample);
    let printable = printable.or_else(|| first_printable_run(&contiguous));
    Ok((Some(entropy), sample.len() as u64, printable))
}

fn shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let total = data.len() as f64;
    -counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

fn first_printable_run(data: &[u8]) -> Option<String> {
    let mut run_start = None;
    for (index, &byte) in data.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&byte);
        match (printable, run_start) {
            (true, None) => run_start = Some(index),
            (false, Some(begin)) => {
                if index - begin >= PRINTABLE_RUN_MIN {
                    return Some(clip(&data[begin..index]));
                }
                run_start = None;
            }
            _ => {}
        }
    }
    if let Some(begin) = run_start
        && data.len() - begin >= PRINTABLE_RUN_MIN
    {
        return Some(clip(&data[begin..]));
    }
    None
}

fn clip(bytes: &[u8]) -> String {
    let end = bytes.len().min(PRINTABLE_PREVIEW_MAX);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// What the page tables actually showed for one VAD.
#[derive(Debug, Clone, Copy)]
struct PageObservation {
    pages_resident: u64,
    pages_missing: u64,
    pages_writable: u64,
    pages_executable: u64,
    vad_writable: bool,
    vad_executable: bool,
}

/// Decide which signals the observation supports.
///
/// The residency gate is the load-bearing rule. "Every page is read-only" is
/// only observable when every page was observed; with pages missing, an unseen
/// page could carry write access, so the claim is not supported. Callers that
/// want the weaker candidates must ask for them, and those records still carry
/// `pages_missing` so the reader can see why they are weaker.
fn decide_signals(
    observation: &PageObservation,
    options: &InjectedRegionOptions,
) -> Vec<InjectionSignal> {
    let mut signals = Vec::new();
    if observation.pages_resident == 0 {
        return signals;
    }
    let fully_observed = observation.pages_missing == 0;
    if !fully_observed && !options.include_partial {
        return signals;
    }
    if observation.vad_writable && observation.pages_writable == 0 {
        signals.push(InjectionSignal::WriteRevoked);
    }
    if !observation.vad_executable && observation.pages_executable > 0 {
        signals.push(InjectionSignal::ExecuteAdded);
    }
    if options.include_executable && observation.pages_executable > 0 {
        signals.push(InjectionSignal::PrivateExecutable);
    }
    signals.dedup();
    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vad(protection: u8, name: &str, private: bool) -> VadRecord {
        VadRecord {
            pid: 2932,
            process: "notepad.exe".to_owned(),
            node: 0xfffffa8001d51de0,
            start: 0x60000,
            end: 0x60fff,
            protection,
            protection_name: name.to_owned(),
            vad_type: 0,
            private_memory: private,
            file: None,
        }
    }

    fn observation(resident: u64, missing: u64, writable: u64) -> PageObservation {
        PageObservation {
            pages_resident: resident,
            pages_missing: missing,
            pages_writable: writable,
            pages_executable: 0,
            vad_writable: true,
            vad_executable: false,
        }
    }

    #[test]
    fn write_revoked_needs_every_page_observed() {
        let options = InjectedRegionOptions::default();
        // the whoami case: one page, resident, no write access left
        assert_eq!(
            decide_signals(&observation(1, 0, 0), &options),
            vec![InjectionSignal::WriteRevoked]
        );
        // 11 of 128 pages resident: the 117 unseen pages could be writable, so
        // the claim is not supported and nothing is reported
        assert!(decide_signals(&observation(11, 117, 0), &options).is_empty());
    }

    #[test]
    fn partial_regions_are_reported_only_when_asked_for() {
        let options = InjectedRegionOptions {
            include_partial: true,
            ..InjectedRegionOptions::default()
        };
        assert_eq!(
            decide_signals(&observation(11, 117, 0), &options),
            vec![InjectionSignal::WriteRevoked]
        );
    }

    #[test]
    fn a_writable_page_disproves_the_downgrade() {
        let options = InjectedRegionOptions::default();
        assert!(decide_signals(&observation(16, 0, 1), &options).is_empty());
    }

    #[test]
    fn no_resident_page_proves_nothing() {
        let options = InjectedRegionOptions {
            include_partial: true,
            ..InjectedRegionOptions::default()
        };
        assert!(decide_signals(&observation(0, 64, 0), &options).is_empty());
    }

    #[test]
    fn execute_added_is_independent_of_the_write_signal() {
        let options = InjectedRegionOptions::default();
        let observation = PageObservation {
            pages_resident: 4,
            pages_missing: 0,
            pages_writable: 4,
            pages_executable: 4,
            vad_writable: true,
            vad_executable: false,
        };
        assert_eq!(
            decide_signals(&observation, &options),
            vec![InjectionSignal::ExecuteAdded]
        );
    }

    #[test]
    fn malfind_shape_is_opt_in() {
        let observation = PageObservation {
            pages_resident: 4,
            pages_missing: 0,
            pages_writable: 4,
            pages_executable: 4,
            vad_writable: true,
            vad_executable: true,
        };
        assert!(decide_signals(&observation, &InjectedRegionOptions::default()).is_empty());
        let options = InjectedRegionOptions {
            include_executable: true,
            ..InjectedRegionOptions::default()
        };
        assert_eq!(
            decide_signals(&observation, &options),
            vec![InjectionSignal::PrivateExecutable]
        );
    }

    #[test]
    fn file_backed_and_shared_ranges_are_out_of_scope() {
        let mut record = vad(4, "READWRITE", true);
        assert!(is_candidate(&record));
        record.private_memory = false;
        assert!(!is_candidate(&record));
        let mut record = vad(4, "READWRITE", true);
        record.file = Some("\\Windows\\System32\\notepad.exe".to_owned());
        assert!(!is_candidate(&record));
    }

    #[test]
    fn protection_names_drive_the_writable_and_executable_decode() {
        assert!(protection_is_writable(4, "READWRITE"));
        assert!(protection_is_writable(0, "EXECUTE_WRITECOPY"));
        assert!(!protection_is_writable(1, "READONLY"));
        assert!(protection_is_executable(0, "EXECUTE_WRITECOPY"));
        assert!(!protection_is_executable(1, "READONLY"));
    }

    #[test]
    fn numeric_protection_is_the_fallback_when_no_name_was_decoded() {
        for value in [
            MM_READWRITE,
            MM_WRITECOPY,
            MM_EXECUTE_READWRITE,
            MM_EXECUTE_WRITECOPY,
        ] {
            assert!(protection_is_writable(value, ""), "{value}");
        }
        for value in [0u8, 1, MM_EXECUTE, MM_EXECUTE_READ] {
            assert!(!protection_is_writable(value, ""), "{value}");
        }
        for value in [
            MM_EXECUTE,
            MM_EXECUTE_READ,
            MM_EXECUTE_READWRITE,
            MM_EXECUTE_WRITECOPY,
        ] {
            assert!(protection_is_executable(value, ""), "{value}");
        }
        for value in [0u8, 1, MM_READWRITE, MM_WRITECOPY] {
            assert!(!protection_is_executable(value, ""), "{value}");
        }
    }

    #[test]
    fn entropy_separates_structured_bytes_from_random_ones() {
        let zeros = vec![0u8; 4096];
        assert!(shannon_entropy(&zeros) < 0.01);
        let spread: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(shannon_entropy(&spread) > 7.9);
    }

    #[test]
    fn printable_run_needs_a_minimum_length() {
        assert_eq!(first_printable_run(b"\x00\x01ab\x00"), None);
        assert_eq!(
            first_printable_run(b"\x00C:\\Users\\alice\x00").as_deref(),
            Some("C:\\Users\\alice")
        );
    }

    #[test]
    fn printable_run_is_clipped_for_preview() {
        let long = vec![b'A'; PRINTABLE_PREVIEW_MAX * 2];
        let run = first_printable_run(&long).expect("run must be found");
        assert_eq!(run.len(), PRINTABLE_PREVIEW_MAX);
    }

    #[test]
    fn merged_mapping_counts_every_page_without_expanding_it() {
        let report = crate::address::VirtualMappingReport {
            directory_table_base: 0x1000,
            region: "user".to_owned(),
            mapped_bytes: 8192,
            mapping_count: 1,
            page_table_pages_read: 1,
            truncated: false,
            mappings: vec![crate::address::VirtualMapping {
                virtual_start: 0x60000,
                virtual_end: 0x62000,
                physical_start: 0xefc7000,
                length: 8192,
                source_page_size: 4096,
                writable: false,
                user_accessible: true,
                executable: false,
                global: false,
            }],
            warnings: Vec::new(),
        };
        let token = CancellationToken::new();
        assert_eq!(
            mapped_page_counts(&report.mappings, 0x60000, 0x62000, &token).unwrap(),
            (2, 0, 0)
        );
        assert_eq!(
            mapped_page_counts(&report.mappings, 0x61000, 0x62000, &token).unwrap(),
            (1, 0, 0)
        );
        assert_eq!(
            mapped_page_counts(&report.mappings, 0x62000, 0x63000, &token).unwrap(),
            (0, 0, 0)
        );
    }
}

#[cfg(test)]
mod performance_tests;
