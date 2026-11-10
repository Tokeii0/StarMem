use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use regex::bytes::Regex;
use serde::Serialize;

use super::plugins::{VadRecord, list_vads};
use super::{ProcessRecord, WindowsKernelContext, list_processes};
use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;

#[derive(Debug, Serialize)]
pub struct VadRegexReport {
    pub records: Vec<VadRegexRecord>,
    pub processes_examined: usize,
    pub vads_examined: usize,
    pub chunks_scanned: usize,
    pub bytes_examined: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct VadRegexRecord {
    pub pid: u64,
    pub process: String,
    pub vad: u64,
    pub vad_start: u64,
    pub vad_end: u64,
    pub match_address: u64,
    pub match_length: usize,
    pub preview_hex: String,
}

#[derive(Debug, Serialize)]
pub struct VadYaraReport {
    pub records: Vec<VadYaraRecord>,
    pub rule_files: Vec<PathBuf>,
    pub processes_examined: usize,
    pub vads_examined: usize,
    pub chunks_scanned: usize,
    pub bytes_examined: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct VadYaraRecord {
    pub pid: u64,
    pub process: String,
    pub vad: u64,
    pub vad_start: u64,
    pub vad_end: u64,
    pub namespace: String,
    pub rule: String,
    pub tags: Vec<String>,
    pub pattern: Option<String>,
    pub match_address: u64,
    pub match_length: usize,
    pub match_hex: Option<String>,
}

#[derive(Default)]
struct ScanCounters {
    processes: usize,
    vads: usize,
    chunks: usize,
    bytes: u64,
    missing: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn vad_regex_scan(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid_filter: Option<u64>,
    pattern: &str,
    chunk_size: usize,
    overlap: usize,
    limit: usize,
) -> Result<VadRegexReport> {
    validate_chunk_options(chunk_size, overlap, limit)?;
    let regex = Regex::new(pattern).context("invalid byte regular expression")?;
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut records = Vec::new();
    let mut warnings = process_warnings(&processes);
    let mut counters = ScanCounters::default();
    let mut complete = processes.complete;
    let mut seen = HashSet::new();

    'processes: for process in processes
        .processes
        .iter()
        .filter(|process| pid_filter.is_none_or(|pid| process.pid == pid))
    {
        counters.processes += 1;
        let Some(space) = process_address_space(image, process) else {
            complete = false;
            push_warning_limited(
                &mut warnings,
                format!("PID {} has no readable page table", process.pid),
            );
            continue;
        };
        let vads = match list_vads(image, kernel, profile, process.pid, 1_000_000) {
            Ok(vads) => vads,
            Err(error) => {
                complete = false;
                push_warning_limited(
                    &mut warnings,
                    format!("PID {} VAD walk failed: {error:#}", process.pid),
                );
                continue;
            }
        };
        counters.vads += vads.records.len();
        complete &= vads.complete;
        for vad in &vads.records {
            let scan = stream_vad_chunks(&space, vad, chunk_size, overlap, |base, bytes| {
                if records.len() == limit {
                    return;
                }
                for matched in regex.find_iter(bytes) {
                    let address = base + matched.start() as u64;
                    let end = base + matched.end() as u64;
                    if !seen.insert((process.pid, vad.node, address, end)) {
                        continue;
                    }
                    let preview_start = matched.start().saturating_sub(16);
                    let preview_end = (matched.end() + 48).min(bytes.len());
                    records.push(VadRegexRecord {
                        pid: process.pid,
                        process: process.name.clone(),
                        vad: vad.node,
                        vad_start: vad.start,
                        vad_end: vad.end,
                        match_address: address,
                        match_length: matched.len(),
                        preview_hex: hex::encode(&bytes[preview_start..preview_end]),
                    });
                    if records.len() == limit {
                        break;
                    }
                }
            });
            counters.chunks += scan.chunks;
            counters.bytes += scan.bytes;
            counters.missing += scan.missing;
            if scan.missing != 0 {
                complete = false;
            }
            if records.len() == limit {
                complete = false;
                warnings.push(format!("VAD regex result limit {limit} reached"));
                break 'processes;
            }
        }
    }
    append_missing_warning(&mut warnings, counters.missing);
    Ok(VadRegexReport {
        records,
        processes_examined: counters.processes,
        vads_examined: counters.vads,
        chunks_scanned: counters.chunks,
        bytes_examined: counters.bytes,
        missing_bytes: counters.missing,
        complete,
        warnings,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn vad_yara_scan(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid_filter: Option<u64>,
    rule_files: &[PathBuf],
    chunk_size: usize,
    overlap: usize,
    limit: usize,
) -> Result<VadYaraReport> {
    validate_chunk_options(chunk_size, overlap, limit)?;
    ensure!(
        !rule_files.is_empty(),
        "provide at least one YARA rule file"
    );
    let sources = rule_files
        .iter()
        .map(|path| {
            fs::read(path).with_context(|| format!("cannot read YARA rule {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut compiler = yara_x::Compiler::new();
    for source in &sources {
        compiler
            .add_source(source.as_slice())
            .context("YARA-X rule compilation failed")?;
    }
    let rules = compiler.build();
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut records = Vec::new();
    let mut warnings = process_warnings(&processes);
    warnings.push(
        "YARA-X block mode preserves virtual offsets and overlapping pattern matches; structured modules, filesize, hash and uint* built-ins are undefined in this mode"
            .to_owned(),
    );
    let mut counters = ScanCounters::default();
    let mut complete = processes.complete;
    let mut seen = HashSet::new();

    'processes: for process in processes
        .processes
        .iter()
        .filter(|process| pid_filter.is_none_or(|pid| process.pid == pid))
    {
        counters.processes += 1;
        let Some(space) = process_address_space(image, process) else {
            complete = false;
            continue;
        };
        let vads = match list_vads(image, kernel, profile, process.pid, 1_000_000) {
            Ok(vads) => vads,
            Err(error) => {
                complete = false;
                push_warning_limited(
                    &mut warnings,
                    format!("PID {} VAD walk failed: {error:#}", process.pid),
                );
                continue;
            }
        };
        counters.vads += vads.records.len();
        complete &= vads.complete;
        for vad in &vads.records {
            let mut scanner = yara_x::blocks::Scanner::new(&rules);
            let mut scan_failed = false;
            let scan = stream_vad_chunks(&space, vad, chunk_size, overlap, |base, bytes| {
                if scan_failed {
                    return;
                }
                if let Err(error) = scanner.scan(base as usize, bytes) {
                    push_warning_limited(
                        &mut warnings,
                        format!(
                            "PID {} VAD {:#x} YARA block scan failed: {error}",
                            process.pid, vad.node
                        ),
                    );
                    complete = false;
                    scan_failed = true;
                }
            });
            counters.chunks += scan.chunks;
            counters.bytes += scan.bytes;
            counters.missing += scan.missing;
            if scan.missing != 0 {
                complete = false;
            }
            if scan_failed || scan.chunks == 0 {
                continue;
            }
            let results = match scanner.finish() {
                Ok(results) => results,
                Err(error) => {
                    complete = false;
                    push_warning_limited(
                        &mut warnings,
                        format!(
                            "PID {} VAD {:#x} YARA evaluation failed: {error}",
                            process.pid, vad.node
                        ),
                    );
                    continue;
                }
            };
            for rule in results.matching_rules() {
                let namespace = rule.namespace().to_owned();
                let rule_name = rule.identifier().to_owned();
                let tags = rule
                    .tags()
                    .map(|tag| tag.identifier().to_owned())
                    .collect::<Vec<_>>();
                let mut pattern_match_count = 0usize;
                for pattern in rule.patterns() {
                    for matched in pattern.matches() {
                        let range = matched.range();
                        if range.end < range.start {
                            continue;
                        }
                        let address = range.start as u64;
                        if address < vad.start || address > vad.end {
                            continue;
                        }
                        let key = (
                            process.pid,
                            vad.node,
                            namespace.clone(),
                            rule_name.clone(),
                            pattern.identifier().to_owned(),
                            range.start,
                            range.end,
                        );
                        if !seen.insert(key) {
                            continue;
                        }
                        if records.len() == limit {
                            break;
                        }
                        pattern_match_count += 1;
                        records.push(VadYaraRecord {
                            pid: process.pid,
                            process: process.name.clone(),
                            vad: vad.node,
                            vad_start: vad.start,
                            vad_end: vad.end,
                            namespace: namespace.clone(),
                            rule: rule_name.clone(),
                            tags: tags.clone(),
                            pattern: Some(pattern.identifier().to_owned()),
                            match_address: address,
                            match_length: range.end - range.start,
                            match_hex: Some(hex::encode(matched.data())),
                        });
                    }
                    if records.len() == limit {
                        break;
                    }
                }
                if pattern_match_count == 0 && records.len() < limit {
                    records.push(VadYaraRecord {
                        pid: process.pid,
                        process: process.name.clone(),
                        vad: vad.node,
                        vad_start: vad.start,
                        vad_end: vad.end,
                        namespace,
                        rule: rule_name,
                        tags,
                        pattern: None,
                        match_address: vad.start,
                        match_length: 0,
                        match_hex: None,
                    });
                }
                if records.len() == limit {
                    complete = false;
                    warnings.push(format!("VAD YARA result limit {limit} reached"));
                    break 'processes;
                }
            }
        }
    }
    append_missing_warning(&mut warnings, counters.missing);
    Ok(VadYaraReport {
        records,
        rule_files: rule_files.to_vec(),
        processes_examined: counters.processes,
        vads_examined: counters.vads,
        chunks_scanned: counters.chunks,
        bytes_examined: counters.bytes,
        missing_bytes: counters.missing,
        complete,
        warnings,
    })
}

struct ChunkScanResult {
    chunks: usize,
    bytes: u64,
    missing: u64,
}

fn stream_vad_chunks(
    space: &X64AddressSpace<'_>,
    vad: &VadRecord,
    chunk_size: usize,
    overlap: usize,
    mut callback: impl FnMut(u64, &[u8]),
) -> ChunkScanResult {
    let mut chunks = 0usize;
    let mut bytes_examined = 0u64;
    let mut missing = 0u64;
    let mut buffer = Vec::with_capacity(chunk_size);
    let mut buffer_base = vad.start;
    let mut address = vad.start;
    while address <= vad.end {
        let count = (vad.end - address + 1).min(0x1000) as usize;
        let mut page = vec![0u8; count];
        if space.read_virtual(address, &mut page).is_ok() {
            bytes_examined += count as u64;
            if buffer.is_empty() {
                buffer_base = address;
            }
            if buffer.len() + count > chunk_size && !buffer.is_empty() {
                callback(buffer_base, &buffer);
                chunks += 1;
                let retained = overlap.min(buffer.len());
                let tail = buffer.split_off(buffer.len() - retained);
                buffer = tail;
                buffer_base = address.saturating_sub(retained as u64);
            }
            buffer.extend_from_slice(&page);
        } else {
            missing += count as u64;
            if !buffer.is_empty() {
                callback(buffer_base, &buffer);
                chunks += 1;
                buffer.clear();
            }
        }
        address = address.saturating_add(count as u64);
        if address == 0 {
            break;
        }
    }
    if !buffer.is_empty() {
        callback(buffer_base, &buffer);
        chunks += 1;
    }
    ChunkScanResult {
        chunks,
        bytes: bytes_examined,
        missing,
    }
}

fn validate_chunk_options(chunk_size: usize, overlap: usize, limit: usize) -> Result<()> {
    ensure!(limit > 0, "VAD scan result limit must be greater than zero");
    ensure!(
        (64 * 1024..=256 * 1024 * 1024).contains(&chunk_size),
        "VAD scan chunk size must be between 64 KiB and 256 MiB"
    );
    ensure!(
        overlap < chunk_size,
        "VAD scan overlap must be smaller than a chunk"
    );
    Ok(())
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

fn process_warnings(processes: &super::ProcessListReport) -> Vec<String> {
    processes
        .warnings
        .iter()
        .map(|warning| format!("pslist/{}: {}", warning.kind, warning.message))
        .collect()
}

fn append_missing_warning(warnings: &mut Vec<String>, missing: u64) {
    if missing != 0 {
        warnings.push(format!(
            "捕获页表中有 {missing} 字节的 VAD 内容不可用，因此未进行扫描"
        ));
    }
}

fn push_warning_limited(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 256 {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_overlap_larger_than_chunk() {
        assert!(validate_chunk_options(64 * 1024, 64 * 1024, 1).is_err());
    }
}
