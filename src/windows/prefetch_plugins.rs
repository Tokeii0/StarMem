use std::collections::HashSet;
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use super::WindowsKernelContext;
use super::files::{DumpSource, RecoveredExtent, recover_file_bytes, scan_files_matching};
use crate::image::MemoryImage;
use crate::profile::KernelProfile;

const FILE_INFO_OFFSET: usize = 84;
const WINDOWS_EPOCH_OFFSET_SECONDS: i64 = 11_644_473_600;

#[derive(Debug, Clone)]
pub struct PrefetchScanOptions {
    pub file_scan_limit: usize,
    pub file_limit: usize,
    pub reference_limit: usize,
    pub max_file_size: u64,
    pub max_uncompressed_size: usize,
}

impl Default for PrefetchScanOptions {
    fn default() -> Self {
        Self {
            file_scan_limit: 1_000_000,
            file_limit: 4096,
            reference_limit: 4096,
            max_file_size: 32 * 1024 * 1024,
            max_uncompressed_size: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PrefetchScanRecord {
    pub file_object: u64,
    pub path: String,
    pub recovery_complete: bool,
    pub recovered_bytes: u64,
    pub logical_size: u64,
    pub container: String,
    pub version: u32,
    pub executable: String,
    pub prefetch_hash: u32,
    pub filename_hash_matches: Option<bool>,
    pub boot_prefetch: bool,
    pub run_count: u32,
    pub last_run_times_raw: Vec<u64>,
    pub last_run_times: Vec<String>,
    pub referenced_file_count: usize,
    pub referenced_files: Vec<String>,
    pub referenced_files_complete: bool,
}

#[derive(Debug, Serialize)]
pub struct PrefetchScanReport {
    pub records: Vec<PrefetchScanRecord>,
    pub complete: bool,
    pub file_candidates_found: usize,
    pub files_attempted: usize,
    pub files_parsed: usize,
    pub duplicate_records: usize,
    pub recovery_failures: usize,
    pub parse_failures: usize,
    pub file_objects_examined: usize,
    pub file_pool_tag_hits: usize,
    pub scan_seconds: f64,
    pub scope: String,
    pub warnings: Vec<String>,
}

struct ParsedPrefetch {
    container: &'static str,
    version: u32,
    executable: String,
    prefetch_hash: u32,
    boot_prefetch: bool,
    run_count: u32,
    last_run_times_raw: Vec<u64>,
    referenced_files: Vec<String>,
    referenced_file_count: usize,
    reference_array_complete: bool,
    reference_range: Option<(u64, u64)>,
}

pub fn scan_prefetch(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &PrefetchScanOptions,
) -> Result<PrefetchScanReport> {
    ensure!(
        options.file_scan_limit > 0,
        "FILE_OBJECT 扫描上限必须大于零"
    );
    ensure!(options.file_limit > 0, "Prefetch 文件上限必须大于零");
    ensure!(
        options.reference_limit > 0,
        "Prefetch 引用文件上限必须大于零"
    );
    ensure!(options.max_file_size > 0, "Prefetch 最大文件大小必须大于零");
    ensure!(
        options.max_uncompressed_size > 0,
        "Prefetch 最大解压大小必须大于零"
    );

    let started = Instant::now();
    let files = scan_files_matching(
        image,
        kernel,
        profile,
        options.file_scan_limit,
        &is_prefetch_candidate_path,
    )?;
    let file_objects_examined = files.records.len();
    let file_pool_tag_hits = files.pool_tag_hits;
    let mut complete = files.complete;
    let mut warnings = files
        .warnings
        .iter()
        .map(|warning| format!("FILE_OBJECT 扫描：{warning}"))
        .collect::<Vec<_>>();
    let mut candidates = files
        .records
        .iter()
        .filter(|file| file.name.as_deref().is_some_and(is_prefetch_candidate_path))
        .collect::<Vec<_>>();
    candidates.sort_unstable_by(|left, right| {
        normalized_path(left.name.as_deref().unwrap_or_default())
            .cmp(&normalized_path(right.name.as_deref().unwrap_or_default()))
            .then_with(|| right.shared_cache_map.cmp(&left.shared_cache_map))
            .then_with(|| right.data_section_object.cmp(&left.data_section_object))
            .then_with(|| left.file_object.cmp(&right.file_object))
    });
    let file_candidates_found = candidates.len();
    if candidates.len() > options.file_limit {
        candidates.truncate(options.file_limit);
        complete = false;
        push_warning(
            &mut warnings,
            format!("Prefetch 文件候选达到 {} 个上限", options.file_limit),
        );
    }

    let mut records = Vec::new();
    let mut seen = HashSet::new();
    let mut duplicate_records = 0usize;
    let mut recovery_failures = 0usize;
    let mut parse_failures = 0usize;
    let mut files_attempted = 0usize;
    for file in candidates {
        files_attempted += 1;
        let path = file.name.clone().unwrap_or_default().replace('/', "\\");
        let recovered = recover_file_bytes(
            image,
            kernel,
            profile,
            file.file_object,
            DumpSource::Auto,
            options.max_file_size,
        );
        let (dump, bytes) = match recovered {
            Ok(recovered) => recovered,
            Err(error) => {
                recovery_failures += 1;
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("无法恢复 Prefetch 候选 {path}：{error:#}"),
                );
                continue;
            }
        };
        if dump.recovered_bytes == 0 || bytes.is_empty() {
            recovery_failures += 1;
            complete = false;
            push_warning(
                &mut warnings,
                format!("Prefetch 候选 {path} 没有驻留文件内容"),
            );
            continue;
        }
        let compressed = bytes.starts_with(b"MAM");
        if compressed && !dump.complete {
            recovery_failures += 1;
            complete = false;
            push_warning(
                &mut warnings,
                format!(
                    "压缩 Prefetch 候选 {path} 仅恢复 {}/{} 字节，拒绝用零填缺页参与解压",
                    dump.recovered_bytes, dump.logical_size
                ),
            );
            continue;
        }
        if !compressed && !range_recovered(&dump.extents, 0, 304.min(bytes.len()) as u64) {
            recovery_failures += 1;
            complete = false;
            push_warning(
                &mut warnings,
                format!("Prefetch 候选 {path} 的头部/执行时间字段不完整"),
            );
            continue;
        }
        let parsed = match parse_prefetch(&bytes, options.max_uncompressed_size) {
            Ok(parsed) => parsed,
            Err(error) => {
                parse_failures += 1;
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("Prefetch 候选 {path} 结构无效：{error:#}"),
                );
                continue;
            }
        };
        let identity = (
            parsed.executable.to_ascii_lowercase(),
            parsed.prefetch_hash,
            parsed.run_count,
            parsed.last_run_times_raw.clone(),
        );
        if !seen.insert(identity) {
            duplicate_records += 1;
            continue;
        }
        let referenced_file_count = parsed.referenced_file_count;
        let mut referenced_files = parsed.referenced_files;
        let reference_truncated = referenced_files.len() > options.reference_limit;
        referenced_files.truncate(options.reference_limit);
        let referenced_files_complete = parsed.reference_array_complete
            && !reference_truncated
            && parsed.reference_range.is_none_or(|(offset, length)| {
                dump.complete || range_recovered(&dump.extents, offset, length)
            });
        if !dump.complete || !referenced_files_complete {
            complete = false;
        }
        let filename_hash_matches = prefetch_filename_hash(&path)
            .map(|filename_hash| filename_hash == parsed.prefetch_hash);
        records.push(PrefetchScanRecord {
            file_object: file.file_object,
            path,
            recovery_complete: dump.complete,
            recovered_bytes: dump.recovered_bytes,
            logical_size: dump.logical_size,
            container: parsed.container.to_owned(),
            version: parsed.version,
            executable: parsed.executable,
            prefetch_hash: parsed.prefetch_hash,
            filename_hash_matches,
            boot_prefetch: parsed.boot_prefetch,
            run_count: parsed.run_count,
            last_run_times: parsed
                .last_run_times_raw
                .iter()
                .filter_map(|timestamp| filetime_to_rfc3339(*timestamp))
                .collect(),
            last_run_times_raw: parsed.last_run_times_raw,
            referenced_file_count,
            referenced_files,
            referenced_files_complete,
        });
    }

    records.sort_unstable_by(|left, right| {
        right
            .last_run_times_raw
            .first()
            .cmp(&left.last_run_times_raw.first())
            .then_with(|| left.executable.cmp(&right.executable))
            .then_with(|| left.prefetch_hash.cmp(&right.prefetch_hash))
    });
    let files_parsed = records.len();
    Ok(PrefetchScanReport {
        records,
        complete,
        file_candidates_found,
        files_attempted,
        files_parsed,
        duplicate_records,
        recovery_failures,
        parse_failures,
        file_objects_examined,
        file_pool_tag_hits,
        scan_seconds: started.elapsed().as_secs_f64(),
        scope: "从驻留 FILE_OBJECT 恢复 Windows\\Prefetch 下的 .pf 文件；MAM 压缩文件必须完整恢复后才解压，未压缩 SCCA 允许在关键头部完整时保留部分引用列表。支持格式版本 17、23、26、30、31。".to_owned(),
        warnings,
    })
}

fn parse_prefetch(data: &[u8], max_uncompressed_size: usize) -> Result<ParsedPrefetch> {
    let (container, scca) = if data.get(4..8) == Some(b"SCCA") {
        ("scca", data.to_vec())
    } else if data.len() >= 8 && &data[..3] == b"MAM" && data[3] == 4 {
        let size = read_u32(data, 4).context("MAM 缺少解压大小")? as usize;
        ensure!(size >= FILE_INFO_OFFSET, "MAM 声明的解压大小过小");
        ensure!(
            size <= max_uncompressed_size,
            "MAM 声明的解压大小超过安全上限"
        );
        let decompressed =
            xpress_huffman::decompress(&data[8..], size).map_err(|error| anyhow::anyhow!(error))?;
        ensure!(decompressed.len() == size, "MAM 解压结果短于声明大小");
        ("mam_xpress_huffman", decompressed)
    } else {
        bail!("没有 SCCA 或 MAM\\x04 签名");
    };
    ensure!(scca.len() >= FILE_INFO_OFFSET, "SCCA 文件头被截断");
    ensure!(scca.get(4..8) == Some(b"SCCA"), "解压结果没有 SCCA 签名");
    let version = read_u32(&scca, 0).context("SCCA 缺少格式版本")?;
    ensure!(
        matches!(version, 17 | 23 | 26 | 30 | 31),
        "不支持的 SCCA 格式版本 {version}"
    );
    let declared_size = read_u32(&scca, 12).context("SCCA 缺少文件大小")? as usize;
    ensure!(
        (FILE_INFO_OFFSET..=scca.len()).contains(&declared_size),
        "SCCA 声明的文件大小越界"
    );
    let executable = read_utf16_z(&scca, 16, 60).context("可执行文件名无效")?;
    ensure!(!executable.is_empty(), "可执行文件名为空");
    ensure!(
        executable.chars().all(|character| !character.is_control()),
        "可执行文件名包含控制字符"
    );
    let prefetch_hash = read_u32(&scca, 76).context("SCCA 缺少 Prefetch hash")?;
    let boot_prefetch =
        read_u32(&scca, 80).unwrap_or(0) & 1 != 0 || executable.eq_ignore_ascii_case("NTOSBOOT");
    let fi = FILE_INFO_OFFSET;
    let metrics_offset = read_u32(&scca, fi).context("FileInformation 被截断")?;
    let valid_metrics_offset = match version {
        17 => metrics_offset == 152,
        23 => metrics_offset == 240,
        26 => metrics_offset == 304,
        30 => matches!(metrics_offset, 296 | 304),
        31 => metrics_offset == 296,
        _ => false,
    };
    ensure!(valid_metrics_offset, "格式版本与 metrics offset 不一致");
    let filename_offset = read_u32(&scca, fi + 16).context("缺少引用文件区偏移")? as usize;
    let filename_size = read_u32(&scca, fi + 20).context("缺少引用文件区大小")? as usize;
    ensure!(filename_size.is_multiple_of(2), "引用文件区大小为奇数");
    ensure!(filename_size <= 16 * 1024 * 1024, "引用文件区超过安全上限");
    let filename_end = filename_offset
        .checked_add(filename_size)
        .context("引用文件区地址溢出")?;
    ensure!(
        filename_offset >= usize::try_from(metrics_offset).unwrap_or(usize::MAX)
            && filename_end <= declared_size,
        "引用文件区越界"
    );
    let (last_run_offset, last_run_count, run_count_offset) = match version {
        17 => (fi + 36, 1, fi + 60),
        23 => (fi + 44, 1, fi + 68),
        26 => (fi + 44, 8, fi + 124),
        30 if metrics_offset == 296 => (fi + 44, 8, fi + 116),
        30 => (fi + 44, 8, fi + 124),
        31 => (fi + 44, 8, fi + 116),
        _ => unreachable!(),
    };
    let mut last_run_times_raw = Vec::new();
    for index in 0..last_run_count {
        let timestamp =
            read_u64(&scca, last_run_offset + index * 8).context("最后运行时间数组被截断")?;
        if timestamp == 0 {
            continue;
        }
        ensure!(
            filetime_to_rfc3339(timestamp).is_some(),
            "最后运行时间不是可转换的 FILETIME"
        );
        last_run_times_raw.push(timestamp);
    }
    // Some modern files preserve the eight timestamp slots in update order
    // rather than strict chronology.  The public field is an execution-time
    // collection, so normalize it newest-first for stable sorting/output.
    last_run_times_raw.sort_unstable_by(|left, right| right.cmp(left));
    let run_count = read_u32(&scca, run_count_offset).context("运行次数字段被截断")?;
    ensure!(run_count <= 100_000_000, "运行次数超过安全上限");
    let (referenced_files, referenced_file_count, reference_array_complete) =
        parse_utf16_string_array(&scca[filename_offset..filename_end]);
    Ok(ParsedPrefetch {
        container,
        version,
        executable,
        prefetch_hash,
        boot_prefetch,
        run_count,
        last_run_times_raw,
        referenced_files,
        referenced_file_count,
        reference_array_complete,
        reference_range: Some((filename_offset as u64, filename_size as u64)),
    })
}

fn parse_utf16_string_array(bytes: &[u8]) -> (Vec<String>, usize, bool) {
    const MAX_REFERENCES: usize = 100_000;
    const MAX_STRING_UNITS: usize = 32 * 1024;
    let mut records = Vec::new();
    let mut current = Vec::new();
    let mut current_oversized = false;
    let mut total = 0usize;
    for pair in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit != 0 {
            if current.len() < MAX_STRING_UNITS {
                current.push(unit);
            } else {
                current_oversized = true;
            }
            continue;
        }
        if !current.is_empty() && !current_oversized {
            let value = String::from_utf16_lossy(&current);
            let value = value.trim();
            if !value.is_empty() && value.chars().all(|character| !character.is_control()) {
                total += 1;
                if records.len() < MAX_REFERENCES {
                    records.push(value.to_owned());
                }
            }
        }
        current.clear();
        current_oversized = false;
    }
    let complete = total <= MAX_REFERENCES && !current_oversized && current.is_empty();
    (records, total, complete)
}

fn is_prefetch_candidate_path(path: &str) -> bool {
    let normalized = normalized_path(path);
    if !normalized.ends_with(".pf") {
        return false;
    }
    normalized.contains("\\windows\\prefetch\\") || prefetch_filename_hash(path).is_some()
}

fn prefetch_filename_hash(path: &str) -> Option<u32> {
    let normalized = path.replace('/', "\\");
    let filename = normalized.rsplit('\\').next()?;
    let stem = filename
        .strip_suffix(".pf")
        .or_else(|| filename.strip_suffix(".PF"))?;
    let (_, hash) = stem.rsplit_once('-')?;
    (hash.len() == 8 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(hash, 16).ok())?
}

fn normalized_path(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

fn range_recovered(extents: &[RecoveredExtent], offset: u64, length: u64) -> bool {
    if length == 0 {
        return true;
    }
    let Some(end) = offset.checked_add(length) else {
        return false;
    };
    let mut cursor = offset;
    let mut sorted = extents.iter().collect::<Vec<_>>();
    sorted.sort_unstable_by_key(|extent| extent.file_offset);
    for extent in sorted {
        let Some(extent_end) = extent.file_offset.checked_add(extent.length) else {
            continue;
        };
        if extent_end <= cursor || extent.file_offset > cursor {
            continue;
        }
        cursor = cursor.max(extent_end);
        if cursor >= end {
            return true;
        }
    }
    false
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn read_utf16_z(data: &[u8], offset: usize, length: usize) -> Option<String> {
    let bytes = data.get(offset..offset.checked_add(length)?)?;
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    String::from_utf16(&units).ok()
}

fn filetime_to_rfc3339(value: u64) -> Option<String> {
    if value == 0 {
        return None;
    }
    let seconds = i64::try_from(value / 10_000_000)
        .ok()?
        .checked_sub(WINDOWS_EPOCH_OFFSET_SECONDS)?;
    let nanos = u32::try_from((value % 10_000_000) * 100).ok()?;
    DateTime::<Utc>::from_timestamp(seconds, nanos)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 128 {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_prefetch(version: u32, metrics_offset: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 512];
        let file_size = bytes.len() as u32;
        bytes[0..4].copy_from_slice(&version.to_le_bytes());
        bytes[4..8].copy_from_slice(b"SCCA");
        bytes[12..16].copy_from_slice(&file_size.to_le_bytes());
        for (index, unit) in "TEST.EXE".encode_utf16().enumerate() {
            bytes[16 + index * 2..18 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes[76..80].copy_from_slice(&0x1234_abcd_u32.to_le_bytes());
        let fi = FILE_INFO_OFFSET;
        bytes[fi..fi + 4].copy_from_slice(&metrics_offset.to_le_bytes());
        bytes[fi + 16..fi + 20].copy_from_slice(&400u32.to_le_bytes());
        let references: Vec<u8> = r"C:\Windows\System32\test.exe"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        bytes[fi + 20..fi + 24].copy_from_slice(&(references.len() as u32).to_le_bytes());
        bytes[400..400 + references.len()].copy_from_slice(&references);
        let (time_offset, count_offset) = match version {
            17 => (fi + 36, fi + 60),
            23 => (fi + 44, fi + 68),
            26 => (fi + 44, fi + 124),
            30 if metrics_offset == 296 => (fi + 44, fi + 116),
            30 => (fi + 44, fi + 124),
            31 => (fi + 44, fi + 116),
            _ => unreachable!(),
        };
        bytes[time_offset..time_offset + 8]
            .copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        bytes[count_offset..count_offset + 4].copy_from_slice(&7u32.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_all_supported_scca_layouts() {
        for (version, metrics) in [
            (17, 152),
            (23, 240),
            (26, 304),
            (30, 304),
            (30, 296),
            (31, 296),
        ] {
            let parsed = parse_prefetch(&synthetic_prefetch(version, metrics), 1024).unwrap();
            assert_eq!(parsed.version, version);
            assert_eq!(parsed.executable, "TEST.EXE");
            assert_eq!(parsed.run_count, 7);
            assert_eq!(parsed.last_run_times_raw.len(), 1);
            assert_eq!(parsed.referenced_files.len(), 1);
        }
    }

    #[test]
    fn recognizes_prefetch_paths_and_hash_names() {
        assert!(is_prefetch_candidate_path(
            r"\Windows\Prefetch\CMD.EXE-1234ABCD.pf"
        ));
        assert!(is_prefetch_candidate_path(r"\CMD.EXE-1234ABCD.pf"));
        assert!(!is_prefetch_candidate_path(r"\Temp\ordinary.pf"));
        assert_eq!(
            prefetch_filename_hash(r"C:\Windows\Prefetch\CMD.EXE-1234ABCD.pf"),
            Some(0x1234_abcd)
        );
    }
}
