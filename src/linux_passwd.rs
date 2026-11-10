use std::collections::{BTreeMap, HashSet};

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::image::MemoryImage;
use crate::linux::LinuxKernelContext;
use crate::linux_files::{
    LinuxFileScanRecord, LinuxFileScanReport, LinuxFileScanStopReason, LinuxFileScanWarning,
};
use crate::linux_pagecache::{
    LinuxDumpFileReport, LinuxMissingRange, LinuxRecoveredFile, LinuxReversePageCacheEvidence,
    read_validated_file, read_validated_file_from_physical_page,
};
use crate::scan::scan_exact;

const PASSWD_FIELD_COUNT: usize = 7;
const PAGE_SIZE: u64 = 0x1000;
const REVERSE_SCAN_SIGNATURE: &[u8] = b"root:";
const REVERSE_SCAN_HIT_LIMIT: usize = 100_000;
const REVERSE_SCAN_CHUNK_SIZE: usize = 64 * 1024 * 1024;
const PASSWD_FIELD_NAMES: [&str; PASSWD_FIELD_COUNT] = [
    "username",
    "password",
    "uid",
    "gid",
    "gecos",
    "home_directory",
    "shell",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxPasswdNonRecordKind {
    Blank,
    Comment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinuxPasswdRecord {
    pub line_number: usize,
    pub raw_line: String,
    pub raw_bytes_hex: String,
    pub username: String,
    pub password: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home_directory: String,
    pub shell: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinuxPasswdInvalidLine {
    pub line_number: usize,
    pub raw_line: String,
    pub raw_bytes_hex: String,
    pub field_count: usize,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinuxPasswdNonRecordLine {
    pub line_number: usize,
    pub kind: LinuxPasswdNonRecordKind,
    pub raw_line: String,
    pub raw_bytes_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinuxPasswdWarning {
    pub line_number: usize,
    pub kind: String,
    pub field: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinuxPasswdParseReport {
    pub line_count: usize,
    pub record_count: usize,
    pub invalid_line_count: usize,
    pub non_record_line_count: usize,
    pub warning_count: usize,
    pub records: Vec<LinuxPasswdRecord>,
    pub invalid_lines: Vec<LinuxPasswdInvalidLine>,
    pub non_record_lines: Vec<LinuxPasswdNonRecordLine>,
    pub warnings: Vec<LinuxPasswdWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxPasswdRecoveryStatus {
    Complete,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxPasswdFileScanProvenance {
    pub source: String,
    pub scope: String,
    pub profile_source: String,
    pub profile_fingerprint: String,
    pub requested_limit: usize,
    pub record_count: usize,
    pub complete: bool,
    pub structural_complete: bool,
    pub limit_reached: bool,
    pub stop_reason: LinuxFileScanStopReason,
    pub warning_count: usize,
    pub warning_counts: BTreeMap<String, usize>,
    pub warnings: Vec<LinuxFileScanWarning>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxPasswdRecoveredFragment {
    pub file_offset: u64,
    pub length: u64,
    pub line_number_scope: String,
    pub parse_report: LinuxPasswdParseReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxPasswdCandidateSource {
    ValidatedDentry,
    ReversePageCache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxPasswdPathEvidence {
    ExactDentryPath,
    InferredFromPasswdContent,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxPasswdReverseScanProvenance {
    pub attempted: bool,
    pub signature: String,
    pub hit_limit: usize,
    pub bytes_scanned: u64,
    pub elapsed_seconds: f64,
    pub gib_per_second: f64,
    pub truncated: bool,
    pub signature_hit_count: usize,
    pub unique_page_count: usize,
    pub plausible_root_line_count: usize,
    pub page_cache_anchor_count: usize,
    pub content_validated_count: usize,
}

impl Default for LinuxPasswdReverseScanProvenance {
    fn default() -> Self {
        Self {
            attempted: false,
            signature: String::from_utf8_lossy(REVERSE_SCAN_SIGNATURE).into_owned(),
            hit_limit: REVERSE_SCAN_HIT_LIMIT,
            bytes_scanned: 0,
            elapsed_seconds: 0.0,
            gib_per_second: 0.0,
            truncated: false,
            signature_hit_count: 0,
            unique_page_count: 0,
            plausible_root_line_count: 0,
            page_cache_anchor_count: 0,
            content_validated_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxPasswdCandidateReport {
    pub discovery_source: LinuxPasswdCandidateSource,
    pub path_evidence: LinuxPasswdPathEvidence,
    pub path_inferred: bool,
    pub reverse_page_cache_evidence: Option<LinuxReversePageCacheEvidence>,
    pub filescan_record: LinuxFileScanRecord,
    pub recovery_status: LinuxPasswdRecoveryStatus,
    pub complete: bool,
    pub parsed_bytes: u64,
    pub discarded_boundary_bytes: u64,
    pub fragments: Vec<LinuxPasswdRecoveredFragment>,
    pub recovery: Option<LinuxDumpFileReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxPasswdAnalysisWarning {
    pub kind: String,
    pub message: String,
    pub candidate_index: Option<usize>,
    pub superblock: Option<u64>,
    pub superblock_hex: Option<String>,
    pub dentry: Option<u64>,
    pub dentry_hex: Option<String>,
    pub inode: Option<u64>,
    pub inode_hex: Option<String>,
    pub file_offset: Option<u64>,
    pub length: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxPasswdAnalysisReport {
    pub kernel: LinuxKernelContext,
    pub source: String,
    pub scope: String,
    pub target_path: String,
    pub max_size: u64,
    pub filescan: LinuxPasswdFileScanProvenance,
    pub reverse_scan: LinuxPasswdReverseScanProvenance,
    pub matched_record_count: usize,
    pub duplicate_record_count: usize,
    pub candidate_count: usize,
    pub recovered_candidate_count: usize,
    pub complete_candidate_count: usize,
    pub account_record_count: usize,
    pub complete: bool,
    pub candidates: Vec<LinuxPasswdCandidateReport>,
    pub warning_count: usize,
    pub warnings: Vec<LinuxPasswdAnalysisWarning>,
}

/// Finds resident `/etc/passwd` dentries and parses bytes recovered from validated page cache.
///
/// If no exact dentry survives, a bounded physical `root:` scan may locate a content page. The
/// candidate is accepted only after reverse `struct page`/inode/page-tree validation and strong
/// passwd semantics; its pathname remains explicitly inferred. This is not an on-disk inventory.
pub fn analyze_linux_passwd(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    filescan: &LinuxFileScanReport,
    file_scan_limit: usize,
    max_size: u64,
) -> Result<LinuxPasswdAnalysisReport> {
    ensure!(file_scan_limit > 0, "Linux filescan 结果上限必须大于零");
    ensure!(max_size > 0, "passwd 页缓存恢复上限必须大于零");
    ensure!(
        filescan.kernel.banner == kernel.banner
            && filescan.kernel.directory_table_base == kernel.directory_table_base
            && filescan.kernel.init_task == kernel.init_task,
        "Linux filescan 报告与当前内核上下文不一致"
    );
    ensure!(
        filescan.record_count == filescan.records.len(),
        "Linux filescan 报告记录计数不一致"
    );
    ensure!(
        filescan.record_count <= file_scan_limit,
        "Linux filescan 报告记录数超过声明的结果上限"
    );
    let selection = select_passwd_candidates(&filescan.records);
    let matched_record_count = selection.matched_record_count;
    let duplicate_record_count = selection.duplicate_record_count;
    let exact_candidate_count = selection.records.len();
    let mut warnings = Vec::new();
    if !filescan.complete || !filescan.structural_complete || filescan.limit_reached {
        warnings.push(analysis_warning(
            "filescan_incomplete",
            "Linux filescan 未完整遍历驻留 VFS；未出现的 /etc/passwd 候选不能解释为磁盘上不存在",
            None,
            None,
            None,
        ));
    }
    if selection.records.is_empty() {
        warnings.push(analysis_warning(
            "no_resident_passwd_candidate",
            "在已验证的驻留 VFS filescan 记录中未找到路径精确为 /etc/passwd 的常规文件；这不表示磁盘或未驻留页缓存中不存在该文件",
            None,
            None,
            None,
        ));
    }

    let mut candidates = Vec::with_capacity(exact_candidate_count.max(1));
    let mut recovered_candidate_count = 0;
    let mut complete_candidate_count = 0;
    let mut account_record_count = 0;
    let mut reverse_scan = LinuxPasswdReverseScanProvenance::default();

    for (candidate_index, record) in selection.records.into_iter().enumerate() {
        match read_validated_file(image, kernel, record, max_size) {
            Ok(recovered) => {
                recovered_candidate_count += 1;
                let (candidate, records, recovery_complete) = build_recovered_candidate(
                    candidate_index,
                    record.clone(),
                    recovered,
                    LinuxPasswdCandidateSource::ValidatedDentry,
                    LinuxPasswdPathEvidence::ExactDentryPath,
                    None,
                    &mut warnings,
                );
                account_record_count += records;
                if recovery_complete {
                    complete_candidate_count += 1;
                }
                candidates.push(candidate);
            }
            Err(error) => {
                warnings.push(analysis_warning(
                    "page_cache_recovery_failed",
                    format!("无法从已验证页缓存恢复候选：{error:#}"),
                    Some((candidate_index, record)),
                    None,
                    None,
                ));
                candidates.push(LinuxPasswdCandidateReport {
                    discovery_source: LinuxPasswdCandidateSource::ValidatedDentry,
                    path_evidence: LinuxPasswdPathEvidence::ExactDentryPath,
                    path_inferred: false,
                    reverse_page_cache_evidence: None,
                    filescan_record: record.clone(),
                    recovery_status: LinuxPasswdRecoveryStatus::Failed,
                    complete: false,
                    parsed_bytes: 0,
                    discarded_boundary_bytes: 0,
                    fragments: Vec::new(),
                    recovery: None,
                });
            }
        }
    }

    if exact_candidate_count == 0 {
        let (reverse_candidates, provenance) =
            discover_reverse_passwd_candidates(image, kernel, filescan, max_size)?;
        reverse_scan = provenance;
        if reverse_scan.truncated {
            warnings.push(analysis_warning(
                "reverse_scan_truncated",
                format!(
                    "反向页缓存内容扫描达到 {} 个 root: 命中上限；未检查的命中可能包含其他候选",
                    reverse_scan.hit_limit
                ),
                None,
                None,
                None,
            ));
        }
        for reverse in reverse_candidates {
            let candidate_index = candidates.len();
            warnings.push(analysis_warning(
                "passwd_path_inferred",
                "候选通过 struct page、address_space、inode 与页树双向校验，并满足 passwd 内容语义；没有存活 dentry，/etc/passwd 仅为角色推断而非已证明路径",
                Some((candidate_index, &reverse.record)),
                Some(reverse.evidence.trigger_file_offset),
                Some(REVERSE_SCAN_SIGNATURE.len() as u64),
            ));
            recovered_candidate_count += 1;
            let (candidate, records, recovery_complete) = build_recovered_candidate(
                candidate_index,
                reverse.record,
                reverse.file,
                LinuxPasswdCandidateSource::ReversePageCache,
                LinuxPasswdPathEvidence::InferredFromPasswdContent,
                Some(reverse.evidence),
                &mut warnings,
            );
            account_record_count += records;
            if recovery_complete {
                complete_candidate_count += 1;
            }
            candidates.push(candidate);
        }
    }

    let candidate_count = candidates.len();
    let complete = filescan.complete
        && filescan.structural_complete
        && !filescan.limit_reached
        && exact_candidate_count > 0
        && candidate_count == exact_candidate_count
        && complete_candidate_count == candidate_count;
    Ok(LinuxPasswdAnalysisReport {
        kernel: kernel.clone(),
        source: "linux.passwd".to_owned(),
        scope: "validated resident VFS /etc/passwd dentries; if no exact dentry survives, validated reverse page-cache passwd-content candidates with an explicitly unproven pathname; not an on-disk account inventory".to_owned(),
        target_path: "/etc/passwd".to_owned(),
        max_size,
        filescan: LinuxPasswdFileScanProvenance {
            source: filescan.source.clone(),
            scope: filescan.scope.clone(),
            profile_source: filescan.profile_source.clone(),
            profile_fingerprint: filescan.profile_fingerprint.clone(),
            requested_limit: file_scan_limit,
            record_count: filescan.record_count,
            complete: filescan.complete,
            structural_complete: filescan.structural_complete,
            limit_reached: filescan.limit_reached,
            stop_reason: filescan.stop_reason,
            warning_count: filescan.warning_count,
            warning_counts: filescan.warning_counts.clone(),
            warnings: filescan.warnings.clone(),
        },
        reverse_scan,
        matched_record_count,
        duplicate_record_count,
        candidate_count,
        recovered_candidate_count,
        complete_candidate_count,
        account_record_count,
        complete,
        candidates,
        warning_count: warnings.len(),
        warnings,
    })
}

struct ReversePasswdCandidate {
    file: LinuxRecoveredFile,
    record: LinuxFileScanRecord,
    evidence: LinuxReversePageCacheEvidence,
}

fn discover_reverse_passwd_candidates(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    filescan: &LinuxFileScanReport,
    max_size: u64,
) -> Result<(
    Vec<ReversePasswdCandidate>,
    LinuxPasswdReverseScanProvenance,
)> {
    let scan = scan_exact(
        image,
        REVERSE_SCAN_SIGNATURE,
        REVERSE_SCAN_HIT_LIMIT,
        REVERSE_SCAN_CHUNK_SIZE,
    )?;
    let mut provenance = LinuxPasswdReverseScanProvenance {
        attempted: true,
        bytes_scanned: scan.bytes_scanned,
        elapsed_seconds: scan.elapsed_seconds,
        gib_per_second: scan.gib_per_second,
        truncated: scan.truncated,
        signature_hit_count: scan.hits.len(),
        ..LinuxPasswdReverseScanProvenance::default()
    };
    let mut page_hits = BTreeMap::<u64, Vec<u64>>::new();
    for hit in scan.hits {
        page_hits
            .entry(hit.physical_address & !(PAGE_SIZE - 1))
            .or_default()
            .push(hit.physical_address);
    }
    provenance.unique_page_count = page_hits.len();

    let mut candidates = Vec::new();
    let mut seen_inodes = HashSet::new();
    for hits in page_hits.into_values() {
        let Some(trigger) = hits
            .into_iter()
            .find(|address| plausible_root_line_at(image, *address))
        else {
            continue;
        };
        provenance.plausible_root_line_count += 1;
        let Ok(mut reverse) =
            read_validated_file_from_physical_page(image, kernel, trigger, max_size)
        else {
            continue;
        };
        provenance.page_cache_anchor_count += 1;

        let offset = reverse.evidence.trigger_file_offset as usize;
        if reverse
            .file
            .bytes
            .get(offset..offset.saturating_add(REVERSE_SCAN_SIGNATURE.len()))
            != Some(REVERSE_SCAN_SIGNATURE)
        {
            continue;
        }
        let parsed =
            parse_recovered_fragments(&reverse.file.bytes, &reverse.file.report.missing_ranges);
        if !is_high_confidence_passwd_content(&parsed)
            || !seen_inodes.insert((reverse.record.superblock, reverse.record.inode))
        {
            continue;
        }

        enrich_reverse_candidate(&mut reverse.record, &mut reverse.file.report, filescan);
        provenance.content_validated_count += 1;
        candidates.push(ReversePasswdCandidate {
            file: reverse.file,
            record: reverse.record,
            evidence: reverse.evidence,
        });
    }
    Ok((candidates, provenance))
}

fn plausible_root_line_at(image: &MemoryImage, physical_address: u64) -> bool {
    let physical_page = physical_address & !(PAGE_SIZE - 1);
    let offset = (physical_address - physical_page) as usize;
    let mut page = [0u8; PAGE_SIZE as usize];
    if image.read_physical(physical_page, &mut page).is_err()
        || (offset > 0 && page[offset - 1] != b'\n')
    {
        return false;
    }
    let Some(line_end) = page[offset..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|relative| offset + relative)
    else {
        return false;
    };
    let parsed = parse_linux_passwd(&page[offset..line_end]);
    parsed.invalid_line_count == 0
        && parsed.record_count == 1
        && parsed.records[0].username == "root"
        && parsed.records[0].uid == 0
        && parsed.records[0].gid == 0
        && parsed.records[0].home_directory == "/root"
        && plausible_absolute_or_empty(&parsed.records[0].shell)
}

fn is_high_confidence_passwd_content(parsed: &FragmentParseOutcome) -> bool {
    if parsed.fragments.iter().any(|fragment| {
        fragment.parse_report.invalid_line_count > 0 || fragment.parse_report.warning_count > 0
    }) {
        return false;
    }
    let records = parsed
        .fragments
        .iter()
        .flat_map(|fragment| fragment.parse_report.records.iter())
        .collect::<Vec<_>>();
    if records.len() < 3
        || records
            .iter()
            .filter(|record| record.username == "root")
            .count()
            != 1
    {
        return false;
    }
    let root = records
        .iter()
        .find(|record| record.username == "root")
        .expect("root 记录数量已经验证");
    root.uid == 0
        && root.gid == 0
        && root.home_directory == "/root"
        && plausible_absolute_or_empty(&root.shell)
        && records
            .iter()
            .any(|record| record.username != "root" && record.uid < 1000)
        && records.iter().all(|record| {
            !record.username.is_empty()
                && record
                    .username
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                && plausible_absolute_or_empty(&record.home_directory)
                && plausible_absolute_or_empty(&record.shell)
        })
}

fn plausible_absolute_or_empty(value: &str) -> bool {
    (value.is_empty() || value.starts_with('/'))
        && value.bytes().all(|byte| !byte.is_ascii_control())
}

fn enrich_reverse_candidate(
    record: &mut LinuxFileScanRecord,
    recovery: &mut LinuxDumpFileReport,
    filescan: &LinuxFileScanReport,
) {
    if let Some(reference) = filescan
        .records
        .iter()
        .filter(|candidate| candidate.superblock == record.superblock)
        .max_by_key(|candidate| {
            (
                candidate.filesystem.is_some(),
                candidate.superblock_id.is_some(),
            )
        })
    {
        record.filesystem = reference.filesystem.clone();
        record.superblock_id = reference.superblock_id.clone();
        record.device = reference.device.clone();
        record.device_raw = reference.device_raw;
        record.device_major = reference.device_major;
        record.device_minor = reference.device_minor;
    }
    record.path_status = "target_inferred_from_passwd_content".to_owned();
    record.path_scope = "semantic_role_only_not_path_evidence".to_owned();
    recovery.filesystem = record.filesystem.clone();
    recovery.superblock_id = record.superblock_id.clone();
    recovery.device = record.device.clone();
    recovery.path = None;
    recovery.path_status = record.path_status.clone();
    recovery.path_scope = record.path_scope.clone();
    recovery.membership_status = record.membership_status.clone();
}

fn build_recovered_candidate(
    candidate_index: usize,
    record: LinuxFileScanRecord,
    recovered: LinuxRecoveredFile,
    discovery_source: LinuxPasswdCandidateSource,
    path_evidence: LinuxPasswdPathEvidence,
    reverse_page_cache_evidence: Option<LinuxReversePageCacheEvidence>,
    warnings: &mut Vec<LinuxPasswdAnalysisWarning>,
) -> (LinuxPasswdCandidateReport, usize, bool) {
    let recovery_complete = recovered.report.complete;
    if !recovery_complete {
        let message = if recovered.report.missing_bytes > 0 {
            format!(
                "页缓存仅恢复 {}/{} 字节；仅解析完全位于已恢复区间内的完整 passwd 行",
                recovered.report.recovered_bytes, recovered.report.logical_size
            )
        } else {
            "页缓存字节已覆盖逻辑文件，但页树结构告警使恢复报告不完整".to_owned()
        };
        warnings.push(analysis_warning(
            "partial_page_cache_recovery",
            message,
            Some((candidate_index, &record)),
            None,
            None,
        ));
    }

    let parsed = parse_recovered_fragments(&recovered.bytes, &recovered.report.missing_ranges);
    for range in &parsed.discarded_boundaries {
        warnings.push(analysis_warning(
            "cross_gap_line_discarded",
            "恢复区间边界处的 passwd 行可能跨越缺页，已保守丢弃而未把零填充当成原始证据",
            Some((candidate_index, &record)),
            Some(range.file_offset),
            Some(range.length),
        ));
    }
    let parsed_bytes = parsed
        .fragments
        .iter()
        .map(|fragment| fragment.length)
        .sum();
    let discarded_boundary_bytes = parsed
        .discarded_boundaries
        .iter()
        .map(|range| range.length)
        .sum();
    let account_record_count = parsed
        .fragments
        .iter()
        .map(|fragment| fragment.parse_report.record_count)
        .sum();
    (
        LinuxPasswdCandidateReport {
            discovery_source,
            path_evidence,
            path_inferred: path_evidence != LinuxPasswdPathEvidence::ExactDentryPath,
            reverse_page_cache_evidence,
            filescan_record: record,
            recovery_status: if recovery_complete {
                LinuxPasswdRecoveryStatus::Complete
            } else {
                LinuxPasswdRecoveryStatus::Partial
            },
            complete: recovery_complete,
            parsed_bytes,
            discarded_boundary_bytes,
            fragments: parsed.fragments,
            recovery: Some(recovered.report),
        },
        account_record_count,
        recovery_complete,
    )
}

struct CandidateSelection<'a> {
    records: Vec<&'a LinuxFileScanRecord>,
    matched_record_count: usize,
    duplicate_record_count: usize,
}

fn select_passwd_candidates(records: &[LinuxFileScanRecord]) -> CandidateSelection<'_> {
    let mut seen = HashSet::new();
    let mut selected = Vec::new();
    let mut matched_record_count = 0;
    let mut duplicate_record_count = 0;

    for record in records {
        if record.path_status != "resolved"
            || record.path.as_deref() != Some("/etc/passwd")
            || record.file_type != "regular"
            || record.mode & 0xf000 != 0x8000
        {
            continue;
        }
        matched_record_count += 1;
        if seen.insert((record.superblock, record.inode)) {
            selected.push(record);
        } else {
            duplicate_record_count += 1;
        }
    }

    CandidateSelection {
        records: selected,
        matched_record_count,
        duplicate_record_count,
    }
}

fn analysis_warning(
    kind: impl Into<String>,
    message: impl Into<String>,
    candidate: Option<(usize, &LinuxFileScanRecord)>,
    file_offset: Option<u64>,
    length: Option<u64>,
) -> LinuxPasswdAnalysisWarning {
    let (candidate_index, superblock, superblock_hex, dentry, dentry_hex, inode, inode_hex) =
        match candidate {
            Some((index, record)) => (
                Some(index),
                Some(record.superblock),
                Some(record.superblock_hex.clone()),
                (record.dentry != 0).then_some(record.dentry),
                (record.dentry != 0).then(|| record.dentry_hex.clone()),
                Some(record.inode),
                Some(record.inode_hex.clone()),
            ),
            None => (None, None, None, None, None, None, None),
        };
    LinuxPasswdAnalysisWarning {
        kind: kind.into(),
        message: message.into(),
        candidate_index,
        superblock,
        superblock_hex,
        dentry,
        dentry_hex,
        inode,
        inode_hex,
        file_offset,
        length,
    }
}

struct FragmentParseOutcome {
    fragments: Vec<LinuxPasswdRecoveredFragment>,
    discarded_boundaries: Vec<LinuxMissingRange>,
}

fn parse_recovered_fragments(
    bytes: &[u8],
    missing_ranges: &[LinuxMissingRange],
) -> FragmentParseOutcome {
    if missing_ranges.is_empty() {
        return FragmentParseOutcome {
            fragments: vec![LinuxPasswdRecoveredFragment {
                file_offset: 0,
                length: bytes.len() as u64,
                line_number_scope: "file_relative".to_owned(),
                parse_report: parse_linux_passwd(bytes),
            }],
            discarded_boundaries: Vec::new(),
        };
    }

    let mut fragments = Vec::new();
    let mut discarded_boundaries = Vec::new();
    for (start, end) in recovered_ranges(bytes.len() as u64, missing_ranges) {
        let available = &bytes[start as usize..end as usize];
        let parse_start = if start == 0 {
            start
        } else {
            available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(end, |position| start + position as u64 + 1)
        };
        let parse_end = if end == bytes.len() as u64 {
            end
        } else {
            available
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(start, |position| start + position as u64 + 1)
        };

        if parse_start < parse_end {
            push_range(&mut discarded_boundaries, start, parse_start - start);
            push_range(&mut discarded_boundaries, parse_end, end - parse_end);
            let fragment_bytes = &bytes[parse_start as usize..parse_end as usize];
            fragments.push(LinuxPasswdRecoveredFragment {
                file_offset: parse_start,
                length: parse_end - parse_start,
                line_number_scope: "fragment_relative".to_owned(),
                parse_report: parse_linux_passwd(fragment_bytes),
            });
        } else {
            push_range(&mut discarded_boundaries, start, end - start);
        }
    }

    FragmentParseOutcome {
        fragments,
        discarded_boundaries,
    }
}

fn recovered_ranges(logical_size: u64, missing_ranges: &[LinuxMissingRange]) -> Vec<(u64, u64)> {
    let mut missing = missing_ranges.to_vec();
    missing.sort_unstable_by_key(|range| range.file_offset);
    let mut ranges = Vec::new();
    let mut cursor = 0;
    for range in missing {
        if range.length == 0 {
            continue;
        }
        let start = range.file_offset.min(logical_size);
        if start > cursor {
            ranges.push((cursor, start));
        }
        let end = range
            .file_offset
            .saturating_add(range.length)
            .min(logical_size);
        cursor = cursor.max(end);
    }
    if cursor < logical_size {
        ranges.push((cursor, logical_size));
    }
    ranges
}

fn push_range(ranges: &mut Vec<LinuxMissingRange>, file_offset: u64, length: u64) {
    if length > 0 {
        ranges.push(LinuxMissingRange {
            file_offset,
            length,
        });
    }
}

/// Parses the exact bytes of an `/etc/passwd`-format file.
///
/// The parser does not infer whether the supplied bytes are complete.  That is
/// the responsibility of the memory-file exporter that produced them.
pub fn parse_linux_passwd(bytes: &[u8]) -> LinuxPasswdParseReport {
    let mut state = ParseState::default();
    let mut line_start = 0;

    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            state.parse_line(&bytes[line_start..index]);
            line_start = index + 1;
        }
    }
    if line_start < bytes.len() {
        state.parse_line(&bytes[line_start..]);
    }

    state.finish()
}

#[derive(Default)]
struct ParseState {
    line_count: usize,
    records: Vec<LinuxPasswdRecord>,
    invalid_lines: Vec<LinuxPasswdInvalidLine>,
    non_record_lines: Vec<LinuxPasswdNonRecordLine>,
    warnings: Vec<LinuxPasswdWarning>,
}

impl ParseState {
    fn parse_line(&mut self, raw_line: &[u8]) {
        self.line_count += 1;
        let line_number = self.line_count;
        let content = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);

        if content.is_empty() {
            self.push_non_record(line_number, raw_line, LinuxPasswdNonRecordKind::Blank);
            return;
        }
        if content.starts_with(b"#") {
            self.push_non_record(line_number, raw_line, LinuxPasswdNonRecordKind::Comment);
            return;
        }

        let fields = content.split(|byte| *byte == b':').collect::<Vec<_>>();
        let mut problems = Vec::new();
        if fields.len() != PASSWD_FIELD_COUNT {
            self.warn(
                line_number,
                "invalid_field_count",
                None,
                format!(
                    "passwd 记录应有 {PASSWD_FIELD_COUNT} 个字段，实际为 {} 个",
                    fields.len()
                ),
                &mut problems,
            );
            self.push_invalid(line_number, raw_line, fields.len(), problems);
            return;
        }

        if content.contains(&0) {
            self.warn(
                line_number,
                "nul_byte",
                None,
                "passwd 记录包含 NUL 字节".to_owned(),
                &mut problems,
            );
        }

        let mut decoded: [Option<String>; PASSWD_FIELD_COUNT] = Default::default();
        for (index, field_bytes) in fields.iter().enumerate() {
            match std::str::from_utf8(field_bytes) {
                Ok(value) => decoded[index] = Some(value.to_owned()),
                Err(_) => self.warn(
                    line_number,
                    "invalid_utf8",
                    Some(PASSWD_FIELD_NAMES[index]),
                    format!("{} 字段不是有效 UTF-8", PASSWD_FIELD_NAMES[index]),
                    &mut problems,
                ),
            }
        }

        if decoded[0].as_deref() == Some("") {
            self.warn(
                line_number,
                "empty_username",
                Some("username"),
                "username 字段不能为空".to_owned(),
                &mut problems,
            );
        }

        let uid = parse_decimal_id(fields[2]);
        if uid.is_none() {
            self.warn(
                line_number,
                "invalid_uid",
                Some("uid"),
                "uid 必须是 0 到 4294967295 的十进制整数".to_owned(),
                &mut problems,
            );
        }
        let gid = parse_decimal_id(fields[3]);
        if gid.is_none() {
            self.warn(
                line_number,
                "invalid_gid",
                Some("gid"),
                "gid 必须是 0 到 4294967295 的十进制整数".to_owned(),
                &mut problems,
            );
        }

        if !problems.is_empty() {
            self.push_invalid(line_number, raw_line, fields.len(), problems);
            return;
        }

        let [username, password, _, _, gecos, home_directory, shell] = decoded.map(Option::unwrap);
        self.records.push(LinuxPasswdRecord {
            line_number,
            raw_line: String::from_utf8_lossy(raw_line).into_owned(),
            raw_bytes_hex: bytes_to_hex(raw_line),
            username,
            password,
            uid: uid.unwrap(),
            gid: gid.unwrap(),
            gecos,
            home_directory,
            shell,
        });
    }

    fn warn(
        &mut self,
        line_number: usize,
        kind: &'static str,
        field: Option<&'static str>,
        message: String,
        problems: &mut Vec<String>,
    ) {
        let problem = match field {
            Some(field) => format!("{kind}:{field}"),
            None => kind.to_owned(),
        };
        if !problems.contains(&problem) {
            problems.push(problem);
        }
        self.warnings.push(LinuxPasswdWarning {
            line_number,
            kind: kind.to_owned(),
            field: field.map(str::to_owned),
            message,
        });
    }

    fn push_invalid(
        &mut self,
        line_number: usize,
        raw_line: &[u8],
        field_count: usize,
        problems: Vec<String>,
    ) {
        self.invalid_lines.push(LinuxPasswdInvalidLine {
            line_number,
            raw_line: String::from_utf8_lossy(raw_line).into_owned(),
            raw_bytes_hex: bytes_to_hex(raw_line),
            field_count,
            problems,
        });
    }

    fn push_non_record(
        &mut self,
        line_number: usize,
        raw_line: &[u8],
        kind: LinuxPasswdNonRecordKind,
    ) {
        self.non_record_lines.push(LinuxPasswdNonRecordLine {
            line_number,
            kind,
            raw_line: String::from_utf8_lossy(raw_line).into_owned(),
            raw_bytes_hex: bytes_to_hex(raw_line),
        });
    }

    fn finish(self) -> LinuxPasswdParseReport {
        LinuxPasswdParseReport {
            line_count: self.line_count,
            record_count: self.records.len(),
            invalid_line_count: self.invalid_lines.len(),
            non_record_line_count: self.non_record_lines.len(),
            warning_count: self.warnings.len(),
            records: self.records,
            invalid_lines: self.invalid_lines,
            non_record_lines: self.non_record_lines,
            warnings: self.warnings,
        }
    }
}

fn parse_decimal_id(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn parses_standard_records_and_crlf_without_a_phantom_line() {
        let bytes = b"root:x:0:0:root:/root:/bin/bash\r\n\
alice:*:1000:1000:Alice Example:/home/alice:/bin/sh\r\n";

        let report = parse_linux_passwd(bytes);

        assert_eq!(report.line_count, 2);
        assert_eq!(report.record_count, 2);
        assert_eq!(report.invalid_line_count, 0);
        assert_eq!(report.warning_count, 0);
        assert_eq!(report.records[0].username, "root");
        assert_eq!(report.records[0].uid, 0);
        assert_eq!(report.records[1].uid, 1000);
        assert_eq!(report.records[1].gecos, "Alice Example");
        assert!(report.records[0].raw_line.ends_with('\r'));
        assert!(report.records[0].raw_bytes_hex.ends_with("0d"));
    }

    #[test]
    fn preserves_comments_blank_lines_and_a_final_unterminated_record() {
        let bytes = b"# generated by test\n\nservice:x:42:43::/srv:/usr/sbin/nologin";

        let report = parse_linux_passwd(bytes);

        assert_eq!(report.line_count, 3);
        assert_eq!(report.record_count, 1);
        assert_eq!(report.non_record_line_count, 2);
        assert_eq!(
            report.non_record_lines[0].kind,
            LinuxPasswdNonRecordKind::Comment
        );
        assert_eq!(
            report.non_record_lines[1].kind,
            LinuxPasswdNonRecordKind::Blank
        );
        assert_eq!(report.records[0].home_directory, "/srv");
    }

    #[test]
    fn retains_invalid_lines_and_reports_each_detected_problem() {
        let mut bytes = b"too:few:fields\n:nopass:not-a-uid:9::/:/bin/sh\n".to_vec();
        bytes.extend_from_slice(b"bad\xff:x:1:2::/:/bin/sh\n");
        bytes.extend_from_slice(b"nul:x:1:2::/home/nul:/bin/sh\0\n");

        let report = parse_linux_passwd(&bytes);

        assert_eq!(report.record_count, 0);
        assert_eq!(report.invalid_line_count, 4);
        assert_eq!(report.invalid_lines[0].raw_line, "too:few:fields");
        assert_eq!(report.invalid_lines[0].field_count, 3);
        assert!(
            report.invalid_lines[2]
                .raw_bytes_hex
                .starts_with("626164ff")
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.kind == "invalid_field_count")
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.kind == "empty_username")
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.kind == "invalid_uid")
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.kind == "invalid_utf8")
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.kind == "nul_byte")
        );
    }

    #[test]
    fn rejects_signed_and_overflowing_ids_but_accepts_u32_max() {
        let bytes = b"signed:x:+1:1::/:/bin/sh\n\
overflow:x:4294967296:1::/:/bin/sh\n\
maximum:x:4294967295:4294967295::/:/bin/sh\n";

        let report = parse_linux_passwd(bytes);

        assert_eq!(report.record_count, 1);
        assert_eq!(report.invalid_line_count, 2);
        assert_eq!(report.records[0].uid, u32::MAX);
        assert_eq!(report.records[0].gid, u32::MAX);
    }

    #[test]
    fn an_empty_input_has_no_lines() {
        let report = parse_linux_passwd(b"");

        assert_eq!(report.line_count, 0);
        assert!(report.records.is_empty());
        assert!(report.invalid_lines.is_empty());
        assert!(report.non_record_lines.is_empty());
    }

    #[test]
    fn partial_recovery_only_parses_complete_lines_outside_missing_ranges() {
        let root = b"root:x:0:0:root:/root:/bin/bash\n";
        let torn_prefix = b"tor";
        let missing = [0u8; 4];
        let torn_suffix = b"n:x:7:7::/:/bin/sh\n";
        let alice = b"alice:x:1000:1000::/home/alice:/bin/sh\n";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(root);
        bytes.extend_from_slice(torn_prefix);
        let missing_offset = bytes.len() as u64;
        bytes.extend_from_slice(&missing);
        bytes.extend_from_slice(torn_suffix);
        bytes.extend_from_slice(alice);

        let parsed = parse_recovered_fragments(
            &bytes,
            &[LinuxMissingRange {
                file_offset: missing_offset,
                length: missing.len() as u64,
            }],
        );

        assert_eq!(parsed.fragments.len(), 2);
        assert_eq!(parsed.fragments[0].parse_report.record_count, 1);
        assert_eq!(parsed.fragments[0].parse_report.records[0].username, "root");
        assert_eq!(parsed.fragments[1].parse_report.record_count, 1);
        assert_eq!(
            parsed.fragments[1].parse_report.records[0].username,
            "alice"
        );
        assert!(
            parsed
                .fragments
                .iter()
                .all(|fragment| fragment.line_number_scope == "fragment_relative")
        );
        assert_eq!(
            parsed
                .discarded_boundaries
                .iter()
                .map(|range| range.length)
                .sum::<u64>(),
            (torn_prefix.len() + torn_suffix.len()) as u64
        );
        assert!(parsed.fragments.iter().all(|fragment| {
            fragment
                .parse_report
                .warnings
                .iter()
                .all(|warning| warning.kind != "nul_byte")
        }));
    }

    #[test]
    fn complete_recovery_is_parsed_as_one_file_relative_fragment() {
        let bytes = b"root:x:0:0:root:/root:/bin/bash\n";

        let parsed = parse_recovered_fragments(bytes, &[]);

        assert_eq!(parsed.fragments.len(), 1);
        assert_eq!(parsed.fragments[0].file_offset, 0);
        assert_eq!(parsed.fragments[0].length, bytes.len() as u64);
        assert_eq!(parsed.fragments[0].line_number_scope, "file_relative");
        assert_eq!(parsed.fragments[0].parse_report.record_count, 1);
        assert!(parsed.discarded_boundaries.is_empty());
    }

    #[test]
    fn reverse_content_validation_accepts_a_coherent_passwd_file() {
        let bytes = b"root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
bin:x:2:2:bin:/bin:/usr/sbin/nologin\n";
        let parsed = parse_recovered_fragments(bytes, &[]);

        assert!(is_high_confidence_passwd_content(&parsed));
    }

    #[test]
    fn reverse_content_validation_rejects_a_weak_root_string_copy() {
        let bytes = b"root:x:0:0:root:/root:/bin/bash\n\
alice:x:1000:1000::/home/alice:/bin/bash\n";
        let parsed = parse_recovered_fragments(bytes, &[]);

        assert!(!is_high_confidence_passwd_content(&parsed));
    }

    #[test]
    fn reverse_content_validation_rejects_malformed_neighboring_lines() {
        let bytes = b"root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
not-a-passwd-record\n";
        let parsed = parse_recovered_fragments(bytes, &[]);

        assert!(!is_high_confidence_passwd_content(&parsed));
    }

    #[test]
    fn candidate_selection_is_exact_and_deduplicates_superblock_inode_pairs() {
        let first = synthetic_filescan_record(0x1000, 0x2000, 0x3000);
        let mut duplicate = first.clone();
        duplicate.dentry = 0x4000;
        duplicate.dentry_hex = "0x0000000000004000".to_owned();
        let second_superblock = synthetic_filescan_record(0x5000, 0x2000, 0x6000);
        let mut unresolved = synthetic_filescan_record(0x7000, 0x8000, 0x9000);
        unresolved.path_status = "parent_mismatch".to_owned();
        let mut backup = synthetic_filescan_record(0xa000, 0xb000, 0xc000);
        backup.path = Some("/etc/passwd.bak".to_owned());
        let mut directory = synthetic_filescan_record(0xd000, 0xe000, 0xf000);
        directory.file_type = "directory".to_owned();
        directory.mode = 0o040755;

        let records = [
            first,
            duplicate,
            second_superblock,
            unresolved,
            backup,
            directory,
        ];
        let selection = select_passwd_candidates(&records);

        assert_eq!(selection.matched_record_count, 3);
        assert_eq!(selection.duplicate_record_count, 1);
        assert_eq!(selection.records.len(), 2);
        assert_eq!(selection.records[0].superblock, 0x1000);
        assert_eq!(selection.records[1].superblock, 0x5000);
    }

    #[test]
    fn aggregate_report_warns_when_no_resident_candidate_exists() {
        let path = temporary_image_path("passwd-no-candidate");
        fs::write(&path, [0u8; 8]).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let kernel = synthetic_kernel_context();
        let filescan = synthetic_filescan_report(&kernel, Vec::new());

        let report = analyze_linux_passwd(&image, &kernel, &filescan, 10, 0x10_0000).unwrap();

        assert!(!report.complete);
        assert_eq!(report.candidate_count, 0);
        assert_eq!(report.filescan.requested_limit, 10);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.kind == "no_resident_passwd_candidate")
        );
        assert!(report.scope.contains("not an on-disk account inventory"));
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn aggregate_api_rejects_invalid_limits() {
        let path = temporary_image_path("passwd-invalid-limit");
        fs::write(&path, [0u8; 8]).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let kernel = synthetic_kernel_context();
        let filescan = synthetic_filescan_report(&kernel, Vec::new());

        assert!(analyze_linux_passwd(&image, &kernel, &filescan, 0, 1).is_err());
        assert!(analyze_linux_passwd(&image, &kernel, &filescan, 1, 0).is_err());
        drop(image);
        fs::remove_file(path).unwrap();
    }

    fn synthetic_kernel_context() -> LinuxKernelContext {
        LinuxKernelContext {
            architecture: "x86_64_4level".to_owned(),
            banner: "Linux version synthetic".to_owned(),
            banner_physical_address: 0,
            directory_table_base: 0x1000,
            page_table_source: "synthetic_test".to_owned(),
            vmcoreinfo_physical_address: None,
            init_task: 0xffff_ffff_8100_0000,
            init_task_physical: 0,
            profile_source: "synthetic_test".to_owned(),
            profile_fingerprint: "synthetic_test".to_owned(),
            btf_physical_address: None,
            task_struct_size: 0,
            task_struct_offsets: Default::default(),
            symbol_table: None,
        }
    }

    fn synthetic_filescan_report(
        kernel: &LinuxKernelContext,
        records: Vec<LinuxFileScanRecord>,
    ) -> LinuxFileScanReport {
        LinuxFileScanReport {
            kernel: kernel.clone(),
            source: "superblock_dentry_tree".to_owned(),
            scope: "resident positive dentries".to_owned(),
            path_semantics: "superblock_relative".to_owned(),
            profile_source: "synthetic_test".to_owned(),
            profile_fingerprint: "synthetic_test".to_owned(),
            record_count: records.len(),
            records,
            complete: true,
            structural_complete: true,
            limit_reached: false,
            stop_reason: LinuxFileScanStopReason::SuperBlockListHead,
            superblocks_seen: 1,
            superblocks_walked: 1,
            dentries_seen: 0,
            negative_dentries: 0,
            invalid_dentries: 0,
            dentry_validation_anomalies: 0,
            unique_inodes: 0,
            warning_count: 0,
            warning_counts: BTreeMap::new(),
            warnings: Vec::new(),
            bytes_scanned: 0,
            discovery_scan_seconds: 0.0,
            discovery_scan_gib_per_second: 0.0,
            traversal_seconds: 0.0,
        }
    }

    fn temporary_image_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "starmem-linux-{label}-{}-{nonce}.raw",
            std::process::id()
        ))
    }

    fn synthetic_filescan_record(superblock: u64, inode: u64, dentry: u64) -> LinuxFileScanRecord {
        let address = |value| format!("{value:#018x}");
        LinuxFileScanRecord {
            source: "synthetic_test".to_owned(),
            superblock,
            superblock_hex: address(superblock),
            superblock_physical: None,
            superblock_physical_hex: None,
            filesystem: Some("ext4".to_owned()),
            superblock_id: Some("test".to_owned()),
            device: "8:1".to_owned(),
            device_raw: (8 << 20) | 1,
            device_major: 8,
            device_minor: 1,
            dentry,
            dentry_hex: address(dentry),
            dentry_physical: None,
            dentry_physical_hex: None,
            parent_dentry: dentry,
            parent_dentry_hex: address(dentry),
            observed_parent_dentry: Some(dentry),
            observed_parent_dentry_hex: Some(address(dentry)),
            inode,
            inode_hex: address(inode),
            inode_physical: None,
            inode_physical_hex: None,
            inode_number: Some(42),
            name: Some("passwd".to_owned()),
            name_bytes_hex: Some("706173737764".to_owned()),
            name_utf8_valid: Some(true),
            name_status: "decoded".to_owned(),
            path: Some("/etc/passwd".to_owned()),
            path_status: "resolved".to_owned(),
            path_scope: "superblock_relative".to_owned(),
            membership_status: "validated_link".to_owned(),
            file_type: "regular".to_owned(),
            mode: 0o100644,
            mode_string: "-rw-r--r--".to_owned(),
            uid: Some(0),
            gid: Some(0),
            link_count: Some(1),
            size: Some(128),
            cached_pages: Some(1),
            accessed_utc: None,
            modified_utc: None,
            changed_utc: None,
            metadata_complete: true,
            deleted: Some(false),
        }
    }
}
