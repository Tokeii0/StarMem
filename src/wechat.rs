use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use aes::Aes256;
use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use anyhow::{Result, ensure};
use serde::Serialize;

use crate::address::{VirtualAddressRegion, X64AddressSpace};
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::scan::scan_patterns_ascii_case_insensitive;
use crate::windows::{ProcessRecord, WindowsKernelContext, list_processes};

const DEFAULT_CHUNK_SIZE: usize = 64 * 1024 * 1024;
const MAX_LITERAL_HEX_LENGTH: usize = 192;
const MAX_EVIDENCE_PER_KEY: usize = 16;
const MAX_WARNING_COUNT: usize = 64;
const MIN_RAW_KEY_PHYSICAL_COPIES: usize = 3;
const KEY_SCAN_PATTERNS: &[&[u8]] = &[
    b"x'",
    b"x\0'\0",
    b"db_storage",
    b"sqlcipher",
    b"sqlite3",
    b"fts3",
    b"fts5",
    b"json_",
];
const ASCII_LITERAL_PATTERN: usize = 0;
const UTF16_LITERAL_PATTERN: usize = 1;
const FIRST_DATABASE_CONTEXT_PATTERN: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WechatScanStage {
    Processes,
    Anchors,
    AddressMapping,
    Validation,
}

#[derive(Debug, Clone)]
pub struct WechatScanOptions {
    pub pid: Option<u64>,
    pub include_helpers: bool,
    pub limit: usize,
    pub anchor_limit: usize,
    pub process_space_limit: usize,
    pub verification_roots: Vec<PathBuf>,
    pub verification_file_limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WechatKeyConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WechatKeyKind {
    AccountMaster,
    Database,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WechatProcessRole {
    Main,
    Helper,
    MiniProgram,
    Explicit,
    Unattributed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WechatKeyEncoding {
    Ascii,
    Utf16Le,
    RawBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WechatKeyContext {
    SqlcipherPragma,
    KeyAssignment,
    HexLiteral,
    RepeatedHeapAllocation,
}

#[derive(Debug, Clone, Serialize)]
pub struct WechatProcessInfo {
    pub pid: u64,
    pub ppid: Option<u64>,
    pub process: String,
    pub role: WechatProcessRole,
    pub selected: bool,
    pub directory_table_base: Option<u64>,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WechatKeyEvidence {
    pub virtual_address: Option<u64>,
    pub physical_address: u64,
    pub encoding: WechatKeyEncoding,
    pub literal_hex_length: usize,
    pub context: WechatKeyContext,
    pub context_preview: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WechatDatabaseValidation {
    pub database_path: PathBuf,
    pub salt_hex: String,
    pub page_size: usize,
    pub reserve_size: usize,
    pub write_version: u8,
    pub read_version: u8,
    pub schema_format: u32,
    pub text_encoding: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct WechatKeyRecord {
    pub pid: u64,
    pub process: String,
    pub process_role: WechatProcessRole,
    pub process_path: Option<String>,
    pub key_kind: WechatKeyKind,
    pub key_hex: String,
    pub salt_hex: Option<String>,
    pub key_entropy: f64,
    pub confidence: WechatKeyConfidence,
    pub sqlcipher_context: bool,
    pub database_validation: Option<WechatDatabaseValidation>,
    pub occurrences: usize,
    pub evidence: Vec<WechatKeyEvidence>,
}

#[derive(Debug, Serialize)]
pub struct WechatScanReport {
    pub records: Vec<WechatKeyRecord>,
    pub processes: Vec<WechatProcessInfo>,
    pub wechat_processes_found: usize,
    pub address_spaces_examined: usize,
    pub raw_anchor_hits: usize,
    pub syntax_anchor_hits: usize,
    pub candidate_pages: usize,
    pub database_context_pages: usize,
    pub raw_key_candidate_windows: usize,
    pub verification_files_examined: usize,
    pub verified_records: usize,
    pub bytes_scanned: u64,
    pub physical_scan_seconds: f64,
    pub address_mapping_seconds: f64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct ProcessCandidate {
    pid: u64,
    ppid: Option<u64>,
    process: String,
    role: WechatProcessRole,
    dtb: Option<u64>,
    image_path: Option<String>,
    command_line: Option<String>,
    working_set: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Anchor {
    physical_address: u64,
    encoding: WechatKeyEncoding,
}

#[derive(Debug)]
struct ParsedLiteral {
    key_hex: String,
    salt_hex: Option<String>,
    key_entropy: f64,
    literal_hex_length: usize,
}

struct RecordBuilder {
    record: WechatKeyRecord,
    physical_occurrences: HashSet<u64>,
}

#[derive(Debug)]
struct RawKeyCandidate {
    physical_address: u64,
    key_hex: String,
    key_entropy: f64,
    context_preview: Option<String>,
}

#[derive(Debug)]
struct RawKeyGroup {
    key_entropy: f64,
    candidates: Vec<RawKeyCandidate>,
}

pub fn scan_wechat_keys<F>(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &WechatScanOptions,
    mut progress: F,
) -> Result<WechatScanReport>
where
    F: FnMut(WechatScanStage),
{
    ensure!(options.limit > 0, "微信密钥结果上限必须大于零");
    ensure!(options.anchor_limit > 0, "微信密钥锚点上限必须大于零");
    ensure!(
        options.process_space_limit > 0,
        "微信进程地址空间上限必须大于零"
    );
    ensure!(
        options.verification_roots.is_empty() || options.verification_file_limit > 0,
        "微信数据库验证文件上限必须大于零"
    );
    let started = Instant::now();
    let mut complete = true;
    let mut warnings = Vec::new();

    progress(WechatScanStage::Processes);
    let process_report = list_processes(image, kernel, profile, 65_536)?;
    complete &= process_report.complete;
    for warning in &process_report.warnings {
        push_warning(
            &mut warnings,
            format!("进程枚举/{}：{}", warning.kind, warning.message),
        );
    }
    let candidates = discover_wechat_processes(&process_report.processes, options.pid);
    let explicit_missing = options
        .pid
        .is_some_and(|pid| !candidates.iter().any(|process| process.pid == pid));
    if explicit_missing {
        complete = false;
        push_warning(
            &mut warnings,
            format!(
                "活动进程链表中没有找到指定 PID {}",
                options.pid.unwrap_or_default()
            ),
        );
    }
    let mut selected = candidates
        .iter()
        .filter(|process| process_selected(process, &candidates, options))
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_unstable_by(process_priority_order);

    let mut selected_dtbs = Vec::<(u64, Vec<ProcessCandidate>)>::new();
    let mut by_dtb = HashMap::<u64, Vec<ProcessCandidate>>::new();
    for process in &selected {
        if let Some(dtb) = process.dtb {
            by_dtb.entry(dtb).or_default().push(process.clone());
        } else {
            complete = false;
            push_warning(
                &mut warnings,
                format!(
                    "微信进程 {}({}) 没有可读的用户页表",
                    process.process, process.pid
                ),
            );
        }
    }
    selected_dtbs.extend(by_dtb);
    selected_dtbs
        .sort_unstable_by(|(_, left), (_, right)| process_priority_order(&left[0], &right[0]));
    if selected_dtbs.len() > options.process_space_limit {
        complete = false;
        push_warning(
            &mut warnings,
            format!(
                "需要分析 {} 个微信地址空间；按优先级只分析前 {} 个",
                selected_dtbs.len(),
                options.process_space_limit
            ),
        );
        selected_dtbs.truncate(options.process_space_limit);
    }
    let selected_pids = selected_dtbs
        .iter()
        .flat_map(|(_, owners)| owners.iter().map(|owner| owner.pid))
        .collect::<HashSet<_>>();
    let processes = candidates
        .iter()
        .map(|process| WechatProcessInfo {
            pid: process.pid,
            ppid: process.ppid,
            process: process.process.clone(),
            role: process.role,
            selected: selected_pids.contains(&process.pid),
            directory_table_base: process.dtb,
            image_path: process.image_path.clone(),
            command_line: process.command_line.clone(),
        })
        .collect::<Vec<_>>();

    if selected_dtbs.is_empty() {
        progress(WechatScanStage::Anchors);
        progress(WechatScanStage::AddressMapping);
        progress(WechatScanStage::Validation);
        if candidates.is_empty() && options.pid.is_none() {
            push_warning(&mut warnings, "没有发现活动的微信进程".to_owned());
        }
        return Ok(WechatScanReport {
            records: Vec::new(),
            processes,
            wechat_processes_found: candidates.len(),
            address_spaces_examined: 0,
            raw_anchor_hits: 0,
            syntax_anchor_hits: 0,
            candidate_pages: 0,
            database_context_pages: 0,
            raw_key_candidate_windows: 0,
            verification_files_examined: 0,
            verified_records: 0,
            bytes_scanned: 0,
            physical_scan_seconds: 0.0,
            address_mapping_seconds: 0.0,
            scan_seconds: started.elapsed().as_secs_f64(),
            scan_gib_per_second: 0.0,
            complete,
            warnings,
        });
    }

    progress(WechatScanStage::Anchors);
    let physical_scan_started = Instant::now();
    let raw = scan_patterns_ascii_case_insensitive(
        image,
        KEY_SCAN_PATTERNS,
        options.anchor_limit,
        DEFAULT_CHUNK_SIZE,
    )?;
    let physical_scan_seconds = physical_scan_started.elapsed().as_secs_f64();
    if raw
        .truncated_patterns
        .iter()
        .take(FIRST_DATABASE_CONTEXT_PATTERN)
        .any(|truncated| *truncated)
    {
        complete = false;
        push_warning(
            &mut warnings,
            format!(
                "十六进制字面量锚点达到 {} 条的安全上限",
                options.anchor_limit
            ),
        );
    }
    let raw_anchor_hits = raw
        .hits
        .iter()
        .filter(|hit| hit.pattern_index < FIRST_DATABASE_CONTEXT_PATTERN)
        .count();
    let mut anchors = raw
        .hits
        .iter()
        .filter_map(|hit| {
            let encoding = match hit.pattern_index {
                ASCII_LITERAL_PATTERN => WechatKeyEncoding::Ascii,
                UTF16_LITERAL_PATTERN => WechatKeyEncoding::Utf16Le,
                _ => return None,
            };
            physical_anchor_may_be_key(image, hit.physical_address, encoding).then_some(Anchor {
                physical_address: hit.physical_address,
                encoding,
            })
        })
        .collect::<Vec<_>>();
    anchors.sort_unstable_by_key(|anchor| (anchor.physical_address, anchor.encoding as u8));
    anchors.dedup();
    let syntax_anchor_hits = anchors.len();
    let mut anchors_by_page = HashMap::<u64, Vec<Anchor>>::new();
    for anchor in anchors {
        anchors_by_page
            .entry(anchor.physical_address & !0xfff)
            .or_default()
            .push(anchor);
    }
    let database_pages = raw
        .hits
        .iter()
        .filter(|hit| hit.pattern_index >= FIRST_DATABASE_CONTEXT_PATTERN)
        .map(|hit| hit.physical_address & !0xfff)
        .collect::<HashSet<_>>();
    if raw
        .truncated_patterns
        .iter()
        .skip(FIRST_DATABASE_CONTEXT_PATTERN)
        .any(|truncated| *truncated)
    {
        complete = false;
        push_warning(
            &mut warnings,
            format!(
                "微信数据库上下文锚点达到每种 {} 条的安全上限",
                options.anchor_limit
            ),
        );
    }
    let mut raw_candidates_by_page = HashMap::<u64, Vec<RawKeyCandidate>>::new();
    for physical_page in &database_pages {
        let mut page = [0u8; 0x1000];
        if image.read_physical(*physical_page, &mut page).is_err() {
            continue;
        }
        let candidates = raw_heap_key_candidates(&page, *physical_page);
        if !candidates.is_empty() {
            raw_candidates_by_page.insert(*physical_page, candidates);
        }
    }
    let raw_key_candidate_windows = raw_candidates_by_page.values().map(Vec::len).sum::<usize>();
    let mut targets = anchors_by_page.keys().copied().collect::<HashSet<_>>();
    targets.extend(database_pages.iter().copied());
    let candidate_pages = targets.len();

    progress(WechatScanStage::AddressMapping);
    let mapping_started = Instant::now();
    let mut builders =
        HashMap::<(u64, WechatKeyKind, String, Option<String>), RecordBuilder>::new();
    let mut address_spaces_examined = 0usize;
    for (dtb, owners) in &selected_dtbs {
        let space = match X64AddressSpace::new(image, *dtb) {
            Ok(space) => space,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("无法打开微信进程页表 {dtb:#x}：{error:#}"),
                );
                continue;
            }
        };
        address_spaces_examined += 1;
        let reverse = match space.reverse_translate_pages(&targets, VirtualAddressRegion::User, 8) {
            Ok(reverse) => reverse,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("无法反向映射微信进程页表 {dtb:#x}：{error:#}"),
                );
                continue;
            }
        };
        for (physical_page, virtual_pages) in reverse {
            let Some(page_anchors) = anchors_by_page.get(&physical_page) else {
                continue;
            };
            for virtual_page in virtual_pages {
                for anchor in page_anchors {
                    let delta = anchor.physical_address - physical_page;
                    let Some(virtual_address) = virtual_page.checked_add(delta) else {
                        continue;
                    };
                    let bytes = read_virtual_prefix(
                        &space,
                        virtual_address,
                        maximum_literal_bytes(anchor.encoding),
                    );
                    let Some(literal) = parse_key_literal(&bytes, anchor.encoding) else {
                        continue;
                    };
                    let (context, context_preview) =
                        read_key_context(&space, virtual_address, anchor.encoding);
                    let confidence = candidate_confidence(context, literal.salt_hex.is_some());
                    for owner in owners {
                        let key = (
                            owner.pid,
                            WechatKeyKind::Database,
                            literal.key_hex.clone(),
                            literal.salt_hex.clone(),
                        );
                        let evidence = WechatKeyEvidence {
                            virtual_address: Some(virtual_address),
                            physical_address: anchor.physical_address,
                            encoding: anchor.encoding,
                            literal_hex_length: literal.literal_hex_length,
                            context,
                            context_preview: context_preview.clone(),
                        };
                        let builder = builders.entry(key).or_insert_with(|| RecordBuilder {
                            record: WechatKeyRecord {
                                pid: owner.pid,
                                process: owner.process.clone(),
                                process_role: owner.role,
                                process_path: owner.image_path.clone(),
                                key_kind: WechatKeyKind::Database,
                                key_hex: literal.key_hex.clone(),
                                salt_hex: literal.salt_hex.clone(),
                                key_entropy: literal.key_entropy,
                                confidence,
                                sqlcipher_context: context == WechatKeyContext::SqlcipherPragma,
                                database_validation: None,
                                occurrences: 0,
                                evidence: Vec::new(),
                            },
                            physical_occurrences: HashSet::new(),
                        });
                        if builder.physical_occurrences.insert(anchor.physical_address) {
                            builder.record.occurrences += 1;
                        }
                        builder.record.confidence = builder.record.confidence.max(confidence);
                        builder.record.sqlcipher_context |=
                            context == WechatKeyContext::SqlcipherPragma;
                        if builder.record.evidence.len() < MAX_EVIDENCE_PER_KEY
                            && !builder.record.evidence.contains(&evidence)
                        {
                            builder.record.evidence.push(evidence);
                        }
                    }
                }
                if let Some(raw_candidates) = raw_candidates_by_page.get(&physical_page) {
                    for candidate in raw_candidates {
                        let delta = candidate.physical_address - physical_page;
                        let Some(virtual_address) = virtual_page.checked_add(delta) else {
                            continue;
                        };
                        for owner in owners {
                            let key = (
                                owner.pid,
                                WechatKeyKind::AccountMaster,
                                candidate.key_hex.clone(),
                                None,
                            );
                            let evidence = WechatKeyEvidence {
                                virtual_address: Some(virtual_address),
                                physical_address: candidate.physical_address,
                                encoding: WechatKeyEncoding::RawBytes,
                                literal_hex_length: 64,
                                context: WechatKeyContext::RepeatedHeapAllocation,
                                context_preview: candidate.context_preview.clone(),
                            };
                            let builder = builders.entry(key).or_insert_with(|| RecordBuilder {
                                record: WechatKeyRecord {
                                    pid: owner.pid,
                                    process: owner.process.clone(),
                                    process_role: owner.role,
                                    process_path: owner.image_path.clone(),
                                    key_kind: WechatKeyKind::AccountMaster,
                                    key_hex: candidate.key_hex.clone(),
                                    salt_hex: None,
                                    key_entropy: candidate.key_entropy,
                                    confidence: WechatKeyConfidence::Medium,
                                    sqlcipher_context: false,
                                    database_validation: None,
                                    occurrences: 0,
                                    evidence: Vec::new(),
                                },
                                physical_occurrences: HashSet::new(),
                            });
                            if builder
                                .physical_occurrences
                                .insert(candidate.physical_address)
                            {
                                builder.record.occurrences += 1;
                            }
                            if builder.record.evidence.len() < MAX_EVIDENCE_PER_KEY
                                && !builder.record.evidence.contains(&evidence)
                            {
                                builder.record.evidence.push(evidence);
                            }
                        }
                    }
                }
            }
        }
    }
    let address_mapping_seconds = mapping_started.elapsed().as_secs_f64();

    progress(WechatScanStage::Validation);
    let mut raw_groups = HashMap::<String, RawKeyGroup>::new();
    for candidate in raw_candidates_by_page.into_values().flatten() {
        let group = raw_groups
            .entry(candidate.key_hex.clone())
            .or_insert_with(|| RawKeyGroup {
                key_entropy: candidate.key_entropy,
                candidates: Vec::new(),
            });
        if !group
            .candidates
            .iter()
            .any(|existing| existing.physical_address == candidate.physical_address)
        {
            group.candidates.push(candidate);
        }
    }
    for (key_hex, mut group) in raw_groups {
        if group.candidates.len() < MIN_RAW_KEY_PHYSICAL_COPIES {
            continue;
        }
        if builders
            .keys()
            .any(|(_, kind, key, _)| *kind == WechatKeyKind::Database && key == &key_hex)
        {
            continue;
        }
        group
            .candidates
            .sort_unstable_by_key(|candidate| candidate.physical_address);
        let matching_keys = builders
            .keys()
            .filter(|(_, kind, key, _)| *kind == WechatKeyKind::AccountMaster && key == &key_hex)
            .cloned()
            .collect::<Vec<_>>();
        if matching_keys.is_empty() {
            let evidence = group
                .candidates
                .iter()
                .take(MAX_EVIDENCE_PER_KEY)
                .map(|candidate| WechatKeyEvidence {
                    virtual_address: None,
                    physical_address: candidate.physical_address,
                    encoding: WechatKeyEncoding::RawBytes,
                    literal_hex_length: 64,
                    context: WechatKeyContext::RepeatedHeapAllocation,
                    context_preview: candidate.context_preview.clone(),
                })
                .collect::<Vec<_>>();
            let physical_occurrences = group
                .candidates
                .iter()
                .map(|candidate| candidate.physical_address)
                .collect::<HashSet<_>>();
            builders.insert(
                (0, WechatKeyKind::AccountMaster, key_hex.clone(), None),
                RecordBuilder {
                    record: WechatKeyRecord {
                        pid: 0,
                        process: "未归属微信残留页".to_owned(),
                        process_role: WechatProcessRole::Unattributed,
                        process_path: None,
                        key_kind: WechatKeyKind::AccountMaster,
                        key_hex,
                        salt_hex: None,
                        key_entropy: group.key_entropy,
                        confidence: WechatKeyConfidence::Medium,
                        sqlcipher_context: false,
                        database_validation: None,
                        occurrences: physical_occurrences.len(),
                        evidence,
                    },
                    physical_occurrences,
                },
            );
            continue;
        }
        for key in matching_keys {
            let Some(builder) = builders.get_mut(&key) else {
                continue;
            };
            for candidate in &group.candidates {
                builder
                    .physical_occurrences
                    .insert(candidate.physical_address);
                if builder.record.evidence.len() < MAX_EVIDENCE_PER_KEY
                    && !builder
                        .record
                        .evidence
                        .iter()
                        .any(|evidence| evidence.physical_address == candidate.physical_address)
                {
                    builder.record.evidence.push(WechatKeyEvidence {
                        virtual_address: None,
                        physical_address: candidate.physical_address,
                        encoding: WechatKeyEncoding::RawBytes,
                        literal_hex_length: 64,
                        context: WechatKeyContext::RepeatedHeapAllocation,
                        context_preview: candidate.context_preview.clone(),
                    });
                }
            }
            builder.record.occurrences = builder.physical_occurrences.len();
        }
    }
    let mut records = builders
        .into_values()
        .filter(|builder| {
            builder.record.key_kind != WechatKeyKind::AccountMaster
                || builder.record.occurrences >= MIN_RAW_KEY_PHYSICAL_COPIES
        })
        .map(|mut builder| {
            builder
                .record
                .evidence
                .sort_unstable_by_key(|item| (item.virtual_address, item.physical_address));
            builder.record
        })
        .collect::<Vec<_>>();
    let (verification_files_examined, verified_records) = verify_database_candidates(
        &mut records,
        &options.verification_roots,
        options.verification_file_limit,
        &mut complete,
        &mut warnings,
    );
    records.sort_unstable_by(|left, right| {
        left.key_kind
            .cmp(&right.key_kind)
            .then_with(|| right.confidence.cmp(&left.confidence))
            .then_with(|| right.occurrences.cmp(&left.occurrences))
            .then_with(|| {
                process_role_priority(left.process_role)
                    .cmp(&process_role_priority(right.process_role))
            })
            .then_with(|| left.pid.cmp(&right.pid))
            .then_with(|| left.key_hex.cmp(&right.key_hex))
    });
    if records.len() > options.limit {
        complete = false;
        push_warning(
            &mut warnings,
            format!("微信密钥候选达到 {} 条结果上限", options.limit),
        );
        records.truncate(options.limit);
    }
    if !records.is_empty() {
        push_warning(
            &mut warnings,
            "结果是内存中的密钥候选；账户主密钥候选来自微信数据库上下文页中重复出现的 32 字节堆分配；数据库密钥只有在存在 SQLCipher PRAGMA 上下文或通过指定数据库首页验证时才标为高置信度".to_owned(),
        );
    }
    if candidates.is_empty() && options.pid.is_none() {
        push_warning(&mut warnings, "没有发现活动的微信进程".to_owned());
    }
    let scan_seconds = started.elapsed().as_secs_f64();
    Ok(WechatScanReport {
        records,
        processes,
        wechat_processes_found: candidates.len(),
        address_spaces_examined,
        raw_anchor_hits,
        syntax_anchor_hits,
        candidate_pages,
        database_context_pages: database_pages.len(),
        raw_key_candidate_windows,
        verification_files_examined,
        verified_records,
        bytes_scanned: raw.bytes_scanned,
        physical_scan_seconds,
        address_mapping_seconds,
        scan_seconds,
        scan_gib_per_second: raw.gib_per_second,
        complete,
        warnings,
    })
}

fn discover_wechat_processes(
    processes: &[ProcessRecord],
    pid_filter: Option<u64>,
) -> Vec<ProcessCandidate> {
    let mut output = processes
        .iter()
        .filter_map(|process| {
            let role = if pid_filter == Some(process.pid) {
                Some(WechatProcessRole::Explicit)
            } else if pid_filter.is_none() {
                classify_wechat_process(process)
            } else {
                None
            }?;
            Some(ProcessCandidate {
                pid: process.pid,
                ppid: process.ppid,
                process: process.name.clone(),
                role,
                dtb: process
                    .details
                    .user_directory_table_base
                    .or(process.details.directory_table_base)
                    .map(|dtb| dtb & 0x000f_ffff_ffff_f000)
                    .filter(|dtb| *dtb != 0),
                image_path: process.details.image_path.clone(),
                command_line: process.details.command_line.clone(),
                working_set: process.details.working_set_private_size.unwrap_or(0),
            })
        })
        .collect::<Vec<_>>();
    output.sort_unstable_by(process_priority_order);
    output
}

fn classify_wechat_process(process: &ProcessRecord) -> Option<WechatProcessRole> {
    let name = process.name.to_ascii_lowercase();
    let image_path = process
        .details
        .image_path
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let command_line = process
        .details
        .command_line
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let app_ex = name.starts_with("wechatappex")
        || image_path.contains("wechatappex.exe")
        || image_path.contains("\\xwechat\\radium");
    if app_ex {
        return Some(WechatProcessRole::MiniProgram);
    }
    let wechat = name.starts_with("wechat")
        || name.starts_with("weixin")
        || image_path.ends_with("\\wechat.exe")
        || image_path.ends_with("\\weixin.exe");
    if !wechat {
        return None;
    }
    let helper = command_line.contains(" --type=")
        || command_line.contains(" --user-lib-dir=")
        || command_line.contains(" --no-sandbox")
        || command_line.contains(" --wmpf-");
    Some(if helper {
        WechatProcessRole::Helper
    } else {
        WechatProcessRole::Main
    })
}

fn process_selected(
    process: &ProcessCandidate,
    candidates: &[ProcessCandidate],
    options: &WechatScanOptions,
) -> bool {
    if options.pid.is_some() || options.include_helpers {
        return true;
    }
    let has_main = candidates
        .iter()
        .any(|candidate| candidate.role == WechatProcessRole::Main);
    if has_main {
        process.role == WechatProcessRole::Main
    } else {
        candidates
            .first()
            .is_some_and(|first| first.pid == process.pid)
    }
}

fn process_priority_order(left: &ProcessCandidate, right: &ProcessCandidate) -> std::cmp::Ordering {
    process_role_priority(left.role)
        .cmp(&process_role_priority(right.role))
        .then_with(|| right.working_set.cmp(&left.working_set))
        .then_with(|| left.pid.cmp(&right.pid))
}

fn process_role_priority(role: WechatProcessRole) -> u8 {
    match role {
        WechatProcessRole::Explicit => 0,
        WechatProcessRole::Main => 1,
        WechatProcessRole::Helper => 2,
        WechatProcessRole::MiniProgram => 3,
        WechatProcessRole::Unattributed => 4,
    }
}

fn maximum_literal_bytes(encoding: WechatKeyEncoding) -> usize {
    let characters = 2 + MAX_LITERAL_HEX_LENGTH + 1;
    match encoding {
        WechatKeyEncoding::Ascii => characters,
        WechatKeyEncoding::Utf16Le => characters * 2,
        WechatKeyEncoding::RawBytes => characters,
    }
}

fn physical_anchor_may_be_key(
    image: &MemoryImage,
    physical_address: u64,
    encoding: WechatKeyEncoding,
) -> bool {
    let maximum = maximum_literal_bytes(encoding);
    let page_remaining = (0x1000 - (physical_address & 0xfff)) as usize;
    let length = maximum.min(page_remaining);
    let mut bytes = vec![0u8; length];
    if image.read_physical(physical_address, &mut bytes).is_err() {
        return false;
    }
    parse_key_literal(&bytes, encoding).is_some() || length < maximum
}

fn read_virtual_prefix(space: &X64AddressSpace<'_>, mut address: u64, maximum: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(maximum);
    while output.len() < maximum {
        let count = (0x1000 - (address & 0xfff)) as usize;
        let count = count.min(maximum - output.len());
        let mut bytes = vec![0u8; count];
        if space.read_virtual(address, &mut bytes).is_err() {
            break;
        }
        output.extend_from_slice(&bytes);
        let Some(next) = address.checked_add(count as u64) else {
            break;
        };
        address = next;
    }
    output
}

fn parse_key_literal(bytes: &[u8], encoding: WechatKeyEncoding) -> Option<ParsedLiteral> {
    let unit = match encoding {
        WechatKeyEncoding::Ascii => 1,
        WechatKeyEncoding::Utf16Le => 2,
        WechatKeyEncoding::RawBytes => return None,
    };
    let character = |index: usize| -> Option<u8> {
        let offset = index.checked_mul(unit)?;
        let value = *bytes.get(offset)?;
        if unit == 2 && *bytes.get(offset + 1)? != 0 {
            return None;
        }
        Some(value)
    };
    if !matches!(character(0)?, b'x' | b'X') || character(1)? != b'\'' {
        return None;
    }
    let mut hex_bytes = Vec::with_capacity(MAX_LITERAL_HEX_LENGTH);
    for index in 2..2 + MAX_LITERAL_HEX_LENGTH + 1 {
        let value = character(index)?;
        if value == b'\'' {
            let hex_length = hex_bytes.len();
            if !(hex_length == 64 || hex_length == 96 || (hex_length > 96 && hex_length % 2 == 0)) {
                return None;
            }
            let raw = hex::decode(&hex_bytes).ok()?;
            let key = raw.get(..32)?;
            if !cryptographic_key_shape(key) {
                return None;
            }
            let salt = if hex_length == 64 {
                None
            } else {
                Some(raw.get(raw.len().checked_sub(16)?..)?.to_vec())
            };
            return Some(ParsedLiteral {
                key_hex: hex::encode(key),
                salt_hex: salt.map(hex::encode),
                key_entropy: shannon_entropy(key),
                literal_hex_length: hex_length,
            });
        }
        if !value.is_ascii_hexdigit() {
            return None;
        }
        hex_bytes.push(value);
    }
    None
}

fn cryptographic_key_shape(key: &[u8]) -> bool {
    if key.len() != 32 {
        return false;
    }
    let unique = key.iter().copied().collect::<HashSet<_>>().len();
    unique >= 12 && shannon_entropy(key) >= 3.5
}

fn verify_database_candidates(
    records: &mut [WechatKeyRecord],
    roots: &[PathBuf],
    file_limit: usize,
    complete: &mut bool,
    warnings: &mut Vec<String>,
) -> (usize, usize) {
    if roots.is_empty() {
        return (0, 0);
    }
    let mut candidates_by_salt = HashMap::<[u8; 16], Vec<usize>>::new();
    for (index, record) in records.iter().enumerate() {
        if record.key_kind != WechatKeyKind::Database {
            continue;
        }
        let Some(salt_hex) = &record.salt_hex else {
            continue;
        };
        let Ok(salt) = hex::decode(salt_hex) else {
            continue;
        };
        let Ok(salt) = <[u8; 16]>::try_from(salt) else {
            continue;
        };
        candidates_by_salt.entry(salt).or_default().push(index);
    }
    if candidates_by_salt.is_empty() {
        return (0, 0);
    }

    let mut files = Vec::new();
    for root in roots {
        collect_database_files(root, &mut files, file_limit, complete, warnings);
        if files.len() >= file_limit {
            break;
        }
    }
    files.sort_unstable();
    files.dedup();
    if files.len() > file_limit {
        files.truncate(file_limit);
    }

    let mut examined = 0usize;
    for path in files {
        let mut page = [0u8; 4096];
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) => {
                *complete = false;
                push_warning(
                    warnings,
                    format!("无法打开微信数据库验证文件 {}：{error}", path.display()),
                );
                continue;
            }
        };
        if file.read_exact(&mut page).is_err() {
            continue;
        }
        examined += 1;
        let salt = <[u8; 16]>::try_from(&page[..16]).expect("fixed slice length");
        let Some(candidate_indices) = candidates_by_salt.get(&salt) else {
            continue;
        };
        for index in candidate_indices {
            if records[*index].database_validation.is_some() {
                continue;
            }
            let Ok(key) = hex::decode(&records[*index].key_hex) else {
                continue;
            };
            let Ok(key) = <[u8; 32]>::try_from(key) else {
                continue;
            };
            let Some(mut validation) = validate_sqlcipher_first_page(&page, &key) else {
                continue;
            };
            validation.database_path = path.clone();
            records[*index].confidence = WechatKeyConfidence::High;
            records[*index].database_validation = Some(validation);
        }
    }
    let verified = records
        .iter()
        .filter(|record| record.database_validation.is_some())
        .count();
    (examined, verified)
}

fn collect_database_files(
    root: &Path,
    output: &mut Vec<PathBuf>,
    limit: usize,
    complete: &mut bool,
    warnings: &mut Vec<String>,
) {
    if output.len() >= limit {
        *complete = false;
        push_warning(
            warnings,
            format!("微信数据库验证文件达到 {limit} 个的安全上限"),
        );
        return;
    }
    if root.is_file() {
        if database_file_extension(root) {
            output.push(root.to_path_buf());
        }
        return;
    }
    if !root.is_dir() {
        *complete = false;
        push_warning(
            warnings,
            format!("微信数据库验证目录不存在：{}", root.display()),
        );
        return;
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                *complete = false;
                push_warning(
                    warnings,
                    format!(
                        "无法读取微信数据库验证目录 {}：{error}",
                        directory.display()
                    ),
                );
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() && database_file_extension(&path) {
                output.push(path);
                if output.len() >= limit {
                    *complete = false;
                    push_warning(
                        warnings,
                        format!("微信数据库验证文件达到 {limit} 个的安全上限"),
                    );
                    return;
                }
            }
        }
    }
}

fn database_file_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "db" | "sqlite" | "sqlite3" | "db3"
            )
        })
}

fn validate_sqlcipher_first_page(
    page: &[u8; 4096],
    key: &[u8; 32],
) -> Option<WechatDatabaseValidation> {
    for reserve_size in [48usize, 64, 80, 96] {
        let content_size = page.len().checked_sub(reserve_size)?;
        let encrypted = page.get(16..content_size)?;
        if encrypted.len() < 64 || encrypted.len() % 16 != 0 {
            continue;
        }
        let iv = page.get(content_size..content_size + 16)?;
        let cipher = Aes256::new_from_slice(key).ok()?;
        let mut plaintext = Vec::with_capacity(64);
        let mut previous = <[u8; 16]>::try_from(iv).ok()?;
        for encrypted_block in encrypted.chunks_exact(16).take(4) {
            let mut block = GenericArray::clone_from_slice(encrypted_block);
            cipher.decrypt_block(&mut block);
            for (byte, previous_byte) in block.iter_mut().zip(previous) {
                *byte ^= previous_byte;
            }
            plaintext.extend_from_slice(&block);
            previous = <[u8; 16]>::try_from(encrypted_block).ok()?;
        }
        let page_size = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        let page_size = if page_size == 1 { 65_536 } else { page_size };
        let write_version = plaintext[2];
        let read_version = plaintext[3];
        let schema_format = read_be_u32(&plaintext, 28)?;
        let text_encoding = read_be_u32(&plaintext, 40)?;
        let database_pages = read_be_u32(&plaintext, 12)?;
        if page_size != 4096
            || !matches!(write_version, 1 | 2)
            || !matches!(read_version, 1 | 2)
            || plaintext[4] as usize != reserve_size
            || plaintext[5..8] != [64, 32, 32]
            || database_pages == 0
            || !(1..=4).contains(&schema_format)
            || !(1..=3).contains(&text_encoding)
        {
            continue;
        }
        return Some(WechatDatabaseValidation {
            database_path: PathBuf::new(),
            salt_hex: hex::encode(&page[..16]),
            page_size,
            reserve_size,
            write_version,
            read_version,
            schema_format,
            text_encoding,
        });
    }
    None
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn raw_heap_key_candidates(page: &[u8], physical_page: u64) -> Vec<RawKeyCandidate> {
    let mut output = Vec::new();
    if page.len() < 64 {
        return output;
    }
    for offset in (16..=page.len() - 33).step_by(16) {
        // Windows x64 heap allocations are 16-byte aligned. In observed
        // Weixin 4.x heaps, the 32-byte key payload follows a 16-byte encoded
        // heap header and is NUL-terminated in the next allocation byte.
        if page[offset - 4] != 0
            || page[offset - 2] != 0
            || page[offset - 1] & 0x80 == 0
            || page[offset + 32] != 0
        {
            continue;
        }
        let key = &page[offset..offset + 32];
        let printable = key.iter().filter(|byte| byte.is_ascii_graphic()).count();
        let zero_bytes = key.iter().filter(|byte| **byte == 0).count();
        if printable > 24 || zero_bytes > 1 || !cryptographic_key_shape(key) {
            continue;
        }
        let context_start = offset.saturating_sub(160);
        let context_end = (offset + 32 + 160).min(page.len());
        let context = decode_context(&page[context_start..context_end], WechatKeyEncoding::Ascii);
        output.push(RawKeyCandidate {
            physical_address: physical_page + offset as u64,
            key_hex: hex::encode(key),
            key_entropy: shannon_entropy(key),
            context_preview: sanitized_context_preview(&context),
        });
    }
    output
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn read_key_context(
    space: &X64AddressSpace<'_>,
    virtual_address: u64,
    encoding: WechatKeyEncoding,
) -> (WechatKeyContext, Option<String>) {
    let available = (virtual_address & 0xfff).min(256) as usize;
    if available == 0 {
        return (WechatKeyContext::HexLiteral, None);
    }
    let start = virtual_address - available as u64;
    let mut bytes = vec![0u8; available];
    if space.read_virtual(start, &mut bytes).is_err() {
        return (WechatKeyContext::HexLiteral, None);
    }
    let text = decode_context(&bytes, encoding);
    let lower = text.to_ascii_lowercase();
    let context = if lower.contains("pragma") && (lower.contains("key") || lower.contains("rekey"))
    {
        WechatKeyContext::SqlcipherPragma
    } else if lower.contains("key") || lower.contains("cipher") {
        WechatKeyContext::KeyAssignment
    } else {
        WechatKeyContext::HexLiteral
    };
    let preview = sanitized_context_preview(&text);
    (context, preview)
}

fn decode_context(bytes: &[u8], encoding: WechatKeyEncoding) -> String {
    match encoding {
        WechatKeyEncoding::Ascii => bytes
            .iter()
            .map(|byte| {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    char::from(*byte)
                } else {
                    ' '
                }
            })
            .collect(),
        WechatKeyEncoding::Utf16Le => bytes
            .chunks_exact(2)
            .map(|pair| {
                if pair[1] == 0 && (pair[0].is_ascii_graphic() || pair[0] == b' ') {
                    char::from(pair[0])
                } else {
                    ' '
                }
            })
            .collect(),
        WechatKeyEncoding::RawBytes => bytes
            .iter()
            .map(|byte| {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    char::from(*byte)
                } else {
                    ' '
                }
            })
            .collect(),
    }
}

fn sanitized_context_preview(text: &str) -> Option<String> {
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let preview = if normalized.len() > 160 {
        normalized[normalized.len() - 160..].to_owned()
    } else {
        normalized
    };
    (!preview.is_empty()).then_some(preview)
}

fn candidate_confidence(context: WechatKeyContext, has_salt: bool) -> WechatKeyConfidence {
    match context {
        WechatKeyContext::SqlcipherPragma => WechatKeyConfidence::High,
        WechatKeyContext::KeyAssignment => WechatKeyConfidence::Medium,
        WechatKeyContext::HexLiteral if has_salt => WechatKeyConfidence::Medium,
        WechatKeyContext::HexLiteral => WechatKeyConfidence::Low,
        WechatKeyContext::RepeatedHeapAllocation => WechatKeyConfidence::Medium,
    }
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNING_COUNT && !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncrypt;

    fn random_key_hex() -> String {
        hex::encode((0u8..32).collect::<Vec<_>>())
    }

    #[test]
    fn parses_lovelymem_ascii_key_and_salt_patterns() {
        let key = random_key_hex();
        let salt = "f0e1d2c3b4a5968778695a4b3c2d1e0f";
        let literal = format!("x'{key}{salt}'");
        let parsed = parse_key_literal(literal.as_bytes(), WechatKeyEncoding::Ascii).unwrap();
        assert_eq!(parsed.key_hex, key);
        assert_eq!(parsed.salt_hex.as_deref(), Some(salt));
        assert_eq!(parsed.literal_hex_length, 96);
        assert!(parsed.key_entropy >= 4.9);
    }

    #[test]
    fn parses_utf16le_key_literal() {
        let literal = format!("X'{}'", random_key_hex());
        let utf16 = literal
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let parsed = parse_key_literal(&utf16, WechatKeyEncoding::Utf16Le).unwrap();
        assert_eq!(parsed.key_hex, random_key_hex());
        assert!(parsed.salt_hex.is_none());
    }

    #[test]
    fn rejects_repetitive_hex_blobs() {
        let literal = format!("x'{}'", "00".repeat(32));
        assert!(parse_key_literal(literal.as_bytes(), WechatKeyEncoding::Ascii).is_none());
    }

    #[test]
    fn recognizes_repeated_raw_heap_key_shape() {
        let key = hex::decode(random_key_hex()).unwrap();
        let mut page = vec![0u8; 0x1000];
        let offset = 0x120;
        page[offset - 4] = 0;
        page[offset - 3] = 7;
        page[offset - 2] = 0;
        page[offset - 1] = 0x90;
        page[offset..offset + 32].copy_from_slice(&key);
        page[offset + 32] = 0;
        let candidates = raw_heap_key_candidates(&page, 0x2000);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].physical_address, 0x2120);
        assert_eq!(candidates[0].key_hex, random_key_hex());
    }

    #[test]
    fn validates_sqlcipher4_raw_key_page_with_eighty_reserved_bytes() {
        let key = <[u8; 32]>::try_from(hex::decode(random_key_hex()).unwrap()).unwrap();
        let reserve_size = 80usize;
        let content_size = 4096 - reserve_size;
        let mut page = [0u8; 4096];
        page[..16].copy_from_slice(&[0x5a; 16]);
        let mut plaintext = vec![0u8; content_size - 16];
        plaintext[..2].copy_from_slice(&4096u16.to_be_bytes());
        plaintext[2] = 2;
        plaintext[3] = 2;
        plaintext[4] = reserve_size as u8;
        plaintext[5..8].copy_from_slice(&[64, 32, 32]);
        plaintext[12..16].copy_from_slice(&7u32.to_be_bytes());
        plaintext[28..32].copy_from_slice(&4u32.to_be_bytes());
        plaintext[40..44].copy_from_slice(&1u32.to_be_bytes());
        let iv = [0x33u8; 16];
        page[content_size..content_size + 16].copy_from_slice(&iv);
        let cipher = Aes256::new_from_slice(&key).unwrap();
        let mut previous = iv;
        for (index, plain_block) in plaintext.chunks_exact(16).enumerate() {
            let mut raw = [0u8; 16];
            for position in 0..16 {
                raw[position] = plain_block[position] ^ previous[position];
            }
            let mut block = GenericArray::clone_from_slice(&raw);
            cipher.encrypt_block(&mut block);
            let output_start = 16 + index * 16;
            page[output_start..output_start + 16].copy_from_slice(&block);
            previous.copy_from_slice(&block);
        }
        let validation = validate_sqlcipher_first_page(&page, &key).unwrap();
        assert_eq!(validation.page_size, 4096);
        assert_eq!(validation.reserve_size, 80);
        assert_eq!(validation.schema_format, 4);
        assert_eq!(validation.text_encoding, 1);
    }

    #[test]
    fn recognizes_main_and_helper_process_context() {
        let mut process = ProcessRecord {
            eprocess: 0,
            pid: 1,
            ppid: None,
            name: "Weixin.exe".to_owned(),
            details: Default::default(),
        };
        assert_eq!(
            classify_wechat_process(&process),
            Some(WechatProcessRole::Main)
        );
        process.details.command_line = Some("Weixin.exe --type=wxutility".to_owned());
        assert_eq!(
            classify_wechat_process(&process),
            Some(WechatProcessRole::Helper)
        );
        process.name = "WeChatAppEx.ex".to_owned();
        assert_eq!(
            classify_wechat_process(&process),
            Some(WechatProcessRole::MiniProgram)
        );
    }
}
