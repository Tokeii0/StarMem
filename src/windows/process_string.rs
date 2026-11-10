//! Fast literal-string ownership lookup for Windows process address spaces.
//!
//! The expensive operation is deliberately a single physical scan for all
//! requested encodings.  Candidate physical pages are then reverse-mapped in
//! batches through each distinct process page-table root.  Every association
//! is finally re-read through that process virtual address so a physically
//! contiguous hit cannot be misattributed across a non-contiguous virtual page
//! boundary.

use std::collections::{BTreeMap, HashSet};
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::{
    ProcessListStopReason, ProcessRecord, WindowsArchitecture, WindowsKernelContext, list_processes,
};
use crate::address::{
    DEFAULT_REVERSE_TRANSLATION_ENTRY_LIMIT, VirtualAddressRegion, X64AddressSpace,
};
use crate::cancellation::CancellationToken;
use crate::evidence::{
    EvidenceLimit, EvidenceLimitKind, EvidenceScope, EvidenceWarning, EvidenceWarningSeverity,
    MissingRange,
};
use crate::image::{MemoryImage, SourceLocation};
use crate::profile::KernelProfile;
use crate::scan::scan_patterns_cancellable;

const MAX_QUERY_BYTES: usize = 1024 * 1024;
const MAX_CONTEXT_BYTES: usize = 4096;
pub const DEFAULT_PROCESS_STRING_REVERSE_ENTRY_LIMIT: usize = 8 * 1024 * 1024;
pub const MAX_PROCESS_STRING_REVERSE_ENTRY_LIMIT: usize = 64 * 1024 * 1024;
pub const DEFAULT_PROCESS_STRING_REVERSE_ALIAS_LIMIT: usize = 1_000_000;
pub const MAX_PROCESS_STRING_REVERSE_ALIAS_LIMIT: usize = 8_000_000;
pub const PROCESS_STRING_WARNING_LIMIT: usize = 128;
const MAX_VIRTUAL_REVALIDATION_MISSING_RANGES: usize = 4096;
const MAX_VIRTUAL_REVALIDATION_ERROR_EXAMPLES: usize = 16;
const MAX_PAGE_TABLE_MISSING_RANGES: usize = 4096;

/// Encodings to generate for the literal query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStringEncodingSelection {
    /// UTF-8 (which is byte-identical to ASCII for ASCII input) and UTF-16LE.
    Both,
    Utf8,
    Utf16Le,
}

#[derive(Debug, Clone)]
pub struct ProcessStringOptions {
    pub query: String,
    pub encoding: ProcessStringEncodingSelection,
    /// Maximum physical hits retained per encoding by the one-pass scanner.
    pub scan_hit_limit: usize,
    /// Maximum process-owned records returned.
    pub limit: usize,
    pub process_limit: usize,
    /// Maximum virtual aliases retained for a physical page in one DTB.
    pub mapping_limit: usize,
    /// Maximum page-table entries inspected across all distinct process DTBs.
    pub reverse_entry_limit: usize,
    /// Maximum reverse-mapped aliases retained cumulatively across process DTBs.
    pub reverse_alias_limit: usize,
    pub chunk_size: usize,
    /// Context bytes requested on each side of the match.
    pub context_bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct ProcessStringReport {
    pub available: bool,
    pub complete: bool,
    pub scope: EvidenceScope,
    pub query: String,
    pub encodings: Vec<String>,
    pub records: Vec<ProcessStringRecord>,
    /// Raw `(encoding, physical address)` occurrences retained by the scanner.
    pub physical_hits: usize,
    /// Distinct raw occurrences with at least one verified process owner. Shared
    /// DTBs and multiple owners do not increase this counter; they do increase
    /// `records` because each process attribution remains independently useful.
    pub mapped_physical_hits: usize,
    /// `null` whenever output truncation or an incomplete process/page-table
    /// universe prevented classification of every retained physical hit.
    pub unmapped_physical_hits: Option<usize>,
    /// True when `mapped_physical_hits` is only the number proven before an
    /// incomplete ownership search or output truncation stopped classification.
    pub mapped_physical_hits_is_lower_bound: bool,
    pub processes_enumerated: usize,
    pub process_address_spaces: usize,
    pub process_address_spaces_walked: usize,
    /// Successful PML4/PDPT/PD/PT read operations across distinct process DTBs.
    pub reverse_page_table_pages_read: u64,
    /// Failed non-root page-table read operations. Any non-zero value makes the
    /// process ownership search incomplete while preserving positive hits from
    /// readable subtrees.
    pub reverse_page_table_read_failures: u64,
    pub reverse_read_failure_details_truncated: bool,
    pub reverse_page_table_entries_examined: u64,
    pub reverse_traversal_limit_reached_address_spaces: usize,
    pub reverse_command_entry_limit_reached: bool,
    pub reverse_command_address_spaces_skipped: usize,
    pub reverse_aliases_retained: usize,
    pub reverse_alias_limit_reached: bool,
    pub reverse_alias_address_spaces_skipped: usize,
    pub mapping_failures: usize,
    /// Physical-page/address-space combinations whose distinct aliases truly
    /// exceeded `mapping_limit` (equality alone is not an overflow).
    pub mapping_limit_exceeded_address_space_pages: usize,
    pub mapping_limit_exceeded_details_truncated: bool,
    pub virtual_revalidation_mismatches: u64,
    pub virtual_revalidation_read_failures: u64,
    pub virtual_revalidation_missing_ranges_truncated: bool,
    pub page_table_missing_ranges_truncated: bool,
    pub bytes_scanned: u64,
    pub physical_scan_seconds: f64,
    pub owner_mapping_seconds: f64,
    pub elapsed_seconds: f64,
    pub gib_per_second: f64,
    pub truncated: bool,
    pub warnings_truncated: bool,
    pub warnings: Vec<EvidenceWarning>,
    pub limits: Vec<EvidenceLimit>,
    pub missing_ranges: Vec<MissingRange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessStringRecord {
    pub pid: u64,
    pub process: String,
    pub eprocess: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    /// Exact source-file offset for Direct mappings; decoded/synthetic mappings use `null`.
    pub file_offset: Option<u64>,
    /// Unambiguous provenance for Direct, decoded, repeated-byte and sidecar mappings.
    pub source_location: Option<SourceLocation>,
    pub encoding: String,
    pub match_length: usize,
    pub context: String,
    pub context_complete: bool,
}

#[derive(Debug)]
struct PatternSpec {
    encoding: &'static str,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ProcessOwner {
    pid: u64,
    process: String,
    eprocess: u64,
}

/// Locates an exact literal string in active Windows process address spaces.
pub fn locate_process_string(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &ProcessStringOptions,
) -> Result<ProcessStringReport> {
    locate_process_string_cancellable(image, kernel, profile, options, &CancellationToken::new())
}

/// Cancellable variant of [`locate_process_string`]. Cancellation is
/// cooperative: it is observed at physical-scan chunk boundaries and between
/// process-address-space, hit, virtual-alias, and owner attribution work.
/// A single in-flight page-table traversal must finish before its following
/// boundary check can return cancellation.
pub fn locate_process_string_cancellable(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &ProcessStringOptions,
    cancellation: &CancellationToken,
) -> Result<ProcessStringReport> {
    cancellation.check_cancelled()?;
    validate_options(options)?;
    let started = Instant::now();
    let patterns = build_patterns(&options.query, options.encoding);
    let encoding_names = patterns
        .iter()
        .map(|pattern| pattern.encoding.to_owned())
        .collect::<Vec<_>>();
    let scope = process_string_scope(&encoding_names);
    let mut missing_ranges = physical_missing_ranges(image);
    let physical_missing_range_count = missing_ranges.len();
    cancellation.check_cancelled()?;

    if kernel.architecture != WindowsArchitecture::X86_64 {
        let warnings = vec![EvidenceWarning::new(
            "platform.unsupported_architecture",
            EvidenceWarningSeverity::Warning,
            "windows.process-string 首版只支持 x86_64 Windows 进程页表",
            "windows.process-string",
        )];
        return Ok(ProcessStringReport {
            available: false,
            complete: false,
            scope,
            query: options.query.clone(),
            encodings: encoding_names,
            records: Vec::new(),
            physical_hits: 0,
            mapped_physical_hits: 0,
            unmapped_physical_hits: None,
            mapped_physical_hits_is_lower_bound: false,
            processes_enumerated: 0,
            process_address_spaces: 0,
            process_address_spaces_walked: 0,
            reverse_page_table_pages_read: 0,
            reverse_page_table_read_failures: 0,
            reverse_read_failure_details_truncated: false,
            reverse_page_table_entries_examined: 0,
            reverse_traversal_limit_reached_address_spaces: 0,
            reverse_command_entry_limit_reached: false,
            reverse_command_address_spaces_skipped: 0,
            reverse_aliases_retained: 0,
            reverse_alias_limit_reached: false,
            reverse_alias_address_spaces_skipped: 0,
            mapping_failures: 0,
            mapping_limit_exceeded_address_space_pages: 0,
            mapping_limit_exceeded_details_truncated: false,
            virtual_revalidation_mismatches: 0,
            virtual_revalidation_read_failures: 0,
            virtual_revalidation_missing_ranges_truncated: false,
            page_table_missing_ranges_truncated: false,
            bytes_scanned: 0,
            physical_scan_seconds: 0.0,
            owner_mapping_seconds: 0.0,
            elapsed_seconds: started.elapsed().as_secs_f64(),
            gib_per_second: 0.0,
            truncated: false,
            warnings_truncated: false,
            warnings,
            limits: evidence_limits(
                options, 0, 0, 0, false, false, false, false, 0, 0, 0, false, 0, false, 0, false,
                0, false, 1, false,
            ),
            missing_ranges,
        });
    }

    let pattern_refs = patterns
        .iter()
        .map(|pattern| pattern.bytes.as_slice())
        .collect::<Vec<_>>();
    let scan = scan_patterns_cancellable(
        image,
        &pattern_refs,
        options.scan_hit_limit,
        options.chunk_size,
        cancellation,
    )?;
    cancellation.check_cancelled()?;
    let physical_hits = scan.hits.len();
    let target_pages = scan
        .hits
        .iter()
        .map(|hit| hit.physical_address & !0xfff)
        .collect::<HashSet<_>>();

    let owner_mapping_started = Instant::now();
    let processes = list_processes(image, kernel, profile, options.process_limit)?;
    cancellation.check_cancelled()?;
    let process_limit_reached = matches!(processes.stop_reason, ProcessListStopReason::Limit);
    let processes_enumerated = processes.processes.len();
    let mut warnings = processes
        .warnings
        .iter()
        .map(|warning| {
            let mut normalized = EvidenceWarning::new(
                format!("process_list.{}", warning.kind.replace('_', "-")),
                EvidenceWarningSeverity::Warning,
                warning.message.clone(),
                "windows.process-string",
            );
            if let Some(list_entry) = warning.list_entry {
                normalized.context.insert(
                    "list_entry".to_owned(),
                    serde_json::Value::String(format!("{list_entry:#018x}")),
                );
            }
            normalized
        })
        .collect::<Vec<_>>();
    let mut warnings_truncated = warnings.len() > PROCESS_STRING_WARNING_LIMIT;
    warnings.truncate(PROCESS_STRING_WARNING_LIMIT);

    let mut grouped = BTreeMap::<u64, Vec<ProcessOwner>>::new();
    let mut processes_without_address_space = 0usize;
    for process in &processes.processes {
        cancellation.check_cancelled()?;
        let Some(dtb) = process_directory_table_base(process) else {
            processes_without_address_space += 1;
            continue;
        };
        grouped.entry(dtb).or_default().push(ProcessOwner {
            pid: process.pid,
            process: process.name.clone(),
            eprocess: process.eprocess,
        });
    }
    if processes_without_address_space > 0 {
        push_warning(
            &mut warnings,
            &mut warnings_truncated,
            EvidenceWarning::new(
                "mapping.process-address-space-unavailable",
                EvidenceWarningSeverity::Warning,
                format!(
                    "{processes_without_address_space} 个活动进程没有可恢复的用户页表根，无法检查其字符串归属"
                ),
                "windows.process-string",
            ),
        );
    }

    let process_address_spaces = grouped.len();
    let mut process_address_spaces_walked = 0usize;
    let mut mapping_failures = 0usize;
    let mut mapping_limit_reached = false;
    let mut max_mappings_observed_lower_bound = 0usize;
    let mut reverse_page_table_pages_read = 0u64;
    let mut reverse_page_table_read_failures = 0u64;
    let mut reverse_read_failure_details_truncated = false;
    let mut reverse_page_table_entries_examined = 0u64;
    let mut max_reverse_page_table_entries_examined = 0u64;
    let mut reverse_traversal_limit_reached_address_spaces = 0usize;
    let mut reverse_command_entry_limit_reached = false;
    let mut reverse_command_address_spaces_skipped = 0usize;
    let mut reverse_entry_budget_remaining = options.reverse_entry_limit;
    let mut reverse_alias_budget_remaining = options.reverse_alias_limit;
    let mut reverse_aliases_retained = 0usize;
    let mut reverse_alias_limit_reached = false;
    let mut reverse_alias_address_spaces_skipped = 0usize;
    let mut mapping_limit_exceeded_address_space_pages = 0usize;
    let mut mapping_limit_exceeded_details_truncated = false;
    let mut records = Vec::new();
    let mut seen_records = HashSet::new();
    let mut mapped_hits = HashSet::new();
    let mut output_truncated = false;
    let mut virtual_revalidation_mismatches = 0u64;
    let mut virtual_revalidation_read_failures = 0u64;
    let mut virtual_revalidation_missing_ranges_truncated = false;
    let mut virtual_revalidation_missing_ranges = HashSet::new();
    let mut virtual_revalidation_error_examples = Vec::new();
    let mut page_table_missing_ranges_truncated = false;
    let mut page_table_missing_ranges = HashSet::new();
    'address_spaces: for (address_space_index, (dtb, owners)) in grouped.into_iter().enumerate() {
        cancellation.check_cancelled()?;
        if reverse_entry_budget_remaining == 0 {
            reverse_command_entry_limit_reached = true;
            reverse_command_address_spaces_skipped =
                process_address_spaces.saturating_sub(address_space_index);
            break;
        }
        if reverse_alias_budget_remaining == 0 {
            reverse_alias_limit_reached = true;
            reverse_alias_address_spaces_skipped =
                process_address_spaces.saturating_sub(address_space_index);
            break;
        }
        let address_space_entry_limit =
            DEFAULT_REVERSE_TRANSLATION_ENTRY_LIMIT.min(reverse_entry_budget_remaining);
        let address_space_uses_all_remaining_budget =
            address_space_entry_limit == reverse_entry_budget_remaining;
        process_address_spaces_walked = process_address_spaces_walked.saturating_add(1);
        let result = X64AddressSpace::new(image, dtb).and_then(|space| {
            let reverse = space.reverse_translate_pages_detailed_with_limits(
                &target_pages,
                VirtualAddressRegion::User,
                options.mapping_limit,
                address_space_entry_limit,
                reverse_alias_budget_remaining,
            )?;
            Ok((space, reverse))
        });
        // Reverse translation is currently one bounded cooperative work unit.
        // Observe cancellation before interpreting a completed walk (including
        // a read failure) so cancellation is never downgraded into a warning.
        cancellation.check_cancelled()?;
        match result {
            Ok((space, reverse)) => {
                reverse_page_table_pages_read =
                    reverse_page_table_pages_read.saturating_add(reverse.page_table_pages_read);
                reverse_page_table_read_failures = reverse_page_table_read_failures
                    .saturating_add(reverse.page_table_read_failures);
                reverse_read_failure_details_truncated |= reverse.read_failure_details_truncated;
                reverse_page_table_entries_examined = reverse_page_table_entries_examined
                    .saturating_add(reverse.page_table_entries_examined);
                max_reverse_page_table_entries_examined = max_reverse_page_table_entries_examined
                    .max(reverse.page_table_entries_examined);
                reverse_entry_budget_remaining = reverse_entry_budget_remaining.saturating_sub(
                    usize::try_from(reverse.page_table_entries_examined).unwrap_or(usize::MAX),
                );
                reverse_aliases_retained =
                    reverse_aliases_retained.saturating_add(reverse.alias_storage_entries_retained);
                reverse_alias_budget_remaining = reverse_alias_budget_remaining
                    .saturating_sub(reverse.alias_storage_entries_retained);
                reverse_alias_limit_reached |= reverse.alias_storage_limit_exceeded;
                max_mappings_observed_lower_bound = max_mappings_observed_lower_bound
                    .max(reverse.max_mappings_observed_lower_bound);
                mapping_limit_reached |= reverse.mapping_limit_exceeded;
                mapping_limit_exceeded_address_space_pages =
                    mapping_limit_exceeded_address_space_pages
                        .saturating_add(reverse.mapping_limit_exceeded_pages.len());
                mapping_limit_exceeded_details_truncated |=
                    reverse.mapping_limit_exceeded_pages_truncated;
                if reverse.page_table_read_failures > 0 {
                    for failure in &reverse.read_failures {
                        cancellation.check_cancelled()?;
                        let key = (failure.table_physical_address, failure.level.clone());
                        if page_table_missing_ranges.contains(&key) {
                            continue;
                        }
                        if page_table_missing_ranges.len() >= MAX_PAGE_TABLE_MISSING_RANGES {
                            page_table_missing_ranges_truncated = true;
                            break;
                        }
                        page_table_missing_ranges.insert(key);
                        missing_ranges.push(MissingRange {
                            address_space: "physical".to_owned(),
                            start: failure.table_physical_address,
                            length: 0x1000,
                            source: format!("windows.process-string.page-table.{}", failure.level),
                        });
                    }
                    page_table_missing_ranges_truncated |= reverse.read_failure_details_truncated;
                    let mut warning = EvidenceWarning::new(
                        "mapping.page-table-read-failed",
                        EvidenceWarningSeverity::Warning,
                        format!(
                            "反向遍历进程 DTB {dtb:#018x} 时发生 {} 次页表读取失败，阴性归属结论不完整",
                            reverse.page_table_read_failures
                        ),
                        "windows.process-string",
                    );
                    warning.context.insert(
                        "directory_table_base".to_owned(),
                        serde_json::Value::String(format!("{dtb:#018x}")),
                    );
                    warning.context.insert(
                        "failure_count".to_owned(),
                        serde_json::Value::from(reverse.page_table_read_failures),
                    );
                    warning.context.insert(
                        "details_truncated".to_owned(),
                        serde_json::Value::Bool(reverse.read_failure_details_truncated),
                    );
                    warning.context.insert(
                        "failures".to_owned(),
                        serde_json::to_value(&reverse.read_failures)
                            .unwrap_or(serde_json::Value::Null),
                    );
                    push_warning(&mut warnings, &mut warnings_truncated, warning);
                }
                if reverse.traversal_limit_reached {
                    reverse_traversal_limit_reached_address_spaces =
                        reverse_traversal_limit_reached_address_spaces.saturating_add(1);
                    let mut warning = EvidenceWarning::new(
                        "mapping.page-table-entry-limit-reached",
                        EvidenceWarningSeverity::Warning,
                        format!(
                            "反向遍历进程 DTB {dtb:#018x} 超过 {} 个页表 entry 上限，保留已验证的部分正向结果",
                            reverse.page_table_entry_limit
                        ),
                        "windows.process-string",
                    );
                    warning.context.insert(
                        "directory_table_base".to_owned(),
                        serde_json::Value::String(format!("{dtb:#018x}")),
                    );
                    warning.context.insert(
                        "entries_examined".to_owned(),
                        serde_json::Value::from(reverse.page_table_entries_examined),
                    );
                    warning.context.insert(
                        "configured".to_owned(),
                        serde_json::Value::from(reverse.page_table_entry_limit),
                    );
                    push_warning(&mut warnings, &mut warnings_truncated, warning);
                    if reverse_entry_budget_remaining == 0
                        && address_space_uses_all_remaining_budget
                    {
                        reverse_command_entry_limit_reached = true;
                    }
                }

                for hit in &scan.hits {
                    cancellation.check_cancelled()?;
                    let pattern = &patterns[hit.pattern_index];
                    let page = hit.physical_address & !0xfff;
                    let page_delta = hit.physical_address & 0xfff;
                    let Some(virtual_pages) = reverse.mappings.get(&page) else {
                        continue;
                    };
                    for virtual_page in virtual_pages {
                        cancellation.check_cancelled()?;
                        let Some(virtual_address) = virtual_page.checked_add(page_delta) else {
                            continue;
                        };
                        match virtual_bytes_equal(&space, virtual_address, &pattern.bytes) {
                            Ok(true) => {}
                            Ok(false) => {
                                virtual_revalidation_mismatches =
                                    virtual_revalidation_mismatches.saturating_add(1);
                                continue;
                            }
                            Err(error) => {
                                virtual_revalidation_read_failures =
                                    virtual_revalidation_read_failures.saturating_add(1);
                                if virtual_revalidation_error_examples.len()
                                    < MAX_VIRTUAL_REVALIDATION_ERROR_EXAMPLES
                                {
                                    virtual_revalidation_error_examples.push(format!(
                                        "DTB {dtb:#018x} VA {virtual_address:#018x}: {error:#}"
                                    ));
                                }
                                let length = u64::try_from(pattern.bytes.len()).unwrap_or(u64::MAX);
                                let key = (dtb, virtual_address, length);
                                if !virtual_revalidation_missing_ranges.contains(&key) {
                                    if virtual_revalidation_missing_ranges.len()
                                        < MAX_VIRTUAL_REVALIDATION_MISSING_RANGES
                                    {
                                        virtual_revalidation_missing_ranges.insert(key);
                                        missing_ranges.push(MissingRange {
                                            address_space: format!(
                                                "process_virtual_dtb_{dtb:#018x}"
                                            ),
                                            start: virtual_address,
                                            length,
                                            source: "windows.process-string.virtual-reread"
                                                .to_owned(),
                                        });
                                    } else {
                                        virtual_revalidation_missing_ranges_truncated = true;
                                    }
                                }
                                continue;
                            }
                        }
                        let (context, context_complete) = read_context(
                            &space,
                            virtual_address,
                            &pattern.bytes,
                            options.context_bytes,
                            pattern.encoding,
                        );
                        for owner in &owners {
                            cancellation.check_cancelled()?;
                            let record_key = (owner.eprocess, virtual_address, hit.pattern_index);
                            if seen_records.contains(&record_key) {
                                continue;
                            }
                            if records.len() >= options.limit {
                                output_truncated = true;
                                break 'address_spaces;
                            }
                            seen_records.insert(record_key);
                            mapped_hits.insert((hit.pattern_index, hit.physical_address));
                            records.push(ProcessStringRecord {
                                pid: owner.pid,
                                process: owner.process.clone(),
                                eprocess: owner.eprocess,
                                virtual_address,
                                physical_address: hit.physical_address,
                                file_offset: image.physical_to_file_offset(hit.physical_address),
                                source_location: image.source_location(hit.physical_address),
                                encoding: pattern.encoding.to_owned(),
                                match_length: pattern.bytes.len(),
                                context: context.clone(),
                                context_complete,
                            });
                        }
                    }
                }
                if reverse.alias_storage_limit_exceeded {
                    reverse_alias_address_spaces_skipped =
                        process_address_spaces.saturating_sub(address_space_index + 1);
                    break 'address_spaces;
                }
            }
            Err(error) => {
                mapping_failures += 1;
                let key = (dtb, "pml4".to_owned());
                if !page_table_missing_ranges.contains(&key) {
                    if page_table_missing_ranges.len() < MAX_PAGE_TABLE_MISSING_RANGES {
                        page_table_missing_ranges.insert(key);
                        missing_ranges.push(MissingRange {
                            address_space: "physical".to_owned(),
                            start: dtb,
                            length: 0x1000,
                            source: "windows.process-string.page-table.pml4".to_owned(),
                        });
                    } else {
                        page_table_missing_ranges_truncated = true;
                    }
                }
                push_warning(
                    &mut warnings,
                    &mut warnings_truncated,
                    EvidenceWarning::new(
                        "mapping.address-space-walk-failed",
                        EvidenceWarningSeverity::Warning,
                        format!("无法反向遍历进程 DTB {dtb:#018x}：{error:#}"),
                        "windows.process-string",
                    ),
                );
            }
        }
    }
    cancellation.check_cancelled()?;
    if mapping_limit_reached {
        let mut warning = EvidenceWarning::new(
            "mapping.alias-limit-reached",
            EvidenceWarningSeverity::Warning,
            format!(
                "有 {mapping_limit_exceeded_address_space_pages} 个物理页/地址空间组合的虚拟别名超过 {} 条上限",
                options.mapping_limit,
            ),
            "windows.process-string",
        );
        warning.context.insert(
            "observed_is_lower_bound".to_owned(),
            serde_json::Value::Bool(true),
        );
        warning.context.insert(
            "details_truncated".to_owned(),
            serde_json::Value::Bool(mapping_limit_exceeded_details_truncated),
        );
        push_warning(&mut warnings, &mut warnings_truncated, warning);
    }
    if reverse_command_entry_limit_reached {
        reverse_command_address_spaces_skipped = reverse_command_address_spaces_skipped
            .max(process_address_spaces.saturating_sub(process_address_spaces_walked));
        push_warning(
            &mut warnings,
            &mut warnings_truncated,
            EvidenceWarning::new(
                "mapping.command-entry-limit-reached",
                EvidenceWarningSeverity::Warning,
                format!(
                    "进程字符串反向页表遍历达到命令级 {} 个 entry 上限，跳过 {reverse_command_address_spaces_skipped} 个剩余地址空间",
                    options.reverse_entry_limit
                ),
                "windows.process-string",
            ),
        );
    }
    if reverse_alias_limit_reached {
        reverse_alias_address_spaces_skipped = reverse_alias_address_spaces_skipped
            .max(process_address_spaces.saturating_sub(process_address_spaces_walked));
        push_warning(
            &mut warnings,
            &mut warnings_truncated,
            EvidenceWarning::new(
                "mapping.command-alias-limit-reached",
                EvidenceWarningSeverity::Warning,
                format!(
                    "进程字符串反向映射达到命令级 {} 条 alias 存储上限，跳过 {} 个剩余地址空间",
                    options.reverse_alias_limit, reverse_alias_address_spaces_skipped
                ),
                "windows.process-string",
            ),
        );
    }
    cancellation.check_cancelled()?;
    records.sort_unstable_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| left.eprocess.cmp(&right.eprocess))
            .then_with(|| left.virtual_address.cmp(&right.virtual_address))
            .then_with(|| left.encoding.cmp(&right.encoding))
    });
    let mapped_physical_hits = mapped_hits.len();

    if scan.truncated {
        push_warning(
            &mut warnings,
            &mut warnings_truncated,
            EvidenceWarning::new(
                "scan.hit-limit-reached",
                EvidenceWarningSeverity::Warning,
                format!(
                    "物理字符串命中达到每种编码 {} 条上限，后续进程归属可能遗漏",
                    options.scan_hit_limit
                ),
                "windows.process-string",
            ),
        );
    }
    if output_truncated {
        push_warning(
            &mut warnings,
            &mut warnings_truncated,
            EvidenceWarning::new(
                "output.record-limit-reached",
                EvidenceWarningSeverity::Warning,
                format!("进程字符串结果达到 {} 条输出上限", options.limit),
                "windows.process-string",
            ),
        );
    }
    if virtual_revalidation_read_failures > 0 {
        let mut warning = EvidenceWarning::new(
            "mapping.virtual-revalidation-read-failed",
            EvidenceWarningSeverity::Warning,
            format!(
                "反向映射候选发生 {virtual_revalidation_read_failures} 次虚拟地址复读失败；这些候选不能判定为不匹配"
            ),
            "windows.process-string",
        );
        warning.context.insert(
            "examples".to_owned(),
            serde_json::Value::Array(
                virtual_revalidation_error_examples
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        warning.context.insert(
            "missing_range_details_truncated".to_owned(),
            serde_json::Value::Bool(virtual_revalidation_missing_ranges_truncated),
        );
        push_warning(&mut warnings, &mut warnings_truncated, warning);
    }
    if page_table_missing_ranges_truncated {
        push_warning(
            &mut warnings,
            &mut warnings_truncated,
            EvidenceWarning::new(
                "mapping.page-table-missing-ranges-truncated",
                EvidenceWarningSeverity::Warning,
                format!(
                    "页表缺失区间明细超过 {MAX_PAGE_TABLE_MISSING_RANGES} 条或页表失败详情未全部保留"
                ),
                "windows.process-string",
            ),
        );
    }
    if physical_missing_range_count > 0 {
        push_warning(
            &mut warnings,
            &mut warnings_truncated,
            EvidenceWarning::new(
                "source.missing-physical-ranges",
                EvidenceWarningSeverity::Warning,
                format!(
                    "镜像包含 {} 个缺失物理区间，阴性结果不能覆盖这些范围",
                    physical_missing_range_count
                ),
                "windows.process-string",
            ),
        );
    }

    let owner_mapping_seconds = owner_mapping_started.elapsed().as_secs_f64();
    let elapsed_seconds = started.elapsed().as_secs_f64();
    let complete = processes.complete
        && !scan.truncated
        && !output_truncated
        && !warnings_truncated
        && !mapping_limit_reached
        && mapping_failures == 0
        && reverse_page_table_read_failures == 0
        && reverse_traversal_limit_reached_address_spaces == 0
        && !reverse_command_entry_limit_reached
        && !reverse_alias_limit_reached
        && virtual_revalidation_read_failures == 0
        && processes_without_address_space == 0
        && missing_ranges.is_empty();
    let truncated = scan.truncated
        || output_truncated
        || process_limit_reached
        || warnings_truncated
        || mapping_limit_reached
        || reverse_traversal_limit_reached_address_spaces > 0
        || reverse_command_entry_limit_reached
        || reverse_alias_limit_reached
        || virtual_revalidation_missing_ranges_truncated;
    let ownership_classification_complete = !output_truncated
        && processes.complete
        && !mapping_limit_reached
        && mapping_failures == 0
        && reverse_page_table_read_failures == 0
        && reverse_traversal_limit_reached_address_spaces == 0
        && !reverse_command_entry_limit_reached
        && !reverse_alias_limit_reached
        && virtual_revalidation_read_failures == 0
        && processes_without_address_space == 0;
    let mapped_physical_hits_is_lower_bound = !ownership_classification_complete;
    let unmapped_physical_hits = ownership_classification_complete
        .then_some(physical_hits.saturating_sub(mapped_physical_hits));
    let limits = evidence_limits(
        options,
        records.len(),
        processes_enumerated,
        max_mappings_observed_lower_bound,
        scan.truncated,
        output_truncated,
        process_limit_reached,
        mapping_limit_reached,
        max_reverse_page_table_entries_examined,
        reverse_traversal_limit_reached_address_spaces,
        reverse_page_table_entries_examined,
        reverse_command_entry_limit_reached,
        reverse_aliases_retained,
        reverse_alias_limit_reached,
        virtual_revalidation_missing_ranges.len(),
        virtual_revalidation_missing_ranges_truncated,
        page_table_missing_ranges.len(),
        page_table_missing_ranges_truncated,
        warnings.len(),
        warnings_truncated,
    );
    cancellation.check_cancelled()?;

    Ok(ProcessStringReport {
        available: true,
        complete,
        scope,
        query: options.query.clone(),
        encodings: encoding_names,
        records,
        physical_hits,
        mapped_physical_hits,
        unmapped_physical_hits,
        mapped_physical_hits_is_lower_bound,
        processes_enumerated,
        process_address_spaces,
        process_address_spaces_walked,
        reverse_page_table_pages_read,
        reverse_page_table_read_failures,
        reverse_read_failure_details_truncated,
        reverse_page_table_entries_examined,
        reverse_traversal_limit_reached_address_spaces,
        reverse_command_entry_limit_reached,
        reverse_command_address_spaces_skipped,
        reverse_aliases_retained,
        reverse_alias_limit_reached,
        reverse_alias_address_spaces_skipped,
        mapping_failures,
        mapping_limit_exceeded_address_space_pages,
        mapping_limit_exceeded_details_truncated,
        virtual_revalidation_mismatches,
        virtual_revalidation_read_failures,
        virtual_revalidation_missing_ranges_truncated,
        page_table_missing_ranges_truncated,
        bytes_scanned: scan.bytes_scanned,
        physical_scan_seconds: scan.elapsed_seconds,
        owner_mapping_seconds,
        elapsed_seconds,
        gib_per_second: scan.gib_per_second,
        truncated,
        warnings_truncated,
        warnings,
        limits,
        missing_ranges,
    })
}

fn process_string_scope(encodings: &[String]) -> EvidenceScope {
    let mut scope = EvidenceScope::new("windows_active_process_acquired_resident_literal_hits");
    scope.description = Some(
        "Physically contiguous literal hits in acquired resident/transition pages, revalidated through active-process user virtual addresses"
            .to_owned(),
    );
    scope.constraints.insert(
        "encodings".to_owned(),
        serde_json::Value::Array(
            encodings
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    scope.constraints.insert(
        "physical_scan".to_owned(),
        serde_json::Value::String("single_pass_contiguous_acquired_ranges".to_owned()),
    );
    scope.constraints.insert(
        "process_universe".to_owned(),
        serde_json::Value::String("ps_active_process_head".to_owned()),
    );
    scope.constraints.insert(
        "virtual_region".to_owned(),
        serde_json::Value::String("user".to_owned()),
    );
    for (name, covered) in [
        ("resident_pages", true),
        ("transition_pages", true),
        ("prototype_pages", false),
        ("swapped_pages", false),
        ("compressed_store_pages", false),
        ("cross_noncontiguous_virtual_page_matches", false),
    ] {
        scope
            .constraints
            .insert(name.to_owned(), serde_json::Value::Bool(covered));
    }
    scope.constraints.insert(
        "ownership_validation".to_owned(),
        serde_json::Value::String("user_virtual_reread".to_owned()),
    );
    scope
}

fn validate_options(options: &ProcessStringOptions) -> Result<()> {
    ensure!(!options.query.is_empty(), "要定位的字符串不能为空");
    ensure!(
        options.query.len() <= MAX_QUERY_BYTES,
        "UTF-8 查询字符串不能超过 {MAX_QUERY_BYTES} 字节"
    );
    ensure!(options.scan_hit_limit > 0, "物理命中上限必须大于零");
    ensure!(options.limit > 0, "输出结果上限必须大于零");
    ensure!(options.process_limit > 0, "进程枚举上限必须大于零");
    ensure!(options.mapping_limit > 0, "页映射别名上限必须大于零");
    ensure!(
        options.reverse_entry_limit > 0,
        "反向页表 entry 上限必须大于零"
    );
    ensure!(
        options.reverse_entry_limit <= MAX_PROCESS_STRING_REVERSE_ENTRY_LIMIT,
        "反向页表 entry 上限不能超过 {MAX_PROCESS_STRING_REVERSE_ENTRY_LIMIT}"
    );
    ensure!(
        options.reverse_alias_limit > 0,
        "反向 alias 存储上限必须大于零"
    );
    ensure!(
        options.reverse_alias_limit <= MAX_PROCESS_STRING_REVERSE_ALIAS_LIMIT,
        "反向 alias 存储上限不能超过 {MAX_PROCESS_STRING_REVERSE_ALIAS_LIMIT}"
    );
    ensure!(
        options.context_bytes <= MAX_CONTEXT_BYTES,
        "单侧上下文字节数不能超过 {MAX_CONTEXT_BYTES}"
    );
    let longest = options
        .query
        .encode_utf16()
        .count()
        .checked_mul(2)
        .context("UTF-16LE 查询长度溢出")?
        .max(options.query.len());
    ensure!(
        options.chunk_size >= longest,
        "扫描块小于编码后的查询字符串"
    );
    Ok(())
}

fn build_patterns(query: &str, selection: ProcessStringEncodingSelection) -> Vec<PatternSpec> {
    let utf8_name = if query.is_ascii() { "ascii" } else { "utf8" };
    let utf8 = || PatternSpec {
        encoding: utf8_name,
        bytes: query.as_bytes().to_vec(),
    };
    let utf16 = || PatternSpec {
        encoding: "utf16le",
        bytes: query.encode_utf16().flat_map(u16::to_le_bytes).collect(),
    };
    match selection {
        ProcessStringEncodingSelection::Both => vec![utf8(), utf16()],
        ProcessStringEncodingSelection::Utf8 => vec![utf8()],
        ProcessStringEncodingSelection::Utf16Le => vec![utf16()],
    }
}

fn process_directory_table_base(process: &ProcessRecord) -> Option<u64> {
    process
        .details
        .user_directory_table_base
        .or(process.details.directory_table_base)
        .map(|dtb| dtb & 0x000f_ffff_ffff_f000)
        .filter(|dtb| *dtb != 0)
}

fn virtual_bytes_equal(space: &X64AddressSpace<'_>, address: u64, expected: &[u8]) -> Result<bool> {
    let mut actual = vec![0u8; expected.len()];
    space.read_virtual(address, &mut actual).with_context(|| {
        format!(
            "无法复读进程虚拟地址 {address:#018x} 的 {} 个匹配字节",
            expected.len()
        )
    })?;
    Ok(actual == expected)
}

fn read_context(
    space: &X64AddressSpace<'_>,
    virtual_address: u64,
    matched: &[u8],
    requested_each_side: usize,
    encoding: &str,
) -> (String, bool) {
    let unit = if encoding == "utf16le" { 2 } else { 1 };
    let desired_before =
        requested_each_side.min(usize::try_from(virtual_address).unwrap_or(usize::MAX)) / unit
            * unit;
    let desired_after = requested_each_side / unit * unit;
    let (prefix, prefix_complete) =
        read_context_side_before(space, virtual_address, desired_before, unit);
    let after_address = virtual_address.saturating_add(matched.len() as u64);
    let (suffix, suffix_complete) =
        read_context_side_after(space, after_address, desired_after, unit);
    let context = format!(
        "{}⟦{}⟧{}",
        decode_context_bytes(&prefix, encoding),
        decode_context_bytes(matched, encoding),
        decode_context_bytes(&suffix, encoding)
    );
    (context, prefix_complete && suffix_complete)
}

fn read_context_side_before(
    space: &X64AddressSpace<'_>,
    address: u64,
    desired: usize,
    unit: usize,
) -> (Vec<u8>, bool) {
    if desired == 0 {
        return (Vec::new(), true);
    }
    let start = address - desired as u64;
    let mut bytes = vec![0u8; desired];
    if space.read_virtual(start, &mut bytes).is_ok() {
        return (bytes, true);
    }
    let same_page = desired.min((address & 0xfff) as usize) / unit * unit;
    let mut bytes = vec![0u8; same_page];
    if same_page > 0
        && space
            .read_virtual(address - same_page as u64, &mut bytes)
            .is_err()
    {
        bytes.clear();
    }
    (bytes, false)
}

fn read_context_side_after(
    space: &X64AddressSpace<'_>,
    address: u64,
    desired: usize,
    unit: usize,
) -> (Vec<u8>, bool) {
    if desired == 0 {
        return (Vec::new(), true);
    }
    let mut bytes = vec![0u8; desired];
    if space.read_virtual(address, &mut bytes).is_ok() {
        return (bytes, true);
    }
    let page_remaining = 0x1000usize.saturating_sub((address & 0xfff) as usize);
    let same_page = desired.min(page_remaining) / unit * unit;
    let mut bytes = vec![0u8; same_page];
    if same_page > 0 && space.read_virtual(address, &mut bytes).is_err() {
        bytes.clear();
    }
    (bytes, false)
}

fn decode_context_bytes(bytes: &[u8], encoding: &str) -> String {
    if encoding != "utf16le" {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let words = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&words)
}

fn physical_missing_ranges(image: &MemoryImage) -> Vec<MissingRange> {
    image
        .missing_ranges()
        .iter()
        .map(|range| MissingRange {
            address_space: "physical".to_owned(),
            start: range.start,
            length: range.length,
            source: range.source.clone(),
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn evidence_limits(
    options: &ProcessStringOptions,
    record_count: usize,
    process_count: usize,
    max_mappings_observed_lower_bound: usize,
    scan_limit_reached: bool,
    output_limit_reached: bool,
    process_limit_reached: bool,
    mapping_limit_reached: bool,
    max_reverse_page_table_entries_examined: u64,
    reverse_traversal_limit_reached_address_spaces: usize,
    reverse_page_table_entries_examined: u64,
    reverse_command_entry_limit_reached: bool,
    reverse_aliases_retained: usize,
    reverse_alias_limit_reached: bool,
    virtual_revalidation_missing_range_count: usize,
    virtual_revalidation_missing_ranges_truncated: bool,
    page_table_missing_range_count: usize,
    page_table_missing_ranges_truncated: bool,
    warning_count: usize,
    warnings_truncated: bool,
) -> Vec<EvidenceLimit> {
    vec![
        EvidenceLimit {
            name: "limit".to_owned(),
            kind: EvidenceLimitKind::Output,
            configured: u64::try_from(options.limit).ok(),
            observed: u64::try_from(record_count).ok(),
            reached: Some(output_limit_reached),
        },
        EvidenceLimit {
            name: "scan_hit_limit".to_owned(),
            kind: EvidenceLimitKind::SourceScan,
            configured: u64::try_from(options.scan_hit_limit).ok(),
            observed: None,
            reached: Some(scan_limit_reached),
        },
        EvidenceLimit {
            name: "process_limit".to_owned(),
            kind: EvidenceLimitKind::SourceScan,
            configured: u64::try_from(options.process_limit).ok(),
            observed: u64::try_from(process_count).ok(),
            reached: Some(process_limit_reached),
        },
        EvidenceLimit {
            name: "mapping_limit".to_owned(),
            kind: EvidenceLimitKind::SourceScan,
            configured: u64::try_from(options.mapping_limit).ok(),
            observed: u64::try_from(max_mappings_observed_lower_bound).ok(),
            reached: Some(mapping_limit_reached),
        },
        EvidenceLimit {
            name: "reverse_entry_limit_per_address_space".to_owned(),
            kind: EvidenceLimitKind::SourceScan,
            configured: u64::try_from(DEFAULT_REVERSE_TRANSLATION_ENTRY_LIMIT).ok(),
            observed: Some(max_reverse_page_table_entries_examined),
            reached: Some(reverse_traversal_limit_reached_address_spaces > 0),
        },
        EvidenceLimit {
            name: "reverse_entry_limit_per_command".to_owned(),
            kind: EvidenceLimitKind::SourceScan,
            configured: u64::try_from(options.reverse_entry_limit).ok(),
            observed: Some(reverse_page_table_entries_examined),
            reached: Some(reverse_command_entry_limit_reached),
        },
        EvidenceLimit {
            name: "reverse_alias_limit_per_command".to_owned(),
            kind: EvidenceLimitKind::SourceScan,
            configured: u64::try_from(options.reverse_alias_limit).ok(),
            observed: u64::try_from(reverse_aliases_retained).ok(),
            reached: Some(reverse_alias_limit_reached),
        },
        EvidenceLimit {
            name: "virtual_revalidation_missing_range_limit".to_owned(),
            kind: EvidenceLimitKind::Output,
            configured: u64::try_from(MAX_VIRTUAL_REVALIDATION_MISSING_RANGES).ok(),
            observed: u64::try_from(virtual_revalidation_missing_range_count).ok(),
            reached: Some(virtual_revalidation_missing_ranges_truncated),
        },
        EvidenceLimit {
            name: "page_table_missing_range_limit".to_owned(),
            kind: EvidenceLimitKind::Output,
            configured: u64::try_from(MAX_PAGE_TABLE_MISSING_RANGES).ok(),
            observed: u64::try_from(page_table_missing_range_count).ok(),
            reached: Some(page_table_missing_ranges_truncated),
        },
        EvidenceLimit {
            name: "warning_limit".to_owned(),
            kind: EvidenceLimitKind::Output,
            configured: u64::try_from(PROCESS_STRING_WARNING_LIMIT).ok(),
            observed: u64::try_from(warning_count).ok(),
            reached: Some(warnings_truncated),
        },
    ]
}

fn push_warning(
    warnings: &mut Vec<EvidenceWarning>,
    warnings_truncated: &mut bool,
    warning: EvidenceWarning,
) {
    if warnings.len() < PROCESS_STRING_WARNING_LIMIT {
        warnings.push(warning);
    } else {
        *warnings_truncated = true;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::cancellation::{CANCELLATION_ERROR_CODE, CancellationHandle, is_cancellation_error};
    use crate::windows::KernelDiscoveryMethod;

    #[test]
    fn builds_ascii_and_utf16le_patterns_in_one_query() {
        let patterns = build_patterns("StarMem", ProcessStringEncodingSelection::Both);
        assert_eq!(patterns.len(), 2);
        assert_eq!(patterns[0].encoding, "ascii");
        assert_eq!(patterns[0].bytes, b"StarMem");
        assert_eq!(patterns[1].encoding, "utf16le");
        assert_eq!(patterns[1].bytes, b"S\0t\0a\0r\0M\0e\0m\0".as_slice());
    }

    #[test]
    fn pre_cancelled_lookup_returns_stable_typed_error() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-cancelled-process-string-{}-{nonce}.raw",
            std::process::id()
        ));
        fs::write(&path, vec![0u8; 0x1000]).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let kernel = WindowsKernelContext {
            architecture: WindowsArchitecture::X86_64,
            directory_table_base: 0,
            kernel_base: 0,
            ps_active_process_head: 0,
            ps_loaded_module_list: 0,
            discovery_method: KernelDiscoveryMethod::LowStub,
        };
        let profile = KernelProfile {
            schema_version: 1,
            pdb_guid: "test".to_owned(),
            pdb_age: 1,
            type_name: "_EPROCESS".to_owned(),
            type_size: 0,
            fields: BTreeMap::new(),
            types: BTreeMap::new(),
            symbols: BTreeMap::new(),
        };
        let options = ProcessStringOptions {
            query: "StarMem".to_owned(),
            encoding: ProcessStringEncodingSelection::Both,
            scan_hit_limit: 8,
            limit: 8,
            process_limit: 8,
            mapping_limit: 8,
            reverse_entry_limit: DEFAULT_PROCESS_STRING_REVERSE_ENTRY_LIMIT,
            reverse_alias_limit: DEFAULT_PROCESS_STRING_REVERSE_ALIAS_LIMIT,
            chunk_size: 4096,
            context_bytes: 0,
        };
        let handle = CancellationHandle::new();
        let cancellation = handle.start();
        handle.cancel();

        let error =
            locate_process_string_cancellable(&image, &kernel, &profile, &options, &cancellation)
                .expect_err("pre-cancelled lookup must not scan or enumerate processes");
        assert!(is_cancellation_error(&error));
        assert!(error.to_string().contains(CANCELLATION_ERROR_CODE));

        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn utf8_mode_preserves_non_ascii_literal_bytes() {
        let patterns = build_patterns("维斯塔斯", ProcessStringEncodingSelection::Utf8);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].encoding, "utf8");
        assert_eq!(patterns[0].bytes, "维斯塔斯".as_bytes());
    }

    #[test]
    fn scope_records_single_pass_active_process_universe() {
        let scope = process_string_scope(&["ascii".to_owned(), "utf16le".to_owned()]);
        assert_eq!(
            scope.kind,
            "windows_active_process_acquired_resident_literal_hits"
        );
        assert_eq!(
            scope.constraints["physical_scan"],
            "single_pass_contiguous_acquired_ranges"
        );
        assert_eq!(
            scope.constraints["process_universe"],
            "ps_active_process_head"
        );
        assert_eq!(scope.constraints["virtual_region"], "user");
        assert_eq!(scope.constraints["resident_pages"], true);
        assert_eq!(scope.constraints["transition_pages"], true);
        assert_eq!(scope.constraints["prototype_pages"], false);
        assert_eq!(scope.constraints["swapped_pages"], false);
        assert_eq!(scope.constraints["compressed_store_pages"], false);
        assert_eq!(
            scope.constraints["cross_noncontiguous_virtual_page_matches"],
            false
        );
    }

    #[test]
    fn decodes_utf16_context_without_nul_artifacts() {
        let bytes = "前目标后"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(decode_context_bytes(&bytes, "utf16le"), "前目标后");
    }

    #[test]
    fn virtual_revalidation_distinguishes_mismatch_from_read_error() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-process-string-reread-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0u8; 0x6000];
        put_u64(&mut bytes, 0x1000, 0x2003);
        put_u64(&mut bytes, 0x2000, 0x3003);
        put_u64(&mut bytes, 0x3000, 0x4003);
        put_u64(&mut bytes, 0x4000, 0x5003);
        bytes[0x5000..0x5007].copy_from_slice(b"StarMem");
        bytes[0x5ffe..0x6000].copy_from_slice(b"xy");
        fs::write(&path, bytes).unwrap();

        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 0x1000).unwrap();
        assert!(virtual_bytes_equal(&space, 0, b"StarMem").unwrap());
        assert!(!virtual_bytes_equal(&space, 0, b"StarMen").unwrap());
        assert!(virtual_bytes_equal(&space, 0xffe, b"xyzz").is_err());
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_empty_query_and_zero_limits() {
        let options = ProcessStringOptions {
            query: String::new(),
            encoding: ProcessStringEncodingSelection::Both,
            scan_hit_limit: 1,
            limit: 1,
            process_limit: 1,
            mapping_limit: 1,
            reverse_entry_limit: DEFAULT_PROCESS_STRING_REVERSE_ENTRY_LIMIT,
            reverse_alias_limit: DEFAULT_PROCESS_STRING_REVERSE_ALIAS_LIMIT,
            chunk_size: 4096,
            context_bytes: 0,
        };
        assert!(validate_options(&options).is_err());

        let options = ProcessStringOptions {
            query: "x".to_owned(),
            scan_hit_limit: 0,
            ..options
        };
        assert!(validate_options(&options).is_err());
    }

    #[test]
    fn limit_evidence_distinguishes_equality_from_actual_resource_truncation() {
        let options = ProcessStringOptions {
            query: "x".to_owned(),
            encoding: ProcessStringEncodingSelection::Both,
            scan_hit_limit: 8,
            limit: 8,
            process_limit: 8,
            mapping_limit: 1,
            reverse_entry_limit: DEFAULT_PROCESS_STRING_REVERSE_ENTRY_LIMIT,
            reverse_alias_limit: DEFAULT_PROCESS_STRING_REVERSE_ALIAS_LIMIT,
            chunk_size: 4096,
            context_bytes: 0,
        };
        let at_limit = evidence_limits(
            &options, 0, 0, 1, false, false, false, false, 0, 0, 0, false, 0, false, 0, false, 0,
            false, 0, false,
        );
        assert_eq!(
            at_limit
                .iter()
                .find(|limit| limit.name == "mapping_limit")
                .and_then(|limit| limit.reached),
            Some(false)
        );
        let overflow_and_failure = evidence_limits(
            &options, 0, 0, 2, false, false, false, true, 4, 1, 5, true, 6, true, 1, true, 2, true,
            128, true,
        );
        assert_eq!(
            overflow_and_failure
                .iter()
                .find(|limit| limit.name == "mapping_limit")
                .and_then(|limit| limit.reached),
            Some(true)
        );
        let per_address_space = overflow_and_failure
            .iter()
            .find(|limit| limit.name == "reverse_entry_limit_per_address_space")
            .unwrap();
        assert_eq!(per_address_space.observed, Some(4));
        assert_eq!(per_address_space.reached, Some(true));
        let per_command = overflow_and_failure
            .iter()
            .find(|limit| limit.name == "reverse_entry_limit_per_command")
            .unwrap();
        assert_eq!(per_command.observed, Some(5));
        assert_eq!(per_command.reached, Some(true));
        let aliases = overflow_and_failure
            .iter()
            .find(|limit| limit.name == "reverse_alias_limit_per_command")
            .unwrap();
        assert_eq!(aliases.observed, Some(6));
        assert_eq!(aliases.reached, Some(true));
        let missing_ranges = overflow_and_failure
            .iter()
            .find(|limit| limit.name == "virtual_revalidation_missing_range_limit")
            .unwrap();
        assert_eq!(missing_ranges.observed, Some(1));
        assert_eq!(missing_ranges.reached, Some(true));
        let page_table_ranges = overflow_and_failure
            .iter()
            .find(|limit| limit.name == "page_table_missing_range_limit")
            .unwrap();
        assert_eq!(page_table_ranges.observed, Some(2));
        assert_eq!(page_table_ranges.reached, Some(true));
        let warning_limit = overflow_and_failure
            .iter()
            .find(|limit| limit.name == "warning_limit")
            .unwrap();
        assert_eq!(warning_limit.observed, Some(128));
        assert_eq!(warning_limit.reached, Some(true));
    }

    fn put_u64(output: &mut [u8], offset: usize, value: u64) {
        output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
