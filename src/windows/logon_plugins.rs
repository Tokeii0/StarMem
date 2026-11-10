use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Instant;

use anyhow::{Result, ensure};
use serde::Serialize;

use super::{
    ProcessRecord, WindowsKernelContext, is_kernel_address, is_kernel_pointer, list_processes,
    read_u16_at, read_u32_at, type_offset,
};
use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::symbols::codeview_from_virtual_pe;

const SEP_LOGON_BUCKETS: usize = 16;
const MAX_KERNEL_SESSIONS: usize = 65_536;
const MAX_WARNINGS: usize = 64;

#[derive(Debug, Clone)]
pub struct LogonSessionOptions {
    pub process_limit: usize,
    pub limit: usize,
}

impl Default for LogonSessionOptions {
    fn default() -> Self {
        Self {
            process_limit: 65_536,
            limit: 4_096,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LogonSessionReport {
    pub records: Vec<LogonSessionRecord>,
    pub sessions_found: usize,
    pub processes_examined: usize,
    pub primary_tokens_examined: usize,
    pub unique_primary_tokens: usize,
    pub missing_primary_token_processes: usize,
    pub unreadable_authentication_ids: usize,
    pub kernel_list_available: bool,
    pub kernel_list_complete: bool,
    pub kernel_buckets_examined: usize,
    pub kernel_sessions_examined: usize,
    pub process_token_only_sessions: usize,
    pub token_association_mismatches: usize,
    pub scope: String,
    pub truncated: bool,
    pub scan_seconds: f64,
    /// Whether all recovered process-token associations agree with the complete
    /// kernel logon-session table. This is intentionally separate from
    /// `complete`, which describes recovery coverage rather than cleanliness.
    pub consistent: bool,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct LogonSessionRecord {
    pub authentication_id_raw: u64,
    pub authentication_id: String,
    pub authentication_id_low_part: u32,
    pub authentication_id_high_part: u32,
    pub well_known_authentication: Option<String>,
    pub kernel_entry_address: Option<u64>,
    pub reference_count: Option<u64>,
    pub flags: Option<u32>,
    pub representative_token: Option<u64>,
    pub account_name: Option<String>,
    pub authority_name: Option<String>,
    pub user_sids: Vec<String>,
    pub logon_sids: Vec<String>,
    pub peb_session_ids: Vec<u32>,
    pub token_session_ids: Vec<u32>,
    pub token_sources: Vec<String>,
    pub integrity_levels: Vec<String>,
    pub process_count: usize,
    pub primary_token_count: usize,
    pub linked_primary_token_count: usize,
    pub mismatched_primary_token_count: usize,
    pub unverified_primary_token_count: usize,
    pub association_status: String,
    pub consistency_warnings: Vec<String>,
    pub processes: Vec<LogonSessionProcessRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogonSessionProcessRecord {
    pub pid: u64,
    pub ppid: Option<u64>,
    pub process: String,
    pub eprocess: u64,
    pub token: Option<u64>,
    pub token_id: Option<u64>,
    pub parent_token_id: Option<u64>,
    pub originating_logon_session: Option<u64>,
    pub token_logon_session: Option<u64>,
    pub peb_session_id: Option<u32>,
    pub token_session_id: Option<u32>,
    pub user_sid: Option<String>,
    pub logon_sid: Option<String>,
    pub user_name: Option<String>,
    pub user_domain: Option<String>,
    pub token_source: Option<String>,
    pub token_type: Option<String>,
    pub impersonation_level: Option<String>,
    pub integrity_level: Option<String>,
    pub create_time: Option<String>,
}

#[derive(Debug)]
pub(super) struct KernelLogonScan {
    pub(super) records: Vec<KernelLogonRecord>,
    pub(super) available: bool,
    pub(super) buckets_examined: usize,
    pub(super) complete: bool,
    pub(super) warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct KernelLogonRecord {
    pub(super) address: u64,
    pub(super) authentication_id: u64,
    next: u64,
    reference_count: Option<u64>,
    flags: Option<u32>,
    representative_token: Option<u64>,
    account_name: Option<String>,
    authority_name: Option<String>,
}

#[derive(Debug, Default)]
struct SessionAccumulator {
    kernel: Option<KernelLogonRecord>,
    processes: Vec<LogonSessionProcessRecord>,
    direct_mismatched_tokens: HashSet<u64>,
}

pub fn scan_logon_sessions(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &LogonSessionOptions,
) -> Result<LogonSessionReport> {
    ensure!(options.process_limit > 0, "活动进程扫描上限必须大于零");
    ensure!(options.limit > 0, "登录会话结果上限必须大于零");
    let started = Instant::now();

    let process_report = list_processes(image, kernel, profile, options.process_limit)?;
    let processes_examined = process_report.processes.len();
    let primary_tokens_examined = process_report
        .processes
        .iter()
        .filter(|process| process.details.token.is_some())
        .count();
    let unique_primary_tokens = process_report
        .processes
        .iter()
        .filter_map(|process| process.details.token)
        .collect::<HashSet<_>>()
        .len();
    let missing_primary_token_processes = process_report
        .processes
        .iter()
        .filter(|process| process.details.token.is_none())
        .count();
    let unreadable_authentication_ids = process_report
        .processes
        .iter()
        .filter(|process| {
            process.details.token.is_some() && process.details.token_authentication_id.is_none()
        })
        .count();

    let mut sessions = BTreeMap::<u64, SessionAccumulator>::new();
    for process in &process_report.processes {
        let Some(authentication_id) = process.details.token_authentication_id else {
            continue;
        };
        sessions
            .entry(authentication_id)
            .or_default()
            .processes
            .push(process_record(process));
    }

    let kernel_scan = walk_kernel_logon_sessions(image, kernel, profile);
    for record in &kernel_scan.records {
        let accumulator = sessions.entry(record.authentication_id).or_default();
        if accumulator.kernel.is_some() {
            continue;
        }
        accumulator.kernel = Some(record.clone());
    }

    // Even when the global bucket array is unavailable, a primary token can
    // still provide a direct, independently checkable LogonSession pointer.
    // Only accept it when the referenced structure repeats the token's LUID.
    if let Ok(space) = X64AddressSpace::new(image, kernel.directory_table_base) {
        for process in &process_report.processes {
            let details = &process.details;
            let (Some(authentication_id), Some(address)) =
                (details.token_authentication_id, details.token_logon_session)
            else {
                continue;
            };
            let Some(accumulator) = sessions.get_mut(&authentication_id) else {
                continue;
            };
            if let Some(record) = read_kernel_logon_record(&space, profile, address) {
                if record.authentication_id == authentication_id {
                    if accumulator.kernel.is_none() {
                        accumulator.kernel = Some(record);
                    }
                } else if let Some(token) = details.token {
                    accumulator.direct_mismatched_tokens.insert(token);
                }
            }
        }
    }

    let sessions_found = sessions.len();
    let mut records = sessions
        .into_iter()
        .map(|(authentication_id, accumulator)| finalize_session(authentication_id, accumulator))
        .collect::<Vec<_>>();
    records.sort_unstable_by_key(|record| record.authentication_id_raw);
    let process_token_only_sessions = records
        .iter()
        .filter(|record| record.association_status == "process_token_only")
        .count();
    let token_association_mismatches = records
        .iter()
        .map(|record| record.mismatched_primary_token_count)
        .sum();
    let truncated = records.len() > options.limit;
    records.truncate(options.limit);

    let mut warnings = process_report
        .warnings
        .into_iter()
        .map(|warning| format!("[{}] {}", warning.kind, warning.message))
        .collect::<Vec<_>>();
    warnings.extend(kernel_scan.warnings);
    if unreadable_authentication_ids > 0 {
        push_warning(
            &mut warnings,
            format!("{unreadable_authentication_ids} 个活动进程未能读取主令牌 AuthenticationId"),
        );
    }
    if missing_primary_token_processes > 0 {
        push_warning(
            &mut warnings,
            format!("{missing_primary_token_processes} 个活动进程没有可关联的主令牌指针"),
        );
    }
    if process_token_only_sessions > 0 && kernel_scan.available && kernel_scan.complete {
        push_warning(
            &mut warnings,
            format!(
                "{process_token_only_sessions} 个活动主令牌登录 LUID 未出现在完整 SepLogonSessions 表中"
            ),
        );
    }
    if token_association_mismatches > 0 {
        push_warning(
            &mut warnings,
            format!(
                "{token_association_mismatches} 个唯一主令牌的 AuthenticationId 与 LogonSession 反向关联不一致"
            ),
        );
    }
    if truncated {
        push_warning(
            &mut warnings,
            format!("登录会话结果达到 {} 条上限", options.limit),
        );
    }
    warnings.truncate(MAX_WARNINGS);

    let scope = if kernel_scan.available && kernel_scan.complete {
        "SepLogonSessions 内核会话表，并与活动进程主令牌交叉关联".to_owned()
    } else if kernel_scan.available {
        "已恢复的 SepLogonSessions 内核会话节点，并与活动进程主令牌交叉关联；内核表遍历不完整"
            .to_owned()
    } else {
        "活动进程主令牌观察范围；SepLogonSessions 内核会话表不可用".to_owned()
    };
    let consistent = kernel_scan.available
        && kernel_scan.complete
        && process_token_only_sessions == 0
        && token_association_mismatches == 0;
    let complete = process_report.complete
        && kernel_scan.available
        && kernel_scan.complete
        && missing_primary_token_processes == 0
        && unreadable_authentication_ids == 0
        && !truncated;

    Ok(LogonSessionReport {
        records,
        sessions_found,
        processes_examined,
        primary_tokens_examined,
        unique_primary_tokens,
        missing_primary_token_processes,
        unreadable_authentication_ids,
        kernel_list_available: kernel_scan.available,
        kernel_list_complete: kernel_scan.complete,
        kernel_buckets_examined: kernel_scan.buckets_examined,
        kernel_sessions_examined: kernel_scan.records.len(),
        process_token_only_sessions,
        token_association_mismatches,
        scope,
        truncated,
        scan_seconds: started.elapsed().as_secs_f64(),
        consistent,
        complete,
        warnings,
    })
}

pub(super) fn walk_kernel_logon_sessions(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
) -> KernelLogonScan {
    let mut scan = KernelLogonScan {
        records: Vec::new(),
        available: false,
        buckets_examined: 0,
        complete: true,
        warnings: Vec::new(),
    };
    if kernel.is_x86_pae() {
        scan.complete = false;
        push_warning(
            &mut scan.warnings,
            "x86 PAE 精确配置暂不包含 SepLogonSessions 与 _TOKEN 登录字段".to_owned(),
        );
        return scan;
    }
    if !profile.types.contains_key("_SEP_LOGON_SESSION_REFERENCES") {
        scan.complete = false;
        push_warning(
            &mut scan.warnings,
            "精确内核配置缺少 _SEP_LOGON_SESSION_REFERENCES".to_owned(),
        );
        return scan;
    }
    match codeview_from_virtual_pe(image, kernel.directory_table_base, kernel.kernel_base) {
        Ok(record) if pdb_guid_matches(&record.guid, profile) => {}
        Ok(record) => {
            scan.complete = false;
            push_warning(
                &mut scan.warnings,
                format!(
                    "目标内核 CodeView GUID {} 与当前配置 GUID {} 不一致；不使用 SepLogonSessions RVA",
                    record.guid, profile.pdb_guid
                ),
            );
            return scan;
        }
        Err(error) => {
            scan.complete = false;
            push_warning(
                &mut scan.warnings,
                format!("无法验证目标内核 CodeView；不使用 SepLogonSessions RVA：{error:#}"),
            );
            return scan;
        }
    }
    let Some(rva) = profile.symbols.get("SepLogonSessions") else {
        scan.complete = false;
        push_warning(
            &mut scan.warnings,
            "精确内核配置缺少 SepLogonSessions 全局符号".to_owned(),
        );
        return scan;
    };
    let Ok(space) = X64AddressSpace::new(image, kernel.directory_table_base) else {
        scan.complete = false;
        push_warning(&mut scan.warnings, "无法创建内核地址空间".to_owned());
        return scan;
    };
    let global = kernel.kernel_base + u64::from(*rva);
    let Ok(bucket_array) = space.read_u64(global) else {
        scan.complete = false;
        push_warning(
            &mut scan.warnings,
            format!("无法读取 SepLogonSessions 全局指针 {global:#x}"),
        );
        return scan;
    };
    if !is_kernel_pointer(bucket_array) {
        scan.complete = false;
        push_warning(
            &mut scan.warnings,
            format!("SepLogonSessions 桶数组指针无效：{bucket_array:#x}"),
        );
        return scan;
    }
    scan.available = true;

    let mut seen = HashSet::new();
    let mut seen_authentication_ids = BTreeMap::new();
    for bucket in 0..SEP_LOGON_BUCKETS {
        scan.buckets_examined += 1;
        let Ok(mut current) = space.read_u64(bucket_array + (bucket as u64) * 8) else {
            scan.complete = false;
            push_warning(
                &mut scan.warnings,
                format!("无法读取 SepLogonSessions 第 {bucket} 个桶"),
            );
            continue;
        };
        while current != 0 {
            if scan.records.len() == MAX_KERNEL_SESSIONS {
                scan.complete = false;
                push_warning(
                    &mut scan.warnings,
                    format!("SepLogonSessions 达到 {MAX_KERNEL_SESSIONS} 个节点安全上限"),
                );
                return scan;
            }
            if !is_kernel_pointer(current) {
                scan.complete = false;
                push_warning(
                    &mut scan.warnings,
                    format!("第 {bucket} 个桶出现无效节点指针 {current:#x}"),
                );
                break;
            }
            if !seen.insert(current) {
                scan.complete = false;
                push_warning(
                    &mut scan.warnings,
                    format!("SepLogonSessions 在 {current:#x} 出现循环或重复节点"),
                );
                break;
            }
            let Some(record) = read_kernel_logon_record(&space, profile, current) else {
                scan.complete = false;
                push_warning(
                    &mut scan.warnings,
                    format!("无法解析第 {bucket} 个桶的会话节点 {current:#x}"),
                );
                break;
            };
            current = record.next;
            if let Some(previous) =
                seen_authentication_ids.insert(record.authentication_id, record.address)
            {
                scan.complete = false;
                push_warning(
                    &mut scan.warnings,
                    format!(
                        "登录 LUID {} 同时出现在 {previous:#x} 与 {:#x}",
                        format_luid(record.authentication_id),
                        record.address
                    ),
                );
                continue;
            }
            scan.records.push(record);
        }
    }
    scan
}

fn read_kernel_logon_record(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    address: u64,
) -> Option<KernelLogonRecord> {
    let next = space
        .read_u64(address + type_offset(profile, "_SEP_LOGON_SESSION_REFERENCES", "Next")?)
        .ok()?;
    if next != 0 && !is_kernel_pointer(next) {
        return None;
    }
    let authentication_id = space
        .read_u64(address + type_offset(profile, "_SEP_LOGON_SESSION_REFERENCES", "LogonId")?)
        .ok()?;
    let reference_count = read_reference_count(space, profile, address);
    let flags = read_u32_field(space, profile, address, "Flags");
    let representative_token = read_u64_field(space, profile, address, "Token")
        .filter(|pointer| is_kernel_pointer(*pointer));
    let account_name = type_offset(profile, "_SEP_LOGON_SESSION_REFERENCES", "AccountName")
        .and_then(|offset| read_strict_account_string(space, profile, address + offset));
    let authority_name = type_offset(profile, "_SEP_LOGON_SESSION_REFERENCES", "AuthorityName")
        .and_then(|offset| read_strict_account_string(space, profile, address + offset));
    Some(KernelLogonRecord {
        address,
        authentication_id,
        next,
        reference_count,
        flags,
        representative_token,
        account_name,
        authority_name,
    })
}

fn read_reference_count(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    address: u64,
) -> Option<u64> {
    let reference = type_offset(profile, "_SEP_LOGON_SESSION_REFERENCES", "ReferenceCount")?;
    let flags = type_offset(profile, "_SEP_LOGON_SESSION_REFERENCES", "Flags")?;
    if flags.saturating_sub(reference) >= 8 {
        space.read_u64(address + reference).ok()
    } else {
        read_u32_at(space, address + reference).map(u64::from)
    }
}

fn read_strict_account_string(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    descriptor: u64,
) -> Option<String> {
    const MAX_ACCOUNT_BYTES: usize = 1024;
    let length_offset = type_offset(profile, "_UNICODE_STRING", "Length").unwrap_or(0);
    let maximum_offset = type_offset(profile, "_UNICODE_STRING", "MaximumLength").unwrap_or(2);
    let buffer_offset = type_offset(profile, "_UNICODE_STRING", "Buffer").unwrap_or(8);
    let length = usize::from(read_u16_at(space, descriptor + length_offset)?);
    let maximum = usize::from(read_u16_at(space, descriptor + maximum_offset)?);
    if length == 0
        || length > MAX_ACCOUNT_BYTES
        || length % 2 != 0
        || maximum < length
        || maximum > MAX_ACCOUNT_BYTES + 2
    {
        return None;
    }
    let buffer = space.read_u64(descriptor + buffer_offset).ok()?;
    if !is_kernel_address(buffer) {
        return None;
    }
    let mut bytes = vec![0u8; length];
    space.read_virtual(buffer, &mut bytes).ok()?;
    let words = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let value = String::from_utf16(&words).ok()?;
    let value = value.trim_end_matches('\0');
    if !valid_account_text(value) {
        return None;
    }
    Some(value.to_owned())
}

fn valid_account_text(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= 256
        && !value.chars().any(|character| {
            character == '\0' || character == '\\' || character == '/' || character.is_control()
        })
}

fn pdb_guid_matches(guid: &str, profile: &KernelProfile) -> bool {
    // KernelProfile::pdb_age comes from the downloaded PDB information stream,
    // while the target exposes the PE RSDS age. Microsoft symbol-server PDBs
    // in the validation corpus legitimately have a newer internal age for the
    // same GUID, so the 128-bit GUID is the stable cross-representation key.
    fn normalize(value: &str) -> String {
        value
            .chars()
            .filter(|character| *character != '-')
            .flat_map(char::to_uppercase)
            .collect()
    }

    normalize(guid) == normalize(&profile.pdb_guid)
}

fn read_u64_field(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    address: u64,
    field: &str,
) -> Option<u64> {
    space
        .read_u64(address + type_offset(profile, "_SEP_LOGON_SESSION_REFERENCES", field)?)
        .ok()
}

fn read_u32_field(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    address: u64,
    field: &str,
) -> Option<u32> {
    read_u32_at(
        space,
        address + type_offset(profile, "_SEP_LOGON_SESSION_REFERENCES", field)?,
    )
}

fn process_record(process: &ProcessRecord) -> LogonSessionProcessRecord {
    let details = &process.details;
    LogonSessionProcessRecord {
        pid: process.pid,
        ppid: process.ppid,
        process: process.name.clone(),
        eprocess: process.eprocess,
        token: details.token,
        token_id: details.token_id,
        parent_token_id: details.token_parent_id,
        originating_logon_session: details.token_originating_logon_session,
        token_logon_session: details.token_logon_session,
        peb_session_id: details.session_id,
        token_session_id: details.token_session_id,
        user_sid: details.user_sid.clone(),
        logon_sid: details.logon_sid.clone(),
        user_name: details.user_name.clone(),
        user_domain: details.user_domain.clone(),
        token_source: details.token_source.clone(),
        token_type: details.token_type.clone(),
        impersonation_level: details.token_impersonation_level.clone(),
        integrity_level: details.integrity_level.clone(),
        create_time: details.create_time.clone(),
    }
}

fn finalize_session(
    authentication_id: u64,
    mut accumulator: SessionAccumulator,
) -> LogonSessionRecord {
    accumulator
        .processes
        .sort_unstable_by_key(|process| (process.pid, process.eprocess));

    let user_sids = collect_strings(
        accumulator
            .processes
            .iter()
            .filter_map(|process| process.user_sid.as_deref()),
    );
    let logon_sids = collect_strings(
        accumulator
            .processes
            .iter()
            .filter_map(|process| process.logon_sid.as_deref()),
    );
    let peb_session_ids = accumulator
        .processes
        .iter()
        .filter_map(|process| process.peb_session_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let token_session_ids = accumulator
        .processes
        .iter()
        .filter_map(|process| process.token_session_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let token_sources = collect_strings(
        accumulator
            .processes
            .iter()
            .filter_map(|process| process.token_source.as_deref()),
    );
    let integrity_levels = collect_strings(
        accumulator
            .processes
            .iter()
            .filter_map(|process| process.integrity_level.as_deref()),
    );
    let unique_tokens = accumulator
        .processes
        .iter()
        .filter_map(|process| {
            process
                .token
                .map(|token| (token, process.token_logon_session))
        })
        .collect::<BTreeMap<_, _>>();
    let primary_token_count = unique_tokens.len();
    let kernel_address = accumulator.kernel.as_ref().map(|entry| entry.address);
    let linked_primary_token_count = unique_tokens
        .iter()
        .filter(|(_, logon_session)| kernel_address.is_some() && **logon_session == kernel_address)
        .count();
    let mut mismatched_tokens = accumulator.direct_mismatched_tokens;
    if let Some(kernel_address) = kernel_address {
        mismatched_tokens.extend(unique_tokens.iter().filter_map(|(token, logon_session)| {
            logon_session
                .is_some_and(|address| address != kernel_address)
                .then_some(*token)
        }));
    }
    let mismatched_primary_token_count = mismatched_tokens.len();
    let unverified_primary_token_count = unique_tokens
        .iter()
        .filter(|(_, logon_session)| logon_session.is_none())
        .count();
    let association_status = association_status(
        kernel_address.is_some(),
        primary_token_count,
        linked_primary_token_count,
        mismatched_primary_token_count,
    )
    .to_owned();
    let mut consistency_warnings = Vec::new();
    if mismatched_primary_token_count > 0 {
        consistency_warnings.push(format!(
            "{mismatched_primary_token_count} 个主令牌的 LogonSession 指针与 LUID 对应内核节点不一致"
        ));
    }
    if peb_session_ids.len() > 1 {
        consistency_warnings.push("同一登录 LUID 关联多个 PEB SessionId".to_owned());
    }
    if token_session_ids.len() > 1 {
        consistency_warnings.push("同一登录 LUID 关联多个 Token SessionId".to_owned());
    }
    if user_sids.len() > 1 {
        consistency_warnings.push("同一登录 LUID 关联多个用户 SID".to_owned());
    }

    let process_count = accumulator.processes.len();
    let kernel = accumulator.kernel;
    LogonSessionRecord {
        authentication_id_raw: authentication_id,
        authentication_id: format_luid(authentication_id),
        authentication_id_low_part: authentication_id as u32,
        authentication_id_high_part: (authentication_id >> 32) as u32,
        well_known_authentication: well_known_authentication(authentication_id).map(str::to_owned),
        kernel_entry_address: kernel.as_ref().map(|entry| entry.address),
        reference_count: kernel.as_ref().and_then(|entry| entry.reference_count),
        flags: kernel.as_ref().and_then(|entry| entry.flags),
        representative_token: kernel.as_ref().and_then(|entry| entry.representative_token),
        account_name: kernel.as_ref().and_then(|entry| entry.account_name.clone()),
        authority_name: kernel
            .as_ref()
            .and_then(|entry| entry.authority_name.clone()),
        user_sids,
        logon_sids,
        peb_session_ids,
        token_session_ids,
        token_sources,
        integrity_levels,
        process_count,
        primary_token_count,
        linked_primary_token_count,
        mismatched_primary_token_count,
        unverified_primary_token_count,
        association_status,
        consistency_warnings,
        processes: accumulator.processes,
    }
}

fn collect_strings<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    values
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn association_status(
    kernel_entry: bool,
    process_count: usize,
    linked: usize,
    mismatched: usize,
) -> &'static str {
    if mismatched > 0 {
        return "mismatch";
    }
    if !kernel_entry {
        return "process_token_only";
    }
    if process_count == 0 {
        return "kernel_only";
    }
    if linked == process_count {
        return "verified";
    }
    if linked > 0 {
        return "partially_verified";
    }
    "unverified"
}

fn format_luid(value: u64) -> String {
    format!("{:08x}:{:08x}", value >> 32, value as u32)
}

fn well_known_authentication(value: u64) -> Option<&'static str> {
    match value {
        0x3e4 => Some("NETWORK SERVICE"),
        0x3e5 => Some("LOCAL SERVICE"),
        0x3e6 => Some("ANONYMOUS LOGON"),
        0x3e7 => Some("SYSTEM"),
        _ => None,
    }
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luid_format_keeps_both_halves() {
        assert_eq!(format_luid(0x1234_5678_9abc_def0), "12345678:9abcdef0");
        assert_eq!(format_luid(0x3e7), "00000000:000003e7");
        assert_eq!(well_known_authentication(0x3e7), Some("SYSTEM"));
    }

    #[test]
    fn association_state_distinguishes_sources_and_mismatches() {
        assert_eq!(association_status(false, 2, 0, 0), "process_token_only");
        assert_eq!(association_status(true, 0, 0, 0), "kernel_only");
        assert_eq!(association_status(true, 2, 2, 0), "verified");
        assert_eq!(association_status(true, 2, 1, 0), "partially_verified");
        assert_eq!(association_status(true, 2, 1, 1), "mismatch");
        assert_eq!(association_status(false, 1, 0, 1), "mismatch");
    }

    #[test]
    fn account_text_rejects_path_fragments_and_controls() {
        assert!(valid_account_text("LOCAL SERVICE"));
        assert!(valid_account_text("DESKTOP-01$"));
        assert!(!valid_account_text(r"Windows\Perf"));
        assert!(!valid_account_text("user\0path"));
    }

    #[test]
    fn finalization_deduplicates_tokens_but_preserves_processes() {
        let process = |pid| LogonSessionProcessRecord {
            pid,
            ppid: Some(4),
            process: "sample.exe".to_owned(),
            eprocess: 0xffff_8000_0000_0000 + pid * 0x1000,
            token: Some(0xffff_9000_0000_1000),
            token_id: Some(7),
            parent_token_id: None,
            originating_logon_session: None,
            token_logon_session: Some(0xffff_a000_0000_2000),
            peb_session_id: Some(1),
            token_session_id: Some(1),
            user_sid: Some("S-1-5-21-1-1001".to_owned()),
            logon_sid: Some("S-1-5-5-0-1234".to_owned()),
            user_name: Some("alice".to_owned()),
            user_domain: Some("LAB".to_owned()),
            token_source: Some("User32".to_owned()),
            token_type: Some("primary".to_owned()),
            impersonation_level: Some("anonymous".to_owned()),
            integrity_level: Some("medium".to_owned()),
            create_time: None,
        };
        let record = finalize_session(
            0x1234,
            SessionAccumulator {
                kernel: Some(KernelLogonRecord {
                    address: 0xffff_a000_0000_2000,
                    authentication_id: 0x1234,
                    next: 0,
                    reference_count: Some(2),
                    flags: Some(0),
                    representative_token: None,
                    account_name: Some("alice".to_owned()),
                    authority_name: Some("LAB".to_owned()),
                }),
                processes: vec![process(10), process(11)],
                direct_mismatched_tokens: HashSet::new(),
            },
        );
        assert_eq!(record.process_count, 2);
        assert_eq!(record.primary_token_count, 1);
        assert_eq!(record.linked_primary_token_count, 1);
        assert_eq!(record.association_status, "verified");
        assert_eq!(record.user_sids, ["S-1-5-21-1-1001"]);
    }
}
