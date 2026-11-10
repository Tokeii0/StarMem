use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Instant;

use anyhow::{Result, ensure};
use serde::Serialize;

use super::logon_plugins::walk_kernel_logon_sessions;
use super::object_plugins::ObjectHeaderDecoder;
use super::{ProcessRecord, WindowsKernelContext, is_kernel_pointer, list_processes};
use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::symbols::codeview_from_virtual_pe;

const MAX_WARNINGS: usize = 64;

const RISK_PRIVILEGE_GLOBALS: &[(&str, TokenAnomalySeverity, &str)] = &[
    (
        "SeCreateTokenPrivilege",
        TokenAnomalySeverity::Critical,
        "可创建访问令牌",
    ),
    (
        "SeAssignPrimaryTokenPrivilege",
        TokenAnomalySeverity::High,
        "可替换进程主令牌",
    ),
    (
        "SeTcbPrivilege",
        TokenAnomalySeverity::Critical,
        "可作为操作系统受信任组件运行",
    ),
    (
        "SeTakeOwnershipPrivilege",
        TokenAnomalySeverity::High,
        "可取得对象所有权",
    ),
    (
        "SeLoadDriverPrivilege",
        TokenAnomalySeverity::High,
        "可加载或卸载驱动",
    ),
    (
        "SeBackupPrivilege",
        TokenAnomalySeverity::Medium,
        "可绕过读取访问控制执行备份",
    ),
    (
        "SeRestorePrivilege",
        TokenAnomalySeverity::High,
        "可绕过写入访问控制执行还原",
    ),
    (
        "SeDebugPrivilege",
        TokenAnomalySeverity::High,
        "可调试并访问其他进程",
    ),
    (
        "SeImpersonatePrivilege",
        TokenAnomalySeverity::Medium,
        "可模拟已验证客户端",
    ),
];

#[derive(Debug, Clone)]
pub struct TokenAnomalyOptions {
    pub process_limit: usize,
    pub limit: usize,
    pub direct_only: bool,
    pub min_severity: TokenAnomalySeverity,
}

impl Default for TokenAnomalyOptions {
    fn default() -> Self {
        Self {
            process_limit: 65_536,
            limit: 4_096,
            direct_only: false,
            min_severity: TokenAnomalySeverity::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenAnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl TokenAnomalySeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TokenAnomalyReport {
    pub records: Vec<TokenAnomalyRecord>,
    pub supported: bool,
    pub scope: String,
    pub direct_only: bool,
    pub min_severity: TokenAnomalySeverity,
    pub processes_examined: usize,
    pub active_processes_examined: usize,
    pub exited_processes_skipped: usize,
    pub primary_token_processes: usize,
    pub unique_primary_tokens: usize,
    pub missing_primary_token_processes: usize,
    pub unsupported_primary_token_processes: usize,
    pub trusted_token_structures: usize,
    pub untrusted_token_structures: usize,
    pub tokens_with_incomplete_core_fields: usize,
    pub object_type_mismatches: usize,
    pub unreadable_logon_session_references: usize,
    pub truncated_group_lists: usize,
    pub exact_profile_match: bool,
    pub object_type_validation_available: bool,
    pub privilege_mapping_available: bool,
    pub privilege_mapping_complete: bool,
    pub logon_session_validation_available: bool,
    pub enrichment_complete: bool,
    pub findings_detected: usize,
    pub direct_findings_detected: usize,
    pub contextual_signals_detected: usize,
    pub recovery_findings_detected: usize,
    pub findings_matched: usize,
    pub tokens_matched: usize,
    /// Whether the filtered result set has no findings and the core scan is complete.
    pub clean: bool,
    /// Whether the unfiltered result set has no findings and the core scan is complete.
    pub unfiltered_clean: bool,
    pub direct_clean: bool,
    pub truncated: bool,
    pub scan_seconds: f64,
    /// Recovery coverage for active-process primary tokens. Optional privilege
    /// and logon-session enrichment is reported separately.
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenAnomalyRecord {
    pub token: u64,
    pub structure_trusted: bool,
    pub object_type: Option<String>,
    pub token_id: Option<u64>,
    pub authentication_id_raw: Option<u64>,
    pub authentication_id: Option<String>,
    pub parent_token_id: Option<u64>,
    pub originating_logon_session: Option<u64>,
    pub logon_session: Option<u64>,
    pub token_session_id: Option<u32>,
    pub token_type: Option<String>,
    pub token_in_use: Option<bool>,
    pub token_source: Option<String>,
    pub user_sid: Option<String>,
    pub logon_sid: Option<String>,
    pub integrity_level: Option<String>,
    pub integrity_sid: Option<String>,
    pub privileges_present: Option<u64>,
    pub privileges_enabled: Option<u64>,
    pub privileges_enabled_by_default: Option<u64>,
    pub declared_group_count: Option<u32>,
    pub recovered_group_count: Option<usize>,
    pub max_severity: TokenAnomalySeverity,
    pub direct_finding_count: usize,
    pub contextual_signal_count: usize,
    pub recovery_finding_count: usize,
    pub findings: Vec<TokenAnomalyFinding>,
    pub owners: Vec<TokenOwnerRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenAnomalyFinding {
    pub rule: String,
    pub category: String,
    pub severity: TokenAnomalySeverity,
    pub directly_proven: bool,
    pub evidence_class: String,
    pub summary: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenOwnerRecord {
    pub pid: u64,
    pub ppid: Option<u64>,
    pub process: String,
    pub eprocess: u64,
    pub peb_session_id: Option<u32>,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
}

#[derive(Debug, Clone)]
struct RiskPrivilege {
    name: String,
    bit: u8,
    severity: TokenAnomalySeverity,
    description: String,
}

#[derive(Debug, Clone)]
struct TokenValidation {
    trusted: bool,
    core_fields_complete: bool,
    object_type: Option<String>,
    object_type_mismatch: bool,
    failures: Vec<String>,
}

pub fn scan_token_anomalies(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &TokenAnomalyOptions,
) -> Result<TokenAnomalyReport> {
    ensure!(options.process_limit > 0, "活动进程扫描上限必须大于零");
    ensure!(options.limit > 0, "令牌异常结果上限必须大于零");
    let started = Instant::now();
    let process_report = list_processes(image, kernel, profile, options.process_limit)?;
    let processes_examined = process_report.processes.len();
    let active_processes = process_report
        .processes
        .iter()
        .filter(|process| process.details.state != "exited")
        .collect::<Vec<_>>();
    let active_processes_examined = active_processes.len();
    let exited_processes_skipped = processes_examined - active_processes_examined;
    let primary_token_processes = active_processes
        .iter()
        .filter(|process| process.details.token.is_some())
        .count();
    let missing_primary_token_processes = active_processes_examined - primary_token_processes;
    let unique_primary_tokens = active_processes
        .iter()
        .filter_map(|process| process.details.token)
        .collect::<HashSet<_>>()
        .len();
    let supported = !kernel.is_x86_pae() && profile.types.contains_key("_TOKEN");
    let unsupported_primary_token_processes = if !supported {
        primary_token_processes
    } else {
        0
    };

    let kernel_space = supported
        .then(|| X64AddressSpace::new(image, kernel.directory_table_base).ok())
        .flatten();
    let exact_profile_match = kernel_space
        .as_ref()
        .is_some_and(|_| target_profile_matches(image, kernel, profile));
    let object_decoder = if exact_profile_match {
        kernel_space
            .as_ref()
            .and_then(|space| ObjectHeaderDecoder::new(space, kernel, profile).ok())
    } else {
        None
    };
    let object_type_validation_available = object_decoder.is_some();

    let mut grouped = BTreeMap::<u64, Vec<&ProcessRecord>>::new();
    if supported {
        for process in &active_processes {
            if let Some(token) = process.details.token {
                grouped.entry(token).or_default().push(*process);
            }
        }
    }

    let mut validations = BTreeMap::new();
    for (token, owners) in &grouped {
        validations.insert(
            *token,
            validate_token_structure(
                *token,
                &owners[0].details,
                exact_profile_match,
                kernel_space.as_ref(),
                object_decoder.as_ref(),
                Some(profile),
            ),
        );
    }

    // TokenId is an object-instance identifier. AuthenticationId identifies a
    // logon session and is intentionally allowed to be shared by many tokens.
    let mut token_id_addresses = BTreeMap::<u64, BTreeSet<u64>>::new();
    let mut authentication_sids = BTreeMap::<u64, BTreeSet<String>>::new();
    for (token, owners) in &grouped {
        if !validations.get(token).is_some_and(|value| value.trusted) {
            continue;
        }
        let details = &owners[0].details;
        if let Some(token_id) = details.token_id.filter(|value| *value != 0) {
            token_id_addresses
                .entry(token_id)
                .or_default()
                .insert(*token);
        }
        if let (Some(authentication_id), Some(user_sid)) =
            (details.token_authentication_id, details.user_sid.as_ref())
        {
            authentication_sids
                .entry(authentication_id)
                .or_default()
                .insert(user_sid.clone());
        }
    }

    let kernel_logons = walk_kernel_logon_sessions(image, kernel, profile);
    let logon_session_validation_available = kernel_logons.available && kernel_logons.complete;
    let logon_entries = kernel_logons
        .records
        .iter()
        .map(|entry| (entry.address, entry.authentication_id))
        .collect::<BTreeMap<_, _>>();
    let (risk_privileges, privilege_mapping_available, privilege_mapping_complete, mut warnings) =
        load_risk_privileges(
            image,
            kernel,
            profile,
            kernel_space.as_ref(),
            exact_profile_match,
        );
    warnings.extend(kernel_logons.warnings);

    let mut records = Vec::new();
    let mut trusted_token_structures = 0usize;
    let mut untrusted_token_structures = 0usize;
    let mut tokens_with_incomplete_core_fields = 0usize;
    let mut object_type_mismatches = 0usize;
    let mut unreadable_logon_session_references = 0usize;
    let mut truncated_group_lists = 0usize;

    for (token, mut owners) in grouped {
        owners.sort_unstable_by_key(|process| (process.pid, process.eprocess));
        let details = &owners[0].details;
        let validation = validations
            .remove(&token)
            .expect("every grouped token has a validation result");
        if details.token_groups_truncated == Some(true) {
            truncated_group_lists += 1;
        }
        if !validation.core_fields_complete {
            tokens_with_incomplete_core_fields += 1;
        }
        if validation.object_type_mismatch {
            object_type_mismatches += 1;
        }

        let mut findings = Vec::new();
        if !validation.trusted {
            untrusted_token_structures += 1;
            add_untrusted_token_finding(&mut findings, token, &validation);
        } else {
            trusted_token_structures += 1;
            add_observation_consistency_findings(&mut findings, &owners);
            add_structural_findings(
                &mut findings,
                token,
                details,
                &logon_entries,
                kernel_logons.available,
                kernel_logons.complete,
                details
                    .token_id
                    .filter(|value| *value != 0)
                    .and_then(|token_id| token_id_addresses.get(&token_id)),
                details
                    .token_authentication_id
                    .and_then(|authentication_id| authentication_sids.get(&authentication_id)),
            );
            add_contextual_findings(&mut findings, details, &owners, &risk_privileges);
        }
        if validation.trusted && kernel_logons.complete {
            let verified = details
                .token_logon_session
                .is_some_and(|address| logon_entries.contains_key(&address));
            if !verified {
                unreadable_logon_session_references += 1;
            }
        }
        findings.sort_by_key(|finding| (Reverse(finding.severity), finding.rule.clone()));
        if findings.is_empty() {
            continue;
        }
        records.push(build_record(token, details, owners, validation, findings));
    }

    let findings_detected = records
        .iter()
        .map(|record| record.findings.len())
        .sum::<usize>();
    let direct_findings_detected = records
        .iter()
        .map(|record| record.direct_finding_count)
        .sum::<usize>();
    let contextual_signals_detected = records
        .iter()
        .map(|record| record.contextual_signal_count)
        .sum::<usize>();
    let recovery_findings_detected = records
        .iter()
        .map(|record| record.recovery_finding_count)
        .sum::<usize>();

    for record in &mut records {
        record.findings.retain(|finding| {
            (!options.direct_only || finding.directly_proven)
                && finding.severity >= options.min_severity
        });
        refresh_record_finding_counts(record);
    }
    records.retain(|record| !record.findings.is_empty());
    records.sort_by_key(|record| {
        (
            Reverse(record.max_severity),
            record
                .owners
                .first()
                .map(|owner| owner.pid)
                .unwrap_or(u64::MAX),
            record.token,
        )
    });
    let tokens_matched = records.len();
    let findings_matched = records
        .iter()
        .map(|record| record.findings.len())
        .sum::<usize>();
    let truncated = records.len() > options.limit;
    records.truncate(options.limit);

    warnings.extend(
        process_report
            .warnings
            .into_iter()
            .map(|warning| format!("[{}] {}", warning.kind, warning.message)),
    );
    if !supported {
        push_warning(
            &mut warnings,
            "当前架构或精确配置不支持 _TOKEN 主令牌结构审计".to_owned(),
        );
    }
    if !exact_profile_match && supported {
        push_warning(
            &mut warnings,
            "目标内核与当前配置的 CodeView GUID 不一致；令牌结构不会被判为可信".to_owned(),
        );
    }
    if !object_type_validation_available && supported {
        push_warning(
            &mut warnings,
            "无法通过 OBJECT_HEADER 验证主令牌对象类型；核心字段可恢复，但覆盖状态不完整"
                .to_owned(),
        );
    }
    if missing_primary_token_processes > 0 {
        push_warning(
            &mut warnings,
            format!("{missing_primary_token_processes} 个未退出进程没有可解析的主令牌"),
        );
    }
    if exited_processes_skipped > 0 {
        push_warning(
            &mut warnings,
            format!("已跳过 {exited_processes_skipped} 个退出进程，避免把对象释放当作令牌异常"),
        );
    }
    if untrusted_token_structures > 0 {
        push_warning(
            &mut warnings,
            format!(
                "{untrusted_token_structures} 个唯一主令牌未通过对象类型或核心字段可信度门控；每个对象仅保留一条恢复证据"
            ),
        );
    }
    if unreadable_logon_session_references > 0 {
        push_warning(
            &mut warnings,
            format!(
                "{unreadable_logon_session_references} 个可信主令牌没有指向完整 SepLogonSessions 表中的节点"
            ),
        );
    }
    if truncated_group_lists > 0 {
        push_warning(
            &mut warnings,
            format!("{truncated_group_lists} 个令牌的组列表超过安全上限或恢复不完整"),
        );
    }
    if truncated {
        push_warning(
            &mut warnings,
            format!("令牌异常结果达到 {} 条上限", options.limit),
        );
    }
    warnings.truncate(MAX_WARNINGS);

    let complete = supported
        && process_report.complete
        && exact_profile_match
        && object_type_validation_available
        && missing_primary_token_processes == 0
        && untrusted_token_structures == 0
        && !truncated;
    let enrichment_complete = privilege_mapping_complete && logon_session_validation_available;
    let clean = complete && findings_matched == 0;
    let unfiltered_clean = complete && findings_detected == 0;
    let direct_clean = complete && direct_findings_detected == 0;
    let scope = if supported {
        "未退出进程的唯一主令牌；结构矛盾经精确内核配置与 TOKEN 可信度门控，权限和登录会话为可选增强"
            .to_owned()
    } else {
        "当前架构仅报告主令牌解析能力缺失，不产生令牌攻击结论".to_owned()
    };

    Ok(TokenAnomalyReport {
        records,
        supported,
        scope,
        direct_only: options.direct_only,
        min_severity: options.min_severity,
        processes_examined,
        active_processes_examined,
        exited_processes_skipped,
        primary_token_processes,
        unique_primary_tokens,
        missing_primary_token_processes,
        unsupported_primary_token_processes,
        trusted_token_structures,
        untrusted_token_structures,
        tokens_with_incomplete_core_fields,
        object_type_mismatches,
        unreadable_logon_session_references,
        truncated_group_lists,
        exact_profile_match,
        object_type_validation_available,
        privilege_mapping_available,
        privilege_mapping_complete,
        logon_session_validation_available,
        enrichment_complete,
        findings_detected,
        direct_findings_detected,
        contextual_signals_detected,
        recovery_findings_detected,
        findings_matched,
        tokens_matched,
        clean,
        unfiltered_clean,
        direct_clean,
        truncated,
        scan_seconds: started.elapsed().as_secs_f64(),
        complete,
        warnings,
    })
}

fn validate_token_structure(
    token: u64,
    details: &super::ProcessDetails,
    exact_profile_match: bool,
    space: Option<&X64AddressSpace<'_>>,
    decoder: Option<&ObjectHeaderDecoder>,
    profile: Option<&KernelProfile>,
) -> TokenValidation {
    let mut core_failures = Vec::new();
    if !is_kernel_pointer(token) {
        core_failures.push(format!("TOKEN 地址不是规范内核指针：{token:#x}"));
    }
    if details.token_id.is_none_or(|value| value == 0) {
        core_failures.push("TokenId 缺失或为零".to_owned());
    }
    if details.token_authentication_id.is_none() {
        core_failures.push("AuthenticationId 不可读".to_owned());
    }
    if details.user_sid.is_none() {
        core_failures.push("用户 SID 不可读".to_owned());
    }
    if details.token_source.is_none() {
        core_failures.push("TokenSource 不可读".to_owned());
    }
    if !matches!(
        details.token_type.as_deref(),
        Some("primary" | "impersonation")
    ) {
        core_failures.push(format!(
            "TokenType 无效：{}",
            details.token_type.as_deref().unwrap_or("unreadable")
        ));
    }
    if details.token_in_use.is_none() {
        core_failures.push("TokenInUse 不可读".to_owned());
    }
    if details.privileges_present.is_none()
        || details.privileges_enabled.is_none()
        || details.privileges_enabled_by_default.is_none()
    {
        core_failures.push("权限位图不完整".to_owned());
    }
    match (
        details.token_user_group_count,
        details.token_groups_recovered,
    ) {
        (Some(declared @ 1..=4096), Some(recovered)) if recovered == declared as usize => {}
        (Some(declared), Some(recovered)) => core_failures.push(format!(
            "用户/组恢复不自洽：declared={declared} recovered={recovered}"
        )),
        _ => core_failures.push("用户/组计数不可读".to_owned()),
    }
    if details.token_groups_truncated == Some(true) {
        core_failures.push("用户/组列表达到安全上限".to_owned());
    }
    let core_fields_complete = core_failures.is_empty();
    let mut failures = core_failures;
    if !exact_profile_match {
        failures.push("目标内核与配置的 CodeView GUID 不一致".to_owned());
    }

    let object_type = match (space, decoder, profile) {
        (Some(space), Some(decoder), Some(profile)) => {
            decoder.body_type_name(space, profile, token)
        }
        _ => None,
    };
    let object_type_mismatch = object_type
        .as_deref()
        .is_some_and(|name| !name.eq_ignore_ascii_case("Token"));
    if object_type_mismatch {
        failures.push(format!(
            "OBJECT_HEADER 类型为 {}，不是 Token",
            object_type.as_deref().unwrap_or("unknown")
        ));
    } else if decoder.is_some() && object_type.is_none() {
        failures.push("无法从 OBJECT_HEADER 解析对象类型".to_owned());
    }

    TokenValidation {
        trusted: failures.is_empty(),
        core_fields_complete,
        object_type,
        object_type_mismatch,
        failures,
    }
}

fn add_untrusted_token_finding(
    findings: &mut Vec<TokenAnomalyFinding>,
    token: u64,
    validation: &TokenValidation,
) {
    let (rule, category, severity, directly_proven, summary) = if validation.object_type_mismatch {
        (
            "primary_token_object_type_mismatch",
            "structure",
            TokenAnomalySeverity::Critical,
            true,
            "EPROCESS 主令牌指针的 OBJECT_HEADER 类型不是 Token",
        )
    } else {
        (
            "invalid_or_incomplete_primary_token",
            "recovery",
            TokenAnomalySeverity::High,
            false,
            "主令牌对象未通过可信度门控；不展开解释其类型、权限或身份位图",
        )
    };
    let mut evidence = vec![format!("TOKEN={token:#x}")];
    evidence.extend(validation.failures.iter().cloned());
    add_finding(
        findings,
        rule,
        category,
        severity,
        directly_proven,
        summary,
        evidence,
    );
}

fn build_record(
    token: u64,
    details: &super::ProcessDetails,
    owners: Vec<&ProcessRecord>,
    validation: TokenValidation,
    findings: Vec<TokenAnomalyFinding>,
) -> TokenAnomalyRecord {
    let mut record = TokenAnomalyRecord {
        token,
        structure_trusted: validation.trusted,
        object_type: validation.object_type,
        token_id: details.token_id,
        authentication_id_raw: details.token_authentication_id,
        authentication_id: details.token_authentication_id.map(format_luid),
        parent_token_id: details.token_parent_id,
        originating_logon_session: details.token_originating_logon_session,
        logon_session: details.token_logon_session,
        token_session_id: details.token_session_id,
        token_type: details.token_type.clone(),
        token_in_use: details.token_in_use,
        token_source: details.token_source.clone(),
        user_sid: details.user_sid.clone(),
        logon_sid: details.logon_sid.clone(),
        integrity_level: details.integrity_level.clone(),
        integrity_sid: details.integrity_sid.clone(),
        privileges_present: details.privileges_present,
        privileges_enabled: details.privileges_enabled,
        privileges_enabled_by_default: details.privileges_enabled_by_default,
        declared_group_count: details.token_user_group_count,
        recovered_group_count: details.token_groups_recovered,
        max_severity: TokenAnomalySeverity::Low,
        direct_finding_count: 0,
        contextual_signal_count: 0,
        recovery_finding_count: 0,
        findings,
        owners: owners.into_iter().map(owner_record).collect(),
    };
    refresh_record_finding_counts(&mut record);
    record
}

fn refresh_record_finding_counts(record: &mut TokenAnomalyRecord) {
    record.max_severity = record
        .findings
        .iter()
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(TokenAnomalySeverity::Low);
    record.direct_finding_count = record
        .findings
        .iter()
        .filter(|finding| finding.directly_proven)
        .count();
    record.recovery_finding_count = record
        .findings
        .iter()
        .filter(|finding| finding.category == "recovery")
        .count();
    record.contextual_signal_count = record
        .findings
        .len()
        .saturating_sub(record.direct_finding_count + record.recovery_finding_count);
}

fn owner_record(process: &ProcessRecord) -> TokenOwnerRecord {
    TokenOwnerRecord {
        pid: process.pid,
        ppid: process.ppid,
        process: process.name.clone(),
        eprocess: process.eprocess,
        peb_session_id: process.details.session_id,
        image_path: process.details.image_path.clone(),
        command_line: process.details.command_line.clone(),
    }
}

fn add_observation_consistency_findings(
    findings: &mut Vec<TokenAnomalyFinding>,
    owners: &[&ProcessRecord],
) {
    let observations = owners
        .iter()
        .map(|process| {
            let details = &process.details;
            (
                details.token_id,
                details.token_authentication_id,
                details.user_sid.as_deref(),
                details.token_session_id,
                details.token_type.as_deref(),
            )
        })
        .collect::<HashSet<_>>();
    if observations.len() > 1 {
        add_finding(
            findings,
            "shared_token_observation_mismatch",
            "structure",
            TokenAnomalySeverity::Critical,
            true,
            "同一 TOKEN 地址在不同进程观察到互相冲突的身份字段",
            vec![format!(
                "{} 个进程产生 {} 组观察值",
                owners.len(),
                observations.len()
            )],
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_structural_findings(
    findings: &mut Vec<TokenAnomalyFinding>,
    token: u64,
    details: &super::ProcessDetails,
    logon_entries: &BTreeMap<u64, u64>,
    logon_list_available: bool,
    logon_list_complete: bool,
    duplicate_token_addresses: Option<&BTreeSet<u64>>,
    authentication_user_sids: Option<&BTreeSet<String>>,
) {
    if details
        .token_type
        .as_deref()
        .is_some_and(|kind| kind != "primary")
    {
        add_finding(
            findings,
            "eprocess_token_not_primary",
            "structure",
            TokenAnomalySeverity::Critical,
            true,
            "EPROCESS 主令牌字段指向非 Primary Token",
            vec![format!(
                "TokenType={}",
                details.token_type.as_deref().unwrap_or("unknown")
            )],
        );
    }
    if let (Some(present), Some(enabled)) = (details.privileges_present, details.privileges_enabled)
    {
        let outside = enabled & !present;
        if outside != 0 {
            add_finding(
                findings,
                "enabled_privilege_outside_present",
                "privilege_bitmap",
                TokenAnomalySeverity::Critical,
                true,
                "令牌 Enabled 权限位出现在 Present 集合之外",
                vec![format!("outside_present={outside:#018x}")],
            );
        }
    }

    match details.token_logon_session {
        Some(address) => match logon_entries.get(&address) {
            Some(referenced_id)
                if details
                    .token_authentication_id
                    .is_some_and(|authentication_id| authentication_id != *referenced_id) =>
            {
                let authentication_id = details.token_authentication_id.unwrap_or_default();
                add_finding(
                    findings,
                    "logon_session_luid_mismatch",
                    "authentication",
                    TokenAnomalySeverity::Critical,
                    true,
                    "TOKEN.AuthenticationId 与已验证 SepLogonSessions 节点的 LogonId 不一致",
                    vec![
                        format!("AuthenticationId={}", format_luid(authentication_id)),
                        format!("LogonSession={address:#x}"),
                        format!("ReferencedLogonId={}", format_luid(*referenced_id)),
                    ],
                );
            }
            None if logon_list_complete => add_finding(
                findings,
                "unlisted_logon_session_reference",
                "recovery",
                TokenAnomalySeverity::High,
                false,
                "TOKEN.LogonSession 没有指向完整 SepLogonSessions 表中的节点",
                vec![format!("LogonSession={address:#x}")],
            ),
            _ => {}
        },
        None if logon_list_complete => add_finding(
            findings,
            "unverified_logon_session_reference",
            "recovery",
            TokenAnomalySeverity::High,
            false,
            "可信主令牌缺少可验证的 LogonSession 反向引用",
            vec![format!("TOKEN={token:#x}")],
        ),
        _ if !logon_list_available => {}
        _ => {}
    }

    if let (Some(authentication_id), Some(user_sid)) =
        (details.token_authentication_id, details.user_sid.as_deref())
        && let Some(expected_sid) = expected_well_known_user_sid(authentication_id)
        && user_sid != expected_sid
    {
        add_finding(
            findings,
            "well_known_authentication_sid_mismatch",
            "identity",
            TokenAnomalySeverity::Critical,
            true,
            "固定系统 AuthenticationId 与令牌用户 SID 不匹配",
            vec![
                format!("AuthenticationId={}", format_luid(authentication_id)),
                format!("expected_sid={expected_sid}"),
                format!("observed_sid={user_sid}"),
            ],
        );
    }
    if duplicate_token_addresses.is_some_and(|addresses| addresses.len() > 1) {
        add_finding(
            findings,
            "duplicate_nonzero_token_id",
            "structure",
            TokenAnomalySeverity::High,
            true,
            "同一非零 TokenId 出现在多个可信 TOKEN 地址",
            duplicate_token_addresses
                .unwrap()
                .iter()
                .map(|address| format!("TOKEN={address:#x}"))
                .collect(),
        );
    }
    if authentication_user_sids.is_some_and(|sids| sids.len() > 1) {
        add_finding(
            findings,
            "authentication_id_multiple_user_sids",
            "identity",
            TokenAnomalySeverity::High,
            false,
            "同一 AuthenticationId 关联多个用户 SID，需要结合令牌创建与登录上下文解释",
            authentication_user_sids
                .unwrap()
                .iter()
                .map(|sid| format!("SID={sid}"))
                .collect(),
        );
    }
}

fn add_contextual_findings(
    findings: &mut Vec<TokenAnomalyFinding>,
    details: &super::ProcessDetails,
    owners: &[&ProcessRecord],
    risk_privileges: &[RiskPrivilege],
) {
    for process in owners {
        if let (Some(peb), Some(token)) = (process.details.session_id, details.token_session_id)
            && peb != token
        {
            add_finding(
                findings,
                "peb_token_session_mismatch",
                "session",
                TokenAnomalySeverity::Medium,
                false,
                "PEB SessionId 与主令牌 SessionId 不同",
                vec![format!("PID={} PEB={peb} Token={token}", process.pid)],
            );
        }
        let name = process.name.to_ascii_lowercase();
        if is_core_system_process(&name)
            && details
                .user_sid
                .as_deref()
                .is_some_and(|sid| sid != "S-1-5-18")
        {
            add_finding(
                findings,
                "core_process_identity_mismatch",
                "identity",
                TokenAnomalySeverity::High,
                false,
                "核心系统进程名称关联的主令牌不是 LocalSystem SID",
                vec![format!(
                    "PID={} process={} SID={}",
                    process.pid,
                    process.name,
                    details.user_sid.as_deref().unwrap_or("unknown")
                )],
            );
        }
        if is_interactive_program(&name) && details.user_sid.as_deref() == Some("S-1-5-18") {
            add_finding(
                findings,
                "interactive_program_system_token",
                "identity",
                TokenAnomalySeverity::Medium,
                false,
                "交互式或双用途程序正以 LocalSystem 主令牌运行",
                vec![format!("PID={} process={}", process.pid, process.name)],
            );
        }
    }
    if details.integrity_level.as_deref() == Some("system")
        && details
            .user_sid
            .as_deref()
            .is_some_and(is_ordinary_account_sid)
    {
        add_finding(
            findings,
            "ordinary_account_system_integrity",
            "integrity",
            TokenAnomalySeverity::High,
            false,
            "普通账户主令牌具有 System 完整性级别",
            vec![format!(
                "SID={}",
                details.user_sid.as_deref().unwrap_or("unknown")
            )],
        );
    }

    let low_or_medium_integrity = matches!(
        details.integrity_level.as_deref(),
        Some("untrusted" | "low" | "medium" | "medium_plus")
    );
    if let (Some(enabled), Some(user_sid)) =
        (details.privileges_enabled, details.user_sid.as_deref())
        && is_ordinary_account_sid(user_sid)
        && low_or_medium_integrity
    {
        let enabled_risks = risk_privileges
            .iter()
            .filter(|privilege| enabled & (1u64 << privilege.bit) != 0)
            .collect::<Vec<_>>();
        if !enabled_risks.is_empty() {
            let severity = enabled_risks
                .iter()
                .map(|privilege| privilege.severity)
                .max()
                .unwrap_or(TokenAnomalySeverity::Medium);
            let mut evidence = vec![
                format!("SID={user_sid}"),
                format!(
                    "integrity={}",
                    details.integrity_level.as_deref().unwrap_or("unknown")
                ),
            ];
            evidence.extend(enabled_risks.iter().map(|privilege| {
                format!(
                    "{}: LUID.LowPart={} ({})",
                    privilege.name, privilege.bit, privilege.description
                )
            }));
            add_finding(
                findings,
                "risky_privileges_on_non_elevated_user_token",
                "privilege_exposure",
                severity,
                false,
                "低或中完整性普通账户令牌启用了一个或多个高风险权限",
                evidence,
            );
        }
    }
}

fn load_risk_privileges(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    space: Option<&X64AddressSpace<'_>>,
    exact_profile_match: bool,
) -> (Vec<RiskPrivilege>, bool, bool, Vec<String>) {
    let mut warnings = Vec::new();
    let Some(space) = space else {
        return (
            Vec::new(),
            false,
            false,
            vec!["当前架构无法读取目标内核权限 LUID 全局变量".to_owned()],
        );
    };
    if !exact_profile_match {
        return (
            Vec::new(),
            false,
            false,
            vec!["目标内核与当前配置的 CodeView GUID 不一致；不使用权限全局 RVA".to_owned()],
        );
    }
    // Re-check at the point where global RVAs are consumed. This keeps the
    // safety invariant local even if this helper is reused later.
    if !target_profile_matches(image, kernel, profile) {
        return (
            Vec::new(),
            false,
            false,
            vec!["无法再次确认目标内核 CodeView GUID；不使用权限全局 RVA".to_owned()],
        );
    }
    let mut privileges = Vec::new();
    for (name, severity, description) in RISK_PRIVILEGE_GLOBALS {
        let Some(rva) = profile.symbols.get(*name) else {
            push_warning(&mut warnings, format!("精确配置缺少 {name} 全局符号"));
            continue;
        };
        let Ok(luid) = space.read_u64(kernel.kernel_base + u64::from(*rva)) else {
            push_warning(&mut warnings, format!("无法读取目标内核 {name} LUID"));
            continue;
        };
        let low = luid as u32;
        let high = (luid >> 32) as u32;
        if high != 0 || low >= 64 {
            push_warning(
                &mut warnings,
                format!("目标内核 {name} LUID 不适合作为 64 位权限位图索引：{high:#x}:{low:#x}"),
            );
            continue;
        }
        privileges.push(RiskPrivilege {
            name: (*name).to_owned(),
            bit: low as u8,
            severity: *severity,
            description: (*description).to_owned(),
        });
    }
    let available = !privileges.is_empty();
    let complete = privileges.len() == RISK_PRIVILEGE_GLOBALS.len();
    (privileges, available, complete, warnings)
}

fn target_profile_matches(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
) -> bool {
    codeview_from_virtual_pe(image, kernel.directory_table_base, kernel.kernel_base)
        .ok()
        .is_some_and(|record| normalized_guid(&record.guid) == normalized_guid(&profile.pdb_guid))
}

fn add_finding(
    findings: &mut Vec<TokenAnomalyFinding>,
    rule: &str,
    category: &str,
    severity: TokenAnomalySeverity,
    directly_proven: bool,
    summary: &str,
    evidence: Vec<String>,
) {
    if let Some(existing) = findings.iter_mut().find(|finding| finding.rule == rule) {
        for item in evidence {
            if !existing.evidence.contains(&item) {
                existing.evidence.push(item);
            }
        }
        existing.severity = existing.severity.max(severity);
        existing.directly_proven |= directly_proven;
        return;
    }
    let evidence_class = if directly_proven {
        "structural_contradiction"
    } else if category == "recovery" {
        "incomplete_evidence"
    } else {
        "observed_risk"
    };
    findings.push(TokenAnomalyFinding {
        rule: rule.to_owned(),
        category: category.to_owned(),
        severity,
        directly_proven,
        evidence_class: evidence_class.to_owned(),
        summary: summary.to_owned(),
        evidence,
    });
}

fn expected_well_known_user_sid(authentication_id: u64) -> Option<&'static str> {
    match authentication_id {
        0x3e4 => Some("S-1-5-20"),
        0x3e5 => Some("S-1-5-19"),
        0x3e6 => Some("S-1-5-7"),
        0x3e7 => Some("S-1-5-18"),
        _ => None,
    }
}

fn is_ordinary_account_sid(sid: &str) -> bool {
    // Local and Active Directory user SIDs use the S-1-5-21 authority. Keep
    // service, app-container, virtual-account and window-manager identities
    // out of user-context heuristics unless a stronger identity resolver is
    // available.
    sid.starts_with("S-1-5-21-")
}

fn is_core_system_process(name: &str) -> bool {
    matches!(
        name,
        "system"
            | "registry"
            | "smss.exe"
            | "csrss.exe"
            | "wininit.exe"
            | "services.exe"
            | "lsass.exe"
            | "winlogon.exe"
            | "secure system"
            | "memcompression"
    )
}

fn is_interactive_program(name: &str) -> bool {
    matches!(
        name,
        "explorer.exe"
            | "cmd.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "winword.exe"
            | "excel.exe"
            | "powerpnt.exe"
            | "chrome.exe"
            | "msedge.exe"
            | "firefox.exe"
    )
}

fn format_luid(value: u64) -> String {
    format!("{:08x}:{:08x}", value >> 32, value as u32)
}

fn normalized_guid(value: &str) -> String {
    value
        .chars()
        .filter(|character| *character != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_details() -> super::super::ProcessDetails {
        super::super::ProcessDetails {
            token_id: Some(7),
            token_authentication_id: Some(0x1234),
            token_source: Some("User32".to_owned()),
            user_sid: Some("S-1-5-21-1-1001".to_owned()),
            token_user_group_count: Some(2),
            token_groups_recovered: Some(2),
            token_groups_truncated: Some(false),
            token_type: Some("primary".to_owned()),
            token_in_use: Some(true),
            privileges_present: Some(0b11),
            privileges_enabled: Some(0b01),
            privileges_enabled_by_default: Some(0b100),
            ..Default::default()
        }
    }

    #[test]
    fn core_quorum_accepts_default_privileges_outside_present() {
        let validation = validate_token_structure(
            0xffff_8000_0000_1000,
            &valid_details(),
            true,
            None,
            None,
            None,
        );
        assert!(validation.trusted);
    }

    #[test]
    fn incomplete_token_collapses_to_one_recovery_finding() {
        let validation = validate_token_structure(
            0xffff_8000_0000_1000,
            &super::super::ProcessDetails::default(),
            true,
            None,
            None,
            None,
        );
        let mut findings = Vec::new();
        add_untrusted_token_finding(&mut findings, 0xffff_8000_0000_1000, &validation);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "invalid_or_incomplete_primary_token");
        assert!(!findings[0].directly_proven);
    }

    #[test]
    fn fixed_system_luids_map_to_their_user_sids() {
        assert_eq!(expected_well_known_user_sid(0x3e4), Some("S-1-5-20"));
        assert_eq!(expected_well_known_user_sid(0x3e5), Some("S-1-5-19"));
        assert_eq!(expected_well_known_user_sid(0x3e6), Some("S-1-5-7"));
        assert_eq!(expected_well_known_user_sid(0x3e7), Some("S-1-5-18"));
        assert_eq!(expected_well_known_user_sid(0x1234), None);
    }

    #[test]
    fn ordinary_account_scope_excludes_service_and_window_manager_sids() {
        assert!(is_ordinary_account_sid("S-1-5-21-1-2-3-1001"));
        assert!(!is_ordinary_account_sid("S-1-5-18"));
        assert!(!is_ordinary_account_sid("S-1-5-80-123"));
        assert!(!is_ordinary_account_sid("S-1-5-90-0-1"));
    }

    #[test]
    fn finding_deduplication_merges_owner_evidence() {
        let mut findings = Vec::new();
        add_finding(
            &mut findings,
            "rule",
            "test",
            TokenAnomalySeverity::Medium,
            false,
            "summary",
            vec!["PID=1".to_owned()],
        );
        add_finding(
            &mut findings,
            "rule",
            "test",
            TokenAnomalySeverity::High,
            false,
            "summary",
            vec!["PID=2".to_owned()],
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, ["PID=1", "PID=2"]);
        assert_eq!(findings[0].severity, TokenAnomalySeverity::High);
    }

    #[test]
    fn severity_order_supports_threshold_filtering() {
        assert!(TokenAnomalySeverity::Critical > TokenAnomalySeverity::High);
        assert!(TokenAnomalySeverity::High > TokenAnomalySeverity::Medium);
        assert!(TokenAnomalySeverity::Medium > TokenAnomalySeverity::Low);
    }
}
