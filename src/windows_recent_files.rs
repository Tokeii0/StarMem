use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use serde::Serialize;

use crate::registry::RegistryValueData;
use crate::session::AnalysisSession;
use crate::system::registry::RegistryPrintRecord;
use crate::windows::plugins::HiveRecord;

const WPS_ROOT: &str = "Software\\Kingsoft\\Office\\6.0";
const RECENTDOCS_ROOT: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs";
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;
const MIN_REASONABLE_UNIX_SECONDS: i64 = 315_532_800;
const MAX_REASONABLE_UNIX_SECONDS: i64 = 4_102_444_800;
const MAX_WARNINGS: usize = 256;

#[derive(Debug, Clone)]
pub struct WindowsRecentFilesOptions {
    pub include_wps: bool,
    pub include_recentdocs: bool,
    pub user: Option<String>,
    pub path_contains: Option<String>,
    pub hive_limit: usize,
    pub registry_limit: usize,
    pub record_limit: usize,
}

impl Default for WindowsRecentFilesOptions {
    fn default() -> Self {
        Self {
            include_wps: true,
            include_recentdocs: true,
            user: None,
            path_contains: None,
            hive_limit: 65_536,
            registry_limit: 100_000,
            record_limit: 100_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsRecentFilesStage {
    Hives,
    Wps,
    RecentDocs,
    Finalize,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowsRecentFilesReport {
    pub image: String,
    pub filters: WindowsRecentFilesFilters,
    pub sources: Vec<WindowsRecentFilesSourceStatus>,
    pub matched_records: usize,
    pub records: Vec<WindowsRecentFileRecord>,
    pub truncated: bool,
    pub warnings_truncated: bool,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowsRecentFilesFilters {
    pub user: Option<String>,
    pub path_contains: Option<String>,
    pub include_wps: bool,
    pub include_recentdocs: bool,
    pub record_limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowsRecentFilesSourceStatus {
    pub source: String,
    pub user_sid: Option<String>,
    pub user_name: Option<String>,
    /// Kernel virtual address of the recovered `_CMHIVE` backing this source.
    pub cmhive: u64,
    pub available: bool,
    pub records_examined: usize,
    pub records_matched: usize,
    pub complete: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowsRecentFileRecord {
    pub source: String,
    pub suite: Option<String>,
    pub application: Option<String>,
    pub user_sid: Option<String>,
    pub user_name: Option<String>,
    pub hive: String,
    pub path: String,
    pub normalized_path: String,
    pub mru_rank: Option<usize>,
    pub timestamp_raw: Option<u64>,
    pub timestamp_encoding: Option<String>,
    pub timestamp_utc: Option<String>,
    pub timestamp_unix_ms: Option<i64>,
    pub timestamp_precision: Option<String>,
    pub time_semantics: String,
    pub timestamp_owner: String,
    pub evidence_class: String,
    pub confidence: String,
    pub registry_key: String,
    pub registry_value: String,
    pub container_key_last_write_raw: Option<u64>,
    pub container_key_last_write_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecentFilesHiveIdentity {
    pub hive: String,
    pub root_path: String,
    pub user_sid: Option<String>,
    pub user_name: Option<String>,
}

#[derive(Debug, Default)]
pub struct RecentFilesParseResult {
    pub records: Vec<WindowsRecentFileRecord>,
    pub records_examined: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

pub fn analyze_windows_recent_files<F>(
    session: &AnalysisSession,
    options: &WindowsRecentFilesOptions,
    mut progress: F,
) -> Result<WindowsRecentFilesReport>
where
    F: FnMut(WindowsRecentFilesStage),
{
    validate_options(options)?;
    progress(WindowsRecentFilesStage::Hives);
    let hive_report = session.hives(options.hive_limit)?;
    let mut complete = hive_report.complete;
    let mut warnings = hive_report.warnings;
    let mut sources = Vec::new();
    let mut records = Vec::new();
    let selected_hives = hive_report
        .records
        .into_iter()
        .filter(is_ntuser_hive)
        .map(|hive| (identity_from_hive(&hive), hive.cmhive, hive.root_path))
        .filter(|(identity, _, _)| identity_matches_user(identity, options.user.as_deref()))
        .collect::<Vec<_>>();

    if selected_hives.is_empty() {
        complete = false;
        push_warning(
            &mut warnings,
            match options.user.as_deref() {
                Some(user) => format!("没有找到与用户筛选 {user} 匹配的活动 NTUSER.DAT Hive"),
                None => "没有找到活动 NTUSER.DAT Hive".to_owned(),
            },
        );
    }

    for (identity, cmhive, hive_root_path) in selected_hives {
        if options.include_wps {
            progress(WindowsRecentFilesStage::Wps);
            append_registry_source(
                session,
                &identity,
                cmhive,
                &hive_root_path,
                WPS_ROOT,
                "registry.wps_recentfiles",
                options,
                parse_wps_recent_files,
                &mut records,
                &mut sources,
                &mut warnings,
                &mut complete,
            );
        }
        if options.include_recentdocs {
            progress(WindowsRecentFilesStage::RecentDocs);
            append_registry_source(
                session,
                &identity,
                cmhive,
                &hive_root_path,
                RECENTDOCS_ROOT,
                "registry.recentdocs",
                options,
                parse_recentdocs,
                &mut records,
                &mut sources,
                &mut warnings,
                &mut complete,
            );
        }
    }

    progress(WindowsRecentFilesStage::Finalize);
    records.sort_unstable_by(|left, right| {
        right
            .timestamp_unix_ms
            .cmp(&left.timestamp_unix_ms)
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| {
                left.mru_rank
                    .unwrap_or(usize::MAX)
                    .cmp(&right.mru_rank.unwrap_or(usize::MAX))
            })
            .then_with(|| left.normalized_path.cmp(&right.normalized_path))
    });
    let matched_records = records.len();
    let truncated = matched_records > options.record_limit;
    if truncated {
        records.truncate(options.record_limit);
        complete = false;
        push_warning(
            &mut warnings,
            format!(
                "最近文件匹配到 {matched_records} 条记录，达到 {} 条输出上限",
                options.record_limit
            ),
        );
    }

    let warnings_truncated = warnings.len() > MAX_WARNINGS;
    if warnings_truncated {
        warnings.truncate(MAX_WARNINGS);
        warnings.push(format!(
            "最近文件告警超过 {MAX_WARNINGS} 条；其余告警已抑制"
        ));
        complete = false;
    }

    Ok(WindowsRecentFilesReport {
        image: session.image().path().display().to_string(),
        filters: WindowsRecentFilesFilters {
            user: options.user.clone(),
            path_contains: options.path_contains.clone(),
            include_wps: options.include_wps,
            include_recentdocs: options.include_recentdocs,
            record_limit: options.record_limit,
        },
        sources,
        matched_records,
        records,
        truncated,
        warnings_truncated,
        complete,
        warnings,
    })
}

#[allow(clippy::too_many_arguments)]
fn append_registry_source(
    session: &AnalysisSession,
    identity: &RecentFilesHiveIdentity,
    cmhive: u64,
    hive_root_path: &str,
    key: &str,
    source_name: &str,
    options: &WindowsRecentFilesOptions,
    parser: fn(
        &[RegistryPrintRecord],
        &RecentFilesHiveIdentity,
        Option<&str>,
    ) -> RecentFilesParseResult,
    records: &mut Vec<WindowsRecentFileRecord>,
    sources: &mut Vec<WindowsRecentFilesSourceStatus>,
    warnings: &mut Vec<String>,
    complete: &mut bool,
) {
    match session.registry_print_key_exact_loaded(
        cmhive,
        hive_root_path,
        key,
        true,
        options.registry_limit,
    ) {
        Ok(registry) => {
            let mut parsed = parser(
                &registry.records,
                identity,
                options.path_contains.as_deref(),
            );
            let source_complete = registry.complete && parsed.complete;
            *complete &= source_complete;
            for warning in registry.warnings {
                push_warning(
                    warnings,
                    format!("{source_name}/{}：{warning}", identity_label(identity)),
                );
            }
            for warning in parsed.warnings.drain(..) {
                push_warning(
                    warnings,
                    format!("{source_name}/{}：{warning}", identity_label(identity)),
                );
            }
            sources.push(WindowsRecentFilesSourceStatus {
                source: source_name.to_owned(),
                user_sid: identity.user_sid.clone(),
                user_name: identity.user_name.clone(),
                cmhive,
                available: registry.available,
                records_examined: parsed.records_examined,
                records_matched: parsed.records.len(),
                complete: source_complete,
                error: None,
            });
            records.append(&mut parsed.records);
        }
        Err(error) => {
            let message = format!(
                "{source_name}/{}：无法读取 {key}：{error:#}",
                identity_label(identity)
            );
            push_warning(warnings, message.clone());
            sources.push(WindowsRecentFilesSourceStatus {
                source: source_name.to_owned(),
                user_sid: identity.user_sid.clone(),
                user_name: identity.user_name.clone(),
                cmhive,
                available: false,
                records_examined: 0,
                records_matched: 0,
                complete: false,
                error: Some(message),
            });
            *complete = false;
        }
    }
}

pub fn parse_wps_recent_files(
    registry_records: &[RegistryPrintRecord],
    identity: &RecentFilesHiveIdentity,
    path_contains: Option<&str>,
) -> RecentFilesParseResult {
    let mut result = RecentFilesParseResult {
        complete: true,
        ..RecentFilesParseResult::default()
    };
    for record in registry_records {
        let Some(application) = wps_sequence_application(&record.path) else {
            continue;
        };
        if record.kind != "value" || record.name.eq_ignore_ascii_case("(Default)") {
            continue;
        }
        result.records_examined += 1;
        let Some(RegistryValueData::String(raw_seconds)) = record.data.as_ref() else {
            result.complete = false;
            push_warning(
                &mut result.warnings,
                format!(
                    "WPS {application} Sequence 值 {} 不是字符串 Unix 秒",
                    record.name
                ),
            );
            continue;
        };
        let Ok(unix_seconds) = raw_seconds.trim().parse::<i64>() else {
            result.complete = false;
            push_warning(
                &mut result.warnings,
                format!(
                    "WPS {application} Sequence 值 {} 含无效 Unix 秒 {:?}",
                    record.name, raw_seconds
                ),
            );
            continue;
        };
        if !(MIN_REASONABLE_UNIX_SECONDS..=MAX_REASONABLE_UNIX_SECONDS).contains(&unix_seconds) {
            result.complete = false;
            push_warning(
                &mut result.warnings,
                format!(
                    "WPS {application} Sequence 值 {} 的 Unix 秒 {unix_seconds} 超出 1980-2100 合理范围",
                    record.name
                ),
            );
            continue;
        }
        let Some(timestamp) = DateTime::<Utc>::from_timestamp(unix_seconds, 0) else {
            result.complete = false;
            push_warning(
                &mut result.warnings,
                format!(
                    "WPS {application} Sequence 值 {} 的 Unix 秒 {unix_seconds} 无法转换",
                    record.name
                ),
            );
            continue;
        };
        if !path_matches(&record.name, path_contains) {
            continue;
        }
        result.records.push(WindowsRecentFileRecord {
            source: "registry.wps_recentfiles.sequence".to_owned(),
            suite: Some("wps".to_owned()),
            application: Some(application.to_owned()),
            user_sid: identity.user_sid.clone(),
            user_name: identity.user_name.clone(),
            hive: identity.hive.clone(),
            path: record.name.clone(),
            normalized_path: normalize_windows_path(&record.name),
            mru_rank: None,
            timestamp_raw: u64::try_from(unix_seconds).ok(),
            timestamp_encoding: Some("unix_seconds".to_owned()),
            timestamp_utc: Some(timestamp.to_rfc3339_opts(SecondsFormat::Secs, true)),
            timestamp_unix_ms: unix_seconds.checked_mul(1_000),
            timestamp_precision: Some("1s".to_owned()),
            time_semantics: "wps_recent_file_sequence_time".to_owned(),
            timestamp_owner: "registry_value_data".to_owned(),
            evidence_class: "direct_application_artifact".to_owned(),
            confidence: "high".to_owned(),
            registry_key: record.path.clone(),
            registry_value: record.name.clone(),
            container_key_last_write_raw: Some(record.last_write_raw),
            container_key_last_write_utc: filetime_to_utc(record.last_write_raw),
        });
    }
    result
}

pub fn parse_recentdocs(
    registry_records: &[RegistryPrintRecord],
    identity: &RecentFilesHiveIdentity,
    path_contains: Option<&str>,
) -> RecentFilesParseResult {
    let mut result = RecentFilesParseResult {
        complete: true,
        ..RecentFilesParseResult::default()
    };
    let mut groups = BTreeMap::<String, Vec<&RegistryPrintRecord>>::new();
    for record in registry_records {
        if is_recentdocs_key_path(&record.path) {
            groups.entry(record.path.clone()).or_default().push(record);
        }
    }

    for (key_path, group) in groups {
        let key_record = group.iter().copied().find(|record| record.kind == "key");
        let key_last_write_raw = key_record.map(|record| record.last_write_raw);
        let key_last_write_utc = key_last_write_raw.and_then(filetime_to_utc);
        let mut order = Vec::new();
        let mru_record = group
            .iter()
            .copied()
            .find(|record| record.kind == "value" && record.name.eq_ignore_ascii_case("MRUListEx"));
        if let Some(mru) = mru_record {
            match mru.data.as_ref() {
                Some(RegistryValueData::Binary(value)) => {
                    let parsed = parse_mru_list_ex(value);
                    order = parsed.order;
                    if let Some(warning) = parsed.warning {
                        result.complete = false;
                        push_warning(
                            &mut result.warnings,
                            format!("{key_path} MRUListEx：{warning}"),
                        );
                    }
                }
                _ => {
                    result.complete = false;
                    push_warning(
                        &mut result.warnings,
                        format!("{key_path} MRUListEx 不是 REG_BINARY"),
                    );
                }
            }
        }
        let ranks = order
            .iter()
            .enumerate()
            .map(|(rank, index)| (*index, rank))
            .collect::<BTreeMap<_, _>>();
        let mut numbered = BTreeMap::<u32, &RegistryPrintRecord>::new();
        for record in group {
            if record.kind != "value" || record.name.eq_ignore_ascii_case("MRUListEx") {
                continue;
            }
            let Ok(index) = record.name.parse::<u32>() else {
                continue;
            };
            result.records_examined += 1;
            numbered.insert(index, record);
        }
        if !numbered.is_empty() && mru_record.is_none() {
            result.complete = false;
            push_warning(
                &mut result.warnings,
                format!("{key_path} 含编号值但缺少 MRUListEx；只能保留无顺序条目"),
            );
        }
        if !numbered.is_empty() && key_record.is_none() {
            result.complete = false;
            push_warning(
                &mut result.warnings,
                format!("{key_path} 缺少键记录；无法确定所属键 LastWrite"),
            );
        }
        let mut indices = order;
        indices.extend(
            numbered
                .keys()
                .copied()
                .filter(|index| !ranks.contains_key(index)),
        );
        let mut emitted = BTreeSet::new();
        for index in indices {
            if !emitted.insert(index) {
                continue;
            }
            let Some(record) = numbered.get(&index).copied() else {
                result.complete = false;
                push_warning(
                    &mut result.warnings,
                    format!("{key_path} MRUListEx 引用不存在的值 {index}"),
                );
                continue;
            };
            let Some(path) = recentdocs_value_name(record) else {
                result.complete = false;
                push_warning(
                    &mut result.warnings,
                    format!("{key_path} 值 {index} 未能解析出 UTF-16 文件名"),
                );
                continue;
            };
            if !path_matches(&path, path_contains) {
                continue;
            }
            let rank = ranks.get(&index).copied();
            result.records.push(WindowsRecentFileRecord {
                source: "registry.recentdocs".to_owned(),
                suite: Some("windows_shell".to_owned()),
                application: None,
                user_sid: identity.user_sid.clone(),
                user_name: identity.user_name.clone(),
                hive: identity.hive.clone(),
                path: path.clone(),
                normalized_path: normalize_windows_path(&path),
                mru_rank: rank,
                timestamp_raw: None,
                timestamp_encoding: None,
                timestamp_utc: None,
                timestamp_unix_ms: None,
                timestamp_precision: None,
                time_semantics: if rank.is_some() {
                    "recentdocs_mru_order_only"
                } else {
                    "recentdocs_unranked_entry"
                }
                .to_owned(),
                timestamp_owner: "none".to_owned(),
                evidence_class: if rank.is_some() {
                    "ordering_only"
                } else {
                    "contextual"
                }
                .to_owned(),
                confidence: if rank.is_some() { "medium" } else { "low" }.to_owned(),
                registry_key: key_path.clone(),
                registry_value: record.name.clone(),
                container_key_last_write_raw: key_last_write_raw,
                container_key_last_write_utc: key_last_write_utc.clone(),
            });
        }
    }
    result
}

fn validate_options(options: &WindowsRecentFilesOptions) -> Result<()> {
    ensure!(
        options.include_wps || options.include_recentdocs,
        "至少选择一个最近文件证据来源"
    );
    ensure!(options.hive_limit > 0, "Hive 结果上限必须大于零");
    ensure!(options.registry_limit > 0, "注册表结果上限必须大于零");
    ensure!(options.record_limit > 0, "最近文件结果上限必须大于零");
    Ok(())
}

fn is_ntuser_hive(hive: &HiveRecord) -> bool {
    [&hive.file_path, &hive.user_name]
        .into_iter()
        .any(|name| name.to_ascii_lowercase().ends_with("\\ntuser.dat"))
}

fn identity_from_hive(hive: &HiveRecord) -> RecentFilesHiveIdentity {
    let hive_name = if !hive.user_name.is_empty() {
        hive.user_name.clone()
    } else if !hive.file_path.is_empty() {
        hive.file_path.clone()
    } else {
        hive.root_path.clone()
    };
    RecentFilesHiveIdentity {
        hive: hive_name.clone(),
        root_path: hive.root_path.clone(),
        user_sid: sid_from_root_path(&hive.root_path),
        user_name: user_name_from_hive_path(&hive_name),
    }
}

pub fn identity_matches_user(identity: &RecentFilesHiveIdentity, filter: Option<&str>) -> bool {
    let Some(filter) = filter.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    identity
        .user_sid
        .as_deref()
        .is_some_and(|sid| sid.eq_ignore_ascii_case(filter))
        || identity
            .user_name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(filter))
}

fn sid_from_root_path(root_path: &str) -> Option<String> {
    root_path
        .replace('/', "\\")
        .rsplit('\\')
        .find(|component| !component.is_empty())
        .filter(|component| component.to_ascii_uppercase().starts_with("S-1-"))
        .filter(|component| !component.to_ascii_lowercase().ends_with("_classes"))
        .map(str::to_owned)
}

fn user_name_from_hive_path(path: &str) -> Option<String> {
    let normalized = path.replace('/', "\\");
    let components = normalized
        .split('\\')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    let ntuser = components
        .iter()
        .position(|component| component.eq_ignore_ascii_case("ntuser.dat"))?;
    ntuser
        .checked_sub(1)
        .and_then(|index| components.get(index))
        .map(|name| (*name).to_owned())
}

fn identity_label(identity: &RecentFilesHiveIdentity) -> &str {
    identity
        .user_name
        .as_deref()
        .or(identity.user_sid.as_deref())
        .unwrap_or(identity.hive.as_str())
}

fn wps_sequence_application(path: &str) -> Option<&str> {
    let components = path.split(['\\', '/']).collect::<Vec<_>>();
    if components.len() != 7
        || !components[0].eq_ignore_ascii_case("Software")
        || !components[1].eq_ignore_ascii_case("Kingsoft")
        || !components[2].eq_ignore_ascii_case("Office")
        || !components[3].eq_ignore_ascii_case("6.0")
        || !components[5].eq_ignore_ascii_case("RecentFiles")
        || !components[6].eq_ignore_ascii_case("Sequence")
    {
        return None;
    }
    let application = components[4];
    ["et", "wps", "wpp", "pdf", "ofd"]
        .into_iter()
        .find(|candidate| application.eq_ignore_ascii_case(candidate))
}

fn is_recentdocs_key_path(path: &str) -> bool {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();
    let root = RECENTDOCS_ROOT.to_ascii_lowercase();
    normalized == root || normalized.starts_with(&(root + "\\"))
}

fn recentdocs_value_name(record: &RegistryPrintRecord) -> Option<String> {
    let RegistryValueData::Binary(value) = record.data.as_ref()? else {
        return None;
    };
    decode_utf16_prefix_hex(value)
}

fn decode_utf16_prefix_hex(value: &str) -> Option<String> {
    let bytes = hex::decode(value).ok()?;
    let mut units = Vec::new();
    let mut terminated = false;
    for pair in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            terminated = true;
            break;
        }
        units.push(unit);
    }
    (terminated && !units.is_empty()).then(|| String::from_utf16_lossy(&units))
}

struct ParsedMruList {
    order: Vec<u32>,
    warning: Option<String>,
}

fn parse_mru_list_ex(value: &str) -> ParsedMruList {
    let Ok(bytes) = hex::decode(value) else {
        return ParsedMruList {
            order: Vec::new(),
            warning: Some("包含无效十六进制数据".to_owned()),
        };
    };
    let mut order = Vec::new();
    let mut seen = BTreeSet::new();
    let mut duplicate = false;
    let mut terminated = false;
    for chunk in bytes.chunks_exact(4) {
        let index = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if index == u32::MAX {
            terminated = true;
            break;
        }
        if seen.insert(index) {
            order.push(index);
        } else {
            duplicate = true;
        }
    }
    let mut issues = Vec::new();
    if bytes.len() % 4 != 0 {
        issues.push("长度不是4字节的整数倍");
    }
    if !terminated {
        issues.push("缺少 0xffffffff 终止值");
    }
    if duplicate {
        issues.push("包含重复 MRU 索引；已保留首次排名");
    }
    let warning = (!issues.is_empty()).then(|| issues.join("；"));
    ParsedMruList { order, warning }
}

fn normalize_windows_path(path: &str) -> String {
    path.trim().replace('/', "\\").to_lowercase()
}

fn path_matches(path: &str, filter: Option<&str>) -> bool {
    let Some(filter) = filter.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    normalize_windows_path(path).contains(&normalize_windows_path(filter))
}

fn filetime_to_utc(value: u64) -> Option<String> {
    let ticks = value.checked_sub(FILETIME_UNIX_EPOCH)?;
    let seconds = i64::try_from(ticks / FILETIME_TICKS_PER_SECOND).ok()?;
    let nanos = u32::try_from((ticks % FILETIME_TICKS_PER_SECOND) * 100).ok()?;
    let timestamp = DateTime::<Utc>::from_timestamp(seconds, nanos)?;
    ((1980..=2100).contains(&timestamp.year()))
        .then(|| timestamp.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(warning);
    } else if warnings.len() == MAX_WARNINGS {
        warnings.push(format!(
            "最近文件告警达到 {MAX_WARNINGS} 条；其余告警已抑制"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> RecentFilesHiveIdentity {
        RecentFilesHiveIdentity {
            hive: "\\??\\C:\\Users\\testuser\\ntuser.dat".to_owned(),
            root_path: "\\Registry\\User\\S-1-5-21-109037057-71577298-1195537789-1000".to_owned(),
            user_sid: Some("S-1-5-21-109037057-71577298-1195537789-1000".to_owned()),
            user_name: Some("testuser".to_owned()),
        }
    }

    fn key(path: &str, name: &str, last_write_raw: u64) -> RegistryPrintRecord {
        RegistryPrintRecord {
            cmhive: None,
            cell_index: 0,
            key_cell_index: 0,
            key_identity: None,
            depth: 0,
            kind: "key".to_owned(),
            path: path.to_owned(),
            name: name.to_owned(),
            data_type: None,
            data_type_name: None,
            data: None,
            last_write_raw,
            last_write: None,
        }
    }

    fn string_value(
        path: &str,
        name: &str,
        value: &str,
        last_write_raw: u64,
    ) -> RegistryPrintRecord {
        RegistryPrintRecord {
            cmhive: None,
            cell_index: 0,
            key_cell_index: 0,
            key_identity: None,
            depth: 1,
            kind: "value".to_owned(),
            path: path.to_owned(),
            name: name.to_owned(),
            data_type: Some(1),
            data_type_name: Some("REG_SZ".to_owned()),
            data: Some(RegistryValueData::String(value.to_owned())),
            last_write_raw,
            last_write: None,
        }
    }

    fn binary_value(
        path: &str,
        name: &str,
        value: &str,
        last_write_raw: u64,
    ) -> RegistryPrintRecord {
        RegistryPrintRecord {
            cmhive: None,
            cell_index: 0,
            key_cell_index: 0,
            key_identity: None,
            depth: 1,
            kind: "value".to_owned(),
            path: path.to_owned(),
            name: name.to_owned(),
            data_type: Some(3),
            data_type_name: Some("REG_BINARY".to_owned()),
            data: Some(RegistryValueData::Binary(value.to_owned())),
            last_write_raw,
            last_write: None,
        }
    }

    fn utf16_hex(value: &str) -> String {
        let mut bytes = value
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        bytes.extend_from_slice(&[0, 0]);
        hex::encode_upper(bytes)
    }

    #[test]
    fn parses_wps_sequence_timestamp_without_using_key_last_write() {
        let path = "Software\\Kingsoft\\Office\\6.0\\et\\RecentFiles\\Sequence";
        let key_last_write = 133_317_540_299_845_480;
        let records = vec![
            key(path, "Sequence", key_last_write),
            string_value(path, "F:/示例表格.xlsx", "1687278594", key_last_write),
            string_value(path, "F:/代理列表.xlsx", "1687280429", key_last_write),
        ];

        let parsed = parse_wps_recent_files(&records, &identity(), Some("示例表格.xlsx"));

        assert!(parsed.complete);
        assert_eq!(parsed.records_examined, 2);
        assert_eq!(parsed.records.len(), 1);
        let record = &parsed.records[0];
        assert_eq!(record.application.as_deref(), Some("et"));
        assert_eq!(record.timestamp_raw, Some(1_687_278_594));
        assert_eq!(
            record.timestamp_utc.as_deref(),
            Some("2023-06-20T16:29:54Z")
        );
        assert_eq!(record.timestamp_owner, "registry_value_data");
        assert_eq!(record.time_semantics, "wps_recent_file_sequence_time");
        assert_eq!(record.evidence_class, "direct_application_artifact");
        assert_eq!(record.container_key_last_write_raw, Some(key_last_write));
        assert_eq!(
            record.container_key_last_write_utc.as_deref(),
            Some("2023-06-20T17:00:29.984Z")
        );
    }

    #[test]
    fn rejects_invalid_wps_sequence_times() {
        let path = "Software\\Kingsoft\\Office\\6.0\\wps\\RecentFiles\\Sequence";
        let records = vec![
            string_value(path, "C:/bad.docx", "not-a-time", 0),
            string_value(path, "C:/old.docx", "1", 0),
        ];

        let parsed = parse_wps_recent_files(&records, &identity(), None);

        assert!(!parsed.complete);
        assert!(parsed.records.is_empty());
        assert_eq!(parsed.records_examined, 2);
        assert_eq!(parsed.warnings.len(), 2);
    }

    #[test]
    fn recognizes_every_supported_wps_application() {
        let mut records = Vec::new();
        for application in ["et", "wps", "wpp", "pdf", "ofd"] {
            let path =
                format!("Software\\Kingsoft\\Office\\6.0\\{application}\\RecentFiles\\Sequence");
            records.push(string_value(
                &path,
                &format!("C:/{application}/evidence.bin"),
                "1687278594",
                133_317_540_299_845_480,
            ));
        }

        let parsed = parse_wps_recent_files(&records, &identity(), None);
        let applications = parsed
            .records
            .iter()
            .filter_map(|record| record.application.as_deref())
            .collect::<BTreeSet<_>>();

        assert!(parsed.complete);
        assert_eq!(
            applications,
            BTreeSet::from(["et", "ofd", "pdf", "wpp", "wps"])
        );
    }

    #[test]
    fn recentdocs_preserves_order_but_never_assigns_parent_key_time_to_a_file() {
        let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.xlsx";
        let key_last_write = 133_317_539_108_487_338;
        let records = vec![
            key(path, ".xlsx", key_last_write),
            binary_value(
                path,
                "MRUListEx",
                "0100000000000000FFFFFFFF",
                key_last_write,
            ),
            binary_value(path, "0", &utf16_hex("示例表格.xlsx"), key_last_write),
            binary_value(path, "1", &utf16_hex("代理列表.xlsx"), key_last_write),
        ];

        let parsed = parse_recentdocs(&records, &identity(), None);

        assert!(parsed.complete);
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[0].path, "代理列表.xlsx");
        assert_eq!(parsed.records[0].mru_rank, Some(0));
        assert_eq!(parsed.records[1].path, "示例表格.xlsx");
        assert_eq!(parsed.records[1].mru_rank, Some(1));
        for record in &parsed.records {
            assert_eq!(record.timestamp_raw, None);
            assert_eq!(record.timestamp_utc, None);
            assert_eq!(record.timestamp_owner, "none");
            assert_eq!(record.time_semantics, "recentdocs_mru_order_only");
            assert_eq!(record.evidence_class, "ordering_only");
            assert_eq!(record.container_key_last_write_raw, Some(key_last_write));
            assert_eq!(
                record.container_key_last_write_utc.as_deref(),
                Some("2023-06-20T16:58:30.848Z")
            );
        }
    }

    #[test]
    fn filters_by_user_name_sid_and_unicode_path() {
        let identity = identity();
        assert!(identity_matches_user(&identity, Some("testuser")));
        assert!(identity_matches_user(
            &identity,
            Some("S-1-5-21-109037057-71577298-1195537789-1000")
        ));
        assert!(!identity_matches_user(&identity, Some("other")));
        assert!(path_matches("F:/示例表格.xlsx", Some("示例表格.XLSX")));
    }

    #[test]
    fn malformed_mru_list_is_best_effort_and_marks_source_incomplete() {
        let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs";
        let records = vec![
            key(path, "RecentDocs", 133_317_539_108_567_343),
            binary_value(path, "MRUListEx", "00000000", 133_317_539_108_567_343),
            binary_value(path, "0", &utf16_hex("readme.txt"), 133_317_539_108_567_343),
        ];

        let parsed = parse_recentdocs(&records, &identity(), None);

        assert!(!parsed.complete);
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].mru_rank, Some(0));
        assert!(parsed.warnings[0].contains("终止值"));
    }

    #[test]
    fn duplicate_mru_indexes_keep_the_first_rank_and_report_damage() {
        let parsed = parse_mru_list_ex("000000000100000000000000ffffffff");
        assert_eq!(parsed.order, vec![0, 1]);
        assert!(
            parsed
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("重复 MRU 索引"))
        );
    }
}
