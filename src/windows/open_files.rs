use std::collections::{HashMap, HashSet};

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::session::AnalysisSession;

use super::plugins::find_handle_owners;

#[derive(Debug, Clone)]
pub struct OpenFileOptions {
    pub path_contains: Option<String>,
    pub process_contains: Option<String>,
    pub file_scan_limit: usize,
    pub process_limit: usize,
    pub handle_scan_limit: usize,
    pub result_limit: usize,
    pub include_unowned: bool,
}

impl Default for OpenFileOptions {
    fn default() -> Self {
        Self {
            path_contains: None,
            process_contains: None,
            file_scan_limit: 1_000_000,
            process_limit: 65_536,
            handle_scan_limit: 4_000_000,
            result_limit: 100_000,
            include_unowned: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenFileRecord {
    pub file_object: u64,
    pub file_physical_address: u64,
    pub path: Option<String>,
    pub pid: Option<u64>,
    pub process: Option<String>,
    pub user_name: Option<String>,
    pub user_sid: Option<String>,
    pub process_create_time: Option<String>,
    pub handle: Option<u32>,
    pub granted_access: Option<u32>,
    pub relationship: String,
    pub time_semantics: String,
    pub timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OpenFileReport {
    pub records: Vec<OpenFileRecord>,
    pub files_examined: usize,
    pub matching_file_objects: usize,
    /// All handle owners recovered for matching FILE_OBJECTs before the
    /// optional process-name filter.
    pub owners_found: usize,
    /// Owner records retained after the optional process-name filter.
    pub owner_matches: usize,
    pub processes_examined: usize,
    pub handle_entries_examined: usize,
    pub truncated: bool,
    pub complete: bool,
    pub warnings: Vec<String>,
}

pub fn scan_open_files(
    session: &AnalysisSession,
    options: &OpenFileOptions,
) -> Result<OpenFileReport> {
    ensure!(options.file_scan_limit > 0, "文件扫描上限必须大于零");
    ensure!(options.process_limit > 0, "进程扫描上限必须大于零");
    ensure!(options.handle_scan_limit > 0, "句柄扫描上限必须大于零");
    ensure!(options.result_limit > 0, "结果上限必须大于零");

    let files = session.files(options.file_scan_limit)?;
    let files_examined = files.records.len();
    let path_filter = options
        .path_contains
        .as_deref()
        .map(normalize_filter)
        .filter(|value| !value.is_empty());
    let process_filter = options
        .process_contains
        .as_deref()
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty());

    let matching = files
        .records
        .iter()
        .filter(|record| {
            path_filter.as_ref().is_none_or(|needle| {
                record
                    .name
                    .as_deref()
                    .map(normalize_filter)
                    .is_some_and(|path| path.contains(needle))
            })
        })
        .collect::<Vec<_>>();
    let targets = matching
        .iter()
        .map(|record| record.file_object)
        .collect::<HashSet<_>>();
    let by_object = matching
        .iter()
        .map(|record| (record.file_object, *record))
        .collect::<HashMap<_, _>>();

    let owners = find_handle_owners(
        session.image(),
        session.kernel(),
        session.profile(),
        &targets,
        options.process_limit,
        options.handle_scan_limit,
    )?;
    let owners_found = owners.records.len();
    let mut owned_objects = HashSet::new();
    let mut records = Vec::new();

    for owner in &owners.records {
        if process_filter
            .as_ref()
            .is_some_and(|needle| !owner.process.to_lowercase().contains(needle))
        {
            continue;
        }
        let Some(file) = by_object.get(&owner.object) else {
            continue;
        };
        owned_objects.insert(owner.object);
        records.push(OpenFileRecord {
            file_object: owner.object,
            file_physical_address: file.physical_address,
            path: file.name.clone(),
            pid: Some(owner.pid),
            process: Some(owner.process.clone()),
            user_name: owner.user_name.clone(),
            user_sid: owner.user_sid.clone(),
            process_create_time: owner.process_create_time.clone(),
            handle: Some(owner.handle),
            granted_access: Some(owner.granted_access),
            relationship: "active_file_handle".to_owned(),
            time_semantics: "open_handle_observed_at_capture".to_owned(),
            timestamp: None,
        });
    }
    let owner_matches = records.len();

    if options.include_unowned && process_filter.is_none() {
        for file in matching
            .iter()
            .filter(|file| !owned_objects.contains(&file.file_object))
        {
            records.push(OpenFileRecord {
                file_object: file.file_object,
                file_physical_address: file.physical_address,
                path: file.name.clone(),
                pid: None,
                process: None,
                user_name: None,
                user_sid: None,
                process_create_time: None,
                handle: None,
                granted_access: None,
                relationship: if owners.complete {
                    "resident_file_object_without_active_handle_owner"
                } else {
                    "resident_file_object_without_recovered_handle_owner"
                }
                .to_owned(),
                time_semantics: "file_object_observed_in_memory".to_owned(),
                timestamp: None,
            });
        }
    }

    records.sort_unstable_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.pid.cmp(&right.pid))
            .then_with(|| left.handle.cmp(&right.handle))
    });
    let truncated = records.len() > options.result_limit;
    records.truncate(options.result_limit);

    let mut warnings = files.warnings;
    warnings.extend(owners.warnings);
    if options.include_unowned && !owners.complete {
        warnings.push(
            "句柄所有者扫描不完整；未关联对象只表示“未恢复到 owner”，不是“确定无活动 owner”"
                .to_owned(),
        );
    }
    if truncated {
        warnings.push(format!(
            "打开文件结果超过 {} 条，仅保留前 {} 条",
            options.result_limit, options.result_limit
        ));
    }

    Ok(OpenFileReport {
        records,
        files_examined,
        matching_file_objects: targets.len(),
        owners_found,
        owner_matches,
        processes_examined: owners.processes_examined,
        handle_entries_examined: owners.handle_entries_examined,
        truncated,
        complete: files.complete && owners.complete && !truncated,
        warnings,
    })
}

fn normalize_filter(value: &str) -> String {
    value.trim().replace('/', "\\").to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::normalize_filter;

    #[test]
    fn path_filter_is_case_and_separator_insensitive() {
        assert_eq!(normalize_filter(" F:/示例表格.XLSX "), "f:\\示例表格.xlsx");
    }
}
