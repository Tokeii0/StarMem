use std::collections::{HashMap, HashSet};
use std::time::Instant;

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::address::X64AddressSpace;
use crate::session::AnalysisSession;
use crate::windows::files::{
    DumpSource, FileScanRecord, RecoveredExtent, recover_file_bytes, scan_files_matching,
};

const PROCESS_ENUMERATION_LIMIT: usize = 65_536;
const MAX_WARNING_COUNT: usize = 128;

#[derive(Debug, Clone, Copy)]
pub struct TerminalHistoryOptions {
    pub limit: usize,
    pub file_scan_limit: usize,
    pub history_file_limit: usize,
    pub max_history_file_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalHistoryStage {
    Processes,
    ConsoleHistories,
    FileObjects,
    HistoryFiles,
    Aggregate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalKind {
    WindowsTerminal,
    OpenConsole,
    PowerShell,
    Pwsh,
    Cmd,
    Conhost,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalProcessRole {
    Frontend,
    ConsoleHost,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalHistorySource {
    ConsoleHistory,
    ConsoleMemoryFallback,
    PsReadLineFile,
}

#[derive(Debug, Clone, Serialize)]
pub struct TerminalProcessRecord {
    pub kind: TerminalKind,
    pub role: TerminalProcessRole,
    pub pid: u64,
    pub ppid: Option<u64>,
    pub process: String,
    pub session_id: Option<u32>,
    pub user_sid: Option<String>,
    pub user_name: Option<String>,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
    pub create_time: Option<String>,
    pub frontend: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TerminalHistoryRecord {
    pub source: TerminalHistorySource,
    pub terminal_kind: TerminalKind,
    pub frontend: Option<String>,
    pub terminal_pid: Option<u64>,
    pub terminal_process: Option<String>,
    pub host_pid: Option<u64>,
    pub host_process: Option<String>,
    pub user_name: Option<String>,
    pub user_sid: Option<String>,
    pub application: Option<String>,
    pub command_index: usize,
    pub command: String,
    pub history_address: Option<u64>,
    pub virtual_address: Option<u64>,
    pub physical_addresses: Vec<u64>,
    pub source_file: Option<String>,
    pub file_objects: Vec<u64>,
    pub file_offset: Option<u64>,
    pub confidence: String,
    pub evidence: String,
}

#[derive(Debug, Serialize)]
pub struct TerminalHistoryStatistics {
    pub terminal_processes: usize,
    pub console_hosts: usize,
    pub console_history_buffers: usize,
    pub console_memory_fallback_groups: usize,
    pub psreadline_files_found: usize,
    pub psreadline_files_parsed: usize,
}

#[derive(Debug, Serialize)]
pub struct TerminalHistoryTiming {
    pub process_seconds: f64,
    pub console_history_seconds: f64,
    pub file_scan_seconds: f64,
    pub history_file_seconds: f64,
    pub aggregation_seconds: f64,
    pub total_seconds: f64,
}

#[derive(Debug, Serialize)]
pub struct TerminalHistoryReport {
    pub records: Vec<TerminalHistoryRecord>,
    pub terminal_processes: Vec<TerminalProcessRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
    pub statistics: TerminalHistoryStatistics,
    pub timing: TerminalHistoryTiming,
}

#[derive(Debug)]
struct ProcessFact {
    pid: u64,
    ppid: Option<u64>,
    kind: TerminalKind,
    process: String,
    user_sid: Option<String>,
    user_name: Option<String>,
    user_profile: Option<String>,
    dtb: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
enum TextEncoding {
    Utf8 { bom: usize },
    Utf16Le { bom: usize },
    Utf16Be { bom: usize },
}

#[derive(Debug)]
struct ParsedCommand {
    index: usize,
    file_offset: u64,
    command: String,
}

pub fn analyze_terminal_history<F>(
    session: &AnalysisSession,
    options: &TerminalHistoryOptions,
    mut progress: F,
) -> Result<TerminalHistoryReport>
where
    F: FnMut(TerminalHistoryStage),
{
    ensure!(options.limit > 0, "终端历史结果数量上限必须大于零");
    ensure!(
        options.file_scan_limit > 0,
        "文件扫描结果数量上限必须大于零"
    );
    ensure!(
        options.history_file_limit > 0,
        "PSReadLine 历史文件数量上限必须大于零"
    );
    ensure!(
        options.max_history_file_size > 0,
        "PSReadLine 历史文件最大恢复大小必须大于零"
    );
    let started = Instant::now();
    let mut complete = true;
    let mut warnings = Vec::new();

    progress(TerminalHistoryStage::Processes);
    let process_started = Instant::now();
    let process_report = session.processes(PROCESS_ENUMERATION_LIMIT)?;
    complete &= process_report.complete;
    for warning in &process_report.warnings {
        push_warning(
            &mut warnings,
            format!("进程枚举/{}：{}", warning.kind, warning.message),
        );
    }
    let facts = process_report
        .processes
        .iter()
        .map(|process| {
            let kind =
                terminal_kind_from_process(&process.name, process.details.image_path.as_deref());
            (
                process.pid,
                ProcessFact {
                    pid: process.pid,
                    ppid: process.ppid,
                    kind,
                    process: process.name.clone(),
                    user_sid: process.details.user_sid.clone(),
                    user_name: process.details.environment_user_name.clone(),
                    user_profile: process.details.environment_user_profile.clone(),
                    dtb: process
                        .details
                        .user_directory_table_base
                        .or(process.details.directory_table_base),
                },
            )
        })
        .collect::<HashMap<_, _>>();
    let mut terminal_processes = process_report
        .processes
        .iter()
        .filter_map(|process| {
            let kind =
                terminal_kind_from_process(&process.name, process.details.image_path.as_deref());
            let role = terminal_process_role(kind)?;
            Some(TerminalProcessRecord {
                kind,
                role,
                pid: process.pid,
                ppid: process.ppid,
                process: process.name.clone(),
                session_id: process.details.session_id,
                user_sid: process.details.user_sid.clone(),
                user_name: process.details.environment_user_name.clone(),
                image_path: process.details.image_path.clone(),
                command_line: process.details.command_line.clone(),
                create_time: process.details.create_time.clone(),
                frontend: process_frontend(process.pid, &facts),
            })
        })
        .collect::<Vec<_>>();
    terminal_processes.sort_unstable_by_key(|process| process.pid);
    let process_seconds = process_started.elapsed().as_secs_f64();

    progress(TerminalHistoryStage::ConsoleHistories);
    let console_started = Instant::now();
    let console_report = session.command_histories(options.limit)?;
    complete &= console_report.complete;
    let mut empty_console_hosts = 0usize;
    for warning in &console_report.warnings {
        if warning.starts_with("PID ")
            && warning.contains("存在可读的")
            && warning.contains("未找到有效的")
        {
            empty_console_hosts += 1;
        } else {
            push_warning(&mut warnings, format!("控制台历史：{warning}"));
        }
    }
    if empty_console_hosts != 0 {
        push_warning(
            &mut warnings,
            format!(
                "控制台历史：{empty_console_hosts} 个控制台宿主存在可读映射，但未恢复到有效历史结构或命令字符串"
            ),
        );
    }
    let console_history_buffers = console_report
        .records
        .iter()
        .filter(|history| history.application.as_deref() != Some("原始 UTF-16 命令字符串回退"))
        .count();
    let console_memory_fallback_groups = console_report
        .records
        .len()
        .saturating_sub(console_history_buffers);
    let mut records = Vec::new();
    for history in &console_report.records {
        let fallback = history.application.as_deref() == Some("原始 UTF-16 命令字符串回退");
        let application_kind = history
            .application
            .as_deref()
            .map(terminal_kind_from_application)
            .unwrap_or(TerminalKind::Unknown);
        let associated = associate_console_shell(history.conhost_pid, application_kind, &facts);
        let host = facts.get(&history.conhost_pid);
        let terminal_kind = associated
            .and_then(|pid| facts.get(&pid).map(|process| process.kind))
            .filter(|kind| is_shell_kind(*kind))
            .unwrap_or(application_kind);
        let frontend = associated
            .and_then(|pid| process_frontend(pid, &facts))
            .or_else(|| process_frontend(history.conhost_pid, &facts));
        let user_sid = associated
            .and_then(|pid| facts.get(&pid))
            .and_then(|process| process.user_sid.clone())
            .or_else(|| host.and_then(|process| process.user_sid.clone()));
        let user_name = associated
            .and_then(|pid| facts.get(&pid))
            .and_then(|process| process.user_name.clone())
            .or_else(|| host.and_then(|process| process.user_name.clone()));
        for command in &history.commands {
            let physical_addresses = translate_process_address(
                session,
                host.and_then(|process| process.dtb),
                command.address,
            )
            .into_iter()
            .collect();
            records.push(TerminalHistoryRecord {
                source: if fallback {
                    TerminalHistorySource::ConsoleMemoryFallback
                } else {
                    TerminalHistorySource::ConsoleHistory
                },
                terminal_kind,
                frontend: frontend.clone(),
                terminal_pid: associated,
                terminal_process: associated
                    .and_then(|pid| facts.get(&pid))
                    .map(|process| process.process.clone()),
                host_pid: Some(history.conhost_pid),
                host_process: Some(history.conhost.clone()),
                user_name: user_name.clone(),
                user_sid: user_sid.clone(),
                application: history.application.clone(),
                command_index: command.index,
                command: command.text.clone(),
                history_address: Some(history.address),
                virtual_address: Some(command.address),
                physical_addresses,
                source_file: None,
                file_objects: Vec::new(),
                file_offset: None,
                confidence: if fallback { "medium" } else { "high" }.to_owned(),
                evidence: if fallback {
                    "控制台宿主私有 VAD 中经过严格命令语法筛选的 UTF-16 字符串；未恢复到完整历史结构"
                } else {
                    "已验证的控制台命令历史结构及命令向量"
                }
                .to_owned(),
            });
        }
    }
    let console_history_seconds = console_started.elapsed().as_secs_f64();

    progress(TerminalHistoryStage::FileObjects);
    let file_scan_started = Instant::now();
    let files = scan_files_matching(
        session.image(),
        session.kernel(),
        session.profile(),
        options.file_scan_limit,
        &is_psreadline_history_path,
    )?;
    complete &= files.complete;
    for warning in &files.warnings {
        push_warning(&mut warnings, format!("PSReadLine 文件扫描：{warning}"));
    }
    let mut candidates = files
        .records
        .iter()
        .filter(|file| file.name.as_deref().is_some_and(is_psreadline_history_path))
        .collect::<Vec<_>>();
    candidates.sort_unstable_by(|left, right| {
        normalized_path(left)
            .cmp(&normalized_path(right))
            .then_with(|| left.shared_cache_map.cmp(&right.shared_cache_map))
            .then_with(|| left.data_section_object.cmp(&right.data_section_object))
            .then_with(|| left.file_object.cmp(&right.file_object))
    });
    candidates.dedup_by(|left, right| same_file_candidate(left, right));
    let psreadline_files_found = candidates.len();
    if candidates.len() > options.history_file_limit {
        candidates.truncate(options.history_file_limit);
        complete = false;
        push_warning(
            &mut warnings,
            format!(
                "PSReadLine 历史文件候选达到 {} 个上限",
                options.history_file_limit
            ),
        );
    }
    let file_scan_seconds = file_scan_started.elapsed().as_secs_f64();

    progress(TerminalHistoryStage::HistoryFiles);
    let history_file_started = Instant::now();
    let kernel_space =
        X64AddressSpace::new(session.image(), session.kernel().directory_table_base)?;
    let mut psreadline_files_parsed = 0usize;
    for file in candidates {
        if records.len() >= options.limit.saturating_mul(4) {
            complete = false;
            push_warning(&mut warnings, "终端历史中间结果达到安全上限".to_owned());
            break;
        }
        let path = file.name.clone().unwrap_or_default().replace('/', "\\");
        let recovered = recover_file_bytes(
            session.image(),
            session.kernel(),
            session.profile(),
            file.file_object,
            DumpSource::Auto,
            options.max_history_file_size,
        );
        let (dump, bytes) = match recovered {
            Ok(value) => value,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("无法恢复 PSReadLine 历史文件 {path}：{error:#}"),
                );
                continue;
            }
        };
        if dump.recovered_bytes == 0 || bytes.is_empty() {
            complete = false;
            push_warning(
                &mut warnings,
                format!("PSReadLine 历史文件 {path} 没有驻留内容"),
            );
            continue;
        }
        if !dump.complete {
            complete = false;
            push_warning(
                &mut warnings,
                format!(
                    "PSReadLine 历史文件 {path} 仅恢复 {}/{} 字节",
                    dump.recovered_bytes, dump.logical_size
                ),
            );
        }
        let parsed = match parse_psreadline_history(&bytes) {
            Ok(parsed) => parsed,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("无法解析 PSReadLine 历史文件 {path}：{error:#}"),
                );
                continue;
            }
        };
        psreadline_files_parsed += 1;
        let physical_extents = recovery_physical_extents(&dump.extents, &kernel_space);
        let user_name = user_name_from_path(&path);
        let user_sid = user_name
            .as_deref()
            .and_then(|user| unique_user_sid(user, &facts));
        let kind = terminal_kind_from_history_path(&path);
        for command in parsed {
            let physical_addresses =
                physical_for_file_offset(&physical_extents, command.file_offset)
                    .into_iter()
                    .collect();
            records.push(TerminalHistoryRecord {
                source: TerminalHistorySource::PsReadLineFile,
                terminal_kind: kind,
                frontend: None,
                terminal_pid: None,
                terminal_process: None,
                host_pid: None,
                host_process: None,
                user_name: user_name.clone(),
                user_sid: user_sid.clone(),
                application: Some("PSReadLine".to_owned()),
                command_index: command.index,
                command: command.command,
                history_address: None,
                virtual_address: None,
                physical_addresses,
                source_file: Some(path.clone()),
                file_objects: vec![file.file_object],
                file_offset: Some(command.file_offset),
                confidence: "high".to_owned(),
                evidence: "从已验证 FILE_OBJECT 的驻留 PSReadLine 历史文件恢复".to_owned(),
            });
        }
    }
    let history_file_seconds = history_file_started.elapsed().as_secs_f64();

    progress(TerminalHistoryStage::Aggregate);
    let aggregation_started = Instant::now();
    records.retain(|record| !record.command.trim().is_empty());
    if records.len() > options.limit {
        records.truncate(options.limit);
        complete = false;
        push_warning(
            &mut warnings,
            format!("终端历史结果达到 {} 条上限", options.limit),
        );
    }
    let aggregation_seconds = aggregation_started.elapsed().as_secs_f64();
    let statistics = TerminalHistoryStatistics {
        terminal_processes: terminal_processes.len(),
        console_hosts: terminal_processes
            .iter()
            .filter(|process| process.role == TerminalProcessRole::ConsoleHost)
            .count(),
        console_history_buffers,
        console_memory_fallback_groups,
        psreadline_files_found,
        psreadline_files_parsed,
    };
    Ok(TerminalHistoryReport {
        records,
        terminal_processes,
        complete,
        warnings,
        statistics,
        timing: TerminalHistoryTiming {
            process_seconds,
            console_history_seconds,
            file_scan_seconds,
            history_file_seconds,
            aggregation_seconds,
            total_seconds: started.elapsed().as_secs_f64(),
        },
    })
}

fn terminal_kind_from_name(name: &str) -> TerminalKind {
    match name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase()
        .as_str()
    {
        "windowsterminal.exe" | "windowstermina" | "wt.exe" => TerminalKind::WindowsTerminal,
        "openconsole.exe" | "openconsole.ex" => TerminalKind::OpenConsole,
        "powershell.exe" => TerminalKind::PowerShell,
        "pwsh.exe" => TerminalKind::Pwsh,
        "cmd.exe" => TerminalKind::Cmd,
        "conhost.exe" => TerminalKind::Conhost,
        _ => TerminalKind::Unknown,
    }
}

fn terminal_kind_from_process(name: &str, image_path: Option<&str>) -> TerminalKind {
    let kind = terminal_kind_from_name(name);
    if kind != TerminalKind::Unknown {
        return kind;
    }
    image_path
        .map(terminal_kind_from_name)
        .unwrap_or(TerminalKind::Unknown)
}

fn terminal_kind_from_application(application: &str) -> TerminalKind {
    let lower = application.trim().trim_matches('"').to_ascii_lowercase();
    for (needle, kind) in [
        ("pwsh.exe", TerminalKind::Pwsh),
        ("pwsh", TerminalKind::Pwsh),
        ("powershell.exe", TerminalKind::PowerShell),
        ("powershell", TerminalKind::PowerShell),
        ("cmd.exe", TerminalKind::Cmd),
        ("cmd", TerminalKind::Cmd),
    ] {
        if lower
            .split(|character: char| {
                character.is_whitespace() || matches!(character, '\\' | '/' | '"')
            })
            .any(|part| part == needle)
        {
            return kind;
        }
    }
    TerminalKind::Unknown
}

fn terminal_process_role(kind: TerminalKind) -> Option<TerminalProcessRole> {
    match kind {
        TerminalKind::WindowsTerminal => Some(TerminalProcessRole::Frontend),
        TerminalKind::OpenConsole | TerminalKind::Conhost => Some(TerminalProcessRole::ConsoleHost),
        TerminalKind::PowerShell | TerminalKind::Pwsh | TerminalKind::Cmd => {
            Some(TerminalProcessRole::Shell)
        }
        TerminalKind::Unknown => None,
    }
}

fn is_shell_kind(kind: TerminalKind) -> bool {
    matches!(
        kind,
        TerminalKind::PowerShell | TerminalKind::Pwsh | TerminalKind::Cmd
    )
}

fn process_frontend(pid: u64, facts: &HashMap<u64, ProcessFact>) -> Option<String> {
    let mut current = Some(pid);
    let mut visited = HashSet::new();
    let mut saw_open_console = false;
    for _ in 0..8 {
        let Some(current_pid) = current else {
            break;
        };
        let Some(process) = facts.get(&current_pid) else {
            break;
        };
        if !visited.insert(process.pid) {
            break;
        }
        match process.kind {
            TerminalKind::WindowsTerminal => {
                return Some(
                    if saw_open_console {
                        "Windows Terminal / OpenConsole"
                    } else {
                        "Windows Terminal"
                    }
                    .to_owned(),
                );
            }
            TerminalKind::OpenConsole => {
                saw_open_console = true;
                current = process.ppid;
            }
            _ => current = process.ppid,
        }
    }
    saw_open_console.then(|| "OpenConsole / ConPTY".to_owned())
}

fn associate_console_shell(
    host_pid: u64,
    application_kind: TerminalKind,
    facts: &HashMap<u64, ProcessFact>,
) -> Option<u64> {
    let host = facts.get(&host_pid)?;
    let mut candidates = facts
        .values()
        .filter(|process| {
            is_shell_kind(process.kind)
                && (application_kind == TerminalKind::Unknown || process.kind == application_kind)
                && (process.ppid == Some(host_pid) || host.ppid == Some(process.pid))
        })
        .map(|process| process.pid)
        .collect::<Vec<_>>();
    candidates.sort_unstable();
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates[0])
}

fn translate_process_address(
    session: &AnalysisSession,
    dtb: Option<u64>,
    virtual_address: u64,
) -> Option<u64> {
    let space = X64AddressSpace::new(session.image(), dtb?).ok()?;
    space.translate(virtual_address).ok()
}

fn is_psreadline_history_path(path: &str) -> bool {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();
    let name = normalized.rsplit('\\').next().unwrap_or(&normalized);
    normalized.contains("\\psreadline\\") && name.ends_with("_history.txt")
}

fn terminal_kind_from_history_path(path: &str) -> TerminalKind {
    let lower = path.replace('/', "\\").to_ascii_lowercase();
    if lower.contains("\\windows\\powershell\\psreadline\\") {
        TerminalKind::PowerShell
    } else {
        TerminalKind::Pwsh
    }
}

fn normalized_path(file: &FileScanRecord) -> String {
    file.name
        .as_deref()
        .unwrap_or_default()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn same_file_candidate(left: &&FileScanRecord, right: &&FileScanRecord) -> bool {
    normalized_path(left) == normalized_path(right)
        && left.shared_cache_map == right.shared_cache_map
        && left.data_section_object == right.data_section_object
        && left.image_section_object == right.image_section_object
}

fn user_name_from_path(path: &str) -> Option<String> {
    let normalized = path.replace('/', "\\");
    let parts = normalized.split('\\').collect::<Vec<_>>();
    parts.windows(2).find_map(|parts| {
        parts[0]
            .eq_ignore_ascii_case("users")
            .then(|| parts[1].trim().to_owned())
            .filter(|user| !user.is_empty())
    })
}

fn unique_user_sid(user: &str, facts: &HashMap<u64, ProcessFact>) -> Option<String> {
    let mut sids = facts
        .values()
        .filter(|process| is_shell_kind(process.kind))
        .filter(|process| {
            process
                .user_name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case(user))
                || process.user_profile.as_deref().is_some_and(|profile| {
                    profile
                        .replace('/', "\\")
                        .rsplit('\\')
                        .next()
                        .is_some_and(|name| name.eq_ignore_ascii_case(user))
                })
        })
        .filter_map(|process| process.user_sid.clone())
        .collect::<Vec<_>>();
    sids.sort_unstable();
    sids.dedup();
    (sids.len() == 1).then(|| sids.remove(0))
}

fn parse_psreadline_history(bytes: &[u8]) -> Result<Vec<ParsedCommand>> {
    let encoding = detect_text_encoding(bytes);
    let usable = trim_unwritten_tail(bytes, encoding);
    ensure!(!usable.is_empty(), "文件内容为空");
    let (text, bom) = match encoding {
        TextEncoding::Utf8 { bom } => (
            std::str::from_utf8(&usable[bom..])
                .map_err(|error| anyhow::anyhow!("历史文件不是有效的 UTF-8：{error}"))?
                .to_owned(),
            bom,
        ),
        TextEncoding::Utf16Le { bom } => (decode_utf16(&usable[bom..], true)?, bom),
        TextEncoding::Utf16Be { bom } => (decode_utf16(&usable[bom..], false)?, bom),
    };
    let unit_bytes = match encoding {
        TextEncoding::Utf8 { .. } => 1,
        TextEncoding::Utf16Le { .. } | TextEncoding::Utf16Be { .. } => 2,
    };
    let mut records = Vec::new();
    let mut pending = String::new();
    let mut pending_offset = bom as u64;
    let mut cursor = bom as u64;
    for raw_line in text.split_inclusive('\n') {
        let line_start = cursor;
        cursor = cursor.saturating_add(encoded_length(raw_line, unit_bytes) as u64);
        let line = raw_line.trim_end_matches(['\r', '\n']);
        if pending.is_empty() {
            pending_offset = line_start;
        }
        let continued = has_unescaped_trailing_backtick(line);
        let fragment = if continued {
            line.strip_suffix('`').unwrap_or(line)
        } else {
            line
        };
        if !pending.is_empty() {
            pending.push('\n');
        }
        pending.push_str(fragment);
        if continued {
            continue;
        }
        if let Some(command) = normalize_history_command(&pending) {
            let index = records.len();
            records.push(ParsedCommand {
                index,
                file_offset: pending_offset,
                command,
            });
        }
        pending.clear();
    }
    if !pending.is_empty()
        && let Some(command) = normalize_history_command(&pending)
    {
        let index = records.len();
        records.push(ParsedCommand {
            index,
            file_offset: pending_offset,
            command,
        });
    }
    Ok(records)
}

fn trim_unwritten_tail(bytes: &[u8], encoding: TextEncoding) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == 0 {
        end -= 1;
    }
    if end < bytes.len()
        && end % 2 == 1
        && matches!(
            encoding,
            TextEncoding::Utf16Le { .. } | TextEncoding::Utf16Be { .. }
        )
    {
        end += 1;
    }
    &bytes[..end.min(bytes.len())]
}

fn detect_text_encoding(bytes: &[u8]) -> TextEncoding {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return TextEncoding::Utf8 { bom: 3 };
    }
    if bytes.starts_with(&[0xff, 0xfe]) {
        return TextEncoding::Utf16Le { bom: 2 };
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        return TextEncoding::Utf16Be { bom: 2 };
    }
    let sample = bytes.len().min(4096) & !1;
    let (mut even_zero, mut odd_zero) = (0usize, 0usize);
    for pair in bytes[..sample].chunks_exact(2) {
        even_zero += usize::from(pair[0] == 0);
        odd_zero += usize::from(pair[1] == 0);
    }
    let pairs = sample / 2;
    if pairs >= 4 && odd_zero * 3 > pairs && even_zero * 10 < pairs {
        TextEncoding::Utf16Le { bom: 0 }
    } else if pairs >= 4 && even_zero * 3 > pairs && odd_zero * 10 < pairs {
        TextEncoding::Utf16Be { bom: 0 }
    } else {
        TextEncoding::Utf8 { bom: 0 }
    }
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> Result<String> {
    ensure!(bytes.len().is_multiple_of(2), "UTF-16 文件长度不是偶数");
    let units = bytes.chunks_exact(2).map(|pair| {
        if little_endian {
            u16::from_le_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], pair[1]])
        }
    });
    char::decode_utf16(units)
        .collect::<std::result::Result<String, _>>()
        .map_err(|error| anyhow::anyhow!("历史文件包含无效的 UTF-16：{error}"))
}

fn encoded_length(text: &str, unit_bytes: usize) -> usize {
    if unit_bytes == 1 {
        text.len()
    } else {
        text.encode_utf16().count() * 2
    }
}

fn has_unescaped_trailing_backtick(line: &str) -> bool {
    line.chars()
        .rev()
        .take_while(|character| *character == '`')
        .count()
        % 2
        == 1
}

fn normalize_history_command(command: &str) -> Option<String> {
    let command = command.trim().trim_matches('\0');
    let length = command.chars().count();
    let incomplete_bracket_fragment =
        length <= 4 && command.starts_with('[') && !command.ends_with(']');
    if length == 0
        || length > 32 * 1024
        || incomplete_bracket_fragment
        || command.contains('\u{fffd}')
        || command
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\r' | '\n' | '\t'))
        || !command
            .chars()
            .any(|character| character.is_alphanumeric() || !character.is_ascii())
    {
        return None;
    }
    Some(command.to_owned())
}

fn recovery_physical_extents(
    extents: &[RecoveredExtent],
    kernel_space: &X64AddressSpace<'_>,
) -> Vec<RecoveredExtent> {
    let mut output = Vec::new();
    for extent in extents {
        if extent.memory_kind == "physical" {
            output.push(RecoveredExtent {
                file_offset: extent.file_offset,
                length: extent.length,
                memory_address: extent.memory_address,
                memory_kind: "physical".to_owned(),
            });
            continue;
        }
        if extent.memory_kind != "virtual" {
            continue;
        }
        let mut relative = 0u64;
        while relative < extent.length {
            let Some(virtual_address) = extent.memory_address.checked_add(relative) else {
                break;
            };
            let length = (extent.length - relative).min(0x1000 - (virtual_address & 0xfff));
            if let Ok(physical_address) = kernel_space.translate(virtual_address) {
                output.push(RecoveredExtent {
                    file_offset: extent.file_offset + relative,
                    length,
                    memory_address: physical_address,
                    memory_kind: "physical".to_owned(),
                });
            }
            relative += length;
        }
    }
    output
}

fn physical_for_file_offset(extents: &[RecoveredExtent], offset: u64) -> Option<u64> {
    extents.iter().find_map(|extent| {
        let end = extent.file_offset.checked_add(extent.length)?;
        (extent.memory_kind == "physical" && (extent.file_offset..end).contains(&offset))
            .then(|| extent.memory_address + (offset - extent.file_offset))
    })
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNING_COUNT && !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_terminal_processes_and_psreadline_paths() {
        assert_eq!(
            terminal_kind_from_name("WindowsTerminal.exe"),
            TerminalKind::WindowsTerminal
        );
        assert_eq!(
            terminal_kind_from_name("WindowsTermina"),
            TerminalKind::WindowsTerminal
        );
        assert_eq!(
            terminal_kind_from_name("OpenConsole.ex"),
            TerminalKind::OpenConsole
        );
        assert_eq!(
            terminal_kind_from_name(r"C:\Program Files\PowerShell\7\pwsh.exe"),
            TerminalKind::Pwsh
        );
        assert!(is_psreadline_history_path(
            r"\Users\Alice\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        ));
        assert!(!is_psreadline_history_path(r"\Users\Alice\notes.txt"));
    }

    #[test]
    fn parses_utf8_multiline_psreadline_history() {
        let bytes = b"Get-Process\r\n[I\r\nGet-ChildItem `\r\n-Recurse C:\\\r\nwhoami\r\n";
        let records = parse_psreadline_history(bytes).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].command, "Get-Process");
        assert_eq!(records[1].command, "Get-ChildItem \n-Recurse C:\\");
        assert_eq!(records[2].command, "whoami");
        assert_eq!(records[2].file_offset, 48);
    }

    #[test]
    fn parses_utf16le_chinese_history_without_garbled_text() {
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend(
            "Get-Content C:\\用户\\口令.txt\r\n"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        let records = parse_psreadline_history(&bytes).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].command, "Get-Content C:\\用户\\口令.txt");
        assert_eq!(records[0].file_offset, 2);
    }

    #[test]
    fn identifies_shell_from_application_path() {
        assert_eq!(
            terminal_kind_from_application(r"C:\Windows\System32\cmd.exe"),
            TerminalKind::Cmd
        );
        assert_eq!(
            terminal_kind_from_application(r"C:\Program Files\PowerShell\7\pwsh.exe -NoLogo"),
            TerminalKind::Pwsh
        );
    }

    #[test]
    fn leaves_console_shell_unassigned_without_direct_process_evidence() {
        let facts = HashMap::from([(
            100,
            ProcessFact {
                pid: 100,
                ppid: Some(4),
                kind: TerminalKind::Conhost,
                process: "conhost.exe".to_owned(),
                user_sid: None,
                user_name: None,
                user_profile: None,
                dtb: None,
            },
        )]);
        assert_eq!(
            associate_console_shell(100, TerminalKind::Cmd, &facts),
            None
        );
    }

    #[test]
    fn distinguishes_windows_terminal_from_generic_openconsole() {
        let facts = HashMap::from([
            (
                10,
                ProcessFact {
                    pid: 10,
                    ppid: None,
                    kind: TerminalKind::WindowsTerminal,
                    process: "WindowsTermina".to_owned(),
                    user_sid: None,
                    user_name: None,
                    user_profile: None,
                    dtb: None,
                },
            ),
            (
                20,
                ProcessFact {
                    pid: 20,
                    ppid: Some(10),
                    kind: TerminalKind::OpenConsole,
                    process: "OpenConsole.ex".to_owned(),
                    user_sid: None,
                    user_name: None,
                    user_profile: None,
                    dtb: None,
                },
            ),
            (
                30,
                ProcessFact {
                    pid: 30,
                    ppid: None,
                    kind: TerminalKind::OpenConsole,
                    process: "OpenConsole.ex".to_owned(),
                    user_sid: None,
                    user_name: None,
                    user_profile: None,
                    dtb: None,
                },
            ),
        ]);
        assert_eq!(
            process_frontend(20, &facts).as_deref(),
            Some("Windows Terminal / OpenConsole")
        );
        assert_eq!(
            process_frontend(30, &facts).as_deref(),
            Some("OpenConsole / ConPTY")
        );
    }
}
