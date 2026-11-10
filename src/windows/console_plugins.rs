use std::collections::HashSet;

use anyhow::{Result, ensure};
use serde::Serialize;

use super::plugins::list_vads;
use super::{ProcessRecord, WindowsKernelContext, list_processes};
use crate::address::{VirtualAddressRegion, X64AddressSpace};
use crate::image::MemoryImage;
use crate::profile::KernelProfile;

#[derive(Debug, Serialize)]
pub struct CommandHistoryReport {
    pub records: Vec<CommandHistoryRecord>,
    pub conhost_processes: usize,
    pub mapped_bytes_examined: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandHistoryRecord {
    pub conhost_pid: u64,
    pub conhost: String,
    pub address: u64,
    pub process_handle: u64,
    pub application: Option<String>,
    pub command_count: usize,
    pub command_count_max: u16,
    pub last_displayed: i32,
    pub commands: Vec<CommandRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandRecord {
    pub index: usize,
    pub address: u64,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct ConsoleReport {
    pub records: Vec<ConsoleRecord>,
    pub histories: Vec<CommandHistoryRecord>,
    pub conhost_processes: usize,
    pub mapped_bytes_examined: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ConsoleRecord {
    pub conhost_pid: u64,
    pub address: u64,
    pub layout: String,
    pub screen_x: i16,
    pub screen_y: i16,
    pub command_history_size: u16,
    pub history_buffer_max: u16,
    pub title: Option<String>,
    pub original_title: Option<String>,
    pub current_screen_buffer: Option<u64>,
    pub screen_lines: Vec<String>,
}

#[derive(Clone, Copy)]
struct ConsoleLayout {
    name: &'static str,
    screen_x: u64,
    screen_y: u64,
    history_size: u64,
    history_max: u64,
    title: u64,
    original_title: u64,
    current_screen: u64,
}

// These candidates correspond to structurally distinct x64 console layouts.
// Selection is made from captured dimensions, titles, pointers and settings;
// the OS build number is deliberately not consulted.
const CONSOLE_LAYOUTS: &[ConsoleLayout] = &[
    ConsoleLayout {
        name: "modern_25398_plus",
        screen_x: 0xa20,
        screen_y: 0xa22,
        history_size: 0xa90,
        history_max: 0xa94,
        title: 0xc30,
        original_title: 0xbf0,
        current_screen: 0xb08,
    },
    ConsoleLayout {
        name: "modern_22621",
        screen_x: 0x960,
        screen_y: 0x962,
        history_size: 0x9d0,
        history_max: 0x9d4,
        title: 0xb60,
        original_title: 0xb80,
        current_screen: 0xa48,
    },
    ConsoleLayout {
        name: "server_20348",
        screen_x: 0x18,
        screen_y: 0x1a,
        history_size: 0x88,
        history_max: 0x8c,
        title: 0x610,
        original_title: 0x650,
        current_screen: 0x510,
    },
    ConsoleLayout {
        name: "legacy_win10",
        screen_x: 0x20,
        screen_y: 0x22,
        history_size: 0x90,
        history_max: 0x94,
        title: 0x698,
        original_title: 0x6d8,
        current_screen: 0x570,
    },
];

pub fn command_histories(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<CommandHistoryReport> {
    let artifacts = scan_console_artifacts(image, kernel, profile, limit, false)?;
    Ok(CommandHistoryReport {
        records: artifacts.histories,
        conhost_processes: artifacts.conhost_processes,
        mapped_bytes_examined: artifacts.mapped_bytes_examined,
        missing_bytes: artifacts.missing_bytes,
        complete: artifacts.complete,
        warnings: artifacts.warnings,
    })
}

pub fn consoles(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<ConsoleReport> {
    scan_console_artifacts(image, kernel, profile, limit, true)
}

fn scan_console_artifacts(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
    scan_console_info: bool,
) -> Result<ConsoleReport> {
    ensure!(limit > 0, "控制台结果数量上限必须大于零");
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let conhosts = processes
        .processes
        .iter()
        .filter(|process| is_console_host_process(&process.name))
        .collect::<Vec<_>>();
    let mut report = ConsoleReport {
        records: Vec::new(),
        histories: Vec::new(),
        conhost_processes: conhosts.len(),
        mapped_bytes_examined: 0,
        missing_bytes: 0,
        complete: processes.complete,
        warnings: processes
            .warnings
            .iter()
            .map(|warning| format!("pslist/{}: {}", warning.kind, warning.message))
            .collect(),
    };
    if conhosts.is_empty() {
        report.complete = false;
        report
            .warnings
            .push("未恢复到活动的 conhost.exe 或 OpenConsole.exe 控制台宿主".to_owned());
        return Ok(report);
    }
    for process in conhosts {
        if report.histories.len() == limit {
            report.complete = false;
            report
                .warnings
                .push(format!("控制台结果达到 {limit} 条上限"));
            break;
        }
        scan_one_conhost(
            image,
            kernel,
            profile,
            process,
            limit,
            scan_console_info,
            &mut report,
        );
    }
    if report.missing_bytes != 0 {
        report.complete = false;
        report.warnings.push(format!(
            "有 {} 个已映射控制台宿主字节不可用，未进行扫描",
            report.missing_bytes
        ));
    }
    Ok(report)
}

fn scan_one_conhost(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    process: &ProcessRecord,
    limit: usize,
    scan_console_info: bool,
    report: &mut ConsoleReport,
) {
    let Some(dtb) = process
        .details
        .user_directory_table_base
        .or(process.details.directory_table_base)
    else {
        report.complete = false;
        report
            .warnings
            .push(format!("PID {} 没有可用的进程 DTB", process.pid));
        return;
    };
    let Ok(space) = X64AddressSpace::new(image, dtb) else {
        report.complete = false;
        return;
    };
    let vads = match list_vads(image, kernel, profile, process.pid, 65_536) {
        Ok(vads) => vads,
        Err(error) => {
            report.complete = false;
            report
                .warnings
                .push(format!("PID {} 的 VAD 遍历失败：{error:#}", process.pid));
            return;
        }
    };
    report.complete &= vads.complete;
    report.warnings.extend(
        vads.warnings
            .into_iter()
            .map(|warning| format!("PID {}: {warning}", process.pid)),
    );
    let mappings = match space.enumerate_mappings(VirtualAddressRegion::User, 1_000_000) {
        Ok(mappings) => mappings,
        Err(error) => {
            report.complete = false;
            report.warnings.push(format!(
                "PID {} 的用户空间映射枚举失败：{error:#}",
                process.pid
            ));
            return;
        }
    };
    report.complete &= !mappings.truncated;

    let eligible = vads
        .records
        .iter()
        .filter(|vad| vad.end.saturating_sub(vad.start) < 0x4000_0000)
        .map(|vad| (vad.start, vad.end.saturating_add(1)))
        .collect::<Vec<_>>();
    let raw_command_ranges = vads
        .records
        .iter()
        .filter(|vad| vad.private_memory || vad.file.is_none())
        .map(|vad| (vad.start, vad.end.saturating_add(1)))
        .collect::<Vec<_>>();
    let image_vad = process.details.image_base.and_then(|image_base| {
        vads.records
            .iter()
            .filter(|vad| image_base >= vad.start && image_base <= vad.end)
            .max_by_key(|vad| {
                usize::from(vad.file.as_deref().is_some_and(|name| {
                    name.to_ascii_lowercase()
                        .ends_with(&process.name.to_ascii_lowercase())
                }))
            })
            .map(|vad| (vad.start, vad.end.saturating_add(1)))
    });
    if scan_console_info && image_vad.is_none() {
        report.complete = false;
        report
            .warnings
            .push(format!("无法识别 PID {} 的控制台宿主映像 VAD", process.pid));
    }
    let mut history_candidates = HashSet::new();
    let mut console_candidates = HashSet::new();
    let mut raw_commands = Vec::new();
    for mapping in mappings.mappings {
        let mapping_end = mapping.virtual_end;
        let intersects_eligible = eligible
            .iter()
            .any(|(start, end)| mapping.virtual_start < *end && mapping_end > *start);
        if !intersects_eligible {
            continue;
        }
        let intersects_image_vad = image_vad
            .is_some_and(|(start, end)| mapping.virtual_start < end && mapping_end > start);
        let mut address = mapping.virtual_start;
        while address < mapping_end {
            let take = usize::try_from((mapping_end - address).min(0x1000)).unwrap_or(0);
            if take == 0 {
                break;
            }
            let mut page = vec![0u8; take];
            if space.read_virtual(address, &mut page).is_err() {
                report.missing_bytes += take as u64;
                address += take as u64;
                continue;
            }
            report.mapped_bytes_examined += take as u64;
            if raw_command_ranges
                .iter()
                .any(|(start, end)| address < *end && address + take as u64 > *start)
            {
                raw_commands.extend(extract_raw_commands(&page, address));
            }
            for offset in (0..page.len().saturating_sub(0x5f)).step_by(8) {
                if history_prefilter(&page[offset..]) {
                    history_candidates.insert(address + offset as u64);
                }
            }
            if scan_console_info && intersects_image_vad {
                for layout in CONSOLE_LAYOUTS {
                    let alignment = usize::try_from(layout.history_size & 7).unwrap_or(0);
                    for offset in (alignment..page.len().saturating_sub(1)).step_by(8) {
                        let history_size = u16::from_le_bytes([page[offset], page[offset + 1]]);
                        if !(1..=1024).contains(&history_size) {
                            continue;
                        }
                        let hit = address + offset as u64;
                        if let Some(base) = hit.checked_sub(layout.history_size)
                            && base & 7 == 0
                        {
                            console_candidates.insert((base, layout.name));
                        }
                    }
                }
            }
            address += take as u64;
        }
    }

    for address in history_candidates {
        if report.histories.len() == limit {
            break;
        }
        if let Some(history) = decode_history(&space, process, address) {
            report.histories.push(history);
        }
    }
    report
        .histories
        .sort_unstable_by_key(|history| history.address);

    if !report
        .histories
        .iter()
        .any(|history| history.conhost_pid == process.pid)
        && !raw_commands.is_empty()
    {
        raw_commands.sort_unstable_by_key(|command| command.address);
        let mut seen_commands = HashSet::new();
        raw_commands.retain(|command| seen_commands.insert(command.text.to_ascii_lowercase()));
        let command_count = raw_commands.len().min(usize::from(u16::MAX));
        raw_commands.truncate(command_count);
        for (index, command) in raw_commands.iter_mut().enumerate() {
            command.index = index;
        }
        report.histories.push(CommandHistoryRecord {
            conhost_pid: process.pid,
            conhost: process.name.clone(),
            address: raw_commands[0].address,
            process_handle: 0,
            application: Some("原始 UTF-16 命令字符串回退".to_owned()),
            command_count,
            command_count_max: command_count as u16,
            last_displayed: -1,
            commands: raw_commands,
        });
        report.complete = false;
        report.warnings.push(format!(
            "PID {} 未找到结构化命令历史，已回退恢复经过严格筛选的 UTF-16 命令字符串",
            process.pid
        ));
    }

    if scan_console_info {
        for (address, layout_name) in console_candidates {
            if report.records.len() == limit {
                break;
            }
            let Some(layout) = CONSOLE_LAYOUTS
                .iter()
                .find(|layout| layout.name == layout_name)
            else {
                continue;
            };
            if let Some(console) = decode_console(&space, process.pid, address, *layout) {
                report.records.push(console);
            }
        }
        report
            .records
            .sort_unstable_by_key(|console| console.address);
    }
    let has_history = report
        .histories
        .iter()
        .any(|history| history.conhost_pid == process.pid);
    let has_console = report
        .records
        .iter()
        .any(|console| console.conhost_pid == process.pid);
    if !has_history && (!scan_console_info || !has_console) {
        report.complete = false;
        report.warnings.push(format!(
            "PID {} 存在可读的 conhost 映射，但未找到有效的{}结构；缺失或不驻留页面中可能还有证据",
            process.pid,
            if scan_console_info {
                "控制台或命令历史"
            } else {
                "命令历史"
            }
        ));
    }
}

fn is_console_host_process(name: &str) -> bool {
    name.eq_ignore_ascii_case("conhost.exe")
        || name.eq_ignore_ascii_case("OpenConsole.exe")
        // EPROCESS.ImageFileName may expose only the first 15 bytes.
        || name.eq_ignore_ascii_case("OpenConsole.ex")
}

fn decode_history(
    space: &X64AddressSpace<'_>,
    process: &ProcessRecord,
    address: u64,
) -> Option<CommandHistoryRecord> {
    let begin = space.read_u64(address + 0x10).ok()?;
    let end = space.read_u64(address + 0x18).ok()?;
    let capacity = space.read_u64(address + 0x20).ok()?;
    let command_count_max = read_u16(space, address + 0x28)?;
    let handle_record = space.read_u64(address + 0x50).ok()?;
    let process_handle = u64::from(read_u32(space, handle_record + 0x30)?);
    let last_displayed = i32::from(read_i16(space, address + 0x5c)?);
    if !(1..=1024).contains(&command_count_max)
        || !valid_user_pointer(begin)
        || end < begin
        || capacity < end
        || (end - begin) % 32 != 0
        || capacity - begin > u64::from(command_count_max) * 32
        || (capacity - begin) % 32 != 0
        || process_handle == 0
        || process_handle > 0xffff
        || process_handle & 3 != 0
        || !(-1..=i32::from(command_count_max)).contains(&last_displayed)
    {
        return None;
    }
    let command_count = usize::try_from((end - begin) / 32).ok()?;
    let application = decode_command(space, address + 0x30);
    if application.as_deref().is_none_or(str::is_empty) {
        return None;
    }
    let mut commands = Vec::new();
    for index in 0..command_count {
        let command_address = begin + index as u64 * 32;
        if let Some(text) = decode_command(space, command_address)
            && !text.is_empty()
        {
            commands.push(CommandRecord {
                index,
                address: command_address,
                text,
            });
        }
    }
    Some(CommandHistoryRecord {
        conhost_pid: process.pid,
        conhost: process.name.clone(),
        address,
        process_handle,
        application,
        command_count,
        command_count_max,
        last_displayed,
        commands,
    })
}

fn decode_command(space: &X64AddressSpace<'_>, address: u64) -> Option<String> {
    let length = usize::try_from(read_u32(space, address + 0x10)?).ok()?;
    let allocated = usize::try_from(read_u32(space, address + 0x18)?).ok()?;
    if length == 0 || length > 1024 || allocated == 0 || allocated > 1024 || length > allocated {
        return None;
    }
    let source = if length < 8 {
        address
    } else {
        let pointer = space.read_u64(address).ok()?;
        valid_user_pointer(pointer).then_some(pointer)?
    };
    read_utf16(space, source, length)
}

fn extract_raw_commands(bytes: &[u8], base: u64) -> Vec<CommandRecord> {
    let mut records = Vec::new();
    for alignment in 0..2usize {
        let mut offset = alignment;
        while offset + 1 < bytes.len() {
            let start = offset;
            let mut units = Vec::new();
            while offset + 1 < bytes.len() && units.len() < 512 {
                let unit = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
                if unit == 0 || !raw_command_unit(unit) {
                    break;
                }
                units.push(unit);
                offset += 2;
            }
            if units.len() >= 4 {
                let text = String::from_utf16_lossy(&units);
                if let Some(text) = normalize_raw_command(&text) {
                    records.push(CommandRecord {
                        index: 0,
                        address: base + start as u64,
                        text,
                    });
                }
            }
            offset = if offset == start {
                offset + 2
            } else {
                offset.saturating_add(2)
            };
        }
    }
    records
}

fn raw_command_unit(unit: u16) -> bool {
    matches!(unit, 0x09 | 0x20..=0x7e | 0x3000..=0x303f | 0x3400..=0x9fff)
}

fn normalize_raw_command(text: &str) -> Option<String> {
    let mut text = text
        .split("        ")
        .next()
        .unwrap_or(text)
        .trim()
        .trim_matches('\0');
    if let Some((_, suffix)) = text.rsplit_once('>')
        && !suffix.trim().is_empty()
    {
        text = suffix.trim();
    }
    if let Some((_, suffix)) = text.rsplit_once(" - ")
        && raw_command_executable(suffix).is_some()
    {
        text = suffix.trim();
    }
    let lower = text.to_ascii_lowercase();
    let executable = raw_command_executable(&lower)?;
    let first = lower.split_whitespace().next().unwrap_or_default();
    let has_arguments = !lower[first.len()..].trim().is_empty();
    let no_argument_commands = [
        "dir",
        "whoami",
        "ipconfig",
        "systeminfo",
        "tasklist",
        "quser",
        "qwinsta",
        "hostname",
    ];
    let looks_like_help = text.contains('[')
        || text.contains(']')
        || lower.contains(" or ")
        || lower.contains("for new features and improvements")
        || lower.contains("--strictport")
        || lower.contains("filename")
        || lower.contains("missing.")
        || lower.contains("%s")
        || text.contains("处于打开状态")
        || text.contains("处于关闭状态")
        || text.contains("开关运行");
    (text.chars().count() <= 512
        && !looks_like_help
        && (has_arguments || no_argument_commands.contains(&executable)))
    .then(|| text.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn raw_command_executable(text: &str) -> Option<&str> {
    let first = text
        .trim()
        .trim_start_matches('"')
        .split_whitespace()
        .next()?
        .trim_matches('"');
    if first.contains('=') {
        return None;
    }
    let executable = first
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(first)
        .trim_end_matches(".exe");
    const COMMANDS: &[&str] = &[
        "net",
        "net1",
        "whoami",
        "ipconfig",
        "systeminfo",
        "tasklist",
        "taskkill",
        "sc",
        "wmic",
        "powershell",
        "pwsh",
        "cmd",
        "certutil",
        "bitsadmin",
        "curl",
        "wget",
        "reg",
        "regsvr32",
        "rundll32",
        "schtasks",
        "dir",
        "cd",
        "type",
        "echo",
        "copy",
        "move",
        "del",
        "erase",
        "mkdir",
        "md",
        "rmdir",
        "rd",
        "attrib",
        "quser",
        "qwinsta",
        "query",
        "ping",
        "tracert",
        "nslookup",
        "route",
        "arp",
        "netstat",
        "hostname",
        "set",
        "chcp",
        "wevtutil",
        "vssadmin",
        "bcdedit",
    ];
    COMMANDS.contains(&executable).then_some(executable)
}

fn decode_console(
    space: &X64AddressSpace<'_>,
    pid: u64,
    address: u64,
    layout: ConsoleLayout,
) -> Option<ConsoleRecord> {
    let history_size = read_u16(space, address + layout.history_size)?;
    let history_max = read_u16(space, address + layout.history_max)?;
    let screen_x = read_i16(space, address + layout.screen_x)?;
    let screen_y = read_i16(space, address + layout.screen_y)?;
    if !(1..=1024).contains(&history_size)
        || !(1..=1024).contains(&history_max)
        || history_size > history_max
        || !(1..=1000).contains(&screen_x)
        || !(1..=10_000).contains(&screen_y)
    {
        return None;
    }
    let title = space
        .read_u64(address + layout.title)
        .ok()
        .and_then(|pointer| read_utf16_z(space, pointer, 512));
    let original_title = space
        .read_u64(address + layout.original_title)
        .ok()
        .and_then(|pointer| read_utf16_z(space, pointer, 512));
    if title.as_deref().unwrap_or("").is_empty()
        && original_title.as_deref().unwrap_or("").is_empty()
    {
        return None;
    }
    let current_screen = space
        .read_u64(address + layout.current_screen)
        .ok()
        .filter(|pointer| valid_user_pointer(*pointer))?;
    let screen_lines = decode_screen(space, current_screen);
    Some(ConsoleRecord {
        conhost_pid: pid,
        address,
        layout: layout.name.to_owned(),
        screen_x,
        screen_y,
        command_history_size: history_size,
        history_buffer_max: history_max,
        title,
        original_title,
        current_screen_buffer: Some(current_screen),
        screen_lines,
    })
}

fn history_prefilter(bytes: &[u8]) -> bool {
    if bytes.len() < 0x60 {
        return false;
    }
    let begin = u64::from_le_bytes(bytes[0x10..0x18].try_into().unwrap());
    let end = u64::from_le_bytes(bytes[0x18..0x20].try_into().unwrap());
    let capacity = u64::from_le_bytes(bytes[0x20..0x28].try_into().unwrap());
    let command_count_max = u16::from_le_bytes(bytes[0x28..0x2a].try_into().unwrap());
    let handle_record = u64::from_le_bytes(bytes[0x50..0x58].try_into().unwrap());
    let last_displayed = i16::from_le_bytes(bytes[0x5c..0x5e].try_into().unwrap());
    (1..=1024).contains(&command_count_max)
        && valid_user_pointer(begin)
        && end >= begin
        && capacity >= end
        && (end - begin) % 32 == 0
        && (capacity - begin) % 32 == 0
        && capacity - begin <= u64::from(command_count_max) * 32
        && valid_user_pointer(handle_record)
        && (-1..=command_count_max as i16).contains(&last_displayed)
}

fn decode_screen(space: &X64AddressSpace<'_>, screen: u64) -> Vec<String> {
    let Some(info) = space
        .read_u64(screen + 0x38)
        .ok()
        .filter(|pointer| valid_user_pointer(*pointer))
    else {
        return Vec::new();
    };
    let capacity = read_i16(space, info + 0x0a).unwrap_or(0);
    let start = read_i16(space, info + 0x58).unwrap_or(0);
    let Some(rows) = space
        .read_u64(info + 0x10)
        .ok()
        .filter(|pointer| valid_user_pointer(*pointer))
    else {
        return Vec::new();
    };
    if !(1..=2000).contains(&capacity) || start < 0 || start >= capacity {
        return Vec::new();
    }
    let mut output = Vec::new();
    for ordinal in 0..capacity as usize {
        let index = (usize::try_from(start).unwrap_or(0) + ordinal) % capacity as usize;
        let Some(row) = space
            .read_u64(rows + index as u64 * 8)
            .ok()
            .filter(|pointer| valid_user_pointer(*pointer))
        else {
            break;
        };
        let length = read_i16(space, row + 8).unwrap_or(0);
        let Some(chars) = space
            .read_u64(row)
            .ok()
            .filter(|pointer| valid_user_pointer(*pointer))
        else {
            break;
        };
        if !(1..=1000).contains(&length) {
            break;
        }
        let mut bytes = vec![0u8; length as usize * 3];
        if space.read_virtual(chars, &mut bytes).is_err() {
            break;
        }
        let line = bytes
            .chunks_exact(3)
            .map(|cell| char::decode_utf16([u16::from_le_bytes([cell[0], cell[1]])]))
            .map(|mut decoded| decoded.next().and_then(Result::ok).unwrap_or('\u{fffd}'))
            .collect::<String>()
            .trim_end()
            .to_owned();
        output.push(line);
    }
    while output.last().is_some_and(|line| line.is_empty()) {
        output.pop();
    }
    output
}

fn read_utf16(space: &X64AddressSpace<'_>, address: u64, units: usize) -> Option<String> {
    let mut bytes = vec![0u8; units.checked_mul(2)?];
    space.read_virtual(address, &mut bytes).ok()?;
    let text = String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    );
    plausible_text(&text).then_some(text)
}

fn read_utf16_z(space: &X64AddressSpace<'_>, address: u64, max_units: usize) -> Option<String> {
    if !valid_user_pointer(address) {
        return None;
    }
    let mut bytes = vec![0u8; max_units.checked_mul(2)?];
    space.read_virtual(address, &mut bytes).ok()?;
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    let text = String::from_utf16_lossy(&units);
    plausible_text(&text).then_some(text)
}

fn plausible_text(text: &str) -> bool {
    let mut meaningful = 0usize;
    let mut unusual = 0usize;
    for character in text.chars() {
        let code = u32::from(character);
        if character.is_control() && !matches!(character, '\r' | '\n' | '\t')
            || (0xe000..=0xf8ff).contains(&code)
            || (0xfdd0..=0xfdef).contains(&code)
            || code & 0xffff == 0xfffe
            || code & 0xffff == 0xffff
        {
            return false;
        }
        if character.is_ascii_alphanumeric() || (0x3400..=0x9fff).contains(&code) {
            meaningful += 1;
        }
        let ordinary = character.is_ascii()
            || (0x00c0..=0x024f).contains(&code)
            || (0x3000..=0x303f).contains(&code)
            || (0x3400..=0x9fff).contains(&code);
        if !ordinary {
            unusual += 1;
        }
    }
    meaningful != 0 && unusual * 10 <= text.chars().count().max(1)
}

fn valid_user_pointer(pointer: u64) -> bool {
    (0x1_0000..0x0000_8000_0000_0000).contains(&pointer)
}

fn read_u16(space: &X64AddressSpace<'_>, address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_i16(space: &X64AddressSpace<'_>, address: u64) -> Option<i16> {
    read_u16(space, address).map(|value| value as i16)
}

fn read_u32(space: &X64AddressSpace<'_>, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_user_pointer_range() {
        assert!(valid_user_pointer(0x7ff6_0000_0000));
        assert!(!valid_user_pointer(0xffff_8000_0000_0000));
        assert!(!valid_user_pointer(0x1000));
    }

    #[test]
    fn recovers_only_command_like_utf16_strings() {
        let bytes = "noise\0net user ASP.NET pn8kMawy /add\0ordinary sentence\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let records = extract_raw_commands(&bytes, 0x1000);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].text, "net user ASP.NET pn8kMawy /add");
    }

    #[test]
    fn recognizes_classic_and_windows_terminal_console_hosts() {
        assert!(is_console_host_process("conhost.exe"));
        assert!(is_console_host_process("OpenConsole.exe"));
        assert!(is_console_host_process("OpenConsole.ex"));
        assert!(!is_console_host_process("WindowsTerminal.exe"));
    }

    #[test]
    fn rejects_terminal_banners_and_host_startup_arguments() {
        assert_eq!(
            normalize_raw_command(
                "PowerShell for new features and improvements! https://aka.ms/powershell"
            ),
            None
        );
        assert_eq!(normalize_raw_command("cmd.exe 4176 --strictPort"), None);
    }
}
