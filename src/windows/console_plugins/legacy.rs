//! Legacy winsrv command history in a 32-bit csrss address space.
//! Structure offsets are documented by the DFRWS 2010 console research and
//! https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/malware/cmdhistory.py
//! This parser validates resident pointers and list backlinks; raw text is not
//! promoted to a command-history record.

use super::*;
use crate::address::X86PaeAddressSpace;
use crate::cancellation::CancellationToken;

pub(super) fn scan(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
    screen_requested: bool,
    cancellation: &CancellationToken,
) -> Result<ConsoleReport> {
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut report = ConsoleReport {
        records: Vec::new(),
        histories: Vec::new(),
        conhost_processes: 0,
        mapped_bytes_examined: 0,
        missing_bytes: 0,
        complete: processes.complete,
        warnings: processes
            .warnings
            .iter()
            .map(|w| w.message.clone())
            .collect(),
    };
    for process in processes
        .processes
        .iter()
        .filter(|p| p.name.eq_ignore_ascii_case("csrss.exe"))
    {
        report.conhost_processes += 1;
        let result = (|| -> Result<()> {
            let space = X86PaeAddressSpace::new(
                image,
                process
                    .details
                    .directory_table_base
                    .ok_or_else(|| anyhow::anyhow!("缺少 csrss DTB"))?,
            )?;
            let mappings = space.enumerate_mappings_cancellable(
                VirtualAddressRegion::User,
                1_000_000,
                cancellation,
            )?;
            report.complete &= !mappings.truncated && mappings.warnings.is_empty();
            report.warnings.extend(mappings.warnings);
            let mut seen = HashSet::new();
            for mapping in mappings.mappings {
                let mut address = mapping.virtual_start;
                while address < mapping.virtual_end {
                    cancellation.check_cancelled()?;
                    let mut page = [0u8; 4096];
                    if space.read_virtual(address, &mut page).is_err() {
                        report.missing_bytes += 4096;
                        report.complete = false;
                        address += 4096;
                        continue;
                    }
                    report.mapped_bytes_examined += 4096;
                    // Counts may straddle the page boundary; the validating
                    // reader below follows the process page tables separately.
                    for offset in (0..4096).step_by(4) {
                        let flags = u32::from_le_bytes(page[offset..offset + 4].try_into()?);
                        if flags > 3 {
                            continue;
                        }
                        let candidate = address + offset as u64;
                        if !seen.insert(candidate) {
                            continue;
                        }
                        if let Some(history) = parse_history(&space, process, candidate) {
                            if report.histories.len() == limit {
                                report.complete = false;
                                report
                                    .warnings
                                    .push(format!("XP 控制台命令历史达到 {limit} 条上限"));
                                return Ok(());
                            }
                            report.histories.push(history);
                        }
                    }
                    address += 4096;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            if crate::cancellation::is_cancellation_error(&error) {
                return Err(error);
            }
            report.complete = false;
            report.warnings.push(format!(
                "PID {} 的 XP 控制台读取失败：{error:#}",
                process.pid
            ));
        }
    }
    if report.conhost_processes == 0 {
        report.complete = false;
        report
            .warnings
            .push("未恢复到活动的 csrss.exe 控制台宿主".into());
    }
    if screen_requested {
        report.complete = false;
        report
            .warnings
            .push("XP winsrv 仅恢复结构化命令历史；屏幕缓冲区尚未重建".into());
    }
    Ok(report)
}

fn pointer(address: u64) -> bool {
    (0x10000..0x8000_0000).contains(&address) && address & 3 == 0
}

fn word(space: &X86PaeAddressSpace<'_>, address: u64) -> Option<i16> {
    let mut bytes = [0; 2];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(i16::from_le_bytes(bytes))
}

fn terminated_text(space: &X86PaeAddressSpace<'_>, address: u64) -> Option<String> {
    if !pointer(address) {
        return None;
    }
    let mut words = Vec::new();
    for index in 0..256 {
        let value = word(space, address + index * 2)? as u16;
        if value == 0 {
            return String::from_utf16(&words)
                .ok()
                .filter(|text| !text.is_empty());
        }
        words.push(value);
    }
    None
}

fn parse_history(
    space: &X86PaeAddressSpace<'_>,
    process: &ProcessRecord,
    address: u64,
) -> Option<CommandHistoryRecord> {
    let count = word(space, address + 0x10)?;
    let maximum = word(space, address + 0x18)?;
    let last_added = word(space, address + 0x12)?;
    let displayed = word(space, address + 0x14)?;
    let first = word(space, address + 0x16)?;
    if !(1..=1024).contains(&maximum)
        || count <= 0
        || count > maximum
        || !(-1..maximum).contains(&last_added)
        || !(-1..maximum).contains(&displayed)
        || !(0..maximum).contains(&first)
        || (first != 0 && first != last_added + 1)
    {
        return None;
    }
    let application = terminated_text(space, u64::from(space.read_u32(address + 0x0c).ok()?))?;
    if !application.to_ascii_lowercase().ends_with(".exe") {
        return None;
    }
    let handle = space.read_u32(address + 0x1c).ok()?;
    if handle == 0 || handle > 0xffff || handle & 3 != 0 {
        return None;
    }
    let popup = address + 0x20;
    let forward = u64::from(space.read_u32(popup).ok()?);
    let backward = u64::from(space.read_u32(popup + 4).ok()?);
    if !pointer(forward)
        || !pointer(backward)
        || space.read_u32(forward + 4).ok()? as u64 != popup
        || space.read_u32(backward).ok()? as u64 != popup
    {
        return None;
    }
    let mut commands = Vec::new();
    for index in 0..count as usize {
        let command = u64::from(space.read_u32(address + 0x28 + index as u64 * 4).ok()?);
        if !pointer(command) {
            return None;
        }
        let length = word(space, command)? as u16 as usize;
        if length == 0 || length > 32766 || length & 1 != 0 {
            return None;
        }
        let mut bytes = vec![0u8; length];
        space.read_virtual(command + 2, &mut bytes).ok()?;
        let words: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        let text = String::from_utf16(&words).ok()?;
        if text
            .chars()
            .any(|c| c == '\0' || (c.is_control() && !matches!(c, '\t' | '\r' | '\n')))
        {
            return None;
        }
        commands.push(CommandRecord {
            index,
            address: command,
            text,
        });
    }
    Some(CommandHistoryRecord {
        conhost_pid: process.pid,
        conhost: process.name.clone(),
        address,
        process_handle: handle as u64,
        application: Some(application),
        command_count: commands.len(),
        command_count_max: maximum as u16,
        last_displayed: displayed as i32,
        commands,
    })
}
