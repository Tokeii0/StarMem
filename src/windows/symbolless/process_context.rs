//! Shared process-context provider for future cmdline/envars fallback adapters.
//! Target export accessors establish EPROCESS fields; user ABI priors remain explicit.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};

use super::{ProbeReport, ProcessRecord, accessor, pe_size, u16_at, u32_at, validate_user_pe};
use crate::address::X64AddressSpace;
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;

const MAX_INVALID_ENV_WARNINGS: usize = 16;

pub struct ProcessContextOptions {
    pub pid: Option<u64>,
    pub limit: usize,
    pub environment_bytes: usize,
}

#[derive(Serialize)]
pub struct ProcessContextRecord {
    pub pid: u64,
    pub name: String,
    pub eprocess: u64,
    pub directory_table_base: Option<u64>,
    pub peb: Option<u64>,
    pub peb_physical: Option<u64>,
    pub process_parameters: Option<u64>,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
    pub command_line_address: Option<u64>,
    pub environment_address: Option<u64>,
    pub parameters_status: &'static str,
    pub environment_status: &'static str,
    pub environment_bytes_read: usize,
    pub warnings: Vec<String>,
}

#[derive(Serialize)]
pub struct EnvironmentRecord {
    pub pid: u64,
    pub name: String,
    pub eprocess: u64,
    pub variable: String,
    pub value: String,
    pub virtual_address: u64,
    pub physical_address: Option<u64>,
}

pub(super) fn user_pointer(value: u64) -> bool {
    (0x10000..0x0000_8000_0000_0000).contains(&value) && value & 1 == 0
}

pub(super) fn unicode(
    space: &X64AddressSpace<'_>,
    descriptor: u64,
) -> Result<(String, Option<u64>)> {
    let mut header = [0; 16];
    space.read_virtual(descriptor, &mut header)?;
    let length = u16_at(&header, 0) as usize;
    let maximum = u16_at(&header, 2) as usize;
    let address = u64::from_le_bytes(header[8..16].try_into()?);
    ensure!(
        length & 1 == 0 && maximum & 1 == 0 && length <= maximum && length <= 16_384,
        "UNICODE_STRING 长度不符合有界 UTF-16 范围"
    );
    if length == 0 {
        return Ok((String::new(), None));
    }
    ensure!(
        user_pointer(address) && address + length as u64 <= 0x0000_8000_0000_0000,
        "UNICODE_STRING 缓冲区不在用户地址范围"
    );
    let mut bytes = vec![0; length];
    space.read_virtual(address, &mut bytes)?;
    let words: Vec<_> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    ensure!(
        !words.contains(&0),
        "长度内出现 NUL，拒绝拼接有歧义的进程字符串"
    );
    Ok((String::from_utf16(&words)?, Some(address)))
}

pub(super) fn validate_native_peb(
    space: &X64AddressSpace<'_>,
    row: &ProcessRecord,
    peb: u64,
) -> Result<()> {
    ensure!(
        row.kernel_mapping_verified && user_pointer(peb) && peb & 7 == 0,
        "进程页表或 PEB 地址未通过校验"
    );
    let image_base = space.read_u64(peb + 0x10)?;
    ensure!(
        row.image_base == Some(image_base) && row.user_image_pe_verified == Some(true),
        "PEB 映像基址与目标 EPROCESS 导出字段不一致或不可核验"
    );
    validate_user_pe(space, image_base)?;
    let mut dos = [0; 64];
    space.read_virtual(image_base, &mut dos)?;
    let mut pe = [0; 26];
    space.read_virtual(image_base + u32_at(&dos, 0x3c) as u64, &mut pe)?;
    ensure!(
        u16_at(&pe, 4) == 0x8664 && u16_at(&pe, 24) == 0x20b,
        "当前只解释原生 AMD64 PEB；WOW64 尚未支持"
    );
    Ok(())
}

fn native_parameters(space: &X64AddressSpace<'_>, row: &ProcessRecord, peb: u64) -> Result<u64> {
    validate_native_peb(space, row, peb)?;
    let parameters = space.read_u64(peb + 0x20)?;
    ensure!(
        user_pointer(parameters) && parameters & 7 == 0,
        "进程参数指针无效"
    );
    let mut header = [0; 12];
    space.read_virtual(parameters, &mut header)?;
    let max = u32_at(&header, 0);
    let length = u32_at(&header, 4);
    ensure!(
        (0x88..=0x1_0000).contains(&length) && length <= max && max <= 0x10_0000,
        "进程参数长度不符合支持范围"
    );
    ensure!(
        u32_at(&header, 8) & 1 != 0,
        "进程参数指针未规范化，不猜测相对地址"
    );
    Ok(parameters)
}

fn environment(
    space: &X64AddressSpace<'_>,
    owner: &ProcessRecord,
    address: u64,
    maximum: usize,
    record_limit: usize,
    cancel: &CancellationToken,
) -> Result<(Vec<EnvironmentRecord>, &'static str, usize, Vec<String>)> {
    ensure!(
        user_pointer(address) && address + maximum as u64 <= 0x0000_8000_0000_0000,
        "环境块指针无效"
    );
    let mut bytes = Vec::new();
    let mut complete = false;
    let mut warnings = Vec::new();
    while bytes.len() < maximum {
        cancel.check_cancelled()?;
        let at = address + bytes.len() as u64;
        let size = (4096 - (at as usize & 4095)).min(maximum - bytes.len());
        let mut page = vec![0; size];
        if let Err(error) = space.read_virtual(at, &mut page) {
            warnings.push(format!("环境块在 {at:#x} 缺页：{error:#}"));
            break;
        }
        let previous = bytes.len();
        bytes.extend_from_slice(&page);
        if let Some(end) = (previous.saturating_sub(2)..bytes.len().saturating_sub(3))
            .step_by(2)
            .find(|&i| bytes[i..i + 4] == [0; 4])
        {
            bytes.truncate(end + 4);
            complete = true;
            break;
        }
    }
    if !complete && warnings.is_empty() {
        warnings.push("环境块达到读取上限，未找到双 NUL 终止符".into());
    }
    let read = bytes.len();
    let words: Vec<_> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let mut records = Vec::new();
    let mut start = 0;
    let mut invalid_entries = 0usize;
    for (index, &word) in words.iter().enumerate() {
        if index & 255 == 0 {
            cancel.check_cancelled()?;
        }
        if word != 0 {
            continue;
        }
        if index == start {
            break;
        }
        if records.len() >= record_limit {
            complete = false;
            warnings.push("环境变量达到记录预算，后续条目未纳入报告".into());
            break;
        }
        let parsed = String::from_utf16(&words[start..index])
            .ok()
            .and_then(|entry| {
                let split = entry.char_indices().skip(1).find(|(_, ch)| *ch == '=')?.0;
                Some((entry[..split].to_owned(), entry[split + 1..].to_owned()))
            });
        if let Some((variable, value)) = parsed {
            let at = address + start as u64 * 2;
            records.push(EnvironmentRecord {
                pid: owner.pid,
                name: owner.name.clone(),
                eprocess: owner.eprocess,
                variable,
                value,
                virtual_address: at,
                physical_address: space.translate(at).ok(),
            });
        } else {
            complete = false;
            invalid_entries += 1;
            if invalid_entries <= MAX_INVALID_ENV_WARNINGS {
                warnings.push(format!(
                    "环境块 +{:#x} 存在无效 UTF-16 或无名称/值分隔符的条目",
                    start * 2
                ));
            }
        }
        start = index + 1;
    }
    if invalid_entries > MAX_INVALID_ENV_WARNINGS {
        warnings.push(format!(
            "另有 {} 条无效环境项；仅保留前 {MAX_INVALID_ENV_WARNINGS} 条位置告警，后续可读变量仍保留",
            invalid_entries - MAX_INVALID_ENV_WARNINGS
        ));
    }
    let status = if complete {
        "complete"
    } else if read == 0 {
        "unavailable"
    } else {
        "partial"
    };
    Ok((records, status, read, warnings))
}

pub(super) fn analyze(
    image: &MemoryImage,
    kernel: &ProbeReport,
    options: &ProcessContextOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    ensure!(
        (1..=128).contains(&options.limit),
        "进程上下文上限必须为 1..128"
    );
    ensure!(
        (4096..=131_072).contains(&options.environment_bytes) && options.environment_bytes & 1 == 0,
        "单进程环境读取上限必须为 4096..131072 的偶数字节数"
    );
    cancel.check_cancelled()?;
    ensure!(
        options
            .pid
            .is_none_or(|pid| kernel.processes.iter().any(|row| row.pid == pid)),
        "未在本次无符号活动进程清单中找到指定 PID"
    );
    let kspace = X64AddressSpace::new(image, kernel.kernel_dtb)?;
    let size = pe_size(&kspace, kernel.kernel_base)?;
    let peb_field = accessor(
        image,
        kernel.kernel_dtb,
        kernel.kernel_base,
        size,
        "PsGetProcessPeb",
        "_EPROCESS.Peb",
        false,
    )?;
    let selected: Vec<_> = kernel
        .processes
        .iter()
        .filter(|row| options.pid.is_none_or(|pid| row.pid == pid))
        .collect();
    let mut records = Vec::new();
    let mut variables = Vec::new();
    for owner in selected.iter().take(options.limit) {
        cancel.check_cancelled()?;
        let mut record = ProcessContextRecord {
            pid: owner.pid,
            name: owner.name.clone(),
            eprocess: owner.eprocess,
            directory_table_base: owner.directory_table_base,
            peb: None,
            peb_physical: None,
            process_parameters: None,
            image_path: None,
            command_line: None,
            command_line_address: None,
            environment_address: None,
            parameters_status: "unavailable",
            environment_status: "not_run",
            environment_bytes_read: 0,
            warnings: Vec::new(),
        };
        let result = (|| -> Result<()> {
            let peb = kspace.read_u64(owner.eprocess + peb_field.offset)?;
            record.peb = Some(peb);
            ensure!(
                peb != 0,
                "该进程没有可读的用户 PEB（系统进程可能不具有用户参数）"
            );
            let space = X64AddressSpace::new(
                image,
                owner.directory_table_base.context("进程 DTB 不可用")?,
            )?;
            record.peb_physical = space.translate(peb).ok();
            let parameters = native_parameters(&space, owner, peb)?;
            record.process_parameters = Some(parameters);
            match unicode(&space, parameters + 0x60) {
                Ok((value, _)) => record.image_path = Some(value),
                Err(error) => record.warnings.push(format!("映像路径不可读：{error:#}")),
            }
            match unicode(&space, parameters + 0x70) {
                Ok((value, address)) => {
                    record.command_line = Some(value);
                    record.command_line_address = address;
                }
                Err(error) => record.warnings.push(format!("命令行不可读：{error:#}")),
            }
            record.parameters_status =
                match (record.image_path.is_some(), record.command_line.is_some()) {
                    (true, true) => "complete",
                    (false, false) => "unavailable",
                    _ => "partial",
                };
            record.environment_status = "unavailable";
            let address = space.read_u64(parameters + 0x80)?;
            record.environment_address = Some(address);
            let remaining = 8192usize.saturating_sub(variables.len()).min(2048);
            ensure!(
                remaining > 0,
                "全报告环境变量已达到 8192 条预算，当前进程环境未继续读取"
            );
            let (rows, status, count, warnings) = environment(
                &space,
                owner,
                address,
                options.environment_bytes,
                remaining,
                cancel,
            )?;
            variables.extend(rows);
            record.environment_status = status;
            record.environment_bytes_read = count;
            record.warnings.extend(warnings);
            Ok(())
        })();
        cancel.check_cancelled()?;
        if let Err(error) = result {
            record
                .warnings
                .push(format!("进程上下文未完整恢复：{error:#}"));
        }
        records.push(record);
    }
    Ok(json!({
        "method":"symbolless_x64_process_context_v1", "complete":false,
        "records":records, "environment":variables, "peb_field_evidence":peb_field,
        "process_list_traversal_complete":kernel.list_traversal_complete,
        "selected_processes":selected.len(),
        "truncated":selected.len() > options.limit,
        "truncated_by":if selected.len() > options.limit { vec!["process_context_limit"] } else { vec![] },
        "limits":{"processes":options.limit, "environment_bytes_per_process":options.environment_bytes, "unicode_string_bytes":16384, "environment_records_per_process":2048, "environment_records_total":8192, "invalid_environment_warning_samples_per_process":MAX_INVALID_ENV_WARNINGS},
        "layout_priors":[
            "PEB 偏移来自目标 PsGetProcessPeb 完整访问函数；PEB.ImageBaseAddress +0x10 与 EPROCESS 映像字段和用户 PE 交叉核验",
            "仅原生 AMD64：PEB.ProcessParameters +0x20；参数长度/规范化标志验证；ImagePathName +0x60、CommandLine +0x70、Environment +0x80",
            "环境块按 UTF-16 双 NUL 终止，分页面读取；保留完整条目和缺失/截断状态，不读取系统外部环境变量",
        ],
        "warnings":["实验性无符号推断，活动进程覆盖不保证完整；PEB 和参数属于可被进程修改的用户空间证据。", "WOW64 参数、DLL 链、VAD 和隐藏/退出进程尚未覆盖；空字段或缺页不说明进程没有对应行为。"],
    }))
}

#[cfg(test)]
pub(super) mod tests;
