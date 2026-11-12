//! Experimental x64 process discovery using only bytes in the captured image.
//! No SymbolStore, PDB, KernelProfile, SSYM, host kernel or version-offset table.
//! The PE export reader below only reads the target's resident PE export directory.

use std::collections::HashSet;

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

use crate::address::X64AddressSpace;
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::symbols::export_rva_from_virtual_pe;

mod api;
pub mod files;
mod process_context;
mod process_modules;
mod registry;
mod system;
pub use api::{RecoveryOptions, SymbollessSession};
pub use process_context::ProcessContextOptions;
pub use process_modules::ProcessModulesOptions;
pub use registry::RegistryOptions;

const DTB_MASK: u64 = 0x000f_ffff_ffff_f000;
const OBJECT_SEARCH_BYTES: u64 = 0x1000;
const DTB_SEARCH_BYTES: u64 = 0x200;
const MIN_PROCESSES: usize = 3;

#[derive(Debug, Serialize)]
pub struct FieldEvidence {
    pub field: &'static str,
    pub offset: u64,
    pub method: &'static str,
    pub instruction_address: Option<u64>,
    pub instruction_bytes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProcessRecord {
    pub pid: u64,
    pub name: String,
    pub eprocess: u64,
    pub eprocess_physical: u64,
    pub directory_table_base: Option<u64>,
    pub kernel_mapping_verified: bool,
    pub image_base: Option<u64>,
    pub user_image_pe_verified: Option<bool>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub method: &'static str,
    pub external_debug_symbols_used: bool,
    pub external_layouts_used: bool,
    pub layout_priors: Vec<&'static str>,
    /// Experimental inferred layouts cannot certify exhaustive process recovery.
    pub complete: bool,
    pub list_traversal_complete: bool,
    pub bootstrap_method: &'static str,
    pub kernel_base: u64,
    pub kernel_dtb: u64,
    pub system_eprocess: u64,
    pub active_process_head: Option<u64>,
    pub alternative_list_offsets: Vec<u64>,
    pub fields: Vec<FieldEvidence>,
    pub processes: Vec<ProcessRecord>,
    pub warnings: Vec<String>,
}

struct Kernel {
    dtb: u64,
    base: u64,
    size: u64,
    system: u64,
    pid: FieldEvidence,
    name: FieldEvidence,
    bootstrap_method: &'static str,
}

fn pointer(value: u64) -> bool {
    (0xffff_8000_0000_0000..=u64::MAX - 0x2000).contains(&value) && value & 7 == 0
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Only recognize a complete leaf accessor, never a byte pattern inside a function.
/// Other instruction forms are rejected instead of guessing their semantics.
fn decode_accessor(code: &[u8], address_result: bool) -> Option<u64> {
    let code = code.strip_prefix(&[0xf3, 0x0f, 0x1e, 0xfa]).unwrap_or(code);
    let opcode = if address_result { 0x8d } else { 0x8b };
    let (offset, end) = match code {
        [0x48, op, 0x81, a, b, c, d, ..] if *op == opcode => {
            (i32::from_le_bytes([*a, *b, *c, *d]) as i64, 7)
        }
        [0x48, op, 0x41, offset, ..] if *op == opcode => (*offset as i8 as i64, 4),
        _ => return None,
    };
    (offset >= 0 && offset < OBJECT_SEARCH_BYTES as i64 && code.get(end) == Some(&0xc3))
        .then_some(offset as u64)
}

fn pe_size(space: &X64AddressSpace<'_>, base: u64) -> Result<u64> {
    ensure!(
        pointer(base) && base & 0xfff == 0 && base < u64::MAX - 0x1_0000_0000,
        "内核候选地址无效"
    );
    let mut dos = [0; 64];
    space.read_virtual(base, &mut dos)?;
    ensure!(&dos[..2] == b"MZ", "无 MZ 签名");
    let offset = u32_at(&dos, 0x3c) as u64;
    ensure!(offset <= 0x1000, "PE 头偏移超限");
    let mut pe = [0; 0x108];
    space.read_virtual(base + offset, &mut pe)?;
    ensure!(
        &pe[..4] == b"PE\0\0" && u16_at(&pe, 4) == 0x8664 && u16_at(&pe, 24) == 0x20b,
        "候选不是 AMD64 PE32+"
    );
    let size = u32_at(&pe, 24 + 56) as u64;
    ensure!((0x1000..=0x4000_0000).contains(&size), "内核 PE 大小超限");
    Ok(size)
}

fn export(image: &MemoryImage, dtb: u64, base: u64, size: u64, name: &str) -> Result<u64> {
    let rva = export_rva_from_virtual_pe(image, dtb, base, name)?
        .with_context(|| format!("目标内核没有导出 {name}"))? as u64;
    ensure!(rva != 0 && rva + 32 <= size, "导出 {name} 超出目标内核");
    Ok(base + rva)
}

fn accessor(
    image: &MemoryImage,
    dtb: u64,
    base: u64,
    size: u64,
    name: &str,
    field: &'static str,
    address_result: bool,
) -> Result<FieldEvidence> {
    let address = export(image, dtb, base, size, name)?;
    let space = X64AddressSpace::new(image, dtb)?;
    let mut code = [0; 32];
    space.read_virtual(address, &mut code)?;
    let offset = decode_accessor(&code, address_result)
        .with_context(|| format!("{name} 不是已支持的完整字段访问函数：{}", hex::encode(code)))?;
    Ok(FieldEvidence {
        field,
        offset,
        method: "target_pe_export_leaf_accessor",
        instruction_address: Some(address),
        instruction_bytes: Some(hex::encode(code)),
    })
}

fn name_at(space: &X64AddressSpace<'_>, object: u64, offset: u64) -> Result<String> {
    let mut bytes = [0; 15];
    space.read_virtual(object + offset, &mut bytes)?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    ensure!(
        end > 0 && bytes[..end].iter().all(|b| (0x20..=0x7e).contains(b)),
        "进程名不是原型支持的有界 ASCII 名称"
    );
    Ok(String::from_utf8(bytes[..end].to_vec())?)
}

fn kernel_at(image: &MemoryImage, dtb: u64, base: u64, method: &'static str) -> Result<Kernel> {
    let space = X64AddressSpace::new(image, dtb)?;
    let size = pe_size(&space, base)?;
    let system = space.read_u64(export(image, dtb, base, size, "PsInitialSystemProcess")?)?;
    ensure!(pointer(system), "System EPROCESS 指针无效");
    let pid = accessor(
        image,
        dtb,
        base,
        size,
        "PsGetProcessId",
        "_EPROCESS.UniqueProcessId",
        false,
    )?;
    let name = accessor(
        image,
        dtb,
        base,
        size,
        "PsGetProcessImageFileName",
        "_EPROCESS.ImageFileName",
        true,
    )?;
    ensure!(
        space.read_u64(system + pid.offset)? == 4
            && name_at(&space, system, name.offset)? == "System",
        "System PID/名称交叉校验失败"
    );
    Ok(Kernel {
        dtb,
        base,
        size,
        system,
        pid,
        name,
        bootstrap_method: method,
    })
}

fn discover(image: &MemoryImage, cancel: &CancellationToken) -> Result<Kernel> {
    if let Some(dump) = image.dump64() {
        ensure!(dump.machine_type == 0x8664, "原型只支持 AMD64");
        let space = X64AddressSpace::new(image, dump.directory_table_base)?;
        if let Ok(base) = space.read_u64(dump.kd_debugger_data_block.saturating_add(0x18))
            && let Ok(kernel) =
                kernel_at(image, dump.directory_table_base, base, "dump_header_kdbg")
        {
            return Ok(kernel);
        }
    }
    let candidates = super::low_stub_candidates(image);
    let mut last_error = String::new();
    for (dtb, hint) in &candidates {
        let space = X64AddressSpace::new(image, *dtb)?;
        for distance in (0..=32 * 1024 * 1024).step_by(0x1000) {
            cancel.check_cancelled()?;
            // The start-up hint can lie in HAL below the kernel, so search both
            // directions. Accept only a PE whose exports and System object agree.
            let hint_page = hint & !0xfff;
            for base in [
                hint_page.checked_sub(distance),
                hint_page.checked_add(distance).filter(|_| distance != 0),
            ]
            .into_iter()
            .flatten()
            {
                let mut magic = [0; 2];
                if space.read_virtual(base, &mut magic).is_err() || magic != *b"MZ" {
                    continue;
                }
                match kernel_at(image, *dtb, base, "low_stub_and_target_pe") {
                    Ok(kernel) => return Ok(kernel),
                    Err(error) => last_error = format!("{base:#x}: {error:#}"),
                }
            }
        }
    }
    bail!(
        "未找到通过验证的内核：{} 个 Low Stub 候选；最近的 PE 候选错误：{last_error}",
        candidates.len()
    )
}

struct Walk {
    records: Vec<ProcessRecord>,
    head: Option<u64>,
    complete: bool,
    stop: Option<String>,
}

fn walk(
    image: &MemoryImage,
    kernel: &Kernel,
    links: u64,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Walk> {
    let space = X64AddressSpace::new(image, kernel.dtb)?;
    let start = kernel.system + links;
    let mut current = start;
    let mut seen = HashSet::new();
    let mut pids = HashSet::new();
    let mut output = Walk {
        records: Vec::new(),
        head: None,
        complete: false,
        stop: None,
    };
    loop {
        cancel.check_cancelled()?;
        if current == start && !seen.is_empty() {
            output.complete = output.head.is_some();
            if !output.complete {
                output.stop = Some("闭环中没有内核链表头".into());
            }
            break;
        }
        let step = (|| -> Result<u64> {
            ensure!(
                pointer(current) && seen.insert(current),
                "无效指针或非起点循环：{current:#x}"
            );
            let next = space.read_u64(current)?;
            let prev = space.read_u64(current + 8)?;
            ensure!(
                pointer(next) && pointer(prev),
                "链表邻接指针无效：{current:#x}"
            );
            ensure!(
                space.read_u64(next + 8)? == current && space.read_u64(prev)? == current,
                "链表双向互指失败：{current:#x}"
            );
            if (kernel.base..kernel.base + kernel.size).contains(&current) {
                ensure!(
                    output.head.replace(current).is_none(),
                    "出现多个内核链表头候选"
                );
            } else {
                ensure!(output.records.len() < limit, "达到进程记录上限 {limit}");
                let object = current.checked_sub(links).context("进程对象地址下溢")?;
                ensure!(pointer(object), "EPROCESS 地址无效");
                let pid = space.read_u64(object + kernel.pid.offset)?;
                ensure!(
                    pid <= u32::MAX as u64 && pids.insert(pid),
                    "PID 超限或重复：{pid}"
                );
                let name = name_at(&space, object, kernel.name.offset)?;
                output.records.push(ProcessRecord {
                    pid,
                    name,
                    eprocess: object,
                    eprocess_physical: space.translate(object)?,
                    directory_table_base: None,
                    kernel_mapping_verified: false,
                    image_base: None,
                    user_image_pe_verified: None,
                    warnings: Vec::new(),
                });
            }
            Ok(next)
        })();
        match step {
            Ok(next) => current = next,
            Err(error) => {
                output.stop = Some(format!("{error:#}"));
                break;
            }
        }
    }
    Ok(output)
}

fn infer_links(
    image: &MemoryImage,
    kernel: &Kernel,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<(u64, Walk, Vec<u64>)> {
    let active_offset = kernel.pid.offset + 8;
    let mut found = None;
    let mut alternatives = Vec::new();
    for offset in (0..OBJECT_SEARCH_BYTES).step_by(8) {
        cancel.check_cancelled()?;
        let candidate = walk(image, kernel, offset, limit, cancel)?;
        if candidate.records.len() < MIN_PROCESSES {
            continue;
        }
        // EPROCESS contains other genuine process lists (e.g. MmProcessLinks).
        // Reciprocity alone cannot give a list its semantic identity. This is
        // an explicit corpus-derived ordering prior, NOT a build-specific offset.
        if offset == active_offset {
            found = Some(candidate);
        } else {
            alternatives.push(offset);
        }
    }
    let traversal = found.with_context(|| format!(
        "PID 邻接活动链表候选 {active_offset:#x} 未通过至少三个进程验证；其他链表候选 {alternatives:x?} 不能替代活动列表"))?;
    Ok((active_offset, traversal, alternatives))
}

fn verify_dtb(image: &MemoryImage, kernel: &Kernel, dtb: u64) -> Result<()> {
    ensure!(
        dtb != 0 && image.contains_physical(dtb),
        "进程 DTB 未包含在镜像中"
    );
    let system = X64AddressSpace::new(image, kernel.dtb)?;
    let process = X64AddressSpace::new(image, dtb)?;
    for address in [kernel.base, kernel.system] {
        ensure!(
            process.translate(address)? == system.translate(address)?,
            "进程 DTB 对内核锚点 {address:#x} 的映射不一致"
        );
    }
    Ok(())
}

fn infer_dtb(
    image: &MemoryImage,
    kernel: &Kernel,
    rows: &[ProcessRecord],
    cancel: &CancellationToken,
) -> Result<u64> {
    let space = X64AddressSpace::new(image, kernel.dtb)?;
    let mut offsets = Vec::new();
    for offset in (0..DTB_SEARCH_BYTES).step_by(8) {
        cancel.check_cancelled()?;
        let Ok(value) = space.read_u64(kernel.system + offset) else {
            continue;
        };
        if value & DTB_MASK != kernel.dtb & DTB_MASK {
            continue;
        }
        let mut valid = 0;
        for row in rows {
            cancel.check_cancelled()?;
            if space
                .read_u64(row.eprocess + offset)
                .is_ok_and(|raw| verify_dtb(image, kernel, raw & DTB_MASK).is_ok())
            {
                valid += 1;
            }
        }
        if valid >= MIN_PROCESSES {
            offsets.push(offset);
        }
    }
    ensure!(
        offsets.len() == 1,
        "DTB 字段候选数量为 {}，拒绝缺失或歧义布局",
        offsets.len()
    );
    Ok(offsets[0])
}

fn validate_user_pe(space: &X64AddressSpace<'_>, base: u64) -> Result<()> {
    ensure!(
        (0x10000..0x0000_8000_0000_0000).contains(&base) && base & 0xfff == 0,
        "用户映像基址无效"
    );
    let mut dos = [0; 64];
    space.read_virtual(base, &mut dos)?;
    ensure!(&dos[..2] == b"MZ", "用户映像 MZ 不可验证");
    let offset = u32_at(&dos, 0x3c) as u64;
    ensure!(offset <= 0x1000, "用户 PE 头偏移超限");
    let mut pe = [0; 26];
    space.read_virtual(base + offset, &mut pe)?;
    ensure!(
        &pe[..4] == b"PE\0\0" && matches!(u16_at(&pe, 24), 0x10b | 0x20b),
        "用户 PE 签名/可选头不可验证"
    );
    Ok(())
}

/// Caller owns authorization and cancellation, as with other in-process modules.
/// System metadata only needs the validated kernel, not a recoverable process list.
fn probe_system(image: &MemoryImage, cancel: &CancellationToken) -> Result<ProbeReport> {
    cancel.check_cancelled()?;
    let kernel = discover(image, cancel)?;
    Ok(ProbeReport {
        method: "symbolless_x64_system_v1",
        external_debug_symbols_used: false,
        external_layouts_used: false,
        layout_priors: vec![],
        complete: false,
        list_traversal_complete: false,
        bootstrap_method: kernel.bootstrap_method,
        kernel_base: kernel.base,
        kernel_dtb: kernel.dtb,
        system_eprocess: kernel.system,
        active_process_head: None,
        alternative_list_offsets: vec![],
        fields: vec![kernel.pid, kernel.name],
        processes: vec![],
        warnings: vec![],
    })
}

pub fn probe(
    image: &MemoryImage,
    process_limit: usize,
    cancel: &CancellationToken,
) -> Result<ProbeReport> {
    ensure!(
        (MIN_PROCESSES..=65_536).contains(&process_limit),
        "进程上限必须为 3..65536"
    );
    cancel.check_cancelled()?;
    let kernel = discover(image, cancel)?;
    let (links, mut traversal, alternative_list_offsets) =
        infer_links(image, &kernel, process_limit, cancel)?;
    let dtb_offset = infer_dtb(image, &kernel, &traversal.records, cancel)?;
    let mut warnings = vec![
        "实验性推断：仅遍历活动进程链表，未扫描脱链或已退出进程，不能声明进程恢复完整".into(),
        "限定 AMD64、48 位规范地址、可读的简单导出访问函数；链表搜索 4 KiB，DTB 字段搜索前 512 字节，进程名按 15 字节 ASCII 读取".into(),
    ];
    if let Some(stop) = traversal.stop {
        warnings.push(stop);
    }
    let image_field = match accessor(
        image,
        kernel.dtb,
        kernel.base,
        kernel.size,
        "PsGetProcessSectionBaseAddress",
        "_EPROCESS.SectionBaseAddress",
        false,
    ) {
        Ok(field) => Some(field),
        Err(error) => {
            warnings.push(format!("用户映像交叉验证不可用：{error:#}"));
            None
        }
    };
    let space = X64AddressSpace::new(image, kernel.dtb)?;
    for row in &mut traversal.records {
        cancel.check_cancelled()?;
        match space.read_u64(row.eprocess + dtb_offset) {
            Ok(raw) => {
                let dtb = raw & DTB_MASK;
                row.directory_table_base = Some(dtb);
                match verify_dtb(image, &kernel, dtb) {
                    Ok(()) => row.kernel_mapping_verified = true,
                    Err(error) => row.warnings.push(format!("页表校验失败：{error:#}")),
                }
                if let Some(field) = &image_field {
                    match space.read_u64(row.eprocess + field.offset) {
                        Ok(base) => {
                            row.image_base = Some(base);
                            if base != 0 {
                                let checked = X64AddressSpace::new(image, dtb)
                                    .and_then(|process| validate_user_pe(&process, base));
                                row.user_image_pe_verified = Some(checked.is_ok());
                                if let Err(error) = checked {
                                    row.warnings.push(format!("用户映像不可验证：{error:#}"));
                                }
                            }
                        }
                        Err(error) => row.warnings.push(format!("映像基址读取失败：{error:#}")),
                    }
                }
            }
            Err(error) => row.warnings.push(format!("DTB 字段读取失败：{error:#}")),
        }
    }
    let mut fields = vec![
        kernel.pid,
        kernel.name,
        FieldEvidence {
            field: "_EPROCESS.ActiveProcessLinks",
            offset: links,
            method: "pid_adjacency_prior_and_reciprocal_process_list",
            instruction_address: None,
            instruction_bytes: None,
        },
        FieldEvidence {
            field: "directory_table_base_from_eprocess",
            offset: dtb_offset,
            method: "bootstrap_dtb_and_multiple_process_page_tables",
            instruction_address: None,
            instruction_bytes: None,
        },
    ];
    if let Some(field) = image_field {
        fields.push(field);
    }
    Ok(ProbeReport {
        method: "symbolless_x64_v1",
        external_debug_symbols_used: false,
        external_layouts_used: false,
        layout_priors: vec![
            "Windows AMD64 ActiveProcessLinks == UniqueProcessId + 8：语料中的 1138 份 AMD64 PDB 均满足；未知布局不保证满足，仍须验证目标链表",
        ],
        complete: false,
        list_traversal_complete: traversal.complete,
        bootstrap_method: kernel.bootstrap_method,
        kernel_base: kernel.base,
        kernel_dtb: kernel.dtb,
        system_eprocess: kernel.system,
        active_process_head: traversal.head,
        alternative_list_offsets,
        fields,
        processes: traversal.records,
        warnings,
    })
}

#[cfg(test)]
mod tests;
