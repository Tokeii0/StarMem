//! Native AMD64 loader-list evidence. These are explicit user ABI priors, not
//! kernel symbol offsets. A readable list does not prove exhaustive module coverage.
use std::collections::HashSet;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};

use super::process_context::{unicode, user_pointer, validate_native_peb};
use super::{ProbeReport, ProcessRecord, accessor, pe_size, u16_at, u32_at};
use crate::address::X64AddressSpace;
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;

const MAX_RECORDS: usize = 8192;
const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;

pub struct ProcessModulesOptions {
    pub pid: Option<u64>,
    pub limit: usize,
    pub module_limit: usize,
}

impl ProcessModulesOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=128).contains(&self.limit),
            "模块分析进程上限须为 1..128"
        );
        ensure!(
            (1..=4096).contains(&self.module_limit),
            "单进程模块上限须为 1..4096"
        );
        Ok(())
    }
}

#[derive(Serialize)]
pub struct SymbollessModuleRecord {
    pub source_label: &'static str,
    pub pid: u64,
    pub name: String,
    pub eprocess: u64,
    pub directory_table_base: u64,
    pub peb: u64,
    pub ldr_entry: u64,
    pub entry_physical: Option<u64>,
    pub base: u64,
    pub size_of_image: u32,
    pub full_name: Option<String>,
    pub base_name: Option<String>,
    pub is_main_image: bool,
    pub pe_status: &'static str,
    pub pe_size_of_image: Option<u32>,
    pub warnings: Vec<String>,
}

#[derive(Serialize)]
struct ProcessModuleSource {
    pid: u64,
    name: String,
    eprocess: u64,
    directory_table_base: Option<u64>,
    peb: Option<u64>,
    ldr: Option<u64>,
    list_head: Option<u64>,
    list_traversal_complete: bool,
    records_recovered: usize,
    module_status: &'static str,
    warnings: Vec<String>,
}

fn aligned_pointer(at: u64) -> bool {
    user_pointer(at) && at & 7 == 0 && at <= 0x0000_8000_0000_0000 - 0x100
}

fn module_pe(space: &X64AddressSpace<'_>, base: u64, size: u32) -> Result<(u32, bool)> {
    // Read failures stay distinct from a readable but unsupported/mismatched PE.
    let mut dos = [0; 64];
    space.read_virtual(base, &mut dos)?;
    let offset = u32_at(&dos, 0x3c) as u64;
    if &dos[..2] != b"MZ" || !(64..=0x10_0000).contains(&offset) || offset + 0x54 > u64::from(size)
    {
        return Ok((0, false));
    }
    let mut header = [0; 0x54];
    space.read_virtual(base + offset, &mut header)?;
    let image_size = u32_at(&header, 24 + 56);
    Ok((
        image_size,
        &header[..4] == b"PE\0\0"
            && u16_at(&header, 4) == 0x8664
            && u16_at(&header, 20) >= 0x70
            && u16_at(&header, 24) == 0x20b
            && image_size == size,
    ))
}

fn read_module(
    space: &X64AddressSpace<'_>,
    owner: &ProcessRecord,
    peb: u64,
    node: u64,
) -> Result<SymbollessModuleRecord> {
    let entry = node.checked_sub(0x10).context("加载器条目地址下溢")?;
    ensure!(aligned_pointer(entry), "加载器条目地址无效");
    let base = space.read_u64(entry + 0x30)?;
    let mut size_bytes = [0; 4];
    space.read_virtual(entry + 0x40, &mut size_bytes)?;
    let size = u32::from_le_bytes(size_bytes);
    ensure!(
        user_pointer(base)
            && base & 4095 == 0
            && (4096..=0x8000_0000).contains(&size)
            && base + u64::from(size) <= 0x0000_8000_0000_0000,
        "模块映像范围无效"
    );
    let mut warnings = Vec::new();
    let mut name = |offset, label| match unicode(space, entry + offset) {
        Ok((name, _)) => Some(name),
        Err(error) => {
            warnings.push(format!("{label}不可读：{error:#}"));
            None
        }
    };
    let full_name = name(0x48, "模块路径");
    let base_name = name(0x58, "模块名称");
    let (pe_status, pe_size) = match module_pe(space, base, size) {
        Ok((size, true)) => ("verified", Some(size)),
        Ok((size, false)) => {
            warnings.push(
                "可读 PE 头未通过 AMD64 格式或映像大小核验；保留加载器记录，不据此判定异常".into(),
            );
            ("unverified", (size != 0).then_some(size))
        }
        Err(error) => {
            warnings.push(format!("模块 PE 头不可读：{error:#}"));
            ("unavailable", None)
        }
    };
    Ok(SymbollessModuleRecord {
        source_label: "无符号推断",
        pid: owner.pid,
        name: owner.name.clone(),
        eprocess: owner.eprocess,
        directory_table_base: owner.directory_table_base.context("进程 DTB 不可用")?,
        peb,
        ldr_entry: entry,
        entry_physical: space.translate(entry).ok(),
        base,
        size_of_image: size,
        full_name,
        base_name,
        is_main_image: owner.image_base == Some(base),
        pe_status,
        pe_size_of_image: pe_size,
        warnings,
    })
}

pub(super) fn analyze(
    image: &MemoryImage,
    kernel: &ProbeReport,
    options: &ProcessModulesOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    options.validate()?;
    cancel.check_cancelled()?;
    let selected: Vec<_> = kernel
        .processes
        .iter()
        .filter(|p| options.pid.is_none_or(|pid| p.pid == pid))
        .collect();
    ensure!(
        !selected.is_empty(),
        "未在本次无符号活动进程清单中找到指定进程"
    );
    let kspace = X64AddressSpace::new(image, kernel.kernel_dtb)?;
    let peb_field = accessor(
        image,
        kernel.kernel_dtb,
        kernel.kernel_base,
        pe_size(&kspace, kernel.kernel_base)?,
        "PsGetProcessPeb",
        "_EPROCESS.Peb",
        false,
    )?;
    let mut records = Vec::new();
    let mut sources = Vec::new();
    let mut report_bytes = 0;
    let mut truncated_by = Vec::new();
    if selected.len() > options.limit {
        truncated_by.push("process_limit");
    }
    for owner in selected.iter().take(options.limit) {
        cancel.check_cancelled()?;
        let start = records.len();
        let mut source = ProcessModuleSource {
            pid: owner.pid,
            name: owner.name.clone(),
            eprocess: owner.eprocess,
            directory_table_base: owner.directory_table_base,
            peb: None,
            ldr: None,
            list_head: None,
            list_traversal_complete: false,
            records_recovered: 0,
            module_status: "unavailable",
            warnings: Vec::new(),
        };
        let result = (|| -> Result<()> {
            let peb = kspace.read_u64(owner.eprocess + peb_field.offset)?;
            source.peb = Some(peb);
            let space = X64AddressSpace::new(
                image,
                owner.directory_table_base.context("进程 DTB 不可用")?,
            )?;
            validate_native_peb(&space, owner, peb)?;
            let ldr = space.read_u64(peb + 0x18)?;
            source.ldr = Some(ldr);
            ensure!(aligned_pointer(ldr), "PEB.Ldr 无效或加载器尚不可读");
            let mut header = [0; 8];
            space.read_virtual(ldr, &mut header)?;
            ensure!(
                (0x30..=0x1000).contains(&u32_at(&header, 0)) && header[4] == 1,
                "加载器长度或初始化状态不符合支持的 AMD64 布局"
            );
            let head = ldr + 0x20;
            source.list_head = Some(head);
            let mut current = space.read_u64(head)?;
            let tail = space.read_u64(head + 8)?;
            let mut previous = head;
            let mut visited = HashSet::new();
            while current != head {
                cancel.check_cancelled()?;
                if records.len() - start >= options.module_limit {
                    truncated_by.push("module_limit");
                    anyhow::bail!("单进程模块达到 {} 条上限", options.module_limit);
                }
                if records.len() >= MAX_RECORDS {
                    truncated_by.push("total_records");
                    anyhow::bail!("全报告达到 {MAX_RECORDS} 条模块上限");
                }
                ensure!(
                    aligned_pointer(current) && visited.insert(current),
                    "加载器链表地址无效或出现非表头循环"
                );
                let next = space.read_u64(current)?;
                ensure!(
                    space.read_u64(current + 8)? == previous && aligned_pointer(next),
                    "加载器双向链不一致"
                );
                // Only publish entries whose forward/back links agree, even when the next
                // module's body or PE later proves unreadable.
                ensure!(
                    space.read_u64(next + 8)? == current,
                    "加载器后继节点未反向指回当前条目"
                );
                let row = read_module(&space, owner, peb, current)?;
                let size = serde_json::to_vec(&row)?.len();
                if report_bytes + size > MAX_REPORT_BYTES {
                    truncated_by.push("record_json_bytes");
                    anyhow::bail!("模块记录达到 {MAX_REPORT_BYTES} 字节报告预算");
                }
                report_bytes += size;
                records.push(row);
                previous = current;
                current = next;
            }
            ensure!(previous == tail, "加载器表头尾指针不一致");
            source.list_traversal_complete = true;
            Ok(())
        })();
        cancel.check_cancelled()?;
        if let Err(error) = result {
            source.warnings.push(format!("模块链未完整恢复：{error:#}"));
        }
        source.records_recovered = records.len() - start;
        let row_warnings = records[start..].iter().any(|r| !r.warnings.is_empty());
        if row_warnings {
            source
                .warnings
                .push("部分模块的名称或 PE 未完整核验，请查看对应条目的告警".into());
        }
        source.module_status = if source.list_traversal_complete && !row_warnings {
            "complete"
        } else if source.records_recovered > 0 {
            "partial"
        } else {
            "unavailable"
        };
        sources.push(source);
    }
    truncated_by.sort_unstable();
    truncated_by.dedup();
    Ok(json!({
        "method":"symbolless_x64_process_modules_v1", "complete":false,
        "available":!records.is_empty() || sources.iter().any(|s| s.list_traversal_complete),
        "records":records, "process_sources":sources, "peb_field_evidence":peb_field,
        "selected_processes":selected.len(), "process_list_traversal_complete":kernel.list_traversal_complete,
        "truncated":!truncated_by.is_empty(), "truncated_by":truncated_by,
        "limits":{"processes":options.limit,"modules_per_process":options.module_limit,"total_records":MAX_RECORDS,"record_json_bytes":MAX_REPORT_BYTES,"unicode_string_bytes":16384},
        "layout_priors":["PEB 偏移从目标 PsGetProcessPeb 导出访问函数提取，复用进程页表、映像基址及原生 AMD64 PE 校验",
            "显式 AMD64 用户 ABI：PEB.Ldr +0x18，Ldr.InMemoryOrderModuleList +0x20；条目链接 +0x10、DllBase +0x30、SizeOfImage +0x40、FullDllName +0x48、BaseDllName +0x58；长度与双向链接逐节点验证"],
        "warnings":["仅恢复所选进程的用户加载器记录；链表可被进程修改，不证明全部模块均已发现。complete 状态只表示本次链表遍历和字段核验完成。",
            "未覆盖 WOW64、VAD 对照、脱链/手动映射模块、内核驱动或模块文件导出；缺页、PE 不一致与空链表均不能直接认定为恶意行为。"],
    }))
}

#[cfg(test)]
mod tests;
