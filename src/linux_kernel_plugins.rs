//! Linux kernel-global forensic plugins.
//!
//! This module intentionally does not depend on `LinuxAnalysisSession` or a valid task ring.
//! Callers provide a page-table root, a validated KASLR slide and a feature-aware Linux ISF.
//! Task-backed data is consulted only by plugins that explicitly request it (for example the
//! default mount namespace lookup).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::evidence::{
    EvidenceLimit, EvidenceLimitKind, EvidenceScope, EvidenceWarning, EvidenceWarningSeverity,
    MissingRange,
};
use crate::image::MemoryImage;
use crate::linux_symbols::{LinuxIsf, LinuxSymbolFeature};
use crate::output_policy::{OutputPolicy, OutputTarget, append_path_suffix};

const PAGE_SIZE: u64 = 0x1000;
const ADDRESS_MASK_4K: u64 = 0x000f_ffff_ffff_f000;
const ADDRESS_MASK_2M: u64 = 0x000f_ffff_ffe0_0000;
const ADDRESS_MASK_1G: u64 = 0x000f_ffff_c000_0000;
const PRESENT: u64 = 1;
const LARGE_PAGE: u64 = 1 << 7;
const DEFAULT_MODULE_LIMIT: usize = 65_536;
const DEFAULT_MOUNT_LIMIT: usize = 262_144;
const DEFAULT_KALLSYMS_LIMIT: usize = 1_000_000;
const DEFAULT_KMSG_LIMIT: usize = 1_000_000;
const DEFAULT_SYSCALL_LIMIT: usize = 1024;
const MAX_STRING_BYTES: usize = 4096;
const MAX_MODULE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_MODULE_SYMBOLS_PER_MODULE: u64 = 10_000_000;
const MAX_MODULE_SYMBOL_ENTRIES_TOTAL: u64 = 1_000_000;
const MAX_MODULE_SEMANTIC_SCAN_BYTES: u64 = 256 * 1024 * 1024;
const MAX_MODULE_SEMANTIC_WARNINGS: usize = 64;
const ELF64_SYMBOL_SIZE: u64 = 24;

/// Minimal kernel-memory contract shared by real and synthetic plugin sessions.
pub trait LinuxKernelMemory {
    fn read_virtual(&self, address: u64, output: &mut [u8]) -> Result<()>;
    fn translate(&self, address: u64) -> Result<u64>;
    fn isf(&self) -> &LinuxIsf;
    fn kernel_slide(&self) -> u64;
    fn source_path(&self) -> Option<&Path>;

    /// Every physical-image source that must remain immutable during publication.  Synthetic
    /// implementations retain the single-source default; real sessions include metadata and
    /// sidecars discovered by `MemoryImage`.
    fn source_paths(&self) -> Vec<&Path> {
        self.source_path().into_iter().collect()
    }

    fn runtime_symbol(&self, name: &str) -> Result<u64> {
        self.isf()
            .symbol_address(name)?
            .checked_add(self.kernel_slide())
            .with_context(|| format!("Linux 运行时符号 {name} 地址溢出"))
    }
}

/// Kernel-global session for x86_64 four-level paging.
///
/// Construction validates `_stext` and the runtime `linux_banner`; it never reads `init_task` or
/// traverses `task_struct.tasks`.
pub struct LinuxKernelSession {
    image: MemoryImage,
    directory_table_base: u64,
    kernel_slide: u64,
    symbols: Arc<LinuxIsf>,
}

impl LinuxKernelSession {
    pub fn new(
        image: MemoryImage,
        directory_table_base: u64,
        kernel_slide: u64,
        symbols: Arc<LinuxIsf>,
    ) -> Result<Self> {
        ensure!(
            directory_table_base != 0 && directory_table_base & (PAGE_SIZE - 1) == 0,
            "Linux x86_64 四级页表根无效"
        );
        ensure!(
            image.contains_physical(directory_table_base),
            "Linux 页表根 {directory_table_base:#x} 不在采集范围"
        );
        let session = Self {
            image,
            directory_table_base,
            kernel_slide,
            symbols,
        };
        let runtime_stext = session.runtime_symbol("_stext")?;
        ensure!(
            is_kernel_pointer(runtime_stext),
            "运行时 _stext 不是规范内核地址"
        );
        let mut opcode = [0_u8; 1];
        session
            .read_virtual(runtime_stext, &mut opcode)
            .context("无法通过四级页表读取运行时 _stext")?;

        let runtime_banner = session.runtime_symbol("linux_banner")?;
        let expected = session.symbols.banner().trim_end();
        // Linux stores `linux_banner` as a C string whose printable text normally ends in a
        // newline.  `LinuxIsf::parse` already applies `trim_end` to constant_data, so normalize
        // the runtime bytes the same way before comparing them.  Reserve room for both the
        // trailing newline and the NUL terminator.
        let mut bytes = vec![0_u8; expected.len().saturating_add(2)];
        session
            .read_virtual(runtime_banner, &mut bytes)
            .context("无法读取运行时 linux_banner")?;
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        let observed = std::str::from_utf8(&bytes[..end])
            .context("运行时 linux_banner 不是有效 UTF-8")?
            .trim_end();
        ensure!(
            observed == expected,
            "运行时 linux_banner 与 ISF constant_data 不同"
        );
        Ok(session)
    }

    pub fn image(&self) -> &MemoryImage {
        &self.image
    }

    pub fn directory_table_base(&self) -> u64 {
        self.directory_table_base
    }

    fn read_page_entry(&self, table: u64, index: u64) -> Result<u64> {
        let address = table
            .checked_add(index.checked_mul(8).context("页表索引溢出")?)
            .context("页表项地址溢出")?;
        let mut bytes = [0_u8; 8];
        self.image
            .read_physical(address, &mut bytes)
            .with_context(|| format!("无法读取页表项 {address:#x}"))?;
        Ok(u64::from_le_bytes(bytes))
    }
}

impl LinuxKernelMemory for LinuxKernelSession {
    fn read_virtual(&self, mut address: u64, mut output: &mut [u8]) -> Result<()> {
        while !output.is_empty() {
            let physical = self.translate(address)?;
            let available = usize::try_from(PAGE_SIZE - (address & (PAGE_SIZE - 1)))?;
            let take = available.min(output.len());
            self.image
                .read_physical(physical, &mut output[..take])
                .with_context(|| format!("无法读取 Linux 虚拟地址 {address:#x}"))?;
            address = address
                .checked_add(take as u64)
                .context("Linux 虚拟读取地址溢出")?;
            output = &mut output[take..];
        }
        Ok(())
    }

    fn translate(&self, address: u64) -> Result<u64> {
        ensure!(
            is_canonical_x86_64(address),
            "非规范 x86_64 虚拟地址 {address:#x}"
        );
        let pml4 = self.directory_table_base & ADDRESS_MASK_4K;
        let pml4e = self.read_page_entry(pml4, (address >> 39) & 0x1ff)?;
        ensure!(pml4e & PRESENT != 0, "PML4E not present for {address:#x}");
        let pdpt = pml4e & ADDRESS_MASK_4K;
        let pdpte = self.read_page_entry(pdpt, (address >> 30) & 0x1ff)?;
        ensure!(pdpte & PRESENT != 0, "PDPTE not present for {address:#x}");
        if pdpte & LARGE_PAGE != 0 {
            return Ok((pdpte & ADDRESS_MASK_1G) | (address & ((1 << 30) - 1)));
        }
        let pd = pdpte & ADDRESS_MASK_4K;
        let pde = self.read_page_entry(pd, (address >> 21) & 0x1ff)?;
        ensure!(pde & PRESENT != 0, "PDE not present for {address:#x}");
        if pde & LARGE_PAGE != 0 {
            return Ok((pde & ADDRESS_MASK_2M) | (address & ((1 << 21) - 1)));
        }
        let pt = pde & ADDRESS_MASK_4K;
        let pte = self.read_page_entry(pt, (address >> 12) & 0x1ff)?;
        ensure!(pte & PRESENT != 0, "PTE not present for {address:#x}");
        Ok((pte & ADDRESS_MASK_4K) | (address & (PAGE_SIZE - 1)))
    }

    fn isf(&self) -> &LinuxIsf {
        &self.symbols
    }

    fn kernel_slide(&self) -> u64 {
        self.kernel_slide
    }

    fn source_path(&self) -> Option<&Path> {
        Some(self.image.path())
    }

    fn source_paths(&self) -> Vec<&Path> {
        self.image
            .sources()
            .map(|source| source.path.as_path())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKernelSourceStatus {
    pub source: String,
    pub available: bool,
    pub complete: bool,
    pub records: usize,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxModuleRecord {
    pub module: u64,
    pub list_entry: u64,
    pub name: String,
    pub core_base: u64,
    pub core_size: u64,
    pub core_text_size: Option<u64>,
    pub init_base: Option<u64>,
    pub init_size: Option<u64>,
    pub state: Option<u64>,
    pub taints: Option<u64>,
    pub next: u64,
    pub previous: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxLsmodReport {
    pub available: bool,
    pub complete: bool,
    pub scope: EvidenceScope,
    pub warnings: Vec<EvidenceWarning>,
    pub limits: Vec<EvidenceLimit>,
    pub missing_ranges: Vec<MissingRange>,
    pub modules_head: Option<u64>,
    pub stop_reason: String,
    pub modules: Vec<LinuxModuleRecord>,
}

#[derive(Debug, Clone)]
struct ModuleLayout {
    list: u64,
    name: u64,
    name_length: usize,
    core_base: u64,
    core_base_width: usize,
    core_size: u64,
    core_size_width: usize,
    core_text_size: Option<(u64, usize)>,
    init_base: Option<(u64, usize)>,
    init_size: Option<(u64, usize)>,
    state: Option<(u64, usize)>,
    taints: Option<(u64, usize)>,
}

impl ModuleLayout {
    fn from_isf(isf: &LinuxIsf) -> Result<Self> {
        let list = isf.field_offset("module", "list")?;
        let name = isf.field_offset("module", "name")?;
        let name_length = usize::try_from(isf.field_array_count("module", "name")?)?;
        ensure!(
            (1..=MAX_STRING_BYTES).contains(&name_length),
            "module.name 数组长度不安全"
        );

        let (core_base, core_base_width, core_size, core_size_width, core_text_size) =
            if let Some(layout) = isf.optional_field_offset("module", "core_layout")? {
                let base = isf.field_offset("module_layout", "base")?;
                let size = isf.field_offset("module_layout", "size")?;
                let text_size = isf
                    .optional_field_offset("module_layout", "text_size")?
                    .map(|offset| -> Result<(u64, usize)> {
                        Ok((
                            layout + offset,
                            usize::try_from(isf.field_size("module_layout", "text_size")?)?,
                        ))
                    })
                    .transpose()?;
                (
                    layout + base,
                    usize::try_from(isf.field_size("module_layout", "base")?)?,
                    layout + size,
                    usize::try_from(isf.field_size("module_layout", "size")?)?,
                    text_size,
                )
            } else {
                (
                    isf.field_offset("module", "module_core")?,
                    usize::try_from(isf.field_size("module", "module_core")?)?,
                    isf.field_offset("module", "core_size")?,
                    usize::try_from(isf.field_size("module", "core_size")?)?,
                    isf.optional_field_offset("module", "core_text_size")?
                        .map(|offset| -> Result<(u64, usize)> {
                            Ok((
                                offset,
                                usize::try_from(isf.field_size("module", "core_text_size")?)?,
                            ))
                        })
                        .transpose()?,
                )
            };

        let (init_base, init_size) =
            if let Some(layout) = isf.optional_field_offset("module", "init_layout")? {
                (
                    isf.optional_field_offset("module_layout", "base")?
                        .map(|offset| -> Result<(u64, usize)> {
                            Ok((
                                layout + offset,
                                usize::try_from(isf.field_size("module_layout", "base")?)?,
                            ))
                        })
                        .transpose()?,
                    isf.optional_field_offset("module_layout", "size")?
                        .map(|offset| -> Result<(u64, usize)> {
                            Ok((
                                layout + offset,
                                usize::try_from(isf.field_size("module_layout", "size")?)?,
                            ))
                        })
                        .transpose()?,
                )
            } else {
                (
                    optional_field_with_size(isf, "module", "module_init")?,
                    optional_field_with_size(isf, "module", "init_size")?,
                )
            };
        Ok(Self {
            list,
            name,
            name_length,
            core_base,
            core_base_width,
            core_size,
            core_size_width,
            core_text_size,
            init_base,
            init_size,
            state: optional_field_with_size(isf, "module", "state")?,
            taints: optional_field_with_size(isf, "module", "taints")?,
        })
    }
}

pub fn linux_lsmod(memory: &impl LinuxKernelMemory, limit: usize) -> LinuxLsmodReport {
    let limit = if limit == 0 {
        DEFAULT_MODULE_LIMIT
    } else {
        limit
    };
    let scope = EvidenceScope::new("linux_kernel_modules_list");
    let mut report = LinuxLsmodReport {
        available: false,
        complete: false,
        scope,
        warnings: Vec::new(),
        limits: vec![evidence_limit("modules", limit as u64, 0, None)],
        missing_ranges: Vec::new(),
        modules_head: None,
        stop_reason: "unavailable".to_owned(),
        modules: Vec::new(),
    };
    let feature = BTreeSet::from([LinuxSymbolFeature::Modules]);
    let missing = memory.isf().requirement_gaps_for(&feature);
    if !missing.is_empty() {
        report.warnings.push(warning_with_context(
            "linux_symbols_missing",
            "请求的 ISF 缺少 linux.lsmod 所需布局",
            "linux.lsmod",
            BTreeMap::from([
                ("types".to_owned(), serde_json::json!(missing.missing_types)),
                (
                    "symbols".to_owned(),
                    serde_json::json!(missing.missing_symbols),
                ),
                (
                    "fields".to_owned(),
                    serde_json::json!(missing.missing_fields),
                ),
            ]),
        ));
        return report;
    }
    let layout = match ModuleLayout::from_isf(memory.isf()) {
        Ok(layout) => layout,
        Err(error) => {
            report.warnings.push(warning(
                "linux_module_layout_unavailable",
                format!("无法构造 module 布局：{error:#}"),
                "linux.lsmod",
            ));
            return report;
        }
    };
    let head = match memory.runtime_symbol("modules") {
        Ok(head) => head,
        Err(error) => {
            report.warnings.push(warning(
                "linux_modules_symbol_unavailable",
                format!("无法解析 modules：{error:#}"),
                "linux.lsmod",
            ));
            return report;
        }
    };
    report.modules_head = Some(head);
    let (first, head_previous) = match read_list(memory, head) {
        Ok(value) => value,
        Err(error) => {
            add_missing(&mut report.missing_ranges, head, 16, "modules.list_head");
            report.warnings.push(warning(
                "linux_modules_head_unreadable",
                format!("无法读取 modules 链表头：{error:#}"),
                "linux.lsmod",
            ));
            return report;
        }
    };
    report.available = true;
    if first == head {
        if head_previous == head {
            report.complete = true;
            report.stop_reason = "list_head".to_owned();
        } else {
            report.stop_reason = "head_blink_mismatch".to_owned();
            report.warnings.push(warning(
                "head_blink_mismatch",
                "空 modules 链表的 head.prev 不指向自身",
                "linux.lsmod",
            ));
        }
        report.limits[0].observed = Some(0);
        report.limits[0].reached = Some(false);
        return report;
    }

    let mut current = first;
    let mut previous = head;
    let mut visited = HashSet::new();
    while current != head {
        if report.modules.len() >= limit {
            report.stop_reason = "limit".to_owned();
            report.limits[0].reached = Some(true);
            report.warnings.push(warning(
                "linux_modules_limit_reached",
                format!("modules 遍历达到 {limit} 条上限"),
                "linux.lsmod",
            ));
            break;
        }
        if !is_kernel_pointer(current) || !visited.insert(current) {
            report.stop_reason = if visited.contains(&current) {
                "cycle"
            } else {
                "invalid_pointer"
            }
            .to_owned();
            report.warnings.push(warning(
                "linux_modules_invalid_link",
                format!("modules 链出现非法或重复指针 {current:#x}"),
                "linux.lsmod",
            ));
            break;
        }
        let module = match current.checked_sub(layout.list) {
            Some(module) if is_kernel_pointer(module) => module,
            _ => {
                report.stop_reason = "invalid_container".to_owned();
                report.warnings.push(warning(
                    "linux_module_container_invalid",
                    format!("list_entry {current:#x} 无法还原 module"),
                    "linux.lsmod",
                ));
                break;
            }
        };
        let record = match read_module(memory, &layout, module) {
            Ok(record) => record,
            Err(error) => {
                report.stop_reason = "unreadable_entry".to_owned();
                add_missing(
                    &mut report.missing_ranges,
                    module,
                    memory.isf().type_size("module").unwrap_or(1),
                    "module",
                );
                report.warnings.push(warning(
                    "linux_module_unreadable",
                    format!("无法读取 module {module:#x}：{error:#}"),
                    "linux.lsmod",
                ));
                break;
            }
        };
        if record.previous != previous {
            report.stop_reason = "backlink_mismatch".to_owned();
            report.warnings.push(warning_with_context(
                "backlink_mismatch",
                format!(
                    "module {} ({module:#x}) 的 prev={:#x}，期望 {previous:#x}",
                    record.name, record.previous
                ),
                "linux.lsmod",
                BTreeMap::from([
                    ("module".to_owned(), serde_json::json!(module)),
                    ("expected_previous".to_owned(), serde_json::json!(previous)),
                    (
                        "observed_previous".to_owned(),
                        serde_json::json!(record.previous),
                    ),
                ]),
            ));
            report.modules.push(record);
            break;
        }
        previous = current;
        current = record.next;
        report.modules.push(record);
    }
    if current == head {
        if head_previous == previous {
            report.complete = true;
            report.stop_reason = "list_head".to_owned();
        } else {
            report.stop_reason = "head_blink_mismatch".to_owned();
            report.warnings.push(warning_with_context(
                "head_blink_mismatch",
                format!("modules head.prev={head_previous:#x}，期望 {previous:#x}"),
                "linux.lsmod",
                BTreeMap::new(),
            ));
        }
    }
    report.limits[0].observed = Some(report.modules.len() as u64);
    if report.limits[0].reached.is_none() {
        report.limits[0].reached = Some(false);
    }
    report
}

fn read_module(
    memory: &impl LinuxKernelMemory,
    layout: &ModuleLayout,
    module: u64,
) -> Result<LinuxModuleRecord> {
    let list_entry = checked_address(module, layout.list, "module.list")?;
    let (next, previous) = read_list(memory, list_entry)?;
    let name = read_fixed_string(
        memory,
        checked_address(module, layout.name, "module.name")?,
        layout.name_length,
    )?;
    ensure!(!name.is_empty(), "module.name 为空");
    let core_base = read_unsigned(
        memory,
        checked_address(module, layout.core_base, "module.core_base")?,
        layout.core_base_width,
    )?;
    let core_size = read_unsigned(
        memory,
        checked_address(module, layout.core_size, "module.core_size")?,
        layout.core_size_width,
    )?;
    ensure!(
        core_size <= MAX_MODULE_BYTES,
        "module.core_size {core_size} 超过安全上限"
    );
    Ok(LinuxModuleRecord {
        module,
        list_entry,
        name,
        core_base,
        core_size,
        core_text_size: read_optional_field(memory, module, layout.core_text_size)?,
        init_base: read_optional_field(memory, module, layout.init_base)?,
        init_size: read_optional_field(memory, module, layout.init_size)?,
        state: read_optional_field(memory, module, layout.state)?,
        taints: read_optional_field(memory, module, layout.taints)?,
        next,
        previous,
    })
}

fn optional_field_with_size(
    isf: &LinuxIsf,
    type_name: &str,
    field_name: &str,
) -> Result<Option<(u64, usize)>> {
    isf.optional_field_offset(type_name, field_name)?
        .map(|offset| {
            Ok((
                offset,
                usize::try_from(isf.field_size(type_name, field_name)?)?,
            ))
        })
        .transpose()
}

fn read_optional_field(
    memory: &impl LinuxKernelMemory,
    base: u64,
    field: Option<(u64, usize)>,
) -> Result<Option<u64>> {
    field
        .map(|(offset, width)| {
            read_unsigned(
                memory,
                checked_address(base, offset, "optional module field")?,
                width,
            )
        })
        .transpose()
}

fn checked_address(base: u64, offset: u64, label: &str) -> Result<u64> {
    base.checked_add(offset)
        .with_context(|| format!("{label} 地址溢出"))
}

fn read_list(memory: &impl LinuxKernelMemory, address: u64) -> Result<(u64, u64)> {
    let mut bytes = [0_u8; 16];
    memory.read_virtual(address, &mut bytes)?;
    Ok((
        u64::from_le_bytes(bytes[..8].try_into().expect("list.next width")),
        u64::from_le_bytes(bytes[8..].try_into().expect("list.prev width")),
    ))
}

fn read_unsigned(memory: &impl LinuxKernelMemory, address: u64, width: usize) -> Result<u64> {
    ensure!(
        matches!(width, 1 | 2 | 4 | 8),
        "不支持的无符号字段宽度 {width}"
    );
    let mut bytes = [0_u8; 8];
    memory.read_virtual(address, &mut bytes[..width])?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_fixed_string(
    memory: &impl LinuxKernelMemory,
    address: u64,
    length: usize,
) -> Result<String> {
    ensure!(length <= MAX_STRING_BYTES, "字符串读取超过安全上限");
    let mut bytes = vec![0_u8; length];
    memory.read_virtual(address, &mut bytes)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .context("固定长度字符串没有 NUL 终止符")?;
    ensure!(end > 0, "字符串为空");
    ensure!(
        bytes[..end]
            .iter()
            .all(|byte| { byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.') }),
        "module.name 包含非规范字符"
    );
    Ok(String::from_utf8(bytes[..end].to_vec())?)
}

fn is_canonical_x86_64(address: u64) -> bool {
    let sign = (address >> 47) & 1;
    let upper = address >> 48;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

fn is_kernel_pointer(address: u64) -> bool {
    is_canonical_x86_64(address) && address >= 0xffff_8000_0000_0000
}

fn warning(
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
) -> EvidenceWarning {
    EvidenceWarning::new(code, EvidenceWarningSeverity::Warning, message, source)
}

fn warning_with_context(
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
    context: BTreeMap<String, serde_json::Value>,
) -> EvidenceWarning {
    let mut warning = warning(code, message, source);
    warning.context = context;
    warning
}

fn evidence_limit(
    name: impl Into<String>,
    configured: u64,
    observed: u64,
    reached: Option<bool>,
) -> EvidenceLimit {
    EvidenceLimit {
        name: name.into(),
        kind: EvidenceLimitKind::Output,
        configured: Some(configured),
        observed: Some(observed),
        reached,
    }
}

fn add_missing(output: &mut Vec<MissingRange>, start: u64, length: u64, source: &str) {
    output.push(MissingRange {
        address_space: "linux_kernel_virtual".to_owned(),
        start,
        length: length.max(1),
        source: source.to_owned(),
    });
}

fn add_missing_coalesced(output: &mut Vec<MissingRange>, start: u64, length: u64, source: &str) {
    let length = length.max(1);
    if let Some(last) = output.last_mut()
        && last.address_space == "linux_kernel_virtual"
        && last.source == source
        && last.start.saturating_add(last.length) >= start
    {
        let end = start.saturating_add(length);
        last.length = last.start.saturating_add(last.length).max(end) - last.start;
        return;
    }
    add_missing(output, start, length, source);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum LinuxModuleSelector {
    Name(String),
    Base(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxModuleExtractSegment {
    pub virtual_address: u64,
    pub memory_size: u64,
    pub output_offset: u64,
    pub output_size: u64,
    pub flags: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxModuleExtractReport {
    pub available: bool,
    pub complete: bool,
    pub scope: EvidenceScope,
    pub warnings: Vec<EvidenceWarning>,
    pub limits: Vec<EvidenceLimit>,
    pub missing_ranges: Vec<MissingRange>,
    pub selector: LinuxModuleSelector,
    pub module: Option<LinuxModuleRecord>,
    pub output: Option<PathBuf>,
    pub manifest: Option<PathBuf>,
    pub reconstructed_elf: bool,
    pub output_bytes: u64,
    pub recovered_memory_bytes: u64,
    pub sha256: Option<String>,
    pub segments: Vec<LinuxModuleExtractSegment>,
}

pub fn linux_module_extract(
    memory: &impl LinuxKernelMemory,
    selector: LinuxModuleSelector,
    output: &Path,
    max_bytes: u64,
    force: bool,
) -> Result<LinuxModuleExtractReport> {
    ensure!(max_bytes > 0, "module-extract 字节上限必须大于 0");
    let mut report = LinuxModuleExtractReport {
        available: false,
        complete: false,
        scope: EvidenceScope::new("linux_kernel_module_image"),
        warnings: Vec::new(),
        limits: vec![EvidenceLimit {
            name: "module_bytes".to_owned(),
            kind: EvidenceLimitKind::Bytes,
            configured: Some(max_bytes),
            observed: Some(0),
            reached: Some(false),
        }],
        missing_ranges: Vec::new(),
        selector: selector.clone(),
        module: None,
        output: None,
        manifest: None,
        reconstructed_elf: true,
        output_bytes: 0,
        recovered_memory_bytes: 0,
        sha256: None,
        segments: Vec::new(),
    };
    let modules = linux_lsmod(memory, DEFAULT_MODULE_LIMIT);
    report.warnings.extend(modules.warnings.clone());
    report.missing_ranges.extend(modules.missing_ranges.clone());
    if !modules.available {
        report.warnings.push(warning(
            "linux_module_source_unavailable",
            "modules 双向链不可用，无法定位并重验目标模块",
            "linux.module-extract",
        ));
        return Ok(report);
    }
    let selected = modules.modules.iter().find(|module| match &selector {
        LinuxModuleSelector::Name(name) => module.name == *name,
        LinuxModuleSelector::Base(base) => module.core_base == *base || module.module == *base,
    });
    let Some(selected) = selected.cloned() else {
        report.warnings.push(warning(
            "linux_module_not_found",
            "modules 链中没有与 selector 匹配的模块",
            "linux.module-extract",
        ));
        return Ok(report);
    };
    let layout = ModuleLayout::from_isf(memory.isf())?;
    let revalidated = read_module(memory, &layout, selected.module)
        .context("module-extract 在写出前重验 module 对象失败")?;
    ensure!(
        revalidated.name == selected.name
            && revalidated.core_base == selected.core_base
            && revalidated.core_size == selected.core_size,
        "module-extract 重验结果与 modules 链枚举结果不一致"
    );
    report.available = true;
    report.module = Some(revalidated.clone());

    let mut requested = Vec::new();
    if revalidated.core_size > 0 {
        requested.push(("core", revalidated.core_base, revalidated.core_size, "rwx"));
    }
    if let (Some(base), Some(size)) = (revalidated.init_base, revalidated.init_size)
        && base != 0
        && size > 0
    {
        requested.push(("init", base, size, "rwx"));
    }
    ensure!(
        !requested.is_empty(),
        "目标 module 没有可恢复的 core/init 范围"
    );

    let requested_bytes = requested
        .iter()
        .try_fold(0_u64, |total, (_, _, length, _)| total.checked_add(*length))
        .context("module 恢复范围总长度溢出")?;
    let mut remaining_budget = max_bytes;
    let mut recovered_segments = Vec::new();
    for (kind, address, length, flags) in requested {
        let selected_length = length.min(remaining_budget);
        if selected_length < length {
            report.limits[0].reached = Some(true);
            report.warnings.push(warning(
                "linux_module_extract_limit_reached",
                format!("module 恢复达到 {max_bytes} 字节上限"),
                "linux.module-extract",
            ));
        }
        if selected_length == 0 {
            break;
        }
        let (bytes, recovered) = read_sparse_virtual_range(
            memory,
            address,
            selected_length,
            kind,
            &mut report.missing_ranges,
            &mut report.warnings,
        )?;
        report.recovered_memory_bytes = report
            .recovered_memory_bytes
            .checked_add(recovered)
            .context("module recovered byte count overflow")?;
        recovered_segments.push((address, bytes, flags));
        remaining_budget -= selected_length;
        if remaining_budget == 0 {
            break;
        }
    }
    report.limits[0].observed = Some(requested_bytes.min(max_bytes));
    let fully_recovered = report.missing_ranges.is_empty()
        && !report.limits[0].reached.unwrap_or(false)
        && modules.complete;
    let (elf, segments) = build_reconstructed_module_elf(&recovered_segments)?;
    let actual_output = if fully_recovered {
        output.to_path_buf()
    } else {
        append_path_suffix(output, ".partial")
    };
    let manifest = append_path_suffix(output, ".manifest.json");
    let sources = memory.source_paths();
    ensure!(
        !sources.is_empty(),
        "module-extract 需要可识别的内存镜像输入路径"
    );
    let mut policy = OutputPolicy::new(force);
    for source in sources {
        policy.protect_file("memory_image_or_sidecar", source);
    }
    policy.protect_file("linux_isf", memory.isf().path());
    policy.output(
        OutputTarget::file("linux_module_elf", &actual_output).with_derived_path(&manifest),
    );
    policy.preflight()?;
    policy.write_bytes_atomic(&actual_output, &elf)?;

    report.complete = fully_recovered;
    report.output = Some(actual_output);
    report.manifest = Some(manifest.clone());
    report.output_bytes = elf.len() as u64;
    report.sha256 = Some(hex::encode(Sha256::digest(&elf)));
    report.segments = segments;
    policy.write_file_atomic(&manifest, |file| {
        serde_json::to_writer_pretty(&mut *file, &report)?;
        file.write_all(b"\n")?;
        Ok(())
    })?;
    Ok(report)
}

fn read_sparse_virtual_range(
    memory: &impl LinuxKernelMemory,
    start: u64,
    length: u64,
    source: &str,
    missing_ranges: &mut Vec<MissingRange>,
    warnings: &mut Vec<EvidenceWarning>,
) -> Result<(Vec<u8>, u64)> {
    let length_usize = usize::try_from(length).context("module 范围无法映射到本机 usize")?;
    let mut output = vec![0_u8; length_usize];
    let mut offset = 0_u64;
    let mut recovered = 0_u64;
    while offset < length {
        let address = start.checked_add(offset).context("module 范围地址溢出")?;
        let page_remaining = PAGE_SIZE - (address & (PAGE_SIZE - 1));
        let take = (length - offset).min(page_remaining);
        let begin = usize::try_from(offset)?;
        let end = usize::try_from(offset + take)?;
        if let Err(error) = memory.read_virtual(address, &mut output[begin..end]) {
            add_missing(missing_ranges, address, take, source);
            warnings.push(warning_with_context(
                "linux_module_page_missing",
                format!("无法恢复 module 虚拟范围 {address:#x}+{take:#x}：{error:#}"),
                "linux.module-extract",
                BTreeMap::from([
                    ("start".to_owned(), serde_json::json!(address)),
                    ("length".to_owned(), serde_json::json!(take)),
                ]),
            ));
        } else {
            recovered += take;
        }
        offset += take;
    }
    Ok((output, recovered))
}

fn build_reconstructed_module_elf(
    input: &[(u64, Vec<u8>, &str)],
) -> Result<(Vec<u8>, Vec<LinuxModuleExtractSegment>)> {
    ensure!(!input.is_empty(), "没有可写入 ELF 的 module segment");
    ensure!(input.len() <= u16::MAX as usize, "ELF segment 过多");
    const ELF_HEADER: usize = 64;
    const PROGRAM_HEADER: usize = 56;
    let header_bytes = ELF_HEADER
        .checked_add(PROGRAM_HEADER * input.len())
        .context("ELF header size overflow")?;
    let mut cursor = align_up(header_bytes as u64, PAGE_SIZE)?;
    let mut segments = Vec::with_capacity(input.len());
    for (address, bytes, flags) in input {
        segments.push(LinuxModuleExtractSegment {
            virtual_address: *address,
            memory_size: bytes.len() as u64,
            output_offset: cursor,
            output_size: bytes.len() as u64,
            flags: (*flags).to_owned(),
        });
        cursor = align_up(
            cursor
                .checked_add(bytes.len() as u64)
                .context("ELF output size overflow")?,
            PAGE_SIZE,
        )?;
    }
    let mut elf = vec![0_u8; usize::try_from(cursor)?];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&3_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[32..40].copy_from_slice(&(ELF_HEADER as u64).to_le_bytes());
    elf[52..54].copy_from_slice(&(ELF_HEADER as u16).to_le_bytes());
    elf[54..56].copy_from_slice(&(PROGRAM_HEADER as u16).to_le_bytes());
    elf[56..58].copy_from_slice(&(input.len() as u16).to_le_bytes());

    for (index, ((_, bytes, flags), segment)) in input.iter().zip(&segments).enumerate() {
        let header = ELF_HEADER + index * PROGRAM_HEADER;
        elf[header..header + 4].copy_from_slice(&1_u32.to_le_bytes());
        let flag_bits = elf_flags(flags);
        elf[header + 4..header + 8].copy_from_slice(&flag_bits.to_le_bytes());
        elf[header + 8..header + 16].copy_from_slice(&segment.output_offset.to_le_bytes());
        elf[header + 16..header + 24].copy_from_slice(&segment.virtual_address.to_le_bytes());
        elf[header + 24..header + 32].copy_from_slice(&0_u64.to_le_bytes());
        elf[header + 32..header + 40].copy_from_slice(&segment.output_size.to_le_bytes());
        elf[header + 40..header + 48].copy_from_slice(&segment.memory_size.to_le_bytes());
        elf[header + 48..header + 56].copy_from_slice(&PAGE_SIZE.to_le_bytes());
        let start = usize::try_from(segment.output_offset)?;
        elf[start..start + bytes.len()].copy_from_slice(bytes);
    }
    Ok((elf, segments))
}

fn elf_flags(flags: &str) -> u32 {
    let mut value = 0_u32;
    if flags.contains('x') {
        value |= 1;
    }
    if flags.contains('w') {
        value |= 2;
    }
    if flags.contains('r') {
        value |= 4;
    }
    value
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    ensure!(
        alignment.is_power_of_two(),
        "alignment must be a power of two"
    );
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .context("alignment overflow")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxMountInfoOptions {
    pub pid: Option<i32>,
    pub task: Option<u64>,
    pub namespace: Option<u64>,
    pub limit: usize,
}

impl Default for LinuxMountInfoOptions {
    fn default() -> Self {
        Self {
            pid: None,
            task: None,
            namespace: None,
            limit: DEFAULT_MOUNT_LIMIT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxMountRecord {
    pub namespace: u64,
    pub mount: u64,
    pub parent: u64,
    pub mount_id: Option<u64>,
    pub group_id: Option<u64>,
    pub root: String,
    pub mount_point: String,
    pub file_system: Option<String>,
    pub device_major: Option<u32>,
    pub device_minor: Option<u32>,
    pub flags: Option<u64>,
    pub next: u64,
    pub previous: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxMountInfoReport {
    pub available: bool,
    pub complete: bool,
    pub scope: EvidenceScope,
    pub warnings: Vec<EvidenceWarning>,
    pub limits: Vec<EvidenceLimit>,
    pub missing_ranges: Vec<MissingRange>,
    pub namespace: Option<u64>,
    pub source: LinuxKernelSourceStatus,
    pub stop_reason: String,
    pub mounts: Vec<LinuxMountRecord>,
}

#[derive(Debug, Clone)]
struct MountLayout {
    task_pid: Option<(u64, usize)>,
    task_nsproxy: u64,
    nsproxy_mnt_ns: u64,
    namespace_list: Option<u64>,
    namespace_mounts: Option<u64>,
    mount_list: u64,
    mount_vfsmount: u64,
    mount_parent: u64,
    mount_mountpoint: u64,
    mount_id: Option<(u64, usize)>,
    mount_group_id: Option<(u64, usize)>,
    vfsmount_root: u64,
    vfsmount_sb: u64,
    vfsmount_flags: Option<(u64, usize)>,
    super_type: u64,
    super_device: Option<(u64, usize)>,
    fs_type_name: u64,
    dentry_parent: u64,
    dentry_name: u64,
    qstr_len: u64,
    qstr_name: u64,
}

impl MountLayout {
    fn from_isf(isf: &LinuxIsf) -> Result<Self> {
        Ok(Self {
            task_pid: optional_field_with_size(isf, "task_struct", "pid")?,
            task_nsproxy: isf.field_offset("task_struct", "nsproxy")?,
            nsproxy_mnt_ns: isf.field_offset("nsproxy", "mnt_ns")?,
            namespace_list: isf.optional_field_offset("mnt_namespace", "list")?,
            namespace_mounts: isf.optional_field_offset("mnt_namespace", "mounts")?,
            mount_list: isf.field_offset("mount", "mnt_list")?,
            mount_vfsmount: isf.field_offset("mount", "mnt")?,
            mount_parent: isf.field_offset("mount", "mnt_parent")?,
            mount_mountpoint: isf.field_offset("mount", "mnt_mountpoint")?,
            mount_id: optional_field_with_size(isf, "mount", "mnt_id")?,
            mount_group_id: optional_field_with_size(isf, "mount", "mnt_group_id")?,
            vfsmount_root: isf.field_offset("vfsmount", "mnt_root")?,
            vfsmount_sb: isf.field_offset("vfsmount", "mnt_sb")?,
            vfsmount_flags: optional_field_with_size(isf, "vfsmount", "mnt_flags")?,
            super_type: isf.field_offset("super_block", "s_type")?,
            super_device: optional_field_with_size(isf, "super_block", "s_dev")?,
            fs_type_name: isf.field_offset("file_system_type", "name")?,
            dentry_parent: isf.field_offset("dentry", "d_parent")?,
            dentry_name: isf.field_offset("dentry", "d_name")?,
            qstr_len: isf.field_offset("qstr", "len")?,
            qstr_name: isf.field_offset("qstr", "name")?,
        })
    }
}

pub fn linux_mountinfo(
    memory: &impl LinuxKernelMemory,
    options: &LinuxMountInfoOptions,
) -> LinuxMountInfoReport {
    let limit = if options.limit == 0 {
        DEFAULT_MOUNT_LIMIT
    } else {
        options.limit
    };
    let mut scope = EvidenceScope::new("linux_mount_namespace");
    scope
        .constraints
        .insert("pid".to_owned(), serde_json::json!(options.pid));
    scope
        .constraints
        .insert("task".to_owned(), serde_json::json!(options.task));
    scope
        .constraints
        .insert("namespace".to_owned(), serde_json::json!(options.namespace));
    let mut report = LinuxMountInfoReport {
        available: false,
        complete: false,
        scope,
        warnings: Vec::new(),
        limits: vec![evidence_limit("mounts", limit as u64, 0, None)],
        missing_ranges: Vec::new(),
        namespace: None,
        source: LinuxKernelSourceStatus {
            source: "mnt_namespace.list".to_owned(),
            available: false,
            complete: false,
            records: 0,
            reason: None,
        },
        stop_reason: "unavailable".to_owned(),
        mounts: Vec::new(),
    };
    if options.pid.is_some() && options.task.is_none() {
        report.source.reason = Some("pid_filter_requires_task_address".to_owned());
        report.warnings.push(warning(
            "linux_mount_pid_resolution_unavailable",
            "kernel-global session 不遍历 task ring；PID 筛选必须由调用方同时提供已验证 task 地址",
            "linux.mountinfo",
        ));
        return report;
    }
    let feature = BTreeSet::from([LinuxSymbolFeature::Mount]);
    let missing = memory.isf().requirement_gaps_for(&feature);
    if !missing.is_empty() {
        report.source.reason = Some("symbol_requirements_missing".to_owned());
        report.warnings.push(warning_with_context(
            "linux_symbols_missing",
            "ISF 缺少 mount namespace 所需布局",
            "linux.mountinfo",
            BTreeMap::from([
                ("types".to_owned(), serde_json::json!(missing.missing_types)),
                (
                    "symbols".to_owned(),
                    serde_json::json!(missing.missing_symbols),
                ),
                (
                    "fields".to_owned(),
                    serde_json::json!(missing.missing_fields),
                ),
            ]),
        ));
        return report;
    }
    let layout = match MountLayout::from_isf(memory.isf()) {
        Ok(layout) => layout,
        Err(error) => {
            report.source.reason = Some("layout_unavailable".to_owned());
            report.warnings.push(warning(
                "linux_mount_layout_unavailable",
                format!("无法构造 mount 布局：{error:#}"),
                "linux.mountinfo",
            ));
            return report;
        }
    };
    let namespace = match resolve_mount_namespace(memory, options, &layout) {
        Ok(namespace) => namespace,
        Err(error) => {
            report.source.reason = Some("namespace_unavailable".to_owned());
            report.warnings.push(warning(
                "linux_mount_namespace_unavailable",
                format!("无法定位 mount namespace：{error:#}"),
                "linux.mountinfo",
            ));
            return report;
        }
    };
    report.namespace = Some(namespace);
    let Some(list_offset) = layout.namespace_list else {
        report.source.source = "mnt_namespace.mounts".to_owned();
        report.source.reason = Some("rbtree_source_unavailable".to_owned());
        report.warnings.push(warning_with_context(
            "linux_mount_rbtree_unavailable",
            "该内核只提供 mnt_namespace.mounts；当前首版仅严格支持 list 源",
            "linux.mountinfo",
            BTreeMap::from([(
                "mounts_offset".to_owned(),
                serde_json::json!(layout.namespace_mounts),
            )]),
        ));
        return report;
    };
    let head = namespace + list_offset;
    let (first, head_previous) = match read_list(memory, head) {
        Ok(value) => value,
        Err(error) => {
            add_missing(&mut report.missing_ranges, head, 16, "mnt_namespace.list");
            report.source.reason = Some("head_unreadable".to_owned());
            report.warnings.push(warning(
                "linux_mount_head_unreadable",
                format!("无法读取 mount list head：{error:#}"),
                "linux.mountinfo",
            ));
            return report;
        }
    };
    report.available = true;
    report.source.available = true;
    if first == head {
        report.complete = head_previous == head;
        report.source.complete = report.complete;
        report.stop_reason = if report.complete {
            "list_head"
        } else {
            "head_blink_mismatch"
        }
        .to_owned();
        if !report.complete {
            report.warnings.push(warning(
                "head_blink_mismatch",
                format!("空 mount list 的 head.prev={head_previous:#x}，期望 {head:#x}"),
                "linux.mountinfo",
            ));
        }
        report.limits[0].observed = Some(0);
        report.limits[0].reached = Some(false);
        return report;
    }

    let mut current = first;
    let mut previous = head;
    let mut visited = HashSet::new();
    while current != head {
        if report.mounts.len() >= limit {
            report.stop_reason = "limit".to_owned();
            report.limits[0].reached = Some(true);
            report.warnings.push(warning(
                "linux_mount_limit_reached",
                format!("mount 遍历达到 {limit} 条上限"),
                "linux.mountinfo",
            ));
            break;
        }
        if !is_kernel_pointer(current) || !visited.insert(current) {
            report.stop_reason = "invalid_or_cycle".to_owned();
            report.warnings.push(warning(
                "linux_mount_invalid_link",
                format!("mount list 出现非法或重复指针 {current:#x}"),
                "linux.mountinfo",
            ));
            break;
        }
        let Some(mount) = current.checked_sub(layout.mount_list) else {
            report.stop_reason = "invalid_container".to_owned();
            break;
        };
        let record = match read_mount_record(memory, &layout, namespace, mount) {
            Ok(record) => record,
            Err(error) => {
                add_missing(&mut report.missing_ranges, mount, 1, "mount");
                report.stop_reason = "unreadable_entry".to_owned();
                report.warnings.push(warning(
                    "linux_mount_unreadable",
                    format!("无法解析 mount {mount:#x}：{error:#}"),
                    "linux.mountinfo",
                ));
                break;
            }
        };
        if record.previous != previous {
            report.stop_reason = "backlink_mismatch".to_owned();
            report.warnings.push(warning(
                "backlink_mismatch",
                format!(
                    "mount {mount:#x} prev={:#x}，期望 {previous:#x}",
                    record.previous
                ),
                "linux.mountinfo",
            ));
            report.mounts.push(record);
            break;
        }
        previous = current;
        current = record.next;
        report.mounts.push(record);
    }
    if current == head {
        report.complete = head_previous == previous;
        report.stop_reason = if report.complete {
            "list_head"
        } else {
            "head_blink_mismatch"
        }
        .to_owned();
        if !report.complete {
            report.warnings.push(warning(
                "head_blink_mismatch",
                format!("mount head.prev={head_previous:#x}，期望 {previous:#x}"),
                "linux.mountinfo",
            ));
        }
    }
    report.source.complete = report.complete;
    report.source.records = report.mounts.len();
    report.limits[0].observed = Some(report.mounts.len() as u64);
    if report.limits[0].reached.is_none() {
        report.limits[0].reached = Some(false);
    }
    report
}

fn resolve_mount_namespace(
    memory: &impl LinuxKernelMemory,
    options: &LinuxMountInfoOptions,
    layout: &MountLayout,
) -> Result<u64> {
    if let Some(namespace) = options.namespace {
        ensure!(is_kernel_pointer(namespace), "namespace 不是规范内核指针");
        return Ok(namespace);
    }
    let task = options
        .task
        .map(Ok)
        .unwrap_or_else(|| memory.runtime_symbol("init_task"))?;
    ensure!(is_kernel_pointer(task), "task 不是规范内核指针");
    if let Some(expected_pid) = options.pid {
        let (offset, width) = layout
            .task_pid
            .context("ISF 缺少 task_struct.pid，无法重验 PID 筛选")?;
        let observed = read_unsigned(memory, task + offset, width)?;
        ensure!(
            observed == expected_pid as u64,
            "task PID {observed} 与筛选 PID {expected_pid} 不同"
        );
    }
    let nsproxy = read_unsigned(memory, task + layout.task_nsproxy, 8)?;
    ensure!(is_kernel_pointer(nsproxy), "task.nsproxy 不是规范内核指针");
    let namespace = read_unsigned(memory, nsproxy + layout.nsproxy_mnt_ns, 8)?;
    ensure!(
        is_kernel_pointer(namespace),
        "nsproxy.mnt_ns 不是规范内核指针"
    );
    Ok(namespace)
}

fn read_mount_record(
    memory: &impl LinuxKernelMemory,
    layout: &MountLayout,
    namespace: u64,
    mount: u64,
) -> Result<LinuxMountRecord> {
    let (next, previous) = read_list(memory, mount + layout.mount_list)?;
    let parent = read_unsigned(memory, mount + layout.mount_parent, 8)?;
    let mountpoint = read_unsigned(memory, mount + layout.mount_mountpoint, 8)?;
    let vfsmount = mount + layout.mount_vfsmount;
    let root_dentry = read_unsigned(memory, vfsmount + layout.vfsmount_root, 8)?;
    let super_block = read_unsigned(memory, vfsmount + layout.vfsmount_sb, 8)?;
    let flags = read_optional_field(memory, vfsmount, layout.vfsmount_flags)?;
    let parent_root = if parent == mount {
        root_dentry
    } else {
        let parent_vfsmount = parent + layout.mount_vfsmount;
        read_unsigned(memory, parent_vfsmount + layout.vfsmount_root, 8)?
    };
    let root = dentry_path(memory, layout, root_dentry, root_dentry)?;
    let mount_point = dentry_path(memory, layout, mountpoint, parent_root)?;
    let file_system = if super_block != 0 {
        let fs_type = read_unsigned(memory, super_block + layout.super_type, 8)?;
        if fs_type != 0 {
            let name = read_unsigned(memory, fs_type + layout.fs_type_name, 8)?;
            (name != 0)
                .then(|| read_c_string(memory, name, 256))
                .transpose()?
        } else {
            None
        }
    } else {
        None
    };
    let device = if super_block == 0 {
        None
    } else {
        layout
            .super_device
            .map(|(offset, width)| read_unsigned(memory, super_block + offset, width))
            .transpose()?
    };
    let (device_major, device_minor) = device.map(decode_linux_dev).unzip();
    Ok(LinuxMountRecord {
        namespace,
        mount,
        parent,
        mount_id: read_optional_field(memory, mount, layout.mount_id)?,
        group_id: read_optional_field(memory, mount, layout.mount_group_id)?,
        root,
        mount_point,
        file_system,
        device_major,
        device_minor,
        flags,
        next,
        previous,
    })
}

fn dentry_path(
    memory: &impl LinuxKernelMemory,
    layout: &MountLayout,
    start: u64,
    stop: u64,
) -> Result<String> {
    ensure!(is_kernel_pointer(start), "dentry 不是规范内核指针");
    let mut current = start;
    let mut components = Vec::new();
    let mut visited = HashSet::new();
    let mut terminated = false;
    for _ in 0..4096 {
        if !visited.insert(current) {
            bail!("dentry parent 链出现环")
        }
        if current == stop {
            terminated = true;
            break;
        }
        let qstr = current + layout.dentry_name;
        let length = usize::try_from(read_unsigned(memory, qstr + layout.qstr_len, 4)?)?;
        ensure!(length <= MAX_STRING_BYTES, "dentry name 超过安全上限");
        let name_pointer = read_unsigned(memory, qstr + layout.qstr_name, 8)?;
        if length > 0 && name_pointer != 0 {
            let mut bytes = vec![0_u8; length];
            memory.read_virtual(name_pointer, &mut bytes)?;
            components.push(String::from_utf8_lossy(&bytes).into_owned());
        }
        let parent = read_unsigned(memory, current + layout.dentry_parent, 8)?;
        if parent == current {
            ensure!(current == stop, "dentry 路径在到达预期 root 前终止");
            terminated = true;
            break;
        }
        ensure!(is_kernel_pointer(parent), "dentry.parent 不是规范内核指针");
        current = parent;
    }
    ensure!(terminated, "dentry parent 遍历达到 4096 层上限");
    components.reverse();
    if components.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(format!("/{}", components.join("/")))
    }
}

fn read_c_string(memory: &impl LinuxKernelMemory, address: u64, limit: usize) -> Result<String> {
    ensure!(
        (1..=MAX_STRING_BYTES).contains(&limit),
        "C string limit 无效"
    );
    let mut bytes = Vec::new();
    let mut terminated = false;
    for offset in 0..limit {
        let mut byte = [0_u8; 1];
        memory.read_virtual(
            checked_address(address, offset as u64, "symbol name")?,
            &mut byte,
        )?;
        if byte[0] == 0 {
            terminated = true;
            break;
        }
        bytes.push(byte[0]);
    }
    ensure!(terminated, "C string 在 {limit} 字节上限内未终止");
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn decode_linux_dev(value: u64) -> (u32, u32) {
    let major = ((value >> 8) & 0xfff) as u32;
    let minor = ((value & 0xff) | ((value >> 12) & 0xfff00)) as u32;
    (major, minor)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKallsymsRecord {
    pub index: u64,
    pub address: u64,
    pub symbol_type: Option<char>,
    pub name: String,
    pub valid_kernel_address: bool,
    pub source: String,
    pub module: Option<u64>,
    pub module_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxKallsymsReport {
    pub available: bool,
    pub complete: bool,
    pub scope: EvidenceScope,
    pub warnings: Vec<EvidenceWarning>,
    pub limits: Vec<EvidenceLimit>,
    pub missing_ranges: Vec<MissingRange>,
    pub declared_symbols: Option<u64>,
    pub address_encoding: Option<String>,
    pub sources: Vec<LinuxKernelSourceStatus>,
    pub symbols: Vec<LinuxKallsymsRecord>,
}

pub fn linux_kallsyms(memory: &impl LinuxKernelMemory, limit: usize) -> LinuxKallsymsReport {
    let limit = if limit == 0 {
        DEFAULT_KALLSYMS_LIMIT
    } else {
        limit
    };
    let mut scope = EvidenceScope::new("linux_core_and_module_kallsyms");
    scope.constraints.insert(
        "included_sources".to_owned(),
        serde_json::json!(["core", "module_symbols"]),
    );
    scope.constraints.insert(
        "excluded_sources".to_owned(),
        serde_json::json!(["ftrace", "bpf"]),
    );
    scope.constraints.insert(
        "module_symbol_scope".to_owned(),
        serde_json::json!("defined_elf64_symbols_inside_verified_module_core_or_init_allocations"),
    );
    let mut report = LinuxKallsymsReport {
        available: false,
        complete: false,
        scope,
        warnings: Vec::new(),
        limits: vec![
            evidence_limit("symbols", limit as u64, 0, None),
            EvidenceLimit {
                name: "modules".to_owned(),
                kind: EvidenceLimitKind::SourceScan,
                configured: Some(DEFAULT_MODULE_LIMIT as u64),
                observed: Some(0),
                reached: None,
            },
            EvidenceLimit {
                name: "module_symbol_entries".to_owned(),
                kind: EvidenceLimitKind::SourceScan,
                configured: Some(MAX_MODULE_SYMBOL_ENTRIES_TOTAL),
                observed: Some(0),
                reached: None,
            },
        ],
        missing_ranges: Vec::new(),
        declared_symbols: None,
        address_encoding: None,
        sources: vec![
            LinuxKernelSourceStatus {
                source: "core".to_owned(),
                available: false,
                complete: false,
                records: 0,
                reason: None,
            },
            LinuxKernelSourceStatus {
                source: "module_symbols".to_owned(),
                available: false,
                complete: false,
                records: 0,
                reason: Some("not_attempted".to_owned()),
            },
            LinuxKernelSourceStatus {
                source: "ftrace".to_owned(),
                available: false,
                complete: false,
                records: 0,
                reason: Some("unsupported_source".to_owned()),
            },
            LinuxKernelSourceStatus {
                source: "bpf".to_owned(),
                available: false,
                complete: false,
                records: 0,
                reason: Some("unsupported_source".to_owned()),
            },
        ],
        symbols: Vec::new(),
    };
    for (code, source) in [
        ("linux_kallsyms_ftrace_unavailable", "ftrace"),
        ("linux_kallsyms_bpf_unavailable", "BPF"),
    ] {
        report.warnings.push(warning(
            code,
            format!("{source} 来源当前明确不可用，不在本报告的搜索宇宙内"),
            "linux.kallsyms",
        ));
    }
    let feature = BTreeSet::from([LinuxSymbolFeature::Kallsyms]);
    let missing = memory.isf().requirement_gaps_for(&feature);
    if !missing.is_empty() {
        report.sources[0].reason = Some("symbol_requirements_missing".to_owned());
        report.warnings.push(warning_with_context(
            "linux_symbols_missing",
            "ISF 缺少 core kallsyms 解码所需符号",
            "linux.kallsyms",
            BTreeMap::from([(
                "symbols".to_owned(),
                serde_json::json!(missing.missing_symbols),
            )]),
        ));
        return report;
    }
    let num_address = match memory.runtime_symbol("kallsyms_num_syms") {
        Ok(value) => value,
        Err(error) => {
            report.sources[0].reason = Some("num_syms_unavailable".to_owned());
            report.warnings.push(warning(
                "linux_kallsyms_num_unavailable",
                format!("无法定位 kallsyms_num_syms：{error:#}"),
                "linux.kallsyms",
            ));
            return report;
        }
    };
    let declared = match read_unsigned(memory, num_address, 4) {
        Ok(value) if value > 0 && value <= 100_000_000 => value,
        Ok(value) => {
            report.sources[0].reason = Some("num_syms_invalid".to_owned());
            report.warnings.push(warning(
                "linux_kallsyms_num_invalid",
                format!("kallsyms_num_syms={value} 超出安全范围"),
                "linux.kallsyms",
            ));
            return report;
        }
        Err(error) => {
            add_missing(
                &mut report.missing_ranges,
                num_address,
                4,
                "kallsyms_num_syms",
            );
            report.sources[0].reason = Some("num_syms_unreadable".to_owned());
            report.warnings.push(warning(
                "linux_kallsyms_num_unreadable",
                format!("无法读取 kallsyms_num_syms：{error:#}"),
                "linux.kallsyms",
            ));
            return report;
        }
    };
    report.declared_symbols = Some(declared);
    let names = match memory.runtime_symbol("kallsyms_names") {
        Ok(value) => value,
        Err(error) => {
            report.sources[0].reason = Some("names_unavailable".to_owned());
            report.warnings.push(warning(
                "linux_kallsyms_names_unavailable",
                format!("无法定位 kallsyms_names：{error:#}"),
                "linux.kallsyms",
            ));
            return report;
        }
    };
    let token_table = match memory.runtime_symbol("kallsyms_token_table") {
        Ok(value) => value,
        Err(error) => {
            report.sources[0].reason = Some("token_table_unavailable".to_owned());
            report.warnings.push(warning(
                "linux_kallsyms_tokens_unavailable",
                format!("无法定位 token table：{error:#}"),
                "linux.kallsyms",
            ));
            return report;
        }
    };
    let token_index = match memory.runtime_symbol("kallsyms_token_index") {
        Ok(value) => value,
        Err(error) => {
            report.sources[0].reason = Some("token_index_unavailable".to_owned());
            report.warnings.push(warning(
                "linux_kallsyms_tokens_unavailable",
                format!("无法定位 token index：{error:#}"),
                "linux.kallsyms",
            ));
            return report;
        }
    };
    let addresses = memory.runtime_symbol("kallsyms_addresses").ok();
    let offsets = memory.runtime_symbol("kallsyms_offsets").ok();
    let relative_base = memory
        .runtime_symbol("kallsyms_relative_base")
        .ok()
        .and_then(|address| read_unsigned(memory, address, 8).ok());
    let address_source = if addresses.is_some() {
        report.address_encoding = Some("absolute_u64".to_owned());
        "kallsyms_addresses"
    } else if offsets.is_some() && relative_base.is_some() {
        report.address_encoding = Some("base_relative_i32".to_owned());
        "kallsyms_offsets"
    } else {
        report.sources[0].reason = Some("address_table_unavailable".to_owned());
        report.warnings.push(warning(
            "linux_kallsyms_addresses_unavailable",
            "没有可验证的 absolute address table 或 offset+relative_base 组合",
            "linux.kallsyms",
        ));
        return report;
    };
    let mut token_offsets = [0_u16; 256];
    let mut raw_token_offsets = [0_u8; 512];
    if let Err(error) = memory.read_virtual(token_index, &mut raw_token_offsets) {
        add_missing(
            &mut report.missing_ranges,
            token_index,
            512,
            "kallsyms_token_index",
        );
        report.sources[0].reason = Some("token_index_unreadable".to_owned());
        report.warnings.push(warning(
            "linux_kallsyms_token_index_unreadable",
            format!("无法读取 token index：{error:#}"),
            "linux.kallsyms",
        ));
        return report;
    }
    for (index, chunk) in raw_token_offsets.chunks_exact(2).enumerate() {
        token_offsets[index] = u16::from_le_bytes([chunk[0], chunk[1]]);
    }

    report.available = true;
    report.sources[0].available = true;
    let wanted = usize::try_from(declared).unwrap_or(usize::MAX).min(limit);
    if declared > limit as u64 {
        report.limits[0].reached = Some(true);
        report.warnings.push(warning(
            "linux_kallsyms_limit_reached",
            format!("core kallsyms 有 {declared} 条，仅输出前 {limit} 条"),
            "linux.kallsyms",
        ));
    }
    let mut names_cursor = names;
    for index in 0..wanted {
        let (encoded, consumed) = match read_kallsyms_encoded_name(memory, names_cursor) {
            Ok(value) => value,
            Err(error) => {
                add_missing(
                    &mut report.missing_ranges,
                    names_cursor,
                    1,
                    "kallsyms_names",
                );
                report.warnings.push(warning(
                    "linux_kallsyms_name_unreadable",
                    format!("第 {index} 个 kallsyms 名称无法读取：{error:#}"),
                    "linux.kallsyms",
                ));
                break;
            }
        };
        names_cursor = names_cursor.saturating_add(consumed);
        let expanded = match expand_kallsyms_name(memory, &encoded, token_table, &token_offsets) {
            Ok(value) => value,
            Err(error) => {
                report.warnings.push(warning(
                    "linux_kallsyms_name_invalid",
                    format!("第 {index} 个 kallsyms 名称解码失败：{error:#}"),
                    "linux.kallsyms",
                ));
                break;
            }
        };
        let mut characters = expanded.chars();
        let symbol_type = characters.next();
        let name = characters.collect::<String>();
        let address = if let Some(base) = addresses {
            match read_unsigned(memory, base + index as u64 * 8, 8) {
                Ok(value) => value,
                Err(error) => {
                    add_missing(
                        &mut report.missing_ranges,
                        base + index as u64 * 8,
                        8,
                        "kallsyms_addresses",
                    );
                    report.warnings.push(warning(
                        "linux_kallsyms_address_unreadable",
                        format!("第 {index} 个 kallsyms 地址无法读取：{error:#}"),
                        "linux.kallsyms",
                    ));
                    break;
                }
            }
        } else {
            let base = relative_base.expect("relative base checked above");
            let offset_address = offsets.expect("offset table checked above") + index as u64 * 4;
            let mut bytes = [0_u8; 4];
            if let Err(error) = memory.read_virtual(offset_address, &mut bytes) {
                add_missing(
                    &mut report.missing_ranges,
                    offset_address,
                    4,
                    "kallsyms_offsets",
                );
                report.warnings.push(warning(
                    "linux_kallsyms_offset_unreadable",
                    format!("第 {index} 个 kallsyms offset 无法读取：{error:#}"),
                    "linux.kallsyms",
                ));
                break;
            }
            let offset = i32::from_le_bytes(bytes);
            if offset >= 0 {
                base.saturating_add(offset as u64)
            } else {
                // CONFIG_KALLSYMS_BASE_RELATIVE encodes absolute-percpu addresses as
                // `relative_base - 1 - address`, hence the negative branch below.
                base.saturating_add((-i64::from(offset)) as u64)
                    .saturating_sub(1)
            }
        };
        report.symbols.push(LinuxKallsymsRecord {
            index: index as u64,
            address,
            symbol_type,
            name,
            valid_kernel_address: is_kernel_pointer(address),
            source: address_source.to_owned(),
            module: None,
            module_name: None,
        });
    }
    let core_records = report.symbols.len();
    let core_complete = core_records as u64 == declared;
    report.sources[0].complete = core_complete;
    report.sources[0].records = core_records;
    report.sources[0].reason = (!core_complete).then(|| "core_decode_incomplete".to_owned());

    let remaining = limit.saturating_sub(report.symbols.len());
    let mut module_symbols = collect_module_symbols(memory, remaining);
    report.sources[1].available = module_symbols.available;
    report.sources[1].complete = module_symbols.complete;
    report.sources[1].records = module_symbols.records.len();
    report.sources[1].reason = module_symbols.reason.take();
    report.limits[1].observed = Some(module_symbols.modules_examined as u64);
    report.limits[1].reached = Some(module_symbols.module_limit_reached);
    report.limits[2].observed = Some(module_symbols.entries_examined);
    report.limits[2].reached = Some(module_symbols.entry_limit_reached);
    report.warnings.append(&mut module_symbols.warnings);
    report
        .missing_ranges
        .append(&mut module_symbols.missing_ranges);
    if module_symbols.output_limit_reached {
        report.limits[0].reached = Some(true);
        report.warnings.push(warning(
            "linux_kallsyms_limit_reached",
            format!("core+module symbol 输出达到 {limit} 条上限"),
            "linux.kallsyms",
        ));
    }
    report.symbols.append(&mut module_symbols.records);
    report.limits[0].observed = Some(report.symbols.len() as u64);
    if report.limits[0].reached.is_none() {
        report.limits[0].reached = Some(false);
    }
    report.complete = core_complete
        && report.sources[1].complete
        && report.limits[0].reached == Some(false)
        && report.limits[1].reached == Some(false)
        && report.limits[2].reached == Some(false);
    report
}

#[derive(Debug, Clone)]
enum ModuleKallsymsStorage {
    Direct,
    Embedded { offset: u64 },
    Pointer { offset: u64 },
}

#[derive(Debug, Clone)]
struct ModuleKallsymsLayout {
    storage: ModuleKallsymsStorage,
    symtab: (u64, usize),
    num_symtab: (u64, usize),
    strtab: (u64, usize),
    typetab: Option<(u64, usize)>,
}

impl ModuleKallsymsLayout {
    fn from_isf(isf: &LinuxIsf) -> Result<Self> {
        // Old kernels stored these fields directly in `struct module`.  New kernels use either
        // an embedded `core_kallsyms` or a pointer named `kallsyms`.  Exact field/type names are
        // intentional: a loose name search is not sufficient proof of a module symbol table.
        if let (Ok(symtab), Ok(num_symtab), Ok(strtab)) = (
            field_with_size_any(isf, "module", &["symtab"]),
            field_with_size_any(isf, "module", &["num_symtab"]),
            field_with_size_any(isf, "module", &["strtab"]),
        ) {
            return Ok(Self {
                storage: ModuleKallsymsStorage::Direct,
                symtab,
                num_symtab,
                strtab,
                typetab: optional_field_with_size(isf, "module", "typetab")?,
            });
        }

        let (field_name, offset) = ["core_kallsyms", "kallsyms"]
            .into_iter()
            .find_map(|field_name| {
                isf.optional_field_offset("module", field_name)
                    .ok()
                    .flatten()
                    .map(|offset| (field_name, offset))
            })
            .context("module 缺少 core_kallsyms/kallsyms 字段")?;
        let width = usize::try_from(isf.field_size("module", field_name)?)?;
        let storage = if field_name == "kallsyms" && width == 8 {
            ModuleKallsymsStorage::Pointer { offset }
        } else {
            ensure!(width > 8, "{field_name} 既不是指针也不是内嵌结构");
            ModuleKallsymsStorage::Embedded { offset }
        };

        let mut last_error = None;
        for type_name in ["mod_kallsyms", "module_kallsyms"] {
            let candidate = (|| -> Result<Self> {
                Ok(Self {
                    storage: storage.clone(),
                    symtab: field_with_size_any(isf, type_name, &["symtab"])?,
                    num_symtab: field_with_size_any(isf, type_name, &["num_symtab"])?,
                    strtab: field_with_size_any(isf, type_name, &["strtab"])?,
                    typetab: optional_field_with_size(isf, type_name, "typetab")?,
                })
            })();
            match candidate {
                Ok(layout) => return Ok(layout),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("module kallsyms 布局不可用")))
    }

    fn container(&self, memory: &impl LinuxKernelMemory, module: u64) -> Result<u64> {
        match self.storage {
            ModuleKallsymsStorage::Direct => Ok(module),
            ModuleKallsymsStorage::Embedded { offset } => module
                .checked_add(offset)
                .context("module kallsyms 内嵌地址溢出"),
            ModuleKallsymsStorage::Pointer { offset } => {
                let address = module
                    .checked_add(offset)
                    .context("module.kallsyms 地址溢出")?;
                let pointer = read_unsigned(memory, address, 8)?;
                ensure!(is_kernel_pointer(pointer), "module.kallsyms 指针无效");
                Ok(pointer)
            }
        }
    }
}

#[derive(Debug, Default)]
struct ModuleSymbolCollection {
    available: bool,
    complete: bool,
    reason: Option<String>,
    modules_examined: usize,
    module_limit_reached: bool,
    entries_examined: u64,
    entry_limit_reached: bool,
    output_limit_reached: bool,
    warnings: Vec<EvidenceWarning>,
    missing_ranges: Vec<MissingRange>,
    records: Vec<LinuxKallsymsRecord>,
}

fn collect_module_symbols(
    memory: &impl LinuxKernelMemory,
    output_limit: usize,
) -> ModuleSymbolCollection {
    let mut output = ModuleSymbolCollection::default();
    let modules = linux_lsmod(memory, DEFAULT_MODULE_LIMIT);
    output.modules_examined = modules.modules.len();
    output.module_limit_reached = modules
        .limits
        .first()
        .and_then(|limit| limit.reached)
        .unwrap_or(false);
    output.warnings.extend(modules.warnings);
    output.missing_ranges.extend(modules.missing_ranges);
    if !modules.available {
        output.reason = Some("modules_list_unavailable".to_owned());
        return output;
    }
    output.available = true;
    if modules.modules.is_empty() {
        output.complete = modules.complete && !output.module_limit_reached;
        output.reason = (!output.complete).then(|| "modules_list_incomplete".to_owned());
        return output;
    }

    let module_layout = match ModuleLayout::from_isf(memory.isf()) {
        Ok(layout) => layout,
        Err(error) => {
            output.available = false;
            output.reason = Some("module_layout_unavailable".to_owned());
            output.warnings.push(warning(
                "linux_kallsyms_module_layout_unavailable",
                format!("无法构造 module 布局：{error:#}"),
                "linux.kallsyms",
            ));
            return output;
        }
    };
    let kallsyms_layout = match ModuleKallsymsLayout::from_isf(memory.isf()) {
        Ok(layout) => layout,
        Err(error) => {
            output.available = false;
            output.reason = Some("module_kallsyms_layout_unavailable".to_owned());
            output.warnings.push(warning(
                "linux_kallsyms_module_layout_unavailable",
                format!("ISF 缺少可验证的 module kallsyms 布局：{error:#}"),
                "linux.kallsyms",
            ));
            return output;
        }
    };

    let mut all_complete = modules.complete && !output.module_limit_reached;
    'modules: for module in &modules.modules {
        if let Err(error) = validate_module_record(memory, &module_layout, module, true) {
            all_complete = false;
            add_missing(
                &mut output.missing_ranges,
                module.module,
                memory.isf().type_size("module").unwrap_or(1),
                "module_symbols.module",
            );
            output.warnings.push(warning_with_context(
                "linux_kallsyms_module_invalid",
                format!("module {} 结构或映射重验失败：{error:#}", module.name),
                "linux.kallsyms",
                BTreeMap::from([("module".to_owned(), serde_json::json!(module.module))]),
            ));
            continue;
        }
        let container = match kallsyms_layout.container(memory, module.module) {
            Ok(value) => value,
            Err(error) => {
                all_complete = false;
                add_missing(
                    &mut output.missing_ranges,
                    module.module,
                    8,
                    "module_symbols.kallsyms",
                );
                output.warnings.push(warning(
                    "linux_kallsyms_module_header_unreadable",
                    format!(
                        "module {} 的 kallsyms header 不可用：{error:#}",
                        module.name
                    ),
                    "linux.kallsyms",
                ));
                continue;
            }
        };
        let count_address = match checked_address(
            container,
            kallsyms_layout.num_symtab.0,
            "module kallsyms num_symtab",
        ) {
            Ok(address) => address,
            Err(error) => {
                all_complete = false;
                output.warnings.push(warning(
                    "linux_kallsyms_module_header_invalid",
                    format!("module {} 的 num_symtab 地址无效：{error:#}", module.name),
                    "linux.kallsyms",
                ));
                continue;
            }
        };
        let count = match read_unsigned(memory, count_address, kallsyms_layout.num_symtab.1) {
            Ok(value) if value <= MAX_MODULE_SYMBOLS_PER_MODULE => value,
            Ok(value) => {
                all_complete = false;
                output.warnings.push(warning(
                    "linux_kallsyms_module_count_invalid",
                    format!("module {} 声明 {value} 个符号，超过安全上限", module.name),
                    "linux.kallsyms",
                ));
                continue;
            }
            Err(error) => {
                all_complete = false;
                add_missing(
                    &mut output.missing_ranges,
                    count_address,
                    kallsyms_layout.num_symtab.1 as u64,
                    "module_symbols.num_symtab",
                );
                output.warnings.push(warning(
                    "linux_kallsyms_module_count_unreadable",
                    format!("module {} 的 num_symtab 不可读：{error:#}", module.name),
                    "linux.kallsyms",
                ));
                continue;
            }
        };
        if count == 0 {
            continue;
        }
        let pointers = (|| -> Result<(u64, u64, Option<u64>)> {
            let symtab = read_unsigned(
                memory,
                checked_address(container, kallsyms_layout.symtab.0, "module symtab")?,
                kallsyms_layout.symtab.1,
            )?;
            let strtab = read_unsigned(
                memory,
                checked_address(container, kallsyms_layout.strtab.0, "module strtab")?,
                kallsyms_layout.strtab.1,
            )?;
            ensure!(is_kernel_pointer(symtab), "symtab 指针无效");
            ensure!(is_kernel_pointer(strtab), "strtab 指针无效");
            let typetab = kallsyms_layout
                .typetab
                .map(|field| {
                    read_unsigned(
                        memory,
                        checked_address(container, field.0, "module typetab")?,
                        field.1,
                    )
                })
                .transpose()?
                .filter(|value| is_kernel_pointer(*value));
            Ok((symtab, strtab, typetab))
        })();
        let (symtab, strtab, typetab) = match pointers {
            Ok(value) => value,
            Err(error) => {
                all_complete = false;
                add_missing(
                    &mut output.missing_ranges,
                    container,
                    memory
                        .isf()
                        .type_size("mod_kallsyms")
                        .or_else(|_| memory.isf().type_size("module_kallsyms"))
                        .unwrap_or(1),
                    "module_symbols.header",
                );
                output.warnings.push(warning(
                    "linux_kallsyms_module_header_invalid",
                    format!("module {} 的符号表指针无效：{error:#}", module.name),
                    "linux.kallsyms",
                ));
                continue;
            }
        };
        let table_bytes = match count.checked_mul(ELF64_SYMBOL_SIZE) {
            Some(value) => value,
            None => {
                all_complete = false;
                output.warnings.push(warning(
                    "linux_kallsyms_module_table_overflow",
                    format!("module {} 的 symtab 长度溢出", module.name),
                    "linux.kallsyms",
                ));
                continue;
            }
        };
        let table_end = symtab.checked_add(table_bytes);
        if table_end.is_none()
            || memory.translate(symtab).is_err()
            || memory
                .translate(table_end.expect("checked above") - 1)
                .is_err()
        {
            all_complete = false;
            add_missing(
                &mut output.missing_ranges,
                symtab,
                table_bytes,
                "module_symbols.symtab",
            );
            output.warnings.push(warning(
                "linux_kallsyms_module_table_unmapped",
                format!("module {} 的 symtab 区间未完整映射", module.name),
                "linux.kallsyms",
            ));
            continue;
        }
        for index in 0..count {
            if output.entries_examined >= MAX_MODULE_SYMBOL_ENTRIES_TOTAL {
                output.entry_limit_reached = true;
                all_complete = false;
                output.warnings.push(warning(
                    "linux_kallsyms_module_entry_limit_reached",
                    format!(
                        "module ELF64 symbol 扫描达到 {} 个候选条目的全局上限",
                        MAX_MODULE_SYMBOL_ENTRIES_TOTAL
                    ),
                    "linux.kallsyms",
                ));
                break 'modules;
            }
            output.entries_examined += 1;
            let entry = match index
                .checked_mul(ELF64_SYMBOL_SIZE)
                .and_then(|offset| symtab.checked_add(offset))
            {
                Some(value) => value,
                None => {
                    all_complete = false;
                    output.warnings.push(warning(
                        "linux_kallsyms_module_table_overflow",
                        format!("module {} 第 {index} 个 symtab 地址溢出", module.name),
                        "linux.kallsyms",
                    ));
                    break 'modules;
                }
            };
            let mut raw = [0_u8; ELF64_SYMBOL_SIZE as usize];
            if let Err(error) = memory.read_virtual(entry, &mut raw) {
                all_complete = false;
                add_missing(
                    &mut output.missing_ranges,
                    entry,
                    ELF64_SYMBOL_SIZE,
                    "module_symbols.symtab",
                );
                output.warnings.push(warning(
                    "linux_kallsyms_module_symbol_unreadable",
                    format!(
                        "module {} 的第 {index} 个 ELF64 symbol 不可读：{error:#}",
                        module.name
                    ),
                    "linux.kallsyms",
                ));
                continue 'modules;
            }
            let name_offset = u32::from_le_bytes(raw[0..4].try_into().expect("st_name"));
            let info = raw[4];
            let section = u16::from_le_bytes(raw[6..8].try_into().expect("st_shndx"));
            let address = u64::from_le_bytes(raw[8..16].try_into().expect("st_value"));
            let size = u64::from_le_bytes(raw[16..24].try_into().expect("st_size"));
            if name_offset == 0 || section == 0 {
                continue;
            }
            let name_address = match strtab.checked_add(u64::from(name_offset)) {
                Some(value) => value,
                None => {
                    all_complete = false;
                    output.warnings.push(warning(
                        "linux_kallsyms_module_name_overflow",
                        format!("module {} 第 {index} 个符号名地址溢出", module.name),
                        "linux.kallsyms",
                    ));
                    continue;
                }
            };
            let name = match read_ascii_symbol_name(memory, name_address, MAX_STRING_BYTES) {
                Ok(value) => value,
                Err(error) => {
                    all_complete = false;
                    add_missing(
                        &mut output.missing_ranges,
                        name_address,
                        1,
                        "module_symbols.strtab",
                    );
                    output.warnings.push(warning(
                        "linux_kallsyms_module_name_unreadable",
                        format!(
                            "module {} 第 {index} 个符号名不可用：{error:#}",
                            module.name
                        ),
                        "linux.kallsyms",
                    ));
                    continue;
                }
            };
            if !module_contains_address(module, address, size)
                || memory.translate(address).is_err()
                || (size > 0
                    && memory
                        .translate(address.saturating_add(size.saturating_sub(1)))
                        .is_err())
            {
                // Absolute/undefined/special symbols are outside the first-pass module allocation
                // universe and are deliberately excluded; they are never promoted on name alone.
                continue;
            }
            if output.records.len() >= output_limit {
                output.output_limit_reached = true;
                all_complete = false;
                break 'modules;
            }
            let symbol_type = typetab.and_then(|base| {
                let mut byte = [0_u8; 1];
                base.checked_add(index)
                    .and_then(|address| memory.read_virtual(address, &mut byte).ok())
                    .and_then(|_| byte[0].is_ascii_graphic().then(|| char::from(byte[0])))
            });
            output.records.push(LinuxKallsymsRecord {
                index,
                address,
                symbol_type: symbol_type.or_else(|| elf_symbol_type(info)),
                name,
                valid_kernel_address: true,
                source: "module_symtab".to_owned(),
                module: Some(module.module),
                module_name: Some(module.name.clone()),
            });
        }
    }
    output.complete = all_complete && !output.output_limit_reached && !output.entry_limit_reached;
    output.reason = (!output.complete).then(|| {
        if output.output_limit_reached {
            "output_limit_reached".to_owned()
        } else if output.entry_limit_reached {
            "entry_scan_limit_reached".to_owned()
        } else if output.module_limit_reached {
            "module_traversal_limit_reached".to_owned()
        } else {
            "module_symbol_scan_incomplete".to_owned()
        }
    });
    output
}

fn read_ascii_symbol_name(
    memory: &impl LinuxKernelMemory,
    address: u64,
    limit: usize,
) -> Result<String> {
    ensure!(
        (1..=MAX_STRING_BYTES).contains(&limit),
        "symbol name limit 无效"
    );
    let mut bytes = Vec::new();
    for offset in 0..limit {
        let mut byte = [0_u8; 1];
        memory.read_virtual(address + offset as u64, &mut byte)?;
        if byte[0] == 0 {
            ensure!(!bytes.is_empty(), "symbol name 为空");
            return Ok(String::from_utf8(bytes)?);
        }
        ensure!(
            byte[0].is_ascii_graphic(),
            "symbol name 含非 ASCII 可见字符"
        );
        bytes.push(byte[0]);
    }
    bail!("symbol name 在 {limit} 字节内未 NUL 终止")
}

fn elf_symbol_type(info: u8) -> Option<char> {
    match info & 0x0f {
        1 => Some('D'),
        2 => Some('T'),
        3 => Some('S'),
        4 => Some('F'),
        5 => Some('C'),
        6 => Some('T'),
        _ => None,
    }
}

fn module_contains_address(module: &LinuxModuleRecord, address: u64, size: u64) -> bool {
    let contains = |base: u64, length: u64| {
        if length == 0 || !is_kernel_pointer(base) {
            return false;
        }
        let Some(end) = base.checked_add(length) else {
            return false;
        };
        let object_end = if size == 0 {
            address.checked_add(1)
        } else {
            address.checked_add(size)
        };
        object_end.is_some_and(|object_end| address >= base && object_end <= end)
    };
    contains(module.core_base, module.core_size)
        || module
            .init_base
            .zip(module.init_size)
            .is_some_and(|(base, length)| contains(base, length))
}

fn validate_module_record(
    memory: &impl LinuxKernelMemory,
    layout: &ModuleLayout,
    module: &LinuxModuleRecord,
    require_topology: bool,
) -> Result<()> {
    ensure!(is_kernel_pointer(module.module), "module 地址无效");
    ensure!(module.module & 7 == 0, "module 地址未 8 字节对齐");
    let reread = read_module(memory, layout, module.module)?;
    ensure!(&reread == module, "module 二次读取结果不一致");
    ensure!(
        module.core_size > 0 && is_kernel_pointer(module.core_base),
        "module core allocation 无效"
    );
    let core_end = module
        .core_base
        .checked_add(module.core_size)
        .context("module core allocation 溢出")?;
    memory.translate(module.core_base)?;
    memory.translate(core_end - 1)?;
    if let Some(text_size) = module.core_text_size {
        ensure!(
            text_size > 0 && text_size <= module.core_size,
            "module text_size 无效"
        );
    }
    match (module.init_base, module.init_size) {
        (Some(base), Some(size)) if size > 0 => {
            ensure!(is_kernel_pointer(base), "module init allocation 指针无效");
            let end = base
                .checked_add(size)
                .context("module init allocation 溢出")?;
            memory.translate(base)?;
            memory.translate(end - 1)?;
        }
        (_, Some(0)) | (None, None) => {}
        _ => bail!("module init allocation 字段不一致"),
    }
    if let Some(state) = module.state {
        ensure!(state <= 3, "module state {state} 无效");
    }
    if require_topology {
        validate_module_list_topology(memory, module)?;
    }
    Ok(())
}

fn validate_module_list_topology(
    memory: &impl LinuxKernelMemory,
    module: &LinuxModuleRecord,
) -> Result<()> {
    let entry = module.list_entry;
    ensure!(
        is_kernel_pointer(module.next) && is_kernel_pointer(module.previous),
        "module list 指针无效"
    );
    if module.next == entry && module.previous == entry {
        return Ok(());
    }
    let (_, next_previous) = read_list(memory, module.next)?;
    let (previous_next, _) = read_list(memory, module.previous)?;
    ensure!(
        next_previous == entry && previous_next == entry,
        "module list 邻接节点不互指"
    );
    Ok(())
}

fn read_kallsyms_encoded_name(
    memory: &impl LinuxKernelMemory,
    address: u64,
) -> Result<(Vec<u8>, u64)> {
    let mut first = [0_u8; 1];
    memory.read_virtual(address, &mut first)?;
    let (length, prefix) = if first[0] & 0x80 != 0 {
        let mut second = [0_u8; 1];
        memory.read_virtual(address + 1, &mut second)?;
        (
            ((first[0] & 0x7f) as usize) | ((second[0] as usize) << 7),
            2,
        )
    } else {
        (first[0] as usize, 1)
    };
    ensure!(
        (1..=MAX_STRING_BYTES).contains(&length),
        "kallsyms name token 长度无效"
    );
    let mut encoded = vec![0_u8; length];
    memory.read_virtual(address + prefix, &mut encoded)?;
    Ok((encoded, prefix + length as u64))
}

fn expand_kallsyms_name(
    memory: &impl LinuxKernelMemory,
    encoded: &[u8],
    token_table: u64,
    token_offsets: &[u16; 256],
) -> Result<String> {
    let mut output = Vec::new();
    for token in encoded {
        let address = token_table + u64::from(token_offsets[*token as usize]);
        let value = read_c_string(memory, address, 256)?;
        output.extend_from_slice(value.as_bytes());
        ensure!(
            output.len() <= MAX_STRING_BYTES,
            "展开后的 kallsyms 名称过长"
        );
    }
    ensure!(!output.is_empty(), "展开后的 kallsyms 名称为空");
    Ok(String::from_utf8_lossy(&output).into_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKmsgOptions {
    pub limit: usize,
    /// Independently proven boot time. Without this value the plugin emits monotonic time only.
    pub boot_time_unix_ns: Option<i128>,
}

impl Default for LinuxKmsgOptions {
    fn default() -> Self {
        Self {
            limit: DEFAULT_KMSG_LIMIT,
            boot_time_unix_ns: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKmsgRecord {
    pub sequence: Option<u64>,
    pub monotonic_ns: u64,
    pub utc: Option<String>,
    pub facility: Option<u8>,
    pub flags: Option<u8>,
    pub text: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxKmsgReport {
    pub available: bool,
    pub complete: bool,
    pub scope: EvidenceScope,
    pub warnings: Vec<EvidenceWarning>,
    pub limits: Vec<EvidenceLimit>,
    pub missing_ranges: Vec<MissingRange>,
    pub timestamp_mode: String,
    pub sources: Vec<LinuxKernelSourceStatus>,
    pub records: Vec<LinuxKmsgRecord>,
}

#[derive(Debug, Clone)]
struct OldKmsgLayout {
    type_name: &'static str,
    size: usize,
    timestamp: (u64, usize),
    record_length: (u64, usize),
    text_length: (u64, usize),
    dictionary_length: Option<(u64, usize)>,
    facility: Option<(u64, usize)>,
    flags: Option<(u64, usize)>,
}

impl OldKmsgLayout {
    fn from_isf(isf: &LinuxIsf) -> Result<Self> {
        let type_name = if isf.type_size("printk_log").is_ok() {
            "printk_log"
        } else {
            "log"
        };
        Ok(Self {
            type_name,
            size: usize::try_from(isf.type_size(type_name)?)?,
            timestamp: field_with_size_any(isf, type_name, &["ts_nsec", "ts_nsec_plus_1"])?,
            record_length: field_with_size_any(isf, type_name, &["len"])?,
            text_length: field_with_size_any(isf, type_name, &["text_len"])?,
            dictionary_length: optional_field_with_size(isf, type_name, "dict_len")?,
            facility: optional_field_with_size(isf, type_name, "facility")?,
            flags: optional_field_with_size(isf, type_name, "flags")?,
        })
    }
}

pub fn linux_kmsg(memory: &impl LinuxKernelMemory, options: &LinuxKmsgOptions) -> LinuxKmsgReport {
    let limit = if options.limit == 0 {
        DEFAULT_KMSG_LIMIT
    } else {
        options.limit
    };
    let mut scope = EvidenceScope::new("linux_kernel_log");
    scope.constraints.insert(
        "boot_time_unix_ns".to_owned(),
        serde_json::json!(options.boot_time_unix_ns.map(|value| value.to_string())),
    );
    let mut report = LinuxKmsgReport {
        available: false,
        complete: false,
        scope,
        warnings: Vec::new(),
        limits: vec![evidence_limit("messages", limit as u64, 0, None)],
        missing_ranges: Vec::new(),
        timestamp_mode: if options.boot_time_unix_ns.is_some() {
            "boot_time_plus_monotonic"
        } else {
            "monotonic_only"
        }
        .to_owned(),
        sources: vec![
            LinuxKernelSourceStatus {
                source: "printk_ringbuffer".to_owned(),
                available: false,
                complete: false,
                records: 0,
                reason: None,
            },
            LinuxKernelSourceStatus {
                source: "legacy_log_buffer".to_owned(),
                available: false,
                complete: false,
                records: 0,
                reason: None,
            },
        ],
        records: Vec::new(),
    };
    let mut limit_reached = false;
    if options.boot_time_unix_ns.is_none() {
        report.warnings.push(warning(
            "linux_kmsg_wall_clock_unavailable",
            "没有独立启动时间证据；仅输出 printk monotonic timestamp",
            "linux.kmsg",
        ));
    }
    let feature = BTreeSet::from([LinuxSymbolFeature::Kmsg]);
    let missing = memory.isf().requirement_gaps_for(&feature);
    if !missing.is_empty() {
        report.warnings.push(warning_with_context(
            "linux_symbols_missing",
            "ISF 缺少旧 log buffer 或新版 printk ring 所需符号/类型",
            "linux.kmsg",
            BTreeMap::from([
                ("types".to_owned(), serde_json::json!(missing.missing_types)),
                (
                    "symbols".to_owned(),
                    serde_json::json!(missing.missing_symbols),
                ),
            ]),
        ));
        report.sources[0].reason = Some("symbol_requirements_missing".to_owned());
        report.sources[1].reason = Some("symbol_requirements_missing".to_owned());
        return report;
    }

    if memory.runtime_symbol("prb").is_ok() || memory.runtime_symbol("printk_rb_static").is_ok() {
        match read_new_printk_ring(memory, options, limit) {
            Ok(mut result) => {
                limit_reached |= result.limit_reached;
                report.available = true;
                report.complete = result.complete;
                report.records.append(&mut result.records);
                report.warnings.append(&mut result.warnings);
                report.missing_ranges.append(&mut result.missing_ranges);
                report.sources[0] = LinuxKernelSourceStatus {
                    source: "printk_ringbuffer".to_owned(),
                    available: true,
                    complete: result.complete,
                    records: report.records.len(),
                    reason: result.reason,
                };
            }
            Err(error) => {
                report.sources[0].reason = Some("layout_or_read_failure".to_owned());
                report.warnings.push(warning(
                    "linux_printk_ring_unavailable",
                    format!("新版 printk ring 无法解析：{error:#}"),
                    "linux.kmsg",
                ));
            }
        }
    } else {
        report.sources[0].reason = Some("symbols_absent".to_owned());
    }
    if !report.available && memory.runtime_symbol("log_buf").is_ok() {
        match read_old_printk_log(memory, options, limit) {
            Ok(mut result) => {
                limit_reached |= result.limit_reached;
                report.available = true;
                report.complete = result.complete;
                report.records.append(&mut result.records);
                report.warnings.append(&mut result.warnings);
                report.missing_ranges.append(&mut result.missing_ranges);
                report.sources[1] = LinuxKernelSourceStatus {
                    source: "legacy_log_buffer".to_owned(),
                    available: true,
                    complete: result.complete,
                    records: report.records.len(),
                    reason: result.reason,
                };
            }
            Err(error) => {
                report.sources[1].reason = Some("layout_or_read_failure".to_owned());
                report.warnings.push(warning(
                    "linux_legacy_kmsg_unavailable",
                    format!("旧 printk log buffer 无法解析：{error:#}"),
                    "linux.kmsg",
                ));
            }
        }
    } else if memory.runtime_symbol("log_buf").is_err() {
        report.sources[1].reason = Some("symbols_absent".to_owned());
    } else {
        report.sources[1].reason = Some("superseded_by_selected_printk_ring".to_owned());
    }
    if !report.available {
        report.warnings.push(warning(
            "linux_kmsg_unavailable",
            "旧 log buffer 与新版 printk ring 均不可用",
            "linux.kmsg",
        ));
    }
    report.limits[0].observed = Some(report.records.len() as u64);
    report.limits[0].reached = Some(limit_reached);
    if limit_reached {
        report.complete = false;
    }
    report
}

struct KmsgReadResult {
    complete: bool,
    limit_reached: bool,
    reason: Option<String>,
    records: Vec<LinuxKmsgRecord>,
    warnings: Vec<EvidenceWarning>,
    missing_ranges: Vec<MissingRange>,
}

fn read_old_printk_log(
    memory: &impl LinuxKernelMemory,
    options: &LinuxKmsgOptions,
    limit: usize,
) -> Result<KmsgReadResult> {
    let layout = OldKmsgLayout::from_isf(memory.isf())?;
    ensure!(
        layout.size >= 8 && layout.size <= 4096,
        "旧 printk record header 大小无效"
    );
    let log_buf_symbol = memory.runtime_symbol("log_buf")?;
    let pointed = read_unsigned(memory, log_buf_symbol, 8).unwrap_or(0);
    let buffer = if is_kernel_pointer(pointed) {
        pointed
    } else {
        log_buf_symbol
    };
    let length_symbol = memory.runtime_symbol("log_buf_len")?;
    let ring_length = read_unsigned(memory, length_symbol, 4)?;
    ensure!(
        ring_length >= layout.size as u64 && ring_length <= 1024 * 1024 * 1024,
        "log_buf_len 超出安全范围"
    );
    let first = read_unsigned(memory, memory.runtime_symbol("log_first_idx")?, 4)?;
    let next = read_unsigned(memory, memory.runtime_symbol("log_next_idx")?, 4)?;
    ensure!(
        first < ring_length && next < ring_length,
        "log index 超出 ring 范围"
    );
    let mut result = KmsgReadResult {
        complete: false,
        limit_reached: false,
        reason: None,
        records: Vec::new(),
        warnings: Vec::new(),
        missing_ranges: Vec::new(),
    };
    let mut cursor = first;
    let mut visited = HashSet::new();
    while cursor != next && result.records.len() < limit {
        if !visited.insert(cursor) {
            result.reason = Some("record_cycle".to_owned());
            result.warnings.push(warning(
                "linux_kmsg_record_cycle",
                format!("旧 printk ring 在 offset {cursor:#x} 出现环"),
                "linux.kmsg",
            ));
            break;
        }
        let header = match read_ring_bytes(memory, buffer, ring_length, cursor, layout.size as u64)
        {
            Ok(value) => value,
            Err(error) => {
                add_missing(
                    &mut result.missing_ranges,
                    buffer + cursor,
                    layout.size as u64,
                    "legacy_printk_header",
                );
                result.reason = Some("header_unreadable".to_owned());
                result.warnings.push(warning(
                    "linux_kmsg_header_unreadable",
                    format!("旧 printk header 无法读取：{error:#}"),
                    "linux.kmsg",
                ));
                break;
            }
        };
        let record_length = read_unsigned_from_slice(&header, layout.record_length)?;
        if record_length == 0 {
            cursor = 0;
            continue;
        }
        let text_length = read_unsigned_from_slice(&header, layout.text_length)?;
        let dictionary_length = layout
            .dictionary_length
            .map(|field| read_unsigned_from_slice(&header, field))
            .transpose()?
            .unwrap_or(0);
        ensure!(
            record_length >= layout.size as u64
                && record_length <= ring_length
                && text_length + dictionary_length <= record_length - layout.size as u64,
            "旧 printk record 长度字段不一致"
        );
        let text = read_ring_bytes(
            memory,
            buffer,
            ring_length,
            (cursor + layout.size as u64) % ring_length,
            text_length,
        )?;
        let monotonic_ns = read_unsigned_from_slice(&header, layout.timestamp)?;
        result.records.push(LinuxKmsgRecord {
            sequence: None,
            monotonic_ns,
            utc: wall_clock_timestamp(options.boot_time_unix_ns, monotonic_ns),
            facility: layout
                .facility
                .map(|field| read_unsigned_from_slice(&header, field).map(|value| value as u8))
                .transpose()?,
            flags: layout
                .flags
                .map(|field| read_unsigned_from_slice(&header, field).map(|value| value as u8))
                .transpose()?,
            text: String::from_utf8_lossy(&text).into_owned(),
            source: layout.type_name.to_owned(),
        });
        cursor = (cursor + record_length) % ring_length;
    }
    result.complete = cursor == next;
    if !result.complete && result.records.len() >= limit {
        result.limit_reached = true;
        result.reason = Some("output_limit".to_owned());
    }
    Ok(result)
}

#[derive(Debug, Clone)]
struct NewKmsgLayout {
    desc_ring: u64,
    text_data_ring: u64,
    count_bits: u64,
    descs: u64,
    infos: u64,
    head_id: u64,
    tail_id: u64,
    atomic_counter: u64,
    desc_state: u64,
    desc_text_lpos: u64,
    lpos_begin: u64,
    lpos_next: u64,
    data_size_bits: u64,
    data_pointer: u64,
    info_seq: u64,
    info_timestamp: u64,
    info_text_length: u64,
    info_facility: Option<u64>,
    info_flags: Option<u64>,
    desc_size: u64,
    info_size: u64,
}

impl NewKmsgLayout {
    fn from_isf(isf: &LinuxIsf) -> Result<Self> {
        let atomic_type = if isf.field_offset("atomic_long_t", "counter").is_ok() {
            "atomic_long_t"
        } else {
            "atomic64_t"
        };
        Ok(Self {
            desc_ring: isf.field_offset("printk_ringbuffer", "desc_ring")?,
            text_data_ring: isf.field_offset("printk_ringbuffer", "text_data_ring")?,
            count_bits: isf.field_offset("prb_desc_ring", "count_bits")?,
            descs: isf.field_offset("prb_desc_ring", "descs")?,
            infos: isf.field_offset("prb_desc_ring", "infos")?,
            head_id: isf.field_offset("prb_desc_ring", "head_id")?,
            tail_id: isf.field_offset("prb_desc_ring", "tail_id")?,
            atomic_counter: isf.field_offset(atomic_type, "counter")?,
            desc_state: isf.field_offset("prb_desc", "state_var")?,
            desc_text_lpos: isf.field_offset("prb_desc", "text_blk_lpos")?,
            lpos_begin: isf.field_offset("prb_data_blk_lpos", "begin")?,
            lpos_next: isf.field_offset("prb_data_blk_lpos", "next")?,
            data_size_bits: isf.field_offset("prb_data_ring", "size_bits")?,
            data_pointer: isf.field_offset("prb_data_ring", "data")?,
            info_seq: isf.field_offset("printk_info", "seq")?,
            info_timestamp: isf.field_offset("printk_info", "ts_nsec")?,
            info_text_length: isf.field_offset("printk_info", "text_len")?,
            info_facility: isf.optional_field_offset("printk_info", "facility")?,
            info_flags: isf.optional_field_offset("printk_info", "flags")?,
            desc_size: isf.type_size("prb_desc")?,
            info_size: isf.type_size("printk_info")?,
        })
    }
}

fn read_new_printk_ring(
    memory: &impl LinuxKernelMemory,
    options: &LinuxKmsgOptions,
    limit: usize,
) -> Result<KmsgReadResult> {
    let layout = NewKmsgLayout::from_isf(memory.isf())?;
    let symbol = memory
        .runtime_symbol("prb")
        .or_else(|_| memory.runtime_symbol("printk_rb_static"))?;
    let pointed = read_unsigned(memory, symbol, 8).unwrap_or(0);
    let ring = if is_kernel_pointer(pointed) {
        pointed
    } else {
        symbol
    };
    let desc_ring = ring + layout.desc_ring;
    let text_ring = ring + layout.text_data_ring;
    let count_bits = read_unsigned(memory, desc_ring + layout.count_bits, 4)?;
    let text_size_bits = read_unsigned(memory, text_ring + layout.data_size_bits, 4)?;
    ensure!(
        (1..=24).contains(&count_bits) && (12..=32).contains(&text_size_bits),
        "printk ring size bits 超出安全范围"
    );
    let descriptor_count = 1_u64 << count_bits;
    let text_size = 1_u64 << text_size_bits;
    let descs = read_unsigned(memory, desc_ring + layout.descs, 8)?;
    let infos = read_unsigned(memory, desc_ring + layout.infos, 8)?;
    let text_data = read_unsigned(memory, text_ring + layout.data_pointer, 8)?;
    ensure!(
        is_kernel_pointer(descs) && is_kernel_pointer(infos) && is_kernel_pointer(text_data),
        "printk ring backing pointer 无效"
    );
    let head = read_unsigned(
        memory,
        desc_ring + layout.head_id + layout.atomic_counter,
        8,
    )?;
    let tail = read_unsigned(
        memory,
        desc_ring + layout.tail_id + layout.atomic_counter,
        8,
    )?;
    ensure!(head >= tail, "printk descriptor head_id 早于 tail_id");
    ensure!(
        head - tail < descriptor_count.saturating_mul(4),
        "printk descriptor ID 范围不可信"
    );
    let mut result = KmsgReadResult {
        complete: false,
        limit_reached: false,
        reason: Some("descriptor_state_validation_limited".to_owned()),
        records: Vec::new(),
        warnings: vec![warning(
            "linux_printk_descriptor_state_limited",
            "新版 printk ring 已解析 descriptor/info/text，但首版未证明所有 descriptor state 位语义；complete=false",
            "linux.kmsg",
        )],
        missing_ranges: Vec::new(),
    };
    for (processed, id) in (tail..=head).enumerate() {
        if processed >= limit {
            result.limit_reached = true;
            result.reason = Some("output_limit".to_owned());
            break;
        }
        let index = id & (descriptor_count - 1);
        let descriptor = descs + index * layout.desc_size;
        let info = infos + index * layout.info_size;
        let _state = read_unsigned(memory, descriptor + layout.desc_state, 8)?;
        let begin = read_unsigned(
            memory,
            descriptor + layout.desc_text_lpos + layout.lpos_begin,
            8,
        )?;
        let next = read_unsigned(
            memory,
            descriptor + layout.desc_text_lpos + layout.lpos_next,
            8,
        )?;
        let text_length = read_unsigned(memory, info + layout.info_text_length, 2)?;
        if text_length == 0 || text_length > text_size {
            continue;
        }
        ensure!(next >= begin, "printk text logical position 倒退");
        let text_offset = begin.wrapping_add(8) & (text_size - 1);
        let text = read_ring_bytes(memory, text_data, text_size, text_offset, text_length)?;
        let monotonic_ns = read_unsigned(memory, info + layout.info_timestamp, 8)?;
        result.records.push(LinuxKmsgRecord {
            sequence: Some(read_unsigned(memory, info + layout.info_seq, 8)?),
            monotonic_ns,
            utc: wall_clock_timestamp(options.boot_time_unix_ns, monotonic_ns),
            facility: layout
                .info_facility
                .map(|offset| read_unsigned(memory, info + offset, 1).map(|value| value as u8))
                .transpose()?,
            flags: layout
                .info_flags
                .map(|offset| read_unsigned(memory, info + offset, 1).map(|value| value as u8))
                .transpose()?,
            text: String::from_utf8_lossy(&text).into_owned(),
            source: "printk_ringbuffer".to_owned(),
        });
    }
    Ok(result)
}

fn field_with_size_any(isf: &LinuxIsf, type_name: &str, names: &[&str]) -> Result<(u64, usize)> {
    let offset = isf.field_offset_any(type_name, names)?;
    let size = usize::try_from(isf.field_size_any(type_name, names)?)?;
    Ok((offset, size))
}

fn read_unsigned_from_slice(bytes: &[u8], field: (u64, usize)) -> Result<u64> {
    let offset = usize::try_from(field.0)?;
    ensure!(matches!(field.1, 1 | 2 | 4 | 8), "字段宽度不受支持");
    let end = offset.checked_add(field.1).context("字段范围溢出")?;
    let source = bytes.get(offset..end).context("字段超出结构体 header")?;
    let mut value = [0_u8; 8];
    value[..field.1].copy_from_slice(source);
    Ok(u64::from_le_bytes(value))
}

fn read_ring_bytes(
    memory: &impl LinuxKernelMemory,
    base: u64,
    ring_length: u64,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    ensure!(ring_length > 0 && offset < ring_length, "ring offset 无效");
    ensure!(length <= ring_length, "ring read 超过 ring 长度");
    let mut output = vec![0_u8; usize::try_from(length)?];
    let first = length.min(ring_length - offset);
    memory.read_virtual(base + offset, &mut output[..usize::try_from(first)?])?;
    if first < length {
        memory.read_virtual(base, &mut output[usize::try_from(first)?..])?;
    }
    Ok(output)
}

fn wall_clock_timestamp(boot_time_unix_ns: Option<i128>, monotonic_ns: u64) -> Option<String> {
    let unix_ns = boot_time_unix_ns?.checked_add(monotonic_ns as i128)?;
    let seconds = i64::try_from(unix_ns.div_euclid(1_000_000_000)).ok()?;
    let nanos = u32::try_from(unix_ns.rem_euclid(1_000_000_000)).ok()?;
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, nanos)
        .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxModxviewRecord {
    pub module: u64,
    pub name: Option<String>,
    pub in_modules_list: bool,
    pub in_module_kset: bool,
    pub in_semantic_scan: Option<bool>,
    pub suspicious: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxModxviewReport {
    pub available: bool,
    pub complete: bool,
    pub scope: EvidenceScope,
    pub warnings: Vec<EvidenceWarning>,
    pub limits: Vec<EvidenceLimit>,
    pub missing_ranges: Vec<MissingRange>,
    pub sources: Vec<LinuxKernelSourceStatus>,
    pub records: Vec<LinuxModxviewRecord>,
}

#[derive(Debug, Clone)]
struct ModuleKsetLayout {
    kset_list: u64,
    kobject_entry: u64,
    module_kobject_kobj: u64,
    module_kobject_mod: u64,
}

impl ModuleKsetLayout {
    fn from_isf(isf: &LinuxIsf) -> Result<Self> {
        Ok(Self {
            kset_list: isf.field_offset("kset", "list")?,
            kobject_entry: isf.field_offset("kobject", "entry")?,
            module_kobject_kobj: isf.field_offset("module_kobject", "kobj")?,
            module_kobject_mod: isf.field_offset("module_kobject", "mod")?,
        })
    }
}

#[derive(Debug, Default)]
struct ModuleSemanticScan {
    available: bool,
    complete: bool,
    reason: Option<String>,
    declared_bytes: u64,
    scanned_bytes: u64,
    byte_limit_reached: bool,
    output_limit_reached: bool,
    warnings: Vec<EvidenceWarning>,
    missing_ranges: Vec<MissingRange>,
    modules: Vec<LinuxModuleRecord>,
}

pub fn linux_modxview(memory: &impl LinuxKernelMemory, limit: usize) -> LinuxModxviewReport {
    let limit = if limit == 0 {
        DEFAULT_MODULE_LIMIT
    } else {
        limit
    };
    let modules = linux_lsmod(memory, limit);
    let module_layout = ModuleLayout::from_isf(memory.isf());
    let mut scope = EvidenceScope::new("linux_module_cross_view");
    scope.constraints.insert(
        "semantic_scan_range".to_owned(),
        serde_json::json!("runtime module_addr_min..module_addr_max"),
    );
    scope
        .constraints
        .insert("semantic_candidate_stride".to_owned(), serde_json::json!(8));
    scope.constraints.insert(
        "semantic_validation".to_owned(),
        serde_json::json!([
            "module_layout",
            "nul_terminated_name",
            "allocation_bounds",
            "mapped_endpoints",
            "list_topology",
            "stable_reread"
        ]),
    );
    let mut report = LinuxModxviewReport {
        available: modules.available,
        complete: false,
        scope,
        warnings: modules.warnings.clone(),
        limits: vec![
            evidence_limit("modules_per_view", limit as u64, 0, None),
            EvidenceLimit {
                name: "semantic_scan_bytes".to_owned(),
                kind: EvidenceLimitKind::SourceScan,
                configured: Some(MAX_MODULE_SEMANTIC_SCAN_BYTES),
                observed: Some(0),
                reached: None,
            },
        ],
        missing_ranges: modules.missing_ranges.clone(),
        sources: vec![
            LinuxKernelSourceStatus {
                source: "modules_list".to_owned(),
                available: modules.available,
                complete: modules.complete,
                records: modules.modules.len(),
                reason: (!modules.available)
                    .then(|| "modules_list_unavailable".to_owned())
                    .or_else(|| (!modules.complete).then(|| "traversal_incomplete".to_owned())),
            },
            LinuxKernelSourceStatus {
                source: "module_kset".to_owned(),
                available: false,
                complete: false,
                records: 0,
                reason: None,
            },
            LinuxKernelSourceStatus {
                source: "semantic_scan".to_owned(),
                available: false,
                complete: false,
                records: 0,
                reason: Some("not_attempted".to_owned()),
            },
        ],
        records: Vec::new(),
    };
    let mut names = HashMap::new();
    let mut list_modules = BTreeSet::new();
    for module in &modules.modules {
        list_modules.insert(module.module);
        names.insert(module.module, module.name.clone());
    }

    let mut kset_modules = BTreeSet::new();
    match module_layout
        .as_ref()
        .map_err(|error| anyhow::anyhow!("{error:#}"))
        .and_then(|layout| read_module_kset(memory, layout, limit))
    {
        Ok((modules, complete, mut warnings, mut missing)) => {
            report.available = true;
            report.sources[1].available = true;
            report.sources[1].complete = complete;
            report.sources[1].records = modules.len();
            report.sources[1].reason = (!complete).then(|| "traversal_incomplete".to_owned());
            report.warnings.append(&mut warnings);
            report.missing_ranges.append(&mut missing);
            for module in modules {
                kset_modules.insert(module.module);
                names.entry(module.module).or_insert(module.name);
            }
        }
        Err(error) => {
            report.sources[1].reason = Some("source_unavailable".to_owned());
            report.warnings.push(warning(
                "linux_module_kset_unavailable",
                format!("module_kset view 不可用：{error:#}"),
                "linux.modxview",
            ));
        }
    }

    let mut semantic_modules = BTreeSet::new();
    let mut semantic = match &module_layout {
        Ok(layout) => scan_modules_semantically(memory, layout, limit),
        Err(error) => ModuleSemanticScan {
            reason: Some("module_layout_unavailable".to_owned()),
            warnings: vec![warning(
                "linux_module_semantic_scan_unavailable",
                format!("受限语义扫描缺少 module 布局：{error:#}"),
                "linux.modxview",
            )],
            ..ModuleSemanticScan::default()
        },
    };
    report.sources[2].available = semantic.available;
    report.sources[2].complete = semantic.complete;
    report.sources[2].records = semantic.modules.len();
    report.sources[2].reason = semantic.reason.take();
    report.limits[1].observed = Some(semantic.scanned_bytes);
    report.limits[1].reached = if semantic.available {
        Some(semantic.byte_limit_reached)
    } else {
        None
    };
    report.warnings.append(&mut semantic.warnings);
    report.missing_ranges.append(&mut semantic.missing_ranges);
    for module in semantic.modules {
        semantic_modules.insert(module.module);
        names.entry(module.module).or_insert(module.name);
    }
    report.available |= report.sources[1].available || report.sources[2].available;

    let universe = list_modules
        .union(&kset_modules)
        .copied()
        .collect::<BTreeSet<_>>()
        .union(&semantic_modules)
        .copied()
        .collect::<BTreeSet<_>>();
    let universe_len = universe.len();
    let source_limit_reached = report.warnings.iter().any(|warning| {
        matches!(
            warning.code.as_str(),
            "linux_modules_limit_reached"
                | "linux_module_kset_limit_reached"
                | "linux_module_semantic_output_limit_reached"
        )
    });
    if universe_len > limit {
        report.warnings.push(warning(
            "linux_modxview_output_limit_reached",
            format!("交叉视图发现 {universe_len} 个对象，仅输出前 {limit} 个"),
            "linux.modxview",
        ));
    }
    for module in universe.into_iter().take(limit) {
        let in_list = list_modules.contains(&module);
        let in_kset = kset_modules.contains(&module);
        let in_semantic = semantic_modules.contains(&module);
        let mut reasons = Vec::new();
        if in_kset && !in_list {
            reasons.push("present_in_module_kset_but_absent_from_modules_list".to_owned());
        }
        if in_list && !in_kset && report.sources[1].complete {
            reasons.push("present_in_modules_list_but_absent_from_complete_module_kset".to_owned());
        }
        if in_semantic && !in_list {
            reasons.push("present_in_semantic_scan_but_absent_from_modules_list".to_owned());
        }
        if in_list && !in_semantic && report.sources[2].complete {
            reasons
                .push("present_in_modules_list_but_absent_from_complete_semantic_scan".to_owned());
        }
        if in_semantic && !in_kset && report.sources[1].complete {
            reasons
                .push("present_in_semantic_scan_but_absent_from_complete_module_kset".to_owned());
        }
        report.records.push(LinuxModxviewRecord {
            module,
            name: names.get(&module).cloned(),
            in_modules_list: in_list,
            in_module_kset: in_kset,
            in_semantic_scan: report.sources[2].available.then_some(in_semantic),
            suspicious: !reasons.is_empty(),
            reasons,
        });
    }
    report.limits[0].observed = Some(universe_len as u64);
    report.limits[0].reached = Some(source_limit_reached || universe_len > limit);
    report.complete = report
        .sources
        .iter()
        .all(|source| source.available && source.complete)
        && report
            .limits
            .iter()
            .all(|limit| limit.reached == Some(false));
    report
}

type ModuleKsetReadResult = (
    Vec<LinuxModuleRecord>,
    bool,
    Vec<EvidenceWarning>,
    Vec<MissingRange>,
);

fn read_module_kset(
    memory: &impl LinuxKernelMemory,
    module_layout: &ModuleLayout,
    limit: usize,
) -> Result<ModuleKsetReadResult> {
    let layout = ModuleKsetLayout::from_isf(memory.isf())?;
    let symbol = memory.runtime_symbol("module_kset")?;
    let pointed = read_unsigned(memory, symbol, 8).unwrap_or(0);
    let kset = if is_kernel_pointer(pointed) {
        pointed
    } else {
        symbol
    };
    let head = kset + layout.kset_list;
    let mut output = Vec::new();
    let mut warnings = Vec::new();
    let mut missing = Vec::new();
    let (first, head_previous) = match read_list(memory, head) {
        Ok(value) => value,
        Err(error) => {
            add_missing(&mut missing, head, 16, "module_kset.list_head");
            warnings.push(warning(
                "linux_module_kset_head_unreadable",
                format!("无法读取 module_kset list head：{error:#}"),
                "linux.modxview",
            ));
            return Ok((output, false, warnings, missing));
        }
    };
    let mut current = first;
    let mut previous = head;
    let mut visited = HashSet::new();
    while current != head {
        if visited.len() >= limit {
            warnings.push(warning(
                "linux_module_kset_limit_reached",
                format!("module_kset 遍历达到 {limit} 条上限"),
                "linux.modxview",
            ));
            return Ok((output, false, warnings, missing));
        }
        ensure!(
            is_kernel_pointer(current) && visited.insert(current),
            "module_kset 出现非法或重复指针 {current:#x}"
        );
        let kobject = current
            .checked_sub(layout.kobject_entry)
            .context("kobject.entry container underflow")?;
        let module_kobject = kobject
            .checked_sub(layout.module_kobject_kobj)
            .context("module_kobject.kobj container underflow")?;
        let module = read_unsigned(memory, module_kobject + layout.module_kobject_mod, 8)?;
        ensure!(is_kernel_pointer(module), "module_kobject.mod 指针无效");
        let (next, backlink) = match read_list(memory, current) {
            Ok(value) => value,
            Err(error) => {
                add_missing(&mut missing, current, 16, "module_kset.list");
                warnings.push(warning(
                    "linux_module_kset_unreadable",
                    format!("无法读取 module_kset entry：{error:#}"),
                    "linux.modxview",
                ));
                return Ok((output, false, warnings, missing));
            }
        };
        if backlink != previous {
            warnings.push(warning(
                "backlink_mismatch",
                format!("module_kset entry {current:#x} backlink 不匹配"),
                "linux.modxview",
            ));
            if let Ok(record) = read_module(memory, module_layout, module)
                && validate_module_record(memory, module_layout, &record, true).is_ok()
            {
                output.push(record);
            }
            return Ok((output, false, warnings, missing));
        }
        match read_module(memory, module_layout, module).and_then(|record| {
            validate_module_record(memory, module_layout, &record, true)?;
            Ok(record)
        }) {
            Ok(record) => output.push(record),
            Err(error) => {
                add_missing(
                    &mut missing,
                    module,
                    memory.isf().type_size("module").unwrap_or(1),
                    "module_kset.module",
                );
                warnings.push(warning_with_context(
                    "linux_module_kset_module_invalid",
                    format!("module_kset 指向的 module {module:#x} 重验失败：{error:#}"),
                    "linux.modxview",
                    BTreeMap::from([("module".to_owned(), serde_json::json!(module))]),
                ));
                // The list can still be traversed, but this view cannot be complete when one of
                // its objects was not structurally recoverable.
            }
        }
        previous = current;
        current = next;
    }
    let structurally_invalid = warnings
        .iter()
        .any(|warning| warning.code == "linux_module_kset_module_invalid");
    let complete = head_previous == previous && !structurally_invalid;
    if head_previous != previous {
        warnings.push(warning(
            "head_blink_mismatch",
            format!("module_kset head.prev={head_previous:#x}，期望 {previous:#x}"),
            "linux.modxview",
        ));
    }
    Ok((output, complete, warnings, missing))
}

fn scan_modules_semantically(
    memory: &impl LinuxKernelMemory,
    layout: &ModuleLayout,
    output_limit: usize,
) -> ModuleSemanticScan {
    let mut output = ModuleSemanticScan::default();
    let structure_size = match memory.isf().type_size("module") {
        Ok(size) if (1..=PAGE_SIZE).contains(&size) => size,
        Ok(size) => {
            output.reason = Some("module_size_out_of_bounds".to_owned());
            output.warnings.push(warning(
                "linux_module_semantic_scan_unavailable",
                format!("module 结构大小 {size} 超出单页扫描上限"),
                "linux.modxview",
            ));
            return output;
        }
        Err(error) => {
            output.reason = Some("module_layout_unavailable".to_owned());
            output.warnings.push(warning(
                "linux_module_semantic_scan_unavailable",
                format!("无法获取 module 结构大小：{error:#}"),
                "linux.modxview",
            ));
            return output;
        }
    };
    let range = (|| -> Result<(u64, u64)> {
        let minimum_symbol = memory.runtime_symbol("module_addr_min")?;
        let maximum_symbol = memory.runtime_symbol("module_addr_max")?;
        let minimum = read_unsigned(memory, minimum_symbol, 8)?;
        let maximum = read_unsigned(memory, maximum_symbol, 8)?;
        ensure!(
            is_kernel_pointer(minimum) && is_kernel_pointer(maximum) && minimum < maximum,
            "module_addr_min/max 范围无效"
        );
        Ok((minimum, maximum))
    })();
    let (minimum, maximum) = match range {
        Ok(value) => value,
        Err(error) => {
            output.reason = Some("provable_scan_range_unavailable".to_owned());
            output.warnings.push(warning(
                "linux_module_semantic_scan_unavailable",
                format!("无 module_addr_min/max 可验证边界，不执行宽松字符串扫描：{error:#}"),
                "linux.modxview",
            ));
            return output;
        }
    };
    output.available = true;
    output.declared_bytes = maximum - minimum;
    let scan_length = output.declared_bytes.min(MAX_MODULE_SEMANTIC_SCAN_BYTES);
    output.byte_limit_reached = scan_length < output.declared_bytes;
    let scan_end = minimum + scan_length;
    let mut scan_complete = !output.byte_limit_reached;
    if output.byte_limit_reached {
        output.warnings.push(warning(
            "linux_module_semantic_byte_limit_reached",
            format!(
                "module 语义扫描范围为 {} 字节，仅检查前 {} 字节",
                output.declared_bytes, MAX_MODULE_SEMANTIC_SCAN_BYTES
            ),
            "linux.modxview",
        ));
    }

    let mut chunk_start = minimum;
    let mut unreadable_chunks = 0_usize;
    'scan: while chunk_start < scan_end {
        let next_page = (chunk_start & !(PAGE_SIZE - 1))
            .saturating_add(PAGE_SIZE)
            .min(scan_end);
        let primary_end = next_page.max(chunk_start);
        let overlap_end = primary_end
            .saturating_add(structure_size.saturating_sub(1))
            .min(scan_end);
        let full_length = usize::try_from(overlap_end - chunk_start).unwrap_or(usize::MAX);
        let primary_length = usize::try_from(primary_end - chunk_start).unwrap_or(usize::MAX);
        let mut bytes = vec![0_u8; full_length];
        let loaded_length = match memory.read_virtual(chunk_start, &mut bytes) {
            Ok(()) => full_length,
            Err(_) => {
                bytes.resize(primary_length, 0);
                match memory.read_virtual(chunk_start, &mut bytes) {
                    Ok(()) => {
                        scan_complete = false;
                        if overlap_end > primary_end {
                            add_missing_coalesced(
                                &mut output.missing_ranges,
                                primary_end,
                                overlap_end - primary_end,
                                "module_semantic_scan",
                            );
                        }
                        primary_length
                    }
                    Err(error) => {
                        scan_complete = false;
                        add_missing_coalesced(
                            &mut output.missing_ranges,
                            chunk_start,
                            primary_end - chunk_start,
                            "module_semantic_scan",
                        );
                        unreadable_chunks += 1;
                        if unreadable_chunks <= MAX_MODULE_SEMANTIC_WARNINGS {
                            output.warnings.push(warning(
                                "linux_module_semantic_page_unreadable",
                                format!(
                                    "语义扫描区间 {chunk_start:#x}..{primary_end:#x} 不可读：{error:#}"
                                ),
                                "linux.modxview",
                            ));
                        }
                        chunk_start = primary_end;
                        continue;
                    }
                }
            }
        };
        output.scanned_bytes = output
            .scanned_bytes
            .saturating_add(primary_end - chunk_start);
        let loaded_end = chunk_start + loaded_length as u64;
        let mut candidate = (chunk_start.saturating_add(7)) & !7;
        while candidate < primary_end {
            let Some(candidate_end) = candidate.checked_add(structure_size) else {
                break;
            };
            if candidate_end > loaded_end {
                break;
            }
            let offset = usize::try_from(candidate - chunk_start).unwrap_or(usize::MAX);
            let end = offset.saturating_add(structure_size as usize);
            let Some(raw) = bytes.get(offset..end) else {
                break;
            };
            let parsed = parse_module_from_slice(layout, candidate, raw);
            if let Ok(module) = parsed
                && module_contains_address(&module, module.module, structure_size)
                && validate_module_record(memory, layout, &module, true).is_ok()
            {
                if output.modules.len() >= output_limit {
                    output.output_limit_reached = true;
                    scan_complete = false;
                    output.warnings.push(warning(
                        "linux_module_semantic_output_limit_reached",
                        format!("语义扫描证明的 module 超过 {output_limit} 条输出上限"),
                        "linux.modxview",
                    ));
                    break 'scan;
                }
                output.modules.push(module);
            }
            candidate = candidate.saturating_add(8);
        }
        chunk_start = primary_end;
    }
    if unreadable_chunks > MAX_MODULE_SEMANTIC_WARNINGS {
        output.warnings.push(warning(
            "linux_module_semantic_warnings_truncated",
            format!(
                "{} 个不可读扫描块仅保留前 {} 条逐块告警",
                unreadable_chunks, MAX_MODULE_SEMANTIC_WARNINGS
            ),
            "linux.modxview",
        ));
    }
    output.complete = scan_complete && !output.output_limit_reached;
    output.reason = (!output.complete).then(|| {
        if output.output_limit_reached {
            "output_limit_reached".to_owned()
        } else if output.byte_limit_reached {
            "byte_limit_reached".to_owned()
        } else {
            "missing_ranges".to_owned()
        }
    });
    output
}

fn parse_module_from_slice(
    layout: &ModuleLayout,
    module: u64,
    bytes: &[u8],
) -> Result<LinuxModuleRecord> {
    let next = read_unsigned_from_slice(bytes, (layout.list, 8))?;
    let previous = read_unsigned_from_slice(bytes, (layout.list + 8, 8))?;
    let name_start = usize::try_from(layout.name)?;
    let name_end = name_start
        .checked_add(layout.name_length)
        .context("module.name 范围溢出")?;
    let name_bytes = bytes
        .get(name_start..name_end)
        .context("module.name 越界")?;
    let name_length = name_bytes
        .iter()
        .position(|byte| *byte == 0)
        .context("module.name 未 NUL 终止")?;
    ensure!(name_length > 0, "module.name 为空");
    ensure!(
        name_bytes[..name_length]
            .iter()
            .all(|byte| { byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.') }),
        "module.name 包含非规范字符"
    );
    let name = String::from_utf8(name_bytes[..name_length].to_vec())?;
    let read_optional = |field: Option<(u64, usize)>| -> Result<Option<u64>> {
        field
            .map(|field| read_unsigned_from_slice(bytes, field))
            .transpose()
    };
    let core_base = read_unsigned_from_slice(bytes, (layout.core_base, layout.core_base_width))?;
    let core_size = read_unsigned_from_slice(bytes, (layout.core_size, layout.core_size_width))?;
    ensure!(
        core_size > 0 && core_size <= MAX_MODULE_BYTES,
        "module.core_size 无效"
    );
    let core_text_size = read_optional(layout.core_text_size)?;
    if let Some(text_size) = core_text_size {
        ensure!(
            text_size > 0 && text_size <= core_size,
            "module.text_size 无效"
        );
    }
    let state = read_optional(layout.state)?;
    if let Some(state) = state {
        ensure!(state <= 3, "module.state 无效");
    }
    Ok(LinuxModuleRecord {
        module,
        list_entry: module + layout.list,
        name,
        core_base,
        core_size,
        core_text_size,
        init_base: read_optional(layout.init_base)?,
        init_size: read_optional(layout.init_size)?,
        state,
        taints: read_optional(layout.taints)?,
        next,
        previous,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxSyscallTable {
    X64,
    Ia32,
    X32,
}

impl LinuxSyscallTable {
    fn symbol(self) -> &'static str {
        match self {
            Self::X64 => "sys_call_table",
            Self::Ia32 => "ia32_sys_call_table",
            Self::X32 => "x32_sys_call_table",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxCheckSyscallOptions {
    pub table: LinuxSyscallTable,
    /// Number of pointer-sized entries to validate. Zero selects the conservative default.
    pub entries: usize,
    /// Include strictly enumerated module text ranges as valid executable owners.
    pub include_modules: bool,
}

impl Default for LinuxCheckSyscallOptions {
    fn default() -> Self {
        Self {
            table: LinuxSyscallTable::X64,
            entries: DEFAULT_SYSCALL_LIMIT,
            include_modules: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxExecutableRange {
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    pub source: String,
    pub owner: String,
    pub provenance: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxSyscallClassification {
    KernelText,
    ModuleText,
    OutsideProvenExecutableRanges,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxSyscallRecord {
    pub index: u64,
    pub entry_address: u64,
    pub handler: Option<u64>,
    pub classification: LinuxSyscallClassification,
    pub owner: Option<String>,
    /// `None` means that an incomplete module universe prevents a reliable verdict.
    pub suspicious: Option<bool>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxCheckSyscallReport {
    pub available: bool,
    pub complete: bool,
    pub scope: EvidenceScope,
    pub warnings: Vec<EvidenceWarning>,
    pub limits: Vec<EvidenceLimit>,
    pub missing_ranges: Vec<MissingRange>,
    pub table: LinuxSyscallTable,
    pub table_address: Option<u64>,
    pub executable_ranges: Vec<LinuxExecutableRange>,
    pub module_source: LinuxKernelSourceStatus,
    pub records: Vec<LinuxSyscallRecord>,
    pub suspicious: usize,
    pub indeterminate: usize,
}

/// Validate syscall pointers against symbol-proven core text and strictly traversed module text.
///
/// This deliberately does not treat a module's whole allocation as executable. A module range is
/// accepted only when `module_layout.text_size` is present, sane and readable at both endpoints.
pub fn linux_check_syscall(
    memory: &impl LinuxKernelMemory,
    options: &LinuxCheckSyscallOptions,
) -> LinuxCheckSyscallReport {
    const ABSOLUTE_ENTRY_CAP: usize = 65_536;
    let requested = if options.entries == 0 {
        DEFAULT_SYSCALL_LIMIT
    } else {
        options.entries
    };
    let mut entries = requested.min(ABSOLUTE_ENTRY_CAP);
    let mut scope = EvidenceScope::new("linux_syscall_table_entries");
    scope.constraints.insert(
        "table".to_owned(),
        serde_json::json!(options.table.symbol()),
    );
    scope
        .constraints
        .insert("entries".to_owned(), serde_json::json!(entries));
    scope.constraints.insert(
        "include_modules".to_owned(),
        serde_json::json!(options.include_modules),
    );
    let mut report = LinuxCheckSyscallReport {
        available: false,
        complete: false,
        scope,
        warnings: Vec::new(),
        limits: vec![EvidenceLimit {
            name: "syscall_entries".to_owned(),
            kind: EvidenceLimitKind::SourceScan,
            configured: Some(requested as u64),
            observed: Some(0),
            reached: Some(requested > ABSOLUTE_ENTRY_CAP),
        }],
        missing_ranges: Vec::new(),
        table: options.table,
        table_address: None,
        executable_ranges: Vec::new(),
        module_source: LinuxKernelSourceStatus {
            source: "modules_list_text_ranges".to_owned(),
            available: false,
            complete: false,
            records: 0,
            reason: None,
        },
        records: Vec::new(),
        suspicious: 0,
        indeterminate: 0,
    };
    if requested > ABSOLUTE_ENTRY_CAP {
        report.warnings.push(warning(
            "linux_syscall_absolute_limit_reached",
            format!(
                "请求 {requested} 个 syscall entry，安全上限为 {ABSOLUTE_ENTRY_CAP}；结果不完整"
            ),
            "linux.check-syscall",
        ));
    }
    let feature = BTreeSet::from([LinuxSymbolFeature::Hooks]);
    let missing = memory.isf().requirement_gaps_for(&feature);
    if !missing.is_empty() {
        report.warnings.push(warning_with_context(
            "linux_symbols_missing",
            "ISF 缺少 syscall table 检查所需的基础符号",
            "linux.check-syscall",
            BTreeMap::from([
                ("types".to_owned(), serde_json::json!(missing.missing_types)),
                (
                    "symbols".to_owned(),
                    serde_json::json!(missing.missing_symbols),
                ),
                (
                    "fields".to_owned(),
                    serde_json::json!(missing.missing_fields),
                ),
            ]),
        ));
        return report;
    }
    let table_address = match memory.runtime_symbol(options.table.symbol()) {
        Ok(address) if is_kernel_pointer(address) => address,
        Ok(address) => {
            report.warnings.push(warning(
                "linux_syscall_table_address_invalid",
                format!("{}={address:#x} 不是规范内核地址", options.table.symbol()),
                "linux.check-syscall",
            ));
            return report;
        }
        Err(error) => {
            report.warnings.push(warning(
                "linux_syscall_table_unavailable",
                format!("无法定位 {}：{error:#}", options.table.symbol()),
                "linux.check-syscall",
            ));
            return report;
        }
    };
    report.table_address = Some(table_address);

    // A scan ceiling is not a table length: adjacent rodata can contain arbitrary
    // non-code values. Only classify entries within the exact ISF array extent.
    let table_entries = match memory
        .isf()
        .symbol_array_count(options.table.symbol())
        .and_then(|count| {
            ensure!(
                memory
                    .isf()
                    .symbol_array_element_size(options.table.symbol())?
                    == 8,
                "syscall table 的 ISF 元素不是 8 字节指针"
            );
            Ok(count)
        }) {
        Ok(count) => count,
        Err(error) => {
            report.warnings.push(warning(
                "linux_syscall_table_extent_unavailable",
                format!("无法核对系统调用表边界，未将相邻内存当作表项：{error:#}"),
                "linux.check-syscall",
            ));
            return report;
        }
    };
    entries = entries.min(usize::try_from(table_entries).unwrap_or(usize::MAX));
    report
        .scope
        .constraints
        .insert("entries".into(), serde_json::json!(entries));
    report
        .scope
        .constraints
        .insert("table_entries".into(), serde_json::json!(table_entries));
    report.scope.constraints.insert(
        "table_extent_basis".into(),
        serde_json::json!("exact ISF symbol array type"),
    );
    let table_truncated = (entries as u64) < table_entries;
    if table_truncated {
        report.limits[0].reached = Some(true);
        report.warnings.push(warning(
            "linux_syscall_table_prefix_only",
            format!("记录上限只覆盖 {entries} / {table_entries} 个系统调用表项"),
            "linux.check-syscall",
        ));
    }

    let kernel_start = match memory.runtime_symbol("_stext") {
        Ok(value) => value,
        Err(error) => {
            report.warnings.push(warning(
                "linux_kernel_text_start_unavailable",
                format!("无法定位 _stext：{error:#}"),
                "linux.check-syscall",
            ));
            return report;
        }
    };
    let kernel_end = match memory.runtime_symbol("_etext") {
        Ok(value) => value,
        Err(error) => {
            report.warnings.push(warning(
                "linux_kernel_text_end_unavailable",
                format!("无法定位 _etext：{error:#}"),
                "linux.check-syscall",
            ));
            return report;
        }
    };
    if !is_kernel_pointer(kernel_start)
        || !is_kernel_pointer(kernel_end)
        || kernel_end <= kernel_start
        || memory.translate(kernel_start).is_err()
        || memory.translate(kernel_end - 1).is_err()
    {
        report.warnings.push(warning(
            "linux_kernel_text_range_unverified",
            format!("无法验证内核 text 区间 [{kernel_start:#x}, {kernel_end:#x})"),
            "linux.check-syscall",
        ));
        return report;
    }
    report.executable_ranges.push(LinuxExecutableRange {
        start: kernel_start,
        end: kernel_end,
        source: "kernel".to_owned(),
        owner: "vmlinux".to_owned(),
        provenance: "_stext/_etext symbols with translated endpoints".to_owned(),
    });

    let mut module_universe_complete = false;
    if options.include_modules {
        let modules = linux_lsmod(memory, DEFAULT_MODULE_LIMIT);
        report
            .missing_ranges
            .extend(modules.missing_ranges.iter().cloned());
        report.warnings.extend(modules.warnings.iter().cloned());
        report.module_source.available = modules.available;
        report.module_source.records = modules.modules.len();
        report.module_source.reason = (!modules.available)
            .then(|| "modules_list_unavailable".to_owned())
            .or_else(|| (!modules.complete).then(|| "modules_list_incomplete".to_owned()));
        let mut all_text_ranges_proven = modules.available && modules.complete;
        for module in &modules.modules {
            let Some(text_size) = module.core_text_size else {
                all_text_ranges_proven = false;
                report.warnings.push(warning_with_context(
                    "linux_module_text_range_unavailable",
                    format!("模块 {} 没有可证明的 core text_size", module.name),
                    "linux.check-syscall",
                    BTreeMap::from([("module".to_owned(), serde_json::json!(module.module))]),
                ));
                continue;
            };
            let Some(end) = module.core_base.checked_add(text_size) else {
                all_text_ranges_proven = false;
                report.warnings.push(warning(
                    "linux_module_text_range_invalid",
                    format!("模块 {} text 区间溢出", module.name),
                    "linux.check-syscall",
                ));
                continue;
            };
            if text_size == 0
                || text_size > module.core_size
                || !is_kernel_pointer(module.core_base)
                || memory.translate(module.core_base).is_err()
                || memory.translate(end - 1).is_err()
            {
                all_text_ranges_proven = false;
                report.warnings.push(warning(
                    "linux_module_text_range_unverified",
                    format!(
                        "模块 {} text 区间 [{:#x}, {end:#x}) 无法重验",
                        module.name, module.core_base
                    ),
                    "linux.check-syscall",
                ));
                continue;
            }
            report.executable_ranges.push(LinuxExecutableRange {
                start: module.core_base,
                end,
                source: "module".to_owned(),
                owner: module.name.clone(),
                provenance: format!("module {:#x} core_layout.text_size", module.module),
            });
        }
        module_universe_complete = all_text_ranges_proven;
        report.module_source.complete = module_universe_complete;
        if modules.available && !module_universe_complete && report.module_source.reason.is_none() {
            report.module_source.reason = Some("module_text_ranges_incomplete".to_owned());
        }
    } else {
        report.module_source.reason = Some("disabled_by_scope".to_owned());
        report.warnings.push(warning(
            "linux_module_ranges_disabled",
            "调用者禁用了 module text 范围；落在 kernel text 之外的指针只能给出不确定结论",
            "linux.check-syscall",
        ));
    }

    report.available = true;
    let mut all_entries_readable = true;
    let mut indeterminate = false;
    for index in 0..entries {
        let entry_address = match table_address.checked_add(index as u64 * 8) {
            Some(value) => value,
            None => {
                all_entries_readable = false;
                report.warnings.push(warning(
                    "linux_syscall_entry_address_overflow",
                    format!("syscall entry {index} 地址溢出"),
                    "linux.check-syscall",
                ));
                break;
            }
        };
        let handler = match read_unsigned(memory, entry_address, 8) {
            Ok(value) => value,
            Err(error) => {
                all_entries_readable = false;
                add_missing(
                    &mut report.missing_ranges,
                    entry_address,
                    8,
                    "syscall_table_entry",
                );
                report.warnings.push(warning(
                    "linux_syscall_entry_unreadable",
                    format!("syscall entry {index} 无法读取：{error:#}"),
                    "linux.check-syscall",
                ));
                report.records.push(LinuxSyscallRecord {
                    index: index as u64,
                    entry_address,
                    handler: None,
                    classification: LinuxSyscallClassification::Unreadable,
                    owner: None,
                    suspicious: None,
                    reason: "entry_unreadable".to_owned(),
                });
                continue;
            }
        };
        let owner = report
            .executable_ranges
            .iter()
            .find(|range| handler >= range.start && handler < range.end);
        let (classification, owner, suspicious, reason) = match owner {
            Some(range) if range.source == "kernel" => (
                LinuxSyscallClassification::KernelText,
                Some(range.owner.clone()),
                Some(false),
                "inside_proven_kernel_text".to_owned(),
            ),
            Some(range) => (
                LinuxSyscallClassification::ModuleText,
                Some(range.owner.clone()),
                Some(false),
                "inside_proven_module_text".to_owned(),
            ),
            None if module_universe_complete => (
                LinuxSyscallClassification::OutsideProvenExecutableRanges,
                None,
                Some(true),
                "outside_complete_kernel_and_module_text_universe".to_owned(),
            ),
            None => {
                indeterminate = true;
                (
                    LinuxSyscallClassification::OutsideProvenExecutableRanges,
                    None,
                    None,
                    "outside_proven_ranges_but_module_universe_incomplete".to_owned(),
                )
            }
        };
        report.records.push(LinuxSyscallRecord {
            index: index as u64,
            entry_address,
            handler: Some(handler),
            classification,
            owner,
            suspicious,
            reason,
        });
    }
    report.suspicious = report
        .records
        .iter()
        .filter(|record| record.suspicious == Some(true))
        .count();
    report.indeterminate = report
        .records
        .iter()
        .filter(|record| record.suspicious.is_none())
        .count();
    report.limits[0].observed = Some(report.records.len() as u64);
    report.complete = requested <= ABSOLUTE_ENTRY_CAP
        && !table_truncated
        && report.records.len() == entries
        && all_entries_readable
        && !indeterminate;
    if indeterminate {
        report.warnings.push(warning(
            "linux_syscall_verdict_incomplete",
            "至少一个 handler 位于已证明范围之外，但 module text 宇宙不完整；未将其确定标为 hook",
            "linux.check-syscall",
        ));
    }
    report
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use serde_json::{Value, json};

    use super::*;
    use crate::linux_symbols::load_linux_isf_for_features;

    const KERNEL: u64 = 0xffff_8000_0010_0000;
    const STEXT: u64 = KERNEL;
    const ETEXT: u64 = KERNEL + 0x2000;
    const BANNER: u64 = KERNEL + 0x3000;
    const MODULES: u64 = KERNEL + 0x4000;
    const MODULE: u64 = KERNEL + 0x5000;
    const MODULE_KSET_POINTER: u64 = KERNEL + 0x6000;
    const MODULE_KSET: u64 = KERNEL + 0x7000;
    const MODULE_KOBJECT: u64 = KERNEL + 0x7800;
    const MODULE_CORE: u64 = KERNEL + 0x8000;
    const INIT_TASK: u64 = KERNEL + 0xb000;
    const NSPROXY: u64 = KERNEL + 0xc000;
    const MOUNT_NAMESPACE: u64 = KERNEL + 0xd000;
    const MOUNT: u64 = KERNEL + 0xe000;
    const ROOT_DENTRY: u64 = KERNEL + 0xf000;
    const SUPER_BLOCK: u64 = KERNEL + 0x10_000;
    const FS_TYPE: u64 = KERNEL + 0x11_000;
    const FS_NAME: u64 = KERNEL + 0x12_000;
    const KALL_NUM: u64 = KERNEL + 0x13_000;
    const KALL_NAMES: u64 = KERNEL + 0x14_000;
    const KALL_MARKERS: u64 = KERNEL + 0x15_000;
    const KALL_TOKENS: u64 = KERNEL + 0x16_000;
    const KALL_TOKEN_INDEX: u64 = KERNEL + 0x17_000;
    const KALL_ADDRESSES: u64 = KERNEL + 0x18_000;
    const KMSG_POINTER: u64 = KERNEL + 0x19_000;
    const KMSG_LENGTH: u64 = KERNEL + 0x19_100;
    const KMSG_FIRST: u64 = KERNEL + 0x19_200;
    const KMSG_NEXT: u64 = KERNEL + 0x19_300;
    const KMSG_BUFFER: u64 = KERNEL + 0x1a_000;
    const PRINTK_RING: u64 = KERNEL + 0x1b_000;
    const PRINTK_DESCS: u64 = KERNEL + 0x1c_000;
    const PRINTK_INFOS: u64 = KERNEL + 0x1d_000;
    const PRINTK_TEXT: u64 = KERNEL + 0x1e_000;
    const SYSCALL_TABLE: u64 = KERNEL + 0x1f_000;
    const MODULE_ADDR_MIN_VARIABLE: u64 = KERNEL + 0x20_000;
    const MODULE_ADDR_MAX_VARIABLE: u64 = KERNEL + 0x20_008;
    const MODULE_SYMTAB: u64 = KERNEL + 0x21_000;
    const MODULE_STRTAB: u64 = KERNEL + 0x22_000;
    const MODULE_TYPETAB: u64 = KERNEL + 0x23_000;
    const SEMANTIC_RANGE: u64 = KERNEL + 0x30_000;
    const HIDDEN_MODULE: u64 = SEMANTIC_RANGE + 0x100;
    const SECOND_HIDDEN_MODULE: u64 = SEMANTIC_RANGE + 0x300;
    const BANNER_TEXT: &str = "Linux version 6.8.0-starmem-test #1 SMP";

    static NONCE: AtomicU64 = AtomicU64::new(1);

    fn field(offset: u64, kind: Value) -> Value {
        json!({"offset": offset, "type": kind})
    }

    fn base(name: &str) -> Value {
        json!({"kind": "base", "name": name})
    }

    fn pointer() -> Value {
        json!({"kind": "pointer"})
    }

    fn structure(name: &str) -> Value {
        json!({"kind": "struct", "name": name})
    }

    fn array(name: &str, count: u64) -> Value {
        json!({"kind": "array", "count": count, "subtype": {"kind": "base", "name": name}})
    }

    fn user_type(size: u64, fields: Value) -> Value {
        json!({"size": size, "fields": fields})
    }

    fn symbol(address: u64) -> Value {
        json!({"address": address})
    }

    fn isf_document(user_types: Value, extra_symbols: Value) -> Value {
        let mut symbols = extra_symbols.as_object().cloned().unwrap_or_default();
        symbols.insert("_stext".to_owned(), symbol(STEXT));
        symbols.insert("_etext".to_owned(), symbol(ETEXT));
        symbols.insert(
            "linux_banner".to_owned(),
            json!({
                "address": BANNER,
                "constant_data": BASE64_STANDARD.encode(format!("{BANNER_TEXT}\n\0")),
            }),
        );
        json!({
            "metadata": {
                "format": "6.2.0",
                "producer": {"name": "dwarf2json", "version": "synthetic"},
                "linux": {"symbols": [], "types": []},
            },
            "base_types": {
                "char": {"size": 1},
                "unsigned char": {"size": 1},
                "unsigned short": {"size": 2},
                "unsigned int": {"size": 4},
                "long unsigned int": {"size": 8},
            },
            "user_types": user_types,
            "enums": {},
            "symbols": Value::Object(symbols),
        })
    }

    fn module_document() -> Value {
        isf_document(
            json!({
                "list_head": user_type(16, json!({})),
                "module_layout": user_type(24, json!({
                    "base": field(0, pointer()),
                    "size": field(8, base("long unsigned int")),
                    "text_size": field(16, base("long unsigned int")),
                })),
                "module": user_type(112, json!({
                    "list": field(0, structure("list_head")),
                    "name": field(16, array("char", 56)),
                    "core_layout": field(72, structure("module_layout")),
                })),
                "module_kobject": user_type(32, json!({
                    "kobj": field(0, structure("kobject")),
                    "mod": field(24, pointer()),
                })),
                "kobject": user_type(24, json!({
                    "entry": field(0, structure("list_head")),
                })),
                "kset": user_type(24, json!({
                    "list": field(0, structure("list_head")),
                })),
            }),
            json!({
                "modules": symbol(MODULES),
                "module_kset": symbol(MODULE_KSET_POINTER),
                "sys_call_table": {"address":SYSCALL_TABLE,"type":array("long unsigned int",3)},
            }),
        )
    }

    fn mount_document() -> Value {
        isf_document(
            json!({
                "list_head": user_type(16, json!({})),
                "task_struct": user_type(16, json!({
                    "nsproxy": field(0, pointer()),
                    "pid": field(8, base("unsigned int")),
                })),
                "nsproxy": user_type(8, json!({"mnt_ns": field(0, pointer())})),
                "mnt_namespace": user_type(16, json!({
                    "list": field(0, structure("list_head")),
                })),
                "mount": user_type(64, json!({
                    "mnt_list": field(0, structure("list_head")),
                    "mnt": field(16, structure("vfsmount")),
                    "mnt_parent": field(32, pointer()),
                    "mnt_mountpoint": field(40, pointer()),
                    "mnt_id": field(48, base("unsigned int")),
                    "mnt_group_id": field(52, base("unsigned int")),
                })),
                "vfsmount": user_type(16, json!({
                    "mnt_root": field(0, pointer()),
                    "mnt_sb": field(8, pointer()),
                })),
                "path": user_type(16, json!({})),
                "dentry": user_type(24, json!({
                    "d_parent": field(0, pointer()),
                    "d_name": field(8, structure("qstr")),
                })),
                "qstr": user_type(16, json!({
                    "len": field(0, base("unsigned int")),
                    "name": field(8, pointer()),
                })),
                "super_block": user_type(16, json!({
                    "s_type": field(0, pointer()),
                    "s_dev": field(8, base("long unsigned int")),
                })),
                "file_system_type": user_type(8, json!({"name": field(0, pointer())})),
            }),
            json!({"init_task": symbol(INIT_TASK)}),
        )
    }

    fn kallsyms_document() -> Value {
        isf_document(
            json!({}),
            json!({
                "kallsyms_num_syms": symbol(KALL_NUM),
                "kallsyms_names": symbol(KALL_NAMES),
                "kallsyms_markers": symbol(KALL_MARKERS),
                "kallsyms_token_table": symbol(KALL_TOKENS),
                "kallsyms_token_index": symbol(KALL_TOKEN_INDEX),
                "kallsyms_addresses": symbol(KALL_ADDRESSES),
            }),
        )
    }

    fn module_kallsyms_document() -> Value {
        isf_document(
            json!({
                "list_head": user_type(16, json!({})),
                "module_layout": user_type(24, json!({
                    "base": field(0, pointer()),
                    "size": field(8, base("long unsigned int")),
                    "text_size": field(16, base("long unsigned int")),
                })),
                "module": user_type(128, json!({
                    "list": field(0, structure("list_head")),
                    "name": field(16, array("char", 56)),
                    "core_layout": field(72, structure("module_layout")),
                    "symtab": field(96, pointer()),
                    "num_symtab": field(104, base("unsigned int")),
                    "strtab": field(112, pointer()),
                    "typetab": field(120, pointer()),
                })),
                "module_kobject": user_type(32, json!({
                    "kobj": field(0, structure("kobject")),
                    "mod": field(24, pointer()),
                })),
                "kobject": user_type(24, json!({
                    "entry": field(0, structure("list_head")),
                })),
                "kset": user_type(24, json!({
                    "list": field(0, structure("list_head")),
                })),
            }),
            json!({
                "modules": symbol(MODULES),
                "module_kset": symbol(MODULE_KSET_POINTER),
                "kallsyms_num_syms": symbol(KALL_NUM),
                "kallsyms_names": symbol(KALL_NAMES),
                "kallsyms_markers": symbol(KALL_MARKERS),
                "kallsyms_token_table": symbol(KALL_TOKENS),
                "kallsyms_token_index": symbol(KALL_TOKEN_INDEX),
                "kallsyms_addresses": symbol(KALL_ADDRESSES),
            }),
        )
    }

    fn old_kmsg_document() -> Value {
        isf_document(
            json!({
                "printk_log": user_type(16, json!({
                    "ts_nsec": field(0, base("long unsigned int")),
                    "len": field(8, base("unsigned short")),
                    "text_len": field(10, base("unsigned short")),
                    "dict_len": field(12, base("unsigned short")),
                    "facility": field(14, base("unsigned char")),
                    "flags": field(15, base("unsigned char")),
                })),
            }),
            json!({
                "log_buf": symbol(KMSG_POINTER),
                "log_buf_len": symbol(KMSG_LENGTH),
                "log_first_idx": symbol(KMSG_FIRST),
                "log_next_idx": symbol(KMSG_NEXT),
            }),
        )
    }

    fn new_kmsg_document() -> Value {
        isf_document(
            json!({
                "atomic_long_t": user_type(8, json!({
                    "counter": field(0, base("long unsigned int")),
                })),
                "printk_ringbuffer": user_type(96, json!({
                    "desc_ring": field(0, structure("prb_desc_ring")),
                    "text_data_ring": field(64, structure("prb_data_ring")),
                })),
                "prb_desc_ring": user_type(40, json!({
                    "count_bits": field(0, base("unsigned int")),
                    "descs": field(8, pointer()),
                    "infos": field(16, pointer()),
                    "head_id": field(24, structure("atomic_long_t")),
                    "tail_id": field(32, structure("atomic_long_t")),
                })),
                "prb_data_ring": user_type(16, json!({
                    "size_bits": field(0, base("unsigned int")),
                    "data": field(8, pointer()),
                })),
                "prb_data_blk_lpos": user_type(16, json!({
                    "begin": field(0, base("long unsigned int")),
                    "next": field(8, base("long unsigned int")),
                })),
                "prb_desc": user_type(24, json!({
                    "state_var": field(0, structure("atomic_long_t")),
                    "text_blk_lpos": field(8, structure("prb_data_blk_lpos")),
                })),
                "printk_info": user_type(24, json!({
                    "seq": field(0, base("long unsigned int")),
                    "ts_nsec": field(8, base("long unsigned int")),
                    "text_len": field(16, base("unsigned short")),
                    "facility": field(18, base("unsigned char")),
                    "flags": field(19, base("unsigned char")),
                })),
            }),
            json!({"prb": symbol(PRINTK_RING)}),
        )
    }

    struct SyntheticMemory {
        root: PathBuf,
        source: PathBuf,
        isf: Arc<LinuxIsf>,
        bytes: BTreeMap<u64, u8>,
        runtime_symbols: BTreeMap<String, u64>,
    }

    impl SyntheticMemory {
        fn new(document: Value, features: &[LinuxSymbolFeature]) -> Self {
            let root = std::env::temp_dir().join(format!(
                "starmem-linux-kernel-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            let isf_path = root.join("kernel.json");
            fs::write(&isf_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
            let source = root.join("image.raw");
            fs::write(&source, [0_u8; 8]).unwrap();
            let isf = load_linux_isf_for_features(&isf_path, features.iter().copied()).unwrap();
            Self {
                root,
                source,
                isf: Arc::new(isf),
                bytes: BTreeMap::new(),
                runtime_symbols: BTreeMap::new(),
            }
        }

        fn set_runtime_symbol(&mut self, name: &str, address: u64) {
            self.runtime_symbols.insert(name.to_owned(), address);
        }

        fn put(&mut self, address: u64, bytes: &[u8]) {
            for (offset, byte) in bytes.iter().copied().enumerate() {
                self.bytes.insert(address + offset as u64, byte);
            }
        }

        fn put_u16(&mut self, address: u64, value: u16) {
            self.put(address, &value.to_le_bytes());
        }

        fn put_u32(&mut self, address: u64, value: u32) {
            self.put(address, &value.to_le_bytes());
        }

        fn put_u64(&mut self, address: u64, value: u64) {
            self.put(address, &value.to_le_bytes());
        }

        fn put_list(&mut self, address: u64, next: u64, previous: u64) {
            self.put_u64(address, next);
            self.put_u64(address + 8, previous);
        }

        fn put_zero_terminated_fixed(&mut self, address: u64, value: &str, length: usize) {
            let mut output = vec![0_u8; length];
            let take = value.len().min(length.saturating_sub(1));
            output[..take].copy_from_slice(&value.as_bytes()[..take]);
            self.put(address, &output);
        }
    }

    impl Drop for SyntheticMemory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    impl LinuxKernelMemory for SyntheticMemory {
        fn read_virtual(&self, address: u64, output: &mut [u8]) -> Result<()> {
            for (offset, slot) in output.iter_mut().enumerate() {
                *slot = *self
                    .bytes
                    .get(&(address + offset as u64))
                    .with_context(|| {
                        format!("synthetic missing byte at {:#x}", address + offset as u64)
                    })?;
            }
            Ok(())
        }

        fn translate(&self, address: u64) -> Result<u64> {
            ensure!(is_kernel_pointer(address), "synthetic non-kernel address");
            let page = address & !(PAGE_SIZE - 1);
            ensure!(
                self.bytes.range(page..page + PAGE_SIZE).next().is_some(),
                "synthetic page missing"
            );
            Ok(address)
        }

        fn isf(&self) -> &LinuxIsf {
            &self.isf
        }

        fn kernel_slide(&self) -> u64 {
            0
        }

        fn source_path(&self) -> Option<&Path> {
            Some(&self.source)
        }

        fn runtime_symbol(&self, name: &str) -> Result<u64> {
            if let Some(address) = self.runtime_symbols.get(name) {
                return Ok(*address);
            }
            self.isf
                .symbol_address(name)?
                .checked_add(self.kernel_slide())
                .with_context(|| format!("synthetic runtime symbol {name} 溢出"))
        }
    }

    fn populate_module(memory: &mut SyntheticMemory, second_page: bool, kset: bool) {
        memory.put_list(MODULES, MODULE, MODULE);
        memory.put_list(MODULE, MODULES, MODULES);
        memory.put_zero_terminated_fixed(MODULE + 16, "starmem_test", 56);
        memory.put_u64(MODULE + 72, MODULE_CORE);
        memory.put_u64(MODULE + 80, PAGE_SIZE * 2);
        memory.put_u64(MODULE + 88, PAGE_SIZE);
        memory.put(MODULE_CORE, &vec![0x90; PAGE_SIZE as usize]);
        if second_page {
            memory.put(MODULE_CORE + PAGE_SIZE, &vec![0xcc; PAGE_SIZE as usize]);
        }
        if kset {
            memory.put_u64(MODULE_KSET_POINTER, MODULE_KSET);
            memory.put_list(MODULE_KSET, MODULE_KOBJECT, MODULE_KOBJECT);
            memory.put_list(MODULE_KOBJECT, MODULE_KSET, MODULE_KSET);
            memory.put_u64(MODULE_KOBJECT + 24, MODULE);
        }
    }

    fn populate_core_kallsyms(memory: &mut SyntheticMemory) {
        memory.put_u32(KALL_NUM, 1);
        memory.put(KALL_NAMES, &[2, 1, 2]);
        memory.put(KALL_TOKENS, b"T\0foo\0");
        let mut token_index = [0_u8; 512];
        token_index[2..4].copy_from_slice(&0_u16.to_le_bytes());
        token_index[4..6].copy_from_slice(&2_u16.to_le_bytes());
        memory.put(KALL_TOKEN_INDEX, &token_index);
        memory.put_u64(KALL_ADDRESSES, STEXT + 0x100);
    }

    fn populate_module_symbols(memory: &mut SyntheticMemory) {
        memory.put_u64(MODULE + 96, MODULE_SYMTAB);
        memory.put_u32(MODULE + 104, 2);
        memory.put_u64(MODULE + 112, MODULE_STRTAB);
        memory.put_u64(MODULE + 120, MODULE_TYPETAB);
        memory.put(MODULE_SYMTAB, &[0_u8; ELF64_SYMBOL_SIZE as usize]);
        let entry = MODULE_SYMTAB + ELF64_SYMBOL_SIZE;
        memory.put_u32(entry, 1);
        memory.put(entry + 4, &[2, 0]);
        memory.put_u16(entry + 6, 1);
        memory.put_u64(entry + 8, MODULE_CORE + 0x100);
        memory.put_u64(entry + 16, 0x20);
        memory.put(MODULE_STRTAB, b"\0module_func\0");
        memory.put(MODULE_TYPETAB, b"?t");
    }

    fn populate_semantic_range(memory: &mut SyntheticMemory, modules: &[u64]) {
        memory.put(SEMANTIC_RANGE, &vec![0_u8; PAGE_SIZE as usize]);
        memory.put_u64(MODULE_ADDR_MIN_VARIABLE, SEMANTIC_RANGE);
        memory.put_u64(MODULE_ADDR_MAX_VARIABLE, SEMANTIC_RANGE + PAGE_SIZE);
        memory.set_runtime_symbol("module_addr_min", MODULE_ADDR_MIN_VARIABLE);
        memory.set_runtime_symbol("module_addr_max", MODULE_ADDR_MAX_VARIABLE);
        for (index, module) in modules.iter().copied().enumerate() {
            memory.put_list(module, module, module);
            memory.put_zero_terminated_fixed(module + 16, &format!("hidden_{index}"), 56);
            memory.put_u64(module + 72, SEMANTIC_RANGE);
            memory.put_u64(module + 80, PAGE_SIZE);
            memory.put_u64(module + 88, PAGE_SIZE / 2);
        }
    }

    #[test]
    fn lsmod_strictly_validates_backlinks() {
        let mut memory = SyntheticMemory::new(module_document(), &[LinuxSymbolFeature::Modules]);
        populate_module(&mut memory, true, false);
        let healthy = linux_lsmod(&memory, 16);
        assert!(healthy.available);
        assert!(healthy.complete);
        assert_eq!(healthy.modules.len(), 1);
        assert_eq!(healthy.modules[0].name, "starmem_test");

        memory.put_u64(MODULE + 8, MODULE + 0x10);
        let damaged = linux_lsmod(&memory, 16);
        assert!(damaged.available);
        assert!(!damaged.complete);
        assert_eq!(damaged.stop_reason, "backlink_mismatch");
        assert!(
            damaged
                .warnings
                .iter()
                .any(|warning| warning.code == "backlink_mismatch")
        );
    }

    #[test]
    fn module_extract_publishes_partial_and_manifest_without_touching_inputs() {
        let mut memory = SyntheticMemory::new(module_document(), &[LinuxSymbolFeature::Modules]);
        populate_module(&mut memory, false, false);
        let image_before = fs::read(&memory.source).unwrap();
        let isf_before = fs::read(memory.isf.path()).unwrap();
        let output = memory.root.join("module.elf");
        let report = linux_module_extract(
            &memory,
            LinuxModuleSelector::Name("starmem_test".to_owned()),
            &output,
            PAGE_SIZE * 2,
            false,
        )
        .unwrap();
        assert!(report.available);
        assert!(!report.complete);
        let partial = report.output.as_ref().unwrap();
        assert_eq!(partial, &append_path_suffix(&output, ".partial"));
        assert!(fs::read(partial).unwrap().starts_with(b"\x7fELF"));
        assert!(report.manifest.as_ref().unwrap().is_file());
        assert!(!report.missing_ranges.is_empty());
        assert_eq!(fs::read(&memory.source).unwrap(), image_before);
        assert_eq!(fs::read(memory.isf.path()).unwrap(), isf_before);
    }

    #[test]
    fn mountinfo_reads_a_namespace_without_traversing_tasks() {
        let mut memory = SyntheticMemory::new(mount_document(), &[LinuxSymbolFeature::Mount]);
        memory.put_u64(INIT_TASK, NSPROXY);
        memory.put_u64(INIT_TASK + 8, 1);
        memory.put_u64(NSPROXY, MOUNT_NAMESPACE);
        memory.put_list(MOUNT_NAMESPACE, MOUNT, MOUNT);
        memory.put_list(MOUNT, MOUNT_NAMESPACE, MOUNT_NAMESPACE);
        memory.put_u64(MOUNT + 16, ROOT_DENTRY);
        memory.put_u64(MOUNT + 24, SUPER_BLOCK);
        memory.put_u64(MOUNT + 32, MOUNT);
        memory.put_u64(MOUNT + 40, ROOT_DENTRY);
        memory.put_u32(MOUNT + 48, 42);
        memory.put_u32(MOUNT + 52, 7);
        memory.put_u64(SUPER_BLOCK, FS_TYPE);
        memory.put_u64(SUPER_BLOCK + 8, 0x801);
        memory.put_u64(FS_TYPE, FS_NAME);
        memory.put(FS_NAME, b"ext4\0");

        let report = linux_mountinfo(&memory, &LinuxMountInfoOptions::default());
        assert!(report.available);
        assert!(report.complete);
        assert_eq!(report.mounts.len(), 1);
        assert_eq!(report.mounts[0].file_system.as_deref(), Some("ext4"));
        assert_eq!(report.mounts[0].mount_point, "/");
    }

    #[test]
    fn kallsyms_core_only_is_positive_but_module_universe_is_unavailable() {
        let mut memory = SyntheticMemory::new(kallsyms_document(), &[LinuxSymbolFeature::Kallsyms]);
        populate_core_kallsyms(&mut memory);

        let report = linux_kallsyms(&memory, 16);
        assert!(report.available);
        assert!(!report.complete);
        assert_eq!(report.symbols.len(), 1);
        assert_eq!(report.symbols[0].symbol_type, Some('T'));
        assert_eq!(report.symbols[0].name, "foo");
        assert!(report.sources[0].complete);
        assert!(!report.sources[1].available);
        assert!(!report.sources[2].available);
        assert!(!report.sources[3].available);
    }

    #[test]
    fn kallsyms_decodes_strictly_validated_module_elf64_symbols() {
        let mut memory = SyntheticMemory::new(
            module_kallsyms_document(),
            &[LinuxSymbolFeature::Kallsyms, LinuxSymbolFeature::Modules],
        );
        populate_core_kallsyms(&mut memory);
        populate_module(&mut memory, true, false);
        populate_module_symbols(&mut memory);

        let report = linux_kallsyms(&memory, 16);
        assert!(report.available);
        assert!(report.complete);
        assert_eq!(report.sources[0].records, 1);
        assert!(report.sources[1].available);
        assert!(report.sources[1].complete);
        assert_eq!(report.sources[1].records, 1);
        let symbol = report
            .symbols
            .iter()
            .find(|symbol| symbol.source == "module_symtab")
            .unwrap();
        assert_eq!(symbol.name, "module_func");
        assert_eq!(symbol.address, MODULE_CORE + 0x100);
        assert_eq!(symbol.module, Some(MODULE));
        assert_eq!(symbol.module_name.as_deref(), Some("starmem_test"));
        assert_eq!(symbol.symbol_type, Some('t'));
    }

    #[test]
    fn kallsyms_module_symbols_report_output_limit_separately() {
        let mut memory = SyntheticMemory::new(
            module_kallsyms_document(),
            &[LinuxSymbolFeature::Kallsyms, LinuxSymbolFeature::Modules],
        );
        populate_core_kallsyms(&mut memory);
        populate_module(&mut memory, true, false);
        populate_module_symbols(&mut memory);

        let report = linux_kallsyms(&memory, 1);
        assert!(report.available);
        assert!(!report.complete);
        assert_eq!(report.symbols.len(), 1);
        assert!(!report.sources[1].complete);
        assert_eq!(
            report.sources[1].reason.as_deref(),
            Some("output_limit_reached")
        );
        assert_eq!(report.limits[0].reached, Some(true));
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.code == "linux_kallsyms_limit_reached")
        );
    }

    #[test]
    fn kmsg_legacy_outputs_monotonic_time_without_inventing_wall_clock() {
        let mut memory = SyntheticMemory::new(old_kmsg_document(), &[LinuxSymbolFeature::Kmsg]);
        memory.put_u64(KMSG_POINTER, KMSG_BUFFER);
        memory.put_u32(KMSG_LENGTH, 64);
        memory.put_u32(KMSG_FIRST, 0);
        memory.put_u32(KMSG_NEXT, 21);
        memory.put_u64(KMSG_BUFFER, 123_456_789);
        memory.put_u16(KMSG_BUFFER + 8, 21);
        memory.put_u16(KMSG_BUFFER + 10, 5);
        memory.put_u16(KMSG_BUFFER + 12, 0);
        memory.put(KMSG_BUFFER + 14, &[1, 2]);
        memory.put(KMSG_BUFFER + 16, b"hello");

        let report = linux_kmsg(
            &memory,
            &LinuxKmsgOptions {
                limit: 8,
                boot_time_unix_ns: None,
            },
        );
        assert!(report.available);
        assert!(report.complete);
        assert_eq!(report.timestamp_mode, "monotonic_only");
        assert_eq!(report.records[0].text, "hello");
        assert_eq!(report.records[0].monotonic_ns, 123_456_789);
        assert_eq!(report.records[0].utc, None);
    }

    #[test]
    fn kmsg_new_ring_is_positive_but_conservatively_incomplete() {
        let mut memory = SyntheticMemory::new(new_kmsg_document(), &[LinuxSymbolFeature::Kmsg]);
        memory.put_u32(PRINTK_RING, 1);
        memory.put_u64(PRINTK_RING + 8, PRINTK_DESCS);
        memory.put_u64(PRINTK_RING + 16, PRINTK_INFOS);
        memory.put_u64(PRINTK_RING + 24, 0);
        memory.put_u64(PRINTK_RING + 32, 0);
        memory.put_u32(PRINTK_RING + 64, 12);
        memory.put_u64(PRINTK_RING + 72, PRINTK_TEXT);
        memory.put_u64(PRINTK_DESCS, 1);
        memory.put_u64(PRINTK_DESCS + 8, 0);
        memory.put_u64(PRINTK_DESCS + 16, 13);
        memory.put_u64(PRINTK_INFOS, 77);
        memory.put_u64(PRINTK_INFOS + 8, 987_654_321);
        memory.put_u16(PRINTK_INFOS + 16, 5);
        memory.put(PRINTK_INFOS + 18, &[3, 4]);
        memory.put(PRINTK_TEXT + 8, b"world");

        let report = linux_kmsg(&memory, &LinuxKmsgOptions::default());
        assert!(report.available);
        assert!(!report.complete);
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].sequence, Some(77));
        assert_eq!(report.records[0].text, "world");
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| { warning.code == "linux_printk_descriptor_state_limited" })
        );
    }

    #[test]
    fn modxview_reports_two_positive_views_and_explicitly_absent_semantic_scan() {
        let mut memory = SyntheticMemory::new(module_document(), &[LinuxSymbolFeature::Modules]);
        populate_module(&mut memory, true, true);
        let report = linux_modxview(&memory, 16);
        assert!(report.available);
        assert!(!report.complete);
        assert_eq!(report.records.len(), 1);
        assert!(report.records[0].in_modules_list);
        assert!(report.records[0].in_module_kset);
        assert_eq!(report.records[0].in_semantic_scan, None);
        assert!(!report.sources[2].available);
    }

    #[test]
    fn modxview_semantic_scan_finds_only_structurally_validated_hidden_module() {
        let mut memory = SyntheticMemory::new(module_document(), &[LinuxSymbolFeature::Modules]);
        populate_module(&mut memory, true, true);
        populate_semantic_range(&mut memory, &[HIDDEN_MODULE]);

        let report = linux_modxview(&memory, 16);
        assert!(report.available);
        assert!(report.complete);
        assert!(report.sources[2].available);
        assert!(report.sources[2].complete);
        assert_eq!(report.sources[2].records, 1);
        let hidden = report
            .records
            .iter()
            .find(|record| record.module == HIDDEN_MODULE)
            .unwrap();
        assert_eq!(hidden.in_semantic_scan, Some(true));
        assert!(!hidden.in_modules_list);
        assert!(!hidden.in_module_kset);
        assert!(hidden.suspicious);
        assert!(
            hidden.reasons.iter().any(|reason| {
                reason == "present_in_semantic_scan_but_absent_from_modules_list"
            })
        );
    }

    #[test]
    fn modxview_semantic_scan_marks_output_limit_incomplete() {
        let mut memory = SyntheticMemory::new(module_document(), &[LinuxSymbolFeature::Modules]);
        populate_module(&mut memory, true, true);
        populate_semantic_range(&mut memory, &[HIDDEN_MODULE, SECOND_HIDDEN_MODULE]);

        let report = linux_modxview(&memory, 1);
        assert!(report.available);
        assert!(!report.complete);
        assert!(report.sources[2].available);
        assert!(!report.sources[2].complete);
        assert_eq!(
            report.sources[2].reason.as_deref(),
            Some("output_limit_reached")
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.code == "linux_module_semantic_output_limit_reached")
        );
        assert_eq!(report.limits[0].reached, Some(true));
    }

    #[test]
    fn check_syscall_only_marks_outside_handlers_when_module_universe_is_complete() {
        let mut memory = SyntheticMemory::new(
            module_document(),
            &[LinuxSymbolFeature::Modules, LinuxSymbolFeature::Hooks],
        );
        populate_module(&mut memory, true, false);
        memory.put(STEXT, &[0x90]);
        memory.put(ETEXT - 1, &[0x90]);
        memory.put_u64(SYSCALL_TABLE, STEXT + 0x100);
        memory.put_u64(SYSCALL_TABLE + 8, MODULE_CORE + 0x100);
        memory.put_u64(SYSCALL_TABLE + 16, KERNEL + 0x40_000);
        let report = linux_check_syscall(
            &memory,
            &LinuxCheckSyscallOptions {
                table: LinuxSyscallTable::X64,
                entries: 3,
                include_modules: true,
            },
        );
        assert!(report.available);
        assert!(report.complete);
        assert_eq!(
            report.records[0].classification,
            LinuxSyscallClassification::KernelText
        );
        assert_eq!(
            report.records[1].classification,
            LinuxSyscallClassification::ModuleText
        );
        assert_eq!(report.records[2].suspicious, Some(true));
        assert_eq!(report.suspicious, 1);
    }

    #[test]
    fn check_syscall_clamps_to_exact_array_and_rejects_unproven_extent() {
        let mut memory = SyntheticMemory::new(
            module_document(),
            &[LinuxSymbolFeature::Modules, LinuxSymbolFeature::Hooks],
        );
        populate_module(&mut memory, true, false);
        memory.put(STEXT, &[0x90]);
        memory.put(ETEXT - 1, &[0x90]);
        for index in 0..3 {
            memory.put_u64(SYSCALL_TABLE + index * 8, STEXT);
        }
        memory.put_u64(SYSCALL_TABLE + 24, 0x1234); // adjacent non-table data must never become a finding
        let report = linux_check_syscall(&memory, &Default::default());
        assert!(report.available);
        assert_eq!(report.records.len(), 3);
        assert_eq!(report.suspicious, 0);
        let prefix = linux_check_syscall(
            &memory,
            &LinuxCheckSyscallOptions {
                entries: 2,
                ..Default::default()
            },
        );
        assert!(!prefix.complete);
        assert_eq!(prefix.records.len(), 2);
        assert_eq!(prefix.limits[0].reached, Some(true));
        let mut document = module_document();
        document["symbols"]["sys_call_table"]["type"] = Value::Null;
        let mut unknown = SyntheticMemory::new(
            document,
            &[LinuxSymbolFeature::Modules, LinuxSymbolFeature::Hooks],
        );
        populate_module(&mut unknown, true, false);
        let report = linux_check_syscall(&unknown, &Default::default());
        assert!(!report.available);
        assert!(!report.complete);
        assert!(report.records.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.code == "linux_syscall_table_extent_unavailable")
        );
    }

    #[test]
    fn kernel_session_uses_four_level_paging_without_requiring_task_ring() {
        let memory = SyntheticMemory::new(module_document(), &[LinuxSymbolFeature::Modules]);
        let mut raw = vec![0_u8; 0x104_000];
        let pml4_index = usize::try_from((STEXT >> 39) & 0x1ff).unwrap();
        raw[0x1000 + pml4_index * 8..0x1008 + pml4_index * 8]
            .copy_from_slice(&(0x2000_u64 | PRESENT).to_le_bytes());
        let pdpt_index = usize::try_from((STEXT >> 30) & 0x1ff).unwrap();
        raw[0x2000 + pdpt_index * 8..0x2008 + pdpt_index * 8]
            .copy_from_slice(&(PRESENT | LARGE_PAGE).to_le_bytes());
        let physical_stext = usize::try_from(STEXT & ((1 << 30) - 1)).unwrap();
        raw[physical_stext] = 0x90;
        let physical_banner = usize::try_from(BANNER & ((1 << 30) - 1)).unwrap();
        let runtime_banner = format!("{BANNER_TEXT}\n\0");
        raw[physical_banner..physical_banner + runtime_banner.len()]
            .copy_from_slice(runtime_banner.as_bytes());
        fs::write(&memory.source, raw).unwrap();
        let image = MemoryImage::open(&memory.source).unwrap();
        let session = LinuxKernelSession::new(image, 0x1000, 0, memory.isf.clone()).unwrap();
        assert_eq!(session.translate(STEXT).unwrap(), physical_stext as u64);
        // `init_task` is intentionally not mapped. Session construction therefore proves that
        // kernel-global plugins are not coupled to task-ring health.
        assert!(session.read_virtual(INIT_TASK, &mut [0_u8; 1]).is_err());
    }
}
