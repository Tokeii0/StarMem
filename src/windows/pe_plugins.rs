use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::plugins::{list_drivers, list_vads};
use super::{ProcessRecord, WindowsKernelContext, list_processes, read_unicode_string};
use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::profile::KernelProfile;

#[derive(Debug, Serialize)]
pub struct LdrModulesReport {
    pub records: Vec<LdrModuleRecord>,
    pub processes_examined: usize,
    pub vads_examined: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct LdrModuleRecord {
    pub pid: u64,
    pub process: String,
    pub base: u64,
    pub in_load_order: bool,
    pub in_memory_order: bool,
    pub in_initialization_order: bool,
    pub mapped_path: Option<String>,
    pub loader_path: Option<String>,
    pub suspicious: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct IatReport {
    pub records: Vec<IatRecord>,
    pub processes_examined: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct IatRecord {
    pub pid: u64,
    pub process: String,
    pub image_base: u64,
    pub library: String,
    pub bound: bool,
    pub function: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub iat_address: u64,
    pub resolved_target: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub enum PeSymbolSource {
    Kernel,
    Processes,
}

#[derive(Debug, Serialize)]
pub struct PeSymbolReport {
    pub records: Vec<PeSymbolRecord>,
    pub modules_examined: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PeSymbolRecord {
    pub source: String,
    pub pid: Option<u64>,
    pub process: Option<String>,
    pub module: String,
    pub path: String,
    pub image_base: u64,
    pub ordinal: u32,
    pub name: Option<String>,
    pub address: Option<u64>,
    pub forwarder: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PeDumpReport {
    pub output: PathBuf,
    pub pid: Option<u64>,
    pub process: String,
    pub base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub output_size: u64,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
    pub sections: Vec<PeSectionRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PeSectionRecord {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
}

#[derive(Clone)]
struct LoaderModule {
    path: Option<String>,
}

#[derive(Clone, Copy)]
struct PeHeaders {
    pointer_size: u64,
    export_rva: u32,
    export_size: u32,
    import_rva: u32,
    import_size: u32,
}

struct PeLayout {
    size_of_image: u32,
    size_of_headers: u32,
    sections: Vec<PeSection>,
}

struct PeSection {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

pub fn ldr_modules(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid_filter: Option<u64>,
    limit: usize,
) -> Result<LdrModulesReport> {
    ensure!(limit > 0, "ldrmodules 结果上限必须大于零");
    let _ = kernel.x64_address_space(image)?;
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut records = Vec::new();
    let mut warnings = process_warnings(&processes);
    let mut complete = processes.complete;
    let mut processes_examined = 0usize;
    let mut vads_examined = 0usize;

    for process in processes
        .processes
        .iter()
        .filter(|process| pid_filter.is_none_or(|pid| process.pid == pid))
    {
        processes_examined += 1;
        let Some(space) = process_address_space(image, process) else {
            complete = false;
            push_warning_limited(
                &mut warnings,
                format!("PID {} 没有可读的进程页表", process.pid),
            );
            continue;
        };
        let Some(peb) = process.details.peb else {
            complete = false;
            push_warning_limited(
                &mut warnings,
                format!("PID {} 没有可恢复的 PEB", process.pid),
            );
            continue;
        };
        let loader_lists = match walk_loader_lists(&space, profile, peb, process.pid) {
            Ok(lists) => lists,
            Err(error) => {
                complete = false;
                push_warning_limited(
                    &mut warnings,
                    format!("PID {} 的加载器链表不可用：{error:#}", process.pid),
                );
                LoaderLists::default()
            }
        };
        let vads = match list_vads(image, kernel, profile, process.pid, 1_000_000) {
            Ok(vads) => vads,
            Err(error) => {
                complete = false;
                push_warning_limited(
                    &mut warnings,
                    format!("PID {} 的 VAD 遍历失败：{error:#}", process.pid),
                );
                continue;
            }
        };
        vads_examined += vads.records.len();
        if !vads.complete {
            complete = false;
        }
        for warning in vads.warnings {
            push_warning_limited(&mut warnings, format!("PID {}: {warning}", process.pid));
        }
        for vad in vads.records {
            if vad.file.is_none() {
                continue;
            }
            let mut magic = [0u8; 2];
            if space.read_virtual(vad.start, &mut magic).is_err() || magic != *b"MZ" {
                continue;
            }
            if records.len() == limit {
                complete = false;
                warnings.push(format!("ldrmodules 结果达到 {limit} 条上限"));
                break;
            }
            let load = loader_lists.load.get(&vad.start);
            let memory = loader_lists.memory.get(&vad.start);
            let initialization = loader_lists.initialization.get(&vad.start);
            let mut reasons = Vec::new();
            if load.is_none() {
                reasons.push("不在 InLoadOrderModuleList 中".to_owned());
            }
            if memory.is_none() {
                reasons.push("不在 InMemoryOrderModuleList 中".to_owned());
            }
            if initialization.is_none() {
                reasons.push("不在 InInitializationOrderModuleList 中".to_owned());
            }
            let loader_path = load
                .or(memory)
                .or(initialization)
                .and_then(|module| module.path.clone());
            // The process image is normally absent from the initialization-order
            // list. A missing init entry alone is therefore descriptive, not a
            // hidden-module finding; load/memory list absence is the strong signal.
            let suspicious = load.is_none() || memory.is_none();
            records.push(LdrModuleRecord {
                pid: process.pid,
                process: process.name.clone(),
                base: vad.start,
                in_load_order: load.is_some(),
                in_memory_order: memory.is_some(),
                in_initialization_order: initialization.is_some(),
                mapped_path: vad.file,
                loader_path,
                suspicious,
                reasons,
            });
        }
        if records.len() == limit {
            break;
        }
    }
    records.sort_unstable_by_key(|record| (record.pid, record.base));
    Ok(LdrModulesReport {
        records,
        processes_examined,
        vads_examined,
        complete,
        warnings,
    })
}

pub fn list_iat(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid_filter: Option<u64>,
    limit: usize,
) -> Result<IatReport> {
    ensure!(limit > 0, "IAT 结果上限必须大于零");
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut records = Vec::new();
    let mut warnings = process_warnings(&processes);
    let mut complete = processes.complete;
    let mut processes_examined = 0usize;
    'processes: for process in processes
        .processes
        .iter()
        .filter(|process| pid_filter.is_none_or(|pid| process.pid == pid))
    {
        processes_examined += 1;
        let Some(base) = process.details.image_base else {
            complete = false;
            push_warning_limited(
                &mut warnings,
                format!("PID {} 的 PEB 映像基址不可用", process.pid),
            );
            continue;
        };
        let Some(space) = process_address_space(image, process) else {
            complete = false;
            continue;
        };
        let headers = match read_pe_headers(&space, base) {
            Ok(headers) => headers,
            Err(error) => {
                complete = false;
                push_warning_limited(
                    &mut warnings,
                    format!("PID {} 的主映像 PE 文件头不可用：{error:#}", process.pid),
                );
                continue;
            }
        };
        if headers.import_rva == 0 || headers.import_size == 0 {
            continue;
        }
        let descriptor_limit = (u64::from(headers.import_size) / 20).clamp(1, 4096);
        for descriptor_index in 0..descriptor_limit {
            let descriptor_address = base + u64::from(headers.import_rva) + descriptor_index * 20;
            let mut descriptor = [0u8; 20];
            if space
                .read_virtual(descriptor_address, &mut descriptor)
                .is_err()
            {
                complete = false;
                push_warning_limited(
                    &mut warnings,
                    format!(
                        "PID {} 的导入描述符 {} 已换出",
                        process.pid, descriptor_index
                    ),
                );
                break;
            }
            let original_thunk = le_u32(&descriptor, 0);
            let timestamp = le_u32(&descriptor, 4);
            let name_rva = le_u32(&descriptor, 12);
            let first_thunk = le_u32(&descriptor, 16);
            if original_thunk == 0 && timestamp == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }
            if name_rva == 0 || first_thunk == 0 {
                continue;
            }
            let Some(library) = read_ascii_z(&space, base + u64::from(name_rva), 4096) else {
                complete = false;
                continue;
            };
            let name_table = if original_thunk != 0 {
                original_thunk
            } else {
                first_thunk
            };
            for thunk_index in 0..65_536u64 {
                let name_address =
                    base + u64::from(name_table) + thunk_index * headers.pointer_size;
                let iat_address =
                    base + u64::from(first_thunk) + thunk_index * headers.pointer_size;
                let Some(name_value) = read_pointer(&space, name_address, headers.pointer_size)
                else {
                    complete = false;
                    break;
                };
                if name_value == 0 {
                    break;
                }
                if records.len() == limit {
                    complete = false;
                    warnings.push(format!("IAT 结果达到 {limit} 条上限"));
                    break 'processes;
                }
                let ordinal_flag = if headers.pointer_size == 8 {
                    1u64 << 63
                } else {
                    1u64 << 31
                };
                let (function, ordinal, hint) = if name_value & ordinal_flag != 0 {
                    (None, Some((name_value & 0xffff) as u16), None)
                } else {
                    let import_by_name = base + (name_value & (ordinal_flag - 1));
                    let hint = read_u16_at(&space, import_by_name);
                    let function = read_ascii_z(&space, import_by_name + 2, 4096);
                    (function, None, hint)
                };
                records.push(IatRecord {
                    pid: process.pid,
                    process: process.name.clone(),
                    image_base: base,
                    library: library.clone(),
                    bound: timestamp != 0,
                    function,
                    ordinal,
                    hint,
                    iat_address,
                    resolved_target: read_pointer(&space, iat_address, headers.pointer_size)
                        .filter(|value| *value != 0),
                });
            }
        }
    }
    Ok(IatReport {
        records,
        processes_examined,
        complete,
        warnings,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn pe_symbols(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    source: PeSymbolSource,
    pid_filter: Option<u64>,
    module_filter: Option<&str>,
    name_filter: Option<&str>,
    limit: usize,
) -> Result<PeSymbolReport> {
    ensure!(limit > 0, "PE 符号结果上限必须大于零");
    let mut records = Vec::new();
    let mut warnings = Vec::new();
    let mut complete = true;
    let mut modules_examined = 0usize;
    match source {
        PeSymbolSource::Kernel => {
            ensure!(pid_filter.is_none(), "解析内核 PE 符号时不能使用 --pid");
            let modules = list_drivers(image, kernel, profile, 65_536)?;
            warnings.extend(modules.warnings);
            complete &= modules.complete;
            let space = kernel.x64_address_space(image)?;
            for module in modules
                .records
                .iter()
                .filter(|module| module_matches(&module.path, module_filter))
            {
                modules_examined += 1;
                let symbols = match read_pe_exports(&space, module.base) {
                    Ok(symbols) => symbols,
                    Err(error) => {
                        complete = false;
                        push_warning_limited(
                            &mut warnings,
                            format!("内核模块 {} 的导出表不可用：{error:#}", module.path),
                        );
                        continue;
                    }
                };
                for symbol in symbols
                    .into_iter()
                    .filter(|symbol| symbol_matches(symbol.name.as_deref(), name_filter))
                {
                    if records.len() == limit {
                        complete = false;
                        warnings.push(format!("PE 符号结果达到 {limit} 条上限"));
                        break;
                    }
                    records.push(PeSymbolRecord {
                        source: "kernel".to_owned(),
                        pid: None,
                        process: None,
                        module: basename(&module.path),
                        path: module.path.clone(),
                        image_base: module.base,
                        ordinal: symbol.ordinal,
                        name: symbol.name,
                        address: symbol.address,
                        forwarder: symbol.forwarder,
                    });
                }
                if records.len() == limit {
                    break;
                }
            }
        }
        PeSymbolSource::Processes => {
            let processes = list_processes(image, kernel, profile, 65_536)?;
            warnings.extend(process_warnings(&processes));
            complete &= processes.complete;
            let process_map = processes
                .processes
                .iter()
                .filter(|process| pid_filter.is_none_or(|pid| process.pid == pid))
                .map(|process| (process.pid, process))
                .collect::<HashMap<_, _>>();
            let modules = ldr_modules(image, kernel, profile, pid_filter, 1_000_000)?;
            warnings.extend(modules.warnings);
            complete &= modules.complete;
            for module in modules.records.iter().filter(|module| {
                module
                    .mapped_path
                    .as_deref()
                    .is_some_and(|path| module_matches(path, module_filter))
            }) {
                let Some(process) = process_map.get(&module.pid) else {
                    continue;
                };
                let Some(space) = process_address_space(image, process) else {
                    complete = false;
                    continue;
                };
                modules_examined += 1;
                let path = module.mapped_path.clone().unwrap_or_default();
                let symbols = match read_pe_exports(&space, module.base) {
                    Ok(symbols) => symbols,
                    Err(error) => {
                        complete = false;
                        push_warning_limited(
                            &mut warnings,
                            format!("PID {} 的模块 {} 导出表不可用：{error:#}", module.pid, path),
                        );
                        continue;
                    }
                };
                for symbol in symbols
                    .into_iter()
                    .filter(|symbol| symbol_matches(symbol.name.as_deref(), name_filter))
                {
                    if records.len() == limit {
                        complete = false;
                        warnings.push(format!("PE 符号结果达到 {limit} 条上限"));
                        break;
                    }
                    records.push(PeSymbolRecord {
                        source: "process".to_owned(),
                        pid: Some(module.pid),
                        process: Some(module.process.clone()),
                        module: basename(&path),
                        path: path.clone(),
                        image_base: module.base,
                        ordinal: symbol.ordinal,
                        name: symbol.name,
                        address: symbol.address,
                        forwarder: symbol.forwarder,
                    });
                }
                if records.len() == limit {
                    break;
                }
            }
        }
    }
    if modules_examined == 0 {
        complete = false;
        warnings.push("没有 PE 模块匹配指定的来源或模块筛选条件".to_owned());
    }
    records.sort_unstable_by_key(|record| {
        (
            record.pid.unwrap_or(0),
            record.module.to_ascii_lowercase(),
            record.ordinal,
        )
    });
    warnings.sort();
    warnings.dedup();
    Ok(PeSymbolReport {
        records,
        modules_examined,
        complete,
        warnings,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn dump_pe(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid: Option<u64>,
    kernel_module: bool,
    base: u64,
    output: &Path,
    force: bool,
    max_output_size: u64,
) -> Result<PeDumpReport> {
    ensure!(max_output_size > 0, "PE 导出大小上限必须大于零");
    ensure!(
        kernel_module ^ pid.is_some(),
        "--kernel-module 与 --pid 必须且只能选择一个"
    );
    let mut output_policy = OutputPolicy::new(force);
    for source in image.sources() {
        output_policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    output_policy.output(OutputTarget::file("pe_image", output));
    output_policy.preflight()?;

    let (space, process_name) = if kernel_module {
        (kernel.x64_address_space(image)?, "Kernel".to_owned())
    } else {
        let wanted_pid = pid.expect("validated above");
        let processes = list_processes(image, kernel, profile, 65_536)?;
        let process = processes
            .processes
            .iter()
            .find(|process| process.pid == wanted_pid)
            .with_context(|| format!("PID {wanted_pid} 不是活动进程"))?;
        (
            process_address_space(image, process)
                .with_context(|| format!("PID {wanted_pid} 没有可读的页表"))?,
            process.name.clone(),
        )
    };
    let layout = read_pe_layout(&space, base)?;
    let output_size = layout
        .sections
        .iter()
        .map(|section| u64::from(section.raw_offset) + u64::from(section.raw_size))
        .max()
        .unwrap_or(0)
        .max(u64::from(layout.size_of_headers));
    ensure!(output_size > 0, "PE 布局声明的输出文件为空");
    ensure!(
        output_size <= max_output_size,
        "PE 输出大小 {output_size:#x} 超出安全上限 {max_output_size:#x}"
    );
    let mut dump_result = None;
    output_policy.write_file_atomic(output, |file| {
        file.set_len(output_size)?;
        let header_length = u64::from(layout.size_of_headers).min(output_size);
        let (header_recovered, header_missing) =
            recover_virtual_range(&space, file, base, 0, header_length)?;
        let mut recovered_bytes = header_recovered;
        let mut missing_bytes = header_missing;
        let mut section_records = Vec::new();
        let mut warnings = Vec::new();
        let mut raw_ranges = Vec::new();
        for section in &layout.sections {
            let destination = u64::from(section.raw_offset);
            let length = u64::from(section.raw_size).min(output_size.saturating_sub(destination));
            if length == 0 {
                section_records.push(PeSectionRecord {
                    name: section.name.clone(),
                    virtual_address: section.virtual_address,
                    virtual_size: section.virtual_size,
                    raw_offset: section.raw_offset,
                    raw_size: section.raw_size,
                    recovered_bytes: 0,
                    missing_bytes: 0,
                });
                continue;
            }
            let end = destination + length;
            if raw_ranges
                .iter()
                .any(|(start, prior_end)| destination < *prior_end && end > *start)
            {
                warnings.push(format!("节区 {} 与前一个原始文件区间重叠", section.name));
            }
            raw_ranges.push((destination, end));
            let source = base + u64::from(section.virtual_address);
            let (recovered, missing) =
                recover_virtual_range(&space, file, source, destination, length)?;
            recovered_bytes += recovered;
            missing_bytes += missing;
            section_records.push(PeSectionRecord {
                name: section.name.clone(),
                virtual_address: section.virtual_address,
                virtual_size: section.virtual_size,
                raw_offset: section.raw_offset,
                raw_size: section.raw_size,
                recovered_bytes: recovered,
                missing_bytes: missing,
            });
        }
        dump_result = Some((recovered_bytes, missing_bytes, section_records, warnings));
        Ok(())
    })?;
    let (recovered_bytes, missing_bytes, section_records, mut warnings) =
        dump_result.context("PE 导出写出未生成恢复统计")?;
    if missing_bytes != 0 {
        warnings.push(format!(
            "捕获页表中有 {missing_bytes} 字节不可用，输出中保留为零值填充"
        ));
    }
    Ok(PeDumpReport {
        output: output.to_path_buf(),
        pid,
        process: process_name,
        base,
        size_of_image: layout.size_of_image,
        size_of_headers: layout.size_of_headers,
        output_size,
        recovered_bytes,
        missing_bytes,
        sections: section_records,
        complete: missing_bytes == 0 && warnings.is_empty(),
        warnings,
    })
}

#[derive(Default)]
struct LoaderLists {
    load: BTreeMap<u64, LoaderModule>,
    memory: BTreeMap<u64, LoaderModule>,
    initialization: BTreeMap<u64, LoaderModule>,
}

fn walk_loader_lists(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    peb: u64,
    pid: u64,
) -> Result<LoaderLists> {
    let ldr_offset = profile.type_field("_PEB", "Ldr")?.offset;
    let ldr = space.read_u64(peb + ldr_offset)?;
    ensure!(ldr != 0 && ldr >> 48 == 0, "PEB 的 Ldr 指针无效");
    let specs = [
        (
            "InLoadOrderModuleList",
            "InLoadOrderLinks",
            LoaderListKind::Load,
        ),
        (
            "InMemoryOrderModuleList",
            "InMemoryOrderLinks",
            LoaderListKind::Memory,
        ),
        (
            "InInitializationOrderModuleList",
            "InInitializationOrderLinks",
            LoaderListKind::Initialization,
        ),
    ];
    let dll_base = profile
        .type_field("_LDR_DATA_TABLE_ENTRY", "DllBase")?
        .offset;
    let full_name = profile
        .type_field("_LDR_DATA_TABLE_ENTRY", "FullDllName")?
        .offset;
    let mut output = LoaderLists::default();
    for (head_field, link_field, kind) in specs {
        let head_offset = profile.type_field("_PEB_LDR_DATA", head_field)?.offset;
        let link_offset = profile
            .type_field("_LDR_DATA_TABLE_ENTRY", link_field)?
            .offset;
        let head = ldr + head_offset;
        let mut link = space.read_u64(head)?;
        let mut previous = head;
        let mut visited = HashSet::new();
        for _ in 0..65_536 {
            if link == head {
                break;
            }
            ensure!(
                link >> 48 == 0,
                "PID {pid} 的加载器链接 {link:#x} 不在用户地址空间"
            );
            ensure!(
                visited.insert(link),
                "PID {pid} 的加载器链表在 {link:#x} 处形成循环"
            );
            ensure!(
                space.read_u64(link + 8)? == previous,
                "PID {pid} 的加载器链表在 {link:#x} 处反向链接不一致"
            );
            let entry = link
                .checked_sub(link_offset)
                .context("加载器链接地址早于其条目基址")?;
            let base = space.read_u64(entry + dll_base)?;
            if base != 0 && base >> 48 == 0 {
                let path = read_unicode_string(space, profile, entry + full_name, 32 * 1024)
                    .filter(|path| !path.is_empty());
                let module = LoaderModule { path };
                match kind {
                    LoaderListKind::Load => {
                        output.load.insert(base, module);
                    }
                    LoaderListKind::Memory => {
                        output.memory.insert(base, module);
                    }
                    LoaderListKind::Initialization => {
                        output.initialization.insert(base, module);
                    }
                }
            }
            previous = link;
            link = space.read_u64(link)?;
        }
    }
    Ok(output)
}

#[derive(Clone, Copy)]
enum LoaderListKind {
    Load,
    Memory,
    Initialization,
}

pub(crate) struct ExportSymbol {
    pub(crate) ordinal: u32,
    pub(crate) name: Option<String>,
    pub(crate) address: Option<u64>,
    pub(crate) forwarder: Option<String>,
}

pub(crate) fn read_pe_exports(space: &X64AddressSpace<'_>, base: u64) -> Result<Vec<ExportSymbol>> {
    let headers = read_pe_headers(space, base)?;
    if headers.export_rva == 0 || headers.export_size == 0 {
        return Ok(Vec::new());
    }
    let mut directory = [0u8; 40];
    space.read_virtual(base + u64::from(headers.export_rva), &mut directory)?;
    let ordinal_base = le_u32(&directory, 16);
    let function_count = le_u32(&directory, 20);
    let name_count = le_u32(&directory, 24);
    let functions_rva = le_u32(&directory, 28);
    let names_rva = le_u32(&directory, 32);
    let ordinals_rva = le_u32(&directory, 36);
    ensure!(function_count <= 1_000_000, "导出函数数量不合理");
    ensure!(name_count <= function_count, "导出名称数量超过函数数量");
    if function_count == 0 || functions_rva == 0 {
        return Ok(Vec::new());
    }
    let functions = read_virtual_vector(
        space,
        base + u64::from(functions_rva),
        function_count as usize * 4,
    )?;
    let mut names_by_index = HashMap::new();
    if name_count != 0 && names_rva != 0 && ordinals_rva != 0 {
        let names =
            read_virtual_vector(space, base + u64::from(names_rva), name_count as usize * 4)?;
        let ordinals = read_virtual_vector(
            space,
            base + u64::from(ordinals_rva),
            name_count as usize * 2,
        )?;
        for index in 0..name_count as usize {
            let function_index =
                u16::from_le_bytes(ordinals[index * 2..index * 2 + 2].try_into().unwrap()) as u32;
            if function_index >= function_count {
                continue;
            }
            let name_rva = le_u32(&names, index * 4);
            if let Some(name) = read_ascii_z(space, base + u64::from(name_rva), 16 * 1024) {
                names_by_index.insert(function_index, name);
            }
        }
    }
    let export_start = u64::from(headers.export_rva);
    let export_end = export_start.saturating_add(u64::from(headers.export_size));
    let mut output = Vec::new();
    for index in 0..function_count {
        let function_rva = le_u32(&functions, index as usize * 4);
        if function_rva == 0 {
            continue;
        }
        let (address, forwarder) =
            if u64::from(function_rva) >= export_start && u64::from(function_rva) < export_end {
                (
                    None,
                    read_ascii_z(space, base + u64::from(function_rva), 16 * 1024),
                )
            } else {
                (Some(base + u64::from(function_rva)), None)
            };
        output.push(ExportSymbol {
            ordinal: ordinal_base.saturating_add(index),
            name: names_by_index.remove(&index),
            address,
            forwarder,
        });
    }
    Ok(output)
}

fn read_pe_layout(space: &X64AddressSpace<'_>, base: u64) -> Result<PeLayout> {
    let mut dos = [0u8; 0x40];
    space.read_virtual(base, &mut dos)?;
    ensure!(&dos[..2] == b"MZ", "缺少 DOS 签名");
    let pe_offset = u64::from(le_u32(&dos, 0x3c));
    ensure!(pe_offset <= 0x1000, "PE 文件头偏移不合理");
    let mut file_header = [0u8; 24];
    space.read_virtual(base + pe_offset, &mut file_header)?;
    ensure!(&file_header[..4] == b"PE\0\0", "缺少 NT 签名");
    let section_count = u16::from_le_bytes(file_header[6..8].try_into().unwrap()) as usize;
    let optional_size = u16::from_le_bytes(file_header[20..22].try_into().unwrap()) as usize;
    ensure!(
        (1..=96).contains(&section_count),
        "PE 节区数量 {section_count} 不合理"
    );
    ensure!(
        (64..=0x1000).contains(&optional_size),
        "可选文件头大小 {optional_size:#x} 不合理"
    );
    let optional = read_virtual_vector(space, base + pe_offset + 24, optional_size)?;
    let magic = u16::from_le_bytes(optional[..2].try_into().unwrap());
    ensure!(
        magic == 0x10b || magic == 0x20b,
        "不支持的 PE 魔数 {magic:#x}"
    );
    ensure!(optional.len() >= 64, "可选文件头被截断");
    let size_of_image = le_u32(&optional, 56);
    let size_of_headers = le_u32(&optional, 60);
    ensure!(
        size_of_image >= 0x1000 && size_of_headers >= 0x40,
        "PE 映像或文件头大小无效"
    );
    let section_table = base + pe_offset + 24 + optional_size as u64;
    let section_bytes = read_virtual_vector(space, section_table, section_count * 40)?;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let section = &section_bytes[index * 40..index * 40 + 40];
        let name_end = section[..8].iter().position(|byte| *byte == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&section[..name_end]).into_owned();
        sections.push(PeSection {
            name,
            virtual_size: le_u32(section, 8),
            virtual_address: le_u32(section, 12),
            raw_size: le_u32(section, 16),
            raw_offset: le_u32(section, 20),
        });
    }
    Ok(PeLayout {
        size_of_image,
        size_of_headers,
        sections,
    })
}

fn recover_virtual_range(
    space: &X64AddressSpace<'_>,
    file: &mut File,
    source: u64,
    destination: u64,
    length: u64,
) -> Result<(u64, u64)> {
    let mut offset = 0u64;
    let mut recovered = 0u64;
    let mut missing = 0u64;
    while offset < length {
        let address = source + offset;
        let page_remaining = 0x1000 - (address & 0xfff);
        let count = page_remaining.min(length - offset) as usize;
        let mut bytes = vec![0u8; count];
        if space.read_virtual(address, &mut bytes).is_ok() {
            file.seek(SeekFrom::Start(destination + offset))?;
            file.write_all(&bytes)?;
            recovered += count as u64;
        } else {
            missing += count as u64;
        }
        offset += count as u64;
    }
    Ok((recovered, missing))
}

fn read_virtual_vector(
    space: &X64AddressSpace<'_>,
    address: u64,
    length: usize,
) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    space.read_virtual(address, &mut bytes)?;
    Ok(bytes)
}

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_owned()
}

fn module_matches(path: &str, filter: Option<&str>) -> bool {
    filter.is_none_or(|wanted| {
        let wanted = wanted.to_ascii_lowercase();
        let path = path.to_ascii_lowercase();
        path == wanted || basename(&path) == wanted
    })
}

fn symbol_matches(name: Option<&str>, filter: Option<&str>) -> bool {
    filter.is_none_or(|wanted| name.is_some_and(|name| name.eq_ignore_ascii_case(wanted)))
}

fn read_pe_headers(space: &X64AddressSpace<'_>, base: u64) -> Result<PeHeaders> {
    let mut dos = [0u8; 0x40];
    space.read_virtual(base, &mut dos)?;
    ensure!(&dos[..2] == b"MZ", "缺少 DOS 签名");
    let pe_offset = u64::from(le_u32(&dos, 0x3c));
    ensure!(pe_offset <= 0x1000, "PE 文件头偏移不合理");
    let mut nt = [0u8; 0x100];
    space.read_virtual(base + pe_offset, &mut nt)?;
    ensure!(&nt[..4] == b"PE\0\0", "缺少 NT 签名");
    let magic = u16::from_le_bytes(nt[24..26].try_into().unwrap());
    let (pointer_size, directory_offset) = match magic {
        0x10b => (4, 24 + 96),
        0x20b => (8, 24 + 112),
        _ => anyhow::bail!("不支持的可选文件头魔数 {magic:#x}"),
    };
    let import = directory_offset + 8;
    ensure!(import + 8 <= nt.len(), "可选文件头被截断");
    Ok(PeHeaders {
        pointer_size,
        export_rva: le_u32(&nt, directory_offset),
        export_size: le_u32(&nt, directory_offset + 4),
        import_rva: le_u32(&nt, import),
        import_size: le_u32(&nt, import + 4),
    })
}

fn process_address_space<'a>(
    image: &'a MemoryImage,
    process: &ProcessRecord,
) -> Option<X64AddressSpace<'a>> {
    process
        .details
        .user_directory_table_base
        .or(process.details.directory_table_base)
        .and_then(|dtb| X64AddressSpace::new(image, dtb).ok())
}

fn read_pointer(space: &X64AddressSpace<'_>, address: u64, size: u64) -> Option<u64> {
    match size {
        8 => space.read_u64(address).ok(),
        4 => {
            let mut bytes = [0u8; 4];
            space.read_virtual(address, &mut bytes).ok()?;
            Some(u64::from(u32::from_le_bytes(bytes)))
        }
        _ => None,
    }
}

fn read_u16_at(space: &X64AddressSpace<'_>, address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_ascii_z(space: &X64AddressSpace<'_>, address: u64, max: usize) -> Option<String> {
    let mut output = Vec::new();
    let mut current = address;
    while output.len() < max {
        let page_remaining = 0x1000usize - (current as usize & 0xfff);
        let count = 64.min(page_remaining).min(max - output.len());
        let mut bytes = vec![0u8; count];
        space.read_virtual(current, &mut bytes).ok()?;
        if let Some(end) = bytes.iter().position(|byte| *byte == 0) {
            output.extend_from_slice(&bytes[..end]);
            return (!output.is_empty() && output.iter().all(|byte| byte.is_ascii_graphic()))
                .then(|| String::from_utf8_lossy(&output).into_owned());
        }
        if !bytes.iter().all(|byte| byte.is_ascii_graphic()) {
            return None;
        }
        output.extend_from_slice(&bytes);
        current += count as u64;
    }
    None
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn process_warnings(processes: &super::ProcessListReport) -> Vec<String> {
    processes
        .warnings
        .iter()
        .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
        .collect()
}

fn push_warning_limited(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 256 {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_little_endian_u32() {
        assert_eq!(le_u32(&[1, 2, 3, 4], 0), 0x0403_0201);
    }
}
