use std::fs::File;
use std::io::{Cursor, Seek, SeekFrom, Write};

use anyhow::{Context, Result, ensure};

use super::WindowsKernelContext;
use super::files::{DumpFileReport, DumpSource, RecoveredExtent, recover_file_bytes};
use super::plugins::resolve_system_handle_object;
use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;

const PAGE_SIZE: u64 = 0x1000;
const HIVE_SIGNATURE: u32 = 0xbee0_bee0;

#[derive(Debug)]
pub struct HiveMemoryImage {
    pub bytes: Vec<u8>,
    pub report: DumpFileReport,
}

struct HiveRecovery {
    logical_size: u64,
    recovered_bytes: u64,
    complete: bool,
    extents: Vec<RecoveredExtent>,
    warnings: Vec<String>,
}

struct HiveFileSource {
    kind: &'static str,
    report: DumpFileReport,
    bytes: Vec<u8>,
}

struct RecoveredFilePage<'a> {
    bytes: &'a [u8],
    memory_address: u64,
    memory_kind: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum HmapEntryLayout {
    /// Windows 8 and later store an offset relative to a permanent bin base.
    PermanentBin {
        block_offset: u64,
        permanent_bin_address: u64,
    },
    /// Windows 7 and earlier store the mapped page address directly. Its low
    /// bits contain HMAP allocation flags and are not part of the pointer.
    DirectBlock { block_address: u64 },
}

/// Reconstruct the stable on-disk portion of a loaded registry hive from its
/// CMHIVE/HHIVE map. Modern Windows maps most hive bins into the user address
/// space of the dedicated Registry process, so its DTB is accepted separately
/// from the kernel DTB used to read CMHIVE and HMAP metadata.
pub fn dump_hive(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    cmhive: u64,
    registry_process_dtb: Option<u64>,
    output: &mut File,
    max_size: u64,
) -> Result<DumpFileReport> {
    output.set_len(0)?;
    let recovery = recover_hive_to(
        image,
        kernel,
        profile,
        cmhive,
        registry_process_dtb,
        output,
        max_size,
    )?;
    output.set_len(recovery.logical_size)?;
    Ok(recovery.into_report())
}

pub fn recover_hive_bytes(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    cmhive: u64,
    registry_process_dtb: Option<u64>,
    max_size: u64,
) -> Result<HiveMemoryImage> {
    let mut output = Cursor::new(Vec::new());
    let recovery = recover_hive_to(
        image,
        kernel,
        profile,
        cmhive,
        registry_process_dtb,
        &mut output,
        max_size,
    )?;
    let logical_size = usize::try_from(recovery.logical_size)?;
    output.get_mut().resize(logical_size, 0);
    Ok(HiveMemoryImage {
        bytes: output.into_inner(),
        report: recovery.into_report(),
    })
}

fn recover_hive_to<W: Write + Seek>(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    cmhive: u64,
    registry_process_dtb: Option<u64>,
    output: &mut W,
    max_size: u64,
) -> Result<HiveRecovery> {
    ensure!(max_size >= PAGE_SIZE, "maximum hive size is below one page");
    let kernel_space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let registry_space = registry_process_dtb
        .filter(|dtb| *dtb != 0)
        .map(|dtb| X64AddressSpace::new(image, dtb))
        .transpose()?;

    let hive_offset = profile.type_field("_CMHIVE", "Hive")?.offset;
    let hhive = cmhive
        .checked_add(hive_offset)
        .context("CMHIVE Hive field address overflow")?;
    let signature_offset = profile.type_field("_HHIVE", "Signature")?.offset;
    ensure!(
        read_u32(&kernel_space, hhive + signature_offset)? == HIVE_SIGNATURE,
        "CMHIVE does not contain a valid HHIVE signature"
    );

    let base_block_offset = profile.type_field("_HHIVE", "BaseBlock")?.offset;
    let base_block = kernel_space.read_u64(hhive + base_block_offset)?;
    let mut base_page = vec![0u8; PAGE_SIZE as usize];
    let (mut base_page_kind, base_page_issue) = if base_block == 0 {
        (None, Some("HHIVE 的 BaseBlock 指针为空".to_owned()))
    } else {
        match read_mapped_page(
            &kernel_space,
            registry_space.as_ref(),
            base_block,
            &mut base_page,
        ) {
            Some(kind) if &base_page[..4] == b"regf" => (Some(kind), None),
            Some(_) => (None, Some("Hive 基础块没有 regf 签名".to_owned())),
            None => (
                None,
                Some("无法从内核或 Registry 进程地址空间读取 Hive 基础块".to_owned()),
            ),
        }
    };

    let storage_offset = profile.type_field("_HHIVE", "Storage")?.offset;
    let dual_size = profile.type_layout("_DUAL")?.size;
    ensure!(dual_size > 0, "PDB reports an empty DUAL layout");
    // Storage[0] is stable/on-disk data; Storage[1] contains volatile cells
    // and must never be appended to an exported hive file.
    let stable = hhive
        .checked_add(storage_offset)
        .context("HHIVE stable storage address overflow")?;
    let length_offset = profile.type_field("_DUAL", "Length")?.offset;
    let stable_length = u64::from(read_u32(&kernel_space, stable + length_offset)?);
    ensure!(stable_length > 0, "stable hive storage is empty");
    ensure!(
        stable_length.is_multiple_of(PAGE_SIZE),
        "stable hive length {stable_length:#x} is not page aligned"
    );
    let logical_size = stable_length
        .checked_add(PAGE_SIZE)
        .context("registry hive output size overflow")?;
    ensure!(
        logical_size <= max_size,
        "hive size {logical_size:#x} exceeds --max-file-size {max_size:#x}"
    );

    let map_offset = profile.type_field("_DUAL", "Map")?.offset;
    let map = read_mapped_u64(&kernel_space, registry_space.as_ref(), stable + map_offset)
        .context("无法读取稳定 Hive 的 HMAP_DIRECTORY 指针")?;
    let small_dir = profile
        .type_field("_DUAL", "SmallDir")
        .ok()
        .and_then(|field| {
            read_mapped_u64(
                &kernel_space,
                registry_space.as_ref(),
                stable + field.offset,
            )
        })
        .filter(|address| is_kernel_address(*address));
    ensure!(
        is_kernel_address(map) || small_dir.is_some(),
        "stable hive storage has neither a map directory nor SmallDir"
    );
    let directory_offset = profile.type_field("_HMAP_DIRECTORY", "Directory")?.offset;
    let table_offset = profile.type_field("_HMAP_TABLE", "Table")?.offset;
    let entry_size = profile.type_layout("_HMAP_ENTRY")?.size;
    let entry_layout = hmap_entry_layout(profile)?;
    ensure!(entry_size >= 16, "PDB reports an invalid HMAP_ENTRY size");

    let mut extents = Vec::new();
    let mut recovered_bytes = 0;
    if let Some(kind) = base_page_kind {
        extents.push(RecoveredExtent {
            file_offset: 0,
            length: PAGE_SIZE,
            memory_address: base_block,
            memory_kind: kind.to_owned(),
        });
        recovered_bytes += PAGE_SIZE;
    }
    let mut missing_store_offsets = Vec::new();
    let mut first_bin_valid = false;
    let mut inferred_root_cell = None;
    let mut root_inference_error = None;

    for store_offset in (0..stable_length).step_by(PAGE_SIZE as usize) {
        let directory_index = (store_offset >> 21) & 0x3ff;
        let table_index = (store_offset >> 12) & 0x1ff;
        let mut tables = Vec::with_capacity(2);
        if directory_index == 0
            && let Some(table) = small_dir
        {
            tables.push(table);
        }
        if is_kernel_address(map)
            && let Some(pointer_address) = map
                .checked_add(directory_offset)
                .and_then(|address| address.checked_add(directory_index * 8))
            && let Some(table) =
                read_mapped_u64(&kernel_space, registry_space.as_ref(), pointer_address)
            && is_kernel_address(table)
            && !tables.contains(&table)
        {
            tables.push(table);
        }
        let mut recovered_page = None;
        for table in tables {
            let Some(memory_address) = hmap_page_address(
                &kernel_space,
                table,
                table_offset,
                table_index,
                entry_size,
                entry_layout,
                registry_space.as_ref(),
            ) else {
                continue;
            };
            let mut page = vec![0u8; PAGE_SIZE as usize];
            if let Some(memory_kind) = read_mapped_page(
                &kernel_space,
                registry_space.as_ref(),
                memory_address,
                &mut page,
            ) {
                recovered_page = Some((page, memory_address, memory_kind));
                break;
            }
        }
        let Some((page, memory_address, memory_kind)) = recovered_page else {
            missing_store_offsets.push(store_offset);
            continue;
        };
        if store_offset == 0 {
            first_bin_valid = &page[..4] == b"hbin";
            if !first_bin_valid {
                missing_store_offsets.push(store_offset);
                continue;
            }
            if base_page_kind.is_none() {
                match infer_root_cell_from_first_hbin(&page, stable_length) {
                    Ok(root) => inferred_root_cell = root,
                    Err(error) => root_inference_error = Some(format!("{error:#}")),
                }
            }
        }
        let file_offset = PAGE_SIZE + store_offset;
        output.seek(SeekFrom::Start(file_offset))?;
        output.write_all(&page)?;
        recovered_bytes += PAGE_SIZE;
        push_extent(
            &mut extents,
            file_offset,
            PAGE_SIZE,
            memory_address,
            memory_kind,
        );
    }

    let mut fallback_warnings = Vec::new();
    let mut backing_pages = 0u64;
    if base_page_kind.is_none() || !missing_store_offsets.is_empty() {
        match recover_hive_file_sources(image, kernel, profile, cmhive, max_size) {
            Ok(sources) => {
                if base_page_kind.is_none() {
                    for source in &sources {
                        let Some(page) = source.page(0) else {
                            continue;
                        };
                        if let Err(error) = validate_backing_base_block(page.bytes, stable_length) {
                            fallback_warnings
                                .push(format!("拒绝 {} 的 Hive 基础块：{error:#}", source.kind));
                            continue;
                        }
                        base_page.copy_from_slice(page.bytes);
                        base_page_kind = Some(page.memory_kind);
                        extents.push(RecoveredExtent {
                            file_offset: 0,
                            length: PAGE_SIZE,
                            memory_address: page.memory_address,
                            memory_kind: page.memory_kind.to_owned(),
                        });
                        recovered_bytes += PAGE_SIZE;
                        backing_pages += 1;
                        fallback_warnings.push(format!(
                            "{}；已从 Hive backing FILE_OBJECT 恢复真实 regf 基础块",
                            base_page_issue.as_deref().unwrap_or("Hive 基础块不可用")
                        ));
                        break;
                    }
                }

                let mut still_missing = Vec::new();
                for store_offset in missing_store_offsets.drain(..) {
                    let file_offset = PAGE_SIZE + store_offset;
                    let mut recovered = None;
                    for source in &sources {
                        let Some(page) = source.page(file_offset) else {
                            continue;
                        };
                        if store_offset == 0 && &page.bytes[..4] != b"hbin" {
                            continue;
                        }
                        recovered = Some(page);
                        break;
                    }
                    let Some(page) = recovered else {
                        still_missing.push(store_offset);
                        continue;
                    };
                    if store_offset == 0 {
                        first_bin_valid = true;
                        if base_page_kind.is_none() {
                            match infer_root_cell_from_first_hbin(page.bytes, stable_length) {
                                Ok(root) => inferred_root_cell = root,
                                Err(error) => root_inference_error = Some(format!("{error:#}")),
                            }
                        }
                    }
                    output.seek(SeekFrom::Start(file_offset))?;
                    output.write_all(page.bytes)?;
                    recovered_bytes += PAGE_SIZE;
                    backing_pages += 1;
                    extents.push(RecoveredExtent {
                        file_offset,
                        length: PAGE_SIZE,
                        memory_address: page.memory_address,
                        memory_kind: page.memory_kind.to_owned(),
                    });
                }
                missing_store_offsets = still_missing;
            }
            Err(error) => {
                fallback_warnings.push(format!("Hive backing FILE_OBJECT 恢复不可用：{error:#}"))
            }
        }
    }
    if backing_pages > 0 {
        fallback_warnings.push(format!(
            "已从 Hive backing FILE_OBJECT 的 Cache/Data 节区补回 {backing_pages} 个页面；HMAP 驻留页面仍具有优先级"
        ));
    }
    let missing_pages = missing_store_offsets.len() as u64;
    let mut warnings = fallback_warnings;
    if base_page_kind.is_some() {
        let base_length = u64::from(u32::from_le_bytes(base_page[40..44].try_into()?));
        if base_length != stable_length {
            warnings.push(format!(
                "基础块长度 {base_length:#x} 与稳定存储映射长度 {stable_length:#x} 不一致"
            ));
        }
        let sequence1 = u32::from_le_bytes(base_page[4..8].try_into()?);
        let sequence2 = u32::from_le_bytes(base_page[8..12].try_into()?);
        if sequence1 != sequence2 {
            warnings.push(format!(
                "注册表配置单元处于未清理状态：基础块序列号不一致（{sequence1} != {sequence2}）"
            ));
        }
    } else {
        ensure!(
            first_bin_valid,
            "{}；并且首个稳定存储 Hive Bin 不可用，无法安全重建解析头",
            base_page_issue.as_deref().unwrap_or("Hive 基础块不可用")
        );
        let root_cell = inferred_root_cell.with_context(|| {
            format!(
                "Hive 基础块不可用，且首个稳定存储 Hive Bin 中没有唯一的根 nk 单元{}",
                root_inference_error
                    .as_deref()
                    .map(|error| format!("：{error}"))
                    .unwrap_or_default()
            )
        })?;
        base_page = synthesize_base_block(stable_length, root_cell)?;
        warnings.push(format!(
            "{}；已依据 HHIVE 稳定存储长度和首个 hbin 的根 nk 单元合成仅用于解析的 regf 头。合成页不计入恢复字节，结果保持不完整",
            base_page_issue.as_deref().unwrap_or("Hive 基础块不可用")
        ));
    }
    output.seek(SeekFrom::Start(0))?;
    output.write_all(&base_page)?;
    if !first_bin_valid {
        warnings.push("首个稳定存储 Hive Bin 缺失或没有 hbin 签名".to_owned());
    }
    if missing_pages > 0 {
        warnings.push(format!(
            "采集的地址空间中有 {missing_pages} 个稳定存储 Hive 页面不驻留"
        ));
    }
    let extents = normalize_extents(extents);

    Ok(HiveRecovery {
        logical_size,
        recovered_bytes,
        // Cache/Data backing pages may represent a different registry
        // transaction than the live HMAP pages. Preserve recovered records,
        // but never claim a page-mixed hive is complete.
        complete: recovered_bytes == logical_size && backing_pages == 0,
        extents,
        warnings,
    })
}

fn normalize_extents(mut extents: Vec<RecoveredExtent>) -> Vec<RecoveredExtent> {
    extents.sort_unstable_by_key(|extent| extent.file_offset);
    let mut normalized = Vec::with_capacity(extents.len());
    for extent in extents {
        push_extent(
            &mut normalized,
            extent.file_offset,
            extent.length,
            extent.memory_address,
            &extent.memory_kind,
        );
    }
    normalized
}

fn hmap_entry_layout(profile: &KernelProfile) -> Result<HmapEntryLayout> {
    if let (Ok(block_offset), Ok(permanent_bin_address)) = (
        profile.type_field("_HMAP_ENTRY", "BlockOffset"),
        profile.type_field("_HMAP_ENTRY", "PermanentBinAddress"),
    ) {
        return Ok(HmapEntryLayout::PermanentBin {
            block_offset: block_offset.offset,
            permanent_bin_address: permanent_bin_address.offset,
        });
    }
    if let Ok(block_address) = profile.type_field("_HMAP_ENTRY", "BlockAddress") {
        return Ok(HmapEntryLayout::DirectBlock {
            block_address: block_address.offset,
        });
    }
    anyhow::bail!(
        "PDB 中的 _HMAP_ENTRY 同时缺少现代 PermanentBinAddress 布局和旧版 BlockAddress 布局"
    )
}

fn hmap_page_address(
    kernel_space: &X64AddressSpace<'_>,
    table: u64,
    table_offset: u64,
    table_index: u64,
    entry_size: u64,
    layout: HmapEntryLayout,
    registry_space: Option<&X64AddressSpace<'_>>,
) -> Option<u64> {
    let entry = table
        .checked_add(table_offset)?
        .checked_add(table_index.checked_mul(entry_size)?)?;
    let address = match layout {
        HmapEntryLayout::PermanentBin {
            block_offset,
            permanent_bin_address,
        } => {
            let block_offset = read_mapped_u64(
                kernel_space,
                registry_space,
                entry.checked_add(block_offset)?,
            )?;
            if !block_offset.is_multiple_of(PAGE_SIZE) || block_offset >= 0x1_0000 {
                return None;
            }
            let permanent_bin = read_mapped_u64(
                kernel_space,
                registry_space,
                entry.checked_add(permanent_bin_address)?,
            )? & !0xf;
            permanent_bin.checked_add(block_offset)?
        }
        HmapEntryLayout::DirectBlock { block_address } => {
            read_mapped_u64(
                kernel_space,
                registry_space,
                entry.checked_add(block_address)?,
            )? & !0xf
        }
    };
    (address != 0).then_some(address)
}

impl HiveFileSource {
    fn page(&self, file_offset: u64) -> Option<RecoveredFilePage<'_>> {
        let page_end = file_offset.checked_add(PAGE_SIZE)?;
        let extent = self.report.extents.iter().find(|extent| {
            extent.file_offset <= file_offset
                && extent.file_offset.saturating_add(extent.length) >= page_end
        })?;
        let start = usize::try_from(file_offset).ok()?;
        let end = start.checked_add(PAGE_SIZE as usize)?;
        let bytes = self.bytes.get(start..end)?;
        let memory_address = extent
            .memory_address
            .checked_add(file_offset - extent.file_offset)?;
        Some(RecoveredFilePage {
            bytes,
            memory_address,
            memory_kind: self.kind,
        })
    }
}

fn recover_hive_file_sources(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    cmhive: u64,
    max_size: u64,
) -> Result<Vec<HiveFileSource>> {
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let file_handles = profile.type_field("_CMHIVE", "FileHandles")?.offset;
    let encoded_handle = space.read_u64(
        cmhive
            .checked_add(file_handles)
            .context("CMHIVE FileHandles 地址溢出")?,
    )?;
    ensure!(
        encoded_handle & 0xffff_ffff_8000_0000 == 0xffff_ffff_8000_0000,
        "CMHIVE primary FileHandles[0] 不是编码的 System 句柄"
    );
    let handle = (encoded_handle & 0x7fff_ffff) as u32;
    let file_object = resolve_system_handle_object(image, kernel, profile, handle)?;
    let mut sources = Vec::new();
    for (source, kind) in [
        (DumpSource::Cache, "hive_file_cache"),
        (DumpSource::Data, "hive_file_data"),
    ] {
        if let Ok((report, bytes)) =
            recover_file_bytes(image, kernel, profile, file_object, source, max_size)
            && report.recovered_bytes > 0
        {
            sources.push(HiveFileSource {
                kind,
                report,
                bytes,
            });
        }
    }
    ensure!(
        !sources.is_empty(),
        "Hive backing FILE_OBJECT 的 Cache/Data 节区均没有可恢复页面"
    );
    Ok(sources)
}

fn infer_root_cell_from_first_hbin(page: &[u8], stable_length: u64) -> Result<Option<u32>> {
    ensure!(page.len() >= PAGE_SIZE as usize, "首个 Hive Bin 页面被截断");
    ensure!(&page[..4] == b"hbin", "首个稳定存储页面没有 hbin 签名");
    let bin_offset = u32::from_le_bytes(page[4..8].try_into()?);
    ensure!(bin_offset == 0, "首个 Hive Bin 的文件偏移不是零");
    let bin_size = u64::from(u32::from_le_bytes(page[8..12].try_into()?));
    ensure!(
        bin_size >= PAGE_SIZE && bin_size.is_multiple_of(PAGE_SIZE),
        "首个 Hive Bin 的长度 {bin_size:#x} 无效"
    );
    ensure!(
        bin_size <= stable_length,
        "首个 Hive Bin 的长度 {bin_size:#x} 超过稳定存储长度 {stable_length:#x}"
    );

    let mut root_cell = None;
    let mut offset = 0x20usize;
    while offset + 8 <= page.len() {
        let raw_size = i32::from_le_bytes(page[offset..offset + 4].try_into()?);
        if raw_size == 0 {
            break;
        }
        let cell_size = raw_size.unsigned_abs() as usize;
        if cell_size < 8 || !cell_size.is_multiple_of(8) {
            break;
        }
        let Some(cell_end) = offset.checked_add(cell_size) else {
            break;
        };
        if cell_end > page.len() {
            break;
        }
        if raw_size < 0 && &page[offset + 4..offset + 6] == b"nk" {
            let flags = u16::from_le_bytes(page[offset + 6..offset + 8].try_into()?);
            if flags & 0x0004 != 0 {
                let candidate = u32::try_from(offset)?;
                ensure!(
                    root_cell.replace(candidate).is_none(),
                    "首个 Hive Bin 中存在多个带 HIVE_ENTRY 标志的根 nk 单元"
                );
            }
        }
        offset = cell_end;
    }
    Ok(root_cell)
}

fn synthesize_base_block(stable_length: u64, root_cell: u32) -> Result<Vec<u8>> {
    let stable_length = u32::try_from(stable_length).context("稳定存储长度超过 regf 格式上限")?;
    let mut base = vec![0u8; PAGE_SIZE as usize];
    base[..4].copy_from_slice(b"regf");
    base[4..8].copy_from_slice(&1u32.to_le_bytes());
    base[8..12].copy_from_slice(&1u32.to_le_bytes());
    base[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    base[0x18..0x1c].copy_from_slice(&5u32.to_le_bytes());
    base[0x1c..0x20].copy_from_slice(&0u32.to_le_bytes());
    base[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    base[0x24..0x28].copy_from_slice(&root_cell.to_le_bytes());
    base[0x28..0x2c].copy_from_slice(&stable_length.to_le_bytes());
    base[0x2c..0x30].copy_from_slice(&1u32.to_le_bytes());
    let checksum = hive_header_checksum(&base);
    base[0x1fc..0x200].copy_from_slice(&checksum.to_le_bytes());
    Ok(base)
}

fn validate_backing_base_block(base: &[u8], stable_length: u64) -> Result<()> {
    ensure!(base.len() >= PAGE_SIZE as usize, "Hive 基础块被截断");
    ensure!(&base[..4] == b"regf", "Hive 基础块没有 regf 签名");
    let sequence1 = u32::from_le_bytes(base[4..8].try_into()?);
    let sequence2 = u32::from_le_bytes(base[8..12].try_into()?);
    ensure!(
        sequence1 == sequence2,
        "Hive 基础块序列号不一致（{sequence1} != {sequence2}）"
    );
    ensure!(
        u32::from_le_bytes(base[0x14..0x18].try_into()?) == 1,
        "Hive 基础块主版本不是 1"
    );
    ensure!(
        u32::from_le_bytes(base[0x1c..0x20].try_into()?) == 0,
        "Hive 基础块文件类型不是 primary"
    );
    ensure!(
        u32::from_le_bytes(base[0x20..0x24].try_into()?) == 1,
        "Hive 基础块格式不是 direct-memory"
    );
    let root_cell = u64::from(u32::from_le_bytes(base[0x24..0x28].try_into()?));
    let length = u64::from(u32::from_le_bytes(base[0x28..0x2c].try_into()?));
    ensure!(
        length == stable_length,
        "Hive 基础块长度 {length:#x} 与 HHIVE 稳定存储长度 {stable_length:#x} 不一致"
    );
    ensure!(
        root_cell < length && root_cell.is_multiple_of(8),
        "Hive 根单元偏移 {root_cell:#x} 超出稳定存储或未按 8 字节对齐"
    );
    let stored_checksum = u32::from_le_bytes(base[0x1fc..0x200].try_into()?);
    ensure!(
        hive_header_checksum(base) == stored_checksum,
        "Hive 基础块校验和不匹配"
    );
    Ok(())
}

fn hive_header_checksum(base: &[u8]) -> u32 {
    let mut checksum = base[..0x1fc].chunks_exact(4).fold(0u32, |sum, word| {
        sum ^ u32::from_le_bytes(word.try_into().expect("fixed registry header word"))
    });
    if checksum == u32::MAX {
        checksum = u32::MAX - 1;
    } else if checksum == 0 {
        checksum = 1;
    }
    checksum
}

impl HiveRecovery {
    fn into_report(self) -> DumpFileReport {
        DumpFileReport {
            file_object: 0,
            name: None,
            source: DumpSource::HiveMemory,
            logical_size: self.logical_size,
            output_size: self.logical_size,
            recovered_bytes: self.recovered_bytes,
            missing_bytes: self.logical_size.saturating_sub(self.recovered_bytes),
            complete: self.complete,
            extents: self.extents,
            warnings: self.warnings,
        }
    }
}

fn read_mapped_page<'a>(
    kernel_space: &X64AddressSpace<'a>,
    registry_space: Option<&X64AddressSpace<'a>>,
    address: u64,
    output: &mut [u8],
) -> Option<&'static str> {
    if is_kernel_address(address) && kernel_space.read_virtual(address, output).is_ok() {
        return Some("kernel_virtual");
    }
    if let Some(space) = registry_space
        && space.read_virtual(address, output).is_ok()
    {
        return Some("registry_process_virtual");
    }
    if !is_kernel_address(address) && kernel_space.read_virtual(address, output).is_ok() {
        return Some("kernel_virtual");
    }
    None
}

fn read_mapped_u64(
    kernel_space: &X64AddressSpace<'_>,
    registry_space: Option<&X64AddressSpace<'_>>,
    address: u64,
) -> Option<u64> {
    let mut bytes = [0u8; 8];
    if is_kernel_address(address) && kernel_space.read_virtual(address, &mut bytes).is_ok() {
        return Some(u64::from_le_bytes(bytes));
    }
    if let Some(space) = registry_space
        && space.read_virtual(address, &mut bytes).is_ok()
    {
        return Some(u64::from_le_bytes(bytes));
    }
    if !is_kernel_address(address) && kernel_space.read_virtual(address, &mut bytes).is_ok() {
        return Some(u64::from_le_bytes(bytes));
    }
    None
}

fn read_u32(space: &X64AddressSpace<'_>, address: u64) -> Result<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn is_kernel_address(address: u64) -> bool {
    address >> 48 == 0xffff
}

fn push_extent(
    extents: &mut Vec<RecoveredExtent>,
    file_offset: u64,
    length: u64,
    memory_address: u64,
    memory_kind: &str,
) {
    if let Some(last) = extents.last_mut()
        && last.file_offset + last.length == file_offset
        && last.memory_address + last.length == memory_address
        && last.memory_kind == memory_kind
    {
        last.length += length;
        return;
    }
    extents.push(RecoveredExtent {
        file_offset,
        length,
        memory_address,
        memory_kind: memory_kind.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmap_indices_cover_two_level_directory() {
        let offset = 0x4567_8000u64;
        assert_eq!((offset >> 21) & 0x3ff, 0x22b);
        assert_eq!((offset >> 12) & 0x1ff, 0x78);
    }

    #[test]
    fn permanent_bin_address_clears_low_flags_before_block_offset() {
        let permanent = 0x0000_01ed_d6d2_1001u64;
        let block_offset = 0x1000u64;
        assert_eq!((permanent & !0xf) + block_offset, 0x0000_01ed_d6d2_2000);
    }

    #[test]
    fn legacy_block_address_clears_hmap_flags() {
        let block = 0xffff_f8a0_0123_4007u64;
        assert_eq!(block & !0xf, 0xffff_f8a0_0123_4000);
    }

    #[test]
    fn infers_root_cell_from_first_hbin() {
        let mut page = vec![0u8; PAGE_SIZE as usize];
        page[..4].copy_from_slice(b"hbin");
        page[8..12].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
        page[0x20..0x24].copy_from_slice(&(-0x50i32).to_le_bytes());
        page[0x24..0x26].copy_from_slice(b"nk");
        page[0x26..0x28].copy_from_slice(&0x0004u16.to_le_bytes());
        page[0x70..0x74].copy_from_slice(&(0xf90i32).to_le_bytes());
        assert_eq!(
            infer_root_cell_from_first_hbin(&page, PAGE_SIZE).unwrap(),
            Some(0x20)
        );
    }

    #[test]
    fn synthesized_base_block_has_valid_checksum_and_fields() {
        let base = synthesize_base_block(0x8000, 0x20).unwrap();
        assert_eq!(&base[..4], b"regf");
        assert_eq!(
            u32::from_le_bytes(base[0x24..0x28].try_into().unwrap()),
            0x20
        );
        assert_eq!(
            u32::from_le_bytes(base[0x28..0x2c].try_into().unwrap()),
            0x8000
        );
        assert_eq!(
            u32::from_le_bytes(base[0x1fc..0x200].try_into().unwrap()),
            hive_header_checksum(&base)
        );
        validate_backing_base_block(&base, 0x8000).unwrap();
    }

    #[test]
    fn backing_base_block_rejects_wrong_length_and_checksum() {
        let mut wrong_length = synthesize_base_block(0x8000, 0x20).unwrap();
        wrong_length[0x28..0x2c].copy_from_slice(&0x9000u32.to_le_bytes());
        assert!(validate_backing_base_block(&wrong_length, 0x8000).is_err());

        let mut wrong_checksum = synthesize_base_block(0x8000, 0x20).unwrap();
        wrong_checksum[0x1fc] ^= 1;
        assert!(validate_backing_base_block(&wrong_checksum, 0x8000).is_err());
    }
}
