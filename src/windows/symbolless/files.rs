//! Conservative image-only FILE_OBJECT discovery and system-cache recovery.
//! Uses disclosed ABI/prefix priors, not a target PDB or KernelProfile.
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{ProbeReport, pointer, u16_at};
use crate::address::{VirtualAddressRegion, X64AddressSpace};
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::scan::scan_exact_4_cancellable;

mod object_type;
pub mod sections;
pub use object_type::ObjectTypeEvidence;
use object_type::ObjectTypeResolver;

const FILE_PREFIX: usize = 0x68;
const VIEW_BYTES: u64 = 0x40000;
const CACHE_PREFIX_BYTES: u64 = 0x100;

#[derive(Debug, Clone, Serialize)]
pub struct FileRecord {
    pub file_object: u64,
    pub physical_address: u64,
    pub pool_header_physical: u64,
    pub pool_allocation_size: u64,
    pub name: String,
    pub device_object: u64,
    pub section_object_pointer: u64,
    pub data_section_object: Option<u64>,
    pub shared_cache_map: Option<u64>,
    pub image_section_object: Option<u64>,
    pub object_manager_type_verified: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct FileScanReport {
    pub complete: bool,
    pub external_debug_symbols_used: bool,
    pub layout_priors: Vec<&'static str>,
    pub object_type_evidence: Option<ObjectTypeEvidence>,
    pub name_filter: Option<String>,
    pub pool_tag_hits: usize,
    pub pool_scan_truncated: bool,
    pub physical_candidates: usize,
    pub candidate_limit_reached: bool,
    pub reverse_mapped_pages: usize,
    pub reverse_unmapped_pages: usize,
    pub reverse_read_failures: u64,
    pub reverse_limits_reached: bool,
    pub output_limit_reached: bool,
    pub rejected_virtual_candidates: usize,
    pub records: Vec<FileRecord>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheView {
    pub vacb: u64,
    pub file_offset: u64,
    pub virtual_base: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Extent {
    pub file_offset: u64,
    pub length: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub vacb: u64,
}

#[derive(Debug, Serialize)]
pub struct MissingExtent {
    pub file_offset: u64,
    pub length: u64,
}

#[derive(Debug, Serialize)]
pub struct CacheRecoveryPlan {
    pub file_object: u64,
    pub file_object_physical: u64,
    pub name: String,
    pub source: &'static str,
    pub shared_cache_map: u64,
    pub cache_file_object: u64,
    pub cache_file_object_offset: u64,
    pub logical_size: u64,
    pub fcb_size_matches: Option<bool>,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub views: Vec<CacheView>,
    pub extents: Vec<Extent>,
    pub missing_ranges: Vec<MissingExtent>,
    pub warnings: Vec<String>,
}

fn qword(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("bounded prefix"),
    )
}

fn valid_file_prefix(bytes: &[u8]) -> bool {
    let size = u16_at(bytes, 2) as usize;
    u16_at(bytes, 0) == 5
        && (FILE_PREFIX..=0x400).contains(&size)
        && pointer(qword(bytes, 8))
        && (qword(bytes, 0x28) == 0 || pointer(qword(bytes, 0x28)))
}

fn name_from_prefix(space: &X64AddressSpace<'_>, bytes: &[u8]) -> Result<String> {
    let length = u16_at(bytes, 0x58) as usize;
    let maximum = u16_at(bytes, 0x5a) as usize;
    let buffer = qword(bytes, 0x60);
    ensure!(
        length > 0 && length <= 32768 && length.is_multiple_of(2) && maximum >= length,
        "文件名长度无效"
    );
    // UTF-16 buffers require two-byte alignment, not pointer-sized alignment.
    ensure!(
        (0xffff_8000_0000_0000..=u64::MAX - 32768).contains(&buffer) && buffer.is_multiple_of(2),
        "文件名缓冲地址无效"
    );
    let mut text = vec![0; length];
    space.read_virtual(buffer, &mut text)?;
    let units: Vec<u16> = text
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let name = String::from_utf16(&units)?;
    ensure!(
        crate::windows::files::validate_file_object_name(&name),
        "文件名含无效字符"
    );
    Ok(name)
}

fn validate_file(space: &X64AddressSpace<'_>, address: u64) -> Result<([u8; FILE_PREFIX], String)> {
    ensure!(pointer(address), "FILE_OBJECT 地址无效");
    let mut bytes = [0; FILE_PREFIX];
    space.read_virtual(address, &mut bytes)?;
    ensure!(valid_file_prefix(&bytes), "FILE_OBJECT 前缀校验失败");
    let mut device = [0; 4];
    space.read_virtual(qword(&bytes, 8), &mut device)?;
    ensure!(
        u16_at(&device, 0) == 3 && u16_at(&device, 2) >= 0x80,
        "DeviceObject 类型/大小校验失败"
    );
    let name = name_from_prefix(space, &bytes)?;
    Ok((bytes, name))
}

/// Re-open an explicitly selected object. Direct recovery requires positive
/// object-manager type evidence, not merely a plausible name or a pool tag.
pub fn inspect_file(image: &MemoryImage, kernel: &ProbeReport, address: u64) -> Result<FileRecord> {
    let space = X64AddressSpace::new(image, kernel.kernel_dtb)?;
    let (bytes, name) = validate_file(&space, address)?;
    ensure!(
        ObjectTypeResolver::load(image, kernel)?.is_file(&space, address)?,
        "所选地址未通过 File 对象管理器类型校验"
    );
    let physical = space.translate(address)?;
    let mut allocation = None;
    for pool in (physical & !4095..physical).step_by(16) {
        let mut header = [0; 16];
        if image.read_physical(pool, &mut header).is_err() {
            continue;
        }
        let size = u64::from(header[2]) * 16;
        if (&header[4..8] == b"File" || header[4..8] == [b'F', b'i', b'l', 0xe5])
            && pool + 16 <= physical
            && physical + u64::from(u16_at(&bytes, 2)) <= pool + size
            && (pool & 4095) + size <= 4096
        {
            ensure!(allocation.is_none(), "所选文件对象池归属存在歧义");
            allocation = Some((pool, size));
        }
    }
    let (pool_header_physical, pool_allocation_size) =
        allocation.context("所选对象未找到有效的小池分配归属")?;
    let section = qword(&bytes, 0x28);
    let mut warnings = Vec::new();
    let mut read_section = |offset| {
        if section == 0 {
            return Some(0);
        }
        match space.read_u64(section + offset) {
            Ok(raw) if raw == 0 || pointer(raw & !15) => Some(raw & !15),
            _ => {
                warnings.push(format!("节对象字段 +{offset:#x} 不可验证"));
                None
            }
        }
    };
    let data_section_object = read_section(0);
    let shared_cache_map = read_section(8);
    let image_section_object = read_section(16);
    Ok(FileRecord {
        file_object: address,
        physical_address: physical,
        pool_header_physical,
        pool_allocation_size,
        name,
        device_object: qword(&bytes, 8),
        section_object_pointer: section,
        data_section_object,
        shared_cache_map,
        image_section_object,
        object_manager_type_verified: true,
        warnings,
    })
}

pub fn scan(
    image: &MemoryImage,
    kernel: &ProbeReport,
    limit: usize,
    name_filter: Option<&str>,
    cancel: &CancellationToken,
) -> Result<FileScanReport> {
    ensure!(
        (1..=100_000).contains(&limit),
        "文件结果上限必须为 1..100000"
    );
    cancel.check_cancelled()?;
    let space = X64AddressSpace::new(image, kernel.kernel_dtb)?;
    let (type_decoder, type_warning) = match ObjectTypeResolver::load(image, kernel) {
        Ok(decoder) => (Some(decoder), None),
        Err(error) => (None, Some(format!("对象管理器类型验证不可用：{error:#}"))),
    };
    let hits = scan_exact_4_cancellable(
        image,
        &[*b"File", [b'F', b'i', b'l', 0xe5]],
        1_000_000,
        32 * 1024 * 1024,
        cancel,
    )?;
    let filter = name_filter.map(str::to_lowercase);
    let mut candidates = Vec::new();
    let mut candidate_limit_reached = false;
    for hit in &hits.hits {
        cancel.check_cancelled()?;
        let tag = hit.physical_address;
        if tag & 15 != 4 {
            continue;
        }
        let pool = tag - 4;
        let mut header = [0; 16];
        if image.read_physical(pool, &mut header).is_err() {
            continue;
        }
        let allocation = u64::from(header[2]) * 16;
        // This prototype scans small allocations wholly contained in one page.
        if allocation < 16 + FILE_PREFIX as u64 || (pool & 4095) + allocation > 4096 {
            continue;
        }
        for physical in (pool + 16..=pool + allocation - FILE_PREFIX as u64).step_by(16) {
            let mut bytes = [0; FILE_PREFIX];
            if image.read_physical(physical, &mut bytes).is_err()
                || !valid_file_prefix(&bytes)
                || physical + u64::from(u16_at(&bytes, 2)) > pool + allocation
            {
                continue;
            }
            let Ok(name) = name_from_prefix(&space, &bytes) else {
                continue;
            };
            if filter
                .as_ref()
                .is_some_and(|f| !name.to_lowercase().contains(f))
            {
                continue;
            }
            if candidates.len() == 200_000 {
                candidate_limit_reached = true;
                break;
            }
            candidates.push((physical, pool, allocation));
        }
        if candidate_limit_reached {
            break;
        }
    }
    let pages: HashSet<u64> = candidates.iter().map(|c| c.0 & !4095).collect();
    cancel.check_cancelled()?;
    let reverse = space.reverse_translate_pages_cancellable(
        &pages,
        VirtualAddressRegion::Kernel,
        8,
        8 * 1024 * 1024,
        1_000_000,
        cancel,
    )?;
    cancel.check_cancelled()?;
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    let mut rejected = 0;
    let mut capped = false;
    for &(physical, pool, allocation) in &candidates {
        for &page in reverse
            .mappings
            .get(&(physical & !4095))
            .into_iter()
            .flatten()
        {
            cancel.check_cancelled()?;
            let address = page + (physical & 4095);
            if !seen.insert((physical, address)) {
                continue;
            }
            let (bytes, name) = match validate_file(&space, address) {
                Ok(value) => value,
                Err(_) => {
                    rejected += 1;
                    continue;
                }
            };
            let type_verified = match type_decoder
                .as_ref()
                .map(|decoder| decoder.is_file(&space, address))
            {
                Some(Ok(true)) => true,
                Some(Ok(false)) => {
                    rejected += 1;
                    continue;
                }
                _ => false,
            };
            if !type_verified && !crate::windows::files::validate_unverified_file_object_name(&name)
            {
                rejected += 1;
                continue;
            }
            if records.len() == limit {
                capped = true;
                break;
            }
            let section = qword(&bytes, 0x28);
            let mut warnings = Vec::new();
            let mut section_field = |offset| {
                if section == 0 {
                    return Some(0);
                }
                match space.read_u64(section + offset) {
                    Ok(raw) if raw == 0 || pointer(raw & !15) => Some(raw & !15),
                    _ => {
                        warnings.push(format!("节对象字段 +{offset:#x} 不可验证"));
                        None
                    }
                }
            };
            let data = section_field(0);
            let cache = section_field(8);
            let mapped_image = section_field(16);
            records.push(FileRecord {
                file_object: address,
                physical_address: physical,
                pool_header_physical: pool,
                pool_allocation_size: allocation,
                name,
                device_object: qword(&bytes, 8),
                section_object_pointer: section,
                data_section_object: data,
                shared_cache_map: cache,
                image_section_object: mapped_image,
                object_manager_type_verified: type_verified,
                warnings,
            });
        }
        if capped {
            break;
        }
    }
    records.sort_by_key(|r| r.file_object);
    Ok(FileScanReport {
        complete: false, external_debug_symbols_used: false,
        layout_priors: vec![
            "AMD64 FILE_OBJECT: Type=0, Size=2, DeviceObject=8, FsContext=0x18, SectionObjectPointer=0x28, FileName=0x58；公开 ABI 前缀，非版本偏移查询",
            "16 字节小池分配、File/Fil(e|0x80) 标签；IoTypeFile=5、IoTypeDevice=3；对象管理器类型规则来自目标 ObGetObjectType/IoFileObjectType 导出",
            "SECTION_OBJECT_POINTERS: data/cache/image = 0/8/16；UNICODE_STRING = Length/MaximumLength/Buffer at 0/2/8",
        ],
        object_type_evidence: type_decoder.map(|decoder| decoder.evidence),
        name_filter: name_filter.map(str::to_owned), pool_tag_hits: hits.hits.len(),
        pool_scan_truncated: hits.truncated, physical_candidates: candidates.len(),
        candidate_limit_reached, reverse_mapped_pages: reverse.mapped_target_pages,
        reverse_unmapped_pages: pages.len().saturating_sub(reverse.mapped_target_pages),
        reverse_read_failures: reverse.page_table_read_failures,
        reverse_limits_reached: reverse.traversal_limit_reached || reverse.mapping_limit_exceeded || reverse.alias_storage_limit_exceeded,
        output_limit_reached: capped, rejected_virtual_candidates: rejected, records,
        warnings: vec![
            "保守扫描：要求可读名称、有效 DeviceObject 和内核反向映射；排除匿名/缺页/大池/已复用候选，不能声称枚举所有文件".into(),
            type_warning.unwrap_or_else(|| "对象管理器类型校验规则来自完整目标叶函数；单条对象是否通过见 object_manager_type_verified".into()),
            format!("镜像缺失物理区间记录数：{}；逆向页表遍历使用有界工作量，仅在调用前后检查取消", image.missing_ranges().len()),
        ],
    })
}

fn vacb_view(
    space: &X64AddressSpace<'_>,
    address: u64,
    owner: u64,
    size: u64,
) -> Option<CacheView> {
    if !pointer(address) {
        return None;
    }
    let mut bytes = [0; 24];
    space.read_virtual(address, &mut bytes).ok()?;
    let base = qword(&bytes, 0);
    // Low 16 bits of the FileOffset union hold the view's active count.
    let offset = qword(&bytes, 16) & !0xffff;
    (qword(&bytes, 8) == owner
        && pointer(base)
        && base & 4095 == 0
        && offset < size
        && offset.is_multiple_of(VIEW_BYTES))
    .then_some(CacheView {
        vacb: address,
        file_offset: offset,
        virtual_base: base,
    })
}

fn insert_view(views: &mut BTreeMap<u64, CacheView>, view: CacheView) -> Result<()> {
    if let Some(previous) = views.get(&view.file_offset) {
        ensure!(
            previous.virtual_base == view.virtual_base,
            "同一文件偏移存在不同 VACB 映射，拒绝选择歧义内容"
        );
    } else {
        views.insert(view.file_offset, view);
    }
    Ok(())
}

/// Build a bounded, independently verified cache plan. No data/image-section fallback.
pub fn plan_cache(
    image: &MemoryImage,
    kernel: &ProbeReport,
    record: &FileRecord,
    max_bytes: u64,
    cancel: &CancellationToken,
) -> Result<CacheRecoveryPlan> {
    ensure!(
        (1..=64 * 1024 * 1024).contains(&max_bytes),
        "单文件上限必须为 1..64 MiB"
    );
    cancel.check_cancelled()?;
    let space = X64AddressSpace::new(image, kernel.kernel_dtb)?;
    ensure!(
        space.translate(record.file_object)? == record.physical_address,
        "文件对象物理归属改变"
    );
    let (bytes, name) = validate_file(&space, record.file_object)?;
    if record.object_manager_type_verified {
        ensure!(
            ObjectTypeResolver::load(image, kernel)?.is_file(&space, record.file_object)?,
            "导出前对象类型校验失败"
        );
    }
    let section = qword(&bytes, 0x28);
    ensure!(
        name == record.name && section == record.section_object_pointer && pointer(section),
        "文件名称或节对象归属改变/不可用"
    );
    let cache = space.read_u64(section + 8)? & !15;
    ensure!(
        pointer(cache) && record.shared_cache_map == Some(cache),
        "文件缓存归属改变/不存在"
    );
    let size = space.read_u64(cache + 8)?;
    ensure!(
        size > 0 && size <= max_bytes,
        "缓存文件大小 {size} 为空或超过上限 {max_bytes}"
    );

    // Infer the cache's owner field by a round trip to the same section object.
    // Multiple open FILE_OBJECTs may share it; their names alone are not identity.
    let mut owners = Vec::new();
    for offset in (0x10..CACHE_PREFIX_BYTES).step_by(8) {
        cancel.check_cancelled()?;
        let Ok(owner) = space.read_u64(cache + offset).map(|p| p & !15) else {
            continue;
        };
        if let Ok((owner_bytes, _)) = validate_file(&space, owner)
            && qword(&owner_bytes, 0x28) == section
        {
            owners.push((offset, owner));
        }
    }
    ensure!(
        owners.len() == 1,
        "缓存 FileObject 反向归属候选为 {}，拒绝缺失或歧义",
        owners.len()
    );
    let (owner_offset, owner) = owners[0];
    let fs_context = qword(&bytes, 0x18);
    let fcb_size_matches = if pointer(fs_context) {
        let mut fcb = [0; 0x30];
        if space.read_virtual(fs_context, &mut fcb).is_ok() && u16_at(&fcb, 2) >= 0x30 {
            Some(qword(&fcb, 0x20) == size)
        } else {
            None
        }
    } else {
        None
    };
    ensure!(
        fcb_size_matches != Some(false),
        "FCB 和缓存的文件大小不一致，拒绝导出"
    );

    let mut views = BTreeMap::new();
    let mut arrays = HashSet::new();
    // Search the bounded prefix for inline VACBs and a single-level VACB array.
    // Do not interpret every pointer as a recursive tree of arbitrary depth.
    for offset in (0x10..CACHE_PREFIX_BYTES).step_by(8) {
        cancel.check_cancelled()?;
        let Ok(candidate) = space.read_u64(cache + offset).map(|p| p & !7) else {
            continue;
        };
        if !pointer(candidate) || offset == owner_offset {
            continue;
        }
        if let Some(view) = vacb_view(&space, candidate, cache, size) {
            insert_view(&mut views, view)?;
        } else if arrays.insert(candidate) {
            // An inline array must stop at the prefix boundary.
            let slots = if (cache..cache + CACHE_PREFIX_BYTES).contains(&candidate) {
                (cache + CACHE_PREFIX_BYTES - candidate) / 8
            } else {
                128
            };
            for index in 0..slots {
                let Ok(child) = space.read_u64(candidate + index * 8).map(|p| p & !7) else {
                    continue;
                };
                if let Some(view) = vacb_view(&space, child, cache, size) {
                    insert_view(&mut views, view)?;
                }
            }
        }
    }
    ensure!(!views.is_empty(), "有缓存对象但未发现经过归属验证的 VACB");
    let mut extents = Vec::<Extent>::new();
    let mut recovered = 0;
    let mut page_bytes = [0; 4096];
    for view in views.values() {
        for relative in (0..VIEW_BYTES.min(size - view.file_offset)).step_by(4096) {
            cancel.check_cancelled()?;
            let file_offset = view.file_offset + relative;
            let length = (size - file_offset).min(4096);
            let Some(virtual_address) = view.virtual_base.checked_add(relative) else {
                continue;
            };
            let Ok(physical) = space.translate(virtual_address) else {
                continue;
            };
            if image
                .read_physical(physical, &mut page_bytes[..length as usize])
                .is_err()
            {
                continue;
            }
            if let Some(last) = extents.last_mut().filter(|last| {
                last.file_offset + last.length == file_offset
                    && last.physical_address + last.length == physical
                    && last.virtual_address + last.length == virtual_address
                    && last.vacb == view.vacb
            }) {
                last.length += length;
            } else {
                extents.push(Extent {
                    file_offset,
                    length,
                    virtual_address,
                    physical_address: physical,
                    vacb: view.vacb,
                });
            }
            recovered += length;
        }
    }
    ensure!(recovered > 0, "已验证 VACB 中没有可读取的驻留文件字节");
    let mut missing = Vec::new();
    let mut end = 0;
    for extent in &extents {
        if extent.file_offset > end {
            missing.push(MissingExtent {
                file_offset: end,
                length: extent.file_offset - end,
            });
        }
        end = extent.file_offset + extent.length;
    }
    if end < size {
        missing.push(MissingExtent {
            file_offset: end,
            length: size - end,
        });
    }
    let mut warnings = vec![
        "仅恢复 SharedCacheMap 的驻留缓存内容；缓存可能含未落盘修改，不证明与原磁盘文件相同".into(),
        "布局先验：SharedCacheMap.FileSize +8；VACB Base/Owner/Overlay +0/+8/+16；256 KiB 视图，FileOffset 清除低 16 位活动计数；仅检查前 256 字节及一层 128 槽数组".into(),
        "不解析 DataSectionObject/ImageSectionObject，不恢复分页文件或压缩页；缺失范围在产物中是占位零，不能当作原始字节".into(),
    ];
    if fcb_size_matches.is_none() {
        warnings.push("无法用公开 FCB 前缀独立复核文件大小".into());
    }
    Ok(CacheRecoveryPlan {
        file_object: record.file_object,
        file_object_physical: record.physical_address,
        name,
        source: "shared_cache_map",
        shared_cache_map: cache,
        cache_file_object: owner,
        cache_file_object_offset: owner_offset,
        logical_size: size,
        fcb_size_matches,
        recovered_bytes: recovered,
        missing_bytes: size - recovered,
        complete: recovered == size,
        views: views.into_values().collect(),
        extents,
        missing_ranges: missing,
        warnings,
    })
}

/// Stream validated ranges to an output owned by the caller's OutputPolicy.
/// Hash returned here covers only recovered bytes in file-offset order.
pub fn write_cache(
    image: &MemoryImage,
    plan: &CacheRecoveryPlan,
    output: &mut File,
    cancel: &CancellationToken,
) -> Result<String> {
    let ranges: Vec<_> = plan
        .extents
        .iter()
        .map(|e| (e.file_offset, e.length, e.physical_address))
        .collect();
    write_ranges(image, plan.logical_size, &ranges, output, cancel)
}

pub(super) fn write_ranges(
    image: &MemoryImage,
    logical_size: u64,
    ranges: &[(u64, u64, u64)],
    output: &mut File,
    cancel: &CancellationToken,
) -> Result<String> {
    let mut bytes = [0; 64 * 1024];
    let mut hash = Sha256::new();
    for &(file_offset, length, physical_address) in ranges {
        output.seek(SeekFrom::Start(file_offset))?;
        let mut copied = 0;
        while copied < length {
            cancel.check_cancelled()?;
            let count = (length - copied).min(bytes.len() as u64) as usize;
            image
                .read_physical(physical_address + copied, &mut bytes[..count])
                .context("写入时原恢复区间已不可读取，取消发布")?;
            output.write_all(&bytes[..count])?;
            hash.update(&bytes[..count]);
            copied += count as u64;
        }
    }
    output.set_len(logical_size)?;
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
pub(super) mod tests;
