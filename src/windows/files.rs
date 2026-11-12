use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Cursor, Error, ErrorKind, Seek, SeekFrom, Write};
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::WindowsKernelContext;
use crate::address::WindowsAddressSpace;
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::scan::scan_exact_4_cancellable;

mod mapping;
pub use mapping::{FileMemoryMap, map_file_memory};
mod pfn;
pub use pfn::{PhysicalFileRecord, PhysicalFileReport, locate_physical_file};

const DEFAULT_CHUNK_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct FileScanRecord {
    pub file_object: u64,
    pub physical_address: u64,
    pub object_header: u64,
    pub pool_header_physical: u64,
    pub pool_allocation_size: u64,
    pub name: Option<String>,
    pub device_object: u64,
    pub section_object_pointer: u64,
    pub data_section_object: u64,
    pub shared_cache_map: u64,
    pub image_section_object: u64,
    pub flags: u32,
    pub delete_pending: bool,
    pub object_type_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct FileScanReport {
    pub records: Vec<FileScanRecord>,
    pub complete: bool,
    pub pool_tag_hits: usize,
    pub physical_candidates: usize,
    pub reverse_mapped_candidates: usize,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub timing: FileScanTiming,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct FileScanTiming {
    pub setup_seconds: f64,
    pub pool_scan_seconds: f64,
    pub candidate_filter_seconds: f64,
    pub reverse_map_seconds: f64,
    pub record_validation_seconds: f64,
    pub total_seconds: f64,
}

pub fn write_file_scan_csv<W: Write>(report: &FileScanReport, mut output: W) -> Result<()> {
    // UTF-8 BOM keeps Chinese paths readable when the CSV is opened directly
    // in localized versions of Microsoft Excel.
    output.write_all(b"\xef\xbb\xbf")?;
    let mut writer = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_writer(output);
    writer.write_record([
        "file_object",
        "physical_address",
        "object_header",
        "pool_header_physical",
        "pool_allocation_size",
        "name",
        "device_object",
        "section_object_pointer",
        "data_section_object",
        "shared_cache_map",
        "image_section_object",
        "cache_available",
        "data_available",
        "image_available",
        "flags",
        "delete_pending",
        "object_type_verified",
    ])?;
    for record in &report.records {
        writer.write_record([
            format!("{:#018x}", record.file_object),
            format!("{:#018x}", record.physical_address),
            format!("{:#018x}", record.object_header),
            format!("{:#018x}", record.pool_header_physical),
            record.pool_allocation_size.to_string(),
            record.name.clone().unwrap_or_default(),
            format!("{:#018x}", record.device_object),
            format!("{:#018x}", record.section_object_pointer),
            format!("{:#018x}", record.data_section_object),
            format!("{:#018x}", record.shared_cache_map),
            format!("{:#018x}", record.image_section_object),
            (record.shared_cache_map != 0).to_string(),
            (record.data_section_object != 0).to_string(),
            (record.image_section_object != 0).to_string(),
            format!("{:#010x}", record.flags),
            record.delete_pending.to_string(),
            record.object_type_verified.to_string(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DumpSource {
    Auto,
    Cache,
    Data,
    Image,
    HiveMemory,
}

#[derive(Debug, Serialize)]
pub struct RecoveredExtent {
    pub file_offset: u64,
    pub length: u64,
    pub memory_address: u64,
    pub memory_kind: String,
}

#[derive(Debug, Serialize)]
pub struct DumpFileReport {
    pub file_object: u64,
    pub name: Option<String>,
    pub source: DumpSource,
    pub logical_size: u64,
    pub output_size: u64,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub extents: Vec<RecoveredExtent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub compressed_pages: Vec<super::compressed_store::CompressedPageEvidence>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct PhysicalFileCandidate {
    file_object: u64,
    pool_header: u64,
    pool_size: u64,
    prefetched_name: Option<String>,
}

struct PhysicalSignatureLayout {
    pointer_size: u64,
    expected_size: u64,
    type_offset: u64,
    size_offset: u64,
    device_offset: u64,
    section_offset: u64,
    name_offset: u64,
}

struct ObjectTypeDecoder {
    cookie: Option<u8>,
    type_table: Option<u64>,
    type_location: ObjectTypeLocation,
    body_offset: u64,
    type_name_offset: u64,
}

enum ObjectTypeLocation {
    Index(u64),
    Pointer(u64),
}

pub fn scan_files(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<FileScanReport> {
    scan_files_cancellable(image, kernel, profile, limit, &CancellationToken::new())
}

pub fn scan_files_cancellable(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
    cancellation: &CancellationToken,
) -> Result<FileScanReport> {
    scan_files_impl(image, kernel, profile, limit, None, None, cancellation)
}

pub fn scan_files_matching(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
    name_filter: &dyn Fn(&str) -> bool,
) -> Result<FileScanReport> {
    scan_files_matching_cancellable(
        image,
        kernel,
        profile,
        limit,
        name_filter,
        &CancellationToken::new(),
    )
}

/// Apply the path predicate before the result cap and kernel reverse mapping,
/// while keeping cancellation attached to the caller's task.
pub fn scan_files_matching_cancellable(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
    name_filter: &dyn Fn(&str) -> bool,
    cancellation: &CancellationToken,
) -> Result<FileScanReport> {
    scan_files_impl(
        image,
        kernel,
        profile,
        limit,
        Some(name_filter),
        None,
        cancellation,
    )
}

pub fn scan_files_matching_from_pool_hits(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
    name_filter: &dyn Fn(&str) -> bool,
    pool_tag_hits: &[u64],
    pool_scan_truncated: bool,
) -> Result<FileScanReport> {
    scan_files_impl(
        image,
        kernel,
        profile,
        limit,
        Some(name_filter),
        Some((pool_tag_hits, pool_scan_truncated)),
        &CancellationToken::new(),
    )
}

fn scan_files_impl(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
    name_filter: Option<&dyn Fn(&str) -> bool>,
    precomputed_pool_hits: Option<(&[u64], bool)>,
    cancellation: &CancellationToken,
) -> Result<FileScanReport> {
    let total_started = Instant::now();
    cancellation.check_cancelled()?;
    ensure!(limit > 0, "文件结果数量上限必须大于零");
    let space = kernel.address_space(image)?;
    let pool_granularity = space.pointer_size() * 2;
    let pool_header_size = pool_granularity;
    let file_layout = profile.type_layout("_FILE_OBJECT")?;
    let file_size = file_layout.size;
    let file_type_offset = profile.type_field("_FILE_OBJECT", "Type")?.offset;
    let file_size_offset = profile.type_field("_FILE_OBJECT", "Size")?.offset;
    let device_offset = profile.type_field("_FILE_OBJECT", "DeviceObject")?.offset;
    let section_offset = profile
        .type_field("_FILE_OBJECT", "SectionObjectPointer")?
        .offset;
    let name_offset = profile.type_field("_FILE_OBJECT", "FileName")?.offset;
    let flags_offset = profile.type_field("_FILE_OBJECT", "Flags")?.offset;
    let delete_pending_offset = profile.type_field("_FILE_OBJECT", "DeletePending")?.offset;
    let data_section_offset = profile
        .type_field("_SECTION_OBJECT_POINTERS", "DataSectionObject")?
        .offset;
    let shared_cache_offset = profile
        .type_field("_SECTION_OBJECT_POINTERS", "SharedCacheMap")?
        .offset;
    let image_section_offset = profile
        .type_field("_SECTION_OBJECT_POINTERS", "ImageSectionObject")?
        .offset;
    let object_decoder = ObjectTypeDecoder::new(&space, kernel, profile)?;
    let signature_layout = PhysicalSignatureLayout {
        pointer_size: space.pointer_size(),
        expected_size: file_size,
        type_offset: file_type_offset,
        size_offset: file_size_offset,
        device_offset,
        section_offset,
        name_offset,
    };
    let setup_seconds = total_started.elapsed().as_secs_f64();

    // Older Windows sets the protected-pool bit in the high bit of the final
    // tag byte, making the on-wire tag `Fil\xe5`. Scan both forms in one pass.
    const FILE_TAGS: [[u8; 4]; 2] = [*b"File", [b'F', b'i', b'l', b'e' | 0x80]];
    let (pool_hits, pool_scan_truncated, pool_scan_seconds, pool_scan_gib_per_second) =
        if let Some((hits, truncated)) = precomputed_pool_hits {
            (hits.to_vec(), truncated, 0.0, 0.0)
        } else {
            let scan = scan_exact_4_cancellable(
                image,
                &FILE_TAGS,
                1_000_000,
                DEFAULT_CHUNK_SIZE,
                cancellation,
            )?;
            (
                scan.hits
                    .into_iter()
                    .map(|hit| hit.physical_address)
                    .collect(),
                scan.truncated,
                scan.elapsed_seconds,
                scan.gib_per_second,
            )
        };
    let pool_tag_hits = pool_hits.len();
    let candidate_filter_started = Instant::now();
    let mut physical_candidates = Vec::new();
    for hit in pool_hits {
        cancellation.check_cancelled()?;
        if hit & (pool_granularity - 1) != 4 {
            continue;
        }
        let Some(pool_header) = hit.checked_sub(4) else {
            continue;
        };
        let mut header = [0u8; 16];
        if image
            .read_physical(pool_header, &mut header[..pool_header_size as usize])
            .is_err()
            || &header[4..7] != b"Fil"
            || header[7] & 0x7f != b'e'
        {
            continue;
        }
        let pool_size = u64::from(header[2]) * pool_granularity;
        let aligned_file_size = file_size.next_multiple_of(pool_granularity);
        if pool_size < pool_header_size + object_decoder.body_offset + aligned_file_size {
            continue;
        }
        let Some(first_body) = pool_header
            .checked_add(pool_header_size)
            .and_then(|start| start.checked_add(object_decoder.body_offset))
        else {
            continue;
        };
        let Some(last_body) = pool_header
            .checked_add(pool_size)
            .and_then(|end| end.checked_sub(aligned_file_size))
        else {
            continue;
        };
        let mut file_object = first_body;
        while file_object <= last_body {
            cancellation.check_cancelled()?;
            if physical_file_signature(image, file_object, &signature_layout) {
                let prefetched_name = if let Some(filter) = name_filter {
                    let Some(name) = read_physical_file_object_name(
                        image,
                        &space,
                        file_object + name_offset,
                        32 * 1024,
                    ) else {
                        file_object += pool_granularity;
                        continue;
                    };
                    if !filter(&name) {
                        file_object += pool_granularity;
                        continue;
                    }
                    Some(name)
                } else {
                    None
                };
                physical_candidates.push(PhysicalFileCandidate {
                    file_object,
                    pool_header,
                    pool_size,
                    prefetched_name,
                });
            }
            file_object += pool_granularity;
        }
    }
    let candidate_filter_seconds = candidate_filter_started.elapsed().as_secs_f64();

    let target_pages: HashSet<u64> = physical_candidates
        .iter()
        .map(|candidate| candidate.file_object & !0xfff)
        .collect();
    cancellation.check_cancelled()?;
    let reverse_map_started = Instant::now();
    let mappings = space.reverse_translate_kernel_pages(&target_pages, 64)?;
    let reverse_map_seconds = reverse_map_started.elapsed().as_secs_f64();
    cancellation.check_cancelled()?;
    let reverse_mapped_candidates = physical_candidates
        .iter()
        .filter(|candidate| mappings.contains_key(&(candidate.file_object & !0xfff)))
        .count();
    let record_validation_started = Instant::now();
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for candidate in &physical_candidates {
        cancellation.check_cancelled()?;
        let physical_page = candidate.file_object & !0xfff;
        let page_offset = candidate.file_object & 0xfff;
        let Some(virtual_pages) = mappings.get(&physical_page) else {
            continue;
        };
        for virtual_page in virtual_pages {
            cancellation.check_cancelled()?;
            if records.len() == limit {
                break;
            }
            let file_object = virtual_page + page_offset;
            if !seen.insert((candidate.file_object, file_object))
                || read_u16(&space, file_object + file_type_offset).ok() != Some(5)
                || read_u16(&space, file_object + file_size_offset)
                    .ok()
                    .is_none_or(|size| u64::from(size) < file_size)
            {
                continue;
            }
            let Some(object_header) = file_object.checked_sub(object_decoder.body_offset) else {
                continue;
            };
            let object_type = object_decoder.type_name(&space, object_header);
            if object_type.as_deref().is_some_and(|name| name != "File") {
                continue;
            }
            let device_object = space.read_pointer(file_object + device_offset).unwrap_or(0);
            let section_object_pointer = space
                .read_pointer(file_object + section_offset)
                .unwrap_or(0);
            if !is_null_or_kernel_pointer(device_object, space.pointer_size())
                || !is_null_or_kernel_pointer(section_object_pointer, space.pointer_size())
            {
                continue;
            }
            let name = candidate.prefetched_name.clone().or_else(|| {
                read_file_object_name(&space, file_object + name_offset, 32 * 1024).ok()
            });
            let object_type_verified = object_type.as_deref() == Some("File");
            // A stale File pool allocation can retain Type == 5 and Size while
            // the rest of the object has already been reused.  When the object
            // header can no longer prove its type, require both independent
            // FILE_OBJECT signals instead of printing the reused bytes as a
            // filename.  Verified objects are still useful even when their
            // name buffer has been paged out.
            if !object_type_verified
                && (name
                    .as_deref()
                    .is_none_or(|value| !validate_unverified_file_object_name(value))
                    || !is_kernel_pointer_for(&space, device_object))
            {
                continue;
            }
            let data_section_object =
                section_field(&space, section_object_pointer, data_section_offset);
            let shared_cache_map =
                section_field(&space, section_object_pointer, shared_cache_offset);
            let image_section_object =
                section_field(&space, section_object_pointer, image_section_offset);
            records.push(FileScanRecord {
                file_object,
                physical_address: candidate.file_object,
                object_header,
                pool_header_physical: candidate.pool_header,
                pool_allocation_size: candidate.pool_size,
                name,
                device_object,
                section_object_pointer,
                data_section_object,
                shared_cache_map,
                image_section_object,
                flags: read_u32(&space, file_object + flags_offset).unwrap_or(0),
                delete_pending: read_u8(&space, file_object + delete_pending_offset).unwrap_or(0)
                    != 0,
                object_type_verified,
            });
        }
        if records.len() == limit {
            break;
        }
    }
    records.sort_unstable_by_key(|record| record.file_object);
    let mut warnings = Vec::new();
    if pool_scan_truncated {
        warnings.push("File 池标签候选已达到数量上限".to_owned());
    }
    if records.len() == limit {
        warnings.push(format!("文件结果达到 {limit} 条上限"));
    }
    let record_validation_seconds = record_validation_started.elapsed().as_secs_f64();
    let total_seconds = total_started.elapsed().as_secs_f64();
    Ok(FileScanReport {
        complete: !pool_scan_truncated && records.len() < limit,
        records,
        pool_tag_hits,
        physical_candidates: physical_candidates.len(),
        reverse_mapped_candidates,
        scan_seconds: pool_scan_seconds,
        scan_gib_per_second: pool_scan_gib_per_second,
        timing: FileScanTiming {
            setup_seconds,
            pool_scan_seconds,
            candidate_filter_seconds,
            reverse_map_seconds,
            record_validation_seconds,
            total_seconds,
        },
        warnings,
    })
}

fn section_field(space: &WindowsAddressSpace<'_>, section: u64, offset: u64) -> u64 {
    if !is_kernel_pointer_for(space, section) {
        return 0;
    }
    space.read_pointer(section + offset).unwrap_or(0) & !(space.pointer_size() * 2 - 1)
}

pub fn dump_file(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    file_object: u64,
    output: &mut File,
    requested_source: DumpSource,
    max_size: u64,
) -> Result<DumpFileReport> {
    dump_file_to_sink(
        image,
        kernel,
        profile,
        file_object,
        output,
        requested_source,
        max_size,
    )
}

/// 将驻留文件恢复到内存，供组合型插件直接解析数据库等取证内容。
/// 这条路径复用与 `dumpfile` 完全相同的缓存和节区恢复逻辑，不产生临时文件。
pub fn recover_file_bytes(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    file_object: u64,
    requested_source: DumpSource,
    max_size: u64,
) -> Result<(DumpFileReport, Vec<u8>)> {
    let mut output = Cursor::new(Vec::new());
    let report = dump_file_to_sink(
        image,
        kernel,
        profile,
        file_object,
        &mut output,
        requested_source,
        max_size,
    )?;
    Ok((report, output.into_inner()))
}

trait RecoverySink: Write + Seek {
    fn resize(&mut self, length: u64) -> std::io::Result<()>;

    fn copy_virtual_page(
        &mut self,
        space: &WindowsAddressSpace<'_>,
        memory: u64,
        offset: u64,
        length: usize,
    ) -> Result<bool> {
        let mut page = vec![0u8; length];
        if space.read_virtual(memory, &mut page).is_err() {
            return Ok(false);
        }
        self.seek(SeekFrom::Start(offset))?;
        self.write_all(&page)?;
        Ok(true)
    }

    fn copy_physical_page(
        &mut self,
        image: &MemoryImage,
        memory: u64,
        offset: u64,
        length: usize,
    ) -> Result<bool> {
        let mut page = vec![0u8; length];
        if image.read_physical(memory, &mut page).is_err() {
            return Ok(false);
        }
        self.seek(SeekFrom::Start(offset))?;
        self.write_all(&page)?;
        Ok(true)
    }
}

impl RecoverySink for File {
    fn resize(&mut self, length: u64) -> std::io::Result<()> {
        self.set_len(length)
    }
}

impl RecoverySink for Cursor<Vec<u8>> {
    fn resize(&mut self, length: u64) -> std::io::Result<()> {
        let length = usize::try_from(length)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "内存恢复大小超过平台限制"))?;
        self.get_mut().resize(length, 0);
        if self.position() > length as u64 {
            self.set_position(length as u64);
        }
        Ok(())
    }
}

fn dump_file_to_sink<O: RecoverySink>(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    file_object: u64,
    output: &mut O,
    requested_source: DumpSource,
    max_size: u64,
) -> Result<DumpFileReport> {
    ensure!(max_size > 0, "最大恢复大小必须大于零");
    let space = kernel.address_space(image)?;
    let file_size = profile.type_layout("_FILE_OBJECT")?.size;
    let type_offset = profile.type_field("_FILE_OBJECT", "Type")?.offset;
    let size_offset = profile.type_field("_FILE_OBJECT", "Size")?.offset;
    ensure!(
        read_u16(&space, file_object + type_offset)? == 5
            && u64::from(read_u16(&space, file_object + size_offset)?) >= file_size,
        "地址 {file_object:#x} 不是有效的 FILE_OBJECT"
    );
    let object_decoder = ObjectTypeDecoder::new(&space, kernel, profile)?;
    let object_header = file_object
        .checked_sub(object_decoder.body_offset)
        .ok_or_else(|| anyhow::anyhow!("FILE_OBJECT 地址位于对象头之前"))?;
    ensure!(
        object_decoder
            .type_name(&space, object_header)
            .is_none_or(|name| name == "File"),
        "地址 {file_object:#x} 的对象头类型不是 File"
    );
    let name_offset = profile.type_field("_FILE_OBJECT", "FileName")?.offset;
    let name = read_file_object_name(&space, file_object + name_offset, 32 * 1024).ok();
    let section_pointer_offset = profile
        .type_field("_FILE_OBJECT", "SectionObjectPointer")?
        .offset;
    let section_object_pointers = space.read_pointer(file_object + section_pointer_offset)?;
    ensure!(
        is_kernel_pointer_for(&space, section_object_pointers),
        "FILE_OBJECT 没有有效的 SectionObjectPointer"
    );
    let data_offset = profile
        .type_field("_SECTION_OBJECT_POINTERS", "DataSectionObject")?
        .offset;
    let cache_offset = profile
        .type_field("_SECTION_OBJECT_POINTERS", "SharedCacheMap")?
        .offset;
    let image_offset = profile
        .type_field("_SECTION_OBJECT_POINTERS", "ImageSectionObject")?
        .offset;
    let shared_cache_map = space
        .read_pointer(section_object_pointers + cache_offset)
        .unwrap_or(0)
        & !(space.pointer_size() * 2 - 1);
    let data_control_area = space
        .read_pointer(section_object_pointers + data_offset)
        .unwrap_or(0)
        & !(space.pointer_size() * 2 - 1);
    let image_control_area = space
        .read_pointer(section_object_pointers + image_offset)
        .unwrap_or(0)
        & !(space.pointer_size() * 2 - 1);

    let sources: &[DumpSource] = match requested_source {
        // Cache and data-section views preserve on-disk byte offsets.  Image
        // sections are only used when neither file-layout source has readable
        // bytes, because resident PE pages may contain loader/runtime changes.
        DumpSource::Auto => &[DumpSource::Cache, DumpSource::Data, DumpSource::Image],
        DumpSource::Cache => &[DumpSource::Cache],
        DumpSource::Data => &[DumpSource::Data],
        DumpSource::Image => &[DumpSource::Image],
        DumpSource::HiveMemory => {
            unreachable!("hive-memory recovery is not a FILE_OBJECT source")
        }
    };
    let logical_hint = cache_file_size(&space, profile, shared_cache_map, max_size)
        .ok()
        .or_else(|| file_object_size(&space, profile, file_object, max_size).ok());
    let recover_source = |source, output: &mut O| -> Result<DumpFileReport> {
        match source {
            DumpSource::Cache => {
                dump_cache_map(&space, profile, shared_cache_map, output, max_size)
            }
            DumpSource::Data => dump_control_area(
                image,
                &space,
                profile,
                data_control_area,
                logical_hint,
                output,
                max_size,
                DumpSource::Data,
            ),
            DumpSource::Image => dump_control_area(
                image,
                &space,
                profile,
                image_control_area,
                None,
                output,
                max_size,
                DumpSource::Image,
            ),
            DumpSource::HiveMemory => {
                unreachable!("hive-memory recovery is not a FILE_OBJECT source")
            }
            DumpSource::Auto => unreachable!(),
        }
    };
    let mut last_report = None;
    let mut best_report: Option<DumpFileReport> = None;
    let mut last_source = None;
    for &source in sources {
        if source == DumpSource::Image && best_report.is_some() {
            break;
        }
        output.resize(0)?;
        output.seek(SeekFrom::Start(0))?;
        let result = recover_source(source, output);
        last_source = Some(source);
        match result {
            Ok(mut report) if report.recovered_bytes > 0 => {
                report.file_object = file_object;
                report.name = name.clone();
                if report.complete {
                    return Ok(report);
                }
                // A readable cache tail is not enough: the data section may
                // still contain the header and every missing cache page.
                if best_report
                    .as_ref()
                    .is_none_or(|best| report.recovered_bytes > best.recovered_bytes)
                {
                    best_report = Some(report);
                }
            }
            Ok(mut report) => {
                report.file_object = file_object;
                report.name = name.clone();
                last_report = Some(report);
            }
            Err(error) => {
                last_report = Some(DumpFileReport {
                    file_object,
                    name: name.clone(),
                    source,
                    logical_size: 0,
                    output_size: 0,
                    recovered_bytes: 0,
                    missing_bytes: 0,
                    complete: false,
                    extents: Vec::new(),
                    compressed_pages: Vec::new(),
                    warnings: vec![format!("{source:?} 恢复失败：{error:#}")],
                });
            }
        }
    }
    if let Some(report) = best_report {
        if last_source == Some(report.source) {
            return Ok(report);
        }
        // Later attempts reused the sink. Replay only the selected source so
        // sparse tails are truncated and bytes from different views never mix.
        // This keeps large file recovery streaming instead of buffering copies.
        output.resize(0)?;
        output.seek(SeekFrom::Start(0))?;
        let mut report = recover_source(report.source, output)?;
        report.file_object = file_object;
        report.name = name;
        return Ok(report);
    }
    Ok(last_report.unwrap_or(DumpFileReport {
        file_object,
        name,
        source: requested_source,
        logical_size: 0,
        output_size: 0,
        recovered_bytes: 0,
        missing_bytes: 0,
        complete: false,
        extents: Vec::new(),
        compressed_pages: Vec::new(),
        warnings: vec!["没有可用的恢复来源".to_owned()],
    }))
}

fn dump_cache_map<O: RecoverySink>(
    space: &WindowsAddressSpace<'_>,
    profile: &KernelProfile,
    shared_cache_map: u64,
    output: &mut O,
    max_size: u64,
) -> Result<DumpFileReport> {
    ensure!(
        is_kernel_pointer_for(space, shared_cache_map),
        "SharedCacheMap 为空或无效"
    );
    let logical_size = cache_file_size(space, profile, shared_cache_map, max_size)?;
    let initial = profile.type_field("_SHARED_CACHE_MAP", "InitialVacbs")?;
    let vacbs_offset = profile.type_field("_SHARED_CACHE_MAP", "Vacbs")?.offset;
    let vacb_base = profile.type_field("_VACB", "BaseAddress")?.offset;
    let vacb_map = profile.type_field("_VACB", "SharedCacheMap")?.offset;
    let vacb_overlay = profile.type_field("_VACB", "Overlay")?.offset;
    let mut vacb_pointers = Vec::new();
    let initial_count = initial
        .size
        .unwrap_or(space.pointer_size() * 4)
        .div_ceil(space.pointer_size())
        .clamp(1, 16);
    for index in 0..initial_count {
        let Some(address) = shared_cache_map
            .checked_add(initial.offset)
            .and_then(|address| address.checked_add(index * space.pointer_size()))
        else {
            continue;
        };
        if let Ok(pointer) = space.read_pointer(address) {
            vacb_pointers.push(pointer & !0x7);
        }
    }
    let initial_array = shared_cache_map.checked_add(initial.offset);
    if let Some(address) = shared_cache_map.checked_add(vacbs_offset)
        && let Ok(root) = space.read_pointer(address)
        && is_kernel_pointer_for(space, root & !0x7)
        // Small files point Vacbs back to the inline four-slot array. Walking
        // 128 entries from there spills into unrelated SHARED_CACHE_MAP fields
        // and can make SECTION_OBJECT_POINTERS look like a VACB by accident.
        && Some(root & !0x7) != initial_array
    {
        collect_vacb_tree(
            space,
            root & !0x7,
            shared_cache_map,
            vacb_map,
            vacb_overlay,
            logical_size,
            &mut vacb_pointers,
        );
    }
    vacb_pointers.sort_unstable();
    vacb_pointers.dedup();

    let mut views = Vec::new();
    for vacb in vacb_pointers {
        let base = vacb
            .checked_add(vacb_base)
            .and_then(|address| space.read_pointer(address).ok())
            .unwrap_or(0);
        let owner = vacb
            .checked_add(vacb_map)
            .and_then(|address| space.read_pointer(address).ok())
            .unwrap_or(0)
            & !(space.pointer_size() * 2 - 1);
        let file_offset = vacb
            .checked_add(vacb_overlay)
            .and_then(|address| space.read_u64(address).ok())
            .unwrap_or(u64::MAX);
        if owner == shared_cache_map
            && is_kernel_pointer_for(space, base)
            // System-cache views are page aligned. This also rejects a false
            // VACB whose "BaseAddress" is actually a CONTROL_AREA pointer.
            && base.is_multiple_of(0x1000)
            && file_offset < logical_size
            && file_offset.is_multiple_of(0x40000)
        {
            views.push((file_offset, base));
        }
    }
    views.sort_unstable();
    views.dedup_by_key(|view| view.0);
    let mut recovered_pages = HashSet::new();
    let mut extents = Vec::new();
    let mut recovered_bytes = 0u64;
    for (view_offset, base) in views {
        let view_length = (logical_size - view_offset).min(0x40000);
        for relative in (0..view_length).step_by(0x1000) {
            let file_offset = view_offset + relative;
            if !recovered_pages.insert(file_offset) {
                continue;
            }
            let length = (view_length - relative).min(0x1000) as usize;
            let Some(memory) = base.checked_add(relative) else {
                continue;
            };
            if !output.copy_virtual_page(space, memory, file_offset, length)? {
                continue;
            }
            recovered_bytes += length as u64;
            push_extent(&mut extents, file_offset, length as u64, memory, "virtual");
        }
    }
    output.resize(extent_output_size(&extents))?;
    Ok(finish_dump_report(
        DumpSource::Cache,
        logical_size,
        recovered_bytes,
        extents,
        (recovered_bytes == 0).then(|| "没有可读取的驻留 VACB 页面".to_owned()),
    ))
}

fn cache_file_size(
    space: &WindowsAddressSpace<'_>,
    profile: &KernelProfile,
    shared_cache_map: u64,
    max_size: u64,
) -> Result<u64> {
    ensure!(
        is_kernel_pointer_for(space, shared_cache_map),
        "SharedCacheMap 为空或无效"
    );
    let offset = profile.type_field("_SHARED_CACHE_MAP", "FileSize")?.offset;
    let address = shared_cache_map
        .checked_add(offset)
        .context("SharedCacheMap 字段地址溢出")?;
    let size = space.read_u64(address)?;
    ensure!(size > 0, "缓存映射报告文件为空");
    ensure!(
        size <= max_size,
        "缓存映射文件大小 {size:#x} 超过 --max-size 限制 {max_size:#x}"
    );
    Ok(size)
}

fn file_object_size(
    space: &WindowsAddressSpace<'_>,
    profile: &KernelProfile,
    file_object: u64,
    max_size: u64,
) -> Result<u64> {
    let fs_context_offset = profile.type_field("_FILE_OBJECT", "FsContext")?.offset;
    let fs_context = space.read_pointer(
        file_object
            .checked_add(fs_context_offset)
            .context("FILE_OBJECT FsContext 字段地址溢出")?,
    )?;
    ensure!(
        is_kernel_pointer_for(space, fs_context),
        "FILE_OBJECT 没有有效的 FsContext"
    );

    // NTFS and the other Windows file systems begin their FCB/SCB with one of
    // the FSRTL common headers.  Reading the exact PDB-derived offsets avoids
    // treating the rounded segment size (commonly 256 KiB) as the file size.
    let header_name = ["_FSRTL_ADVANCED_FCB_HEADER", "_FSRTL_COMMON_FCB_HEADER"]
        .into_iter()
        .find(|name| profile.type_layout(name).is_ok())
        .context("符号配置中没有 FSRTL FCB 头布局")?;
    let header = profile.type_layout(header_name)?;
    let node_size_offset = profile.type_field(header_name, "NodeByteSize")?.offset;
    let file_size_offset = profile.type_field(header_name, "FileSize")?.offset;
    let node_size = u64::from(read_u16(
        space,
        fs_context
            .checked_add(node_size_offset)
            .context("FCB 节点大小字段地址溢出")?,
    )?);
    ensure!(
        node_size >= header.size,
        "FsContext 开头不是完整的 FSRTL FCB 头"
    );
    let size = space.read_u64(
        fs_context
            .checked_add(file_size_offset)
            .context("FCB 文件大小字段地址溢出")?,
    )?;
    ensure!(size > 0, "FCB 报告文件为空");
    ensure!(
        size <= max_size,
        "FCB 文件大小 {size:#x} 超过 --max-size 限制 {max_size:#x}"
    );
    Ok(size)
}

#[allow(clippy::too_many_arguments)]
fn collect_vacb_tree(
    space: &WindowsAddressSpace<'_>,
    root: u64,
    shared_cache_map: u64,
    vacb_map_offset: u64,
    vacb_overlay_offset: u64,
    logical_size: u64,
    output: &mut Vec<u64>,
) {
    const MAX_ARRAYS: usize = 65_536;
    let mut pending = vec![(root, 0usize)];
    let mut visited = HashSet::new();
    while let Some((array, depth)) = pending.pop() {
        if visited.len() == MAX_ARRAYS || depth > 4 || !visited.insert(array) {
            continue;
        }
        for index in 0..128u64 {
            let pointer = array
                .checked_add(index * space.pointer_size())
                .and_then(|address| space.read_pointer(address).ok())
                .unwrap_or(0)
                & !0x7;
            if !is_kernel_pointer_for(space, pointer) {
                continue;
            }
            let owner = pointer
                .checked_add(vacb_map_offset)
                .and_then(|address| space.read_pointer(address).ok())
                .unwrap_or(0)
                & !(space.pointer_size() * 2 - 1);
            let file_offset = space
                .read_u64(match pointer.checked_add(vacb_overlay_offset) {
                    Some(address) => address,
                    None => continue,
                })
                .unwrap_or(u64::MAX);
            if owner == shared_cache_map
                && file_offset < logical_size
                && file_offset.is_multiple_of(0x40000)
            {
                output.push(pointer);
            } else if depth < 4 {
                pending.push((pointer, depth + 1));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dump_control_area<O: RecoverySink>(
    image: &MemoryImage,
    space: &WindowsAddressSpace<'_>,
    profile: &KernelProfile,
    control_area: u64,
    logical_hint: Option<u64>,
    output: &mut O,
    max_size: u64,
    source: DumpSource,
) -> Result<DumpFileReport> {
    ensure!(
        is_kernel_pointer_for(space, control_area),
        "控制区为空或无效"
    );
    let segment_offset = profile.type_field("_CONTROL_AREA", "Segment")?.offset;
    let segment_address = control_area
        .checked_add(segment_offset)
        .context("控制区字段地址溢出")?;
    let segment = space.read_pointer(segment_address)? & !(space.pointer_size() * 2 - 1);
    ensure!(is_kernel_pointer_for(space, segment), "控制区没有有效的段");
    let segment_control = profile.type_field("_SEGMENT", "ControlArea")?.offset;
    ensure!(
        space.read_pointer(
            segment
                .checked_add(segment_control)
                .context("段控制区字段地址溢出")?,
        )? & !(space.pointer_size() * 2 - 1)
            == control_area,
        "段没有引用所选控制区"
    );
    let total_ptes_offset = profile.type_field("_SEGMENT", "TotalNumberOfPtes")?.offset;
    let size_offset = profile.type_field("_SEGMENT", "SizeOfSegment")?.offset;
    let total_ptes = u64::from(read_u32(
        space,
        segment
            .checked_add(total_ptes_offset)
            .context("段 PTE 数量字段地址溢出")?,
    )?);
    let segment_size = space.read_u64(
        segment
            .checked_add(size_offset)
            .context("段大小字段地址溢出")?,
    )?;
    let logical_size = logical_hint.unwrap_or(segment_size).min(segment_size);
    ensure!(logical_size > 0, "段内容为空");
    ensure!(
        logical_size <= max_size,
        "段大小 {logical_size:#x} 超过 --max-size 限制 {max_size:#x}"
    );
    let control_area_size = profile.type_layout("_CONTROL_AREA")?.size;
    let subsection_control = profile.type_field("_SUBSECTION", "ControlArea")?.offset;
    let subsection_base = profile.type_field("_SUBSECTION", "SubsectionBase")?.offset;
    let subsection_next = profile.type_field("_SUBSECTION", "NextSubsection")?.offset;
    let subsection_ptes = profile
        .type_field("_SUBSECTION", "PtesInSubsection")?
        .offset;
    let subsection_start = profile.type_field("_SUBSECTION", "StartingSector")?.offset;
    let mut subsection = control_area
        .checked_add(control_area_size)
        .context("第一个子节地址溢出")?;
    let page_count = total_ptes.min(logical_size.div_ceil(0x1000));
    let mut extents = Vec::new();
    let mut recovered_bytes = 0u64;
    let mut recovered_pages = HashSet::new();
    let mut seen_subsections = HashSet::new();
    let mut subsections_examined = 0usize;
    while is_kernel_pointer_for(space, subsection)
        && seen_subsections.insert(subsection)
        && subsections_examined < 65_536
    {
        let owner = space.read_pointer(
            subsection
                .checked_add(subsection_control)
                .context("子节控制区字段地址溢出")?,
        )? & !(space.pointer_size() * 2 - 1);
        if owner != control_area {
            break;
        }
        subsections_examined += 1;
        let prototype_pte = space.read_pointer(
            subsection
                .checked_add(subsection_base)
                .context("子节 PTE 基址字段地址溢出")?,
        )? & !0x7;
        let ptes_in_subsection = u64::from(read_u32(
            space,
            subsection
                .checked_add(subsection_ptes)
                .context("子节 PTE 数量字段地址溢出")?,
        )?);
        let starting_sector = u64::from(read_u32(
            space,
            subsection
                .checked_add(subsection_start)
                .context("子节起始扇区字段地址溢出")?,
        )?);
        // Image subsections use disk sectors, while data subsections use pages.
        let sector_size = if source == DumpSource::Image {
            0x200
        } else {
            0x1000
        };
        let subsection_file_offset = starting_sector
            .checked_mul(sector_size)
            .context("子节文件偏移溢出")?;
        if is_kernel_pointer_for(space, prototype_pte) {
            let subsection_pages = ptes_in_subsection.min(page_count);
            for index in 0..subsection_pages {
                let Some(file_offset) = subsection_file_offset.checked_add(index * 0x1000) else {
                    continue;
                };
                if file_offset >= logical_size
                    || (source != DumpSource::Image && recovered_pages.contains(&file_offset))
                {
                    continue;
                }
                let Some(pte_address) = prototype_pte.checked_add(index * 8) else {
                    continue;
                };
                let pte = match space.read_u64(pte_address) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let Some(physical) = resident_pte_physical(pte) else {
                    continue;
                };
                let length = (logical_size - file_offset).min(0x1000) as usize;
                if !output.copy_physical_page(image, physical, file_offset, length)? {
                    continue;
                }
                recovered_pages.insert(file_offset);
                recovered_bytes += length as u64;
                push_extent(
                    &mut extents,
                    file_offset,
                    length as u64,
                    physical,
                    "physical",
                );
            }
        }
        let next = space.read_pointer(
            subsection
                .checked_add(subsection_next)
                .context("下一子节字段地址溢出")?,
        )?;
        if next == 0 {
            break;
        }
        subsection = next;
    }
    ensure!(subsections_examined > 0, "控制区没有有效的子节链");
    if source == DumpSource::Image {
        // Sector-aligned sections can overlap the padding of earlier pages.
        // Preserve the provenance of the bytes actually left by the last write.
        extents = normalize_written_extents(extents);
        recovered_bytes = extents.iter().map(|extent| extent.length).sum();
    }
    output.resize(extent_output_size(&extents))?;
    let warning = if recovered_bytes == 0 {
        Some("没有可读取的驻留子节 PTE 页面".to_owned())
    } else if source == DumpSource::Image {
        Some("映像节按文件扇区偏移重建；驻留页可能包含重定位或运行时修改，不能保证与原始磁盘文件一致".to_owned())
    } else {
        None
    };
    Ok(finish_dump_report(
        source,
        logical_size,
        recovered_bytes,
        extents,
        warning,
    ))
}

fn resident_pte_physical(pte: u64) -> Option<u64> {
    let valid = pte & 1 != 0;
    let prototype = pte & (1 << 10) != 0;
    let transition = pte & (1 << 11) != 0;
    let physical = if valid {
        pte & 0x000f_ffff_ffff_f000
    } else if transition && !prototype {
        pte & 0x0000_dfff_ffff_f000
    } else {
        return None;
    };
    (physical != 0).then_some(physical)
}

fn finish_dump_report(
    source: DumpSource,
    logical_size: u64,
    recovered_bytes: u64,
    extents: Vec<RecoveredExtent>,
    warning: Option<String>,
) -> DumpFileReport {
    DumpFileReport {
        file_object: 0,
        name: None,
        source,
        logical_size,
        output_size: extent_output_size(&extents),
        recovered_bytes,
        missing_bytes: logical_size.saturating_sub(recovered_bytes),
        complete: recovered_bytes == logical_size,
        extents,
        compressed_pages: Vec::new(),
        warnings: warning.into_iter().collect(),
    }
}

fn extent_output_size(extents: &[RecoveredExtent]) -> u64 {
    extents
        .iter()
        .map(|extent| extent.file_offset.saturating_add(extent.length))
        .max()
        .unwrap_or(0)
}

/// Resolve overlapping writes without counting a byte twice or attributing it to an overwritten page.
fn normalize_written_extents(extents: Vec<RecoveredExtent>) -> Vec<RecoveredExtent> {
    let mut spans: BTreeMap<u64, RecoveredExtent> = BTreeMap::new();
    for extent in extents {
        let start = extent.file_offset;
        let end = start + extent.length;
        let first = spans
            .range(..=start)
            .next_back()
            .filter(|(_, previous)| previous.file_offset + previous.length > start)
            .map(|(&offset, _)| offset)
            .unwrap_or(start);
        let overlaps: Vec<u64> = spans.range(first..end).map(|(&offset, _)| offset).collect();
        for key in overlaps {
            let previous = spans.remove(&key).expect("key was collected from the map");
            let previous_end = previous.file_offset + previous.length;
            if previous_end > end {
                spans.insert(
                    end,
                    RecoveredExtent {
                        file_offset: end,
                        length: previous_end - end,
                        memory_address: previous.memory_address + (end - previous.file_offset),
                        memory_kind: previous.memory_kind.clone(),
                    },
                );
            }
            if previous.file_offset < start {
                spans.insert(
                    previous.file_offset,
                    RecoveredExtent {
                        length: start - previous.file_offset,
                        ..previous
                    },
                );
            }
        }
        spans.insert(start, extent);
    }
    spans.into_values().collect()
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

impl ObjectTypeDecoder {
    fn new(
        space: &WindowsAddressSpace<'_>,
        kernel: &WindowsKernelContext,
        profile: &KernelProfile,
    ) -> Result<Self> {
        let cookie = profile
            .symbol_rva("ObHeaderCookie")
            .ok()
            .and_then(|rva| read_u8(space, kernel.kernel_base + u64::from(rva)).ok());
        let type_table = profile
            .symbol_rva("ObTypeIndexTable")
            .ok()
            .map(|rva| kernel.kernel_base + u64::from(rva));
        Ok(Self {
            cookie,
            type_table,
            type_location: match profile.type_field("_OBJECT_HEADER", "TypeIndex") {
                Ok(field) => ObjectTypeLocation::Index(field.offset),
                Err(_) => ObjectTypeLocation::Pointer(
                    profile.type_field("_OBJECT_HEADER", "Type")?.offset,
                ),
            },
            body_offset: profile.type_field("_OBJECT_HEADER", "Body")?.offset,
            type_name_offset: profile.type_field("_OBJECT_TYPE", "Name")?.offset,
        })
    }

    fn type_name(&self, space: &WindowsAddressSpace<'_>, object_header: u64) -> Option<String> {
        let object_type = match self.type_location {
            ObjectTypeLocation::Index(offset) => {
                let raw_index = read_u8(space, object_header + offset).ok()?;
                let type_index = self
                    .cookie
                    .map(|cookie| raw_index ^ cookie ^ ((object_header >> 8) as u8))
                    .unwrap_or(raw_index);
                space
                    .read_pointer(self.type_table? + u64::from(type_index) * space.pointer_size())
                    .ok()?
            }
            // XP/Server 2003 store the _OBJECT_TYPE pointer directly. Never
            // interpret its low byte as a Vista+ TypeIndex or guess a type ID.
            ObjectTypeLocation::Pointer(offset) => {
                space.read_pointer(object_header + offset).ok()?
            }
        };
        if !is_kernel_pointer_width(object_type, space.pointer_size()) {
            return None;
        }
        read_unicode_string(space, object_type + self.type_name_offset, 4096).ok()
    }
}

fn physical_file_signature(
    image: &MemoryImage,
    file_object: u64,
    layout: &PhysicalSignatureLayout,
) -> bool {
    if read_u16_physical(image, file_object + layout.type_offset) != Some(5)
        || read_u16_physical(image, file_object + layout.size_offset)
            .is_none_or(|size| u64::from(size) < layout.expected_size)
    {
        return false;
    }
    let device = read_pointer_physical(
        image,
        file_object + layout.device_offset,
        layout.pointer_size,
    )
    .unwrap_or(1);
    let section = read_pointer_physical(
        image,
        file_object + layout.section_offset,
        layout.pointer_size,
    )
    .unwrap_or(1);
    if !is_null_or_kernel_pointer(device, layout.pointer_size)
        || !is_null_or_kernel_pointer(section, layout.pointer_size)
    {
        return false;
    }
    let mut descriptor = [0u8; 16];
    if image
        .read_physical(
            file_object + layout.name_offset,
            &mut descriptor[..(layout.pointer_size * 2) as usize],
        )
        .is_err()
    {
        return false;
    }
    let length = u16::from_le_bytes([descriptor[0], descriptor[1]]);
    let maximum = u16::from_le_bytes([descriptor[2], descriptor[3]]);
    let buffer = unicode_buffer(&descriptor, layout.pointer_size);
    length <= maximum
        && length <= 32 * 1024
        && length.is_multiple_of(2)
        && (length == 0 || is_kernel_pointer_width(buffer, layout.pointer_size))
}

fn read_physical_file_object_name(
    image: &MemoryImage,
    space: &WindowsAddressSpace<'_>,
    descriptor: u64,
    max_bytes: usize,
) -> Option<String> {
    let mut header = [0u8; 16];
    image
        .read_physical(
            descriptor,
            &mut header[..(space.pointer_size() * 2) as usize],
        )
        .ok()?;
    let length = usize::from(u16::from_le_bytes([header[0], header[1]]));
    let maximum = usize::from(u16::from_le_bytes([header[2], header[3]]));
    if length == 0 || length > maximum || length > max_bytes || !length.is_multiple_of(2) {
        return None;
    }
    let buffer = unicode_buffer(&header, space.pointer_size());
    if !is_kernel_pointer_for(space, buffer) {
        return None;
    }
    let mut bytes = vec![0u8; length];
    space.read_virtual(buffer, &mut bytes).ok()?;
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    decode_file_object_name(&units).ok()
}

fn is_null_or_kernel_pointer(address: u64, width: u64) -> bool {
    address == 0 || is_kernel_pointer_width(address, width)
}

fn read_pointer_physical(image: &MemoryImage, address: u64, width: u64) -> Result<u64> {
    ensure!(matches!(width, 4 | 8), "无效的指针宽度");
    let mut bytes = [0u8; 8];
    image.read_physical(address, &mut bytes[..width as usize])?;
    Ok(u64::from_le_bytes(bytes))
}

fn unicode_buffer(header: &[u8; 16], width: u64) -> u64 {
    if width == 4 {
        u64::from(u32::from_le_bytes([
            header[4], header[5], header[6], header[7],
        ]))
    } else {
        u64::from_le_bytes([
            header[8], header[9], header[10], header[11], header[12], header[13], header[14],
            header[15],
        ])
    }
}

fn is_kernel_pointer_for(space: &WindowsAddressSpace<'_>, address: u64) -> bool {
    is_kernel_pointer_width(address, space.pointer_size())
}

fn is_kernel_pointer_width(address: u64, width: u64) -> bool {
    let kernel = if width == 4 {
        (0x8000_0000..=u32::MAX as u64).contains(&address)
    } else {
        address >> 48 == 0xffff
    };
    kernel && address & (width - 1) == 0
}

fn read_u8(space: &WindowsAddressSpace<'_>, address: u64) -> Result<u8> {
    let mut bytes = [0u8; 1];
    space.read_virtual(address, &mut bytes)?;
    Ok(bytes[0])
}

fn read_u16(space: &WindowsAddressSpace<'_>, address: u64) -> Result<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(space: &WindowsAddressSpace<'_>, address: u64) -> Result<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u16_physical(image: &MemoryImage, address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    image.read_physical(address, &mut bytes).ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_unicode_string(
    space: &WindowsAddressSpace<'_>,
    descriptor: u64,
    max_bytes: usize,
) -> Result<String> {
    decode_utf16_strict(&read_unicode_units(space, descriptor, max_bytes)?)
}

fn read_file_object_name(
    space: &WindowsAddressSpace<'_>,
    descriptor: u64,
    max_bytes: usize,
) -> Result<String> {
    let utf16 = read_unicode_units(space, descriptor, max_bytes)?;
    decode_file_object_name(&utf16)
}

fn decode_file_object_name(utf16: &[u16]) -> Result<String> {
    let end = utf16
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(utf16.len());
    let name = decode_utf16_strict(&utf16[..end])?;
    ensure!(
        validate_file_object_name(&name),
        "FILE_OBJECT 名称包含无效字符"
    );
    Ok(name)
}

fn read_unicode_units(
    space: &WindowsAddressSpace<'_>,
    descriptor: u64,
    max_bytes: usize,
) -> Result<Vec<u16>> {
    let mut header = [0u8; 16];
    space.read_virtual(
        descriptor,
        &mut header[..(space.pointer_size() * 2) as usize],
    )?;
    let length = usize::from(u16::from_le_bytes([header[0], header[1]]));
    let maximum = usize::from(u16::from_le_bytes([header[2], header[3]]));
    ensure!(length <= maximum, "UNICODE_STRING 长度超过最大值");
    ensure!(length <= max_bytes, "UNICODE_STRING 超过安全长度限制");
    ensure!(length.is_multiple_of(2), "UNICODE_STRING 的字节长度为奇数");
    if length == 0 {
        return Ok(Vec::new());
    }
    let buffer = unicode_buffer(&header, space.pointer_size());
    ensure!(
        is_kernel_pointer_for(space, buffer),
        "UNICODE_STRING 缓冲区无效"
    );
    let mut bytes = vec![0u8; length];
    space.read_virtual(buffer, &mut bytes)?;
    Ok(bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}

fn decode_utf16_strict(utf16: &[u16]) -> Result<String> {
    String::from_utf16(utf16).context("UNICODE_STRING 包含无效的 UTF-16")
}

pub(crate) fn validate_file_object_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|character| {
            let codepoint = u32::from(character);
            !character.is_control()
                && character != '\u{fffd}'
                && !(0xfdd0..=0xfdef).contains(&codepoint)
                && codepoint & 0xffff != 0xfffe
                && codepoint & 0xffff != 0xffff
        })
}

pub(crate) fn validate_unverified_file_object_name(name: &str) -> bool {
    if name.starts_with(['\\', ':']) || name.contains('\\') {
        return true;
    }

    let characters: Vec<char> = name.chars().collect();
    if characters.len() < 2 {
        return false;
    }
    if name.is_ascii() {
        return characters.len() >= 3
            && characters
                .iter()
                .any(|character| character.is_ascii_alphanumeric())
            && characters.iter().all(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(
                        character,
                        ' ' | '.' | '_' | '-' | '$' | '(' | ')' | '[' | ']'
                    )
            });
    }

    characters
        .iter()
        .any(|character| is_cjk_ideograph(*character))
        && characters.iter().all(|character| {
            is_cjk_ideograph(*character)
                || character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    ' ' | '.' | '_' | '-' | '$' | '(' | ')' | '[' | ']'
                )
        })
}

fn is_cjk_ideograph(character: char) -> bool {
    matches!(
        u32::from(character),
        0x3400..=0x4dbf
            | 0x4e00..=0x9fff
            | 0x20000..=0x2a6df
            | 0x2a700..=0x2ebef
            | 0x30000..=0x323af
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_extents_only_merge_when_file_and_memory_are_contiguous() {
        let mut extents = Vec::new();
        push_extent(&mut extents, 0, 0x1000, 0x2000, "physical");
        push_extent(&mut extents, 0x1000, 0x1000, 0x3000, "physical");
        push_extent(&mut extents, 0x3000, 0x1000, 0x4000, "physical");
        assert_eq!(extents.len(), 2);
        assert_eq!(extents[0].length, 0x2000);
        assert_eq!(extent_output_size(&extents), 0x4000);
    }

    #[test]
    fn overlapping_image_pages_keep_last_writer_and_unique_coverage() {
        let mut extents = Vec::new();
        push_extent(&mut extents, 0, 8192, 0x10000, "physical");
        push_extent(&mut extents, 1024, 4096, 0x20000, "physical");
        push_extent(&mut extents, 512, 1024, 0x30000, "physical");
        let extents = normalize_written_extents(extents);
        let ranges: Vec<_> = extents
            .iter()
            .map(|e| (e.file_offset, e.length, e.memory_address))
            .collect();
        assert_eq!(
            ranges,
            vec![
                (0, 512, 0x10000),
                (512, 1024, 0x30000),
                (1536, 3584, 0x20200),
                (5120, 3072, 0x11400)
            ]
        );
        assert_eq!(extents.iter().map(|e| e.length).sum::<u64>(), 8192);
    }

    #[test]
    fn resident_pte_decoder_accepts_hardware_and_transition_pages() {
        assert_eq!(
            resident_pte_physical(0x0000_0000_0300_0021),
            Some(0x0300_0000)
        );
        assert_eq!(
            resident_pte_physical(0x0000_0000_4d1f_08c0),
            Some(0x4d1f_0000)
        );
        assert_eq!(
            resident_pte_physical(0x0000_2000_40c1_5880),
            Some(0x40c1_5000)
        );
    }

    #[test]
    fn resident_pte_decoder_rejects_prototype_and_empty_entries() {
        assert_eq!(resident_pte_physical(0), None);
        assert_eq!(resident_pte_physical(0x400), None);
        assert_eq!(resident_pte_physical(0x0c00), None);
        assert_eq!(resident_pte_physical(1), None);
    }

    #[test]
    fn file_object_name_validation_accepts_paths_unicode_and_streams() {
        assert!(validate_file_object_name(
            "\\Windows\\System32\\kernel32.dll"
        ));
        assert!(validate_file_object_name("\\用户\\桌面\\答案.txt"));
        assert!(validate_file_object_name("\\$Directory"));
        assert!(validate_file_object_name(":WofCompressedData"));
        assert!(validate_file_object_name("单文件名.txt"));
    }

    #[test]
    fn file_object_name_validation_rejects_reused_structure_bytes() {
        assert!(!validate_file_object_name(""));
        assert!(!validate_file_object_name(
            "\\Windows\\System32\\svchost.exe\0随机结构"
        ));
        assert!(!validate_file_object_name("name\u{001f}.txt"));
        assert!(!validate_file_object_name("name\u{0085}.txt"));
        assert!(!validate_file_object_name("name\u{fffd}.txt"));
        assert!(!validate_file_object_name("name\u{fdd0}.txt"));
        assert!(!validate_file_object_name("name\u{10ffff}.txt"));
    }

    #[test]
    fn unverified_file_names_need_path_or_filename_structure() {
        assert!(validate_unverified_file_object_name(
            "\\Users\\Public\\Desktop\\微信.lnk"
        ));
        assert!(validate_unverified_file_object_name(":WofCompressedData"));
        assert!(validate_unverified_file_object_name("report.txt"));
        assert!(validate_unverified_file_object_name("答案.txt"));
        assert!(validate_unverified_file_object_name("OLE3B4"));
        assert!(!validate_unverified_file_object_name("錗"));
        assert!(!validate_unverified_file_object_name("新ჷ"));
        assert!(!validate_unverified_file_object_name("\"\""));
    }

    #[test]
    fn file_object_name_units_stop_at_the_first_nul() {
        let mut units: Vec<u16> = "\\Windows\\System32\\svchost.exe".encode_utf16().collect();
        units.extend([0, 0xffff, 0xd800]);
        assert_eq!(
            decode_file_object_name(&units).unwrap(),
            "\\Windows\\System32\\svchost.exe"
        );
    }

    #[test]
    fn unicode_string_decoder_rejects_unpaired_surrogates() {
        assert_eq!(decode_utf16_strict(&[0x7b54, 0x6848]).unwrap(), "答案");
        assert!(decode_utf16_strict(&[0xd800]).is_err());
        assert!(decode_utf16_strict(&[0xdc00]).is_err());
    }

    #[test]
    fn filescan_csv_has_excel_bom_and_quotes_names() {
        let report = FileScanReport {
            records: vec![FileScanRecord {
                file_object: 0xffff_8000_0000_1230,
                physical_address: 0x4560,
                object_header: 0xffff_8000_0000_1200,
                pool_header_physical: 0x44e0,
                pool_allocation_size: 0x190,
                name: Some("\\目录\\a,\"b.csv".to_owned()),
                device_object: 0xffff_8000_0000_2000,
                section_object_pointer: 0xffff_8000_0000_3000,
                data_section_object: 0xffff_8000_0000_4000,
                shared_cache_map: 0,
                image_section_object: 0,
                flags: 0x1234,
                delete_pending: false,
                object_type_verified: true,
            }],
            complete: true,
            pool_tag_hits: 1,
            physical_candidates: 1,
            reverse_mapped_candidates: 1,
            scan_seconds: 0.1,
            scan_gib_per_second: 1.0,
            timing: FileScanTiming::default(),
            warnings: Vec::new(),
        };
        let mut output = Vec::new();
        write_file_scan_csv(&report, &mut output).unwrap();
        assert!(output.starts_with(b"\xef\xbb\xbf"));
        let mut reader = csv::Reader::from_reader(&output[3..]);
        let row = reader.records().next().unwrap().unwrap();
        assert_eq!(&row[0], "0xffff800000001230");
        assert_eq!(&row[5], "\\目录\\a,\"b.csv");
        assert_eq!(&row[11], "false");
        assert_eq!(&row[12], "true");
    }
}
