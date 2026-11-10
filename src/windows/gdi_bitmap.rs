use std::collections::{HashMap, HashSet};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::plugins::{VadRecord, list_vads};
use super::{ProcessRecord, WindowsKernelContext, list_processes};
use crate::address::{VirtualAddressRegion, VirtualMapping, X64AddressSpace};
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::profile::KernelProfile;

const SCAN_CHUNK_SIZE: usize = 1024 * 1024;
const COPY_BUFFER_SIZE: usize = 1024 * 1024;
const MAX_MAPPING_RECORDS: usize = 262_144;
const MAX_HEADER_HITS: usize = 1_000_000;
const DIB_HEADER_SIZES: [u32; 6] = [12, 40, 52, 56, 108, 124];

#[derive(Debug, Clone)]
pub struct GdiBitmapOptions {
    pub pid: Option<u64>,
    pub output: PathBuf,
    pub limit: usize,
    pub max_dimension: u32,
    pub max_bitmap_bytes: u64,
    pub force: bool,
}

#[derive(Debug, Serialize)]
pub struct GdiBitmapReport {
    pub records: Vec<GdiBitmapRecord>,
    pub manifest: PathBuf,
    pub processes_examined: usize,
    pub vads_examined: usize,
    pub mapped_bytes_examined: u64,
    pub missing_bytes: u64,
    pub header_hits: usize,
    pub validated_headers: usize,
    pub exported_bitmaps: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct GdiBitmapRecord {
    pub pid: u64,
    pub process: String,
    pub vad: u64,
    pub vad_start: u64,
    pub vad_end: u64,
    pub structure_address: Option<u64>,
    pub header_address: u64,
    pub pixel_address: u64,
    pub source: &'static str,
    pub asset_kind: &'static str,
    pub header_kind: &'static str,
    pub width: u32,
    pub height: u32,
    pub top_down: bool,
    pub bits_per_pixel: u16,
    pub compression: &'static str,
    pub row_stride: u64,
    pub pixel_bytes: u64,
    pub output: Option<PathBuf>,
    pub dib_sha256: Option<String>,
    pub duplicate_of_header_address: Option<u64>,
    pub complete: bool,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct DibLayout {
    header_kind: &'static str,
    width: u32,
    height: u32,
    top_down: bool,
    bits_per_pixel: u16,
    compression: &'static str,
    prefix_bytes: u64,
    row_stride: u64,
    pixel_bytes: u64,
}

struct DibSectionCandidate {
    structure_address: u64,
    header_address: u64,
    pixel_address: u64,
    layout: DibLayout,
    prefix: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn recover_gdi_bitmaps(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &GdiBitmapOptions,
    cancellation: &CancellationToken,
) -> Result<GdiBitmapReport> {
    validate_options(options)?;
    cancellation.check_cancelled()?;
    let mut manifest_policy = OutputPolicy::new(options.force);
    for source in image.sources() {
        manifest_policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    manifest_policy.output(
        OutputTarget::directory("gdi_bitmap", &options.output)
            .with_owned_file("gdi-bitmap-report.json"),
    );
    manifest_policy.prepare_directories()?;

    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut records = Vec::new();
    let mut warnings = processes
        .warnings
        .iter()
        .map(|warning| format!("pslist/{}: {}", warning.kind, warning.message))
        .collect::<Vec<_>>();
    let mut processes_examined = 0usize;
    let mut vads_examined = 0usize;
    let mut mapped_bytes_examined = 0u64;
    let mut missing_bytes = 0u64;
    let mut header_hits = 0usize;
    let mut validated_headers = 0usize;
    let mut exported_bitmaps = 0usize;
    let mut complete = processes.complete;
    let mut seen = HashSet::new();
    let mut exported_by_content: HashMap<(u32, u32, u16, String), (u64, PathBuf)> = HashMap::new();
    let matcher = dib_header_matcher()?;

    'processes: for process in processes
        .processes
        .iter()
        .filter(|process| options.pid.is_none_or(|pid| process.pid == pid))
    {
        cancellation.check_cancelled()?;
        processes_examined += 1;
        let Some(space) = process_address_space(image, process) else {
            complete = false;
            push_warning_limited(
                &mut warnings,
                format!("PID {} 没有可读的进程页表", process.pid),
            );
            continue;
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
        complete &= vads.complete;
        warnings.extend(
            vads.warnings
                .into_iter()
                .take(64)
                .map(|warning| format!("PID {}: {warning}", process.pid)),
        );
        let mut eligible = vads
            .records
            .iter()
            .filter(|vad| vad.private_memory || vad.file.is_none())
            .collect::<Vec<_>>();
        eligible.sort_unstable_by_key(|vad| vad.start);
        vads_examined += eligible.len();
        if eligible.is_empty() {
            continue;
        }
        let mapping_report =
            match space.enumerate_mappings(VirtualAddressRegion::User, MAX_MAPPING_RECORDS) {
                Ok(report) => report,
                Err(error) => {
                    complete = false;
                    push_warning_limited(
                        &mut warnings,
                        format!("PID {} 的用户空间映射枚举失败：{error:#}", process.pid),
                    );
                    continue;
                }
            };
        complete &= !mapping_report.truncated;
        for warning in mapping_report.warnings.iter().take(64) {
            push_warning_limited(&mut warnings, format!("PID {}: {warning}", process.pid));
        }

        let mut vad_index = 0usize;
        for mapping in &mapping_report.mappings {
            cancellation.check_cancelled()?;
            while vad_index < eligible.len() && eligible[vad_index].end < mapping.virtual_start {
                vad_index += 1;
            }
            let mut candidate_vad = vad_index;
            while candidate_vad < eligible.len()
                && eligible[candidate_vad].start < mapping.virtual_end
            {
                let vad = eligible[candidate_vad];
                let start = mapping.virtual_start.max(vad.start);
                let end = mapping.virtual_end.min(vad.end.saturating_add(1));
                if start < end {
                    let scan =
                        scan_mapped_range(&space, start, end, &matcher, cancellation, |address| {
                            if header_hits == MAX_HEADER_HITS
                                || !seen.insert((process.pid, address))
                            {
                                return Ok(());
                            }
                            header_hits += 1;
                            if records.len() == options.limit {
                                return Ok(());
                            }
                            if let Some(candidate) = parse_dibsection_at(
                                &space,
                                address,
                                vad,
                                options.max_dimension,
                                options.max_bitmap_bytes,
                            ) {
                                validated_headers += 1;
                                let record = recover_candidate(
                                    image,
                                    &space,
                                    process,
                                    vad,
                                    "dibsection",
                                    Some(candidate.structure_address),
                                    candidate.header_address,
                                    candidate.pixel_address,
                                    candidate.layout,
                                    candidate.prefix,
                                    &mapping_report.mappings,
                                    options,
                                    cancellation,
                                )?;
                                complete &= record.complete;
                                store_record(
                                    record,
                                    &mut records,
                                    &mut exported_by_content,
                                    &mut exported_bitmaps,
                                    &mut warnings,
                                );
                                return Ok(());
                            }
                            let Some(layout) = parse_dib_at(
                                &space,
                                address,
                                vad,
                                options.max_dimension,
                                options.max_bitmap_bytes,
                            )?
                            else {
                                return Ok(());
                            };
                            validated_headers += 1;
                            let mut prefix = vec![0u8; layout.prefix_bytes as usize];
                            if space.read_virtual(address, &mut prefix).is_err() {
                                return Ok(());
                            }
                            let record = recover_candidate(
                                image,
                                &space,
                                process,
                                vad,
                                "packed_dib",
                                None,
                                address,
                                address + layout.prefix_bytes,
                                layout,
                                prefix,
                                &mapping_report.mappings,
                                options,
                                cancellation,
                            )?;
                            complete &= record.complete;
                            store_record(
                                record,
                                &mut records,
                                &mut exported_by_content,
                                &mut exported_bitmaps,
                                &mut warnings,
                            );
                            Ok(())
                        })?;
                    mapped_bytes_examined = mapped_bytes_examined.saturating_add(scan.0);
                    missing_bytes = missing_bytes.saturating_add(scan.1);
                    if scan.1 != 0 {
                        complete = false;
                    }
                }
                if records.len() == options.limit || header_hits == MAX_HEADER_HITS {
                    break 'processes;
                }
                candidate_vad += 1;
            }
        }
    }

    if let Some(pid) = options.pid
        && processes_examined == 0
    {
        ensure!(false, "未找到 PID {pid} 的活动进程");
    }
    if records.len() == options.limit {
        complete = false;
        push_warning_limited(
            &mut warnings,
            format!("GDI 位图结果达到 {} 条上限", options.limit),
        );
    }
    if header_hits == MAX_HEADER_HITS {
        complete = false;
        push_warning_limited(
            &mut warnings,
            format!("DIB 头候选达到 {MAX_HEADER_HITS} 条安全上限"),
        );
    }
    if missing_bytes != 0 {
        push_warning_limited(
            &mut warnings,
            format!("有 {missing_bytes} 字节的已映射进程内存无法读取"),
        );
    }

    let manifest = options.output.join("gdi-bitmap-report.json");
    let report = GdiBitmapReport {
        records,
        manifest: manifest.clone(),
        processes_examined,
        vads_examined,
        mapped_bytes_examined,
        missing_bytes,
        header_hits,
        validated_headers,
        exported_bitmaps,
        complete,
        warnings,
    };
    manifest_policy.write_file_atomic(&manifest, |file| {
        serde_json::to_writer_pretty(BufWriter::new(file), &report)?;
        Ok(())
    })?;
    Ok(report)
}

fn validate_options(options: &GdiBitmapOptions) -> Result<()> {
    ensure!(options.limit > 0, "GDI 位图结果上限必须大于零");
    ensure!(
        (1..=65_535).contains(&options.max_dimension),
        "GDI 位图最大边长必须在 1 到 65535 之间"
    );
    ensure!(
        options.max_bitmap_bytes > 0,
        "单张 GDI 位图大小上限必须大于零"
    );
    Ok(())
}

fn dib_header_matcher() -> Result<AhoCorasick> {
    let patterns = DIB_HEADER_SIZES.map(u32::to_le_bytes);
    AhoCorasick::new(patterns).context("创建 DIB 头扫描器失败")
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

fn scan_mapped_range(
    space: &X64AddressSpace<'_>,
    start: u64,
    end: u64,
    matcher: &AhoCorasick,
    cancellation: &CancellationToken,
    mut callback: impl FnMut(u64) -> Result<()>,
) -> Result<(u64, u64)> {
    let mut buffer = vec![0u8; SCAN_CHUNK_SIZE];
    let mut address = start;
    let mut bytes_examined = 0u64;
    let mut missing_bytes = 0u64;
    while address < end {
        cancellation.check_cancelled()?;
        let take = (end - address).min(buffer.len() as u64) as usize;
        if space.read_virtual(address, &mut buffer[..take]).is_ok() {
            bytes_examined += take as u64;
            scan_dib_signatures(&buffer[..take], address, matcher, &mut callback)?;
        } else {
            let mut page_address = address;
            let chunk_end = address + take as u64;
            while page_address < chunk_end {
                cancellation.check_cancelled()?;
                let page_take = (chunk_end - page_address).min(0x1000) as usize;
                if space
                    .read_virtual(page_address, &mut buffer[..page_take])
                    .is_ok()
                {
                    bytes_examined += page_take as u64;
                    scan_dib_signatures(
                        &buffer[..page_take],
                        page_address,
                        matcher,
                        &mut callback,
                    )?;
                } else {
                    missing_bytes += page_take as u64;
                }
                page_address += page_take as u64;
            }
        }
        address += take as u64;
    }
    Ok((bytes_examined, missing_bytes))
}

fn scan_dib_signatures(
    bytes: &[u8],
    base: u64,
    matcher: &AhoCorasick,
    callback: &mut impl FnMut(u64) -> Result<()>,
) -> Result<()> {
    for matched in matcher.find_overlapping_iter(bytes) {
        let address = base + matched.start() as u64;
        if address & 3 == 0 {
            callback(address)?;
        }
    }
    Ok(())
}

fn parse_dib_at(
    space: &X64AddressSpace<'_>,
    address: u64,
    vad: &VadRecord,
    max_dimension: u32,
    max_bitmap_bytes: u64,
) -> Result<Option<DibLayout>> {
    let mut size_bytes = [0u8; 4];
    if space.read_virtual(address, &mut size_bytes).is_err() {
        return Ok(None);
    }
    let header_size = u32::from_le_bytes(size_bytes);
    if !DIB_HEADER_SIZES.contains(&header_size) {
        return Ok(None);
    }
    let mut header = vec![0u8; header_size as usize];
    if space.read_virtual(address, &mut header).is_err() {
        return Ok(None);
    }
    let Some(layout) = parse_dib_header(&header, max_dimension, max_bitmap_bytes) else {
        return Ok(None);
    };
    let Some(end) = layout
        .prefix_bytes
        .checked_add(layout.pixel_bytes)
        .and_then(|length| address.checked_add(length))
    else {
        return Ok(None);
    };
    if end > vad.end.saturating_add(1) {
        return Ok(None);
    }
    Ok(Some(layout))
}

fn parse_dibsection_at(
    space: &X64AddressSpace<'_>,
    header_address: u64,
    vad: &VadRecord,
    max_dimension: u32,
    max_bitmap_bytes: u64,
) -> Option<DibSectionCandidate> {
    let structure_address = header_address.checked_sub(32)?;
    if structure_address < vad.start
        || structure_address
            .checked_add(104)
            .is_none_or(|end| end > vad.end.saturating_add(1))
    {
        return None;
    }
    let mut bytes = [0u8; 104];
    if space.read_virtual(structure_address, &mut bytes).is_err() {
        return None;
    }
    let (pixel_address, layout, prefix) =
        parse_dibsection_bytes(&bytes, max_dimension, max_bitmap_bytes)?;
    Some(DibSectionCandidate {
        structure_address,
        header_address,
        pixel_address,
        layout,
        prefix,
    })
}

fn parse_dibsection_bytes(
    bytes: &[u8],
    max_dimension: u32,
    max_bitmap_bytes: u64,
) -> Option<(u64, DibLayout, Vec<u8>)> {
    if bytes.len() < 104 {
        return None;
    }
    let bitmap_type = read_i32(bytes, 0)?;
    let bitmap_width = read_i32(bytes, 4)?;
    let bitmap_height = read_i32(bytes, 8)?;
    let bitmap_width_bytes = read_i32(bytes, 12)?;
    let bitmap_planes = read_u16(bytes, 16)?;
    let bitmap_bits_per_pixel = read_u16(bytes, 18)?;
    let pixel_address = read_u64(bytes, 24)?;
    if bitmap_type != 0
        || bitmap_width <= 0
        || bitmap_height == 0
        || bitmap_height == i32::MIN
        || bitmap_width_bytes <= 0
        || bitmap_planes != 1
        || pixel_address == 0
        || pixel_address >= 0x0000_8000_0000_0000
    {
        return None;
    }
    let layout = parse_dib_header(&bytes[32..72], max_dimension, max_bitmap_bytes)?;
    if layout.bits_per_pixel < 16
        || layout.compression == "alpha_bitfields"
        || u32::try_from(bitmap_width).ok() != Some(layout.width)
        || bitmap_height.unsigned_abs() != layout.height
        || bitmap_bits_per_pixel != layout.bits_per_pixel
        || u64::try_from(bitmap_width_bytes).ok() != Some(layout.row_stride)
        || u64::try_from(bitmap_width_bytes)
            .ok()
            .and_then(|stride| stride.checked_mul(u64::from(layout.height)))
            != Some(layout.pixel_bytes)
    {
        return None;
    }
    let mut prefix = bytes[32..72].to_vec();
    if layout.compression == "bitfields" {
        let red = read_u32(bytes, 72)?;
        let green = read_u32(bytes, 76)?;
        let blue = read_u32(bytes, 80)?;
        if !valid_color_masks(red, green, blue, layout.bits_per_pixel) {
            return None;
        }
        prefix.extend_from_slice(&bytes[72..84]);
    }
    if prefix.len() as u64 != layout.prefix_bytes {
        return None;
    }
    Some((pixel_address, layout, prefix))
}

fn valid_color_masks(red: u32, green: u32, blue: u32, bits_per_pixel: u16) -> bool {
    if red == 0
        || green == 0
        || blue == 0
        || red & green != 0
        || red & blue != 0
        || green & blue != 0
    {
        return false;
    }
    let allowed = if bits_per_pixel == 32 {
        u32::MAX
    } else {
        (1u32 << bits_per_pixel) - 1
    };
    (red | green | blue) & !allowed == 0
}

fn parse_dib_header(header: &[u8], max_dimension: u32, max_bitmap_bytes: u64) -> Option<DibLayout> {
    let header_size = read_u32(header, 0)?;
    if header_size == 12 {
        let width = u32::from(read_u16(header, 4)?);
        let height = u32::from(read_u16(header, 6)?);
        let planes = read_u16(header, 8)?;
        let bits_per_pixel = read_u16(header, 10)?;
        if planes != 1
            || width == 0
            || height == 0
            || width > max_dimension
            || height > max_dimension
            || bits_per_pixel != 24
        {
            return None;
        }
        return finish_layout(
            "bitmap_core_header",
            width,
            height,
            false,
            bits_per_pixel,
            "rgb",
            12,
            max_bitmap_bytes,
        );
    }
    if !matches!(header_size, 40 | 52 | 56 | 108 | 124) {
        return None;
    }
    let width_signed = read_i32(header, 4)?;
    let height_signed = read_i32(header, 8)?;
    let planes = read_u16(header, 12)?;
    let bits_per_pixel = read_u16(header, 14)?;
    let compression = read_u32(header, 16)?;
    let image_size = u64::from(read_u32(header, 20)?);
    let colors_used = u64::from(read_u32(header, 32)?);
    if width_signed <= 0 || height_signed == 0 || height_signed == i32::MIN || planes != 1 {
        return None;
    }
    let width = width_signed as u32;
    let height = height_signed.unsigned_abs();
    if width > max_dimension
        || height > max_dimension
        || !matches!(bits_per_pixel, 1 | 4 | 8 | 16 | 24 | 32)
    {
        return None;
    }
    let compression_name = match compression {
        0 => "rgb",
        3 if matches!(bits_per_pixel, 16 | 32) => "bitfields",
        6 if matches!(bits_per_pixel, 16 | 32) => "alpha_bitfields",
        _ => return None,
    };
    let maximum_colors = if bits_per_pixel <= 8 {
        1u64 << bits_per_pixel
    } else {
        256
    };
    if colors_used > maximum_colors {
        return None;
    }
    let palette_colors = if colors_used != 0 {
        colors_used
    } else if bits_per_pixel <= 8 {
        1u64 << bits_per_pixel
    } else {
        0
    };
    let external_masks = match (header_size, compression) {
        (40, 3) => 12u64,
        (40, 6) => 16u64,
        _ => 0,
    };
    let prefix_bytes = u64::from(header_size)
        .checked_add(external_masks)?
        .checked_add(palette_colors.checked_mul(4)?)?;
    let layout = finish_layout(
        match header_size {
            40 => "bitmap_info_header",
            52 => "bitmap_v2_info_header",
            56 => "bitmap_v3_info_header",
            108 => "bitmap_v4_header",
            124 => "bitmap_v5_header",
            _ => return None,
        },
        width,
        height,
        height_signed < 0,
        bits_per_pixel,
        compression_name,
        prefix_bytes,
        max_bitmap_bytes,
    )?;
    if image_size != 0 && image_size != layout.pixel_bytes {
        return None;
    }
    Some(layout)
}

#[allow(clippy::too_many_arguments)]
fn finish_layout(
    header_kind: &'static str,
    width: u32,
    height: u32,
    top_down: bool,
    bits_per_pixel: u16,
    compression: &'static str,
    prefix_bytes: u64,
    max_bitmap_bytes: u64,
) -> Option<DibLayout> {
    let row_bits = u64::from(width).checked_mul(u64::from(bits_per_pixel))?;
    let row_stride = row_bits.checked_add(31)?.checked_div(32)?.checked_mul(4)?;
    let pixel_bytes = row_stride.checked_mul(u64::from(height))?;
    if pixel_bytes == 0 || pixel_bytes > max_bitmap_bytes {
        return None;
    }
    Some(DibLayout {
        header_kind,
        width,
        height,
        top_down,
        bits_per_pixel,
        compression,
        prefix_bytes,
        row_stride,
        pixel_bytes,
    })
}

fn range_is_fully_mapped(mappings: &[VirtualMapping], start: u64, end: u64) -> bool {
    if start >= end {
        return false;
    }
    let mut cursor = start;
    let mut index = mappings.partition_point(|mapping| mapping.virtual_end <= start);
    while cursor < end && index < mappings.len() {
        let mapping = &mappings[index];
        if mapping.virtual_start > cursor || mapping.virtual_end <= cursor {
            return false;
        }
        cursor = mapping.virtual_end.min(end);
        index += 1;
    }
    cursor == end
}

fn bitmap_record(
    process: &ProcessRecord,
    vad: &VadRecord,
    source: &'static str,
    structure_address: Option<u64>,
    header_address: u64,
    pixel_address: u64,
    layout: DibLayout,
) -> GdiBitmapRecord {
    GdiBitmapRecord {
        pid: process.pid,
        process: process.name.clone(),
        vad: vad.node,
        vad_start: vad.start,
        vad_end: vad.end,
        structure_address,
        header_address,
        pixel_address,
        source,
        asset_kind: classify_asset(layout),
        header_kind: layout.header_kind,
        width: layout.width,
        height: layout.height,
        top_down: layout.top_down,
        bits_per_pixel: layout.bits_per_pixel,
        compression: layout.compression,
        row_stride: layout.row_stride,
        pixel_bytes: layout.pixel_bytes,
        output: None,
        dib_sha256: None,
        duplicate_of_header_address: None,
        complete: false,
        warning: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn recover_candidate(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    process: &ProcessRecord,
    vad: &VadRecord,
    source: &'static str,
    structure_address: Option<u64>,
    header_address: u64,
    pixel_address: u64,
    layout: DibLayout,
    prefix: Vec<u8>,
    mappings: &[VirtualMapping],
    options: &GdiBitmapOptions,
    cancellation: &CancellationToken,
) -> Result<GdiBitmapRecord> {
    let mut record = bitmap_record(
        process,
        vad,
        source,
        structure_address,
        header_address,
        pixel_address,
        layout,
    );
    let fully_mapped = pixel_address
        .checked_add(layout.pixel_bytes)
        .is_some_and(|end| range_is_fully_mapped(mappings, pixel_address, end));
    if !fully_mapped {
        record.warning = Some("DIB 结构有效，但像素跨度包含未驻留页；未生成伪完整图片".to_owned());
        return Ok(record);
    }
    match export_bitmap(
        image,
        space,
        process,
        source,
        header_address,
        pixel_address,
        &prefix,
        layout,
        options,
        cancellation,
    ) {
        Ok((output, digest)) => {
            record.output = Some(output);
            record.dib_sha256 = Some(digest);
            record.complete = true;
        }
        Err(error) => {
            cancellation.check_cancelled()?;
            record.warning = Some(format!("位图导出失败：{error:#}"));
        }
    }
    Ok(record)
}

fn store_record(
    mut record: GdiBitmapRecord,
    records: &mut Vec<GdiBitmapRecord>,
    exported_by_content: &mut HashMap<(u32, u32, u16, String), (u64, PathBuf)>,
    exported_bitmaps: &mut usize,
    warnings: &mut Vec<String>,
) {
    let Some(output) = record.output.clone() else {
        records.push(record);
        return;
    };
    let Some(digest) = record.dib_sha256.clone() else {
        records.push(record);
        return;
    };
    let content_key = (record.width, record.height, record.bits_per_pixel, digest);
    if let Some((first_address, first_output)) = exported_by_content.get(&content_key) {
        // The digest is only known after atomic publication. Keep this command-owned output
        // instead of deleting a path which may have replaced an earlier run under --force.
        record.duplicate_of_header_address = Some(*first_address);
        *exported_bitmaps += 1;
        push_warning_limited(
            warnings,
            format!(
                "GDI 位图 {} 与 {} 内容相同；为保留原子发布证据未删除重复文件",
                output.display(),
                first_output.display()
            ),
        );
    } else {
        exported_by_content.insert(content_key, (record.header_address, output));
        *exported_bitmaps += 1;
    }
    records.push(record);
}

fn classify_asset(layout: DibLayout) -> &'static str {
    let area = u64::from(layout.width) * u64::from(layout.height);
    if layout.bits_per_pixel == 1 && layout.height == layout.width.saturating_mul(2) {
        "icon_mask"
    } else if layout.width <= 128 && layout.height <= 128 {
        "icon_or_control"
    } else if area >= 640 * 480 {
        "large_canvas"
    } else {
        "bitmap"
    }
}

#[allow(clippy::too_many_arguments)]
fn export_bitmap(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    process: &ProcessRecord,
    source: &str,
    evidence_address: u64,
    pixel_address: u64,
    prefix: &[u8],
    layout: DibLayout,
    options: &GdiBitmapOptions,
    cancellation: &CancellationToken,
) -> Result<(PathBuf, String)> {
    cancellation.check_cancelled()?;
    let process_name = sanitize_component(&process.name);
    let file_name = format!(
        "{}-pid{}-{}-{evidence_address:016x}-{}x{}-{}bpp.bmp",
        process_name, process.pid, source, layout.width, layout.height, layout.bits_per_pixel
    );
    let output = options.output.join(file_name);
    let mut policy = OutputPolicy::new(options.force);
    for source in image.sources() {
        policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    policy.output(OutputTarget::file("gdi_bitmap.bmp", &output));
    policy.preflight()?;
    let mut digest = None;
    policy.write_file_atomic(&output, |file| {
        let mut writer = BufWriter::new(file);
        ensure!(
            prefix.len() as u64 == layout.prefix_bytes,
            "DIB 前缀长度与结构声明不一致"
        );
        let bmp_size = 14u64
            .checked_add(prefix.len() as u64)
            .and_then(|size| size.checked_add(layout.pixel_bytes))
            .context("BMP 文件大小溢出")?;
        let pixel_offset = 14u64
            .checked_add(prefix.len() as u64)
            .context("BMP 像素偏移溢出")?;
        ensure!(
            bmp_size <= u64::from(u32::MAX) && pixel_offset <= u64::from(u32::MAX),
            "BMP 文件超过 32 位格式上限"
        );
        writer.write_all(&bmp_file_header(bmp_size as u32, pixel_offset as u32))?;
        let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
        let mut hasher = Sha256::new();
        writer.write_all(prefix)?;
        hasher.update(prefix);
        read_virtual_to_writer(
            space,
            pixel_address,
            layout.pixel_bytes,
            &mut buffer,
            &mut writer,
            Some(&mut hasher),
            cancellation,
        )?;
        writer.flush()?;
        cancellation.check_cancelled()?;
        digest = Some(hex::encode(hasher.finalize()));
        Ok(())
    })?;
    Ok((output, digest.context("GDI 位图写出未生成摘要")?))
}

#[allow(clippy::too_many_arguments)]
fn read_virtual_to_writer(
    space: &X64AddressSpace<'_>,
    mut address: u64,
    mut length: u64,
    buffer: &mut [u8],
    writer: &mut impl Write,
    mut hasher: Option<&mut Sha256>,
    cancellation: &CancellationToken,
) -> Result<()> {
    while length != 0 {
        cancellation.check_cancelled()?;
        let take = length.min(buffer.len() as u64) as usize;
        space
            .read_virtual(address, &mut buffer[..take])
            .with_context(|| format!("读取 DIB 虚拟地址 {address:#x} 失败"))?;
        writer.write_all(&buffer[..take])?;
        if let Some(hasher) = hasher.as_deref_mut() {
            hasher.update(&buffer[..take]);
        }
        address += take as u64;
        length -= take as u64;
    }
    Ok(())
}

fn bmp_file_header(file_size: u32, pixel_offset: u32) -> [u8; 14] {
    let mut header = [0u8; 14];
    header[0..2].copy_from_slice(b"BM");
    header[2..6].copy_from_slice(&file_size.to_le_bytes());
    header[10..14].copy_from_slice(&pixel_offset.to_le_bytes());
    header
}

fn sanitize_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| match character {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            character if character.is_control() => '_',
            character => character,
        })
        .collect::<String>();
    let sanitized = sanitized.trim_matches([' ', '.']);
    if sanitized.is_empty() {
        "process".to_owned()
    } else {
        sanitized.to_owned()
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn push_warning_limited(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 256 {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_header(width: i32, height: i32, bits: u16, compression: u32) -> [u8; 124] {
        let mut header = [0u8; 124];
        header[0..4].copy_from_slice(&40u32.to_le_bytes());
        header[4..8].copy_from_slice(&width.to_le_bytes());
        header[8..12].copy_from_slice(&height.to_le_bytes());
        header[12..14].copy_from_slice(&1u16.to_le_bytes());
        header[14..16].copy_from_slice(&bits.to_le_bytes());
        header[16..20].copy_from_slice(&compression.to_le_bytes());
        header
    }

    #[test]
    fn parses_padded_24_bit_rows() {
        let header = info_header(2, 2, 24, 0);
        let layout = parse_dib_header(&header, 16_384, 1024).unwrap();
        assert_eq!(layout.header_kind, "bitmap_info_header");
        assert_eq!(layout.prefix_bytes, 40);
        assert_eq!(layout.row_stride, 8);
        assert_eq!(layout.pixel_bytes, 16);
        assert!(!layout.top_down);
    }

    #[test]
    fn parses_top_down_v5_argb_bitmap() {
        let mut header = info_header(1920, -1080, 32, 3);
        header[0..4].copy_from_slice(&124u32.to_le_bytes());
        let layout = parse_dib_header(&header, 4096, 16 * 1024 * 1024).unwrap();
        assert_eq!(layout.header_kind, "bitmap_v5_header");
        assert_eq!(layout.prefix_bytes, 124);
        assert_eq!(layout.pixel_bytes, 1920 * 1080 * 4);
        assert!(layout.top_down);
    }

    #[test]
    fn rejects_compressed_or_oversized_candidates() {
        assert!(parse_dib_header(&info_header(640, 480, 24, 1), 4096, u64::MAX).is_none());
        assert!(parse_dib_header(&info_header(20_000, 480, 24, 0), 4096, u64::MAX).is_none());
        assert!(parse_dib_header(&info_header(640, 480, 12, 0), 4096, u64::MAX).is_none());
    }

    #[test]
    fn rejects_inconsistent_declared_pixel_size() {
        let mut header = info_header(32, 64, 1, 0);
        header[20..24].copy_from_slice(&4224u32.to_le_bytes());
        assert!(parse_dib_header(&header, 4096, u64::MAX).is_none());
    }

    #[test]
    fn only_accepts_true_color_legacy_core_headers() {
        let mut header = [0u8; 12];
        header[0..4].copy_from_slice(&12u32.to_le_bytes());
        header[4..6].copy_from_slice(&5u16.to_le_bytes());
        header[6..8].copy_from_slice(&384u16.to_le_bytes());
        header[8..10].copy_from_slice(&1u16.to_le_bytes());
        header[10..12].copy_from_slice(&8u16.to_le_bytes());
        assert!(parse_dib_header(&header, 4096, u64::MAX).is_none());
        header[10..12].copy_from_slice(&24u16.to_le_bytes());
        assert!(parse_dib_header(&header, 4096, u64::MAX).is_some());
    }

    #[test]
    fn follows_x64_dibsection_pixel_pointer() {
        let mut section = [0u8; 104];
        section[4..8].copy_from_slice(&800i32.to_le_bytes());
        section[8..12].copy_from_slice(&600i32.to_le_bytes());
        section[12..16].copy_from_slice(&3200i32.to_le_bytes());
        section[16..18].copy_from_slice(&1u16.to_le_bytes());
        section[18..20].copy_from_slice(&32u16.to_le_bytes());
        section[24..32].copy_from_slice(&0x0000_0123_4567_8000u64.to_le_bytes());
        section[32..36].copy_from_slice(&40u32.to_le_bytes());
        section[36..40].copy_from_slice(&800i32.to_le_bytes());
        section[40..44].copy_from_slice(&600i32.to_le_bytes());
        section[44..46].copy_from_slice(&1u16.to_le_bytes());
        section[46..48].copy_from_slice(&32u16.to_le_bytes());
        section[52..56].copy_from_slice(&(800u32 * 600 * 4).to_le_bytes());

        let (pixel_address, layout, prefix) =
            parse_dibsection_bytes(&section, 4096, 16 * 1024 * 1024).unwrap();
        assert_eq!(pixel_address, 0x0000_0123_4567_8000);
        assert_eq!(layout.width, 800);
        assert_eq!(layout.height, 600);
        assert_eq!(layout.row_stride, 3200);
        assert_eq!(layout.pixel_bytes, 800 * 600 * 4);
        assert_eq!(prefix.len(), 40);
    }

    #[test]
    fn rejects_dibsection_with_inconsistent_bitmap_stride() {
        let mut section = [0u8; 104];
        section[4..8].copy_from_slice(&800i32.to_le_bytes());
        section[8..12].copy_from_slice(&600i32.to_le_bytes());
        section[12..16].copy_from_slice(&3196i32.to_le_bytes());
        section[16..18].copy_from_slice(&1u16.to_le_bytes());
        section[18..20].copy_from_slice(&32u16.to_le_bytes());
        section[24..32].copy_from_slice(&0x0000_0123_4567_8000u64.to_le_bytes());
        section[32..36].copy_from_slice(&40u32.to_le_bytes());
        section[36..40].copy_from_slice(&800i32.to_le_bytes());
        section[40..44].copy_from_slice(&600i32.to_le_bytes());
        section[44..46].copy_from_slice(&1u16.to_le_bytes());
        section[46..48].copy_from_slice(&32u16.to_le_bytes());
        section[52..56].copy_from_slice(&(800u32 * 600 * 4).to_le_bytes());

        assert!(parse_dibsection_bytes(&section, 4096, 16 * 1024 * 1024).is_none());
    }

    #[test]
    fn requires_complete_mapping_coverage() {
        let mappings = vec![
            VirtualMapping {
                virtual_start: 0x1000,
                virtual_end: 0x2000,
                physical_start: 0,
                length: 0x1000,
                source_page_size: 0x1000,
                writable: true,
                user_accessible: true,
                executable: false,
                global: false,
            },
            VirtualMapping {
                virtual_start: 0x2000,
                virtual_end: 0x3000,
                physical_start: 0x5000,
                length: 0x1000,
                source_page_size: 0x1000,
                writable: true,
                user_accessible: true,
                executable: false,
                global: false,
            },
        ];
        assert!(range_is_fully_mapped(&mappings, 0x1800, 0x2800));
        assert!(!range_is_fully_mapped(&mappings, 0x0800, 0x1800));
        assert!(!range_is_fully_mapped(&mappings, 0x2800, 0x3800));
    }

    #[test]
    fn creates_standard_bitmap_file_header() {
        let header = bmp_file_header(1234, 54);
        assert_eq!(&header[0..2], b"BM");
        assert_eq!(u32::from_le_bytes(header[2..6].try_into().unwrap()), 1234);
        assert_eq!(u32::from_le_bytes(header[10..14].try_into().unwrap()), 54);
    }

    #[test]
    fn sanitizes_windows_file_names() {
        assert_eq!(sanitize_component("a<b>:c?.exe"), "a_b__c_.exe");
        assert_eq!(sanitize_component("..."), "process");
    }
}
