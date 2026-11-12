//! Bounded recovery of CPU pixel buffers, independent of version-specific DWM vtables.
//! Geometry and pixel statistics nominate candidates; they do not establish window
//! ownership or capture time. Kernel candidates need several independent byte anchors.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use aho_corasick::AhoCorasickBuilder;
use anyhow::Result;
use serde::Serialize;

use super::dwm_surfaces::{WriteStats, write_bgra_bmp};
use super::gui_plugins::WindowRecord;
use super::plugins::list_vads_cancellable;
use super::{ProcessRecord, WindowsKernelContext, list_processes};
use crate::address::{VirtualAddressRegion, X64AddressSpace};
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::profile::KernelProfile;
use crate::progress::start_progress;

const MAX_SHAPES: usize = 128;
const MAX_SURFACES: usize = 32;
const MAX_FRAME_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_REFERENCES: usize = 4;
const ANCHOR_BYTES: usize = 128;
const MAX_ANCHOR_HITS: usize = 64;
const SCAN_CHUNK: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct GeometryMatch {
    pub session_id: u32,
    pub window_station: String,
    pub desktop: String,
    pub window_address: u64,
    pub window_pid: Option<u64>,
    pub rectangle: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct PixelSample {
    pub readable_pixels: usize,
    pub requested_pixels: usize,
    pub distinct_colors: usize,
    pub non_black_percent: f64,
    pub reserved_zero_or_ff_percent: f64,
    pub smooth_neighbor_percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PixelAnchorMatch {
    pub x: u32,
    pub y: u32,
    pub length: usize,
    pub reference_virtual_address: u64,
    pub matched_virtual_address: u64,
    pub matched_physical_address: u64,
    pub bgrx_hex: String,
}

#[derive(Debug, Serialize)]
pub struct PixelCandidate {
    pub render_kind: &'static str,
    pub pid: Option<u64>,
    pub process: Option<String>,
    pub process_parent_pid: Option<u64>,
    pub session_id: u32,
    pub directory_table_base: u64,
    pub pixel_address: u64,
    pub vad_node: Option<u64>,
    pub vad_private_memory: Option<bool>,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: &'static str,
    pub geometry_matches: Vec<GeometryMatch>,
    pub sample: PixelSample,
    pub reference_output: Option<PathBuf>,
    pub anchors: Vec<PixelAnchorMatch>,
    pub recovered_bytes: u64,
    pub total_bytes: u64,
    pub coverage_percent: f64,
    pub bytes_complete: bool,
    pub pixel_sha256: String,
    pub bgr_sha256: String,
    pub output_sha256: String,
    pub output: PathBuf,
    pub recovery_manifest: PathBuf,
    pub interpretation: &'static str,
}

#[derive(Debug, Default, Serialize)]
pub struct PixelRecoveryReport {
    pub records: Vec<PixelCandidate>,
    pub processes_examined: usize,
    pub size_candidates: usize,
    pub sample_rejections: usize,
    pub unreadable_candidates: usize,
    pub anchor_bytes_scanned: u64,
    pub anchor_hits: usize,
    pub search_complete: bool,
    pub warnings: Vec<String>,
    pub scope: &'static str,
}

#[derive(Clone)]
struct Shape {
    width: u32,
    height: u32,
    session: u32,
    geometry: Vec<GeometryMatch>,
}

struct Reference {
    record_index: usize,
    dtb: u64,
    pixels: u64,
    width: u32,
    height: u32,
    stride: u32,
}

struct Anchor {
    reference: usize,
    x: u32,
    y: u32,
    offset: u64,
    bytes: Vec<u8>,
}

pub fn recover_pixel_candidates(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    windows: &[WindowRecord],
    options: &super::desktop_reconstruct::DesktopReconstructOptions,
    cancellation: &CancellationToken,
) -> Result<PixelRecoveryReport> {
    let mut report = PixelRecoveryReport {
        search_complete: true,
        scope: "x64 csrss/dwm and window owners/same-image direct children; same-session anonymous VADs; window/client geometry, largest first per process; BGRX8; at least 65536 pixels; 16 processes, 128 shapes, 32 surfaces, 128 MiB/surface, 512 MiB total; at most 4 anchor references and 64 hits/anchor; no GPU VRAM decoding",
        ..Default::default()
    };
    cancellation.check_cancelled()?;
    if kernel.is_x86_pae() || image.is_live() {
        report.search_complete = false;
        report
            .warnings
            .push("像素候选路径目前只支持静态 x64 Windows 镜像".into());
        return Ok(report);
    }
    let mut shapes = geometry_shapes(windows, options);
    if shapes.len() > MAX_SHAPES {
        shapes.truncate(MAX_SHAPES);
        report.search_complete = false;
        report
            .warnings
            .push("窗口尺寸候选超过 128，保留面积最大的尺寸；范围不完整".into());
    }
    if shapes.is_empty() {
        report.search_complete = false;
        report
            .warnings
            .push("当前筛选范围没有可用窗口尺寸，未猜测分辨率或扫描任意尺寸".into());
        return Ok(report);
    }
    let processes = list_processes(image, kernel, profile, 65_536)?;
    report.search_complete &= processes.complete;
    report.warnings.extend(
        processes
            .warnings
            .iter()
            .map(|w| format!("pslist/{}: {}", w.kind, w.message)),
    );
    let mut graphics = processes
        .processes
        .iter()
        .filter_map(|p| {
            let selected = process_shapes(p, &processes.processes, &shapes);
            (!selected.is_empty()).then_some((p, selected))
        })
        .collect::<Vec<_>>();
    graphics.sort_by_key(|(p, selected)| {
        let role = if p.name.eq_ignore_ascii_case("csrss.exe") {
            0
        } else if p.name.eq_ignore_ascii_case("dwm.exe") {
            1
        } else {
            2
        };
        let area = selected
            .iter()
            .map(|s| u64::from(s.width) * u64::from(s.height))
            .max()
            .unwrap_or(0);
        (role, std::cmp::Reverse(area), p.pid)
    });
    let mut references = Vec::new();
    let mut kernel_tables = BTreeSet::from([kernel.directory_table_base]);
    let mut total = 0u64;
    let mut emitted = BTreeSet::new();
    let progress = start_progress("图形进程像素候选", graphics.len() as u64);
    for (process, selected) in graphics {
        cancellation.check_cancelled()?;
        progress.advance(1);
        let Some(session) = process
            .details
            .session_id
            .or(process.details.token_session_id)
        else {
            report.search_complete = false;
            report.warnings.push(format!(
                "PID {} 缺少会话归属，未跨会话匹配尺寸",
                process.pid
            ));
            continue;
        };
        if report.processes_examined >= 16 {
            report.search_complete = false;
            report
                .warnings
                .push("图形进程扫描达到 16 个进程上限".into());
            break;
        }
        report.processes_examined += 1;
        let Some(dtb) = process
            .details
            .user_directory_table_base
            .filter(|dtb| *dtb != 0)
            .or(process.details.directory_table_base)
        else {
            report.search_complete = false;
            report
                .warnings
                .push(format!("PID {} 没有可用页表", process.pid));
            continue;
        };
        let space = X64AddressSpace::new(image, dtb)?;
        if let Some(dtb) = process.details.directory_table_base.filter(|dtb| *dtb != 0)
            && kernel_tables.len() < 4
        {
            kernel_tables.insert(dtb);
        }
        let vads =
            match list_vads_cancellable(image, kernel, profile, process.pid, 8192, cancellation) {
                Ok(vads) => vads,
                Err(error) => {
                    cancellation.check_cancelled()?;
                    report.search_complete = false;
                    report
                        .warnings
                        .push(format!("PID {} VAD 读取失败：{error:#}", process.pid));
                    continue;
                }
            };
        report.search_complete &= vads.complete;
        report.warnings.extend(vads.warnings);
        // Shape order is descending area. Small buffers cannot consume this
        // process's remaining export budget before its full window candidates.
        for shape in &selected {
            for vad in &vads.records {
                cancellation.check_cancelled()?;
                if vad.file.is_some()
                    || vad.protection_name.contains("EXECUTE")
                    || (vad.private_memory && process.name.eq_ignore_ascii_case("csrss.exe"))
                {
                    continue;
                }
                let Some(length) = vad
                    .end
                    .checked_sub(vad.start)
                    .and_then(|n| n.checked_add(1))
                else {
                    continue;
                };
                for stride in matching_strides(shape.width, shape.height, length) {
                    if !emitted.insert((dtb, vad.start, shape.width, shape.height, stride)) {
                        continue;
                    }
                    report.size_candidates += 1;
                    let sample = sample_pixels(
                        &space,
                        vad.start,
                        shape.width,
                        shape.height,
                        stride,
                        cancellation,
                    )?;
                    if sample.readable_pixels == 0 {
                        report.unreadable_candidates += 1;
                        report.search_complete = false;
                        continue;
                    }
                    if !plausible_pixels(&sample) {
                        report.sample_rejections += 1;
                        continue;
                    }
                    let bytes = u64::from(shape.width) * u64::from(shape.height) * 4;
                    if report.records.len() >= MAX_SURFACES || total + bytes > MAX_TOTAL_BYTES {
                        report.search_complete = false;
                        if !report.warnings.iter().any(|w| w.contains("导出预算")) {
                            report
                                .warnings
                                .push("像素候选达到导出预算，仍可能存在未恢复表面".into());
                        }
                        continue;
                    }
                    let path = options.output.join(format!(
                        "vad-pixels-{}-{:x}-{}x{}-s{}.bmp",
                        process.pid, vad.start, shape.width, shape.height, stride
                    ));
                    let recovered = write_bgra_bmp(
                        image,
                        &space,
                        vad.start,
                        shape.width,
                        shape.height,
                        stride,
                        &path,
                        options.force,
                        true,
                        cancellation,
                    )
                    .and_then(|stats| {
                        save_recovery(image, &path, &stats, dtb, options.force)
                            .map(|manifest| (stats, manifest))
                    });
                    let (stats, manifest) = match recovered {
                        Ok(recovered) => recovered,
                        Err(error) => {
                            cancellation.check_cancelled()?;
                            report.search_complete = false;
                            report.warnings.push(format!(
                                "PID {} 像素候选 {:#x} 导出失败，其他结果保留：{error:#}",
                                process.pid, vad.start
                            ));
                            continue;
                        }
                    };
                    let complete = stats.recovered_bytes == bytes;
                    report.search_complete &= complete;
                    let record_index = report.records.len();
                    report.records.push(PixelCandidate {
                        render_kind: "geometry_pixel_candidate", pid: Some(process.pid), process: Some(process.name.clone()), process_parent_pid: process.ppid,
                        session_id: session, directory_table_base: dtb, pixel_address: vad.start,
                        vad_node: Some(vad.node), vad_private_memory: Some(vad.private_memory),
                        width: shape.width, height: shape.height, stride, pixel_format: "BGRX8 (fourth byte preserved, not opacity)",
                        geometry_matches: shape.geometry.clone(), sample, reference_output: None, anchors: Vec::new(),
                        recovered_bytes: stats.recovered_bytes, total_bytes: bytes, coverage_percent: percent(stats.recovered_bytes, bytes),
                        bytes_complete: complete, pixel_sha256: stats.pixel_sha256, bgr_sha256: stats.bgr_sha256,
                        output_sha256: stats.output_sha256, output: path, recovery_manifest: manifest,
                        interpretation: "窗口尺寸、页对齐区间和像素统计匹配的候选；应用候选按窗口 PID 或同会话同映像的直接子进程限定尺寸，映射及父子关系不证明生成者或具体窗口，字节完整不证明同一时刻的完整桌面",
                    });
                    total += bytes;
                    if complete
                        && shape.width >= 640
                        && shape.height >= 400
                        && references.len() < MAX_REFERENCES
                    {
                        references.push(Reference {
                            record_index,
                            dtb,
                            pixels: vad.start,
                            width: shape.width,
                            height: shape.height,
                            stride,
                        });
                    }
                }
            }
        }
    }
    progress.finish();
    if report.unreadable_candidates != 0 {
        report.warnings.push(format!(
            "{} 个尺寸候选的采样页均不可读；这不证明原表面不存在",
            report.unreadable_candidates
        ));
    }
    if let Err(error) = recover_anchored_buffers(
        image,
        &references,
        &kernel_tables,
        &mut report,
        options,
        total,
        cancellation,
    ) {
        cancellation.check_cancelled()?;
        report.search_complete = false;
        report.warnings.push(format!(
            "内核像素锚点阶段未完成；已导出的进程候选保留：{error:#}"
        ));
    }
    Ok(report)
}

/// Window geometry limits application scans to their own buffers or a same-image
/// direct child's buffers (e.g. Chromium GPU/renderer processes). This is a
/// search constraint, not a claim that a candidate belongs to a particular window.
fn process_shapes(
    process: &ProcessRecord,
    processes: &[ProcessRecord],
    shapes: &[Shape],
) -> Vec<Shape> {
    if process.details.state == "exited" {
        return Vec::new();
    }
    let session = process
        .details
        .session_id
        .or(process.details.token_session_id);
    let compositor = process.name.eq_ignore_ascii_case("csrss.exe")
        || process.name.eq_ignore_ascii_case("dwm.exe");
    // Keep unknown-session compositor targets so the caller reports the missing
    // prerequisite rather than silently treating them as an empty search.
    if session.is_none() && compositor {
        return shapes.to_vec();
    }
    let Some(session) = session else {
        return Vec::new();
    };
    let parent = process
        .ppid
        .and_then(|pid| {
            processes.iter().find(|p| {
                p.pid == pid
                    && p.pid != process.pid
                    && p.details.state != "exited"
                    && p.name.eq_ignore_ascii_case(&process.name)
                    && p.details.session_id.or(p.details.token_session_id) == Some(session)
                    && match (&p.details.image_path, &process.details.image_path) {
                        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                        _ => true,
                    }
            })
        })
        .map(|p| p.pid);
    shapes
        .iter()
        .filter(|s| s.session == session)
        .filter_map(|s| {
            let mut selected = s.clone();
            if !compositor {
                selected.geometry.retain(|g| {
                    g.window_pid == Some(process.pid)
                        || parent.is_some_and(|pid| g.window_pid == Some(pid))
                });
            }
            (!selected.geometry.is_empty()).then_some(selected)
        })
        .collect()
}

fn geometry_shapes(
    windows: &[WindowRecord],
    options: &super::desktop_reconstruct::DesktopReconstructOptions,
) -> Vec<Shape> {
    let mut shapes = BTreeMap::<(u32, u32, u32), Vec<GeometryMatch>>::new();
    for window in windows {
        if options.session_id.is_some_and(|id| id != window.session_id)
            || options
                .desktop
                .as_ref()
                .is_some_and(|name| !name.eq_ignore_ascii_case(&window.desktop))
        {
            continue;
        }
        for (kind, rect) in [
            ("window", window.window_rect),
            ("client", window.client_rect),
        ] {
            let Some(rect) = rect else {
                continue;
            };
            let (w, h) = (rect.width(), rect.height());
            if w < 64
                || h < 64
                || w > options.max_dimension
                || h > options.max_dimension
                || u64::from(w) * u64::from(h) < 65_536
                || u64::from(w) * u64::from(h) * 4 > MAX_FRAME_BYTES
            {
                continue;
            }
            shapes
                .entry((window.session_id, w, h))
                .or_default()
                .push(GeometryMatch {
                    session_id: window.session_id,
                    window_station: window.window_station.clone(),
                    desktop: window.desktop.clone(),
                    window_address: window.address,
                    window_pid: window.pid,
                    rectangle: kind,
                });
        }
    }
    let mut result = shapes
        .into_iter()
        .map(|((session, width, height), geometry)| Shape {
            session,
            width,
            height,
            geometry,
        })
        .collect::<Vec<_>>();
    result.sort_by_key(|s| {
        (
            std::cmp::Reverse(u64::from(s.width) * u64::from(s.height)),
            s.session,
            s.width,
        )
    });
    result
}

fn matching_strides(width: u32, height: u32, vad_bytes: u64) -> Vec<u32> {
    if width == 0 || height == 0 {
        return Vec::new();
    }
    let row = u64::from(width) * 4;
    [4u64, 16, 64, 256]
        .into_iter()
        .filter_map(|alignment| {
            let stride = row.div_ceil(alignment) * alignment;
            let bytes = stride.checked_mul(u64::from(height))?;
            (bytes <= MAX_FRAME_BYTES && bytes.div_ceil(4096) * 4096 == vad_bytes)
                .then(|| u32::try_from(stride).ok())
                .flatten()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sample_pixels(
    space: &X64AddressSpace<'_>,
    pixels: u64,
    width: u32,
    height: u32,
    stride: u32,
    cancellation: &CancellationToken,
) -> Result<PixelSample> {
    let mut sample = PixelSample {
        readable_pixels: 0,
        requested_pixels: 0,
        distinct_colors: 0,
        non_black_percent: 0.0,
        reserved_zero_or_ff_percent: 0.0,
        smooth_neighbor_percent: 0.0,
    };
    let mut colors = BTreeSet::new();
    let (mut nonblack, mut reserved, mut smooth, mut neighbors) = (0u64, 0u64, 0u64, 0u64);
    let count = width.min(64) as usize;
    for gy in 0..16u32 {
        let y = ((u64::from(gy) * u64::from(height - 1)) / 15) as u32;
        for gx in 0..3u32 {
            cancellation.check_cancelled()?;
            let x = (width - count as u32) * gx / 2;
            let mut bytes = vec![0u8; count * 4];
            sample.requested_pixels += count;
            let Some(address) =
                pixels.checked_add(u64::from(y) * u64::from(stride) + u64::from(x) * 4)
            else {
                continue;
            };
            if space.read_virtual(address, &mut bytes).is_err() {
                continue;
            }
            sample.readable_pixels += count;
            for pixel in bytes.chunks_exact(4) {
                colors.insert([pixel[0], pixel[1], pixel[2]]);
                nonblack += u64::from(pixel[..3] != [0, 0, 0]);
                reserved += u64::from(pixel[3] == 0 || pixel[3] == 255);
            }
            for pair in bytes.windows(8).step_by(4) {
                neighbors += 1;
                let delta: u32 = (0..3)
                    .map(|i| u32::from(pair[i].abs_diff(pair[i + 4])))
                    .sum();
                smooth += u64::from(delta <= 96);
            }
        }
    }
    sample.distinct_colors = colors.len();
    sample.non_black_percent = percent(nonblack, sample.readable_pixels as u64);
    sample.reserved_zero_or_ff_percent = percent(reserved, sample.readable_pixels as u64);
    sample.smooth_neighbor_percent = percent(smooth, neighbors);
    Ok(sample)
}

fn plausible_pixels(sample: &PixelSample) -> bool {
    sample.readable_pixels >= 128
        && sample.distinct_colors >= 4
        && sample.non_black_percent >= 0.5
        && sample.reserved_zero_or_ff_percent >= 90.0
        && sample.smooth_neighbor_percent >= 60.0
}

fn save_recovery(
    image: &MemoryImage,
    output: &Path,
    stats: &WriteStats,
    dtb: u64,
    force: bool,
) -> Result<PathBuf> {
    let path = output.with_extension("bmp.recovery.json");
    let mut policy = OutputPolicy::new(force);
    for source in image.sources() {
        policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    policy.output(OutputTarget::file("pixel_recovery_manifest", &path));
    policy.preflight()?;
    policy.write_file_atomic(&path, |file| {
        let mut writer = std::io::BufWriter::new(file);
        serde_json::to_writer(&mut writer, &serde_json::json!({
            "schema_version": 1, "output": output, "image": image.path(), "sources": image.sources().collect::<Vec<_>>(),
            "directory_table_base": dtb, "pixel_offset_origin": "top-down BMP pixel array, excluding 54-byte header and stride padding",
            "missing_fill": "zero; excluded from recovered_bytes and recovered_sha256",
            "fourth_byte": "original bytes preserved; BGRX rendering ignores opacity",
            "recovered_bytes": stats.recovered_bytes, "pixel_sha256": stats.pixel_sha256,
            "recovered_sha256": stats.recovered_sha256, "bgr_sha256": stats.bgr_sha256,
            "output_sha256": stats.output_sha256, "ranges": stats.ranges,
        }))?;
        writer.flush()?;
        Ok(())
    })?;
    Ok(path)
}

fn normalized_anchor(mut bytes: Vec<u8>) -> Option<Vec<u8>> {
    let colors = bytes
        .chunks_exact(4)
        .map(|p| [p[0], p[1], p[2]])
        .collect::<BTreeSet<_>>();
    if bytes.len() != ANCHOR_BYTES || colors.len() < 12 {
        return None;
    }
    for pixel in bytes.chunks_exact_mut(4) {
        pixel[3] = 0;
    }
    Some(bytes)
}

fn build_anchors(
    image: &MemoryImage,
    references: &[Reference],
    cancellation: &CancellationToken,
) -> Result<Vec<Anchor>> {
    let mut anchors = Vec::new();
    for (reference, r) in references.iter().enumerate() {
        let space = X64AddressSpace::new(image, r.dtb)?;
        let mut seen = BTreeSet::new();
        for gy in 1..=5u32 {
            for gx in 1..=5u32 {
                cancellation.check_cancelled()?;
                let (x, y) = ((r.width - 32) * gx / 6, (r.height - 1) * gy / 6);
                let offset = u64::from(y) * u64::from(r.stride) + u64::from(x) * 4;
                let mut bytes = vec![0u8; ANCHOR_BYTES];
                if space.read_virtual(r.pixels + offset, &mut bytes).is_err() {
                    continue;
                }
                if let Some(bytes) = normalized_anchor(bytes)
                    && seen.insert(bytes.clone())
                {
                    anchors.push(Anchor {
                        reference,
                        x,
                        y,
                        offset,
                        bytes,
                    });
                }
            }
        }
    }
    Ok(anchors)
}

/// Retain overlap only inside contiguous acquired physical memory. A file-order
/// neighbor across a bitmap-dump hole must never form a valid anchor.
#[allow(clippy::type_complexity)]
fn scan_anchors(
    image: &MemoryImage,
    anchors: &[Anchor],
    cancellation: &CancellationToken,
) -> Result<(Vec<(usize, u64)>, u64, bool)> {
    cancellation.check_cancelled()?;
    let _scan_guard = image.scan_engine().lock_physical_scan()?;
    cancellation.check_cancelled()?;
    let matcher = AhoCorasickBuilder::new().build(anchors.iter().map(|a| &a.bytes))?;
    let mut ranges = Vec::<(u64, u64)>::new();
    for span in image.spans() {
        if let Some((start, length)) = ranges.last_mut()
            && *start + *length == span.start
        {
            *length += span.length;
        } else {
            ranges.push((span.start, span.length));
        }
    }
    let progress = start_progress("像素锚点物理扫描", image.mapped_bytes());
    let mut buffer = Vec::new();
    let mut hits = Vec::new();
    let mut counts = vec![0; anchors.len()];
    let (mut scanned, mut truncated) = (0, false);
    for (start, length) in ranges {
        let mut offset = 0;
        while offset < length {
            cancellation.check_cancelled()?;
            let core = (length - offset).min(SCAN_CHUNK as u64) as usize;
            let overlap = (length - offset - core as u64).min((ANCHOR_BYTES - 1) as u64) as usize;
            buffer.resize(core + overlap, 0);
            let physical = start + offset;
            image.read_physical(physical, &mut buffer)?;
            // User VAD starts and candidate canvas bases are page aligned.
            // Physical page offsets preserve this pixel alignment.
            let first_reserved = (3usize.wrapping_sub(physical as usize & 3)) & 3;
            for i in (first_reserved..buffer.len()).step_by(4) {
                buffer[i] = 0;
            }
            for matched in matcher.find_overlapping_iter(&buffer) {
                if matched.start() >= core {
                    break;
                }
                if (physical + matched.start() as u64) & 3 != 0 {
                    continue;
                }
                let index = matched.pattern().as_usize();
                if counts[index] >= MAX_ANCHOR_HITS {
                    truncated = true;
                    continue;
                }
                counts[index] += 1;
                hits.push((index, physical + matched.start() as u64));
            }
            offset += core as u64;
            scanned += core as u64;
            progress.advance(core as u64);
        }
    }
    progress.finish();
    Ok((hits, scanned, truncated))
}

fn anchors_are_independent(matches: &[&Anchor], width: u32, height: u32) -> bool {
    if matches.len() < 3 {
        return false;
    }
    let xs = matches.iter().map(|a| a.x).collect::<BTreeSet<_>>();
    let ys = matches.iter().map(|a| a.y).collect::<BTreeSet<_>>();
    xs.len() >= 2
        && ys.len() >= 2
        && xs.last().unwrap() - xs.first().unwrap() >= width / 4
        && ys.last().unwrap() - ys.first().unwrap() >= height / 4
}

fn recover_anchored_buffers(
    image: &MemoryImage,
    references: &[Reference],
    tables: &BTreeSet<u64>,
    report: &mut PixelRecoveryReport,
    options: &super::desktop_reconstruct::DesktopReconstructOptions,
    mut total: u64,
    cancellation: &CancellationToken,
) -> Result<()> {
    let anchors = build_anchors(image, references, cancellation)?;
    if anchors.len() < 3 {
        return Ok(());
    }
    let (hits, scanned, truncated) = scan_anchors(image, &anchors, cancellation)?;
    report.anchor_bytes_scanned = scanned;
    report.anchor_hits = hits.len();
    if truncated {
        report.search_complete = false;
        report
            .warnings
            .push("部分像素锚点超过 64 个物理命中，定位范围不完整".into());
    }
    let pages = hits
        .iter()
        .map(|(_, pa)| pa & !0xfff)
        .collect::<HashSet<_>>();
    let mut published = BTreeSet::new();
    for &dtb in tables {
        cancellation.check_cancelled()?;
        let space = X64AddressSpace::new(image, dtb)?;
        let reverse = match space.reverse_translate_pages_detailed_with_limits(
            &pages,
            VirtualAddressRegion::Kernel,
            8,
            4 * 1024 * 1024,
            32768,
        ) {
            Ok(reverse) => reverse,
            Err(error) => {
                report.search_complete = false;
                report
                    .warnings
                    .push(format!("DTB {dtb:#x} 像素反向映射失败：{error:#}"));
                continue;
            }
        };
        cancellation.check_cancelled()?;
        if reverse.page_table_read_failures != 0
            || reverse.traversal_limit_reached
            || reverse.mapping_limit_exceeded
            || reverse.alias_storage_limit_exceeded
        {
            report.search_complete = false;
            report.warnings.push(format!(
                "DTB {dtb:#x} 反向映射范围不完整：缺失页表 {}，遍历截断 {}，别名截断 {}",
                reverse.page_table_read_failures,
                reverse.traversal_limit_reached,
                reverse.mapping_limit_exceeded || reverse.alias_storage_limit_exceeded
            ));
        }
        let mut candidates = BTreeMap::<(usize, u64), BTreeSet<usize>>::new();
        for &(index, physical) in &hits {
            if let Some(aliases) = reverse.mappings.get(&(physical & !0xfff)) {
                let anchor = &anchors[index];
                for alias in aliases {
                    let address = alias + (physical & 0xfff);
                    if let Some(base) = address.checked_sub(anchor.offset)
                        && base >= 0xffff800000000000
                        && base & 0xfff == 0
                    {
                        candidates
                            .entry((anchor.reference, base))
                            .or_default()
                            .insert(index);
                    }
                }
            }
        }
        for ((reference, base), indexes) in candidates {
            cancellation.check_cancelled()?;
            let r = &references[reference];
            if !anchors_are_independent(
                &indexes.iter().map(|&i| &anchors[i]).collect::<Vec<_>>(),
                r.width,
                r.height,
            ) {
                continue;
            }
            let mut verified = Vec::new();
            for &index in &indexes {
                let a = &anchors[index];
                let Some(address) = base.checked_add(a.offset) else {
                    continue;
                };
                let mut bytes = vec![0u8; ANCHOR_BYTES];
                if space.read_virtual(address, &mut bytes).is_ok()
                    && normalized_anchor(bytes).as_ref() == Some(&a.bytes)
                {
                    verified.push(index);
                }
            }
            if !anchors_are_independent(
                &verified.iter().map(|&i| &anchors[i]).collect::<Vec<_>>(),
                r.width,
                r.height,
            ) {
                continue;
            }
            // The same virtual buffer can appear in several process kernel tables.
            let first_physical = space.translate(base).ok();
            if !published.insert((base, first_physical, r.width, r.height, r.stride)) {
                continue;
            }
            let bytes = u64::from(r.width) * u64::from(r.height) * 4;
            if report.records.len() >= MAX_SURFACES || total + bytes > MAX_TOTAL_BYTES {
                report.search_complete = false;
                report.warnings.push("内核关联画布达到导出预算".into());
                return Ok(());
            }
            let sample = sample_pixels(&space, base, r.width, r.height, r.stride, cancellation)?;
            // Anchors prove byte correspondence, but a mapped interval is still required.
            if sample.readable_pixels < 128 {
                continue;
            }
            let path = options.output.join(format!(
                "kernel-pixels-{:x}-{:x}-{}x{}-s{}.bmp",
                dtb, base, r.width, r.height, r.stride
            ));
            let stats = write_bgra_bmp(
                image,
                &space,
                base,
                r.width,
                r.height,
                r.stride,
                &path,
                options.force,
                true,
                cancellation,
            )?;
            let manifest = save_recovery(image, &path, &stats, dtb, options.force)?;
            let source = &report.records[r.record_index];
            let anchors = verified
                .iter()
                .map(|&i| {
                    let a = &anchors[i];
                    let address = base + a.offset;
                    Ok(PixelAnchorMatch {
                        x: a.x,
                        y: a.y,
                        length: ANCHOR_BYTES,
                        reference_virtual_address: r.pixels + a.offset,
                        matched_virtual_address: address,
                        matched_physical_address: space.translate(address)?,
                        bgrx_hex: hex::encode(&a.bytes),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let complete = stats.recovered_bytes == bytes;
            report.search_complete &= complete;
            report.records.push(PixelCandidate {
                render_kind: "anchor_correlated_kernel_pixels", pid: None, process: None, process_parent_pid: None, session_id: source.session_id,
                directory_table_base: dtb, pixel_address: base, vad_node: None, vad_private_memory: None,
                width: r.width, height: r.height, stride: r.stride, pixel_format: "BGRX8 (fourth byte preserved, not opacity)",
                geometry_matches: source.geometry_matches.clone(), sample, reference_output: Some(source.output.clone()), anchors,
                recovered_bytes: stats.recovered_bytes, total_bytes: bytes, coverage_percent: percent(stats.recovered_bytes, bytes), bytes_complete: complete,
                pixel_sha256: stats.pixel_sha256, bgr_sha256: stats.bgr_sha256, output_sha256: stats.output_sha256,
                output: path, recovery_manifest: manifest,
                interpretation: "多个分散 BGR 字节锚点推导同一内核画布起点并经虚拟读取复验；会话/桌面是参考图的关联，不是对象归属证明，可能包含跨时间的绘制残留",
            });
            total += bytes;
        }
    }
    Ok(())
}

fn percent(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 * 100.0 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::super::desktop_reconstruct::DesktopReconstructOptions;
    use super::super::gui_plugins::WindowRect;
    use super::*;
    use crate::cancellation::is_cancellation_error;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        root: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "starmem-pixel-tests-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            Self { root }
        }
        fn options(&self) -> DesktopReconstructOptions {
            DesktopReconstructOptions {
                output: self.root.clone(),
                session_id: None,
                desktop: None,
                limit: 100,
                max_dimension: 4096,
                force: false,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn geometry_and_stride_are_bounded_and_session_filtered() {
        let f = Fixture::new();
        let window = |session, desktop: &str| WindowRecord {
            address: 1,
            session_id: session,
            window_station: "WinSta0".into(),
            desktop: desktop.into(),
            title: None,
            procedure: None,
            process: None,
            pid: None,
            parent: None,
            next: None,
            child: None,
            style: None,
            ex_style: None,
            visible: Some(true),
            window_rect: Some(WindowRect {
                left: 0,
                top: 0,
                right: 801,
                bottom: 600,
            }),
            client_rect: None,
            geometry_address: None,
            tree_depth: 0,
            z_order: 0,
            layout: "test".into(),
        };
        let mut options = f.options();
        options.session_id = Some(2);
        options.desktop = Some("Default".into());
        let shapes = geometry_shapes(
            &[
                window(1, "Default"),
                window(2, "Winlogon"),
                window(2, "Default"),
            ],
            &options,
        );
        assert_eq!(shapes.len(), 1);
        assert_eq!(shapes[0].session, 2);
        assert_eq!(shapes[0].geometry[0].desktop, "Default");
        let mut tiny = window(2, "Default");
        tiny.window_rect = Some(WindowRect {
            left: 0,
            top: 0,
            right: 64,
            bottom: 64,
        });
        assert!(geometry_shapes(&[tiny], &options).is_empty());
        assert_eq!(
            matching_strides(801, 600, (3264u64 * 600).div_ceil(4096) * 4096),
            [3264]
        );
        assert!(matching_strides(u32::MAX, u32::MAX, 4096).is_empty());
        assert!(matching_strides(801, 600, 4096).is_empty());
    }

    #[test]
    fn application_buffers_use_owner_and_same_image_child_geometry_only() {
        use super::super::ProcessDetails;
        let process = |pid, ppid, name: &str, session| ProcessRecord {
            eprocess: 0,
            pid,
            ppid,
            name: name.into(),
            details: ProcessDetails {
                state: "running".into(),
                session_id: session,
                ..Default::default()
            },
        };
        let mut family = vec![
            process(100, None, "Browser.exe", Some(1)),
            process(200, Some(100), "browser.EXE", Some(1)),
            process(300, None, "Browser.exe", Some(1)),
            process(400, Some(100), "Browser.exe", Some(2)),
            process(500, Some(100), "helper.exe", Some(1)),
            process(600, Some(100), "Browser.exe", None),
        ];
        let geometry = |session, pid| GeometryMatch {
            session_id: session,
            window_station: "WinSta0".into(),
            desktop: "Default".into(),
            window_address: 0x1000 + pid,
            window_pid: Some(pid),
            rectangle: "client",
        };
        let shapes = vec![
            Shape {
                width: 1600,
                height: 900,
                session: 1,
                geometry: vec![geometry(1, 100), geometry(1, 999)],
            },
            Shape {
                width: 800,
                height: 600,
                session: 1,
                geometry: vec![geometry(1, 999)],
            },
            Shape {
                width: 1600,
                height: 900,
                session: 2,
                geometry: vec![geometry(2, 100)],
            },
        ];
        for i in [0, 1] {
            let selected = process_shapes(&family[i], &family, &shapes);
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].geometry.len(), 1);
            assert_eq!(selected[0].geometry[0].window_pid, Some(100));
            assert_eq!(selected[0].session, 1);
        }
        for i in 2..family.len() {
            assert!(process_shapes(&family[i], &family, &shapes).is_empty());
        }
        // A token session is a usable fallback; a different executable path or
        // exited parent must never expand the child's geometry scope.
        family[5].details.token_session_id = Some(1);
        assert_eq!(process_shapes(&family[5], &family, &shapes).len(), 1);
        family[0].details.image_path = Some("C:\\one\\Browser.exe".into());
        family[1].details.image_path = Some("C:\\two\\Browser.exe".into());
        assert!(process_shapes(&family[1], &family, &shapes).is_empty());
        family[0].details.state = "exited".into();
        assert!(process_shapes(&family[0], &family, &shapes).is_empty());
        assert!(process_shapes(&family[5], &family, &shapes).is_empty());
        let compositor = process(700, None, "dwm.exe", Some(1));
        let selected = process_shapes(&compositor, &family, &shapes);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].geometry.len(), 2);
    }

    #[test]
    fn solid_or_random_samples_do_not_become_images_by_length_alone() {
        let mut sample = PixelSample {
            readable_pixels: 1024,
            requested_pixels: 1024,
            distinct_colors: 1024,
            non_black_percent: 100.0,
            reserved_zero_or_ff_percent: 0.8,
            smooth_neighbor_percent: 10.0,
        };
        assert!(!plausible_pixels(&sample));
        sample.reserved_zero_or_ff_percent = 100.0;
        assert!(!plausible_pixels(&sample)); // RGB noise with an artificial alpha channel.
        sample.distinct_colors = 6;
        sample.smooth_neighbor_percent = 99.0;
        assert!(plausible_pixels(&sample)); // Text/lockscreen buffers can have very few colors.
        sample.distinct_colors = 1;
        sample.smooth_neighbor_percent = 100.0;
        assert!(!plausible_pixels(&sample));
        assert!(normalized_anchor(vec![0; ANCHOR_BYTES]).is_none());
    }

    #[test]
    fn multiple_hits_in_one_local_area_do_not_prove_a_canvas() {
        let make = |x, y| Anchor {
            reference: 0,
            x,
            y,
            offset: 0,
            bytes: vec![],
        };
        let (a, b, c) = (make(10, 10), make(11, 11), make(12, 12));
        assert!(!anchors_are_independent(&[&a, &b, &c], 1920, 1080));
        let (a, b, c) = (make(100, 100), make(1200, 100), make(600, 800));
        assert!(anchors_are_independent(&[&a, &b, &c], 1920, 1080));
        assert!(!anchors_are_independent(&[&a, &b], 1920, 1080));
    }

    /// Two distinct buffers, noncontiguous/reversed physical pages, row padding,
    /// different X bytes and a modified drawing area. No hard-coded production VA.
    #[test]
    fn finds_kernel_canvas_with_changed_x_and_shuffled_pages() {
        let f = Fixture::new();
        let (width, height, stride) = (192u32, 160u32, 800u32);
        let pages = (u64::from(stride) * u64::from(height)).div_ceil(4096) as usize;
        let mut data = vec![0u8; (8 + pages * 2) * 4096];
        let mut entry =
            |at: usize, value: u64| data[at..at + 8].copy_from_slice(&value.to_le_bytes());
        for (at, value) in [
            (0x1000, 0x2003),
            (0x1000 + 256 * 8, 0x5003),
            (0x2000, 0x3003),
            (0x3000, 0x4003),
            (0x5000, 0x6003),
            (0x6000, 0x7003),
        ] {
            entry(at, value);
        }
        for i in 0..pages {
            entry(0x4000 + i * 8, ((8 + i) as u64 * 4096) | 3);
            entry(0x7000 + i * 8, ((8 + pages * 2 - 1 - i) as u64 * 4096) | 3);
        }
        let mut pixels = vec![0x42u8; pages * 4096];
        for y in 0..height as usize {
            for x in 0..width as usize {
                let at = y * stride as usize + x * 4;
                pixels[at..at + 4].copy_from_slice(&[
                    ((x * 3 + y * 7) & 255) as u8,
                    ((x * 5 + y / 3) & 255) as u8,
                    ((x / 2 + y * 2) & 255) as u8,
                    255,
                ]);
            }
        }
        for i in 0..pages {
            data[(8 + i) * 4096..(9 + i) * 4096].copy_from_slice(&pixels[i * 4096..(i + 1) * 4096]);
        }
        for y in 0..height as usize {
            for x in 0..width as usize {
                let at = y * stride as usize + x * 4;
                pixels[at + 3] = 0x11;
                if x < 20 && y < 20 {
                    pixels[at..at + 3].fill(0);
                }
            }
        }
        for i in 0..pages {
            let physical = (8 + pages * 2 - 1 - i) * 4096;
            data[physical..physical + 4096].copy_from_slice(&pixels[i * 4096..(i + 1) * 4096]);
        }
        let path = f.root.join("shuffled.raw");
        fs::write(&path, data).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 0x1000).unwrap();
        let token = CancellationToken::new();
        let references = vec![Reference {
            record_index: 0,
            dtb: 0x1000,
            pixels: 0,
            width,
            height,
            stride,
        }];
        let anchors = build_anchors(&image, &references, &token).unwrap();
        assert!(anchors.len() >= 3);
        let (hits, _, truncated) = scan_anchors(&image, &anchors, &token).unwrap();
        assert!(!truncated);
        let targets = hits.iter().map(|(_, pa)| pa & !0xfff).collect();
        let reverse = space.reverse_translate_kernel_pages(&targets, 8).unwrap();
        let base = 0xffff800000000000u64;
        let verified = hits
            .iter()
            .filter_map(|(i, pa)| {
                let a = &anchors[*i];
                reverse.get(&(pa & !0xfff)).and_then(|aliases| {
                    aliases
                        .iter()
                        .any(|va| va + (pa & 0xfff) - a.offset == base)
                        .then_some(a)
                })
            })
            .collect::<Vec<_>>();
        assert!(anchors_are_independent(&verified, width, height));
        let output = f.root.join("pixels.bmp");
        let stats = write_bgra_bmp(
            &image, &space, base, width, height, stride, &output, false, true, &token,
        )
        .unwrap();
        assert_eq!(
            stats.recovered_bytes,
            u64::from(width) * u64::from(height) * 4
        );
        assert_eq!(
            stats.ranges[0].physical_address,
            Some((8 + pages * 2 - 1) as u64 * 4096)
        );
        let expected = pixels
            .chunks_exact(stride as usize)
            .take(height as usize)
            .flat_map(|row| row[..width as usize * 4].iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(&fs::read(&output).unwrap()[54..], expected);
        let reference = f.root.join("reference.bmp");
        let original = write_bgra_bmp(
            &image, &space, 0, width, height, stride, &reference, false, true, &token,
        )
        .unwrap();
        assert_ne!(stats.bgr_sha256, original.bgr_sha256); // Drawing residue is a distinct artifact.
        drop(image);
    }

    #[test]
    fn cancellation_and_output_protection_preserve_existing_evidence() {
        let f = Fixture::new();
        let path = f.root.join("input.raw");
        fs::write(&path, vec![0u8; 8192]).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 4096).unwrap();
        let token = CancellationToken::new();
        token.request_cancel();
        let anchors = vec![Anchor {
            reference: 0,
            x: 0,
            y: 0,
            offset: 0,
            bytes: vec![1; ANCHOR_BYTES],
        }];
        assert!(is_cancellation_error(
            &scan_anchors(&image, &anchors, &token).unwrap_err()
        ));
        assert!(
            write_bgra_bmp(
                &image,
                &space,
                0,
                1,
                1,
                4,
                &path,
                true,
                false,
                &CancellationToken::new()
            )
            .is_err()
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), 8192);
        let output = f.root.join("existing.bmp");
        fs::write(&output, b"prior evidence").unwrap();
        assert!(
            write_bgra_bmp(
                &image,
                &space,
                0,
                1,
                1,
                4,
                &output,
                false,
                false,
                &CancellationToken::new()
            )
            .is_err()
        );
        assert_eq!(fs::read(&output).unwrap(), b"prior evidence");
        drop(image);
    }
}
