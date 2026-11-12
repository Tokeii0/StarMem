use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::WindowsKernelContext;
use super::list_processes;
use super::pe_plugins::ldr_modules;
use crate::address::{VirtualAddressRegion, X64AddressSpace};
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::profile::KernelProfile;
use crate::scan::scan_patterns_streaming_cancellable;
use crate::symbols::{SymbolStore, codeview_from_virtual_pe, discover_codeview, inspect_pdb};

const MAX_DWM_POINTER_HITS: usize = 256;
const MAX_EXPORTED_FRAMES: usize = 16;
const MAX_FRAME_BYTES: u64 = 512 * 1024 * 1024;
const DXGI_FORMAT_B8G8R8A8_UNORM: u32 = 87;
const MIN_DISPLAY_LONG_EDGE: u32 = 1280;
const MIN_DISPLAY_SHORT_EDGE: u32 = 720;
const MIN_DISPLAY_PIXELS: u64 = 1_000_000;
const REGISTRY_SCAN_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const MAX_REGISTRY_DIMENSION_HITS: usize = 4096;
const REGISTRY_CORROBORATION_DISTANCE: u64 = 0x800;
const REGISTRY_DIMENSION_PATTERNS: [&[u8]; 4] = [
    b"ActiveSize.cx",
    b"ActiveSize.cy",
    b"PrimSurfSize.cx",
    b"PrimSurfSize.cy",
];

const CD3D_SURFACE_VTABLE: &str = "??_7CD3DSurface@@6B@";
const SYSTEM_MEMORY_VTABLES: [&str; 2] = [
    "??_7CSystemMemoryBitmap@@6B@",
    "??_7CSystemMemoryBitmap@@6BIPixelColor@@@",
];
const D3D11_TEXTURE_VTABLE: &str = "??_7CContainedObject@?$CLayeredObjectWithCLS@VCTexture2D@@@@6B?$CPrivateDataImpl@UID3D11Texture2D1@@@@@";
const D3D11_RESOURCE_VTABLE: &str = "??_7CContainedObject@?$CLayeredObjectWithCLS@VCTexture2D@@@@6B?$CResource@UID3D11Texture2D1@@@@@";
const D3D11_GET_DDI_HANDLE: &str = "?GetDDIHandle@?$CResource@UID3D11Texture2D1@@@@UEAAJPEAPEAX@Z";
const WARP_RESOURCE_VTABLE: &str = "??_7UMResource@@6BTaskResource@@@";
const WARP_GET_VIRTUAL_ADDRESS: &str = "?GetVirtualAddress@UMResource@@QEBA_KXZ";

#[derive(Debug, Default, Serialize)]
pub struct DwmSurfaceReport {
    pub frames: Vec<DwmFrameRecord>,
    pub processes_examined: usize,
    pub surface_objects_examined: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DwmFrameRecord {
    pub render_kind: &'static str,
    pub pid: u64,
    pub surface_address: u64,
    pub texture_address: u64,
    pub resource_address: u64,
    pub pixel_address: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
    pub recovered_bytes: u64,
    pub total_bytes: u64,
    pub coverage_percent: f64,
    pub sampled_non_black_percent: f64,
    pub output: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct ScreenResolutionReport {
    pub records: Vec<ScreenResolutionRecord>,
    pub processes_examined: usize,
    pub surface_objects_examined: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScreenResolutionRecord {
    pub resolution: String,
    pub width: u32,
    pub height: u32,
    pub orientation: &'static str,
    pub aspect_ratio: f64,
    pub likely_primary: bool,
    pub surface_count: usize,
    pub registry_value_pairs: usize,
    pub sources: Vec<&'static str>,
    pub dwm_pids: Vec<u64>,
    pub evidence_addresses: Vec<u64>,
    pub confidence: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum ResolutionTarget {
    SystemMemory,
    LegacyD3d { texture_vtable: u64 },
}

#[derive(Default)]
struct ResolutionAggregate {
    surface_count: usize,
    registry_value_pairs: usize,
    sources: BTreeSet<&'static str>,
    dwm_pids: BTreeSet<u64>,
    evidence_addresses: BTreeSet<u64>,
}

type ResolutionAggregates = BTreeMap<(u32, u32), ResolutionAggregate>;

#[derive(Debug, Clone, Copy)]
struct RegistryDwordHit {
    cell_address: u64,
    cell_size: u64,
    value: u32,
}

#[derive(Debug, Clone, Copy)]
struct SurfaceCandidate {
    surface_address: u64,
    texture_address: u64,
    resource_address: u64,
    width: u32,
    height: u32,
    format: u32,
}

#[derive(Debug, Clone, Copy)]
struct WarpAddressLayout {
    device_offset: u64,
    generation_offset: u64,
    encoded_offset: u64,
    primary_offset: u64,
    preferred_address_offset: u64,
    fallback_address_offset: u64,
}

pub fn detect_screen_resolutions(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    symbol_store: &SymbolStore,
    limit: usize,
    cancellation: &CancellationToken,
) -> Result<ScreenResolutionReport> {
    ensure!(limit > 0, "屏幕分辨率结果上限必须大于零");
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut report = ScreenResolutionReport {
        records: Vec::new(),
        processes_examined: 0,
        surface_objects_examined: 0,
        complete: processes.complete,
        warnings: processes
            .warnings
            .iter()
            .map(|warning| format!("[{}] {}", warning.kind, warning.message))
            .collect(),
    };
    let dwm_processes = processes
        .processes
        .iter()
        .filter(|process| {
            process
                .name
                .trim_matches(['"', '\'', ' '])
                .eq_ignore_ascii_case("dwm.exe")
        })
        .collect::<Vec<_>>();
    if dwm_processes.is_empty() {
        report.complete = false;
        report
            .warnings
            .push("没有定位到 dwm.exe 进程，无法验证屏幕分辨率".to_owned());
    }

    let mut resolutions = BTreeMap::<(u32, u32), ResolutionAggregate>::new();
    for process in dwm_processes {
        cancellation.check_cancelled()?;
        report.processes_examined += 1;
        let Some(dtb) = process
            .details
            .user_directory_table_base
            .or(process.details.directory_table_base)
        else {
            report.complete = false;
            report
                .warnings
                .push(format!("dwm.exe PID {} 没有可用页表", process.pid));
            continue;
        };
        let space = match X64AddressSpace::new(image, dtb) {
            Ok(space) => space,
            Err(error) => {
                report.complete = false;
                report
                    .warnings
                    .push(format!("dwm.exe PID {} 页表无效：{error:#}", process.pid));
                continue;
            }
        };
        let modules = match ldr_modules(image, kernel, profile, Some(process.pid), 4096) {
            Ok(modules) => modules,
            Err(error) => {
                report.complete = false;
                report.warnings.push(format!(
                    "dwm.exe PID {} 模块枚举失败：{error:#}",
                    process.pid
                ));
                continue;
            }
        };
        let Some(dwmcore_base) = module_base(&modules.records, "dwmcore.dll") else {
            report.complete = false;
            report
                .warnings
                .push(format!("dwm.exe PID {} 未定位到 dwmcore.dll", process.pid));
            continue;
        };
        let dwmcore_pdb = match resolve_virtual_module_pdb(
            image,
            &space,
            dtb,
            dwmcore_base,
            "dwmcore.pdb",
            symbol_store,
        ) {
            Ok(path) => path,
            Err(error) => {
                report.complete = false;
                report.warnings.push(format!(
                    "dwm.exe PID {} 无法验证 dwmcore 符号：{error:#}",
                    process.pid
                ));
                continue;
            }
        };

        let mut targets = BTreeMap::<u64, ResolutionTarget>::new();
        for name in SYSTEM_MEMORY_VTABLES {
            if let Some(rva) = optional_symbol_rva(&dwmcore_pdb, name)? {
                targets.insert(
                    dwmcore_base + u64::from(rva),
                    ResolutionTarget::SystemMemory,
                );
            }
        }
        if let Some(surface_rva) = optional_symbol_rva(&dwmcore_pdb, CD3D_SURFACE_VTABLE)?
            && let Some(d3d11_base) = module_base(&modules.records, "d3d11.dll")
        {
            match resolve_virtual_module_pdb(
                image,
                &space,
                dtb,
                d3d11_base,
                "d3d11.pdb",
                symbol_store,
            )
            .and_then(|pdb| exact_symbol_rva(&pdb, D3D11_TEXTURE_VTABLE))
            {
                Ok(texture_rva) => {
                    targets.insert(
                        dwmcore_base + u64::from(surface_rva),
                        ResolutionTarget::LegacyD3d {
                            texture_vtable: d3d11_base + u64::from(texture_rva),
                        },
                    );
                }
                Err(error) => report.warnings.push(format!(
                    "dwm.exe PID {} 无法验证 D3D11 纹理类型：{error:#}",
                    process.pid
                )),
            }
        }
        if targets.is_empty() {
            report.complete = false;
            report.warnings.push(format!(
                "dwm.exe PID {} 没有当前支持的显示表面类型",
                process.pid
            ));
            continue;
        }

        let hits =
            scan_pointer_target_hits(image, &space, &targets, MAX_DWM_POINTER_HITS, cancellation)?;
        report.surface_objects_examined += hits.len();
        for (hit, target) in hits {
            cancellation.check_cancelled()?;
            let parsed = match target {
                ResolutionTarget::SystemMemory => parse_system_memory_bitmap(&space, hit, 32_768)
                    .map(|(_, width, height, _, _)| {
                        (width, height, "dwm_system_memory_bitmap", hit)
                    }),
                ResolutionTarget::LegacyD3d { texture_vtable } => {
                    parse_legacy_surface_resolution(&space, hit, texture_vtable, 32_768).map(
                        |(width, height)| {
                            (
                                width,
                                height,
                                "dwm_legacy_composition_surface",
                                hit.saturating_sub(0x78),
                            )
                        },
                    )
                }
            };
            let Some((width, height, source, evidence_address)) = parsed else {
                continue;
            };
            let aggregate = resolutions.entry((width, height)).or_default();
            aggregate.surface_count += 1;
            aggregate.sources.insert(source);
            aggregate.dwm_pids.insert(process.pid);
            if aggregate.evidence_addresses.len() < 32 {
                aggregate.evidence_addresses.insert(evidence_address);
            }
        }
    }

    if resolutions.is_empty() {
        let (registry_resolutions, truncated) =
            detect_registry_display_configurations(image, cancellation)?;
        if !registry_resolutions.is_empty() {
            resolutions = registry_resolutions;
            report.complete = false;
            report.warnings.push(
                "DWM 显示表面不可用；结果来自物理内存中的注册表显示配置值，表示已配置/活动模式候选，不等同于已恢复的实时桌面帧"
                    .to_owned(),
            );
        }
        if truncated {
            report.complete = false;
            report.warnings.push(format!(
                "注册表显示配置锚点超过每类上限 {MAX_REGISTRY_DIMENSION_HITS}，结果可能不完整"
            ));
        }
    }

    report.records = resolutions
        .into_iter()
        .map(|((width, height), aggregate)| {
            let confidence = if aggregate.surface_count > 0 {
                "verified_dwm_surface"
            } else if aggregate.sources.contains("registry_primary_surface_size") {
                "corroborated_registry_display_configuration"
            } else {
                "verified_registry_display_configuration"
            };
            ScreenResolutionRecord {
                resolution: format!("{width} × {height}"),
                width,
                height,
                orientation: if width > height {
                    "landscape"
                } else if height > width {
                    "portrait"
                } else {
                    "square"
                },
                aspect_ratio: width as f64 / height as f64,
                likely_primary: false,
                surface_count: aggregate.surface_count,
                registry_value_pairs: aggregate.registry_value_pairs,
                sources: aggregate.sources.into_iter().collect(),
                dwm_pids: aggregate.dwm_pids.into_iter().collect(),
                evidence_addresses: aggregate.evidence_addresses.into_iter().collect(),
                confidence,
            }
        })
        .collect();
    report.records.sort_by(|left, right| {
        let left_area = u64::from(left.width) * u64::from(left.height);
        let right_area = u64::from(right.width) * u64::from(right.height);
        right_area
            .cmp(&left_area)
            .then_with(|| right.surface_count.cmp(&left.surface_count))
    });
    if let Some(primary_area) = report
        .records
        .first()
        .map(|record| u64::from(record.width) * u64::from(record.height))
    {
        for record in &mut report.records {
            record.likely_primary =
                u64::from(record.width) * u64::from(record.height) == primary_area;
        }
    }
    if report.records.len() > limit {
        report.records.truncate(limit);
        report.complete = false;
        report.warnings.push(format!(
            "屏幕分辨率结果超过上限 {limit}，仅保留前 {limit} 项"
        ));
    }
    if report.records.is_empty() {
        report.complete = false;
        report
            .warnings
            .push("没有恢复到通过 DWM 表面或严格注册表值单元验证的显示器级分辨率".to_owned());
    }
    Ok(report)
}

fn detect_registry_display_configurations(
    image: &MemoryImage,
    cancellation: &CancellationToken,
) -> Result<(ResolutionAggregates, bool)> {
    let scan = scan_patterns_streaming_cancellable(
        image,
        &REGISTRY_DIMENSION_PATTERNS,
        MAX_REGISTRY_DIMENSION_HITS,
        REGISTRY_SCAN_CHUNK_SIZE,
        cancellation,
    )?;
    let mut hits = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    for hit in scan.hits {
        let Some(expected_name) = REGISTRY_DIMENSION_PATTERNS.get(hit.pattern_index) else {
            continue;
        };
        if let Some(value) = parse_inline_registry_dword(image, hit.physical_address, expected_name)
        {
            hits[hit.pattern_index].push(value);
        }
    }

    let mut resolutions = BTreeMap::<(u32, u32), ResolutionAggregate>::new();
    for width in &hits[0] {
        cancellation.check_cancelled()?;
        let expected_height_cell = width.cell_address.saturating_add(width.cell_size);
        let Some(height) = hits[1]
            .iter()
            .find(|height| height.cell_address == expected_height_cell)
        else {
            continue;
        };
        if !plausible_registry_display_dimensions(width.value, height.value) {
            continue;
        }
        let aggregate = resolutions.entry((width.value, height.value)).or_default();
        aggregate.registry_value_pairs += 1;
        aggregate.sources.insert("registry_active_size");
        if aggregate.evidence_addresses.len() < 32 {
            aggregate.evidence_addresses.insert(width.cell_address);
            aggregate.evidence_addresses.insert(height.cell_address);
        }

        let primary_width = nearest_registry_value(
            &hits[2],
            width.cell_address,
            width.value,
            REGISTRY_CORROBORATION_DISTANCE,
        );
        let primary_height = nearest_registry_value(
            &hits[3],
            width.cell_address,
            height.value,
            REGISTRY_CORROBORATION_DISTANCE,
        );
        if let (Some(primary_width), Some(primary_height)) = (primary_width, primary_height) {
            aggregate.sources.insert("registry_primary_surface_size");
            if aggregate.evidence_addresses.len() < 32 {
                aggregate
                    .evidence_addresses
                    .insert(primary_width.cell_address);
                aggregate
                    .evidence_addresses
                    .insert(primary_height.cell_address);
            }
        }
    }
    Ok((resolutions, scan.truncated))
}

fn parse_inline_registry_dword(
    image: &MemoryImage,
    name_address: u64,
    expected_name: &[u8],
) -> Option<RegistryDwordHit> {
    let cell_address = name_address.checked_sub(24)?;
    let mut bytes = vec![0u8; 24 + expected_name.len()];
    image.read_physical(cell_address, &mut bytes).ok()?;
    let signed_size = i32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let cell_size = u64::from(signed_size.checked_neg()? as u32);
    if !(24 + expected_name.len()..=4096).contains(&usize::try_from(cell_size).ok()?)
        || cell_size % 8 != 0
        || &bytes[4..6] != b"vk"
        || usize::from(u16::from_le_bytes(bytes[6..8].try_into().ok()?)) != expected_name.len()
        || u32::from_le_bytes(bytes[8..12].try_into().ok()?) != 0x8000_0004
        || u32::from_le_bytes(bytes[16..20].try_into().ok()?) != 4
        || u16::from_le_bytes(bytes[20..22].try_into().ok()?) & 1 == 0
        || &bytes[24..] != expected_name
    {
        return None;
    }
    Some(RegistryDwordHit {
        cell_address,
        cell_size,
        value: u32::from_le_bytes(bytes[12..16].try_into().ok()?),
    })
}

fn nearest_registry_value(
    hits: &[RegistryDwordHit],
    anchor: u64,
    value: u32,
    max_distance: u64,
) -> Option<&RegistryDwordHit> {
    hits.iter()
        .filter(|hit| hit.value == value && hit.cell_address.abs_diff(anchor) <= max_distance)
        .min_by_key(|hit| hit.cell_address.abs_diff(anchor))
}

fn plausible_registry_display_dimensions(width: u32, height: u32) -> bool {
    (320..=32_768).contains(&width)
        && (200..=32_768).contains(&height)
        && u64::from(width) * u64::from(height) >= 64_000
        && width <= height.saturating_mul(8)
        && height <= width.saturating_mul(8)
}

#[allow(clippy::too_many_arguments)]
pub fn recover_dwm_surfaces(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    symbol_store: &SymbolStore,
    output: &Path,
    max_dimension: u32,
    force: bool,
    cancellation: &CancellationToken,
) -> Result<DwmSurfaceReport> {
    recover_dwm_surfaces_in_session(
        image,
        kernel,
        profile,
        symbol_store,
        output,
        max_dimension,
        force,
        None,
        cancellation,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_dwm_surfaces_in_session(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    symbol_store: &SymbolStore,
    output: &Path,
    max_dimension: u32,
    force: bool,
    session_id: Option<u32>,
    cancellation: &CancellationToken,
) -> Result<DwmSurfaceReport> {
    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut report = DwmSurfaceReport {
        warnings: processes
            .warnings
            .iter()
            .map(|warning| format!("[{}] {}", warning.kind, warning.message))
            .collect(),
        complete: processes.complete,
        ..DwmSurfaceReport::default()
    };
    let dwm_processes = processes
        .processes
        .iter()
        .filter(|process| {
            process
                .name
                .trim_matches(['"', '\'', ' '])
                .eq_ignore_ascii_case("dwm.exe")
        })
        .collect::<Vec<_>>();
    if dwm_processes.is_empty() {
        report.complete = false;
        report
            .warnings
            .push("没有定位到 dwm.exe 进程，无法恢复合成表面".to_owned());
        return Ok(report);
    }

    for process in dwm_processes {
        cancellation.check_cancelled()?;
        if session_id.is_some_and(|session| {
            process
                .details
                .session_id
                .or(process.details.token_session_id)
                != Some(session)
        }) {
            continue;
        }
        report.processes_examined += 1;
        let Some(dtb) = process
            .details
            .user_directory_table_base
            .or(process.details.directory_table_base)
        else {
            report.complete = false;
            report
                .warnings
                .push(format!("dwm.exe PID {} 没有可用页表", process.pid));
            continue;
        };
        let space = match X64AddressSpace::new(image, dtb) {
            Ok(space) => space,
            Err(error) => {
                report.complete = false;
                report
                    .warnings
                    .push(format!("dwm.exe PID {} 页表无效：{error:#}", process.pid));
                continue;
            }
        };
        let modules = match ldr_modules(image, kernel, profile, Some(process.pid), 4096) {
            Ok(modules) => modules,
            Err(error) => {
                report.complete = false;
                report.warnings.push(format!(
                    "dwm.exe PID {} 模块枚举失败：{error:#}",
                    process.pid
                ));
                continue;
            }
        };
        let Some(dwmcore_base) = module_base(&modules.records, "dwmcore.dll") else {
            report.complete = false;
            report
                .warnings
                .push(format!("dwm.exe PID {} 未定位到 dwmcore.dll", process.pid));
            continue;
        };
        let dwmcore_pdb = resolve_virtual_module_pdb(
            image,
            &space,
            dtb,
            dwmcore_base,
            "dwmcore.pdb",
            symbol_store,
        )?;
        match recover_system_memory_frames(
            image,
            &space,
            &dwmcore_pdb,
            dwmcore_base,
            process.pid,
            output,
            max_dimension,
            force,
            cancellation,
        ) {
            Ok(mut frames) => report.frames.append(&mut frames),
            Err(error) => report.warnings.push(format!(
                "dwm.exe PID {} 的系统内存合成帧恢复失败：{error:#}",
                process.pid
            )),
        }

        let Some(surface_rva) = optional_symbol_rva(&dwmcore_pdb, CD3D_SURFACE_VTABLE)? else {
            report.warnings.push(format!(
                "dwm.exe PID {} 的 dwmcore 版本不包含旧式 CD3DSurface 主 vtable；已尝试系统内存合成帧路径",
                process.pid
            ));
            continue;
        };
        let Some(d3d11_base) = module_base(&modules.records, "d3d11.dll") else {
            report
                .warnings
                .push(format!("dwm.exe PID {} 未定位到 d3d11.dll", process.pid));
            continue;
        };
        let Some(warp_base) = module_base(&modules.records, "d3d10warp.dll") else {
            report.warnings.push(format!(
                "dwm.exe PID {} 未使用可验证的 d3d10warp.dll CPU 后备存储；GPU 驱动表面暂不导出",
                process.pid
            ));
            continue;
        };
        let d3d11_pdb =
            resolve_virtual_module_pdb(image, &space, dtb, d3d11_base, "d3d11.pdb", symbol_store)?;
        let surface_vtable = dwmcore_base + u64::from(surface_rva);
        let texture_vtable =
            d3d11_base + u64::from(exact_symbol_rva(&d3d11_pdb, D3D11_TEXTURE_VTABLE)?);
        let resource_vtable =
            d3d11_base + u64::from(exact_symbol_rva(&d3d11_pdb, D3D11_RESOURCE_VTABLE)?);
        let ddi_method = exact_symbol_rva(&d3d11_pdb, D3D11_GET_DDI_HANDLE)?;
        let mut ddi_code = [0u8; 96];
        space
            .read_virtual(d3d11_base + u64::from(ddi_method), &mut ddi_code)
            .context("读取 D3D11 GetDDIHandle 实现失败")?;
        let ddi_handle_offset = derive_d3d11_handle_offset(&ddi_code)?;

        let hits = scan_pointer_hits(
            image,
            &space,
            surface_vtable,
            MAX_DWM_POINTER_HITS,
            cancellation,
        )?;
        report.surface_objects_examined += hits.len();
        let mut candidates = Vec::new();
        for hit in hits {
            cancellation.check_cancelled()?;
            if let Some(candidate) = parse_surface_candidate(
                &space,
                hit,
                texture_vtable,
                resource_vtable,
                ddi_handle_offset,
                max_dimension,
            ) {
                candidates.push(candidate);
            }
        }
        if candidates.is_empty() {
            report.warnings.push(format!(
                "dwm.exe PID {} 找到了 CD3DSurface 类型，但没有通过纹理结构校验的表面",
                process.pid
            ));
            continue;
        }

        let observed_warp_vtable = space.read_u64(candidates[0].resource_address)?;
        let (warp_pdb, warp_resource_vtable) =
            resolve_warp_pdb(image, symbol_store, dtb, warp_base, observed_warp_vtable)?;
        let warp_method = exact_symbol_rva(&warp_pdb, WARP_GET_VIRTUAL_ADDRESS)?;
        let mut warp_code = [0u8; 160];
        space
            .read_virtual(warp_base + u64::from(warp_method), &mut warp_code)
            .context("读取 WARP GetVirtualAddress 实现失败")?;
        let warp_layout = derive_warp_address_layout(&warp_code)?;

        let mut published = BTreeSet::new();
        let remaining = MAX_EXPORTED_FRAMES.saturating_sub(report.frames.len());
        for candidate in candidates.into_iter().take(remaining) {
            cancellation.check_cancelled()?;
            if space.read_u64(candidate.resource_address).ok() != Some(warp_resource_vtable) {
                continue;
            }
            let Some(pixel_address) =
                warp_virtual_address(&space, candidate.resource_address, warp_layout)?
            else {
                continue;
            };
            if pixel_address == 0 || pixel_address >= 0x0000_8000_0000_0000 {
                continue;
            }
            let shape = space.read_u64(candidate.resource_address + warp_layout.primary_offset)?;
            let Some(stride) = locate_subresource_stride(
                &space,
                shape,
                pixel_address,
                candidate.width,
                candidate.height,
            )?
            else {
                report.warnings.push(format!(
                    "WARP 资源 {:#x} 缺少与 {}x{} 匹配的行跨度描述",
                    candidate.resource_address, candidate.width, candidate.height
                ));
                continue;
            };
            let total_bytes = u64::from(stride) * u64::from(candidate.height);
            if total_bytes == 0 || total_bytes > MAX_FRAME_BYTES {
                report.warnings.push(format!(
                    "跳过不合理的 DWM 表面 {:#x}：{} 字节",
                    candidate.surface_address, total_bytes
                ));
                continue;
            }
            if !published.insert((pixel_address, candidate.width, candidate.height, stride)) {
                continue;
            }
            let file_name = format!(
                "dwm-pid{}-surface-{:016x}-{}x{}.bmp",
                process.pid, candidate.surface_address, candidate.width, candidate.height
            );
            let frame_output = output.join(file_name);
            let stats = write_bgra_bmp(
                image,
                &space,
                pixel_address,
                candidate.width,
                candidate.height,
                stride,
                &frame_output,
                force,
                false,
                cancellation,
            )?;
            report.frames.push(DwmFrameRecord {
                render_kind: "verified_dwm_warp_frame",
                pid: process.pid,
                surface_address: candidate.surface_address,
                texture_address: candidate.texture_address,
                resource_address: candidate.resource_address,
                pixel_address,
                width: candidate.width,
                height: candidate.height,
                stride,
                format: candidate.format,
                recovered_bytes: stats.recovered_bytes,
                total_bytes: u64::from(candidate.width) * u64::from(candidate.height) * 4,
                coverage_percent: percent(
                    stats.recovered_bytes,
                    u64::from(candidate.width) * u64::from(candidate.height) * 4,
                ),
                sampled_non_black_percent: percent(stats.non_black_samples, stats.samples),
                output: frame_output,
            });
        }
    }

    if report.frames.is_empty() {
        report.complete = false;
        report.warnings.push(
            "没有导出像素级桌面帧；当前来源可能没有可读取的 DWM/WARP CPU 像素存储".to_owned(),
        );
    } else {
        report.complete &= report
            .frames
            .iter()
            .all(|frame| frame.recovered_bytes == frame.total_bytes);
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn recover_system_memory_frames(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    dwmcore_pdb: &Path,
    dwmcore_base: u64,
    pid: u64,
    output: &Path,
    max_dimension: u32,
    force: bool,
    cancellation: &CancellationToken,
) -> Result<Vec<DwmFrameRecord>> {
    let mut vtables = BTreeSet::new();
    for name in SYSTEM_MEMORY_VTABLES {
        if let Some(rva) = optional_symbol_rva(dwmcore_pdb, name)? {
            vtables.insert(dwmcore_base + u64::from(rva));
        }
    }

    let mut frames = Vec::new();
    let mut published = BTreeSet::new();
    for vtable in vtables {
        let hits = scan_pointer_hits(image, space, vtable, MAX_DWM_POINTER_HITS, cancellation)?;
        for hit in hits {
            cancellation.check_cancelled()?;
            let Some((pixel_address, width, height, stride, format)) =
                parse_system_memory_bitmap(space, hit, max_dimension)
            else {
                continue;
            };
            if !published.insert((pixel_address, width, height, stride)) {
                continue;
            }
            let total_bytes = u64::from(stride) * u64::from(height);
            if total_bytes == 0 || total_bytes > MAX_FRAME_BYTES {
                continue;
            }
            let frame_output = output.join(format!(
                "dwm-pid{pid}-sysmem-{hit:016x}-{width}x{height}.bmp"
            ));
            let stats = match write_bgra_bmp(
                image,
                space,
                pixel_address,
                width,
                height,
                stride,
                &frame_output,
                force,
                true,
                cancellation,
            ) {
                Ok(stats) => stats,
                Err(error) if error.downcast_ref::<EmptyDwmFrame>().is_some() => continue,
                Err(error) => return Err(error),
            };
            frames.push(DwmFrameRecord {
                render_kind: "verified_dwm_system_memory_frame",
                pid,
                surface_address: hit,
                texture_address: 0,
                resource_address: 0,
                pixel_address,
                width,
                height,
                stride,
                format,
                recovered_bytes: stats.recovered_bytes,
                total_bytes: u64::from(width) * u64::from(height) * 4,
                coverage_percent: percent(
                    stats.recovered_bytes,
                    u64::from(width) * u64::from(height) * 4,
                ),
                sampled_non_black_percent: percent(stats.non_black_samples, stats.samples),
                output: frame_output,
            });
            if frames.len() == MAX_EXPORTED_FRAMES {
                return Ok(frames);
            }
        }
    }
    Ok(frames)
}

fn parse_system_memory_bitmap(
    space: &X64AddressSpace<'_>,
    vtable_hit: u64,
    max_dimension: u32,
) -> Option<(u64, u32, u32, u32, u32)> {
    let pixel_address = space.read_u64(vtable_hit + 0x08).ok()?;
    let stride = read_virtual_u32(space, vtable_hit + 0x10)?;
    if pixel_address == 0 || pixel_address >= 0x0000_8000_0000_0000 {
        return None;
    }
    for relative in (0x10u64..=0x80).step_by(8) {
        let descriptor = vtable_hit.checked_sub(relative)?;
        let width = read_virtual_u32(space, descriptor)?;
        let height = read_virtual_u32(space, descriptor + 4)?;
        let format = read_virtual_u32(space, descriptor + 0x10)?;
        if plausible_display_dimensions(width, height, max_dimension)
            && format == DXGI_FORMAT_B8G8R8A8_UNORM
            && stride >= width.saturating_mul(4)
            && stride <= width.saturating_mul(16)
        {
            return Some((pixel_address, width, height, stride, format));
        }
    }
    None
}

fn plausible_display_dimensions(width: u32, height: u32, max_dimension: u32) -> bool {
    width <= max_dimension
        && height <= max_dimension
        && width.max(height) >= MIN_DISPLAY_LONG_EDGE
        && width.min(height) >= MIN_DISPLAY_SHORT_EDGE
        && u64::from(width) * u64::from(height) >= MIN_DISPLAY_PIXELS
}

fn module_base(records: &[super::pe_plugins::LdrModuleRecord], name: &str) -> Option<u64> {
    records.iter().find_map(|record| {
        let path = record
            .mapped_path
            .as_deref()
            .or(record.loader_path.as_deref())?;
        path.rsplit(['\\', '/'])
            .next()
            .is_some_and(|part| part.eq_ignore_ascii_case(name))
            .then_some(record.base)
    })
}

fn resolve_virtual_module_pdb(
    image: &MemoryImage,
    _space: &X64AddressSpace<'_>,
    dtb: u64,
    module_base: u64,
    pdb_name: &str,
    store: &SymbolStore,
) -> Result<PathBuf> {
    if let Ok(record) = codeview_from_virtual_pe(image, dtb, module_base) {
        ensure!(
            record.pdb_name.eq_ignore_ascii_case(pdb_name),
            "模块 PDB 名称不匹配"
        );
        return store.resolve(&record);
    }
    ensure!(
        !image.is_live(),
        "实时模块 {pdb_name} 的 CodeView 无法直接验证，拒绝使用其他内存位置的符号指纹"
    );
    let records = discover_codeview(image, pdb_name)?;
    ensure!(
        !records.is_empty(),
        "镜像中未恢复到 {pdb_name} CodeView 标识"
    );
    let mut errors = Vec::new();
    for record in records {
        match store.resolve(&record) {
            Ok(path) => return Ok(path),
            Err(error) => errors.push(error.to_string()),
        }
    }
    bail!("无法解析 {pdb_name}：{}", errors.join("；"))
}

fn resolve_warp_pdb(
    image: &MemoryImage,
    store: &SymbolStore,
    dtb: u64,
    module_base: u64,
    observed_vtable: u64,
) -> Result<(PathBuf, u64)> {
    if image.is_live() {
        let record = codeview_from_virtual_pe(image, dtb, module_base)
            .context("实时 WARP 模块的 CodeView 无法直接验证")?;
        ensure!(
            record.pdb_name.eq_ignore_ascii_case("d3d10warp.pdb"),
            "WARP 模块 PDB 名称不匹配"
        );
        let path = store.resolve(&record)?;
        let runtime = module_base + u64::from(exact_symbol_rva(&path, WARP_RESOURCE_VTABLE)?);
        ensure!(
            runtime == observed_vtable,
            "WARP 精确符号与当前资源类型不匹配"
        );
        return Ok((path, runtime));
    }
    let records = discover_codeview(image, "d3d10warp.pdb")?;
    ensure!(
        !records.is_empty(),
        "镜像中未恢复到 d3d10warp.pdb CodeView 标识"
    );
    let mut errors = Vec::new();
    for record in records {
        let path = match store.resolve(&record) {
            Ok(path) => path,
            Err(error) => {
                errors.push(format!("{}：{error:#}", record.symbol_key));
                continue;
            }
        };
        let Ok(rva) = exact_symbol_rva(&path, WARP_RESOURCE_VTABLE) else {
            continue;
        };
        let runtime = module_base + u64::from(rva);
        if runtime == observed_vtable {
            return Ok((path, runtime));
        }
    }
    bail!(
        "没有 d3d10warp.pdb 与运行时 UMResource vtable {observed_vtable:#x} 匹配{}",
        if errors.is_empty() {
            String::new()
        } else {
            format!("：{}", errors.join("；"))
        }
    )
}

fn exact_symbol_rva(path: &Path, name: &str) -> Result<u32> {
    let report = inspect_pdb(path, name, 32)?;
    report
        .matches
        .iter()
        .find(|symbol| symbol.name == name)
        .and_then(|symbol| symbol.rva)
        .with_context(|| format!("{} 缺少符号 {name}", path.display()))
}

fn optional_symbol_rva(path: &Path, name: &str) -> Result<Option<u32>> {
    let report = inspect_pdb(path, name, 32)?;
    Ok(report
        .matches
        .iter()
        .find(|symbol| symbol.name == name)
        .and_then(|symbol| symbol.rva))
}

fn scan_pointer_hits(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    target: u64,
    limit: usize,
    cancellation: &CancellationToken,
) -> Result<Vec<u64>> {
    let mappings = space.enumerate_mappings(VirtualAddressRegion::User, 262_144)?;
    let needle = target.to_le_bytes();
    let mut hits = Vec::new();
    for mapping in mappings.mappings {
        let mut offset = 0u64;
        while offset < mapping.length {
            cancellation.check_cancelled()?;
            let count = usize::try_from((mapping.length - offset).min(1024 * 1024))?;
            let mut bytes = vec![0u8; count];
            image.read_physical(mapping.physical_start + offset, &mut bytes)?;
            for relative in (0..bytes.len().saturating_sub(7)).step_by(8) {
                if bytes[relative..relative + 8] == needle {
                    hits.push(mapping.virtual_start + offset + relative as u64);
                    if hits.len() == limit {
                        return Ok(hits);
                    }
                }
            }
            offset += count as u64;
        }
    }
    Ok(hits)
}

fn scan_pointer_target_hits(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    targets: &BTreeMap<u64, ResolutionTarget>,
    limit_per_target: usize,
    cancellation: &CancellationToken,
) -> Result<Vec<(u64, ResolutionTarget)>> {
    let mappings = space.enumerate_mappings(VirtualAddressRegion::User, 262_144)?;
    let mut counts = BTreeMap::<u64, usize>::new();
    let mut hits = Vec::new();
    for mapping in mappings.mappings {
        let mut offset = 0u64;
        while offset < mapping.length {
            cancellation.check_cancelled()?;
            let count = usize::try_from((mapping.length - offset).min(1024 * 1024))?;
            let mut bytes = vec![0u8; count];
            image.read_physical(mapping.physical_start + offset, &mut bytes)?;
            for relative in (0..bytes.len().saturating_sub(7)).step_by(8) {
                let value = u64::from_le_bytes(bytes[relative..relative + 8].try_into()?);
                let Some(target) = targets.get(&value).copied() else {
                    continue;
                };
                let target_count = counts.entry(value).or_default();
                if *target_count >= limit_per_target {
                    continue;
                }
                *target_count += 1;
                hits.push((mapping.virtual_start + offset + relative as u64, target));
            }
            offset += count as u64;
        }
    }
    Ok(hits)
}

fn parse_surface_candidate(
    space: &X64AddressSpace<'_>,
    vtable_hit: u64,
    texture_vtable: u64,
    resource_vtable: u64,
    ddi_handle_offset: u64,
    max_dimension: u32,
) -> Option<SurfaceCandidate> {
    let texture_address = space.read_u64(vtable_hit + 0x08).ok()?;
    let width = read_virtual_u32(space, vtable_hit + 0x14)?;
    let height = read_virtual_u32(space, vtable_hit + 0x18)?;
    let format = read_virtual_u32(space, vtable_hit + 0x24)?;
    if texture_address == 0
        || space.read_u64(texture_address).ok()? != texture_vtable
        || !(16..=max_dimension).contains(&width)
        || !(16..=max_dimension).contains(&height)
        || format != DXGI_FORMAT_B8G8R8A8_UNORM
    {
        return None;
    }
    let mut texture = [0u8; 0x300];
    space.read_virtual(texture_address, &mut texture).ok()?;
    let resource_vtable_bytes = resource_vtable.to_le_bytes();
    let subobject_offset = (0..texture.len().saturating_sub(7))
        .step_by(8)
        .find(|offset| texture[*offset..*offset + 8] == resource_vtable_bytes)?;
    let resource_address = space
        .read_u64(texture_address + subobject_offset as u64 + ddi_handle_offset)
        .ok()?;
    (resource_address != 0).then_some(SurfaceCandidate {
        surface_address: vtable_hit.saturating_sub(0x78),
        texture_address,
        resource_address,
        width,
        height,
        format,
    })
}

fn parse_legacy_surface_resolution(
    space: &X64AddressSpace<'_>,
    vtable_hit: u64,
    texture_vtable: u64,
    max_dimension: u32,
) -> Option<(u32, u32)> {
    let texture_address = space.read_u64(vtable_hit + 0x08).ok()?;
    let width = read_virtual_u32(space, vtable_hit + 0x14)?;
    let height = read_virtual_u32(space, vtable_hit + 0x18)?;
    let format = read_virtual_u32(space, vtable_hit + 0x24)?;
    if texture_address == 0
        || texture_address >= 0x0000_8000_0000_0000
        || space.read_u64(texture_address).ok()? != texture_vtable
        || !plausible_display_dimensions(width, height, max_dimension)
        || format != DXGI_FORMAT_B8G8R8A8_UNORM
    {
        return None;
    }
    Some((width, height))
}

fn derive_d3d11_handle_offset(code: &[u8]) -> Result<u64> {
    ensure!(code.len() >= 7, "GetDDIHandle 指令流过短");
    for index in 0..=code.len() - 7 {
        if code[index..index + 3] == [0x48, 0x81, 0xc1] {
            return Ok(u64::from(u32::from_le_bytes(
                code[index + 3..index + 7]
                    .try_into()
                    .expect("fixed displacement"),
            )));
        }
    }
    bail!("无法从 GetDDIHandle 指令流推导资源句柄字段")
}

fn derive_warp_address_layout(code: &[u8]) -> Result<WarpAddressLayout> {
    ensure!(code.len() >= 96, "GetVirtualAddress 指令流过短");
    let device_offset = find_disp8(code, [0x48, 0x8b, 0x41])?;
    let encoded_offset = find_disp32(code, [0x0f, 0xb6, 0x91])?;
    let generation_offset = find_disp32(code, [0x80, 0xb8])?;
    let mut pointer_offsets = BTreeMap::<u64, usize>::new();
    for pattern in [[0x48, 0x8b, 0x81], [0x48, 0x8b, 0x91]] {
        for value in find_all_disp32(code, pattern) {
            *pointer_offsets.entry(value).or_default() += 1;
        }
    }
    let primary_offset = pointer_offsets
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .map(|(offset, _)| offset)
        .min()
        .context("无法从 GetVirtualAddress 推导 ResourceShape 字段")?;
    let mut allocation_offsets = find_all_disp8(code, [0x48, 0x8b, 0x42]);
    allocation_offsets.sort_unstable();
    allocation_offsets.dedup();
    ensure!(
        allocation_offsets.len() >= 2,
        "无法推导 WARP allocation 地址字段"
    );
    Ok(WarpAddressLayout {
        device_offset,
        generation_offset,
        encoded_offset,
        primary_offset,
        preferred_address_offset: allocation_offsets[0],
        fallback_address_offset: *allocation_offsets.last().expect("checked"),
    })
}

fn find_disp8<const N: usize>(bytes: &[u8], pattern: [u8; N]) -> Result<u64> {
    ensure!(bytes.len() > N, "指令流过短");
    for index in 0..=bytes.len() - N - 1 {
        if bytes[index..index + N] == pattern {
            return Ok(u64::from(bytes[index + N]));
        }
    }
    bail!("指令特征 {:?} 不存在", pattern)
}

fn find_all_disp8<const N: usize>(bytes: &[u8], pattern: [u8; N]) -> Vec<u64> {
    if bytes.len() <= N {
        return Vec::new();
    }
    (0..=bytes.len() - N - 1)
        .filter(|index| bytes[*index..*index + N] == pattern)
        .map(|index| u64::from(bytes[index + N]))
        .collect()
}

fn find_disp32<const N: usize>(bytes: &[u8], pattern: [u8; N]) -> Result<u64> {
    find_all_disp32(bytes, pattern)
        .into_iter()
        .next()
        .with_context(|| "指令特征不存在")
}

fn find_all_disp32<const N: usize>(bytes: &[u8], pattern: [u8; N]) -> Vec<u64> {
    if bytes.len() < N + 4 {
        return Vec::new();
    }
    (0..=bytes.len() - N - 4)
        .filter(|index| bytes[*index..*index + N] == pattern)
        .map(|index| {
            u64::from(u32::from_le_bytes(
                bytes[index + N..index + N + 4]
                    .try_into()
                    .expect("fixed displacement"),
            ))
        })
        .collect()
}

fn warp_virtual_address(
    space: &X64AddressSpace<'_>,
    resource: u64,
    layout: WarpAddressLayout,
) -> Result<Option<u64>> {
    let device = space.read_u64(resource + layout.device_offset)?;
    let generation = read_virtual_u8(space, device + layout.generation_offset)?;
    let encoded = read_virtual_u8(space, resource + layout.encoded_offset)? != 0;
    // WDDM 2 GPU virtual addresses and renamed resources require kernel/GPU allocation
    // translation. Only export the older WARP CPU mapping that is directly captured.
    if generation >= 0x11 || encoded {
        return Ok(None);
    }
    let shape = space.read_u64(resource + layout.primary_offset)?;
    if shape == 0 {
        return Ok(None);
    }
    let preferred = space
        .read_u64(shape + layout.preferred_address_offset)
        .unwrap_or(0);
    if preferred != 0 {
        return Ok(Some(preferred));
    }
    Ok(Some(
        space.read_u64(shape + layout.fallback_address_offset)?,
    ))
}

fn locate_subresource_stride(
    space: &X64AddressSpace<'_>,
    shape: u64,
    pixels: u64,
    width: u32,
    height: u32,
) -> Result<Option<u32>> {
    if shape == 0 {
        return Ok(None);
    }
    let mut bytes = [0u8; 0x800];
    space.read_virtual(shape, &mut bytes)?;
    let needle = pixels.to_le_bytes();
    for start in (0..bytes.len().saturating_sub(40)).step_by(8) {
        if bytes[start..start + 8] != needle {
            continue;
        }
        let stride = u32::from_le_bytes(bytes[start + 0x18..start + 0x1c].try_into()?);
        let described_width = u32::from_le_bytes(bytes[start + 0x20..start + 0x24].try_into()?);
        let described_height = u32::from_le_bytes(bytes[start + 0x24..start + 0x28].try_into()?);
        if described_width == width
            && described_height == height
            && stride >= width.saturating_mul(4)
            && stride <= width.saturating_mul(16)
        {
            return Ok(Some(stride));
        }
    }
    Ok(None)
}

/// A range in the packed, top-down BMP pixel array (header excluded).
/// `source` describes the first byte; missing ranges have no physical source.
#[derive(Debug, Clone, Serialize)]
pub struct PixelByteRange {
    pub pixel_offset: u64,
    pub virtual_address: u64,
    pub physical_address: Option<u64>,
    pub length: u64,
    pub source: Option<crate::image::SourceLocation>,
}

pub(crate) struct WriteStats {
    pub recovered_bytes: u64,
    pub samples: u64,
    pub non_black_samples: u64,
    pub ranges: Vec<PixelByteRange>,
    pub pixel_sha256: String,
    pub recovered_sha256: String,
    pub bgr_sha256: String,
    pub output_sha256: String,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_bgra_bmp(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    pixels: u64,
    width: u32,
    height: u32,
    stride: u32,
    output: &Path,
    force: bool,
    require_non_black: bool,
    cancellation: &CancellationToken,
) -> Result<WriteStats> {
    ensure!(
        width > 0 && height > 0 && width <= i32::MAX as u32 && height <= i32::MAX as u32,
        "无效的 BMP 尺寸"
    );
    let row_bytes = u64::from(width) * 4;
    ensure!(u64::from(stride) >= row_bytes, "像素行步长小于行宽");
    pixels
        .checked_add(u64::from(height - 1) * u64::from(stride))
        .and_then(|last| last.checked_add(row_bytes))
        .context("像素地址溢出")?;
    let mut policy = OutputPolicy::new(force);
    for source in image.sources() {
        policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    policy.output(OutputTarget::file("dwm_frame.bmp", output));
    policy.preflight()?;
    let pixel_bytes = u64::from(width) * u64::from(height) * 4;
    let file_size = 54u64 + pixel_bytes;
    ensure!(file_size <= u64::from(u32::MAX), "BMP 文件超过 4 GiB");
    let mut header = [0u8; 54];
    header[..2].copy_from_slice(b"BM");
    header[2..6].copy_from_slice(&(file_size as u32).to_le_bytes());
    header[10..14].copy_from_slice(&54u32.to_le_bytes());
    header[14..18].copy_from_slice(&40u32.to_le_bytes());
    header[18..22].copy_from_slice(&(width as i32).to_le_bytes());
    header[22..26].copy_from_slice(&(-(height as i32)).to_le_bytes());
    header[26..28].copy_from_slice(&1u16.to_le_bytes());
    header[28..30].copy_from_slice(&32u16.to_le_bytes());
    header[34..38].copy_from_slice(&(pixel_bytes as u32).to_le_bytes());
    let mut completed_stats = None;
    policy.write_file_atomic(output, |file| {
        let mut writer = BufWriter::new(file);
        writer.write_all(&header)?;
        let row_len = usize::try_from(u64::from(width) * 4)?;
        let mut row = vec![0u8; row_len];
        let mut stats = WriteStats {
            recovered_bytes: 0,
            samples: 0,
            non_black_samples: 0,
            ranges: Vec::new(),
            pixel_sha256: String::new(),
            recovered_sha256: String::new(),
            bgr_sha256: String::new(),
            output_sha256: String::new(),
        };
        let mut packed_hash = Sha256::new();
        let mut recovered_hash = Sha256::new();
        let mut bgr_hash = Sha256::new();
        let mut output_hash = Sha256::new();
        let mut has_non_black_pixels = false;
        output_hash.update(header);
        for y in 0..height {
            cancellation.check_cancelled()?;
            row.fill(0);
            let row_address = pixels + u64::from(y) * u64::from(stride);
            let mut offset = 0usize;
            while offset < row.len() {
                let address = row_address + offset as u64;
                let count = (0x1000 - (address as usize & 0xfff)).min(row.len() - offset);
                let physical = space.translate(address).ok().filter(|physical| {
                    image
                        .read_physical(*physical, &mut row[offset..offset + count])
                        .is_ok()
                });
                if physical.is_some() {
                    stats.recovered_bytes += count as u64;
                    recovered_hash.update(&row[offset..offset + count]);
                } else {
                    // A failed multi-step read may already have modified the
                    // destination. Do not publish those unverified bytes.
                    row[offset..offset + count].fill(0);
                }
                stats.ranges.push(PixelByteRange {
                    pixel_offset: u64::from(y) * row_len as u64 + offset as u64,
                    virtual_address: address,
                    physical_address: physical,
                    length: count as u64,
                    source: physical.and_then(|pa| image.source_location(pa)),
                });
                offset += count;
            }
            if y % 32 == 0 {
                for pixel in row.chunks_exact(4).step_by(32) {
                    stats.samples += 1;
                    if pixel[0] != 0 || pixel[1] != 0 || pixel[2] != 0 {
                        stats.non_black_samples += 1;
                    }
                }
            }
            packed_hash.update(&row);
            output_hash.update(&row);
            // X/alpha is deliberately excluded from the comparison hash only.
            // The BMP and packed hash preserve all original fourth bytes.
            for pixel in row.chunks_exact(4) {
                bgr_hash.update(&pixel[..3]);
                has_non_black_pixels |= pixel[..3] != [0, 0, 0];
            }
            writer.write_all(&row)?;
        }
        writer.flush()?;
        if require_non_black && (stats.recovered_bytes == 0 || !has_non_black_pixels) {
            return Err(EmptyDwmFrame.into());
        }
        stats.pixel_sha256 = hex::encode(packed_hash.finalize());
        stats.recovered_sha256 = hex::encode(recovered_hash.finalize());
        stats.bgr_sha256 = hex::encode(bgr_hash.finalize());
        stats.output_sha256 = hex::encode(output_hash.finalize());
        completed_stats = Some(stats);
        Ok(())
    })?;
    completed_stats.context("桌面帧写出未生成统计")
}

#[derive(Debug)]
struct EmptyDwmFrame;

impl std::fmt::Display for EmptyDwmFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DWM frame contains no recoverable non-black samples")
    }
}

impl std::error::Error for EmptyDwmFrame {}

fn percent(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 * 100.0 / total as f64
    }
}

fn read_virtual_u8(space: &X64AddressSpace<'_>, address: u64) -> Result<u8> {
    let mut bytes = [0u8; 1];
    space.read_virtual(address, &mut bytes)?;
    Ok(bytes[0])
}

fn read_virtual_u32(space: &X64AddressSpace<'_>, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn bmp_counts_only_pixels_and_marks_missing_pages_black() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-dwm-pixels-{}-{nonce}.raw",
            std::process::id()
        ));
        let output = path.with_extension("bmp");
        let partial = path.with_extension("partial.bmp");
        let sparse = path.with_extension("sparse.bmp");
        let mut bytes = vec![0u8; 0x6000];
        for (at, entry) in [
            (0x1000, 0x2003u64),
            (0x2000, 0x3003),
            (0x3000, 0x4003),
            (0x4008, 0x5003),
        ] {
            bytes[at..at + 8].copy_from_slice(&entry.to_le_bytes());
        }
        bytes[0x5000..0x5008].fill(11);
        bytes[0x5008..0x5010].fill(99); // Row padding must not enter the BMP.
        bytes[0x5010..0x5018].fill(22);
        bytes[0x5ffc..0x6000].fill(33);
        bytes[0x510c..0x5110].fill(55); // Content outside the legacy 32x32 sample grid.
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 0x1000).unwrap();
        let token = CancellationToken::new();
        let stats = write_bgra_bmp(
            &image, &space, 0x1000, 2, 2, 16, &output, false, true, &token,
        )
        .unwrap();
        assert_eq!(stats.recovered_bytes, 16);
        let bmp = fs::read(&output).unwrap();
        assert_eq!(bmp.len(), 54 + 16);
        assert_eq!(&bmp[54..62], &[11; 8]);
        assert_eq!(&bmp[62..70], &[22; 8]);
        let stats = write_bgra_bmp(
            &image, &space, 0x1ffc, 2, 1, 8, &partial, false, true, &token,
        )
        .unwrap();
        assert_eq!(stats.recovered_bytes, 4);
        assert_eq!(stats.ranges.len(), 2);
        assert_eq!(stats.ranges[0].physical_address, Some(0x5ffc));
        assert_eq!(stats.ranges[1].physical_address, None);
        assert_eq!(stats.ranges[1].pixel_offset, 4);
        assert_eq!(stats.ranges[1].length, 4);
        assert_ne!(stats.pixel_sha256, stats.recovered_sha256);
        assert_eq!(
            &fs::read(&partial).unwrap()[54..],
            &[33, 33, 33, 33, 0, 0, 0, 0]
        );
        let stats = write_bgra_bmp(
            &image, &space, 0x1100, 2, 2, 8, &sparse, false, true, &token,
        )
        .unwrap();
        assert_eq!(stats.non_black_samples, 0);
        assert_eq!(&fs::read(&sparse).unwrap()[66..70], &[55; 4]);
        drop(image);
        for file in [output, partial, sparse, path] {
            fs::remove_file(file).unwrap();
        }
    }

    #[test]
    fn derives_current_d3d11_handle_offset() {
        let bytes = [
            0x48, 0x85, 0xd2, 0x74, 0x1d, 0x8a, 0x81, 0xc3, 0, 0, 0, 0x48, 0x81, 0xc1, 0xf0, 0, 0,
            0,
        ];
        assert_eq!(derive_d3d11_handle_offset(&bytes).unwrap(), 0xf0);
    }

    #[test]
    fn derives_current_warp_address_layout() {
        let mut bytes = vec![0x90; 120];
        bytes[0..4].copy_from_slice(&[0x48, 0x8b, 0x41, 0x60]);
        bytes[4..11].copy_from_slice(&[0x0f, 0xb6, 0x91, 0xae, 0x02, 0, 0]);
        bytes[11..18].copy_from_slice(&[0x80, 0xb8, 0x54, 0x0a, 0, 0, 0x11]);
        bytes[20..27].copy_from_slice(&[0x48, 0x8b, 0x91, 0x80, 0x02, 0, 0]);
        bytes[30..37].copy_from_slice(&[0x48, 0x8b, 0x81, 0x80, 0x02, 0, 0]);
        bytes[40..44].copy_from_slice(&[0x48, 0x8b, 0x42, 0x38]);
        bytes[50..54].copy_from_slice(&[0x48, 0x8b, 0x42, 0x78]);
        let layout = derive_warp_address_layout(&bytes).unwrap();
        assert_eq!(layout.device_offset, 0x60);
        assert_eq!(layout.generation_offset, 0xa54);
        assert_eq!(layout.encoded_offset, 0x2ae);
        assert_eq!(layout.primary_offset, 0x280);
        assert_eq!(layout.preferred_address_offset, 0x38);
        assert_eq!(layout.fallback_address_offset, 0x78);
    }

    #[test]
    fn rejects_application_bitmaps_as_display_frames() {
        assert!(!plausible_display_dimensions(1079, 860, 16_384));
        assert!(plausible_display_dimensions(2998, 1808, 16_384));
        assert!(plausible_display_dimensions(3838, 1920, 16_384));
        assert!(plausible_display_dimensions(1080, 1920, 16_384));
    }

    #[test]
    fn validates_inline_registry_display_dword_cell() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-screen-resolution-{}-{nonce}.raw",
            std::process::id()
        ));
        let name = b"ActiveSize.cx";
        let cell_offset = 64usize;
        let mut bytes = vec![0u8; 256];
        bytes[cell_offset..cell_offset + 4].copy_from_slice(&(-40i32).to_le_bytes());
        bytes[cell_offset + 4..cell_offset + 6].copy_from_slice(b"vk");
        bytes[cell_offset + 6..cell_offset + 8].copy_from_slice(&(name.len() as u16).to_le_bytes());
        bytes[cell_offset + 8..cell_offset + 12].copy_from_slice(&0x8000_0004u32.to_le_bytes());
        bytes[cell_offset + 12..cell_offset + 16].copy_from_slice(&3838u32.to_le_bytes());
        bytes[cell_offset + 16..cell_offset + 20].copy_from_slice(&4u32.to_le_bytes());
        bytes[cell_offset + 20..cell_offset + 22].copy_from_slice(&1u16.to_le_bytes());
        bytes[cell_offset + 24..cell_offset + 24 + name.len()].copy_from_slice(name);
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let hit = parse_inline_registry_dword(&image, (cell_offset + 24) as u64, name).unwrap();
        assert_eq!(hit.cell_address, cell_offset as u64);
        assert_eq!(hit.cell_size, 40);
        assert_eq!(hit.value, 3838);
        assert!(
            parse_inline_registry_dword(&image, (cell_offset + 24) as u64, b"PrimSurfSize.cx")
                .is_none()
        );
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn accepts_realistic_registry_display_modes_only() {
        assert!(plausible_registry_display_dimensions(1024, 768));
        assert!(plausible_registry_display_dimensions(3838, 1920));
        assert!(!plausible_registry_display_dimensions(1079, 1));
        assert!(!plausible_registry_display_dimensions(65_535, 1080));
    }
}
