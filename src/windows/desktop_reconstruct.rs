use std::collections::BTreeMap;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use serde::Serialize;

use super::WindowsKernelContext;
use super::desktop_pixels::{PixelRecoveryReport, recover_pixel_candidates};
use super::dwm_surfaces::{DwmFrameRecord, recover_dwm_surfaces_in_session};
use super::gui_plugins::{WindowRecord, WindowRect, windows};
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::profile::KernelProfile;
use crate::symbols::SymbolStore;

const MAX_WINDOWS: usize = 65_536;

#[derive(Debug, Clone)]
pub struct DesktopReconstructOptions {
    pub output: PathBuf,
    pub session_id: Option<u32>,
    pub desktop: Option<String>,
    pub limit: usize,
    pub max_dimension: u32,
    pub force: bool,
}

#[derive(Debug, Serialize)]
pub struct DesktopReconstructReport {
    pub desktops: Vec<DesktopCanvasRecord>,
    pub frames: Vec<DwmFrameRecord>,
    pub pixel_recovery: PixelRecoveryReport,
    pub manifest: PathBuf,
    pub windows_examined: usize,
    pub visible_windows: usize,
    pub rendered_windows: usize,
    pub pixel_backed_windows: usize,
    pub pixel_backed_frames: usize,
    pub pixel_coverage_percent: f64,
    pub layout_complete: bool,
    pub pixel_bytes_complete: bool,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DesktopCanvasRecord {
    pub session_id: u32,
    pub window_station: String,
    pub desktop: String,
    pub bounds: WindowRect,
    pub width: u32,
    pub height: u32,
    pub visible_windows: usize,
    pub rendered_windows: usize,
    pub pixel_backed_windows: usize,
    pub pixel_coverage_percent: f64,
    pub render_kind: &'static str,
    pub output: PathBuf,
}

pub fn reconstruct_desktops(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    symbol_store: &SymbolStore,
    options: &DesktopReconstructOptions,
    cancellation: &CancellationToken,
) -> Result<DesktopReconstructReport> {
    validate_options(options)?;
    cancellation.check_cancelled()?;
    let mut manifest_policy = OutputPolicy::new(options.force);
    for source in image.sources() {
        manifest_policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    manifest_policy.output(
        OutputTarget::directory("desktop_reconstruct", &options.output)
            .with_owned_file("desktop-reconstruct-report.json"),
    );
    manifest_policy.prepare_directories()?;

    let window_report = windows(image, kernel, profile, options.limit.min(MAX_WINDOWS))?;
    cancellation.check_cancelled()?;
    let windows_examined = window_report.records.len();
    let visible_windows = window_report
        .records
        .iter()
        .filter(|window| window.visible == Some(true))
        .count();
    let mut warnings = window_report.warnings;
    let mut grouped = BTreeMap::<(u32, String, String), Vec<&WindowRecord>>::new();
    for window in &window_report.records {
        if options
            .session_id
            .is_some_and(|session_id| window.session_id != session_id)
            || options
                .desktop
                .as_deref()
                .is_some_and(|desktop| !window.desktop.eq_ignore_ascii_case(desktop))
        {
            continue;
        }
        grouped
            .entry((
                window.session_id,
                window.window_station.clone(),
                window.desktop.clone(),
            ))
            .or_default()
            .push(window);
    }

    let mut desktops = Vec::new();
    for ((session_id, window_station, desktop), group) in grouped {
        cancellation.check_cancelled()?;
        let visible = group
            .iter()
            .copied()
            .filter(|window| {
                window.visible == Some(true)
                    && window
                        .window_rect
                        .is_some_and(|rect| rect.width() != 0 && rect.height() != 0)
            })
            .collect::<Vec<_>>();
        let Some(bounds) = desktop_bounds(&visible, options.max_dimension) else {
            warnings.push(format!(
                "会话 {session_id} 的 {window_station}\\{desktop} 没有可验证的可见桌面边界"
            ));
            continue;
        };
        let root_depth = visible
            .iter()
            .filter(|window| window.window_rect == Some(bounds))
            .map(|window| window.tree_depth)
            .min()
            .unwrap_or(0);
        let mut rendered = visible
            .iter()
            .copied()
            .filter(|window| {
                window.tree_depth <= root_depth.saturating_add(1)
                    && window.window_rect != Some(bounds)
                    && window
                        .window_rect
                        .is_some_and(|rect| intersects(rect, bounds))
            })
            .collect::<Vec<_>>();
        rendered.sort_by_key(|window| {
            (
                std::cmp::Reverse(window.tree_depth),
                std::cmp::Reverse(window.z_order),
                window.address,
            )
        });

        let file_name = format!(
            "session-{session_id}-{}-{}-layout.svg",
            sanitize_component(&window_station),
            sanitize_component(&desktop)
        );
        let output = options.output.join(file_name);
        write_svg(image, &output, bounds, &rendered, options.force)?;
        desktops.push(DesktopCanvasRecord {
            session_id,
            window_station,
            desktop,
            bounds,
            width: bounds.width(),
            height: bounds.height(),
            visible_windows: visible.len(),
            rendered_windows: rendered.len(),
            pixel_backed_windows: 0,
            pixel_coverage_percent: 0.0,
            render_kind: "verified_window_layout",
            output,
        });
    }

    if desktops.is_empty() {
        warnings.push("没有生成桌面布局画布".to_owned());
    }
    let pixel_recovery = match recover_pixel_candidates(
        image,
        kernel,
        profile,
        &window_report.records,
        options,
        cancellation,
    ) {
        Ok(report) => report,
        Err(error) => {
            cancellation.check_cancelled()?;
            PixelRecoveryReport {
                search_complete: false,
                warnings: vec![format!("通用像素候选恢复失败：{error:#}")],
                ..Default::default()
            }
        }
    };
    warnings.extend(pixel_recovery.warnings.iter().cloned());
    let (frames, dwm_complete) = if options.desktop.is_some() {
        warnings.push(
            "已按桌面名称筛选尺寸候选；旧 DWM 对象链缺少可验证的桌面名归属，跳过该路径".into(),
        );
        (Vec::new(), true)
    } else {
        match recover_dwm_surfaces_in_session(
            image,
            kernel,
            profile,
            symbol_store,
            &options.output,
            options.max_dimension,
            options.force,
            options.session_id,
            cancellation,
        ) {
            Ok(dwm) => {
                warnings.extend(dwm.warnings);
                (dwm.frames, dwm.complete)
            }
            Err(error) => {
                warnings.push(format!("DWM 像素表面恢复失败：{error:#}"));
                (Vec::new(), false)
            }
        }
    };
    cancellation.check_cancelled()?;
    let rendered_windows = desktops.iter().map(|canvas| canvas.rendered_windows).sum();
    let pixel_coverage_percent = frames
        .iter()
        .map(|frame| frame.coverage_percent)
        .chain(
            pixel_recovery
                .records
                .iter()
                .map(|record| record.coverage_percent),
        )
        .fold(0.0f64, f64::max);
    let pixel_backed_frames = frames.len() + pixel_recovery.records.len();
    let pixel_bytes_complete = pixel_backed_frames != 0
        && frames
            .iter()
            .all(|frame| frame.recovered_bytes == frame.total_bytes)
        && pixel_recovery
            .records
            .iter()
            .all(|record| record.bytes_complete);
    let layout_complete = window_report.complete && !desktops.is_empty();
    // Layout success cannot hide unreadable pixel candidates or an incomplete search.
    let complete = layout_complete && dwm_complete && pixel_recovery.search_complete;
    let manifest = options.output.join("desktop-reconstruct-report.json");
    let report = DesktopReconstructReport {
        desktops,
        pixel_backed_frames,
        frames,
        pixel_recovery,
        manifest: manifest.clone(),
        windows_examined,
        visible_windows,
        rendered_windows,
        pixel_backed_windows: 0,
        pixel_coverage_percent,
        layout_complete,
        pixel_bytes_complete,
        complete,
        warnings,
    };
    write_json_atomic(&manifest_policy, &manifest, &report)?;
    Ok(report)
}

fn validate_options(options: &DesktopReconstructOptions) -> Result<()> {
    ensure!(options.limit > 0, "桌面窗口结果上限必须大于零");
    ensure!(
        (320..=32_768).contains(&options.max_dimension),
        "桌面画布最大边长必须位于 320..=32768"
    );
    Ok(())
}

fn desktop_bounds(windows: &[&WindowRecord], max_dimension: u32) -> Option<WindowRect> {
    windows
        .iter()
        .filter_map(|window| window.window_rect)
        .filter(|rect| {
            rect.left <= 0
                && rect.top <= 0
                && rect.right >= 0
                && rect.bottom >= 0
                && rect.width() >= 320
                && rect.height() >= 200
                && rect.width() <= max_dimension
                && rect.height() <= max_dimension
        })
        .max_by_key(|rect| u64::from(rect.width()) * u64::from(rect.height()))
}

fn intersects(left: WindowRect, right: WindowRect) -> bool {
    left.left < right.right
        && left.right > right.left
        && left.top < right.bottom
        && left.bottom > right.top
}

fn write_svg(
    image: &MemoryImage,
    output: &Path,
    bounds: WindowRect,
    windows: &[&WindowRecord],
    force: bool,
) -> Result<()> {
    let mut policy = OutputPolicy::new(force);
    for source in image.sources() {
        policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    policy.output(OutputTarget::file("desktop_layout.svg", output));
    policy.preflight()?;
    policy.write_file_atomic(output, |file| {
        let mut writer = BufWriter::new(file);
        writeln!(
            writer,
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" width="{}" height="{}">"#,
            bounds.width(),
            bounds.height(),
            bounds.width(),
            bounds.height()
        )?;
        writeln!(
            writer,
            r##"<rect width="100%" height="100%" fill="#162033"/><g font-family="Segoe UI, sans-serif" font-size="13">"##
        )?;
        for window in windows {
            let Some(rect) = window.window_rect else {
                continue;
            };
            let clipped = clip_rect(rect, bounds);
            if clipped.width() == 0 || clipped.height() == 0 {
                continue;
            }
            let x = clipped.left - bounds.left;
            let y = clipped.top - bounds.top;
            let color = process_color(window.pid.unwrap_or(0));
            let label = window
                .title
                .as_deref()
                .filter(|title| !title.trim().is_empty())
                .map(str::to_owned)
                .or_else(|| window.process.clone())
                .unwrap_or_else(|| format!("window {:#x}", window.address));
            writeln!(
                writer,
                r##"<g><title>{}</title><rect x="{}" y="{}" width="{}" height="{}" rx="3" fill="#{:06x}" fill-opacity="0.34" stroke="#{:06x}" stroke-width="2"/>"##,
                escape_xml(&format!(
                    "{} · {} · PID {} · {:#x}",
                    label,
                    window.process.as_deref().unwrap_or("未关联"),
                    window.pid.unwrap_or(0),
                    window.address
                )),
                x,
                y,
                clipped.width(),
                clipped.height(),
                color,
                color,
            )?;
            if clipped.width() >= 80 && clipped.height() >= 24 {
                writeln!(
                    writer,
                    r##"<text x="{}" y="{}" fill="#f8fafc">{}</text>"##,
                    x.saturating_add(6),
                    y.saturating_add(18),
                    escape_xml(&label)
                )?;
            }
            writeln!(writer, "</g>")?;
        }
        writeln!(writer, "</g></svg>")?;
        writer.flush()?;
        Ok(())
    })
}

fn clip_rect(rect: WindowRect, bounds: WindowRect) -> WindowRect {
    WindowRect {
        left: rect.left.max(bounds.left),
        top: rect.top.max(bounds.top),
        right: rect.right.min(bounds.right),
        bottom: rect.bottom.min(bounds.bottom),
    }
}

fn process_color(pid: u64) -> u32 {
    let mut value = pid.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value ^= value >> 29;
    let red = 96 + ((value >> 16) & 0x7f) as u32;
    let green = 96 + ((value >> 8) & 0x7f) as u32;
    let blue = 96 + (value & 0x7f) as u32;
    (red << 16) | (green << 8) | blue
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
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
    let trimmed = sanitized.trim_matches([' ', '.']);
    if trimmed.is_empty() {
        "desktop".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn write_json_atomic(
    policy: &OutputPolicy,
    path: &Path,
    report: &DesktopReconstructReport,
) -> Result<()> {
    policy.write_file_atomic(path, |file| {
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, report)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(rect: WindowRect, depth: usize) -> WindowRecord {
        WindowRecord {
            address: 0x1000 + depth as u64,
            window_station: "WinSta0".to_owned(),
            session_id: 1,
            desktop: "Default".to_owned(),
            title: Some("Window".to_owned()),
            procedure: None,
            geometry_address: None,
            process: Some("app.exe".to_owned()),
            pid: Some(42),
            parent: None,
            next: None,
            child: None,
            style: Some(0x1000_0000),
            ex_style: Some(0),
            visible: Some(true),
            window_rect: Some(rect),
            client_rect: None,
            tree_depth: depth,
            z_order: 0,
            layout: "test".to_owned(),
        }
    }

    #[test]
    fn selects_largest_origin_containing_desktop_bounds() {
        let desktop = window(
            WindowRect {
                left: 0,
                top: 0,
                right: 1920,
                bottom: 1080,
            },
            0,
        );
        let app = window(
            WindowRect {
                left: 100,
                top: 100,
                right: 900,
                bottom: 700,
            },
            1,
        );
        let minimized = window(
            WindowRect {
                left: -32_000,
                top: -32_000,
                right: -31_900,
                bottom: -31_900,
            },
            1,
        );
        assert_eq!(
            desktop_bounds(&[&app, &minimized, &desktop], 8192),
            desktop.window_rect
        );
    }

    #[test]
    fn escapes_untrusted_window_titles_for_svg() {
        assert_eq!(escape_xml("a<&\"'"), "a&lt;&amp;&quot;&apos;");
    }
}
