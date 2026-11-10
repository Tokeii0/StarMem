use std::time::SystemTime;

use anyhow::{Result, ensure};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::Serialize;

use crate::image::ImageFormat;
use crate::session::AnalysisSession;
use crate::system::{ForensicTimestamp, analyze_system_info_quick};

const CLOCK_PROBE_PROCESS_LIMIT: usize = 1;
const MAX_CAPTURE_TOOL_CANDIDATES: usize = 64;
const WINDOWS_TO_UNIX_100NS: u64 = 116_444_736_000_000_000;
const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;

#[derive(Debug, Clone)]
pub struct AcquisitionInfoOptions {
    pub scan_tools: bool,
    pub include_host_times: bool,
    pub process_limit: usize,
    pub handle_limit: usize,
}

impl Default for AcquisitionInfoOptions {
    fn default() -> Self {
        Self {
            scan_tools: true,
            include_host_times: false,
            process_limit: 65_536,
            handle_limit: 200_000,
        }
    }
}

fn validate_options(options: &AcquisitionInfoOptions) -> Result<()> {
    if options.scan_tools {
        ensure!(
            options.process_limit > 0,
            "acquisition-info process limit must be greater than zero"
        );
        ensure!(
            options.handle_limit > 0,
            "acquisition-info handle limit must be greater than zero"
        );
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct AcquisitionInfoReport {
    pub image: String,
    pub image_format: String,
    pub file_size: u64,
    pub logical_size: u64,
    pub container_acquisition_metadata: ContainerAcquisitionMetadata,
    pub snapshot_observed_time: ForensicTimestamp,
    pub boot_time: ForensicTimestamp,
    pub previous_shutdown_time: ForensicTimestamp,
    pub previous_shutdown_time_status: String,
    pub previous_shutdown_time_reason: String,
    pub capture_tool_candidates: Vec<AcquisitionToolCandidate>,
    pub inferred_capture_window: Option<InferredCaptureWindow>,
    pub host_file_times: Option<HostFileTimes>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ContainerAcquisitionMetadata {
    pub available: bool,
    pub timestamp_raw: Option<u64>,
    pub timestamp_utc: Option<String>,
    pub source: Option<String>,
    pub semantic: String,
    pub exact_start: bool,
    pub exact_end: bool,
    pub confidence: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AcquisitionToolCandidate {
    pub pid: u64,
    pub process: String,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
    pub user_name: Option<String>,
    pub process_create_time_raw: Option<u64>,
    pub process_create_time: Option<String>,
    pub output_handles: Vec<AcquisitionOutputHandle>,
    pub current_image_bound: bool,
    pub relationship: String,
    pub confidence: String,
}

#[derive(Debug, Serialize)]
pub struct AcquisitionOutputHandle {
    pub handle: u32,
    pub object: u64,
    pub object_type: String,
    pub name: String,
    pub current_image_match: bool,
    pub match_basis: String,
}

#[derive(Debug, Serialize)]
pub struct InferredCaptureWindow {
    pub lower_bound_candidate_raw: Option<u64>,
    pub lower_bound_candidate: Option<String>,
    pub observed_time_raw: Option<u64>,
    pub observed_time: Option<String>,
    pub elapsed_100ns: Option<u64>,
    pub duration_seconds: Option<f64>,
    pub duration_semantic: String,
    pub semantic: String,
    pub exact_start: bool,
    pub exact_end: bool,
    pub observed_time_is_capture_end: bool,
    pub confidence: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct HostFileTimes {
    pub created_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub semantic: String,
    pub acquisition_time_supported: bool,
}

pub fn analyze_acquisition_info(
    session: &AnalysisSession,
    options: &AcquisitionInfoOptions,
) -> Result<AcquisitionInfoReport> {
    validate_options(options)?;

    // The quick system report currently enumerates processes to populate its
    // general-purpose process summary. Acquisition analysis consumes only the
    // clock fields, so probing one process avoids a second full traversal; the
    // dedicated tool scan below performs the sole full enumeration when asked.
    let system = analyze_system_info_quick(session, CLOCK_PROBE_PROCESS_LIMIT)?;
    let utc_offset_minutes = system.clock.timezone.utc_offset_minutes;
    let snapshot_observed_time =
        exact_filetime_timestamp(system.clock.system_time_details, utc_offset_minutes);
    let boot_time = exact_filetime_timestamp(system.clock.boot_time_details, utc_offset_minutes);
    // analyze_system_info_quick deliberately skips registry Hive recovery.  Do
    // not expose its empty placeholder as though ShutdownTime had been queried.
    let previous_shutdown_time =
        previous_shutdown_not_examined(system.clock.last_shutdown_time_details);
    let previous_shutdown_time_status = "not_examined".to_owned();
    let previous_shutdown_time_reason =
        "acquisition-info 快速时钟路径未恢复 SYSTEM Hive；未查询 CurrentControlSet\\Control\\Windows\\ShutdownTime"
            .to_owned();
    let mut warnings = session.warnings().to_vec();
    let container_acquisition_metadata = container_metadata(session.image().format());
    let mut capture_tool_candidates = Vec::new();
    let mut complete =
        snapshot_observed_time.raw_value.is_some() && previous_shutdown_time_status == "examined";
    if snapshot_observed_time.raw_value.is_none() {
        warnings.push(
            "未恢复 _KUSER_SHARED_DATA.SystemTime；不能给出镜像页中的系统时钟观察值".to_owned(),
        );
    }
    if previous_shutdown_time_status != "examined" {
        warnings.push(
            "未检查 SYSTEM Hive ShutdownTime；previous_shutdown_time_status=not_examined，报告 complete=false"
                .to_owned(),
        );
    }

    if options.scan_tools {
        let processes = session.processes(options.process_limit)?;
        complete &= processes.complete;
        warnings.extend(
            processes
                .warnings
                .iter()
                .map(|warning| format!("采集工具进程枚举/{}：{}", warning.kind, warning.message)),
        );
        let mut tool_processes = processes
            .processes
            .iter()
            .filter(|process| is_capture_tool(process))
            .collect::<Vec<_>>();
        tool_processes.sort_unstable_by(|left, right| {
            capture_tool_score(right)
                .cmp(&capture_tool_score(left))
                .then_with(|| {
                    right
                        .details
                        .create_time_raw
                        .cmp(&left.details.create_time_raw)
                })
                .then_with(|| left.pid.cmp(&right.pid))
        });
        if tool_processes.len() > MAX_CAPTURE_TOOL_CANDIDATES {
            complete = false;
            warnings.push(format!(
                "采集工具候选数 {} 超过安全检查上限 {MAX_CAPTURE_TOOL_CANDIDATES}；仅检查评分最高的候选",
                tool_processes.len()
            ));
            tool_processes.truncate(MAX_CAPTURE_TOOL_CANDIDATES);
        }

        for process in tool_processes {
            let handles = match session.handles(process.pid, options.handle_limit) {
                Ok(report) => report,
                Err(error) => {
                    complete = false;
                    warnings.push(format!(
                        "无法枚举候选采集工具 PID {} 的句柄：{error:#}",
                        process.pid
                    ));
                    continue;
                }
            };
            complete &= handles.complete;
            warnings.extend(
                handles
                    .warnings
                    .iter()
                    .map(|warning| format!("PID {} 句柄：{warning}", process.pid)),
            );
            let current_image = session.image().path();
            let output_handles = handles
                .records
                .into_iter()
                .filter_map(|handle| {
                    let name = handle.name?;
                    classify_capture_output_handle(&handle.object_type, &name, current_image).map(
                        |binding| AcquisitionOutputHandle {
                            handle: handle.handle,
                            object: handle.object,
                            object_type: handle.object_type,
                            name,
                            current_image_match: binding.current_image_match,
                            match_basis: binding.match_basis.to_owned(),
                        },
                    )
                })
                .collect::<Vec<_>>();
            let current_image_bound = output_handles
                .iter()
                .any(|output| output.current_image_match);
            let (relationship, confidence) = if current_image_bound {
                (
                    "capture_tool_process_with_current_image_output_handle",
                    "high",
                )
            } else if output_handles.is_empty() {
                (
                    "capture_tool_process_name_observed_without_output_file_handle",
                    "low",
                )
            } else {
                (
                    "capture_tool_process_with_unbound_memory_output_candidate",
                    "low",
                )
            };
            capture_tool_candidates.push(AcquisitionToolCandidate {
                pid: process.pid,
                process: process.name.clone(),
                image_path: process.details.image_path.clone(),
                command_line: process.details.command_line.clone(),
                user_name: process.details.user_name.clone(),
                process_create_time_raw: process.details.create_time_raw,
                process_create_time: process
                    .details
                    .create_time_raw
                    .and_then(filetime_to_utc)
                    .or_else(|| process.details.create_time.clone()),
                output_handles,
                current_image_bound,
                relationship: relationship.to_owned(),
                confidence: confidence.to_owned(),
            });
        }
    }

    capture_tool_candidates.sort_unstable_by(|left, right| {
        right
            .current_image_bound
            .cmp(&left.current_image_bound)
            .then_with(|| right.output_handles.len().cmp(&left.output_handles.len()))
            .then_with(|| {
                left.process_create_time_raw
                    .cmp(&right.process_create_time_raw)
            })
            .then_with(|| left.pid.cmp(&right.pid))
    });
    let inferred_capture_window =
        infer_capture_window(&capture_tool_candidates, &snapshot_observed_time);
    if options.scan_tools && inferred_capture_window.is_none() {
        let has_bound_output = capture_tool_candidates
            .iter()
            .any(|tool| tool.current_image_bound);
        let has_unbound_output = capture_tool_candidates
            .iter()
            .any(|tool| !tool.output_handles.is_empty() && !tool.current_image_bound);
        if has_bound_output {
            warnings.push(
                "发现与当前检材文件名匹配的采集工具输出句柄，但进程创建时间与镜像内系统时钟不足以形成有序的证据区间"
                    .to_owned(),
            );
        } else if has_unbound_output {
            warnings.push(format!(
                "发现采集工具内存输出候选，但没有输出句柄文件名与当前检材 {} 精确匹配；候选保持低置信度且不生成采集区间",
                session
                    .image()
                    .path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("<非 UTF-8 文件名>")
            ));
        }
    }
    let host_file_times = options
        .include_host_times
        .then(|| host_file_times(session.image().path()))
        .transpose()?;

    Ok(AcquisitionInfoReport {
        image: session.image().path().display().to_string(),
        image_format: image_format_name(session.image().format()).to_owned(),
        file_size: session.image().file_len(),
        logical_size: session.image().logical_len(),
        container_acquisition_metadata,
        snapshot_observed_time,
        boot_time,
        previous_shutdown_time,
        previous_shutdown_time_status,
        previous_shutdown_time_reason,
        capture_tool_candidates,
        inferred_capture_window,
        host_file_times,
        complete,
        warnings,
    })
}

fn container_metadata(format: &ImageFormat) -> ContainerAcquisitionMetadata {
    match format {
        ImageFormat::WindowsCrashDump64(dump) if dump.system_time_raw != 0 => {
            ContainerAcquisitionMetadata {
                available: true,
                timestamp_raw: Some(dump.system_time_raw),
                timestamp_utc: filetime_to_utc(dump.system_time_raw),
                source: Some("windows_crash_dump_header.SystemTime".to_owned()),
                semantic: "container_header_guest_system_time_observation".to_owned(),
                exact_start: false,
                exact_end: false,
                confidence: "high_for_header_value_not_for_acquisition_boundary".to_owned(),
                reason: Some(
                    "崩溃转储头 SystemTime 是写入头部的来宾系统时间；它不是采集开始或采集结束字段"
                        .to_owned(),
                ),
            }
        }
        ImageFormat::Raw => ContainerAcquisitionMetadata {
            available: false,
            timestamp_raw: None,
            timestamp_utc: None,
            source: None,
            semantic: "no_container_timestamp".to_owned(),
            exact_start: false,
            exact_end: false,
            confidence: "not_applicable".to_owned(),
            reason: Some("raw 镜像没有标准容器采集时间头".to_owned()),
        },
        ImageFormat::ExpertWitness { .. } => ContainerAcquisitionMetadata {
            available: false,
            timestamp_raw: None,
            timestamp_utc: None,
            source: None,
            semantic: "container_metadata_not_exposed".to_owned(),
            exact_start: false,
            exact_end: false,
            confidence: "unknown".to_owned(),
            reason: Some(
                "当前构建尚未公开 EWF acquisition metadata；保留镜像内系统时钟作为独立证据"
                    .to_owned(),
            ),
        },
        _ => ContainerAcquisitionMetadata {
            available: false,
            timestamp_raw: None,
            timestamp_utc: None,
            source: None,
            semantic: "no_verified_container_timestamp".to_owned(),
            exact_start: false,
            exact_end: false,
            confidence: "unknown".to_owned(),
            reason: Some("该容器格式没有可验证的标准采集时间字段".to_owned()),
        },
    }
}

fn image_format_name(format: &ImageFormat) -> &'static str {
    match format {
        ImageFormat::Raw => "raw",
        ImageFormat::VmwareVmem { .. } => "vmware_vmem",
        ImageFormat::ElfPhysicalCore { .. } => "elf_physical_core",
        ImageFormat::XenElf64(_) => "xen_elf64",
        ImageFormat::AvmlV2 { .. } => "avml_v2",
        ImageFormat::QevmV3 { .. } => "qevm_v3",
        ImageFormat::Lime { .. } => "lime",
        ImageFormat::WindowsCrashDump64(_) => "windows_crash_dump64",
        ImageFormat::ExpertWitness { .. } => "expert_witness",
    }
}

fn capture_tool_haystack(process: &crate::windows::ProcessRecord) -> String {
    format!(
        "{} {} {}",
        process.name,
        process.details.image_path.as_deref().unwrap_or(""),
        process.details.command_line.as_deref().unwrap_or("")
    )
    .to_lowercase()
}

fn is_capture_tool(process: &crate::windows::ProcessRecord) -> bool {
    let haystack = capture_tool_haystack(process);
    [
        "ftk imager",
        "ftkimager",
        "dumpit",
        "winpmem",
        "magnet ram capture",
        "magnetramcapture",
        "belkasoft",
        "ramcapture",
        "memoryze",
        "win32dd",
        "win64dd",
        "osforensics",
    ]
    .iter()
    .any(|needle| haystack.contains(needle))
}

fn capture_tool_score(process: &crate::windows::ProcessRecord) -> u8 {
    let haystack = capture_tool_haystack(process);
    if [
        "ftk imager",
        "ftkimager",
        "magnet ram capture",
        "magnetramcapture",
    ]
    .iter()
    .any(|needle| haystack.contains(needle))
    {
        3
    } else if [
        "dumpit",
        "winpmem",
        "ramcapture",
        "memoryze",
        "win32dd",
        "win64dd",
    ]
    .iter()
    .any(|needle| haystack.contains(needle))
    {
        2
    } else {
        1
    }
}

fn is_capture_output_path(path: &str) -> bool {
    let basename = path
        .trim_end_matches('\0')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    [".mem", ".raw", ".vmem", ".lime"]
        .iter()
        .any(|extension| basename.ends_with(extension))
}

fn is_capture_output_handle(object_type: &str, path: &str) -> bool {
    object_type.eq_ignore_ascii_case("File") && is_capture_output_path(path)
}

struct CaptureOutputBinding {
    current_image_match: bool,
    match_basis: &'static str,
}

fn classify_capture_output_handle(
    object_type: &str,
    path: &str,
    current_image: &std::path::Path,
) -> Option<CaptureOutputBinding> {
    if !is_capture_output_handle(object_type, path) {
        return None;
    }
    let output_basename = path
        .trim_end_matches('\0')
        .rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty());
    let current_basename = current_image.file_name().and_then(|name| name.to_str());
    let current_image_match = output_basename
        .zip(current_basename)
        .is_some_and(|(output, current)| output.eq_ignore_ascii_case(current));
    Some(CaptureOutputBinding {
        current_image_match,
        match_basis: if current_image_match {
            "current_image_basename"
        } else {
            "memory_image_extension_only"
        },
    })
}

fn infer_capture_window(
    tools: &[AcquisitionToolCandidate],
    observed: &ForensicTimestamp,
) -> Option<InferredCaptureWindow> {
    let observed_raw = observed.raw_value?;
    let tool = tools
        .iter()
        .filter(|tool| tool.current_image_bound)
        .filter_map(|tool| {
            let created = tool.process_create_time_raw?;
            (created <= observed_raw).then_some((tool, created))
        })
        // The newest ordered tool start gives the narrowest defensible
        // evidence interval. It is not asserted to be the acquisition start.
        .max_by_key(|(_, created)| *created)?;
    let (tool, lower_raw) = tool;
    let elapsed_100ns = observed_raw.checked_sub(lower_raw);
    Some(InferredCaptureWindow {
        lower_bound_candidate_raw: Some(lower_raw),
        lower_bound_candidate: filetime_to_utc(lower_raw),
        observed_time_raw: Some(observed_raw),
        observed_time: filetime_to_utc(observed_raw),
        elapsed_100ns,
        duration_seconds: elapsed_100ns.map(|ticks| ticks as f64 / 10_000_000.0),
        duration_semantic:
            "elapsed_between_tool_process_creation_and_snapshot_clock_observation_not_capture_duration"
                .to_owned(),
        semantic: "ordered_evidence_interval_not_exact_capture_window".to_owned(),
        exact_start: false,
        exact_end: false,
        observed_time_is_capture_end: false,
        confidence: "medium".to_owned(),
        reason: format!(
            "PID {} {} 持有文件名与当前检材匹配的内存输出句柄；进程创建时间仅表示采集不可能早于工具进程存在之前，镜像内系统时钟仅是该页被读取时的观察值，两者间隔不是精确采集耗时或结束时间",
            tool.pid, tool.process
        ),
    })
}

fn previous_shutdown_not_examined(mut timestamp: ForensicTimestamp) -> ForensicTimestamp {
    timestamp.raw_value = None;
    timestamp.utc = None;
    timestamp.image_local = None;
    timestamp.source = "not_examined_by_acquisition_info_quick_path".to_owned();
    timestamp
}

fn host_file_times(path: &std::path::Path) -> Result<HostFileTimes> {
    let metadata = std::fs::metadata(path)?;
    Ok(HostFileTimes {
        created_utc: metadata.created().ok().map(format_system_time),
        modified_utc: metadata.modified().ok().map(format_system_time),
        semantic: "analysis_host_filesystem_metadata".to_owned(),
        acquisition_time_supported: false,
    })
}

fn format_system_time(value: SystemTime) -> String {
    DateTime::<Utc>::from(value).to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn exact_filetime_timestamp(
    mut timestamp: ForensicTimestamp,
    utc_offset_minutes: Option<i32>,
) -> ForensicTimestamp {
    let Some(raw_value) = timestamp.raw_value else {
        return timestamp;
    };
    timestamp.utc = filetime_to_utc(raw_value);
    timestamp.image_local =
        utc_offset_minutes.and_then(|minutes| filetime_to_local(raw_value, minutes));
    timestamp
}

fn filetime_to_utc(value: u64) -> Option<String> {
    let unix_100ns = value.checked_sub(WINDOWS_TO_UNIX_100NS)?;
    let seconds = i64::try_from(unix_100ns / FILETIME_TICKS_PER_SECOND).ok()?;
    let nanos = u32::try_from((unix_100ns % FILETIME_TICKS_PER_SECOND) * 100).ok()?;
    let time = DateTime::<Utc>::from_timestamp(seconds, nanos)?;
    Some(format!(
        "{}.{:07}Z",
        time.format("%Y-%m-%dT%H:%M:%S"),
        unix_100ns % FILETIME_TICKS_PER_SECOND
    ))
}

fn filetime_to_local(value: u64, utc_offset_minutes: i32) -> Option<String> {
    if utc_offset_minutes.unsigned_abs() > 24 * 60 {
        return None;
    }
    let unix_100ns = value.checked_sub(WINDOWS_TO_UNIX_100NS)?;
    let seconds = i64::try_from(unix_100ns / FILETIME_TICKS_PER_SECOND).ok()?;
    let nanos = u32::try_from((unix_100ns % FILETIME_TICKS_PER_SECOND) * 100).ok()?;
    let utc = DateTime::<Utc>::from_timestamp(seconds, nanos)?;
    let offset = FixedOffset::east_opt(utc_offset_minutes.checked_mul(60)?)?;
    let local = utc.with_timezone(&offset);
    Some(format!(
        "{}.{:07}{}",
        local.format("%Y-%m-%dT%H:%M:%S"),
        unix_100ns % FILETIME_TICKS_PER_SECOND,
        local.format("%:z")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(raw_value: u64) -> ForensicTimestamp {
        ForensicTimestamp {
            raw_value: Some(raw_value),
            raw_format: "windows_filetime_100ns".to_owned(),
            // Deliberately use millisecond-only placeholders: the helper under
            // test must replace them from the raw FILETIME value.
            utc: Some("2023-06-20T17:02:27.861Z".to_owned()),
            image_local: Some("2023-06-21T01:02:27.861+08:00".to_owned()),
            timezone: Some("China Standard Time".to_owned()),
            utc_offset: Some("+08:00".to_owned()),
            source: "_KUSER_SHARED_DATA.SystemTime".to_owned(),
        }
    }

    fn tool_candidate(
        pid: u64,
        create_time_raw: Option<u64>,
        output_name: Option<&str>,
    ) -> AcquisitionToolCandidate {
        AcquisitionToolCandidate {
            pid,
            process: "FTK ImagerChs.".to_owned(),
            image_path: Some(r"H:\FTK Imager-1\FTK ImagerChs.exe".to_owned()),
            command_line: None,
            user_name: Some("testuser".to_owned()),
            process_create_time_raw: create_time_raw,
            process_create_time: create_time_raw.and_then(filetime_to_utc),
            output_handles: output_name
                .map(|name| {
                    vec![AcquisitionOutputHandle {
                        handle: 1_480,
                        object: 0xffff_9286_a2d9_d7b0,
                        object_type: "File".to_owned(),
                        name: name.to_owned(),
                        current_image_match: true,
                        match_basis: "current_image_basename".to_owned(),
                    }]
                })
                .unwrap_or_default(),
            current_image_bound: output_name.is_some(),
            relationship: if output_name.is_some() {
                "capture_tool_process_with_current_image_output_handle"
            } else {
                "capture_tool_process_name_observed_without_output_file_handle"
            }
            .to_owned(),
            confidence: if output_name.is_some() { "high" } else { "low" }.to_owned(),
        }
    }

    #[test]
    fn recognizes_capture_outputs_without_matching_unrelated_files() {
        assert!(is_capture_output_path(r"\memdump.mem"));
        assert!(is_capture_output_path(r"C:\cases\host.raw"));
        assert!(is_capture_output_path(r"C:\cases\host.VMEM"));
        assert!(!is_capture_output_path(r"C:\Windows\memory.dmp.txt"));
        assert!(!is_capture_output_path(r"C:\cases\memory.dmp"));
        assert!(!is_capture_output_path(r"C:\cases\disk.e01"));
        assert!(!is_capture_output_path(r"C:\cases\disk.ex01"));
        assert!(!is_capture_output_path(r"C:\cases\memory.aff4"));
        assert!(!is_capture_output_path(r"C:\cases\memdump-notes.txt"));
        assert!(is_capture_output_handle("File", r"\memdump.mem"));
        assert!(!is_capture_output_handle("Event", r"\memdump.mem"));
    }

    #[test]
    fn output_binding_requires_the_current_image_basename() {
        let bound = classify_capture_output_handle(
            "File",
            r"C:\cases\MEMDUMP.MEM",
            std::path::Path::new("/evidence/memdump.mem"),
        )
        .unwrap();
        assert!(bound.current_image_match);
        assert_eq!(bound.match_basis, "current_image_basename");

        let unbound = classify_capture_output_handle(
            "File",
            r"C:\cases\memdump.mem",
            std::path::Path::new("/evidence/capture.raw"),
        )
        .unwrap();
        assert!(!unbound.current_image_match);
        assert_eq!(unbound.match_basis, "memory_image_extension_only");

        assert!(
            classify_capture_output_handle(
                "File",
                r"C:\cases\memdump-notes.txt",
                std::path::Path::new("/evidence/memdump-notes.txt"),
            )
            .is_none()
        );
    }

    #[test]
    fn skipped_tool_scan_does_not_validate_unused_limits() {
        let skipped = AcquisitionInfoOptions {
            scan_tools: false,
            include_host_times: false,
            process_limit: 0,
            handle_limit: 0,
        };
        assert!(validate_options(&skipped).is_ok());

        let enabled = AcquisitionInfoOptions {
            scan_tools: true,
            ..skipped
        };
        assert!(validate_options(&enabled).is_err());
    }

    #[test]
    fn raw_images_do_not_claim_a_container_acquisition_time() {
        let metadata = container_metadata(&ImageFormat::Raw);

        assert!(!metadata.available);
        assert_eq!(metadata.timestamp_raw, None);
        assert_eq!(metadata.timestamp_utc, None);
        assert_eq!(metadata.source, None);
        assert_eq!(metadata.semantic, "no_container_timestamp");
        assert!(!metadata.exact_start);
        assert!(!metadata.exact_end);
        assert_eq!(metadata.confidence, "not_applicable");
        assert!(
            metadata
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("raw"))
        );
    }

    #[test]
    fn recognizes_ftk_candidate_from_process_path() {
        let process = crate::windows::ProcessRecord {
            eprocess: 0xffff_9286_a98f_6080,
            pid: 4_044,
            ppid: Some(3_812),
            name: "FTK ImagerChs.".to_owned(),
            details: crate::windows::ProcessDetails {
                image_path: Some(r"H:\FTK Imager-1\FTK ImagerChs.exe".to_owned()),
                ..Default::default()
            },
        };

        assert!(is_capture_tool(&process));
        assert_eq!(capture_tool_score(&process), 3);
    }

    #[test]
    fn preserves_windows_filetime_precision() {
        assert_eq!(
            filetime_to_utc(133_317_541_478_612_902).as_deref(),
            Some("2023-06-20T17:02:27.8612902Z")
        );
        assert_eq!(
            filetime_to_local(133_317_541_478_612_902, 8 * 60).as_deref(),
            Some("2023-06-21T01:02:27.8612902+08:00")
        );
    }

    #[test]
    fn exact_timestamp_replaces_lossy_renderings_but_preserves_evidence_fields() {
        let raw_value = 133_317_541_478_612_902;
        let exact = exact_filetime_timestamp(timestamp(raw_value), Some(8 * 60));

        assert_eq!(exact.raw_value, Some(raw_value));
        assert_eq!(exact.raw_format, "windows_filetime_100ns");
        assert_eq!(exact.utc.as_deref(), Some("2023-06-20T17:02:27.8612902Z"));
        assert_eq!(
            exact.image_local.as_deref(),
            Some("2023-06-21T01:02:27.8612902+08:00")
        );
        assert_eq!(exact.timezone.as_deref(), Some("China Standard Time"));
        assert_eq!(exact.source, "_KUSER_SHARED_DATA.SystemTime");
    }

    #[test]
    fn quick_shutdown_placeholder_is_explicitly_not_examined() {
        let value = previous_shutdown_not_examined(timestamp(133_317_541_478_612_902));

        assert_eq!(value.raw_value, None);
        assert_eq!(value.utc, None);
        assert_eq!(value.image_local, None);
        assert_eq!(value.source, "not_examined_by_acquisition_info_quick_path");
        assert_eq!(value.timezone.as_deref(), Some("China Standard Time"));
    }

    #[test]
    fn inferred_interval_is_not_reported_as_exact_capture_start_or_end() {
        let created = 133_317_541_252_479_968;
        let observed = 133_317_541_478_612_902;
        let tools = vec![tool_candidate(4_044, Some(created), Some(r"\memdump.mem"))];

        let window = infer_capture_window(&tools, &timestamp(observed)).unwrap();

        assert_eq!(window.lower_bound_candidate_raw, Some(created));
        assert_eq!(window.observed_time_raw, Some(observed));
        assert_eq!(window.elapsed_100ns, Some(226_132_934));
        assert_eq!(window.duration_seconds, Some(22.613_293_4));
        assert_eq!(
            window.semantic,
            "ordered_evidence_interval_not_exact_capture_window"
        );
        assert!(!window.exact_start);
        assert!(!window.exact_end);
        assert!(!window.observed_time_is_capture_end);
        assert!(window.reason.contains("不是精确采集耗时或结束时间"));
    }

    #[test]
    fn inferred_interval_requires_an_output_handle_and_ordered_times() {
        let observed = 133_317_541_478_612_902;
        let no_output = tool_candidate(4_044, Some(observed - 1), None);
        let after_observation = tool_candidate(4_045, Some(observed + 1), Some(r"\later.mem"));
        let mut unbound = tool_candidate(4_046, Some(observed - 2), Some(r"\other.mem"));
        unbound.current_image_bound = false;
        unbound.output_handles[0].current_image_match = false;
        unbound.output_handles[0].match_basis = "memory_image_extension_only".to_owned();
        unbound.relationship =
            "capture_tool_process_with_unbound_memory_output_candidate".to_owned();
        unbound.confidence = "low".to_owned();

        assert!(infer_capture_window(&[no_output], &timestamp(observed)).is_none());
        assert!(infer_capture_window(&[after_observation], &timestamp(observed)).is_none());
        assert!(infer_capture_window(&[unbound], &timestamp(observed)).is_none());
    }
}
