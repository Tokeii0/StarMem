use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use evtx::{EvtxParser, ParserSettings};
use serde::Serialize;
use serde_json::Value;

use crate::output_policy::{OutputPolicy, OutputTarget};

const MAX_FIELD_VALUE_CHARS: usize = 16_384;
const MAX_SUMMARY_CHARS: usize = 768;
const MAX_WARNING_SAMPLES: usize = 100;

#[derive(Debug, Clone)]
pub struct EventTimelineOptions {
    pub include_all_events: bool,
    pub event_limit: usize,
}

impl Default for EventTimelineOptions {
    fn default() -> Self {
        Self {
            include_all_events: false,
            event_limit: 1_000_000,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EventTimelineReport {
    pub input: String,
    pub include_all_events: bool,
    pub files_discovered: usize,
    pub files_parsed: usize,
    pub records_seen: usize,
    pub records_matched: usize,
    pub record_errors: usize,
    pub truncated: bool,
    pub category_counts: BTreeMap<String, usize>,
    pub files: Vec<EventLogFileStatus>,
    pub warnings: Vec<String>,
    pub events: Vec<EventTimelineEvent>,
}

#[derive(Debug, Serialize)]
pub struct EventLogFileStatus {
    pub path: String,
    pub parsed: bool,
    pub records_seen: usize,
    pub records_matched: usize,
    pub record_errors: usize,
    pub error: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EventTimelineEvent {
    pub timestamp: String,
    pub record_id: u64,
    pub source_file: String,
    pub event_id: u32,
    pub provider: String,
    pub channel: Option<String>,
    pub computer: Option<String>,
    pub level: Option<String>,
    pub task: Option<String>,
    pub opcode: Option<String>,
    pub keywords: Option<String>,
    pub user_sid: Option<String>,
    pub process_id: Option<String>,
    pub thread_id: Option<String>,
    pub activity_id: Option<String>,
    pub category: String,
    pub action: String,
    pub summary: String,
    pub event_data: BTreeMap<String, String>,
}

struct Classification {
    category: &'static str,
    action: &'static str,
    description: &'static str,
    focus_fields: &'static [&'static str],
}

pub fn analyze_event_logs(
    input: impl AsRef<Path>,
    options: &EventTimelineOptions,
) -> Result<EventTimelineReport> {
    ensure!(
        options.event_limit > 0,
        "event limit must be greater than zero"
    );
    let input = input.as_ref();
    let files = discover_evtx_files(input)?;
    ensure!(
        !files.is_empty(),
        "no .evtx files were found under {}",
        input.display()
    );

    let mut report = EventTimelineReport {
        input: input.display().to_string(),
        include_all_events: options.include_all_events,
        files_discovered: files.len(),
        files_parsed: 0,
        records_seen: 0,
        records_matched: 0,
        record_errors: 0,
        truncated: false,
        category_counts: BTreeMap::new(),
        files: Vec::with_capacity(files.len()),
        warnings: Vec::new(),
        events: Vec::new(),
    };

    'files: for path in files {
        let mut status = EventLogFileStatus {
            path: path.display().to_string(),
            parsed: false,
            records_seen: 0,
            records_matched: 0,
            record_errors: 0,
            error: None,
            warnings: Vec::new(),
        };
        let mut parser = match EvtxParser::from_path(&path) {
            Ok(parser) => parser.with_configuration(
                ParserSettings::default()
                    .validate_checksums(false)
                    .separate_json_attributes(false)
                    .indent(false),
            ),
            Err(error) => {
                status.error = Some(format!("{error}"));
                push_warning(
                    &mut report.warnings,
                    format!("cannot open {}: {error}", path.display()),
                );
                report.files.push(status);
                continue;
            }
        };
        status.parsed = true;
        report.files_parsed += 1;

        for record in parser.records_json_value() {
            match record {
                Ok(record) => {
                    status.records_seen += 1;
                    report.records_seen += 1;
                    let Some(event) = parse_event(
                        &path,
                        record.event_record_id,
                        &record.timestamp.to_string(),
                        &record.data,
                        options.include_all_events,
                    ) else {
                        continue;
                    };
                    status.records_matched += 1;
                    report.records_matched += 1;
                    *report
                        .category_counts
                        .entry(event.category.clone())
                        .or_default() += 1;
                    report.events.push(event);
                    if report.events.len() >= options.event_limit {
                        report.truncated = true;
                        push_warning(
                            &mut report.warnings,
                            format!(
                                "event limit {} reached while parsing {}",
                                options.event_limit,
                                path.display()
                            ),
                        );
                        report.files.push(status);
                        break 'files;
                    }
                }
                Err(error) => {
                    status.record_errors += 1;
                    report.record_errors += 1;
                    push_warning(&mut status.warnings, format!("{error}"));
                }
            }
        }
        report.files.push(status);
    }

    report.events.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.source_file.cmp(&right.source_file))
            .then_with(|| left.record_id.cmp(&right.record_id))
    });
    Ok(report)
}

pub fn write_event_timeline_json(
    report: &EventTimelineReport,
    output: impl AsRef<Path>,
) -> Result<()> {
    write_event_timeline_json_with_force(report, output, false)
}

pub fn write_event_timeline_json_with_force(
    report: &EventTimelineReport,
    output: impl AsRef<Path>,
    force: bool,
) -> Result<()> {
    let output = output.as_ref();
    let policy = event_timeline_output_policy(report, output, "event_timeline.json", force)?;
    policy.write_file_atomic(output, |writer| {
        serde_json::to_writer_pretty(writer, report)
            .with_context(|| format!("cannot write {}", output.display()))
    })
}

pub fn write_event_timeline_csv(
    report: &EventTimelineReport,
    output: impl AsRef<Path>,
) -> Result<()> {
    write_event_timeline_csv_with_force(report, output, false)
}

pub fn write_event_timeline_csv_with_force(
    report: &EventTimelineReport,
    output: impl AsRef<Path>,
    force: bool,
) -> Result<()> {
    let output = output.as_ref();
    let policy = event_timeline_output_policy(report, output, "event_timeline.csv", force)?;
    policy.write_file_atomic(output, |file| write_event_timeline_csv_writer(report, file))
}

fn event_timeline_output_policy(
    report: &EventTimelineReport,
    output: &Path,
    role: &str,
    force: bool,
) -> Result<OutputPolicy> {
    let mut policy = OutputPolicy::new(force);
    let input = Path::new(&report.input);
    if fs::metadata(input).is_ok_and(|metadata| metadata.is_dir()) {
        policy.protect_directory("event_log_directory", input);
    } else {
        policy.protect_file("event_log_input", input);
    }
    // Preserve the exact EVTX sources even when the original input was a directory that was
    // renamed after analysis.  Duplicates are harmless and hard-link identities are checked.
    for source in &report.files {
        policy.protect_file("event_log_file", Path::new(&source.path));
    }
    policy.output(OutputTarget::file(role, output));
    policy.preflight()?;
    Ok(policy)
}

pub fn write_event_timeline_csv_writer<W: Write>(
    report: &EventTimelineReport,
    mut writer: W,
) -> Result<()> {
    writer.write_all(b"\xef\xbb\xbf")?;
    let mut csv = csv::WriterBuilder::new().from_writer(writer);
    csv.write_record([
        "timestamp",
        "category",
        "action",
        "event_id",
        "provider",
        "channel",
        "record_id",
        "computer",
        "user_sid",
        "process_id",
        "thread_id",
        "activity_id",
        "level",
        "summary",
        "source_file",
        "event_data_json",
    ])?;
    for event in &report.events {
        csv.write_record([
            event.timestamp.as_str(),
            event.category.as_str(),
            event.action.as_str(),
            &event.event_id.to_string(),
            event.provider.as_str(),
            event.channel.as_deref().unwrap_or(""),
            &event.record_id.to_string(),
            event.computer.as_deref().unwrap_or(""),
            event.user_sid.as_deref().unwrap_or(""),
            event.process_id.as_deref().unwrap_or(""),
            event.thread_id.as_deref().unwrap_or(""),
            event.activity_id.as_deref().unwrap_or(""),
            event.level.as_deref().unwrap_or(""),
            event.summary.as_str(),
            event.source_file.as_str(),
            &serde_json::to_string(&event.event_data)?,
        ])?;
    }
    csv.flush()?;
    Ok(())
}

fn discover_evtx_files(input: &Path) -> Result<Vec<PathBuf>> {
    if input.is_file() {
        ensure!(
            input
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("evtx")),
            "input file is not an EVTX log: {}",
            input.display()
        );
        return Ok(vec![input.to_path_buf()]);
    }
    ensure!(input.is_dir(), "input does not exist: {}", input.display());
    let mut pending = VecDeque::from([input.to_path_buf()]);
    let mut files = Vec::new();
    while let Some(directory) = pending.pop_front() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("cannot read directory {}", directory.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push_back(entry.path());
            } else if file_type.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("evtx"))
            {
                files.push(entry.path());
            }
        }
    }
    files.sort_by_key(|path| path.to_string_lossy().to_ascii_lowercase());
    Ok(files)
}

fn parse_event(
    path: &Path,
    record_id: u64,
    record_timestamp: &str,
    data: &Value,
    include_all: bool,
) -> Option<EventTimelineEvent> {
    let event = object_field(data, "Event").unwrap_or(data);
    let system = object_field(event, "System")?;
    let event_id =
        scalar_u64(object_field(system, "EventID")?).and_then(|value| u32::try_from(value).ok())?;
    let provider = object_field(system, "Provider")
        .and_then(|value| attribute(value, "Name"))
        .unwrap_or_else(|| "unknown".to_owned());
    let channel = object_field(system, "Channel").and_then(scalar_string);
    let mut event_data = BTreeMap::new();
    for section in ["EventData", "UserData", "DebugData", "BinaryEventData"] {
        if let Some(value) = object_field(event, section) {
            flatten_payload(value, "", &mut event_data);
        }
    }
    let classification = classify_event(&provider, channel.as_deref(), event_id, &event_data);
    if classification.is_none() && !include_all {
        return None;
    }
    let classification = classification.unwrap_or(Classification {
        category: "other",
        action: "event",
        description: "Windows event",
        focus_fields: &[],
    });
    let timestamp = object_field(system, "TimeCreated")
        .and_then(|value| attribute(value, "SystemTime"))
        .unwrap_or_else(|| record_timestamp.to_owned());
    let execution = object_field(system, "Execution");
    let correlation = object_field(system, "Correlation");
    let security = object_field(system, "Security");
    let summary = build_summary(&classification, &event_data);
    Some(EventTimelineEvent {
        timestamp,
        record_id,
        source_file: path.display().to_string(),
        event_id,
        provider,
        channel,
        computer: object_field(system, "Computer").and_then(scalar_string),
        level: object_field(system, "Level").and_then(scalar_string),
        task: object_field(system, "Task").and_then(scalar_string),
        opcode: object_field(system, "Opcode").and_then(scalar_string),
        keywords: object_field(system, "Keywords").and_then(scalar_string),
        user_sid: security
            .and_then(|value| attribute(value, "UserID"))
            .or_else(|| field_value(&event_data, &["SubjectUserSid", "TargetUserSid"])),
        process_id: execution.and_then(|value| attribute(value, "ProcessID")),
        thread_id: execution.and_then(|value| attribute(value, "ThreadID")),
        activity_id: correlation.and_then(|value| attribute(value, "ActivityID")),
        category: classification.category.to_owned(),
        action: classification.action.to_owned(),
        summary,
        event_data,
    })
}

fn classify_event(
    provider: &str,
    channel: Option<&str>,
    event_id: u32,
    _fields: &BTreeMap<String, String>,
) -> Option<Classification> {
    let provider = provider.to_ascii_lowercase();
    let channel = channel.unwrap_or("").to_ascii_lowercase();
    let security = provider.contains("security-auditing") || channel == "security";
    let sysmon = provider.contains("sysmon") || channel.contains("sysmon");
    let powershell = provider.contains("powershell") || channel.contains("powershell");
    let defender = provider.contains("windows defender") || channel.contains("windows defender");
    let terminal_services =
        provider.contains("terminalservices") || channel.contains("terminalservices");
    let task_scheduler = provider.contains("taskscheduler") || channel.contains("taskscheduler");

    let item = if provider.ends_with("eventlog") || provider == "eventlog" {
        match event_id {
            104 => class(
                "anti_forensics",
                "event_log_cleared",
                "Windows 事件日志被清除",
                &["Channel", "SubjectUserName", "ClientProcessId"],
            ),
            6005 => class("system", "startup", "事件日志服务启动（系统启动）", &[]),
            6006 => class("system", "shutdown", "事件日志服务停止（正常关机）", &[]),
            6008 => class(
                "system",
                "unexpected_shutdown",
                "检测到非正常关机",
                &["param1", "param2", "Binary"],
            ),
            _ => return None,
        }
    } else if provider.contains("kernel-power") && event_id == 41 {
        class(
            "system",
            "unexpected_restart",
            "系统在未正常关机的情况下重新启动",
            &["BugcheckCode", "PowerButtonTimestamp", "SleepInProgress"],
        )
    } else if provider.ends_with("user32") && event_id == 1074 {
        class(
            "system",
            "shutdown_requested",
            "进程或用户发起关机/重启",
            &[
                "param1",
                "param3",
                "param4",
                "param5",
                "ProcessName",
                "UserName",
            ],
        )
    } else if provider.contains("kernel-general") && matches!(event_id, 12 | 13) {
        if event_id == 12 {
            class("system", "startup", "操作系统启动", &["StartTime"])
        } else {
            class("system", "shutdown", "操作系统关机", &["StopTime"])
        }
    } else if security {
        match event_id {
            1102 => class(
                "anti_forensics",
                "audit_log_cleared",
                "安全审计日志被清除",
                &["SubjectUserName", "SubjectDomainName", "SubjectUserSid"],
            ),
            4624 => class(
                "authentication",
                "logon_success",
                "账户登录成功",
                &[
                    "TargetUserName",
                    "TargetDomainName",
                    "LogonType",
                    "IpAddress",
                    "IpPort",
                    "WorkstationName",
                    "ProcessName",
                    "AuthenticationPackageName",
                ],
            ),
            4625 => class(
                "authentication",
                "logon_failure",
                "账户登录失败",
                &[
                    "TargetUserName",
                    "TargetDomainName",
                    "LogonType",
                    "IpAddress",
                    "WorkstationName",
                    "Status",
                    "SubStatus",
                    "FailureReason",
                    "ProcessName",
                ],
            ),
            4634 | 4647 => class(
                "authentication",
                "logoff",
                "账户注销",
                &[
                    "TargetUserName",
                    "TargetDomainName",
                    "LogonType",
                    "TargetLogonId",
                ],
            ),
            4648 => class(
                "authentication",
                "explicit_credentials",
                "使用显式凭据登录",
                &[
                    "SubjectUserName",
                    "TargetUserName",
                    "TargetServerName",
                    "ProcessName",
                    "IpAddress",
                ],
            ),
            4672 => class(
                "authentication",
                "special_privileges",
                "新登录获得敏感特权",
                &["SubjectUserName", "SubjectDomainName", "PrivilegeList"],
            ),
            4688 => class(
                "process",
                "process_created",
                "创建新进程",
                &[
                    "NewProcessName",
                    "NewProcessId",
                    "ParentProcessName",
                    "ProcessCommandLine",
                    "SubjectUserName",
                    "TargetUserName",
                ],
            ),
            4689 => class(
                "process",
                "process_terminated",
                "进程退出",
                &["ProcessName", "ProcessId", "SubjectUserName"],
            ),
            4697 => class(
                "persistence",
                "service_installed",
                "系统中安装了服务",
                &[
                    "ServiceName",
                    "ServiceFileName",
                    "ServiceStartType",
                    "ServiceAccount",
                    "SubjectUserName",
                ],
            ),
            4698..=4702 => {
                let action = match event_id {
                    4698 => "scheduled_task_created",
                    4699 => "scheduled_task_deleted",
                    4700 => "scheduled_task_enabled",
                    4701 => "scheduled_task_disabled",
                    _ => "scheduled_task_updated",
                };
                class(
                    "persistence",
                    action,
                    "计划任务发生变更",
                    &["TaskName", "SubjectUserName", "TaskContent"],
                )
            }
            4720..=4726 | 4738 | 4740 | 4767 => {
                let action = match event_id {
                    4720 => "account_created",
                    4722 => "account_enabled",
                    4725 => "account_disabled",
                    4726 => "account_deleted",
                    4738 => "account_changed",
                    4740 => "account_locked",
                    4767 => "account_unlocked",
                    _ => "account_credentials_changed",
                };
                class(
                    "account",
                    action,
                    "本地或域账户发生变更",
                    &[
                        "TargetUserName",
                        "TargetDomainName",
                        "TargetSid",
                        "SubjectUserName",
                        "CallerComputerName",
                    ],
                )
            }
            4768 | 4769 | 4771 | 4776 => class(
                "authentication",
                "credential_validation",
                "Kerberos/NTLM 凭据验证",
                &[
                    "TargetUserName",
                    "TargetDomainName",
                    "ServiceName",
                    "IpAddress",
                    "Workstation",
                    "Status",
                    "FailureCode",
                ],
            ),
            4778 | 4779 => class(
                "remote_access",
                if event_id == 4778 {
                    "rdp_reconnect"
                } else {
                    "rdp_disconnect"
                },
                "远程桌面会话重连或断开",
                &["AccountName", "SessionName", "ClientName", "ClientAddress"],
            ),
            5140 | 5145 => class(
                "network_share",
                "share_access",
                "访问网络共享",
                &[
                    "SubjectUserName",
                    "IpAddress",
                    "ShareName",
                    "RelativeTargetName",
                    "AccessList",
                ],
            ),
            5156 => class(
                "network",
                "connection_allowed",
                "Windows 筛选平台允许连接",
                &[
                    "Application",
                    "SourceAddress",
                    "SourcePort",
                    "DestAddress",
                    "DestPort",
                    "Protocol",
                ],
            ),
            _ => return None,
        }
    } else if task_scheduler && matches!(event_id, 106 | 129 | 140 | 141 | 142 | 200 | 201) {
        class(
            "persistence",
            "scheduled_task_activity",
            "计划任务注册、更新、删除或执行",
            &[
                "TaskName",
                "TaskInstanceId",
                "UserContext",
                "ActionName",
                "ResultCode",
            ],
        )
    } else if terminal_services && matches!(event_id, 21 | 22 | 24 | 25 | 39 | 40 | 1149) {
        class(
            "remote_access",
            if event_id == 1149 {
                "rdp_authentication"
            } else {
                "rdp_session"
            },
            "远程桌面身份验证或会话状态变化",
            &[
                "User",
                "UserName",
                "DomainName",
                "SessionID",
                "Address",
                "SourceNetworkAddress",
            ],
        )
    } else if powershell && matches!(event_id, 400 | 403 | 600 | 4103 | 4104) {
        class(
            "powershell",
            if event_id == 4104 {
                "script_block"
            } else if event_id == 4103 {
                "module_logging"
            } else {
                "engine_lifecycle"
            },
            "PowerShell 执行或引擎活动",
            &[
                "ScriptBlockText",
                "ScriptBlockId",
                "Payload",
                "HostApplication",
                "CommandName",
                "UserId",
            ],
        )
    } else if defender
        && matches!(
            event_id,
            1006 | 1007 | 1008 | 1009 | 1116 | 1117 | 1118 | 1119 | 5001 | 5004 | 5007 | 5010
        )
    {
        class(
            "defender",
            match event_id {
                1116 => "threat_detected",
                1117 => "threat_action",
                5001 | 5010 => "protection_disabled",
                5007 => "configuration_changed",
                _ => "security_product_event",
            },
            "Microsoft Defender 检测、处置或配置变化",
            &[
                "Threat Name",
                "ThreatName",
                "Path",
                "Detection Source",
                "Action Name",
                "Old Value",
                "New Value",
            ],
        )
    } else if sysmon {
        match event_id {
            1 => class(
                "process",
                "sysmon_process_created",
                "Sysmon 记录进程创建",
                &[
                    "Image",
                    "CommandLine",
                    "ParentImage",
                    "ParentCommandLine",
                    "User",
                    "Hashes",
                ],
            ),
            3 => class(
                "network",
                "sysmon_network_connection",
                "Sysmon 记录网络连接",
                &[
                    "Image",
                    "User",
                    "SourceIp",
                    "SourcePort",
                    "DestinationIp",
                    "DestinationPort",
                    "Protocol",
                ],
            ),
            6 | 7 => class(
                "module",
                "driver_or_image_loaded",
                "Sysmon 记录驱动或映像加载",
                &[
                    "ImageLoaded",
                    "Image",
                    "Hashes",
                    "Signature",
                    "SignatureStatus",
                ],
            ),
            8 | 10 => class(
                "process",
                "process_access_or_injection",
                "Sysmon 记录远程线程或跨进程访问",
                &[
                    "SourceImage",
                    "TargetImage",
                    "StartFunction",
                    "GrantedAccess",
                    "CallTrace",
                ],
            ),
            11 | 15 | 23 | 26 => class(
                "file",
                "file_activity",
                "Sysmon 记录文件创建、流或删除活动",
                &["Image", "TargetFilename", "Hashes", "Contents"],
            ),
            12..=14 => class(
                "registry",
                "registry_activity",
                "Sysmon 记录注册表变更",
                &["EventType", "Image", "TargetObject", "Details"],
            ),
            19..=21 => class(
                "persistence",
                "wmi_subscription",
                "Sysmon 记录 WMI 永久事件订阅",
                &["Operation", "User", "Name", "Query", "Destination"],
            ),
            22 => class(
                "network",
                "dns_query",
                "Sysmon 记录 DNS 查询",
                &["Image", "User", "QueryName", "QueryResults"],
            ),
            _ => return None,
        }
    } else if provider.contains("service control manager") && event_id == 7045 {
        class(
            "persistence",
            "service_installed",
            "服务控制管理器安装了新服务",
            &[
                "ServiceName",
                "ImagePath",
                "ServiceType",
                "StartType",
                "AccountName",
                "param1",
                "param2",
            ],
        )
    } else if (provider.contains("kernel-pnp") || provider.contains("driverframeworks-usermode"))
        && matches!(event_id, 2003 | 2100 | 2101 | 2102 | 400 | 410 | 430)
    {
        class(
            "device",
            "device_activity",
            "即插即用或 USB 设备活动",
            &[
                "DeviceInstanceId",
                "InstanceId",
                "DeviceId",
                "LifetimeId",
                "DriverName",
            ],
        )
    } else if provider.contains("wmi-activity") && matches!(event_id, 5857..=5861) {
        class(
            "wmi",
            "wmi_activity",
            "WMI 查询、消费者或永久订阅活动",
            &[
                "Operation",
                "User",
                "NamespaceName",
                "Query",
                "Consumer",
                "PossibleCause",
            ],
        )
    } else {
        return None;
    };
    Some(item)
}

fn class(
    category: &'static str,
    action: &'static str,
    description: &'static str,
    focus_fields: &'static [&'static str],
) -> Classification {
    Classification {
        category,
        action,
        description,
        focus_fields,
    }
}

fn build_summary(classification: &Classification, fields: &BTreeMap<String, String>) -> String {
    let mut parts = vec![classification.description.to_owned()];
    for name in classification.focus_fields {
        if let Some(value) = field_value(fields, &[*name]) {
            let value = truncate_chars(&value, 256);
            if !value.is_empty() && value != "-" {
                parts.push(format!("{name}={value}"));
            }
        }
    }
    truncate_chars(&parts.join("; "), MAX_SUMMARY_CHARS)
}

fn flatten_payload(value: &Value, prefix: &str, output: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(object) => {
            let named = object
                .get("#attributes")
                .and_then(|attributes| object_field(attributes, "Name"))
                .and_then(scalar_string);
            if let (Some(name), Some(text)) = (named, object.get("#text").and_then(scalar_string)) {
                append_field(output, &name, text);
                return;
            }
            if let Some(text) = object.get("#text").and_then(scalar_string)
                && !prefix.is_empty()
            {
                append_field(output, prefix, text);
            }
            for (key, child) in object {
                if key == "#text" || key == "#attributes" {
                    continue;
                }
                let child_prefix = if prefix.is_empty() {
                    key.to_owned()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_payload(child, &child_prefix, output);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                let child_prefix = if prefix.is_empty() {
                    format!("Data[{index}]")
                } else {
                    format!("{prefix}[{index}]")
                };
                flatten_payload(child, &child_prefix, output);
            }
        }
        _ if !prefix.is_empty() => {
            if let Some(value) = scalar_string(value) {
                append_field(output, prefix, value);
            }
        }
        _ => {}
    }
}

fn append_field(output: &mut BTreeMap<String, String>, key: &str, value: String) {
    let value = truncate_chars(&value, MAX_FIELD_VALUE_CHARS);
    output
        .entry(key.to_owned())
        .and_modify(|current| {
            if current != &value {
                current.push_str("; ");
                current.push_str(&value);
                *current = truncate_chars(current, MAX_FIELD_VALUE_CHARS);
            }
        })
        .or_insert(value);
}

fn field_value(fields: &BTreeMap<String, String>, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some((_, value)) = fields.iter().find(|(key, _)| {
            key.eq_ignore_ascii_case(name)
                || key
                    .rsplit(['.', ']'])
                    .find(|component| !component.is_empty() && !component.starts_with('['))
                    .is_some_and(|component| component.eq_ignore_ascii_case(name))
        }) {
            return Some(value.clone());
        }
    }
    None
}

fn object_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .as_object()?
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value))
}

fn attribute(value: &Value, name: &str) -> Option<String> {
    object_field(value, "#attributes")
        .and_then(|attributes| object_field(attributes, name))
        .and_then(scalar_string)
        .or_else(|| object_field(value, name).and_then(scalar_string))
}

fn scalar_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(value) => parse_u64(value),
        Value::Object(_) => object_field(value, "#text").and_then(scalar_u64),
        _ => None,
    }
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Object(_) => object_field(value, "#text").and_then(scalar_string),
        Value::Array(_) => None,
    }
}

fn parse_u64(value: &str) -> Option<u64> {
    let value = value.trim();
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .or_else(|| value.parse().ok())
}

fn truncate_chars(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_owned();
    }
    let mut output = value.chars().take(limit).collect::<String>();
    output.push('…');
    output
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNING_SAMPLES {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn empty_report(input: &Path, source: &Path) -> EventTimelineReport {
        EventTimelineReport {
            input: input.display().to_string(),
            include_all_events: false,
            files_discovered: 1,
            files_parsed: 1,
            records_seen: 0,
            records_matched: 0,
            record_errors: 0,
            truncated: false,
            category_counts: BTreeMap::new(),
            files: vec![EventLogFileStatus {
                path: source.display().to_string(),
                parsed: true,
                records_seen: 0,
                records_matched: 0,
                record_errors: 0,
                error: None,
                warnings: Vec::new(),
            }],
            warnings: Vec::new(),
            events: Vec::new(),
        }
    }

    #[test]
    fn extracts_named_event_data_and_classifies_logon() {
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                    "EventID": 4624,
                    "TimeCreated": {"#attributes": {"SystemTime": "2026-06-06T17:45:00.000Z"}},
                    "Channel": "Security",
                    "Computer": "HACKER"
                },
                "EventData": {
                    "Data": [
                        {"#attributes": {"Name": "TargetUserName"}, "#text": "HACK"},
                        {"#attributes": {"Name": "LogonType"}, "#text": 10},
                        {"#attributes": {"Name": "IpAddress"}, "#text": "192.168.10.20"}
                    ]
                }
            }
        });
        let event = parse_event(
            Path::new("Security.evtx"),
            42,
            "2026-06-06T17:45:00Z",
            &data,
            false,
        )
        .unwrap();
        assert_eq!(event.category, "authentication");
        assert_eq!(event.action, "logon_success");
        assert_eq!(
            event.event_data.get("TargetUserName"),
            Some(&"HACK".to_owned())
        );
        assert!(event.summary.contains("LogonType=10"));
    }

    #[test]
    fn ignores_uncurated_events_unless_requested() {
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": "Example"}},
                    "EventID": 123,
                    "Channel": "Example"
                }
            }
        });
        assert!(parse_event(Path::new("x.evtx"), 1, "2026-01-01Z", &data, false).is_none());
        let event = parse_event(Path::new("x.evtx"), 1, "2026-01-01Z", &data, true).unwrap();
        assert_eq!(event.category, "other");
    }

    #[test]
    fn library_writer_never_overwrites_evtx_input_even_with_force() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "starmem-eventlog-output-policy-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let input = root.join("Security.evtx");
        fs::write(&input, b"EVTX evidence").unwrap();
        let report = empty_report(&input, &input);

        assert!(write_event_timeline_json_with_force(&report, &input, true).is_err());
        assert_eq!(fs::read(&input).unwrap(), b"EVTX evidence");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn library_writer_rejects_output_inside_eventlog_directory() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "starmem-eventlog-directory-policy-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let input = root.join("System.evtx");
        fs::write(&input, b"EVTX evidence").unwrap();
        let report = empty_report(&root, &input);

        assert!(write_event_timeline_csv(&report, root.join("timeline.csv")).is_err());
        assert!(!root.join("timeline.csv").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
