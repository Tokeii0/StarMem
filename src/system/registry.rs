use std::collections::{BTreeMap, BTreeSet};

use anyhow::Context;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::registry::{RegistryHive, RegistryKey, RegistryValue, RegistryValueData};
use crate::session::AnalysisSession;
use crate::windows::ProcessListReport;
use crate::windows::plugins::HiveRecord;

const MAX_HIVE_SIZE: u64 = 512 * 1024 * 1024;
const MAX_USB_SOURCE_WARNINGS: usize = 512;

#[derive(Debug, Default, Serialize)]
pub struct RegistrySystemInfo {
    pub available: bool,
    pub hive_enumeration_complete: bool,
    /// Whether the SYSTEM-Hive evidence needed by `usb-history` was recovered
    /// and enumerated without loss. This is deliberately independent from
    /// warnings emitted by SOFTWARE, SAM, or per-user Hive parsers.
    pub usb_source_complete: bool,
    pub usb_source_warnings: Vec<String>,
    pub usb_system_cmhive: Option<u64>,
    pub usb_control_set_used: Option<u32>,
    pub system_persistence_complete: bool,
    pub software_persistence_complete: bool,
    pub user_persistence_complete: bool,
    pub current_control_set: Option<u32>,
    pub default_control_set: Option<u32>,
    pub last_known_good_control_set: Option<u32>,
    pub failed_control_set: Option<u32>,
    pub computer_name: Option<String>,
    pub active_computer_name: Option<String>,
    pub hostname: Option<String>,
    pub domain: Option<String>,
    pub last_shutdown_time_raw: Option<u64>,
    pub last_shutdown_time: Option<String>,
    pub product: RegistryProductInfo,
    pub timezone: RegistryTimeZoneInfo,
    pub profiles: Vec<RegistryProfileInfo>,
    pub network_adapters: Vec<RegistryNetworkAdapter>,
    pub network_profiles: Vec<RegistryNetworkProfile>,
    pub network_signatures: Vec<RegistryNetworkSignature>,
    pub services: Vec<RegistryServiceInfo>,
    pub autoruns: Vec<RegistryAutorun>,
    pub scheduled_tasks: Vec<RegistryScheduledTask>,
    pub usb_devices: Vec<RegistryUsbDevice>,
    pub mounted_devices: Vec<RegistryMountedDevice>,
    pub bam_entries: Vec<RegistryBamEntry>,
    pub local_accounts: Vec<RegistryLocalAccount>,
    pub printers: Vec<RegistryPrinterRecord>,
    pub policies: Vec<RegistryPolicyRecord>,
    pub security_software: Vec<RegistrySecurityRecord>,
    pub virtualization: Vec<RegistryVirtualizationRecord>,
    pub wmi_configuration: Vec<RegistryWmiRecord>,
    pub event_log_configuration: Vec<RegistryEventLogConfigRecord>,
    pub crash_dump_configuration: Vec<RegistryCrashDumpRecord>,
    pub rdp_history: Vec<RegistryRdpRecord>,
    pub network_configuration: Vec<RegistryNetworkConfigRecord>,
    pub wireless_history: Vec<RegistryWirelessRecord>,
    pub hives: Vec<RegistryHiveStatus>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct RegistryProductInfo {
    pub product_name: Option<String>,
    pub display_version: Option<String>,
    pub release_id: Option<String>,
    pub current_version: Option<String>,
    pub current_major_version_number: Option<u32>,
    pub current_minor_version_number: Option<u32>,
    pub edition_id: Option<String>,
    pub composition_edition_id: Option<String>,
    pub installation_type: Option<String>,
    pub current_type: Option<String>,
    pub current_build: Option<String>,
    pub current_build_number: Option<String>,
    pub ubr: Option<u32>,
    pub build_branch: Option<String>,
    pub build_guid: Option<String>,
    pub build_lab: Option<String>,
    pub build_lab_ex: Option<String>,
    pub csd_version: Option<String>,
    pub registered_owner: Option<String>,
    pub registered_organization: Option<String>,
    pub product_id: Option<String>,
    pub install_date_raw: Option<u64>,
    pub install_date: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct RegistryTimeZoneInfo {
    pub key_name: Option<String>,
    pub standard_name: Option<String>,
    pub daylight_name: Option<String>,
    pub bias_minutes: Option<i32>,
    pub active_bias_minutes: Option<i32>,
    pub dynamic_daylight_disabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct RegistryProfileInfo {
    pub sid: String,
    pub profile_path: Option<String>,
    pub flags: Option<u32>,
    pub state: Option<u32>,
    pub ref_count: Option<u32>,
    pub full_profile: Option<bool>,
    pub last_write_raw: u64,
    pub last_write: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryNetworkAdapter {
    pub interface_id: String,
    pub description: Option<String>,
    pub enable_dhcp: Option<bool>,
    pub ip_addresses: Vec<String>,
    pub subnet_masks: Vec<String>,
    pub default_gateways: Vec<String>,
    pub dns_servers: Vec<String>,
    pub domain: Option<String>,
    pub dhcp_server: Option<String>,
    pub lease_obtained_raw: Option<u64>,
    pub lease_obtained: Option<String>,
    pub lease_terminates_raw: Option<u64>,
    pub lease_terminates: Option<String>,
    pub last_write_raw: u64,
    pub last_write: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryNetworkProfile {
    pub profile_guid: String,
    pub profile_name: Option<String>,
    pub description: Option<String>,
    pub category: Option<u32>,
    pub managed: Option<bool>,
    pub date_created: Option<String>,
    pub date_last_connected: Option<String>,
    pub last_write_raw: u64,
    pub last_write: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryNetworkSignature {
    pub signature_id: String,
    pub managed: bool,
    pub profile_guid: Option<String>,
    pub description: Option<String>,
    pub dns_suffix: Option<String>,
    pub first_network: Option<String>,
    pub default_gateway_mac: Option<String>,
    pub last_write_raw: u64,
    pub last_write: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryServiceInfo {
    pub name: String,
    pub display_name: Option<String>,
    pub image_path: Option<String>,
    pub service_dll: Option<String>,
    pub object_name: Option<String>,
    pub group: Option<String>,
    pub depend_on_service: Vec<String>,
    pub start: Option<u32>,
    pub service_type: Option<u32>,
    pub error_control: Option<u32>,
    pub last_write_raw: u64,
    pub last_write: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryAutorun {
    pub mechanism: String,
    pub scope: String,
    pub user_sid: Option<String>,
    pub key_path: String,
    pub name: String,
    pub command: String,
    pub enabled: Option<bool>,
    pub source_hive: String,
    pub source_root: String,
    pub key_last_write_raw: u64,
    pub key_last_write: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryScheduledTask {
    pub tree_path: String,
    pub task_id: Option<String>,
    pub uri: Option<String>,
    pub author: Option<String>,
    pub source: Option<String>,
    pub index: Option<u32>,
    pub tree_key_present: bool,
    pub task_key_present: bool,
    pub registration_status: String,
    pub actions_size: Option<usize>,
    pub actions_sha256: Option<String>,
    pub action_strings: Vec<String>,
    pub triggers_size: Option<usize>,
    pub triggers_sha256: Option<String>,
    pub trigger_strings: Vec<String>,
    pub action_parse_status: String,
    pub dynamic_info_hex: Option<String>,
    pub last_write_raw: u64,
    pub last_write: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryUsbDevice {
    #[serde(skip)]
    pub(crate) registry_key: RegistryKey,
    pub device_type: String,
    pub instance_id: String,
    pub friendly_name: Option<String>,
    pub device_description: Option<String>,
    pub manufacturer: Option<String>,
    pub service: Option<String>,
    pub class_guid: Option<String>,
    pub container_id: Option<String>,
    pub last_write_raw: u64,
    pub last_write: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryMountedDevice {
    pub name: String,
    pub decoded_target: Option<String>,
    pub raw_hex: String,
}

#[derive(Debug, Serialize)]
pub struct RegistryBamEntry {
    pub source: String,
    pub sid: String,
    pub executable: String,
    pub last_execution_raw: Option<u64>,
    pub last_execution: Option<String>,
    pub raw_hex: String,
}

#[derive(Debug, Serialize)]
pub struct RegistryLocalAccount {
    pub name: String,
    pub rid: Option<u32>,
    pub last_write_raw: u64,
    pub last_write: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryPrinterRecord {
    #[serde(rename = "Category")]
    pub category: String,
    #[serde(rename = "Printer_Name")]
    pub printer_name: String,
    #[serde(rename = "Port")]
    pub port: Option<String>,
    #[serde(rename = "Driver")]
    pub driver: Option<String>,
    #[serde(rename = "Server")]
    pub server: Option<String>,
    #[serde(rename = "Status")]
    pub status: Option<String>,
    #[serde(rename = "Key_Timestamp")]
    pub key_timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryPolicyRecord {
    #[serde(rename = "Category")]
    pub category: String,
    #[serde(rename = "Setting_Name")]
    pub setting_name: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Key_Timestamp")]
    pub key_timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistrySecurityRecord {
    #[serde(rename = "Security_Software")]
    pub security_software: String,
    #[serde(rename = "Component")]
    pub component: String,
    #[serde(rename = "Setting")]
    pub setting: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "Key_Timestamp")]
    pub key_timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryVirtualizationRecord {
    #[serde(rename = "Category")]
    pub category: String,
    #[serde(rename = "Indicator")]
    pub indicator: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "Details")]
    pub details: String,
    #[serde(rename = "Key_Timestamp")]
    pub key_timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryWmiRecord {
    #[serde(rename = "Category")]
    pub category: String,
    #[serde(rename = "Component")]
    pub component: String,
    #[serde(rename = "Setting")]
    pub setting: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "Key_Timestamp")]
    pub key_timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryEventLogConfigRecord {
    #[serde(rename = "Category")]
    pub category: String,
    #[serde(rename = "Channel")]
    pub channel: String,
    #[serde(rename = "Setting")]
    pub setting: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "Key_Timestamp")]
    pub key_timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryCrashDumpRecord {
    #[serde(rename = "Category")]
    pub category: String,
    #[serde(rename = "Setting_Name")]
    pub setting_name: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "Details")]
    pub details: String,
    #[serde(rename = "Key_Timestamp")]
    pub key_timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryRdpRecord {
    #[serde(rename = "Category")]
    pub category: String,
    #[serde(rename = "Target_or_Setting")]
    pub target_or_setting: String,
    #[serde(rename = "Username")]
    pub username: Option<String>,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "Last_Connected")]
    pub last_connected: Option<String>,
    #[serde(rename = "Key_Timestamp")]
    pub key_timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryNetworkConfigRecord {
    #[serde(rename = "Category")]
    pub category: String,
    #[serde(rename = "Interface_or_Protocol")]
    pub interface_or_protocol: String,
    #[serde(rename = "Configuration")]
    pub configuration: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "Key_Timestamp")]
    pub key_timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryWirelessRecord {
    #[serde(rename = "Network_Name")]
    pub network_name: String,
    #[serde(rename = "GUID")]
    pub guid: String,
    #[serde(rename = "Category")]
    pub category: String,
    #[serde(rename = "Network_Type")]
    pub network_type: String,
    #[serde(rename = "First_Connect")]
    pub first_connect: Option<String>,
    #[serde(rename = "Last_Connect")]
    pub last_connect: Option<String>,
    #[serde(rename = "Gateway_MAC")]
    pub gateway_mac: Option<String>,
    #[serde(rename = "Key_Timestamp")]
    pub key_timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryHiveStatus {
    pub cmhive: u64,
    pub cmhive_hex: String,
    pub file_path: String,
    pub user_name: String,
    pub root_path: String,
    pub recovery_attempted: bool,
    pub parsed: bool,
    pub complete: Option<bool>,
    pub logical_size: Option<u64>,
    pub recovered_bytes: Option<u64>,
    pub missing_bytes: Option<u64>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

struct LoadedHive {
    cmhive: u64,
    root_path: String,
    source_name: String,
    hive: RegistryHive,
}

#[derive(Debug, Serialize)]
pub struct RegistryEvidence<T> {
    pub records: Vec<T>,
    pub available: bool,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistryPrintRecord {
    pub depth: usize,
    pub kind: String,
    /// Exact recovered hive and nk/vk identities, never inferred from a name.
    pub cmhive: Option<u64>,
    pub cell_index: u32,
    pub key_cell_index: u32,
    pub key_identity: Option<String>,
    pub path: String,
    pub name: String,
    pub data_type: Option<u32>,
    pub data_type_name: Option<String>,
    pub data: Option<RegistryValueData>,
    pub last_write_raw: u64,
    pub last_write: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserAssistRecord {
    pub hive: String,
    pub guid: String,
    pub encoded_name: String,
    pub decoded_name: String,
    pub session_id: Option<u32>,
    pub run_count: Option<u32>,
    pub focus_count: Option<u32>,
    pub focus_time_ms: Option<u32>,
    pub last_execution_raw: Option<u64>,
    pub last_execution: Option<String>,
    pub raw_data_hex: String,
}

#[derive(Debug, Serialize)]
pub struct AmcacheRecord {
    pub hive: String,
    pub key_path: String,
    pub entry_type: String,
    pub key_name: String,
    pub path: Option<String>,
    pub program_id: Option<String>,
    pub sha1: Option<String>,
    pub sha1_raw: Option<String>,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    pub publisher: Option<String>,
    pub service: Option<String>,
    pub link_date: Option<String>,
    pub last_write_raw: u64,
    pub last_write: Option<String>,
}

pub(crate) struct RecoveredTargetHive {
    pub(crate) hive: Option<RegistryHive>,
    pub(crate) cmhive: Option<u64>,
    pub(crate) complete: bool,
    pub(crate) warnings: Vec<String>,
}

/// Recover one uniquely validated hive from the active CMHIVE list only.
///
/// Credential material must not silently combine a current active SYSTEM hive
/// with an unrelated pool-scan SAM remnant. Candidates are tried by name score,
/// each score group is validated transactionally, and ambiguous successes are
/// rejected instead of selecting whichever address happened to sort first.
pub(crate) fn recover_loaded_target_hive_validated<F>(
    session: &AnalysisSession,
    processes: &ProcessListReport,
    root_path: &str,
    minimum_name_score: u8,
    validator: F,
) -> RecoveredTargetHive
where
    F: Fn(&RegistryHive) -> anyhow::Result<()>,
{
    let mut output = RecoveredTargetHive {
        hive: None,
        cmhive: None,
        complete: processes.complete,
        warnings: Vec::new(),
    };
    let registry_dtb = registry_process_dtb(processes);
    let hives = match session.hives(65_536) {
        Ok(report) => report,
        Err(error) => {
            output.complete = false;
            output
                .warnings
                .push(format!("无法枚举已加载注册表 Hive：{error:#}"));
            return output;
        }
    };
    output.complete &= hives.complete;
    output.warnings.extend(
        hives
            .warnings
            .into_iter()
            .map(|warning| format!("Hive 活动链表：{warning}")),
    );

    let mut candidates = hives
        .records
        .into_iter()
        .filter_map(|hive| {
            let score = hive_target_score(
                Some(&hive.file_path),
                Some(&hive.user_name),
                Some(&hive.root_path),
                root_path,
            );
            (score >= minimum_name_score).then(|| (score, hive.cmhive, hive_source_name(&hive)))
        })
        .collect::<Vec<_>>();
    candidates
        .sort_unstable_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

    let mut index = 0usize;
    while index < candidates.len() {
        let score = candidates[index].0;
        let group_end = candidates[index..]
            .iter()
            .position(|candidate| candidate.0 != score)
            .map(|offset| index + offset)
            .unwrap_or(candidates.len());
        let mut successes = Vec::new();
        let mut rejected = Vec::new();
        for (_, cmhive, source) in &candidates[index..group_end] {
            match session.recover_hive_memory(*cmhive, registry_dtb, MAX_HIVE_SIZE) {
                Ok(memory) => {
                    let candidate_complete = memory.report.complete;
                    let candidate_warnings = memory
                        .report
                        .warnings
                        .into_iter()
                        .map(|warning| format!("{source}: {warning}"))
                        .collect::<Vec<_>>();
                    let recovered_ranges = memory
                        .report
                        .extents
                        .iter()
                        .map(|extent| {
                            let start = usize::try_from(extent.file_offset)?;
                            let length = usize::try_from(extent.length)?;
                            let end = start
                                .checked_add(length)
                                .context("recovered hive range overflow")?;
                            Ok(start..end)
                        })
                        .collect::<anyhow::Result<Vec<_>>>();
                    match recovered_ranges
                        .and_then(|ranges| RegistryHive::from_recovered_bytes(memory.bytes, ranges))
                        .and_then(|hive| validator(&hive).map(|()| hive))
                    {
                        Ok(hive) => successes.push((
                            *cmhive,
                            source.clone(),
                            hive,
                            candidate_complete,
                            candidate_warnings,
                        )),
                        Err(error) => {
                            rejected.push(format!(
                                "活动候选 {source}（CMHIVE {cmhive:#x}）未通过凭据完整性校验：{error:#}"
                            ));
                            rejected.extend(candidate_warnings);
                        }
                    }
                }
                Err(error) => rejected.push(format!(
                    "无法恢复活动候选 {source}（CMHIVE {cmhive:#x}）：{error:#}"
                )),
            }
        }
        match successes.len() {
            1 => {
                let (cmhive, _, hive, candidate_complete, mut candidate_warnings) =
                    successes.pop().expect("one validated hive candidate");
                output.complete &= candidate_complete;
                output.warnings.append(&mut candidate_warnings);
                output.hive = Some(hive);
                output.cmhive = Some(cmhive);
                return output;
            }
            count if count > 1 => {
                output.complete = false;
                let sources = successes
                    .iter()
                    .map(|(cmhive, source, ..)| format!("{source} ({cmhive:#x})"))
                    .collect::<Vec<_>>()
                    .join("、");
                output.warnings.push(format!(
                    "活动 Hive 候选存在歧义：{count} 个同等级候选均通过 {root_path} 凭据校验：{sources}；已拒绝输出未经唯一绑定的凭据"
                ));
                return output;
            }
            _ => {
                let remaining = 16usize.saturating_sub(output.warnings.len());
                output.warnings.extend(rejected.into_iter().take(remaining));
            }
        }
        index = group_end;
    }

    output.complete = false;
    output.warnings.push(format!(
        "没有唯一且完整通过凭据校验的活动 Hive {root_path}（最低名称绑定分数 {minimum_name_score}）；为避免混配旧的池扫描残留，Hashdump 未使用 hivescan 候选"
    ));
    output
}

struct RecoveredNamedHive {
    source: String,
    hive: RegistryHive,
}

struct RecoveredHiveSet {
    hives: Vec<RecoveredNamedHive>,
    complete: bool,
    warnings: Vec<String>,
}

fn recover_hives_matching(
    session: &AnalysisSession,
    processes: &ProcessListReport,
    predicate: impl Fn(&HiveRecord) -> bool,
) -> RecoveredHiveSet {
    let registry_dtb = registry_process_dtb(processes);
    let mut output = RecoveredHiveSet {
        hives: Vec::new(),
        complete: processes.complete,
        warnings: Vec::new(),
    };
    let report = match session.hives(65_536) {
        Ok(report) => report,
        Err(error) => {
            output.complete = false;
            output
                .warnings
                .push(format!("无法枚举已加载注册表 Hive：{error:#}"));
            return output;
        }
    };
    output.complete &= report.complete;
    output.warnings.extend(
        report
            .warnings
            .into_iter()
            .map(|warning| format!("Hive 活动链表：{warning}")),
    );
    for hive in report.records.into_iter().filter(predicate) {
        let source = hive_source_name(&hive);
        match session.recover_hive_memory(hive.cmhive, registry_dtb, MAX_HIVE_SIZE) {
            Ok(memory) => {
                output.complete &= memory.report.complete;
                output.warnings.extend(
                    memory
                        .report
                        .warnings
                        .into_iter()
                        .map(|warning| format!("{source}: {warning}")),
                );
                match RegistryHive::from_bytes(memory.bytes) {
                    Ok(parsed) => output.hives.push(RecoveredNamedHive {
                        source,
                        hive: parsed,
                    }),
                    Err(error) => {
                        output.complete = false;
                        push_registry_warning(
                            &mut output.warnings,
                            format!("无法解析 {source}：{error:#}"),
                        );
                    }
                }
            }
            Err(error) => {
                output.complete = false;
                push_registry_warning(
                    &mut output.warnings,
                    format!("无法恢复 {source}：{error:#}"),
                );
            }
        }
    }
    if output.hives.is_empty() {
        output.complete = false;
        output
            .warnings
            .push("没有恢复出与请求匹配的驻留注册表 Hive".to_owned());
    }
    output
}

pub(crate) fn registry_process_dtb(processes: &ProcessListReport) -> Option<u64> {
    processes
        .processes
        .iter()
        .find(|process| process.name.eq_ignore_ascii_case("Registry") && process.ppid == Some(4))
        .and_then(|process| {
            // The full process page table maps both HMAP metadata and the
            // private hive views. The KPTI user table can contain only flags
            // (for example 1) and must not hide a usable full process DTB.
            [
                process.details.directory_table_base,
                process.details.user_directory_table_base,
            ]
            .into_iter()
            .flatten()
            .find(|dtb| dtb & 0x000f_ffff_ffff_f000 != 0)
        })
}

pub fn analyze_service_registry(
    session: &AnalysisSession,
    processes: &ProcessListReport,
) -> RegistryEvidence<RegistryServiceInfo> {
    let mut target = recover_target_hive(session, processes, "\\REGISTRY\\MACHINE\\SYSTEM");
    let Some(hive) = target.hive.take() else {
        return RegistryEvidence {
            records: Vec::new(),
            available: false,
            complete: false,
            warnings: target.warnings,
        };
    };
    let current = value_u32(&hive, "Select", "Current").unwrap_or(1);
    let control_set = format!("ControlSet{current:03}");
    let records = parse_services(&hive, &control_set, &mut target.warnings);
    RegistryEvidence {
        records,
        available: true,
        complete: target.complete,
        warnings: target.warnings,
    }
}

pub fn analyze_scheduled_task_registry(
    session: &AnalysisSession,
    processes: &ProcessListReport,
) -> RegistryEvidence<RegistryScheduledTask> {
    let mut target = recover_target_hive(session, processes, "\\REGISTRY\\MACHINE\\SOFTWARE");
    let Some(hive) = target.hive.take() else {
        return RegistryEvidence {
            records: Vec::new(),
            available: false,
            complete: false,
            warnings: target.warnings,
        };
    };
    let records = parse_scheduled_tasks(&hive, &mut target.warnings);
    RegistryEvidence {
        records,
        available: true,
        complete: target.complete,
        warnings: target.warnings,
    }
}

fn registry_key_identity(cmhive: Option<u64>, cell_index: u32) -> Option<String> {
    cmhive.map(|address| format!("{address:016x}:{cell_index:08x}"))
}

pub fn print_registry_key(
    session: &AnalysisSession,
    processes: &ProcessListReport,
    hive_selector: &str,
    key_path: &str,
    recurse: bool,
    limit: usize,
) -> RegistryEvidence<RegistryPrintRecord> {
    let root_path = if hive_selector.starts_with('\\') {
        hive_selector.to_owned()
    } else {
        format!(
            "\\REGISTRY\\MACHINE\\{}",
            hive_selector.to_ascii_uppercase()
        )
    };
    let target = recover_target_hive(session, processes, &root_path);
    print_registry_key_from_target(target, &root_path, key_path, recurse, limit)
}

/// Print a key from one exact active CMHIVE.
///
/// Unlike [`print_registry_key`], this path never tries a differently named
/// loaded hive or a pool-scan candidate.  User-scoped artifacts use it to keep
/// the records bound to the same CMHIVE and mounted root from which the user
/// identity was derived.
pub fn print_registry_key_exact_loaded(
    session: &AnalysisSession,
    processes: &ProcessListReport,
    cmhive: u64,
    expected_root_path: &str,
    key_path: &str,
    recurse: bool,
    limit: usize,
) -> RegistryEvidence<RegistryPrintRecord> {
    let target = recover_exact_loaded_hive(session, processes, cmhive, expected_root_path);
    print_registry_key_from_target(target, expected_root_path, key_path, recurse, limit)
}

/// Reuse the existing key/value decoder with an explicitly recovered stable Hive.
pub fn print_registry_hive(
    hive: RegistryHive,
    source: &str,
    key: &str,
    recurse: bool,
    limit: usize,
) -> RegistryEvidence<RegistryPrintRecord> {
    print_registry_key_from_target(
        RecoveredTargetHive {
            hive: Some(hive),
            cmhive: None,
            complete: true,
            warnings: Vec::new(),
        },
        source,
        key,
        recurse,
        limit,
    )
}

fn print_registry_key_from_target(
    mut target: RecoveredTargetHive,
    root_path: &str,
    key_path: &str,
    recurse: bool,
    limit: usize,
) -> RegistryEvidence<RegistryPrintRecord> {
    let Some(hive) = target.hive.take() else {
        return RegistryEvidence {
            records: Vec::new(),
            available: false,
            complete: false,
            warnings: target.warnings,
        };
    };
    let lookup = hive.open_key_best_effort(key_path).map(|lookup| {
        if !lookup.warnings.is_empty() {
            target.complete = false;
        }
        target.warnings.extend(lookup.warnings);
        lookup.key
    });
    let start = match lookup {
        Ok(Some(key)) => key,
        Ok(None) => {
            target.complete = false;
            target
                .warnings
                .push(format!("在 {root_path} 中没有找到注册表键 {key_path}"));
            return RegistryEvidence {
                records: Vec::new(),
                available: true,
                complete: false,
                warnings: target.warnings,
            };
        }
        Err(error) => {
            target.complete = false;
            target
                .warnings
                .push(format!("无法打开注册表键 {key_path}：{error:#}"));
            return RegistryEvidence {
                records: Vec::new(),
                available: true,
                complete: false,
                warnings: target.warnings,
            };
        }
    };
    let normalized_start = key_path.replace('/', "\\").trim_matches('\\').to_owned();
    let mut records = Vec::new();
    let mut stack = vec![(start, normalized_start, 0usize)];
    let mut visited = BTreeSet::new();
    while let Some((key, path, depth)) = stack.pop() {
        if records.len() == limit {
            target.complete = false;
            target
                .warnings
                .push(format!("注册表输出结果达到 {limit} 条上限"));
            break;
        }
        if !visited.insert(key.cell_index) {
            target.complete = false;
            target
                .warnings
                .push(format!("注册表键在 Cell {:#x} 处形成循环", key.cell_index));
            continue;
        }
        records.push(RegistryPrintRecord {
            depth,
            kind: "key".to_owned(),
            cmhive: target.cmhive,
            cell_index: key.cell_index,
            key_cell_index: key.cell_index,
            key_identity: registry_key_identity(target.cmhive, key.cell_index),
            path: path.clone(),
            name: key.name.clone(),
            data_type: None,
            data_type_name: None,
            data: None,
            last_write_raw: key.last_write_raw,
            last_write: filetime_to_rfc3339(key.last_write_raw),
        });
        match hive.values_best_effort(&key) {
            Ok(values) => {
                if !values.warnings.is_empty() {
                    target.complete = false;
                }
                target.warnings.extend(values.warnings);
                for value in values.values {
                    if records.len() == limit {
                        target.complete = false;
                        target
                            .warnings
                            .push(format!("注册表输出结果达到 {limit} 条上限"));
                        break;
                    }
                    records.push(RegistryPrintRecord {
                        depth: depth + 1,
                        kind: "value".to_owned(),
                        cmhive: target.cmhive,
                        cell_index: value.cell_index,
                        key_cell_index: key.cell_index,
                        key_identity: registry_key_identity(target.cmhive, key.cell_index),
                        path: path.clone(),
                        name: if value.name.is_empty() {
                            "(Default)".to_owned()
                        } else {
                            value.name
                        },
                        data_type: Some(value.data_type),
                        data_type_name: Some(registry_type_name(value.data_type).to_owned()),
                        data: Some(value.data),
                        last_write_raw: key.last_write_raw,
                        last_write: filetime_to_rfc3339(key.last_write_raw),
                    });
                }
            }
            Err(error) => {
                target.complete = false;
                push_registry_warning(
                    &mut target.warnings,
                    format!("无法枚举 {path} 下的值：{error:#}"),
                );
            }
        }
        if recurse || depth == 0 {
            match hive.subkeys_best_effort(&key) {
                Ok(mut children) => {
                    if !children.warnings.is_empty() {
                        target.complete = false;
                    }
                    target.warnings.append(&mut children.warnings);
                    for child in children.keys.into_iter().rev() {
                        let child_path = if path.is_empty() {
                            child.name.clone()
                        } else {
                            format!("{path}\\{}", child.name)
                        };
                        if recurse {
                            stack.push((child, child_path, depth + 1));
                        } else if records.len() < limit {
                            records.push(RegistryPrintRecord {
                                depth: depth + 1,
                                kind: "key".to_owned(),
                                cmhive: target.cmhive,
                                cell_index: child.cell_index,
                                key_cell_index: child.cell_index,
                                key_identity: registry_key_identity(
                                    target.cmhive,
                                    child.cell_index,
                                ),
                                path: child_path,
                                name: child.name,
                                data_type: None,
                                data_type_name: None,
                                data: None,
                                last_write_raw: child.last_write_raw,
                                last_write: filetime_to_rfc3339(child.last_write_raw),
                            });
                        } else {
                            target.complete = false;
                            push_registry_warning(
                                &mut target.warnings,
                                format!("注册表输出结果达到 {limit} 条上限"),
                            );
                            break;
                        }
                    }
                }
                Err(error) => {
                    target.complete = false;
                    push_registry_warning(
                        &mut target.warnings,
                        format!("无法枚举 {path} 下的子键：{error:#}"),
                    );
                }
            }
        }
    }
    RegistryEvidence {
        records,
        available: true,
        complete: target.complete,
        warnings: target.warnings,
    }
}

pub fn analyze_userassist(
    session: &AnalysisSession,
    processes: &ProcessListReport,
    limit: usize,
) -> RegistryEvidence<UserAssistRecord> {
    let hives = recover_hives_matching(session, processes, |hive| {
        [&hive.file_path, &hive.user_name]
            .into_iter()
            .any(|name| name.to_ascii_lowercase().ends_with("\\ntuser.dat"))
    });
    userassist_from_recovered(hives, limit)
}

/// Decode a selected file-backed Hive without opening a symbol-dependent session.
pub fn userassist_from_hive(
    hive: RegistryHive,
    source: &str,
    limit: usize,
) -> RegistryEvidence<UserAssistRecord> {
    userassist_from_recovered(
        RecoveredHiveSet {
            hives: vec![RecoveredNamedHive {
                source: source.into(),
                hive,
            }],
            complete: true,
            warnings: Vec::new(),
        },
        limit,
    )
}

fn artifact_open_key(
    hive: &RegistryHive,
    path: &str,
    context: &str,
    warnings: &mut Vec<String>,
) -> Option<RegistryKey> {
    match hive.open_key_best_effort(path) {
        Ok(result) => {
            warnings.extend(
                result
                    .warnings
                    .into_iter()
                    .map(|warning| format!("{context}: {warning}")),
            );
            result.key
        }
        Err(error) => {
            push_registry_warning(warnings, format!("无法读取 {context} 的 {path}：{error:#}"));
            None
        }
    }
}

fn artifact_values(
    hive: &RegistryHive,
    key: &RegistryKey,
    context: &str,
    warnings: &mut Vec<String>,
) -> Vec<RegistryValue> {
    match hive.values_best_effort(key) {
        Ok(result) => {
            warnings.extend(
                result
                    .warnings
                    .into_iter()
                    .map(|warning| format!("{context}: {warning}")),
            );
            result.values
        }
        Err(error) => {
            push_registry_warning(warnings, format!("无法枚举 {context} 的值：{error:#}"));
            Vec::new()
        }
    }
}

fn userassist_from_recovered(
    mut hives: RecoveredHiveSet,
    limit: usize,
) -> RegistryEvidence<UserAssistRecord> {
    let initial_warnings = hives.warnings.len();
    let mut records = Vec::new();
    let mut limit_reached = false;
    'userassist: for recovered in &hives.hives {
        let Some(base) = artifact_open_key(
            &recovered.hive,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
            &recovered.source,
            &mut hives.warnings,
        ) else {
            continue;
        };
        for guid in best_effort_subkeys(
            &recovered.hive,
            &base,
            &format!("UserAssist {}", recovered.source),
            &mut hives.warnings,
        ) {
            let Some(count) = best_effort_subkeys(
                &recovered.hive,
                &guid,
                &format!("UserAssist {} {}", recovered.source, guid.name),
                &mut hives.warnings,
            )
            .into_iter()
            .find(|key| key.name.eq_ignore_ascii_case("Count")) else {
                continue;
            };
            let values = artifact_values(
                &recovered.hive,
                &count,
                &format!("UserAssist {} {}", recovered.source, guid.name),
                &mut hives.warnings,
            );
            for value in values {
                if records.len() == limit {
                    hives.complete = false;
                    limit_reached = true;
                    break 'userassist;
                }
                let raw = value.raw_data();
                let (session_id, run_count, focus_count, focus_time_ms, last_execution_raw) =
                    if value.data_type == 3 && raw.len() == 72 {
                        (
                            None,
                            read_slice_u32(raw, 4),
                            read_slice_u32(raw, 8),
                            read_slice_u32(raw, 12),
                            read_slice_u64(raw, 60),
                        )
                    } else if value.data_type == 3 && raw.len() == 16 {
                        let stored = read_slice_u32(raw, 4);
                        (
                            read_slice_u32(raw, 0),
                            stored.map(|count| if count < 5 { count } else { count - 5 }),
                            None,
                            None,
                            read_slice_u64(raw, 8),
                        )
                    } else {
                        push_registry_warning(
                            &mut hives.warnings,
                            format!(
                                "UserAssist {} {} 的类型/长度不支持（type={}，{} 字节）；仅保留原始数据",
                                guid.name,
                                value.name,
                                value.data_type,
                                raw.len()
                            ),
                        );
                        (None, None, None, None, None)
                    };
                let last_execution_raw = last_execution_raw.filter(|value| {
                    (122_125_536_000_000_000..=157_469_184_000_000_000).contains(value)
                });
                records.push(UserAssistRecord {
                    hive: recovered.source.clone(),
                    guid: guid.name.clone(),
                    encoded_name: value.name.clone(),
                    decoded_name: rot13(&value.name),
                    session_id,
                    run_count,
                    focus_count,
                    focus_time_ms,
                    last_execution_raw,
                    last_execution: last_execution_raw.and_then(filetime_to_rfc3339),
                    raw_data_hex: hex::encode_upper(raw),
                });
            }
        }
    }
    if limit_reached {
        push_registry_warning(
            &mut hives.warnings,
            format!("UserAssist 结果达到 {limit} 条上限"),
        );
    }
    RegistryEvidence {
        records,
        available: !hives.hives.is_empty(),
        complete: hives.complete && hives.warnings.len() == initial_warnings,
        warnings: hives.warnings,
    }
}

pub fn analyze_amcache(
    session: &AnalysisSession,
    processes: &ProcessListReport,
    limit: usize,
) -> RegistryEvidence<AmcacheRecord> {
    let hives = recover_hives_matching(session, processes, |hive| {
        [&hive.file_path, &hive.user_name]
            .into_iter()
            .any(|name| name.to_ascii_lowercase().ends_with("\\amcache.hve"))
    });
    amcache_from_recovered(hives, limit)
}

pub fn amcache_from_hive(
    hive: RegistryHive,
    source: &str,
    limit: usize,
) -> RegistryEvidence<AmcacheRecord> {
    amcache_from_recovered(
        RecoveredHiveSet {
            hives: vec![RecoveredNamedHive {
                source: source.into(),
                hive,
            }],
            complete: true,
            warnings: Vec::new(),
        },
        limit,
    )
}

fn amcache_from_recovered(
    mut hives: RecoveredHiveSet,
    limit: usize,
) -> RegistryEvidence<AmcacheRecord> {
    let initial_warnings = hives.warnings.len();
    let mut records = Vec::new();
    'amcache: for recovered in &hives.hives {
        let mut recognized = false;
        for (path, entry_type) in [
            ("Root\\InventoryApplication", "program"),
            ("Root\\InventoryApplicationFile", "file"),
            ("Root\\InventoryDriverBinary", "driver"),
            ("Root\\Programs", "program"),
        ] {
            let Some(root) = artifact_open_key(
                &recovered.hive,
                path,
                &recovered.source,
                &mut hives.warnings,
            ) else {
                continue;
            };
            recognized = true;
            for key in best_effort_subkeys(
                &recovered.hive,
                &root,
                &format!("Amcache {path}"),
                &mut hives.warnings,
            ) {
                if records.len() == limit {
                    hives.complete = false;
                    hives
                        .warnings
                        .push(format!("Amcache 结果达到 {limit} 条上限"));
                    break 'amcache;
                }
                let values = artifact_values(
                    &recovered.hive,
                    &key,
                    &format!("Amcache {} {path}\\{}", recovered.source, key.name),
                    &mut hives.warnings,
                );
                let string = |names: &[&str]| {
                    names.iter().find_map(|name| {
                        values
                            .iter()
                            .find(|value| value.name.eq_ignore_ascii_case(name))
                            .and_then(RegistryValue::as_string)
                            .map(str::to_owned)
                    })
                };
                let path_value = string(if entry_type == "file" {
                    &["LowerCaseLongPath", "15"]
                } else if entry_type == "driver" {
                    &["DriverName"]
                } else {
                    &["RootDirPath"]
                });
                let mut sha1 = string(if entry_type == "file" {
                    &["FileId", "101"]
                } else {
                    &["DriverId"]
                });
                let sha1_raw = sha1.clone();
                if let Some(value) = &mut sha1 {
                    // FileId uses a four-character prefix; leading zeroes in a
                    // 40-character digest belong to the hash and must survive.
                    if value.len() == 44
                        && value.starts_with("0000")
                        && value.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        value.drain(..4);
                    }
                }
                if sha1.as_ref().is_some_and(|value| {
                    value.len() != 40 || !value.bytes().all(|b| b.is_ascii_hexdigit())
                }) {
                    push_registry_warning(
                        &mut hives.warnings,
                        format!(
                            "Amcache {path}\\{} 的摘要格式不支持；原文保留在 sha1_raw",
                            key.name
                        ),
                    );
                    sha1 = None;
                }
                records.push(AmcacheRecord {
                    hive: recovered.source.clone(),
                    key_path: format!("{path}\\{}", key.name),
                    entry_type: entry_type.to_owned(),
                    key_name: key.name.clone(),
                    path: path_value,
                    program_id: string(&["ProgramId", "100"]),
                    sha1,
                    sha1_raw,
                    product_name: string(&["ProductName", "Name", "0"]),
                    product_version: string(&["ProductVersion", "Version", "1", "d"]),
                    publisher: string(&["Publisher", "Company", "2", "1"]),
                    service: string(&["Service"]),
                    link_date: string(&["LinkDate", "DriverTimeStamp"]),
                    last_write_raw: key.last_write_raw,
                    last_write: filetime_to_rfc3339(key.last_write_raw),
                });
            }
        }
        if !recognized {
            push_registry_warning(
                &mut hives.warnings,
                format!(
                    "{} 未找到支持的 Amcache 清单分支；旧版 Root\\File 布局尚未覆盖",
                    recovered.source
                ),
            );
        }
    }
    RegistryEvidence {
        records,
        available: !hives.hives.is_empty(),
        complete: hives.complete && hives.warnings.len() == initial_warnings,
        warnings: hives.warnings,
    }
}

pub(crate) fn recover_target_hive(
    session: &AnalysisSession,
    processes: &ProcessListReport,
    root_path: &str,
) -> RecoveredTargetHive {
    let mut output = RecoveredTargetHive {
        hive: None,
        cmhive: None,
        complete: processes.complete,
        warnings: Vec::new(),
    };
    let registry_dtb = registry_process_dtb(processes);
    let hives = match session.hives(65_536) {
        Ok(report) => report,
        Err(error) => {
            output
                .warnings
                .push(format!("无法枚举已加载注册表 Hive：{error:#}"));
            output.complete = false;
            return output;
        }
    };
    output.complete &= hives.complete;
    output.warnings.extend(
        hives
            .warnings
            .into_iter()
            .map(|warning| format!("Hive 活动链表：{warning}")),
    );
    let mut attempted = BTreeSet::new();
    let mut active_candidates = hives
        .records
        .into_iter()
        .filter_map(|hive| {
            let score = hive_target_score(
                Some(&hive.file_path),
                Some(&hive.user_name),
                Some(&hive.root_path),
                root_path,
            );
            (score > 0).then(|| (score, hive.cmhive, hive_source_name(&hive)))
        })
        .collect::<Vec<_>>();
    active_candidates
        .sort_unstable_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

    for (_, cmhive, source) in active_candidates {
        attempted.insert(cmhive);
        if recover_candidate_hive(
            session,
            registry_dtb,
            cmhive,
            &source,
            root_path,
            &mut output,
        ) {
            return output;
        }
    }

    match session.hive_scan(4096) {
        Ok(scan) => {
            output.complete &= scan.complete;
            output.warnings.extend(
                scan.warnings
                    .into_iter()
                    .map(|warning| format!("Hive 池扫描：{warning}")),
            );
            let mut scanned_candidates = scan
                .records
                .into_iter()
                .filter(|hive| !attempted.contains(&hive.cmhive))
                .filter_map(|hive| {
                    let score = hive_target_score(
                        hive.file_path.as_deref(),
                        hive.user_name.as_deref(),
                        hive.root_path.as_deref(),
                        root_path,
                    );
                    (score > 0).then(|| {
                        let source = hive
                            .root_path
                            .as_deref()
                            .filter(|value| !value.is_empty())
                            .or_else(|| hive.file_path.as_deref().filter(|value| !value.is_empty()))
                            .or_else(|| hive.user_name.as_deref().filter(|value| !value.is_empty()))
                            .map(str::to_owned)
                            .unwrap_or_else(|| format!("扫描 CMHIVE {:#x}", hive.cmhive));
                        (score, hive.cmhive, source)
                    })
                })
                .collect::<Vec<_>>();
            scanned_candidates.sort_unstable_by(|left, right| {
                right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1))
            });
            if scanned_candidates.len() > 64 {
                output.complete = false;
                output.warnings.push(format!(
                    "Hive 池扫描候选有 {} 个，仅尝试排序最高的 64 个",
                    scanned_candidates.len()
                ));
            }
            for (_, cmhive, source) in scanned_candidates.into_iter().take(64) {
                if recover_candidate_hive(
                    session,
                    registry_dtb,
                    cmhive,
                    &source,
                    root_path,
                    &mut output,
                ) {
                    return output;
                }
            }
        }
        Err(error) => output
            .warnings
            .push(format!("Hive 池扫描不可用：{error:#}")),
    }
    output.complete = false;
    output
        .warnings
        .push(format!("没有恢复出语义匹配的 Hive {root_path}"));
    output
}

struct ExactLoadedHiveRecovery {
    hive: RegistryHive,
    complete: bool,
    warnings: Vec<String>,
}

/// Recover only the active CMHIVE whose address and mounted root both match
/// the caller's identity.  There is deliberately no name-score or hivescan
/// fallback: returning no user records is safer than attributing another
/// user's records to the requested SID.
fn recover_exact_loaded_hive(
    session: &AnalysisSession,
    processes: &ProcessListReport,
    cmhive: u64,
    expected_root_path: &str,
) -> RecoveredTargetHive {
    let mut output = RecoveredTargetHive {
        hive: None,
        cmhive: None,
        complete: processes.complete,
        warnings: Vec::new(),
    };
    let registry_dtb = registry_process_dtb(processes);
    let hives = match session.hives(65_536) {
        Ok(report) => report,
        Err(error) => {
            output.complete = false;
            output
                .warnings
                .push(format!("无法枚举已加载注册表 Hive：{error:#}"));
            return output;
        }
    };
    output.complete &= hives.complete;
    output.warnings.extend(
        hives
            .warnings
            .into_iter()
            .map(|warning| format!("Hive 活动链表：{warning}")),
    );

    match recover_exact_loaded_candidate_with(
        &hives.records,
        cmhive,
        expected_root_path,
        |candidate| {
            let source = hive_source_name(candidate);
            let memory = session
                .recover_hive_memory(candidate.cmhive, registry_dtb, MAX_HIVE_SIZE)
                .map_err(|error| {
                    format!(
                        "无法恢复精确活动 Hive {source}（CMHIVE {:#x}）：{error:#}",
                        candidate.cmhive
                    )
                })?;
            let complete = memory.report.complete;
            let warnings = memory
                .report
                .warnings
                .into_iter()
                .map(|warning| format!("{source}: {warning}"))
                .collect::<Vec<_>>();
            let hive = RegistryHive::from_bytes(memory.bytes).map_err(|error| {
                format!(
                    "无法解析精确活动 Hive {source}（CMHIVE {:#x}）：{error:#}",
                    candidate.cmhive
                )
            })?;
            Ok(ExactLoadedHiveRecovery {
                hive,
                complete,
                warnings,
            })
        },
    ) {
        Ok(mut recovered) => {
            output.complete &= recovered.complete;
            output.warnings.append(&mut recovered.warnings);
            output.hive = Some(recovered.hive);
            output.cmhive = Some(cmhive);
        }
        Err(error) => {
            output.complete = false;
            output.warnings.push(error);
        }
    }
    output
}

fn recover_exact_loaded_candidate_with<T>(
    hives: &[HiveRecord],
    cmhive: u64,
    expected_root_path: &str,
    recover: impl FnOnce(&HiveRecord) -> Result<T, String>,
) -> Result<T, String> {
    let expected_root = normalize_registry_root(expected_root_path);
    if expected_root.is_empty() {
        return Err(format!(
            "精确活动 Hive CMHIVE {cmhive:#x} 缺少可验证的挂载根路径；已拒绝用户证据归属"
        ));
    }
    let address_matches = hives
        .iter()
        .filter(|candidate| candidate.cmhive == cmhive)
        .collect::<Vec<_>>();
    let root_matches = address_matches
        .iter()
        .copied()
        .filter(|candidate| normalize_registry_root(&candidate.root_path) == expected_root)
        .collect::<Vec<_>>();
    match root_matches.as_slice() {
        [candidate] => recover(candidate),
        [] if address_matches.is_empty() => Err(format!(
            "活动 Hive 链表中没有 CMHIVE {cmhive:#x}（期望根 {expected_root_path}）；未尝试其他 Hive"
        )),
        [] => {
            let observed = address_matches
                .iter()
                .map(|candidate| candidate.root_path.as_str())
                .collect::<Vec<_>>()
                .join("、");
            Err(format!(
                "活动 Hive CMHIVE {cmhive:#x} 的挂载根为 {observed:?}，与期望 {expected_root_path} 不同；未尝试其他 Hive"
            ))
        }
        matches => Err(format!(
            "活动 Hive CMHIVE {cmhive:#x} 与根 {expected_root_path} 出现 {} 个重复候选；已拒绝不唯一归属",
            matches.len()
        )),
    }
}

fn normalize_registry_root(value: &str) -> String {
    value
        .trim()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn recover_candidate_hive(
    session: &AnalysisSession,
    registry_dtb: Option<u64>,
    cmhive: u64,
    source: &str,
    root_path: &str,
    output: &mut RecoveredTargetHive,
) -> bool {
    match session.recover_hive_memory(cmhive, registry_dtb, MAX_HIVE_SIZE) {
        Ok(memory) => {
            output.complete &= memory.report.complete;
            output.warnings.extend(
                memory
                    .report
                    .warnings
                    .into_iter()
                    .map(|warning| format!("{source}: {warning}")),
            );
            match RegistryHive::from_bytes(memory.bytes) {
                Ok(hive) if hive_semantically_matches(&hive, root_path) => {
                    output.hive = Some(hive);
                    output.cmhive = Some(cmhive);
                    true
                }
                Ok(_) => {
                    output.complete = false;
                    output.warnings.push(format!(
                        "候选 {source} 可解析，但其关键注册表结构与 {root_path} 不匹配"
                    ));
                    false
                }
                Err(error) => {
                    output.complete = false;
                    output
                        .warnings
                        .push(format!("无法解析候选 {source}：{error:#}"));
                    false
                }
            }
        }
        Err(error) => {
            output.complete = false;
            output
                .warnings
                .push(format!("无法恢复候选 {source}：{error:#}"));
            false
        }
    }
}

fn hive_target_score(
    file_path: Option<&str>,
    user_name: Option<&str>,
    root: Option<&str>,
    target: &str,
) -> u8 {
    if root.is_some_and(|value| value.eq_ignore_ascii_case(target)) {
        return 100;
    }
    let basename = target.rsplit('\\').next().unwrap_or(target);
    for value in [root, file_path, user_name].into_iter().flatten() {
        if value.is_empty() {
            continue;
        }
        if value
            .trim_end_matches(['\\', '/'])
            .rsplit(['\\', '/'])
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case(basename))
        {
            return 80;
        }
    }
    // CMHIVE names are best-effort paged strings. A stale or corrupted name
    // lowers priority but must not make an otherwise valid hive unreachable.
    1
}

fn hive_semantically_matches(hive: &RegistryHive, target: &str) -> bool {
    let basename = target.rsplit('\\').next().unwrap_or(target);
    let has_key = |path: &str| hive.open_key(path).ok().flatten().is_some();
    if basename.eq_ignore_ascii_case("SYSTEM") {
        let current = value_u32(hive, "Select", "Current").unwrap_or(1);
        return has_key("Select") && has_key(&format!("ControlSet{current:03}\\Control\\Lsa"));
    }
    if basename.eq_ignore_ascii_case("SAM") {
        return has_key("SAM\\Domains\\Account") && has_key("SAM\\Domains\\Account\\Users");
    }
    if basename.eq_ignore_ascii_case("SECURITY") {
        return has_key("Policy");
    }
    if basename.eq_ignore_ascii_case("SOFTWARE") {
        return has_key("Microsoft");
    }
    true
}

pub fn analyze_registry(
    session: &AnalysisSession,
    processes: &ProcessListReport,
) -> RegistrySystemInfo {
    analyze_registry_with_system_hive(session, processes).0
}

/// Decode one file-backed Hive without claiming an active CMHIVE or live state.
/// The caller supplies checked byte ranges and keeps acquisition provenance.
pub fn analyze_registry_file(
    hive: RegistryHive,
    kind: &str,
    source: &str,
) -> anyhow::Result<RegistrySystemInfo> {
    let mut output = RegistrySystemInfo::default();
    match kind {
        "system" => parse_system_hive(&hive, &mut output),
        "software" => parse_software_hive(&hive, &mut output),
        "sam" => parse_sam_hive(&hive, &mut output),
        "ntuser" => {
            parse_user_hives(
                &[LoadedHive {
                    cmhive: 0,
                    root_path: String::new(),
                    source_name: source.to_owned(),
                    hive,
                }],
                &mut output,
            );
        }
        _ => anyhow::bail!("此 Hive 类型暂仅支持键值读取：{kind}"),
    }
    derive_network_artifacts(&mut output);
    derive_service_artifacts(&mut output);
    output.available = true;
    // These flags belong to an active in-memory Hive acquisition, which this path does not establish.
    output.hive_enumeration_complete = false;
    output.usb_source_complete = false;
    output.system_persistence_complete = false;
    output.software_persistence_complete = false;
    output.user_persistence_complete = false;
    output.warnings.push("文件来源仅代表所选 Hive 的已恢复稳定数据；未核验活动 CMHIVE、易失性键、事务日志或当前运行状态".into());
    Ok(output)
}

/// Analyze all supported registry artifacts and also return the exact parsed
/// active SYSTEM hive used for the report. Composite plugins such as USB
/// history use the hive for device-property timestamps without recovering a
/// second, potentially different candidate.
pub fn analyze_registry_with_system_hive(
    session: &AnalysisSession,
    processes: &ProcessListReport,
) -> (RegistrySystemInfo, Option<RegistryHive>) {
    let mut output = RegistrySystemInfo::default();
    let registry_dtb = registry_process_dtb(processes);
    if registry_dtb.is_none() {
        output
            .warnings
            .push("未恢复注册表进程的 DTB；新版用户映射 Hive Bin 可能不完整".to_owned());
    }

    let hive_report = match session.hives(65_536) {
        Ok(report) => report,
        Err(error) => {
            let warning = format!("无法枚举已加载注册表 Hive：{error:#}");
            push_usb_registry_warning(&mut output.usb_source_warnings, warning.clone());
            output.warnings.push(warning);
            return (output, None);
        }
    };
    output.hive_enumeration_complete = hive_report.complete;
    let hive_enumeration_warnings = hive_report
        .warnings
        .into_iter()
        .map(|warning| format!("Hive 活动链表：{warning}"))
        .collect::<Vec<_>>();
    if !output.hive_enumeration_complete {
        push_usb_registry_warning(
            &mut output.usb_source_warnings,
            format!(
                "Hive 活动链表未完整枚举（通用枚举告警 {} 条；详见 registry.warnings）",
                hive_enumeration_warnings.len()
            ),
        );
    }
    output.warnings.extend(hive_enumeration_warnings);

    let mut loaded = Vec::new();
    for hive in hive_report.records {
        let target = registry_analysis_target(&hive);
        let source_name = hive_source_name(&hive);
        let mut status = RegistryHiveStatus {
            cmhive: hive.cmhive,
            cmhive_hex: format!("{:#018x}", hive.cmhive),
            file_path: hive.file_path.clone(),
            user_name: hive.user_name.clone(),
            root_path: hive.root_path.clone(),
            recovery_attempted: target,
            parsed: false,
            complete: None,
            logical_size: None,
            recovered_bytes: None,
            missing_bytes: None,
            warnings: Vec::new(),
            error: None,
        };
        if target {
            match session.recover_hive_memory(hive.cmhive, registry_dtb, MAX_HIVE_SIZE) {
                Ok(memory) => {
                    status.complete = Some(memory.report.complete);
                    status.logical_size = Some(memory.report.logical_size);
                    status.recovered_bytes = Some(memory.report.recovered_bytes);
                    status.missing_bytes = Some(memory.report.missing_bytes);
                    status.warnings = memory.report.warnings;
                    match RegistryHive::from_bytes(memory.bytes) {
                        Ok(parsed) => {
                            status.parsed = true;
                            loaded.push(LoadedHive {
                                cmhive: hive.cmhive,
                                root_path: hive.root_path.clone(),
                                source_name,
                                hive: parsed,
                            });
                        }
                        Err(error) => status.error = Some(format!("{error:#}")),
                    }
                }
                Err(error) => status.error = Some(format!("{error:#}")),
            }
        }
        output.hives.push(status);
    }

    let system = loaded.iter().find(|loaded| {
        loaded
            .root_path
            .eq_ignore_ascii_case("\\REGISTRY\\MACHINE\\SYSTEM")
    });
    let parsed_system_cmhive = system.map(|loaded| loaded.cmhive);
    let exact_system_cmhives = output
        .hives
        .iter()
        .filter(|status| is_exact_system_root(&status.root_path))
        .map(|status| status.cmhive)
        .collect::<Vec<_>>();
    let system_candidates = exact_system_hive_count(&output.hives);
    output.usb_system_cmhive = match exact_system_cmhives.as_slice() {
        [only] => Some(*only),
        _ => parsed_system_cmhive.or_else(|| exact_system_cmhives.first().copied()),
    };
    if system_candidates != 1 {
        push_usb_registry_warning(
            &mut output.usb_source_warnings,
            format!("活动 Hive 中精确 SYSTEM 根候选数量为 {system_candidates}；USB 来源身份不唯一"),
        );
    }
    let software = loaded.iter().find(|loaded| {
        loaded
            .root_path
            .eq_ignore_ascii_case("\\REGISTRY\\MACHINE\\SOFTWARE")
    });
    let sam = loaded.iter().find(|loaded| {
        loaded
            .root_path
            .eq_ignore_ascii_case("\\REGISTRY\\MACHINE\\SAM")
    });

    if let Some(system) = system {
        parse_system_hive(&system.hive, &mut output);
    } else {
        output.warnings.push("无法解析 SYSTEM Hive".to_owned());
    }
    if let Some(software) = software {
        parse_software_hive(&software.hive, &mut output);
    } else {
        output.warnings.push("无法解析 SOFTWARE Hive".to_owned());
    }
    if let Some(sam) = sam {
        parse_sam_hive(&sam.hive, &mut output);
    }
    parse_user_hives(&loaded, &mut output);
    derive_network_artifacts(&mut output);
    derive_service_artifacts(&mut output);
    output.available = system.is_some() || software.is_some() || sam.is_some();

    let mut system_recovery_complete = false;
    if let Some(status) = output
        .usb_system_cmhive
        .and_then(|cmhive| exact_system_hive_status(&output.hives, cmhive))
    {
        system_recovery_complete = status.parsed
            && status.complete == Some(true)
            && parsed_system_cmhive == Some(status.cmhive);
        for warning in &status.warnings {
            push_usb_registry_warning(
                &mut output.usb_source_warnings,
                format!("SYSTEM Hive 恢复：{warning}"),
            );
        }
        if let Some(error) = status.error.as_deref() {
            push_usb_registry_warning(
                &mut output.usb_source_warnings,
                format!("SYSTEM Hive 恢复：{error}"),
            );
        }
        if !system_recovery_complete && status.warnings.is_empty() && status.error.is_none() {
            push_usb_registry_warning(
                &mut output.usb_source_warnings,
                format!(
                    "SYSTEM Hive 未完整恢复（parsed={}，complete={:?}，missing_bytes={:?}）",
                    status.parsed, status.complete, status.missing_bytes
                ),
            );
        }
    } else if output.usb_system_cmhive.is_none() {
        push_usb_registry_warning(
            &mut output.usb_source_warnings,
            "未恢复出可解析且根路径精确匹配的 SYSTEM Hive".to_owned(),
        );
    } else {
        push_usb_registry_warning(
            &mut output.usb_source_warnings,
            "已解析 SYSTEM Hive 与恢复状态无法按 CMHIVE 身份绑定".to_owned(),
        );
    }
    output.usb_source_complete = output.hive_enumeration_complete
        && system_recovery_complete
        && output.usb_source_warnings.is_empty();

    let system_hive = loaded
        .into_iter()
        .find(|loaded| Some(loaded.cmhive) == parsed_system_cmhive)
        .map(|loaded| loaded.hive);
    (output, system_hive)
}

fn exact_system_hive_count(hives: &[RegistryHiveStatus]) -> usize {
    hives
        .iter()
        .filter(|status| is_exact_system_root(&status.root_path))
        .count()
}

fn exact_system_hive_status(
    hives: &[RegistryHiveStatus],
    cmhive: u64,
) -> Option<&RegistryHiveStatus> {
    hives
        .iter()
        .find(|status| status.cmhive == cmhive && is_exact_system_root(&status.root_path))
}

fn is_exact_system_root(root_path: &str) -> bool {
    root_path.eq_ignore_ascii_case("\\REGISTRY\\MACHINE\\SYSTEM")
}

fn registry_analysis_target(hive: &HiveRecord) -> bool {
    let root = hive.root_path.to_ascii_lowercase();
    let name = hive.user_name.to_ascii_lowercase();
    matches!(
        root.as_str(),
        "\\registry\\machine\\system"
            | "\\registry\\machine\\software"
            | "\\registry\\machine\\sam"
    ) || name.ends_with("\\ntuser.dat")
}

fn hive_source_name(hive: &HiveRecord) -> String {
    [&hive.file_path, &hive.user_name, &hive.root_path]
        .into_iter()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| format!("CMHIVE {:#x}", hive.cmhive))
}

fn parse_system_hive(hive: &RegistryHive, output: &mut RegistrySystemInfo) {
    let mut usb_warnings = Vec::new();
    output.current_control_set = usb_control_set_selector(hive, "Current", &mut usb_warnings);
    output.default_control_set = value_u32(hive, "Select", "Default");
    output.last_known_good_control_set = value_u32(hive, "Select", "LastKnownGood");
    output.failed_control_set = value_u32(hive, "Select", "Failed");
    let fallback_default = output
        .current_control_set
        .is_none()
        .then(|| usb_control_set_selector(hive, "Default", &mut usb_warnings))
        .flatten();
    let current = choose_usb_control_set(
        output.current_control_set,
        fallback_default,
        &mut usb_warnings,
    );
    output.usb_control_set_used = Some(current);
    let control_set = format!("ControlSet{current:03}");
    if usb_open_key(hive, &control_set, &mut usb_warnings).is_none() {
        push_usb_registry_warning(
            &mut usb_warnings,
            format!("Select 指向的 {control_set} 根键不可达；未改用其他 ControlSet 冒充活动配置"),
        );
    } else {
        let enum_path = format!("{control_set}\\Enum");
        if usb_open_key(hive, &enum_path, &mut usb_warnings).is_none() {
            push_usb_registry_warning(
                &mut usb_warnings,
                format!("Select 指向的活动 ControlSet 中不存在或无法恢复 {enum_path}"),
            );
        }
    }

    output.computer_name = value_string(
        hive,
        &format!("{control_set}\\Control\\ComputerName\\ComputerName"),
        "ComputerName",
    );
    output.active_computer_name = value_string(
        hive,
        &format!("{control_set}\\Control\\ComputerName\\ActiveComputerName"),
        "ComputerName",
    );
    let tcp_parameters = format!("{control_set}\\Services\\Tcpip\\Parameters");
    output.hostname = value_string(hive, &tcp_parameters, "Hostname")
        .or_else(|| value_string(hive, &tcp_parameters, "NV Hostname"));
    output.domain = value_string(hive, &tcp_parameters, "Domain")
        .or_else(|| value_string(hive, &tcp_parameters, "NV Domain"));

    let shutdown = value_raw(
        hive,
        &format!("{control_set}\\Control\\Windows"),
        "ShutdownTime",
    );
    output.last_shutdown_time_raw = shutdown
        .as_deref()
        .filter(|bytes| bytes.len() >= 8)
        .map(|bytes| u64::from_le_bytes(bytes[..8].try_into().expect("length checked")));
    output.last_shutdown_time = output.last_shutdown_time_raw.and_then(filetime_to_rfc3339);

    let timezone = format!("{control_set}\\Control\\TimeZoneInformation");
    output.timezone = RegistryTimeZoneInfo {
        key_name: value_string(hive, &timezone, "TimeZoneKeyName"),
        standard_name: value_string(hive, &timezone, "StandardName"),
        daylight_name: value_string(hive, &timezone, "DaylightName"),
        bias_minutes: value_u32(hive, &timezone, "Bias").map(|value| value as i32),
        active_bias_minutes: value_u32(hive, &timezone, "ActiveTimeBias").map(|value| value as i32),
        dynamic_daylight_disabled: value_u32(hive, &timezone, "DynamicDaylightTimeDisabled")
            .map(|value| value != 0),
    };

    output.network_adapters =
        parse_network_adapters(hive, &control_set, &BTreeMap::new(), &mut output.warnings);
    let mut persistence_warnings = Vec::new();
    output.services = parse_services(hive, &control_set, &mut persistence_warnings);
    output.autoruns.extend(parse_named_autorun_values(
        hive,
        "boot_execute",
        "machine",
        None,
        "SYSTEM",
        "\\REGISTRY\\MACHINE\\SYSTEM",
        &format!("{control_set}\\Control\\Session Manager"),
        &["BootExecute"],
        Some(true),
        &mut persistence_warnings,
    ));
    output.autoruns.extend(parse_named_autorun_values(
        hive,
        "lsa_package",
        "machine",
        None,
        "SYSTEM",
        "\\REGISTRY\\MACHINE\\SYSTEM",
        &format!("{control_set}\\Control\\Lsa"),
        &[
            "Authentication Packages",
            "Security Packages",
            "Notification Packages",
        ],
        Some(true),
        &mut persistence_warnings,
    ));
    output.system_persistence_complete = persistence_warnings.is_empty();
    output.warnings.extend(
        persistence_warnings
            .into_iter()
            .map(|warning| format!("SYSTEM 持久化：{warning}")),
    );
    output.usb_devices = parse_usb_devices(hive, &control_set, &mut usb_warnings);
    output.mounted_devices = parse_mounted_devices(hive, &mut usb_warnings);
    let mut seen_usb_warnings = BTreeSet::new();
    usb_warnings.retain(|warning| seen_usb_warnings.insert(warning.clone()));
    for warning in &usb_warnings {
        push_usb_registry_warning(
            &mut output.usb_source_warnings,
            format!("SYSTEM USB：{warning}"),
        );
    }
    output.warnings.extend(
        usb_warnings
            .into_iter()
            .map(|warning| format!("SYSTEM USB：{warning}")),
    );
    output.bam_entries = parse_bam(hive, &control_set, &mut output.warnings);
    output.printers.extend(parse_machine_printers(
        hive,
        &control_set,
        &mut output.warnings,
    ));
    output
        .event_log_configuration
        .extend(parse_event_log_configuration(
            hive,
            &control_set,
            &mut output.warnings,
        ));
    output.crash_dump_configuration = parse_crash_dump_configuration(hive, &control_set);
    output
        .rdp_history
        .extend(parse_machine_rdp_configuration(hive, &control_set));
}

fn parse_software_hive(hive: &RegistryHive, output: &mut RegistrySystemInfo) {
    const CURRENT_VERSION: &str = "Microsoft\\Windows NT\\CurrentVersion";
    let install_date = value_u64(hive, CURRENT_VERSION, "InstallDate");
    output.product = RegistryProductInfo {
        product_name: value_string(hive, CURRENT_VERSION, "ProductName"),
        display_version: value_string(hive, CURRENT_VERSION, "DisplayVersion"),
        release_id: value_string(hive, CURRENT_VERSION, "ReleaseId"),
        current_version: value_string(hive, CURRENT_VERSION, "CurrentVersion"),
        current_major_version_number: value_u32(hive, CURRENT_VERSION, "CurrentMajorVersionNumber"),
        current_minor_version_number: value_u32(hive, CURRENT_VERSION, "CurrentMinorVersionNumber"),
        edition_id: value_string(hive, CURRENT_VERSION, "EditionID"),
        composition_edition_id: value_string(hive, CURRENT_VERSION, "CompositionEditionID"),
        installation_type: value_string(hive, CURRENT_VERSION, "InstallationType"),
        current_type: value_string(hive, CURRENT_VERSION, "CurrentType"),
        current_build: value_string(hive, CURRENT_VERSION, "CurrentBuild"),
        current_build_number: value_string(hive, CURRENT_VERSION, "CurrentBuildNumber"),
        ubr: value_u32(hive, CURRENT_VERSION, "UBR"),
        build_branch: value_string(hive, CURRENT_VERSION, "BuildBranch"),
        build_guid: value_string(hive, CURRENT_VERSION, "BuildGUID"),
        build_lab: value_string(hive, CURRENT_VERSION, "BuildLab"),
        build_lab_ex: value_string(hive, CURRENT_VERSION, "BuildLabEx"),
        csd_version: value_string(hive, CURRENT_VERSION, "CSDVersion"),
        registered_owner: value_string(hive, CURRENT_VERSION, "RegisteredOwner"),
        registered_organization: value_string(hive, CURRENT_VERSION, "RegisteredOrganization"),
        product_id: value_string(hive, CURRENT_VERSION, "ProductId"),
        install_date_raw: install_date,
        install_date: install_date.and_then(unix_seconds_to_rfc3339),
    };
    output.profiles = parse_profiles(hive, &mut output.warnings);
    output.network_profiles = parse_network_profiles(hive, &mut output.warnings);
    output.network_signatures = parse_network_signatures(hive, &mut output.warnings);
    let descriptions = parse_network_card_descriptions(hive, &mut output.warnings);
    for adapter in &mut output.network_adapters {
        adapter.description = descriptions
            .get(&adapter.interface_id.to_ascii_lowercase())
            .cloned();
    }
    let mut persistence_warnings = Vec::new();
    output.autoruns.extend(parse_autoruns(
        hive,
        "run_key",
        "machine",
        None,
        "SOFTWARE",
        "\\REGISTRY\\MACHINE\\SOFTWARE",
        &[
            "Microsoft\\Windows\\CurrentVersion\\Run",
            "Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ],
        &mut persistence_warnings,
    ));
    output.autoruns.extend(parse_named_autorun_values(
        hive,
        "winlogon",
        "machine",
        None,
        "SOFTWARE",
        "\\REGISTRY\\MACHINE\\SOFTWARE",
        "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        &["Shell", "Userinit", "Taskman"],
        Some(true),
        &mut persistence_warnings,
    ));
    let appinit_path = "Microsoft\\Windows NT\\CurrentVersion\\Windows";
    let appinit_enabled = value_u32(hive, appinit_path, "LoadAppInit_DLLs").map(|value| value != 0);
    output.autoruns.extend(parse_named_autorun_values(
        hive,
        "appinit_dll",
        "machine",
        None,
        "SOFTWARE",
        "\\REGISTRY\\MACHINE\\SOFTWARE",
        appinit_path,
        &["AppInit_DLLs"],
        appinit_enabled,
        &mut persistence_warnings,
    ));
    output.autoruns.extend(parse_autoruns(
        hive,
        "appcert_dll",
        "machine",
        None,
        "SOFTWARE",
        "\\REGISTRY\\MACHINE\\SOFTWARE",
        &["Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppCertDlls"],
        &mut persistence_warnings,
    ));
    output.autoruns.extend(parse_subkey_named_autoruns(
        hive,
        "ifeo_debugger",
        "machine",
        None,
        "SOFTWARE",
        "\\REGISTRY\\MACHINE\\SOFTWARE",
        "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        &["Debugger"],
        &mut persistence_warnings,
    ));
    output.autoruns.extend(parse_subkey_named_autoruns(
        hive,
        "silent_process_exit",
        "machine",
        None,
        "SOFTWARE",
        "\\REGISTRY\\MACHINE\\SOFTWARE",
        "Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
        &["MonitorProcess"],
        &mut persistence_warnings,
    ));
    output.autoruns.extend(parse_subkey_named_autoruns(
        hive,
        "active_setup",
        "machine",
        None,
        "SOFTWARE",
        "\\REGISTRY\\MACHINE\\SOFTWARE",
        "Microsoft\\Active Setup\\Installed Components",
        &["StubPath"],
        &mut persistence_warnings,
    ));
    output.scheduled_tasks = parse_scheduled_tasks(hive, &mut persistence_warnings);
    output.software_persistence_complete = persistence_warnings.is_empty();
    output.warnings.extend(
        persistence_warnings
            .into_iter()
            .map(|warning| format!("SOFTWARE 持久化：{warning}")),
    );
    output.policies.extend(parse_policy_roots(
        hive,
        "计算机策略",
        &["Policies", "Microsoft\\Windows\\CurrentVersion\\Policies"],
        &mut output.warnings,
    ));
    output
        .security_software
        .extend(parse_security_software(hive, &mut output.warnings));
    output
        .virtualization
        .extend(parse_virtualization_software(hive));
    output
        .wmi_configuration
        .extend(parse_wmi_configuration(hive));
}

fn parse_sam_hive(hive: &RegistryHive, output: &mut RegistrySystemInfo) {
    let Some(names) = open_key(hive, "SAM\\Domains\\Account\\Users\\Names") else {
        return;
    };
    let accounts = best_effort_subkeys(hive, &names, "SAM account names", &mut output.warnings);
    for account in accounts {
        let rid = hive
            .values(&account)
            .ok()
            .and_then(|values| values.into_iter().find(|value| value.name.is_empty()))
            .map(|value| value.data_type);
        output.local_accounts.push(RegistryLocalAccount {
            name: account.name,
            rid,
            last_write_raw: account.last_write_raw,
            last_write: filetime_to_rfc3339(account.last_write_raw),
        });
    }
}

fn parse_user_hives(loaded: &[LoadedHive], output: &mut RegistrySystemInfo) {
    let mut users_examined = 0usize;
    let mut all_persistence_complete = true;
    for loaded in loaded.iter().filter(|loaded| {
        loaded
            .source_name
            .to_ascii_lowercase()
            .ends_with("\\ntuser.dat")
    }) {
        users_examined += 1;
        let mut persistence_warnings = Vec::new();
        output.autoruns.extend(parse_autoruns(
            &loaded.hive,
            "run_key",
            "user",
            user_sid_from_root(&loaded.root_path).as_deref(),
            &loaded.source_name,
            &loaded.root_path,
            &[
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            ],
            &mut persistence_warnings,
        ));
        let user_sid = user_sid_from_root(&loaded.root_path);
        output.autoruns.extend(parse_named_autorun_values(
            &loaded.hive,
            "winlogon",
            "user",
            user_sid.as_deref(),
            &loaded.source_name,
            &loaded.root_path,
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            &["Shell", "Userinit", "Taskman"],
            None,
            &mut persistence_warnings,
        ));
        output.autoruns.extend(parse_subkey_named_autoruns(
            &loaded.hive,
            "active_setup",
            "user",
            user_sid.as_deref(),
            &loaded.source_name,
            &loaded.root_path,
            "Software\\Microsoft\\Active Setup\\Installed Components",
            &["StubPath"],
            &mut persistence_warnings,
        ));
        all_persistence_complete &= persistence_warnings.is_empty();
        output.warnings.extend(
            persistence_warnings
                .into_iter()
                .map(|warning| format!("{} 持久化：{warning}", loaded.source_name)),
        );
        output
            .printers
            .extend(parse_user_printers(&loaded.hive, &loaded.source_name));
        output.policies.extend(parse_policy_roots(
            &loaded.hive,
            "用户策略",
            &[
                "Software\\Policies",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Policies",
            ],
            &mut output.warnings,
        ));
        output.rdp_history.extend(parse_user_rdp_history(
            &loaded.hive,
            &loaded.source_name,
            &mut output.warnings,
        ));
    }
    output.user_persistence_complete = users_examined != 0 && all_persistence_complete;
}

fn parse_machine_printers(
    hive: &RegistryHive,
    control_set: &str,
    warnings: &mut Vec<String>,
) -> Vec<RegistryPrinterRecord> {
    let path = format!("{control_set}\\Control\\Print\\Printers");
    let Some(base) = open_key(hive, &path) else {
        return Vec::new();
    };
    best_effort_subkeys(hive, &base, "installed printers", warnings)
        .into_iter()
        .map(|key| RegistryPrinterRecord {
            category: "系统打印机".to_owned(),
            printer_name: key.name.clone(),
            port: value_string_for_key(hive, &key, "Port"),
            driver: value_string_for_key(hive, &key, "Printer Driver")
                .or_else(|| value_string_for_key(hive, &key, "Driver")),
            server: value_string_for_key(hive, &key, "ServerName")
                .or_else(|| value_string_for_key(hive, &key, "Share Name")),
            status: value_for_key(hive, &key, "Status").map(|value| registry_value_display(&value)),
            key_timestamp: filetime_to_rfc3339(key.last_write_raw),
        })
        .collect()
}

fn parse_user_printers(hive: &RegistryHive, source: &str) -> Vec<RegistryPrinterRecord> {
    let mut output = Vec::new();
    if let Some(devices) = open_key(
        hive,
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Devices",
    ) && let Ok(values) = hive.values(&devices)
    {
        for value in values {
            let raw = registry_value_display(&value);
            let mut parts = raw.split(',').map(str::trim);
            output.push(RegistryPrinterRecord {
                category: format!("用户打印机（{source}）"),
                printer_name: value.name,
                port: parts
                    .nth(1)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned),
                driver: raw
                    .split(',')
                    .next()
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned),
                server: None,
                status: None,
                key_timestamp: filetime_to_rfc3339(devices.last_write_raw),
            });
        }
    }
    if let Some(connections) = open_key(hive, "Printers\\Connections")
        && let Ok(keys) = hive.subkeys(&connections)
    {
        for key in keys {
            output.push(RegistryPrinterRecord {
                category: format!("网络打印机（{source}）"),
                printer_name: value_string_for_key(hive, &key, "PrinterPath")
                    .unwrap_or_else(|| key.name.replace(',', "\\")),
                port: None,
                driver: value_string_for_key(hive, &key, "Provider"),
                server: value_string_for_key(hive, &key, "Server"),
                status: None,
                key_timestamp: filetime_to_rfc3339(key.last_write_raw),
            });
        }
    }
    output
}

fn parse_policy_roots(
    hive: &RegistryHive,
    scope: &str,
    roots: &[&str],
    warnings: &mut Vec<String>,
) -> Vec<RegistryPolicyRecord> {
    let mut output = Vec::new();
    for root in roots {
        let Some(key) = open_key(hive, root) else {
            continue;
        };
        collect_policy_values(hive, &key, root, scope, 0, &mut output, warnings);
    }
    output
}

fn collect_policy_values(
    hive: &RegistryHive,
    key: &RegistryKey,
    path: &str,
    scope: &str,
    depth: usize,
    output: &mut Vec<RegistryPolicyRecord>,
    warnings: &mut Vec<String>,
) {
    if depth > 8 || output.len() >= 50_000 {
        return;
    }
    if let Ok(values) = hive.values(key) {
        for value in values {
            output.push(RegistryPolicyRecord {
                category: format!("{scope} · {path}"),
                setting_name: if value.name.is_empty() {
                    "(默认)".to_owned()
                } else {
                    value.name.clone()
                },
                value: registry_value_display(&value),
                description: format!("注册表策略 {path}"),
                key_timestamp: filetime_to_rfc3339(key.last_write_raw),
            });
        }
    }
    for child in best_effort_subkeys(hive, key, path, warnings) {
        let child_path = format!("{path}\\{}", child.name);
        collect_policy_values(
            hive,
            &child,
            &child_path,
            scope,
            depth + 1,
            output,
            warnings,
        );
    }
}

fn parse_security_software(
    hive: &RegistryHive,
    warnings: &mut Vec<String>,
) -> Vec<RegistrySecurityRecord> {
    let mut output = Vec::new();
    for (software, path) in [
        ("Microsoft Defender", "Microsoft\\Windows Defender"),
        (
            "Windows Security Center",
            "Microsoft\\Security Center\\Provider",
        ),
    ] {
        let Some(base) = open_key(hive, path) else {
            continue;
        };
        collect_security_values(hive, &base, path, software, 0, &mut output, warnings);
    }
    output
}

fn collect_security_values(
    hive: &RegistryHive,
    key: &RegistryKey,
    path: &str,
    software: &str,
    depth: usize,
    output: &mut Vec<RegistrySecurityRecord>,
    warnings: &mut Vec<String>,
) {
    if depth > 4 || output.len() >= 20_000 {
        return;
    }
    let display_name = value_string_for_key(hive, key, "DISPLAYNAME")
        .or_else(|| value_string_for_key(hive, key, "DisplayName"))
        .unwrap_or_else(|| software.to_owned());
    if let Ok(values) = hive.values(key) {
        for value in values {
            output.push(RegistrySecurityRecord {
                security_software: display_name.clone(),
                component: path.to_owned(),
                setting: if value.name.is_empty() {
                    "(默认)".to_owned()
                } else {
                    value.name.clone()
                },
                value: registry_value_display(&value),
                key_timestamp: filetime_to_rfc3339(key.last_write_raw),
            });
        }
    }
    for child in best_effort_subkeys(hive, key, path, warnings) {
        let child_path = format!("{path}\\{}", child.name);
        collect_security_values(
            hive,
            &child,
            &child_path,
            software,
            depth + 1,
            output,
            warnings,
        );
    }
}

fn parse_virtualization_software(hive: &RegistryHive) -> Vec<RegistryVirtualizationRecord> {
    [
        ("VMware", "VMware, Inc."),
        ("Oracle VirtualBox", "Oracle\\VirtualBox Guest Additions"),
        ("QEMU", "QEMU"),
        ("Parallels", "Parallels"),
        ("Hyper-V", "Microsoft\\Virtual Machine\\Guest\\Parameters"),
    ]
    .into_iter()
    .filter_map(|(name, path)| {
        open_key(hive, path).map(|key| RegistryVirtualizationRecord {
            category: "虚拟化软件".to_owned(),
            indicator: name.to_owned(),
            value: "已检测".to_owned(),
            details: format!("SOFTWARE\\{path}"),
            key_timestamp: filetime_to_rfc3339(key.last_write_raw),
        })
    })
    .collect()
}

fn parse_wmi_configuration(hive: &RegistryHive) -> Vec<RegistryWmiRecord> {
    let mut output = Vec::new();
    for path in [
        "Microsoft\\WBEM\\CIMOM",
        "Microsoft\\WBEM\\WDM",
        "Microsoft\\Windows NT\\CurrentVersion\\WMI",
    ] {
        let Some(key) = open_key(hive, path) else {
            continue;
        };
        if let Ok(values) = hive.values(&key) {
            for value in values {
                output.push(RegistryWmiRecord {
                    category: "WMI 配置".to_owned(),
                    component: path.to_owned(),
                    setting: if value.name.is_empty() {
                        "(默认)".to_owned()
                    } else {
                        value.name.clone()
                    },
                    value: registry_value_display(&value),
                    key_timestamp: filetime_to_rfc3339(key.last_write_raw),
                });
            }
        }
    }
    output
}

fn parse_event_log_configuration(
    hive: &RegistryHive,
    control_set: &str,
    warnings: &mut Vec<String>,
) -> Vec<RegistryEventLogConfigRecord> {
    let path = format!("{control_set}\\Services\\EventLog");
    let Some(base) = open_key(hive, &path) else {
        return Vec::new();
    };
    let mut output = Vec::new();
    for channel in best_effort_subkeys(hive, &base, "EventLog channels", warnings) {
        if let Ok(values) = hive.values(&channel) {
            for value in values {
                output.push(RegistryEventLogConfigRecord {
                    category: "经典事件日志".to_owned(),
                    channel: channel.name.clone(),
                    setting: if value.name.is_empty() {
                        "(默认)".to_owned()
                    } else {
                        value.name.clone()
                    },
                    value: registry_value_display(&value),
                    key_timestamp: filetime_to_rfc3339(channel.last_write_raw),
                });
            }
        }
    }
    output
}

fn parse_crash_dump_configuration(
    hive: &RegistryHive,
    control_set: &str,
) -> Vec<RegistryCrashDumpRecord> {
    let path = format!("{control_set}\\Control\\CrashControl");
    let Some(key) = open_key(hive, &path) else {
        return Vec::new();
    };
    hive.values(&key)
        .unwrap_or_default()
        .into_iter()
        .map(|value| {
            let details = match value.name.as_str() {
                "CrashDumpEnabled" => "转储类型：0=关闭，1=完整，2=内核，3=小型，7=自动",
                "DumpFile" | "MinidumpDir" | "DedicatedDumpFile" => "崩溃转储输出位置",
                "AutoReboot" => "系统崩溃后是否自动重启",
                "LogEvent" => "是否把系统崩溃写入事件日志",
                _ => "CrashControl 注册表配置",
            };
            RegistryCrashDumpRecord {
                category: "CrashControl".to_owned(),
                setting_name: if value.name.is_empty() {
                    "(默认)".to_owned()
                } else {
                    value.name.clone()
                },
                value: registry_value_display(&value),
                details: details.to_owned(),
                key_timestamp: filetime_to_rfc3339(key.last_write_raw),
            }
        })
        .collect()
}

fn parse_machine_rdp_configuration(
    hive: &RegistryHive,
    control_set: &str,
) -> Vec<RegistryRdpRecord> {
    let paths = [
        format!("{control_set}\\Control\\Terminal Server"),
        format!("{control_set}\\Control\\Terminal Server\\WinStations\\RDP-Tcp"),
    ];
    let mut output = Vec::new();
    for path in paths {
        let Some(key) = open_key(hive, &path) else {
            continue;
        };
        if let Ok(values) = hive.values(&key) {
            for value in values {
                output.push(RegistryRdpRecord {
                    category: "RDP 配置".to_owned(),
                    target_or_setting: value.name.clone(),
                    username: None,
                    value: registry_value_display(&value),
                    last_connected: None,
                    key_timestamp: filetime_to_rfc3339(key.last_write_raw),
                });
            }
        }
    }
    output
}

fn parse_user_rdp_history(
    hive: &RegistryHive,
    source: &str,
    warnings: &mut Vec<String>,
) -> Vec<RegistryRdpRecord> {
    const BASE: &str = "Software\\Microsoft\\Terminal Server Client";
    let mut output = Vec::new();
    if let Some(default) = open_key(hive, &format!("{BASE}\\Default"))
        && let Ok(values) = hive.values(&default)
    {
        for value in values
            .into_iter()
            .filter(|value| value.name.to_ascii_uppercase().starts_with("MRU"))
        {
            output.push(RegistryRdpRecord {
                category: format!("RDP 最近连接（{source}）"),
                target_or_setting: registry_value_display(&value),
                username: None,
                value: value.name,
                last_connected: filetime_to_rfc3339(default.last_write_raw),
                key_timestamp: filetime_to_rfc3339(default.last_write_raw),
            });
        }
    }
    let Some(servers) = open_key(hive, &format!("{BASE}\\Servers")) else {
        return output;
    };
    for server in best_effort_subkeys(hive, &servers, "RDP server history", warnings) {
        output.push(RegistryRdpRecord {
            category: format!("RDP 服务器（{source}）"),
            target_or_setting: server.name.clone(),
            username: value_string_for_key(hive, &server, "UsernameHint"),
            value: "历史连接".to_owned(),
            last_connected: filetime_to_rfc3339(server.last_write_raw),
            key_timestamp: filetime_to_rfc3339(server.last_write_raw),
        });
    }
    output
}

fn derive_network_artifacts(output: &mut RegistrySystemInfo) {
    for adapter in &output.network_adapters {
        let interface = adapter
            .description
            .clone()
            .unwrap_or_else(|| adapter.interface_id.clone());
        let mut add = |configuration: &str, value: String| {
            if !value.trim().is_empty() {
                output
                    .network_configuration
                    .push(RegistryNetworkConfigRecord {
                        category: "网络接口".to_owned(),
                        interface_or_protocol: interface.clone(),
                        configuration: configuration.to_owned(),
                        value,
                        key_timestamp: adapter.last_write.clone(),
                    });
            }
        };
        add("接口 GUID", adapter.interface_id.clone());
        add(
            "DHCP",
            adapter
                .enable_dhcp
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
        add("IP 地址", adapter.ip_addresses.join("; "));
        add("子网掩码", adapter.subnet_masks.join("; "));
        add("默认网关", adapter.default_gateways.join("; "));
        add("DNS 服务器", adapter.dns_servers.join("; "));
        add(
            "DHCP 服务器",
            adapter.dhcp_server.clone().unwrap_or_default(),
        );
        add("DNS 域", adapter.domain.clone().unwrap_or_default());
    }

    for profile in &output.network_profiles {
        let signature = output.network_signatures.iter().find(|signature| {
            signature
                .profile_guid
                .as_deref()
                .is_some_and(|guid| guid.eq_ignore_ascii_case(&profile.profile_guid))
        });
        output.wireless_history.push(RegistryWirelessRecord {
            network_name: profile
                .profile_name
                .clone()
                .or_else(|| profile.description.clone())
                .unwrap_or_else(|| "未命名网络".to_owned()),
            guid: profile.profile_guid.clone(),
            category: match profile.category {
                Some(0) => "公用网络",
                Some(1) => "专用网络",
                Some(2) => "域网络",
                _ => "网络历史",
            }
            .to_owned(),
            network_type: if signature.is_some() {
                "NetworkList 配置"
            } else {
                "历史配置"
            }
            .to_owned(),
            first_connect: profile.date_created.clone(),
            last_connect: profile
                .date_last_connected
                .clone()
                .or_else(|| profile.last_write.clone()),
            gateway_mac: signature.and_then(|signature| signature.default_gateway_mac.clone()),
            key_timestamp: profile.last_write.clone(),
        });
    }
}

fn derive_service_artifacts(output: &mut RegistrySystemInfo) {
    const VM_TOKENS: &[(&str, &str)] = &[
        ("vmware", "VMware"),
        ("vbox", "Oracle VirtualBox"),
        ("virtualbox", "Oracle VirtualBox"),
        ("xen", "Xen"),
        ("qemu", "QEMU"),
        ("prl_", "Parallels"),
        ("hyper-v", "Hyper-V"),
        ("vmicheartbeat", "Hyper-V"),
    ];
    const SECURITY_TOKENS: &[(&str, &str)] = &[
        ("windefend", "Microsoft Defender"),
        ("sense", "Microsoft Defender for Endpoint"),
        ("wdnis", "Microsoft Defender"),
        ("msmpeng", "Microsoft Defender"),
        ("avast", "Avast"),
        ("avg", "AVG"),
        ("kaspersky", "Kaspersky"),
        ("symantec", "Symantec"),
        ("mcafee", "McAfee"),
        ("crowdstrike", "CrowdStrike"),
        ("sentinel", "SentinelOne"),
        ("360", "360 安全软件"),
    ];
    let mut virtualization = Vec::new();
    let mut security = Vec::new();
    for service in &output.services {
        let evidence = format!(
            "{} {} {}",
            service.name,
            service.display_name.as_deref().unwrap_or(""),
            service.image_path.as_deref().unwrap_or("")
        )
        .to_ascii_lowercase();
        for (token, product) in VM_TOKENS {
            if evidence.contains(token) {
                virtualization.push(RegistryVirtualizationRecord {
                    category: "虚拟化服务".to_owned(),
                    indicator: (*product).to_owned(),
                    value: service.name.clone(),
                    details: service.image_path.clone().unwrap_or_default(),
                    key_timestamp: service.last_write.clone(),
                });
                break;
            }
        }
        for (token, product) in SECURITY_TOKENS {
            if evidence.contains(token) {
                security.push(RegistrySecurityRecord {
                    security_software: (*product).to_owned(),
                    component: "系统服务".to_owned(),
                    setting: service.name.clone(),
                    value: match service.start {
                        Some(2) => "自动启动",
                        Some(3) => "手动启动",
                        Some(4) => "已禁用",
                        _ => "已注册",
                    }
                    .to_owned(),
                    key_timestamp: service.last_write.clone(),
                });
                break;
            }
        }
    }
    output.virtualization.extend(virtualization);
    output.security_software.extend(security);
}

fn registry_value_display(value: &RegistryValue) -> String {
    match &value.data {
        RegistryValueData::None => String::new(),
        RegistryValueData::String(value)
        | RegistryValueData::Binary(value)
        | RegistryValueData::Unknown(value) => value.clone(),
        RegistryValueData::MultiString(values) => values.join("; "),
        RegistryValueData::Dword(value) => value.to_string(),
        RegistryValueData::Qword(value) => value.to_string(),
    }
}

fn parse_profiles(hive: &RegistryHive, warnings: &mut Vec<String>) -> Vec<RegistryProfileInfo> {
    let path = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    let Some(base) = open_key(hive, path) else {
        return Vec::new();
    };
    let children = best_effort_subkeys(hive, &base, "ProfileList", warnings);
    children
        .into_iter()
        .filter(|key| key.name.to_ascii_uppercase().starts_with("S-1-"))
        .map(|key| RegistryProfileInfo {
            sid: key.name.clone(),
            profile_path: value_string_for_key(hive, &key, "ProfileImagePath"),
            flags: value_u32_for_key(hive, &key, "Flags"),
            state: value_u32_for_key(hive, &key, "State"),
            ref_count: value_u32_for_key(hive, &key, "RefCount"),
            full_profile: value_u32_for_key(hive, &key, "FullProfile").map(|value| value != 0),
            last_write_raw: key.last_write_raw,
            last_write: filetime_to_rfc3339(key.last_write_raw),
        })
        .collect()
}

fn parse_network_card_descriptions(
    hive: &RegistryHive,
    warnings: &mut Vec<String>,
) -> BTreeMap<String, String> {
    let mut descriptions = BTreeMap::new();
    let Some(base) = open_key(hive, "Microsoft\\Windows NT\\CurrentVersion\\NetworkCards") else {
        return descriptions;
    };
    let cards = best_effort_subkeys(hive, &base, "NetworkCards", warnings);
    for card in cards {
        if let (Some(service), Some(description)) = (
            value_string_for_key(hive, &card, "ServiceName"),
            value_string_for_key(hive, &card, "Description"),
        ) {
            descriptions.insert(service.to_ascii_lowercase(), description);
        }
    }
    descriptions
}

fn parse_network_adapters(
    hive: &RegistryHive,
    control_set: &str,
    descriptions: &BTreeMap<String, String>,
    warnings: &mut Vec<String>,
) -> Vec<RegistryNetworkAdapter> {
    let path = format!("{control_set}\\Services\\Tcpip\\Parameters\\Interfaces");
    let Some(base) = open_key(hive, &path) else {
        return Vec::new();
    };
    let interfaces = best_effort_subkeys(hive, &base, "TCP/IP interfaces", warnings);
    interfaces
        .into_iter()
        .map(|key| {
            let mut ip_addresses = values_as_strings(hive, &key, &["IPAddress", "DhcpIPAddress"]);
            retain_meaningful_network_values(&mut ip_addresses);
            let mut subnet_masks = values_as_strings(hive, &key, &["SubnetMask", "DhcpSubnetMask"]);
            retain_meaningful_network_values(&mut subnet_masks);
            let mut default_gateways =
                values_as_strings(hive, &key, &["DefaultGateway", "DhcpDefaultGateway"]);
            retain_meaningful_network_values(&mut default_gateways);
            let mut dns_servers = values_as_strings(hive, &key, &["NameServer", "DhcpNameServer"])
                .into_iter()
                .flat_map(|value| {
                    value
                        .split([',', ' ', ';'])
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            dedup_case_insensitive(&mut dns_servers);
            let lease_obtained = value_u64_for_key(hive, &key, "LeaseObtainedTime");
            let lease_terminates = value_u64_for_key(hive, &key, "LeaseTerminatesTime");
            RegistryNetworkAdapter {
                interface_id: key.name.clone(),
                description: descriptions.get(&key.name.to_ascii_lowercase()).cloned(),
                enable_dhcp: value_u32_for_key(hive, &key, "EnableDHCP").map(|value| value != 0),
                ip_addresses,
                subnet_masks,
                default_gateways,
                dns_servers,
                domain: value_string_for_key(hive, &key, "Domain")
                    .or_else(|| value_string_for_key(hive, &key, "DhcpDomain")),
                dhcp_server: value_string_for_key(hive, &key, "DhcpServer"),
                lease_obtained_raw: lease_obtained,
                lease_obtained: lease_obtained.and_then(unix_seconds_to_rfc3339),
                lease_terminates_raw: lease_terminates,
                lease_terminates: lease_terminates.and_then(unix_seconds_to_rfc3339),
                last_write_raw: key.last_write_raw,
                last_write: filetime_to_rfc3339(key.last_write_raw),
            }
        })
        .collect()
}

fn parse_network_profiles(
    hive: &RegistryHive,
    warnings: &mut Vec<String>,
) -> Vec<RegistryNetworkProfile> {
    let path = "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles";
    let Some(base) = open_key(hive, path) else {
        return Vec::new();
    };
    let profiles = best_effort_subkeys(hive, &base, "NetworkList profiles", warnings);
    profiles
        .into_iter()
        .map(|key| RegistryNetworkProfile {
            profile_guid: key.name.clone(),
            profile_name: value_string_for_key(hive, &key, "ProfileName"),
            description: value_string_for_key(hive, &key, "Description"),
            category: value_u32_for_key(hive, &key, "Category"),
            managed: value_u32_for_key(hive, &key, "Managed").map(|value| value != 0),
            date_created: value_raw_for_key(hive, &key, "DateCreated")
                .as_deref()
                .and_then(systemtime_to_string),
            date_last_connected: value_raw_for_key(hive, &key, "DateLastConnected")
                .as_deref()
                .and_then(systemtime_to_string),
            last_write_raw: key.last_write_raw,
            last_write: filetime_to_rfc3339(key.last_write_raw),
        })
        .collect()
}

fn parse_network_signatures(
    hive: &RegistryHive,
    warnings: &mut Vec<String>,
) -> Vec<RegistryNetworkSignature> {
    let mut output = Vec::new();
    for (branch, managed) in [("Managed", true), ("Unmanaged", false)] {
        let path =
            format!("Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\{branch}");
        let Some(base) = open_key(hive, &path) else {
            continue;
        };
        let signatures = best_effort_subkeys(
            hive,
            &base,
            &format!("NetworkList {branch} signatures"),
            warnings,
        );
        for key in signatures {
            output.push(RegistryNetworkSignature {
                signature_id: key.name.clone(),
                managed,
                profile_guid: value_string_for_key(hive, &key, "ProfileGuid"),
                description: value_string_for_key(hive, &key, "Description"),
                dns_suffix: value_string_for_key(hive, &key, "DnsSuffix"),
                first_network: value_string_for_key(hive, &key, "FirstNetwork"),
                default_gateway_mac: value_raw_for_key(hive, &key, "DefaultGatewayMac")
                    .as_deref()
                    .map(format_mac),
                last_write_raw: key.last_write_raw,
                last_write: filetime_to_rfc3339(key.last_write_raw),
            });
        }
    }
    output
}

fn parse_services(
    hive: &RegistryHive,
    control_set: &str,
    warnings: &mut Vec<String>,
) -> Vec<RegistryServiceInfo> {
    let path = format!("{control_set}\\Services");
    let base = match hive.open_key(&path) {
        Ok(Some(base)) => base,
        Ok(None) => {
            warnings.push(format!("SYSTEM Hive 中不存在必需的服务根键 {path}"));
            return Vec::new();
        }
        Err(error) => {
            warnings.push(format!("无法打开服务根键 {path}：{error:#}"));
            return Vec::new();
        }
    };
    let services = best_effort_subkeys(hive, &base, "services", warnings);
    let mut output = Vec::new();
    for key in services {
        let values = match hive.values(&key) {
            Ok(values) => values,
            Err(error) => {
                warnings.push(format!(
                    "服务键 {path}\\{} 的值列表恢复失败：{error:#}",
                    key.name
                ));
                continue;
            }
        };
        let named = |name: &str| {
            values
                .iter()
                .find(|value| value.name.eq_ignore_ascii_case(name))
        };
        let service_dll =
            best_effort_subkeys(hive, &key, &format!("服务 {} 子键", key.name), warnings)
                .into_iter()
                .find(|child| child.name.eq_ignore_ascii_case("Parameters"))
                .and_then(
                    |parameters| match hive.value_by_name(&parameters, "ServiceDll") {
                        Ok(value) => value.and_then(|value| value.as_string().map(str::to_owned)),
                        Err(error) => {
                            warnings.push(format!(
                                "服务键 {path}\\{}\\Parameters 的 ServiceDll 恢复失败：{error:#}",
                                key.name
                            ));
                            None
                        }
                    },
                );
        let depend_on_service = match named("DependOnService").map(|value| &value.data) {
            Some(RegistryValueData::String(value)) => vec![value.clone()],
            Some(RegistryValueData::MultiString(values)) => values.clone(),
            _ => Vec::new(),
        };
        output.push(RegistryServiceInfo {
            name: key.name.clone(),
            display_name: named("DisplayName")
                .and_then(RegistryValue::as_string)
                .map(str::to_owned),
            image_path: named("ImagePath")
                .and_then(RegistryValue::as_string)
                .map(str::to_owned),
            service_dll,
            object_name: named("ObjectName")
                .and_then(RegistryValue::as_string)
                .map(str::to_owned),
            group: named("Group")
                .and_then(RegistryValue::as_string)
                .map(str::to_owned),
            depend_on_service,
            start: named("Start").and_then(RegistryValue::as_u32),
            service_type: named("Type").and_then(RegistryValue::as_u32),
            error_control: named("ErrorControl").and_then(RegistryValue::as_u32),
            last_write_raw: key.last_write_raw,
            last_write: filetime_to_rfc3339(key.last_write_raw),
        });
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn parse_autoruns(
    hive: &RegistryHive,
    mechanism: &str,
    scope: &str,
    user_sid: Option<&str>,
    source_hive: &str,
    source_root: &str,
    paths: &[&str],
    warnings: &mut Vec<String>,
) -> Vec<RegistryAutorun> {
    let mut output = Vec::new();
    for path in paths {
        let key = match hive.open_key(path) {
            Ok(Some(key)) => key,
            Ok(None) => continue,
            Err(error) => {
                warnings.push(format!("无法打开 autorun 键 {path}：{error:#}"));
                continue;
            }
        };
        let values = match hive.values(&key) {
            Ok(values) => values,
            Err(error) => {
                warnings.push(format!("autorun 键 {path} 的值列表恢复失败：{error:#}"));
                continue;
            }
        };
        for value in values {
            if let Some(command) = value
                .as_string()
                .map(str::trim)
                .filter(|command| !command.is_empty())
                .map(str::to_owned)
            {
                output.push(RegistryAutorun {
                    mechanism: mechanism.to_owned(),
                    scope: scope.to_owned(),
                    user_sid: user_sid.map(str::to_owned),
                    key_path: (*path).to_owned(),
                    name: value.name,
                    command,
                    enabled: None,
                    source_hive: source_hive.to_owned(),
                    source_root: source_root.to_owned(),
                    key_last_write_raw: key.last_write_raw,
                    key_last_write: filetime_to_rfc3339(key.last_write_raw),
                });
            }
        }
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn parse_named_autorun_values(
    hive: &RegistryHive,
    mechanism: &str,
    scope: &str,
    user_sid: Option<&str>,
    source_hive: &str,
    source_root: &str,
    path: &str,
    names: &[&str],
    enabled: Option<bool>,
    warnings: &mut Vec<String>,
) -> Vec<RegistryAutorun> {
    let key = match hive.open_key(path) {
        Ok(Some(key)) => key,
        Ok(None) => return Vec::new(),
        Err(error) => {
            warnings.push(format!("无法打开 autorun 键 {path}：{error:#}"));
            return Vec::new();
        }
    };
    let values = match hive.values(&key) {
        Ok(values) => values,
        Err(error) => {
            warnings.push(format!("autorun 键 {path} 的值列表恢复失败：{error:#}"));
            return Vec::new();
        }
    };
    let mut output = Vec::new();
    for value in values {
        if !names
            .iter()
            .any(|name| value.name.eq_ignore_ascii_case(name))
        {
            continue;
        }
        for command in registry_value_commands(&value) {
            if command.trim().is_empty() {
                continue;
            }
            output.push(RegistryAutorun {
                mechanism: mechanism.to_owned(),
                scope: scope.to_owned(),
                user_sid: user_sid.map(str::to_owned),
                key_path: path.to_owned(),
                name: value.name.clone(),
                command,
                enabled,
                source_hive: source_hive.to_owned(),
                source_root: source_root.to_owned(),
                key_last_write_raw: key.last_write_raw,
                key_last_write: filetime_to_rfc3339(key.last_write_raw),
            });
        }
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn parse_subkey_named_autoruns(
    hive: &RegistryHive,
    mechanism: &str,
    scope: &str,
    user_sid: Option<&str>,
    source_hive: &str,
    source_root: &str,
    base_path: &str,
    names: &[&str],
    warnings: &mut Vec<String>,
) -> Vec<RegistryAutorun> {
    let base = match hive.open_key(base_path) {
        Ok(Some(base)) => base,
        Ok(None) => return Vec::new(),
        Err(error) => {
            warnings.push(format!("无法打开 autorun 根键 {base_path}：{error:#}"));
            return Vec::new();
        }
    };
    let subkeys = best_effort_subkeys(hive, &base, base_path, warnings);
    let mut output = Vec::new();
    for key in subkeys {
        let values = match hive.values(&key) {
            Ok(values) => values,
            Err(error) => {
                warnings.push(format!(
                    "autorun 键 {base_path}\\{} 的值列表恢复失败：{error:#}",
                    key.name
                ));
                continue;
            }
        };
        for value in values {
            if !names
                .iter()
                .any(|name| value.name.eq_ignore_ascii_case(name))
            {
                continue;
            }
            for command in registry_value_commands(&value) {
                if command.trim().is_empty() {
                    continue;
                }
                output.push(RegistryAutorun {
                    mechanism: mechanism.to_owned(),
                    scope: scope.to_owned(),
                    user_sid: user_sid.map(str::to_owned),
                    key_path: format!("{base_path}\\{}", key.name),
                    name: format!("{}:{}", key.name, value.name),
                    command,
                    enabled: None,
                    source_hive: source_hive.to_owned(),
                    source_root: source_root.to_owned(),
                    key_last_write_raw: key.last_write_raw,
                    key_last_write: filetime_to_rfc3339(key.last_write_raw),
                });
            }
        }
    }
    output
}

fn registry_value_commands(value: &RegistryValue) -> Vec<String> {
    match &value.data {
        RegistryValueData::String(command) => vec![command.trim().to_owned()],
        RegistryValueData::MultiString(commands) => commands
            .iter()
            .map(|command| command.trim())
            .filter(|command| !command.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn user_sid_from_root(root: &str) -> Option<String> {
    let prefix = "\\REGISTRY\\USER\\";
    let suffix = root.get(prefix.len()..).filter(|_| {
        root.get(..prefix.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
    })?;
    let sid = suffix.split('\\').next()?;
    let sid = sid
        .get(..sid.len().saturating_sub("_Classes".len()))
        .filter(|_| sid.to_ascii_lowercase().ends_with("_classes"))
        .unwrap_or(sid);
    (sid.to_ascii_uppercase().starts_with("S-1-5-") && !sid.is_empty()).then(|| sid.to_owned())
}

fn parse_scheduled_tasks(
    hive: &RegistryHive,
    warnings: &mut Vec<String>,
) -> Vec<RegistryScheduledTask> {
    const TREE: &str = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree";
    const TASKS: &str = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks";
    let mut output = Vec::new();
    match hive.open_key(TREE) {
        Ok(Some(root)) => {
            for child in best_effort_subkeys(hive, &root, "TaskCache Tree", warnings) {
                walk_task_tree(hive, &child, "", 0, &mut output, warnings);
            }
        }
        Ok(None) => {}
        Err(error) => warnings.push(format!("无法打开 TaskCache Tree：{error:#}")),
    }

    let tree_ids = output
        .iter()
        .filter_map(|task| task.task_id.as_deref())
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    match hive.open_key(TASKS) {
        Ok(Some(root)) => {
            for task_key in best_effort_subkeys(hive, &root, "TaskCache Tasks", warnings) {
                let task_id = task_key.name.clone();
                if tree_ids.contains(&task_id.to_ascii_lowercase()) {
                    continue;
                }
                let artifacts = task_binary_artifacts(
                    hive,
                    Some(&task_key),
                    warnings,
                    &format!("TaskCache Tasks\\{task_id}"),
                );
                output.push(RegistryScheduledTask {
                    tree_path: format!("\\<orphan>\\{task_id}"),
                    task_id: Some(task_id),
                    uri: value_string_for_key(hive, &task_key, "URI"),
                    author: value_string_for_key(hive, &task_key, "Author"),
                    source: value_string_for_key(hive, &task_key, "Source"),
                    index: None,
                    tree_key_present: false,
                    task_key_present: true,
                    registration_status: "task_only".to_owned(),
                    actions_size: artifacts.actions.as_ref().map(Vec::len),
                    actions_sha256: artifacts.actions.as_deref().map(sha256_hex),
                    action_strings: artifacts.action_strings,
                    triggers_size: artifacts.triggers.as_ref().map(Vec::len),
                    triggers_sha256: artifacts.triggers.as_deref().map(sha256_hex),
                    trigger_strings: artifacts.trigger_strings,
                    action_parse_status: artifacts.action_parse_status,
                    dynamic_info_hex: value_raw_for_key(hive, &task_key, "DynamicInfo")
                        .map(hex::encode_upper),
                    last_write_raw: task_key.last_write_raw,
                    last_write: filetime_to_rfc3339(task_key.last_write_raw),
                });
            }
        }
        Ok(None) if !tree_ids.is_empty() => warnings.push(format!(
            "TaskCache Tree 含 {} 个任务 ID，但 Tasks 根键不存在",
            tree_ids.len()
        )),
        Ok(None) => {}
        Err(error) => warnings.push(format!("无法打开 TaskCache Tasks：{error:#}")),
    }
    output
}

fn walk_task_tree(
    hive: &RegistryHive,
    key: &RegistryKey,
    parent: &str,
    depth: usize,
    output: &mut Vec<RegistryScheduledTask>,
    warnings: &mut Vec<String>,
) {
    if depth > 64 {
        warnings.push(format!("TaskCache 在 {parent} 下的分支超过 64 层，已跳过"));
        return;
    }
    let tree_path = if parent.is_empty() {
        format!("\\{}", key.name)
    } else {
        format!("{parent}\\{}", key.name)
    };
    let task_id = value_string_for_key(hive, key, "Id");
    if task_id.is_some() {
        let task_key_path = format!(
            "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{}",
            task_id.as_deref().unwrap_or_default()
        );
        let task_key = match hive.open_key(&task_key_path) {
            Ok(key) => key,
            Err(error) => {
                warnings.push(format!("无法打开 {task_key_path}：{error:#}"));
                None
            }
        };
        let artifacts = task_binary_artifacts(hive, task_key.as_ref(), warnings, &task_key_path);
        output.push(RegistryScheduledTask {
            tree_path: tree_path.clone(),
            task_id,
            uri: task_key
                .as_ref()
                .and_then(|key| value_string_for_key(hive, key, "URI")),
            author: task_key
                .as_ref()
                .and_then(|key| value_string_for_key(hive, key, "Author")),
            source: task_key
                .as_ref()
                .and_then(|key| value_string_for_key(hive, key, "Source")),
            index: value_u32_for_key(hive, key, "Index"),
            tree_key_present: true,
            task_key_present: task_key.is_some(),
            registration_status: if task_key.is_some() {
                "tree_and_task"
            } else {
                "tree_only"
            }
            .to_owned(),
            actions_size: artifacts.actions.as_ref().map(Vec::len),
            actions_sha256: artifacts.actions.as_deref().map(sha256_hex),
            action_strings: artifacts.action_strings,
            triggers_size: artifacts.triggers.as_ref().map(Vec::len),
            triggers_sha256: artifacts.triggers.as_deref().map(sha256_hex),
            trigger_strings: artifacts.trigger_strings,
            action_parse_status: artifacts.action_parse_status,
            dynamic_info_hex: task_key
                .as_ref()
                .and_then(|key| value_raw_for_key(hive, key, "DynamicInfo"))
                .map(hex::encode_upper),
            last_write_raw: key.last_write_raw,
            last_write: filetime_to_rfc3339(key.last_write_raw),
        });
    }
    for child in best_effort_subkeys(hive, key, &format!("TaskCache {tree_path}"), warnings) {
        walk_task_tree(hive, &child, &tree_path, depth + 1, output, warnings);
    }
}

#[derive(Default)]
struct TaskBinaryArtifacts {
    actions: Option<Vec<u8>>,
    action_strings: Vec<String>,
    triggers: Option<Vec<u8>>,
    trigger_strings: Vec<String>,
    action_parse_status: String,
}

fn task_binary_artifacts(
    hive: &RegistryHive,
    task_key: Option<&RegistryKey>,
    warnings: &mut Vec<String>,
    context: &str,
) -> TaskBinaryArtifacts {
    let Some(task_key) = task_key else {
        return TaskBinaryArtifacts {
            action_parse_status: "task_record_missing".to_owned(),
            ..TaskBinaryArtifacts::default()
        };
    };
    let checked_raw =
        |name: &str, warnings: &mut Vec<String>| match hive.value_by_name(task_key, name) {
            Ok(value) => value.map(|value| value.raw_data().to_vec()),
            Err(error) => {
                warnings.push(format!("{context} 的 {name} 恢复失败：{error:#}"));
                None
            }
        };
    let actions = checked_raw("Actions", warnings);
    let triggers = checked_raw("Triggers", warnings);
    let action_strings = actions
        .as_deref()
        .map(extract_utf16_strings)
        .unwrap_or_default();
    let trigger_strings = triggers
        .as_deref()
        .map(extract_utf16_strings)
        .unwrap_or_default();
    let action_parse_status = if actions.is_none() {
        "actions_unavailable"
    } else if action_strings.is_empty() {
        "opaque_binary"
    } else {
        "utf16_strings_recovered"
    };
    TaskBinaryArtifacts {
        actions,
        action_strings,
        triggers,
        trigger_strings,
        action_parse_status: action_parse_status.to_owned(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn extract_utf16_strings(bytes: &[u8]) -> Vec<String> {
    const MAX_STRINGS: usize = 64;
    const MAX_CHARS: usize = 1024;
    let mut output = Vec::new();
    let mut seen = BTreeSet::new();
    for alignment in 0..=1 {
        if alignment >= bytes.len() {
            continue;
        }
        let mut current = String::new();
        for pair in bytes[alignment..].chunks_exact(2) {
            let word = u16::from_le_bytes([pair[0], pair[1]]);
            let character = char::from_u32(u32::from(word));
            let accepted = character.filter(|character| {
                *character != '\0'
                    && !character.is_control()
                    && *character != char::REPLACEMENT_CHARACTER
            });
            if let Some(character) = accepted
                && current.chars().count() < MAX_CHARS
            {
                current.push(character);
                continue;
            }
            push_utf16_candidate(&mut output, &mut seen, &mut current);
            if output.len() == MAX_STRINGS {
                return output;
            }
        }
        push_utf16_candidate(&mut output, &mut seen, &mut current);
        if output.len() == MAX_STRINGS {
            break;
        }
    }
    output
}

fn push_utf16_candidate(
    output: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
    current: &mut String,
) {
    let value = current.trim().to_owned();
    current.clear();
    if value.chars().count() < 4
        || !value.chars().any(char::is_alphanumeric)
        || !seen.insert(value.to_lowercase())
    {
        return;
    }
    output.push(value);
}

fn usb_control_set_selector(
    hive: &RegistryHive,
    name: &str,
    warnings: &mut Vec<String>,
) -> Option<u32> {
    let Some(select) = usb_open_key(hive, "Select", warnings) else {
        push_usb_registry_warning(
            warnings,
            "SYSTEM Hive 中不存在或无法恢复 Select 键".to_owned(),
        );
        return None;
    };
    let values = usb_values_for_key(hive, &select, "Select", warnings);
    match values
        .iter()
        .find(|value| value.name.eq_ignore_ascii_case(name))
    {
        Some(value) => match value.as_u32() {
            Some(number) if valid_usb_control_set_number(number) => Some(number),
            Some(number) => {
                push_usb_registry_warning(
                    warnings,
                    format!("Select\\{name} 的 ControlSet 编号 {number} 超出 1-999 合理范围"),
                );
                None
            }
            None => {
                push_usb_registry_warning(warnings, format!("Select\\{name} 不是 REG_DWORD"));
                None
            }
        },
        None => {
            push_usb_registry_warning(warnings, format!("SYSTEM Hive 中不存在 Select\\{name}"));
            None
        }
    }
}

fn valid_usb_control_set_number(number: u32) -> bool {
    (1..=999).contains(&number)
}

fn choose_usb_control_set(
    current: Option<u32>,
    default: Option<u32>,
    warnings: &mut Vec<String>,
) -> u32 {
    if let Some(current) = current {
        return current;
    }
    if let Some(default) = default {
        push_usb_registry_warning(
            warnings,
            format!("Select\\Current 不可用；USB 枚举降级使用 Select\\Default={default}"),
        );
        return default;
    }
    push_usb_registry_warning(
        warnings,
        "Select\\Current/Default 均不可用；USB 枚举降级使用 ControlSet001".to_owned(),
    );
    1
}

fn usb_open_key(
    hive: &RegistryHive,
    path: &str,
    warnings: &mut Vec<String>,
) -> Option<RegistryKey> {
    match hive.open_key_best_effort(path) {
        Ok(lookup) => {
            if lookup.key.is_none() {
                for warning in lookup.warnings {
                    push_usb_registry_warning(warnings, format!("注册表路径 {path}：{warning}"));
                }
            }
            lookup.key
        }
        Err(error) => {
            push_usb_registry_warning(warnings, format!("无法打开注册表路径 {path}：{error:#}"));
            None
        }
    }
}

fn usb_values_for_key(
    hive: &RegistryHive,
    key: &RegistryKey,
    context: &str,
    warnings: &mut Vec<String>,
) -> Vec<RegistryValue> {
    match hive.values_best_effort(key) {
        Ok(enumeration) => {
            for warning in enumeration.warnings {
                push_usb_registry_warning(warnings, format!("注册表键 {context}：{warning}"));
            }
            enumeration.values
        }
        Err(error) => {
            push_usb_registry_warning(
                warnings,
                format!("无法读取注册表键 {context} 的值：{error:#}"),
            );
            Vec::new()
        }
    }
}

fn usb_best_effort_subkeys(
    hive: &RegistryHive,
    key: &RegistryKey,
    context: &str,
    warnings: &mut Vec<String>,
) -> Vec<RegistryKey> {
    match hive.subkeys_best_effort(key) {
        Ok(enumeration) => {
            for warning in enumeration.warnings {
                push_usb_registry_warning(warnings, format!("{context}：{warning}"));
            }
            enumeration.keys
        }
        Err(error) => {
            push_usb_registry_warning(warnings, format!("无法枚举 {context}：{error:#}"));
            Vec::new()
        }
    }
}

fn parse_usb_devices(
    hive: &RegistryHive,
    control_set: &str,
    warnings: &mut Vec<String>,
) -> Vec<RegistryUsbDevice> {
    let mut output = Vec::new();
    for branch in ["USBSTOR", "USB"] {
        let path = format!("{control_set}\\Enum\\{branch}");
        let Some(base) = usb_open_key(hive, &path, warnings) else {
            continue;
        };
        let classes = usb_best_effort_subkeys(hive, &base, branch, warnings);
        for class in classes {
            let instances = usb_best_effort_subkeys(
                hive,
                &class,
                &format!("{branch}\\{}", class.name),
                warnings,
            );
            for instance in instances {
                let context = format!("{path}\\{}\\{}", class.name, instance.name);
                let values = usb_values_for_key(hive, &instance, &context, warnings);
                let friendly_name = usb_string_value(&values, "FriendlyName", &context, warnings);
                let device_description =
                    usb_string_value(&values, "DeviceDesc", &context, warnings);
                let manufacturer = usb_string_value(&values, "Mfg", &context, warnings);
                let service = usb_string_value(&values, "Service", &context, warnings);
                let class_guid = usb_string_value(&values, "ClassGUID", &context, warnings);
                let container_id = usb_string_value(&values, "ContainerID", &context, warnings);
                output.push(RegistryUsbDevice {
                    registry_key: instance.clone(),
                    device_type: class.name.clone(),
                    instance_id: instance.name.clone(),
                    friendly_name,
                    device_description,
                    manufacturer,
                    service,
                    class_guid,
                    container_id,
                    last_write_raw: instance.last_write_raw,
                    last_write: filetime_to_rfc3339(instance.last_write_raw),
                });
            }
        }
    }
    output
}

fn usb_string_value(
    values: &[RegistryValue],
    name: &str,
    context: &str,
    warnings: &mut Vec<String>,
) -> Option<String> {
    match values
        .iter()
        .find(|value| value.name.eq_ignore_ascii_case(name))
    {
        Some(value) => match value.as_string() {
            Some(value) => Some(value.to_owned()),
            None => {
                push_usb_registry_warning(
                    warnings,
                    format!("USB 实例键 {context} 的 {name} 不是字符串值"),
                );
                None
            }
        },
        None => None,
    }
}

fn parse_mounted_devices(
    hive: &RegistryHive,
    warnings: &mut Vec<String>,
) -> Vec<RegistryMountedDevice> {
    let Some(key) = usb_open_key(hive, "MountedDevices", warnings) else {
        return Vec::new();
    };
    let values = usb_values_for_key(hive, &key, "MountedDevices", warnings);
    values
        .into_iter()
        .map(|value| {
            let raw = value.raw_data().to_vec();
            RegistryMountedDevice {
                name: value.name,
                decoded_target: decode_probable_utf16(&raw),
                raw_hex: hex::encode_upper(&raw),
            }
        })
        .collect()
}

fn parse_bam(
    hive: &RegistryHive,
    control_set: &str,
    warnings: &mut Vec<String>,
) -> Vec<RegistryBamEntry> {
    let mut output = Vec::new();
    for (source, suffix) in [
        ("bam", "Services\\bam\\State\\UserSettings"),
        ("bam_legacy", "Services\\bam\\UserSettings"),
        ("dam", "Services\\dam\\State\\UserSettings"),
        ("dam_legacy", "Services\\dam\\UserSettings"),
    ] {
        let path = format!("{control_set}\\{suffix}");
        let Some(base) = open_key(hive, &path) else {
            continue;
        };
        let users = best_effort_subkeys(hive, &base, source, warnings);
        for user in users {
            let Ok(values) = hive.values(&user) else {
                continue;
            };
            for value in values.into_iter().filter(|value| !value.name.is_empty()) {
                let raw = value.raw_data().to_vec();
                let timestamp = (raw.len() >= 8)
                    .then(|| u64::from_le_bytes(raw[..8].try_into().expect("length checked")))
                    .filter(|value| *value != 0);
                output.push(RegistryBamEntry {
                    source: source.to_owned(),
                    sid: user.name.clone(),
                    executable: value.name,
                    last_execution_raw: timestamp,
                    last_execution: timestamp.and_then(filetime_to_rfc3339),
                    raw_hex: hex::encode_upper(&raw),
                });
            }
        }
    }
    output
}

fn best_effort_subkeys(
    hive: &RegistryHive,
    key: &RegistryKey,
    context: &str,
    warnings: &mut Vec<String>,
) -> Vec<RegistryKey> {
    match hive.subkeys_best_effort(key) {
        Ok(result) => {
            warnings.extend(
                result
                    .warnings
                    .into_iter()
                    .map(|warning| format!("{context}: {warning}")),
            );
            result.keys
        }
        Err(error) => {
            warnings.push(format!("无法枚举 {context}：{error:#}"));
            Vec::new()
        }
    }
}

fn open_key(hive: &RegistryHive, path: &str) -> Option<RegistryKey> {
    hive.open_key(path).ok().flatten()
}

fn value_string(hive: &RegistryHive, path: &str, name: &str) -> Option<String> {
    hive.query_value(path, name)
        .ok()
        .flatten()
        .and_then(|value| value.as_string().map(str::to_owned))
}

fn value_u32(hive: &RegistryHive, path: &str, name: &str) -> Option<u32> {
    hive.query_value(path, name)
        .ok()
        .flatten()
        .and_then(|value| value.as_u32())
}

fn value_u64(hive: &RegistryHive, path: &str, name: &str) -> Option<u64> {
    hive.query_value(path, name)
        .ok()
        .flatten()
        .and_then(|value| value.as_u64())
}

fn value_raw(hive: &RegistryHive, path: &str, name: &str) -> Option<Vec<u8>> {
    hive.query_value(path, name)
        .ok()
        .flatten()
        .map(|value| value.raw_data().to_vec())
}

fn value_for_key(hive: &RegistryHive, key: &RegistryKey, name: &str) -> Option<RegistryValue> {
    hive.value_by_name(key, name).ok().flatten()
}

fn value_string_for_key(hive: &RegistryHive, key: &RegistryKey, name: &str) -> Option<String> {
    value_for_key(hive, key, name).and_then(|value| value.as_string().map(str::to_owned))
}

fn value_strings_for_key(hive: &RegistryHive, key: &RegistryKey, name: &str) -> Vec<String> {
    let Some(value) = value_for_key(hive, key, name) else {
        return Vec::new();
    };
    match value.data {
        RegistryValueData::String(value) => vec![value],
        RegistryValueData::MultiString(values) => values,
        _ => Vec::new(),
    }
}

fn value_u32_for_key(hive: &RegistryHive, key: &RegistryKey, name: &str) -> Option<u32> {
    value_for_key(hive, key, name).and_then(|value| value.as_u32())
}

fn value_u64_for_key(hive: &RegistryHive, key: &RegistryKey, name: &str) -> Option<u64> {
    value_for_key(hive, key, name).and_then(|value| value.as_u64())
}

fn value_raw_for_key(hive: &RegistryHive, key: &RegistryKey, name: &str) -> Option<Vec<u8>> {
    value_for_key(hive, key, name).map(|value| value.raw_data().to_vec())
}

fn values_as_strings(hive: &RegistryHive, key: &RegistryKey, names: &[&str]) -> Vec<String> {
    let mut output = Vec::new();
    for name in names {
        output.extend(value_strings_for_key(hive, key, name));
    }
    dedup_case_insensitive(&mut output);
    output
}

fn retain_meaningful_network_values(values: &mut Vec<String>) {
    values.retain(|value| {
        let value = value.trim();
        !value.is_empty() && value != "0.0.0.0" && value != "::"
    });
    dedup_case_insensitive(values);
}

fn dedup_case_insensitive(values: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.to_ascii_lowercase()));
}

fn filetime_to_rfc3339(value: u64) -> Option<String> {
    const WINDOWS_TO_UNIX_SECONDS: i128 = 11_644_473_600;
    const TICKS_PER_SECOND: i128 = 10_000_000;
    let unix_ticks = i128::from(value).checked_sub(WINDOWS_TO_UNIX_SECONDS * TICKS_PER_SECOND)?;
    let seconds = i64::try_from(unix_ticks.div_euclid(TICKS_PER_SECOND)).ok()?;
    let nanos = u32::try_from(unix_ticks.rem_euclid(TICKS_PER_SECOND) * 100).ok()?;
    DateTime::<Utc>::from_timestamp(seconds, nanos)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn registry_type_name(value: u32) -> &'static str {
    match value {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

fn read_slice_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_slice_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn rot13(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            'a'..='m' | 'A'..='M' => char::from_u32(character as u32 + 13).unwrap(),
            'n'..='z' | 'N'..='Z' => char::from_u32(character as u32 - 13).unwrap(),
            _ => character,
        })
        .collect()
}

fn push_registry_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 256 {
        warnings.push(warning);
    }
}

fn push_usb_registry_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.iter().any(|existing| existing == &warning) {
        return;
    }
    if warnings.len() < MAX_USB_SOURCE_WARNINGS {
        warnings.push(warning);
    } else if warnings.len() == MAX_USB_SOURCE_WARNINGS {
        warnings.push(format!(
            "SYSTEM USB 来源告警达到 {MAX_USB_SOURCE_WARNINGS} 条；其余告警已抑制"
        ));
    }
}

fn unix_seconds_to_rfc3339(value: u64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(i64::try_from(value).ok()?, 0)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn systemtime_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 16 {
        return None;
    }
    let word = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    let (year, month, day, hour, minute, second, millis) = (
        word(0),
        word(2),
        word(6),
        word(8),
        word(10),
        word(12),
        word(14),
    );
    (year > 0 && (1..=12).contains(&month) && (1..=31).contains(&day)).then(|| {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}")
    })
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn decode_probable_utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let words = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|word| *word != 0)
        .collect::<Vec<_>>();
    let printable = words
        .iter()
        .filter(|word| char::from_u32(u32::from(**word)).is_some_and(|value| !value.is_control()))
        .count();
    (printable * 4 >= words.len().saturating_mul(3) && !words.is_empty())
        .then(|| String::from_utf16_lossy(&words))
}

#[cfg(test)]
#[path = "registry_artifact_tests.rs"]
pub(crate) mod artifact_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_hive_mapping_uses_full_process_dtb_and_rejects_flag_only_values() {
        use crate::windows::{ProcessDetails, ProcessListStopReason, ProcessRecord};
        let mut processes = ProcessListReport {
            processes: vec![ProcessRecord {
                eprocess: 0xffff_8000_0000_1000,
                pid: 108,
                ppid: Some(4),
                name: "Registry".to_owned(),
                details: ProcessDetails {
                    directory_table_base: Some(0x4e1002),
                    user_directory_table_base: Some(1),
                    ..Default::default()
                },
            }],
            complete: true,
            stop_reason: ProcessListStopReason::ListHead,
            warnings: Vec::new(),
        };
        assert_eq!(registry_process_dtb(&processes), Some(0x4e1002));
        processes.processes[0].details.user_directory_table_base = Some(0x8001);
        assert_eq!(registry_process_dtb(&processes), Some(0x4e1002));
        processes.processes[0].details.directory_table_base = Some(0);
        assert_eq!(registry_process_dtb(&processes), Some(0x8001));
        processes.processes[0].details.user_directory_table_base = Some(1);
        assert_eq!(registry_process_dtb(&processes), None);
        processes.processes[0].details.directory_table_base = Some(0x4e1002);
        processes.processes[0].ppid = Some(88);
        assert_eq!(registry_process_dtb(&processes), None);
    }

    #[test]
    fn converts_real_hacker_registry_timestamps() {
        assert_eq!(
            filetime_to_rfc3339(134_252_414_377_337_294).as_deref(),
            Some("2026-06-06T17:43:57.733Z")
        );
        assert_eq!(
            unix_seconds_to_rfc3339(1_780_757_374).as_deref(),
            Some("2026-06-06T14:49:34Z")
        );
    }

    #[test]
    fn decodes_network_list_systemtime() {
        let words = [2026u16, 6, 0, 7, 1, 44, 11, 832];
        let bytes = words
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            systemtime_to_string(&bytes).as_deref(),
            Some("2026-06-07T01:44:11.832")
        );
    }

    #[test]
    fn scores_hive_names_without_dropping_unnamed_candidates() {
        let target = "\\REGISTRY\\MACHINE\\SAM";
        assert_eq!(hive_target_score(None, None, Some(target), target), 100);
        assert_eq!(
            hive_target_score(
                Some("\\SystemRoot\\System32\\Config\\SAM"),
                None,
                None,
                target
            ),
            80
        );
        assert_eq!(hive_target_score(None, None, None, target), 1);
        assert_eq!(
            hive_target_score(
                Some("\\SystemRoot\\System32\\Config\\SYSTEM"),
                None,
                None,
                target
            ),
            1
        );
    }

    #[test]
    fn system_recovery_status_is_bound_to_the_selected_cmhive() {
        let status = |cmhive, root_path: &str, parsed, complete| RegistryHiveStatus {
            cmhive,
            cmhive_hex: format!("{cmhive:#x}"),
            file_path: String::new(),
            user_name: String::new(),
            root_path: root_path.to_owned(),
            recovery_attempted: true,
            parsed,
            complete,
            logical_size: None,
            recovered_bytes: None,
            missing_bytes: None,
            warnings: Vec::new(),
            error: None,
        };
        let hives = vec![
            status(0x1000, "\\REGISTRY\\MACHINE\\SYSTEM", false, Some(false)),
            status(0x2000, "\\registry\\machine\\system", true, Some(true)),
            status(0x3000, "\\REGISTRY\\MACHINE\\SOFTWARE", true, Some(true)),
        ];

        assert_eq!(exact_system_hive_count(&hives), 2);
        let selected = exact_system_hive_status(&hives, 0x2000).unwrap();
        assert_eq!(selected.cmhive, 0x2000);
        assert!(selected.parsed);
        assert_eq!(selected.complete, Some(true));
        assert!(exact_system_hive_status(&hives, 0x3000).is_none());
    }

    #[test]
    fn usb_control_set_fallback_is_bounded_and_explicit() {
        assert!(!valid_usb_control_set_number(0));
        assert!(valid_usb_control_set_number(1));
        assert!(valid_usb_control_set_number(999));
        assert!(!valid_usb_control_set_number(1000));

        let mut warnings = Vec::new();
        assert_eq!(choose_usb_control_set(Some(2), Some(3), &mut warnings), 2);
        assert!(warnings.is_empty());

        assert_eq!(choose_usb_control_set(None, Some(3), &mut warnings), 3);
        assert!(warnings.last().unwrap().contains("Select\\Default=3"));

        assert_eq!(choose_usb_control_set(None, None, &mut warnings), 1);
        assert!(warnings.last().unwrap().contains("ControlSet001"));
    }

    #[test]
    fn exact_ntuser_recovery_never_falls_back_after_target_corruption() {
        let target_root = "\\Registry\\User\\S-1-5-21-1-2-3-1001";
        let other_root = "\\Registry\\User\\S-1-5-21-1-2-3-1002";
        let hives = vec![
            HiveRecord {
                cmhive: 0x1000,
                file_path: "\\??\\C:\\Users\\alice\\NTUSER.DAT".to_owned(),
                user_name: "\\??\\C:\\Users\\alice\\NTUSER.DAT".to_owned(),
                root_path: target_root.to_owned(),
            },
            HiveRecord {
                cmhive: 0x2000,
                file_path: "\\??\\C:\\Users\\bob\\NTUSER.DAT".to_owned(),
                user_name: "\\??\\C:\\Users\\bob\\NTUSER.DAT".to_owned(),
                root_path: other_root.to_owned(),
            },
        ];
        let mut attempted = Vec::new();

        let result =
            recover_exact_loaded_candidate_with(&hives, 0x1000, target_root, |candidate| {
                attempted.push(candidate.cmhive);
                Err::<(), _>("目标 NTUSER.DAT 损坏".to_owned())
            });

        assert!(result.is_err());
        assert_eq!(attempted, vec![0x1000]);
        assert!(!attempted.contains(&0x2000));
    }

    #[test]
    fn exact_ntuser_recovery_requires_the_same_mounted_root() {
        let hives = vec![HiveRecord {
            cmhive: 0x1000,
            file_path: "\\??\\C:\\Users\\alice\\NTUSER.DAT".to_owned(),
            user_name: "\\??\\C:\\Users\\alice\\NTUSER.DAT".to_owned(),
            root_path: "\\Registry\\User\\S-1-5-21-1-2-3-1001".to_owned(),
        }];
        let mut attempted = false;

        let result = recover_exact_loaded_candidate_with(
            &hives,
            0x1000,
            "\\Registry\\User\\S-1-5-21-1-2-3-1002",
            |_| {
                attempted = true;
                Ok(())
            },
        );

        assert!(result.is_err());
        assert!(!attempted);
        assert!(result.unwrap_err().contains("未尝试其他 Hive"));
    }

    #[test]
    fn extracts_user_sid_from_ntuser_root_case_insensitively() {
        assert_eq!(
            user_sid_from_root("\\registry\\user\\S-1-5-21-1-2-3-1001_classes").as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert_eq!(user_sid_from_root("\\REGISTRY\\MACHINE\\SOFTWARE"), None);
    }

    #[test]
    fn carves_bounded_utf16_task_strings() {
        let mut bytes = vec![0x01, 0x00, 0x02, 0x00, 0x00, 0x00];
        bytes.extend(
            r"C:\Windows\System32\cmd.exe"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        bytes.extend([0, 0]);
        let strings = extract_utf16_strings(&bytes);
        assert!(
            strings
                .iter()
                .any(|value| value == r"C:\Windows\System32\cmd.exe")
        );
    }
}
