use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use chrono::{DateTime, Datelike, FixedOffset, Utc};
use serde::Serialize;

use crate::registry::{RegistryHive, RegistryKey};
use crate::system::registry::{RegistryMountedDevice, RegistrySystemInfo, RegistryUsbDevice};

const DEVICE_PROPERTY_TIMESTAMPS_GUID: &str = "{83da6326-97a6-4088-9453-a1923f573b29}";
const WINDOWS_TO_UNIX_SECONDS: i128 = 11_644_473_600;
const FILETIME_TICKS_PER_SECOND: i128 = 10_000_000;
const MAX_PROPERTY_NODES_PER_INTERFACE: usize = 256;
pub const USB_HISTORY_WARNING_LIMIT: usize = 512;

#[derive(Debug, Clone)]
pub struct UsbHistoryOptions {
    pub serial: Option<String>,
    pub container_id: Option<String>,
    pub storage_only: bool,
    pub allow_last_write_proxy: bool,
    pub limit: usize,
}

impl Default for UsbHistoryOptions {
    fn default() -> Self {
        Self {
            serial: None,
            container_id: None,
            storage_only: true,
            allow_last_write_proxy: true,
            limit: 65_536,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UsbHistoryReport {
    pub records: Vec<UsbHistoryDevice>,
    pub interfaces_examined: usize,
    pub devices_detected: usize,
    pub properties_recovered: usize,
    pub property_interfaces_scanned: usize,
    pub property_nodes_examined: usize,
    pub property_scan_scope: String,
    pub property_node_limit_per_interface: usize,
    pub property_scan_truncated: bool,
    pub output_truncated: bool,
    pub warnings_truncated: bool,
    pub available: bool,
    pub complete: bool,
    pub registry_source_complete: bool,
    pub registry_system_cmhive: Option<String>,
    pub control_set_used: Option<u32>,
    pub property_source_available: bool,
    pub timezone: UsbTimeZoneContext,
    pub filters: UsbHistoryFilterSummary,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsbTimeZoneContext {
    pub windows_key_name: Option<String>,
    pub utc_offset: Option<String>,
    pub offset_basis: String,
    pub conversion_note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsbHistoryFilterSummary {
    pub serial: Option<String>,
    pub container_id: Option<String>,
    pub storage_only: bool,
    pub allow_last_write_proxy: bool,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsbHistoryDevice {
    pub group_key: String,
    pub container_id: Option<String>,
    pub serial: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub revision: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub storage_device: bool,
    pub interfaces: Vec<UsbHistoryInterface>,
    pub install_date: Option<UsbForensicTimestamp>,
    pub first_install_date: Option<UsbForensicTimestamp>,
    pub last_arrival_date: Option<UsbForensicTimestamp>,
    pub last_removal_date: Option<UsbForensicTimestamp>,
    pub selected_last_connected: Option<UsbSelectedTimestamp>,
    pub mounted_devices: Vec<UsbMountedDeviceEvidence>,
    pub mounted_device_hints: Vec<UsbMountedDeviceEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsbHistoryInterface {
    #[serde(skip)]
    pub(crate) registry_key: RegistryKey,
    /// Hive-relative key-cell index retained for raw-object correlation.
    pub registry_cell_index: u32,
    pub role: UsbInterfaceRole,
    pub enum_branch: String,
    pub registry_path: String,
    pub device_type: String,
    pub instance_id: String,
    pub decoded_serial: Option<String>,
    pub friendly_name: Option<String>,
    pub device_description: Option<String>,
    pub manufacturer: Option<String>,
    pub service: Option<String>,
    pub class_guid: Option<String>,
    pub container_id: Option<String>,
    pub key_last_write: UsbForensicTimestamp,
    pub properties: UsbDevicePropertyTimes,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UsbDevicePropertyTimes {
    pub install_date: Option<UsbForensicTimestamp>,
    pub first_install_date: Option<UsbForensicTimestamp>,
    pub last_arrival_date: Option<UsbForensicTimestamp>,
    pub last_removal_date: Option<UsbForensicTimestamp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsbForensicTimestamp {
    pub raw_value: u64,
    pub raw_format: String,
    pub utc: Option<String>,
    pub image_local: Option<String>,
    pub utc_offset: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsbSelectedTimestamp {
    pub timestamp: UsbForensicTimestamp,
    pub semantic: UsbLastConnectedSemantic,
    pub proxy: bool,
    pub confidence: UsbEvidenceConfidence,
    pub interface_role: UsbInterfaceRole,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsbMountedDeviceEvidence {
    pub name: String,
    pub decoded_target: Option<String>,
    pub raw_hex: String,
    pub match_basis: String,
    pub match_kind: String,
    pub confidence: UsbEvidenceConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbInterfaceRole {
    PrimaryStorage,
    UsbBusParent,
    AuxiliarySes,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbLastConnectedSemantic {
    LastArrivalDate,
    PrimaryStorageInstanceKeyLastWriteProxy,
    UsbBusParentInstanceKeyLastWriteProxy,
    AuxiliaryInterfaceLastArrivalDate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbEvidenceConfidence {
    High,
    Medium,
    Low,
}

/// Build USB history from the already recovered registry report and, when
/// available, the exact parsed SYSTEM hive used to create that report.
///
/// Passing the hive enables DEVPKEY timestamp parsing without performing a
/// second memory-Hive recovery. Callers that only have `RegistrySystemInfo`
/// still receive interface grouping and the explicitly marked primary-Disk
/// LastWrite fallback.
pub fn analyze_usb_history(
    registry: &RegistrySystemInfo,
    system_hive: Option<&RegistryHive>,
    options: &UsbHistoryOptions,
) -> Result<UsbHistoryReport> {
    ensure!(
        options.limit > 0,
        "USB history result limit must be greater than zero"
    );
    if let Some(serial) = options.serial.as_deref() {
        ensure!(
            normalize_identity(serial).is_some(),
            "USB serial filter must contain a non-empty identifier"
        );
    }
    if let Some(container_id) = options.container_id.as_deref() {
        ensure!(
            usable_container_id(Some(container_id)).is_some(),
            "USB ContainerID filter must be a valid, usable GUID"
        );
    }

    let control_set_used = registry
        .usb_control_set_used
        .or(registry.current_control_set);
    let current_control_set = control_set_used.unwrap_or(1);
    let control_set = format!("ControlSet{current_control_set:03}");
    let utc_offset_minutes = registry
        .timezone
        .active_bias_minutes
        .or(registry.timezone.bias_minutes)
        .and_then(i32::checked_neg)
        .filter(|offset| offset.unsigned_abs() <= 24 * 60);
    let mut warnings = Vec::new();
    for warning in &registry.usb_source_warnings {
        push_usb_warning(&mut warnings, format!("注册表来源：{warning}"));
    }
    let mut properties_recovered = 0usize;
    let mut property_interfaces_scanned = 0usize;
    let mut property_nodes_examined = 0usize;
    let mut property_scan_truncated = false;
    let mut interfaces = Vec::with_capacity(registry.usb_devices.len());

    for device in &registry.usb_devices {
        let role = classify_interface(device);
        let enum_branch = infer_enum_branch(device).to_owned();
        let registry_path = format!(
            "{control_set}\\Enum\\{enum_branch}\\{}\\{}",
            device.device_type, device.instance_id
        );
        let key_last_write = forensic_filetime(
            device.last_write_raw,
            format!("SYSTEM\\{registry_path}（实例键 LastWrite）"),
            utc_offset_minutes,
        );
        interfaces.push(UsbHistoryInterface {
            registry_key: device.registry_key.clone(),
            registry_cell_index: device.registry_key.cell_index,
            role,
            enum_branch,
            registry_path: registry_path.clone(),
            device_type: device.device_type.clone(),
            instance_id: device.instance_id.clone(),
            decoded_serial: decode_instance_serial(&device.instance_id),
            friendly_name: device.friendly_name.clone(),
            device_description: device.device_description.clone(),
            manufacturer: device.manufacturer.clone(),
            service: device.service.clone(),
            class_guid: device.class_guid.clone(),
            container_id: device.container_id.clone(),
            key_last_write,
            properties: UsbDevicePropertyTimes::default(),
        });
    }

    if system_hive.is_none() {
        push_usb_warning(&mut warnings,
            "未提供已解析的 SYSTEM Hive；未检查 InstallDate、FirstInstallDate、LastArrivalDate 和 LastRemovalDate，仍可使用明确标注的主磁盘实例键 LastWrite 代理"
                .to_owned(),
        );
    }

    let interfaces_examined = interfaces.len();
    let mut grouped = BTreeMap::<String, Vec<UsbHistoryInterface>>::new();
    for interface in interfaces {
        grouped
            .entry(interface_group_key(&interface))
            .or_default()
            .push(interface);
    }
    let devices_detected = grouped.len();
    let serial_filter = options.serial.as_deref().and_then(normalize_identity);
    let container_filter = options
        .container_id
        .as_deref()
        .and_then(normalize_container_id);
    let mut records = Vec::new();
    let mut truncated = false;

    for (group_key, mut group_interfaces) in grouped {
        group_interfaces.sort_by_key(|interface| {
            (
                interface_role_priority(interface.role),
                Reverse(interface.key_last_write.raw_value),
                interface.registry_path.to_ascii_lowercase(),
            )
        });
        let storage_device = group_interfaces
            .iter()
            .any(|interface| interface.role != UsbInterfaceRole::Other);
        if options.storage_only && !storage_device {
            continue;
        }

        let serial = preferred_serial(&group_interfaces);
        let container_id = group_interfaces
            .iter()
            .find_map(|interface| usable_container_id(interface.container_id.as_deref()))
            .map(str::to_owned);
        if let Some(filter) = serial_filter.as_deref()
            && !group_matches_serial(&group_interfaces, serial.as_deref(), filter)
        {
            continue;
        }
        if let Some(filter) = container_filter.as_deref()
            && container_id
                .as_deref()
                .and_then(normalize_container_id)
                .as_deref()
                != Some(filter)
        {
            continue;
        }
        if records.len() == options.limit {
            truncated = true;
            break;
        }

        for interface in &mut group_interfaces {
            if interface.key_last_write.utc.is_none() {
                push_usb_warning(
                    &mut warnings,
                    format!(
                        "USB 实例键 {} 的 LastWrite {:#x} 超出 1980-2100 合理范围",
                        interface.registry_path, interface.key_last_write.raw_value
                    ),
                );
            }
            if let Some(hive) = system_hive {
                property_interfaces_scanned += 1;
                let (parsed, scan) = parse_device_property_times(
                    hive,
                    &interface.registry_key,
                    &interface.registry_path,
                    utc_offset_minutes,
                    &mut warnings,
                );
                properties_recovered += property_count(&parsed);
                property_nodes_examined =
                    property_nodes_examined.saturating_add(scan.nodes_examined);
                property_scan_truncated |= scan.truncated;
                interface.properties = parsed;
            }
        }

        let preferred = preferred_interface(&group_interfaces);
        let install_date = select_property_timestamp(&group_interfaces, PropertyKind::Install);
        let first_install_date =
            select_property_timestamp(&group_interfaces, PropertyKind::FirstInstall);
        let last_arrival_date =
            select_property_timestamp(&group_interfaces, PropertyKind::LastArrival);
        let last_removal_date =
            select_property_timestamp(&group_interfaces, PropertyKind::LastRemoval);
        let selected_last_connected =
            select_last_connected(&group_interfaces, options.allow_last_write_proxy);
        let (mounted_devices, mounted_device_hints) = associate_mounted_devices(
            &registry.mounted_devices,
            &group_interfaces,
            serial.as_deref(),
        );
        let (vendor, product, revision) = preferred
            .map(|interface| parse_usb_storage_identity(&interface.device_type))
            .unwrap_or_default();
        records.push(UsbHistoryDevice {
            group_key,
            container_id,
            serial,
            vendor,
            product,
            revision,
            friendly_name: preferred.and_then(|interface| interface.friendly_name.clone()),
            manufacturer: preferred.and_then(|interface| interface.manufacturer.clone()),
            storage_device,
            interfaces: group_interfaces,
            install_date,
            first_install_date,
            last_arrival_date,
            last_removal_date,
            selected_last_connected,
            mounted_devices,
            mounted_device_hints,
        });
    }

    if truncated {
        push_usb_warning(
            &mut warnings,
            format!("USB history result limit {} reached", options.limit),
        );
    }
    let system_source_available = system_hive.is_some()
        || !registry.usb_devices.is_empty()
        || registry.hives.iter().any(|status| {
            status
                .root_path
                .eq_ignore_ascii_case("\\REGISTRY\\MACHINE\\SYSTEM")
                && status.parsed
        });
    let complete = !truncated
        && !property_scan_truncated
        && system_hive.is_some()
        && registry.usb_source_complete
        && warnings.is_empty();
    let warnings_truncated = warnings.len() > USB_HISTORY_WARNING_LIMIT;

    Ok(UsbHistoryReport {
        records,
        interfaces_examined,
        devices_detected,
        properties_recovered,
        property_interfaces_scanned,
        property_nodes_examined,
        property_scan_scope: "returned_filtered_groups_only".to_owned(),
        property_node_limit_per_interface: MAX_PROPERTY_NODES_PER_INTERFACE,
        property_scan_truncated,
        output_truncated: truncated,
        warnings_truncated,
        available: system_source_available,
        complete,
        registry_source_complete: registry.usb_source_complete,
        registry_system_cmhive: registry
            .usb_system_cmhive
            .map(|cmhive| format!("{cmhive:#018x}")),
        control_set_used,
        property_source_available: system_hive.is_some(),
        timezone: UsbTimeZoneContext {
            windows_key_name: registry.timezone.key_name.clone(),
            utc_offset: utc_offset_minutes.map(format_utc_offset),
            offset_basis: match (
                utc_offset_minutes,
                registry.timezone.active_bias_minutes,
                registry.timezone.bias_minutes,
            ) {
                (Some(_), Some(_), _) => "snapshot_active_time_bias_fixed_offset",
                (Some(_), None, Some(_)) => "snapshot_standard_bias_fixed_offset",
                (Some(_), None, None) => "derived_fixed_offset",
                (None, Some(_), _) | (None, None, Some(_)) => "snapshot_bias_out_of_range",
                (None, None, None) => "snapshot_bias_unavailable",
            }
            .to_owned(),
            conversion_note: if utc_offset_minutes.is_some() {
                "本地时间使用镜像采集时的固定偏移换算；UTC/raw 是权威值，跨夏令时边界时请以 UTC 为准"
            } else {
                "未使用分析主机时区；镜像偏移不可用，因此不生成本地时间"
            }
            .to_owned(),
        },
        filters: UsbHistoryFilterSummary {
            serial: options.serial.clone(),
            container_id: options.container_id.clone(),
            storage_only: options.storage_only,
            allow_last_write_proxy: options.allow_last_write_proxy,
            limit: options.limit,
        },
        warnings,
    })
}

#[derive(Debug, Default)]
struct PropertyScanBudget {
    nodes_examined: usize,
    truncated: bool,
}

fn parse_device_property_times(
    hive: &RegistryHive,
    instance_key: &RegistryKey,
    instance_path: &str,
    utc_offset_minutes: Option<i32>,
    warnings: &mut Vec<String>,
) -> (UsbDevicePropertyTimes, PropertyScanBudget) {
    let mut scan = PropertyScanBudget::default();
    let relative_base = format!("Properties\\{DEVICE_PROPERTY_TIMESTAMPS_GUID}");
    let base = format!("{instance_path}\\{relative_base}");
    let property_keys = match hive.open_subkey_best_effort(instance_key, &relative_base) {
        Ok(lookup) => {
            for warning in lookup.warnings {
                push_usb_warning(warnings, format!("USB 设备属性 {base}：{warning}"));
            }
            match lookup.key {
                Some(key) => match hive.subkeys_best_effort(&key) {
                    Ok(enumeration) => {
                        for warning in enumeration.warnings {
                            push_usb_warning(warnings, format!("USB 设备属性 {base}：{warning}"));
                        }
                        enumeration.keys
                    }
                    Err(error) => {
                        push_usb_warning(
                            warnings,
                            format!("无法枚举 USB 设备属性 {base}：{error:#}"),
                        );
                        Vec::new()
                    }
                },
                None => Vec::new(),
            }
        }
        Err(error) => {
            push_usb_warning(warnings, format!("无法打开 USB 设备属性 {base}：{error:#}"));
            Vec::new()
        }
    };
    let properties = UsbDevicePropertyTimes {
        install_date: read_device_property_filetime(
            hive,
            &base,
            &property_keys,
            0x64,
            utc_offset_minutes,
            warnings,
            &mut scan,
        ),
        first_install_date: read_device_property_filetime(
            hive,
            &base,
            &property_keys,
            0x65,
            utc_offset_minutes,
            warnings,
            &mut scan,
        ),
        last_arrival_date: read_device_property_filetime(
            hive,
            &base,
            &property_keys,
            0x66,
            utc_offset_minutes,
            warnings,
            &mut scan,
        ),
        last_removal_date: read_device_property_filetime(
            hive,
            &base,
            &property_keys,
            0x67,
            utc_offset_minutes,
            warnings,
            &mut scan,
        ),
    };
    (properties, scan)
}

fn read_device_property_filetime(
    hive: &RegistryHive,
    base: &str,
    property_keys: &[RegistryKey],
    property_id: u32,
    utc_offset_minutes: Option<i32>,
    warnings: &mut Vec<String>,
    scan: &mut PropertyScanBudget,
) -> Option<UsbForensicTimestamp> {
    let candidates = [
        format!("{property_id:08X}"),
        format!("{property_id:04X}"),
        format!("{property_id:X}"),
    ];
    for name in candidates {
        let path = format!("{base}\\{name}");
        let Some(key) = property_keys
            .iter()
            .find(|key| key.name.eq_ignore_ascii_case(&name))
            .cloned()
        else {
            continue;
        };
        let mut found = Vec::new();
        collect_property_filetimes(hive, key, path, 0, &mut found, warnings, scan);
        found.sort_by_key(|candidate| (candidate.key_last_write_raw, candidate.raw_value));
        if let Some(candidate) = found.pop() {
            return Some(forensic_filetime(
                candidate.raw_value,
                format!("SYSTEM\\{}\\Data", candidate.path),
                utc_offset_minutes,
            ));
        }
    }
    None
}

#[derive(Debug)]
struct PropertyFiletimeCandidate {
    raw_value: u64,
    key_last_write_raw: u64,
    path: String,
}

fn collect_property_filetimes(
    hive: &RegistryHive,
    key: RegistryKey,
    path: String,
    depth: usize,
    output: &mut Vec<PropertyFiletimeCandidate>,
    warnings: &mut Vec<String>,
    scan: &mut PropertyScanBudget,
) {
    if scan.nodes_examined == MAX_PROPERTY_NODES_PER_INTERFACE {
        if !scan.truncated {
            push_usb_warning(
                warnings,
                format!(
                    "USB 设备属性 {path} 扫描达到每接口 {MAX_PROPERTY_NODES_PER_INTERFACE} 个节点的安全上限"
                ),
            );
            scan.truncated = true;
        }
        return;
    }
    scan.nodes_examined += 1;
    if depth > 4 {
        push_usb_warning(warnings, format!("USB 设备属性 {path} 子键深度超过限制"));
        return;
    }
    let values = match hive.values_best_effort(&key) {
        Ok(enumeration) => {
            for warning in enumeration.warnings {
                push_usb_warning(warnings, format!("USB 设备属性 {path}：{warning}"));
            }
            enumeration.values
        }
        Err(error) => {
            push_usb_warning(
                warnings,
                format!("无法读取 USB 设备属性 {path} 的值列表：{error:#}"),
            );
            Vec::new()
        }
    };
    let value_named = |name: &str| {
        values
            .iter()
            .find(|value| value.name.eq_ignore_ascii_case(name))
    };
    let type_is_filetime = match value_named("Type") {
        Some(value) if value.raw_data().len() >= 4 => {
            u32::from_le_bytes(value.raw_data()[..4].try_into().expect("length checked")) == 0x10
        }
        Some(_) => {
            push_usb_warning(warnings, format!("USB 设备属性 {path} 的 Type 值被截断"));
            false
        }
        None => true,
    };
    match value_named("Data") {
        Some(_) if !type_is_filetime => push_usb_warning(
            warnings,
            format!("USB 设备属性 {path} 的 Type 不是 DEVPROP_TYPE_FILETIME (0x10)"),
        ),
        Some(value) => match decode_property_filetime(value.raw_data()) {
            Some(raw_value) => output.push(PropertyFiletimeCandidate {
                raw_value,
                key_last_write_raw: key.last_write_raw,
                path: path.clone(),
            }),
            None => push_usb_warning(
                warnings,
                format!("USB 设备属性 {path} 的 Data 不是有效的 8 字节 FILETIME"),
            ),
        },
        None => {}
    }
    match hive.subkeys_best_effort(&key) {
        Ok(enumeration) => {
            for warning in enumeration.warnings {
                push_usb_warning(warnings, format!("USB 设备属性 {path}：{warning}"));
            }
            for child in enumeration.keys {
                let child_path = format!("{path}\\{}", child.name);
                collect_property_filetimes(
                    hive,
                    child,
                    child_path,
                    depth + 1,
                    output,
                    warnings,
                    scan,
                );
            }
        }
        Err(error) => {
            push_usb_warning(warnings, format!("无法枚举 USB 设备属性 {path}：{error:#}"))
        }
    }
}

fn decode_property_filetime(bytes: &[u8]) -> Option<u64> {
    let raw = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
    filetime_to_datetime(raw).map(|_| raw)
}

fn property_count(properties: &UsbDevicePropertyTimes) -> usize {
    [
        properties.install_date.as_ref(),
        properties.first_install_date.as_ref(),
        properties.last_arrival_date.as_ref(),
        properties.last_removal_date.as_ref(),
    ]
    .into_iter()
    .flatten()
    .count()
}

fn classify_interface(device: &RegistryUsbDevice) -> UsbInterfaceRole {
    let device_type = device.device_type.to_ascii_lowercase();
    let description = device
        .device_description
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let service = device
        .service
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let class_guid = device
        .class_guid
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();

    if device_type.starts_with("disk&")
        || service == "disk"
        || class_guid == "{4d36e967-e325-11ce-bfc1-08002be10318}"
    {
        UsbInterfaceRole::PrimaryStorage
    } else if device_type.contains("ses_device")
        || device_type.contains("ses&")
        || description.contains("ses device")
    {
        UsbInterfaceRole::AuxiliarySes
    } else if device_type.starts_with("vid_") && service == "usbstor" {
        UsbInterfaceRole::UsbBusParent
    } else {
        UsbInterfaceRole::Other
    }
}

fn infer_enum_branch(device: &RegistryUsbDevice) -> &'static str {
    let kind = device.device_type.to_ascii_lowercase();
    if ["disk&", "cdrom&", "other&", "tape&", "floppy&"]
        .iter()
        .any(|prefix| kind.starts_with(prefix))
    {
        "USBSTOR"
    } else {
        "USB"
    }
}

fn interface_group_key(interface: &UsbHistoryInterface) -> String {
    if let Some(container) = usable_container_id(interface.container_id.as_deref()) {
        let normalized = normalize_container_id(container).expect("usable ContainerID is valid");
        return format!("container:{normalized}");
    }
    if let Some(serial) = interface
        .decoded_serial
        .as_deref()
        .and_then(normalize_identity)
    {
        return format!("serial:{serial}");
    }
    format!("interface:{}", interface.registry_path.to_ascii_lowercase())
}

fn usable_container_id(value: Option<&str>) -> Option<&str> {
    let value = value?.trim();
    let normalized = normalize_container_id(value)?;
    if normalized == "00000000000000000000000000000000"
        || normalized == "0000000000000000ffffffffffffffff"
    {
        return None;
    }
    Some(value)
}

fn normalize_container_id(value: &str) -> Option<String> {
    let value = value.trim();
    let value = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(value);
    let groups = value.split('-').collect::<Vec<_>>();
    if groups.len() != 5
        || groups
            .iter()
            .zip([8usize, 4, 4, 4, 12])
            .any(|(group, length)| {
                group.len() != length || !group.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    {
        return None;
    }
    Some(
        groups
            .into_iter()
            .flat_map(str::chars)
            .flat_map(char::to_lowercase)
            .collect(),
    )
}

fn normalize_identity(value: &str) -> Option<String> {
    let normalized = value
        .trim_matches(|character: char| character.is_whitespace() || character == '\0')
        .chars()
        .filter(|character| !character.is_control())
        .flat_map(char::to_uppercase)
        .collect::<String>();
    (!normalized.is_empty()).then_some(normalized)
}

fn decode_instance_serial(instance_id: &str) -> Option<String> {
    let base = instance_id.split('&').next()?.trim();
    if base.len() < 4 {
        return None;
    }
    if base.len().is_multiple_of(2) && base.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let bytes = (0..base.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&base[index..index + 2], 16).ok())
            .collect::<Option<Vec<_>>>()?;
        if bytes
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
            && bytes.iter().any(u8::is_ascii_alphanumeric)
        {
            let decoded = String::from_utf8(bytes).ok()?.trim().to_owned();
            if decoded.len() >= 4 {
                return Some(decoded);
            }
        }
    }
    Some(base.to_owned())
}

fn preferred_serial(interfaces: &[UsbHistoryInterface]) -> Option<String> {
    interfaces
        .iter()
        .filter_map(|interface| {
            interface
                .decoded_serial
                .as_ref()
                .map(|serial| (interface_role_priority(interface.role), serial))
        })
        .min_by_key(|(priority, _)| *priority)
        .map(|(_, serial)| serial.clone())
}

fn preferred_interface(interfaces: &[UsbHistoryInterface]) -> Option<&UsbHistoryInterface> {
    interfaces
        .iter()
        .min_by_key(|interface| interface_role_priority(interface.role))
}

fn interface_role_priority(role: UsbInterfaceRole) -> u8 {
    match role {
        UsbInterfaceRole::PrimaryStorage => 0,
        UsbInterfaceRole::UsbBusParent => 1,
        UsbInterfaceRole::AuxiliarySes => 2,
        UsbInterfaceRole::Other => 3,
    }
}

fn group_matches_serial(
    interfaces: &[UsbHistoryInterface],
    preferred: Option<&str>,
    filter: &str,
) -> bool {
    preferred.is_some_and(|serial| normalize_identity(serial).as_deref() == Some(filter))
        || interfaces.iter().any(|interface| {
            normalize_identity(&interface.instance_id).as_deref() == Some(filter)
                || interface
                    .decoded_serial
                    .as_deref()
                    .is_some_and(|serial| normalize_identity(serial).as_deref() == Some(filter))
        })
}

#[derive(Debug, Clone, Copy)]
enum PropertyKind {
    Install,
    FirstInstall,
    LastArrival,
    LastRemoval,
}

fn property_for_interface(
    interface: &UsbHistoryInterface,
    kind: PropertyKind,
) -> Option<&UsbForensicTimestamp> {
    match kind {
        PropertyKind::Install => interface.properties.install_date.as_ref(),
        PropertyKind::FirstInstall => interface.properties.first_install_date.as_ref(),
        PropertyKind::LastArrival => interface.properties.last_arrival_date.as_ref(),
        PropertyKind::LastRemoval => interface.properties.last_removal_date.as_ref(),
    }
}

fn select_property_timestamp(
    interfaces: &[UsbHistoryInterface],
    kind: PropertyKind,
) -> Option<UsbForensicTimestamp> {
    interfaces
        .iter()
        .filter_map(|interface| {
            property_for_interface(interface, kind).map(|timestamp| (interface, timestamp))
        })
        .min_by_key(|(interface, timestamp)| {
            (
                interface_role_priority(interface.role),
                Reverse(timestamp.raw_value),
            )
        })
        .map(|(_, timestamp)| timestamp.clone())
}

fn select_last_connected(
    interfaces: &[UsbHistoryInterface],
    allow_last_write_proxy: bool,
) -> Option<UsbSelectedTimestamp> {
    for role in [
        UsbInterfaceRole::PrimaryStorage,
        UsbInterfaceRole::UsbBusParent,
    ] {
        if let Some((_interface, timestamp)) = latest_arrival_for_role(interfaces, role) {
            return Some(UsbSelectedTimestamp {
                timestamp: timestamp.clone(),
                semantic: UsbLastConnectedSemantic::LastArrivalDate,
                proxy: false,
                confidence: UsbEvidenceConfidence::High,
                interface_role: role,
                reason: if role == UsbInterfaceRole::PrimaryStorage {
                    "选择主存储接口的 Windows LastArrivalDate（DEVPKEY PID 0x66）".to_owned()
                } else {
                    "主存储接口没有 LastArrivalDate；选择同容器 USB 总线父接口的 LastArrivalDate（DEVPKEY PID 0x66）"
                        .to_owned()
                },
            });
        }
    }

    if allow_last_write_proxy
        && let Some(interface) =
            latest_interface_for_role(interfaces, UsbInterfaceRole::PrimaryStorage)
    {
        return Some(UsbSelectedTimestamp {
            timestamp: interface.key_last_write.clone(),
            semantic: UsbLastConnectedSemantic::PrimaryStorageInstanceKeyLastWriteProxy,
            proxy: true,
            confidence: UsbEvidenceConfidence::Medium,
            interface_role: UsbInterfaceRole::PrimaryStorage,
            reason: "未恢复 LastArrivalDate；使用主 USBSTOR Disk 实例键 LastWrite 作为连接时间代理，并忽略同容器较晚的 SES 辅助接口配置时间"
                .to_owned(),
        });
    }

    if let Some((_, timestamp)) =
        latest_arrival_for_role(interfaces, UsbInterfaceRole::AuxiliarySes)
    {
        return Some(UsbSelectedTimestamp {
            timestamp: timestamp.clone(),
            semantic: UsbLastConnectedSemantic::AuxiliaryInterfaceLastArrivalDate,
            proxy: false,
            confidence: UsbEvidenceConfidence::Low,
            interface_role: UsbInterfaceRole::AuxiliarySes,
            reason: "仅恢复到 SES 辅助接口的 LastArrivalDate；它不能可靠代表主存储接口连接时间"
                .to_owned(),
        });
    }

    if allow_last_write_proxy
        && let Some(interface) =
            latest_interface_for_role(interfaces, UsbInterfaceRole::UsbBusParent)
    {
        return Some(UsbSelectedTimestamp {
            timestamp: interface.key_last_write.clone(),
            semantic: UsbLastConnectedSemantic::UsbBusParentInstanceKeyLastWriteProxy,
            proxy: true,
            confidence: UsbEvidenceConfidence::Low,
            interface_role: UsbInterfaceRole::UsbBusParent,
            reason: "未恢复主存储接口或 LastArrivalDate；使用 USB 总线父接口键 LastWrite 作为低置信度代理"
                .to_owned(),
        });
    }
    None
}

fn latest_arrival_for_role(
    interfaces: &[UsbHistoryInterface],
    role: UsbInterfaceRole,
) -> Option<(&UsbHistoryInterface, &UsbForensicTimestamp)> {
    interfaces
        .iter()
        .filter(|interface| interface.role == role)
        .filter_map(|interface| {
            interface
                .properties
                .last_arrival_date
                .as_ref()
                .map(|timestamp| (interface, timestamp))
        })
        .max_by_key(|(_, timestamp)| timestamp.raw_value)
}

fn latest_interface_for_role(
    interfaces: &[UsbHistoryInterface],
    role: UsbInterfaceRole,
) -> Option<&UsbHistoryInterface> {
    interfaces
        .iter()
        .filter(|interface| interface.role == role)
        .filter(|interface| interface.key_last_write.utc.is_some())
        .max_by_key(|interface| interface.key_last_write.raw_value)
}

fn associate_mounted_devices(
    mounted_devices: &[RegistryMountedDevice],
    interfaces: &[UsbHistoryInterface],
    serial: Option<&str>,
) -> (Vec<UsbMountedDeviceEvidence>, Vec<UsbMountedDeviceEvidence>) {
    let mut needles = BTreeSet::new();
    if let Some(serial) = serial {
        push_mount_needle(&mut needles, serial);
    }
    for interface in interfaces {
        if let Some(serial) = interface.decoded_serial.as_deref() {
            push_mount_needle(&mut needles, serial);
        }
        if let Some(base) = interface.instance_id.split('&').next()
            && base.len() >= 6
        {
            push_mount_needle(&mut needles, base);
        }
    }
    let mut exact = Vec::new();
    let mut hints = Vec::new();
    for mounted in mounted_devices {
        let decoded = mounted
            .decoded_target
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let raw = hex::decode(&mounted.raw_hex).unwrap_or_default();
        let exact_basis = needles.iter().find_map(|needle| {
            if contains_bounded_text(&decoded, &needle.text) {
                Some(format!("decoded_target identifier equals {}", needle.text))
            } else if contains_bounded_ascii(&raw, needle.text.as_bytes()) {
                Some(format!("raw identifier equals ASCII {}", needle.text))
            } else if contains_bounded_utf16(&raw, &needle.text) {
                Some(format!("raw identifier equals UTF-16LE {}", needle.text))
            } else {
                None
            }
        });
        let heuristic_basis = exact_basis
            .is_none()
            .then(|| {
                let raw_hex = mounted.raw_hex.to_ascii_uppercase();
                needles.iter().find_map(|needle| {
                    if decoded.contains(&needle.text.to_ascii_lowercase()) {
                        Some(format!("decoded_target substring contains {}", needle.text))
                    } else if raw_hex.contains(&needle.ascii_hex) {
                        Some(format!("raw substring contains ASCII {}", needle.text))
                    } else if raw_hex.contains(&needle.utf16_hex) {
                        Some(format!("raw substring contains UTF-16LE {}", needle.text))
                    } else {
                        None
                    }
                })
            })
            .flatten();
        if let Some(match_basis) = exact_basis {
            exact.push(UsbMountedDeviceEvidence {
                name: mounted.name.clone(),
                decoded_target: mounted.decoded_target.clone(),
                raw_hex: mounted.raw_hex.clone(),
                match_basis,
                match_kind: "exact_identifier_component".to_owned(),
                confidence: UsbEvidenceConfidence::High,
            });
        } else if let Some(match_basis) = heuristic_basis {
            hints.push(UsbMountedDeviceEvidence {
                name: mounted.name.clone(),
                decoded_target: mounted.decoded_target.clone(),
                raw_hex: mounted.raw_hex.clone(),
                match_basis,
                match_kind: "substring_hint_not_device_attribution".to_owned(),
                confidence: UsbEvidenceConfidence::Low,
            });
        }
    }
    exact.sort_by(|left, right| left.name.cmp(&right.name));
    hints.sort_by(|left, right| left.name.cmp(&right.name));
    (exact, hints)
}

fn contains_bounded_text(haystack: &str, needle: &str) -> bool {
    let haystack = haystack.to_lowercase();
    let needle = needle.to_lowercase();
    haystack.match_indices(&needle).any(|(start, matched)| {
        let end = start + matched.len();
        haystack[..start]
            .chars()
            .next_back()
            .is_none_or(|character| !character.is_alphanumeric())
            && haystack[end..]
                .chars()
                .next()
                .is_none_or(|character| !character.is_alphanumeric())
    })
}

fn push_usb_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < USB_HISTORY_WARNING_LIMIT {
        warnings.push(warning);
    } else if warnings.len() == USB_HISTORY_WARNING_LIMIT {
        warnings.push(format!(
            "USB history warnings reached {USB_HISTORY_WARNING_LIMIT}; additional warnings were suppressed"
        ));
    }
}

fn contains_bounded_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .any(|(start, value)| {
            value.eq_ignore_ascii_case(needle)
                && start
                    .checked_sub(1)
                    .and_then(|index| haystack.get(index))
                    .is_none_or(|byte| !byte.is_ascii_alphanumeric())
                && haystack
                    .get(start + needle.len())
                    .is_none_or(|byte| !byte.is_ascii_alphanumeric())
        })
}

fn contains_bounded_utf16(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.encode_utf16().collect::<Vec<_>>();
    if needle.is_empty() {
        return false;
    }
    [0usize, 1].into_iter().any(|offset| {
        let units = haystack
            .get(offset..)
            .unwrap_or_default()
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        units
            .windows(needle.len())
            .enumerate()
            .any(|(start, value)| {
                value.iter().zip(&needle).all(|(left, right)| {
                    match (u8::try_from(*left), u8::try_from(*right)) {
                        (Ok(left), Ok(right)) => left.eq_ignore_ascii_case(&right),
                        _ => left == right,
                    }
                }) && start
                    .checked_sub(1)
                    .and_then(|index| units.get(index))
                    .is_none_or(|unit| {
                        !char::from_u32(u32::from(*unit)).is_some_and(char::is_alphanumeric)
                    })
                    && units.get(start + needle.len()).is_none_or(|unit| {
                        !char::from_u32(u32::from(*unit)).is_some_and(char::is_alphanumeric)
                    })
            })
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MountNeedle {
    text: String,
    ascii_hex: String,
    utf16_hex: String,
}

fn push_mount_needle(needles: &mut BTreeSet<MountNeedle>, value: &str) {
    let value = value.trim();
    if value.chars().count() < 6 {
        return;
    }
    needles.insert(MountNeedle {
        text: value.to_owned(),
        ascii_hex: hex::encode_upper(value.as_bytes()),
        utf16_hex: hex::encode_upper(
            value
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        ),
    });
}

fn parse_usb_storage_identity(
    device_type: &str,
) -> (Option<String>, Option<String>, Option<String>) {
    let mut vendor = None;
    let mut product = None;
    let mut revision = None;
    for component in device_type.split('&') {
        let (target, value) = if let Some(value) = strip_prefix_ascii_case(component, "Ven_") {
            (&mut vendor, value)
        } else if let Some(value) = strip_prefix_ascii_case(component, "Prod_") {
            (&mut product, value)
        } else if let Some(value) = strip_prefix_ascii_case(component, "Rev_") {
            (&mut revision, value)
        } else {
            continue;
        };
        let value = value.replace('_', " ").trim().to_owned();
        if !value.is_empty() {
            *target = Some(value);
        }
    }
    (vendor, product, revision)
}

fn strip_prefix_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))?;
    value.get(prefix.len()..)
}

fn forensic_filetime(
    raw_value: u64,
    source: String,
    utc_offset_minutes: Option<i32>,
) -> UsbForensicTimestamp {
    let utc = filetime_to_datetime(raw_value);
    let image_local = utc.and_then(|utc| {
        let minutes = utc_offset_minutes?;
        let offset = FixedOffset::east_opt(minutes.checked_mul(60)?)?;
        Some(format_datetime_exact(
            utc.with_timezone(&offset),
            raw_value,
            false,
        ))
    });
    UsbForensicTimestamp {
        raw_value,
        raw_format: "Windows FILETIME（自 1601-01-01 UTC 起的 100 纳秒数）".to_owned(),
        utc: utc.map(|value| format_datetime_exact(value, raw_value, true)),
        image_local,
        utc_offset: utc_offset_minutes.map(format_utc_offset),
        source,
    }
}

fn filetime_to_datetime(value: u64) -> Option<DateTime<Utc>> {
    let unix_ticks =
        i128::from(value).checked_sub(WINDOWS_TO_UNIX_SECONDS * FILETIME_TICKS_PER_SECOND)?;
    let seconds = i64::try_from(unix_ticks.div_euclid(FILETIME_TICKS_PER_SECOND)).ok()?;
    let nanos = u32::try_from(unix_ticks.rem_euclid(FILETIME_TICKS_PER_SECOND) * 100).ok()?;
    let timestamp = DateTime::<Utc>::from_timestamp(seconds, nanos)?;
    (1980..=2100)
        .contains(&timestamp.year())
        .then_some(timestamp)
}

fn format_datetime_exact<Tz: chrono::TimeZone>(
    value: DateTime<Tz>,
    raw_value: u64,
    utc: bool,
) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let fraction = raw_value % FILETIME_TICKS_PER_SECOND as u64;
    if utc {
        format!("{}.{fraction:07}Z", value.format("%Y-%m-%dT%H:%M:%S"))
    } else {
        format!(
            "{}.{fraction:07}{}",
            value.format("%Y-%m-%dT%H:%M:%S"),
            value.format("%:z")
        )
    }
}

fn format_utc_offset(minutes: i32) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let absolute = minutes.unsigned_abs();
    format!("UTC{sign}{:02}:{:02}", absolute / 60, absolute % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::registry::{RegistryTimeZoneInfo, RegistryUsbDevice};

    const CONTAINER: &str = "{ad409054-19e5-5dd9-ade9-925239576e82}";

    #[test]
    fn groups_container_and_prefers_primary_disk_proxy_over_later_ses() {
        let mut registry = RegistrySystemInfo {
            available: true,
            current_control_set: Some(1),
            timezone: RegistryTimeZoneInfo {
                bias_minutes: Some(-480),
                active_bias_minutes: Some(-480),
                ..RegistryTimeZoneInfo::default()
            },
            ..RegistrySystemInfo::default()
        };
        registry.usb_devices = vec![
            usb_device(
                "Disk&Ven_SanDisk&Prod_Extreme_SSD&Rev_1012",
                "32313131374D343032343132&0",
                Some("disk"),
                133_317_540_861_257_591,
            ),
            usb_device(
                "Other&Ven_SanDisk&Prod_SES_Device&Rev_1012",
                "32313131374D343032343132&1",
                None,
                133_317_541_106_531_620,
            ),
            usb_device(
                "VID_0781&PID_558C",
                "32313131374D343032343132",
                Some("USBSTOR"),
                133_317_540_856_747_333,
            ),
        ];

        let report = analyze_usb_history(&registry, None, &UsbHistoryOptions::default()).unwrap();
        assert_eq!(report.records.len(), 1);
        let device = &report.records[0];
        assert_eq!(device.serial.as_deref(), Some("21117M402412"));
        assert_eq!(device.interfaces.len(), 3);
        assert!(
            device
                .interfaces
                .iter()
                .any(|entry| entry.role == UsbInterfaceRole::AuxiliarySes)
        );
        let selected = device.selected_last_connected.as_ref().unwrap();
        assert_eq!(
            selected.semantic,
            UsbLastConnectedSemantic::PrimaryStorageInstanceKeyLastWriteProxy
        );
        assert!(selected.proxy);
        assert_eq!(selected.confidence, UsbEvidenceConfidence::Medium);
        assert_eq!(selected.timestamp.raw_value, 133_317_540_861_257_591);
        assert_eq!(
            selected.timestamp.image_local.as_deref(),
            Some("2023-06-21T01:01:26.1257591+08:00")
        );
    }

    #[test]
    fn explicit_primary_last_arrival_beats_all_last_write_values() {
        let mut primary =
            history_interface(UsbInterfaceRole::PrimaryStorage, 133_317_540_861_257_591);
        primary.properties.last_arrival_date = Some(forensic_filetime(
            133_317_530_000_000_000,
            "primary LastArrivalDate".to_owned(),
            Some(480),
        ));
        let ses = history_interface(UsbInterfaceRole::AuxiliarySes, 133_317_541_106_531_620);
        let selected = select_last_connected(&[primary, ses], true).unwrap();
        assert_eq!(selected.semantic, UsbLastConnectedSemantic::LastArrivalDate);
        assert!(!selected.proxy);
        assert_eq!(selected.confidence, UsbEvidenceConfidence::High);
        assert_eq!(selected.timestamp.raw_value, 133_317_530_000_000_000);
    }

    #[test]
    fn strict_mode_does_not_turn_key_last_write_into_last_connected() {
        let primary = history_interface(UsbInterfaceRole::PrimaryStorage, 133_317_540_861_257_591);
        assert!(select_last_connected(&[primary], false).is_none());
    }

    #[test]
    fn decodes_property_filetime_and_exact_fraction() {
        let bytes = hex::decode("E0A15FD998A3D901").unwrap();
        let raw = decode_property_filetime(&bytes).unwrap();
        assert_eq!(raw, 133_317_540_861_420_000);
        let timestamp = forensic_filetime(raw, "test".to_owned(), Some(480));
        assert_eq!(
            timestamp.utc.as_deref(),
            Some("2023-06-20T17:01:26.1420000Z")
        );
        assert_eq!(
            timestamp.image_local.as_deref(),
            Some("2023-06-21T01:01:26.1420000+08:00")
        );
    }

    #[test]
    fn filters_by_decoded_serial_and_container() {
        let mut registry = RegistrySystemInfo {
            available: true,
            current_control_set: Some(1),
            ..RegistrySystemInfo::default()
        };
        registry.usb_devices.push(usb_device(
            "Disk&Ven_SanDisk&Prod_Extreme_SSD&Rev_1012",
            "32313131374D343032343132&0",
            Some("disk"),
            133_317_540_861_257_591,
        ));
        let options = UsbHistoryOptions {
            serial: Some("21117M402412".to_owned()),
            container_id: Some("AD409054-19E5-5DD9-ADE9-925239576E82".to_owned()),
            ..UsbHistoryOptions::default()
        };
        assert_eq!(
            analyze_usb_history(&registry, None, &options)
                .unwrap()
                .records
                .len(),
            1
        );
        let no_match = UsbHistoryOptions {
            serial: Some("different".to_owned()),
            ..UsbHistoryOptions::default()
        };
        assert!(
            analyze_usb_history(&registry, None, &no_match)
                .unwrap()
                .records
                .is_empty()
        );
    }

    #[test]
    fn associates_mounted_device_by_utf16_serial() {
        let interface =
            history_interface(UsbInterfaceRole::PrimaryStorage, 133_317_540_861_257_591);
        let serial = "21117M402412";
        let mounted = RegistryMountedDevice {
            name: "\\DosDevices\\H:".to_owned(),
            decoded_target: None,
            raw_hex: hex::encode_upper(
                format!("USBSTOR#{serial}")
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
            ),
        };
        let (evidence, hints) = associate_mounted_devices(&[mounted], &[interface], Some(serial));
        assert_eq!(evidence.len(), 1);
        assert!(hints.is_empty());
        assert_eq!(evidence[0].name, "\\DosDevices\\H:");
        assert!(evidence[0].match_basis.contains("UTF-16LE"));
        assert_eq!(evidence[0].confidence, UsbEvidenceConfidence::High);
    }

    #[test]
    fn mounted_device_substring_collision_is_only_a_low_confidence_hint() {
        let interface =
            history_interface(UsbInterfaceRole::PrimaryStorage, 133_317_540_861_257_591);
        let mounted = RegistryMountedDevice {
            name: "\\DosDevices\\X:".to_owned(),
            decoded_target: Some("USBSTOR#XSERIALY".to_owned()),
            raw_hex: String::new(),
        };
        let (evidence, hints) = associate_mounted_devices(&[mounted], &[interface], Some("SERIAL"));
        assert!(evidence.is_empty());
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].confidence, UsbEvidenceConfidence::Low);
        assert_eq!(hints[0].match_kind, "substring_hint_not_device_attribution");
    }

    #[test]
    fn identity_normalization_preserves_punctuation_and_rejects_invalid_guids() {
        assert_ne!(normalize_identity("AB-CD12"), normalize_identity("ABCD12"));
        assert_eq!(normalize_identity("\0\t"), None);
        assert_eq!(
            normalize_container_id(CONTAINER).as_deref(),
            Some("ad40905419e55dd9ade9925239576e82")
        );
        assert_eq!(
            normalize_container_id("ad40905419e55dd9ade9925239576e82"),
            None
        );
        assert_eq!(normalize_container_id("not-a-guid"), None);
    }

    #[test]
    fn availability_and_registry_warnings_are_system_source_scoped() {
        let mut registry = RegistrySystemInfo {
            available: true,
            ..RegistrySystemInfo::default()
        };
        registry
            .warnings
            .push("SOFTWARE persistence parser warning".to_owned());
        registry
            .usb_source_warnings
            .push("SYSTEM USB enumeration incomplete".to_owned());
        let report = analyze_usb_history(&registry, None, &UsbHistoryOptions::default()).unwrap();
        assert!(!report.available);
        assert!(!report.complete);
        assert_eq!(report.control_set_used, None);
        assert_eq!(report.registry_system_cmhive, None);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("SYSTEM USB enumeration incomplete"))
        );
        assert!(
            report
                .warnings
                .iter()
                .all(|warning| !warning.contains("SOFTWARE persistence"))
        );
    }

    #[test]
    fn output_limit_is_reported_separately_from_property_scan_budget() {
        let mut first = usb_device(
            "Disk&Ven_Test&Prod_One&Rev_1",
            "SERIAL-ONE&0",
            Some("disk"),
            133_317_540_861_257_591,
        );
        first.container_id = Some("{11111111-1111-1111-1111-111111111111}".to_owned());
        let mut second = usb_device(
            "Disk&Ven_Test&Prod_Two&Rev_1",
            "SERIAL-TWO&0",
            Some("disk"),
            133_317_540_861_257_592,
        );
        second.container_id = Some("{22222222-2222-2222-2222-222222222222}".to_owned());
        let registry = RegistrySystemInfo {
            available: true,
            usb_devices: vec![first, second],
            ..RegistrySystemInfo::default()
        };
        let options = UsbHistoryOptions {
            limit: 1,
            ..UsbHistoryOptions::default()
        };
        let report = analyze_usb_history(&registry, None, &options).unwrap();
        assert_eq!(report.records.len(), 1);
        assert!(report.output_truncated);
        assert!(!report.property_scan_truncated);
        assert_eq!(report.property_interfaces_scanned, 0);
        assert_eq!(report.property_scan_scope, "returned_filtered_groups_only");
        assert_eq!(
            report.property_node_limit_per_interface,
            MAX_PROPERTY_NODES_PER_INTERFACE
        );
    }

    fn usb_device(
        device_type: &str,
        instance_id: &str,
        service: Option<&str>,
        last_write_raw: u64,
    ) -> RegistryUsbDevice {
        RegistryUsbDevice {
            registry_key: RegistryKey {
                cell_index: 0,
                name: instance_id.to_owned(),
                last_write_raw,
                flags: 0,
            },
            device_type: device_type.to_owned(),
            instance_id: instance_id.to_owned(),
            friendly_name: device_type
                .starts_with("Disk&")
                .then(|| "SanDisk Extreme SSD USB Device".to_owned()),
            device_description: device_type
                .contains("SES")
                .then(|| "SanDisk SES Device USB Device".to_owned()),
            manufacturer: None,
            service: service.map(str::to_owned),
            class_guid: device_type
                .starts_with("Disk&")
                .then(|| "{4d36e967-e325-11ce-bfc1-08002be10318}".to_owned()),
            container_id: Some(CONTAINER.to_owned()),
            last_write_raw,
            last_write: None,
        }
    }

    fn history_interface(role: UsbInterfaceRole, last_write_raw: u64) -> UsbHistoryInterface {
        UsbHistoryInterface {
            registry_key: RegistryKey {
                cell_index: 0,
                name: "instance".to_owned(),
                last_write_raw,
                flags: 0,
            },
            registry_cell_index: 0,
            role,
            enum_branch: "USBSTOR".to_owned(),
            registry_path: "ControlSet001\\Enum\\USBSTOR\\test\\instance".to_owned(),
            device_type: "Disk&Ven_Test&Prod_Test&Rev_1".to_owned(),
            instance_id: "serial&0".to_owned(),
            decoded_serial: Some("serial".to_owned()),
            friendly_name: None,
            device_description: None,
            manufacturer: None,
            service: Some("disk".to_owned()),
            class_guid: None,
            container_id: Some(CONTAINER.to_owned()),
            key_last_write: forensic_filetime(last_write_raw, "test".to_owned(), Some(480)),
            properties: UsbDevicePropertyTimes::default(),
        }
    }
}
