use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::Serialize;

use crate::address::WindowsAddressSpace;
use crate::session::AnalysisSession;
use crate::windows::WindowsArchitecture;
use crate::windows::plugins::{NetworkRecord, PluginReport};

pub mod credentials;
pub mod registry;
use registry::{
    RegistryCrashDumpRecord, RegistryEventLogConfigRecord, RegistryNetworkConfigRecord,
    RegistryPolicyRecord, RegistryPrinterRecord, RegistryRdpRecord, RegistrySecurityRecord,
    RegistrySystemInfo, RegistryVirtualizationRecord, RegistryWirelessRecord, RegistryWmiRecord,
    analyze_registry,
};

const KUSER_SHARED_DATA: u64 = 0xffff_f780_0000_0000;

#[derive(Debug, Serialize)]
pub struct SystemInfoReport {
    pub image: SystemImageInfo,
    pub kernel: SystemKernelInfo,
    pub operating_system: OperatingSystemInfo,
    pub clock: SystemClockInfo,
    pub host: HostInfo,
    pub processes: SystemProcessSummary,
    pub network: SystemNetworkSummary,
    pub registry: RegistrySystemInfo,
    pub warnings: Vec<String>,
}

/// Registry-backed system artifacts used by dedicated LovelyMem views.
///
/// All sections are produced from one process enumeration and one recovered Hive set so hosts do
/// not need to rescan the image separately for printers, policies, networking, RDP, and related
/// configuration.
#[derive(Debug, Serialize)]
pub struct SystemArtifactReport {
    pub complete: bool,
    pub warnings: Vec<String>,
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
}

pub fn analyze_system_artifacts(session: &AnalysisSession) -> Result<SystemArtifactReport> {
    let processes = session.processes(65_536)?;
    let process_complete = processes.complete;
    let mut registry = analyze_registry(session, &processes);
    Ok(SystemArtifactReport {
        complete: process_complete && registry.available,
        warnings: std::mem::take(&mut registry.warnings),
        printers: std::mem::take(&mut registry.printers),
        policies: std::mem::take(&mut registry.policies),
        security_software: std::mem::take(&mut registry.security_software),
        virtualization: std::mem::take(&mut registry.virtualization),
        wmi_configuration: std::mem::take(&mut registry.wmi_configuration),
        event_log_configuration: std::mem::take(&mut registry.event_log_configuration),
        crash_dump_configuration: std::mem::take(&mut registry.crash_dump_configuration),
        rdp_history: std::mem::take(&mut registry.rdp_history),
        network_configuration: std::mem::take(&mut registry.network_configuration),
        wireless_history: std::mem::take(&mut registry.wireless_history),
    })
}

#[derive(Debug, Serialize)]
pub struct SystemImageInfo {
    pub path: String,
    pub format: String,
    pub file_size: u64,
    pub logical_size: u64,
    pub mapped_physical_bytes: u64,
    pub physical_span_count: usize,
}

#[derive(Debug, Serialize)]
pub struct SystemKernelInfo {
    pub architecture: String,
    pub directory_table_base: u64,
    pub kernel_base: u64,
    pub ps_active_process_head: u64,
    pub ps_loaded_module_list: u64,
    pub discovery_method: String,
    pub pdb_guid: String,
    pub pdb_age: u32,
    pub build_lab: Option<String>,
    pub build_lab_ex: Option<String>,
    pub kernel_build_number: Option<u32>,
    pub processor_count: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct OperatingSystemInfo {
    pub major_version: Option<u32>,
    pub minor_version: Option<u32>,
    pub build_number: Option<u32>,
    pub system_version: Option<String>,
    pub system_version_source: String,
    pub product_type: Option<String>,
    pub suite_mask: Option<u32>,
    pub system_root: Option<String>,
    pub safe_boot_mode: Option<bool>,
    pub kernel_debugger_enabled: Option<bool>,
    pub mitigation_policy_bits: Option<u8>,
    pub active_processor_count: Option<u32>,
    pub active_group_count: Option<u8>,
    pub number_of_physical_pages: Option<u64>,
    pub page_size_bytes: Option<u64>,
    pub physical_memory_bytes: Option<u64>,
    pub boot_id: Option<u32>,
    pub registry_product_name: Option<String>,
    pub display_version: Option<String>,
    pub registry_current_version: Option<String>,
    pub registry_major_version: Option<u32>,
    pub registry_minor_version: Option<u32>,
    pub edition_id: Option<String>,
    pub composition_edition_id: Option<String>,
    pub installation_type: Option<String>,
    pub current_type: Option<String>,
    pub registry_current_build: Option<String>,
    pub update_build_revision: Option<u32>,
    pub release_id: Option<String>,
    pub build_branch: Option<String>,
    pub build_guid: Option<String>,
    pub registry_build_lab: Option<String>,
    pub registry_build_lab_ex: Option<String>,
    pub service_pack: Option<String>,
    pub install_date_raw: Option<u64>,
    pub install_date: Option<String>,
    pub install_time_details: ForensicTimestamp,
    pub registered_owner: Option<String>,
    pub registered_organization: Option<String>,
    pub product_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SystemClockInfo {
    pub timezone: ImageTimeZoneInfo,
    pub system_time_raw: Option<u64>,
    pub system_time: Option<String>,
    pub system_time_details: ForensicTimestamp,
    pub boot_time_raw: Option<u64>,
    pub boot_time: Option<String>,
    pub boot_time_details: ForensicTimestamp,
    pub last_shutdown_time: Option<String>,
    pub last_shutdown_time_details: ForensicTimestamp,
    pub interrupt_time_100ns: Option<u64>,
    pub uptime_seconds: Option<f64>,
    pub timezone_bias_100ns: Option<i64>,
    pub timezone_bias_minutes: Option<f64>,
    pub qpc_frequency: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageTimeZoneInfo {
    pub windows_key_name: Option<String>,
    pub standard_name: Option<String>,
    pub daylight_name: Option<String>,
    pub windows_bias_minutes: Option<i32>,
    pub active_bias_minutes: Option<i32>,
    pub effective_bias_minutes: Option<i32>,
    pub utc_offset_minutes: Option<i32>,
    pub utc_offset: Option<String>,
    pub dynamic_daylight_disabled: Option<bool>,
    pub source: String,
    pub conversion_note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForensicTimestamp {
    pub raw_value: Option<u64>,
    pub raw_format: String,
    pub utc: Option<String>,
    pub image_local: Option<String>,
    pub timezone: Option<String>,
    pub utc_offset: Option<String>,
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct HostInfo {
    pub computer_name: Option<String>,
    pub registry_hostname: Option<String>,
    pub registry_domain: Option<String>,
    pub user_domain: Option<String>,
    pub computer_name_evidence_count: usize,
    pub users: Vec<SystemUserEvidence>,
}

#[derive(Debug, Serialize)]
pub struct SystemUserEvidence {
    pub sid: Option<String>,
    pub user_name: Option<String>,
    pub domain: Option<String>,
    pub profile_path: Option<String>,
    pub process_count: usize,
}

#[derive(Debug, Serialize)]
pub struct SystemProcessSummary {
    pub total: usize,
    pub running: usize,
    pub exited: usize,
    pub total_active_threads: u64,
    pub command_lines_recovered: usize,
    pub image_paths_recovered: usize,
    pub user_sids_recovered: usize,
    pub process_list_complete: bool,
    pub process_list_stop_reason: String,
}

#[derive(Debug, Serialize)]
pub struct SystemNetworkSummary {
    pub endpoint_count: usize,
    pub tcp_count: usize,
    pub udp_count: usize,
    pub listening_count: usize,
    pub owner_resolved_count: usize,
    pub local_addresses: Vec<String>,
    pub remote_addresses: Vec<String>,
    pub configured_adapter_count: usize,
    pub historical_profile_count: usize,
    pub configured_addresses: Vec<String>,
    pub configured_dns_servers: Vec<String>,
    pub configured_gateways: Vec<String>,
    pub endpoints: Vec<NetworkRecord>,
    pub complete: bool,
}

#[derive(Default)]
struct UserAccumulator {
    process_count: usize,
    names: BTreeMap<String, usize>,
    domains: BTreeMap<String, usize>,
    profiles: BTreeMap<String, usize>,
}

pub fn analyze_system_info(
    session: &AnalysisSession,
    process_limit: usize,
    network_limit: usize,
) -> Result<SystemInfoReport> {
    analyze_system_info_inner(session, process_limit, network_limit, true)
}

/// 快速生成适合交互式首屏的系统概览。
///
/// 深度网络池扫描与注册表 Hive 恢复由各自插件独立执行；系统首屏不应为了这些
/// 全镜像任务等待数分钟。完整 CLI 报告仍使用 [`analyze_system_info`]。
pub fn analyze_system_info_quick(
    session: &AnalysisSession,
    process_limit: usize,
) -> Result<SystemInfoReport> {
    analyze_system_info_inner(session, process_limit, 0, false)
}

fn analyze_system_info_inner(
    session: &AnalysisSession,
    process_limit: usize,
    network_limit: usize,
    include_deep_sources: bool,
) -> Result<SystemInfoReport> {
    let process_report = session.processes(process_limit)?;
    let network_report = if include_deep_sources && session.kernel().is_x86_pae() {
        match session.network(network_limit) {
            Ok(report) => report,
            Err(error) => PluginReport {
                records: Vec::new(),
                complete: false,
                warnings: vec![format!("网络端点证据不可用（不代表无网络连接）：{error:#}")],
            },
        }
    } else if include_deep_sources {
        session.network(network_limit)?
    } else {
        PluginReport {
            records: Vec::new(),
            complete: false,
            warnings: vec![
                "快速系统概览未执行深度网络池扫描；请使用 netscan/netstat 插件补充".to_string(),
            ],
        }
    };
    let registry = if include_deep_sources {
        analyze_registry(session, &process_report)
    } else {
        RegistrySystemInfo::default()
    };
    let space = session.kernel().address_space(session.image())?;
    let profile = session.profile();
    let shared_data_address = if session.kernel().is_x86_pae() {
        0xffdf_0000
    } else {
        KUSER_SHARED_DATA
    };
    let shared = |field: &str| {
        profile
            .type_field("_KUSER_SHARED_DATA", field)
            .ok()
            .map(|field| shared_data_address + field.offset)
    };

    let system_time_raw =
        shared("SystemTime").and_then(|address| read_ksystem_time(&space, address));
    let interrupt_time =
        shared("InterruptTime").and_then(|address| read_ksystem_time(&space, address));
    let kernel_boot_time =
        read_kernel_u64(session, &space, "KeBootTime").filter(|value| *value != 0);
    let (boot_time_raw, boot_time_source) = if let Some(value) = kernel_boot_time {
        (Some(value), "nt!KeBootTime（Windows FILETIME）")
    } else {
        (
            system_time_raw.and_then(|system| {
                interrupt_time.and_then(|interrupt| system.checked_sub(interrupt))
            }),
            "_KUSER_SHARED_DATA.SystemTime - InterruptTime（推算的 Windows FILETIME）",
        )
    };
    let timezone_bias = shared("TimeZoneBias")
        .and_then(|address| read_ksystem_time(&space, address))
        .map(|value| value as i64);

    let mut computer_names = BTreeMap::<String, usize>::new();
    let mut domains = BTreeMap::<String, usize>::new();
    let mut users = BTreeMap::<String, UserAccumulator>::new();
    let mut running = 0usize;
    let mut exited = 0usize;
    let mut total_threads = 0u64;
    let mut command_lines = 0usize;
    let mut image_paths = 0usize;
    let mut user_sids = 0usize;
    for process in &process_report.processes {
        let details = &process.details;
        if details.state == "exited" {
            exited += 1;
        } else {
            running += 1;
        }
        total_threads += u64::from(details.active_threads.unwrap_or(0));
        command_lines += usize::from(details.command_line.is_some());
        image_paths += usize::from(details.image_path.is_some());
        user_sids += usize::from(details.user_sid.is_some());
        if let Some(name) = normalized_value(details.environment_computer_name.as_deref()) {
            *computer_names.entry(name).or_default() += 1;
        }
        if let Some(domain) = normalized_value(details.environment_user_domain.as_deref()) {
            *domains.entry(domain).or_default() += 1;
        }
        let sid = details.user_sid.as_deref().unwrap_or("");
        let user = details.environment_user_name.as_deref().unwrap_or("");
        let domain = details.environment_user_domain.as_deref().unwrap_or("");
        let profile_path = details.environment_user_profile.as_deref().unwrap_or("");
        if !sid.is_empty() || !user.is_empty() {
            let key = if sid.is_empty() {
                format!(
                    "account:{}\\{}",
                    domain.to_ascii_lowercase(),
                    user.to_ascii_lowercase()
                )
            } else {
                format!("sid:{sid}")
            };
            let entry = users.entry(key).or_default();
            entry.process_count += 1;
            if !user.is_empty() {
                *entry.names.entry(user.to_owned()).or_default() += 1;
            }
            if !domain.is_empty() {
                *entry.domains.entry(domain.to_owned()).or_default() += 1;
            }
            if !profile_path.is_empty() {
                *entry.profiles.entry(profile_path.to_owned()).or_default() += 1;
            }
        }
    }

    for profile in &registry.profiles {
        let entry = users.entry(format!("sid:{}", profile.sid)).or_default();
        if let Some(path) = normalized_value(profile.profile_path.as_deref()) {
            *entry.profiles.entry(path).or_default() += 1;
        }
    }
    for account in &registry.local_accounts {
        let profile_sid = account.rid.and_then(|rid| {
            registry
                .profiles
                .iter()
                .find(|profile| profile.sid.ends_with(&format!("-{rid}")))
                .map(|profile| profile.sid.clone())
        });
        let key = profile_sid
            .map(|sid| format!("sid:{sid}"))
            .unwrap_or_else(|| format!("sam:{}", account.name.to_ascii_lowercase()));
        *users
            .entry(key)
            .or_default()
            .names
            .entry(account.name.clone())
            .or_default() += 1;
    }

    let computer_name = registry
        .computer_name
        .clone()
        .or_else(|| registry.active_computer_name.clone())
        .or_else(|| most_frequent(&computer_names));
    let user_domain = most_frequent(&domains);
    let users = users
        .into_iter()
        .map(|(key, evidence)| {
            let sid = key.strip_prefix("sid:").map(str::to_owned);
            let known = sid.as_deref().and_then(well_known_account);
            SystemUserEvidence {
                sid,
                user_name: known
                    .map(|(_, user)| user.to_owned())
                    .or_else(|| most_frequent(&evidence.names)),
                domain: known
                    .map(|(domain, _)| domain.to_owned())
                    .or_else(|| most_frequent(&evidence.domains)),
                profile_path: most_frequent(&evidence.profiles),
                process_count: evidence.process_count,
            }
        })
        .collect::<Vec<_>>();

    let mut local_addresses = BTreeSet::new();
    let mut remote_addresses = BTreeSet::new();
    let mut tcp_count = 0usize;
    let mut udp_count = 0usize;
    let mut listening_count = 0usize;
    let mut owner_resolved_count = 0usize;
    for endpoint in &network_report.records {
        if endpoint.protocol.to_ascii_lowercase().starts_with("tcp") {
            tcp_count += 1;
        }
        if endpoint.protocol.to_ascii_lowercase().starts_with("udp") {
            udp_count += 1;
        }
        if endpoint.state.as_deref().is_some_and(|state| {
            state.eq_ignore_ascii_case("listen") || state.eq_ignore_ascii_case("listening")
        }) {
            listening_count += 1;
        }
        owner_resolved_count += usize::from(endpoint.pid != 0);
        if !is_unspecified_address(&endpoint.local_address) {
            local_addresses.insert(endpoint.local_address.clone());
        }
        if !is_unspecified_address(&endpoint.remote_address) {
            remote_addresses.insert(endpoint.remote_address.clone());
        }
    }

    let mut configured_addresses = BTreeSet::new();
    let mut configured_dns_servers = BTreeSet::new();
    let mut configured_gateways = BTreeSet::new();
    for adapter in &registry.network_adapters {
        configured_addresses.extend(adapter.ip_addresses.iter().cloned());
        configured_dns_servers.extend(adapter.dns_servers.iter().cloned());
        configured_gateways.extend(adapter.default_gateways.iter().cloned());
    }

    let mut warnings = session.warnings().to_vec();
    warnings.extend(
        process_report
            .warnings
            .iter()
            .map(|warning| format!("process [{}]: {}", warning.kind, warning.message)),
    );
    warnings.extend(
        network_report
            .warnings
            .iter()
            .map(|warning| format!("network: {warning}")),
    );
    warnings.extend(
        registry
            .warnings
            .iter()
            .map(|warning| format!("registry: {warning}")),
    );

    let process_major = process_report
        .processes
        .iter()
        .find_map(|process| process.details.peb_os_major_version);
    let process_minor = process_report
        .processes
        .iter()
        .find_map(|process| process.details.peb_os_minor_version);
    let process_build = process_report
        .processes
        .iter()
        .find_map(|process| process.details.peb_os_build_number)
        .map(u32::from);
    let shared_major = shared("NtMajorVersion").and_then(|address| read_u32(&space, address));
    let shared_minor = shared("NtMinorVersion").and_then(|address| read_u32(&space, address));
    let shared_build = shared("NtBuildNumber")
        .and_then(|address| read_u32(&space, address))
        .map(|value| value & 0xffff);
    let major = shared_major.or(process_major);
    let minor = shared_minor.or(process_minor);
    let build = shared_build.or(process_build);
    let system_root =
        shared("NtSystemRoot").and_then(|address| read_fixed_utf16(&space, address, 260));
    let product_type = shared("NtProductType")
        .and_then(|address| read_u32(&space, address))
        .map(product_type_name)
        .map(str::to_owned);
    let physical_pages = shared("FullNumberOfPhysicalPages")
        .and_then(|address| space.read_u64(address).ok())
        .or_else(|| {
            shared("NumberOfPhysicalPages")
                .and_then(|address| read_u32(&space, address))
                .map(u64::from)
        });
    let page_size_bytes = physical_pages.map(|_| 4096u64);
    let physical_memory_bytes = physical_pages.and_then(|pages| pages.checked_mul(4096));
    let registry_build = registry
        .product
        .current_build
        .as_deref()
        .or(registry.product.current_build_number.as_deref())
        .and_then(|value| value.parse::<u32>().ok());
    let system_version = format_system_version(
        major.or(registry.product.current_major_version_number),
        minor.or(registry.product.current_minor_version_number),
        build.or(registry_build),
        registry.product.ubr,
    );
    let system_version_source = if shared_major.is_some()
        && shared_minor.is_some()
        && shared_build.is_some()
    {
        "_KUSER_SHARED_DATA.NtMajorVersion/NtMinorVersion/NtBuildNumber；修订号来自 SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UBR"
    } else if shared_major.is_some() && shared_minor.is_some() && process_build.is_some() {
        "_KUSER_SHARED_DATA.NtMajorVersion/NtMinorVersion；Build 来自进程 PEB.OSBuildNumber，修订号来自 SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UBR"
    } else if session.kernel().is_x86_pae()
        && process_major.is_some()
        && process_minor.is_some()
        && process_build.is_some()
    {
        "Windows x86 PAE 进程 PEB 的 OSMajorVersion/OSMinorVersion/OSBuildNumber"
    } else {
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion 的主版本、次版本、Build 与 UBR"
    };
    let image_timezone = build_image_timezone(&registry, timezone_bias);
    let system_time_details = forensic_filetime(
        system_time_raw,
        "_KUSER_SHARED_DATA.SystemTime（Windows FILETIME，100 纳秒）",
        &image_timezone,
    );
    let boot_time_details = forensic_filetime(boot_time_raw, boot_time_source, &image_timezone);
    let last_shutdown_time_details = forensic_filetime(
        registry.last_shutdown_time_raw,
        "SYSTEM\\CurrentControlSet\\Control\\Windows\\ShutdownTime（Windows FILETIME，100 纳秒）",
        &image_timezone,
    );
    let install_time_details = forensic_unix_seconds(
        registry.product.install_date_raw,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\InstallDate（Unix 秒）",
        &image_timezone,
    );

    Ok(SystemInfoReport {
        image: SystemImageInfo {
            path: session.image().path().display().to_string(),
            format: format!("{:?}", session.image().format()),
            file_size: session.image().file_len(),
            logical_size: session.image().logical_len(),
            mapped_physical_bytes: session.image().mapped_bytes(),
            physical_span_count: session.image().spans().len(),
        },
        kernel: SystemKernelInfo {
            architecture: match session.kernel().architecture {
                WindowsArchitecture::X86_64 => "x86_64",
                WindowsArchitecture::X86Pae => "x86_pae",
            }
            .to_owned(),
            directory_table_base: session.kernel().directory_table_base,
            kernel_base: session.kernel().kernel_base,
            ps_active_process_head: session.kernel().ps_active_process_head,
            ps_loaded_module_list: session.kernel().ps_loaded_module_list,
            discovery_method: format!("{:?}", session.kernel().discovery_method),
            pdb_guid: profile.pdb_guid.clone(),
            pdb_age: profile.pdb_age,
            build_lab: read_kernel_c_string(session, &space, "NtBuildLab", 256),
            build_lab_ex: read_kernel_c_string(session, &space, "NtBuildLabEx", 256),
            kernel_build_number: read_kernel_u32(session, &space, "NtBuildNumber")
                .map(|value| value & 0xffff),
            processor_count: read_kernel_u8(session, &space, "KeNumberProcessors").map(u32::from),
        },
        operating_system: OperatingSystemInfo {
            major_version: major,
            minor_version: minor,
            build_number: build,
            system_version,
            system_version_source: system_version_source.to_owned(),
            product_type,
            suite_mask: shared("SuiteMask").and_then(|address| read_u32(&space, address)),
            system_root,
            safe_boot_mode: shared("SafeBootMode")
                .and_then(|address| read_u8(&space, address))
                .map(|value| value != 0),
            kernel_debugger_enabled: shared("KdDebuggerEnabled")
                .and_then(|address| read_u8(&space, address))
                .map(|value| value != 0),
            mitigation_policy_bits: shared("MitigationPolicies")
                .and_then(|address| read_u8(&space, address)),
            active_processor_count: shared("ActiveProcessorCount")
                .and_then(|address| read_u32(&space, address)),
            active_group_count: shared("ActiveGroupCount")
                .and_then(|address| read_u8(&space, address)),
            number_of_physical_pages: physical_pages,
            page_size_bytes,
            physical_memory_bytes,
            boot_id: shared("BootId").and_then(|address| read_u32(&space, address)),
            registry_product_name: registry.product.product_name.clone(),
            display_version: registry.product.display_version.clone(),
            registry_current_version: registry.product.current_version.clone(),
            registry_major_version: registry.product.current_major_version_number,
            registry_minor_version: registry.product.current_minor_version_number,
            edition_id: registry.product.edition_id.clone(),
            composition_edition_id: registry.product.composition_edition_id.clone(),
            installation_type: registry.product.installation_type.clone(),
            current_type: registry.product.current_type.clone(),
            registry_current_build: registry
                .product
                .current_build
                .clone()
                .or_else(|| registry.product.current_build_number.clone()),
            update_build_revision: registry.product.ubr,
            release_id: registry.product.release_id.clone(),
            build_branch: registry.product.build_branch.clone(),
            build_guid: registry.product.build_guid.clone(),
            registry_build_lab: registry.product.build_lab.clone(),
            registry_build_lab_ex: registry.product.build_lab_ex.clone(),
            service_pack: registry.product.csd_version.clone(),
            install_date_raw: registry.product.install_date_raw,
            install_date: registry.product.install_date.clone(),
            install_time_details,
            registered_owner: registry.product.registered_owner.clone(),
            registered_organization: registry.product.registered_organization.clone(),
            product_id: registry.product.product_id.clone(),
        },
        clock: SystemClockInfo {
            timezone: image_timezone,
            system_time_raw,
            system_time: system_time_raw.and_then(filetime_to_rfc3339),
            system_time_details,
            boot_time_raw,
            boot_time: boot_time_raw.and_then(filetime_to_rfc3339),
            boot_time_details,
            last_shutdown_time: registry.last_shutdown_time.clone(),
            last_shutdown_time_details,
            interrupt_time_100ns: interrupt_time,
            uptime_seconds: interrupt_time.map(|value| value as f64 / 10_000_000.0),
            timezone_bias_100ns: timezone_bias,
            timezone_bias_minutes: timezone_bias.map(|value| value as f64 / 600_000_000.0),
            qpc_frequency: shared("QpcFrequency").and_then(|address| space.read_u64(address).ok()),
        },
        host: HostInfo {
            computer_name,
            registry_hostname: registry.hostname.clone(),
            registry_domain: registry.domain.clone(),
            user_domain,
            computer_name_evidence_count: computer_names.values().sum::<usize>()
                + usize::from(registry.computer_name.is_some()),
            users,
        },
        processes: SystemProcessSummary {
            total: process_report.processes.len(),
            running,
            exited,
            total_active_threads: total_threads,
            command_lines_recovered: command_lines,
            image_paths_recovered: image_paths,
            user_sids_recovered: user_sids,
            process_list_complete: process_report.complete,
            process_list_stop_reason: format!("{:?}", process_report.stop_reason),
        },
        network: SystemNetworkSummary {
            endpoint_count: network_report.records.len(),
            tcp_count,
            udp_count,
            listening_count,
            owner_resolved_count,
            local_addresses: local_addresses.into_iter().collect(),
            remote_addresses: remote_addresses.into_iter().collect(),
            configured_adapter_count: registry.network_adapters.len(),
            historical_profile_count: registry.network_profiles.len(),
            configured_addresses: configured_addresses.into_iter().collect(),
            configured_dns_servers: configured_dns_servers.into_iter().collect(),
            configured_gateways: configured_gateways.into_iter().collect(),
            endpoints: network_report.records,
            complete: network_report.complete,
        },
        registry,
        warnings,
    })
}

fn read_kernel_c_string(
    session: &AnalysisSession,
    space: &WindowsAddressSpace<'_>,
    symbol: &str,
    limit: usize,
) -> Option<String> {
    let address = kernel_symbol_address(session, symbol)?;
    let mut bytes = Vec::with_capacity(64);
    for index in 0..limit {
        let byte = read_u8(space, address.checked_add(index as u64)?)?;
        if byte == 0 {
            break;
        }
        if !byte.is_ascii() || byte.is_ascii_control() {
            return None;
        }
        bytes.push(byte);
    }
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

fn read_kernel_u64(
    session: &AnalysisSession,
    space: &WindowsAddressSpace<'_>,
    symbol: &str,
) -> Option<u64> {
    space.read_u64(kernel_symbol_address(session, symbol)?).ok()
}

fn read_kernel_u32(
    session: &AnalysisSession,
    space: &WindowsAddressSpace<'_>,
    symbol: &str,
) -> Option<u32> {
    read_u32(space, kernel_symbol_address(session, symbol)?)
}

fn read_kernel_u8(
    session: &AnalysisSession,
    space: &WindowsAddressSpace<'_>,
    symbol: &str,
) -> Option<u8> {
    read_u8(space, kernel_symbol_address(session, symbol)?)
}

fn kernel_symbol_address(session: &AnalysisSession, symbol: &str) -> Option<u64> {
    session
        .profile()
        .symbols
        .get(symbol)
        .and_then(|rva| session.kernel().kernel_base.checked_add(u64::from(*rva)))
}

fn read_ksystem_time(space: &WindowsAddressSpace<'_>, address: u64) -> Option<u64> {
    let low = u64::from(read_u32(space, address)?);
    let high1 = u64::from(read_u32(space, address.checked_add(4)?)?);
    let high2 = u64::from(read_u32(space, address.checked_add(8)?)?);
    let high = if high1 == high2 { high1 } else { high2 };
    Some((high << 32) | low)
}

fn read_fixed_utf16(
    space: &WindowsAddressSpace<'_>,
    address: u64,
    max_words: usize,
) -> Option<String> {
    let mut bytes = vec![0u8; max_words.checked_mul(2)?];
    space.read_virtual(address, &mut bytes).ok()?;
    let words = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|word| *word != 0)
        .collect::<Vec<_>>();
    (!words.is_empty()).then(|| String::from_utf16_lossy(&words))
}

fn read_u8(space: &WindowsAddressSpace<'_>, address: u64) -> Option<u8> {
    let mut bytes = [0u8; 1];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(bytes[0])
}

fn read_u32(space: &WindowsAddressSpace<'_>, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn filetime_to_rfc3339(value: u64) -> Option<String> {
    filetime_to_datetime(value).map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn filetime_to_datetime(value: u64) -> Option<DateTime<Utc>> {
    const WINDOWS_TO_UNIX_SECONDS: i128 = 11_644_473_600;
    const TICKS_PER_SECOND: i128 = 10_000_000;
    let unix_ticks = i128::from(value).checked_sub(WINDOWS_TO_UNIX_SECONDS * TICKS_PER_SECOND)?;
    let seconds = i64::try_from(unix_ticks.div_euclid(TICKS_PER_SECOND)).ok()?;
    let nanos = u32::try_from(unix_ticks.rem_euclid(TICKS_PER_SECOND) * 100).ok()?;
    DateTime::<Utc>::from_timestamp(seconds, nanos)
}

fn build_image_timezone(
    registry: &RegistrySystemInfo,
    kuser_bias_100ns: Option<i64>,
) -> ImageTimeZoneInfo {
    let registry_active_bias = registry
        .timezone
        .active_bias_minutes
        .filter(|value| value.unsigned_abs() <= 24 * 60);
    let registry_standard_bias = registry
        .timezone
        .bias_minutes
        .filter(|value| value.unsigned_abs() <= 24 * 60);
    let kuser_bias = kuser_bias_100ns
        .and_then(|value| i32::try_from(value / 600_000_000).ok())
        .filter(|value| value.unsigned_abs() <= 24 * 60);
    let effective_bias = registry_active_bias
        .or(registry_standard_bias)
        .or(kuser_bias);
    let utc_offset_minutes = effective_bias.and_then(i32::checked_neg);
    let source = if registry_active_bias.is_some() {
        "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation\\ActiveTimeBias"
    } else if registry_standard_bias.is_some() {
        "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation\\Bias"
    } else if kuser_bias.is_some() {
        "_KUSER_SHARED_DATA.TimeZoneBias"
    } else {
        "未恢复到可用的镜像时区偏移"
    };
    let conversion_note = if utc_offset_minutes.is_some() {
        "Windows Bias 语义为 UTC = 本地时间 + Bias；历史时间按镜像采集时有效偏移换算，UTC 为权威值，跨夏令时边界时请以 UTC 为准"
    } else {
        "未使用分析机时区；因镜像时区偏移缺失，无法生成镜像本地时间"
    };

    ImageTimeZoneInfo {
        windows_key_name: registry.timezone.key_name.clone(),
        standard_name: registry.timezone.standard_name.clone(),
        daylight_name: registry.timezone.daylight_name.clone(),
        windows_bias_minutes: registry.timezone.bias_minutes,
        active_bias_minutes: registry.timezone.active_bias_minutes,
        effective_bias_minutes: effective_bias,
        utc_offset_minutes,
        utc_offset: utc_offset_minutes.map(format_utc_offset),
        dynamic_daylight_disabled: registry.timezone.dynamic_daylight_disabled,
        source: source.to_owned(),
        conversion_note: conversion_note.to_owned(),
    }
}

fn forensic_filetime(
    raw_value: Option<u64>,
    source: &str,
    timezone: &ImageTimeZoneInfo,
) -> ForensicTimestamp {
    forensic_timestamp(
        raw_value,
        "Windows FILETIME（自 1601-01-01 UTC 起的 100 纳秒数）",
        raw_value.and_then(filetime_to_datetime),
        source,
        timezone,
    )
}

fn forensic_unix_seconds(
    raw_value: Option<u64>,
    source: &str,
    timezone: &ImageTimeZoneInfo,
) -> ForensicTimestamp {
    let utc = raw_value
        .and_then(|value| i64::try_from(value).ok())
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0));
    forensic_timestamp(
        raw_value,
        "Unix 时间戳（自 1970-01-01 UTC 起的秒数）",
        utc,
        source,
        timezone,
    )
}

fn forensic_timestamp(
    raw_value: Option<u64>,
    raw_format: &str,
    utc: Option<DateTime<Utc>>,
    source: &str,
    timezone: &ImageTimeZoneInfo,
) -> ForensicTimestamp {
    let image_local = utc.and_then(|time| {
        let seconds = timezone.utc_offset_minutes?.checked_mul(60)?;
        let offset = FixedOffset::east_opt(seconds)?;
        Some(
            time.with_timezone(&offset)
                .to_rfc3339_opts(SecondsFormat::Millis, false),
        )
    });
    ForensicTimestamp {
        raw_value,
        raw_format: raw_format.to_owned(),
        utc: utc.map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true)),
        image_local,
        timezone: timezone
            .windows_key_name
            .clone()
            .or_else(|| timezone.standard_name.clone()),
        utc_offset: timezone.utc_offset.clone(),
        source: source.to_owned(),
    }
}

fn format_utc_offset(minutes: i32) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let absolute = minutes.unsigned_abs();
    format!("UTC{sign}{:02}:{:02}", absolute / 60, absolute % 60)
}

fn format_system_version(
    major: Option<u32>,
    minor: Option<u32>,
    build: Option<u32>,
    revision: Option<u32>,
) -> Option<String> {
    let (major, minor, build) = (major?, minor?, build?);
    Some(match revision {
        Some(revision) => format!("{major}.{minor}.{build}.{revision}"),
        None => format!("{major}.{minor}.{build}"),
    })
}

fn product_type_name(value: u32) -> &'static str {
    match value {
        1 => "workstation",
        2 => "domain_controller",
        3 => "server",
        _ => "unknown",
    }
}

fn normalized_value(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn most_frequent(values: &BTreeMap<String, usize>) -> Option<String> {
    values
        .iter()
        .max_by(|(left_name, left_count), (right_name, right_count)| {
            left_count
                .cmp(right_count)
                .then_with(|| right_name.cmp(left_name))
        })
        .map(|(name, _)| name.clone())
}

fn well_known_account(sid: &str) -> Option<(&'static str, &'static str)> {
    match sid {
        "S-1-5-18" => Some(("NT AUTHORITY", "SYSTEM")),
        "S-1-5-19" => Some(("NT AUTHORITY", "LOCAL SERVICE")),
        "S-1-5-20" => Some(("NT AUTHORITY", "NETWORK SERVICE")),
        _ => None,
    }
}

fn is_unspecified_address(address: &str) -> bool {
    matches!(address, "" | "0.0.0.0" | "::" | "*" | "unspecified")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timezone_from_bias(bias_minutes: i32) -> ImageTimeZoneInfo {
        ImageTimeZoneInfo {
            windows_key_name: Some("测试时区".to_owned()),
            standard_name: None,
            daylight_name: None,
            windows_bias_minutes: Some(bias_minutes),
            active_bias_minutes: Some(bias_minutes),
            effective_bias_minutes: Some(bias_minutes),
            utc_offset_minutes: bias_minutes.checked_neg(),
            utc_offset: bias_minutes.checked_neg().map(format_utc_offset),
            dynamic_daylight_disabled: None,
            source: "测试".to_owned(),
            conversion_note: "测试".to_owned(),
        }
    }

    #[test]
    fn windows_bias_has_the_opposite_sign_from_utc_offset() {
        assert_eq!(
            timezone_from_bias(-480).utc_offset.as_deref(),
            Some("UTC+08:00")
        );
        assert_eq!(
            timezone_from_bias(300).utc_offset.as_deref(),
            Some("UTC-05:00")
        );
        assert_eq!(
            timezone_from_bias(-330).utc_offset.as_deref(),
            Some("UTC+05:30")
        );
    }

    #[test]
    fn formats_filetime_as_utc_and_image_local_time() {
        let timestamp = forensic_filetime(
            Some(134_252_414_377_337_294),
            "测试",
            &timezone_from_bias(-480),
        );
        assert_eq!(timestamp.utc.as_deref(), Some("2026-06-06T17:43:57.733Z"));
        assert_eq!(
            timestamp.image_local.as_deref(),
            Some("2026-06-07T01:43:57.733+08:00")
        );
    }

    #[test]
    fn formats_unix_install_time_with_explicit_half_hour_offset() {
        let timestamp =
            forensic_unix_seconds(Some(1_780_757_374), "测试", &timezone_from_bias(-330));
        assert_eq!(timestamp.utc.as_deref(), Some("2026-06-06T14:49:34.000Z"));
        assert_eq!(
            timestamp.image_local.as_deref(),
            Some("2026-06-06T20:19:34.000+05:30")
        );
    }

    #[test]
    fn missing_image_timezone_never_uses_the_analysis_host_timezone() {
        let timezone = ImageTimeZoneInfo {
            windows_key_name: None,
            standard_name: None,
            daylight_name: None,
            windows_bias_minutes: None,
            active_bias_minutes: None,
            effective_bias_minutes: None,
            utc_offset_minutes: None,
            utc_offset: None,
            dynamic_daylight_disabled: None,
            source: "测试".to_owned(),
            conversion_note: "测试".to_owned(),
        };
        let timestamp = forensic_unix_seconds(Some(0), "测试", &timezone);
        assert_eq!(timestamp.utc.as_deref(), Some("1970-01-01T00:00:00.000Z"));
        assert_eq!(timestamp.image_local, None);
    }

    #[test]
    fn formats_complete_and_partial_system_versions() {
        assert_eq!(
            format_system_version(Some(10), Some(0), Some(26200), Some(8457)).as_deref(),
            Some("10.0.26200.8457")
        );
        assert_eq!(
            format_system_version(Some(6), Some(1), Some(7601), None).as_deref(),
            Some("6.1.7601")
        );
        assert_eq!(
            format_system_version(Some(10), None, Some(26200), None),
            None
        );
    }
}
