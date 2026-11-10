use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use crate::accounts::{AccountScanReport, scan_account_traces};
use crate::address::VirtualMappingReport;
use crate::browser_session::{
    BrowserSessionOptions, BrowserSessionReport, BrowserSessionStage, reconstruct_browser_sessions,
};
use crate::cancellation::CancellationToken;
use crate::clipboard::{
    ClipboardScanOptions, ClipboardScanReport, ClipboardScanStage, ResidualScanOptions,
    ResidualScanReport, ResidualScanStage, scan_clipboard, scan_residual_text,
};
use crate::cobaltstrike::{
    CobaltStrikeScanOptions, CobaltStrikeScanReport, scan_cobaltstrike_configs,
};
use crate::cookies::{CookieScanOptions, CookieScanReport, CookieScanStage, scan_browser_cookies};
use crate::dns_scan::{DnsScanOptions, DnsScanReport, scan_dns_evidence};
use crate::evidence::{EvidenceWarning, EvidenceWarningSeverity};
use crate::image::{ImageOpenOptions, MemoryImage};
use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::packet_scan::{
    PacketScanArtifacts, PacketScanOptions, PacketScanStage, scan_memory_packets,
};
use crate::process_dump::{ProcessMemoryDumpReport, dump_process_memory_with_force};
use crate::profile::{KernelProfile, build_eprocess_profile, legacy_windows_profile};
use crate::symbols::{SymbolStore, default_symbol_store, resolve_kernel_pdb_with_store};
use crate::system::credentials::{
    CachedumpRecord, HashdumpRecord, LsaSecretRecord, cachedump, hashdump, lsadump,
};
use crate::system::registry::{
    AmcacheRecord, RegistryEvidence, RegistryPrintRecord, RegistryScheduledTask, UserAssistRecord,
    analyze_amcache, analyze_registry, analyze_scheduled_task_registry, analyze_service_registry,
    analyze_userassist, print_registry_key, print_registry_key_exact_loaded,
};
use crate::terminal_history::{
    TerminalHistoryOptions, TerminalHistoryReport, TerminalHistoryStage, analyze_terminal_history,
};
use crate::wechat::{WechatScanOptions, WechatScanReport, WechatScanStage, scan_wechat_keys};
use crate::windows::autorun_plugins::{AutorunOptions, AutorunReport, scan_autoruns};
use crate::windows::check_pslist::{CheckPslistOptions, CheckPslistReport, check_pslist};
use crate::windows::console_plugins::{
    CommandHistoryReport, ConsoleReport, command_histories, consoles,
};
use crate::windows::desktop_reconstruct::{
    DesktopReconstructOptions, DesktopReconstructReport, reconstruct_desktops,
};
use crate::windows::disk_plugins::{
    MbrScanReport, MftScanReport, MftView, scan_mbr, scan_mft, scan_mft_cancellable,
};
use crate::windows::dwm_surfaces::{ScreenResolutionReport, detect_screen_resolutions};
use crate::windows::files::{
    DumpFileReport, DumpSource, FileScanReport, dump_file, scan_files, scan_files_cancellable,
};
use crate::windows::gdi_bitmap::{GdiBitmapOptions, GdiBitmapReport, recover_gdi_bitmaps};
use crate::windows::gui_plugins::{
    DesktopRecord, GuiReport, WindowRecord, WindowStationRecord, WindowTitleRecord,
    desktops as scan_gui_desktops, window_stations as scan_window_stations,
    window_titles as enumerate_window_titles, windows as enumerate_gui_windows,
};
use crate::windows::injected_regions::{
    InjectedRegionOptions, InjectedRegionReport, find_injected_regions,
};
use crate::windows::kernel_plugins::{
    CallbackReport, DeviceTreeReport, DriverInspectReport, DriverIrpReport, DriverModuleReport,
    DriverScanReport, ModuleScanReport, SsdtReport, UnloadedModuleReport, callbacks,
    correlate_drivers, device_tree, driver_irps, inspect_drivers, scan_driver_objects,
    scan_modules, ssdt, unloaded_modules,
};
use crate::windows::logon_plugins::{LogonSessionOptions, LogonSessionReport, scan_logon_sessions};
use crate::windows::malware_plugins::{
    MalfindReport, ProcessImageAnomalyReport, ProcessImageView, malfind, process_image_anomalies,
};
use crate::windows::netstat_plugins::{NetstatReport, netstat};
use crate::windows::object_plugins::{
    MutantScanReport, NamedObjectScanReport, SymbolicLinkScanReport, TimerReport, list_timers,
    scan_named_objects,
};
use crate::windows::pe_plugins::{
    IatReport, LdrModulesReport, PeDumpReport, PeSymbolReport, PeSymbolSource, dump_pe,
    ldr_modules, list_iat, pe_symbols,
};
use crate::windows::pipe_plugins::{PipeScanOptions, PipeScanReport, scan_pipes};
use crate::windows::plugins::{
    DllRecord, DriverRecord, GetCellRoutineReport, HandleRecord, HiveRecord, HiveScanRecord,
    NetworkRecord, PluginReport, VadRecord, check_get_cell_routines, list_dlls, list_drivers,
    list_handles, list_hives, list_vads, scan_hives, scan_network, scan_network_cancellable,
};
use crate::windows::prefetch_plugins::{PrefetchScanOptions, PrefetchScanReport, scan_prefetch};
use crate::windows::process_plugins::{
    CommandLineReport, EnvironmentReport, JobLinkReport, PrivilegeReport, ProcessScanReport,
    ProcessSessionReport, ProcessTreeReport, PsxviewReport, ServiceSidReport, SidReport,
    ThreadReport, ThreadScanReport, command_lines, environment_variables, job_links, list_threads,
    process_privileges, process_sessions, process_sids, process_tree, psxview, scan_processes,
    scan_processes_cancellable, scan_threads, service_sid_report,
};
use crate::windows::process_string::{
    PROCESS_STRING_WARNING_LIMIT, ProcessStringOptions, ProcessStringReport,
    locate_process_string_cancellable,
};
use crate::windows::registry::{HiveMemoryImage, dump_hive, recover_hive_bytes};
use crate::windows::service_plugins::{ServiceReport, ServiceView, analyze_services};
use crate::windows::shimcache_plugins::{ShimcacheReport, shimcache_memory};
use crate::windows::syscall_plugins::{
    EtwPatchReport, SkeletonKeyReport, SyscallScanReport, SyscallView, UnhookedSyscallReport,
    compare_ntdll_syscalls, detect_etw_patches, scan_system_calls, skeleton_key_check,
};
use crate::windows::system_plugins::{
    BigPoolReport, CrashInfoReport, KpcrReport, MemoryStatisticsReport, PoolScanReport,
    ProcessMemmapReport, StringOffsetKind, StringsMapReport, crash_info, kernel_virtmap,
    list_big_pools, list_kpcrs, map_strings, memory_statistics, process_memmap,
    scan_pool_allocations,
};
use crate::windows::token_plugins::{
    TokenAnomalyOptions, TokenAnomalyReport, scan_token_anomalies,
};
use crate::windows::vad_dump::{VadDumpOptions, VadDumpReport, dump_vads};
use crate::windows::vad_scan::{VadRegexReport, VadYaraReport, vad_regex_scan, vad_yara_scan};
use crate::windows::{ProcessListReport, WindowsKernelContext, list_processes};

/// Options for opening a reusable Windows analysis session.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub image_options: ImageOpenOptions,
    pub profile: Option<PathBuf>,
    pub pdb: Option<PathBuf>,
    pub symbol_store: SymbolStore,
    /// Permit a local `ntoskrnl.exe` PDB to provide type layouts when the
    /// target's exact public PDB is unavailable. Target globals are still
    /// discovered from the captured image.
    pub allow_compatible_local_symbols: bool,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            image_options: ImageOpenOptions::default(),
            profile: None,
            pdb: None,
            symbol_store: default_symbol_store(),
            allow_compatible_local_symbols: true,
        }
    }
}

/// Whether the Windows type layout belongs to the captured kernel itself.
///
/// A compatible local PDB can still provide useful positive evidence, but it
/// cannot prove that every target structure was interpreted correctly. Keep
/// this state separate from human-readable warnings so completeness decisions
/// never depend on matching translated warning text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolLayoutExactness {
    Exact,
    CompatibleLocal,
}

impl SymbolLayoutExactness {
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::Exact)
    }

    const fn evidence_name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::CompatibleLocal => "compatible_local",
        }
    }
}

/// A memory image, its symbol-derived profile, and the validated kernel
/// bootstrap context. Keeping these together lets multiple plugins reuse the
/// expensive initialization work.
pub struct AnalysisSession {
    image: MemoryImage,
    profile: KernelProfile,
    kernel: WindowsKernelContext,
    symbol_store: SymbolStore,
    warnings: Vec<String>,
    symbol_layout_exactness: SymbolLayoutExactness,
}

impl AnalysisSession {
    pub fn open(path: impl AsRef<Path>, options: SessionOptions) -> Result<Self> {
        Self::open_cancellable(path, options, &CancellationToken::new())
    }

    /// Opens a reusable session while checking cancellation between image,
    /// symbol/profile, and kernel-bootstrap stages.
    pub fn open_cancellable(
        path: impl AsRef<Path>,
        options: SessionOptions,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        cancellation.check_cancelled()?;
        let image = MemoryImage::open_with_options(path.as_ref(), options.image_options.clone())?;
        cancellation.check_cancelled()?;
        Self::from_image_cancellable(image, options, cancellation)
    }

    pub fn from_image(image: MemoryImage, options: SessionOptions) -> Result<Self> {
        Self::from_image_cancellable(image, options, &CancellationToken::new())
    }

    pub fn from_image_cancellable(
        image: MemoryImage,
        options: SessionOptions,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        cancellation.check_cancelled()?;
        ensure!(
            !image.spans().is_empty(),
            "Expert Witness 镜像包含磁盘或卷介质，而不是物理内存"
        );
        ensure!(
            options.profile.is_none() || options.pdb.is_none(),
            "不能同时指定配置文件和 PDB 符号覆盖项"
        );

        let (profile, warnings, symbol_layout_exactness) = load_profile(&image, &options)?;
        cancellation.check_cancelled()?;
        let kernel = WindowsKernelContext::discover(&image, &profile)?;
        cancellation.check_cancelled()?;
        Ok(Self {
            image,
            profile,
            kernel,
            symbol_store: options.symbol_store,
            warnings,
            symbol_layout_exactness,
        })
    }

    pub fn image(&self) -> &MemoryImage {
        &self.image
    }

    pub fn profile(&self) -> &KernelProfile {
        &self.profile
    }

    pub fn kernel(&self) -> &WindowsKernelContext {
        &self.kernel
    }

    pub fn symbol_store(&self) -> &SymbolStore {
        &self.symbol_store
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn symbol_layout_exactness(&self) -> SymbolLayoutExactness {
        self.symbol_layout_exactness
    }

    pub fn processes(&self, limit: usize) -> Result<ProcessListReport> {
        list_processes(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn processes_cancellable(
        &self,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<ProcessListReport> {
        cancellation.check_cancelled()?;
        let report = self.processes(limit)?;
        cancellation.check_cancelled()?;
        Ok(report)
    }

    pub fn process_scan(&self, limit: usize) -> Result<ProcessScanReport> {
        scan_processes(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn process_scan_cancellable(
        &self,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<ProcessScanReport> {
        scan_processes_cancellable(
            &self.image,
            &self.kernel,
            &self.profile,
            limit,
            cancellation,
        )
    }

    pub fn process_tree(&self, limit: usize) -> Result<ProcessTreeReport> {
        process_tree(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn check_pslist(&self, options: &CheckPslistOptions) -> Result<CheckPslistReport> {
        check_pslist(&self.image, &self.kernel, &self.profile, options)
    }

    pub fn psxview(&self, limit: usize) -> Result<PsxviewReport> {
        psxview(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn threads(&self, limit: usize) -> Result<ThreadReport> {
        list_threads(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn thread_scan(&self, limit: usize) -> Result<ThreadScanReport> {
        scan_threads(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn process_sessions(&self, limit: usize) -> Result<ProcessSessionReport> {
        process_sessions(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn logon_sessions(&self, options: &LogonSessionOptions) -> Result<LogonSessionReport> {
        scan_logon_sessions(&self.image, &self.kernel, &self.profile, options)
    }

    pub fn token_anomalies(&self, options: &TokenAnomalyOptions) -> Result<TokenAnomalyReport> {
        scan_token_anomalies(&self.image, &self.kernel, &self.profile, options)
    }

    pub fn job_links(&self, limit: usize) -> Result<JobLinkReport> {
        job_links(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn command_lines(&self, limit: usize) -> Result<CommandLineReport> {
        command_lines(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn account_scan(&self, limit: usize) -> Result<AccountScanReport> {
        scan_account_traces(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn cookie_scan<F>(
        &self,
        options: &CookieScanOptions,
        progress: F,
    ) -> Result<CookieScanReport>
    where
        F: FnMut(CookieScanStage),
    {
        scan_browser_cookies(&self.image, &self.kernel, &self.profile, options, progress)
    }

    pub fn clipboard_scan<F>(
        &self,
        options: &ClipboardScanOptions,
        progress: F,
    ) -> Result<ClipboardScanReport>
    where
        F: FnMut(ClipboardScanStage),
    {
        scan_clipboard(&self.image, &self.kernel, &self.profile, options, progress)
    }

    pub fn residual_scan<F>(
        &self,
        options: &ResidualScanOptions,
        progress: F,
    ) -> Result<ResidualScanReport>
    where
        F: FnMut(ResidualScanStage),
    {
        scan_residual_text(&self.image, &self.kernel, &self.profile, options, progress)
    }

    pub fn wechat_scan<F>(
        &self,
        options: &WechatScanOptions,
        progress: F,
    ) -> Result<WechatScanReport>
    where
        F: FnMut(WechatScanStage),
    {
        scan_wechat_keys(&self.image, &self.kernel, &self.profile, options, progress)
    }

    pub fn browser_sessions<F>(
        &self,
        options: &BrowserSessionOptions,
        progress: F,
    ) -> Result<BrowserSessionReport>
    where
        F: FnMut(BrowserSessionStage),
    {
        reconstruct_browser_sessions(self, options, progress)
    }

    pub fn dns_scan<F>(&self, options: &DnsScanOptions, progress: F) -> Result<DnsScanReport>
    where
        F: FnMut(BrowserSessionStage),
    {
        scan_dns_evidence(self, options, progress)
    }

    pub fn command_histories(&self, limit: usize) -> Result<CommandHistoryReport> {
        command_histories(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn consoles(&self, limit: usize) -> Result<ConsoleReport> {
        consoles(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn terminal_history<F>(
        &self,
        options: &TerminalHistoryOptions,
        progress: F,
    ) -> Result<TerminalHistoryReport>
    where
        F: FnMut(TerminalHistoryStage),
    {
        analyze_terminal_history(self, options, progress)
    }

    pub fn window_stations(&self, limit: usize) -> Result<GuiReport<WindowStationRecord>> {
        scan_window_stations(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn desktops(&self, limit: usize, pool_scanned: bool) -> Result<GuiReport<DesktopRecord>> {
        scan_gui_desktops(
            &self.image,
            &self.kernel,
            &self.profile,
            limit,
            pool_scanned,
        )
    }

    pub fn windows(&self, limit: usize) -> Result<GuiReport<WindowRecord>> {
        enumerate_gui_windows(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn window_titles(&self, limit: usize) -> Result<GuiReport<WindowTitleRecord>> {
        enumerate_window_titles(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn reconstruct_desktops(
        &self,
        options: &DesktopReconstructOptions,
    ) -> Result<DesktopReconstructReport> {
        self.reconstruct_desktops_cancellable(options, &CancellationToken::new())
    }

    pub fn reconstruct_desktops_cancellable(
        &self,
        options: &DesktopReconstructOptions,
        cancellation: &CancellationToken,
    ) -> Result<DesktopReconstructReport> {
        reconstruct_desktops(
            &self.image,
            &self.kernel,
            &self.profile,
            &self.symbol_store,
            options,
            cancellation,
        )
    }

    pub fn screen_resolutions(&self, limit: usize) -> Result<ScreenResolutionReport> {
        self.screen_resolutions_cancellable(limit, &CancellationToken::new())
    }

    pub fn screen_resolutions_cancellable(
        &self,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<ScreenResolutionReport> {
        detect_screen_resolutions(
            &self.image,
            &self.kernel,
            &self.profile,
            &self.symbol_store,
            limit,
            cancellation,
        )
    }

    pub fn gdi_bitmaps(&self, options: &GdiBitmapOptions) -> Result<GdiBitmapReport> {
        self.gdi_bitmaps_cancellable(options, &CancellationToken::new())
    }

    pub fn gdi_bitmaps_cancellable(
        &self,
        options: &GdiBitmapOptions,
        cancellation: &CancellationToken,
    ) -> Result<GdiBitmapReport> {
        recover_gdi_bitmaps(
            &self.image,
            &self.kernel,
            &self.profile,
            options,
            cancellation,
        )
    }

    pub fn injected_regions(
        &self,
        options: &InjectedRegionOptions,
    ) -> Result<InjectedRegionReport> {
        self.injected_regions_cancellable(options, &CancellationToken::new())
    }

    pub fn injected_regions_cancellable(
        &self,
        options: &InjectedRegionOptions,
        cancellation: &CancellationToken,
    ) -> Result<InjectedRegionReport> {
        find_injected_regions(
            &self.image,
            &self.kernel,
            &self.profile,
            options,
            cancellation,
        )
    }

    pub fn vad_dump(&self, options: &VadDumpOptions) -> Result<VadDumpReport> {
        self.vad_dump_cancellable(options, &CancellationToken::new())
    }

    pub fn vad_dump_cancellable(
        &self,
        options: &VadDumpOptions,
        cancellation: &CancellationToken,
    ) -> Result<VadDumpReport> {
        dump_vads(
            &self.image,
            &self.kernel,
            &self.profile,
            options,
            cancellation,
        )
    }

    pub fn environment_variables(&self, limit: usize) -> Result<EnvironmentReport> {
        environment_variables(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn process_sids(&self, pid: Option<u64>, limit: usize) -> Result<SidReport> {
        process_sids(&self.image, &self.kernel, &self.profile, pid, limit)
    }

    pub fn process_privileges(&self, limit: usize) -> Result<PrivilegeReport> {
        process_privileges(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn process_privileges_for_pid(&self, pid: u64, limit: usize) -> Result<PrivilegeReport> {
        ensure!(limit > 0, "权限结果上限必须大于零");
        let mut report = self.process_privileges(65_536)?;
        report.records.retain(|record| record.pid == pid);
        if report.records.len() > limit {
            report.complete = false;
            report
                .warnings
                .push(format!("PID {pid} 的权限结果达到 {limit} 条上限"));
        }
        report.records.truncate(limit);
        if report.records.is_empty() {
            report
                .warnings
                .push(format!("PID {pid} 未发现令牌特权记录"));
        }
        Ok(report)
    }

    pub fn dump_process_executable(
        &self,
        pid: u64,
        output: &Path,
        force: bool,
        max_output_size: u64,
    ) -> Result<PeDumpReport> {
        let processes = self.processes(65_536)?;
        let process = processes
            .processes
            .iter()
            .find(|process| process.pid == pid)
            .with_context(|| format!("未找到 PID {pid} 的活动进程"))?;
        let base = process
            .details
            .image_base
            .or(process.details.section_base_address)
            .with_context(|| format!("PID {pid} 缺少主映像基址"))?;
        self.dump_pe(Some(pid), false, base, output, force, max_output_size)
    }

    pub fn dump_process_memory(
        &self,
        pid: u64,
        output: &Path,
        max_output_size: u64,
    ) -> Result<ProcessMemoryDumpReport> {
        self.dump_process_memory_cancellable(
            pid,
            output,
            max_output_size,
            &CancellationToken::new(),
        )
    }

    pub fn dump_process_memory_cancellable(
        &self,
        pid: u64,
        output: &Path,
        max_output_size: u64,
        cancellation: &CancellationToken,
    ) -> Result<ProcessMemoryDumpReport> {
        self.dump_process_memory_with_force_cancellable(
            pid,
            output,
            max_output_size,
            false,
            cancellation,
        )
    }

    pub fn dump_process_memory_with_force(
        &self,
        pid: u64,
        output: &Path,
        max_output_size: u64,
        force: bool,
    ) -> Result<ProcessMemoryDumpReport> {
        self.dump_process_memory_with_force_cancellable(
            pid,
            output,
            max_output_size,
            force,
            &CancellationToken::new(),
        )
    }

    pub fn dump_process_memory_with_force_cancellable(
        &self,
        pid: u64,
        output: &Path,
        max_output_size: u64,
        force: bool,
        cancellation: &CancellationToken,
    ) -> Result<ProcessMemoryDumpReport> {
        dump_process_memory_with_force(
            &self.image,
            &self.kernel,
            &self.profile,
            pid,
            output,
            max_output_size,
            force,
            cancellation,
        )
    }

    pub fn service_sids(&self, limit: usize) -> Result<ServiceSidReport> {
        ensure!(limit > 0, "服务 SID 结果上限必须大于零");
        let processes = self.processes(65_536)?;
        let registry = analyze_registry(self, &processes);
        let mut warnings = registry.warnings;
        if !registry.available {
            warnings.push("注册表服务枚举不完整".to_owned());
        }
        let mut report = service_sid_report(
            registry.services.into_iter().map(|service| service.name),
            limit,
            warnings,
        );
        report.complete &= registry.available && processes.complete;
        Ok(report)
    }

    pub fn services(
        &self,
        view: ServiceView,
        limit: usize,
        correlate_registry: bool,
    ) -> Result<ServiceReport> {
        ensure!(limit > 0, "服务结果上限必须大于零");
        let processes = self.processes(65_536)?;
        if correlate_registry {
            let registry = analyze_service_registry(self, &processes);
            analyze_services(
                &self.image,
                &self.kernel,
                &self.profile,
                &processes,
                &registry.records,
                registry.available && registry.complete,
                registry.warnings,
                view,
                limit,
            )
        } else {
            analyze_services(
                &self.image,
                &self.kernel,
                &self.profile,
                &processes,
                &[],
                true,
                Vec::new(),
                view,
                limit,
            )
        }
    }

    pub fn scheduled_tasks(&self, limit: usize) -> Result<PluginReport<RegistryScheduledTask>> {
        ensure!(limit > 0, "计划任务结果上限必须大于零");
        let processes = self.processes(65_536)?;
        let registry = analyze_scheduled_task_registry(self, &processes);
        let mut records = registry.records;
        let mut warnings = registry.warnings;
        let mut complete = registry.available && registry.complete && processes.complete;
        if records.len() > limit {
            records.truncate(limit);
            complete = false;
            warnings.push(format!("注册表结构验证后的计划任务结果达到 {limit} 条上限"));
        }
        Ok(PluginReport {
            records,
            complete,
            warnings,
        })
    }

    pub fn autoruns(&self, options: &AutorunOptions) -> Result<AutorunReport> {
        scan_autoruns(self, options)
    }

    pub fn registry_print_key(
        &self,
        hive: &str,
        key: &str,
        recurse: bool,
        limit: usize,
    ) -> Result<RegistryEvidence<RegistryPrintRecord>> {
        ensure!(limit > 0, "注册表输出结果上限必须大于零");
        let processes = self.processes(65_536)?;
        Ok(print_registry_key(
            self, &processes, hive, key, recurse, limit,
        ))
    }

    pub fn registry_print_key_exact_loaded(
        &self,
        cmhive: u64,
        expected_root_path: &str,
        key: &str,
        recurse: bool,
        limit: usize,
    ) -> Result<RegistryEvidence<RegistryPrintRecord>> {
        ensure!(limit > 0, "注册表输出结果上限必须大于零");
        ensure!(cmhive != 0, "精确 Hive 的 CMHIVE 地址必须非零");
        ensure!(
            !expected_root_path.trim().is_empty(),
            "精确 Hive 的挂载根路径不能为空"
        );
        let processes = self.processes(65_536)?;
        Ok(print_registry_key_exact_loaded(
            self,
            &processes,
            cmhive,
            expected_root_path,
            key,
            recurse,
            limit,
        ))
    }

    pub fn userassist(&self, limit: usize) -> Result<RegistryEvidence<UserAssistRecord>> {
        ensure!(limit > 0, "UserAssist 结果上限必须大于零");
        let processes = self.processes(65_536)?;
        Ok(analyze_userassist(self, &processes, limit))
    }

    pub fn amcache(&self, limit: usize) -> Result<RegistryEvidence<AmcacheRecord>> {
        ensure!(limit > 0, "Amcache 结果上限必须大于零");
        let processes = self.processes(65_536)?;
        Ok(analyze_amcache(self, &processes, limit))
    }

    pub fn shimcache(&self, limit: usize) -> Result<ShimcacheReport> {
        shimcache_memory(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn system_calls(&self, view: SyscallView, limit: usize) -> Result<SyscallScanReport> {
        scan_system_calls(&self.image, &self.kernel, &self.profile, view, limit)
    }

    pub fn unhooked_system_calls(&self, limit: usize) -> Result<UnhookedSyscallReport> {
        compare_ntdll_syscalls(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn etw_patches(&self, limit: usize) -> Result<EtwPatchReport> {
        detect_etw_patches(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn skeleton_key(&self, limit: usize) -> Result<SkeletonKeyReport> {
        skeleton_key_check(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn crash_info(&self) -> Result<CrashInfoReport> {
        crash_info(&self.image)
    }

    pub fn kpcrs(&self, limit: usize) -> Result<KpcrReport> {
        list_kpcrs(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn kernel_virtmap(&self, limit: usize) -> Result<VirtualMappingReport> {
        kernel_virtmap(&self.image, &self.kernel, limit)
    }

    pub fn process_memmap(&self, pid: u64, limit: usize) -> Result<ProcessMemmapReport> {
        process_memmap(&self.image, &self.kernel, &self.profile, pid, limit)
    }

    pub fn map_strings(
        &self,
        strings_file: impl AsRef<Path>,
        offset_kind: StringOffsetKind,
        limit: usize,
    ) -> Result<StringsMapReport> {
        map_strings(
            &self.image,
            &self.kernel,
            &self.profile,
            strings_file.as_ref(),
            offset_kind,
            limit,
        )
    }

    /// Scans acquired physical ranges once, then resolves physically contiguous
    /// literal hits back to verified active-process user virtual aliases. This
    /// fast path does not claim coverage of swapped/compressed pages or matches
    /// split across non-contiguous physical frames.
    pub fn process_string(&self, options: &ProcessStringOptions) -> Result<ProcessStringReport> {
        self.process_string_cancellable(options, &CancellationToken::new())
    }

    /// Cancellable variant of [`Self::process_string`]. Cancellation is
    /// cooperative and is checked at physical-scan chunks plus process-owner
    /// attribution boundaries. A bounded in-flight page-table walk completes
    /// before cancellation is observed.
    pub fn process_string_cancellable(
        &self,
        options: &ProcessStringOptions,
        cancellation: &CancellationToken,
    ) -> Result<ProcessStringReport> {
        cancellation.check_cancelled()?;
        let mut report = locate_process_string_cancellable(
            &self.image,
            &self.kernel,
            &self.profile,
            options,
            cancellation,
        )?;
        cancellation.check_cancelled()?;
        merge_process_string_session_evidence(
            &mut report,
            self.symbol_layout_exactness,
            &self.warnings,
        );
        cancellation.check_cancelled()?;
        Ok(report)
    }

    pub fn memory_statistics(&self, mapping_limit: usize) -> Result<MemoryStatisticsReport> {
        memory_statistics(&self.image, &self.kernel, &self.profile, mapping_limit)
    }

    pub fn big_pools(
        &self,
        tags: &[String],
        show_free: bool,
        limit: usize,
    ) -> Result<BigPoolReport> {
        list_big_pools(
            &self.image,
            &self.kernel,
            &self.profile,
            tags,
            show_free,
            limit,
        )
    }

    pub fn pool_scan(&self, tags: &[[u8; 4]], limit_per_tag: usize) -> Result<PoolScanReport> {
        scan_pool_allocations(
            &self.image,
            &self.kernel,
            &self.profile,
            tags,
            limit_per_tag,
        )
    }

    pub fn drivers(&self, limit: usize) -> Result<PluginReport<DriverRecord>> {
        list_drivers(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn module_scan(&self, limit: usize) -> Result<ModuleScanReport> {
        scan_modules(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn driver_scan(&self, limit: usize) -> Result<DriverScanReport> {
        scan_driver_objects(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn driver_modules(&self, limit: usize) -> Result<DriverModuleReport> {
        correlate_drivers(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn driver_irps(&self, limit: usize) -> Result<DriverIrpReport> {
        driver_irps(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn device_tree(&self, limit: usize) -> Result<DeviceTreeReport> {
        device_tree(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn driver_inspect(
        &self,
        name_filter: Option<&str>,
        address_filter: Option<u64>,
        limit: usize,
    ) -> Result<DriverInspectReport> {
        inspect_drivers(
            &self.image,
            &self.kernel,
            &self.profile,
            name_filter,
            address_filter,
            limit,
        )
    }

    pub fn callbacks(&self, limit: usize) -> Result<CallbackReport> {
        callbacks(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn ssdt(&self, limit: usize) -> Result<SsdtReport> {
        ssdt(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn unloaded_modules(&self, limit: usize) -> Result<UnloadedModuleReport> {
        unloaded_modules(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn named_objects(&self, limit_per_kind: usize) -> Result<NamedObjectScanReport> {
        scan_named_objects(&self.image, &self.kernel, &self.profile, limit_per_kind)
    }

    pub fn mutants(&self, limit: usize) -> Result<MutantScanReport> {
        Ok(self.named_objects(limit)?.into_mutants())
    }

    pub fn symbolic_links(&self, limit: usize) -> Result<SymbolicLinkScanReport> {
        Ok(self.named_objects(limit)?.into_symbolic_links())
    }

    pub fn timers(&self, limit: usize) -> Result<TimerReport> {
        list_timers(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn malfind(&self, pid: Option<u64>, limit: usize) -> Result<MalfindReport> {
        malfind(&self.image, &self.kernel, &self.profile, pid, limit)
    }

    pub fn cobaltstrikescan(
        &self,
        options: &CobaltStrikeScanOptions,
    ) -> Result<CobaltStrikeScanReport> {
        self.cobaltstrikescan_cancellable(options, &CancellationToken::new())
    }

    pub fn cobaltstrikescan_cancellable(
        &self,
        options: &CobaltStrikeScanOptions,
        cancellation: &CancellationToken,
    ) -> Result<CobaltStrikeScanReport> {
        scan_cobaltstrike_configs(
            &self.image,
            &self.kernel,
            &self.profile,
            options,
            cancellation,
        )
    }

    pub fn process_image_anomalies(
        &self,
        view: ProcessImageView,
        limit: usize,
    ) -> Result<ProcessImageAnomalyReport> {
        process_image_anomalies(&self.image, &self.kernel, &self.profile, view, limit)
    }

    pub fn dlls(
        &self,
        pid: Option<u64>,
        per_process_limit: usize,
    ) -> Result<PluginReport<DllRecord>> {
        list_dlls(
            &self.image,
            &self.kernel,
            &self.profile,
            pid,
            per_process_limit,
        )
    }

    pub fn ldr_modules(&self, pid: Option<u64>, limit: usize) -> Result<LdrModulesReport> {
        ldr_modules(&self.image, &self.kernel, &self.profile, pid, limit)
    }

    pub fn iat(&self, pid: Option<u64>, limit: usize) -> Result<IatReport> {
        list_iat(&self.image, &self.kernel, &self.profile, pid, limit)
    }

    pub fn pe_symbols(
        &self,
        source: PeSymbolSource,
        pid: Option<u64>,
        module: Option<&str>,
        name: Option<&str>,
        limit: usize,
    ) -> Result<PeSymbolReport> {
        pe_symbols(
            &self.image,
            &self.kernel,
            &self.profile,
            source,
            pid,
            module,
            name,
            limit,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dump_pe(
        &self,
        pid: Option<u64>,
        kernel_module: bool,
        base: u64,
        output: &Path,
        force: bool,
        max_output_size: u64,
    ) -> Result<PeDumpReport> {
        dump_pe(
            &self.image,
            &self.kernel,
            &self.profile,
            pid,
            kernel_module,
            base,
            output,
            force,
            max_output_size,
        )
    }

    pub fn vads(&self, pid: u64, limit: usize) -> Result<PluginReport<VadRecord>> {
        list_vads(&self.image, &self.kernel, &self.profile, pid, limit)
    }

    pub fn vad_regex(
        &self,
        pid: Option<u64>,
        pattern: &str,
        chunk_size: usize,
        overlap: usize,
        limit: usize,
    ) -> Result<VadRegexReport> {
        vad_regex_scan(
            &self.image,
            &self.kernel,
            &self.profile,
            pid,
            pattern,
            chunk_size,
            overlap,
            limit,
        )
    }

    pub fn vad_yara(
        &self,
        pid: Option<u64>,
        rule_files: &[PathBuf],
        chunk_size: usize,
        overlap: usize,
        limit: usize,
    ) -> Result<VadYaraReport> {
        vad_yara_scan(
            &self.image,
            &self.kernel,
            &self.profile,
            pid,
            rule_files,
            chunk_size,
            overlap,
            limit,
        )
    }

    pub fn hives(&self, limit: usize) -> Result<PluginReport<HiveRecord>> {
        list_hives(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn hive_scan(&self, limit: usize) -> Result<PluginReport<HiveScanRecord>> {
        scan_hives(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn get_cell_routines(&self, limit: usize) -> Result<GetCellRoutineReport> {
        check_get_cell_routines(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn hashdump(&self, limit: usize) -> Result<RegistryEvidence<HashdumpRecord>> {
        hashdump(self, limit)
    }

    pub fn cachedump(&self, limit: usize) -> Result<RegistryEvidence<CachedumpRecord>> {
        cachedump(self, limit)
    }

    pub fn lsadump(&self, limit: usize) -> Result<RegistryEvidence<LsaSecretRecord>> {
        lsadump(self, limit)
    }

    pub fn handles(&self, pid: u64, limit: usize) -> Result<PluginReport<HandleRecord>> {
        list_handles(&self.image, &self.kernel, &self.profile, pid, limit)
    }

    pub fn pipes(&self, options: &PipeScanOptions) -> Result<PipeScanReport> {
        scan_pipes(&self.image, &self.kernel, &self.profile, options)
    }

    pub fn prefetch(&self, options: &PrefetchScanOptions) -> Result<PrefetchScanReport> {
        scan_prefetch(&self.image, &self.kernel, &self.profile, options)
    }

    pub fn network(&self, limit: usize) -> Result<PluginReport<NetworkRecord>> {
        scan_network(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn network_cancellable(
        &self,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<PluginReport<NetworkRecord>> {
        scan_network_cancellable(
            &self.image,
            &self.kernel,
            &self.profile,
            limit,
            cancellation,
        )
    }

    pub fn netstat(&self, limit: usize) -> Result<NetstatReport> {
        netstat(
            &self.image,
            &self.kernel,
            &self.profile,
            &self.symbol_store,
            limit,
        )
    }

    pub fn packet_scan<F>(
        &self,
        options: &PacketScanOptions,
        progress: F,
    ) -> Result<PacketScanArtifacts>
    where
        F: FnMut(PacketScanStage),
    {
        scan_memory_packets(self, options, progress)
    }

    pub fn files(&self, limit: usize) -> Result<FileScanReport> {
        scan_files(&self.image, &self.kernel, &self.profile, limit)
    }

    pub fn files_cancellable(
        &self,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<FileScanReport> {
        scan_files_cancellable(
            &self.image,
            &self.kernel,
            &self.profile,
            limit,
            cancellation,
        )
    }

    pub fn mft(&self, view: MftView, limit: usize) -> Result<MftScanReport> {
        scan_mft(&self.image, view, limit)
    }

    pub fn mft_cancellable(
        &self,
        view: MftView,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<MftScanReport> {
        scan_mft_cancellable(&self.image, view, limit, cancellation)
    }

    pub fn mbrs(&self, limit: usize) -> Result<MbrScanReport> {
        scan_mbr(&self.image, limit)
    }

    pub fn recover_file(
        &self,
        file_object: u64,
        output_path: impl AsRef<Path>,
        source: DumpSource,
        max_size: u64,
        force: bool,
    ) -> Result<DumpFileReport> {
        let output_path = output_path.as_ref();
        let mut policy = OutputPolicy::new(force);
        for source in self.image.sources() {
            policy.protect_file("memory_image_or_sidecar", &source.path);
        }
        policy.output(OutputTarget::file("recovered_file", output_path));
        policy.preflight()?;
        let mut report = None;
        policy.write_file_atomic(output_path, |output| {
            report = Some(dump_file(
                &self.image,
                &self.kernel,
                &self.profile,
                file_object,
                output,
                source,
                max_size,
            )?);
            Ok(())
        })?;
        report.context("恢复文件写出未生成报告")
    }

    pub fn recover_hive(
        &self,
        cmhive: u64,
        registry_process_dtb: Option<u64>,
        output_path: impl AsRef<Path>,
        max_size: u64,
        force: bool,
    ) -> Result<DumpFileReport> {
        let output_path = output_path.as_ref();
        let mut policy = OutputPolicy::new(force);
        for source in self.image.sources() {
            policy.protect_file("memory_image_or_sidecar", &source.path);
        }
        policy.output(OutputTarget::file("recovered_hive", output_path));
        policy.preflight()?;
        let mut report = None;
        policy.write_file_atomic(output_path, |output| {
            report = Some(dump_hive(
                &self.image,
                &self.kernel,
                &self.profile,
                cmhive,
                registry_process_dtb,
                output,
                max_size,
            )?);
            Ok(())
        })?;
        report.context("Hive 恢复写出未生成报告")
    }

    pub fn recover_hive_memory(
        &self,
        cmhive: u64,
        registry_process_dtb: Option<u64>,
        max_size: u64,
    ) -> Result<HiveMemoryImage> {
        recover_hive_bytes(
            &self.image,
            &self.kernel,
            &self.profile,
            cmhive,
            registry_process_dtb,
            max_size,
        )
    }
}

fn load_profile(
    image: &MemoryImage,
    options: &SessionOptions,
) -> Result<(KernelProfile, Vec<String>, SymbolLayoutExactness)> {
    if let Some(path) = &options.profile {
        let profile = serde_json::from_reader::<_, KernelProfile>(BufReader::new(
            File::open(path).with_context(|| format!("无法打开配置文件 {}", path.display()))?,
        ))?;
        return Ok((profile, Vec::new(), SymbolLayoutExactness::Exact));
    }
    if let Some(path) = &options.pdb {
        return Ok((
            build_eprocess_profile(path)?,
            Vec::new(),
            SymbolLayoutExactness::Exact,
        ));
    }

    match resolve_kernel_pdb_with_store(image, &options.symbol_store) {
        Ok(resolved) => {
            if let Some(profile) = legacy_windows_profile(
                &resolved.record.pdb_name,
                &resolved.record.guid,
                resolved.record.age,
            ) {
                return Ok((
                    profile,
                    vec![
                        "已识别 Windows XP SP2 x86 PAE 精确内核指纹；公共 PDB 不含私有类型，使用受 CodeView GUID 约束的内置基础结构布局"
                            .to_owned(),
                    ],
                    SymbolLayoutExactness::Exact,
                ));
            }
            Ok((
                build_eprocess_profile(&resolved.path)?,
                Vec::new(),
                SymbolLayoutExactness::Exact,
            ))
        }
        Err(exact_error) if options.allow_compatible_local_symbols => {
            let system_root = std::env::var_os("SystemRoot")
                .context("目标内核的精确 PDB 不可用，且未设置 SystemRoot")?;
            let local_kernel = PathBuf::from(system_root)
                .join("System32")
                .join("ntoskrnl.exe");
            let local_image = MemoryImage::open(&local_kernel).with_context(|| {
                format!(
                    "目标内核的精确 PDB 解析失败（{exact_error:#}）；无法打开兼容的本地内核 {}",
                    local_kernel.display()
                )
            })?;
            let resolved = resolve_kernel_pdb_with_store(&local_image, &options.symbol_store)
                .with_context(|| {
                    format!(
                        "目标内核的精确 PDB 解析失败（{exact_error:#}）；兼容本地符号回退也失败"
                    )
                })?;
            let profile = build_eprocess_profile(&resolved.path)?;
            let warning = format!(
                "目标内核的精确 PDB 不可用；正在使用本地 {} 的类型布局 {}，内核全局变量仍从目标镜像推导",
                local_kernel.display(),
                profile.pdb_guid
            );
            Ok((
                profile,
                vec![warning],
                SymbolLayoutExactness::CompatibleLocal,
            ))
        }
        Err(error) => Err(error),
    }
}

fn merge_process_string_session_evidence(
    report: &mut ProcessStringReport,
    exactness: SymbolLayoutExactness,
    warnings: &[String],
) {
    let code = match exactness {
        SymbolLayoutExactness::Exact => "symbols.session-notice",
        SymbolLayoutExactness::CompatibleLocal => "symbols.compatible-local-layout",
    };
    let severity = match exactness {
        SymbolLayoutExactness::Exact => EvidenceWarningSeverity::Info,
        SymbolLayoutExactness::CompatibleLocal => EvidenceWarningSeverity::Warning,
    };
    let mut evidence_warnings = warnings
        .iter()
        .map(|message| {
            let mut warning =
                EvidenceWarning::new(code, severity, message.clone(), "analysis-session.symbols");
            warning.context.insert(
                "layout_exactness".to_owned(),
                serde_json::Value::String(exactness.evidence_name().to_owned()),
            );
            warning
        })
        .collect::<Vec<_>>();

    // The fallback currently always emits a human-readable warning. Preserve
    // the evidence invariant even if a future caller constructs the typed state
    // without one.
    if !exactness.is_exact() && evidence_warnings.is_empty() {
        let mut warning = EvidenceWarning::new(
            code,
            severity,
            "Windows 会话使用非精确的本机兼容符号布局，不能声明进程字符串归属搜索完整",
            "analysis-session.symbols",
        );
        warning.context.insert(
            "layout_exactness".to_owned(),
            serde_json::Value::String(exactness.evidence_name().to_owned()),
        );
        evidence_warnings.push(warning);
    }

    let remaining = PROCESS_STRING_WARNING_LIMIT.saturating_sub(report.warnings.len());
    if evidence_warnings.len() > remaining {
        evidence_warnings.truncate(remaining);
        report.warnings_truncated = true;
        report.truncated = true;
    }
    report.warnings.extend(evidence_warnings);
    if let Some(limit) = report
        .limits
        .iter_mut()
        .find(|limit| limit.name == "warning_limit")
    {
        limit.observed = u64::try_from(report.warnings.len()).ok();
        limit.reached = Some(report.warnings_truncated);
    }
    if !exactness.is_exact() {
        report.mapped_physical_hits_is_lower_bound = true;
        report.unmapped_physical_hits = None;
    }
    report.complete &= exactness.is_exact() && !report.warnings_truncated;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_string_report_for_session_test() -> ProcessStringReport {
        ProcessStringReport {
            available: true,
            complete: true,
            scope: crate::evidence::EvidenceScope::new("test"),
            query: "needle".to_owned(),
            encodings: Vec::new(),
            records: Vec::new(),
            physical_hits: 0,
            mapped_physical_hits: 0,
            unmapped_physical_hits: Some(1),
            mapped_physical_hits_is_lower_bound: false,
            processes_enumerated: 0,
            process_address_spaces: 0,
            process_address_spaces_walked: 0,
            reverse_page_table_pages_read: 0,
            reverse_page_table_read_failures: 0,
            reverse_read_failure_details_truncated: false,
            reverse_page_table_entries_examined: 0,
            reverse_traversal_limit_reached_address_spaces: 0,
            reverse_command_entry_limit_reached: false,
            reverse_command_address_spaces_skipped: 0,
            reverse_aliases_retained: 0,
            reverse_alias_limit_reached: false,
            reverse_alias_address_spaces_skipped: 0,
            mapping_failures: 0,
            mapping_limit_exceeded_address_space_pages: 0,
            mapping_limit_exceeded_details_truncated: false,
            virtual_revalidation_mismatches: 0,
            virtual_revalidation_read_failures: 0,
            virtual_revalidation_missing_ranges_truncated: false,
            page_table_missing_ranges_truncated: false,
            bytes_scanned: 0,
            physical_scan_seconds: 0.0,
            owner_mapping_seconds: 0.0,
            elapsed_seconds: 0.0,
            gib_per_second: 0.0,
            truncated: false,
            warnings_truncated: false,
            warnings: Vec::new(),
            limits: Vec::new(),
            missing_ranges: Vec::new(),
        }
    }

    #[test]
    fn exact_builtin_layout_notice_does_not_reduce_process_string_completeness() {
        let mut report = process_string_report_for_session_test();
        merge_process_string_session_evidence(
            &mut report,
            SymbolLayoutExactness::Exact,
            &["CodeView 指纹约束的 XP 内置布局".to_owned()],
        );

        assert!(report.complete);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].code, "symbols.session-notice");
        assert_eq!(report.warnings[0].severity, EvidenceWarningSeverity::Info);
        assert_eq!(report.warnings[0].source, "analysis-session.symbols");
        assert_eq!(report.warnings[0].context["layout_exactness"], "exact");
        assert!(!report.mapped_physical_hits_is_lower_bound);
        assert_eq!(report.unmapped_physical_hits, Some(1));
    }

    #[test]
    fn compatible_local_layout_is_structurally_incomplete() {
        let mut report = process_string_report_for_session_test();
        merge_process_string_session_evidence(
            &mut report,
            SymbolLayoutExactness::CompatibleLocal,
            &["使用本机兼容 PDB 类型布局".to_owned()],
        );

        assert!(!report.complete);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].code, "symbols.compatible-local-layout");
        assert_eq!(
            report.warnings[0].severity,
            EvidenceWarningSeverity::Warning
        );
        assert_eq!(
            report.warnings[0].context["layout_exactness"],
            "compatible_local"
        );
        assert!(report.mapped_physical_hits_is_lower_bound);
        assert_eq!(report.unmapped_physical_hits, None);
    }

    #[test]
    fn compatible_local_layout_cannot_silently_omit_evidence_warning() {
        let mut report = process_string_report_for_session_test();
        merge_process_string_session_evidence(
            &mut report,
            SymbolLayoutExactness::CompatibleLocal,
            &[],
        );

        assert!(!report.complete);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].code, "symbols.compatible-local-layout");
    }

    #[test]
    fn process_string_session_warning_merge_respects_the_report_cap() {
        let mut report = process_string_report_for_session_test();
        report.unmapped_physical_hits = Some(0);
        report.warnings = (0..PROCESS_STRING_WARNING_LIMIT)
            .map(|index| {
                EvidenceWarning::new(
                    format!("existing.{index}"),
                    EvidenceWarningSeverity::Warning,
                    "existing",
                    "test",
                )
            })
            .collect::<Vec<_>>();
        merge_process_string_session_evidence(
            &mut report,
            SymbolLayoutExactness::Exact,
            &["one more exact-symbol notice".to_owned()],
        );

        assert_eq!(report.warnings.len(), PROCESS_STRING_WARNING_LIMIT);
        assert!(report.warnings_truncated);
        assert!(report.truncated);
        assert!(!report.complete);
        assert!(!report.mapped_physical_hits_is_lower_bound);
        assert_eq!(report.unmapped_physical_hits, Some(0));
    }
}
