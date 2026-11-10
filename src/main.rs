use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufWriter, IsTerminal, Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use sha2::{Digest, Sha256};
use starmem::accounts::AccountAction;
use starmem::acquisition::{AcquisitionInfoOptions, analyze_acquisition_info};
use starmem::address::X64AddressSpace;
use starmem::artifacts::{ArtifactExportOptions, ArtifactSelection, export_artifacts};
use starmem::browser_artifacts::{
    BrowserArtifactOptions, BrowserArtifactOwnerOptions,
    parse_browser_history_artifacts_from_file_scan,
};
use starmem::browser_session::{
    BrowserSessionKind, BrowserSessionOptions, BrowserSessionReport, BrowserSessionStage,
};
use starmem::build_info::current_build_info;
use starmem::clipboard::{
    ClipboardScanOptions, ClipboardScanStage, ResidualScanOptions, ResidualScanStage,
};
use starmem::cobaltstrike::CobaltStrikeScanOptions;
use starmem::collection::{DatabaseCollectionEvent, DatabaseCollectionOptions, collect_to_sqlite};
use starmem::cookies::{CookieScanOptions, CookieScanStage, CookieSource};
use starmem::csv_report::write_csv_report;
use starmem::dns_scan::DnsScanOptions;
use starmem::downloads::scan_download_traces;
use starmem::eventlog::{
    EventTimelineOptions, analyze_event_logs, write_event_timeline_csv_writer,
};
use starmem::evidence::{
    DigestReference, EngineIdentity, EvidenceEnvelope, EvidenceLimit, EvidenceLimitKind,
    EvidenceScope, EvidenceWarning, EvidenceWarningSeverity, MissingRange, RawEvidenceSummary,
    SourceIdentity, SourceModifiedTime, SymbolIdentity, normalize_legacy_warnings,
    source_identity_for_memory_image, windows_symbol_identity,
};
use starmem::image::{ImageFormat, ImageOpenOptions, MemoryImage, QevmPhysicalLayout};
use starmem::linux::{
    LinuxAnalysisSession, LinuxKernelSessionEvidence, LinuxKernelSessionOptions,
    discover_linux_banners, is_supported_linux_physical_image, open_linux_kernel_session,
    probe_linux_memory,
};
use starmem::linux_kernel_plugins::{
    LinuxCheckSyscallOptions, LinuxKmsgOptions, LinuxModuleSelector, LinuxMountInfoOptions,
    LinuxSyscallTable, linux_check_syscall, linux_kallsyms, linux_kmsg, linux_lsmod,
    linux_module_extract, linux_modxview, linux_mountinfo,
};
use starmem::linux_passwd::{LinuxPasswdCandidateSource, LinuxPasswdRecoveryStatus};
use starmem::linux_symbols::{
    LinuxSymbolDiagnosticOptions, LinuxSymbolFeature, diagnose_local_linux_symbols,
    install_linux_isf_for_image, refresh_remote_linux_isf, resolve_remote_linux_isf,
};
use starmem::output_policy::{OutputPolicy, OutputTarget};
use starmem::packet_scan::{
    InternetProtocol, PacketScanOptions, PacketScanStage, TransportProtocol,
};
use starmem::profile::build_eprocess_profile;
use starmem::raw_objects::{extract_raw_objects, write_raw_objects_jsonl_with_policy};
use starmem::resources::ANALYSIS_THREAD_STACK_BYTES;
use starmem::scan::{COMMON_POOL_TAGS, scan_exact};
use starmem::session::{AnalysisSession as CoreAnalysisSession, SessionOptions};
use starmem::sqlite_recover::{SqliteRecoverOptions, recover_sqlite};
use starmem::symbols::{
    SymbolStore, codeview_from_virtual_pe, default_symbol_cache, discover_codeview, inspect_pdb,
    select_unique_record, symbol_store,
};
use starmem::system::registry::analyze_registry_with_system_hive;
use starmem::system::{
    ForensicTimestamp, analyze_system_artifacts, analyze_system_info, analyze_system_info_quick,
};
use starmem::terminal_history::{
    TerminalHistoryOptions, TerminalHistoryReport, TerminalHistorySource, TerminalHistoryStage,
    TerminalKind, TerminalProcessRole,
};
use starmem::wechat::{
    WechatKeyConfidence, WechatKeyContext, WechatKeyEncoding, WechatKeyKind, WechatProcessRole,
    WechatScanOptions, WechatScanStage,
};
use starmem::windows::autorun_plugins::AutorunOptions;
use starmem::windows::check_pslist::{
    CheckPslistConfidence, CheckPslistOptions, CheckPslistVerdict,
};
use starmem::windows::desktop_reconstruct::DesktopReconstructOptions;
use starmem::windows::files::DumpSource;
use starmem::windows::gdi_bitmap::GdiBitmapOptions;
use starmem::windows::injected_regions::InjectedRegionOptions;
use starmem::windows::logon_plugins::LogonSessionOptions;
use starmem::windows::open_files::{OpenFileOptions, scan_open_files};
use starmem::windows::pipe_plugins::PipeScanOptions;
use starmem::windows::plugins::find_handle_owners;
use starmem::windows::prefetch_plugins::PrefetchScanOptions;
use starmem::windows::process_string::{
    DEFAULT_PROCESS_STRING_REVERSE_ALIAS_LIMIT, DEFAULT_PROCESS_STRING_REVERSE_ENTRY_LIMIT,
    ProcessStringEncodingSelection, ProcessStringOptions,
};
use starmem::windows::token_plugins::{TokenAnomalyOptions, TokenAnomalySeverity};
use starmem::windows::usb_history::{
    USB_HISTORY_WARNING_LIMIT, UsbHistoryOptions, analyze_usb_history,
};
use starmem::windows::vad_dump::VadDumpOptions;
use starmem::windows_execution::{
    WindowsExecutionOptions, WindowsExecutionStage, analyze_windows_execution,
};
use starmem::windows_recent_files::{
    WindowsRecentFilesOptions, WindowsRecentFilesStage, analyze_windows_recent_files,
};
use starmem::windows_timeline::{
    WindowsTimelineOptions, WindowsTimelineReport, WindowsTimelineStage, analyze_windows_timeline,
};

mod cli_help_en;

static CSV_OUTPUT: OnceLock<PathBuf> = OnceLock::new();
static RAW_OBJECTS_OUTPUT: OnceLock<PathBuf> = OnceLock::new();
static EVIDENCE_OUTPUT_CONTEXT: OnceLock<EvidenceOutputContext> = OnceLock::new();
static OUTPUT_POLICY: OnceLock<OutputPolicy> = OnceLock::new();
static IMAGE_OPEN_OPTIONS: OnceLock<ImageOpenOptions> = OnceLock::new();
static WINDOWS_SYMBOL_IDENTITY: OnceLock<Mutex<Option<SymbolIdentity>>> = OnceLock::new();

/// CLI-local wrapper that records the exact Windows symbol/profile identity consumed by every
/// session. The library type remains unchanged; `Deref` preserves its complete public API.
struct AnalysisSession(CoreAnalysisSession);

impl AnalysisSession {
    fn open(path: impl AsRef<Path>, options: SessionOptions) -> Result<Self> {
        let session = CoreAnalysisSession::open(path, options)?;
        Self::from_core(session)
    }

    fn from_image(image: MemoryImage, options: SessionOptions) -> Result<Self> {
        let session = CoreAnalysisSession::from_image(image, options)?;
        Self::from_core(session)
    }

    fn from_core(session: CoreAnalysisSession) -> Result<Self> {
        remember_windows_symbol_identity(session.profile())?;
        Ok(Self(session))
    }
}

impl Deref for AnalysisSession {
    type Target = CoreAnalysisSession;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn remember_windows_symbol_identity(profile: &starmem::profile::KernelProfile) -> Result<()> {
    let identity = windows_symbol_identity(profile)?;
    let mut current = WINDOWS_SYMBOL_IDENTITY
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| anyhow::anyhow!("Windows 符号身份状态锁已损坏"))?;
    *current = identity;
    Ok(())
}

fn current_image_open_options() -> ImageOpenOptions {
    IMAGE_OPEN_OPTIONS.get().cloned().unwrap_or_default()
}

fn open_memory_image(path: impl AsRef<Path>) -> Result<MemoryImage> {
    MemoryImage::open_with_options(path, current_image_open_options())
}

#[derive(Debug, Clone)]
struct EvidenceOutputContext {
    command: String,
    source_identity: SourceIdentity,
    scope: EvidenceScope,
    limits: Vec<EvidenceLimit>,
}

#[derive(Default)]
struct TerminalProgressObserver {
    display: Mutex<TerminalProgressDisplay>,
}

#[derive(Default)]
struct TerminalProgressDisplay {
    tasks: HashMap<u64, TerminalProgressTask>,
    active: Option<u64>,
    previous_width: usize,
}

struct TerminalProgressTask {
    label: String,
    total: u64,
    current: u64,
    started: Instant,
    last_draw: Instant,
}

impl starmem::progress::ProgressObserver for TerminalProgressObserver {
    fn started(&self, id: u64, label: &str, total: u64) {
        let Ok(mut display) = self.display.lock() else {
            return;
        };
        if display.active.is_some() {
            write_terminal_progress(&mut display, "", true);
        }
        let now = Instant::now();
        display.tasks.insert(
            id,
            TerminalProgressTask {
                label: label.to_owned(),
                total,
                current: 0,
                started: now,
                last_draw: now,
            },
        );
        display.active = Some(id);
        let line = render_terminal_progress(display.tasks.get(&id).unwrap(), None);
        write_terminal_progress(&mut display, &line, false);
    }

    fn advanced(&self, id: u64, current: u64, total: u64) {
        let Ok(mut display) = self.display.lock() else {
            return;
        };
        let is_active = display.active == Some(id);
        let Some(task) = display.tasks.get_mut(&id) else {
            return;
        };
        // Parallel workers can reach the observer out of order after updating
        // the shared atomic counter.  Never let a late callback move the bar
        // backwards.
        task.current = task.current.max(current.min(total));
        task.total = total;
        let now = Instant::now();
        if !is_active
            || (now.duration_since(task.last_draw) < Duration::from_millis(100)
                && task.current < task.total)
        {
            return;
        }
        task.last_draw = now;
        let line = render_terminal_progress(task, None);
        write_terminal_progress(&mut display, &line, false);
    }

    fn finished(&self, id: u64, current: u64, total: u64, success: bool) {
        let Ok(mut display) = self.display.lock() else {
            return;
        };
        let Some(mut task) = display.tasks.remove(&id) else {
            return;
        };
        task.current = current.min(total);
        task.total = total;
        if display.active == Some(id) {
            let line = render_terminal_progress(&task, Some(success));
            write_terminal_progress(&mut display, &line, true);
            display.active = display.tasks.keys().copied().max();
            if let Some(active) = display.active {
                let line = render_terminal_progress(display.tasks.get(&active).unwrap(), None);
                write_terminal_progress(&mut display, &line, false);
            }
        }
    }
}

#[derive(Parser)]
#[command(name = "starmem", version, about = "高速内存取证引擎")]
struct Cli {
    /// 输出便于程序处理的 JSON。
    #[arg(long, global = true, conflicts_with = "csv")]
    json: bool,

    /// 将当前插件的完整结构化报告写为兼容 Excel 的 CSV；使用 - 输出到标准输出。
    #[arg(long, global = true, value_name = "文件", conflicts_with = "json")]
    csv: Option<PathBuf>,

    /// 并行工作线程数；0 表示使用全部逻辑处理器。
    #[arg(long, global = true, default_value_t = 0)]
    threads: usize,

    /// 禁用交互终端中的动态分析进度条。
    #[arg(long, global = true)]
    no_progress: bool,

    /// 允许替换普通输出；任何受保护输入及目录中的无关文件仍不可覆盖。
    #[arg(long, global = true)]
    force: bool,

    /// 将可复核原始对象按稳定 evidence_id 排序写为 JSONL。
    #[arg(long, global = true, value_name = "文件.jsonl", requires = "json")]
    raw_objects: Option<PathBuf>,

    /// 显式指定 VMware VMSS/VMSN metadata；默认自动发现唯一同 stem sidecar。
    #[arg(long, global = true, value_name = "VMSS_OR_VMSN")]
    metadata: Option<PathBuf>,

    /// QEVM 中承载来宾系统内存的 RAMBlock 名称（通常为 pc.ram）。
    #[arg(
        long,
        global = true,
        value_name = "NAME",
        requires_all = ["qevm_below_4g_length", "qevm_above_4g_base"]
    )]
    qevm_ram_block: Option<String>,

    /// QEVM RAMBlock 从物理地址 0 开始映射的字节数；支持十进制或 0x 十六进制。
    #[arg(
        long,
        global = true,
        value_name = "BYTES",
        requires_all = ["qevm_ram_block", "qevm_above_4g_base"]
    )]
    qevm_below_4g_length: Option<String>,

    /// QEVM 剩余高端 RAM 的来宾物理基址；支持十进制或 0x 十六进制。
    #[arg(
        long,
        global = true,
        value_name = "ADDRESS",
        requires_all = ["qevm_ram_block", "qevm_below_4g_length"]
    )]
    qevm_above_4g_base: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 显示当前二进制、源码和公共契约的可复现构建身份。
    #[command(name = "build-info")]
    BuildInfo,
    /// 执行所有无需额外输入的只读插件，并将结构化结果汇总到 SQLite 数据库。
    Collect(CollectArgs),
    /// 检测镜像采集格式并显示物理布局。
    Info { image: PathBuf },
    /// 定位并验证 Windows 内核启动上下文。
    WindowsInfo(WindowsInfoArgs),
    /// 根据内核、进程、令牌、时钟和网络证据生成系统取证概况。
    SystemInfo(SystemInfoArgs),
    /// 一次恢复注册表并输出打印机、策略、安全、WMI、RDP、网络与 WiFi 等系统证据。
    SystemArtifacts(PluginArgs),
    /// 从经过精确符号验证的 DWM 合成表面恢复屏幕分辨率。
    #[command(name = "screen-resolution")]
    ScreenResolution(PluginArgs),
    /// 显示 Windows 崩溃转储头、错误检查信息和采集元数据。
    Crashinfo { image: PathBuf },
    /// 聚合容器、镜像时钟与采集工具进程，解释内存采集时间边界。
    #[command(name = "acquisition-info")]
    AcquisitionInfo(AcquisitionInfoArgs),
    /// 从 KiProcessorBlock 枚举各处理器的 KPCR/KPRCB 状态。
    Kpcrs(PluginArgs),
    /// 检查镜像中的硬件调试寄存器和活动断点。
    Debugregisters(PluginArgs),
    /// 遍历内核页表并输出合并后的虚拟地址映射。
    Virtmap(MappingArgs),
    /// 显示采集镜像、物理区间和内核映射统计。
    Statistics(MappingArgs),
    /// 遍历指定进程页表并输出合并后的用户空间映射。
    Memmap(ProcessMappingArgs),
    /// 枚举内核大页池跟踪表。
    Bigpools(BigPoolArgs),
    /// 单次遍历物理内存并扫描多个池标签。
    Poolscanner(PoolScannerArgs),
    /// 将预先生成的字符串偏移映射到内核或进程虚拟地址。
    Strings(StringsArgs),
    /// 一次物理扫描 ASCII/UTF-8 与 UTF-16LE 字面字符串，并反查活动进程归属。
    #[command(name = "windows.process-string", visible_alias = "process-string")]
    WindowsProcessString(ProcessStringArgs),
    /// 在已采集的物理内存范围中扫描精确字节序列。
    Scan(ScanArgs),
    /// 扫描下载命令、URL、远端 IP 和可疑载荷名称。
    Downloadscan(DownloadScanArgs),
    /// 恢复浏览器进程内明文 Cookie，并解析驻留的 Chromium、Firefox 和旧式 Cookie 文件。
    Cookiescan(CookieScanArgs),
    /// 解析 Window Station、格式数组、句柄和数据块，恢复活动剪切板内容。
    Clipboardscan(ClipboardScanArgs),
    /// 扫描邮箱、URL、IPv4、Windows 路径、命令及用户指定的进程文本残留。
    Residualscan(ResidualScanArgs),
    /// 从微信进程地址空间恢复 SQLCipher 数据库密钥候选及 salt。
    Wechatscan(WechatScanArgs),
    /// 聚合浏览器进程、Cookie、下载、History 与 Login Data，重建可验证的浏览器会话证据。
    BrowserSession(BrowserSessionArgs),
    /// 从 Chromium History 数据库恢复 URL 访问历史。
    BrowserHistory(BrowserHistoryArgs),
    /// 恢复浏览器 Cookie、下载 URL 与会话中的域名证据，并关联进程归属。
    Dnsscan(BrowserSessionArgs),
    /// 扫描账户创建、删除、改密、启停及本地组变更痕迹。
    Accountscan(AccountScanArgs),
    /// 通过镜像中的页表转换 x64 虚拟地址。
    Virt2phys(Virt2physArgs),
    /// 查找、下载和检查 Microsoft PDB 符号。
    Symbols {
        #[command(subcommand)]
        command: SymbolCommand,
    },
    /// 从内核 PDB 生成精简的 _EPROCESS 字段配置。
    Profile {
        pdb: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// 遍历 Windows PsActiveProcessHead 或 Linux task_struct.tasks 活动进程链表。
    Pslist(PslistArgs),
    /// 无需 Linux profile，交叉恢复 hostname、登录用户与内核版本。
    #[command(name = "linux.info", visible_alias = "linux-info")]
    LinuxInfo { image: PathBuf },
    /// Linux 应急响应：权限、线程、ELF、可疑映射、文件内容、持久化与时间线。
    #[command(name = "linux.ir", visible_alias = "linux-ir")]
    LinuxIr(LinuxIrArgs),
    /// Linux 内核应急响应：系统、网络接口、回调、追踪与设备，不依赖活动任务链。
    #[command(name = "linux.ir-kernel", visible_alias = "linux-ir-kernel")]
    LinuxIrKernel(LinuxIrKernelArgs),
    /// 定位 Linux _stext，并通过已验证页表给出首条内核指令的虚拟/物理地址。
    #[command(name = "linux.kaslr", visible_alias = "linux-kaslr")]
    LinuxKaslr(LinuxKernelArgs),
    /// 从 Linux 进程 mm_struct 的参数区间恢复 argv/命令行。
    #[command(name = "linux.cmdline", visible_alias = "linux-cmdline")]
    LinuxCmdline(LinuxProcessTextArgs),
    /// 汇总 Linux 活动进程状态与命令行；argv 不可用时明确退化为 comm。
    #[command(name = "linux.psaux", visible_alias = "linux-psaux")]
    LinuxPsaux(LinuxProcessTextArgs),
    /// 从 Linux 进程 mm_struct 的环境区间恢复环境变量。
    #[command(name = "linux.envars", visible_alias = "linux-envars")]
    LinuxEnvars(LinuxProcessTextArgs),
    /// 遍历 Linux files_struct/fdtable 并解析打开文件路径。
    #[command(name = "linux.lsof", visible_alias = "linux-lsof")]
    LinuxLsof(LinuxLsofArgs),
    /// 从活动进程的已验证 socket FD 恢复网络与 UNIX socket 端点。
    #[command(name = "linux.sockstat", visible_alias = "linux-sockstat")]
    LinuxSockstat(LinuxLsofArgs),
    /// 遍历 Linux 进程 VMA 链表或 Maple Tree，生成 /proc/PID/maps 等价证据。
    #[command(name = "linux.proc.maps", visible_alias = "linux-proc-maps")]
    LinuxProcMaps(LinuxProcMapsArgs),
    /// 按 VMA 将 Linux 进程驻留虚拟内存导出到目录；缺页结果保留为 .partial。
    #[command(name = "linux.proc.dump", visible_alias = "linux-proc-dump")]
    LinuxProcDump(LinuxProcDumpArgs),
    /// 从活动 Bash 堆中恢复与 #epoch 时间戳关联的 HIST_ENTRY 命令。
    #[command(name = "linux.bash", visible_alias = "linux-bash")]
    LinuxBash(LinuxBashArgs),
    /// 按 PID/PPID 重建 Linux 活动进程树，并标记孤儿父进程与父链循环。
    #[command(name = "linux.pstree", visible_alias = "linux-pstree")]
    LinuxPstree(LinuxPstreeArgs),
    /// 严格遍历 Linux modules 双向链并验证每个 module 对象。
    #[command(name = "linux.lsmod", visible_alias = "linux-lsmod")]
    LinuxLsmod(LinuxKernelLimitArgs),
    /// 按模块名或基址重验 Linux 内核模块并恢复为 ELF；缺页时保留 .partial 与 manifest。
    #[command(name = "linux.module-extract", visible_alias = "linux-module-extract")]
    LinuxModuleExtract(LinuxModuleExtractArgs),
    /// 按 mount namespace 遍历 Linux 挂载树，支持 PID/task 或 namespace 筛选。
    #[command(name = "linux.mountinfo", visible_alias = "linux-mountinfo")]
    LinuxMountinfo(LinuxMountinfoArgs),
    /// 解码 Linux 内核 core kallsyms 名称与地址。
    #[command(name = "linux.kallsyms", visible_alias = "linux-kallsyms")]
    LinuxKallsyms(LinuxKallsymsArgs),
    /// 解析旧式 log buffer 或新版 printk ring；无启动时间证据时仅输出 monotonic 时间。
    #[command(name = "linux.kmsg", visible_alias = "linux-kmsg")]
    LinuxKmsg(LinuxKmsgArgs),
    /// 交叉对比 modules list 与 module_kset，显式报告尚不可用的语义扫描视图。
    #[command(name = "linux.modxview", visible_alias = "linux-modxview")]
    LinuxModxview(LinuxKernelLimitArgs),
    /// 验证 Linux syscall table handler 是否落在已证明的 kernel/module 可执行范围。
    #[command(name = "linux.check-syscall", visible_alias = "linux-check-syscall")]
    LinuxCheckSyscall(LinuxCheckSyscallArgs),
    /// 从已验证的内存池恢复活动、已退出和脱链的 EPROCESS 对象。
    Psscan(PluginArgs),
    /// 以父子树形式显示活动进程。
    Pstree(PluginArgs),
    /// 交叉关联进程、最早活动线程与句柄，检查记录 PPID 是否疑似伪造。
    #[command(name = "check-pslist", visible_alias = "check_pslist")]
    CheckPslist(CheckPslistArgs),
    /// 交叉比对链表、内存池和线程归属证据以发现隐藏进程。
    Psxview(PluginArgs),
    /// 使用 PDB 中的 ETHREAD 布局遍历所有进程线程链表。
    Threads(PluginArgs),
    /// 从已验证的线程池恢复 ETHREAD 对象。
    Thrdscan(PluginArgs),
    /// 显示存在挂起或冻结证据的线程。
    SuspendedThreads(PluginArgs),
    /// 显示启动地址、归属或调试状态异常的线程。
    SuspiciousThreads(PluginArgs),
    /// 显示启动地址不属于已加载模块的内核线程。
    OrphanKernelThreads(PluginArgs),
    /// 按 Windows 会话 ID 对活动进程分组。
    Sessions(PluginArgs),
    /// 枚举 SepLogonSessions，并按主令牌 AuthenticationId 关联活动进程。
    #[command(name = "logonsessions", visible_alias = "logon-sessions")]
    LogonSessions(LogonSessionArgs),
    /// 检查主令牌结构、身份、登录会话、完整性级别和高风险已启用权限。
    #[command(name = "token-anomalies", visible_alias = "tokenanomalies")]
    TokenAnomalies(TokenAnomalyArgs),
    /// 关联进程、EJOB 对象及其作业限制。
    Joblinks(PluginArgs),
    /// 从各进程 PEB 恢复映像路径和命令行。
    Cmdline(PluginArgs),
    /// 恢复完整的进程环境变量块。
    Envars(PluginArgs),
    /// 聚合 Windows Terminal、PowerShell、pwsh 和 cmd 的结构化控制台及 PSReadLine 历史。
    TerminalHistory(TerminalHistoryArgs),
    /// 扫描已验证的 conhost _COMMAND_HISTORY 向量并恢复命令历史。
    Cmdscan(PluginArgs),
    /// 恢复 conhost 控制台元数据、屏幕内容和命令历史。
    Consoles(PluginArgs),
    /// 扫描并遍历各 GUI 会话中的 WindowStation 对象。
    Windowstations(PluginArgs),
    /// 枚举已验证 WindowStation 关联的 Desktop 对象。
    Desktops(PluginArgs),
    /// 独立扫描并验证 Desktop 内存池对象。
    Deskscan(PluginArgs),
    /// 枚举各已验证 Desktop 对象中的 GUI 窗口。
    #[command(name = "gui-windows")]
    GuiWindows(PluginArgs),
    /// 恢复每个具有非空标题的 GUI 窗口，并关联进程、桌面和父窗口。
    Windowtitles(PluginArgs),
    /// 从进程 VAD 中验证标准 DIB 结构，并将完整驻留像素无损导出为 BMP。
    #[command(name = "gdi-bitmap")]
    GdiBitmap(GdiBitmapArgs),
    /// 从 DWM/WARP 或系统内存合成表面恢复真实显示帧，并生成窗口布局画布。
    #[command(name = "desktop-reconstruct")]
    DesktopReconstruct(DesktopReconstructArgs),
    /// 解析进程令牌权限及其状态位。
    Privileges(PluginArgs),
    /// 解析进程令牌中的用户、组、完整性级别和能力 SID。
    Getsids(GetSidsArgs),
    /// 计算注册表服务对应的确定性 NT SERVICE SID。
    Getservicesids(PluginArgs),
    /// 枚举已加载的内核模块和驱动。
    Drivers(PluginArgs),
    /// 扫描已验证的 MmLd 池分配并查找脱链内核模块。
    Modscan(PluginArgs),
    /// 扫描已验证的 Driv 池并恢复 DRIVER_OBJECT 结构。
    Driverscan(PluginArgs),
    /// 将 DRIVER_OBJECT 映像与已加载模块链表进行关联。
    Drivermodule(PluginArgs),
    /// 检查各 DRIVER_OBJECT 的 IRP MajorFunction 目标地址。
    Driverirp(PluginArgs),
    /// 聚合驱动、设备、模块支持关系、IRP 与 Fast I/O 分发表。
    #[command(name = "driver-inspect")]
    DriverInspect(DriverInspectArgs),
    /// 遍历以已恢复驱动为根的 DEVICE_OBJECT 链。
    Devicetree(PluginArgs),
    /// 枚举内核回调数组、链表、注册表回调和池对象。
    Callbacks(PluginArgs),
    /// 解析原生及影子系统服务描述符表。
    Ssdt(PluginArgs),
    /// 恢复内核循环记录的已卸载驱动历史。
    Unloadedmodules(PluginArgs),
    /// 扫描已验证的执行体对象池并恢复 Mutant/Mutex 对象。
    Mutantscan(PluginArgs),
    /// 扫描已验证的执行体对象池并恢复符号链接对象。
    Symlinkscan(PluginArgs),
    /// 遍历各处理器定时器表并将 DPC 例程解析到模块。
    Timers(PluginArgs),
    /// 通过各进程 PEB 枚举用户态 DLL。
    Dlllist(DllArgs),
    /// 比对 PEB 的三条加载器链表与文件支持的 PE VAD。
    Ldrmodules(DllArgs),
    /// 解析各进程主映像的导入地址表。
    Iat(DllArgs),
    /// 枚举或解析内核及进程模块中的 PE 导出符号。
    PeSymbols(PeSymbolsArgs),
    /// 从指定虚拟地址重建进程或内核 PE 映像。
    Pedump(PeDumpArgs),
    /// 遍历进程 VAD 树。
    Vad(VadArgs),
    /// 按 PID 将每个 VAD 区间导出为独立文件；缺页结果保留为 .partial。
    Vaddump(VadDumpArgs),
    /// 查找 VAD 声明保护与 PTE 有效保护不一致的私有已提交区间。
    #[command(name = "injected-regions")]
    InjectedRegions(InjectedRegionsArgs),
    /// 使用字节正则表达式扫描驻留的 VAD 区间。
    Vadregexscan(VadRegexArgs),
    /// 使用 YARA-X 编译规则并扫描驻留的 VAD 区间。
    Vadyarascan(VadYaraArgs),
    /// 枚举已加载的注册表 Hive。
    Hivelist(PluginArgs),
    /// 扫描已验证的 CM10 大页池并恢复活动及残留 Hive。
    Hivescan(PluginArgs),
    /// 对照内核映像检查各 HHIVE GetCellRoutine 目标。
    Getcellroutine(PluginArgs),
    /// 使用驻留的 SYSTEM 和 SAM Hive 解密本地 LM/NT 哈希。
    Hashdump(PluginArgs),
    /// 从驻留的 SECURITY 数据解密域缓存登录哈希。
    Cachedump(PluginArgs),
    /// 从驻留的 SYSTEM 和 SECURITY Hive 解密 LSA Policy Secrets。
    Lsadump(PluginArgs),
    /// 扫描 services.exe 的 VAD 并恢复结构有效的服务记录。
    Svcscan(ServiceArgs),
    /// 从映像锚点或结构化前驱关系恢复 services.exe 的活动服务链表。
    Svclist(ServiceArgs),
    /// 显示扫描发现但不在活动链表中的服务记录。
    Svcdiff(ServiceArgs),
    /// 从驻留注册表 Hive 恢复 TaskCache 计划任务注册信息。
    ScheduledTasks(PluginArgs),
    /// 汇总注册表 ASEP、自动启动服务/驱动，并可选关联 services.exe 与 TaskCache 候选。
    #[command(name = "autoruns", visible_alias = "autorun")]
    Autoruns(AutorunArgs),
    /// 输出驻留 Hive 中指定键、键值及可选的子项。
    RegistryPrintkey(RegistryPrintArgs),
    /// 恢复各用户的 UserAssist 程序执行记录。
    Userassist(PluginArgs),
    /// 恢复新版和旧版 Amcache 的应用、文件及驱动记录。
    Amcache(PluginArgs),
    /// 从 ahcache.sys 或 NT 内核中恢复结构有效的 Shimcache AVL/LRU 条目。
    Shimcachemem(PluginArgs),
    /// 枚举指定进程句柄，或按对象地址反查全部活动句柄所有者。
    Handles(HandleArgs),
    /// 一次关联驻留文件对象与全部活动进程句柄。
    #[command(name = "windows.open-files", visible_alias = "open-files")]
    WindowsOpenFiles(OpenFileArgs),
    /// 扫描由 NPFS 结构链验证的命名管道，并关联活动进程句柄。
    Pipescan(PipeScanArgs),
    /// 从驻留 FILE_OBJECT 恢复并解析 Windows Prefetch 执行记录。
    Prefetchscan(PrefetchScanArgs),
    /// 扫描 TCP/UDP 池分配并恢复网络端点。
    Netscan(PluginArgs),
    /// 使用精确 PDB 遍历 tcpip.sys 分区哈希及活动 TCP/UDP 端口池。
    Netstat(PluginArgs),
    /// 从物理内存恢复经过校验的完整 IP 包，并可导出为 PCAPNG。
    #[command(alias = "packet-scan")]
    Packetscan(PacketScanArgs),
    /// Windows 扫描文件对象池；Linux 遍历已验证的 superblock/dentry 文件树。
    Filescan(FileScanArgs),
    /// 恢复 Linux /etc/passwd；无存活 dentry 时使用明确标注的反向页缓存候选。
    #[command(name = "linux.passwd", visible_alias = "linux-passwd")]
    LinuxPasswd(LinuxPasswdArgs),
    /// 扫描并解析驻留的 NTFS MFT FILE 记录。
    Mftscan(DiskScanArgs),
    /// 显示包含具名 $DATA 备用数据流的 MFT 记录。
    MftAds(DiskScanArgs),
    /// 恢复驻留 MFT $DATA 属性的数据预览。
    MftResidentData(DiskScanArgs),
    /// 从指定 MFT FILE 记录完整导出常驻 $DATA 或备用数据流。
    Mftdump(MftDumpArgs),
    /// 扫描结构有效的传统 MBR 分区扇区。
    Mbrscan(DiskScanArgs),
    /// 从 Windows FILE_OBJECT 或 Linux 已验证页缓存恢复文件内容。
    #[command(visible_alias = "linux.dumpfile")]
    Dumpfile(DumpFileArgs),
    /// 恢复驻留 SQLite 主库及 WAL/SHM/Journal，并生成页级缺失清单。
    #[command(name = "sqlite-recover")]
    SqliteRecover(SqliteRecoverArgs),
    /// 恢复全部驻留的注册表 Hive 和事务文件。
    DumpRegistry(ArtifactExportArgs),
    /// 恢复全部驻留的 Windows 事件日志和 ETL 文件。
    DumpLogs(LogExportArgs),
    /// 将 EVTX 文件解析为筛选后的取证事件时间线。
    EventTimeline(EventTimelineArgs),
    /// 从 Windows 内存聚合进程、线程、MFT、Shimcache 与注册表时间证据。
    #[command(name = "windows.timeline", visible_alias = "windows-timeline")]
    WindowsTimeline(WindowsTimelineArgs),
    /// 聚合 Prefetch、BAM/DAM、UserAssist、Shimcache 与 Amcache 执行证据。
    #[command(name = "windows.execution", visible_alias = "windows-execution")]
    WindowsExecution(WindowsExecutionArgs),
    /// 聚合 WPS 最近文件逐项时间与 Explorer RecentDocs MRU 顺序。
    #[command(name = "windows.recent-files", visible_alias = "recent-files")]
    WindowsRecentFiles(WindowsRecentFilesArgs),
    /// 聚合同一物理 USB 的总线、存储与辅助接口并解释连接时间。
    #[command(name = "usb-history")]
    UsbHistory(UsbHistoryArgs),
    /// 查找私有或可写的可执行 VAD 并检查驻留字节。
    Malfind(MalfindArgs),
    /// 扫描进程 VAD，严格解析并去重 Cobalt Strike Beacon 配置。
    Cobaltstrikescan(CobaltStrikeScanArgs),
    /// 检测主映像替换以及节区与 PEB 不一致。
    Hollowprocesses(PluginArgs),
    /// 检测映像节区缺少正常文件证据的进程。
    Processghosting(PluginArgs),
    /// 比对 EPROCESS 标识与 PEB 映像及命令行标识。
    Pebmasquerade(PluginArgs),
    /// 检测 ntdll/win32u 之外已验证的直接系统调用代码块。
    DirectSystemCalls(PluginArgs),
    /// 检测解析到 ntdll/win32u 系统调用指令的 RIP 相对间接跳转。
    IndirectSystemCalls(PluginArgs),
    /// 跨全部可读进程比对指定的 ntdll 系统调用桩。
    UnhookedSystemCalls(PluginArgs),
    /// 检测 ETW API 返回/跳转补丁及跨进程实现异常。
    Etwpatch(PluginArgs),
    /// 验证 lsass cryptdll RC4-HMAC 处理表中的 Skeleton Key 挂钩。
    SkeletonKeyCheck(PluginArgs),
}

#[derive(Args)]
struct CollectArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 输出 SQLite 数据库；已有数据库会追加新的分析批次。
    #[arg(long, value_name = "SQLite文件")]
    db: PathBuf,
    /// 每个普通插件最多保留的结果数量。
    #[arg(long, default_value_t = 65_536)]
    limit: usize,
    /// 文件扫描最多保留的 FILE_OBJECT 数量。
    #[arg(long, default_value_t = 1_000_000)]
    file_scan_limit: usize,
    /// 文本、浏览器、微信等插件最多反向映射的进程地址空间数量。
    #[arg(long, default_value_t = 256)]
    process_space_limit: usize,
    /// 单个数据库、剪切板块或历史文件允许读取的最大大小，单位为 MiB。
    #[arg(long, default_value_t = 256)]
    max_data_mib: usize,
}

#[derive(Args)]
struct ScanArgs {
    image: PathBuf,
    /// 要搜索的 UTF-8 文本。
    #[arg(long, conflicts_with = "hex")]
    text: Option<String>,
    /// 精确的十六进制字节，例如 "4d 5a 90 00"。
    #[arg(long, conflicts_with = "text")]
    hex: Option<String>,
    #[arg(long, default_value_t = 100)]
    limit: usize,
    #[arg(long, default_value_t = 64)]
    chunk_mib: usize,
}

#[derive(Args)]
struct DownloadScanArgs {
    image: PathBuf,
    /// 最多保留的去重下载痕迹数量。
    #[arg(long, default_value_t = 1000)]
    limit: usize,
}

#[derive(Args)]
struct CookieScanArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 最多保留的去重 Cookie 数量。
    #[arg(long, default_value_t = 10_000)]
    limit: usize,
    /// 最多尝试恢复和解析的 Cookie 数据库及旧式 Cookie 文件数量。
    #[arg(long, default_value_t = 256)]
    database_limit: usize,
    /// filescan 最多保留的 FILE_OBJECT 数量。
    #[arg(long, default_value_t = 1_000_000)]
    file_scan_limit: usize,
    /// 单个 Cookie 数据库允许恢复的最大大小，单位为 MiB。
    #[arg(long, default_value_t = 256)]
    max_database_mib: usize,
    /// 最多反向映射的浏览器相关进程地址空间数量。
    #[arg(long, default_value_t = 32)]
    process_space_limit: usize,
}

#[derive(Args)]
struct ClipboardScanArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 最多保留的活动剪切板格式数量。
    #[arg(long, default_value_t = 1024)]
    limit: usize,
    /// 单个活动剪切板数据块允许读取的最大大小，单位为 MiB。
    #[arg(long, default_value_t = 16)]
    max_data_mib: usize,
}

#[derive(Args)]
struct ResidualScanArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 最多保留的去重文本残留数量。
    #[arg(long, default_value_t = 1024)]
    limit: usize,
    /// 最多反向映射的进程地址空间数量。
    #[arg(long, default_value_t = 256)]
    process_space_limit: usize,
    /// 精确搜索任意文本；同时匹配 UTF-8 和 UTF-16LE，可多次指定。
    #[arg(long = "text")]
    search_texts: Vec<String>,
}

#[derive(Args)]
struct WechatScanArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 仅分析指定 PID；可用于微信辅助进程或残缺进程名。
    #[arg(long)]
    pid: Option<u64>,
    /// 仅分析微信主进程，跳过辅助进程和小程序运行时。
    #[arg(long)]
    main_only: bool,
    /// 最多保留的去重密钥候选数量。
    #[arg(long, default_value_t = 256)]
    limit: usize,
    /// 十六进制字面量锚点最多保留的数量。
    #[arg(long, default_value_t = 1_000_000)]
    anchor_limit: usize,
    /// 最多反向映射的微信进程地址空间数量。
    #[arg(long, default_value_t = 32)]
    process_space_limit: usize,
    /// 用候选密钥验证目录中的本机微信数据库；可多次指定。
    #[arg(long = "verify-db-root")]
    verify_db_roots: Vec<PathBuf>,
    /// 最多读取的本机微信数据库验证文件数量。
    #[arg(long, default_value_t = 10_000)]
    verification_file_limit: usize,
}

#[derive(Args)]
struct BrowserSessionArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 最多保留的浏览器会话数量。
    #[arg(long, default_value_t = 2048)]
    session_limit: usize,
    /// 最多保留的去重 Cookie 数量。
    #[arg(long, default_value_t = 10_000)]
    cookie_limit: usize,
    /// 最多保留的去重下载痕迹数量。
    #[arg(long, default_value_t = 2000)]
    download_limit: usize,
    /// 最多尝试恢复和解析的 Cookie 数据库及旧式 Cookie 文件数量。
    #[arg(long, default_value_t = 256)]
    database_limit: usize,
    /// filescan 最多保留的 FILE_OBJECT 数量。
    #[arg(long, default_value_t = 1_000_000)]
    file_scan_limit: usize,
    /// 单个 Cookie 数据库允许恢复的最大大小，单位为 MiB。
    #[arg(long, default_value_t = 256)]
    max_database_mib: usize,
    /// 最多反向映射的浏览器相关进程地址空间数量。
    #[arg(long, default_value_t = 64)]
    process_space_limit: usize,
    /// 同时将完整 JSON 报告写入此文件。
    #[arg(short, long, value_name = "文件")]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct BrowserHistoryArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 最多保留的去重 URL 访问记录数量。
    #[arg(long, default_value_t = 10_000)]
    limit: usize,
    /// 最多尝试恢复的浏览器数据库数量。
    #[arg(long, default_value_t = 256)]
    database_limit: usize,
    /// filescan 最多保留的 FILE_OBJECT 数量。
    #[arg(long, default_value_t = 1_000_000)]
    file_scan_limit: usize,
    /// 单个 History 数据库允许恢复的最大大小，单位为 MiB。
    #[arg(long, default_value_t = 256)]
    max_database_mib: usize,
    /// 输出 URL 聚合摘要，或 visits 表中的逐次访问事件。
    #[arg(long, value_enum, default_value_t = BrowserHistoryView::Summary)]
    view: BrowserHistoryView,
    /// 扫描文件句柄，报告采集时持有 History 数据库的进程（不等同于访问行为人）。
    #[arg(long)]
    owners: bool,
    /// --owners 最多枚举的进程数。
    #[arg(long, default_value_t = 65_536, requires = "owners")]
    process_limit: usize,
    /// --owners 最多扫描的句柄表项数。
    #[arg(long, default_value_t = 2_000_000, requires = "owners")]
    handle_scan_limit: usize,
    /// 同时将完整 JSON 报告写入此文件。
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BrowserHistoryView {
    Summary,
    Visits,
}

impl BrowserHistoryView {
    fn as_str(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Visits => "visits",
        }
    }
}

#[derive(Args)]
struct AccountScanArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 最多保留的去重账户操作痕迹数量。
    #[arg(long, default_value_t = 1000)]
    limit: usize,
}

#[derive(Args)]
struct TerminalHistoryArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 最多保留的终端历史命令数量。
    #[arg(long, default_value_t = 10_000, value_name = "数量")]
    limit: usize,
    /// filescan 最多保留的 FILE_OBJECT 数量。
    #[arg(long, default_value_t = 1_000_000, value_name = "数量")]
    file_scan_limit: usize,
    /// 最多尝试恢复的 PSReadLine 历史文件数量。
    #[arg(long, default_value_t = 256, value_name = "数量")]
    history_file_limit: usize,
    /// 单个 PSReadLine 历史文件允许恢复的最大大小，单位为 MiB。
    #[arg(long, default_value_t = 16, value_name = "兆字节")]
    max_history_file_mib: usize,
}

#[derive(Args)]
struct WindowsInfoArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
}

#[derive(Args)]
struct SystemInfoArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    #[arg(long, default_value_t = 1_000_000)]
    network_limit: usize,
    /// 仅生成交互式首屏所需的快速概览，不执行深度网络池与注册表扫描。
    #[arg(long, default_value_t = false)]
    quick: bool,
    /// 同时将完整 JSON 报告写入此文件。
    #[arg(short, long, value_name = "文件")]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct AcquisitionInfoArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 不扫描 FTK Imager、DumpIt、WinPmem 等采集工具进程及输出句柄。
    #[arg(long)]
    skip_tool_scan: bool,
    /// 同时输出分析主机文件系统的创建/修改时间；这些时间不作为采集时间。
    #[arg(long)]
    include_host_times: bool,
    /// 最多遍历的活动进程数量。
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    /// 每个采集工具候选最多检查的句柄数量。
    #[arg(long, default_value_t = 200_000)]
    handle_limit: usize,
}

#[derive(Args)]
struct Virt2physArgs {
    image: PathBuf,
    address: String,
    /// 为 raw/vmem 镜像显式指定页表根地址。
    #[arg(long)]
    dtb: Option<String>,
}

#[derive(Subcommand)]
enum SymbolCommand {
    /// 在内存镜像中定位 RSDS 记录。
    Id {
        image: PathBuf,
        #[arg(long, default_value = "ntkrnlmp.pdb")]
        name: String,
    },
    /// 定位 PDB 标识并从 Microsoft 符号服务器下载。
    Fetch {
        image: PathBuf,
        #[arg(long, default_value = "ntkrnlmp.pdb")]
        name: String,
        #[command(flatten)]
        symbols: SymbolStoreOptions,
    },
    /// 搜索 PDB 中的公共和全局记录。
    Search {
        pdb: PathBuf,
        query: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// 读取并按需下载已加载内核模块 PE 的符号。
    Module {
        image: PathBuf,
        /// 已加载模块的虚拟基址。
        #[arg(long)]
        base: String,
        /// 将发现的 PDB 下载到符号缓存。
        #[arg(long)]
        fetch: bool,
        #[command(flatten)]
        symbols: SymbolStoreOptions,
    },
    /// 诊断、安装或显式获取与镜像完整 banner 匹配的 Linux ISF。
    Linux(LinuxSymbolArgs),
}

#[derive(Args)]
struct LinuxSymbolArgs {
    image: PathBuf,
    /// 需要保留并验证的符号功能集合；可重复或用逗号分隔。
    #[arg(long, value_delimiter = ',', value_name = "FEATURE")]
    feature: Vec<LinuxSymbolFeature>,
    /// 仅诊断指定的 Volatility 3 ISF（.json 或 .json.xz）。
    #[arg(long, value_name = "FILE_OR_ARCHIVE")]
    isf: Option<PathBuf>,
    /// 将 --isf 复验后安装到 StarMem 可写符号根。
    #[arg(long, requires = "isf")]
    install: bool,
    /// 显式访问远程 banner 索引并获取精确匹配 ISF。
    #[arg(long, conflicts_with = "offline")]
    fetch: bool,
    /// 禁止任何远程访问。
    #[arg(long, conflicts_with_all = ["fetch", "refresh_index"])]
    offline: bool,
    /// 强制刷新远程 banner 索引后再解析精确匹配候选。
    #[arg(long)]
    refresh_index: bool,
    #[command(flatten)]
    symbols: SymbolStoreOptions,
}

#[derive(Args)]
struct PslistArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    #[arg(long, default_value_t = 65536)]
    limit: usize,
}

#[derive(Args)]
struct CheckPslistArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 仅检查指定活动进程；默认检查全部活动进程。
    #[arg(long)]
    pid: Option<u64>,
    /// 最多枚举的活动进程数量。
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    /// 最多保留的活动 ETHREAD 记录数。
    #[arg(long, default_value_t = 262_144)]
    thread_limit: usize,
    /// 跨全部活动进程最多检查的句柄表项数。
    #[arg(long, default_value_t = 4_000_000)]
    handle_scan_limit: usize,
    /// 最多保留的替代创建者关系数量。
    #[arg(long, default_value_t = 65_536)]
    limit: usize,
}

#[derive(Args)]
struct LinuxKernelArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolStoreOptions,
}

#[derive(Args)]
struct LinuxProcessTextArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolStoreOptions,
    /// 仅分析指定 PID；默认分析所有活动线程组主进程。
    #[arg(long)]
    pid: Option<i32>,
    /// 活动任务链允许保留的最大记录数。
    #[arg(long, default_value_t = 65536)]
    process_limit: usize,
    /// 每个进程参数区或环境区允许读取的最大字节数。
    #[arg(long, default_value_t = 1024 * 1024u64)]
    max_bytes: u64,
}

#[derive(Args)]
struct LinuxIrArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolStoreOptions,
    /// 要分析的应急响应模块。
    #[arg(long, default_value = "pslist", value_parser = clap::builder::PossibleValuesParser::new(starmem::linux_ir::TASK_MODULES.iter().copied()))]
    module: String,
    #[arg(long)]
    pid: Option<i32>,
    #[arg(long, default_value_t = 65_536)]
    limit: usize,
    /// 本次文件内容读取预算（字节）。
    #[arg(long, default_value_t = 1024 * 1024)]
    max_bytes: u64,
    /// Linux 文件路径；file-content 必填，其他文件模块可按目录收窄。
    #[arg(long)]
    path: Option<String>,
}

#[derive(Args)]
struct LinuxIrKernelArgs {
    #[command(flatten)]
    kernel: LinuxKernelGlobalArgs,
    #[arg(long, default_value = "system", value_parser = clap::builder::PossibleValuesParser::new(starmem::linux_ir::KERNEL_MODULES.iter().copied()))]
    module: String,
    #[arg(long, default_value_t = 65_536)]
    limit: usize,
    /// 仅 fbdev：保存完整驻留帧缓冲的 BMP 目录；默认只列设备。
    #[arg(long)]
    framebuffer_output: Option<PathBuf>,
    #[arg(long, default_value_t = 32 * 1024 * 1024)]
    max_bytes: u64,
}

#[derive(Args)]
struct LinuxLsofArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolStoreOptions,
    /// 仅分析指定 PID；默认分析所有活动线程组主进程。
    #[arg(long)]
    pid: Option<i32>,
    #[arg(long, default_value_t = 65536)]
    process_limit: usize,
    /// 每个进程最多检查的文件描述符数。
    #[arg(long, default_value_t = 65536)]
    max_fds: usize,
}

#[derive(Args)]
struct LinuxProcMapsArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolStoreOptions,
    /// 仅分析指定 PID；默认分析所有活动线程组主进程。
    #[arg(long)]
    pid: Option<i32>,
    #[arg(long, default_value_t = 65536)]
    process_limit: usize,
    /// 每个进程最多保留的 VMA 数。
    #[arg(long, default_value_t = 1_000_000)]
    map_limit: usize,
}

#[derive(Args)]
struct LinuxProcDumpArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolStoreOptions,
    /// 要导出的活动进程 PID。
    #[arg(long)]
    pid: i32,
    /// VMA 文件及结构化报告的输出目录。
    #[arg(short, long, value_name = "目录")]
    output: PathBuf,
    #[arg(long, default_value_t = 65536)]
    process_limit: usize,
    #[arg(long, default_value_t = 1_000_000)]
    map_limit: usize,
    /// 单个 VMA 允许导出的最大逻辑大小。
    #[arg(long, default_value_t = 4 * 1024 * 1024 * 1024u64)]
    max_region_size: u64,
    /// 全部 VMA 允许导出的最大逻辑大小。
    #[arg(long, default_value_t = 16 * 1024 * 1024 * 1024u64)]
    max_total_size: u64,
}

#[derive(Args)]
struct LinuxBashArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolStoreOptions,
    /// 仅分析指定 Bash PID；默认分析所有活动 Bash 主进程。
    #[arg(long)]
    pid: Option<i32>,
    #[arg(long, default_value_t = 65536)]
    process_limit: usize,
    #[arg(long, default_value_t = 1_000_000)]
    map_limit: usize,
    /// 全部 Bash 堆/匿名可写 VMA 的最大扫描字节数。
    #[arg(long, default_value_t = 256 * 1024 * 1024u64)]
    max_scan_bytes: u64,
    /// 单条 Bash 命令允许读取的最大字节数。
    #[arg(long, default_value_t = 16 * 1024usize)]
    max_command_bytes: usize,
}

#[derive(Args)]
struct LinuxPstreeArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolStoreOptions,
    /// 仅显示指定 PID 及其活动后代；默认显示完整活动进程树。
    #[arg(long)]
    pid: Option<i32>,
    /// 活动任务链允许保留的最大记录数。
    #[arg(long, default_value_t = 65536)]
    limit: usize,
}

/// 所有 kernel-global Linux 插件共用的镜像、符号和显式内核上下文。
#[derive(Args)]
struct LinuxKernelGlobalArgs {
    /// Linux x86_64 物理内存镜像。
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolStoreOptions,
    /// 显式的 x86_64 四级页表根（十进制或 0x 十六进制）。
    #[arg(long, value_name = "ADDRESS")]
    dtb: Option<String>,
    /// 显式的 Linux KASLR slide（十进制或 0x 十六进制）。
    #[arg(long, value_name = "ADDRESS")]
    kernel_slide: Option<String>,
}

impl LinuxKernelGlobalArgs {
    fn open(
        &self,
        features: impl IntoIterator<Item = LinuxSymbolFeature>,
    ) -> Result<starmem::linux::OpenedLinuxKernelSession> {
        ensure_csv_does_not_overwrite_input(&self.image)?;
        let image = open_memory_image(&self.image)?;
        let symbols = self.symbols.build();
        open_linux_kernel_session(
            image,
            &symbols,
            features,
            LinuxKernelSessionOptions {
                directory_table_base: self
                    .dtb
                    .as_deref()
                    .map(parse_integer)
                    .transpose()
                    .context("--dtb 无效")?,
                kernel_slide: self
                    .kernel_slide
                    .as_deref()
                    .map(parse_integer)
                    .transpose()
                    .context("--kernel-slide 无效")?,
            },
        )
    }
}

#[derive(Args)]
struct LinuxKernelLimitArgs {
    #[command(flatten)]
    kernel: LinuxKernelGlobalArgs,
    /// 最多保留的结构化记录数。
    #[arg(long, default_value_t = 65_536)]
    limit: usize,
}

#[derive(Args)]
struct LinuxKallsymsArgs {
    #[command(flatten)]
    kernel: LinuxKernelGlobalArgs,
    /// 最多保留的 core kallsyms 记录数。
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct LinuxModuleExtractArgs {
    #[command(flatten)]
    kernel: LinuxKernelGlobalArgs,
    /// 按 modules 链中的精确模块名选择。
    #[arg(long, conflicts_with = "base", required_unless_present = "base")]
    name: Option<String>,
    /// 按 module 对象或 core 基址选择（十进制或 0x 十六进制）。
    #[arg(long, conflicts_with = "name", required_unless_present = "name")]
    base: Option<String>,
    /// 恢复 ELF 的目标文件。
    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,
    /// 允许从 module core/init 恢复的最大逻辑字节数。
    #[arg(long, value_name = "BYTES")]
    max_bytes: u64,
}

#[derive(Args)]
struct LinuxMountinfoArgs {
    #[command(flatten)]
    kernel: LinuxKernelGlobalArgs,
    /// 校验已知 task 地址中的 PID；必须与 --task 同时提供。
    #[arg(long, requires = "task", conflicts_with = "namespace")]
    pid: Option<i32>,
    /// 已由其他证据验证的 task_struct 地址。
    #[arg(long, value_name = "ADDRESS", conflicts_with = "namespace")]
    task: Option<String>,
    /// 直接指定 mnt_namespace 地址。
    #[arg(long, value_name = "ADDRESS", conflicts_with_all = ["pid", "task"])]
    namespace: Option<String>,
    /// 最多保留的 mount 记录数。
    #[arg(long, default_value_t = 262_144)]
    limit: usize,
}

#[derive(Args)]
struct LinuxKmsgArgs {
    #[command(flatten)]
    kernel: LinuxKernelGlobalArgs,
    /// 最多保留的 printk 记录数。
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
    /// 由独立证据证明的 Unix epoch 启动时间，单位纳秒。
    #[arg(long, value_name = "NANOSECONDS")]
    boot_time_unix_ns: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LinuxSyscallTableArg {
    X64,
    Ia32,
    X32,
}

impl From<LinuxSyscallTableArg> for LinuxSyscallTable {
    fn from(value: LinuxSyscallTableArg) -> Self {
        match value {
            LinuxSyscallTableArg::X64 => Self::X64,
            LinuxSyscallTableArg::Ia32 => Self::Ia32,
            LinuxSyscallTableArg::X32 => Self::X32,
        }
    }
}

#[derive(Args)]
struct LinuxCheckSyscallArgs {
    #[command(flatten)]
    kernel: LinuxKernelGlobalArgs,
    /// 要验证的 syscall table ABI。
    #[arg(long, value_enum, default_value_t = LinuxSyscallTableArg::X64)]
    table: LinuxSyscallTableArg,
    /// 从 syscall table 起始验证的指针数。
    #[arg(long, default_value_t = 1024)]
    entries: usize,
    /// 不把严格 modules 链证明的 module text 纳入可执行范围。
    #[arg(long)]
    no_modules: bool,
}

#[derive(Serialize)]
struct LinuxKernelPluginOutput<'a, T> {
    /// 保留与插件结果同一次验证的 DTB、KASLR 和符号身份。
    kernel_session: &'a LinuxKernelSessionEvidence,
    #[serde(flatten)]
    report: &'a T,
}

#[derive(Args)]
struct SymbolOptions {
    /// 使用已有 JSON 配置覆盖自动符号解析。
    #[arg(long, conflicts_with = "pdb")]
    profile: Option<PathBuf>,
    /// 使用本地内核 PDB 覆盖自动符号解析。
    #[arg(long, conflicts_with = "profile")]
    pdb: Option<PathBuf>,
    #[command(flatten)]
    store: SymbolStoreOptions,
}

impl SymbolOptions {
    fn session_options(&self) -> SessionOptions {
        SessionOptions {
            image_options: current_image_open_options(),
            profile: self.profile.clone(),
            pdb: self.pdb.clone(),
            symbol_store: self.store.build(),
            allow_compatible_local_symbols: true,
        }
    }
}

#[derive(Args, Debug, Clone, Default)]
struct SymbolStoreOptions {
    /// 可写符号缓存目录；同时兼容 --symbol-cache。
    #[arg(long, alias = "symbol-cache", value_name = "目录")]
    cache: Option<PathBuf>,
    /// 共享只读符号根；Windows 使用 PDB 布局，Linux 复用 Volatility 3 ISF；未知 Linux 构建最后使用远程精确 banner 兜底；可多次指定。
    #[arg(long = "symbol-path", value_name = "目录")]
    search_roots: Vec<PathBuf>,
}

impl SymbolStoreOptions {
    fn build(&self) -> SymbolStore {
        symbol_store(
            self.cache.clone().unwrap_or_else(default_symbol_cache),
            self.search_roots.clone(),
        )
    }
}

#[derive(Args)]
struct PluginArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    #[arg(long, default_value_t = 65536)]
    limit: usize,
}

#[derive(Args)]
struct DriverInspectArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 仅保留名称完全匹配（忽略大小写）的 DRIVER_OBJECT。
    #[arg(long, conflicts_with = "address")]
    name: Option<String>,
    /// 仅保留指定 DRIVER_OBJECT 地址（十进制或 0x 十六进制）。
    #[arg(long, value_name = "ADDRESS", conflicts_with = "name")]
    address: Option<String>,
    #[arg(long, default_value_t = 65536)]
    limit: usize,
}

#[derive(Args)]
struct LogonSessionArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 活动进程链允许检查的最大记录数。
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    /// 最多保留的登录会话数量。
    #[arg(long, default_value_t = 4_096)]
    limit: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TokenAnomalySeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

impl From<TokenAnomalySeverityArg> for TokenAnomalySeverity {
    fn from(value: TokenAnomalySeverityArg) -> Self {
        match value {
            TokenAnomalySeverityArg::Low => Self::Low,
            TokenAnomalySeverityArg::Medium => Self::Medium,
            TokenAnomalySeverityArg::High => Self::High,
            TokenAnomalySeverityArg::Critical => Self::Critical,
        }
    }
}

#[derive(Args)]
struct TokenAnomalyArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 活动进程链允许检查的最大记录数。
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    /// 仅保留结构或身份字段能够直接证明的异常，隐藏上下文风险信号。
    #[arg(long)]
    direct_only: bool,
    /// 输出的最低严重级别。
    #[arg(long, value_enum, default_value = "low")]
    min_severity: TokenAnomalySeverityArg,
    /// 最多保留的异常令牌数量。
    #[arg(long, default_value_t = 4_096)]
    limit: usize,
}

#[derive(Args)]
struct AutorunArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 活动进程链允许检查的最大记录数。
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    /// 关联 services.exe 内存中的服务控制管理器记录。
    #[arg(long)]
    service_memory: bool,
    /// services.exe 内存关联允许保留的最大服务记录数。
    #[arg(long, default_value_t = 65_536)]
    service_scan_limit: usize,
    /// 附加触发器尚未结构化解码的 TaskCache 持久化候选。
    #[arg(long)]
    include_task_candidates: bool,
    /// 最多保留的持久化配置记录数。
    #[arg(long, default_value_t = 16_384)]
    limit: usize,
}

#[derive(Args)]
struct GdiBitmapArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 仅扫描指定进程 ID；默认扫描全部活动进程。
    #[arg(long)]
    pid: Option<u64>,
    /// 用于保存恢复 BMP 和 gdi-bitmap-report.json 的目录。
    #[arg(short, long, value_name = "目录")]
    output: PathBuf,
    /// 最多保留的结构有效 DIB 数量。
    #[arg(long, default_value_t = 256)]
    limit: usize,
    /// 单张位图允许的最大边长。
    #[arg(long, default_value_t = 16_384)]
    max_dimension: u32,
    /// 单张位图允许的最大像素数据大小，单位为 MiB。
    #[arg(long, default_value_t = 256)]
    max_bitmap_mib: u64,
}

#[derive(Args)]
struct DesktopReconstructArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 用于保存 DWM 桌面帧、窗口 SVG 画布和统一 JSON 清单的目录。
    #[arg(short, long, value_name = "目录")]
    output: PathBuf,
    /// 仅重建指定登录会话。
    #[arg(long)]
    session_id: Option<u32>,
    /// 仅重建指定桌面名称，例如 Default 或 Winlogon。
    #[arg(long)]
    desktop: Option<String>,
    /// 最多枚举的窗口数量。
    #[arg(long, default_value_t = 65_536)]
    limit: usize,
    /// 单张桌面画布允许的最大边长。
    #[arg(long, default_value_t = 16_384)]
    max_dimension: u32,
}

#[derive(Args)]
struct PacketScanArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 最多保留的去重数据包数量。
    #[arg(long, default_value_t = 100_000)]
    limit: usize,
    /// 用于关联 PID 和进程的网络端点数量上限。
    #[arg(long, default_value_t = 1_000_000)]
    endpoint_limit: usize,
    /// 允许恢复的单个 IP 包最大字节数。
    #[arg(long, default_value_t = 65_535)]
    max_packet_size: usize,
    /// 每个去重数据包最多保留的物理证据地址数量。
    #[arg(long, default_value_t = 16)]
    max_occurrences: usize,
    /// 物理内存并行扫描块大小，单位为 MiB。
    #[arg(long, default_value_t = 64)]
    chunk_mib: usize,
    /// 将恢复的数据包写入 PCAPNG 文件。
    #[arg(short, long, value_name = "文件")]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct ServiceArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 同时恢复 SYSTEM 注册表中的服务元数据。默认只执行快速内存枚举，
    /// 因为注册表重建属于独立证据来源。
    #[arg(long)]
    registry: bool,
    #[arg(long, default_value_t = 65_536)]
    limit: usize,
}

#[derive(Args)]
struct RegistryPrintArgs {
    image: PathBuf,
    /// Hive 名称（如 SYSTEM/SOFTWARE）或完整注册表根路径。
    #[arg(long)]
    hive: String,
    /// 相对于所选 Hive 根的键路径。
    #[arg(long, default_value = "")]
    key: String,
    #[arg(long)]
    recurse: bool,
    #[command(flatten)]
    symbols: SymbolOptions,
    #[arg(long, default_value_t = 65_536)]
    limit: usize,
}

#[derive(Args)]
struct MappingArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 报告中保留的最大合并映射数量。
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct ProcessMappingArgs {
    image: PathBuf,
    /// 要遍历用户页表的进程 ID。
    #[arg(long)]
    pid: u64,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 报告中保留的最大合并映射数量。
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct BigPoolArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 仅显示指定的四字节池标签；可多次指定。
    #[arg(long = "tag", value_name = "标签")]
    tags: Vec<String>,
    /// 包含被内核跟踪器标记为空闲的条目。
    #[arg(long)]
    show_free: bool,
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct PoolScannerArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 四字节池标签；可多次指定。未指定时扫描常见对象类型。
    #[arg(long = "tag", value_name = "标签")]
    tags: Vec<String>,
    /// 每个标签最多保留的物理命中数。
    #[arg(long, default_value_t = 1_000_000)]
    limit_per_tag: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum StringOffsetKindArg {
    File,
    Physical,
}

impl From<StringOffsetKindArg> for starmem::windows::system_plugins::StringOffsetKind {
    fn from(value: StringOffsetKindArg) -> Self {
        match value {
            StringOffsetKindArg::File => Self::File,
            StringOffsetKindArg::Physical => Self::Physical,
        }
    }
}

#[derive(Args)]
struct StringsArgs {
    image: PathBuf,
    /// GNU/Sysinternals strings 输出文件，内容为偏移及对应文本。
    #[arg(long, value_name = "文件")]
    strings_file: PathBuf,
    /// 输入偏移指向镜像容器文件还是物理内存。
    #[arg(long, value_enum, default_value_t = StringOffsetKindArg::File)]
    offset_kind: StringOffsetKindArg,
    #[command(flatten)]
    symbols: SymbolOptions,
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProcessStringEncodingArg {
    Both,
    Utf8,
    Utf16le,
}

impl From<ProcessStringEncodingArg> for ProcessStringEncodingSelection {
    fn from(value: ProcessStringEncodingArg) -> Self {
        match value {
            ProcessStringEncodingArg::Both => Self::Both,
            ProcessStringEncodingArg::Utf8 => Self::Utf8,
            ProcessStringEncodingArg::Utf16le => Self::Utf16Le,
        }
    }
}

#[derive(Args)]
struct ProcessStringArgs {
    image: PathBuf,
    /// 要精确定位的字面字符串；UTF-8 模式天然覆盖 ASCII。
    #[arg(long)]
    text: String,
    /// 默认在一次物理扫描中同时搜索 UTF-8/ASCII 和 UTF-16LE。
    #[arg(long, value_enum, default_value_t = ProcessStringEncodingArg::Both)]
    encoding: ProcessStringEncodingArg,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 每种编码最多保留的物理命中数。
    #[arg(long, default_value_t = 1_000_000)]
    scan_hit_limit: usize,
    /// 最多输出的进程归属记录数。
    #[arg(long, default_value_t = 10_000)]
    limit: usize,
    /// 最多枚举的活动进程数。
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    /// 单个物理页在同一进程页表中最多保留的虚拟别名数。
    #[arg(long, default_value_t = 64)]
    mapping_limit: usize,
    /// 所有进程地址空间累计最多检查的页表 entry 数（最大 67108864）。
    #[arg(long, default_value_t = DEFAULT_PROCESS_STRING_REVERSE_ENTRY_LIMIT)]
    reverse_entry_limit: usize,
    /// 所有进程地址空间累计最多保留的反向 alias 数（最大 8000000）。
    #[arg(long, default_value_t = DEFAULT_PROCESS_STRING_REVERSE_ALIAS_LIMIT)]
    reverse_alias_limit: usize,
    /// 物理扫描分块大小，单位为 MiB。
    #[arg(long, default_value_t = 64)]
    chunk_mib: usize,
    /// 命中两侧各输出的上下文字节数，最大 4096。
    #[arg(long, default_value_t = 32)]
    context_bytes: usize,
}

#[derive(Args)]
struct FileScanArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 最多保留和导出的有效文件记录数。
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct LinuxPasswdArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolStoreOptions,
    /// 定位 /etc/passwd 时最多保留的驻留 VFS 文件记录数。
    #[arg(long, default_value_t = 1_000_000)]
    file_scan_limit: usize,
    /// 单个 /etc/passwd 候选允许恢复的最大逻辑大小。
    #[arg(long, default_value_t = 1024 * 1024u64)]
    max_size: u64,
}

#[derive(Args)]
struct DiskScanArgs {
    image: PathBuf,
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct MftDumpArgs {
    image: PathBuf,
    /// mftscan 报告的 MFT FILE 记录物理地址。
    #[arg(long)]
    address: String,
    /// 目标文件；已有内容将被覆盖。
    #[arg(short, long)]
    output: PathBuf,
    /// 按 MFT 属性 ID 精确选择 $DATA。
    #[arg(long, conflicts_with = "stream")]
    attribute_id: Option<u16>,
    /// 备用数据流名称；不指定时导出无名 $DATA。
    #[arg(long, conflicts_with = "attribute_id")]
    stream: Option<String>,
    /// 常驻数据导出的安全上限。
    #[arg(long, default_value_t = 64 * 1024 * 1024u64)]
    max_size: u64,
}

#[derive(Args)]
struct DllArgs {
    image: PathBuf,
    /// 仅显示指定进程 ID。
    #[arg(long)]
    pid: Option<u64>,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 每个进程最多保留的 DLL 数量。
    #[arg(long, default_value_t = 4096)]
    limit: usize,
}

#[derive(Args)]
struct VadArgs {
    image: PathBuf,
    #[arg(long)]
    pid: u64,
    #[command(flatten)]
    symbols: SymbolOptions,
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct InjectedRegionsArgs {
    image: PathBuf,
    #[arg(long)]
    pid: Option<u64>,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 同时报告私有且可执行的区间（malfind 同款判据）。
    #[arg(long)]
    include_executable: bool,
    /// 同时报告未完全驻留的区间；缺页时"全部页只读"并未被证明，默认不报。
    #[arg(long)]
    include_partial: bool,
    /// 每个进程最多遍历的 VAD 数量。
    #[arg(long, default_value_t = 1_000_000)]
    vad_limit: usize,
    /// 最多保留的可疑区间数量。
    #[arg(long, default_value_t = 65_536)]
    limit: usize,
}

#[derive(Args)]
struct GetSidsArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 仅解析指定活动进程的令牌；默认解析全部活动进程。
    #[arg(long)]
    pid: Option<u64>,
    /// 最多保留的 SID 数量。
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct VadDumpArgs {
    image: PathBuf,
    #[arg(long)]
    pid: u64,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 用于保存每个 VAD 区间和 vad-dump-report.json 的目录。
    #[arg(short, long, value_name = "目录")]
    output: PathBuf,
    /// 最多导出的 VAD 数量。
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
    /// 单个 VAD 允许导出的最大字节数。
    #[arg(long, default_value_t = 1024 * 1024 * 1024)]
    max_region_size: u64,
    /// 本次导出允许写出的逻辑字节总量。
    #[arg(long, default_value_t = 8 * 1024 * 1024 * 1024)]
    max_total_size: u64,
}

#[derive(Args)]
struct VadRegexArgs {
    image: PathBuf,
    #[arg(long)]
    pid: Option<u64>,
    #[arg(long)]
    pattern: String,
    #[command(flatten)]
    symbols: SymbolOptions,
    #[arg(long, default_value_t = 8)]
    chunk_mib: usize,
    #[arg(long, default_value_t = 64)]
    overlap_kib: usize,
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct VadYaraArgs {
    image: PathBuf,
    #[arg(long)]
    pid: Option<u64>,
    /// YARA 规则文件；可多次指定。
    #[arg(long = "rule", required = true)]
    rules: Vec<PathBuf>,
    #[command(flatten)]
    symbols: SymbolOptions,
    #[arg(long, default_value_t = 8)]
    chunk_mib: usize,
    #[arg(long, default_value_t = 64)]
    overlap_kib: usize,
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct MalfindArgs {
    image: PathBuf,
    #[arg(long)]
    pid: Option<u64>,
    #[command(flatten)]
    symbols: SymbolOptions,
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct CobaltStrikeScanArgs {
    image: PathBuf,
    /// 只扫描指定 PID；默认扫描全部活动进程。
    #[arg(long)]
    pid: Option<u64>,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// VAD 流式扫描分块大小，单位为 MiB。
    #[arg(long, default_value_t = 1)]
    chunk_mib: usize,
    /// 最多保留的去重 Beacon 配置数量。
    #[arg(long, default_value_t = 4096)]
    limit: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PeSymbolSourceArg {
    Kernel,
    Processes,
}

impl From<PeSymbolSourceArg> for starmem::windows::pe_plugins::PeSymbolSource {
    fn from(value: PeSymbolSourceArg) -> Self {
        match value {
            PeSymbolSourceArg::Kernel => Self::Kernel,
            PeSymbolSourceArg::Processes => Self::Processes,
        }
    }
}

#[derive(Args)]
struct PeSymbolsArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    #[arg(long, value_enum, default_value_t = PeSymbolSourceArg::Processes)]
    source: PeSymbolSourceArg,
    #[arg(long)]
    pid: Option<u64>,
    /// 模块基本名称或完整路径，不区分大小写。
    #[arg(long)]
    module: Option<String>,
    /// 仅解析此导出名称，不区分大小写。
    #[arg(long)]
    name: Option<String>,
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct PeDumpArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 要重建的虚拟映像基址。
    #[arg(long)]
    base: String,
    #[arg(
        long,
        conflicts_with = "kernel_module",
        required_unless_present = "kernel_module"
    )]
    pid: Option<u64>,
    #[arg(long, conflicts_with = "pid", required_unless_present = "pid")]
    kernel_module: bool,
    #[arg(short, long)]
    output: PathBuf,
    #[arg(long, default_value_t = 1_073_741_824)]
    max_output_size: u64,
}

#[derive(Args)]
struct HandleArgs {
    image: PathBuf,
    /// 枚举此进程的全部句柄；与 --object 互斥。
    #[arg(long, conflicts_with = "object", required_unless_present = "object")]
    pid: Option<u64>,
    /// 从十进制或 0x 十六进制对象地址反查全部活动句柄所有者。
    #[arg(long, conflicts_with = "pid")]
    object: Option<String>,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// --object 模式最多遍历的活动进程数。
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    /// --object 模式跨全部进程最多检查的句柄表项数。
    #[arg(long, default_value_t = 4_000_000)]
    handle_scan_limit: usize,
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Args)]
struct OpenFileArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 路径不区分大小写的子串；同时兼容 / 与反斜杠。
    #[arg(long)]
    path_contains: Option<String>,
    /// 仅保留进程名包含此字符串的活动句柄。
    #[arg(long)]
    process_contains: Option<String>,
    /// 同时输出没有活动句柄所有者的驻留 FILE_OBJECT。
    #[arg(long, conflicts_with = "process_contains")]
    include_unowned: bool,
    /// filescan 最多保留的 FILE_OBJECT 数量。
    #[arg(long, default_value_t = 1_000_000)]
    file_scan_limit: usize,
    /// 最多遍历的活动进程数。
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    /// 跨全部进程最多检查的句柄表项数。
    #[arg(long, default_value_t = 4_000_000)]
    handle_scan_limit: usize,
    /// 最多保留的关联结果数。
    #[arg(long, default_value_t = 100_000)]
    limit: usize,
}

#[derive(Args)]
struct PipeScanArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// filescan 最多保留的 FILE_OBJECT 数量。
    #[arg(long, default_value_t = 1_000_000)]
    file_limit: usize,
    /// 最多遍历的活动进程数量。
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    /// 跨全部进程最多检查的句柄表项数量。
    #[arg(long, default_value_t = 4_000_000)]
    handle_scan_limit: usize,
    /// 最多输出的命名管道对象数量。
    #[arg(long, default_value_t = 100_000)]
    limit: usize,
}

#[derive(Args)]
struct PrefetchScanArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// filescan 最多保留的 FILE_OBJECT 数量。
    #[arg(long, default_value_t = 1_000_000)]
    file_scan_limit: usize,
    /// 最多尝试恢复的 Prefetch 文件数量。
    #[arg(long, default_value_t = 4096)]
    limit: usize,
    /// 每个 Prefetch 最多输出的引用文件数量。
    #[arg(long, default_value_t = 4096)]
    reference_limit: usize,
    /// 单个驻留 Prefetch 文件的最大恢复字节数。
    #[arg(long, default_value_t = 32 * 1024 * 1024u64)]
    max_file_size: u64,
    /// 单个 MAM 容器允许的最大解压字节数。
    #[arg(long, default_value_t = 64 * 1024 * 1024usize)]
    max_uncompressed_size: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DumpSourceArg {
    Auto,
    Cache,
    Data,
    Image,
}

impl From<DumpSourceArg> for DumpSource {
    fn from(value: DumpSourceArg) -> Self {
        match value {
            DumpSourceArg::Auto => Self::Auto,
            DumpSourceArg::Cache => Self::Cache,
            DumpSourceArg::Data => Self::Data,
            DumpSourceArg::Image => Self::Image,
        }
    }
}

#[derive(Args)]
struct DumpFileArgs {
    image: PathBuf,
    /// Windows filescan/handles 的 FILE_OBJECT，或 Linux filescan 的 dentry 虚拟地址。
    #[arg(long)]
    address: String,
    /// 目标文件；Windows 会覆盖，Linux 页缓存恢复拒绝覆盖已有文件。
    #[arg(short, long)]
    output: PathBuf,
    /// 恢复来源：自动选择、缓存、数据节区或映像节区。
    #[arg(long, value_enum, default_value_t = DumpSourceArg::Auto)]
    source: DumpSourceArg,
    /// 逻辑输出大小的安全上限。
    #[arg(long, default_value_t = 16 * 1024 * 1024 * 1024u64)]
    max_size: u64,
    /// Linux 中为定位 dentry 最多保留的驻留 VFS 文件记录数。
    #[arg(long, default_value_t = 1_000_000)]
    file_scan_limit: usize,
    #[command(flatten)]
    symbols: SymbolOptions,
}

#[derive(Args)]
struct SqliteRecoverArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 主数据库 FILE_OBJECT，支持十进制或 0x 十六进制。
    #[arg(
        long,
        conflicts_with = "path_contains",
        required_unless_present = "path_contains"
    )]
    file_object: Option<String>,
    /// 通过 filescan 路径子串定位主数据库；与 --file-object 互斥。
    #[arg(long, conflicts_with = "file_object")]
    path_contains: Option<String>,
    /// 恢复数据库、sidecar 与页级清单的输出目录。
    #[arg(long)]
    output_dir: PathBuf,
    /// 恢复来源：自动选择、缓存、数据节区或映像节区。
    #[arg(long, value_enum, default_value_t = DumpSourceArg::Auto)]
    source: DumpSourceArg,
    /// 不自动定位并恢复同目录的 -wal、-shm 与 -journal。
    #[arg(long)]
    no_sidecars: bool,
    /// 仅对指定表执行行数查询；可重复传入。默认只列出全部表结构。
    #[arg(long = "table")]
    tables: Vec<String>,
    /// filescan 最多保留的 FILE_OBJECT 数量。
    #[arg(long, default_value_t = 1_000_000)]
    file_scan_limit: usize,
    /// 每个 SQLite 文件允许恢复的最大逻辑大小。
    #[arg(long, default_value_t = 4 * 1024 * 1024 * 1024u64)]
    max_size: u64,
}

#[derive(Args)]
struct ArtifactExportArgs {
    image: PathBuf,
    /// 用于保存恢复文件和 export-report.json 的目录。
    #[arg(short, long, value_name = "目录")]
    output: PathBuf,
    /// filescan 最多保留的 FILE_OBJECT 记录数。
    #[arg(long, default_value_t = 1_000_000)]
    file_scan_limit: usize,
    /// 本次导出最多尝试的匹配取证文件数。
    #[arg(long, default_value_t = 100_000)]
    artifact_limit: usize,
    /// 单个文件逻辑大小的安全上限。
    #[arg(long, default_value_t = 4 * 1024 * 1024 * 1024u64)]
    max_file_size: u64,
    #[command(flatten)]
    symbols: SymbolOptions,
}

#[derive(Args)]
struct LogExportArgs {
    #[command(flatten)]
    export: ArtifactExportArgs,
    /// 跳过自动生成 event-timeline.json 和 event-timeline.csv。
    #[arg(long)]
    no_timeline: bool,
    /// 包含全部已解析 EVTX 记录，而非仅保留高价值取证事件。
    #[arg(long)]
    all_events: bool,
    /// 内存中保留并导出的最大时间线事件数。
    #[arg(long, default_value_t = 1_000_000)]
    event_limit: usize,
}

#[derive(Args)]
struct EventTimelineArgs {
    /// 单个 EVTX 文件，或要递归搜索 EVTX 文件的目录。
    input: PathBuf,
    /// 将完整时间线报告写为 JSON。
    #[arg(short, long, value_name = "文件")]
    output: Option<PathBuf>,
    /// 包含全部已解析记录，而非仅保留高价值取证事件。
    #[arg(long)]
    all_events: bool,
    /// 内存中保留并导出的最大时间线事件数。
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum WindowsTimelineSourceArg {
    /// EPROCESS 创建和退出时间。
    Process,
    /// ETHREAD 创建和退出时间。
    Thread,
    /// NTFS MFT Standard Information 与 File Name 时间。
    Mft,
    /// Shimcache 文件最后修改时间证据。
    Shimcache,
    /// BAM/DAM、UserAssist、Amcache 与计划任务注册表时间证据。
    Registry,
}

#[derive(Args)]
struct WindowsTimelineArgs {
    /// Windows 物理内存、VMEM、崩溃转储或内存 EWF 镜像。
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 仅启用指定来源；可重复指定或使用逗号分隔，默认启用全部来源。
    #[arg(long = "source", value_enum, value_delimiter = ',')]
    sources: Vec<WindowsTimelineSourceArg>,
    /// 起始 UTC 时间（含）；支持 RFC3339 或 YYYY-MM-DD。
    #[arg(long)]
    from: Option<String>,
    /// 结束 UTC 时间（含）；支持 RFC3339 或 YYYY-MM-DD。
    #[arg(long)]
    to: Option<String>,
    /// 仅过滤带 PID 的进程和线程事件；不移除无 PID 的文件及注册表事件。
    #[arg(long)]
    pid: Option<u64>,
    /// 同时包含通常噪声较高的 MFT 文件访问时间。
    #[arg(long)]
    include_accessed: bool,
    /// 按时间从新到旧输出；默认从旧到新。
    #[arg(long)]
    reverse: bool,
    /// 最多保留的 EPROCESS 记录数。
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    /// 最多保留的 ETHREAD 记录数。
    #[arg(long, default_value_t = 262_144)]
    thread_limit: usize,
    /// 最多保留的 MFT FILE 记录数。
    #[arg(long, default_value_t = 250_000)]
    mft_limit: usize,
    /// 最多保留的 Shimcache 记录数。
    #[arg(long, default_value_t = 100_000)]
    shimcache_limit: usize,
    /// 每类注册表时间线来源最多保留的记录数。
    #[arg(long, default_value_t = 100_000)]
    registry_limit: usize,
    /// 最终时间线最多保留的事件数；达到上限时保留时间上最新的事件。
    #[arg(long, default_value_t = 1_000_000)]
    limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum WindowsExecutionSourceArg {
    /// EPROCESS CreateTime 与进程身份、PID、映像路径。
    Process,
    /// 驻留 Windows Prefetch 文件中的程序运行记录。
    Prefetch,
    /// SYSTEM Hive 中的 BAM/DAM 执行时间。
    BamDam,
    /// 用户 Hive 中的 UserAssist 运行记录。
    Userassist,
    /// Shimcache 文件修改时间上下文。
    Shimcache,
    /// Amcache 清单键最后写入时间上下文。
    Amcache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum WindowsRecentFilesSourceArg {
    /// WPS Writer/ET/WPP/PDF/OFD RecentFiles Sequence。
    Wps,
    /// Explorer RecentDocs 与 MRUListEx。
    Recentdocs,
}

#[derive(Args)]
struct WindowsRecentFilesArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 仅启用指定来源；可重复指定或逗号分隔，默认启用全部。
    #[arg(long = "source", value_enum, value_delimiter = ',')]
    sources: Vec<WindowsRecentFilesSourceArg>,
    /// 按账户名或 SID 筛选用户 NTUSER.DAT。
    #[arg(long)]
    user: Option<String>,
    /// 路径不区分大小写的子串筛选。
    #[arg(long)]
    path_contains: Option<String>,
    /// 最多枚举的 Hive 数量。
    #[arg(long, default_value_t = 65_536)]
    hive_limit: usize,
    /// 每次注册表递归最多保留的记录数。
    #[arg(long, default_value_t = 100_000)]
    registry_limit: usize,
    /// 最多保留的最近文件记录数。
    #[arg(long, default_value_t = 100_000)]
    limit: usize,
}

#[derive(Args)]
struct UsbHistoryArgs {
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 按设备序列号筛选。
    #[arg(long)]
    serial: Option<String>,
    /// 按 ContainerID 筛选。
    #[arg(long)]
    container_id: Option<String>,
    /// 同时输出非存储类 USB 接口。
    #[arg(long)]
    include_non_storage: bool,
    /// 只接受显式 LastArrivalDate；缺失时不使用主存储实例键 LastWrite 代理。
    #[arg(long)]
    strict_last_arrival: bool,
    /// 最多枚举的活动进程数量，用于恢复注册表 Hive。
    #[arg(long, default_value_t = 65_536)]
    process_limit: usize,
    /// 最多保留的物理设备数量。
    #[arg(long, default_value_t = 65_536)]
    limit: usize,
}

#[derive(Args)]
struct WindowsExecutionArgs {
    /// Windows 物理内存、VMEM、崩溃转储或内存 EWF 镜像。
    image: PathBuf,
    #[command(flatten)]
    symbols: SymbolOptions,
    /// 仅启用指定来源；可重复指定或使用逗号分隔，默认启用全部来源。
    #[arg(long = "source", value_enum, value_delimiter = ',')]
    sources: Vec<WindowsExecutionSourceArg>,
    /// 将 EPROCESS 创建时间纳入执行证据；--aggregate 且未限定来源时自动启用。
    #[arg(long)]
    include_processes: bool,
    /// 将时间相近且身份一致的原始证据聚合为执行 episode；原 events 仍保留。
    #[arg(long)]
    aggregate: bool,
    /// 按程序名、路径或规范化程序标识筛选。
    #[arg(long)]
    program: Option<String>,
    /// 按用户名或 SID 筛选。
    #[arg(long)]
    user: Option<String>,
    /// 聚合同一执行 episode 的最大时间差，单位毫秒。
    #[arg(long, default_value_t = 2_000)]
    correlation_window_ms: u64,
    /// 每个规范化程序只保留最新 episode。
    #[arg(long, requires = "aggregate")]
    latest_per_program: bool,
    /// 只输出具备直接执行时间语义的 Prefetch、BAM/DAM 与 UserAssist。
    #[arg(long)]
    exact_only: bool,
    /// 起始 UTC 时间（含）；支持 RFC3339 或 YYYY-MM-DD。
    #[arg(long)]
    from: Option<String>,
    /// 结束 UTC 时间（含）；支持 RFC3339 或 YYYY-MM-DD。
    #[arg(long)]
    to: Option<String>,
    /// 按时间从旧到新输出；默认从新到旧。
    #[arg(long)]
    oldest_first: bool,
    /// filescan 最多保留的 FILE_OBJECT 数量。
    #[arg(long, default_value_t = 1_000_000)]
    file_scan_limit: usize,
    /// 最多尝试恢复的 Prefetch 文件数量。
    #[arg(long, default_value_t = 4096)]
    prefetch_limit: usize,
    /// 每个 Prefetch 最多输出和用于关联的引用文件数量。
    #[arg(long, default_value_t = 1024)]
    reference_limit: usize,
    /// 单个驻留 Prefetch 文件的最大恢复字节数。
    #[arg(long, default_value_t = 32 * 1024 * 1024u64)]
    max_prefetch_file_size: u64,
    /// 单个 MAM 容器允许的最大解压字节数。
    #[arg(long, default_value_t = 64 * 1024 * 1024usize)]
    max_prefetch_uncompressed_size: usize,
    /// 每类注册表执行来源最多保留的记录数。
    #[arg(long, default_value_t = 100_000)]
    registry_limit: usize,
    /// 最多保留的 Shimcache 记录数。
    #[arg(long, default_value_t = 100_000)]
    shimcache_limit: usize,
    /// 最终最多保留的执行证据事件数。
    #[arg(long, default_value_t = 500_000)]
    limit: usize,
}

#[derive(Serialize)]
struct InfoReport<'a> {
    path: String,
    file_size: u64,
    logical_size: u64,
    mapped_bytes: u64,
    format: &'a ImageFormat,
    sources: Vec<&'a starmem::image::ImageSourceInfo>,
    physical_spans: &'a [starmem::image::PhysicalSpan],
    missing_ranges: &'a [starmem::image::PhysicalMissingRange],
}

#[derive(Serialize)]
struct TranslationReport {
    virtual_address: u64,
    physical_address: u64,
    directory_table_base: u64,
}

#[derive(Serialize)]
struct FetchReport {
    record: starmem::symbols::CodeViewRecord,
    path: String,
}

const CHINESE_HELP_TEMPLATE: &str =
    "{before-help}{about-with-newline}\n用法：{usage}\n\n{all-args}{after-help}";

fn cli_command(english: bool) -> clap::Command {
    let mut command = Cli::command().arg(
        clap::Arg::new("help_en")
            .long("help-en")
            .global(true)
            .action(clap::ArgAction::HelpLong),
    );
    // 先让 Clap 生成内置帮助和版本参数，再为整个命令树设置帮助语言。
    command.build();
    localize_command(command, english)
}

fn localize_command(mut command: clap::Command, english: bool) -> clap::Command {
    if command.get_name() == "help" {
        command = command.about("显示当前命令或指定子命令的帮助信息");
    }
    let command_name = command.get_name().to_owned();
    command = if english {
        cli_help_en::localize(command)
    } else {
        command
            .help_template(CHINESE_HELP_TEMPLATE)
            .subcommand_help_heading("命令")
            .subcommand_value_name("命令")
            .hide_possible_values(true)
            .mut_args(move |argument| localize_argument(argument, &command_name))
    };

    let subcommands = command
        .get_subcommands()
        .map(|subcommand| subcommand.get_name().to_owned())
        .collect::<Vec<_>>();
    for name in subcommands {
        command = command.mut_subcommand(name, |child| localize_command(child, english));
    }
    command
}

fn localize_argument(mut argument: clap::Arg, command_name: &str) -> clap::Arg {
    let id = argument.get_id().as_str().to_owned();
    let positional = argument.is_positional();
    let existing_help = argument.get_help().map(ToString::to_string);
    let mut help = argument_help(command_name, &id)
        .map(str::to_owned)
        .or(existing_help)
        .unwrap_or_else(|| format!("命令参数 {id}"));

    let defaults = argument
        .get_default_values()
        .iter()
        .map(|value| value.to_string_lossy())
        .collect::<Vec<_>>();
    if !defaults.is_empty() {
        help.push_str(&format!("（默认值：{}）", defaults.join(", ")));
    }

    argument = argument
        .help(help)
        .long_help(None)
        .hide_default_value(true)
        .hide_possible_values(true)
        .help_heading(if positional { "位置参数" } else { "选项" });
    if let Some(value_name) = argument_value_name(&id) {
        argument = argument.value_name(value_name);
    }
    argument
}

fn argument_help(command_name: &str, id: &str) -> Option<&'static str> {
    if command_name == "browser-history" {
        match id {
            "database_limit" => return Some("最多恢复和解析的 Chromium History 数据库数量"),
            "max_database_mib" => {
                return Some("单个 History 数据库允许恢复的最大大小，单位为 MiB");
            }
            "limit" => return Some("最多保留的 URL 摘要与逐次访问记录数量"),
            _ => {}
        }
    }
    if id == "process_space_limit" && command_name == "collect" {
        return Some("文本、浏览器、微信等插件最多反向映射的进程地址空间数量");
    }
    if id == "max_data_mib" && command_name == "collect" {
        return Some("单个数据库、剪切板块或历史文件允许读取的最大大小，单位为 MiB");
    }
    if id == "limit" && command_name == "collect" {
        return Some("每个普通插件最多保留的结果数量");
    }
    if id == "source" && command_name == "pe-symbols" {
        return Some("符号来源：kernel 表示内核模块，processes 表示进程模块");
    }
    if id == "output" && command_name == "packetscan" {
        return Some("将恢复的数据包写入 PCAPNG 文件");
    }
    if id == "address" && command_name == "mftdump" {
        return Some("mftscan 报告的 MFT FILE 记录物理地址");
    }
    if id == "address" && command_name == "dumpfile" {
        return Some(
            "Windows filescan/handles 的 FILE_OBJECT，或 Linux filescan 的 dentry 虚拟地址",
        );
    }
    if id == "source" && command_name == "dumpfile" {
        return Some("Windows 恢复来源；Linux 物理内存当前仅接受默认 auto，并从页缓存恢复");
    }
    if id == "output" && command_name == "dumpfile" {
        return Some("恢复内容目标文件；Linux 完整结果使用此路径，不完整结果保留为同名 .partial");
    }
    if id == "file_scan_limit" && command_name == "dumpfile" {
        return Some("Linux 定位 dentry 时最多保留的驻留 VFS 文件记录数；Windows 忽略");
    }
    if id == "file_scan_limit" && command_name == "linux.passwd" {
        return Some("定位 /etc/passwd 时最多保留的驻留 VFS 文件记录数");
    }
    if id == "process_space_limit" && command_name == "wechatscan" {
        return Some("最多反向映射的微信进程地址空间数量");
    }
    if id == "process_space_limit" && command_name == "residualscan" {
        return Some("最多反向映射的候选文本进程地址空间数量");
    }
    if id == "search_texts" && command_name == "residualscan" {
        return Some("精确搜索任意文本；同时匹配 UTF-8 和 UTF-16LE，可多次指定");
    }
    if id == "verify_db_roots" && command_name == "wechatscan" {
        return Some("用候选密钥验证目录中的本机微信数据库；可多次指定");
    }
    Some(match id {
        "help" => "显示帮助信息",
        "help_en" => "显示英文帮助",
        "version" => "显示版本信息",
        "image" => "要分析的内存镜像文件",
        "input" => "输入文件或目录",
        "output" => "输出文件或目录",
        "json" => "输出便于程序处理的 JSON",
        "threads" => "并行工作线程数；0 表示使用全部逻辑处理器",
        "no_progress" => "禁用交互终端中的动态分析进度条",
        "command" | "subcommand" => "要查看帮助的子命令",
        "text" => "要搜索的 UTF-8 文本",
        "search_texts" => "要精确搜索的任意文本；可多次指定",
        "hex" => "要搜索的十六进制字节",
        "limit" => "最多保留的结果数量",
        "chunk_mib" => "每个扫描块的大小，单位为 MiB",
        "process_limit" => "最多分析的进程数量",
        "network_limit" => "最多分析的网络记录数量",
        "address" => "虚拟地址或对象地址",
        "dtb" => "显式指定的页表根地址（DTB/CR3）",
        "name" => "名称",
        "query" => "要搜索的符号文本",
        "pdb" => "本地 PDB 符号文件",
        "profile" => "已有的 JSON 符号配置文件",
        "base" => "虚拟基址",
        "fetch" => "将发现的 PDB 下载到符号缓存",
        "csv" => "将当前插件的完整结构化报告写为兼容 Excel 的 UTF-8 CSV；使用 - 输出到标准输出",
        "cache" => "可写符号缓存目录；同时兼容 --symbol-cache",
        "search_roots" => {
            "共享只读符号根；Linux 复用 Volatility 3 ISF，未知构建最后使用远程精确 banner 兜底；可多次指定"
        }
        "registry" => "同时恢复 SYSTEM 注册表中的服务元数据",
        "hive" => "Hive 名称或完整注册表根路径",
        "key" => "相对于所选 Hive 根的键路径",
        "recurse" => "递归输出全部子键",
        "pid" => "进程 ID",
        "tags" => "四字节池标签；可多次指定",
        "show_free" => "包含已标记为空闲的池条目",
        "limit_per_tag" => "每个池标签最多保留的结果数量",
        "strings_file" => "包含偏移和文本的 strings 输出文件",
        "offset_kind" => "偏移类型：file 表示镜像文件，physical 表示物理内存",
        "pattern" => "字节正则表达式",
        "overlap_kib" => "相邻扫描块的重叠大小，单位为 KiB",
        "rules" => "YARA 规则文件；可多次指定",
        "source" => "恢复来源：auto 自动选择，cache 缓存，data 数据节区，image 映像节区",
        "kernel_module" => "从内核模块重建 PE 映像",
        "force" => "允许覆盖已存在的输出文件",
        "max_output_size" => "PE 输出文件的最大安全大小",
        "max_size" => "恢复文件的最大逻辑大小",
        "attribute_id" => "按 MFT 属性 ID 精确选择要导出的 $DATA",
        "stream" => "备用数据流名称；不指定时导出无名 $DATA",
        "file_scan_limit" => "filescan 最多保留的 FILE_OBJECT 记录数",
        "database_limit" => "最多恢复和解析的 Cookie 数据库及旧式 Cookie 文件数量",
        "max_database_mib" => "单个 Cookie 数据库的最大恢复大小，单位为 MiB",
        "max_data_mib" => "单个活动剪切板数据块的最大读取大小，单位为 MiB",
        "process_space_limit" => "最多反向映射的浏览器相关进程地址空间数量",
        "main_only" => "仅分析微信主进程，跳过辅助进程和小程序运行时",
        "anchor_limit" => "十六进制字面量锚点最多保留的数量",
        "verification_file_limit" => "最多读取的本机微信数据库验证文件数量",
        "session_limit" => "最多保留的浏览器会话数量",
        "cookie_limit" => "最多保留的去重 Cookie 数量",
        "download_limit" => "最多保留的去重下载痕迹数量",
        "endpoint_limit" => "用于关联 PID 和进程的网络端点数量上限",
        "max_packet_size" => "允许恢复的单个 IP 包最大字节数",
        "max_occurrences" => "每个去重数据包最多保留的物理证据地址数量",
        "artifact_limit" => "本次最多尝试导出的匹配取证文件数",
        "max_file_size" => "单个导出文件的最大逻辑大小",
        "no_timeline" => "不自动生成事件时间线文件",
        "all_events" => "包含全部事件，而非仅保留高价值取证事件",
        "event_limit" => "最多保留并导出的时间线事件数",
        _ => return None,
    })
}

fn argument_value_name(id: &str) -> Option<&'static str> {
    Some(match id {
        "image" => "镜像文件",
        "input" => "输入路径",
        "output" | "csv" | "pdb" | "profile" | "strings_file" | "rules" => "文件",
        "cache" | "search_roots" | "verify_db_roots" => "目录",
        "address" | "base" | "dtb" => "地址",
        "attribute_id" => "属性ID",
        "pid" => "进程ID",
        "limit"
        | "limit_per_tag"
        | "process_limit"
        | "network_limit"
        | "file_scan_limit"
        | "artifact_limit"
        | "event_limit"
        | "database_limit"
        | "process_space_limit"
        | "session_limit"
        | "cookie_limit"
        | "download_limit"
        | "endpoint_limit"
        | "max_packet_size"
        | "max_occurrences" => "数量",
        "anchor_limit" => "数量",
        "verification_file_limit" => "数量",
        "threads" => "线程数",
        "chunk_mib" | "overlap_kib" | "max_output_size" | "max_size" | "max_file_size"
        | "max_database_mib" | "max_data_mib" => "大小",
        "tags" => "标签",
        "command" | "subcommand" => "命令",
        "text" | "search_texts" | "hex" | "name" | "query" | "hive" | "key" | "pattern"
        | "stream" => "值",
        "offset_kind" => "类型",
        "source" => "来源",
        _ => return None,
    })
}

fn clap_context(error: &clap::Error, wanted: clap::error::ContextKind) -> Option<String> {
    error
        .context()
        .find_map(|(kind, value)| (kind == wanted).then(|| value.to_string()))
        .filter(|value| !value.trim().is_empty())
}

fn exit_clap_error(error: clap::Error, english_help: bool) -> ! {
    use clap::error::{ContextKind, ErrorKind};

    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    ) {
        if english_help && error.kind() == ErrorKind::DisplayHelp {
            error.exit();
        }
        print!("{}", localize_generated_text(&error.render().to_string()));
        std::process::exit(error.exit_code());
    }
    if error.kind() == ErrorKind::DisplayVersion {
        error.exit();
    }

    let invalid_arg = clap_context(&error, ContextKind::InvalidArg);
    let invalid_subcommand = clap_context(&error, ContextKind::InvalidSubcommand);
    let invalid_value = clap_context(&error, ContextKind::InvalidValue);
    let prior_arg = clap_context(&error, ContextKind::PriorArg);
    let detail = match error.kind() {
        ErrorKind::MissingRequiredArgument => format!(
            "缺少以下必需参数：\n{}",
            invalid_arg.as_deref().unwrap_or("  （无法确定参数名称）")
        ),
        ErrorKind::MissingSubcommand => "缺少必需的子命令。".to_owned(),
        ErrorKind::UnknownArgument => format!(
            "无法识别参数 {}。",
            invalid_arg.as_deref().unwrap_or("（未知）")
        ),
        ErrorKind::InvalidSubcommand => format!(
            "无法识别子命令 {}。",
            invalid_subcommand.as_deref().unwrap_or("（未知）")
        ),
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => format!(
            "参数 {} 的值 {} 无效。",
            invalid_arg.as_deref().unwrap_or("（未知）"),
            invalid_value.as_deref().unwrap_or("（未知）")
        ),
        ErrorKind::ArgumentConflict => format!(
            "参数 {} 与 {} 不能同时使用。",
            invalid_arg.as_deref().unwrap_or("（未知）"),
            prior_arg.as_deref().unwrap_or("另一个参数")
        ),
        ErrorKind::NoEquals => format!(
            "参数 {} 必须使用等号传值。",
            invalid_arg.as_deref().unwrap_or("（未知）")
        ),
        ErrorKind::TooManyValues => format!(
            "参数 {} 接收到的值过多。",
            invalid_arg.as_deref().unwrap_or("（未知）")
        ),
        ErrorKind::TooFewValues => format!(
            "参数 {} 接收到的值不足。",
            invalid_arg.as_deref().unwrap_or("（未知）")
        ),
        ErrorKind::WrongNumberOfValues => format!(
            "参数 {} 的值数量不正确。",
            invalid_arg.as_deref().unwrap_or("（未知）")
        ),
        _ => "命令行参数无效。".to_owned(),
    };

    eprintln!("参数错误：{detail}");
    if let Some(usage) = clap_context(&error, ContextKind::Usage) {
        let usage = usage.trim().strip_prefix("Usage:").unwrap_or(usage.trim());
        eprintln!("\n用法：{}", localize_generated_text(usage.trim()));
    }
    eprintln!("\n请使用 --help 查看中文帮助。");
    std::process::exit(error.exit_code());
}

fn localize_generated_text(text: &str) -> String {
    text.replace("[OPTIONS]", "[选项]")
        .replace("<COMMAND>", "<命令>")
        .replace("[COMMAND]", "[命令]")
}

fn main() {
    configure_windows_console();
    // Clap's generated parser and the large command dispatcher are deep in
    // unoptimized Windows builds.  Run the CLI on an explicitly sized stack
    // so adding real plugins cannot exhaust the platform's small main stack.
    let result = std::thread::Builder::new()
        .name("starmem-main".to_owned())
        .stack_size(ANALYSIS_THREAD_STACK_BYTES)
        .spawn(run)
        .expect("无法启动 starmem 工作线程")
        .join()
        .unwrap_or_else(|_| Err(anyhow::anyhow!("starmem 工作线程异常退出")));
    if let Err(error) = result {
        eprintln!("错误：{}", localize_runtime_message(&format!("{error:#}")));
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn configure_windows_console() {
    use windows_sys::Win32::System::Console::{SetConsoleCP, SetConsoleOutputCP};

    // Native PowerShell commonly leaves the console on CP936.  Rust writes
    // UTF-8 to redirected streams, so align the attached console with the
    // same encoding and keep direct output, pipes and JSON consistent.
    unsafe {
        SetConsoleCP(65001);
        SetConsoleOutputCP(65001);
    }
}

#[cfg(not(windows))]
fn configure_windows_console() {}

fn wants_english_help(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|arg| arg.as_os_str() != "--")
        .any(|arg| arg == "--help-en")
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    let english_help = wants_english_help(&args);
    let mut matches = match cli_command(english_help).try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(error) => exit_clap_error(error, english_help),
    };
    let output_policy = output_policy_from_matches(&matches)?;
    output_policy.preflight()?;
    OUTPUT_POLICY
        .set(output_policy)
        .map_err(|_| anyhow::anyhow!("输出安全策略已被重复初始化"))?;
    let qevm_layout = match (
        matches
            .try_get_one::<String>("qevm_ram_block")
            .ok()
            .flatten(),
        matches
            .try_get_one::<String>("qevm_below_4g_length")
            .ok()
            .flatten(),
        matches
            .try_get_one::<String>("qevm_above_4g_base")
            .ok()
            .flatten(),
    ) {
        (Some(ram_block), Some(below_4g_length), Some(above_4g_physical_base)) => {
            Some(QevmPhysicalLayout {
                ram_block: ram_block.clone(),
                below_4g_length: parse_integer(below_4g_length)
                    .context("--qevm-below-4g-length 无效")?,
                above_4g_physical_base: parse_integer(above_4g_physical_base)
                    .context("--qevm-above-4g-base 无效")?,
            })
        }
        (None, None, None) => None,
        _ => bail!("QEVM 物理布局的三个参数必须同时提供"),
    };
    IMAGE_OPEN_OPTIONS
        .set(ImageOpenOptions {
            metadata_path: matched_path_argument(&matches, "metadata").map(Path::to_path_buf),
            qevm_layout,
            ..ImageOpenOptions::default()
        })
        .map_err(|_| anyhow::anyhow!("镜像打开选项已被重复初始化"))?;
    let evidence_context = evidence_output_context(&matches)?;
    EVIDENCE_OUTPUT_CONTEXT
        .set(evidence_context)
        .map_err(|_| anyhow::anyhow!("Evidence 输出上下文已被重复初始化"))?;
    // Perform the global CSV/input collision check against the still-intact
    // Clap match tree.  This covers every selected command (including nested
    // `symbols` subcommands) that declares an `image` argument without keeping
    // a second, manually synchronized list of command variants.
    ensure_matched_csv_does_not_overwrite_image(&matches)?;
    let mut cli = match Cli::from_arg_matches_mut(&mut matches) {
        Ok(cli) => cli,
        Err(error) => exit_clap_error(error, false),
    };
    if !cli.no_progress
        && !cli.json
        && cli.csv.is_none()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal()
    {
        let _ = starmem::progress::install_progress_observer(Arc::new(
            TerminalProgressObserver::default(),
        ));
    }
    if let Some(path) = cli.csv.clone() {
        CSV_OUTPUT
            .set(path)
            .map_err(|_| anyhow::anyhow!("CSV 输出状态已被重复初始化"))?;
        // 复用每个插件现有的结构化报告分支，由 print_json 统一切换为 CSV 编码。
        cli.json = true;
    }
    if let Some(path) = cli.raw_objects.clone() {
        RAW_OBJECTS_OUTPUT
            .set(path)
            .map_err(|_| anyhow::anyhow!("Raw objects 输出状态已被重复初始化"))?;
    }
    let mut thread_pool = rayon::ThreadPoolBuilder::new()
        .stack_size(ANALYSIS_THREAD_STACK_BYTES)
        .thread_name(|index| format!("starmem-cli-{index}"));
    if cli.threads > 0 {
        thread_pool = thread_pool.num_threads(cli.threads);
    }
    thread_pool
        .build_global()
        .context("无法配置并行工作线程池")?;
    let debug_registers_command = matches!(&cli.command, Command::Debugregisters(_));
    let force = cli.force;

    match cli.command {
        Command::BuildInfo => {
            let report = current_build_info();
            if cli.json {
                print_json(&report)?;
            } else {
                println!("StarMem {}", report.version);
                println!("Build ID：{}", report.build_id);
                println!("Git commit：{}", report.git_commit.unwrap_or("未知"));
                println!(
                    "工作树：{}",
                    match report.dirty {
                        Some(true) => "dirty",
                        Some(false) => "clean",
                        None => "unknown",
                    }
                );
                println!("Rust target：{}", report.rust_target);
                println!(
                    "Features：{}",
                    if report.features.is_empty() {
                        "(none)".to_owned()
                    } else {
                        report.features.join(",")
                    }
                );
                println!(
                    "Host API schema={}；Evidence schema={}；Command registry schema={}；Leaf manifest schema={}；Integration API={}；SQLite schema={}；Raw object schema={}",
                    report.host_api_schema_version,
                    report.evidence_schema_version,
                    report.command_registry_schema_version,
                    report.leaf_command_manifest_schema_version,
                    report.integration_api_version,
                    report.sqlite_schema_version,
                    report.raw_object_schema_version,
                );
            }
        }
        Command::Collect(args) => {
            ensure!(args.limit > 0, "每个插件的结果上限必须大于零");
            ensure!(args.file_scan_limit > 0, "文件扫描结果上限必须大于零");
            ensure!(
                args.process_space_limit > 0,
                "进程地址空间数量上限必须大于零"
            );
            let max_data_size = args
                .max_data_mib
                .checked_mul(1024 * 1024)
                .context("数据库采集的单项最大读取大小溢出")?;
            let options = DatabaseCollectionOptions {
                database: args.db,
                session: args.symbols.session_options(),
                result_limit: args.limit,
                file_scan_limit: args.file_scan_limit,
                process_space_limit: args.process_space_limit,
                max_data_size,
            };
            let report = collect_to_sqlite(&args.image, &options, |event| match event {
                DatabaseCollectionEvent::Opening => {
                    eprintln!("[准备] 正在加载镜像、Windows 内核和符号表……")
                }
                DatabaseCollectionEvent::Started {
                    index,
                    total,
                    plugin,
                    display_name,
                } => eprintln!("[{index}/{total}] 正在执行 {display_name}（{plugin}）……"),
                DatabaseCollectionEvent::Finished {
                    index,
                    total,
                    plugin,
                    display_name,
                    outcome,
                } => match outcome.status.as_str() {
                    "success" => eprintln!(
                        "[{index}/{total}] {display_name}（{plugin}）完成：{} 行，{:.3} 秒",
                        outcome.rows_written, outcome.duration_seconds
                    ),
                    "incomplete" => eprintln!(
                        "[{index}/{total}] {display_name}（{plugin}）结果不完整：{} 行，{:.3} 秒",
                        outcome.rows_written, outcome.duration_seconds
                    ),
                    "unknown_completeness" => eprintln!(
                        "[{index}/{total}] {display_name}（{plugin}）未声明完整性（按不完整计入汇总）：{} 行，{:.3} 秒",
                        outcome.rows_written, outcome.duration_seconds
                    ),
                    "skipped" => eprintln!(
                        "[{index}/{total}] 已跳过 {display_name}（{plugin}）：{}",
                        outcome.error.as_deref().unwrap_or("不适用于自动采集")
                    ),
                    _ => eprintln!(
                        "[{index}/{total}] {display_name}（{plugin}）失败：{}",
                        outcome.error.as_deref().unwrap_or("未知错误")
                    ),
                },
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("SQLite 数据库：{}", report.database.display());
                println!("分析批次 ID：{}", report.analysis_id);
                println!("插件总数：{}", report.plugins_total);
                println!(
                    "已执行={}；成功={}；结果不完整={}；失败={}；跳过={}",
                    report.plugins_executed,
                    report.plugins_succeeded,
                    report.plugins_incomplete,
                    report.plugins_failed,
                    report.plugins_skipped,
                );
                println!("写入行数：{}", report.rows_written);
                println!("总耗时：{:.3} 秒", report.total_seconds);
            }
        }
        Command::Info { image } => {
            let image = open_memory_image(image)?;
            let report = InfoReport {
                path: image.path().display().to_string(),
                file_size: image.file_len(),
                logical_size: image.logical_len(),
                mapped_bytes: image.mapped_bytes(),
                format: image.format(),
                sources: image.sources().collect(),
                physical_spans: image.spans(),
                missing_ranges: image.missing_ranges(),
            };
            if cli.json {
                print_json(&report)?;
            } else {
                println!("镜像：{}", report.path);
                println!("格式：{:?}", report.format);
                println!("文件字节数：{}", report.file_size);
                println!("逻辑介质字节数：{}", report.logical_size);
                println!("已映射物理字节数：{}", report.mapped_bytes);
                println!("source 数：{}", report.sources.len());
                for source in &report.sources {
                    println!(
                        "  source[{}] {:?} {}（容器={} 逻辑={}）",
                        source.index,
                        source.role,
                        source.path.display(),
                        source.container_len,
                        source.logical_len
                    );
                }
                println!("物理区间数：{}", report.physical_spans.len());
                for span in report.physical_spans {
                    println!(
                        "  {:#018x}-{:#018x} -> source[{}] 容器偏移 {:#x}，{:?}（{} 字节）",
                        span.start,
                        span.end() - 1,
                        span.source_index,
                        span.file_offset,
                        span.encoding,
                        span.length
                    );
                }
                if !report.missing_ranges.is_empty() {
                    println!("缺失物理区间数：{}", report.missing_ranges.len());
                    for range in report.missing_ranges {
                        println!(
                            "  {:#018x}-{:#018x}（{}）",
                            range.start,
                            range.start + range.length - 1,
                            range.source
                        );
                    }
                }
            }
        }
        Command::WindowsInfo(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let context = session.kernel();
            if cli.json {
                print_json(&context)?;
            } else {
                println!("定位方式：{:?}", context.discovery_method);
                println!("DTB/CR3: {:#018x}", context.directory_table_base);
                println!("内核基址：{:#018x}", context.kernel_base);
                println!(
                    "PsActiveProcessHead: {:#018x}",
                    context.ps_active_process_head
                );
                println!(
                    "PsLoadedModuleList: {:#018x}",
                    context.ps_loaded_module_list
                );
            }
        }
        Command::ScreenResolution(args) => run_screen_resolution_plugin(args, cli.json)?,
        Command::SystemArtifacts(args) => {
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = analyze_system_artifacts(&session)?;
            if cli.json || CSV_OUTPUT.get().is_some() {
                print_json(&report)?;
            } else {
                println!("打印机：{}", report.printers.len());
                println!("系统策略：{}", report.policies.len());
                println!("安全软件：{}", report.security_software.len());
                println!("虚拟化指标：{}", report.virtualization.len());
                println!("WMI 配置：{}", report.wmi_configuration.len());
                println!("日志配置：{}", report.event_log_configuration.len());
                println!("崩溃转储配置：{}", report.crash_dump_configuration.len());
                println!("RDP 配置与历史：{}", report.rdp_history.len());
                println!("网络配置：{}", report.network_configuration.len());
                println!("WiFi/网络历史：{}", report.wireless_history.len());
                println!("结果完整：{}", if report.complete { "是" } else { "否" });
                for warning in &report.warnings {
                    eprintln!("警告：{warning}");
                }
            }
        }
        Command::SystemInfo(args) => {
            eprintln!("[1/3] 正在打开内存镜像并加载精确符号……");
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            let report = if args.quick {
                eprintln!("[2/3] 正在生成快速系统概览……");
                analyze_system_info_quick(&session, args.process_limit)?
            } else {
                eprintln!("[2/3] 正在分析系统、进程、网络和注册表证据……");
                analyze_system_info(&session, args.process_limit, args.network_limit)?
            };
            eprintln!("[3/3] 正在整理时区、时间戳和系统取证摘要……");
            if let Some(path) = &args.output {
                write_json_file(path, &report)?;
            }
            if cli.json {
                print_json(&report)?;
            } else {
                println!("【镜像】");
                println!("路径：{}", report.image.path);
                println!(
                    "格式：{}；文件大小：{}；映射物理内存：{}",
                    localized_image_format(&report.image.format),
                    format_byte_size(report.image.file_size),
                    format_byte_size(report.image.mapped_physical_bytes)
                );

                println!("\n【系统身份】");
                println!(
                    "计算机名：{}",
                    optional_text(report.host.computer_name.as_deref())
                );
                println!(
                    "注册表主机名：{}；域/工作组：{}；进程环境域：{}",
                    optional_text(report.host.registry_hostname.as_deref()),
                    optional_text(report.host.registry_domain.as_deref()),
                    optional_text(report.host.user_domain.as_deref())
                );

                println!("\n【操作系统】");
                println!(
                    "系统版本：{}",
                    report
                        .operating_system
                        .system_version
                        .as_deref()
                        .unwrap_or("未知")
                );
                println!(
                    "版本来源：{}",
                    report.operating_system.system_version_source
                );
                println!(
                    "产品：{}；显示版本：{}；版本标识：{}",
                    report
                        .operating_system
                        .registry_product_name
                        .as_deref()
                        .unwrap_or("未知"),
                    report
                        .operating_system
                        .display_version
                        .as_deref()
                        .unwrap_or("未知"),
                    report
                        .operating_system
                        .release_id
                        .as_deref()
                        .unwrap_or("未知")
                );
                println!(
                    "内核版本：{}.{}.{}；产品类型：{}；版本：{}；安装类型：{}",
                    optional_u32(report.operating_system.major_version),
                    optional_u32(report.operating_system.minor_version),
                    optional_u32(report.operating_system.build_number),
                    localized_product_type(report.operating_system.product_type.as_deref()),
                    report
                        .operating_system
                        .edition_id
                        .as_deref()
                        .unwrap_or("未知"),
                    report
                        .operating_system
                        .installation_type
                        .as_deref()
                        .unwrap_or("未知")
                );
                println!(
                    "注册表版本字段：CurrentVersion={}；Major={}；Minor={}",
                    report
                        .operating_system
                        .registry_current_version
                        .as_deref()
                        .unwrap_or("未知"),
                    optional_u32(report.operating_system.registry_major_version),
                    optional_u32(report.operating_system.registry_minor_version)
                );
                println!(
                    "构建：{}.{}；分支：{}；构建实验室：{}",
                    report
                        .operating_system
                        .registry_current_build
                        .as_deref()
                        .unwrap_or("未知"),
                    optional_u32(report.operating_system.update_build_revision),
                    report
                        .operating_system
                        .build_branch
                        .as_deref()
                        .unwrap_or("未知"),
                    report
                        .kernel
                        .build_lab_ex
                        .as_deref()
                        .or(report.operating_system.registry_build_lab_ex.as_deref())
                        .unwrap_or("未知")
                );
                println!(
                    "组合版本：{}；系统类型：{}；服务包：{}",
                    report
                        .operating_system
                        .composition_edition_id
                        .as_deref()
                        .unwrap_or("未知"),
                    report
                        .operating_system
                        .current_type
                        .as_deref()
                        .unwrap_or("未知"),
                    report
                        .operating_system
                        .service_pack
                        .as_deref()
                        .unwrap_or("无或未恢复")
                );
                println!(
                    "架构：{}；系统根目录：{}",
                    report.kernel.architecture,
                    report
                        .operating_system
                        .system_root
                        .as_deref()
                        .unwrap_or("未知")
                );
                println!(
                    "注册所有者：{}；注册组织：{}；产品 ID：{}",
                    report
                        .operating_system
                        .registered_owner
                        .as_deref()
                        .unwrap_or("未知"),
                    report
                        .operating_system
                        .registered_organization
                        .as_deref()
                        .unwrap_or("未知"),
                    report
                        .operating_system
                        .product_id
                        .as_deref()
                        .unwrap_or("未知")
                );
                print_forensic_time(
                    "操作系统安装时间",
                    &report.operating_system.install_time_details,
                );

                println!("\n【时间证据】");
                println!(
                    "镜像时区：{}（{}）；标准名称：{}；夏令时名称：{}",
                    report
                        .clock
                        .timezone
                        .windows_key_name
                        .as_deref()
                        .unwrap_or("未知"),
                    report
                        .clock
                        .timezone
                        .utc_offset
                        .as_deref()
                        .unwrap_or("UTC 偏移未知"),
                    report
                        .clock
                        .timezone
                        .standard_name
                        .as_deref()
                        .unwrap_or("未知"),
                    report
                        .clock
                        .timezone
                        .daylight_name
                        .as_deref()
                        .unwrap_or("未知")
                );
                println!(
                    "有效 Windows Bias：{} 分钟；动态夏令时已禁用：{}",
                    report
                        .clock
                        .timezone
                        .effective_bias_minutes
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "未知".to_owned()),
                    optional_yes_no(report.clock.timezone.dynamic_daylight_disabled)
                );
                println!("时区来源：{}", report.clock.timezone.source);
                println!("时区说明：{}", report.clock.timezone.conversion_note);
                print_forensic_time("镜像系统时间", &report.clock.system_time_details);
                print_forensic_time("本次启动时间", &report.clock.boot_time_details);
                print_forensic_time("上次正常关机时间", &report.clock.last_shutdown_time_details);
                let uptime = report
                    .clock
                    .uptime_seconds
                    .map(|seconds| format!("{}（{seconds:.3} 秒）", format_duration(Some(seconds))))
                    .unwrap_or_else(|| "未知".to_owned());
                println!("系统运行时长：{uptime}");

                println!("\n【启动与硬件】");
                println!(
                    "启动 ID：{}；安全模式：{}；内核调试：{}",
                    optional_u32(report.operating_system.boot_id),
                    optional_yes_no(report.operating_system.safe_boot_mode),
                    optional_yes_no(report.operating_system.kernel_debugger_enabled)
                );
                println!(
                    "处理器：{} 个活动处理器，{} 个活动组；物理内存：{}（{} 页，每页 {} 字节）",
                    report
                        .operating_system
                        .active_processor_count
                        .or(report.kernel.processor_count)
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "未知".to_owned()),
                    report
                        .operating_system
                        .active_group_count
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "未知".to_owned()),
                    report
                        .operating_system
                        .physical_memory_bytes
                        .map(format_byte_size)
                        .unwrap_or_else(|| "未知".to_owned()),
                    report
                        .operating_system
                        .number_of_physical_pages
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "未知".to_owned()),
                    report
                        .operating_system
                        .page_size_bytes
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "未知".to_owned())
                );
                println!(
                    "控制集：当前={} 默认={} 最后一次正确配置={} 失败={}",
                    optional_u32(report.registry.current_control_set),
                    optional_u32(report.registry.default_control_set),
                    optional_u32(report.registry.last_known_good_control_set),
                    optional_u32(report.registry.failed_control_set)
                );

                println!("\n【账户与进程】");
                println!("用户数：{}", report.host.users.len());
                for user in &report.host.users {
                    println!(
                        "  {}\\{} SID={} 配置目录={} 进程数={}",
                        user.domain.as_deref().unwrap_or(""),
                        user.user_name.as_deref().unwrap_or("未知"),
                        user.sid.as_deref().unwrap_or("未知"),
                        user.profile_path.as_deref().unwrap_or("未知"),
                        user.process_count
                    );
                }
                println!(
                    "进程数：{}（命令行 {}，路径 {}，SID {}，线程 {}）",
                    report.processes.total,
                    report.processes.command_lines_recovered,
                    report.processes.image_paths_recovered,
                    report.processes.user_sids_recovered,
                    report.processes.total_active_threads
                );

                println!("\n【网络摘要】");
                println!(
                    "网络：{} 个端点，TCP {}，UDP {}，监听 {}，已解析归属 {}",
                    report.network.endpoint_count,
                    report.network.tcp_count,
                    report.network.udp_count,
                    report.network.listening_count,
                    report.network.owner_resolved_count
                );
                println!(
                    "网络配置：{} 个适配器，IP=[{}]，DNS=[{}]，网关=[{}]，历史配置数={}",
                    report.network.configured_adapter_count,
                    report.network.configured_addresses.join(", "),
                    report.network.configured_dns_servers.join(", "),
                    report.network.configured_gateways.join(", "),
                    report.network.historical_profile_count
                );
                println!(
                    "注册表证据：服务={}，自动运行={}（计算机 {}，用户 {}），计划任务={}，USB={}，挂载设备={}，BAM/DAM={}，本地账户={}",
                    report.registry.services.len(),
                    report.registry.autoruns.len(),
                    report
                        .registry
                        .autoruns
                        .iter()
                        .filter(|entry| entry.scope == "machine")
                        .count(),
                    report
                        .registry
                        .autoruns
                        .iter()
                        .filter(|entry| entry.scope == "user")
                        .count(),
                    report.registry.scheduled_tasks.len(),
                    report.registry.usb_devices.len(),
                    report.registry.mounted_devices.len(),
                    report.registry.bam_entries.len(),
                    report.registry.local_accounts.len()
                );
                if let Some(path) = &args.output {
                    println!("JSON 文件：{}", path.display());
                }
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::Crashinfo { image } => {
            let image = open_memory_image(image)?;
            let report = starmem::windows::system_plugins::crash_info(&image)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("签名：{}", report.signature);
                println!(
                    "转储类型：{}（{}）",
                    report.dump_type_name, report.dump_type
                );
                println!(
                    "内核：{}.{}，{} 个 CPU，{}",
                    report.major_version,
                    report.minor_version,
                    report.number_processors,
                    report.machine_type_name
                );
                println!("DTB/CR3: {:#018x}", report.directory_table_base);
                println!("PsLoadedModuleList: {:#018x}", report.ps_loaded_module_list);
                println!(
                    "PsActiveProcessHead: {:#018x}",
                    report.ps_active_process_head
                );
                println!(
                    "KdDebuggerDataBlock: {:#018x}",
                    report.kd_debugger_data_block
                );
                println!(
                    "错误检查：{:#x} [{:#x}, {:#x}, {:#x}, {:#x}]",
                    report.bug_check_code,
                    report.bug_check_parameters[0],
                    report.bug_check_parameters[1],
                    report.bug_check_parameters[2],
                    report.bug_check_parameters[3]
                );
                println!(
                    "系统时间：{}",
                    report.system_time.as_deref().unwrap_or("unknown")
                );
                println!("运行时间：{:.3} 秒", report.system_uptime_seconds);
                println!(
                    "物理内存：{} 个区间，{} 页，所需转储字节数 {}",
                    report.number_of_runs, report.number_of_pages, report.required_dump_space
                );
                if !report.comment.is_empty() {
                    println!("备注：{}", report.comment);
                }
            }
        }
        Command::AcquisitionInfo(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = analyze_acquisition_info(
                &session,
                &AcquisitionInfoOptions {
                    scan_tools: !args.skip_tool_scan,
                    include_host_times: args.include_host_times,
                    process_limit: args.process_limit,
                    handle_limit: args.handle_limit,
                },
            )?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("镜像：{}", report.image);
                println!("格式：{}", report.image_format);
                println!("文件大小：{}", format_byte_size(report.file_size));
                println!("逻辑大小：{}", format_byte_size(report.logical_size));
                let container = &report.container_acquisition_metadata;
                println!(
                    "容器时间：{}",
                    container.timestamp_utc.as_deref().unwrap_or("不可用")
                );
                println!(
                    "  可用={}；语义={}；来源={}；置信度={}；精确开始={}；精确结束={}",
                    yes_no(container.available),
                    container.semantic,
                    container.source.as_deref().unwrap_or("无"),
                    container.confidence,
                    yes_no(container.exact_start),
                    yes_no(container.exact_end),
                );
                if let Some(reason) = &container.reason {
                    println!("  说明：{reason}");
                }
                print_forensic_time("镜像内系统时钟", &report.snapshot_observed_time);
                print_forensic_time("系统启动时间", &report.boot_time);
                if report.previous_shutdown_time_status == "examined" {
                    print_forensic_time("上次关机时间", &report.previous_shutdown_time);
                } else {
                    println!(
                        "上次关机时间：未检查（status={}；{}）",
                        report.previous_shutdown_time_status, report.previous_shutdown_time_reason,
                    );
                }
                if report.capture_tool_candidates.is_empty() {
                    println!("采集工具候选：未发现");
                } else {
                    println!("采集工具候选：");
                    for tool in &report.capture_tool_candidates {
                        println!(
                            "  PID {} {} | 创建={} | 输出句柄={} | 当前检材绑定={} | 置信度={} | 关系={}",
                            tool.pid,
                            tool.image_path.as_deref().unwrap_or(&tool.process),
                            tool.process_create_time.as_deref().unwrap_or("未知"),
                            tool.output_handles.len(),
                            yes_no(tool.current_image_bound),
                            tool.confidence,
                            tool.relationship,
                        );
                        for output in &tool.output_handles {
                            println!(
                                "    {:#010x} {:#018x} {} | 当前检材匹配={} | 依据={}",
                                output.handle,
                                output.object,
                                output.name,
                                yes_no(output.current_image_match),
                                output.match_basis,
                            );
                        }
                    }
                }
                if let Some(window) = &report.inferred_capture_window {
                    println!(
                        "推断采集活动窗口：{} -> {}（精确开始={}，精确结束={}）",
                        window.lower_bound_candidate.as_deref().unwrap_or("未知"),
                        window.observed_time.as_deref().unwrap_or("未知"),
                        yes_no(window.exact_start),
                        yes_no(window.exact_end),
                    );
                    println!("说明：{}", window.reason);
                }
                if let Some(host) = &report.host_file_times {
                    println!(
                        "分析主机文件时间（不作为采集时间）：创建={}；修改={}",
                        host.created_utc.as_deref().unwrap_or("未知"),
                        host.modified_utc.as_deref().unwrap_or("未知"),
                    );
                    println!(
                        "  语义={}；支持作为采集时间={}",
                        host.semantic,
                        yes_no(host.acquisition_time_supported),
                    );
                } else {
                    println!("分析主机文件时间：未请求（可使用 --include-host-times）");
                }
                println!("报告完整：{}", yes_no(report.complete));
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::Kpcrs(args) | Command::Debugregisters(args) => {
            let debug_only = debug_registers_command;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.kpcrs(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else if debug_only {
                println!(
                    "{:>4} {:>18} {:>18} {:>18} {:>18} {:>18} 活动",
                    "CPU", "DR0", "DR1", "DR2", "DR3", "DR7"
                );
                for cpu in &report.records {
                    println!(
                        "{:>4} {:#018x} {:#018x} {:#018x} {:#018x} {:#018x} {}",
                        cpu.processor_index,
                        cpu.dr0.unwrap_or(0),
                        cpu.dr1.unwrap_or(0),
                        cpu.dr2.unwrap_or(0),
                        cpu.dr3.unwrap_or(0),
                        cpu.dr7.unwrap_or(0),
                        cpu.hardware_breakpoints_active
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            } else {
                println!(
                    "{:>4} {:>18} {:>18} {:>6} {:>12} {:>18} {:>18}",
                    "CPU", "KPCR", "KPRCB", "MHz", "VENDOR", "CURRENT", "IDLE"
                );
                for cpu in &report.records {
                    println!(
                        "{:>4} {:#018x} {:#018x} {:>6} {:>12.12} {:#018x} {:#018x}",
                        cpu.processor_index,
                        cpu.kpcr,
                        cpu.prcb,
                        cpu.mhz.unwrap_or(0),
                        cpu.vendor.as_deref().unwrap_or(""),
                        cpu.current_thread.unwrap_or(0),
                        cpu.idle_thread.unwrap_or(0)
                    );
                }
                println!("报告的处理器数：{}", report.processor_count_reported);
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Virtmap(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.kernel_virtmap(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                print_mapping_report(&report);
            }
        }
        Command::Statistics(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.memory_statistics(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("镜像格式：{}", report.image_format);
                println!("文件字节数：{}", report.file_size);
                println!("已采集物理字节数：{}", report.acquired_physical_bytes);
                println!("物理区间数：{}", report.physical_span_count);
                println!(
                    "物理描述符：{} 页，{} 个区间",
                    report
                        .physical_memory_descriptor_pages
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "unknown".to_owned()),
                    report.physical_memory_runs.len()
                );
                println!("内核已映射字节数：{}", report.kernel_mapped_bytes);
                println!("合并映射数：{}", report.kernel_mapping_count);
                println!(
                    "来源页：4K={} 2M={} 1G={}",
                    report.kernel_4k_mapping_count,
                    report.kernel_2m_mapping_count,
                    report.kernel_1g_mapping_count
                );
                println!(
                    "内核可写且可执行字节数：{}",
                    report.kernel_writable_executable_bytes
                );
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::Memmap(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.process_memmap(args.pid, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "进程 PID={} 名称={} EPROCESS={:#018x} DTB={:#018x}",
                    report.pid, report.process, report.eprocess, report.directory_table_base
                );
                print_mapping_report(&report.mappings);
            }
        }
        Command::Bigpools(args) => {
            validate_text_pool_tags(&args.tags)?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.big_pools(&args.tags, args.show_free, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>8} {:>12} {:>10} {:>18} 状态",
                    "地址", "标签", "字节数", "标志", "计费进程"
                );
                for entry in &report.records {
                    println!(
                        "{:#018x} {:>8} {:>12} {:#010x} {:#018x} {}",
                        entry.virtual_address,
                        entry.tag,
                        entry.number_of_bytes,
                        entry.pool_flags,
                        entry.process_billed.unwrap_or(0),
                        if entry.free { "free" } else { "allocated" }
                    );
                }
                println!(
                    "表地址={:#018x}；声明条目数={}",
                    report.table, report.declared_entries
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Poolscanner(args) => {
            let tags = parse_pool_tags_or_defaults(&args.tags)?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.pool_scan(&tags, args.limit_per_tag)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>18} {:>8} {:>8} {:>8} 类型",
                    "虚拟地址", "物理地址", "标签", "块数", "字节数"
                );
                for allocation in &report.records {
                    println!(
                        "{:#018x} {:#018x} {:>8} {:>8} {:>8} {:#04x}",
                        allocation.kernel_virtual_body.unwrap_or(0),
                        allocation.physical_body,
                        allocation.tag,
                        allocation.block_size,
                        allocation.allocation_size,
                        allocation.pool_type
                    );
                }
                println!(
                    "扫描：{} 字节，耗时 {:.3} 秒（{:.2} GiB/s）；标签数={}",
                    report.bytes_scanned,
                    report.elapsed_seconds,
                    report.gib_per_second,
                    report.tags.join(",")
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Strings(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report =
                session.map_strings(&args.strings_file, args.offset_kind.into(), args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>18} {:>7} {:<18} {:>18} 字符串",
                    "来源偏移", "物理地址", "PID", "归属", "虚拟地址"
                );
                for record in &report.records {
                    if record.owners.is_empty() {
                        println!(
                            "{:#018x} {:#018x} {:>7} {:<18} {:>18} {}",
                            record.source_offset,
                            record.physical_address,
                            "-",
                            "unmapped",
                            "-",
                            record.text
                        );
                    } else {
                        for owner in &record.owners {
                            println!(
                                "{:#018x} {:#018x} {:>7} {:<18.18} {:#018x} {}",
                                record.source_offset,
                                record.physical_address,
                                owner
                                    .pid
                                    .map(|pid| pid.to_string())
                                    .unwrap_or_else(|| "-".to_owned()),
                                owner.process,
                                owner.virtual_address,
                                record.text
                            );
                        }
                    }
                }
                println!(
                    "输入={} 已映射={} 格式错误={} 进程地址空间={} 已截断={}",
                    report.input_records,
                    report.mapped_records,
                    report.malformed_lines,
                    report.process_address_spaces,
                    yes_no(report.truncated)
                );
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::WindowsProcessString(args) => {
            let chunk_size = args
                .chunk_mib
                .checked_mul(1024 * 1024)
                .context("进程字符串扫描块大小溢出")?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.process_string(&ProcessStringOptions {
                query: args.text,
                encoding: args.encoding.into(),
                scan_hit_limit: args.scan_hit_limit,
                limit: args.limit,
                process_limit: args.process_limit,
                mapping_limit: args.mapping_limit,
                reverse_entry_limit: args.reverse_entry_limit,
                reverse_alias_limit: args.reverse_alias_limit,
                chunk_size,
                context_bytes: args.context_bytes,
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                if !report.available {
                    println!("当前镜像的进程字符串归属功能不可用。");
                } else if report.records.is_empty() {
                    println!("没有找到可由活动进程页表验证的字符串命中。");
                } else {
                    println!(
                        "{:>7} {:<18} {:>18} {:>18} {:<9} 上下文",
                        "PID", "进程", "虚拟地址", "物理地址", "编码"
                    );
                    for record in &report.records {
                        println!(
                            "{:>7} {:<18.18} {:#018x} {:#018x} {:<9} {}",
                            record.pid,
                            safe_terminal_text(&record.process),
                            record.virtual_address,
                            record.physical_address,
                            record.encoding,
                            safe_terminal_text(&record.context),
                        );
                    }
                }
                println!(
                    "查询={}；编码={}；物理命中={}；已关联命中={}{}；未关联命中={}；进程={}；地址空间={}/{}；结果={}；扫描={:.3}秒/{:.2} GiB/s；映射={:.3}秒；完整={}",
                    safe_terminal_text(&report.query),
                    report.encodings.join(","),
                    report.physical_hits,
                    report.mapped_physical_hits,
                    if report.mapped_physical_hits_is_lower_bound {
                        "（下界）"
                    } else {
                        ""
                    },
                    report
                        .unmapped_physical_hits
                        .map(|count| count.to_string())
                        .unwrap_or_else(|| "未知（归属搜索不完整）".to_owned()),
                    report.processes_enumerated,
                    report.process_address_spaces_walked,
                    report.process_address_spaces,
                    report.records.len(),
                    report.physical_scan_seconds,
                    report.gib_per_second,
                    report.owner_mapping_seconds,
                    yes_no(report.complete),
                );
                for warning in &report.warnings {
                    eprintln!(
                        "警告[{}]：{}",
                        safe_terminal_text(&warning.code),
                        safe_terminal_text(&warning.message)
                    );
                }
            }
        }
        Command::Scan(args) => {
            let needle = match (args.text, args.hex) {
                (Some(text), None) => text.into_bytes(),
                (None, Some(hex_text)) => parse_hex(&hex_text)?,
                (None, None) => bail!("必须提供 --text 或 --hex 其中之一"),
                _ => unreachable!("clap 已保证两个参数互斥"),
            };
            let chunk_size = args
                .chunk_mib
                .checked_mul(1024 * 1024)
                .context("扫描块大小溢出")?;
            let image = open_memory_image(args.image)?;
            ensure!(!image.spans().is_empty(), "此镜像容器格式无法直接扫描");
            let report = scan_exact(&image, &needle, args.limit, chunk_size)?;
            if cli.json {
                print_json(&report)?;
            } else {
                for hit in &report.hits {
                    println!(
                        "物理地址={:#018x} 文件偏移={:#018x}",
                        hit.physical_address, hit.file_offset
                    );
                }
                println!(
                    "命中 {} 次，耗时 {:.3} 秒，{:.2} GiB/s，已扫描 {} 字节{}",
                    report.hits.len(),
                    report.elapsed_seconds,
                    report.gib_per_second,
                    report.bytes_scanned,
                    if report.truncated { "，已截断" } else { "" }
                );
            }
        }
        Command::Downloadscan(args) => {
            let image = open_memory_image(args.image)?;
            ensure!(!image.spans().is_empty(), "此镜像容器格式无法直接扫描");
            let report = scan_download_traces(&image, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                for record in &report.records {
                    let confidence = match record.confidence.as_str() {
                        "high" => "高",
                        "medium" => "中",
                        _ => "低",
                    };
                    println!(
                        "[置信度：{}] IP={} 端口={} 方法={} 文件={}",
                        confidence,
                        record.ip_address.as_deref().unwrap_or("非IP主机名"),
                        record
                            .port
                            .map(|port| port.to_string())
                            .unwrap_or_else(|| "默认".to_owned()),
                        record.method.as_deref().unwrap_or("未知"),
                        record.file_name.as_deref().unwrap_or("未知"),
                    );
                    println!("  URL：{}", record.url);
                    println!(
                        "  物理地址：{}（共 {} 处）",
                        record
                            .physical_addresses
                            .iter()
                            .map(|address| format!("{address:#018x}"))
                            .collect::<Vec<_>>()
                            .join(", "),
                        record.occurrences
                    );
                    println!("  证据：{}", record.evidence);
                }
                println!(
                    "\n下载痕迹={}；URL原始命中={}；耗时={:.3}秒/{:.2} GiB/s；是否完整={}",
                    report.records.len(),
                    report.raw_url_hits,
                    report.scan_seconds,
                    report.scan_gib_per_second,
                    yes_no(report.complete),
                );
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::Cookiescan(args) => {
            let max_database_size = args
                .max_database_mib
                .checked_mul(1024 * 1024)
                .and_then(|size| u64::try_from(size).ok())
                .context("Cookie 数据库最大恢复大小溢出")?;
            eprintln!("[1/6] 正在解析 Windows 内核与符号表……");
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.cookie_scan(
                &CookieScanOptions {
                    limit: args.limit,
                    database_limit: args.database_limit,
                    file_scan_limit: args.file_scan_limit,
                    max_database_size,
                    process_space_limit: args.process_space_limit,
                },
                |stage| match stage {
                    CookieScanStage::RuntimeHeaders => {
                        eprintln!("[2/6] 正在单遍扫描明文 Cookie 和文件对象锚点……")
                    }
                    CookieScanStage::FileObjects => {
                        eprintln!("[3/6] 正在验证 Cookie 数据库和旧式 Cookie 文件对象……")
                    }
                    CookieScanStage::Databases => {
                        eprintln!("[4/6] 正在恢复驻留文件并解析 SQLite Cookie 记录……")
                    }
                    CookieScanStage::ProcessOwners => {
                        eprintln!("[5/6] 正在优先关联浏览器进程、PID 和虚拟地址……")
                    }
                },
            )?;
            eprintln!("[6/6] 正在去重并生成 Cookie 报告……");
            if cli.json {
                print_json(&report)?;
            } else {
                if report.records.is_empty() {
                    println!("没有发现可验证的浏览器 Cookie。")
                }
                for record in &report.records {
                    let confidence = match record.confidence.as_str() {
                        "high" => "高",
                        "medium" => "中",
                        _ => "低",
                    };
                    println!(
                        "[{}][{}][置信度：{}] {}{} {}={}",
                        record.browser,
                        cookie_source_name(record.source),
                        confidence,
                        record.domain.as_deref().unwrap_or("未知域名"),
                        record.path.as_deref().unwrap_or(""),
                        record.name,
                        record.value.as_deref().unwrap_or("（值已加密）"),
                    );
                    if let Some(encrypted) = &record.encrypted_value_hex {
                        println!("  加密值（十六进制）：{encrypted}");
                    }
                    println!(
                        "  过期={}；Secure={}；HttpOnly={}；SameSite={}；出现={}次",
                        record.expires.as_deref().unwrap_or("未知"),
                        optional_yes_no(record.secure),
                        optional_yes_no(record.http_only),
                        record.same_site.as_deref().unwrap_or("未知"),
                        record.occurrences,
                    );
                    if let Some(profile) = &record.profile {
                        println!("  浏览器配置：{profile}");
                    }
                    if let Some(source_file) = &record.source_file {
                        println!(
                            "  来源文件：{}（FILE_OBJECT={}，数据库行={}）",
                            source_file,
                            record
                                .file_object
                                .map(|address| format!("{address:#018x}"))
                                .unwrap_or_else(|| "未知".to_owned()),
                            record
                                .database_rowid
                                .map(|rowid| rowid.to_string())
                                .unwrap_or_else(|| "不适用".to_owned()),
                        );
                    }
                    if !record.owners.is_empty() {
                        println!(
                            "  进程：{}",
                            record
                                .owners
                                .iter()
                                .map(|owner| format!(
                                    "{}({})@{:#018x}",
                                    owner.process, owner.pid, owner.virtual_address
                                ))
                                .collect::<Vec<_>>()
                                .join("、")
                        );
                    }
                    if !record.physical_addresses.is_empty() {
                        println!(
                            "  物理地址：{}",
                            record
                                .physical_addresses
                                .iter()
                                .map(|address| format!("{address:#018x}"))
                                .collect::<Vec<_>>()
                                .join("、")
                        );
                    }
                }
                println!(
                    "\nCookie={}；请求/响应头原始命中={}；候选文件={}；已解析数据库={}；进程地址空间={}；耗时={:.3}秒/{:.2} GiB/s；是否完整={}",
                    report.records.len(),
                    report.runtime_header_hits,
                    report.cookie_files_found,
                    report.cookie_databases_parsed,
                    report.process_address_spaces,
                    report.scan_seconds,
                    report.scan_gib_per_second,
                    yes_no(report.complete),
                );
                println!(
                    "阶段耗时：联合扫描={:.3}秒；文件结构解析={:.3}秒；数据库解析={:.3}秒；进程关联={:.3}秒",
                    report.combined_scan_seconds,
                    report.file_scan_seconds,
                    report.database_parse_seconds,
                    report.owner_mapping_seconds,
                );
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::Clipboardscan(args) => {
            let max_data_size = args
                .max_data_mib
                .checked_mul(1024 * 1024)
                .context("剪切板数据块最大读取大小溢出")?;
            eprintln!("[1/5] 正在加载镜像、解析 Windows 内核并准备符号表……");
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.clipboard_scan(
                &ClipboardScanOptions {
                    limit: args.limit,
                    max_data_size,
                },
                |stage| match stage {
                    ClipboardScanStage::Structures => {
                        eprintln!("[2/5] 正在枚举窗口站并验证活动剪切板格式数组……")
                    }
                    ClipboardScanStage::PhysicalScan => {
                        eprintln!("[3/5] 正在扫描活动剪切板引用的 Uscb 数据块……")
                    }
                    ClipboardScanStage::DataRecovery => {
                        eprintln!("[4/5] 正在按格式句柄恢复活动剪切板驻留数据……")
                    }
                },
            )?;
            eprintln!("[5/5] 正在生成活动剪切板结构报告……");
            if cli.json {
                print_json(&report)?;
            } else {
                println!("【活动剪切板格式】");
                if report.formats.is_empty() {
                    println!("没有恢复到通过结构验证的活动剪切板格式。");
                }
                for record in &report.formats {
                    println!(
                        "[会话 {}][{}][置信度：{}] {}；句柄={:#x}；数据={}字节{}",
                        record.session_id,
                        record.window_station,
                        record.confidence,
                        record.format_name,
                        record.handle,
                        record.data_size.unwrap_or(0),
                        if record.delayed_render {
                            "；延迟渲染"
                        } else {
                            ""
                        },
                    );
                    if let Some(content) = &record.content {
                        println!("  {}：{}", record.content_type, content);
                    }
                    println!(
                        "  格式数组={:#018x}+{:#x}；数据对象={}；物理地址={}",
                        record.clip_base,
                        record.clip_base_field_offset,
                        record
                            .data_object
                            .map(|address| format!("{address:#018x}"))
                            .unwrap_or_else(|| "未恢复".to_owned()),
                        record
                            .data_physical_address
                            .map(|address| format!("{address:#018x}"))
                            .unwrap_or_else(|| "未恢复".to_owned()),
                    );
                }

                println!(
                    "\n窗口站={}；格式数组={}；活动格式={}；活动数据块={}；Uscb 标签命中={}",
                    report.window_stations_examined,
                    report.clip_arrays_validated,
                    report.formats.len(),
                    report.structured_data_blocks,
                    report.raw_pool_tag_hits,
                );
                println!(
                    "耗时：结构={:.3}秒；数据块扫描={:.3}秒；总计={:.3}秒；是否完整={}",
                    report.structure_seconds,
                    report.physical_scan_seconds,
                    report.total_seconds,
                    yes_no(report.complete),
                );
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::Residualscan(args) => {
            eprintln!("[1/5] 正在加载镜像、解析 Windows 内核并准备符号表……");
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.residual_scan(
                &ResidualScanOptions {
                    limit: args.limit,
                    process_space_limit: args.process_space_limit,
                    search_texts: args.search_texts,
                },
                |stage| match stage {
                    ResidualScanStage::PhysicalScan => eprintln!(
                        "[2/5] 正在单遍扫描邮箱、URL、IPv4、Windows 路径、命令和指定文本……"
                    ),
                    ResidualScanStage::ProcessOwners => {
                        eprintln!("[3/5] 正在将候选物理页批量关联到进程和虚拟地址……")
                    }
                    ResidualScanStage::Classification => {
                        eprintln!("[4/5] 正在去重、过滤并评估文本残留证据……")
                    }
                },
            )?;
            eprintln!("[5/5] 正在生成进程文本残留报告……");
            if cli.json {
                print_json(&report)?;
            } else {
                println!("【进程文本残留】");
                if report.records.is_empty() {
                    println!("没有发现满足去重和进程归属条件的文本残留。");
                }
                for record in &report.records {
                    println!(
                        "[{}][{}][置信度：{}] {}（出现 {} 次）",
                        record.evidence_kind,
                        record.content_type,
                        record.confidence,
                        record.content,
                        record.occurrences,
                    );
                    if !record.owners.is_empty() {
                        println!(
                            "  进程：{}",
                            record
                                .owners
                                .iter()
                                .map(|owner| format!(
                                    "{}({})@{:#018x}",
                                    owner.process, owner.pid, owner.virtual_address
                                ))
                                .collect::<Vec<_>>()
                                .join("、")
                        );
                    }
                    println!("  说明：{}", record.evidence_note);
                    println!(
                        "  物理地址：{}",
                        record
                            .physical_addresses
                            .iter()
                            .map(|address| format!("{address:#018x}"))
                            .collect::<Vec<_>>()
                            .join("、")
                    );
                }
                println!(
                    "\n文本残留={}；原始候选={}（邮箱={}）；自定义搜索={}；进程地址空间={}",
                    report.records.len(),
                    report.raw_residual_candidates,
                    report.raw_email_candidates,
                    report.custom_searches,
                    report.process_address_spaces,
                );
                if !report.candidate_types.is_empty() {
                    println!(
                        "候选类型：{}",
                        report
                            .candidate_types
                            .iter()
                            .map(|(kind, count)| format!("{kind}={count}"))
                            .collect::<Vec<_>>()
                            .join("；")
                    );
                }
                println!(
                    "耗时：物理扫描={:.3}秒；进程关联={:.3}秒；总计={:.3}秒；是否完整={}",
                    report.physical_scan_seconds,
                    report.owner_mapping_seconds,
                    report.total_seconds,
                    yes_no(report.complete),
                );
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::Wechatscan(args) => {
            eprintln!("[1/6] 正在加载镜像、解析 Windows 内核并准备符号表……");
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.wechat_scan(
                &WechatScanOptions {
                    pid: args.pid,
                    include_helpers: !args.main_only,
                    limit: args.limit,
                    anchor_limit: args.anchor_limit,
                    process_space_limit: args.process_space_limit,
                    verification_roots: args.verify_db_roots,
                    verification_file_limit: args.verification_file_limit,
                },
                |stage| match stage {
                    WechatScanStage::Processes => {
                        eprintln!("[2/6] 正在识别微信主进程、辅助进程和用户页表……")
                    }
                    WechatScanStage::Anchors => {
                        eprintln!("[3/6] 正在单遍扫描微信密钥字面量和数据库上下文……")
                    }
                    WechatScanStage::AddressMapping => {
                        eprintln!("[4/6] 正在将候选物理页批量反向映射到微信地址空间……")
                    }
                    WechatScanStage::Validation => {
                        eprintln!("[5/6] 正在验证 SQLCipher 上下文、重复堆密钥、随机性和 salt……")
                    }
                },
            )?;
            eprintln!("[6/6] 正在去重并生成微信密钥报告……");
            if cli.json {
                print_json(&report)?;
            } else {
                if report.processes.is_empty() {
                    println!("没有发现活动的微信进程。");
                } else {
                    println!("微信进程：");
                    for process in &report.processes {
                        println!(
                            "  {}({})；角色={}；已分析={}；DTB={}",
                            process.process,
                            process.pid,
                            wechat_process_role_name(process.role),
                            yes_no(process.selected),
                            process
                                .directory_table_base
                                .map(|dtb| format!("{dtb:#018x}"))
                                .unwrap_or_else(|| "未知".to_owned()),
                        );
                    }
                }
                if report.records.is_empty() {
                    println!("没有发现通过结构过滤的微信密钥候选。");
                }
                for (index, record) in report.records.iter().enumerate() {
                    let process = if record.pid == 0 {
                        record.process.clone()
                    } else {
                        format!("{}({})", record.process, record.pid)
                    };
                    println!(
                        "\n候选 #{}：{}；{}；角色={}；置信度={}",
                        index + 1,
                        wechat_key_kind_name(record.key_kind),
                        process,
                        wechat_process_role_name(record.process_role),
                        wechat_key_confidence_name(record.confidence),
                    );
                    println!("  密钥：{}", record.key_hex);
                    println!("  Salt：{}", record.salt_hex.as_deref().unwrap_or("未发现"));
                    println!(
                        "  熵={:.3}；SQLCipher上下文={}；出现={}次",
                        record.key_entropy,
                        yes_no(record.sqlcipher_context),
                        record.occurrences,
                    );
                    if let Some(validation) = &record.database_validation {
                        println!("  数据库验证：已通过");
                        println!("    文件：{}", validation.database_path.display());
                        println!(
                            "    页大小={}；保留区={}；读写版本={}/{}；Schema格式={}；文本编码={}",
                            validation.page_size,
                            validation.reserve_size,
                            validation.read_version,
                            validation.write_version,
                            validation.schema_format,
                            validation.text_encoding,
                        );
                    }
                    for evidence in &record.evidence {
                        println!(
                            "  证据：虚拟={} 物理={:#018x} 编码={} 上下文={} 十六进制长度={}",
                            evidence
                                .virtual_address
                                .map(|address| format!("{address:#018x}"))
                                .unwrap_or_else(|| "未映射（残留页）".to_owned()),
                            evidence.physical_address,
                            wechat_key_encoding_name(evidence.encoding),
                            wechat_key_context_name(evidence.context),
                            evidence.literal_hex_length,
                        );
                        if let Some(preview) = &evidence.context_preview {
                            println!("    上下文：{preview}");
                        }
                    }
                }
                println!(
                    "\n密钥候选={}；已验证={}；验证文件={}；微信进程={}；已分析地址空间={}；字面量锚点={}；语法候选={}；数据库上下文页={}；二进制候选窗口={}；候选物理页={}；耗时={:.3}秒/{:.2} GiB/s；是否完整={}",
                    report.records.len(),
                    report.verified_records,
                    report.verification_files_examined,
                    report.wechat_processes_found,
                    report.address_spaces_examined,
                    report.raw_anchor_hits,
                    report.syntax_anchor_hits,
                    report.database_context_pages,
                    report.raw_key_candidate_windows,
                    report.candidate_pages,
                    report.scan_seconds,
                    report.scan_gib_per_second,
                    yes_no(report.complete),
                );
                println!(
                    "阶段耗时：物理扫描={:.3}秒；地址映射与候选解析={:.3}秒",
                    report.physical_scan_seconds, report.address_mapping_seconds,
                );
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::BrowserSession(args) => {
            let max_database_size = args
                .max_database_mib
                .checked_mul(1024 * 1024)
                .and_then(|size| u64::try_from(size).ok())
                .context("Cookie 数据库最大恢复大小溢出")?;
            eprintln!("[1/9] 正在加载镜像、解析 Windows 内核并准备符号表……");
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.browser_sessions(
                &BrowserSessionOptions {
                    session_limit: args.session_limit,
                    download_limit: args.download_limit,
                    cookie: CookieScanOptions {
                        limit: args.cookie_limit,
                        database_limit: args.database_limit,
                        file_scan_limit: args.file_scan_limit,
                        max_database_size,
                        process_space_limit: args.process_space_limit,
                    },
                },
                |stage| match stage {
                    BrowserSessionStage::CookieRuntimeHeaders => {
                        eprintln!("[2/9] 正在单遍扫描明文 Cookie 和文件对象锚点……")
                    }
                    BrowserSessionStage::CookieFileObjects => {
                        eprintln!("[3/9] 正在验证浏览器数据库与旧式 Cookie 文件对象……")
                    }
                    BrowserSessionStage::CookieDatabases => {
                        eprintln!("[4/9] 正在恢复驻留文件并解析浏览器 Cookie……")
                    }
                    BrowserSessionStage::CookieOwners => {
                        eprintln!("[5/9] 正在关联 Cookie 的浏览器进程与虚拟地址……")
                    }
                    BrowserSessionStage::BrowserDatabases => {
                        eprintln!("[6/9] 正在重组 History 下载链并提取 Login Data 站点账号……")
                    }
                    BrowserSessionStage::DownloadTraces => {
                        eprintln!("[7/9] 正在扫描下载 URL、远端 IP 与文件名……")
                    }
                    BrowserSessionStage::DownloadOwners => {
                        eprintln!("[8/9] 正在批量关联下载痕迹与浏览器进程……")
                    }
                    BrowserSessionStage::Aggregate => {
                        eprintln!("[9/9] 正在重建会话、域名关系和证据索引……")
                    }
                },
            )?;
            if let Some(path) = &args.output {
                write_json_file(path, &report)?;
            }
            if cli.json {
                print_json(&report)?;
            } else {
                print_browser_session_report(&report);
                if let Some(path) = &args.output {
                    println!("\n完整 JSON 报告：{}", path.display());
                }
            }
        }
        Command::BrowserHistory(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            if let Some(path) = &args.output {
                ensure!(
                    !output_paths_conflict(path, &args.image),
                    "browser-history --output 不能与输入内存镜像为同一文件：{}",
                    args.image.display()
                );
            }
            let max_database_size = args
                .max_database_mib
                .checked_mul(1024 * 1024)
                .and_then(|size| u64::try_from(size).ok())
                .context("History 数据库最大恢复大小溢出")?;
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let files = session.files(args.file_scan_limit)?;
            let owner_options = args.owners.then_some(BrowserArtifactOwnerOptions {
                process_limit: args.process_limit,
                handle_scan_limit: args.handle_scan_limit,
            });
            let report = parse_browser_history_artifacts_from_file_scan(
                session.image(),
                session.kernel(),
                session.profile(),
                files,
                &BrowserArtifactOptions {
                    result_limit: args.limit,
                    database_limit: args.database_limit,
                    max_database_size,
                },
                owner_options.as_ref(),
            )?;
            let (records, visit_summaries) = match args.view {
                BrowserHistoryView::Summary => (
                    serde_json::to_value(&report.visit_history)?,
                    serde_json::Value::Null,
                ),
                BrowserHistoryView::Visits => (
                    serde_json::to_value(&report.visit_events)?,
                    serde_json::to_value(&report.visit_history)?,
                ),
            };
            let output = serde_json::json!({
                "view": args.view.as_str(),
                "records": records,
                // visits 视图附带一份非重复的 URL 聚合摘要；summary
                // 视图不再复制大量同内容 JSON。
                "visit_summaries": visit_summaries,
                "artifact_owners": report.artifact_owners,
                "artifact_owner_scan": report.artifact_owner_scan,
                "artifact_files_found": report.artifact_files_found,
                "databases_parsed": report.databases_parsed,
                "complete": report.complete,
                "warnings": report.warnings,
                "parse_seconds": report.parse_seconds,
            });
            if let Some(path) = &args.output {
                write_json_file(path, &output)?;
            }
            if cli.json {
                print_json(&output)?;
            } else {
                let records = output["records"].as_array().map_or(0, Vec::len);
                println!("浏览器访问历史（{}）：{records} 条", args.view.as_str());
                if let Some(rows) = output["records"].as_array() {
                    for row in rows {
                        match args.view {
                            BrowserHistoryView::Summary => println!(
                                "  [{}] {} | {} | {} | aggregate={} recovered={}",
                                row["browser"].as_str().unwrap_or("未知浏览器"),
                                row["last_visit_time"].as_str().unwrap_or("时间未知"),
                                row["title"].as_str().unwrap_or("无标题"),
                                row["url"].as_str().unwrap_or("无 URL"),
                                row["aggregate_visit_count"]
                                    .as_i64()
                                    .map_or_else(|| "?".to_owned(), |value| value.to_string()),
                                row["recovered_visit_event_count"]
                                    .as_u64()
                                    .map_or_else(|| "?".to_owned(), |value| value.to_string()),
                            ),
                            BrowserHistoryView::Visits => println!(
                                "  [{}] {} | visit={} | {} | {}",
                                row["browser"].as_str().unwrap_or("未知浏览器"),
                                row["visit_time_utc"].as_str().unwrap_or("时间未知"),
                                row["visit_id"]
                                    .as_i64()
                                    .map_or_else(|| "?".to_owned(), |value| value.to_string()),
                                row["title"].as_str().unwrap_or("无标题"),
                                row["url"].as_str().unwrap_or("无 URL"),
                            ),
                        }
                    }
                }
                if args.owners {
                    let owners = output["artifact_owners"].as_array().map_or(0, Vec::len);
                    println!("History 数据库句柄持有者：{owners} 条");
                }
            }
        }
        Command::Dnsscan(args) => {
            let max_database_size = args
                .max_database_mib
                .checked_mul(1024 * 1024)
                .and_then(|size| u64::try_from(size).ok())
                .context("Cookie 数据库最大恢复大小溢出")?;
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.dns_scan(
                &DnsScanOptions {
                    limit: args.session_limit,
                    browser: BrowserSessionOptions {
                        session_limit: args.session_limit,
                        download_limit: args.download_limit,
                        cookie: CookieScanOptions {
                            limit: args.cookie_limit,
                            database_limit: args.database_limit,
                            file_scan_limit: args.file_scan_limit,
                            max_database_size,
                            process_space_limit: args.process_space_limit,
                        },
                    },
                },
                |_| {},
            )?;
            if let Some(path) = &args.output {
                write_json_file(path, &report)?;
            }
            if cli.json {
                print_json(&report)?;
            } else {
                if report.records.is_empty() {
                    println!("没有发现可验证的 DNS 或域名引用证据。");
                }
                for record in &report.records {
                    println!(
                        "域名={} 类型={} 答案={} PID={} 进程={} 证据={} 置信度={} 命中={}",
                        record.domain,
                        record.record_type,
                        record.answer.as_deref().unwrap_or("未恢复"),
                        record
                            .pid
                            .map(|pid| pid.to_string())
                            .unwrap_or_else(|| "未关联".to_owned()),
                        record.process.as_deref().unwrap_or("未关联"),
                        record.evidence_type,
                        record.confidence,
                        record.occurrences,
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Accountscan(args) => {
            eprintln!("[1/3] 正在解析 Windows 内核与符号表……");
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            eprintln!("[2/3] 正在扫描账户操作并关联进程地址……");
            let report = session.account_scan(args.limit)?;
            eprintln!("[3/3] 正在整理账户、SID 与管理员权限证据……");
            if cli.json {
                print_json(&report)?;
            } else {
                if report.findings.is_empty() {
                    println!("没有发现可验证的账户操作痕迹。");
                } else {
                    println!("账户分析结果：");
                    for finding in &report.findings {
                        let confidence = match finding.confidence.as_str() {
                            "high" => "高",
                            "medium" => "中",
                            _ => "低",
                        };
                        println!(
                            "[置信度：{}] 用户={} SID={} 创建={} 删除={} 管理员={} 活动进程={} 证据={}",
                            confidence,
                            finding.username,
                            finding.sid.as_deref().unwrap_or("未知"),
                            yes_no(finding.created),
                            yes_no(finding.deleted),
                            yes_no(finding.administrator),
                            finding.process_count,
                            finding.evidence_count,
                        );
                        if !finding.groups.is_empty() {
                            println!("  加入组：{}", finding.groups.join("、"));
                        }
                    }
                }
                if !report.records.is_empty() {
                    println!("\n账户操作证据：");
                }
                for record in &report.records {
                    println!(
                        "- 操作={} 用户={} 组={} 置信度={} 出现={}次",
                        account_action_name(record.action),
                        record.username.as_deref().unwrap_or("不适用"),
                        record.group.as_deref().unwrap_or("不适用"),
                        match record.confidence.as_str() {
                            "high" => "高",
                            "medium" => "中",
                            _ => "低",
                        },
                        record.occurrences,
                    );
                    println!("  命令：{}", record.command);
                    if record.owners.is_empty() {
                        println!(
                            "  物理地址：{}",
                            record
                                .physical_addresses
                                .iter()
                                .map(|address| format!("{address:#018x}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    } else {
                        for owner in record.owners.iter().take(8) {
                            println!(
                                "  来源：{}（PID {}）虚拟地址={:#018x} 执行账户={} SID={}",
                                owner.process,
                                owner.pid,
                                owner.virtual_address,
                                owner.executor_user.as_deref().unwrap_or("未知"),
                                owner.executor_sid.as_deref().unwrap_or("未知"),
                            );
                        }
                    }
                }
                println!(
                    "\n账户={}；操作={}；原始锚点={}；已关联证据={}；物理扫描={:.3}秒/{:.2} GiB/s；总耗时={:.3}秒；是否完整={}",
                    report.findings.len(),
                    report.records.len(),
                    report.raw_anchor_hits,
                    report.mapped_evidence_count,
                    report.scan_seconds,
                    report.scan_gib_per_second,
                    report.total_seconds,
                    yes_no(report.complete),
                );
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::Virt2phys(args) => {
            let image = open_memory_image(args.image)?;
            let directory_table_base = match args.dtb {
                Some(dtb) => parse_integer(&dtb)?,
                None => image
                    .dump64()
                    .map(|dump| dump.directory_table_base)
                    .context("转换 raw/vmem 镜像地址时必须显式提供 --dtb")?,
            };
            let virtual_address = parse_integer(&args.address)?;
            let address_space = X64AddressSpace::new(&image, directory_table_base)?;
            let report = TranslationReport {
                virtual_address,
                physical_address: address_space.translate(virtual_address)?,
                directory_table_base: address_space.directory_table_base(),
            };
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "虚拟地址 {:#018x} -> 物理地址 {:#018x}",
                    report.virtual_address, report.physical_address
                );
                println!("DTB/CR3 {:#018x}", report.directory_table_base);
            }
        }
        Command::Symbols { command } => match command {
            SymbolCommand::Id { image, name } => {
                let image = open_memory_image(image)?;
                ensure!(!image.spans().is_empty(), "此镜像容器格式无法直接扫描");
                let records = discover_codeview(&image, &name)?;
                if cli.json {
                    print_json(&records)?;
                } else if records.is_empty() {
                    println!("未找到 {name} 的 RSDS 记录");
                } else {
                    for record in records {
                        println!(
                            "{} 符号标识={} 物理地址={:#x}\n  {}",
                            record.pdb_name,
                            record.symbol_key,
                            record.physical_address,
                            record.embedded_path
                        );
                    }
                }
            }
            SymbolCommand::Fetch {
                image,
                name,
                symbols,
            } => {
                let image = open_memory_image(image)?;
                let records = discover_codeview(&image, &name)?;
                let record = select_unique_record(&records)?.clone();
                let protected = image
                    .sources()
                    .map(|source| ("memory_image", source.path.as_path()))
                    .collect::<Vec<_>>();
                let destination = symbols.build().resolve_protecting(&record, &protected)?;
                let report = FetchReport {
                    record,
                    path: destination.display().to_string(),
                };
                if cli.json {
                    print_json(&report)?;
                } else {
                    println!("符号标识：{}", report.record.symbol_key);
                    println!("缓存位置：{}", report.path);
                }
            }
            SymbolCommand::Search { pdb, query, limit } => {
                let report = inspect_pdb(&pdb, &query, limit)?;
                if cli.json {
                    print_json(&report)?;
                } else {
                    println!("PDB {} 修订号 {}", report.guid, report.age);
                    for symbol in report.matches {
                        match symbol.rva {
                            Some(rva) => {
                                println!("RVA {rva:#010x} {:9} {}", symbol.kind, symbol.name)
                            }
                            None => println!(
                                "{:04x}:{:08x} {:9} {}",
                                symbol.section, symbol.section_offset, symbol.kind, symbol.name
                            ),
                        }
                    }
                }
            }
            SymbolCommand::Module {
                image,
                base,
                fetch,
                symbols,
            } => {
                let image = open_memory_image(image)?;
                let protected_paths = image
                    .sources()
                    .map(|source| source.path.clone())
                    .collect::<Vec<_>>();
                let record = if let Some(dump) = image.dump64() {
                    codeview_from_virtual_pe(
                        &image,
                        dump.directory_table_base,
                        parse_integer(&base)?,
                    )?
                } else {
                    let automatic = SymbolOptions {
                        profile: None,
                        pdb: None,
                        store: symbols.clone(),
                    };
                    let session = AnalysisSession::from_image(image, automatic.session_options())?;
                    print_session_warnings(&session);
                    codeview_from_virtual_pe(
                        session.image(),
                        session.kernel().directory_table_base,
                        parse_integer(&base)?,
                    )?
                };
                let protected = protected_paths
                    .iter()
                    .map(|path| ("memory_image", path.as_path()))
                    .collect::<Vec<_>>();
                let destination = fetch
                    .then(|| symbols.build().resolve_protecting(&record, &protected))
                    .transpose()?;
                if cli.json {
                    print_json(&(record, destination))?;
                } else {
                    println!("{} 符号标识={}", record.pdb_name, record.symbol_key);
                    println!("  {}", record.embedded_path);
                    if let Some(path) = destination {
                        println!("缓存位置：{}", path.display());
                    }
                }
            }
            SymbolCommand::Linux(args) => {
                let image = open_memory_image(&args.image)?;
                ensure!(
                    is_supported_linux_physical_image(&image),
                    "symbols linux 仅支持可解码的 Linux 物理内存镜像"
                );
                let banners = discover_linux_banners(&image)?;
                let store = args.symbols.build();
                let features = args.feature.into_iter().collect::<BTreeSet<_>>();
                let requested = LinuxSymbolDiagnosticOptions {
                    features: features.clone(),
                    isf: args.isf.clone(),
                    install: args.install,
                    fetch: args.fetch,
                    offline: args.offline,
                    refresh_index: args.refresh_index,
                };
                requested.validate()?;

                let install = args
                    .install
                    .then(|| {
                        install_linux_isf_for_image(
                            &store,
                            &image,
                            &banners,
                            args.isf.as_deref().expect("Clap requires --isf"),
                            features.iter().copied(),
                            force,
                        )
                    })
                    .transpose()?;
                let remote = if args.refresh_index {
                    Some(refresh_remote_linux_isf(&store, &banners)?)
                } else if args.fetch {
                    Some(resolve_remote_linux_isf(&store, &banners)?)
                } else {
                    None
                };

                let diagnostic_options = LinuxSymbolDiagnosticOptions {
                    features,
                    isf: args.isf,
                    install: false,
                    fetch: false,
                    offline: args.offline,
                    refresh_index: false,
                };
                let mut report =
                    diagnose_local_linux_symbols(&store, &banners, &diagnostic_options, None)?;
                report.effects.install_requested = requested.install;
                report.effects.fetch_requested = requested.fetch;
                report.effects.refresh_index_requested = requested.refresh_index;
                report.effects.offline = requested.offline;
                report.effects.network_accessed = remote.is_some();
                report.effects.cache_written = install.as_ref().is_some_and(|item| item.installed)
                    || remote
                        .as_ref()
                        .is_some_and(|resolution| resolution.table.is_some());

                let remote_summary = remote
                    .as_ref()
                    .map(|resolution| -> Result<serde_json::Value> {
                        Ok(serde_json::json!({
                            "files_considered": resolution.files_considered,
                            "selected_identity": resolution
                                .table
                                .as_ref()
                                .map(|table| table.identity())
                                .transpose()?,
                            "warnings": resolution.warnings,
                        }))
                    })
                    .transpose()?;
                let output = serde_json::json!({
                    "available": report.available,
                    "complete": report.complete,
                    "selection": report.selection,
                    "requested_features": report.requested_features,
                    "files_considered": report.files_considered,
                    "selected_identity": report.selected_identity,
                    "candidates": report.candidates,
                    "warnings": report.warnings,
                    "effects": report.effects,
                    "install": install,
                    "remote": remote_summary,
                    "banners": banners,
                });
                if cli.json {
                    print_json(&output)?;
                } else {
                    println!("Linux banner 候选：{}", banners.len());
                    println!("本地 ISF 候选：{}", report.files_considered);
                    println!("选择状态：{:?}", report.selection);
                    for candidate in &report.candidates {
                        println!("  {:?} {}", candidate.status, candidate.path);
                        for reason in &candidate.rejection_reasons {
                            println!("    [{}] {}", reason.code, reason.message);
                        }
                    }
                    if let Some(install) = install {
                        println!("ISF 安装目标：{}", install.destination);
                    }
                    for warning in &report.warnings {
                        eprintln!("警告 [{}]：{}", warning.kind, warning.message);
                    }
                }
            }
        },
        Command::Profile { pdb, output } => {
            let profile = build_eprocess_profile(&pdb)?;
            remember_windows_symbol_identity(&profile)?;
            OUTPUT_POLICY
                .get()
                .context("输出安全策略尚未初始化")?
                .write_file_atomic(&output, |file| {
                    serde_json::to_writer_pretty(BufWriter::new(file), &profile)?;
                    Ok(())
                })?;
            if cli.json {
                print_json(&profile)?;
            } else {
                println!(
                    "已将 {} 个字段写入 {}（结构大小 {:#x}）：{}",
                    profile.fields.len(),
                    profile.type_name,
                    profile.type_size,
                    output.display()
                );
            }
        }
        Command::Pslist(args) => {
            let image = open_memory_image(&args.image)?;
            if probe_linux_memory(&image)? {
                ensure!(
                    args.symbols.profile.is_none() && args.symbols.pdb.is_none(),
                    "Linux pslist 从内存 BTF、Volatility 3 ISF 或严格构建指纹自动选择布局，不接受 Windows --profile/--pdb"
                );
                let session = LinuxAnalysisSession::from_image_with_symbol_store(
                    image,
                    &args.symbols.store.build(),
                )?;
                let report = session.processes(args.limit)?;
                if cli.json {
                    print_json(&report)?;
                } else {
                    println!(
                        "{:>7} {:>7} {:>7} {:<18} {:<8} {:>18} 名称",
                        "PID", "TGID", "父PID", "状态", "内核线程", "TASK"
                    );
                    for process in &report.processes {
                        println!(
                            "{:>7} {:>7} {:>7} {:<18.18} {:<8} {:#018x} {}",
                            process.pid,
                            process.tgid,
                            process
                                .ppid
                                .map(|pid| pid.to_string())
                                .unwrap_or_else(|| "-".to_owned()),
                            process.state,
                            process.kernel_thread.map(yes_no).unwrap_or("未知"),
                            process.task,
                            process.name
                        );
                    }
                    println!("\n内核：{}", report.kernel.banner);
                    println!(
                        "DTB={:#x}；init_task={:#x}（物理 {:#x}）；布局来源={}",
                        report.kernel.directory_table_base,
                        report.kernel.init_task,
                        report.kernel.init_task_physical,
                        report.kernel.profile_source
                    );
                    println!(
                        "进程数：{}；是否完整={}；停止原因={:?}；扫描={:.3} 秒/{:.2} GiB/s",
                        report.processes.len(),
                        yes_no(report.complete),
                        report.stop_reason,
                        report.scan_seconds,
                        report.scan_gib_per_second
                    );
                    for warning in &report.warnings {
                        eprintln!("警告 [{}]：{}", warning.kind, warning.message);
                    }
                }
            } else {
                let session = AnalysisSession::from_image(image, args.symbols.session_options())?;
                print_session_warnings(&session);
                let report = session.processes(args.limit)?;
                if cli.json {
                    print_json(&report)?;
                } else {
                    println!(
                        "{:>7} {:>7} {:>4} {:>5} {:<28} {:<18} 命令行",
                        "PID", "父PID", "会话", "线程", "用户/SID", "映像"
                    );
                    for process in &report.processes {
                        let details = &process.details;
                        let account =
                            match (details.user_domain.as_deref(), details.user_name.as_deref()) {
                                (Some(domain), Some(user)) => format!("{domain}\\{user}"),
                                (_, Some(user)) => user.to_owned(),
                                _ => details.user_sid.clone().unwrap_or_else(|| "-".to_owned()),
                            };
                        println!(
                            "{:>7} {:>7} {:>4} {:>5} {:<28.28} {:<18.18} {}",
                            process.pid,
                            process
                                .ppid
                                .map(|pid| pid.to_string())
                                .unwrap_or_else(|| "-".to_owned()),
                            details
                                .session_id
                                .map(|session| session.to_string())
                                .unwrap_or_else(|| "-".to_owned()),
                            details
                                .active_threads
                                .map(|threads| threads.to_string())
                                .unwrap_or_else(|| "-".to_owned()),
                            account,
                            process.name,
                            details.command_line.as_deref().unwrap_or("")
                        );
                    }
                    println!(
                        "\n进程数：{}；是否完整={}；停止原因={}",
                        report.processes.len(),
                        yes_no(report.complete),
                        localize_runtime_message(&format!("{:?}", report.stop_reason))
                    );
                    for warning in report.warnings {
                        eprintln!(
                            "警告 [{}]：{}",
                            warning.kind,
                            localize_runtime_message(&warning.message)
                        );
                    }
                }
            }
        }
        Command::LinuxKaslr(args) => {
            let image = open_memory_image(&args.image)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.kaslr 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let report = session.kernel_text()?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("内核：{}", report.banner);
                println!("符号来源：{}", report.symbol_source);
                println!("_stext 虚拟地址：{:#018x}", report.virtual_address);
                println!("_stext 物理地址：{:#018x}", report.physical_address);
                println!(
                    "DTB={:#018x}；翻译={}；已核对首 {} 字节={}",
                    report.directory_table_base,
                    report.translation_source,
                    report.bytes_verified,
                    report.first_bytes_hex
                );
            }
        }
        Command::LinuxInfo { image: path } => {
            let image = open_memory_image(&path)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.info 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            ensure!(
                probe_linux_memory(&image)?,
                "镜像未同时通过 Linux banner 与 swapper 任务锚点探测"
            );
            let report = starmem::linux_info::analyze_linux_info(&image)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "HOSTNAME：{}",
                    report.hostname.as_deref().unwrap_or("未恢复")
                );
                println!(
                    "登录用户：{}",
                    report.logged_in_username.as_deref().unwrap_or("未恢复")
                );
                println!("Linux 版本：{}", report.linux_version);
                println!("内核：{}", report.kernel_banner);
                println!(
                    "是否完整={}；扫描={:.3} 秒/{:.2} GiB/s；范围：{}",
                    yes_no(report.complete),
                    report.scan_seconds,
                    report.scan_gib_per_second,
                    report.scope
                );
                for warning in &report.warnings {
                    eprintln!("警告 [{}]：{}", warning.kind, warning.message);
                }
            }
        }
        Command::LinuxCmdline(args) => {
            ensure!(args.process_limit > 0, "活动任务链上限必须大于零");
            ensure!(args.max_bytes > 0, "cmdline 最大读取字节数必须大于零");
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.cmdline 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let report = session.cmdline(args.pid, args.process_limit, args.max_bytes)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:>7} {:<18} {:<8} 命令行", "PID", "名称", "完整");
                for record in &report.records {
                    println!(
                        "{:>7} {:<18.18} {:<8} {}",
                        record.pid,
                        safe_terminal_text(&record.name),
                        yes_no(record.complete),
                        safe_terminal_text(&record.command_line)
                    );
                }
                println!(
                    "\n记录={}/{}；是否完整={}；范围：{}",
                    report.records_recovered,
                    report.processes_considered,
                    yes_no(report.complete),
                    report.scope
                );
                for warning in &report.warnings {
                    eprintln!("警告 [{}]：{}", warning.kind, warning.message);
                }
            }
        }
        Command::LinuxPsaux(args) => {
            ensure!(args.process_limit > 0, "活动任务链上限必须大于零");
            ensure!(args.max_bytes > 0, "psaux 最大读取字节数必须大于零");
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.psaux 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let report = session.psaux(args.pid, args.process_limit, args.max_bytes)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:>7} {:<16} {:<9} 命令行",
                    "PID", "父PID", "状态", "argv完整"
                );
                for record in &report.records {
                    println!(
                        "{:>7} {:>7} {:<16.16} {:<9} {}",
                        record.pid,
                        record
                            .ppid
                            .map(|pid| pid.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        record.state,
                        yes_no(record.command_line_complete),
                        safe_terminal_text(&record.command_line)
                    );
                }
                println!(
                    "\n进程={}；argv恢复={}；用户进程comm退化={}；内核线程={}；是否完整={}；范围：{}",
                    report.processes_considered,
                    report.command_lines_recovered,
                    report.user_cmdline_fallback_count,
                    report.kernel_thread_count,
                    yes_no(report.complete),
                    report.scope
                );
                for warning in &report.warnings {
                    eprintln!("警告 [{}]：{}", warning.kind, warning.message);
                }
            }
        }
        Command::LinuxEnvars(args) => {
            ensure!(args.process_limit > 0, "活动任务链上限必须大于零");
            ensure!(args.max_bytes > 0, "envars 最大读取字节数必须大于零");
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.envars 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let report = session.envars(args.pid, args.process_limit, args.max_bytes)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:>7} {:<18} {:<32} 值", "PID", "进程", "变量");
                for variable in &report.variables {
                    println!(
                        "{:>7} {:<18.18} {:<32.32} {}",
                        variable.pid,
                        safe_terminal_text(&variable.process_name),
                        safe_terminal_text(&variable.name),
                        safe_terminal_text(&variable.value)
                    );
                }
                println!(
                    "\n进程={}/{}；变量={}；是否完整={}；范围：{}",
                    report.processes_recovered,
                    report.processes_considered,
                    report.variable_count,
                    yes_no(report.complete),
                    report.scope
                );
                for warning in &report.warnings {
                    eprintln!("警告 [{}]：{}", warning.kind, warning.message);
                }
            }
        }
        Command::LinuxLsof(args) => {
            ensure!(args.process_limit > 0, "活动任务链上限必须大于零");
            ensure!(args.max_fds > 0, "FD 扫描上限必须大于零");
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.lsof 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let report = session.lsof(args.pid, args.process_limit, args.max_fds)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<18} {:>6} {:<16} {:<10} 路径",
                    "PID", "进程", "FD", "类型", "访问"
                );
                for record in &report.records {
                    println!(
                        "{:>7} {:<18.18} {:>6} {:<16.16} {:<10.10} {}",
                        record.pid,
                        safe_terminal_text(&record.process_name),
                        record.fd,
                        record.file_type.as_deref().unwrap_or("-"),
                        record.access_mode.as_deref().unwrap_or("-"),
                        safe_terminal_text(record.path.as_deref().unwrap_or("<路径未解析>"))
                    );
                }
                println!(
                    "\n进程={}；打开文件={}；是否完整={}；范围：{}",
                    report.process_count,
                    report.record_count,
                    yes_no(report.complete),
                    report.scope
                );
                for warning in &report.warnings {
                    eprintln!("警告 [{}]：{}", warning.kind, warning.message);
                }
            }
        }
        Command::LinuxSockstat(args) => {
            ensure!(args.process_limit > 0, "活动任务链上限必须大于零");
            ensure!(args.max_fds > 0, "FD 扫描上限必须大于零");
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.sockstat 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let report = session.sockstat(args.pid, args.process_limit, args.max_fds)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>10} {:>7} {:<18} {:>5} {:<9} {:<13} {:<30} {:<30} 状态",
                    "NETNS", "PID", "进程", "FD", "协议族", "协议", "本地", "远端"
                );
                for record in &report.records {
                    println!(
                        "{:>10} {:>7} {:<18.18} {:>5} {:<9.9} {:<13.13} {:<30.30} {:<30.30} {}",
                        record
                            .socket_net_namespace
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        record.pid,
                        safe_terminal_text(&record.process_name),
                        record.fd,
                        record.family,
                        record.protocol.as_deref().unwrap_or("-"),
                        safe_terminal_text(&format_linux_socket_endpoint(
                            record.local_address.as_deref(),
                            record.local_port,
                            record.family_raw,
                        )),
                        safe_terminal_text(&format_linux_socket_endpoint(
                            record.remote_address.as_deref(),
                            record.remote_port,
                            record.family_raw,
                        )),
                        record.state,
                    );
                }
                println!(
                    "\n候选 FD={}；已恢复={}；唯一 socket={}；进程={}；部分={}；失败={}；是否完整={}；范围：{}",
                    report.socket_fd_candidates,
                    report.records_recovered,
                    report.unique_sockets,
                    report.processes_with_sockets,
                    report.partial_records,
                    report.unrecoverable_candidates,
                    yes_no(report.complete),
                    report.scope,
                );
                for warning in &report.warnings {
                    eprintln!("警告 [{}]：{}", warning.kind, warning.message);
                }
            }
        }
        Command::LinuxProcMaps(args) => {
            ensure!(args.process_limit > 0, "活动任务链上限必须大于零");
            ensure!(args.map_limit > 0, "VMA 结果上限必须大于零");
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.proc.maps 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let report = session.proc_maps(args.pid, args.process_limit, args.map_limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:>18} {:>18} {:<4} {:>12} 路径",
                    "PID", "起始", "结束", "权限", "文件偏移"
                );
                for record in &report.records {
                    println!(
                        "{:>7} {:#018x} {:#018x} {:<4} {:#012x} {}",
                        record.pid,
                        record.start,
                        record.end,
                        record.permissions,
                        record.byte_offset,
                        safe_terminal_text(record.path.as_deref().unwrap_or(""))
                    );
                }
                println!(
                    "\n进程={}/{}；VMA={}；是否完整={}；来源={}",
                    report.processes_recovered,
                    report.processes_considered,
                    report.record_count,
                    yes_no(report.complete),
                    report.source
                );
                for warning in &report.warnings {
                    eprintln!("警告 [{}]：{}", warning.kind, warning.message);
                }
            }
        }
        Command::LinuxProcDump(args) => {
            ensure!(args.pid >= 0, "PID 不能为负数");
            ensure!(args.process_limit > 0, "活动任务链上限必须大于零");
            ensure!(args.map_limit > 0, "VMA 结果上限必须大于零");
            ensure!(args.max_region_size > 0, "单个 VMA 导出上限必须大于零");
            ensure!(args.max_total_size > 0, "进程导出总上限必须大于零");
            ensure_csv_does_not_overwrite_input(&args.image)?;
            ensure!(
                !output_paths_conflict(&args.image, &args.output),
                "进程导出目录不能与输入镜像相同：{}",
                args.output.display()
            );
            let image = open_memory_image(&args.image)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.proc.dump 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let report = session.proc_dump(
                args.pid,
                args.process_limit,
                &args.output,
                args.map_limit,
                args.max_region_size,
                args.max_total_size,
                force,
            )?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "PID {} {}：VMA={}，已写={}（完整={}，部分={}，跳过={}）",
                    report.pid,
                    safe_terminal_text(&report.process_name),
                    report.map_count,
                    report.regions_written,
                    report.regions_complete,
                    report.regions_partial,
                    report.regions_skipped
                );
                println!(
                    "逻辑字节={}；恢复字节={}；是否完整={}；输出目录={}",
                    report.total_logical_bytes,
                    report.total_recovered_bytes,
                    yes_no(report.complete),
                    report.output_directory
                );
                for warning in &report.warnings {
                    eprintln!("警告 [{}]：{}", warning.kind, warning.message);
                }
            }
        }
        Command::LinuxIr(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let options = starmem::linux_ir::LinuxIrOptions {
                module: args.module,
                pid: args.pid,
                limit: args.limit,
                max_bytes: args.max_bytes,
                path: args.path,
                ..Default::default()
            };
            print_json(&starmem::linux_ir::run_task(
                &session,
                &options,
                &starmem::cancellation::CancellationToken::new(),
            )?)?;
        }
        Command::LinuxIrKernel(args) => {
            let opened = args.kernel.open([LinuxSymbolFeature::IncidentResponse])?;
            let options = starmem::linux_ir::LinuxIrOptions {
                module: args.module,
                limit: args.limit,
                framebuffer_output: args.framebuffer_output,
                max_bytes: args.max_bytes,
                ..Default::default()
            };
            let report = starmem::linux_ir::run_kernel(
                &opened.session,
                &options,
                &starmem::cancellation::CancellationToken::new(),
            )?;
            print_json(&LinuxKernelPluginOutput {
                kernel_session: &opened.evidence,
                report: &report,
            })?;
        }
        Command::LinuxBash(args) => {
            ensure!(args.process_limit > 0, "活动任务链上限必须大于零");
            ensure!(args.map_limit > 0, "Bash VMA 结果上限必须大于零");
            ensure!(args.max_scan_bytes > 0, "Bash 扫描字节上限必须大于零");
            ensure!(args.max_command_bytes > 0, "Bash 命令长度上限必须大于零");
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.bash 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let report = session.bash(
                args.pid,
                args.process_limit,
                args.map_limit,
                args.max_scan_bytes,
                args.max_command_bytes,
            )?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:>7} {:>12} {:<12} 命令", "PID", "EPOCH", "置信度");
                for record in &report.records {
                    println!(
                        "{:>7} {:>12} {:<12.12} {}",
                        record.pid,
                        record.timestamp_epoch,
                        record.confidence,
                        safe_terminal_text(&record.command)
                    );
                }
                println!(
                    "\nBash 进程={}；扫描区={}；记录={}；是否完整={}；范围：{}",
                    report.bash_processes,
                    report.scan_region_count,
                    report.record_count,
                    yes_no(report.complete),
                    report.scope
                );
                for warning in &report.warnings {
                    eprintln!("警告 [{}]：{}", warning.kind, warning.message);
                }
            }
        }
        Command::LinuxPstree(args) => {
            ensure!(args.limit > 0, "活动任务链上限必须大于零");
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.pstree 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let report = session.process_tree(args.pid, args.limit)?;
            output_linux_process_tree(&report, cli.json)?;
        }
        Command::LinuxLsmod(args) => {
            ensure!(args.limit > 0, "module 结果上限必须大于零");
            let opened = args.kernel.open([LinuxSymbolFeature::Modules])?;
            let report = linux_lsmod(&opened.session, args.limit);
            if cli.json {
                print_json(&LinuxKernelPluginOutput {
                    kernel_session: &opened.evidence,
                    report: &report,
                })?;
            } else {
                print_linux_kernel_session_evidence(&opened.evidence);
                println!(
                    "{:>18} {:<28} {:>18} {:>12} {:>12} {:>18}",
                    "MODULE", "名称", "CORE 基址", "CORE 字节", "TEXT 字节", "INIT 基址"
                );
                for module in &report.modules {
                    println!(
                        "{:#018x} {:<28.28} {:#018x} {:>12} {:>12} {:#018x}",
                        module.module,
                        safe_terminal_text(&module.name),
                        module.core_base,
                        module.core_size,
                        module
                            .core_text_size
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        module.init_base.unwrap_or(0),
                    );
                }
                println!("\n停止原因：{}", report.stop_reason);
                print_linux_evidence_footer(
                    report.modules.len(),
                    report.available,
                    report.complete,
                    &report.warnings,
                );
            }
        }
        Command::LinuxModuleExtract(args) => {
            ensure!(args.max_bytes > 0, "module-extract 字节上限必须大于零");
            let opened = args.kernel.open([LinuxSymbolFeature::Modules])?;
            let selector = match (args.name, args.base) {
                (Some(name), None) => LinuxModuleSelector::Name(name),
                (None, Some(base)) => {
                    LinuxModuleSelector::Base(parse_integer(&base).context("--base 无效")?)
                }
                _ => unreachable!("clap 已保证 --name/--base 精确选择一项"),
            };
            let report = linux_module_extract(
                &opened.session,
                selector,
                &args.output,
                args.max_bytes,
                force,
            )?;
            if cli.json {
                print_json(&LinuxKernelPluginOutput {
                    kernel_session: &opened.evidence,
                    report: &report,
                })?;
            } else {
                print_linux_kernel_session_evidence(&opened.evidence);
                if let Some(module) = &report.module {
                    println!(
                        "模块：{}（module={:#018x}，core={:#018x}+{:#x}）",
                        safe_terminal_text(&module.name),
                        module.module,
                        module.core_base,
                        module.core_size,
                    );
                } else {
                    println!("没有找到与 selector 匹配的已验证模块。");
                }
                println!(
                    "恢复字节={}；ELF 字节={}；完整 ELF={}",
                    report.recovered_memory_bytes,
                    report.output_bytes,
                    yes_no(report.complete),
                );
                println!(
                    "输出：{}",
                    report
                        .output
                        .as_deref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "未写出".to_owned())
                );
                println!(
                    "Manifest：{}",
                    report
                        .manifest
                        .as_deref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "未写出".to_owned())
                );
                println!("SHA-256：{}", report.sha256.as_deref().unwrap_or("未生成"));
                print_linux_evidence_footer(
                    usize::from(report.module.is_some()),
                    report.available,
                    report.complete,
                    &report.warnings,
                );
            }
        }
        Command::LinuxMountinfo(args) => {
            ensure!(args.limit > 0, "mount 结果上限必须大于零");
            if let Some(pid) = args.pid {
                ensure!(pid >= 0, "PID 不能为负数");
            }
            let task = args
                .task
                .as_deref()
                .map(parse_integer)
                .transpose()
                .context("--task 无效")?;
            let namespace = args
                .namespace
                .as_deref()
                .map(parse_integer)
                .transpose()
                .context("--namespace 无效")?;
            let opened = args.kernel.open([LinuxSymbolFeature::Mount])?;
            let report = linux_mountinfo(
                &opened.session,
                &LinuxMountInfoOptions {
                    pid: args.pid,
                    task,
                    namespace,
                    limit: args.limit,
                },
            );
            if cli.json {
                print_json(&LinuxKernelPluginOutput {
                    kernel_session: &opened.evidence,
                    report: &report,
                })?;
            } else {
                print_linux_kernel_session_evidence(&opened.evidence);
                println!(
                    "{:>18} {:>8} {:>8} {:<14} {:<28} 挂载点",
                    "MOUNT", "ID", "设备", "文件系统", "ROOT"
                );
                for mount in &report.mounts {
                    let device = match (mount.device_major, mount.device_minor) {
                        (Some(major), Some(minor)) => format!("{major}:{minor}"),
                        _ => "-".to_owned(),
                    };
                    println!(
                        "{:#018x} {:>8} {:>8} {:<14.14} {:<28.28} {}",
                        mount.mount,
                        mount
                            .mount_id
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        device,
                        mount.file_system.as_deref().unwrap_or("-"),
                        safe_terminal_text(&mount.root),
                        safe_terminal_text(&mount.mount_point),
                    );
                }
                println!(
                    "\nNamespace={}；来源={}；停止原因={}",
                    report
                        .namespace
                        .map(|value| format!("{value:#018x}"))
                        .unwrap_or_else(|| "未解析".to_owned()),
                    report.source.source,
                    report.stop_reason,
                );
                print_linux_evidence_footer(
                    report.mounts.len(),
                    report.available,
                    report.complete,
                    &report.warnings,
                );
            }
        }
        Command::LinuxKallsyms(args) => {
            ensure!(args.limit > 0, "kallsyms 结果上限必须大于零");
            let opened = args.kernel.open([LinuxSymbolFeature::Kallsyms])?;
            let report = linux_kallsyms(&opened.session, args.limit);
            if cli.json {
                print_json(&LinuxKernelPluginOutput {
                    kernel_session: &opened.evidence,
                    report: &report,
                })?;
            } else {
                print_linux_kernel_session_evidence(&opened.evidence);
                println!(
                    "{:>10} {:>18} {:>4} {:<8} 名称",
                    "INDEX", "地址", "TYPE", "来源"
                );
                for symbol in &report.symbols {
                    println!(
                        "{:>10} {:#018x} {:>4} {:<8.8} {}",
                        symbol.index,
                        symbol.address,
                        symbol
                            .symbol_type
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        symbol.source,
                        safe_terminal_text(&symbol.name),
                    );
                }
                println!(
                    "\n声明符号={}；地址编码={}",
                    report
                        .declared_symbols
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "未知".to_owned()),
                    report.address_encoding.as_deref().unwrap_or("未知"),
                );
                print_linux_evidence_footer(
                    report.symbols.len(),
                    report.available,
                    report.complete,
                    &report.warnings,
                );
            }
        }
        Command::LinuxKmsg(args) => {
            ensure!(args.limit > 0, "kmsg 结果上限必须大于零");
            let boot_time_unix_ns = args
                .boot_time_unix_ns
                .as_deref()
                .map(parse_signed_integer)
                .transpose()
                .context("--boot-time-unix-ns 无效")?;
            let opened = args.kernel.open([LinuxSymbolFeature::Kmsg])?;
            let report = linux_kmsg(
                &opened.session,
                &LinuxKmsgOptions {
                    limit: args.limit,
                    boot_time_unix_ns,
                },
            );
            if cli.json {
                print_json(&LinuxKernelPluginOutput {
                    kernel_session: &opened.evidence,
                    report: &report,
                })?;
            } else {
                print_linux_kernel_session_evidence(&opened.evidence);
                println!("{:>12} {:>18} {:<30} 消息", "SEQ", "MONOTONIC_NS", "UTC");
                for record in &report.records {
                    println!(
                        "{:>12} {:>18} {:<30.30} {}",
                        record
                            .sequence
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        record.monotonic_ns,
                        record.utc.as_deref().unwrap_or("-"),
                        safe_terminal_text(&record.text),
                    );
                }
                println!("\n时间模式：{}", report.timestamp_mode);
                print_linux_evidence_footer(
                    report.records.len(),
                    report.available,
                    report.complete,
                    &report.warnings,
                );
            }
        }
        Command::LinuxModxview(args) => {
            ensure!(args.limit > 0, "modxview 结果上限必须大于零");
            let opened = args.kernel.open([LinuxSymbolFeature::Modules])?;
            let report = linux_modxview(&opened.session, args.limit);
            if cli.json {
                print_json(&LinuxKernelPluginOutput {
                    kernel_session: &opened.evidence,
                    report: &report,
                })?;
            } else {
                print_linux_kernel_session_evidence(&opened.evidence);
                println!(
                    "{:>18} {:<28} {:>8} {:>8} {:>8} 原因",
                    "MODULE", "名称", "LIST", "KSET", "可疑"
                );
                for module in &report.records {
                    println!(
                        "{:#018x} {:<28.28} {:>8} {:>8} {:>8} {}",
                        module.module,
                        safe_terminal_text(module.name.as_deref().unwrap_or("-")),
                        yes_no(module.in_modules_list),
                        yes_no(module.in_module_kset),
                        yes_no(module.suspicious),
                        module.reasons.join(";"),
                    );
                }
                for source in &report.sources {
                    println!(
                        "视图 {}: available={} complete={} records={}{}",
                        source.source,
                        yes_no(source.available),
                        yes_no(source.complete),
                        source.records,
                        source
                            .reason
                            .as_deref()
                            .map(|reason| format!("；{reason}"))
                            .unwrap_or_default(),
                    );
                }
                print_linux_evidence_footer(
                    report.records.len(),
                    report.available,
                    report.complete,
                    &report.warnings,
                );
            }
        }
        Command::LinuxCheckSyscall(args) => {
            ensure!(args.entries > 0, "syscall entry 数必须大于零");
            let features = if args.no_modules {
                vec![LinuxSymbolFeature::Hooks]
            } else {
                vec![LinuxSymbolFeature::Hooks, LinuxSymbolFeature::Modules]
            };
            let opened = args.kernel.open(features)?;
            let report = linux_check_syscall(
                &opened.session,
                &LinuxCheckSyscallOptions {
                    table: args.table.into(),
                    entries: args.entries,
                    include_modules: !args.no_modules,
                },
            );
            if cli.json {
                print_json(&LinuxKernelPluginOutput {
                    kernel_session: &opened.evidence,
                    report: &report,
                })?;
            } else {
                print_linux_kernel_session_evidence(&opened.evidence);
                println!(
                    "{:>8} {:>18} {:>18} {:<32} {:<20} 判定",
                    "INDEX", "ENTRY", "HANDLER", "分类", "归属"
                );
                for record in &report.records {
                    let classification = format!("{:?}", record.classification);
                    println!(
                        "{:>8} {:#018x} {:>18} {:<32.32} {:<20.20} {}",
                        record.index,
                        record.entry_address,
                        record
                            .handler
                            .map(|value| format!("{value:#018x}"))
                            .unwrap_or_else(|| "-".to_owned()),
                        classification,
                        record.owner.as_deref().unwrap_or("-"),
                        match record.suspicious {
                            Some(true) => "可疑",
                            Some(false) => "已验证",
                            None => "不确定",
                        },
                    );
                }
                println!(
                    "\n表={:?}@{}；可疑={}；不确定={}",
                    report.table,
                    report
                        .table_address
                        .map(|value| format!("{value:#018x}"))
                        .unwrap_or_else(|| "未解析".to_owned()),
                    report.suspicious,
                    report.indeterminate,
                );
                print_linux_evidence_footer(
                    report.records.len(),
                    report.available,
                    report.complete,
                    &report.warnings,
                );
            }
        }
        Command::Psscan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.process_scan(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>18} {:>7} {:>7} {:<18} {:>6} {:>6} 创建时间",
                    "EPROCESS", "物理地址", "PID", "父PID", "映像", "活动", "评分"
                );
                for process in &report.records {
                    println!(
                        "{:#018x} {:#018x} {:>7} {:>7} {:<18.18} {:>6} {:>6} {}",
                        process.eprocess,
                        process.physical_address,
                        process.pid,
                        process
                            .ppid
                            .map(|pid| pid.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        process.name,
                        process.in_active_list,
                        process.validation_score,
                        process.create_time.as_deref().unwrap_or("")
                    );
                }
                println!(
                    "扫描：{} 字节，耗时 {:.3} 秒（{:.2} GiB/s）；活动进程={}；池候选={}",
                    report.bytes_scanned,
                    report.scan_seconds,
                    report.scan_gib_per_second,
                    report.active_process_count,
                    report.pool_candidates
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Pstree(args) => {
            ensure!(args.limit > 0, "进程树结果上限必须大于零");
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            if probe_linux_memory(&image)? {
                ensure!(
                    args.symbols.profile.is_none() && args.symbols.pdb.is_none(),
                    "Linux pstree 从内存 BTF、Volatility 3 ISF 或严格构建指纹自动选择布局，不接受 Windows --profile/--pdb"
                );
                let session = LinuxAnalysisSession::from_image_with_symbol_store(
                    image,
                    &args.symbols.store.build(),
                )?;
                let report = session.process_tree(None, args.limit)?;
                output_linux_process_tree(&report, cli.json)?;
            } else {
                let session = AnalysisSession::from_image(image, args.symbols.session_options())?;
                print_session_warnings(&session);
                let report = session.process_tree(args.limit)?;
                if cli.json {
                    print_json(&report)?;
                } else {
                    println!("{:>7} {:>7} {:>18} 进程树", "PID", "父PID", "EPROCESS");
                    for process in &report.records {
                        println!(
                            "{:>7} {:>7} {:#018x} {}{}{}",
                            process.pid,
                            process
                                .ppid
                                .map(|pid| pid.to_string())
                                .unwrap_or_else(|| "-".to_owned()),
                            process.eprocess,
                            "  ".repeat(process.depth),
                            process.name,
                            if process.orphan_parent {
                                " [orphan parent]"
                            } else {
                                ""
                            }
                        );
                    }
                    print_plugin_footer(report.records.len(), report.complete, &report.warnings);
                }
            }
        }
        Command::CheckPslist(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.check_pslist(&CheckPslistOptions {
                pid: args.pid,
                process_limit: args.process_limit,
                thread_limit: args.thread_limit,
                handle_scan_limit: args.handle_scan_limit,
                result_limit: args.limit,
            })?;
            if cli.json || CSV_OUTPUT.get().is_some() {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:>7} {:>7} {:<18} {:<18} {:<6} 判定",
                    "PID", "记录父PID", "创建者PID", "进程", "可能创建者", "置信度"
                );
                for record in &report.records {
                    let confidence = match record.confidence {
                        CheckPslistConfidence::High => "高",
                        CheckPslistConfidence::Medium => "中",
                    };
                    let verdict = match record.verdict {
                        CheckPslistVerdict::PpidSpoofSuspected => "疑似 PPID spoof",
                        CheckPslistVerdict::AlternativeCreatorObserved => "发现替代创建者",
                    };
                    println!(
                        "{:>7} {:>7} {:>7} {:<18.18} {:<18.18} {:<6} {}",
                        record.pid,
                        record
                            .reported_ppid
                            .map(|pid| pid.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        record.likely_creator_pid,
                        record.process,
                        record.likely_creator,
                        confidence,
                        verdict
                    );
                }
                if report.records.is_empty() {
                    println!("未恢复到替代创建者句柄组合；请结合完整性和告警判断。");
                }
                println!(
                    "检查：进程={}；目标={}；线程={}；句柄表项={}；高置信度={}；中置信度={}；无法评估={}；忽略例行代理={}",
                    report.processes_examined,
                    report.target_processes,
                    report.threads_examined,
                    report.handle_entries_examined,
                    report.high_confidence_count,
                    report.medium_confidence_count,
                    report.unassessed_processes,
                    report.routine_broker_candidates_ignored
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Psxview(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.psxview(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>7} {:<18} {:>7} {:>7} {:>7} {:>7} 隐藏",
                    "EPROCESS", "PID", "映像", "活动", "内存池", "线程", "CID"
                );
                for process in &report.records {
                    println!(
                        "{:#018x} {:>7} {:<18.18} {:>7} {:>7} {:>7} {:>7} {}",
                        process.eprocess,
                        process
                            .pid
                            .map(|pid| pid.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        process.name.as_deref().unwrap_or(""),
                        process.active_process_list,
                        process.process_pool,
                        process.thread_owner,
                        process
                            .psp_cid_table
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "n/a".to_owned()),
                        process.hidden_suspect
                    );
                }
                println!(
                    "扫描：{} 字节，耗时 {:.3} 秒（{:.2} GiB/s）",
                    report.bytes_scanned, report.scan_seconds, report.scan_gib_per_second
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Threads(args) => run_thread_view(args, ThreadView::All, cli.json)?,
        Command::SuspendedThreads(args) => run_thread_view(args, ThreadView::Suspended, cli.json)?,
        Command::SuspiciousThreads(args) => {
            run_thread_view(args, ThreadView::Suspicious, cli.json)?
        }
        Command::OrphanKernelThreads(args) => {
            run_thread_view(args, ThreadView::OrphanKernel, cli.json)?
        }
        Command::Thrdscan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.thread_scan(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                print_thread_table(&report.records);
                println!(
                    "扫描：{} 字节，耗时 {:.3} 秒（{:.2} GiB/s）；池候选={}",
                    report.bytes_scanned,
                    report.scan_seconds,
                    report.scan_gib_per_second,
                    report.pool_candidates
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Sessions(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.process_sessions(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                for session in &report.sessions {
                    println!(
                        "会话 {}：{} 个进程，SID=[{}]",
                        session.session_id,
                        session.process_count,
                        session.user_sids.join(", ")
                    );
                    for process in &session.processes {
                        println!(
                            "  {:>7} {:#018x} {:<18} {}",
                            process.pid,
                            process.eprocess,
                            process.name,
                            process.user_sid.as_deref().unwrap_or("")
                        );
                    }
                }
                print_plugin_footer(report.sessions.len(), report.complete, &report.warnings);
            }
        }
        Command::LogonSessions(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.logon_sessions(&LogonSessionOptions {
                process_limit: args.process_limit,
                limit: args.limit,
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:<18} {:<24} {:<16} {:>7} {:>7} {:>7} 关联",
                    "AuthenticationId", "账户", "Token会话", "进程", "令牌", "引用"
                );
                for record in &report.records {
                    let account = match (&record.authority_name, &record.account_name) {
                        (Some(authority), Some(account)) => format!("{authority}\\{account}"),
                        (_, Some(account)) => account.clone(),
                        _ => record
                            .well_known_authentication
                            .clone()
                            .unwrap_or_else(|| "-".to_owned()),
                    };
                    println!(
                        "{:<18} {:<24.24} {:<16.16} {:>7} {:>7} {:>7} {}",
                        record.authentication_id,
                        safe_terminal_text(&account),
                        record
                            .token_session_ids
                            .iter()
                            .map(u32::to_string)
                            .collect::<Vec<_>>()
                            .join(","),
                        record.process_count,
                        record.primary_token_count,
                        record
                            .reference_count
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        record.association_status
                    );
                    if !record.user_sids.is_empty() {
                        println!("  用户SID：{}", record.user_sids.join(", "));
                    }
                    if !record.logon_sids.is_empty() {
                        println!("  登录SID：{}", record.logon_sids.join(", "));
                    }
                    for process in &record.processes {
                        println!(
                            "  {:>7} {:#018x} {:<18.18} Token={:#018x} PEB/Token会话={}/{}",
                            process.pid,
                            process.eprocess,
                            safe_terminal_text(&process.process),
                            process.token.unwrap_or(0),
                            process
                                .peb_session_id
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "-".to_owned()),
                            process
                                .token_session_id
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "-".to_owned())
                        );
                    }
                    for warning in &record.consistency_warnings {
                        println!("  一致性：{}", safe_terminal_text(warning));
                    }
                }
                println!(
                    "范围：{}；活动进程={}；主令牌={}/{}；内核会话={}/{}；一致={}；耗时={:.3}s",
                    report.scope,
                    report.processes_examined,
                    report.unique_primary_tokens,
                    report.primary_tokens_examined,
                    report.kernel_sessions_examined,
                    report.sessions_found,
                    yes_no(report.consistent),
                    report.scan_seconds
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::TokenAnomalies(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.token_anomalies(&TokenAnomalyOptions {
                process_limit: args.process_limit,
                limit: args.limit,
                direct_only: args.direct_only,
                min_severity: args.min_severity.into(),
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:<10} {:>18} {:<24} {:<18} {:<18} 发现",
                    "严重度", "TOKEN", "进程", "AuthenticationId", "用户SID"
                );
                for record in &report.records {
                    let processes = record
                        .owners
                        .iter()
                        .map(|owner| format!("{}({})", owner.process, owner.pid))
                        .collect::<Vec<_>>()
                        .join(",");
                    println!(
                        "{:<10} {:#018x} {:<24.24} {:<18} {:<18.18} {}",
                        record.max_severity.as_str(),
                        record.token,
                        safe_terminal_text(&processes),
                        record.authentication_id.as_deref().unwrap_or("-"),
                        record.user_sid.as_deref().unwrap_or("-"),
                        record.findings.len()
                    );
                    for finding in &record.findings {
                        println!(
                            "  [{}][{}][{}] {}",
                            finding.severity.as_str(),
                            match finding.evidence_class.as_str() {
                                "structural_contradiction" => "结构矛盾",
                                "incomplete_evidence" => "恢复不完整",
                                _ => "上下文风险",
                            },
                            finding.rule,
                            safe_terminal_text(&finding.summary)
                        );
                        for evidence in &finding.evidence {
                            println!("    {}", safe_terminal_text(evidence));
                        }
                    }
                }
                println!(
                    "范围：{}\n扫描进程={}/{}；可信/不可信令牌={}/{}；发现={}/{}；直接={}；上下文={}；恢复={}；clean={}；增强完整={}；耗时={:.3}s",
                    report.scope,
                    report.active_processes_examined,
                    report.processes_examined,
                    report.trusted_token_structures,
                    report.untrusted_token_structures,
                    report.findings_matched,
                    report.findings_detected,
                    report.direct_findings_detected,
                    report.contextual_signals_detected,
                    report.recovery_findings_detected,
                    yes_no(report.clean),
                    yes_no(report.enrichment_complete),
                    report.scan_seconds
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Joblinks(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.job_links(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<18} {:>18} {:>8} {:>8} {:>8} 标志",
                    "PID", "进程", "EJOB", "作业ID", "会话", "活动"
                );
                for job in &report.records {
                    println!(
                        "{:>7} {:<18.18} {:#018x} {:>8} {:>8} {:>8} {:#010x}",
                        job.pid,
                        job.process,
                        job.job,
                        job.job_id.unwrap_or(0),
                        job.session_id.unwrap_or(0),
                        job.active_processes.unwrap_or(0),
                        job.limit_flags.unwrap_or(0)
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Cmdline(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.command_lines(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:>7} {:<18} 命令行", "PID", "进程");
                for process in &report.records {
                    println!(
                        "{:>7} {:<18.18} {}",
                        process.pid,
                        process.process,
                        process.command_line.as_deref().unwrap_or("")
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Envars(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.environment_variables(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:>7} {:<18} {:<32} 值", "PID", "进程", "变量");
                for variable in &report.records {
                    println!(
                        "{:>7} {:<18.18} {:<32.32} {}",
                        variable.pid, variable.process, variable.variable, variable.value
                    );
                }
                println!("已检查进程数：{}", report.process_count);
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::TerminalHistory(args) => {
            let max_history_file_size = args
                .max_history_file_mib
                .checked_mul(1024 * 1024)
                .and_then(|size| u64::try_from(size).ok())
                .context("PSReadLine 历史文件最大恢复大小溢出")?;
            eprintln!("[1/6] 正在加载镜像、解析 Windows 内核并准备符号表……");
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.terminal_history(
                &TerminalHistoryOptions {
                    limit: args.limit,
                    file_scan_limit: args.file_scan_limit,
                    history_file_limit: args.history_file_limit,
                    max_history_file_size,
                },
                |stage| match stage {
                    TerminalHistoryStage::Processes => {
                        eprintln!("[2/6] 正在枚举 Windows Terminal、控制台宿主和命令解释器……")
                    }
                    TerminalHistoryStage::ConsoleHistories => {
                        eprintln!("[3/6] 正在恢复 conhost/OpenConsole 结构化命令历史……")
                    }
                    TerminalHistoryStage::FileObjects => {
                        eprintln!("[4/6] 正在扫描并验证 PSReadLine 历史文件对象……")
                    }
                    TerminalHistoryStage::HistoryFiles => {
                        eprintln!("[5/6] 正在恢复驻留历史文件并识别 UTF-8/UTF-16 编码……")
                    }
                    TerminalHistoryStage::Aggregate => {
                        eprintln!("[6/6] 正在关联终端进程并整理证据来源……")
                    }
                },
            )?;
            if cli.json {
                print_json(&report)?;
            } else {
                print_terminal_history_report(&report);
            }
        }
        Command::Cmdscan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.command_histories(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:>18} {:>5} 应用程序/命令",
                    "PID", "HISTORY", "INDEX"
                );
                for history in &report.records {
                    println!(
                        "{:>7} {:#018x} {:>5} {}",
                        history.conhost_pid,
                        history.address,
                        "APP",
                        history.application.as_deref().unwrap_or("")
                    );
                    for command in &history.commands {
                        println!(
                            "{:>7} {:#018x} {:>5} {}",
                            history.conhost_pid, history.address, command.index, command.text
                        );
                    }
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Consoles(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.consoles(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                for console in &report.records {
                    println!(
                        "PID {} 控制台 {:#x} {}x{} 标题={}（{}）",
                        console.conhost_pid,
                        console.address,
                        console.screen_x,
                        console.screen_y,
                        console.title.as_deref().unwrap_or(""),
                        console.layout
                    );
                    for line in &console.screen_lines {
                        println!("  {line}");
                    }
                }
                println!("命令历史数：{}", report.histories.len());
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Windowstations(args) => run_windowstations_plugin(args, cli.json)?,
        Command::Desktops(args) => run_desktop_plugin(args, false, cli.json)?,
        Command::Deskscan(args) => run_desktop_plugin(args, true, cli.json)?,
        Command::GuiWindows(args) => run_windows_plugin(args, cli.json)?,
        Command::Windowtitles(args) => run_window_titles_plugin(args, cli.json)?,
        Command::GdiBitmap(args) => {
            let max_bitmap_bytes = args
                .max_bitmap_mib
                .checked_mul(1024 * 1024)
                .context("单张 GDI 位图大小上限溢出")?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.gdi_bitmaps(&GdiBitmapOptions {
                pid: args.pid,
                output: args.output,
                limit: args.limit,
                max_dimension: args.max_dimension,
                max_bitmap_bytes,
                force,
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                for bitmap in &report.records {
                    println!(
                        "{} PID={} {:#018x} {}x{} {}bpp {}：{}",
                        bitmap.process,
                        bitmap.pid,
                        bitmap.header_address,
                        bitmap.width,
                        bitmap.height,
                        bitmap.bits_per_pixel,
                        bitmap.compression,
                        bitmap
                            .output
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .or_else(|| bitmap.warning.clone())
                            .unwrap_or_else(|| "未导出".to_owned())
                    );
                }
                println!("清单：{}", report.manifest.display());
                println!(
                    "进程={}；VAD={}；扫描字节={}；DIB 头命中={}；结构有效={}；完整导出={}",
                    report.processes_examined,
                    report.vads_examined,
                    report.mapped_bytes_examined,
                    report.header_hits,
                    report.validated_headers,
                    report.exported_bitmaps,
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::DesktopReconstruct(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.reconstruct_desktops(&DesktopReconstructOptions {
                output: args.output,
                session_id: args.session_id,
                desktop: args.desktop,
                limit: args.limit,
                max_dimension: args.max_dimension,
                force,
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                for desktop in &report.desktops {
                    println!(
                        "会话 {} {}\\{}：{}x{}，可见窗口={}，布局窗口={}，真实像素覆盖={:.2}%\n  {}",
                        desktop.session_id,
                        desktop.window_station,
                        desktop.desktop,
                        desktop.width,
                        desktop.height,
                        desktop.visible_windows,
                        desktop.rendered_windows,
                        desktop.pixel_coverage_percent,
                        desktop.output.display(),
                    );
                }
                println!("清单：{}", report.manifest.display());
                println!(
                    "当前阶段仅恢复经过结构验证的窗口布局；像素覆盖率为 {:.2}%，不把线框冒充屏幕像素。",
                    report.pixel_coverage_percent
                );
                print_plugin_footer(report.rendered_windows, report.complete, &report.warnings);
            }
        }
        Command::Privileges(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.process_privileges(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<18} {:>5} {:<42} 存在 启用 默认",
                    "PID", "进程", "值", "权限"
                );
                for privilege in &report.records {
                    println!(
                        "{:>7} {:<18.18} {:>5} {:<42} {:>7} {:>7} {:>7}",
                        privilege.pid,
                        privilege.process,
                        privilege.value,
                        privilege.privilege,
                        yes_no(privilege.present),
                        yes_no(privilege.enabled),
                        yes_no(privilege.enabled_by_default)
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Getsids(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.process_sids(args.pid, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<18} {:<10} {:<48} {:<42} 属性",
                    "PID", "进程", "类别", "SID", "账户"
                );
                for sid in &report.records {
                    println!(
                        "{:>7} {:<18.18} {:<10} {:<48.48} {:<42.42} {}",
                        sid.pid,
                        sid.process,
                        sid.kind,
                        sid.sid,
                        sid.account.as_deref().unwrap_or(""),
                        sid.attribute_names.join(",")
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Getservicesids(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.service_sids(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:<48} SID", "服务");
                for service in &report.records {
                    println!("{:<48.48} {}", service.service, service.sid);
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Modscan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.module_scan(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>18} {:>10} {:>7} 路径",
                    "条目", "基址", "大小", "已加载"
                );
                for module in &report.records {
                    println!(
                        "{:#018x} {:#018x} {:#010x} {:>7} {}",
                        module.entry,
                        module.base,
                        module.size,
                        module.in_loaded_module_list,
                        module.path
                    );
                }
                println!(
                    "扫描：{} 字节，耗时 {:.3} 秒（{:.2} GiB/s）",
                    report.bytes_scanned, report.scan_seconds, report.scan_gib_per_second
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Driverscan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.driver_scan(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>18} {:>10} {:>18} 名称",
                    "DRIVER_OBJECT", "起始地址", "大小", "设备"
                );
                for driver in &report.records {
                    println!(
                        "{:#018x} {:#018x} {:#010x} {:#018x} {}",
                        driver.driver_object,
                        driver.driver_start,
                        driver.driver_size,
                        driver.device_object.unwrap_or(0),
                        driver.name
                    );
                }
                println!(
                    "扫描：{} 字节，耗时 {:.3} 秒（{:.2} GiB/s）",
                    report.bytes_scanned, report.scan_seconds, report.scan_gib_per_second
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Drivermodule(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.driver_modules(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>18} {:<30} {:<30} 无模块支持",
                    "DRIVER_OBJECT", "起始地址", "驱动", "模块"
                );
                for driver in &report.records {
                    println!(
                        "{:#018x} {:#018x} {:<30.30} {:<30.30} {}",
                        driver.driver_object,
                        driver.driver_start,
                        driver.driver_name,
                        driver.module_path.as_deref().unwrap_or(""),
                        driver.suspicious_unbacked
                    );
                }
                println!(
                    "已加载模块数={}；驱动对象数={}",
                    report.loaded_module_count, report.driver_object_count
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Driverirp(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.driver_irps(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:<28} {:<28} {:>18} {:<30} 可疑",
                    "DRIVER_OBJECT", "驱动", "主功能号", "例程", "模块"
                );
                for irp in &report.records {
                    println!(
                        "{:#018x} {:<28.28} {:<28.28} {:#018x} {:<30.30} {}",
                        irp.driver_object,
                        irp.driver_name,
                        irp.major_name,
                        irp.routine,
                        irp.module.as_deref().unwrap_or(""),
                        irp.suspicious
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::DriverInspect(args) => {
            let address_filter = args
                .address
                .as_deref()
                .map(parse_integer)
                .transpose()
                .context("--address 无效")?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report =
                session.driver_inspect(args.name.as_deref(), address_filter, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:<6} {:<32} {:>18} {:<20} {:<27} 路径",
                    "节点", "驱动", "DRIVER_OBJECT", "路径类别", "内存映像状态"
                );
                for driver in &report.drivers {
                    println!(
                        "{:<6} {:<32.32} {:#018x} {:<20.20} {:<27.27} {}",
                        if driver.triage_attention {
                            "[DRV!]"
                        } else {
                            "[DRV]"
                        },
                        driver.name,
                        driver.driver_object,
                        driver.path_status,
                        driver.module_status,
                        driver.module_path.as_deref().unwrap_or("")
                    );
                    for device in report
                        .devices
                        .iter()
                        .filter(|device| device.driver_object == driver.driver_object)
                    {
                        println!(
                            "  └─ [DEV] <unnamed> {:#018x} type={:#x} attached={:#018x}",
                            device.device_object,
                            device.device_type.unwrap_or(0),
                            device.attached_device.unwrap_or(0)
                        );
                    }
                    if driver.triage_attention {
                        println!("     关注原因：{}", driver.triage_reasons.join(", "));
                    }
                }
                if args.name.is_some() || address_filter.is_some() || report.drivers.len() == 1 {
                    println!("\nIRP Dispatch");
                    println!("{:<28} {:>18} {:<32} 模块", "主功能号", "例程", "驱动");
                    for dispatch in &report.irp_dispatch {
                        println!(
                            "{:<28.28} {:#018x} {:<32.32} {}",
                            dispatch.major_name,
                            dispatch.routine,
                            dispatch.driver_name,
                            dispatch.module.as_deref().unwrap_or("")
                        );
                    }
                    println!("\nFast I/O Dispatch");
                    println!("{:<34} {:>18} {:<32} 模块", "名称", "例程", "驱动");
                    for dispatch in report
                        .fast_io_dispatch
                        .iter()
                        .filter(|dispatch| dispatch.implemented)
                    {
                        println!(
                            "{:<34.34} {:#018x} {:<32.32} {}",
                            dispatch.function_name,
                            dispatch.routine,
                            dispatch.driver_name,
                            dispatch.module.as_deref().unwrap_or("")
                        );
                    }
                } else {
                    println!(
                        "提示：使用 --name <驱动对象名> 或 --address <DRIVER_OBJECT> 展开 IRP/Fast I/O 分发表；JSON 始终包含全部区段。"
                    );
                }
                println!(
                    "已加载模块数={}；驱动对象数={}；匹配={}；需关注={}；可疑挂钩={}；Fast I/O 可用={}",
                    report.loaded_module_count,
                    report.driver_object_count,
                    report.matched_driver_count,
                    report.attention_driver_count,
                    report.suspicious_driver_count,
                    report.fast_io_available
                );
                print_plugin_footer(report.drivers.len(), report.complete, &report.warnings);
            }
        }
        Command::Devicetree(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.device_tree(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>18} {:>18} {:>10} 驱动",
                    "DEVICE_OBJECT", "下一个", "附加对象", "类型"
                );
                for device in &report.records {
                    println!(
                        "{:#018x} {:#018x} {:#018x} {:#010x} {}",
                        device.device_object,
                        device.next_device.unwrap_or(0),
                        device.attached_device.unwrap_or(0),
                        device.device_type.unwrap_or(0),
                        device.driver_name
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Callbacks(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.callbacks(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:<38} {:>5} {:>18} {:>18} {:<18} {:<17} {:<40} {:<8} 详情",
                    "类别", "索引", "块", "例程", "状态", "证据来源", "模块", "无模块支持"
                );
                for callback in &report.records {
                    let evidence_sources = callback.evidence_sources.join("+");
                    println!(
                        "{:<38} {:>5} {:#018x} {:#018x} {:<18.18} {:<17.17} {:<40.40} {:<8} {}",
                        callback.kind,
                        callback.index,
                        callback.callback_block,
                        callback.routine,
                        callback.registration_status,
                        evidence_sources,
                        callback.module.as_deref().unwrap_or(""),
                        callback.suspicious_unbacked,
                        callback.detail.as_deref().unwrap_or("")
                    );
                }
                println!(
                    "证据观察={}；唯一回调/候选={}；活动注册={}；纯池候选={}；保留记录={}；合并重复证据={}；扫描池分配={}；缺页={}",
                    report.evidence_observations,
                    report.unique_callback_count,
                    report.unique_registration_count,
                    report.pool_only_candidate_count,
                    report.records_retained,
                    report.duplicate_evidence_merged,
                    report.pool_candidates,
                    report.missing_pages
                );
                for source in &report.sources {
                    println!(
                        "  来源 {:<38.38} 可用={} 完整={} 恢复={} 畸形={} 辅助计数={:?}",
                        source.name,
                        yes_no(source.available),
                        yes_no(source.complete),
                        source.recovered,
                        source.malformed,
                        source.helper_counts
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Ssdt(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.ssdt(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:<16} {:>6} {:>18} {:>4} {:<40} 无模块支持",
                    "表", "索引", "例程", "参数数", "模块"
                );
                for entry in &report.records {
                    println!(
                        "{:<16} {:>6} {:#018x} {:>4} {:<40.40} {}",
                        entry.table,
                        entry.index,
                        entry.routine,
                        entry.argument_count,
                        entry.module.as_deref().unwrap_or(""),
                        entry.suspicious_unbacked
                    );
                }
                for descriptor in &report.descriptors {
                    println!(
                        "描述符 {} 位于 {:#018x}：表地址={:#018x}，服务数={}",
                        descriptor.name,
                        descriptor.descriptor,
                        descriptor.service_table,
                        descriptor.number_of_services
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Unloadedmodules(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.unloaded_modules(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>4} {:>18} {:>18} {:<32} 卸载时间",
                    "槽位", "起始地址", "结束地址", "名称"
                );
                for module in &report.records {
                    println!(
                        "{:>4} {:#018x} {:#018x} {:<32.32} {}",
                        module.slot,
                        module.start_address,
                        module.end_address,
                        module.name,
                        module
                            .unload_time
                            .clone()
                            .or_else(|| module
                                .unload_uptime_seconds
                                .map(|seconds| format!("uptime+{seconds:.3}s")))
                            .as_deref()
                            .unwrap_or("")
                    );
                }
                println!("最后循环索引：{}", report.last_index);
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Mutantscan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.mutants(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>18} {:>18} {:>8} 名称",
                    "MUTANT", "物理地址", "归属", "状态"
                );
                for mutant in &report.records {
                    println!(
                        "{:#018x} {:#018x} {:#018x} {:>8} {}",
                        mutant.mutant,
                        mutant.physical_address,
                        mutant.owner_thread.unwrap_or(0),
                        mutant.signal_state,
                        mutant.name.as_deref().unwrap_or("")
                    );
                }
                println!(
                    "共享 Muta/Symb 扫描：{} 字节，耗时 {:.3} 秒（{:.2} GiB/s）",
                    report.bytes_scanned, report.scan_seconds, report.scan_gib_per_second
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Symlinkscan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.symbolic_links(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:>18} {:<26} {:<36} 目标", "符号链接", "创建时间", "名称");
                for link in &report.records {
                    println!(
                        "{:#018x} {:<26.26} {:<36.36} {}",
                        link.symbolic_link,
                        link.creation_time.as_deref().unwrap_or(""),
                        link.name.as_deref().unwrap_or(""),
                        link.target
                    );
                }
                println!(
                    "共享 Muta/Symb 扫描：{} 字节，耗时 {:.3} 秒（{:.2} GiB/s）",
                    report.bytes_scanned, report.scan_seconds, report.scan_gib_per_second
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Timers(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.timers(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>3} {:>18} {:<21} {:>10} {:>18} {:<36} 无模块支持",
                    "CPU", "定时器", "到期时间", "周期", "例程", "模块"
                );
                for timer in &report.records {
                    println!(
                        "{:>3} {:#018x} {:<21} {:>10} {:#018x} {:<36.36} {}",
                        timer.processor_index,
                        timer.timer,
                        timer.due_time_hex,
                        timer.period_ms,
                        timer.deferred_routine.unwrap_or(0),
                        timer.module.as_deref().unwrap_or(""),
                        timer.suspicious_unbacked
                    );
                }
                println!(
                    "处理器数={}；定时器桶数={}",
                    report.processors_examined, report.timer_buckets_examined
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Drivers(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.drivers(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:>18} {:>10} 名称", "基址", "大小");
                for driver in &report.records {
                    println!(
                        "{:#018x} {:#010x} {}",
                        driver.base, driver.size, driver.path
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Dlllist(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.dlls(args.pid, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:>8} {:>18} {:>10} 名称", "PID", "基址", "大小");
                for dll in &report.records {
                    println!(
                        "{:>8} {:#018x} {:#010x} {}",
                        dll.pid, dll.base, dll.size, dll.path
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Ldrmodules(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.ldr_modules(args.pid, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<18} {:>18} {:>5} {:>5} {:>5} 路径",
                    "PID", "进程", "基址", "加载链", "内存链", "初始化链"
                );
                for module in &report.records {
                    println!(
                        "{:>7} {:<18.18} {:#018x} {:>5} {:>5} {:>5} {}",
                        module.pid,
                        module.process,
                        module.base,
                        module.in_load_order,
                        module.in_memory_order,
                        module.in_initialization_order,
                        module.mapped_path.as_deref().unwrap_or("")
                    );
                }
                println!(
                    "已检查进程数={}；已检查 VAD 数={}",
                    report.processes_examined, report.vads_examined
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Iat(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.iat(args.pid, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<18} {:<28} {:<36} {:>18} {:>18}",
                    "PID", "进程", "库", "函数", "IAT", "目标"
                );
                for import in &report.records {
                    let function = import
                        .function
                        .clone()
                        .or_else(|| import.ordinal.map(|ordinal| format!("ordinal:{ordinal}")))
                        .unwrap_or_default();
                    println!(
                        "{:>7} {:<18.18} {:<28.28} {:<36.36} {:#018x} {:#018x}",
                        import.pid,
                        import.process,
                        import.library,
                        function,
                        import.iat_address,
                        import.resolved_target.unwrap_or(0)
                    );
                }
                println!("已检查进程数={}", report.processes_examined);
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::PeSymbols(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.pe_symbols(
                args.source.into(),
                args.pid,
                args.module.as_deref(),
                args.name.as_deref(),
                args.limit,
            )?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<24} {:>8} {:>18} {:<42} 转发目标",
                    "PID", "模块", "序号", "地址", "符号"
                );
                for symbol in &report.records {
                    println!(
                        "{:>7} {:<24.24} {:>8} {:#018x} {:<42.42} {}",
                        symbol.pid.unwrap_or(0),
                        symbol.module,
                        symbol.ordinal,
                        symbol.address.unwrap_or(0),
                        symbol.name.as_deref().unwrap_or(""),
                        symbol.forwarder.as_deref().unwrap_or("")
                    );
                }
                println!("已检查模块数={}", report.modules_examined);
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Pedump(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let base = parse_integer(&args.base)?;
            let report = session.dump_pe(
                args.pid,
                args.kernel_module,
                base,
                &args.output,
                force,
                args.max_output_size,
            )?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("输出文件：{}", report.output.display());
                println!("进程：{}", report.process);
                println!("基址：{:#018x}", report.base);
                println!("SizeOfImage: {:#x}", report.size_of_image);
                println!("输出字节数：{}", report.output_size);
                println!("已恢复字节数：{}", report.recovered_bytes);
                println!("缺失字节数：{}", report.missing_bytes);
                println!("是否完整：{}", yes_no(report.complete));
                for section in &report.sections {
                    println!(
                        "节区 {:<8.8} RVA={:#010x} 原始数据={:#010x}/{:#x} 已恢复={} 缺失={}",
                        section.name,
                        section.virtual_address,
                        section.raw_offset,
                        section.raw_size,
                        section.recovered_bytes,
                        section.missing_bytes
                    );
                }
                for warning in report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(&warning));
                }
            }
        }
        Command::Vad(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.vads(args.pid, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:>18} {:>18} {:>18} 保护属性 文件", "START", "END", "VAD");
                for vad in &report.records {
                    println!(
                        "{:#018x} {:#018x} {:#018x} {:<18} {}",
                        vad.start,
                        vad.end,
                        vad.node,
                        vad.protection_name,
                        vad.file.as_deref().unwrap_or("")
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Vaddump(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.vad_dump(&VadDumpOptions {
                pid: args.pid,
                output: args.output,
                limit: args.limit,
                max_region_size: args.max_region_size,
                max_total_size: args.max_total_size,
                force,
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                for region in &report.regions {
                    let status = if region.skipped {
                        region.skip_reason.as_deref().unwrap_or("已跳过")
                    } else if region.complete {
                        "完整"
                    } else {
                        "缺页（.partial）"
                    };
                    println!(
                        "{:#018x}-{:#018x} {:<18} 逻辑={} 已恢复={} 缺失={} {} {}",
                        region.start,
                        region.end,
                        region.protection_name,
                        region.logical_size,
                        region.recovered_bytes,
                        region.missing_bytes,
                        status,
                        region.output_path.as_deref().unwrap_or("")
                    );
                }
                println!(
                    "PID {} {}：VAD={} 已写出={} 完整={} 缺页={} 已跳过={}",
                    report.pid,
                    report.process,
                    report.vad_count,
                    report.regions_written,
                    report.regions_complete,
                    report.regions_partial,
                    report.regions_skipped
                );
                println!(
                    "逻辑字节={} 已恢复={} 缺失={}；清单：{}",
                    report.total_logical_bytes,
                    report.total_recovered_bytes,
                    report.total_missing_bytes,
                    report.manifest.display()
                );
                print_plugin_footer(report.regions.len(), report.complete, &report.warnings);
            }
        }
        Command::InjectedRegions(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.injected_regions(&InjectedRegionOptions {
                pid: args.pid,
                include_executable: args.include_executable,
                include_partial: args.include_partial,
                vad_limit: args.vad_limit,
                limit: args.limit,
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<16} {:>18} {:>18} {:<14} {:>9} {:>7} 判据",
                    "PID", "进程", "起始", "结束", "VAD 保护", "驻留页", "熵"
                );
                for region in &report.records {
                    println!(
                        "{:>7} {:<16.16} {:#018x} {:#018x} {:<14.14} {:>4}/{:<4} {:>7} {}",
                        region.pid,
                        region.process,
                        region.start,
                        region.end,
                        region.vad_protection_name,
                        region.pages_resident,
                        region.pages_total,
                        region
                            .entropy
                            .map(|value| format!("{value:.2}"))
                            .unwrap_or_else(|| "-".to_owned()),
                        region.signal_names.join(",")
                    );
                    for explanation in &region.explanations {
                        println!("        └ {explanation}");
                    }
                    if let Some(preview) = &region.first_printable {
                        println!("        └ 首个可打印串：{preview}");
                    }
                }
                println!(
                    "已检查进程={} VAD={} 候选私有区间={} 含缺页区间={}",
                    report.processes_examined,
                    report.vads_examined,
                    report.candidate_vads,
                    report.regions_with_missing_pages
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Vadregexscan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let chunk_size = args
                .chunk_mib
                .checked_mul(1024 * 1024)
                .context("VAD 正则扫描块大小超出 usize 范围")?;
            let overlap = args
                .overlap_kib
                .checked_mul(1024)
                .context("VAD 正则扫描重叠大小超出 usize 范围")?;
            let report =
                session.vad_regex(args.pid, &args.pattern, chunk_size, overlap, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<18} {:>18} {:>8} 预览",
                    "PID", "进程", "地址", "长度"
                );
                for matched in &report.records {
                    println!(
                        "{:>7} {:<18.18} {:#018x} {:>8} {}",
                        matched.pid,
                        matched.process,
                        matched.match_address,
                        matched.match_length,
                        matched.preview_hex
                    );
                }
                println!(
                    "进程数={}；VAD 数={}；扫描块数={}；字节数={}；缺失字节数={}",
                    report.processes_examined,
                    report.vads_examined,
                    report.chunks_scanned,
                    report.bytes_examined,
                    report.missing_bytes
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Vadyarascan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let chunk_size = args
                .chunk_mib
                .checked_mul(1024 * 1024)
                .context("VAD YARA 扫描块大小超出 usize 范围")?;
            let overlap = args
                .overlap_kib
                .checked_mul(1024)
                .context("VAD YARA 扫描重叠大小超出 usize 范围")?;
            let report =
                session.vad_yara(args.pid, &args.rules, chunk_size, overlap, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<18} {:<30} {:<16} {:>18} {:>8}",
                    "PID", "进程", "规则", "模式", "地址", "长度"
                );
                for matched in &report.records {
                    println!(
                        "{:>7} {:<18.18} {:<30.30} {:<16.16} {:#018x} {:>8}",
                        matched.pid,
                        matched.process,
                        matched.rule,
                        matched.pattern.as_deref().unwrap_or(""),
                        matched.match_address,
                        matched.match_length
                    );
                }
                println!(
                    "进程数={}；VAD 数={}；扫描块数={}；字节数={}；缺失字节数={}",
                    report.processes_examined,
                    report.vads_examined,
                    report.chunks_scanned,
                    report.bytes_examined,
                    report.missing_bytes
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Svcscan(args) => run_service_view(
            args,
            starmem::windows::service_plugins::ServiceView::Scan,
            cli.json,
        )?,
        Command::Svclist(args) => run_service_view(
            args,
            starmem::windows::service_plugins::ServiceView::List,
            cli.json,
        )?,
        Command::Svcdiff(args) => run_service_view(
            args,
            starmem::windows::service_plugins::ServiceView::Difference,
            cli.json,
        )?,
        Command::ScheduledTasks(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.scheduled_tasks(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:<48} {:<38} {:<32} 作者", "任务路径", "任务ID", "URI");
                for task in &report.records {
                    println!(
                        "{:<48.48} {:<38.38} {:<32.32} {}",
                        task.tree_path,
                        task.task_id.as_deref().unwrap_or(""),
                        task.uri.as_deref().unwrap_or(""),
                        task.author.as_deref().unwrap_or("")
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Autoruns(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.autoruns(&AutorunOptions {
                process_limit: args.process_limit,
                limit: args.limit,
                correlate_service_memory: args.service_memory,
                service_scan_limit: args.service_scan_limit,
                include_task_candidates: args.include_task_candidates,
            })?;
            if cli.json || CSV_OUTPUT.get().is_some() {
                print_json(&report)?;
            } else {
                println!(
                    "{:<28} {:<34} {:<8} {:<6} {:<32} 命令/载荷",
                    "类别", "机制", "范围", "启用", "名称"
                );
                for record in &report.records {
                    println!(
                        "{:<28.28} {:<34.34} {:<8.8} {:<6} {:<32.32} {}",
                        safe_terminal_text(&record.category),
                        safe_terminal_text(&record.mechanism),
                        safe_terminal_text(&record.scope),
                        optional_yes_no(record.enabled),
                        safe_terminal_text(&record.name),
                        safe_terminal_text(record.command.as_deref().unwrap_or("<未恢复>"))
                    );
                    if !record.triage_indicators.is_empty() {
                        println!(
                            "  取证提示：{}",
                            safe_terminal_text(&record.triage_indicators.join(", "))
                        );
                    }
                }
                println!(
                    "检测={}；输出={}；注册表 ASEP={}；自动服务/驱动={}；按需跳过={}；禁用跳过={}；禁用/运行冲突={}；未知启动类型跳过={}；TaskCache 检查={}；候选输出={}；服务内存记录={}",
                    report.records_detected,
                    report.records_emitted,
                    report.registry_entries,
                    report.automatic_services_included,
                    report.manual_services_skipped,
                    report.disabled_services_skipped,
                    report.disabled_runtime_conflicts,
                    report.unknown_start_services_skipped,
                    report.scheduled_tasks_examined,
                    report.scheduled_task_candidates_included,
                    report.service_memory_records
                );
                for source in &report.sources {
                    println!(
                        "  来源 {:<14.14} 可用={} 完整={} Hive={}/{} 缺失字节={} 记录={} 解析警告={}",
                        source.name,
                        yes_no(source.available),
                        yes_no(source.complete),
                        source.hives_parsed,
                        source.hives_examined,
                        source.missing_bytes,
                        source.records,
                        source.parse_warnings
                    );
                }
                println!("范围：{}", safe_terminal_text(&report.scope));
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::RegistryPrintkey(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report =
                session.registry_print_key(&args.hive, &args.key, args.recurse, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:<8} {:<12} {:<48} 名称/数据", "深度", "类型", "键");
                for record in &report.records {
                    let indent = "  ".repeat(record.depth.min(32));
                    let data = record
                        .data
                        .as_ref()
                        .map(|value| serde_json::to_string(value).unwrap_or_default())
                        .unwrap_or_default();
                    println!(
                        "{:<8} {:<12.12} {:<48.48} {}{} {}",
                        record.depth,
                        record.data_type_name.as_deref().unwrap_or(&record.kind),
                        record.path,
                        indent,
                        record.name,
                        data
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Userassist(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.userassist(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:<42} {:>10} {:>10} {:<28} 程序",
                    "GUID", "运行次数", "聚焦次数", "最后执行时间"
                );
                for record in &report.records {
                    println!(
                        "{:<42.42} {:>10} {:>10} {:<28.28} {}",
                        record.guid,
                        record.run_count.unwrap_or(0),
                        record.focus_count.unwrap_or(0),
                        record.last_execution.as_deref().unwrap_or(""),
                        record.decoded_name
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Amcache(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.amcache(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:<9} {:<42} {:<40} 路径", "类型", "SHA1", "产品");
                for record in &report.records {
                    println!(
                        "{:<9.9} {:<42.42} {:<40.40} {}",
                        record.entry_type,
                        record.sha1.as_deref().unwrap_or(""),
                        record.product_name.as_deref().unwrap_or(""),
                        record.path.as_deref().unwrap_or("")
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Shimcachemem(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.shimcache(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:>18} {:<28} {:>8} 路径",
                    "序号", "条目", "最后修改时间", "已执行"
                );
                for record in &report.records {
                    println!(
                        "{:>7} {:#018x} {:<28.28} {:>8} {}",
                        record.order,
                        record.entry,
                        record.last_modified.as_deref().unwrap_or(""),
                        record.executed.map(yes_no).unwrap_or_default(),
                        record.path
                    );
                }
                println!(
                    "扫描模块={:#x}/{}；句柄或旧式 AVL 候选数={}；选中句柄={:#x}；AVL={:#x}；声明条目数={}",
                    report.module_base,
                    report.module_size,
                    report.handle_candidates,
                    report.selected_handle.unwrap_or(0),
                    report.selected_avl_table.unwrap_or(0),
                    report.declared_elements.unwrap_or(0)
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Getcellroutine(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.get_cell_routines(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>18} {:<24} {:>10} HIVE",
                    "CMHIVE", "处理例程", "模块", "可疑"
                );
                for hive in &report.records {
                    println!(
                        "{:#018x} {:#018x} {:<24.24} {:>10} {}",
                        hive.cmhive,
                        hive.handler,
                        hive.module.as_deref().unwrap_or("<未映射>"),
                        yes_no(hive.suspicious),
                        hive.hive_name
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Hashdump(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.hashdump(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                for record in &report.records {
                    println!(
                        "{}:{}:{}:{}:::",
                        record.username, record.rid, record.lm_hash, record.nt_hash
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Cachedump(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.cachedump(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:<24} {:<24} {:<24} 哈希", "用户", "域", "域名");
                for record in &report.records {
                    println!(
                        "{:<24.24} {:<24.24} {:<24.24} {}",
                        record.username, record.domain, record.domain_name, record.hash
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Lsadump(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.lsadump(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:<32} {:<32} 十六进制", "密钥", "UTF16");
                for record in &report.records {
                    println!(
                        "{:<32.32} {:<32.32} {}",
                        record.name,
                        record.utf16.as_deref().unwrap_or(""),
                        record.secret_hex
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Hivescan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.hive_scan(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:>18} {:>10} {:>7} 路径", "CMHIVE", "字节数", "活动");
                for hive in &report.records {
                    println!(
                        "{:#018x} {:>10} {:>7} {}",
                        hive.cmhive,
                        hive.allocation_size,
                        hive.active_list,
                        hive.file_path
                            .as_deref()
                            .or(hive.root_path.as_deref())
                            .unwrap_or("")
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Hivelist(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.hives(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("{:>18} 路径", "CMHIVE");
                for hive in &report.records {
                    let path = if hive.file_path.is_empty() {
                        &hive.root_path
                    } else {
                        &hive.file_path
                    };
                    println!("{:#018x} {}", hive.cmhive, path);
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Handles(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            if let Some(pid) = args.pid {
                let report = session.handles(pid, args.limit)?;
                if cli.json {
                    print_json(&report)?;
                } else {
                    println!("{:>10} {:>18} {:>16} 名称", "句柄", "对象", "类型");
                    for handle in &report.records {
                        println!(
                            "{:#010x} {:#018x} {:>16} {}",
                            handle.handle,
                            handle.object,
                            handle.object_type,
                            handle.name.as_deref().unwrap_or("")
                        );
                    }
                    print_plugin_footer(report.records.len(), report.complete, &report.warnings);
                }
            } else {
                let object = parse_integer(args.object.as_deref().context("缺少 --object")?)?;
                ensure!(args.limit > 0, "句柄结果上限必须大于零");
                let mut report = find_handle_owners(
                    session.image(),
                    session.kernel(),
                    session.profile(),
                    &HashSet::from([object]),
                    args.process_limit,
                    args.handle_scan_limit,
                )?;
                if report.records.len() > args.limit {
                    report.records.truncate(args.limit);
                    report.complete = false;
                    report
                        .warnings
                        .push(format!("对象句柄所有者超过 {} 条结果上限", args.limit));
                }
                if cli.json {
                    print_json(&report)?;
                } else {
                    println!(
                        "{:>8} {:>18} {:>10} {:>16} 用户",
                        "PID", "对象", "句柄", "进程"
                    );
                    for owner in &report.records {
                        println!(
                            "{:>8} {:#018x} {:#010x} {:>16.16} {}",
                            owner.pid,
                            owner.object,
                            owner.handle,
                            owner.process,
                            owner.user_name.as_deref().unwrap_or(""),
                        );
                    }
                    print_plugin_footer(report.records.len(), report.complete, &report.warnings);
                }
            }
        }
        Command::WindowsOpenFiles(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = scan_open_files(
                &session,
                &OpenFileOptions {
                    path_contains: args.path_contains,
                    process_contains: args.process_contains,
                    file_scan_limit: args.file_scan_limit,
                    process_limit: args.process_limit,
                    handle_scan_limit: args.handle_scan_limit,
                    result_limit: args.limit,
                    include_unowned: args.include_unowned,
                },
            )?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>8} {:>16} {:>10} 路径",
                    "FILE_OBJECT", "PID", "进程", "句柄"
                );
                for record in &report.records {
                    println!(
                        "{:#018x} {:>8} {:>16.16} {:>10} {}",
                        record.file_object,
                        record
                            .pid
                            .map_or_else(|| "-".to_owned(), |pid| pid.to_string()),
                        record.process.as_deref().unwrap_or("-"),
                        record
                            .handle
                            .map_or_else(|| "-".to_owned(), |handle| format!("{handle:#x}")),
                        record.path.as_deref().unwrap_or(""),
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Pipescan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.pipes(&PipeScanOptions {
                file_limit: args.file_limit,
                process_limit: args.process_limit,
                handle_scan_limit: args.handle_scan_limit,
                limit: args.limit,
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>8} {:>16} {:>8} 管道",
                    "FILE_OBJECT", "PID", "进程", "句柄"
                );
                for pipe in &report.records {
                    if pipe.owners.is_empty() {
                        println!(
                            "{:#018x} {:>8} {:>16} {:>8} {} [残留池对象]",
                            pipe.file_object, "-", "-", "-", pipe.full_name
                        );
                    } else {
                        for owner in &pipe.owners {
                            println!(
                                "{:#018x} {:>8} {:>16.16} {:#08x} {}",
                                pipe.file_object,
                                owner.pid,
                                owner.process,
                                owner.handle,
                                pipe.full_name
                            );
                        }
                    }
                }
                println!(
                    "\n管道对象={}（活动端点={}，残留={}）；关联句柄={}；检查 FILE_OBJECT={}、设备={}、进程={}、句柄表项={}；耗时={:.3} 秒；是否完整={}",
                    report.named_pipe_objects_found,
                    report.active_endpoint_count,
                    report.residual_endpoint_count,
                    report.correlated_handle_count,
                    report.file_objects_examined,
                    report.device_objects_examined,
                    report.processes_examined,
                    report.handle_entries_examined,
                    report.scan_seconds,
                    yes_no(report.complete),
                );
                println!("范围：{}", report.scope);
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::Prefetchscan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.prefetch(&PrefetchScanOptions {
                file_scan_limit: args.file_scan_limit,
                file_limit: args.limit,
                reference_limit: args.reference_limit,
                max_file_size: args.max_file_size,
                max_uncompressed_size: args.max_uncompressed_size,
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:<30} {:>5} {:>8} {:<30} 最近运行时间",
                    "可执行文件", "版本", "次数", "PF 文件"
                );
                for prefetch in &report.records {
                    println!(
                        "{:<30.30} {:>5} {:>8} {:<30.30} {}",
                        prefetch.executable,
                        prefetch.version,
                        prefetch.run_count,
                        prefetch
                            .path
                            .replace('/', "\\")
                            .rsplit('\\')
                            .next()
                            .unwrap_or(&prefetch.path),
                        prefetch
                            .last_run_times
                            .first()
                            .map(String::as_str)
                            .unwrap_or(""),
                    );
                }
                println!(
                    "\nPrefetch={}；候选={}；尝试={}；重复={}；恢复失败={}；解析失败={}；FILE_OBJECT={}；耗时={:.3} 秒；是否完整={}",
                    report.files_parsed,
                    report.file_candidates_found,
                    report.files_attempted,
                    report.duplicate_records,
                    report.recovery_failures,
                    report.parse_failures,
                    report.file_objects_examined,
                    report.scan_seconds,
                    yes_no(report.complete),
                );
                println!("范围：{}", report.scope);
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::Netscan(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.network(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>5} {:>24} {:>24} {:>8} {:>16} 进程",
                    "协议", "本地端点", "远程端点", "PID", "状态"
                );
                for endpoint in &report.records {
                    let local = format!("{}:{}", endpoint.local_address, endpoint.local_port);
                    let remote = endpoint
                        .remote_port
                        .map(|port| format!("{}:{port}", endpoint.remote_address))
                        .unwrap_or_else(|| endpoint.remote_address.clone());
                    println!(
                        "{:>5} {:>24} {:>24} {:>8} {:>16} {}",
                        endpoint.protocol,
                        local,
                        remote,
                        endpoint.pid,
                        endpoint.state.as_deref().unwrap_or(""),
                        endpoint.process
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Netstat(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.netstat(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>7} {:>24} {:>24} {:>8} {:>16} 进程",
                    "对象", "协议", "本地端点", "远程端点", "PID", "状态"
                );
                for endpoint in &report.records {
                    let local = format!("{}:{}", endpoint.local_address, endpoint.local_port);
                    let remote = endpoint
                        .remote_port
                        .map(|port| format!("{}:{port}", endpoint.remote_address))
                        .unwrap_or_else(|| endpoint.remote_address.clone());
                    println!(
                        "{:#018x} {:>7} {:>24} {:>24} {:>8} {:>16} {}",
                        endpoint.virtual_address,
                        endpoint.protocol,
                        local,
                        remote,
                        endpoint.pid,
                        endpoint.state.as_deref().unwrap_or(""),
                        endpoint.process
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Packetscan(args) => {
            let chunk_size = args
                .chunk_mib
                .checked_mul(1024 * 1024)
                .context("扫描块大小溢出")?;
            eprintln!("[1/6] 正在加载镜像、解析 Windows 内核并准备符号表……");
            let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let mut artifacts = session.packet_scan(
                &PacketScanOptions {
                    limit: args.limit,
                    endpoint_limit: args.endpoint_limit,
                    max_packet_size: args.max_packet_size,
                    max_occurrences: args.max_occurrences,
                    chunk_size,
                },
                |stage| match stage {
                    PacketScanStage::NdisStructures => {
                        eprintln!("[2/6] 正在解析 NDIS 精确符号并遍历 NBL/NB/MDL/PFN……")
                    }
                    PacketScanStage::PhysicalMemory => {
                        eprintln!("[3/6] 正在并行雕刻物理内存中的完整 IPv4/IPv6 TCP、UDP 包……")
                    }
                    PacketScanStage::EndpointTables => {
                        eprintln!("[4/6] 正在遍历 tcpip 端点表……")
                    }
                    PacketScanStage::Correlate => {
                        eprintln!("[5/6] 正在合并证据并按五元组关联 PID、进程和数据方向……")
                    }
                },
            )?;
            if let Some(path) = &args.output {
                eprintln!("[6/6] 正在导出 PCAPNG 并计算文件 SHA-256……");
                artifacts.export_pcapng(path, force)?;
            } else {
                eprintln!("[6/6] 正在生成数据包取证报告……");
            }
            if cli.json {
                print_json(&artifacts.report)?;
            } else {
                print_packet_scan_report(&artifacts.report);
            }
        }
        Command::Mftscan(args) => {
            run_mft_scan(args, starmem::windows::disk_plugins::MftView::All, cli.json)?
        }
        Command::MftAds(args) => run_mft_scan(
            args,
            starmem::windows::disk_plugins::MftView::AlternateDataStreams,
            cli.json,
        )?,
        Command::MftResidentData(args) => run_mft_scan(
            args,
            starmem::windows::disk_plugins::MftView::ResidentData,
            cli.json,
        )?,
        Command::Mftdump(args) => {
            eprintln!("[1/2] 正在读取并校验 MFT FILE 记录及常驻 $DATA……");
            let image = open_memory_image(&args.image)?;
            let physical_address = parse_integer(&args.address)?;
            let (report, bytes) = starmem::windows::disk_plugins::recover_mft_resident_data(
                &image,
                physical_address,
                args.attribute_id,
                args.stream.as_deref(),
                args.max_size,
            )?;
            eprintln!("[2/2] 正在写入恢复文件并核对 SHA-256……");
            OUTPUT_POLICY
                .get()
                .context("输出安全策略尚未初始化")?
                .write_bytes_atomic(&args.output, &bytes)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("输出文件：{}", args.output.display());
                println!("文件名：{}", report.file_name.as_deref().unwrap_or("未知"));
                println!("MFT 记录号：{}", report.record_number);
                println!("MFT 物理地址：{:#018x}", report.mft_physical_address);
                println!("数据物理地址：{:#018x}", report.data_physical_address);
                println!("属性 ID：{}", report.attribute_id);
                println!(
                    "数据流：{}",
                    report.stream_name.as_deref().unwrap_or("$DATA")
                );
                println!("输出字节数：{}", report.output_size);
                println!("缺失字节数：{}", report.missing_bytes);
                println!("是否完整：{}", yes_no(report.complete));
                println!("SHA-256：{}", report.sha256);
            }
        }
        Command::Mbrscan(args) => {
            let image = open_memory_image(args.image)?;
            let report = starmem::windows::disk_plugins::scan_mbr(&image, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>18} {:>10} {:<40} 分区",
                    "物理地址", "磁盘签名", "引导区SHA1"
                );
                for mbr in &report.records {
                    let partitions = mbr
                        .partitions
                        .iter()
                        .map(|partition| {
                            format!(
                                "{}:type={:#04x},lba={},sectors={}",
                                partition.index,
                                partition.partition_type,
                                partition.start_lba,
                                partition.sector_count
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ");
                    println!(
                        "{:#018x} {:#010x} {:<40} {}",
                        mbr.physical_address, mbr.disk_signature, mbr.boot_code_sha1, partitions
                    );
                }
                println!(
                    "扫描：{} 字节，耗时 {:.3} 秒（{:.2} GiB/s）；原始签名数={}",
                    report.bytes_scanned,
                    report.elapsed_seconds,
                    report.gib_per_second,
                    report.raw_signature_hits
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Filescan(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            if probe_linux_memory(&image)? {
                ensure!(
                    args.symbols.profile.is_none() && args.symbols.pdb.is_none(),
                    "Linux filescan 从 Volatility 3 ISF 或严格构建指纹选择 VFS 布局，不接受 Windows --profile/--pdb"
                );
                let session = LinuxAnalysisSession::from_image_with_symbol_store(
                    image,
                    &args.symbols.store.build(),
                )?;
                let report = session.files(args.limit)?;
                if cli.json {
                    print_json(&report)?;
                } else {
                    println!(
                        "{:<12} {:<16} {:>10} {:>8} {:>18} 路径（相对 superblock）",
                        "文件系统", "类型", "大小", "缓存页", "DENTRY"
                    );
                    for file in &report.records {
                        let filesystem =
                            safe_terminal_text(file.filesystem.as_deref().unwrap_or("-"));
                        let size = file
                            .size
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_owned());
                        let path =
                            safe_terminal_text(file.path.as_deref().unwrap_or("<路径未解析>"));
                        let status = if file.path_status == "resolved"
                            && matches!(
                                file.membership_status.as_str(),
                                "validated_link" | "superblock_root"
                            ) {
                            String::new()
                        } else {
                            format!(" [{};{}]", file.path_status, file.membership_status)
                        };
                        println!(
                            "{:<12.12} {:<16.16} {:>10} {:>8} {:#018x} {}",
                            filesystem,
                            file.file_type,
                            size,
                            file.cached_pages
                                .map(|pages| pages.to_string())
                                .unwrap_or_else(|| "-".to_owned()),
                            file.dentry,
                            format_args!("{path}{status}")
                        );
                    }
                    println!("\n内核：{}", report.kernel.banner);
                    println!(
                        "驻留 VFS 记录={}；唯一 inode={}；superblock={}/{}；dentry={}；负 dentry={}；校验异常事件={}",
                        report.records.len(),
                        report.unique_inodes,
                        report.superblocks_walked,
                        report.superblocks_seen,
                        report.dentries_seen,
                        report.negative_dentries,
                        report.invalid_dentries
                    );
                    println!(
                        "是否完整={}；结构是否完整={}；达到上限={}；停止原因={:?}；来源={}；遍历={:.3} 秒",
                        yes_no(report.complete),
                        yes_no(report.structural_complete),
                        yes_no(report.limit_reached),
                        report.stop_reason,
                        report.source,
                        report.traversal_seconds
                    );
                    println!(
                        "告警事件={}；分项={}",
                        report.warning_count,
                        report
                            .warning_counts
                            .iter()
                            .map(|(kind, count)| format!("{kind}={count}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    println!("范围：{}", report.scope);
                    println!("路径语义：{}", report.path_semantics);
                    for warning in &report.warnings {
                        eprintln!(
                            "警告 [{}]{}：{}",
                            warning.kind,
                            warning
                                .address_hex
                                .as_deref()
                                .map(|address| format!(" @{address}"))
                                .unwrap_or_default(),
                            warning.message
                        );
                    }
                }
            } else {
                let session = AnalysisSession::from_image(image, args.symbols.session_options())?;
                print_session_warnings(&session);
                let report = session.files(args.limit)?;
                if cli.json {
                    print_json(&report)?;
                } else {
                    println!("{:>18} {:>18} 名称", "FILE_OBJECT", "物理地址");
                    for file in &report.records {
                        println!(
                            "{:#018x} {:#018x} {}",
                            file.file_object,
                            file.physical_address,
                            file.name.as_deref().unwrap_or("")
                        );
                    }
                    println!(
                        "\n文件数：{}；是否完整={}；标签数={}；物理候选数={}；反向映射数={}；扫描={:.3}秒/{:.2} GiB/s",
                        report.records.len(),
                        yes_no(report.complete),
                        report.pool_tag_hits,
                        report.physical_candidates,
                        report.reverse_mapped_candidates,
                        report.scan_seconds,
                        report.scan_gib_per_second,
                    );
                    for warning in report.warnings {
                        eprintln!("警告：{}", localize_runtime_message(&warning));
                    }
                }
            }
        }
        Command::LinuxPasswd(args) => {
            ensure!(
                args.file_scan_limit > 0,
                "Linux filescan 结果上限必须大于零"
            );
            ensure!(args.max_size > 0, "passwd 页缓存恢复上限必须大于零");
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let image = open_memory_image(&args.image)?;
            ensure!(
                is_supported_linux_physical_image(&image),
                "linux.passwd 仅支持 Linux LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
            );
            let session =
                LinuxAnalysisSession::from_image_with_symbol_store(image, &args.symbols.build())?;
            let report = session.passwd(args.file_scan_limit, args.max_size)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>4} {:<8} {:>18} {:<20} {:>10} {:>10} {:<24} SHELL",
                    "候选", "来源", "DENTRY", "用户名", "UID", "GID", "HOME"
                );
                for (candidate_index, candidate) in report.candidates.iter().enumerate() {
                    let source = match candidate.discovery_source {
                        LinuxPasswdCandidateSource::ValidatedDentry => "VFS",
                        LinuxPasswdCandidateSource::ReversePageCache => "页缓存*",
                    };
                    let dentry = if candidate.filescan_record.dentry == 0 {
                        "-".to_owned()
                    } else {
                        format!("{:#018x}", candidate.filescan_record.dentry)
                    };
                    for fragment in &candidate.fragments {
                        for account in &fragment.parse_report.records {
                            println!(
                                "{:>4} {:<8} {:>18} {:<20.20} {:>10} {:>10} {:<24.24} {}",
                                candidate_index + 1,
                                source,
                                dentry,
                                safe_terminal_text(&account.username),
                                account.uid,
                                account.gid,
                                safe_terminal_text(&account.home_directory),
                                safe_terminal_text(&account.shell)
                            );
                        }
                    }
                }
                println!("\n内核：{}", report.kernel.banner);
                println!("范围：{}", report.scope);
                println!(
                    "匹配记录={}；去重={}；候选={}；已恢复={}；完整候选={}；账户记录={}",
                    report.matched_record_count,
                    report.duplicate_record_count,
                    report.candidate_count,
                    report.recovered_candidate_count,
                    report.complete_candidate_count,
                    report.account_record_count
                );
                println!(
                    "filescan 记录={}；请求上限={}；是否完整={}；结构完整={}；达到上限={}；停止原因={:?}",
                    report.filescan.record_count,
                    report.filescan.requested_limit,
                    yes_no(report.filescan.complete),
                    yes_no(report.filescan.structural_complete),
                    yes_no(report.filescan.limit_reached),
                    report.filescan.stop_reason
                );
                if report.reverse_scan.attempted {
                    println!(
                        "反向页缓存扫描：root: 命中={}；唯一页={}；有效 root 行={}；页缓存锚点={}；内容候选={}；扫描字节={}；截断={}",
                        report.reverse_scan.signature_hit_count,
                        report.reverse_scan.unique_page_count,
                        report.reverse_scan.plausible_root_line_count,
                        report.reverse_scan.page_cache_anchor_count,
                        report.reverse_scan.content_validated_count,
                        report.reverse_scan.bytes_scanned,
                        yes_no(report.reverse_scan.truncated),
                    );
                }
                println!("linux.passwd 是否完整：{}", yes_no(report.complete));
                for (candidate_index, candidate) in report.candidates.iter().enumerate() {
                    let status = match candidate.recovery_status {
                        LinuxPasswdRecoveryStatus::Complete => "完整",
                        LinuxPasswdRecoveryStatus::Partial => "部分",
                        LinuxPasswdRecoveryStatus::Failed => "失败",
                    };
                    let record = &candidate.filescan_record;
                    let recovery = candidate.recovery.as_ref();
                    let (source, path_evidence) = match candidate.discovery_source {
                        LinuxPasswdCandidateSource::ValidatedDentry => ("VFS dentry", "精确路径"),
                        LinuxPasswdCandidateSource::ReversePageCache => {
                            ("反向页缓存", "内容推断，路径未证明")
                        }
                    };
                    eprintln!(
                        "候选 {}：{}；来源={}；路径证据={}；fs={}；superblock={}；inode={}；dentry={}；deleted={}；恢复={}/{} 字节；解析={} 字节；边界丢弃={} 字节",
                        candidate_index + 1,
                        status,
                        source,
                        path_evidence,
                        safe_terminal_text(record.filesystem.as_deref().unwrap_or("-")),
                        record.superblock_hex,
                        record.inode_hex,
                        if record.dentry == 0 {
                            "-"
                        } else {
                            &record.dentry_hex
                        },
                        optional_yes_no(record.deleted),
                        recovery.map(|item| item.recovered_bytes).unwrap_or(0),
                        recovery.map(|item| item.logical_size).unwrap_or(0),
                        candidate.parsed_bytes,
                        candidate.discarded_boundary_bytes
                    );
                    if let Some(evidence) = &candidate.reverse_page_cache_evidence {
                        eprintln!(
                            "  反向证据：物理命中={}；文件偏移={:#x}；struct page={}；mapping={}；page.index={}",
                            evidence.trigger_physical_address_hex,
                            evidence.trigger_file_offset,
                            evidence.struct_page_hex,
                            evidence.mapping_hex,
                            evidence.page_index,
                        );
                    }
                    for fragment in &candidate.fragments {
                        for invalid in &fragment.parse_report.invalid_lines {
                            eprintln!(
                                "警告 [passwd_invalid_line] 候选 {} 文件偏移 {:#x} 片段行 {}：{}；原始={} ",
                                candidate_index + 1,
                                fragment.file_offset,
                                invalid.line_number,
                                invalid.problems.join(","),
                                safe_terminal_text(&invalid.raw_line)
                            );
                        }
                        for warning in &fragment.parse_report.warnings {
                            eprintln!(
                                "警告 [{}] 候选 {} 文件偏移 {:#x} 片段行 {}：{}",
                                warning.kind,
                                candidate_index + 1,
                                fragment.file_offset,
                                warning.line_number,
                                warning.message
                            );
                        }
                    }
                }
                for warning in &report.filescan.warnings {
                    eprintln!(
                        "警告 [filescan:{}]{}：{}",
                        warning.kind,
                        warning
                            .address_hex
                            .as_deref()
                            .map(|address| format!(" @{address}"))
                            .unwrap_or_default(),
                        warning.message
                    );
                }
                for warning in &report.warnings {
                    eprintln!(
                        "警告 [{}]{}：{}",
                        warning.kind,
                        warning
                            .dentry_hex
                            .as_deref()
                            .map(|address| format!(" dentry={address}"))
                            .unwrap_or_default(),
                        warning.message
                    );
                }
            }
        }
        Command::Malfind(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.malfind(args.pid, args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<18} {:>18} {:>18} {:<20} {:>7} 原因",
                    "PID", "进程", "起始地址", "结束地址", "保护属性", "熵"
                );
                for record in &report.records {
                    println!(
                        "{:>7} {:<18.18} {:#018x} {:#018x} {:<20} {:>7.3} {}",
                        record.pid,
                        record.process,
                        record.start,
                        record.end,
                        record.protection,
                        record.entropy.unwrap_or(0.0),
                        record.reasons.join("; ")
                    );
                }
                println!(
                    "已检查进程数={}；已检查 VAD 数={}",
                    report.processes_examined, report.vads_examined
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Cobaltstrikescan(args) => {
            let chunk_size = args
                .chunk_mib
                .checked_mul(1024 * 1024)
                .context("Cobalt Strike VAD 分块大小溢出")?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.cobaltstrikescan(&CobaltStrikeScanOptions {
                pid: args.pid,
                result_limit: args.limit,
                chunk_size,
            })?;
            if cli.json || CSV_OUTPUT.get().is_some() {
                print_json(&report)?;
            } else {
                for record in &report.records {
                    println!(
                        "\n=== PID {} {} · {} · {} ===",
                        record.pid, record.process, record.version_hint, record.confidence,
                    );
                    println!(
                        "进程：PPID={}；EPROCESS={:#018x}；用户={}；会话={}；状态={}；创建时间={}",
                        record
                            .ppid
                            .map_or_else(|| "未知".to_owned(), |value| value.to_string()),
                        record.eprocess,
                        record.process_user.as_deref().unwrap_or("未知"),
                        record
                            .process_session_id
                            .map_or_else(|| "未知".to_owned(), |value| value.to_string()),
                        record.process_state,
                        record.process_create_time.as_deref().unwrap_or("未知"),
                    );
                    println!(
                        "映像：{}",
                        record.process_image_path.as_deref().unwrap_or("未知")
                    );
                    println!(
                        "命令行：{}",
                        record.process_command_line.as_deref().unwrap_or("未知")
                    );
                    println!(
                        "VAD：节点={:#018x}；范围={:#018x}-{:#018x}；大小={}；保护={}；私有={}；映射文件={}",
                        record.vad,
                        record.vad_start,
                        record.vad_end,
                        record.vad_size,
                        record.vad_protection,
                        record.vad_private_memory,
                        record.vad_file.as_deref().unwrap_or("无"),
                    );
                    println!(
                        "配置：地址={:#018x}；XOR={:#04x}；字段={}/{}；最大设置ID={}；完整={}；SHA256={}；副本={}",
                        record.config_address,
                        record.xor_key,
                        record.recognized_field_count,
                        record.field_count,
                        record.max_setting_id,
                        record.complete,
                        record.config_sha256,
                        record.copy_count,
                    );
                    println!(
                        "行为：协议={}；端口={}；休眠={}ms；抖动={}%；管道={}；License={}",
                        record.protocols.join(" + "),
                        record
                            .port
                            .map_or_else(|| "未知".to_owned(), |value| value.to_string()),
                        record
                            .sleep_time_ms
                            .map_or_else(|| "未知".to_owned(), |value| value.to_string()),
                        record
                            .jitter_percent
                            .map_or_else(|| "未知".to_owned(), |value| value.to_string()),
                        record.pipe_name.as_deref().unwrap_or("未知"),
                        record
                            .license_id
                            .map_or_else(|| "未知".to_owned(), |value| value.to_string()),
                    );
                    for endpoint in &record.c2_endpoints {
                        println!("C2：{}", endpoint.url);
                    }
                    for highlight in &record.configuration_highlights {
                        println!("研判：{highlight}");
                    }
                    if let Some(allocator) = &record.process_injection.allocator {
                        println!(
                            "进程注入：allocator={}；execute={}；start_rwx={:?}；use_rwx={:?}；min_alloc={}",
                            allocator,
                            record.process_injection.execute_methods.join(", "),
                            record.process_injection.start_rwx,
                            record.process_injection.use_rwx,
                            record
                                .process_injection
                                .minimum_allocation
                                .map_or_else(|| "未知".to_owned(), |value| value.to_string()),
                        );
                    }
                    if !record.stage_profile.beacon_gate_apis.is_empty()
                        || record.stage_profile.data_store_size.is_some()
                        || record.stage_profile.kill_date.is_some()
                    {
                        println!(
                            "Stage：kill_date={}；data_store={}；BeaconGate={}",
                            record.stage_profile.kill_date.as_deref().unwrap_or("无"),
                            record
                                .stage_profile
                                .data_store_size
                                .map_or_else(|| "未知".to_owned(), |value| value.to_string()),
                            record.stage_profile.beacon_gate_apis.join(", "),
                        );
                    }
                    if !record.profile_preview.is_empty() {
                        println!("Profile 预览：");
                        for line in &record.profile_preview {
                            println!("  {line}");
                        }
                    }
                    println!("全部设置：");
                    for setting in &record.settings {
                        println!(
                            "  [{:>2}] {:<48} {:<5} len={:<5} {}",
                            setting.id,
                            setting.name,
                            setting.value_type,
                            setting.length,
                            setting.value,
                        );
                    }
                }
                println!(
                    "命中配置={}；进程={}；VAD={}（无效跳过={}）；页表警告={}；候选={}/拒绝={}；扫描字节={}；读取失败字节={}",
                    report.records.len(),
                    report.processes_examined,
                    report.vads_examined,
                    report.invalid_vads_skipped,
                    report.page_table_warning_count,
                    report.candidates_examined,
                    report.rejected_candidates,
                    report.bytes_examined,
                    report.missing_bytes,
                );
                if !report.rejected_by_reason.is_empty() {
                    println!("候选淘汰原因：");
                    for (reason, count) in &report.rejected_by_reason {
                        println!("  {count:>6}  {reason}");
                    }
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Hollowprocesses(args) => run_process_image_view(
            args,
            starmem::windows::malware_plugins::ProcessImageView::Hollowing,
            cli.json,
        )?,
        Command::Processghosting(args) => run_process_image_view(
            args,
            starmem::windows::malware_plugins::ProcessImageView::Ghosting,
            cli.json,
        )?,
        Command::Pebmasquerade(args) => run_process_image_view(
            args,
            starmem::windows::malware_plugins::ProcessImageView::PebMasquerade,
            cli.json,
        )?,
        Command::DirectSystemCalls(args) => run_syscall_view(
            args,
            starmem::windows::syscall_plugins::SyscallView::Direct,
            cli.json,
        )?,
        Command::IndirectSystemCalls(args) => run_syscall_view(
            args,
            starmem::windows::syscall_plugins::SyscallView::Indirect,
            cli.json,
        )?,
        Command::UnhookedSystemCalls(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.unhooked_system_calls(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:<32} {:>16} {:>12} 异常数",
                    "FUNCTION", "IMPLEMENTATIONS", "MAJORITY"
                );
                for record in &report.records {
                    println!(
                        "{:<32.32} {:>16} {:>12} {}",
                        record.function,
                        record.implementations,
                        record.majority_processes,
                        record.outliers.join(", ")
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Etwpatch(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.etw_patches(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:<18} {:<14} {:<28} {:>18} 原因",
                    "PID", "进程", "DLL", "函数", "地址"
                );
                for record in &report.records {
                    println!(
                        "{:>7} {:<18.18} {:<14.14} {:<28.28} {:#018x} {}",
                        record.pid,
                        record.process,
                        record.dll,
                        record.function,
                        record.address,
                        record.reasons.join("; ")
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::SkeletonKeyCheck(args) => {
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = session.skeleton_key(args.limit)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:>7} {:>18} {:>18} {:>18} {:>10} 原因",
                    "PID", "CSYSTEM", "INITIALIZE", "DECRYPT", "HOOKED"
                );
                for record in &report.records {
                    println!(
                        "{:>7} {:#018x} {:#018x} {:#018x} {:>10} {}",
                        record.pid,
                        record.csystem,
                        record.initialize,
                        record.decrypt,
                        record.skeleton_key_found,
                        record.reasons.join("; ")
                    );
                }
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
        Command::Dumpfile(args) => {
            ensure!(
                !output_paths_conflict(&args.image, &args.output),
                "恢复文件输出路径不能与输入内存镜像相同：{}",
                args.image.display()
            );
            ensure_csv_does_not_overwrite_input(&args.image)?;
            if let Some(csv_path) = CSV_OUTPUT
                .get()
                .filter(|path| path.as_path() != Path::new("-"))
            {
                ensure!(
                    !output_paths_conflict(csv_path, &args.output),
                    "--csv 报告路径不能与恢复文件输出路径相同：{}",
                    args.output.display()
                );
            }
            let image = open_memory_image(&args.image)?;
            let address = parse_integer(&args.address)?;
            if probe_linux_memory(&image)? {
                ensure!(args.file_scan_limit > 0, "文件扫描结果上限必须大于零");
                ensure!(args.max_size > 0, "页缓存文件恢复上限必须大于零");
                ensure!(
                    address >> 48 == 0xffff && address & 7 == 0,
                    "Linux dentry 必须是规范且按 8 字节对齐的内核虚拟地址"
                );
                if let Some(csv_path) = CSV_OUTPUT
                    .get()
                    .filter(|path| path.as_path() != Path::new("-"))
                {
                    let partial_output =
                        starmem::linux_pagecache::partial_output_path(&args.output)?;
                    ensure!(
                        !output_paths_conflict(csv_path, &partial_output),
                        "--csv 报告路径不能与 Linux 部分恢复路径相同：{}",
                        partial_output.display()
                    );
                }
                ensure!(
                    args.symbols.profile.is_none() && args.symbols.pdb.is_none(),
                    "Linux dumpfile 从 Volatility 3 ISF 或严格构建指纹选择页缓存布局，不接受 Windows --profile/--pdb"
                );
                ensure!(
                    matches!(args.source, DumpSourceArg::Auto),
                    "Linux dumpfile 当前仅支持 --source auto（严格恢复已验证的 page cache）"
                );
                let session = LinuxAnalysisSession::from_image_with_symbol_store(
                    image,
                    &args.symbols.store.build(),
                )?;
                let report = session.dump_file_with_force(
                    address,
                    &args.output,
                    args.max_size,
                    args.file_scan_limit,
                    force,
                )?;
                if cli.json {
                    print_json(&report)?;
                } else {
                    println!(
                        "输出文件：{}",
                        safe_terminal_text(report.output_path.as_deref().unwrap_or("<未发布>"))
                    );
                    println!(
                        "文件路径（相对 superblock）：{}",
                        safe_terminal_text(report.path.as_deref().unwrap_or("<路径未解析>"))
                    );
                    println!(
                        "路径范围={}；路径状态={}；成员关系={}",
                        report.path_scope, report.path_status, report.membership_status
                    );
                    println!(
                        "文件系统={}；superblock={}；ID={}；设备={}；deleted={}",
                        safe_terminal_text(report.filesystem.as_deref().unwrap_or("-")),
                        report.superblock_hex,
                        safe_terminal_text(report.superblock_id.as_deref().unwrap_or("-")),
                        safe_terminal_text(&report.device),
                        optional_yes_no(report.deleted)
                    );
                    println!("DENTRY：{}；INODE：{}", report.dentry_hex, report.inode_hex);
                    println!("恢复来源：{}；页树：{}", report.source, report.tree_kind);
                    println!("范围：{}", report.scope);
                    println!("逻辑字节数：{}", report.logical_size);
                    println!("输出字节数：{}", report.output_size);
                    println!("已恢复字节数：{}", report.recovered_bytes);
                    println!("缺失字节数：{}", report.missing_bytes);
                    println!(
                        "是否完整：{}；页树遍历完整：{}",
                        yes_no(report.complete),
                        yes_no(report.tree_complete)
                    );
                    println!(
                        "已恢复页：{}/{}；数据区间数：{}；缺失区间数：{}",
                        report.pages_recovered,
                        report.expected_pages,
                        report.extents.len(),
                        report.missing_ranges.len()
                    );
                    let sha256_scope = match report.sha256_scope.as_str() {
                        "complete_recovered_file" => "完整恢复文件",
                        "reconstruction_with_zero_filled_reported_missing_ranges" => {
                            "含已报告缺页零占位的重建"
                        }
                        "all_logical_bytes_recovered_but_page_tree_structurally_incomplete" => {
                            "逻辑字节均已恢复，但页树结构遍历不完整"
                        }
                        other => other,
                    };
                    println!("SHA-256：{}（{}）", report.sha256, sha256_scope);
                    if report.missing_bytes > 0 {
                        eprintln!(
                            "警告：输出中的缺失区间是零占位，不属于恢复证据；实际证据范围仅为 extents 中列出的已验证页"
                        );
                    } else if !report.tree_complete {
                        eprintln!(
                            "警告：所有逻辑字节均已恢复，但页树结构告警使本次恢复不能标记为完整"
                        );
                    }
                    for range in report.missing_ranges.iter().take(32) {
                        eprintln!(
                            "缺失区间：文件偏移 {:#x}，长度 {:#x}",
                            range.file_offset, range.length
                        );
                    }
                    if report.missing_ranges.len() > 32 {
                        eprintln!(
                            "警告：另有 {} 个缺失区间未在终端展开；请使用 --json 或 --csv 查看完整报告",
                            report.missing_ranges.len() - 32
                        );
                    }
                    println!("页缓存告警事件：{}", report.warning_count);
                    for warning in &report.warnings {
                        eprintln!(
                            "警告 [{}]{}：{}",
                            warning.kind,
                            warning
                                .address_hex
                                .as_deref()
                                .map(|address| format!(" @{address}"))
                                .unwrap_or_default(),
                            warning.message
                        );
                    }
                    if let Some(selection) = &report.filescan_selection {
                        println!(
                            "filescan 选择链：记录={}；请求上限={}；完整={}；结构完整={}；达到上限={}；停止原因={:?}；告警事件={}",
                            selection.record_count,
                            selection.requested_limit,
                            yes_no(selection.complete),
                            yes_no(selection.structural_complete),
                            yes_no(selection.limit_reached),
                            selection.stop_reason,
                            selection.warning_count
                        );
                        for warning in &selection.warnings {
                            eprintln!(
                                "警告 [filescan:{}]{}：{}",
                                warning.kind,
                                warning
                                    .address_hex
                                    .as_deref()
                                    .map(|address| format!(" @{address}"))
                                    .unwrap_or_default(),
                                warning.message
                            );
                        }
                    }
                }
            } else {
                let session = AnalysisSession::from_image(image, args.symbols.session_options())?;
                print_session_warnings(&session);
                let report = session.recover_file(
                    address,
                    &args.output,
                    args.source.into(),
                    args.max_size,
                    force,
                )?;
                if cli.json {
                    print_json(&report)?;
                } else {
                    println!("输出文件：{}", args.output.display());
                    println!("恢复来源：{}", dump_source_name(report.source));
                    println!("逻辑字节数：{}", report.logical_size);
                    println!("输出字节数：{}", report.output_size);
                    println!("已恢复字节数：{}", report.recovered_bytes);
                    println!("缺失字节数：{}", report.missing_bytes);
                    println!("是否完整：{}", yes_no(report.complete));
                    println!("数据区间数：{}", report.extents.len());
                    if let Some(name) = &report.name {
                        println!("文件名：{name}");
                    }
                    for warning in report.warnings {
                        eprintln!("警告：{}", localize_runtime_message(&warning));
                    }
                }
            }
        }
        Command::SqliteRecover(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let file_object = args.file_object.as_deref().map(parse_integer).transpose()?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = recover_sqlite(
                &session,
                &SqliteRecoverOptions {
                    file_object,
                    path_contains: args.path_contains,
                    output_dir: args.output_dir,
                    source: args.source.into(),
                    include_sidecars: !args.no_sidecars,
                    tables: args.tables,
                    file_scan_limit: args.file_scan_limit,
                    max_size: args.max_size,
                    force,
                },
            )?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("SQLite 主库：{}", report.main.output_path);
                println!("FILE_OBJECT：{:#018x}", report.main.file_object);
                println!(
                    "恢复：{}/{} 字节；缺失={}；SHA-256={}",
                    report.main.recovered_bytes,
                    report.main.logical_size,
                    report.main.missing_bytes,
                    report.main.sha256,
                );
                println!(
                    "页大小={}；声明页数={}；缺页={}；表={}",
                    report
                        .database
                        .page_size
                        .map_or_else(|| "未知".to_owned(), |value| value.to_string()),
                    report
                        .database
                        .declared_page_count
                        .map_or_else(|| "未知".to_owned(), |value| value.to_string()),
                    report
                        .database
                        .missing_page_count
                        .map_or_else(|| "未知".to_owned(), |value| value.to_string()),
                    report.database.tables.len(),
                );
                println!("查询视图：{}", report.database.view_semantic);
                if let Some(error) = &report.database.query_error {
                    eprintln!("SQLite 查询警告：{error}");
                }
                for table in &report.database.tables {
                    println!(
                        "  {} root={} rows={} complete={}",
                        table.name,
                        table.root_page,
                        table.recovered_row_count.map_or_else(
                            || {
                                if table.row_count_attempted {
                                    "未知".to_owned()
                                } else {
                                    "未请求".to_owned()
                                }
                            },
                            |value| value.to_string()
                        ),
                        yes_no(table.query_complete),
                    );
                    if let Some(error) = &table.error {
                        eprintln!("  表 {} 查询警告：{error}", table.name);
                    }
                }
                for sidecar in &report.sidecars {
                    println!(
                        "Sidecar {}：{}；恢复={}/{}；头有效={}",
                        sidecar.kind,
                        sidecar.output_path,
                        sidecar.recovered_bytes,
                        sidecar.logical_size,
                        yes_no(sidecar.details.header_valid),
                    );
                    println!("  语义：{}", sidecar.details.note);
                    for warning in &sidecar.warnings {
                        eprintln!("  Sidecar {} 警告：{warning}", sidecar.kind);
                    }
                }
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::DumpRegistry(args) => {
            run_artifact_export(args, ArtifactSelection::Registry, cli.json, force)?;
        }
        Command::DumpLogs(args) => {
            let timeline_input = args.export.output.join("event-logs");
            let timeline_json = args.export.output.join("event-timeline.json");
            let timeline_csv = args.export.output.join("event-timeline.csv");
            run_artifact_export(args.export, ArtifactSelection::EventLogs, cli.json, force)?;
            if !args.no_timeline {
                let options = EventTimelineOptions {
                    include_all_events: args.all_events,
                    event_limit: args.event_limit,
                };
                match analyze_event_logs(&timeline_input, &options) {
                    Ok(report) => {
                        write_json_file(&timeline_json, &report)?;
                        OUTPUT_POLICY
                            .get()
                            .context("输出安全策略尚未初始化")?
                            .write_file_atomic(&timeline_csv, |file| {
                                write_event_timeline_csv_writer(&report, file)
                            })?;
                        eprintln!(
                            "时间线：从 {} 条记录中提取 {} 条高价值事件；JSON={} CSV={}",
                            report.records_seen,
                            report.events.len(),
                            timeline_json.display(),
                            timeline_csv.display()
                        );
                        for warning in &report.warnings {
                            eprintln!("警告：事件时间线：{warning}");
                        }
                    }
                    Err(error) => {
                        eprintln!("警告：自动生成事件时间线失败：{error:#}");
                    }
                }
            }
        }
        Command::EventTimeline(args) => {
            let options = EventTimelineOptions {
                include_all_events: args.all_events,
                event_limit: args.limit,
            };
            let report = analyze_event_logs(&args.input, &options)?;
            if let Some(path) = &args.output {
                write_json_file(path, &report)?;
            }
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "EVTX 文件：已解析 {}/{}",
                    report.files_parsed, report.files_discovered
                );
                println!(
                    "记录：已读取 {}，已匹配 {}，错误 {}",
                    report.records_seen, report.records_matched, report.record_errors
                );
                for (category, count) in &report.category_counts {
                    println!("  {category}: {count}");
                }
                if let Some(path) = &args.output {
                    println!("JSON 文件：{}", path.display());
                }
                if report.truncated {
                    eprintln!("警告：已达到事件数量上限");
                }
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::WindowsTimeline(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let source_enabled = |source| args.sources.is_empty() || args.sources.contains(&source);
            let options = WindowsTimelineOptions {
                include_processes: source_enabled(WindowsTimelineSourceArg::Process),
                include_threads: source_enabled(WindowsTimelineSourceArg::Thread),
                include_mft: source_enabled(WindowsTimelineSourceArg::Mft),
                include_shimcache: source_enabled(WindowsTimelineSourceArg::Shimcache),
                include_registry: source_enabled(WindowsTimelineSourceArg::Registry),
                include_accessed: args.include_accessed,
                process_limit: args.process_limit,
                thread_limit: args.thread_limit,
                mft_limit: args.mft_limit,
                shimcache_limit: args.shimcache_limit,
                registry_limit: args.registry_limit,
                event_limit: args.limit,
                pid: args.pid,
                from: args.from,
                to: args.to,
                newest_first: args.reverse,
            };
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = analyze_windows_timeline(&session, &options, |stage| match stage {
                WindowsTimelineStage::Processes => {
                    eprintln!("[Windows 时间线] 正在恢复 EPROCESS 创建/退出时间……")
                }
                WindowsTimelineStage::Threads => {
                    eprintln!("[Windows 时间线] 正在恢复 ETHREAD 创建/退出时间……")
                }
                WindowsTimelineStage::Mft => {
                    eprintln!("[Windows 时间线] 正在恢复 MFT SI/FN 文件时间……")
                }
                WindowsTimelineStage::Shimcache => {
                    eprintln!("[Windows 时间线] 正在恢复 Shimcache 修改时间证据……")
                }
                WindowsTimelineStage::Registry => {
                    eprintln!("[Windows 时间线] 正在恢复注册表执行与持久化时间证据……")
                }
                WindowsTimelineStage::Finalize => {
                    eprintln!("[Windows 时间线] 正在过滤、排序并统计事件……")
                }
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                print_windows_timeline(&report);
            }
        }
        Command::WindowsExecution(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let source_enabled = |source| args.sources.is_empty() || args.sources.contains(&source);
            let process_source_selected =
                args.sources.contains(&WindowsExecutionSourceArg::Process);
            let options = WindowsExecutionOptions {
                include_processes: args.include_processes
                    || process_source_selected
                    || (args.aggregate && args.sources.is_empty()),
                include_prefetch: source_enabled(WindowsExecutionSourceArg::Prefetch),
                include_bam_dam: source_enabled(WindowsExecutionSourceArg::BamDam),
                include_userassist: source_enabled(WindowsExecutionSourceArg::Userassist),
                include_shimcache: source_enabled(WindowsExecutionSourceArg::Shimcache),
                include_amcache: source_enabled(WindowsExecutionSourceArg::Amcache),
                exact_only: args.exact_only,
                aggregate: args.aggregate,
                program: args.program,
                user: args.user,
                correlation_window_ms: args.correlation_window_ms,
                latest_per_program: args.latest_per_program,
                file_scan_limit: args.file_scan_limit,
                prefetch_file_limit: args.prefetch_limit,
                reference_limit: args.reference_limit,
                max_prefetch_file_size: args.max_prefetch_file_size,
                max_prefetch_uncompressed_size: args.max_prefetch_uncompressed_size,
                registry_limit: args.registry_limit,
                shimcache_limit: args.shimcache_limit,
                event_limit: args.limit,
                from: args.from,
                to: args.to,
                newest_first: !args.oldest_first,
            };
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = analyze_windows_execution(&session, &options, |stage| match stage {
                WindowsExecutionStage::Prefetch => {
                    eprintln!("[Windows 执行证据] 正在恢复并解析 Prefetch……")
                }
                WindowsExecutionStage::RegistryAndShimcache => {
                    eprintln!("[Windows 执行证据] 正在恢复注册表与 Shimcache 证据……")
                }
                WindowsExecutionStage::Finalize => {
                    eprintln!("[Windows 执行证据] 正在统一时间语义并排序……")
                }
            })?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:<30} {:<12} {:<7} {:<28} 路径",
                    "UTC 时间", "来源", "精确", "可执行文件"
                );
                for event in &report.events {
                    println!(
                        "{:<30.30} {:<12.12} {:<7} {:<28.28} {}",
                        event.timestamp,
                        event.artifact,
                        yes_no(event.exact_execution_time),
                        event.executable,
                        event.path.as_deref().unwrap_or(""),
                    );
                }
                if !report.episodes.is_empty() {
                    println!("\n执行 Episode：");
                    println!(
                        "{:<30} {:>7} {:>8} {:<24} 程序",
                        "规范时间", "PID", "证据", "用户"
                    );
                    for episode in &report.episodes {
                        println!(
                            "{:<30.30} {:>7} {:>8} {:<24.24} {}",
                            episode.canonical_timestamp,
                            episode
                                .pid
                                .map_or_else(|| "-".to_owned(), |pid| pid.to_string()),
                            episode.evidence_count,
                            episode
                                .user
                                .as_deref()
                                .or(episode.user_sid.as_deref())
                                .unwrap_or("未知"),
                            episode.program,
                        );
                    }
                }
                println!(
                    "\n匹配事件={}；保留={}；Episode={}（精确执行时间={}，上下文={}，异常时间={}）；是否截断={}；是否完整={}",
                    report.matched_events,
                    report.events.len(),
                    report.episodes.len(),
                    report.exact_execution_events,
                    report.contextual_events,
                    report.outlier_events_matched,
                    yes_no(report.truncated),
                    yes_no(report.complete),
                );
                println!(
                    "分来源：{}",
                    report
                        .artifact_counts
                        .iter()
                        .map(|(source, count)| format!("{source}={count}"))
                        .collect::<Vec<_>>()
                        .join("；")
                );
                println!("范围：{}", report.scope);
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::WindowsRecentFiles(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let source_enabled = |source| args.sources.is_empty() || args.sources.contains(&source);
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let report = analyze_windows_recent_files(
                &session,
                &WindowsRecentFilesOptions {
                    include_wps: source_enabled(WindowsRecentFilesSourceArg::Wps),
                    include_recentdocs: source_enabled(WindowsRecentFilesSourceArg::Recentdocs),
                    user: args.user,
                    path_contains: args.path_contains,
                    hive_limit: args.hive_limit,
                    registry_limit: args.registry_limit,
                    record_limit: args.limit,
                },
                |stage| match stage {
                    WindowsRecentFilesStage::Hives => {
                        eprintln!("[Windows 最近文件] 正在定位用户 NTUSER.DAT Hive……")
                    }
                    WindowsRecentFilesStage::Wps => {
                        eprintln!("[Windows 最近文件] 正在解析 WPS RecentFiles Sequence……")
                    }
                    WindowsRecentFilesStage::RecentDocs => {
                        eprintln!("[Windows 最近文件] 正在解析 Explorer RecentDocs MRU……")
                    }
                    WindowsRecentFilesStage::Finalize => {
                        eprintln!("[Windows 最近文件] 正在归一路径、时间语义与证据顺序……")
                    }
                },
            )?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:<24} {:<12} {:<12} {:<8} 路径",
                    "UTC 时间", "来源", "用户", "MRU"
                );
                for record in &report.records {
                    println!(
                        "{:<24.24} {:<12.12} {:<12.12} {:<8} {}",
                        record.timestamp_utc.as_deref().unwrap_or("无独立时间"),
                        record.source,
                        record
                            .user_name
                            .as_deref()
                            .or(record.user_sid.as_deref())
                            .unwrap_or("未知"),
                        record
                            .mru_rank
                            .map_or_else(|| "-".to_owned(), |rank| rank.to_string()),
                        record.path,
                    );
                }
                println!(
                    "\n匹配={}；保留={}；是否截断={}；是否完整={}",
                    report.matched_records,
                    report.records.len(),
                    yes_no(report.truncated),
                    yes_no(report.complete),
                );
                for warning in &report.warnings {
                    eprintln!("警告：{}", localize_runtime_message(warning));
                }
            }
        }
        Command::UsbHistory(args) => {
            ensure_csv_does_not_overwrite_input(&args.image)?;
            let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
            print_session_warnings(&session);
            let processes = session.processes(args.process_limit)?;
            let process_complete = processes.complete;
            let process_warnings = processes
                .warnings
                .iter()
                .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
                .collect::<Vec<_>>();
            let (registry, system_hive) = analyze_registry_with_system_hive(&session, &processes);
            let mut report = analyze_usb_history(
                &registry,
                system_hive.as_ref(),
                &UsbHistoryOptions {
                    serial: args.serial,
                    container_id: args.container_id,
                    storage_only: !args.include_non_storage,
                    allow_last_write_proxy: !args.strict_last_arrival,
                    limit: args.limit,
                },
            )?;
            report.complete &= process_complete && process_warnings.is_empty();
            for warning in process_warnings {
                if report.warnings.len() < USB_HISTORY_WARNING_LIMIT {
                    report.warnings.push(warning);
                } else if report.warnings.len() == USB_HISTORY_WARNING_LIMIT {
                    report.warnings.push(format!(
                        "USB history warnings reached {USB_HISTORY_WARNING_LIMIT}; additional warnings were suppressed"
                    ));
                }
            }
            report.warnings_truncated = report.warnings.len() > USB_HISTORY_WARNING_LIMIT;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "{:<24} {:<18} {:<20} {:<8} 设备",
                    "最后连接 UTC", "序列号", "VID/产品", "代理"
                );
                for device in &report.records {
                    let selected = device.selected_last_connected.as_ref();
                    println!(
                        "{:<24.24} {:<18.18} {:<20.20} {:<8} {}",
                        selected
                            .and_then(|selected| selected.timestamp.utc.as_deref())
                            .unwrap_or("未知"),
                        device.serial.as_deref().unwrap_or("未知"),
                        [device.vendor.as_deref(), device.product.as_deref()]
                            .into_iter()
                            .flatten()
                            .collect::<Vec<_>>()
                            .join(" "),
                        selected
                            .map(|selected| yes_no(selected.proxy))
                            .unwrap_or("-"),
                        device.friendly_name.as_deref().unwrap_or("未知 USB 设备"),
                    );
                    if let Some(selected) = selected {
                        println!(
                            "  本地时间：{}",
                            selected.timestamp.image_local.as_deref().unwrap_or("未知")
                        );
                        println!("  选择依据：{}", selected.reason);
                    }
                }
                println!(
                    "接口扫描={}；属性节点={}（每接口上限={}）；属性扫描截断={}；输出截断={}",
                    report.interfaces_examined,
                    report.property_nodes_examined,
                    report.property_node_limit_per_interface,
                    yes_no(report.property_scan_truncated),
                    yes_no(report.output_truncated),
                );
                print_plugin_footer(report.records.len(), report.complete, &report.warnings);
            }
        }
    }
    Ok(())
}

fn run_artifact_export(
    args: ArtifactExportArgs,
    selection: ArtifactSelection,
    json: bool,
    force: bool,
) -> Result<()> {
    let session = AnalysisSession::open(&args.image, args.symbols.session_options())?;
    print_session_warnings(&session);
    let options = ArtifactExportOptions {
        selection,
        file_scan_limit: args.file_scan_limit,
        artifact_limit: args.artifact_limit,
        max_file_size: args.max_file_size,
        force,
    };
    let report = export_artifacts(&session, &args.output, &options)?;
    if json {
        print_json(&report)?;
    } else {
        println!("输出目录：{}", report.output_directory);
        println!("filescan 记录数：{}", report.file_scan_records);
        println!("已加载 Hive 候选数：{}", report.loaded_hive_candidates);
        println!("已恢复的已加载 Hive 数：{}", report.loaded_hives_recovered);
        println!("候选文件数：{}", report.candidates);
        println!("已尝试数：{}", report.attempted);
        println!("已恢复数：{}", report.recovered);
        println!("完整文件数：{}", report.complete_files);
        println!("部分文件数：{}", report.partial_files);
        println!("签名有效数：{}", report.signature_valid_files);
        println!("签名无效数：{}", report.signature_invalid_files);
        println!("签名未检查数：{}", report.signature_unchecked_files);
        println!("不可用数：{}", report.unavailable);
        println!("失败数：{}", report.failed);
        println!("清单：{}\\export-report.json", report.output_directory);
        if report.truncated {
            eprintln!("警告：已达到取证文件数量上限");
        }
        for warning in report.warnings {
            eprintln!("警告：{}", localize_runtime_message(&warning));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ThreadView {
    All,
    Suspended,
    Suspicious,
    OrphanKernel,
}

fn run_thread_view(args: PluginArgs, view: ThreadView, json: bool) -> Result<()> {
    let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
    print_session_warnings(&session);
    let mut report = session.threads(args.limit)?;
    report.records.retain(|thread| match view {
        ThreadView::All => true,
        ThreadView::Suspended => {
            thread.suspend_count.unwrap_or(0) > 0
                || thread.freeze_count.unwrap_or(0) > 0
                || matches!(thread.wait_reason, Some(5 | 12))
        }
        ThreadView::Suspicious => !thread.suspicious_reasons.is_empty(),
        ThreadView::OrphanKernel => thread
            .suspicious_reasons
            .iter()
            .any(|reason| reason == "kernel start address is outside loaded modules"),
    });
    if json {
        print_json(&report)?;
    } else {
        print_thread_table(&report.records);
        print_plugin_footer(report.records.len(), report.complete, &report.warnings);
    }
    Ok(())
}

fn run_process_image_view(
    args: PluginArgs,
    view: starmem::windows::malware_plugins::ProcessImageView,
    json: bool,
) -> Result<()> {
    let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
    print_session_warnings(&session);
    let report = session.process_image_anomalies(view, args.limit)?;
    if json {
        print_json(&report)?;
    } else {
        println!(
            "{:>7} {:<18} {:>18} {:>18} {:<36} 原因",
            "PID", "进程", "映像基址", "节区基址", "映像文件"
        );
        for process in &report.records {
            println!(
                "{:>7} {:<18.18} {:#018x} {:#018x} {:<36.36} {}",
                process.pid,
                process.process,
                process.image_base.unwrap_or(0),
                process.section_base.unwrap_or(0),
                process
                    .kernel_image_file
                    .as_deref()
                    .or(process.image_vad_file.as_deref())
                    .unwrap_or(""),
                process.reasons.join("; ")
            );
        }
        println!("已检查进程数：{}", report.processes_examined);
        print_plugin_footer(report.records.len(), report.complete, &report.warnings);
    }
    Ok(())
}

fn run_service_view(
    args: ServiceArgs,
    view: starmem::windows::service_plugins::ServiceView,
    json: bool,
) -> Result<()> {
    let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
    print_session_warnings(&session);
    let report = session.services(view, args.limit, args.registry)?;
    if json {
        print_json(&report)?;
    } else {
        println!(
            "{:>18} {:>6} {:>7} {:<22} {:<24} {:<28} 名称",
            "记录", "顺序", "PID", "起始地址", "状态", "类型"
        );
        for service in &report.records {
            println!(
                "{:#018x} {:>6} {:>7} {:<22.22} {:<24.24} {:<28.28} {}",
                service.address,
                service.order,
                service.pid.unwrap_or(0),
                service.start_name,
                service.state_name,
                service.type_names.join("|"),
                service.name
            );
            if let Some(display) = &service.display_name {
                println!("  显示名称：{display}");
            }
            if let Some(binary) = service
                .binary_path_memory
                .as_deref()
                .or(service.binary_path_registry.as_deref())
            {
                println!("  可执行文件：{binary}");
            }
        }
        println!(
            "services.exe PID={:?}；VAD 数={}；字节数={}；缺失字节数={}；未映射 VAD 字节数={}；serH={}；映像锚点候选={}；扫描记录数={}；链表记录数={}；恢复方式={}；{:.3}秒/{:.2} GiB/s",
            report.services_pids,
            report.vads_examined,
            report.bytes_examined,
            report.missing_bytes,
            report.unmapped_vad_bytes,
            report.scan_header_candidates,
            report.list_anchor_candidates,
            report.structurally_valid_scan_records,
            report.structurally_valid_list_records,
            report.list_recovery,
            report.elapsed_seconds,
            report.gib_per_second,
        );
        print_plugin_footer(report.records.len(), report.complete, &report.warnings);
    }
    Ok(())
}

fn run_syscall_view(
    args: PluginArgs,
    view: starmem::windows::syscall_plugins::SyscallView,
    json: bool,
) -> Result<()> {
    let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
    print_session_warnings(&session);
    let report = session.system_calls(view, args.limit)?;
    if json {
        print_json(&report)?;
    } else {
        println!(
            "{:>7} {:<18} {:>18} {:>18} {:<36} 证据",
            "PID", "进程", "代码块", "指令", "范围"
        );
        for record in &report.records {
            println!(
                "{:>7} {:<18.18} {:#018x} {:#018x} {:<36.36} {}",
                record.pid,
                record.process,
                record.block_address,
                record.instruction_address,
                record.range.as_deref().unwrap_or(""),
                record.evidence
            );
        }
        println!(
            "进程数={}；VAD 数={}；字节数={}；缺失字节数={}",
            report.processes_examined,
            report.vads_examined,
            report.bytes_examined,
            report.missing_bytes
        );
        print_plugin_footer(report.records.len(), report.complete, &report.warnings);
    }
    Ok(())
}

fn run_mft_scan(
    args: DiskScanArgs,
    view: starmem::windows::disk_plugins::MftView,
    json: bool,
) -> Result<()> {
    eprintln!("[1/2] 正在并行扫描并验证 NTFS MFT FILE 记录……");
    let image = open_memory_image(args.image)?;
    let report = starmem::windows::disk_plugins::scan_mft(&image, view, args.limit)?;
    eprintln!("[2/2] 正在整理 MFT 名称、时间戳和 $DATA 属性……");
    if json {
        print_json(&report)?;
    } else {
        println!(
            "{:>18} {:>10} {:>6} {:>5} {:<48} 数据",
            "物理地址", "记录", "序号", "标志", "名称"
        );
        for record in &report.records {
            let names = record
                .file_names
                .iter()
                .map(|name| name.name.as_str())
                .collect::<Vec<_>>()
                .join(" | ");
            let data = record
                .data_attributes
                .iter()
                .map(|data| {
                    format!(
                        "{}:{}:{}",
                        data.name.as_deref().unwrap_or("$DATA"),
                        if data.resident { "常驻" } else { "非常驻" },
                        data.data_size
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            println!(
                "{:#018x} {:>10} {:>6} {:#05x} {:<48.48} {}",
                record.physical_address,
                record.record_number,
                record.sequence_number,
                record.flags,
                names,
                data
            );
        }
        println!(
            "扫描：{} 字节，耗时 {:.3} 秒（{:.2} GiB/s）；原始签名数={}；已验证={}",
            report.bytes_scanned,
            report.elapsed_seconds,
            report.gib_per_second,
            report.raw_signature_hits,
            report.validated_records
        );
        print_plugin_footer(report.records.len(), report.complete, &report.warnings);
    }
    Ok(())
}

fn run_windowstations_plugin(args: PluginArgs, json: bool) -> Result<()> {
    let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
    print_session_warnings(&session);
    let report = session.window_stations(args.limit)?;
    if json {
        print_json(&report)?;
    } else {
        println!("{:>18} {:>7} {:<32} 来源", "偏移", "会话", "名称");
        for station in &report.records {
            println!(
                "{:#018x} {:>7} {:<32.32} {}",
                station.address,
                station.session_id,
                station.name,
                if station.pool_scanned {
                    "pool+list"
                } else {
                    "list"
                }
            );
        }
        println!(
            "扫描：{} 字节，耗时 {:.3} 秒；原始标签数={}；池候选数={}；会话地址空间数={}",
            report.bytes_scanned,
            report.scan_seconds,
            report.raw_tag_hits,
            report.pool_candidates,
            report.session_spaces_examined
        );
        print_plugin_footer(report.records.len(), report.complete, &report.warnings);
    }
    Ok(())
}

fn run_desktop_plugin(args: PluginArgs, pool_scanned: bool, json: bool) -> Result<()> {
    let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
    print_session_warnings(&session);
    let report = session.desktops(args.limit, pool_scanned)?;
    if json {
        print_json(&report)?;
    } else {
        println!(
            "{:>18} {:>7} {:<20} {:<24} 线程归属",
            "偏移", "会话", "窗口站", "桌面"
        );
        for desktop in &report.records {
            let owners = desktop
                .thread_owners
                .iter()
                .map(|owner| format!("{}({})", owner.process, owner.pid))
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "{:#018x} {:>7} {:<20.20} {:<24.24} {}",
                desktop.address,
                desktop.session_id,
                desktop.window_station_name,
                desktop.name,
                owners
            );
        }
        println!(
            "扫描：{} 字节，耗时 {:.3} 秒；原始标签数={}；池候选数={}；会话地址空间数={}",
            report.bytes_scanned,
            report.scan_seconds,
            report.raw_tag_hits,
            report.pool_candidates,
            report.session_spaces_examined
        );
        print_plugin_footer(report.records.len(), report.complete, &report.warnings);
    }
    Ok(())
}

fn run_windows_plugin(args: PluginArgs, json: bool) -> Result<()> {
    let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
    print_session_warnings(&session);
    let report = session.windows(args.limit)?;
    if json {
        print_json(&report)?;
    } else {
        println!(
            "{:>18} {:>7} {:<18} {:<18} {:>7} {:<18} 标题",
            "偏移", "会话", "窗口站", "桌面", "PID", "进程"
        );
        for window in &report.records {
            println!(
                "{:#018x} {:>7} {:<18.18} {:<18.18} {:>7} {:<18.18} {}",
                window.address,
                window.session_id,
                window.window_station,
                window.desktop,
                window.pid.unwrap_or(0),
                window.process.as_deref().unwrap_or(""),
                window.title.as_deref().unwrap_or("")
            );
        }
        println!(
            "扫描：{} 字节，耗时 {:.3} 秒；原始标签数={}；池候选数={}；会话地址空间数={}",
            report.bytes_scanned,
            report.scan_seconds,
            report.raw_tag_hits,
            report.pool_candidates,
            report.session_spaces_examined
        );
        print_plugin_footer(report.records.len(), report.complete, &report.warnings);
    }
    Ok(())
}

fn run_window_titles_plugin(args: PluginArgs, json: bool) -> Result<()> {
    let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
    print_session_warnings(&session);
    let report = session.window_titles(args.limit)?;
    if json {
        print_json(&report)?;
    } else {
        for window in &report.records {
            println!("窗口标题：{}", window.title.replace('\n', "\n  "));
            println!(
                "  进程={} PID={} 会话={} 窗口站={} 桌面={}",
                window.process.as_deref().unwrap_or("未关联"),
                window.pid.unwrap_or(0),
                window.session_id,
                window.window_station,
                window.desktop,
            );
            println!(
                "  窗口={:#018x} 层级={} 有标题父窗口={} 重复标题={} 父标题={}",
                window.address,
                window.depth,
                yes_no(window.has_titled_parent),
                window.duplicate_title_count,
                window.parent_title.as_deref().unwrap_or("无"),
            );
        }
        println!(
            "扫描：{} 字节，耗时 {:.3} 秒；恢复窗口标题={}；会话地址空间数={}",
            report.bytes_scanned,
            report.scan_seconds,
            report.records.len(),
            report.session_spaces_examined,
        );
        print_plugin_footer(report.records.len(), report.complete, &report.warnings);
    }
    Ok(())
}

fn run_screen_resolution_plugin(args: PluginArgs, json: bool) -> Result<()> {
    let session = AnalysisSession::open(args.image, args.symbols.session_options())?;
    print_session_warnings(&session);
    let report = session.screen_resolutions(args.limit)?;
    if json {
        print_json(&report)?;
    } else if report.records.is_empty() {
        println!("没有恢复到通过验证的显示器级分辨率证据。");
        print_plugin_footer(0, report.complete, &report.warnings);
    } else {
        for resolution in &report.records {
            println!(
                "{}{}（{}，宽高比 {:.3}:1）",
                resolution.resolution,
                if resolution.likely_primary {
                    " [主显示候选]"
                } else {
                    " [附加候选]"
                },
                match resolution.orientation {
                    "landscape" => "横屏",
                    "portrait" => "竖屏",
                    _ => "正方形",
                },
                resolution.aspect_ratio,
            );
            if resolution.surface_count > 0 {
                println!(
                    "  DWM PID={}；已验证表面={}；来源={}",
                    resolution
                        .dwm_pids
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                    resolution.surface_count,
                    resolution.sources.join(","),
                );
            } else {
                println!(
                    "  注册表配置值对={}；来源={}；置信度={}",
                    resolution.registry_value_pairs,
                    resolution.sources.join(","),
                    resolution.confidence,
                );
            }
            println!(
                "  证据地址={}",
                resolution
                    .evidence_addresses
                    .iter()
                    .map(|address| format!("{address:#018x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if report.surface_objects_examined > 0 {
            println!(
                "DWM 进程={}；检查表面对象={}",
                report.processes_examined, report.surface_objects_examined
            );
        }
        print_plugin_footer(report.records.len(), report.complete, &report.warnings);
    }
    Ok(())
}

fn print_thread_table(records: &[starmem::windows::process_plugins::ThreadRecord]) {
    println!(
        "{:>7} {:>7} {:>18} {:<18} {:>18} {:>12} {:>7} 原因",
        "PID", "TID", "ETHREAD", "进程", "起始地址", "状态", "挂起数"
    );
    for thread in records {
        println!(
            "{:>7} {:>7} {:#018x} {:<18.18} {:#018x} {:>12} {:>7} {}",
            thread.pid,
            thread.tid,
            thread.ethread,
            thread.process,
            thread.start_address.unwrap_or(0),
            localize_thread_state(&thread.state_name),
            thread.suspend_count.unwrap_or(0),
            thread.suspicious_reasons.join("; ")
        );
    }
}

fn print_session_warnings(session: &AnalysisSession) {
    for warning in session.warnings() {
        eprintln!("警告：{}", localize_runtime_message(warning));
    }
}

fn print_linux_kernel_session_evidence(evidence: &LinuxKernelSessionEvidence) {
    println!("Linux 内核：{}", safe_terminal_text(&evidence.banner));
    println!(
        "DTB={:#018x}（{}）；KASLR slide={:#x}（{}）",
        evidence.directory_table_base,
        evidence.page_table_source,
        evidence.kernel_slide,
        evidence.kernel_slide_source,
    );
    println!(
        "符号身份：{}；features={}；本地候选={}",
        evidence.symbol_identity.canonical_sha256,
        evidence
            .requested_features
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        evidence.symbol_files_considered,
    );
    println!(
        "锚点扫描：{} 字节，{:.3} 秒/{:.2} GiB/s",
        evidence.bytes_scanned, evidence.scan_seconds, evidence.scan_gib_per_second,
    );
    for warning in &evidence.symbol_warnings {
        eprintln!("符号警告 [{}]：{}", warning.kind, warning.message);
    }
    println!();
}

fn print_linux_evidence_footer(
    count: usize,
    available: bool,
    complete: bool,
    warnings: &[EvidenceWarning],
) {
    println!(
        "\n记录数：{count}；证据源可用：{}；搜索宇宙完整：{}",
        yes_no(available),
        yes_no(complete),
    );
    for warning in warnings {
        eprintln!(
            "警告 [{}/{:?}]：{}",
            warning.code,
            warning.severity,
            safe_terminal_text(&warning.message),
        );
    }
}

fn print_plugin_footer(count: usize, complete: bool, warnings: &[String]) {
    println!("\n记录数：{count}；是否完整：{}", yes_no(complete));
    for warning in warnings {
        eprintln!("警告：{}", localize_runtime_message(warning));
    }
}

fn print_packet_scan_report(report: &starmem::packet_scan::PacketScanReport) {
    if report.records.is_empty() {
        println!("没有恢复出通过严格校验的完整 IP 数据包。");
    } else {
        println!("已恢复的数据包：");
    }
    for packet in &report.records {
        let network = match packet.internet_protocol {
            InternetProtocol::Ipv4 => "IPv4",
            InternetProtocol::Ipv6 => "IPv6",
        };
        let transport = match packet.transport_protocol {
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Udp => "UDP",
        };
        let source = format_packet_endpoint(&packet.source_address, packet.source_port);
        let destination =
            format_packet_endpoint(&packet.destination_address, packet.destination_port);
        println!(
            "#{:06} {}/{} {} -> {}；长度={}；载荷={}；置信度={}",
            packet.index,
            network,
            transport,
            source,
            destination,
            packet.packet_length,
            packet.payload_length,
            localize_packet_confidence(&packet.confidence),
        );
        println!(
            "  校验和：IP={}，传输层={}；TCP 标志={}",
            localize_packet_checksum(&packet.ip_checksum),
            localize_packet_checksum(&packet.transport_checksum),
            packet.tcp_flags.as_deref().unwrap_or("不适用"),
        );
        if packet.owners.is_empty() {
            println!("  进程关联：未证明");
        } else {
            println!(
                "  进程关联：{}",
                packet
                    .owners
                    .iter()
                    .map(|owner| format!(
                        "{}({})/{}[{}]",
                        owner.process,
                        owner.pid,
                        match owner.direction.as_str() {
                            "outbound" => "出站",
                            "inbound" => "入站",
                            _ => "方向未知",
                        },
                        localize_packet_confidence(&owner.confidence),
                    ))
                    .collect::<Vec<_>>()
                    .join("、")
            );
        }
        println!(
            "  物理地址：{}；出现={}次；SHA-256={}",
            packet
                .physical_addresses
                .iter()
                .map(|address| format!("{address:#018x}"))
                .collect::<Vec<_>>()
                .join("、"),
            packet.occurrences,
            packet.sha256,
        );
        if let Some(evidence) = packet.ndis_evidence.first() {
            println!(
                "  NDIS 证据：NBL={:#018x}，NB={:#018x}，MDL={:#018x}，PFN={}页，跨页={}；来源={}",
                evidence.net_buffer_list,
                evidence.net_buffer,
                evidence.current_mdl,
                evidence.page_frame_numbers.len(),
                yes_no(evidence.crosses_physical_pages),
                packet.recovery_sources.join("、"),
            );
        }
    }
    println!(
        "\n唯一数据包={}；有效出现={}；重复出现={}；NDIS 结构包={}次（跨页={}，结构独有={}）；已排除零校验和候选={}/{}次；端点记录={}；进程关联={}；NDIS={:.3}秒；物理扫描={:.3}秒/{:.2} GiB/s；结果完整={}；NDIS 完整={}；端点关联完整={}",
        report.statistics.unique_packets,
        report.statistics.validated_occurrences,
        report.statistics.duplicate_occurrences,
        report.statistics.ndis_packet_occurrences,
        report.statistics.ndis_cross_page_occurrences,
        report.statistics.ndis_only_packets,
        report.statistics.rejected_offload_candidates,
        report.statistics.rejected_offload_occurrences,
        report.statistics.endpoint_records,
        report.statistics.owner_associations,
        report.timing.ndis_scan_seconds,
        report.timing.packet_scan_seconds,
        report.timing.scan_gib_per_second,
        yes_no(report.complete),
        yes_no(report.ndis_structure_complete),
        yes_no(report.endpoint_correlation_complete),
    );
    if let Some(key) = &report.ndis_pdb_key {
        println!(
            "NDIS：PDB={}；pool={}；分配={}；NET_BUFFER={}",
            key,
            report.statistics.ndis_pools_examined,
            report.statistics.ndis_allocations_examined,
            report.statistics.ndis_net_buffers_examined,
        );
        if !report.statistics.ndis_rejections.is_empty() {
            println!(
                "NDIS 未接受候选：{}",
                report
                    .statistics
                    .ndis_rejections
                    .iter()
                    .map(|(reason, count)| {
                        format!("{}={count}", localize_ndis_rejection(reason))
                    })
                    .collect::<Vec<_>>()
                    .join("；")
            );
        }
    }
    if let Some(export) = &report.export {
        println!(
            "PCAPNG：{}（{} 包，{} 字节）\nPCAPNG SHA-256：{}",
            export.output_path, export.packet_count, export.output_bytes, export.sha256,
        );
    }
    for warning in &report.warnings {
        eprintln!("警告：{}", localize_runtime_message(warning));
    }
}

fn format_packet_endpoint(address: &str, port: u16) -> String {
    if address.contains(':') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

fn localize_packet_checksum(value: &str) -> &'static str {
    match value {
        "valid" => "有效",
        "zero_or_offloaded" => "零值/硬件卸载候选",
        "invalid_or_offloaded" => "未完成/硬件卸载候选",
        "not_applicable" => "不适用",
        _ => "未知",
    }
}

fn localize_packet_confidence(value: &str) -> &'static str {
    match value {
        "high" => "高",
        "medium" => "中",
        "low" => "低",
        _ => "未知",
    }
}

fn localize_ndis_rejection(value: &str) -> &'static str {
    match value {
        "net_buffer_fields_unreadable" => "NET_BUFFER 字段不可读",
        "net_buffer_fields_invalid" => "NET_BUFFER 字段无效",
        "net_buffer_data_length_invalid" => "数据长度无效",
        "net_buffer_mdl_pointer_invalid" => "MDL 指针无效",
        "net_buffer_data_position_invalid" => "数据位置关系无效",
        "mdl_pointer_invalid_or_cycle" => "MDL 指针无效或成环",
        "mdl_current_offset_out_of_range" => "MDL 当前偏移越界",
        "mdl_pdb_header_size_invalid" => "PDB MDL 头大小无效",
        "mdl_header_unreadable" => "MDL 头不可读",
        "mdl_geometry_invalid" => "MDL 内存范围无效",
        "mdl_page_count_invalid" => "MDL 页数无效",
        "mdl_declared_size_mismatch" => "MDL 声明大小不一致",
        "mdl_pfn_array_unreadable" => "PFN 数组不可读",
        "mdl_pfn_value_invalid" => "PFN 值无效",
        "mdl_pfn_page_missing" => "PFN 页面缺失",
        "mdl_pfn_page_unreadable" => "PFN 页面不可读",
        "mdl_chain_shorter_than_data_length" => "MDL 链短于数据长度",
        "network_raw_ip_header_invalid" => "原始 IP 头无效",
        "network_ethernet_ip_header_invalid" => "以太网 IP 头无效",
        "network_vlan_ip_header_invalid" => "VLAN IP 头无效",
        "network_non_ip_or_unsupported_link_type" => "非 IP 或未支持链路类型",
        "network_packet_range_invalid" => "包字节范围无效",
        "packet_physical_address_unavailable" => "包物理地址不可用",
        "packet_file_offset_unavailable" => "包文件偏移不可用",
        _ => "其他结构拒绝",
    }
}

fn print_mapping_report(report: &starmem::address::VirtualMappingReport) {
    println!(
        "{:>18} {:>18} {:>18} {:>12} {:>6} 标志",
        "虚拟起始", "虚拟结束", "物理地址", "长度", "页大小"
    );
    for mapping in &report.mappings {
        let flags = format!(
            "{}{}{}{}",
            if mapping.writable { 'W' } else { 'R' },
            if mapping.executable { 'X' } else { '-' },
            if mapping.user_accessible { 'U' } else { 'K' },
            if mapping.global { 'G' } else { '-' }
        );
        println!(
            "{:#018x} {:#018x} {:#018x} {:#012x} {:#06x} {}",
            mapping.virtual_start,
            mapping.virtual_end,
            mapping.physical_start,
            mapping.length,
            mapping.source_page_size,
            flags
        );
    }
    println!(
        "\n映射数：{}，已映射字节数：{}，页表页数：{}；已截断={}",
        report.mapping_count,
        report.mapped_bytes,
        report.page_table_pages_read,
        yes_no(report.truncated)
    );
    for warning in &report.warnings {
        eprintln!("警告：{}", localize_runtime_message(warning));
    }
}

fn validate_text_pool_tags(tags: &[String]) -> Result<()> {
    for tag in tags {
        ensure!(
            tag.len() == 4 && tag.is_ascii(),
            "池标签 {tag:?} 必须恰好包含四个 ASCII 字节"
        );
    }
    Ok(())
}

fn parse_pool_tags_or_defaults(tags: &[String]) -> Result<Vec<[u8; 4]>> {
    if tags.is_empty() {
        return Ok(COMMON_POOL_TAGS.to_vec());
    }
    validate_text_pool_tags(tags)?;
    tags.iter()
        .map(|tag| {
            tag.as_bytes()
                .try_into()
                .map_err(|_| anyhow::anyhow!("无效的池标签 {tag:?}"))
        })
        .collect()
}

fn output_linux_process_tree(
    report: &starmem::linux::LinuxProcessTreeReport,
    structured: bool,
) -> Result<()> {
    if structured {
        return print_json(report);
    }

    println!(
        "{:>7} {:>7} {:>7} {:<16} {:>18} 进程树",
        "PID", "TGID", "父PID", "状态", "TASK"
    );
    for process in &report.records {
        let mut findings = Vec::new();
        if process.orphan_parent {
            findings.push("orphan parent");
        }
        if process.parent_cycle {
            findings.push("parent cycle");
        }
        let suffix = if findings.is_empty() {
            String::new()
        } else {
            format!(" [{}]", findings.join(", "))
        };
        println!(
            "{:>7} {:>7} {:>7} {:<16.16} {:#018x} {}{}{}",
            process.pid,
            process.tgid,
            process
                .ppid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            process.state,
            process.task,
            "  ".repeat(process.depth),
            safe_terminal_text(&process.name),
            suffix
        );
    }
    println!("\n内核：{}", safe_terminal_text(&report.kernel.banner));
    println!(
        "来源进程={}；输出={}；根={}；孤儿父进程={}；父链循环={}；筛选PID={}；是否完整={}；停止原因={:?}",
        report.source_process_count,
        report.records.len(),
        report.root_count,
        report.orphan_count,
        report.parent_cycle_count,
        report
            .filtered_pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "全部".to_owned()),
        yes_no(report.complete),
        report.stop_reason
    );
    println!(
        "扫描：{} 字节，耗时 {:.3} 秒（{:.2} GiB/s）",
        report.bytes_scanned, report.scan_seconds, report.scan_gib_per_second
    );
    for warning in &report.warnings {
        eprintln!("警告 [{}]：{}", warning.kind, warning.message);
    }
    Ok(())
}

fn render_terminal_progress(task: &TerminalProgressTask, finished: Option<bool>) -> String {
    const BAR_WIDTH: usize = 24;
    let progress_current = if finished == Some(true) {
        task.total
    } else {
        task.current
    };
    let ratio = if task.total == 0 {
        1.0
    } else {
        (progress_current as f64 / task.total as f64).clamp(0.0, 1.0)
    };
    let filled = ((ratio * BAR_WIDTH as f64).round() as usize).min(BAR_WIDTH);
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(BAR_WIDTH - filled));
    let elapsed = task.started.elapsed().as_secs_f64().max(f64::EPSILON);
    let bytes_per_second = task.current as f64 / elapsed;
    let rate = compact_rate(bytes_per_second);
    let tail = match finished {
        Some(true) if task.current < task.total => {
            format!("完成（提前） {}", compact_duration(elapsed))
        }
        Some(true) => format!("完成 {}", compact_duration(elapsed)),
        Some(false) => format!("中断 {}", compact_duration(elapsed)),
        None if bytes_per_second > 0.0 && task.current < task.total => {
            let eta = compact_duration((task.total - task.current) as f64 / bytes_per_second);
            format!("ETA {eta}")
        }
        None => "ETA --".to_owned(),
    };
    let label = truncate_progress_label(&safe_terminal_text(&task.label), 36);
    format!(
        "{label:<36} [{bar}] {:>5.1}% {}/{} {rate} {tail}",
        ratio * 100.0,
        compact_bytes(task.current),
        compact_bytes(task.total)
    )
}

fn write_terminal_progress(display: &mut TerminalProgressDisplay, line: &str, newline: bool) {
    let width = line.chars().count();
    let padding = display.previous_width.saturating_sub(width);
    let mut stderr = std::io::stderr().lock();
    let _ = write!(stderr, "\r{line}{}", " ".repeat(padding));
    if newline {
        let _ = writeln!(stderr);
        display.previous_width = 0;
    } else {
        display.previous_width = width;
    }
    let _ = stderr.flush();
}

fn compact_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.2}GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1}MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1}KiB", bytes / KIB)
    } else {
        format!("{bytes:.0}B")
    }
}

fn compact_rate(bytes_per_second: f64) -> String {
    format!("{}/s", compact_bytes(bytes_per_second.max(0.0) as u64))
}

fn compact_duration(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{seconds:.1}s")
    } else if seconds < 3600.0 {
        format!("{}m{:02}s", (seconds / 60.0) as u64, seconds as u64 % 60)
    } else {
        format!(
            "{}h{:02}m",
            (seconds / 3600.0) as u64,
            (seconds as u64 % 3600) / 60
        )
    }
}

fn truncate_progress_label(label: &str, max_chars: usize) -> String {
    let mut characters = label.chars();
    let mut output = characters.by_ref().take(max_chars).collect::<String>();
    if characters.next().is_some() {
        output.pop();
        output.push('…');
    }
    output
}

fn print_windows_timeline(report: &WindowsTimelineReport) {
    println!(
        "{:<24} {:<9} {:<24} {:>7} {:>7} {:<25} 证据",
        "UTC 时间", "类别", "动作", "PID", "TID", "来源"
    );
    for event in &report.events {
        println!(
            "{:<24.24} {:<9.9} {:<24.24} {:>7} {:>7} {:<25.25} {}",
            event.timestamp,
            event.category,
            event.action,
            event
                .pid
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            event
                .tid
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            event.source,
            safe_terminal_text(&event.description)
        );
    }
    println!(
        "\n匹配事件={}；输出事件={}；异常时间={}/{}；截断={}；顺序={}",
        report.matched_events,
        report.events.len(),
        report.outlier_events_retained,
        report.outlier_events_matched,
        yes_no(report.truncated),
        if report.filters.newest_first {
            "从新到旧"
        } else {
            "从旧到新"
        }
    );
    for source in &report.sources {
        println!(
            "  来源 {:<10} 记录={} 事件={} 合并副本={} 完整={}{}",
            source.source,
            source.records_examined,
            source.events_matched,
            source.duplicate_events_merged,
            yes_no(source.complete),
            source
                .error
                .as_deref()
                .map(|error| format!(" 错误={}", safe_terminal_text(error)))
                .unwrap_or_default()
        );
    }
    print_plugin_footer(report.events.len(), report.complete, &report.warnings);
}

fn output_policy_from_matches(matches: &clap::ArgMatches) -> Result<OutputPolicy> {
    let force = matches
        .try_get_one::<bool>("force")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false);
    let command = selected_command_id(matches).unwrap_or_else(|| "unknown".to_owned());
    let mut policy = OutputPolicy::new(force);

    for id in [
        "image",
        "pdb",
        "profile",
        "strings_file",
        "rules",
        "input",
        "verify_db_roots",
        "search_roots",
        "isf",
        "metadata",
    ] {
        for path in matched_path_arguments(matches, id) {
            let is_directory_role = matches!(id, "verify_db_roots" | "search_roots")
                || fs::metadata(&path).is_ok_and(|metadata| metadata.is_dir());
            if is_directory_role {
                policy.protect_directory(id, path);
            } else if id == "image" {
                let sidecars = [path.with_extension("vmss"), path.with_extension("vmsn")]
                    .into_iter()
                    .filter(|sidecar| sidecar.is_file())
                    .collect::<Vec<_>>();
                policy.protect_file_with_sidecars(id, path, sidecars);
            } else {
                policy.protect_file(id, path);
            }
        }
    }

    if let Some(csv) = matched_path_argument(matches, "csv")
        && csv != Path::new("-")
    {
        policy.output_file("csv", csv);
    }
    if let Some(database) = matched_path_argument(matches, "db") {
        policy.output(OutputTarget::append_file("collect.sqlite", database).with_sqlite_sidecars());
    }
    if let Some(raw_objects) = matched_path_argument(matches, "raw_objects") {
        policy.output_file("raw_objects.jsonl", raw_objects);
    }
    if let Some(output_dir) = matched_path_argument(matches, "output_dir") {
        policy.output(OutputTarget::directory("recovery.directory", output_dir));
    }
    if let Some(output) = matched_path_argument(matches, "output") {
        let directory = matches!(
            command.as_str(),
            "linux.proc.dump"
                | "gdi-bitmap"
                | "desktop-reconstruct"
                | "dump-registry"
                | "dump-logs"
        );
        if directory {
            let mut target = OutputTarget::directory("output.directory", output);
            target = match command.as_str() {
                "gdi-bitmap" => target.with_owned_file("gdi-bitmap-report.json"),
                "desktop-reconstruct" => target.with_owned_file("desktop-reconstruct-report.json"),
                "dump-registry" => target.with_owned_file("export-report.json"),
                "dump-logs" => target
                    .with_owned_file("export-report.json")
                    .with_owned_file("event-timeline.json")
                    .with_owned_file("event-timeline.csv"),
                _ => target,
            };
            policy.output(target);
        } else {
            let mut target = OutputTarget::file("output.file", output);
            if command == "dumpfile" {
                target = target.with_sibling_suffix(".partial");
            } else if command == "linux.module-extract" {
                target = target
                    .with_sibling_suffix(".partial")
                    .with_sibling_suffix(".manifest.json");
            }
            policy.output(target);
        }
    }
    Ok(policy)
}

fn matched_path_arguments(matches: &clap::ArgMatches, id: &str) -> Vec<PathBuf> {
    let mut paths = matches
        .try_get_many::<PathBuf>(id)
        .ok()
        .flatten()
        .map(|values| values.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    if let Some((_, child)) = matches.subcommand() {
        paths.extend(matched_path_arguments(child, id));
    }
    paths
}

fn evidence_output_context(matches: &clap::ArgMatches) -> Result<EvidenceOutputContext> {
    let command = selected_command_id(matches).context("CLI 没有选中可执行的叶子命令")?;
    let source = ["image", "input", "pdb"]
        .into_iter()
        .find_map(|id| matched_path_argument(matches, id).map(|path| (id, path)));
    let (source_id, source_path) = source
        .map(|(id, path)| (Some(id), Some(path)))
        .unwrap_or((None, None));
    let source_identity = match source_path {
        Some(path) => source_identity_for_path(path, source_id.unwrap_or("input"))?,
        None => SourceIdentity {
            format: "none".to_owned(),
            size: 0,
            mtime: None,
            sample_digest: DigestReference::new("not-applicable", "not-applicable"),
            symbol_identity: None,
            components: Vec::new(),
            physical_layout: None,
        },
    };
    let mut scope = EvidenceScope::new(match source_id {
        Some("image") => "memory_image",
        Some("input") => "event_log_input",
        Some("pdb") => "symbol_file",
        _ => "engine",
    });
    scope.constraints.insert(
        "command_id".to_owned(),
        serde_json::Value::String(command.clone()),
    );
    Ok(EvidenceOutputContext {
        command,
        source_identity,
        scope,
        limits: evidence_limits_from_matches(matches),
    })
}

fn selected_command_id(matches: &clap::ArgMatches) -> Option<String> {
    let mut current = matches;
    let mut parts = Vec::new();
    while let Some((name, child)) = current.subcommand() {
        parts.push(name);
        current = child;
    }
    (!parts.is_empty()).then(|| parts.join("."))
}

fn source_identity_for_path(path: &Path, role: &str) -> Result<SourceIdentity> {
    let metadata =
        fs::metadata(path).with_context(|| format!("无法读取证据源 {}", path.display()))?;
    if metadata.is_dir() {
        return directory_source_identity(path);
    }
    let format = if role == "image" {
        let image = open_memory_image(path)?;
        return source_identity_for_memory_image(path, &image);
    } else {
        path.extension()
            .and_then(|extension| extension.to_str())
            .filter(|extension| !extension.is_empty())
            .unwrap_or(role)
            .to_ascii_lowercase()
    };
    SourceIdentity::from_path(path, format)
}

fn directory_source_identity(root: &Path) -> Result<SourceIdentity> {
    let mut files = Vec::new();
    collect_identity_files(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut digest = Sha256::new();
    digest.update(b"starmem-directory-sample-v1\0");
    let mut total_size = 0u64;
    for (relative, path, size, modified_nanos) in files {
        total_size = total_size.saturating_add(size);
        digest.update((relative.len() as u64).to_le_bytes());
        digest.update(relative.as_bytes());
        digest.update(size.to_le_bytes());
        digest.update(modified_nanos.to_le_bytes());
        let mut file = File::open(&path)
            .with_context(|| format!("无法采样目录证据文件 {}", path.display()))?;
        let sample_len = size.min(4096) as usize;
        let mut buffer = vec![0u8; sample_len];
        if sample_len > 0 {
            file.read_exact(&mut buffer)?;
            digest.update(&buffer);
            if size > sample_len as u64 {
                file.seek(SeekFrom::Start(size - sample_len as u64))?;
                file.read_exact(&mut buffer)?;
                digest.update(&buffer);
            }
        }
    }
    let metadata = fs::metadata(root)?;
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| SourceModifiedTime {
            unix_nanos: duration.as_nanos().to_string(),
        });
    Ok(SourceIdentity {
        format: "directory".to_owned(),
        size: total_size,
        mtime,
        sample_digest: DigestReference::new(
            "sha256-directory-sample-v1",
            hex::encode(digest.finalize()),
        ),
        symbol_identity: None,
        components: Vec::new(),
        physical_layout: None,
    })
}

fn collect_identity_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, PathBuf, u64, u128)>,
) -> Result<()> {
    for entry in
        fs::read_dir(current).with_context(|| format!("无法读取证据目录 {}", current.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_identity_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let modified_nanos = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_nanos());
            files.push((relative, path, metadata.len(), modified_nanos));
        }
    }
    Ok(())
}

fn evidence_limits_from_matches(matches: &clap::ArgMatches) -> Vec<EvidenceLimit> {
    let mut limits = Vec::new();
    collect_evidence_limits(matches, &mut limits);
    limits.sort_by(|left, right| left.name.cmp(&right.name));
    limits.dedup_by(|left, right| left.name == right.name);
    limits
}

fn collect_evidence_limits(matches: &clap::ArgMatches, limits: &mut Vec<EvidenceLimit>) {
    for id in matches.ids() {
        let name = id.as_str();
        if !is_evidence_limit_argument(name) {
            continue;
        }
        let configured = matches
            .try_get_one::<usize>(name)
            .ok()
            .flatten()
            .and_then(|value| u64::try_from(*value).ok())
            .or_else(|| matches.try_get_one::<u64>(name).ok().flatten().copied())
            .or_else(|| {
                matches
                    .try_get_one::<u32>(name)
                    .ok()
                    .flatten()
                    .map(|value| u64::from(*value))
            });
        let kind = if name.contains("bytes")
            || name.contains("size")
            || name.ends_with("_mib")
            || name.ends_with("_kib")
        {
            EvidenceLimitKind::Bytes
        } else if name == "limit" {
            EvidenceLimitKind::Output
        } else {
            EvidenceLimitKind::SourceScan
        };
        let configured = configured.and_then(|value| {
            if name.ends_with("_mib") {
                value.checked_mul(1024 * 1024)
            } else if name.ends_with("_kib") {
                value.checked_mul(1024)
            } else {
                Some(value)
            }
        });
        let mut limit = EvidenceLimit::new(name, kind);
        limit.configured = configured;
        limits.push(limit);
    }
    if let Some((_, child)) = matches.subcommand() {
        collect_evidence_limits(child, limits);
    }
}

fn is_evidence_limit_argument(name: &str) -> bool {
    name == "limit"
        || name.ends_with("_limit")
        || name.ends_with("_size")
        || name.ends_with("_bytes")
        || name.ends_with("_mib")
        || name.ends_with("_kib")
}

fn envelope_json_value(value: &impl Serialize) -> Result<serde_json::Value> {
    let mut data = serde_json::to_value(value).context("无法序列化插件报告")?;
    if data
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        == Some(u64::from(starmem::EVIDENCE_SCHEMA_VERSION))
        && data.get("data").is_some()
    {
        if let Some(raw_evidence) = write_requested_raw_objects(&data)?
            && let Some(object) = data.as_object_mut()
        {
            object.insert(
                "raw_evidence".to_owned(),
                serde_json::to_value(raw_evidence)?,
            );
        }
        return Ok(data);
    }
    let context = EVIDENCE_OUTPUT_CONTEXT
        .get()
        .context("Evidence 输出上下文尚未初始化")?;
    let root = data.as_object();
    let available = root
        .and_then(|object| object.get("available"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let declared_complete = root
        .and_then(|object| object.get("complete"))
        .and_then(serde_json::Value::as_bool);
    let administrative_complete = matches!(
        context.command.as_str(),
        "build-info" | "info" | "profile" | "symbols.id" | "symbols.search" | "virt2phys"
    );
    let complete = if available {
        declared_complete.unwrap_or(administrative_complete)
    } else {
        false
    };
    let mut warnings = normalize_legacy_warnings(
        root.and_then(|object| object.get("warnings")),
        &context.command,
    )?;
    if declared_complete.is_none() && !administrative_complete {
        warnings.push(EvidenceWarning::new(
            "contract.completeness_unknown",
            EvidenceWarningSeverity::Warning,
            "插件报告未声明搜索宇宙完整性，Evidence Envelope 按 complete=false 处理",
            &context.command,
        ));
    }
    let missing_ranges = root
        .and_then(|object| object.get("missing_ranges"))
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<MissingRange>>(value).ok())
        .unwrap_or_default();
    let scope = root
        .and_then(|object| object.get("scope"))
        .filter(|value| value.is_object())
        .cloned()
        .and_then(|value| serde_json::from_value::<EvidenceScope>(value).ok())
        .unwrap_or_else(|| context.scope.clone());
    let reported_limits = root
        .and_then(|object| object.get("limits"))
        .filter(|value| value.is_array())
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<EvidenceLimit>>(value).ok())
        .unwrap_or_default();
    let limits = merge_evidence_limits(&context.limits, reported_limits);
    let source_identity =
        source_identity_with_consumed_symbols(context.source_identity.clone(), root);
    let mut raw_evidence = root
        .and_then(|object| object.get("raw_evidence"))
        .cloned()
        .and_then(|value| serde_json::from_value::<RawEvidenceSummary>(value).ok())
        .unwrap_or_default();
    if let Some(requested) = write_requested_raw_objects(&data)? {
        raw_evidence = requested;
    }
    let envelope = EvidenceEnvelope::from_parts(
        context.command.clone(),
        EngineIdentity::new(
            starmem::VERSION,
            starmem::BUILD_ID,
            starmem::INTEGRATION_API_VERSION,
        ),
        source_identity,
        available,
        complete,
        scope,
        warnings,
        limits,
        missing_ranges,
        raw_evidence,
        data,
    )?;
    serde_json::to_value(envelope).context("无法序列化 Evidence Envelope")
}

fn merge_evidence_limits(
    configured: &[EvidenceLimit],
    reported: Vec<EvidenceLimit>,
) -> Vec<EvidenceLimit> {
    let mut merged = configured.to_vec();
    for mut plugin_limit in reported {
        if let Some(cli_limit) = merged.iter_mut().find(|candidate| {
            candidate.name == plugin_limit.name && candidate.kind == plugin_limit.kind
        }) {
            if plugin_limit.configured.is_none() {
                plugin_limit.configured = cli_limit.configured;
            }
            *cli_limit = plugin_limit;
        } else {
            merged.push(plugin_limit);
        }
    }
    merged.sort_by(|left, right| {
        left.name.cmp(&right.name).then_with(|| {
            evidence_limit_kind_rank(left.kind).cmp(&evidence_limit_kind_rank(right.kind))
        })
    });
    merged
}

fn evidence_limit_kind_rank(kind: EvidenceLimitKind) -> u8 {
    match kind {
        EvidenceLimitKind::SourceScan => 0,
        EvidenceLimitKind::Output => 1,
        EvidenceLimitKind::Bytes => 2,
    }
}

fn linux_symbol_identity_from_report(
    root: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Option<SymbolIdentity> {
    let root = root?;
    let candidates = [
        root.get("kernel_session")
            .and_then(|value| value.get("symbol_identity")),
        root.get("selected_identity"),
        root.get("install").and_then(|value| value.get("identity")),
        root.get("remote")
            .and_then(|value| value.get("selected_identity")),
    ];
    candidates
        .into_iter()
        .flatten()
        .find_map(linux_symbol_identity_from_value)
}

fn source_identity_with_consumed_symbols(
    mut source_identity: SourceIdentity,
    report_root: Option<&serde_json::Map<String, serde_json::Value>>,
) -> SourceIdentity {
    if let Some(symbol_identity) = linux_symbol_identity_from_report(report_root) {
        source_identity.symbol_identity = Some(symbol_identity);
    } else if let Some(symbol_identity) = WINDOWS_SYMBOL_IDENTITY
        .get()
        .and_then(|identity| identity.lock().ok())
        .and_then(|identity| identity.clone())
    {
        source_identity.symbol_identity = Some(symbol_identity);
    }
    source_identity
}

fn linux_symbol_identity_from_value(value: &serde_json::Value) -> Option<SymbolIdentity> {
    let object = value.as_object()?;
    let canonical = object.get("canonical_sha256")?.as_str()?;
    let isf_sha256 = object.get("isf_sha256")?.as_str()?;
    if canonical.is_empty() || isf_sha256.is_empty() {
        return None;
    }
    let mut identity = SymbolIdentity::new("linux_isf", canonical);
    identity.digest = Some(DigestReference::new("sha256", isf_sha256));
    for key in [
        "schema_version",
        "provider",
        "format",
        "producer",
        "banner_sha256",
        "vmlinux_sha256",
        "features",
    ] {
        if let Some(detail) = object.get(key)
            && !detail.is_null()
        {
            identity.details.insert(key.to_owned(), detail.clone());
        }
    }
    Some(identity)
}

fn write_requested_raw_objects(report: &serde_json::Value) -> Result<Option<RawEvidenceSummary>> {
    let Some(path) = RAW_OBJECTS_OUTPUT.get() else {
        return Ok(None);
    };
    let context = EVIDENCE_OUTPUT_CONTEXT
        .get()
        .context("Evidence 输出上下文尚未初始化")?;
    let embedded_source_identity = report
        .get("source_identity")
        .cloned()
        .and_then(|value| serde_json::from_value::<SourceIdentity>(value).ok());
    let report_data = report.get("data").unwrap_or(report);
    let source_identity = source_identity_with_consumed_symbols(
        embedded_source_identity.unwrap_or_else(|| context.source_identity.clone()),
        report_data.as_object(),
    );
    let bundle = extract_raw_objects(&context.command, &source_identity, report_data)?;
    let summary = write_raw_objects_jsonl_with_policy(
        OUTPUT_POLICY.get().context("输出安全策略尚未初始化")?,
        path,
        &bundle,
    )?;
    Ok(Some(summary))
}

fn print_json(value: &impl Serialize) -> Result<()> {
    let envelope = envelope_json_value(value)?;
    if let Some(path) = CSV_OUTPUT.get() {
        if path == std::path::Path::new("-") {
            write_csv_report(std::io::stdout().lock(), &envelope)?;
            eprintln!("CSV 报告已写入标准输出。");
        } else {
            OUTPUT_POLICY
                .get()
                .context("输出安全策略尚未初始化")?
                .write_file_atomic(path, |file| write_csv_report(file, &envelope))?;
            eprintln!("CSV 报告：{}", path.display());
        }
        return Ok(());
    }
    serde_json::to_writer_pretty(std::io::stdout().lock(), &envelope)?;
    println!();
    Ok(())
}

fn output_paths_conflict(left: &Path, right: &Path) -> bool {
    if matches!(same_file::is_same_file(left, right), Ok(true)) {
        return true;
    }
    let left = comparable_output_path(left);
    let right = comparable_output_path(right);
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn matched_path_argument<'a>(matches: &'a clap::ArgMatches, id: &str) -> Option<&'a Path> {
    matches
        .try_get_one::<PathBuf>(id)
        .ok()
        .flatten()
        .map(PathBuf::as_path)
        .or_else(|| {
            matches
                .subcommand()
                .and_then(|(_, child)| matched_path_argument(child, id))
        })
}

fn ensure_matched_csv_does_not_overwrite_image(matches: &clap::ArgMatches) -> Result<()> {
    let Some(csv_path) = matched_path_argument(matches, "csv") else {
        return Ok(());
    };
    let Some(input) = matched_path_argument(matches, "image") else {
        return Ok(());
    };
    ensure_csv_path_does_not_overwrite_input(csv_path, input)
}

fn ensure_csv_path_does_not_overwrite_input(csv_path: &Path, input: &Path) -> Result<()> {
    if csv_path == Path::new("-") {
        return Ok(());
    }
    ensure!(
        !output_paths_conflict(csv_path, input),
        "--csv 报告路径不能与输入内存镜像相同：{}",
        input.display()
    );
    Ok(())
}

fn ensure_csv_does_not_overwrite_input(input: &Path) -> Result<()> {
    if let Some(csv_path) = CSV_OUTPUT
        .get()
        .filter(|path| path.as_path() != Path::new("-"))
    {
        ensure_csv_path_does_not_overwrite_input(csv_path, input)?;
    }
    Ok(())
}

fn comparable_output_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(current) = std::env::current_dir() {
        current.join(path)
    } else {
        path.to_path_buf()
    };
    let Some(file_name) = absolute.file_name() else {
        return absolute;
    };
    absolute
        .parent()
        .and_then(|parent| fs::canonicalize(parent).ok())
        .map(|parent| parent.join(file_name))
        .unwrap_or(absolute)
}

fn write_json_file(path: &std::path::Path, value: &impl Serialize) -> Result<()> {
    let envelope = envelope_json_value(value)?;
    OUTPUT_POLICY
        .get()
        .context("输出安全策略尚未初始化")?
        .write_file_atomic(path, |file| {
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, &envelope)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            Ok(())
        })
}

fn print_browser_session_report(report: &BrowserSessionReport) {
    println!("浏览器会话：");
    if report.sessions.is_empty() {
        println!("  没有重建出可验证的浏览器会话证据。");
    }
    for (index, session) in report.sessions.iter().enumerate() {
        println!(
            "\n会话 #{} [{}][置信度：{}] {}",
            index + 1,
            browser_session_kind_name(session.kind),
            confidence_name(&session.confidence),
            session.browser,
        );
        if let Some(process) = &session.process {
            println!(
                "  进程：{}（PID={}）",
                process,
                session
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "未知".to_owned())
            );
        }
        if let Some(profile) = &session.profile {
            println!("  浏览器配置：{profile}");
        }
        if let Some(directory) = &session.configuration_directory {
            println!("  配置目录：{directory}");
        }
        if let Some(user_sid) = &session.user_sid {
            println!("  用户 SID：{user_sid}");
        }
        if let Some(image_path) = &session.image_path {
            println!("  映像路径：{image_path}");
        }
        if let Some(command_line) = &session.command_line {
            println!("  命令行：{}", display_excerpt(command_line, 320));
        }
        println!(
            "  时间依据：{}{}",
            session.time_basis,
            session
                .process_create_time
                .as_deref()
                .map(|time| format!("；进程创建时间={time}"))
                .unwrap_or_default()
        );
        println!(
            "  证据：Cookie={}；下载={}；合计={}",
            session.cookie_indices.len(),
            session.download_indices.len(),
            session.evidence_count
        );
        if !session.domains.is_empty() {
            println!("  域名：{}", session.domains.join("、"));
        }
        if !session.cookie_indices.is_empty() {
            println!(
                "  Cookie 索引：{}",
                format_report_indices(&session.cookie_indices)
            );
        }
        if !session.download_indices.is_empty() {
            println!(
                "  下载索引：{}",
                format_report_indices(&session.download_indices)
            );
        }
    }

    println!("\nCookie 证据：");
    if report.cookies.is_empty() {
        println!("  未发现可验证的浏览器 Cookie。");
    }
    for (index, cookie) in report.cookies.iter().enumerate() {
        println!(
            "  #{} [{}][{}][置信度：{}] {}{} {}={}",
            index + 1,
            cookie.browser,
            cookie_source_name(cookie.source),
            confidence_name(&cookie.confidence),
            cookie.domain.as_deref().unwrap_or("未知域名"),
            cookie.path.as_deref().unwrap_or(""),
            cookie.name,
            cookie
                .value
                .as_deref()
                .map(|value| display_excerpt(value, 160))
                .unwrap_or_else(|| "（值已加密）".to_owned()),
        );
        if let Some(source_file) = &cookie.source_file {
            println!(
                "    来源文件：{}；FILE_OBJECT={}；数据库行={}",
                source_file,
                cookie
                    .file_object
                    .map(|address| format!("{address:#018x}"))
                    .unwrap_or_else(|| "未知".to_owned()),
                cookie
                    .database_rowid
                    .map(|row| row.to_string())
                    .unwrap_or_else(|| "不适用".to_owned())
            );
        }
        if !cookie.owners.is_empty() {
            println!(
                "    进程证据：{}",
                cookie
                    .owners
                    .iter()
                    .map(|owner| format!(
                        "{}({})@{:#018x}",
                        owner.process, owner.pid, owner.virtual_address
                    ))
                    .collect::<Vec<_>>()
                    .join("、")
            );
        }
    }

    println!("\n下载证据：");
    if report.downloads.is_empty() {
        println!("  未发现可验证的下载痕迹。");
    }
    for (index, download) in report.downloads.iter().enumerate() {
        println!(
            "  #{} [置信度：{}] 主机={}；IP={}；端口={}；方法={}；文件={}",
            index + 1,
            confidence_name(&download.confidence),
            download.host,
            download.ip_address.as_deref().unwrap_or("非 IP 主机名"),
            download
                .port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "默认".to_owned()),
            download_method_name(download.method.as_deref()),
            download.file_name.as_deref().unwrap_or("未知")
        );
        println!("    URL：{}", download.url);
        if download.owners.is_empty() {
            println!("    进程归属：未证明，已保留在未归属下载列表");
        } else {
            println!(
                "    进程证据：{}",
                download
                    .owners
                    .iter()
                    .map(|owner| format!(
                        "{} / {}({})@{:#018x}",
                        owner.browser, owner.process, owner.pid, owner.virtual_address
                    ))
                    .collect::<Vec<_>>()
                    .join("、")
            );
        }
        println!("    上下文：{}", display_excerpt(&download.evidence, 320));
    }

    println!("\n浏览器 History 下载记录：");
    if report.download_history.is_empty() {
        println!("  未恢复到结构化的浏览器下载数据库记录。");
    }
    for (index, download) in report.download_history.iter().enumerate() {
        println!(
            "  #{} [{} / {}] 站点={}；文件={}；状态={}；接收={}/{} 字节",
            index + 1,
            download.browser,
            download.profile.as_deref().unwrap_or("默认配置"),
            download.website.as_deref().unwrap_or("未知"),
            download.file_name.as_deref().unwrap_or("未知"),
            download.state.as_deref().unwrap_or("未知"),
            download
                .received_bytes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "未知".to_owned()),
            download
                .total_bytes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "未知".to_owned()),
        );
        if let Some(path) = &download.target_path {
            println!("    目标：{path}");
        }
        if !download.url_chain.is_empty() {
            println!("    URL 链：{}", download.url_chain.join(" -> "));
        } else if let Some(url) = &download.source_url {
            println!("    URL：{url}");
        }
        println!(
            "    来源：{}；FILE_OBJECT={:#018x}；数据库行={}",
            download.source_file, download.file_object, download.database_rowid
        );
    }

    println!("\n网站登录账号：");
    if report.login_accounts.is_empty() {
        println!("  未恢复到具有明文用户名的 Login Data 记录。");
    }
    for (index, account) in report.login_accounts.iter().enumerate() {
        println!(
            "  #{} [{} / {}] {}：{}（{}；已保存密码={}）",
            index + 1,
            account.browser,
            account.profile.as_deref().unwrap_or("默认配置"),
            account.domain.as_deref().unwrap_or(&account.website),
            account.username,
            account.username_kind,
            yes_no(account.password_stored),
        );
        println!(
            "    来源：{}；FILE_OBJECT={:#018x}；数据库行={}",
            account.source_file, account.file_object, account.database_rowid
        );
    }

    if !report.domain_relations.is_empty() {
        println!("\n域名证据关系：");
        for relation in &report.domain_relations {
            println!(
                "  {}：下载={}；相关 Cookie={}；相关会话={}；{}",
                relation.download_host,
                format_report_indices(&relation.download_indices),
                if relation.cookie_indices.is_empty() {
                    "无".to_owned()
                } else {
                    format_report_indices(&relation.cookie_indices)
                },
                if relation.session_indices.is_empty() {
                    "无".to_owned()
                } else {
                    format_report_indices(&relation.session_indices)
                },
                relation.relation_basis
            );
        }
    }

    println!(
        "\n会话={}；浏览器进程={}；Cookie={}；内存下载痕迹={}；History下载={}；登录账号={}；未归属下载={}；域名关系={}；是否完整={}",
        report.sessions.len(),
        report.browser_processes.len(),
        report.cookies.len(),
        report.downloads.len(),
        report.download_history.len(),
        report.login_accounts.len(),
        report.unassigned_downloads.len(),
        report.domain_relations.len(),
        yes_no(report.complete)
    );
    println!(
        "扫描统计：Cookie 头命中={}；Cookie 文件={}；Cookie数据库={}；浏览器证据文件={}；History/Login数据库={}；下载 URL 命中={}；扫描字节={}",
        report.statistics.runtime_cookie_header_hits,
        report.statistics.cookie_files_found,
        report.statistics.cookie_databases_parsed,
        report.statistics.browser_artifact_files_found,
        report.statistics.browser_artifact_databases_parsed,
        report.statistics.raw_download_url_hits,
        report.statistics.bytes_scanned
    );
    println!(
        "阶段耗时：Cookie={:.3}秒；History/Login={:.3}秒；下载={:.3}秒；下载进程关联={:.3}秒；会话聚合={:.3}秒；总计={:.3}秒",
        report.timing.cookie_seconds,
        report.timing.browser_database_seconds,
        report.timing.download_seconds,
        report.timing.download_owner_mapping_seconds,
        report.timing.aggregation_seconds,
        report.timing.total_seconds
    );
    for warning in &report.warnings {
        eprintln!("警告：{}", localize_runtime_message(warning));
    }
}

fn print_terminal_history_report(report: &TerminalHistoryReport) {
    println!("终端相关进程：");
    if report.terminal_processes.is_empty() {
        println!("  没有恢复到活动的终端相关进程。");
    }
    for process in &report.terminal_processes {
        println!(
            "  PID={} PPID={} [{}][{}] {} 用户={} 前端={}",
            process.pid,
            process
                .ppid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "未知".to_owned()),
            terminal_kind_name(process.kind),
            terminal_process_role_name(process.role),
            process.process,
            process
                .user_name
                .as_deref()
                .or(process.user_sid.as_deref())
                .unwrap_or("未知"),
            process.frontend.as_deref().unwrap_or("未证明"),
        );
    }

    println!("\n终端历史：");
    if report.records.is_empty() {
        println!("  没有发现可验证的终端历史记录。");
    }
    for (index, record) in report.records.iter().enumerate() {
        println!(
            "  #{} [{}][{}][置信度：{}] {}",
            index + 1,
            terminal_history_source_name(record.source),
            terminal_kind_name(record.terminal_kind),
            confidence_name(&record.confidence),
            display_excerpt(&record.command, 512),
        );
        println!(
            "    终端 PID={}；宿主={}；用户={}；前端={}",
            record
                .terminal_pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "未证明".to_owned()),
            match (&record.host_process, record.host_pid) {
                (Some(process), Some(pid)) => format!("{process}({pid})"),
                _ => "不适用".to_owned(),
            },
            record
                .user_name
                .as_deref()
                .or(record.user_sid.as_deref())
                .unwrap_or("未知"),
            record.frontend.as_deref().unwrap_or("未证明"),
        );
        if let Some(path) = &record.source_file {
            println!(
                "    来源文件：{}；FILE_OBJECT={}；文件偏移={}",
                path,
                record
                    .file_objects
                    .iter()
                    .map(|address| format!("{address:#018x}"))
                    .collect::<Vec<_>>()
                    .join("、"),
                record
                    .file_offset
                    .map(|offset| format!("{offset:#x}"))
                    .unwrap_or_else(|| "未知".to_owned()),
            );
        } else {
            println!(
                "    历史结构={}；命令地址={}；物理地址={}",
                record
                    .history_address
                    .map(|address| format!("{address:#018x}"))
                    .unwrap_or_else(|| "未知".to_owned()),
                record
                    .virtual_address
                    .map(|address| format!("{address:#018x}"))
                    .unwrap_or_else(|| "未知".to_owned()),
                record
                    .physical_addresses
                    .first()
                    .map(|address| format!("{address:#018x}"))
                    .unwrap_or_else(|| "不可用".to_owned()),
            );
        }
    }
    println!(
        "\n终端进程={}；控制台宿主={}；结构化历史缓冲={}；内存回退组={}；PSReadLine 文件={}/{}；耗时={:.3}秒",
        report.statistics.terminal_processes,
        report.statistics.console_hosts,
        report.statistics.console_history_buffers,
        report.statistics.console_memory_fallback_groups,
        report.statistics.psreadline_files_parsed,
        report.statistics.psreadline_files_found,
        report.timing.total_seconds,
    );
    print_plugin_footer(report.records.len(), report.complete, &report.warnings);
}

fn browser_session_kind_name(kind: BrowserSessionKind) -> &'static str {
    match kind {
        BrowserSessionKind::Process => "进程会话",
        BrowserSessionKind::Profile => "配置会话",
        BrowserSessionKind::Browser => "浏览器证据会话",
    }
}

fn wechat_process_role_name(role: WechatProcessRole) -> &'static str {
    match role {
        WechatProcessRole::Main => "主进程",
        WechatProcessRole::Helper => "辅助进程",
        WechatProcessRole::MiniProgram => "小程序运行时",
        WechatProcessRole::Explicit => "用户指定进程",
        WechatProcessRole::Unattributed => "未归属微信残留页",
    }
}

fn wechat_key_kind_name(kind: WechatKeyKind) -> &'static str {
    match kind {
        WechatKeyKind::AccountMaster => "账户主密钥候选",
        WechatKeyKind::Database => "数据库密钥候选",
    }
}

fn wechat_key_confidence_name(confidence: WechatKeyConfidence) -> &'static str {
    match confidence {
        WechatKeyConfidence::High => "高",
        WechatKeyConfidence::Medium => "中",
        WechatKeyConfidence::Low => "低",
    }
}

fn wechat_key_encoding_name(encoding: WechatKeyEncoding) -> &'static str {
    match encoding {
        WechatKeyEncoding::Ascii => "ASCII",
        WechatKeyEncoding::Utf16Le => "UTF-16LE",
        WechatKeyEncoding::RawBytes => "原始二进制",
    }
}

fn wechat_key_context_name(context: WechatKeyContext) -> &'static str {
    match context {
        WechatKeyContext::SqlcipherPragma => "SQLCipher 密钥指令",
        WechatKeyContext::KeyAssignment => "密钥赋值上下文",
        WechatKeyContext::HexLiteral => "十六进制字面量",
        WechatKeyContext::RepeatedHeapAllocation => "重复的32字节堆分配",
    }
}

fn terminal_kind_name(kind: TerminalKind) -> &'static str {
    match kind {
        TerminalKind::WindowsTerminal => "Windows Terminal",
        TerminalKind::OpenConsole => "OpenConsole",
        TerminalKind::PowerShell => "Windows PowerShell",
        TerminalKind::Pwsh => "PowerShell 7+",
        TerminalKind::Cmd => "命令提示符",
        TerminalKind::Conhost => "传统控制台宿主",
        TerminalKind::Unknown => "未知终端",
    }
}

fn terminal_process_role_name(role: TerminalProcessRole) -> &'static str {
    match role {
        TerminalProcessRole::Frontend => "终端前端",
        TerminalProcessRole::ConsoleHost => "控制台宿主",
        TerminalProcessRole::Shell => "命令解释器",
    }
}

fn terminal_history_source_name(source: TerminalHistorySource) -> &'static str {
    match source {
        TerminalHistorySource::ConsoleHistory => "控制台历史结构",
        TerminalHistorySource::ConsoleMemoryFallback => "控制台内存回退",
        TerminalHistorySource::PsReadLineFile => "PSReadLine 文件",
    }
}

fn confidence_name(confidence: &str) -> &'static str {
    match confidence {
        "high" => "高",
        "medium" => "中",
        _ => "低",
    }
}

fn download_method_name(method: Option<&str>) -> &'static str {
    match method {
        Some("certutil") => "证书工具下载",
        Some("powershell_invoke_webrequest") => "PowerShell 网络请求",
        Some("powershell_webclient") => "PowerShell 网络客户端",
        Some("bits") => "后台智能传输服务",
        Some("curl") => "curl 下载",
        Some("wget") => "wget 下载",
        Some(_) => "其他下载方式",
        None => "未知",
    }
}

fn format_report_indices(indices: &[usize]) -> String {
    indices
        .iter()
        .map(|index| format!("#{}", index + 1))
        .collect::<Vec<_>>()
        .join("、")
}

fn display_excerpt(value: &str, max_characters: usize) -> String {
    let mut output = value.chars().take(max_characters).collect::<String>();
    if value.chars().count() > max_characters {
        output.push_str("...");
    }
    output
}

fn optional_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "未知".to_owned())
}

fn optional_text(value: Option<&str>) -> &str {
    value
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("未知")
}

fn localized_image_format(format: &str) -> &str {
    if format.starts_with("WindowsCrashDump64") {
        "Windows 64 位崩溃转储"
    } else if format.starts_with("Raw") {
        "原始内存镜像"
    } else if format.starts_with("Vmware") || format.starts_with("VMware") {
        "VMware 内存镜像"
    } else if format.starts_with("Lime") || format.starts_with("LiME") {
        "LiME 内存镜像"
    } else if format.starts_with("Ewf") || format.starts_with("EWF") {
        "EWF 镜像"
    } else {
        format
    }
}

fn print_forensic_time(label: &str, timestamp: &ForensicTimestamp) {
    let timezone = match (&timestamp.timezone, &timestamp.utc_offset) {
        (Some(name), Some(offset)) => format!("{name} / {offset}"),
        (Some(name), None) => name.clone(),
        (None, Some(offset)) => offset.clone(),
        (None, None) => "时区未知".to_owned(),
    };
    println!(
        "{label}（镜像本地，{timezone}）：{}",
        timestamp.image_local.as_deref().unwrap_or("未知")
    );
    println!(
        "{label}（UTC）：{}",
        timestamp.utc.as_deref().unwrap_or("未知")
    );
    println!(
        "  原始值：{}；格式：{}；来源：{}",
        timestamp
            .raw_value
            .map(|value| value.to_string())
            .unwrap_or_else(|| "未知".to_owned()),
        timestamp.raw_format,
        timestamp.source
    );
}

fn localized_product_type(value: Option<&str>) -> &'static str {
    match value {
        Some("workstation") => "工作站",
        Some("domain_controller") => "域控制器",
        Some("server") => "服务器",
        _ => "未知",
    }
}

fn format_byte_size(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB（{} 字节）", bytes as f64 / GIB, bytes)
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MiB（{} 字节）", bytes as f64 / MIB, bytes)
    } else {
        format!("{} 字节", bytes)
    }
}

fn format_duration(seconds: Option<f64>) -> String {
    let Some(seconds) = seconds.filter(|value| value.is_finite() && *value >= 0.0) else {
        return "未知".to_owned();
    };
    let total = seconds.floor() as u64;
    let days = total / 86_400;
    let hours = total % 86_400 / 3_600;
    let minutes = total % 3_600 / 60;
    let seconds = total % 60;
    format!("{days} 天 {hours:02} 小时 {minutes:02} 分 {seconds:02} 秒")
}

fn yes_no(value: bool) -> &'static str {
    if value { "是" } else { "否" }
}

fn format_linux_socket_endpoint(
    address: Option<&str>,
    port: Option<u16>,
    family_raw: u16,
) -> String {
    match (address, port) {
        (Some(address), Some(port)) if family_raw == 10 => format!("[{address}]:{port}"),
        (Some(address), Some(port)) => format!("{address}:{port}"),
        (Some(address), None) => address.to_owned(),
        (None, Some(port)) => format!("*:{port}"),
        (None, None) => "-".to_owned(),
    }
}

fn safe_terminal_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            output.push_str(&format!("\\u{{{:x}}}", character as u32));
        } else {
            output.push(character);
        }
    }
    output
}

fn optional_yes_no(value: Option<bool>) -> &'static str {
    value.map(yes_no).unwrap_or("未知")
}

fn cookie_source_name(source: CookieSource) -> &'static str {
    match source {
        CookieSource::RequestHeader => "请求头",
        CookieSource::ResponseHeader => "响应头",
        CookieSource::ChromiumDatabase => "Chromium 数据库",
        CookieSource::FirefoxDatabase => "Firefox 数据库",
        CookieSource::LegacyCookieFile => "旧式 Cookie 文件",
    }
}

fn localize_thread_state(state: &str) -> &str {
    match state {
        "initialized" => "已初始化",
        "ready" => "就绪",
        "running" => "运行中",
        "standby" => "待运行",
        "terminated" => "已终止",
        "waiting" => "等待中",
        "transition" => "转换中",
        "deferred_ready" => "延迟就绪",
        "gate_wait" => "门等待",
        "unknown" => "未知",
        _ => state,
    }
}

fn localize_runtime_message(message: &str) -> String {
    if let Some((subject, tail)) = message.split_once(" result limit ")
        && let Some(limit) = tail.strip_suffix(" reached")
    {
        return format!("{subject} 结果达到 {limit} 条上限");
    }
    match message {
        "Limit" => "达到数量上限".to_owned(),
        "None" => "无".to_owned(),
        "crashinfo requires a 64-bit Windows crash dump" => {
            "crashinfo 需要 64 位 Windows 崩溃转储".to_owned()
        }
        "ahcache.sys is not present in PsLoadedModuleList" => {
            "PsLoadedModuleList 中没有 ahcache.sys".to_owned()
        }
        "File pool-tag candidate limit was reached" => "File 池标签候选已达到数量上限".to_owned(),
        _ => message
            .replace(
                " mapped executable byte(s) were unavailable and not scanned",
                " 个已映射可执行字节不可用，未进行扫描",
            )
            .replace(" failed: ", " 失败：")
            .replace(" is unavailable", " 不可用")
            .replace(
                " is absent from PsLoadedModuleList",
                " 不在 PsLoadedModuleList 中",
            )
            .replace(
                "complete bucket-chain traversal reached",
                "完整桶链遍历恢复了",
            )
            .replace("unique endpoint(s)", "个唯一端点")
            .replace("record(s)", "条记录"),
    }
}

fn dump_source_name(source: DumpSource) -> &'static str {
    match source {
        DumpSource::Auto => "自动选择",
        DumpSource::Cache => "缓存",
        DumpSource::Data => "数据节区",
        DumpSource::Image => "映像节区",
        DumpSource::HiveMemory => "注册表内存",
    }
}

fn account_action_name(action: AccountAction) -> &'static str {
    match action {
        AccountAction::CreateUser => "创建用户",
        AccountAction::DeleteUser => "删除用户",
        AccountAction::EnableUser => "启用用户",
        AccountAction::DisableUser => "禁用用户",
        AccountAction::ModifyUser => "修改用户",
        AccountAction::ChangePassword => "修改密码",
        AccountAction::AddToGroup => "加入组",
        AccountAction::RemoveFromGroup => "移出组",
        AccountAction::CreateGroup => "创建组",
        AccountAction::DeleteGroup => "删除组",
    }
}

fn parse_hex(input: &str) -> Result<Vec<u8>> {
    let compact: String = input
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '_')
        .collect();
    ensure!(
        compact.len().is_multiple_of(2),
        "十六进制模式的数字个数不能为奇数"
    );
    let bytes = hex::decode(compact).context("无效的十六进制扫描模式")?;
    ensure!(!bytes.is_empty(), "扫描模式不能为空");
    Ok(bytes)
}

fn parse_integer(input: &str) -> Result<u64> {
    let input = input.replace('_', "");
    if let Some(hex) = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
    {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(input.parse()?)
    }
}

fn parse_signed_integer(input: &str) -> Result<i128> {
    let input = input.replace('_', "");
    let (negative, digits) = input
        .strip_prefix('-')
        .map(|digits| (true, digits))
        .unwrap_or((false, input.as_str()));
    let value = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        i128::from_str_radix(hex, 16)?
    } else {
        digits.parse::<i128>()?
    };
    if negative {
        value.checked_neg().context("有符号整数超出 i128 范围")
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn localized_cli_command() -> clap::Command {
        cli_command(false)
    }

    #[test]
    fn every_english_help_page_is_translated() {
        fn record(text: impl ToString, missing: &mut BTreeSet<String>) {
            let text = text.to_string();
            if text
                .chars()
                .any(|ch| ('\u{3400}'..='\u{9fff}').contains(&ch))
            {
                missing.insert(text);
            }
        }

        fn visit(command: &clap::Command, missing: &mut BTreeSet<String>) {
            if let Some(about) = command.get_about() {
                record(about, missing);
            }
            for argument in command.get_arguments() {
                if let Some(help) = argument.get_help() {
                    record(help, missing);
                }
                for name in argument.get_value_names().into_iter().flatten() {
                    record(name, missing);
                }
            }
            for child in command.get_subcommands() {
                visit(child, missing);
            }
        }

        let mut missing = BTreeSet::new();
        visit(&cli_command(true), &mut missing);
        assert!(
            missing.is_empty(),
            "Untranslated English help strings:\n{}",
            missing.into_iter().collect::<Vec<_>>().join("\n")
        );
    }

    #[test]
    fn english_help_selects_the_requested_page() {
        for (path, usage, description) in [
            (&[][..], "Usage: starmem", "Fast memory forensics engine."),
            (
                &["pslist"][..],
                "Usage: starmem pslist",
                "Memory image file to analyze.",
            ),
            (
                &["symbols", "linux"][..],
                "Usage: starmem symbols linux",
                "Disable all remote access.",
            ),
            (
                &["linux-info"][..],
                "Usage: starmem linux.info",
                "kernel version",
            ),
        ] {
            let args = std::iter::once("starmem")
                .chain(path.iter().copied())
                .chain(["--help-en"])
                .map(OsString::from)
                .collect::<Vec<_>>();
            assert!(wants_english_help(&args));
            let error = cli_command(true).try_get_matches_from(args).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
            let help = error.render().to_string();
            assert!(help.contains(usage) && help.contains(description), "{help}");
            assert!(!help.contains("用法"), "{help}");
        }

        let literal = ["starmem", "info", "--", "--help-en"].map(OsString::from);
        assert!(!wants_english_help(&literal));
        let matches = localized_cli_command()
            .try_get_matches_from(literal)
            .unwrap();
        assert_eq!(
            matches
                .subcommand_matches("info")
                .unwrap()
                .get_one::<PathBuf>("image"),
            Some(&PathBuf::from("--help-en"))
        );
    }

    #[test]
    fn every_help_page_uses_chinese_ui_text() {
        fn check(command: &mut clap::Command) {
            let name = command.get_name().to_owned();
            let mut buffer = Vec::new();
            command.write_long_help(&mut buffer).unwrap();
            let help = localize_generated_text(&String::from_utf8(buffer).unwrap());

            assert!(help.contains("用法："), "{name} 缺少中文用法标题");
            for english in [
                "Usage:",
                "Commands:",
                "Options:",
                "Arguments:",
                "Print help",
                "Print version",
                "[OPTIONS]",
                "<COMMAND>",
                "[COMMAND]",
            ] {
                assert!(
                    !help.contains(english),
                    "{name} 的帮助中仍包含英文界面文字 {english:?}\n{help}"
                );
            }

            for subcommand in command.get_subcommands_mut() {
                check(subcommand);
            }
        }

        check(&mut localized_cli_command());
    }

    #[test]
    fn every_help_argument_has_a_description() {
        fn check(command: &clap::Command) {
            for argument in command.get_arguments() {
                assert!(
                    argument.get_help().is_some(),
                    "{} 的参数 {} 缺少帮助说明",
                    command.get_name(),
                    argument.get_id()
                );
            }
            for subcommand in command.get_subcommands() {
                check(subcommand);
            }
        }

        check(&localized_cli_command());
    }

    #[test]
    fn every_plugin_command_supports_csv_output() {
        let command = localized_cli_command();
        assert!(
            command
                .get_arguments()
                .any(|argument| argument.get_id() == "csv")
        );
        for plugin in command
            .get_subcommands()
            .filter(|subcommand| subcommand.get_name() != "help")
        {
            assert!(
                plugin
                    .get_arguments()
                    .any(|argument| argument.get_id() == "csv"),
                "{} 没有继承全局 CSV 输出参数",
                plugin.get_name()
            );
        }
    }

    #[test]
    fn every_leaf_command_has_an_explicit_collection_disposition() {
        fn leaves(command: &clap::Command, prefix: &str, output: &mut HashSet<String>) {
            for child in command
                .get_subcommands()
                .filter(|child| child.get_name() != "help")
            {
                let id = if prefix.is_empty() {
                    child.get_name().to_owned()
                } else {
                    format!("{prefix}.{}", child.get_name())
                };
                if child
                    .get_subcommands()
                    .any(|leaf| leaf.get_name() != "help")
                {
                    leaves(child, &id, output);
                } else {
                    output.insert(id);
                }
            }
        }
        let command = localized_cli_command();
        let mut cli_names = HashSet::new();
        leaves(&command, "", &mut cli_names);
        let catalog = starmem::collection::collection_plugin_catalog();
        let catalog_names = catalog
            .iter()
            .map(|plugin| plugin.name.to_owned())
            .collect::<HashSet<_>>();
        let registry = starmem::command_registry::CommandRegistry::load_embedded()
            .expect("内置命令注册表必须有效");
        let registry_names = registry
            .command_ids()
            .map(str::to_owned)
            .collect::<HashSet<_>>();

        assert_eq!(catalog_names.len(), catalog.len(), "collect 目录含重复命令");
        assert_eq!(
            cli_names, registry_names,
            "CLI 与版本化命令注册表必须覆盖同一组叶子命令"
        );
        let mut collectable_cli_names = cli_names;
        assert!(collectable_cli_names.remove("collect"));
        assert_eq!(
            collectable_cli_names, catalog_names,
            "除 collect 自身外，每个 CLI 叶子命令都必须在 collect 目录中标为 runnable 或 skipped"
        );
        for plugin in &catalog {
            let declared = &registry.by_id(plugin.name).unwrap().collect_disposition;
            assert!(
                matches!(
                    (declared, plugin.disposition),
                    (
                        starmem::command_registry::CollectDisposition::Runnable,
                        starmem::collection::CollectionPluginDisposition::Runnable
                    ) | (
                        starmem::command_registry::CollectDisposition::Skipped,
                        starmem::collection::CollectionPluginDisposition::Skipped
                    )
                ),
                "{} 的 manifest 与 collect disposition 不一致",
                plugin.name
            );
        }
    }

    #[test]
    fn leaf_command_manifest_matches_the_real_clap_tree() {
        fn value_type(argument: &clap::Arg, name: &str) -> &'static str {
            if matches!(
                argument.get_action(),
                clap::ArgAction::SetTrue | clap::ArgAction::SetFalse | clap::ArgAction::Count
            ) {
                return "boolean";
            }
            if matches!(
                name,
                "dtb"
                    | "kernel-slide"
                    | "base"
                    | "address"
                    | "object"
                    | "task"
                    | "namespace"
                    | "file-object"
                    | "offset"
                    | "record"
                    | "qevm-above-4g-base"
            ) {
                return "address";
            }
            if name.contains("time")
                || name.contains("since")
                || name.contains("until")
                || matches!(name, "from" | "to")
            {
                return "timestamp";
            }
            if matches!(
                name,
                "text" | "hex" | "regex" | "rule" | "pattern" | "query"
            ) {
                return "pattern";
            }
            if matches!(
                name,
                "output"
                    | "output-dir"
                    | "framebuffer-output"
                    | "database"
                    | "db"
                    | "csv"
                    | "raw-objects"
                    | "cache"
            ) {
                return "output_path";
            }
            if name.contains("limit")
                || name.starts_with("max-")
                || matches!(
                    name,
                    "pid"
                        | "entries"
                        | "threads"
                        | "chunk-mib"
                        | "context-bytes"
                        | "session-id"
                        | "index"
                        | "length"
                        | "age"
                        | "correlation-window-ms"
                        | "overlap-kib"
                )
            {
                return "integer";
            }
            if matches!(
                name,
                "source"
                    | "view"
                    | "table"
                    | "feature"
                    | "severity"
                    | "format"
                    | "action"
                    | "min-severity"
                    | "offset-kind"
                    | "encoding"
            ) {
                return "choice";
            }
            // A string path can select a file inside the captured filesystem.
            if name == "path"
                && argument.get_value_parser().type_id()
                    == clap::builder::ValueParser::string().type_id()
            {
                return "string";
            }
            if name == "image"
                || name.contains("file")
                || name.contains("path")
                || name.contains("root")
                || matches!(
                    name,
                    "input"
                        | "pdb"
                        | "profile"
                        | "isf"
                        | "hive"
                        | "system"
                        | "sam"
                        | "security"
                        | "logs"
                        | "metadata"
                        | "strings"
                        | "verification"
                )
            {
                return "path";
            }
            "string"
        }

        fn visit(command: &clap::Command, prefix: &[String], output: &mut Vec<serde_json::Value>) {
            const GLOBAL_ARGUMENTS: &[&str] = &[
                "json",
                "csv",
                "threads",
                "no_progress",
                "force",
                "raw_objects",
                "metadata",
                "qevm_ram_block",
                "qevm_below_4g_length",
                "qevm_above_4g_base",
                "help",
                "help_en",
                "version",
            ];
            for child in command
                .get_subcommands()
                .filter(|child| child.get_name() != "help")
            {
                let mut path = prefix.to_vec();
                path.push(child.get_name().to_owned());
                if child
                    .get_subcommands()
                    .any(|subcommand| subcommand.get_name() != "help")
                {
                    visit(child, &path, output);
                    continue;
                }
                let command_id = path.join(".");
                let mut aliases = child
                    .get_all_aliases()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                aliases.sort();
                let arguments = child
                    .get_arguments()
                    .filter(|argument| !GLOBAL_ARGUMENTS.contains(&argument.get_id().as_str()))
                    .map(|argument| {
                        let name = argument
                            .get_long()
                            .unwrap_or(argument.get_id().as_str())
                            .replace('_', "-");
                        serde_json::json!({
                            "name": name,
                            "value_type": value_type(argument, &name),
                            "required": argument.is_required_set(),
                            "repeatable": matches!(
                                argument.get_action(),
                                clap::ArgAction::Append | clap::ArgAction::Count
                            ),
                        })
                    })
                    .collect::<Vec<_>>();
                output.push(serde_json::json!({
                    "command_id": command_id,
                    "cli_path": path,
                    "aliases": aliases,
                    "help": child.get_about().map(ToString::to_string).unwrap_or_default(),
                    "arguments": arguments,
                }));
            }
        }

        let mut commands = Vec::new();
        visit(&localized_cli_command(), &[], &mut commands);
        let registry = starmem::command_registry::CommandRegistry::load_embedded()
            .expect("内置叶子命令 manifest 必须有效");
        assert_eq!(commands.len(), registry.len());
        for cli in commands {
            let command_id = cli["command_id"].as_str().unwrap();
            let contract = registry
                .by_id(command_id)
                .unwrap_or_else(|| panic!("manifest 缺少 CLI 叶子命令 {command_id}"));
            assert_eq!(
                serde_json::to_value(&contract.cli_path).unwrap(),
                cli["cli_path"],
                "{command_id} cli_path"
            );
            assert_eq!(
                serde_json::to_value(&contract.aliases.values).unwrap(),
                cli["aliases"],
                "{command_id} aliases"
            );
            assert_eq!(
                contract.help.value.as_deref(),
                cli["help"].as_str(),
                "{command_id} help"
            );
            assert_eq!(
                serde_json::to_value(&contract.arguments.items).unwrap(),
                cli["arguments"],
                "{command_id} arguments"
            );
        }
    }

    #[test]
    fn progress_bar_formats_percentage_bytes_and_eta() {
        let now = Instant::now();
        let task = TerminalProgressTask {
            label: "物理扫描 memory.raw".to_owned(),
            total: 1024 * 1024 * 1024,
            current: 512 * 1024 * 1024,
            started: now - Duration::from_secs(2),
            last_draw: now,
        };
        let line = render_terminal_progress(&task, None);
        assert!(line.contains("50.0%"));
        assert!(line.contains("512.0MiB/1.00GiB"));
        assert!(line.contains("ETA"));

        let complete = render_terminal_progress(&task, Some(true));
        assert!(complete.contains("100.0%"));
        assert!(complete.contains("完成（提前）"));
    }

    #[test]
    fn plugin_evidence_scope_limits_and_linux_symbol_identity_are_preserved() {
        let mut configured = EvidenceLimit::new("modules", EvidenceLimitKind::Output);
        configured.configured = Some(128);
        let mut reported = EvidenceLimit::new("modules", EvidenceLimitKind::Output);
        reported.observed = Some(12);
        reported.reached = Some(false);
        let merged = merge_evidence_limits(&[configured], vec![reported]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].configured, Some(128));
        assert_eq!(merged[0].observed, Some(12));
        assert_eq!(merged[0].reached, Some(false));

        let canonical = "a".repeat(64);
        let isf = "b".repeat(64);
        let report = serde_json::json!({
            "kernel_session": {
                "symbol_identity": {
                    "schema_version": 1,
                    "provider": "volatility3_isf",
                    "format": "6.2.0",
                    "producer": "dwarf2json",
                    "banner_sha256": "c".repeat(64),
                    "isf_sha256": isf,
                    "vmlinux_sha256": ["d".repeat(64)],
                    "features": ["modules"],
                    "canonical_sha256": canonical,
                }
            }
        });
        let identity = linux_symbol_identity_from_report(report.as_object()).unwrap();
        assert_eq!(identity.kind, "linux_isf");
        assert_eq!(identity.key, "a".repeat(64));
        assert_eq!(identity.digest.unwrap().value, "b".repeat(64));
        assert_eq!(identity.details["provider"], "volatility3_isf");
    }

    #[test]
    fn memory_source_identity_does_not_serialize_absolute_paths() {
        let path = std::env::temp_dir().join(format!(
            "starmem-source-identity-{}-{}.raw",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, b"portable source identity").unwrap();
        let identity = source_identity_for_path(&path, "image").unwrap();
        let serialized = serde_json::to_string(&identity).unwrap();
        assert!(!serialized.contains(&path.display().to_string()));
        assert_eq!(identity.components.len(), 1);
        assert_eq!(
            identity.components[0].name,
            path.file_name().unwrap().to_string_lossy()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn cli_accepts_global_no_progress_after_a_subcommand() {
        let matches = localized_cli_command()
            .try_get_matches_from(["starmem", "linux.pstree", "memory.lime", "--no-progress"])
            .unwrap();
        assert!(matches.get_flag("no_progress"));
    }

    #[test]
    fn clipboardscan_does_not_accept_text_search_options() {
        let result = localized_cli_command().try_get_matches_from([
            "starmem",
            "clipboardscan",
            "memory.raw",
            "--text",
            "not-clipboard-evidence",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn residualscan_accepts_repeated_exact_text_searches() {
        let matches = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "residualscan",
                "memory.raw",
                "--text",
                "第一条",
                "--text",
                "second",
            ])
            .unwrap();
        let (_, residual) = matches.subcommand().unwrap();
        let values = residual
            .get_many::<String>("search_texts")
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(values, ["第一条", "second"]);
    }

    #[test]
    fn linux_passwd_accepts_the_literal_dotted_command() {
        let matches = localized_cli_command()
            .try_get_matches_from(["starmem", "linux.passwd", "memory.lime"])
            .unwrap();
        assert_eq!(matches.subcommand_name(), Some("linux.passwd"));
    }

    #[test]
    fn windows_timeline_accepts_dotted_command_alias_and_filters() {
        let dotted = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "windows.timeline",
                "memory.raw",
                "--source",
                "process,thread,registry",
                "--pid",
                "42",
                "--from",
                "2026-08-01",
                "--to",
                "2026-08-26T12:00:00Z",
                "--include-accessed",
                "--registry-limit",
                "4096",
                "--reverse",
            ])
            .unwrap();
        assert_eq!(dotted.subcommand_name(), Some("windows.timeline"));

        let alias = localized_cli_command()
            .try_get_matches_from(["starmem", "windows-timeline", "memory.raw"])
            .unwrap();
        assert_eq!(alias.subcommand_name(), Some("windows.timeline"));
    }

    #[test]
    fn windows_execution_accepts_sources_exact_filter_and_alias() {
        let dotted = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "windows.execution",
                "memory.raw",
                "--source",
                "prefetch,bam-dam,userassist",
                "--exact-only",
                "--from",
                "2026-08-01",
                "--to",
                "2026-08-26",
                "--prefetch-limit",
                "512",
                "--aggregate",
                "--program",
                "veracrypt",
                "--user",
                "testuser",
                "--correlation-window-ms",
                "2000",
                "--latest-per-program",
            ])
            .unwrap();
        assert_eq!(dotted.subcommand_name(), Some("windows.execution"));

        let alias = localized_cli_command()
            .try_get_matches_from(["starmem", "windows-execution", "memory.raw"])
            .unwrap();
        assert_eq!(alias.subcommand_name(), Some("windows.execution"));
    }

    #[test]
    fn windows_forensic_shortcuts_accept_their_new_evidence_options() {
        let recent = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "windows.recent-files",
                "memory.raw",
                "--source",
                "wps,recentdocs",
                "--user",
                "testuser",
                "--path-contains",
                "示例表格.xlsx",
            ])
            .unwrap();
        assert_eq!(recent.subcommand_name(), Some("windows.recent-files"));

        let usb = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "usb-history",
                "memory.raw",
                "--serial",
                "21117M402412",
                "--strict-last-arrival",
            ])
            .unwrap();
        assert_eq!(usb.subcommand_name(), Some("usb-history"));

        let acquisition = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "acquisition-info",
                "memory.raw",
                "--include-host-times",
                "--handle-limit",
                "10000",
            ])
            .unwrap();
        assert_eq!(acquisition.subcommand_name(), Some("acquisition-info"));
    }

    #[test]
    fn windows_process_string_accepts_literal_encodings_limits_and_alias() {
        let dotted = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "windows.process-string",
                "memory.raw",
                "--text",
                "维斯塔斯",
                "--encoding",
                "utf16le",
                "--scan-hit-limit",
                "100000",
                "--process-limit",
                "4096",
                "--mapping-limit",
                "32",
                "--reverse-entry-limit",
                "12000000",
                "--reverse-alias-limit",
                "750000",
                "--context-bytes",
                "64",
            ])
            .unwrap();
        assert_eq!(dotted.subcommand_name(), Some("windows.process-string"));

        let alias = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "process-string",
                "memory.raw",
                "--text",
                "StarMem",
            ])
            .unwrap();
        assert_eq!(alias.subcommand_name(), Some("windows.process-string"));
    }

    #[test]
    fn browser_history_accepts_visit_and_owner_views() {
        let command = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "browser-history",
                "memory.raw",
                "--view",
                "visits",
                "--owners",
                "--process-limit",
                "4096",
                "--handle-scan-limit",
                "100000",
            ])
            .unwrap();
        assert_eq!(command.subcommand_name(), Some("browser-history"));

        let missing_owners = localized_cli_command().try_get_matches_from([
            "starmem",
            "browser-history",
            "memory.raw",
            "--handle-scan-limit",
            "100000",
        ]);
        assert!(missing_owners.is_err());
    }

    #[test]
    fn object_open_file_and_sqlite_recovery_arguments_are_unambiguous() {
        let handles = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "handles",
                "memory.raw",
                "--object",
                "0xfffffa801af6c530",
            ])
            .unwrap();
        assert_eq!(handles.subcommand_name(), Some("handles"));

        let open_files = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "windows.open-files",
                "memory.raw",
                "--path-contains",
                "History",
            ])
            .unwrap();
        assert_eq!(open_files.subcommand_name(), Some("windows.open-files"));

        let sqlite = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "sqlite-recover",
                "memory.raw",
                "--file-object",
                "0xfffffa801af6c530",
                "--output-dir",
                "recovered",
                "--table",
                "urls",
            ])
            .unwrap();
        assert_eq!(sqlite.subcommand_name(), Some("sqlite-recover"));

        let ambiguous = localized_cli_command().try_get_matches_from([
            "starmem",
            "sqlite-recover",
            "memory.raw",
            "--file-object",
            "0xfffffa801af6c530",
            "--path-contains",
            "History",
            "--output-dir",
            "recovered",
        ]);
        assert!(ambiguous.is_err());
    }

    #[test]
    fn windows_pipe_and_prefetch_scanners_accept_safety_limits() {
        let pipes = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "pipescan",
                "memory.raw",
                "--handle-scan-limit",
                "10000",
            ])
            .unwrap();
        assert_eq!(pipes.subcommand_name(), Some("pipescan"));

        let prefetch = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "prefetchscan",
                "memory.raw",
                "--reference-limit",
                "512",
            ])
            .unwrap();
        assert_eq!(prefetch.subcommand_name(), Some("prefetchscan"));
    }

    #[test]
    fn logonsessions_accepts_independent_process_and_result_limits() {
        let command = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "logonsessions",
                "memory.raw",
                "--process-limit",
                "65536",
                "--limit",
                "4096",
            ])
            .unwrap();
        assert_eq!(command.subcommand_name(), Some("logonsessions"));

        let alias = localized_cli_command()
            .try_get_matches_from(["starmem", "logon-sessions", "memory.raw"])
            .unwrap();
        assert_eq!(alias.subcommand_name(), Some("logonsessions"));
    }

    #[test]
    fn token_anomalies_accepts_alias_filters_and_independent_limits() {
        let command = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "token-anomalies",
                "memory.raw",
                "--process-limit",
                "65536",
                "--direct-only",
                "--min-severity",
                "high",
                "--limit",
                "4096",
            ])
            .unwrap();
        assert_eq!(command.subcommand_name(), Some("token-anomalies"));

        let alias = localized_cli_command()
            .try_get_matches_from(["starmem", "tokenanomalies", "memory.raw"])
            .unwrap();
        assert_eq!(alias.subcommand_name(), Some("token-anomalies"));
    }

    #[test]
    fn callbacks_accepts_result_limit_and_progress_control() {
        let command = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "callbacks",
                "memory.raw",
                "--limit",
                "4096",
                "--no-progress",
            ])
            .unwrap();
        assert_eq!(command.subcommand_name(), Some("callbacks"));
    }

    #[test]
    fn autoruns_accepts_alias_and_evidence_options() {
        let command = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "autoruns",
                "memory.raw",
                "--process-limit",
                "65536",
                "--service-memory",
                "--service-scan-limit",
                "4096",
                "--include-task-candidates",
                "--limit",
                "2048",
            ])
            .unwrap();
        assert_eq!(command.subcommand_name(), Some("autoruns"));

        let alias = localized_cli_command()
            .try_get_matches_from(["starmem", "autorun", "memory.raw"])
            .unwrap();
        assert_eq!(alias.subcommand_name(), Some("autoruns"));
    }

    #[test]
    fn linux_sockstat_accepts_dotted_command_and_hyphen_alias() {
        let dotted = localized_cli_command()
            .try_get_matches_from(["starmem", "linux.sockstat", "memory.lime", "--pid", "1"])
            .unwrap();
        assert_eq!(dotted.subcommand_name(), Some("linux.sockstat"));

        let alias = localized_cli_command()
            .try_get_matches_from(["starmem", "linux-sockstat", "memory.lime"])
            .unwrap();
        assert_eq!(alias.subcommand_name(), Some("linux.sockstat"));
    }

    #[test]
    fn linux_pstree_accepts_dotted_command_alias_and_pid_filter() {
        let dotted = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "linux.pstree",
                "memory.lime",
                "--pid",
                "42",
                "--limit",
                "4096",
            ])
            .unwrap();
        assert_eq!(dotted.subcommand_name(), Some("linux.pstree"));

        let alias = localized_cli_command()
            .try_get_matches_from(["starmem", "linux-pstree", "memory.lime"])
            .unwrap();
        assert_eq!(alias.subcommand_name(), Some("linux.pstree"));
    }

    #[test]
    fn linux_kernel_global_plugins_accept_their_scoped_arguments_and_aliases() {
        let cases: &[(&[&str], &str)] = &[
            (
                &[
                    "starmem",
                    "linux.lsmod",
                    "memory.lime",
                    "--dtb",
                    "0x1000",
                    "--kernel-slide",
                    "0x200000",
                    "--limit",
                    "4096",
                ],
                "linux.lsmod",
            ),
            (
                &[
                    "starmem",
                    "linux-module-extract",
                    "memory.lime",
                    "--name",
                    "ext4",
                    "--output",
                    "ext4.ko",
                    "--max-bytes",
                    "1048576",
                    "--force",
                ],
                "linux.module-extract",
            ),
            (
                &[
                    "starmem",
                    "linux.mountinfo",
                    "memory.lime",
                    "--pid",
                    "1",
                    "--task",
                    "0xffff888000001000",
                    "--limit",
                    "8192",
                ],
                "linux.mountinfo",
            ),
            (
                &[
                    "starmem",
                    "linux-kallsyms",
                    "memory.lime",
                    "--limit",
                    "200000",
                ],
                "linux.kallsyms",
            ),
            (
                &[
                    "starmem",
                    "linux.kmsg",
                    "memory.lime",
                    "--boot-time-unix-ns",
                    "1720000000000000000",
                ],
                "linux.kmsg",
            ),
            (
                &["starmem", "linux-modxview", "memory.lime"],
                "linux.modxview",
            ),
            (
                &[
                    "starmem",
                    "linux.check-syscall",
                    "memory.lime",
                    "--table",
                    "ia32",
                    "--entries",
                    "512",
                    "--no-modules",
                ],
                "linux.check-syscall",
            ),
        ];

        for (arguments, expected) in cases {
            let matches = localized_cli_command()
                .try_get_matches_from(arguments.iter().copied())
                .unwrap_or_else(|error| panic!("{arguments:?}: {error}"));
            assert_eq!(matches.subcommand_name(), Some(*expected));
        }
    }

    #[test]
    fn linux_module_extract_requires_exactly_one_selector_and_a_byte_limit() {
        for arguments in [
            vec![
                "starmem",
                "linux.module-extract",
                "memory.lime",
                "--output",
                "module.ko",
                "--max-bytes",
                "4096",
            ],
            vec![
                "starmem",
                "linux.module-extract",
                "memory.lime",
                "--name",
                "ext4",
                "--base",
                "0xffffffffc0000000",
                "--output",
                "module.ko",
                "--max-bytes",
                "4096",
            ],
            vec![
                "starmem",
                "linux.module-extract",
                "memory.lime",
                "--name",
                "ext4",
                "--output",
                "module.ko",
            ],
        ] {
            assert!(
                localized_cli_command()
                    .try_get_matches_from(arguments)
                    .is_err()
            );
        }
    }

    #[test]
    fn linux_mountinfo_rejects_ambiguous_namespace_and_task_filters() {
        let result = localized_cli_command().try_get_matches_from([
            "starmem",
            "linux.mountinfo",
            "memory.lime",
            "--task",
            "0xffff888000001000",
            "--namespace",
            "0xffff888000002000",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn signed_integer_parser_supports_decimal_and_hex_nanoseconds() {
        assert_eq!(parse_signed_integer("1_000").unwrap(), 1000);
        assert_eq!(parse_signed_integer("-0x10").unwrap(), -16);
    }

    #[test]
    fn linux_psaux_accepts_dotted_command_and_hyphen_alias() {
        let dotted = localized_cli_command()
            .try_get_matches_from(["starmem", "linux.psaux", "memory.lime", "--pid", "1"])
            .unwrap();
        assert_eq!(dotted.subcommand_name(), Some("linux.psaux"));

        let alias = localized_cli_command()
            .try_get_matches_from(["starmem", "linux-psaux", "memory.lime"])
            .unwrap();
        assert_eq!(alias.subcommand_name(), Some("linux.psaux"));
    }

    #[test]
    fn linux_kaslr_accepts_dotted_command_and_hyphen_alias() {
        let dotted = localized_cli_command()
            .try_get_matches_from(["starmem", "linux.kaslr", "memory.mem"])
            .unwrap();
        assert_eq!(dotted.subcommand_name(), Some("linux.kaslr"));

        let alias = localized_cli_command()
            .try_get_matches_from(["starmem", "linux-kaslr", "memory.mem"])
            .unwrap();
        assert_eq!(alias.subcommand_name(), Some("linux.kaslr"));
    }

    #[test]
    fn linux_info_accepts_dotted_command_and_hyphen_alias() {
        let dotted = localized_cli_command()
            .try_get_matches_from(["starmem", "linux.info", "memory.mem"])
            .unwrap();
        assert_eq!(dotted.subcommand_name(), Some("linux.info"));

        let alias = localized_cli_command()
            .try_get_matches_from(["starmem", "linux-info", "memory.mem"])
            .unwrap();
        assert_eq!(alias.subcommand_name(), Some("linux.info"));
    }

    #[test]
    fn linux_dumpfile_alias_uses_the_existing_dumpfile_command() {
        let matches = localized_cli_command()
            .try_get_matches_from([
                "starmem",
                "linux.dumpfile",
                "memory.lime",
                "--address",
                "0xffff888010001000",
                "--output",
                "passwd",
            ])
            .unwrap();
        assert_eq!(matches.subcommand_name(), Some("dumpfile"));
    }

    #[test]
    fn terminal_text_escapes_control_characters() {
        assert_eq!(safe_terminal_text("ok\u{1b}[31m\n"), "ok\\u{1b}[31m\\u{a}");
        assert_eq!(safe_terminal_text("中文/path"), "中文/path");
    }

    #[test]
    fn output_path_conflict_detects_relative_aliases() {
        assert!(output_paths_conflict(
            Path::new("artifact.bin"),
            Path::new("./artifact.bin")
        ));
        assert!(!output_paths_conflict(
            Path::new("artifact.bin"),
            Path::new("artifact.csv")
        ));
    }

    #[test]
    fn central_csv_guard_covers_top_level_collect_and_nested_image_commands() {
        let cases: &[&[&str]] = &[
            &["starmem", "info", "memory.raw", "--csv", "./memory.raw"],
            &[
                "starmem",
                "collect",
                "memory.raw",
                "--db",
                "evidence.sqlite",
                "--csv",
                "./memory.raw",
            ],
            &[
                "starmem",
                "symbols",
                "id",
                "memory.raw",
                "--csv",
                "./memory.raw",
            ],
        ];

        for arguments in cases {
            let matches = localized_cli_command()
                .try_get_matches_from(arguments.iter().copied())
                .unwrap();
            assert_eq!(
                matched_path_argument(&matches, "image"),
                Some(Path::new("memory.raw"))
            );
            let error = ensure_matched_csv_does_not_overwrite_image(&matches).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("--csv 报告路径不能与输入内存镜像相同"),
                "unexpected error for {arguments:?}: {error:#}"
            );
        }
    }

    #[test]
    fn central_csv_guard_allows_stdout_for_image_commands() {
        let matches = localized_cli_command()
            .try_get_matches_from(["starmem", "info", "memory.raw", "--csv", "-"])
            .unwrap();
        ensure_matched_csv_does_not_overwrite_image(&matches).unwrap();
    }

    #[test]
    fn output_path_conflict_detects_hard_link_identity() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "starmem-hardlink-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let image = directory.join("memory.lime");
        let alias = directory.join("report.csv");
        fs::write(&image, b"evidence").unwrap();
        if fs::hard_link(&image, &alias).is_ok() {
            assert!(output_paths_conflict(&image, &alias));
            let matches = localized_cli_command()
                .try_get_matches_from([
                    std::ffi::OsString::from("starmem"),
                    std::ffi::OsString::from("info"),
                    image.as_os_str().to_owned(),
                    std::ffi::OsString::from("--csv"),
                    alias.as_os_str().to_owned(),
                ])
                .unwrap();
            assert!(ensure_matched_csv_does_not_overwrite_image(&matches).is_err());
            assert_eq!(fs::read(&image).unwrap(), b"evidence");
            fs::remove_file(&alias).unwrap();
        }
        fs::remove_file(&image).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
}
