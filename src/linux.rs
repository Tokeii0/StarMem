use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

use crate::cancellation::CancellationToken;
use crate::image::{ExpertWitnessMedia, ImageFormat, MemoryImage};
use crate::linux_kernel_plugins::LinuxKernelSession;
use crate::linux_symbols::{
    LinuxIsf, LinuxIsfWarning, LinuxSymbolFeature, LinuxSymbolIdentity, resolve_linux_isf,
    resolve_linux_isf_for_features, resolve_remote_linux_isf,
};
use crate::scan::scan_patterns;
use crate::symbols::{SymbolStore, default_symbol_store};

mod system_map;

const PAGE_SIZE: u64 = 0x1000;
const ADDRESS_MASK_4K: u64 = 0x000f_ffff_ffff_f000;
const ADDRESS_MASK_2M: u64 = 0x000f_ffff_ffe0_0000;
const ADDRESS_MASK_1G: u64 = 0x000f_ffff_c000_0000;
const DISCOVERY_CHUNK_SIZE: usize = 64 * 1024 * 1024;
const DISCOVERY_LIMIT_PER_PATTERN: usize = 32 * 1024;
const MAX_BTF_SIZE: usize = 64 * 1024 * 1024;

const LINUX_BANNER_PATTERN: &[u8] = b"Linux version ";
const BTF_HEADER_PATTERN: &[u8] = b"\x9f\xeb\x01\x00";
const SWAPPER_PATTERN: &[u8] = b"swapper";
const VMCOREINFO_PATTERN: &[u8] = b"OSRELEASE=";
const X86_KERNEL_IMAGE_BASE: u64 = 0xffff_ffff_8000_0000;

pub(crate) const UBUNTU_5_4_0_84_BIONIC: &str = "Linux version 5.4.0-84-generic (buildd@lcy01-amd64-007) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #94~18.04.1-Ubuntu SMP Thu Aug 26 23:17:46 UTC 2021 (Ubuntu 5.4.0-84.94~18.04.1-generic 5.4.133)";
pub(crate) const UBUNTU_4_13_0_36_XENIAL: &str = "Linux version 4.13.0-36-generic (buildd@lgw01-amd64-033) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.9)) #40~16.04.1-Ubuntu SMP Fri Feb 16 23:25:58 UTC 2018 (Ubuntu 4.13.0-36.40~16.04.1-generic 4.13.13)";
pub(crate) const UBUNTU_6_8_0_49_NOBLE: &str = "Linux version 6.8.0-49-generic (buildd@lcy02-amd64-028) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #49-Ubuntu SMP PREEMPT_DYNAMIC Mon Nov  4 02:06:24 UTC 2024 (Ubuntu 6.8.0-49.49-generic 6.8.12)";
pub(crate) const DEEPIN_4_9_0_57_1: &str = "Linux version 4.9.0-deepin13-amd64 (yangbo@deepin.com) (gcc version 6.3.0 20170321 (Debian 6.3.0-11) ) #1 SMP PREEMPT Deepin 4.9.57-1 (2017-10-19) ()";

#[derive(Debug, Clone, Serialize)]
pub struct LinuxKernelContext {
    pub architecture: String,
    pub banner: String,
    pub banner_physical_address: u64,
    pub directory_table_base: u64,
    pub page_table_source: String,
    pub vmcoreinfo_physical_address: Option<u64>,
    pub init_task: u64,
    pub init_task_physical: u64,
    pub profile_source: String,
    pub profile_fingerprint: String,
    pub btf_physical_address: Option<u64>,
    pub task_struct_size: u64,
    pub task_struct_offsets: BTreeMap<String, u64>,
    /// The exact Volatility 3 ISF selected for this image.  Reports retain the
    /// stable provenance fields above rather than serializing the large table.
    #[serde(skip)]
    pub symbol_table: Option<Arc<LinuxIsf>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_map: Option<crate::linux_system_map::LinuxSystemMapIdentity>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxProcessRecord {
    /// Runtime virtual address of the Linux `task_struct`.
    pub task: u64,
    /// Runtime virtual address of `task_struct.tasks` used as the list anchor.
    pub list_entry: u64,
    pub pid: i32,
    pub tgid: i32,
    pub ppid: Option<i32>,
    pub name: String,
    pub state: String,
    pub state_raw: u64,
    pub exit_state: Option<u32>,
    pub flags: Option<u32>,
    pub mm: Option<u64>,
    pub kernel_thread: Option<bool>,
    pub start_time_ns: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxProcessListStopReason {
    ListHead,
    Limit,
    Cycle,
    InvalidPointer,
    UnreadableEntry,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxProcessWarning {
    pub kind: String,
    pub message: String,
    pub list_entry: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct LinuxProcessListReport {
    pub kernel: LinuxKernelContext,
    pub processes: Vec<LinuxProcessRecord>,
    pub complete: bool,
    pub stop_reason: LinuxProcessListStopReason,
    pub warnings: Vec<LinuxProcessWarning>,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxProcessTreeRecord {
    pub depth: usize,
    pub task: u64,
    pub pid: i32,
    pub tgid: i32,
    pub ppid: Option<i32>,
    pub name: String,
    pub state: String,
    pub kernel_thread: Option<bool>,
    pub start_time_ns: Option<u64>,
    /// The recorded parent PID is non-zero but no matching active task exists.
    pub orphan_parent: bool,
    /// This task's parent chain contains a repeated PID.
    pub parent_cycle: bool,
}

#[derive(Debug, Serialize)]
pub struct LinuxProcessTreeReport {
    pub kernel: LinuxKernelContext,
    pub records: Vec<LinuxProcessTreeRecord>,
    pub source_process_count: usize,
    pub root_count: usize,
    pub orphan_count: usize,
    pub parent_cycle_count: usize,
    pub filtered_pid: Option<i32>,
    pub complete: bool,
    pub stop_reason: LinuxProcessListStopReason,
    pub warnings: Vec<LinuxProcessWarning>,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxKernelTextReport {
    pub architecture: String,
    pub banner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_map: Option<crate::linux_system_map::LinuxSystemMapIdentity>,
    pub symbol: String,
    pub virtual_address: u64,
    pub virtual_address_hex: String,
    pub physical_address: u64,
    pub physical_address_hex: String,
    pub symbol_source: String,
    pub translation_source: String,
    pub directory_table_base: u64,
    pub vmcoreinfo_physical_address: Option<u64>,
    pub kernel_offset: Option<u64>,
    pub phys_base: Option<u64>,
    pub first_bytes_hex: String,
    pub bytes_verified: usize,
    pub complete: bool,
}

/// Explicit overrides for opening a kernel-global Linux session.
///
/// Neither field changes the runtime validation policy: `_stext` must remain readable and the
/// runtime `linux_banner` must exactly match the selected ISF.  Supplying both fields makes the
/// opener independent of VMCOREINFO while still retaining that validation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinuxKernelSessionOptions {
    pub directory_table_base: Option<u64>,
    pub kernel_slide: Option<u64>,
}

/// Provenance for a kernel-global Linux session.
///
/// `symbol_identity` is stable and path-free.  Human-readable symbol diagnostics may still name
/// rejected local candidate paths and are therefore not part of that identity.
#[derive(Debug, Clone, Serialize)]
pub struct LinuxKernelSessionEvidence {
    pub architecture: String,
    pub banner: String,
    pub banner_physical_address: u64,
    pub directory_table_base: u64,
    pub page_table_source: String,
    pub kernel_slide: u64,
    pub kernel_slide_source: String,
    pub vmcoreinfo_physical_address: Option<u64>,
    pub requested_features: Vec<LinuxSymbolFeature>,
    pub symbol_identity: LinuxSymbolIdentity,
    pub symbol_files_considered: usize,
    pub symbol_warnings: Vec<LinuxIsfWarning>,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
}

/// A validated kernel-global Linux session and the evidence used to construct it.
///
/// With an ISF input, opening this value does not consult `task_struct.tasks`.
/// Explicit System.map inputs first require task-session validation and exact ISF completion.
pub struct OpenedLinuxKernelSession {
    pub session: LinuxKernelSession,
    pub evidence: LinuxKernelSessionEvidence,
}

#[derive(Debug, Clone)]
struct LinuxKernelTextEvidence {
    virtual_address: u64,
    physical_address: u64,
    symbol_source: String,
    kernel_offset: Option<u64>,
    phys_base: Option<u64>,
    first_bytes_hex: String,
    bytes_verified: usize,
}

/// A deliberately separate Linux session.  The existing `AnalysisSession`
/// remains Windows-specific so Linux pslist does not perturb the many Windows
/// plugins that share its PDB-derived context.
pub struct LinuxAnalysisSession {
    image: MemoryImage,
    profile: LinuxTaskProfile,
    kernel: LinuxKernelContext,
    warnings: Vec<LinuxProcessWarning>,
    scan: DiscoveryScanStats,
    kernel_text: Option<LinuxKernelTextEvidence>,
    kernel_text_diagnostic: Option<String>,
}

impl LinuxAnalysisSession {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::from_image(MemoryImage::open(path)?)
    }

    pub fn from_image(image: MemoryImage) -> Result<Self> {
        let symbols = default_symbol_store();
        Self::from_image_with_symbol_store(image, &symbols)
    }

    pub fn from_image_with_symbol_store(image: MemoryImage, symbols: &SymbolStore) -> Result<Self> {
        Self::from_image_with_symbol_store_cancellable(image, symbols, &CancellationToken::new())
    }

    pub fn from_image_with_symbol_store_cancellable(
        image: MemoryImage,
        symbols: &SymbolStore,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        cancellation.check_cancelled()?;
        ensure!(
            is_supported_linux_physical_image(&image),
            "Linux 分析仅支持 LiME、RAW、VMware VMEM 或物理内存 EWF 镜像"
        );
        if let Some(path) = symbols.linux_system_map() {
            ensure!(
                symbols.linux_isf().is_none(),
                "不能同时指定 Linux ISF 和 System.map"
            );
            return system_map::open_with_symbols(image, path, symbols, cancellation);
        }
        let discovery = scan_linux_anchors_with_policy(&image, true, cancellation)?;
        let banners = discovery
            .banners
            .iter()
            .map(|banner| banner.text.clone())
            .collect::<Vec<_>>();
        let mut resolution = resolve_linux_isf(symbols, &banners)?;
        // 基础内置布局不能替代 cred、网络与跟踪等完整类型；仍允许精确 ISF 自动补齐。
        if resolution.table.is_none() {
            let remote = resolve_remote_linux_isf(symbols, &banners)?;
            resolution.files_considered = resolution
                .files_considered
                .saturating_add(remote.files_considered);
            resolution.warnings.extend(remote.warnings);
            resolution.table = remote.table;
        }
        let mut symbol_table = resolution.table;
        let profile_selection = select_profile(&image, &discovery, symbol_table.as_deref());
        let (mut profile, mut selected_banner, profile_warning) = match profile_selection {
            Ok(selection) => selection,
            Err(error) => {
                let diagnostics = resolution
                    .warnings
                    .iter()
                    .map(|warning| format!("{}: {}", warning.kind, warning.message))
                    .collect::<Vec<_>>()
                    .join("；");
                if diagnostics.is_empty() {
                    return Err(error);
                }
                bail!("{error:#}；Linux 符号解析诊断：{diagnostics}");
            }
        };
        let selected_release =
            linux_release(&selected_banner.text).context("Linux banner 缺少 release")?;
        let mut selected = select_runtime_context(
            &image,
            &discovery,
            &profile,
            &selected_banner,
            &selected_release,
            symbol_table.as_deref(),
        )?;
        let mut runtime_isf_warning = None;
        if selected.is_none() && symbol_table.is_some() {
            ensure!(
                symbols.linux_isf().is_none(),
                "用户指定的 Linux ISF 未通过 init_task、运行时 linux_banner、页表和活动任务链联合验证；请核对符号与镜像完整性，或重新导入并选择自动判断"
            );
            runtime_isf_warning = Some(
                "与镜像完整 linux_banner 匹配的 Volatility 3 ISF 未通过 init_task slide、运行时 linux_banner、页表和活动任务链联合验证；已禁用该 ISF 并尝试安全回退"
                    .to_owned(),
            );
            symbol_table = None;
            let fallback = select_profile(&image, &discovery, None)?;
            profile = fallback.0;
            selected_banner = fallback.1;
            let fallback_release =
                linux_release(&selected_banner.text).context("Linux banner 缺少 release")?;
            selected = select_runtime_context(
                &image,
                &discovery,
                &profile,
                &selected_banner,
                &fallback_release,
                None,
            )?;
        }
        let (init, directory_table_base, page_table_source, vmcoreinfo_physical_address) =
            match selected {
                Some(selection) => selection,
                None => {
                    let mut reasons = Vec::new();
                    // 重跑一次只为拿失败原因：候选验证是纯读，没有副作用，
                    // 而没有原因的那句兜底文案排查不了任何问题。
                    let _ = select_runtime_context_diagnosed(
                        &image,
                        &discovery,
                        &profile,
                        &selected_banner,
                        &selected_release,
                        symbol_table.as_deref(),
                        &mut reasons,
                    );
                    let detail = if reasons.is_empty() {
                        String::new()
                    } else {
                        format!("；候选失败原因：{}", reasons.join("；"))
                    };
                    bail!(
                        "没有任何 swapper/init_task 候选能通过严格 present-only 四级页表、\
                         自指针和活动任务链验证{detail}"
                    );
                }
            };

        let mut offsets = BTreeMap::new();
        for (name, offset) in profile.reported_offsets() {
            offsets.insert(name.to_owned(), offset);
        }
        let mut warnings = resolution
            .warnings
            .into_iter()
            .map(|warning| LinuxProcessWarning {
                kind: warning.kind,
                message: warning.message,
                list_entry: None,
            })
            .collect::<Vec<_>>();
        if let Some(message) = profile_warning {
            warnings.push(LinuxProcessWarning {
                kind: "linux_isf_task_profile_rejected".to_owned(),
                message,
                list_entry: None,
            });
        }
        if let Some(message) = runtime_isf_warning {
            warnings.push(LinuxProcessWarning {
                kind: "linux_isf_runtime_rejected".to_owned(),
                message,
                list_entry: None,
            });
        }
        if let Some(table) = symbol_table.as_deref() {
            warnings.push(LinuxProcessWarning {
                kind: "volatility3_isf".to_owned(),
                message: format!(
                    "复用 Volatility 3 Linux ISF {}（共检查 {} 个 .json/.json.xz 候选；{}）；linux_banner、init_task slide、运行时符号映射和活动任务链均已现场复验",
                    table.path().display(),
                    resolution.files_considered,
                    table.fingerprint()
                ),
                list_entry: None,
            });
        }
        if profile.source == "exact_banner_profile" {
            warnings.push(LinuxProcessWarning {
                kind: "embedded_exact_profile".to_owned(),
                message: format!(
                    "内存中未恢复到完整 vmlinux BTF；使用与完整发行版构建指纹绑定的内置 task_struct 基础布局（{}），并已通过现场 init_task 自指针、PID/TGID、页表映射和任务链反向链接验证",
                    profile.fingerprint
                ),
                list_entry: None,
            });
        }
        if profile.source == "validated_memory_heuristic" {
            warnings.push(LinuxProcessWarning {
                kind: "symbol_less_task_profile".to_owned(),
                message: format!(
                    "镜像没有可用的 vmlinux BTF 或精确 ISF；task_struct 基础布局由 VMCOREINFO 页表、init_task 自父指针、完整双向任务链以及跨任务 PID/TGID 唯一性联合推断并现场复验（{}）。该布局只证明已报告的基础字段，不等同于完整调试符号表",
                    profile.fingerprint
                ),
                list_entry: None,
            });
        }
        let (kernel_text, kernel_text_diagnostic) = match resolve_kernel_text_evidence(
            &image,
            &discovery,
            directory_table_base,
            vmcoreinfo_physical_address,
            &init,
            symbol_table.as_deref(),
        ) {
            Ok(evidence) => (evidence, None),
            Err(error) => {
                let diagnostic = format!("{error:#}");
                warnings.push(LinuxProcessWarning {
                    kind: "kernel_text_validation_failed".to_owned(),
                    message: diagnostic.clone(),
                    list_entry: None,
                });
                (None, Some(diagnostic))
            }
        };
        let kernel = LinuxKernelContext {
            architecture: "x86_64_4level".to_owned(),
            banner: selected_banner.text,
            banner_physical_address: selected_banner.physical_address,
            directory_table_base,
            page_table_source,
            vmcoreinfo_physical_address,
            init_task: init.virtual_address,
            init_task_physical: init.physical_address,
            profile_source: profile.source.to_owned(),
            profile_fingerprint: profile.fingerprint.clone(),
            btf_physical_address: profile.btf_physical_address,
            task_struct_size: profile.task_size,
            task_struct_offsets: offsets,
            symbol_table,
            system_map: None,
        };
        Ok(Self {
            image,
            profile,
            kernel,
            warnings,
            scan: discovery.stats,
            kernel_text,
            kernel_text_diagnostic,
        })
    }

    /// Open an address-only System.map session with cancellation at scan chunks
    /// and runtime-candidate boundaries. No ISF discovery or fallback is performed.
    pub fn from_image_with_system_map(
        image: MemoryImage,
        path: &std::path::Path,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<Self> {
        cancellation.check_cancelled()?;
        ensure!(
            is_supported_linux_physical_image(&image),
            "System.map 需要可解码的 Linux 物理内存镜像"
        );
        system_map::open(
            image,
            &crate::linux_system_map::LinuxSystemMap::load(path)?,
            cancellation,
        )
    }

    pub fn image(&self) -> &MemoryImage {
        &self.image
    }

    pub fn kernel(&self) -> &LinuxKernelContext {
        &self.kernel
    }

    pub fn warnings(&self) -> &[LinuxProcessWarning] {
        &self.warnings
    }

    pub fn kernel_text(&self) -> Result<LinuxKernelTextReport> {
        let evidence = self.kernel_text.as_ref().with_context(|| {
            self.kernel_text_diagnostic.clone().unwrap_or_else(|| {
                "镜像中没有可验证的 VMCOREINFO SYMBOL(_stext)，且精确 ISF 也未提供 _stext"
                    .to_owned()
            })
        })?;
        Ok(LinuxKernelTextReport {
            architecture: self.kernel.architecture.clone(),
            banner: self.kernel.banner.clone(),
            system_map: self.kernel.system_map.clone(),
            symbol: "_stext".to_owned(),
            virtual_address: evidence.virtual_address,
            virtual_address_hex: format!("{:#018x}", evidence.virtual_address),
            physical_address: evidence.physical_address,
            physical_address_hex: format!("{:#018x}", evidence.physical_address),
            symbol_source: evidence.symbol_source.clone(),
            translation_source: "strict_present_x86_64_page_tables".to_owned(),
            directory_table_base: self.kernel.directory_table_base,
            vmcoreinfo_physical_address: self.kernel.vmcoreinfo_physical_address,
            kernel_offset: evidence.kernel_offset,
            phys_base: evidence.phys_base,
            first_bytes_hex: evidence.first_bytes_hex.clone(),
            bytes_verified: evidence.bytes_verified,
            complete: true,
        })
    }

    pub fn processes(&self, limit: usize) -> Result<LinuxProcessListReport> {
        list_processes(
            &self.image,
            &self.profile,
            &self.kernel,
            &self.warnings,
            &self.scan,
            limit,
        )
    }

    pub fn process_tree(&self, pid: Option<i32>, limit: usize) -> Result<LinuxProcessTreeReport> {
        build_process_tree(self.processes(limit)?, pid)
    }

    pub fn files(&self, limit: usize) -> Result<crate::linux_files::LinuxFileScanReport> {
        crate::linux_files::scan_files(
            &self.image,
            &self.kernel,
            self.scan.bytes_scanned,
            self.scan.elapsed_seconds,
            self.scan.gib_per_second,
            limit,
        )
    }

    pub fn cmdline(
        &self,
        pid: Option<i32>,
        process_limit: usize,
        max_bytes: u64,
    ) -> Result<crate::linux_process::LinuxCmdlineReport> {
        let processes = self.processes(process_limit)?;
        crate::linux_process::analyze_cmdline(&self.image, &self.kernel, &processes, pid, max_bytes)
    }

    pub fn psaux(
        &self,
        pid: Option<i32>,
        process_limit: usize,
        max_bytes: u64,
    ) -> Result<crate::linux_process::LinuxPsAuxReport> {
        let processes = self.processes(process_limit)?;
        crate::linux_process::analyze_psaux(&self.image, &self.kernel, &processes, pid, max_bytes)
    }

    pub fn envars(
        &self,
        pid: Option<i32>,
        process_limit: usize,
        max_bytes: u64,
    ) -> Result<crate::linux_process::LinuxEnvarsReport> {
        let processes = self.processes(process_limit)?;
        crate::linux_process::analyze_envars(&self.image, &self.kernel, &processes, pid, max_bytes)
    }

    pub fn lsof(
        &self,
        pid: Option<i32>,
        process_limit: usize,
        max_fds: usize,
    ) -> Result<crate::linux_process::LinuxLsofReport> {
        let processes = self.processes(process_limit)?;
        crate::linux_process::analyze_lsof(&self.image, &self.kernel, &processes, pid, max_fds)
    }

    pub fn sockstat(
        &self,
        pid: Option<i32>,
        process_limit: usize,
        max_fds: usize,
    ) -> Result<crate::linux_network::LinuxSockstatReport> {
        let lsof = self.lsof(pid, process_limit, max_fds)?;
        crate::linux_network::analyze_sockstat(&self.image, &self.kernel, &lsof)
    }

    pub fn proc_maps(
        &self,
        pid: Option<i32>,
        process_limit: usize,
        map_limit: usize,
    ) -> Result<crate::linux_process::LinuxProcMapsReport> {
        let processes = self.processes(process_limit)?;
        crate::linux_process::analyze_proc_maps(
            &self.image,
            &self.kernel,
            &processes,
            pid,
            map_limit,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn proc_dump(
        &self,
        pid: i32,
        process_limit: usize,
        output_directory: &std::path::Path,
        map_limit: usize,
        max_region_size: u64,
        max_total_size: u64,
        force: bool,
    ) -> Result<crate::linux_process::LinuxProcDumpReport> {
        let processes = self.processes(process_limit)?;
        crate::linux_process::dump_process(
            &self.image,
            &self.kernel,
            &processes,
            pid,
            output_directory,
            map_limit,
            max_region_size,
            max_total_size,
            force,
        )
    }

    /// 提取进程堆、栈及可选匿名可写映射中的可读字符串。
    pub fn proc_strings(
        &self,
        options: &crate::linux_process::strings::LinuxProcStringsOptions,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<crate::linux_process::strings::LinuxProcStringsReport> {
        let processes = self.processes(options.process_limit)?;
        crate::linux_process::strings::analyze_proc_strings(
            &self.image,
            &self.kernel,
            &processes,
            options,
            cancellation,
        )
    }

    pub fn bash(
        &self,
        pid: Option<i32>,
        process_limit: usize,
        map_limit: usize,
        max_scan_bytes: u64,
        max_command_bytes: usize,
    ) -> Result<crate::linux_bash::LinuxBashReport> {
        let processes = self.processes(process_limit)?;
        crate::linux_bash::analyze_bash_history(
            &self.image,
            &self.kernel,
            &processes,
            pid,
            map_limit,
            max_scan_bytes,
            max_command_bytes,
        )
    }

    /// Parse exact VFS `/etc/passwd` candidates, with a labeled reverse page-cache fallback.
    pub fn passwd(
        &self,
        file_scan_limit: usize,
        max_size: u64,
    ) -> Result<crate::linux_passwd::LinuxPasswdAnalysisReport> {
        ensure!(file_scan_limit > 0, "Linux filescan 结果上限必须大于零");
        ensure!(max_size > 0, "passwd 页缓存恢复上限必须大于零");
        let files = self.files(file_scan_limit)?;
        crate::linux_passwd::analyze_linux_passwd(
            &self.image,
            &self.kernel,
            &files,
            file_scan_limit,
            max_size,
        )
    }

    /// Revalidate a `filescan` dentry and recover its resident page-cache bytes.
    pub fn dump_file(
        &self,
        dentry: u64,
        output: &std::path::Path,
        max_size: u64,
        file_scan_limit: usize,
    ) -> Result<crate::linux_pagecache::LinuxDumpFileReport> {
        self.dump_file_with_force(dentry, output, max_size, file_scan_limit, false)
    }

    pub fn dump_file_with_force(
        &self,
        dentry: u64,
        output: &std::path::Path,
        max_size: u64,
        file_scan_limit: usize,
        force: bool,
    ) -> Result<crate::linux_pagecache::LinuxDumpFileReport> {
        self.dump_file_with_force_cancellable(
            dentry,
            output,
            max_size,
            file_scan_limit,
            force,
            &crate::cancellation::CancellationToken::new(),
        )
    }

    pub fn dump_file_with_force_cancellable(
        &self,
        dentry: u64,
        output: &std::path::Path,
        max_size: u64,
        file_scan_limit: usize,
        force: bool,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<crate::linux_pagecache::LinuxDumpFileReport> {
        use crate::output_policy::{OutputPolicy, append_path_suffix};
        cancellation.check_cancelled()?;
        ensure!(file_scan_limit > 0, "文件扫描结果上限必须大于零");
        ensure!(max_size > 0, "页缓存文件恢复上限必须大于零");
        ensure!(
            is_kernel_pointer(dentry),
            "Linux dentry 必须是规范且按 8 字节对齐的内核虚拟地址"
        );
        let partial = crate::linux_pagecache::partial_output_path(output)?;
        let mut policy = OutputPolicy::new(force);
        for source in self.image.sources() {
            policy.protect_file("memory_image_or_sidecar", &source.path);
        }
        policy.output_file(
            "recovery_report",
            append_path_suffix(output, ".recovery.json"),
        );
        policy.output_file(
            "partial_recovery_report",
            append_path_suffix(&partial, ".recovery.json"),
        );
        policy.preflight()?;
        let files = self.files(file_scan_limit)?;
        cancellation.check_cancelled()?;
        let Some(record) = files.records.iter().find(|record| record.dentry == dentry) else {
            bail!(
                "Linux filescan 记录中未找到 dentry {dentry:#018x}（stop_reason={:?}，complete={}，structural_complete={}，limit_reached={}，warning_count={}，请求上限={}）；请使用同一镜像的 filescan dentry 地址并检查完整告警",
                files.stop_reason,
                files.complete,
                files.structural_complete,
                files.limit_reached,
                files.warning_count,
                file_scan_limit
            );
        };
        let mut report = crate::linux_pagecache::dump_validated_file_cancellable(
            &self.image,
            &self.kernel,
            record,
            output,
            max_size,
            force,
            cancellation,
        )?;
        report.filescan_selection = Some(crate::linux_pagecache::LinuxDumpFileSelection {
            requested_limit: file_scan_limit,
            record_count: files.record_count,
            complete: files.complete,
            structural_complete: files.structural_complete,
            limit_reached: files.limit_reached,
            stop_reason: files.stop_reason,
            warning_count: files.warning_count,
            warning_counts: files.warning_counts.clone(),
            warnings: files.warnings.clone(),
        });
        let actual = if report.complete {
            output
        } else {
            partial.as_path()
        };
        // Once content is published, always finish its provenance sidecar, even if the
        // caller requests cancellation at this boundary.
        crate::linux_pagecache::write_recovery_sidecar(&self.image, &mut report, actual, &policy)?;
        Ok(report)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LinuxKernelSessionCandidate {
    directory_table_base: u64,
    page_table_source: String,
    kernel_slide: u64,
    kernel_slide_source: String,
    vmcoreinfo_physical_address: Option<u64>,
}

/// Open a feature-aware Linux kernel-global session without consulting the task list.
///
/// Symbol discovery is deliberately local-only.  The selected ISF must contain an exact
/// `linux_banner.constant_data` match for the image and satisfy every requested feature.  When an
/// override is absent, the corresponding DTB or KASLR slide is recovered from matching
/// VMCOREINFO evidence.  Every candidate is then independently validated by
/// [`LinuxKernelSession::new`].
/// System.map inputs are first validated and enriched through a task session; its verified
/// DTB/slide are reused unless the caller explicitly supplied overrides.
pub fn open_linux_kernel_session(
    image: MemoryImage,
    symbols: &SymbolStore,
    features: impl IntoIterator<Item = LinuxSymbolFeature>,
    options: LinuxKernelSessionOptions,
) -> Result<OpenedLinuxKernelSession> {
    open_linux_kernel_session_cancellable(
        image,
        symbols,
        features,
        options,
        &CancellationToken::new(),
    )
}

pub fn open_linux_kernel_session_cancellable(
    image: MemoryImage,
    symbols: &SymbolStore,
    features: impl IntoIterator<Item = LinuxSymbolFeature>,
    options: LinuxKernelSessionOptions,
    cancellation: &CancellationToken,
) -> Result<OpenedLinuxKernelSession> {
    cancellation.check_cancelled()?;
    if symbols.linux_system_map().is_some() {
        let task_session = LinuxAnalysisSession::from_image_with_symbol_store_cancellable(
            image,
            symbols,
            cancellation,
        )?;
        let table = task_session.kernel.symbol_table.as_ref().context(
            "System.map 自动补齐未找到精确匹配的类型来源；请将同一构建的 ISF 放入符号目录，再重试。System.map 本身不能生成结构体类型"
        )?;
        let pinned = symbols
            .without_linux_selection()
            .with_linux_isf(table.path().to_owned());
        let options = LinuxKernelSessionOptions {
            directory_table_base: options
                .directory_table_base
                .or(Some(task_session.kernel.directory_table_base)),
            kernel_slide: options.kernel_slide.or(task_session
                .kernel_text
                .as_ref()
                .and_then(|text| text.kernel_offset)),
        };
        let map_warnings = task_session
            .warnings
            .iter()
            .map(|warning| LinuxIsfWarning {
                kind: warning.kind.clone(),
                message: warning.message.clone(),
            })
            .collect::<Vec<_>>();
        let mut opened = open_linux_kernel_session_cancellable(
            task_session.image,
            &pinned,
            features,
            options,
            cancellation,
        )?;
        opened.evidence.symbol_warnings.extend(map_warnings);
        return Ok(opened);
    }
    ensure!(
        is_supported_linux_physical_image(&image),
        "Linux kernel-global 分析仅支持已解码的 x86_64 物理内存镜像"
    );
    let features = features.into_iter().collect::<BTreeSet<_>>();
    ensure!(
        !features.is_empty(),
        "Linux kernel-global 会话必须声明至少一个符号 feature"
    );
    if let Some(directory_table_base) = options.directory_table_base {
        ensure!(
            directory_table_base != 0 && directory_table_base & (PAGE_SIZE - 1) == 0,
            "显式 Linux 页表根必须非零且按页对齐"
        );
    }
    if let Some(kernel_slide) = options.kernel_slide {
        ensure!(
            kernel_slide & (PAGE_SIZE - 1) == 0,
            "显式 Linux kernel slide 必须按页对齐"
        );
    }

    let discovery = scan_linux_anchors_with_policy(&image, false, cancellation)?;
    let banners = discovery
        .banners
        .iter()
        .map(|banner| banner.text.clone())
        .collect::<Vec<_>>();
    let mut resolution =
        resolve_linux_isf_for_features(symbols, &banners, features.iter().copied())?;
    if resolution.table.is_none() {
        let remote = resolve_remote_linux_isf(symbols, &banners)?;
        resolution.warnings.extend(remote.warnings);
        if remote.table.is_some() {
            // 远程解析先校验 banner；按本次内核 feature 重新加载，避免复用 task-only 类型裁剪。
            let refreshed =
                resolve_linux_isf_for_features(symbols, &banners, features.iter().copied())?;
            resolution.files_considered += refreshed.files_considered;
            resolution.warnings.extend(refreshed.warnings);
            resolution.table = refreshed.table;
        }
    }
    let symbols = resolution.table.take().with_context(|| {
        let diagnostics = resolution
            .warnings
            .iter()
            .map(|warning| format!("{}: {}", warning.kind, warning.message))
            .collect::<Vec<_>>()
            .join("；");
        if diagnostics.is_empty() {
            format!(
                "未找到与镜像完整 linux_banner 精确匹配且满足 feature 的本地 Linux ISF（检查 {} 个候选）",
                resolution.files_considered
            )
        } else {
            format!(
                "未找到可用的本地 Linux ISF（检查 {} 个候选）；{diagnostics}",
                resolution.files_considered
            )
        }
    })?;
    let selected_banner = discovery
        .banners
        .iter()
        .find(|banner| banner.text == symbols.banner())
        .context("内部错误：已选 ISF 的 linux_banner 不在扫描证据中")?;
    let release = linux_release(symbols.banner()).context("已选 ISF linux_banner 缺少 release")?;
    let matching_vmcoreinfo = discovery
        .vmcoreinfo
        .iter()
        .filter(|evidence| evidence.release == release)
        .collect::<Vec<_>>();

    let mut candidates = Vec::new();
    if let Some(directory_table_base) = options.directory_table_base {
        if let Some(kernel_slide) = options.kernel_slide {
            candidates.push(LinuxKernelSessionCandidate {
                directory_table_base,
                page_table_source: "explicit_override".to_owned(),
                kernel_slide,
                kernel_slide_source: "explicit_override".to_owned(),
                vmcoreinfo_physical_address: None,
            });
        } else {
            for evidence in &matching_vmcoreinfo {
                if let Ok((kernel_slide, kernel_slide_source)) =
                    vmcore_kernel_slide(evidence, &symbols)
                {
                    candidates.push(LinuxKernelSessionCandidate {
                        directory_table_base,
                        page_table_source: "explicit_override".to_owned(),
                        kernel_slide,
                        kernel_slide_source,
                        vmcoreinfo_physical_address: Some(evidence.physical_address),
                    });
                }
            }
        }
    } else {
        for evidence in &matching_vmcoreinfo {
            let Ok(directory_table_base) = vmcore_directory_table_base(&image, evidence) else {
                continue;
            };
            let (kernel_slide, kernel_slide_source) =
                if let Some(kernel_slide) = options.kernel_slide {
                    (kernel_slide, "explicit_override".to_owned())
                } else {
                    let Ok(slide) = vmcore_kernel_slide(evidence, &symbols) else {
                        continue;
                    };
                    slide
                };
            candidates.push(LinuxKernelSessionCandidate {
                directory_table_base,
                page_table_source: "vmcoreinfo".to_owned(),
                kernel_slide,
                kernel_slide_source,
                vmcoreinfo_physical_address: Some(evidence.physical_address),
            });
        }
    }
    candidates.sort();
    candidates.dedup_by(|left, right| {
        left.directory_table_base == right.directory_table_base
            && left.kernel_slide == right.kernel_slide
    });
    ensure!(
        !candidates.is_empty(),
        "无法形成 Linux kernel-global 会话候选：需要显式 --dtb/--kernel-slide，或与已选 ISF release 匹配且可推导四级页表与 KASLR slide 的 VMCOREINFO（匹配 VMCOREINFO={} ）",
        matching_vmcoreinfo.len()
    );

    let mut validated = Vec::new();
    let mut failures = Vec::new();
    for candidate in candidates {
        match LinuxKernelSession::new(
            image.clone(),
            candidate.directory_table_base,
            candidate.kernel_slide,
            symbols.clone(),
        ) {
            Ok(session) => validated.push((candidate, session)),
            Err(error) => {
                if failures.len() < 8 {
                    failures.push(format!(
                        "dtb={:#x}, slide={:#x}: {error:#}",
                        candidate.directory_table_base, candidate.kernel_slide
                    ));
                }
            }
        }
    }
    ensure!(
        !validated.is_empty(),
        "没有 Linux kernel-global 候选通过 _stext 可读性与运行时 linux_banner 精确匹配验证：{}",
        failures.join("；")
    );
    ensure!(
        validated.len() == 1,
        "多个不同的 Linux DTB/kernel slide 组合均通过运行时验证，拒绝模糊选择（{} 个）",
        validated.len()
    );
    let (candidate, session) = validated.pop().expect("validated is non-empty");
    let evidence = LinuxKernelSessionEvidence {
        architecture: "x86_64_4level".to_owned(),
        banner: selected_banner.text.clone(),
        banner_physical_address: selected_banner.physical_address,
        directory_table_base: candidate.directory_table_base,
        page_table_source: candidate.page_table_source,
        kernel_slide: candidate.kernel_slide,
        kernel_slide_source: candidate.kernel_slide_source,
        vmcoreinfo_physical_address: candidate.vmcoreinfo_physical_address,
        requested_features: features.into_iter().collect(),
        symbol_identity: symbols.identity()?,
        symbol_files_considered: resolution.files_considered,
        symbol_warnings: resolution.warnings,
        bytes_scanned: discovery.stats.bytes_scanned,
        scan_seconds: discovery.stats.elapsed_seconds,
        scan_gib_per_second: discovery.stats.gib_per_second,
    };
    Ok(OpenedLinuxKernelSession { session, evidence })
}

fn vmcore_kernel_slide(evidence: &VmcoreInfoEvidence, symbols: &LinuxIsf) -> Result<(u64, String)> {
    let symbol_slide = evidence
        .stext_virtual
        .map(|runtime| -> Result<u64> {
            runtime
                .checked_sub(symbols.symbol_address("_stext")?)
                .context("VMCOREINFO 运行时 _stext 低于 ISF 链接地址")
        })
        .transpose()?;
    if let (Some(symbol_slide), Some(kernel_offset)) = (symbol_slide, evidence.kernel_offset) {
        ensure!(
            symbol_slide == kernel_offset,
            "VMCOREINFO SYMBOL(_stext) 推导的 slide {symbol_slide:#x} 与 KERNELOFFSET {kernel_offset:#x} 冲突"
        );
    }
    let (slide, source) = if let Some(symbol_slide) = symbol_slide {
        (symbol_slide, "vmcoreinfo:SYMBOL(_stext)-isf:_stext")
    } else if let Some(kernel_offset) = evidence.kernel_offset {
        (kernel_offset, "vmcoreinfo:KERNELOFFSET")
    } else {
        bail!("VMCOREINFO 缺少可推导 KASLR slide 的 SYMBOL(_stext)/KERNELOFFSET")
    };
    ensure!(
        slide & (PAGE_SIZE - 1) == 0,
        "VMCOREINFO 推导的 kernel slide 未按页对齐"
    );
    Ok((slide, source.to_owned()))
}

pub fn is_supported_linux_physical_image(image: &MemoryImage) -> bool {
    matches!(
        image.format(),
        ImageFormat::Raw
            | ImageFormat::VmwareVmem { .. }
            | ImageFormat::ElfPhysicalCore { .. }
            | ImageFormat::XenElf64(_)
            | ImageFormat::AvmlV2 { .. }
            | ImageFormat::QevmV3 { .. }
            | ImageFormat::Lime { .. }
    ) || matches!(
        image.format(),
        ImageFormat::ExpertWitness {
            media: ExpertWitnessMedia::PhysicalMemory,
            ..
        }
    )
}

pub fn probe_linux_memory(image: &MemoryImage) -> Result<bool> {
    if !is_supported_linux_physical_image(image) {
        return Ok(false);
    }
    if matches!(image.format(), ImageFormat::Lime { .. }) {
        return Ok(true);
    }
    let Ok(discovery) = scan_linux_anchors(image) else {
        return Ok(false);
    };
    let Ok((profile, banner, _)) = select_profile(image, &discovery, None) else {
        return Ok(false);
    };
    let Some(release) = linux_release(&banner.text) else {
        return Ok(false);
    };
    Ok(
        select_runtime_context(image, &discovery, &profile, &banner, &release, None)
            .is_ok_and(|selection| selection.is_some()),
    )
}

#[derive(Debug, Clone)]
struct LinuxTaskProfile {
    source: &'static str,
    fingerprint: String,
    btf_physical_address: Option<u64>,
    task_size: u64,
    tasks: u64,
    pid: u64,
    tgid: u64,
    comm: u64,
    comm_len: usize,
    real_parent: u64,
    parent: Option<u64>,
    state: u64,
    state_size: usize,
    exit_state: Option<u64>,
    flags: Option<u64>,
    mm: Option<u64>,
    start_time: Option<LinuxTaskStartTime>,
}

#[derive(Debug, Clone, Copy)]
enum LinuxTaskStartTime {
    Nanoseconds(u64),
    Timespec { seconds: u64, nanoseconds: u64 },
}

impl LinuxTaskStartTime {
    fn from_isf(isf: &LinuxIsf) -> Result<Option<Self>> {
        if isf
            .optional_field_offset("task_struct", "start_time")?
            .is_none()
        {
            return Ok(None);
        }
        if let Ok((offset, 8)) = isf.field_scalar_layout("task_struct", "start_time") {
            return Ok(Some(Self::Nanoseconds(offset)));
        }
        let (seconds, seconds_width) =
            isf.field_scalar_layout("task_struct", "start_time.tv_sec")?;
        let (nanoseconds, nanoseconds_width) =
            isf.field_scalar_layout("task_struct", "start_time.tv_nsec")?;
        ensure!(
            seconds_width == 8 && nanoseconds_width == 8 && seconds != nanoseconds,
            "task_struct.start_time 的 timespec 字段布局无效"
        );
        Ok(Some(Self::Timespec {
            seconds,
            nanoseconds,
        }))
    }

    fn offset(self) -> u64 {
        match self {
            Self::Nanoseconds(offset) => offset,
            Self::Timespec { seconds, .. } => seconds,
        }
    }

    fn read(self, space: &LinuxX64AddressSpace<'_>, task: u64) -> Result<u64> {
        match self {
            Self::Nanoseconds(offset) => space.read_u64(task + offset),
            Self::Timespec {
                seconds,
                nanoseconds,
            } => {
                let seconds = space.read_u64(task + seconds)?;
                let nanoseconds = space.read_u64(task + nanoseconds)?;
                timespec_start_time_ns(seconds, nanoseconds)
            }
        }
    }
}

fn timespec_start_time_ns(seconds: u64, nanoseconds: u64) -> Result<u64> {
    ensure!(
        nanoseconds < 1_000_000_000,
        "task_struct.start_time.tv_nsec 超出有效范围"
    );
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .context("task_struct.start_time 为负数或超出纳秒范围")
}

impl LinuxTaskProfile {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.task_size >= 0x100 && self.task_size <= 0x10000,
            "task_struct 大小不合理"
        );
        ensure!(
            self.tasks + 16 <= self.task_size,
            "task_struct.tasks 超出结构范围"
        );
        ensure!(
            self.pid + 4 <= self.task_size,
            "task_struct.pid 超出结构范围"
        );
        ensure!(
            self.tgid + 4 <= self.task_size,
            "task_struct.tgid 超出结构范围"
        );
        ensure!(
            self.real_parent + 8 <= self.task_size,
            "task_struct.real_parent 超出结构范围"
        );
        ensure!(
            self.comm_len > 0 && self.comm_len <= 64,
            "task_struct.comm 长度不合理"
        );
        ensure!(
            self.comm + self.comm_len as u64 <= self.task_size,
            "task_struct.comm 超出结构范围"
        );
        ensure!(
            matches!(self.state_size, 4 | 8),
            "task_struct state 字段大小不支持"
        );
        ensure!(
            self.state + self.state_size as u64 <= self.task_size,
            "task_struct state 超出结构范围"
        );
        if let Some(start_time) = self.start_time {
            let last = match start_time {
                LinuxTaskStartTime::Nanoseconds(offset) => offset,
                LinuxTaskStartTime::Timespec {
                    seconds,
                    nanoseconds,
                } => seconds.max(nanoseconds),
            };
            ensure!(
                last.checked_add(8).is_some_and(|end| end <= self.task_size),
                "task_struct.start_time 超出结构范围"
            );
        }
        Ok(())
    }

    fn reported_offsets(&self) -> Vec<(&'static str, u64)> {
        let mut fields = vec![
            ("tasks", self.tasks),
            ("pid", self.pid),
            ("tgid", self.tgid),
            ("comm", self.comm),
            ("real_parent", self.real_parent),
            ("state", self.state),
        ];
        for (name, value) in [
            ("parent", self.parent),
            ("exit_state", self.exit_state),
            ("flags", self.flags),
            ("mm", self.mm),
            (
                "start_time",
                self.start_time.map(LinuxTaskStartTime::offset),
            ),
        ] {
            if let Some(value) = value {
                fields.push((name, value));
            }
        }
        if let Some(LinuxTaskStartTime::Timespec { nanoseconds, .. }) = self.start_time {
            fields.push(("start_time.tv_nsec", nanoseconds));
        }
        fields
    }
}

#[derive(Debug, Clone)]
struct BannerEvidence {
    physical_address: u64,
    text: String,
}

#[derive(Debug, Clone, Copy)]
struct DiscoveryScanStats {
    bytes_scanned: u64,
    elapsed_seconds: f64,
    gib_per_second: f64,
}

struct LinuxDiscovery {
    banners: Vec<BannerEvidence>,
    btf_hits: Vec<u64>,
    swapper_hits: Vec<u64>,
    vmcoreinfo: Vec<VmcoreInfoEvidence>,
    stats: DiscoveryScanStats,
}

#[derive(Debug, Clone)]
struct VmcoreInfoEvidence {
    physical_address: u64,
    release: String,
    page_table_virtual: u64,
    phys_base: u64,
    stext_virtual: Option<u64>,
    kernel_offset: Option<u64>,
    pgtable_l5_enabled: Option<u64>,
    sme_mask: Option<u64>,
}

type LinuxRuntimeSelection = (InitTaskCandidate, u64, String, Option<u64>);

fn scan_linux_anchors(image: &MemoryImage) -> Result<LinuxDiscovery> {
    scan_linux_anchors_with_policy(image, true, &CancellationToken::new())
}

fn scan_linux_anchors_with_policy(
    image: &MemoryImage,
    require_task_anchor: bool,
    cancellation: &CancellationToken,
) -> Result<LinuxDiscovery> {
    let patterns = [
        LINUX_BANNER_PATTERN,
        BTF_HEADER_PATTERN,
        SWAPPER_PATTERN,
        VMCOREINFO_PATTERN,
    ];
    let report = crate::scan::scan_patterns_cancellable(
        image,
        &patterns,
        DISCOVERY_LIMIT_PER_PATTERN,
        DISCOVERY_CHUNK_SIZE,
        cancellation,
    )?;
    let mut banners = Vec::new();
    let mut btf_hits = Vec::new();
    let mut swapper_hits = Vec::new();
    let mut vmcoreinfo = Vec::new();
    for hit in report.hits {
        cancellation.check_cancelled()?;
        match hit.pattern_index {
            0 => {
                if let Some(text) = read_physical_c_string(image, hit.physical_address, 512) {
                    let text = normalize_linux_banner(text);
                    if linux_release(&text).is_some() {
                        banners.push(BannerEvidence {
                            physical_address: hit.physical_address,
                            text,
                        });
                    }
                }
            }
            1 => btf_hits.push(hit.physical_address),
            2 => swapper_hits.push(hit.physical_address),
            3 => {
                if let Some(text) = read_physical_nul_string(image, hit.physical_address, 8192)
                    && let Ok(evidence) = parse_vmcoreinfo(hit.physical_address, &text)
                {
                    vmcoreinfo.push(evidence);
                }
            }
            _ => unreachable!(),
        }
    }
    banners.sort_unstable_by_key(|banner| banner.physical_address);
    banners.dedup_by(|left, right| left.text == right.text);
    btf_hits.sort_unstable();
    btf_hits.dedup();
    swapper_hits.sort_unstable();
    swapper_hits.dedup();
    vmcoreinfo.sort_unstable_by_key(|evidence| evidence.physical_address);
    vmcoreinfo.dedup_by(|left, right| {
        left.release == right.release
            && left.page_table_virtual == right.page_table_virtual
            && left.phys_base == right.phys_base
    });
    ensure!(
        !banners.is_empty(),
        "Linux 物理内存镜像中未恢复到有效的 Linux version banner"
    );
    if require_task_anchor {
        ensure!(
            !swapper_hits.is_empty(),
            "Linux 物理内存镜像中未恢复到 swapper 任务名称锚点"
        );
    }
    Ok(LinuxDiscovery {
        banners,
        btf_hits,
        swapper_hits,
        vmcoreinfo,
        stats: DiscoveryScanStats {
            bytes_scanned: report.bytes_scanned,
            elapsed_seconds: report.elapsed_seconds,
            gib_per_second: report.gib_per_second,
        },
    })
}

/// Recover complete Linux banner strings without requiring a valid task ring or kernel session.
/// This is intentionally sufficient for local ISF diagnostics even when process enumeration is
/// structurally damaged.
pub fn discover_linux_banners(image: &MemoryImage) -> Result<Vec<String>> {
    let report = scan_patterns(
        image,
        &[LINUX_BANNER_PATTERN],
        DISCOVERY_LIMIT_PER_PATTERN,
        DISCOVERY_CHUNK_SIZE,
    )?;
    let mut banners = report
        .hits
        .into_iter()
        .filter_map(|hit| read_physical_c_string(image, hit.physical_address, 512))
        .map(normalize_linux_banner)
        .filter(|banner| linux_release(banner).is_some())
        .collect::<Vec<_>>();
    banners.sort();
    banners.dedup();
    ensure!(
        !banners.is_empty(),
        "Linux 物理内存镜像中未恢复到有效的 Linux version banner"
    );
    Ok(banners)
}

fn select_profile(
    image: &MemoryImage,
    discovery: &LinuxDiscovery,
    isf: Option<&LinuxIsf>,
) -> Result<(LinuxTaskProfile, BannerEvidence, Option<String>)> {
    if let Some(mut profile) = profile_from_memory_btf(image, &discovery.btf_hits)? {
        let banner = isf
            .and_then(|table| {
                discovery
                    .banners
                    .iter()
                    .find(|banner| banner.text == table.banner())
            })
            .or_else(|| {
                discovery
                    .banners
                    .iter()
                    .max_by_key(|banner| banner.text.len())
            })
            .context("Linux banner 列表为空")?
            .clone();
        if let Some(identity) = exact_banner_profile(&banner.text) {
            profile
                .fingerprint
                .push_str(&format!("; {}", identity.fingerprint));
        }
        profile.validate()?;
        return Ok((profile, banner, None));
    }
    let mut isf_warning = None;
    if let Some(table) = isf {
        let banner = discovery
            .banners
            .iter()
            .find(|banner| banner.text == table.banner())
            .context("已选择的 Volatility 3 ISF banner 未在镜像证据中找到")?
            .clone();
        match profile_from_volatility_isf(table) {
            Ok(profile) => return Ok((profile, banner, None)),
            Err(error) => {
                isf_warning = Some(format!(
                    "Volatility 3 ISF {} 与完整 linux_banner 匹配，但 task_struct 基础布局不可用：{error:#}；仅在存在严格内存 BTF/内置完整构建 profile 时回退",
                    table.path().display()
                ));
            }
        }
    }
    for banner in &discovery.banners {
        if let Some(profile) = exact_banner_profile(&banner.text) {
            profile.validate()?;
            return Ok((profile, banner.clone(), isf_warning));
        }
    }
    let heuristic_error = match profile_from_validated_memory_heuristics(image, discovery) {
        Ok(Some((profile, banner))) => return Ok((profile, banner, isf_warning)),
        Ok(None) => None,
        Err(error) => Some(format!("{error:#}")),
    };
    let releases = discovery
        .banners
        .iter()
        .filter_map(|banner| linux_release(&banner.text))
        .collect::<Vec<_>>();
    if let Some(warning) = isf_warning {
        bail!(
            "{warning}；同时没有可解析的内存 vmlinux BTF、与完整构建指纹匹配的内置 Linux profile，且无符号现场布局推断未成功（发现版本：{}{}）",
            releases.join(", "),
            heuristic_error
                .as_deref()
                .map(|error| format!("；推断诊断：{error}"))
                .unwrap_or_default()
        );
    }
    bail!(
        "内存中没有可解析的 vmlinux BTF、精确匹配的 Volatility 3 ISF、与完整构建指纹匹配的内置 Linux profile，且无符号现场布局推断未成功（发现版本：{}{}）",
        releases.join(", "),
        heuristic_error
            .as_deref()
            .map(|error| format!("；推断诊断：{error}"))
            .unwrap_or_default()
    )
}

#[derive(Debug)]
struct HeuristicTaskLayout {
    task_physical: u64,
    task_virtual: u64,
    comm: u64,
    real_parent: u64,
    tasks: u64,
    pid: u64,
    tgid: u64,
    state: u64,
    state_size: usize,
    task_count: usize,
}

fn profile_from_validated_memory_heuristics(
    image: &MemoryImage,
    discovery: &LinuxDiscovery,
) -> Result<Option<(LinuxTaskProfile, BannerEvidence)>> {
    let mut best: Option<(HeuristicTaskLayout, BannerEvidence, Option<u64>)> = None;
    let mut matching_vmcoreinfo = 0usize;
    let mut valid_page_tables = 0usize;
    let mut swapper_candidates = 0usize;
    for banner in &discovery.banners {
        let Some(release) = linux_release(&banner.text) else {
            continue;
        };
        for vmcoreinfo in discovery
            .vmcoreinfo
            .iter()
            .filter(|evidence| evidence.release == release)
        {
            matching_vmcoreinfo += 1;
            let Ok(directory_table_base) = vmcore_directory_table_base(image, vmcoreinfo) else {
                continue;
            };
            let Ok(space) = LinuxX64AddressSpace::new(image, directory_table_base) else {
                continue;
            };
            valid_page_tables += 1;
            for swapper in &discovery.swapper_hits {
                swapper_candidates += 1;
                let Some(layout) = infer_task_layout_at_swapper(image, &space, *swapper) else {
                    continue;
                };
                if best
                    .as_ref()
                    .is_none_or(|(current, _, _)| layout.task_count > current.task_count)
                {
                    best = Some((layout, banner.clone(), Some(vmcoreinfo.physical_address)));
                }
            }
        }
    }
    if best.is_none()
        && let Some(layout) = infer_task_layout_without_vmcoreinfo(image, discovery)?
        && let Some(banner) = discovery
            .banners
            .iter()
            .max_by_key(|candidate| candidate.text.len())
    {
        best = Some((layout, banner.clone(), None));
    }
    let Some((layout, banner, vmcoreinfo_physical)) = best else {
        bail!(
            "未找到通过自父指针、双向任务链和 PID/TGID 联合校验的 init_task（VMCOREINFO={}，release 匹配={}，有效页表={}，swapper 候选={}）",
            discovery.vmcoreinfo.len(),
            matching_vmcoreinfo,
            valid_page_tables,
            swapper_candidates
        );
    };
    let page_table_evidence = vmcoreinfo_physical
        .map(|address| format!("vmcoreinfo={address:#x}"))
        .unwrap_or_else(|| "page_table=validated_pml4_scan".to_owned());
    let profile = task_profile_from_inferred_layout(&layout, &page_table_evidence)?;
    Ok(Some((profile, banner)))
}

fn task_profile_from_inferred_layout(
    layout: &HeuristicTaskLayout,
    page_table_evidence: &str,
) -> Result<LinuxTaskProfile> {
    let task_size = align_up(layout.comm.saturating_add(64), 0x100)
        .context("无符号 task_struct 大小推断溢出")?;
    let profile = LinuxTaskProfile {
        source: "validated_memory_heuristic",
        fingerprint: format!(
            "runtime field inference; {page_table_evidence}; init_task={:#x}/{:#x}; tasks={:#x}; pid={:#x}; tgid={:#x}; real_parent={:#x}; comm={:#x}; state={:#x}/{}; observed_tasks={}",
            layout.task_virtual,
            layout.task_physical,
            layout.tasks,
            layout.pid,
            layout.tgid,
            layout.real_parent,
            layout.comm,
            layout.state,
            layout.state_size,
            layout.task_count
        ),
        btf_physical_address: None,
        task_size,
        tasks: layout.tasks,
        pid: layout.pid,
        tgid: layout.tgid,
        comm: layout.comm,
        comm_len: 16,
        real_parent: layout.real_parent,
        parent: Some(layout.real_parent + 8),
        state: layout.state,
        state_size: layout.state_size,
        exit_state: None,
        flags: None,
        mm: None,
        start_time: None,
    };
    profile.validate()?;
    Ok(profile)
}

fn infer_task_layout_at_swapper(
    image: &MemoryImage,
    space: &LinuxX64AddressSpace<'_>,
    swapper_physical: u64,
) -> Option<HeuristicTaskLayout> {
    let search_start = swapper_physical.saturating_sub(0x3000);
    let mut address = align_up(search_start, 8)?;
    let mut best = None;
    while address.checked_add(16)? <= swapper_physical {
        let (Ok(self_pointer), Ok(second)) = (
            image.read_u64_physical(address),
            image.read_u64_physical(address + 8),
        ) else {
            address = address.checked_add(8)?;
            continue;
        };
        if self_pointer == second && is_kernel_pointer(self_pointer) {
            let task_physical = space.translate(self_pointer).ok()?;
            if task_physical <= address && task_physical < swapper_physical {
                let real_parent = address.checked_sub(task_physical)?;
                let comm = swapper_physical.checked_sub(task_physical)?;
                if (0x100..=0x3000).contains(&comm)
                    && real_parent < comm
                    && comm.saturating_sub(real_parent) <= 0x800
                    && space.translate(self_pointer + real_parent).ok() == Some(address)
                    && space.translate(self_pointer + comm).ok() == Some(swapper_physical)
                    && read_valid_task_comm(space, self_pointer + comm).is_some()
                    && let Some(candidate) = finish_inferred_task_layout(
                        space,
                        task_physical,
                        self_pointer,
                        real_parent,
                        comm,
                    )
                    && best.as_ref().is_none_or(|current: &HeuristicTaskLayout| {
                        candidate.task_count > current.task_count
                    })
                {
                    best = Some(candidate);
                }
            }
        }
        address = address.checked_add(8)?;
    }
    best
}

fn infer_task_layout_without_vmcoreinfo(
    image: &MemoryImage,
    discovery: &LinuxDiscovery,
) -> Result<Option<HeuristicTaskLayout>> {
    let mut best = None;
    let mut page_table_cache = BTreeMap::<u64, Option<(u64, u64)>>::new();
    let mut evaluated_tasks = HashSet::<u64>::new();
    let mut swapper_names = 0usize;
    let mut self_pointer_pairs = 0usize;
    let mut task_layout_candidates = 0usize;
    let mut mapped_candidates = 0usize;
    let mut mapping_diagnostic = None;
    for swapper_physical in &discovery.swapper_hits {
        if !read_fixed_name_physical(image, *swapper_physical, 16)
            .is_ok_and(|name| name.starts_with("swapper"))
        {
            continue;
        }
        swapper_names += 1;
        let pair_start = align_up(swapper_physical.saturating_sub(0x800), 8)
            .context("swapper 自指针搜索起点溢出")?;
        let mut pair_physical = pair_start;
        while pair_physical + 16 <= *swapper_physical {
            let (Ok(self_pointer), Ok(second)) = (
                image.read_u64_physical(pair_physical),
                image.read_u64_physical(pair_physical + 8),
            ) else {
                pair_physical += 8;
                continue;
            };
            if self_pointer != second || !is_kernel_pointer(self_pointer) {
                pair_physical += 8;
                continue;
            }
            self_pointer_pairs += 1;
            if !evaluated_tasks.insert(self_pointer) {
                pair_physical += 8;
                continue;
            }
            let mapping = page_table_cache
                .entry(self_pointer)
                .or_insert_with(|| {
                    discover_page_table_root_for_virtual(image, self_pointer)
                        .map_err(|error| {
                            mapping_diagnostic.get_or_insert_with(|| format!("{error:#}"));
                            error
                        })
                        .ok()
                })
                .to_owned();
            let Some((directory_table_base, task_physical)) = mapping else {
                pair_physical += 8;
                continue;
            };
            let Ok(space) = LinuxX64AddressSpace::new(image, directory_table_base) else {
                pair_physical += 8;
                continue;
            };
            mapped_candidates += 1;
            let real_parent_offsets = (0x100u64..0x1800)
                .step_by(8)
                .filter(|offset| {
                    space.read_u64(self_pointer + offset).ok() == Some(self_pointer)
                        && space.read_u64(self_pointer + offset + 8).ok() == Some(self_pointer)
                })
                .collect::<Vec<_>>();
            let comm_offsets = (0x400u64..0x2000)
                .step_by(8)
                .filter(|offset| {
                    read_valid_task_comm(&space, self_pointer + offset)
                        .is_some_and(|name| name.starts_with("swapper"))
                })
                .collect::<Vec<_>>();
            for real_parent in &real_parent_offsets {
                for comm in &comm_offsets {
                    if *comm <= *real_parent || comm.saturating_sub(*real_parent) > 0x800 {
                        continue;
                    }
                    task_layout_candidates += 1;
                    match finish_inferred_task_layout_diagnosed(
                        &space,
                        task_physical,
                        self_pointer,
                        *real_parent,
                        *comm,
                    ) {
                        Ok(candidate)
                            if best.as_ref().is_none_or(|current: &HeuristicTaskLayout| {
                                candidate.task_count > current.task_count
                            }) =>
                        {
                            best = Some(candidate);
                        }
                        Err(stage) => {
                            mapping_diagnostic.get_or_insert_with(|| {
                                format!(
                                    "task={self_pointer:#x}/{task_physical:#x}, real_parent={real_parent:#x}, comm={comm:#x} 在 {stage} 阶段未通过"
                                )
                            });
                        }
                        _ => {}
                    }
                }
            }
            pair_physical += 8;
        }
    }
    if best.is_none() {
        bail!(
            "无 VMCOREINFO 页表推断未形成有效任务布局（有效 swapper 名称={}，自指针对={}，虚拟布局候选={}，可翻译 task_struct={}{}）",
            swapper_names,
            self_pointer_pairs,
            task_layout_candidates,
            mapped_candidates,
            mapping_diagnostic
                .as_deref()
                .map(|diagnostic| format!("；页表诊断：{diagnostic}"))
                .unwrap_or_default()
        );
    }
    Ok(best)
}

pub(crate) fn discover_page_table_root_for_virtual(
    image: &MemoryImage,
    virtual_address: u64,
) -> Result<(u64, u64)> {
    ensure!(
        is_canonical_48(virtual_address),
        "无符号页表锚点不是 48 位规范地址"
    );
    let pml4_index = (virtual_address >> 39) & 0x1ff;
    for span in image.spans() {
        let mut root = align_up(span.start, PAGE_SIZE).context("页表候选地址溢出")?;
        let end = span.end() & !(PAGE_SIZE - 1);
        while root < end {
            let entry_address = root + pml4_index * 8;
            let Ok(entry) = image.read_u64_physical(entry_address) else {
                root += PAGE_SIZE;
                continue;
            };
            if entry & 1 == 0
                || entry & (1 << 7) != 0
                || !image.contains_physical(entry & ADDRESS_MASK_4K)
            {
                root += PAGE_SIZE;
                continue;
            }
            let Ok(space) = LinuxX64AddressSpace::new(image, root) else {
                root += PAGE_SIZE;
                continue;
            };
            if let Ok(physical_address) = space.translate(virtual_address)
                && image.contains_physical(physical_address)
            {
                return Ok((root, physical_address));
            }
            root += PAGE_SIZE;
        }
    }
    bail!("没有四级页表能翻译无符号内核锚点 {virtual_address:#x}")
}

fn finish_inferred_task_layout(
    space: &LinuxX64AddressSpace<'_>,
    task_physical: u64,
    task_virtual: u64,
    real_parent: u64,
    comm: u64,
) -> Option<HeuristicTaskLayout> {
    finish_inferred_task_layout_diagnosed(space, task_physical, task_virtual, real_parent, comm)
        .ok()
}

fn finish_inferred_task_layout_diagnosed(
    space: &LinuxX64AddressSpace<'_>,
    task_physical: u64,
    task_virtual: u64,
    real_parent: u64,
    comm: u64,
) -> std::result::Result<HeuristicTaskLayout, String> {
    if space.read_u64(task_virtual + real_parent).ok() != Some(task_virtual)
        || space.read_u64(task_virtual + real_parent + 8).ok() != Some(task_virtual)
        || read_valid_task_comm(space, task_virtual + comm)
            .is_none_or(|name| !name.starts_with("swapper"))
    {
        return Err("init_task 自父指针/名称".to_owned());
    }
    let Some((tasks, task_addresses, task_count)) = infer_tasks_offset(space, task_virtual, comm)
    else {
        return Err(format!(
            "双向 tasks 环（{}）",
            diagnose_task_link_candidates(space, task_virtual, comm)
        ));
    };
    let Some((pid, tgid)) = infer_pid_offsets(space, task_virtual, real_parent, &task_addresses)
    else {
        return Err("PID/TGID".to_owned());
    };
    let Some((state, state_size)) = infer_state_field(space, task_virtual, &task_addresses) else {
        return Err("任务状态".to_owned());
    };
    Ok(HeuristicTaskLayout {
        task_physical,
        task_virtual,
        comm,
        real_parent,
        tasks,
        pid,
        tgid,
        state,
        state_size,
        task_count,
    })
}

fn diagnose_task_link_candidates(
    space: &LinuxX64AddressSpace<'_>,
    init_task: u64,
    comm: u64,
) -> String {
    let mut candidates = Vec::new();
    let mut offset = 0u64;
    while offset + 16 <= comm && candidates.len() < 12 {
        let head = init_task + offset;
        if let (Ok(next), Ok(prev)) = (space.read_u64(head), space.read_u64(head + 8))
            && next != head
            && is_kernel_pointer(next)
            && next >= offset
        {
            let next_back = space.read_u64(next + 8).ok() == Some(head);
            let prev_forward = space.read_u64(prev).ok() == Some(head);
            let next_name = read_valid_task_comm(space, next - offset + comm);
            if next_back || prev_forward || next_name.is_some() {
                candidates.push(format!(
                    "{offset:#x}:next={next:#x}/name={}/back={next_back},prev={prev:#x}/forward={prev_forward},trace=[{}]",
                    next_name.as_deref().unwrap_or("<invalid>"),
                    trace_task_ring(space, init_task, offset, comm)
                ));
            }
        }
        offset += 8;
    }
    if candidates.is_empty() {
        "未发现带反向链接的指针对".to_owned()
    } else {
        candidates.join("; ")
    }
}

fn trace_task_ring(
    space: &LinuxX64AddressSpace<'_>,
    init_task: u64,
    tasks: u64,
    comm: u64,
) -> String {
    let head = init_task + tasks;
    let Ok(mut current) = space.read_u64(head) else {
        return "head unreadable".to_owned();
    };
    let mut previous = head;
    let mut trace = Vec::new();
    for _ in 0..8 {
        if current == head {
            trace.push("closed".to_owned());
            break;
        }
        if !is_kernel_pointer(current) || current < tasks {
            trace.push(format!("invalid={current:#x}"));
            break;
        }
        let task = current - tasks;
        let back = space.read_u64(current + 8).ok();
        let name =
            read_valid_task_comm(space, task + comm).unwrap_or_else(|| "<invalid-comm>".to_owned());
        trace.push(format!(
            "{task:#x}:{name}:back_ok={}",
            back == Some(previous)
        ));
        let Ok(next) = space.read_u64(current) else {
            trace.push("next unreadable".to_owned());
            break;
        };
        previous = current;
        current = next;
    }
    trace.join(",")
}

fn infer_tasks_offset(
    space: &LinuxX64AddressSpace<'_>,
    init_task: u64,
    comm: u64,
) -> Option<(u64, Vec<u64>, usize)> {
    let mut best: Option<(bool, usize, usize, u64, Vec<u64>)> = None;
    let mut offset = 0u64;
    while offset + 16 <= comm {
        let head = init_task.checked_add(offset)?;
        let (Ok(next), Ok(prev)) = (space.read_u64(head), space.read_u64(head + 8)) else {
            offset = offset.checked_add(8)?;
            continue;
        };
        if next != head
            && is_kernel_pointer(next)
            && next >= offset
            && (prev == head || is_kernel_pointer(prev))
        {
            let mut current = next;
            let mut previous = head;
            let mut visited = HashSet::new();
            let mut samples = Vec::new();
            let mut count = 0usize;
            let mut backlinks = 0usize;
            while current != head && count < 65_536 {
                if !is_kernel_pointer(current) || current < offset || !visited.insert(current) {
                    break;
                }
                let task = current - offset;
                if read_valid_task_comm(space, task + comm).is_none() {
                    break;
                }
                backlinks += usize::from(space.read_u64(current + 8).ok() == Some(previous));
                if samples.len() < 128 {
                    samples.push(task);
                }
                count += 1;
                previous = current;
                let Some(next_link) = space.read_u64(current).ok() else {
                    break;
                };
                current = next_link;
            }
            let closed = current == head;
            backlinks += usize::from(closed && space.read_u64(head + 8).ok() == Some(previous));
            if count >= 4
                && (closed || count >= 8)
                && backlinks * 2 >= count
                && best.as_ref().is_none_or(
                    |(current_closed, current_count, current_backlinks, _, _)| {
                        (closed, count, backlinks)
                            > (*current_closed, *current_count, *current_backlinks)
                    },
                )
            {
                best = Some((closed, count, backlinks, offset, samples));
            }
        }
        offset = offset.checked_add(8)?;
    }
    best.map(|(_, count, _, offset, samples)| (offset, samples, count))
}

fn infer_pid_offsets(
    space: &LinuxX64AddressSpace<'_>,
    init_task: u64,
    real_parent: u64,
    tasks: &[u64],
) -> Option<(u64, u64)> {
    const PID_MAX_LIMIT: i32 = 4_194_304;
    let start = real_parent.saturating_sub(0x80);
    let mut offset = start & !3;
    let mut best: Option<(usize, usize, usize, u64)> = None;
    while offset + 8 <= real_parent {
        if space.read_i32(init_task + offset).ok() == Some(0)
            && space.read_i32(init_task + offset + 4).ok() == Some(0)
        {
            let mut pids = HashSet::new();
            let mut equal = 0usize;
            let mut parents = 0usize;
            let mut valid = true;
            for task in tasks.iter().take(96) {
                let Some(pid) = space.read_i32(*task + offset).ok() else {
                    valid = false;
                    break;
                };
                let Some(tgid) = space.read_i32(*task + offset + 4).ok() else {
                    valid = false;
                    break;
                };
                if !(1..=PID_MAX_LIMIT).contains(&pid) || !(1..=PID_MAX_LIMIT).contains(&tgid) {
                    valid = false;
                    break;
                }
                pids.insert(pid);
                equal += usize::from(pid == tgid);
                if let Ok(parent) = space.read_u64(*task + real_parent)
                    && is_kernel_pointer(parent)
                    && space
                        .read_i32(parent + offset + 4)
                        .is_ok_and(|value| (0..=PID_MAX_LIMIT).contains(&value))
                {
                    parents += 1;
                }
            }
            if valid && pids.len() == tasks.len().min(96) && parents == tasks.len().min(96) {
                let score = (pids.len(), equal, parents, offset);
                if best.as_ref().is_none_or(|current| score > *current) {
                    best = Some(score);
                }
            }
        }
        offset = offset.checked_add(4)?;
    }
    best.map(|(_, _, _, offset)| (offset, offset + 4))
}

fn infer_state_field(
    space: &LinuxX64AddressSpace<'_>,
    init_task: u64,
    tasks: &[u64],
) -> Option<(u64, usize)> {
    let mut best: Option<((usize, usize, u64), u64, usize)> = None;
    for size in [8usize, 4usize] {
        let step = size as u64;
        let mut offset = 0u64;
        while offset < 0x40 {
            let init = match size {
                8 => space.read_u64(init_task + offset).ok(),
                4 => space.read_u32(init_task + offset).ok().map(u64::from),
                _ => None,
            }?;
            if init == 0 {
                let mut nonzero = 0usize;
                let mut valid = true;
                for task in tasks.iter().take(96) {
                    let value = match size {
                        8 => space.read_u64(*task + offset).ok(),
                        4 => space.read_u32(*task + offset).ok().map(u64::from),
                        _ => None,
                    };
                    let Some(value) = value else {
                        valid = false;
                        break;
                    };
                    if value > 0x4000 {
                        valid = false;
                        break;
                    }
                    nonzero += usize::from(value != 0);
                }
                if valid && nonzero > 0 {
                    let alignment = usize::from(offset.is_multiple_of(size as u64));
                    let score = (nonzero, alignment, u64::MAX - offset);
                    if best.as_ref().is_none_or(|(current, _, _)| score > *current) {
                        best = Some((score, offset, size));
                    }
                }
            }
            offset = offset.checked_add(step)?;
        }
    }
    best.map(|(_, offset, size)| (offset, size))
}

fn read_valid_task_comm(space: &LinuxX64AddressSpace<'_>, address: u64) -> Option<String> {
    let mut bytes = [0u8; 16];
    space.read_virtual(address, &mut bytes).ok()?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    if end == 0 {
        return None;
    }
    let printable = bytes[..end]
        .iter()
        .filter(|byte| (0x20..=0x7e).contains(*byte))
        .count();
    if printable * 2 < end {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn profile_from_volatility_isf(isf: &LinuxIsf) -> Result<LinuxTaskProfile> {
    ensure!(
        is_kernel_pointer(isf.symbol_address("init_task")?),
        "Volatility 3 ISF init_task 不是规范内核链接地址"
    );
    let state_names = ["__state", "state"];
    let comm_len = usize::try_from(isf.field_array_count("task_struct", "comm")?)
        .context("task_struct.comm 数组长度无法转换")?;
    let profile = LinuxTaskProfile {
        source: "volatility3_isf",
        fingerprint: format!("{}; task_struct=runtime-validated", isf.fingerprint()),
        btf_physical_address: None,
        task_size: isf.type_size("task_struct")?,
        tasks: isf.field_offset("task_struct", "tasks")?,
        pid: isf.field_offset("task_struct", "pid")?,
        tgid: isf.field_offset("task_struct", "tgid")?,
        comm: isf.field_offset("task_struct", "comm")?,
        comm_len,
        real_parent: isf.field_offset("task_struct", "real_parent")?,
        parent: isf.optional_field_offset("task_struct", "parent")?,
        state: isf.field_offset_any("task_struct", &state_names)?,
        state_size: usize::try_from(isf.field_size_any("task_struct", &state_names)?)
            .context("task_struct state 字段大小无法转换")?,
        exit_state: isf.optional_field_offset("task_struct", "exit_state")?,
        flags: isf.optional_field_offset("task_struct", "flags")?,
        mm: isf.optional_field_offset("task_struct", "mm")?,
        start_time: LinuxTaskStartTime::from_isf(isf)?,
    };
    profile.validate()?;
    Ok(profile)
}

fn select_runtime_context(
    image: &MemoryImage,
    discovery: &LinuxDiscovery,
    profile: &LinuxTaskProfile,
    selected_banner: &BannerEvidence,
    selected_release: &str,
    isf: Option<&LinuxIsf>,
) -> Result<Option<LinuxRuntimeSelection>> {
    select_runtime_context_diagnosed(
        image,
        discovery,
        profile,
        selected_banner,
        selected_release,
        isf,
        &mut Vec::new(),
    )
}

/// 同 [`select_runtime_context`]，但把每个候选的首个失败原因写进 `reasons`。
///
/// 全部候选都失败时，调用方原本只能抛一句「没有任何候选通过验证」的兜底文案 ——
/// 它把页表翻译不一致、pid 非零、comm 不是 swapper、父指针不是自指针、
/// tasks 环断裂等七八种完全不同的原因压成同一句话，既定位不了问题，也判断不出
/// 是镜像残缺还是别的。带上原因才谈得上排查。
fn select_runtime_context_diagnosed(
    image: &MemoryImage,
    discovery: &LinuxDiscovery,
    profile: &LinuxTaskProfile,
    selected_banner: &BannerEvidence,
    selected_release: &str,
    isf: Option<&LinuxIsf>,
    reasons: &mut Vec<String>,
) -> Result<Option<LinuxRuntimeSelection>> {
    let init_candidates = discover_init_task_candidates(image, profile, &discovery.swapper_hits)?;
    for init in init_candidates {
        for vmcoreinfo in discovery
            .vmcoreinfo
            .iter()
            .filter(|evidence| evidence.release == selected_release)
        {
            let Ok(directory_table_base) = vmcore_directory_table_base(image, vmcoreinfo) else {
                continue;
            };
            let space = LinuxX64AddressSpace::new(image, directory_table_base)?;
            match validate_selected_runtime_context(&space, profile, &init, isf, selected_banner) {
                Ok(()) => {
                    return Ok(Some((
                        init,
                        directory_table_base,
                        "vmcoreinfo".to_owned(),
                        Some(vmcoreinfo.physical_address),
                    )));
                }
                Err(error) => record_runtime_reason(
                    reasons,
                    format_args!(
                        "vmcoreinfo(dtb={directory_table_base:#x}) init_task={:#x}/{:#x}：{error:#}",
                        init.virtual_address, init.physical_address
                    ),
                ),
            }
        }
        if let Ok(directory_table_base) =
            discover_page_table_root(image, profile, &init, isf, selected_banner)
        {
            let space = LinuxX64AddressSpace::new(image, directory_table_base)?;
            match validate_selected_runtime_context(&space, profile, &init, isf, selected_banner) {
                Ok(()) => {
                    return Ok(Some((
                        init,
                        directory_table_base,
                        "validated_pml4_scan".to_owned(),
                        None,
                    )));
                }
                Err(error) => record_runtime_reason(
                    reasons,
                    format_args!(
                        "pml4扫描(dtb={directory_table_base:#x}) init_task={:#x}/{:#x}：{error:#}",
                        init.virtual_address, init.physical_address
                    ),
                ),
            }
        }
    }
    Ok(None)
}

/// 收集候选失败原因；同一句原因只留一条，并封顶，避免几百个候选把错误刷爆。
fn record_runtime_reason(reasons: &mut Vec<String>, reason: std::fmt::Arguments<'_>) {
    const MAX_REASONS: usize = 6;
    if reasons.len() >= MAX_REASONS {
        return;
    }
    let text = reason.to_string();
    if !reasons.iter().any(|existing| existing == &text) {
        reasons.push(text);
    }
}

fn validate_isf_runtime_context(
    space: &LinuxX64AddressSpace<'_>,
    isf: &LinuxIsf,
    init: &InitTaskCandidate,
    selected_banner: &BannerEvidence,
) -> Result<()> {
    ensure!(
        isf.banner() == selected_banner.text,
        "ISF linux_banner 与已选镜像 banner 不同"
    );
    let linked_init = isf.symbol_address("init_task")?;
    let slide = init
        .virtual_address
        .checked_sub(linked_init)
        .context("运行时 init_task 低于 ISF 链接地址")?;
    ensure!(slide & (PAGE_SIZE - 1) == 0, "ISF 内核 slide 未按页对齐");
    ensure!(slide <= 0x4000_0000, "ISF 内核 slide 超出安全范围");
    let runtime_banner = isf
        .symbol_address("linux_banner")?
        .checked_add(slide)
        .context("运行时 linux_banner 地址溢出")?;
    ensure!(
        is_kernel_pointer(runtime_banner),
        "运行时 linux_banner 不是规范内核指针"
    );
    let mut bytes = vec![0u8; isf.banner().len().saturating_add(2)];
    space
        .read_virtual(runtime_banner, &mut bytes)
        .context("无法读取 ISF 推导的运行时 linux_banner")?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let runtime = std::str::from_utf8(&bytes[..end])
        .context("运行时 linux_banner 不是 UTF-8")?
        .trim_end();
    ensure!(
        runtime == isf.banner(),
        "ISF init_task 与 linux_banner 未共享同一有效内核 slide"
    );
    Ok(())
}

/// Exact symbols and a byte-verified runtime banner establish layout identity independently
/// of the mutable task-list tail. Keep the head and first backlink strict; the actual walker
/// reports a torn tail/cycle/missing page as partial evidence. Inferred layouts still require
/// both boundary links and never gain this exception.
fn validate_selected_runtime_context(
    space: &LinuxX64AddressSpace<'_>,
    profile: &LinuxTaskProfile,
    init: &InitTaskCandidate,
    isf: Option<&LinuxIsf>,
    banner: &BannerEvidence,
) -> Result<()> {
    match isf {
        Some(table) => {
            validate_isf_runtime_context(space, table, init, banner)?;
            validate_runtime_head(space, profile, init)?;
            let head = init.virtual_address + profile.tasks;
            if init.tasks_next != head {
                let task = init
                    .tasks_next
                    .checked_sub(profile.tasks)
                    .context("首个 task 地址下溢")?;
                let record = read_process_record(space, profile, task, init.tasks_next)?;
                ensure!(
                    record.pid > 0 && record.pid == record.tgid,
                    "首个活动任务不是线程组主进程"
                );
            }
            Ok(())
        }
        None => validate_runtime_context(space, profile, init),
    }
}

pub(crate) fn linux_release(banner: &str) -> Option<String> {
    let release = banner
        .strip_prefix("Linux version ")?
        .split_ascii_whitespace()
        .next()?;
    if release.len() < 3
        || release.len() > 128
        || !release.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+' | b'~')
        })
    {
        return None;
    }

    // A Linux kernel release starts with a numeric major.minor pair.  Merely
    // finding English prose such as "Linux version lacks ..." is not kernel
    // banner evidence and must not influence profile or release selection.
    let (major, remainder) = release.split_once('.')?;
    let minor = remainder.split(['.', '-']).next()?;
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(release.to_owned())
}

fn normalize_linux_banner(mut banner: String) -> String {
    // Ubuntu banners end in a parenthesized source-package identity.  Captured
    // copies can lose their terminating NUL and bleed a few adjacent bytes;
    // truncate only when that distro-specific group occurs after the kernel's
    // `#build` marker.  A compiler identity such as `gcc (Ubuntu 13.3...)`
    // appears before `#build` and is part of the real banner.
    if let Some(build) = banner.find(" #")
        && let Some(relative_group) = banner[build..].rfind("(Ubuntu ")
        && let Some(group) = build.checked_add(relative_group)
        && let Some(relative_end) = banner[group..].find(')')
    {
        banner.truncate(group + relative_end + 1);
    }
    banner.trim_end().to_owned()
}

fn parse_vmcoreinfo(physical_address: u64, text: &str) -> Result<VmcoreInfoEvidence> {
    let values = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect::<HashMap<_, _>>();
    let release = values
        .get("OSRELEASE")
        .copied()
        .context("VMCOREINFO 缺少 OSRELEASE")?;
    ensure!(
        !release.is_empty() && !release.contains('%'),
        "VMCOREINFO OSRELEASE 无效"
    );
    let page_size = parse_vmcore_number(
        values
            .get("PAGESIZE")
            .copied()
            .context("VMCOREINFO 缺少 PAGESIZE")?,
    )?;
    ensure!(page_size == PAGE_SIZE, "VMCOREINFO PAGESIZE 不是 4096");
    let page_table = values
        .get("SYMBOL(swapper_pg_dir)")
        .or_else(|| values.get("SYMBOL(init_top_pgt)"))
        .copied()
        .context("VMCOREINFO 缺少 swapper_pg_dir/init_top_pgt")?;
    let page_table_virtual = parse_vmcore_hex(page_table)?;
    ensure!(
        is_kernel_pointer(page_table_virtual) && page_table_virtual & (PAGE_SIZE - 1) == 0,
        "VMCOREINFO 页表符号地址无效"
    );
    let phys_base = parse_vmcore_number(
        values
            .get("NUMBER(phys_base)")
            .copied()
            .context("VMCOREINFO 缺少 NUMBER(phys_base)")?,
    )?;
    let stext_virtual = values
        .get("SYMBOL(_stext)")
        .map(|value| parse_vmcore_hex(value))
        .transpose()?;
    if let Some(address) = stext_virtual {
        ensure!(
            is_kernel_pointer(address),
            "VMCOREINFO SYMBOL(_stext) 不是规范内核指针"
        );
    }
    let kernel_offset = values
        .get("KERNELOFFSET")
        .map(|value| parse_vmcore_hex(value))
        .transpose()?;
    let pgtable_l5_enabled = values
        .get("NUMBER(pgtable_l5_enabled)")
        .map(|value| parse_vmcore_number(value))
        .transpose()?;
    let sme_mask = values
        .get("NUMBER(sme_mask)")
        .map(|value| parse_vmcore_number(value))
        .transpose()?;
    Ok(VmcoreInfoEvidence {
        physical_address,
        release: release.to_owned(),
        page_table_virtual,
        phys_base,
        stext_virtual,
        kernel_offset,
        pgtable_l5_enabled,
        sme_mask,
    })
}

fn parse_vmcore_hex(value: &str) -> Result<u64> {
    u64::from_str_radix(value.trim().trim_start_matches("0x"), 16)
        .with_context(|| format!("VMCOREINFO 十六进制数值无效：{value}"))
}

fn parse_vmcore_number(value: &str) -> Result<u64> {
    let value = value.trim();
    if value.starts_with("0x") {
        return parse_vmcore_hex(value);
    }
    value
        .parse::<u64>()
        // 内核的 VMCOREINFO_NUMBER 宏按 `%ld` 输出有符号 long，KASLR 一开
        // NUMBER(phys_base) 常态为负（实测 Debian 5.4 上是 -836763648）。
        // 少了这一步整块 VMCOREINFO 会被判无效丢弃，Linux 会话再也开不起来。
        .or_else(|_| value.parse::<i64>().map(|signed| signed as u64))
        .or_else(|_| u64::from_str_radix(value, 16))
        .with_context(|| format!("VMCOREINFO NUMBER 数值无效：{value}"))
}

fn vmcore_directory_table_base(image: &MemoryImage, evidence: &VmcoreInfoEvidence) -> Result<u64> {
    ensure!(
        evidence.pgtable_l5_enabled.unwrap_or(0) == 0,
        "VMCOREINFO 表明目标启用了五级页表，当前 Linux pslist 仅支持四级页表"
    );
    ensure!(
        evidence.sme_mask.unwrap_or(0) == 0,
        "VMCOREINFO 表明目标启用了内存加密位，当前 Linux pslist 尚未清除 SME mask"
    );
    let image_relative = evidence
        .page_table_virtual
        .checked_sub(X86_KERNEL_IMAGE_BASE)
        .context("VMCOREINFO 页表地址低于 x86 kernel image base")?;
    // phys_base 语义上是有符号的，负值以补码存在 u64 里，这里的加法本就是
    // 模运算：-0x31E00000 + 0x3e80a000 = 0xca0a000。用 checked_add 会把这种
    // 完全正常的 KASLR 镜像判成「溢出」。真正的安全网是下面的页对齐检查与
    // contains_physical —— 算错的根不可能同时通过这两道。
    let root = evidence.phys_base.wrapping_add(image_relative);
    ensure!(root & (PAGE_SIZE - 1) == 0, "VMCOREINFO 页表根未对齐");
    ensure!(
        image.contains_physical(root),
        "VMCOREINFO 推导的页表根 {root:#x} 不在采集范围"
    );
    Ok(root)
}

fn resolve_kernel_text_evidence(
    image: &MemoryImage,
    discovery: &LinuxDiscovery,
    directory_table_base: u64,
    vmcoreinfo_physical_address: Option<u64>,
    init: &InitTaskCandidate,
    isf: Option<&LinuxIsf>,
) -> Result<Option<LinuxKernelTextEvidence>> {
    let selected_vmcoreinfo = vmcoreinfo_physical_address.and_then(|physical_address| {
        discovery
            .vmcoreinfo
            .iter()
            .find(|evidence| evidence.physical_address == physical_address)
    });
    let candidate = selected_vmcoreinfo
        .and_then(|evidence| {
            evidence.stext_virtual.map(|virtual_address| {
                (
                    virtual_address,
                    "vmcoreinfo:SYMBOL(_stext)".to_owned(),
                    evidence.kernel_offset,
                    Some(evidence.phys_base),
                )
            })
        })
        .or_else(|| {
            let table = isf?;
            let linked_stext = table.symbol_address("_stext").ok()?;
            let linked_init = table.symbol_address("init_task").ok()?;
            let slide = init.virtual_address.checked_sub(linked_init)?;
            let virtual_address = linked_stext.checked_add(slide)?;
            Some((
                virtual_address,
                "volatility3_isf:_stext+validated_init_task_slide".to_owned(),
                Some(slide),
                selected_vmcoreinfo.map(|evidence| evidence.phys_base),
            ))
        });
    let Some((virtual_address, symbol_source, kernel_offset, phys_base)) = candidate else {
        return Ok(None);
    };
    ensure!(
        is_kernel_pointer(virtual_address),
        "_stext {virtual_address:#x} 不是规范内核指针"
    );
    let space = LinuxX64AddressSpace::new(image, directory_table_base)?;
    let physical_address = space
        .translate(virtual_address)
        .context("无法通过已验证 Linux 页表翻译 _stext")?;
    ensure!(
        image.contains_physical(physical_address),
        "_stext 页表翻译结果 {physical_address:#x} 不在采集范围"
    );
    const VERIFY_BYTES: usize = 16;
    let mut virtual_bytes = [0u8; VERIFY_BYTES];
    let mut physical_bytes = [0u8; VERIFY_BYTES];
    space
        .read_virtual(virtual_address, &mut virtual_bytes)
        .context("无法读取 _stext 的首条内核指令")?;
    image
        .read_physical(physical_address, &mut physical_bytes)
        .context("无法读取 _stext 对应物理页")?;
    ensure!(
        virtual_bytes == physical_bytes,
        "_stext 的虚拟读取与物理读取字节不一致"
    );
    ensure!(
        virtual_bytes.iter().any(|byte| *byte != 0),
        "_stext 的首 {VERIFY_BYTES} 字节全为零，拒绝报告伪地址"
    );
    Ok(Some(LinuxKernelTextEvidence {
        virtual_address,
        physical_address,
        symbol_source,
        kernel_offset,
        phys_base,
        first_bytes_hex: hex::encode(virtual_bytes),
        bytes_verified: VERIFY_BYTES,
    }))
}

// Filled only with exact, full-build fingerprints.  Offsets are added below
// alongside their provenance; a release-name-only fallback is intentionally
// forbidden because Ubuntu HWE kernels can share uname strings across builds.
fn exact_banner_profile(banner: &str) -> Option<LinuxTaskProfile> {
    let profile = match banner {
        UBUNTU_5_4_0_84_BIONIC => LinuxTaskProfile {
            source: "exact_banner_profile",
            fingerprint: "Ubuntu Bionic HWE 5.4.0-84.94; banner_sha256=1b1376f3ad4aa6a9d542261e94649daeb2fae2c92fc87d8d5d3b53fa3cb69356; build_id=c56268a4878b2c99f78e1fa2d0ace9bc5f6d575d; runtime-validated task layout".to_owned(),
            btf_physical_address: None,
            task_size: 0x2400,
            state: 0x10,
            state_size: 8,
            tasks: 0x7c0,
            mm: Some(0x810),
            pid: 0x8c0,
            tgid: 0x8c4,
            real_parent: 0x8d0,
            parent: Some(0x8d8),
            start_time: Some(LinuxTaskStartTime::Nanoseconds(0x9e8)),
            comm: 0xa78,
            comm_len: 16,
            exit_state: None,
            flags: None,
        },
        UBUNTU_4_13_0_36_XENIAL => LinuxTaskProfile {
            source: "exact_banner_profile",
            fingerprint: "Ubuntu Xenial HWE 4.13.0-36.40; banner_sha256=4b5aecdcfa9a9d79637be74580ce16f92a65efb027662cfc863e33f050309975; build_id=d9142b737a5bb09c7f1aef87f7dd2834dba7d934; runtime-validated task layout".to_owned(),
            btf_physical_address: None,
            task_size: 0x2400,
            state: 0x08,
            state_size: 8,
            tasks: 0x800,
            mm: Some(0x850),
            pid: 0x900,
            tgid: 0x904,
            real_parent: 0x910,
            parent: Some(0x918),
            start_time: Some(LinuxTaskStartTime::Nanoseconds(0xa28)),
            comm: 0xaa8,
            comm_len: 16,
            exit_state: None,
            flags: None,
        },
        UBUNTU_6_8_0_49_NOBLE => LinuxTaskProfile {
            source: "exact_banner_profile",
            fingerprint: "Ubuntu Noble 6.8.0-49.49; banner_sha256=78f733edb03a7139bf1e0b14e565ab9733449c4e7b0daa6997b6432fa310a3f9; build_id=9c2aa265a404792954898609a7a72988d9bac935; runtime-validated task layout".to_owned(),
            btf_physical_address: None,
            task_size: 0x3580,
            state: 0x18,
            state_size: 4,
            tasks: 0x8d0,
            mm: Some(0x920),
            pid: 0x9a0,
            tgid: 0x9a4,
            real_parent: 0x9b0,
            parent: Some(0x9b8),
            start_time: Some(LinuxTaskStartTime::Nanoseconds(0xaf8)),
            comm: 0xbc0,
            comm_len: 16,
            exit_state: None,
            flags: None,
        },
        DEEPIN_4_9_0_57_1 => LinuxTaskProfile {
            source: "exact_banner_profile",
            fingerprint: "Deepin 15.5 4.9.57-1; banner_sha256=087e194cadd568ddd4ddd945029e6f3e0ad5bf551fa34d324a85cb9efa1af81f; build_id=b026618626bc7370e33edfc59f132b8f7de5892b; ISO MD5=0d2bb518b30356ef83c13bfb6f450466; dwarf2json/runtime-validated task layout".to_owned(),
            btf_physical_address: None,
            task_size: 0x1b40,
            state: 0x08,
            state_size: 8,
            tasks: 0x3a8,
            mm: Some(0x3f8),
            pid: 0x4a8,
            tgid: 0x4ac,
            real_parent: 0x4b8,
            parent: Some(0x4c0),
            start_time: Some(LinuxTaskStartTime::Nanoseconds(0x5e0)),
            comm: 0x660,
            comm_len: 16,
            exit_state: Some(0x444),
            flags: Some(0x1c),
        },
        _ => return None,
    };
    Some(profile)
}

#[derive(Debug, Clone, Copy)]
struct BtfHeader {
    header_len: usize,
    type_offset: usize,
    type_len: usize,
    string_offset: usize,
    string_len: usize,
    total_len: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct BtfTypeMeta {
    kind: u8,
    value: u32,
    array: Option<(u32, u32)>,
}

#[derive(Debug, Clone, Copy)]
struct BtfMember {
    offset: u64,
    type_id: u32,
}

fn profile_from_memory_btf(
    image: &MemoryImage,
    candidates: &[u64],
) -> Result<Option<LinuxTaskProfile>> {
    let mut headers = Vec::new();
    for physical in candidates {
        let mut bytes = [0u8; 24];
        if image.read_physical(*physical, &mut bytes).is_err() {
            continue;
        }
        if let Ok(header) = parse_btf_header(&bytes) {
            headers.push((*physical, header));
        }
    }
    // vmlinux BTF is normally much larger than module BTF.  Trying the
    // largest structurally valid blobs first avoids reading every module blob.
    headers.sort_unstable_by_key(|(_, header)| std::cmp::Reverse(header.total_len));
    for (physical, header) in headers {
        let mut blob = vec![0u8; header.total_len];
        if image.read_physical(physical, &mut blob).is_err() {
            continue;
        }
        if let Ok(profile) = task_profile_from_btf_blob(&blob, physical, header) {
            return Ok(Some(profile));
        }
    }
    Ok(None)
}

fn parse_btf_header(bytes: &[u8]) -> Result<BtfHeader> {
    ensure!(read_u16(bytes, 0)? == 0xeb9f, "BTF magic 无效");
    ensure!(bytes.get(2) == Some(&1), "BTF version 不支持");
    ensure!(bytes.get(3) == Some(&0), "BTF flags 不支持");
    let header_len = usize::try_from(read_u32(bytes, 4)?)?;
    let type_offset = usize::try_from(read_u32(bytes, 8)?)?;
    let type_len = usize::try_from(read_u32(bytes, 12)?)?;
    let string_offset = usize::try_from(read_u32(bytes, 16)?)?;
    let string_len = usize::try_from(read_u32(bytes, 20)?)?;
    ensure!((24..=4096).contains(&header_len), "BTF header 长度不合理");
    ensure!(type_len > 0 && string_len > 1, "BTF 类型或字符串区为空");
    let type_end = type_offset
        .checked_add(type_len)
        .context("BTF type section 长度溢出")?;
    let string_end = string_offset
        .checked_add(string_len)
        .context("BTF string section 长度溢出")?;
    let total_len = header_len
        .checked_add(type_end.max(string_end))
        .context("BTF 总长度溢出")?;
    ensure!(total_len <= MAX_BTF_SIZE, "BTF blob 超过安全读取上限");
    Ok(BtfHeader {
        header_len,
        type_offset,
        type_len,
        string_offset,
        string_len,
        total_len,
    })
}

fn task_profile_from_btf_blob(
    blob: &[u8],
    physical: u64,
    header: BtfHeader,
) -> Result<LinuxTaskProfile> {
    ensure!(blob.len() >= header.total_len, "BTF blob 被截断");
    let type_start = header
        .header_len
        .checked_add(header.type_offset)
        .context("BTF type 起点溢出")?;
    let type_end = type_start
        .checked_add(header.type_len)
        .context("BTF type 终点溢出")?;
    let string_start = header
        .header_len
        .checked_add(header.string_offset)
        .context("BTF string 起点溢出")?;
    let string_end = string_start
        .checked_add(header.string_len)
        .context("BTF string 终点溢出")?;
    let strings = blob
        .get(string_start..string_end)
        .context("BTF string section 被截断")?;
    ensure!(strings.first() == Some(&0), "BTF 字符串区未以空字符串开始");

    let mut cursor = type_start;
    let mut types = vec![BtfTypeMeta::default()]; // type id zero is void.
    let mut task_size = None;
    let mut task_fields = HashMap::<String, BtfMember>::new();
    while cursor < type_end {
        ensure!(cursor + 12 <= type_end, "BTF type record 头被截断");
        let name_offset = usize::try_from(read_u32(blob, cursor)?)?;
        let info = read_u32(blob, cursor + 4)?;
        let value = read_u32(blob, cursor + 8)?;
        let kind = ((info >> 24) & 0x1f) as u8;
        let kind_flag = info >> 31 != 0;
        let vlen = usize::try_from(info & 0xffff)?;
        let name = btf_string(strings, name_offset)?;
        cursor += 12;

        let extra_len = match kind {
            1 => 4,
            2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
            3 => 12,
            4 | 5 => vlen.checked_mul(12).context("BTF member 数量溢出")?,
            6 => vlen.checked_mul(8).context("BTF enum 数量溢出")?,
            13 => vlen.checked_mul(8).context("BTF 参数数量溢出")?,
            14 | 17 => 4,
            15 | 19 => vlen.checked_mul(12).context("BTF 记录数量溢出")?,
            _ => bail!("不支持的 BTF kind {kind}"),
        };
        ensure!(cursor + extra_len <= type_end, "BTF kind {kind} 记录被截断");

        let mut meta = BtfTypeMeta {
            kind,
            value,
            array: None,
        };
        if kind == 3 {
            meta.array = Some((read_u32(blob, cursor)?, read_u32(blob, cursor + 8)?));
        }
        if kind == 4 && name == "task_struct" {
            task_size = Some(u64::from(value));
            for index in 0..vlen {
                let member = cursor + index * 12;
                let member_name = btf_string(strings, usize::try_from(read_u32(blob, member)?)?)?;
                if !matches!(
                    member_name,
                    "tasks"
                        | "pid"
                        | "tgid"
                        | "comm"
                        | "real_parent"
                        | "parent"
                        | "state"
                        | "__state"
                        | "exit_state"
                        | "flags"
                        | "mm"
                        | "start_time"
                ) {
                    continue;
                }
                let raw_offset = read_u32(blob, member + 8)?;
                let bit_offset = if kind_flag {
                    raw_offset & 0x00ff_ffff
                } else {
                    raw_offset
                };
                ensure!(
                    bit_offset % 8 == 0,
                    "task_struct.{member_name} 不是字节对齐字段"
                );
                task_fields.insert(
                    member_name.to_owned(),
                    BtfMember {
                        offset: u64::from(bit_offset / 8),
                        type_id: read_u32(blob, member + 4)?,
                    },
                );
            }
        }
        types.push(meta);
        cursor += extra_len;
    }
    ensure!(cursor == type_end, "BTF type section 未精确结束");
    let task_size = task_size.context("BTF 不包含完整的 task_struct 定义")?;
    let field = |name: &str| {
        task_fields
            .get(name)
            .copied()
            .with_context(|| format!("BTF task_struct 缺少 {name} 字段"))
    };
    let state = task_fields
        .get("__state")
        .or_else(|| task_fields.get("state"))
        .copied()
        .context("BTF task_struct 缺少 state/__state 字段")?;
    let comm = field("comm")?;
    let state_size = btf_type_size(&types, state.type_id, 0)?;
    let comm_len = btf_type_size(&types, comm.type_id, 0)?;
    let optional = |name: &str| task_fields.get(name).map(|field| field.offset);
    let profile = LinuxTaskProfile {
        source: "memory_btf",
        fingerprint: format!(
            "BTF@{physical:#x}/types={}/strings={}",
            header.type_len, header.string_len
        ),
        btf_physical_address: Some(physical),
        task_size,
        tasks: field("tasks")?.offset,
        pid: field("pid")?.offset,
        tgid: field("tgid")?.offset,
        comm: comm.offset,
        comm_len,
        real_parent: field("real_parent")?.offset,
        parent: optional("parent"),
        state: state.offset,
        state_size,
        exit_state: optional("exit_state"),
        flags: optional("flags"),
        mm: optional("mm"),
        start_time: optional("start_time").map(LinuxTaskStartTime::Nanoseconds),
    };
    profile.validate()?;
    Ok(profile)
}

fn btf_type_size(types: &[BtfTypeMeta], type_id: u32, depth: usize) -> Result<usize> {
    ensure!(depth < 32, "BTF 类型引用过深");
    let meta = types
        .get(usize::try_from(type_id)?)
        .context("BTF 类型引用越界")?;
    match meta.kind {
        1 | 4 | 5 | 6 | 16 | 19 => Ok(usize::try_from(meta.value)?),
        2 => Ok(8),
        3 => {
            let (element, count) = meta.array.context("BTF array 缺少描述符")?;
            btf_type_size(types, element, depth + 1)?
                .checked_mul(usize::try_from(count)?)
                .context("BTF array 大小溢出")
        }
        8 | 9 | 10 | 11 | 18 => btf_type_size(types, meta.value, depth + 1),
        _ => bail!("BTF kind {} 没有可用的字段大小", meta.kind),
    }
}

fn btf_string(strings: &[u8], offset: usize) -> Result<&str> {
    let tail = strings.get(offset..).context("BTF 字符串偏移越界")?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .context("BTF 字符串未终止")?;
    std::str::from_utf8(&tail[..end]).context("BTF 字符串不是 UTF-8")
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value: [u8; 2] = bytes
        .get(offset..offset + 2)
        .context("读取 u16 时越界")?
        .try_into()?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .context("读取 u32 时越界")?
        .try_into()?;
    Ok(u32::from_le_bytes(value))
}

#[derive(Debug, Clone, Copy)]
struct InitTaskCandidate {
    physical_address: u64,
    virtual_address: u64,
    tasks_next: u64,
    tasks_prev: u64,
}

fn discover_init_task_candidates(
    image: &MemoryImage,
    profile: &LinuxTaskProfile,
    swapper_hits: &[u64],
) -> Result<Vec<InitTaskCandidate>> {
    let mut candidates = Vec::new();
    for hit in swapper_hits {
        let Some(task) = hit.checked_sub(profile.comm) else {
            continue;
        };
        let Ok(pid) = read_i32_physical(image, task + profile.pid) else {
            continue;
        };
        let Ok(tgid) = read_i32_physical(image, task + profile.tgid) else {
            continue;
        };
        if pid != 0 || tgid != 0 {
            continue;
        }
        let Ok(name) = read_fixed_name_physical(image, task + profile.comm, profile.comm_len)
        else {
            continue;
        };
        if !name.starts_with("swapper") {
            continue;
        }
        let Ok(real_parent) = image.read_u64_physical(task + profile.real_parent) else {
            continue;
        };
        if !is_kernel_pointer(real_parent) {
            continue;
        }
        if let Some(parent_offset) = profile.parent {
            let Ok(parent) = image.read_u64_physical(task + parent_offset) else {
                continue;
            };
            if parent != real_parent {
                continue;
            }
        }
        let Ok(tasks_next) = image.read_u64_physical(task + profile.tasks) else {
            continue;
        };
        let Ok(tasks_prev) = image.read_u64_physical(task + profile.tasks + 8) else {
            continue;
        };
        if !is_kernel_pointer(tasks_next) || !is_kernel_pointer(tasks_prev) {
            continue;
        }
        candidates.push(InitTaskCandidate {
            physical_address: task,
            virtual_address: real_parent,
            tasks_next,
            tasks_prev,
        });
    }
    candidates.sort_unstable_by_key(|candidate| candidate.physical_address);
    candidates.dedup_by_key(|candidate| candidate.physical_address);
    ensure!(
        !candidates.is_empty(),
        "swapper 命中均未通过 init_task 的 PID/TGID、父指针和任务链基础验证"
    );
    Ok(candidates)
}

fn discover_page_table_root(
    image: &MemoryImage,
    profile: &LinuxTaskProfile,
    init: &InitTaskCandidate,
    isf: Option<&LinuxIsf>,
    banner: &BannerEvidence,
) -> Result<u64> {
    ensure!(
        is_canonical_48(init.virtual_address),
        "init_task 不是 48 位规范地址"
    );
    let pml4_index = (init.virtual_address >> 39) & 0x1ff;
    for span in image.spans() {
        let mut root = align_up(span.start, PAGE_SIZE).context("页表候选地址溢出")?;
        let end = span.end() & !(PAGE_SIZE - 1);
        while root < end {
            let entry_address = root + pml4_index * 8;
            let Ok(entry) = image.read_u64_physical(entry_address) else {
                root += PAGE_SIZE;
                continue;
            };
            if entry & 1 == 0
                || entry & (1 << 7) != 0
                || !image.contains_physical(entry & ADDRESS_MASK_4K)
            {
                root += PAGE_SIZE;
                continue;
            }
            let Ok(space) = LinuxX64AddressSpace::new(image, root) else {
                root += PAGE_SIZE;
                continue;
            };
            if space.translate(init.virtual_address).ok() == Some(init.physical_address)
                && validate_selected_runtime_context(&space, profile, init, isf, banner).is_ok()
            {
                return Ok(root);
            }
            root += PAGE_SIZE;
        }
    }
    bail!(
        "未找到能将 init_task {:#x} 严格翻译到物理地址 {:#x} 的四级页表根",
        init.virtual_address,
        init.physical_address
    )
}

fn validate_runtime_context(
    space: &LinuxX64AddressSpace<'_>,
    profile: &LinuxTaskProfile,
    init: &InitTaskCandidate,
) -> Result<()> {
    validate_runtime_head(space, profile, init)?;
    let head = init.virtual_address + profile.tasks;
    if init.tasks_prev != head {
        ensure!(
            space.read_u64(init.tasks_prev)? == head,
            "最后一个活动任务的 tasks.next 未正向指向 init_task.tasks"
        );
    }
    Ok(())
}

fn validate_runtime_head(
    space: &LinuxX64AddressSpace<'_>,
    profile: &LinuxTaskProfile,
    init: &InitTaskCandidate,
) -> Result<()> {
    ensure!(
        space.translate(init.virtual_address)? == init.physical_address,
        "init_task 虚实地址证据不一致"
    );
    ensure!(
        space.read_i32(init.virtual_address + profile.pid)? == 0,
        "init_task.pid 不是零"
    );
    ensure!(
        space.read_i32(init.virtual_address + profile.tgid)? == 0,
        "init_task.tgid 不是零"
    );
    let name =
        read_fixed_name_virtual(space, init.virtual_address + profile.comm, profile.comm_len)?;
    ensure!(name.starts_with("swapper"), "init_task.comm 不是 swapper");
    ensure!(
        space.read_u64(init.virtual_address + profile.real_parent)? == init.virtual_address,
        "init_task.real_parent 不是自指针"
    );
    if let Some(parent) = profile.parent {
        ensure!(
            space.read_u64(init.virtual_address + parent)? == init.virtual_address,
            "init_task.parent 不是自指针"
        );
    }
    let head = init.virtual_address + profile.tasks;
    ensure!(
        space.read_u64(head)? == init.tasks_next,
        "init_task.tasks.next 虚实读取不一致"
    );
    ensure!(
        space.read_u64(head + 8)? == init.tasks_prev,
        "init_task.tasks.prev 虚实读取不一致"
    );
    if init.tasks_next != head {
        ensure!(
            space.read_u64(init.tasks_next + 8)? == head,
            "首个活动任务的 tasks.prev 未反向指向 init_task.tasks"
        );
    }
    Ok(())
}

pub(crate) struct LinuxX64AddressSpace<'a> {
    image: &'a MemoryImage,
    directory_table_base: u64,
}

impl<'a> LinuxX64AddressSpace<'a> {
    pub(crate) fn new(image: &'a MemoryImage, directory_table_base: u64) -> Result<Self> {
        let directory_table_base = directory_table_base & ADDRESS_MASK_4K;
        ensure!(directory_table_base != 0, "Linux 页表根为零");
        ensure!(
            image.contains_physical(directory_table_base),
            "Linux 页表根 {directory_table_base:#x} 不在镜像中"
        );
        Ok(Self {
            image,
            directory_table_base,
        })
    }

    pub(crate) fn translate(&self, virtual_address: u64) -> Result<u64> {
        ensure!(
            is_canonical_48(virtual_address),
            "Linux 虚拟地址不是 48 位规范地址"
        );
        let pml4 = self.present_entry(
            self.directory_table_base,
            (virtual_address >> 39) & 0x1ff,
            "PML4E",
        )?;
        let pdpt = self.present_entry(
            pml4 & ADDRESS_MASK_4K,
            (virtual_address >> 30) & 0x1ff,
            "PDPTE",
        )?;
        if pdpt & (1 << 7) != 0 {
            return Ok((pdpt & ADDRESS_MASK_1G) | (virtual_address & 0x3fff_ffff));
        }
        let pd = self.present_entry(
            pdpt & ADDRESS_MASK_4K,
            (virtual_address >> 21) & 0x1ff,
            "PDE",
        )?;
        if pd & (1 << 7) != 0 {
            return Ok((pd & ADDRESS_MASK_2M) | (virtual_address & 0x1f_ffff));
        }
        let pt =
            self.present_entry(pd & ADDRESS_MASK_4K, (virtual_address >> 12) & 0x1ff, "PTE")?;
        Ok((pt & ADDRESS_MASK_4K) | (virtual_address & 0xfff))
    }

    pub(crate) fn read_virtual(&self, mut address: u64, mut output: &mut [u8]) -> Result<()> {
        while !output.is_empty() {
            let physical = self.translate(address)?;
            let page_remaining = (PAGE_SIZE - (address & (PAGE_SIZE - 1))) as usize;
            let take = page_remaining.min(output.len());
            self.image
                .read_physical(physical, &mut output[..take])
                .with_context(|| format!("读取 Linux 虚拟地址 {address:#x} 失败"))?;
            address = address
                .checked_add(take as u64)
                .context("Linux 虚拟地址溢出")?;
            output = &mut output[take..];
        }
        Ok(())
    }

    pub(crate) fn read_u32(&self, address: u64) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.read_virtual(address, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub(crate) fn read_i32(&self, address: u64) -> Result<i32> {
        Ok(self.read_u32(address)? as i32)
    }

    pub(crate) fn read_u64(&self, address: u64) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.read_virtual(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn present_entry(&self, table: u64, index: u64, level: &str) -> Result<u64> {
        let address = table
            .checked_add(index * 8)
            .context("Linux 页表项地址溢出")?;
        let entry = self
            .image
            .read_u64_physical(address)
            .with_context(|| format!("无法读取 Linux {level} {address:#x}"))?;
        ensure!(entry & 1 != 0, "Linux {level} 不 present（{entry:#x}）");
        let physical = if level == "PDPTE" && entry & (1 << 7) != 0 {
            entry & ADDRESS_MASK_1G
        } else if level == "PDE" && entry & (1 << 7) != 0 {
            entry & ADDRESS_MASK_2M
        } else {
            entry & ADDRESS_MASK_4K
        };
        ensure!(physical != 0, "Linux {level} 指向物理页零");
        ensure!(
            self.image.contains_physical(physical),
            "Linux {level} 物理地址 {physical:#x} 不在采集范围中"
        );
        Ok(entry)
    }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|value| value & !(alignment - 1))
}

fn is_canonical_48(address: u64) -> bool {
    address >> 48 == 0 || address >> 48 == 0xffff
}

pub(crate) fn is_kernel_pointer(address: u64) -> bool {
    address >> 48 == 0xffff && address & 7 == 0
}

fn read_i32_physical(image: &MemoryImage, address: u64) -> Result<i32> {
    Ok(image.read_u32_physical(address)? as i32)
}

fn read_fixed_name_physical(image: &MemoryImage, address: u64, length: usize) -> Result<String> {
    let mut bytes = vec![0u8; length];
    image.read_physical(address, &mut bytes)?;
    Ok(decode_fixed_name(&bytes))
}

fn read_fixed_name_virtual(
    space: &LinuxX64AddressSpace<'_>,
    address: u64,
    length: usize,
) -> Result<String> {
    let mut bytes = vec![0u8; length];
    space.read_virtual(address, &mut bytes)?;
    Ok(decode_fixed_name(&bytes))
}

fn decode_fixed_name(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn read_physical_c_string(image: &MemoryImage, address: u64, max_len: usize) -> Option<String> {
    let mut bytes = Vec::with_capacity(max_len.min(512));
    for index in 0..max_len {
        let mut byte = [0u8; 1];
        if image
            .read_physical(address.checked_add(index as u64)?, &mut byte)
            .is_err()
        {
            break;
        }
        if byte[0] == 0 || byte[0] == b'\n' {
            break;
        }
        if byte[0] < 0x20 && byte[0] != b'\t' {
            break;
        }
        bytes.push(byte[0]);
    }
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

fn read_physical_nul_string(image: &MemoryImage, address: u64, max_len: usize) -> Option<String> {
    let mut bytes = Vec::with_capacity(max_len.min(4096));
    for index in 0..max_len {
        let mut byte = [0u8; 1];
        if image
            .read_physical(address.checked_add(index as u64)?, &mut byte)
            .is_err()
        {
            break;
        }
        if byte[0] == 0 {
            break;
        }
        if byte[0] < 0x20 && !matches!(byte[0], b'\n' | b'\r' | b'\t') {
            break;
        }
        bytes.push(byte[0]);
    }
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

fn list_processes(
    image: &MemoryImage,
    profile: &LinuxTaskProfile,
    kernel: &LinuxKernelContext,
    session_warnings: &[LinuxProcessWarning],
    scan: &DiscoveryScanStats,
    limit: usize,
) -> Result<LinuxProcessListReport> {
    ensure!(limit > 0, "process limit 必须大于零");
    let space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let head = kernel
        .init_task
        .checked_add(profile.tasks)
        .context("init_task.tasks 地址溢出")?;
    let mut link = space
        .read_u64(head)
        .context("无法读取 init_task.tasks.next")?;
    let mut previous_link = head;
    let mut visited = HashSet::new();
    let mut records = Vec::new();
    let mut warnings = session_warnings.to_vec();
    let mut structurally_complete = true;
    let mut stop_reason = LinuxProcessListStopReason::Limit;

    while link != head && records.len() < limit {
        if !visited.insert(link) {
            warnings.push(LinuxProcessWarning {
                kind: "cycle".to_owned(),
                message: format!(
                    "活动任务链在 {link:#x} 形成非头部环；保留已验证的 {} 条记录",
                    records.len()
                ),
                list_entry: Some(link),
            });
            stop_reason = LinuxProcessListStopReason::Cycle;
            break;
        }
        if !is_kernel_pointer(link) || link < profile.tasks {
            warnings.push(LinuxProcessWarning {
                kind: "invalid_pointer".to_owned(),
                message: format!(
                    "无效的 task_struct.tasks 指针 {link:#x}；保留已验证的 {} 条记录",
                    records.len()
                ),
                list_entry: Some(link),
            });
            stop_reason = LinuxProcessListStopReason::InvalidPointer;
            break;
        }
        match space.read_u64(link + 8) {
            Ok(backlink) if backlink != previous_link => {
                structurally_complete = false;
                warnings.push(LinuxProcessWarning {
                    kind: "backlink_mismatch".to_owned(),
                    message: format!(
                        "任务链 {link:#x} 的 prev={backlink:#x}，预期 {previous_link:#x}"
                    ),
                    list_entry: Some(link),
                });
            }
            Err(error) => {
                warnings.push(LinuxProcessWarning {
                    kind: "unreadable_backlink".to_owned(),
                    message: format!("无法读取任务链 {link:#x} 的 prev：{error:#}"),
                    list_entry: Some(link),
                });
                stop_reason = LinuxProcessListStopReason::UnreadableEntry;
                break;
            }
            _ => {}
        }

        let task = link - profile.tasks;
        let record = match read_process_record(&space, profile, task, link) {
            Ok(record) => record,
            Err(error) => {
                warnings.push(LinuxProcessWarning {
                    kind: "unreadable_entry".to_owned(),
                    message: format!(
                        "无法解析 task_struct {task:#x}：{error:#}；保留已验证的 {} 条记录",
                        records.len()
                    ),
                    list_entry: Some(link),
                });
                stop_reason = LinuxProcessListStopReason::UnreadableEntry;
                break;
            }
        };
        records.push(record);
        let next = match space.read_u64(link) {
            Ok(next) => next,
            Err(error) => {
                warnings.push(LinuxProcessWarning {
                    kind: "unreadable_next".to_owned(),
                    message: format!("无法读取任务链 {link:#x} 的 next：{error:#}"),
                    list_entry: Some(link),
                });
                stop_reason = LinuxProcessListStopReason::UnreadableEntry;
                break;
            }
        };
        previous_link = link;
        link = next;
    }

    if link == head {
        stop_reason = LinuxProcessListStopReason::ListHead;
        match space.read_u64(head + 8) {
            Ok(backlink) if backlink != previous_link => {
                structurally_complete = false;
                warnings.push(LinuxProcessWarning {
                    kind: "head_backlink_mismatch".to_owned(),
                    message: format!(
                        "init_task.tasks.prev={backlink:#x}，预期最后条目 {previous_link:#x}"
                    ),
                    list_entry: Some(head),
                });
            }
            Err(error) => {
                structurally_complete = false;
                warnings.push(LinuxProcessWarning {
                    kind: "unreadable_head_backlink".to_owned(),
                    message: format!("无法读取 init_task.tasks.prev：{error:#}"),
                    list_entry: Some(head),
                });
            }
            _ => {}
        }
    }
    let complete = stop_reason == LinuxProcessListStopReason::ListHead && structurally_complete;
    Ok(LinuxProcessListReport {
        kernel: kernel.clone(),
        processes: records,
        complete,
        stop_reason,
        warnings,
        bytes_scanned: scan.bytes_scanned,
        scan_seconds: scan.elapsed_seconds,
        scan_gib_per_second: scan.gib_per_second,
    })
}

fn build_process_tree(
    mut report: LinuxProcessListReport,
    filtered_pid: Option<i32>,
) -> Result<LinuxProcessTreeReport> {
    if let Some(pid) = filtered_pid {
        ensure!(pid >= 0, "Linux pstree PID 不能为负数");
    }

    let source_process_count = report.processes.len();
    let (records, duplicate_pid_warnings) = {
        let processes = &report.processes;
        let mut ordered = (0..processes.len()).collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|index| (processes[*index].pid, processes[*index].task));

        let mut by_pid = HashMap::<i32, usize>::new();
        let mut duplicate_pid_warnings = Vec::new();
        for &index in &ordered {
            let process = &processes[index];
            if let Some(&existing) = by_pid.get(&process.pid) {
                duplicate_pid_warnings.push(LinuxProcessWarning {
                    kind: "duplicate_pid".to_owned(),
                    message: format!(
                        "活动任务链中 PID {} 同时对应 task_struct {:#x} 和 {:#x}；进程树父节点使用地址较小的记录",
                        process.pid, processes[existing].task, process.task
                    ),
                    list_entry: Some(process.list_entry),
                });
            } else {
                by_pid.insert(process.pid, index);
            }
        }

        let orphan_parent = processes
            .iter()
            .map(|process| {
                process.ppid.is_some_and(|parent| {
                    parent != 0 && parent != process.pid && !by_pid.contains_key(&parent)
                })
            })
            .collect::<Vec<_>>();
        let parent_cycle = (0..processes.len())
            .map(|index| linux_parent_chain_has_cycle(index, processes, &by_pid))
            .collect::<Vec<_>>();

        let mut children = BTreeMap::<i32, Vec<usize>>::new();
        let mut roots = Vec::new();
        for &index in &ordered {
            let process = &processes[index];
            match process.ppid {
                Some(parent)
                    if parent != 0 && parent != process.pid && by_pid.contains_key(&parent) =>
                {
                    children.entry(parent).or_default().push(index);
                }
                _ => roots.push(index),
            }
        }
        for values in children.values_mut() {
            values.sort_unstable_by_key(|index| (processes[*index].pid, processes[*index].task));
        }

        let mut records = Vec::with_capacity(match filtered_pid {
            Some(_) => processes.len().min(256),
            None => processes.len(),
        });
        let mut emitted = HashSet::new();
        if let Some(pid) = filtered_pid {
            let root = by_pid
                .get(&pid)
                .copied()
                .with_context(|| format!("活动任务链中未找到 PID {pid}"))?;
            append_linux_process_subtree(
                root,
                processes,
                &children,
                &orphan_parent,
                &parent_cycle,
                &mut emitted,
                &mut records,
            );
        } else {
            for root in roots {
                append_linux_process_subtree(
                    root,
                    processes,
                    &children,
                    &orphan_parent,
                    &parent_cycle,
                    &mut emitted,
                    &mut records,
                );
            }
            // Parent cycles do not have a natural root.  Emit each remaining
            // component deterministically so suspicious tasks never disappear.
            for index in ordered {
                if !emitted.contains(&index) {
                    append_linux_process_subtree(
                        index,
                        processes,
                        &children,
                        &orphan_parent,
                        &parent_cycle,
                        &mut emitted,
                        &mut records,
                    );
                }
            }
        }
        (records, duplicate_pid_warnings)
    };

    report.warnings.extend(duplicate_pid_warnings);
    let root_count = records.iter().filter(|record| record.depth == 0).count();
    let orphan_count = records.iter().filter(|record| record.orphan_parent).count();
    let parent_cycle_count = records.iter().filter(|record| record.parent_cycle).count();
    Ok(LinuxProcessTreeReport {
        kernel: report.kernel,
        records,
        source_process_count,
        root_count,
        orphan_count,
        parent_cycle_count,
        filtered_pid,
        complete: report.complete,
        stop_reason: report.stop_reason,
        warnings: report.warnings,
        bytes_scanned: report.bytes_scanned,
        scan_seconds: report.scan_seconds,
        scan_gib_per_second: report.scan_gib_per_second,
    })
}

fn linux_parent_chain_has_cycle(
    start: usize,
    processes: &[LinuxProcessRecord],
    by_pid: &HashMap<i32, usize>,
) -> bool {
    let mut current = Some(start);
    let mut visited = HashSet::new();
    while let Some(index) = current {
        if !visited.insert(index) {
            return true;
        }
        current = processes[index]
            .ppid
            .and_then(|parent| by_pid.get(&parent).copied());
    }
    false
}

fn append_linux_process_subtree(
    root: usize,
    processes: &[LinuxProcessRecord],
    children: &BTreeMap<i32, Vec<usize>>,
    orphan_parent: &[bool],
    parent_cycle: &[bool],
    emitted: &mut HashSet<usize>,
    output: &mut Vec<LinuxProcessTreeRecord>,
) {
    let mut pending = vec![(root, 0usize)];
    while let Some((index, depth)) = pending.pop() {
        if !emitted.insert(index) {
            continue;
        }
        let process = &processes[index];
        output.push(LinuxProcessTreeRecord {
            depth,
            task: process.task,
            pid: process.pid,
            tgid: process.tgid,
            ppid: process.ppid,
            name: process.name.clone(),
            state: process.state.clone(),
            kernel_thread: process.kernel_thread,
            start_time_ns: process.start_time_ns,
            orphan_parent: orphan_parent[index],
            parent_cycle: parent_cycle[index],
        });
        if let Some(values) = children.get(&process.pid) {
            for &child in values.iter().rev() {
                pending.push((child, depth.saturating_add(1)));
            }
        }
    }
}

fn read_process_record(
    space: &LinuxX64AddressSpace<'_>,
    profile: &LinuxTaskProfile,
    task: u64,
    list_entry: u64,
) -> Result<LinuxProcessRecord> {
    let pid = space.read_i32(task + profile.pid)?;
    let tgid = space.read_i32(task + profile.tgid)?;
    ensure!(pid >= 0 && tgid >= 0, "PID/TGID 为负数");
    let name = read_fixed_name_virtual(space, task + profile.comm, profile.comm_len)?;
    ensure!(!name.is_empty(), "task_struct.comm 为空");
    let state_raw = match profile.state_size {
        4 => u64::from(space.read_u32(task + profile.state)?),
        8 => space.read_u64(task + profile.state)?,
        _ => unreachable!(),
    };
    let exit_state = profile
        .exit_state
        .map(|offset| space.read_u32(task + offset))
        .transpose()?;
    let parent = space.read_u64(task + profile.real_parent)?;
    let ppid = if parent == 0 {
        None
    } else if is_kernel_pointer(parent) {
        space
            .read_i32(parent + profile.tgid)
            .ok()
            .filter(|pid| *pid >= 0)
    } else {
        None
    };
    let flags = profile
        .flags
        .map(|offset| space.read_u32(task + offset))
        .transpose()?;
    let raw_mm = profile
        .mm
        .map(|offset| space.read_u64(task + offset))
        .transpose()?;
    let mm = raw_mm.filter(|address| *address != 0);
    // 用户进程退出后 mm 也会变为 NULL；只有 PF_KTHREAD 能证明内核线程身份。
    let kernel_thread = flags
        .map(|value| value & 0x0020_0000 != 0)
        .or_else(|| raw_mm.filter(|address| *address != 0).map(|_| false));
    let start_time_ns = profile
        .start_time
        .map(|layout| layout.read(space, task))
        .transpose()?;
    Ok(LinuxProcessRecord {
        task,
        list_entry,
        pid,
        tgid,
        ppid,
        name,
        state: task_state_for_profile(profile, state_raw, exit_state),
        state_raw,
        exit_state,
        flags,
        mm,
        kernel_thread,
        start_time_ns,
    })
}

fn task_state_for_profile(
    profile: &LinuxTaskProfile,
    state: u64,
    exit_state: Option<u32>,
) -> String {
    // System.map has no state constants; pre-u64 start_time kernels also predate
    // the modern state/exit-state masks. Preserve raw values instead of calling
    // old TASK_WAKEKILL (0x80) "dead" or reversing EXIT_ZOMBIE/EXIT_DEAD.
    if profile.source == "system_map_validated_memory"
        || matches!(
            profile.start_time,
            Some(LinuxTaskStartTime::Timespec { .. })
        )
    {
        if let Some(exit) = exit_state.filter(|value| *value != 0) {
            return format!("unknown(state={state:#x},exit_state={exit:#x})");
        }
        if state & !0xf != 0 {
            return format!("unknown({state:#x})");
        }
    }
    linux_task_state(state, exit_state)
}

fn linux_task_state(state: u64, exit_state: Option<u32>) -> String {
    if let Some(exit_state) = exit_state {
        if exit_state & 0x20 != 0 {
            return "zombie".to_owned();
        }
        if exit_state & 0x10 != 0 {
            return "dead".to_owned();
        }
    }
    if state == 0 {
        return "running".to_owned();
    }
    let mut names = Vec::new();
    for (bit, name) in [
        (0x0001, "interruptible"),
        (0x0002, "uninterruptible"),
        (0x0004, "stopped"),
        (0x0008, "traced"),
        (0x0010, "exit_dead"),
        (0x0020, "exit_zombie"),
        (0x0040, "parked"),
        (0x0080, "dead"),
        (0x0100, "wakekill"),
        (0x0200, "waking"),
        (0x0400, "no_load"),
        (0x0800, "new"),
    ] {
        if state & bit != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        format!("unknown({state:#x})")
    } else {
        names.join("|")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    use super::*;
    use crate::linux_kernel_plugins::LinuxKernelMemory;

    #[test]
    fn isf_task_start_time_reads_legacy_timespec_and_scalar_nanoseconds() {
        let mut types = serde_json::json!({
            "task_struct": {"size": 512, "fields": {
                "start_time": {"offset": 256, "type": {"kind": "struct", "name": "timespec"}}
            }},
            "timespec": {"size": 16, "fields": {
                "tv_sec": {"offset": 0, "type": {"kind": "base", "name": "long unsigned int"}},
                "tv_nsec": {"offset": 8, "type": {"kind": "base", "name": "long unsigned int"}}
            }}
        });
        let isf = crate::linux_symbols::test_isf(types.clone());
        let legacy = LinuxTaskStartTime::from_isf(&isf).unwrap().unwrap();
        assert!(matches!(
            legacy,
            LinuxTaskStartTime::Timespec {
                seconds: 256,
                nanoseconds: 264
            }
        ));

        let path = temporary_path("timespec-start-time");
        let task = 0xffff_8000_0020_0000u64;
        let mut bytes = vec![0; 0x20_2000];
        put_u64(
            &mut bytes,
            0x1000 + ((task >> 39) & 0x1ff) as usize * 8,
            0x2003,
        );
        put_u64(&mut bytes, 0x2000, 0x3003);
        put_u64(&mut bytes, 0x3008, 0x20_0083);
        put_u64(&mut bytes, 0x20_0100, 42);
        put_u64(&mut bytes, 0x20_0108, 123_456_789);
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let space = LinuxX64AddressSpace::new(&image, 0x1000).unwrap();
        assert_eq!(legacy.read(&space, task).unwrap(), 42_123_456_789);
        types["task_struct"]["fields"]["start_time"]["type"] =
            serde_json::json!({"kind": "base", "name": "long unsigned int"});
        let scalar = LinuxTaskStartTime::from_isf(&crate::linux_symbols::test_isf(types.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(scalar.read(&space, task).unwrap(), 42);
        drop(image);
        fs::remove_file(path).unwrap();
        assert!(timespec_start_time_ns(1, 1_000_000_000).is_err());
        assert!(timespec_start_time_ns(u64::MAX, 0).is_err());
        types["task_struct"]["fields"]["start_time"]["type"] = serde_json::json!({"kind": "pointer", "subtype": {"kind": "struct", "name": "timespec"}});
        assert!(LinuxTaskStartTime::from_isf(&crate::linux_symbols::test_isf(types)).is_err());
    }

    #[test]
    fn legacy_timespec_profiles_do_not_apply_modern_task_state_masks() {
        let mut profile = synthetic_profile();
        profile.start_time = Some(LinuxTaskStartTime::Timespec {
            seconds: 0x58,
            nanoseconds: 0x60,
        });
        assert_eq!(task_state_for_profile(&profile, 2, None), "uninterruptible");
        assert_eq!(
            task_state_for_profile(&profile, 0x82, Some(0)),
            "unknown(0x82)"
        );
        assert_eq!(
            task_state_for_profile(&profile, 0, Some(0x10)),
            "unknown(state=0x0,exit_state=0x10)"
        );
        assert_eq!(
            task_state_for_profile(&profile, 0xffff_8000_0000_0001, None),
            "unknown(0xffff800000000001)"
        );
        profile.start_time = Some(LinuxTaskStartTime::Nanoseconds(0x58));
        assert_eq!(task_state_for_profile(&profile, 0, Some(0x20)), "zombie");
    }

    #[test]
    fn exact_profiles_require_the_full_build_banner() {
        let banner = "Linux version 4.13.0-36-generic (buildd@lgw01-amd64-033) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.9)) #40~16.04.1-Ubuntu SMP Fri Feb 16 23:25:58 UTC 2018 (Ubuntu 4.13.0-36.40~16.04.1-generic 4.13.13)";
        let profile = exact_banner_profile(banner).unwrap();
        assert_eq!(profile.tasks, 0x800);
        assert_eq!(profile.pid, 0x900);
        assert_eq!(profile.comm, 0xaa8);
        assert!(exact_banner_profile("Linux version 4.13.0-36-generic").is_none());
        assert_eq!(normalize_linux_banner(format!("{banner}garbage")), banner);

        let deepin = exact_banner_profile(DEEPIN_4_9_0_57_1).unwrap();
        assert_eq!(deepin.task_size, 0x1b40);
        assert_eq!(deepin.tasks, 0x3a8);
        assert_eq!(deepin.pid, 0x4a8);
        assert_eq!(deepin.comm, 0x660);
        assert!(exact_banner_profile("Linux version 4.9.0-deepin13-amd64").is_none());

        let custom = "Linux version 6.18.0 (fcsc@fcsc) (gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #1 SMP PREEMPT_DYNAMIC 0";
        assert_eq!(normalize_linux_banner(custom.to_owned()), custom);
    }

    #[test]
    fn linux_release_requires_a_numeric_major_minor_pair() {
        assert_eq!(
            linux_release("Linux version 6.18.0-rc7+ (builder@test) #1 SMP").as_deref(),
            Some("6.18.0-rc7+")
        );
        assert_eq!(
            linux_release("Linux version 3.10.0-1160.el7.x86_64 #1 SMP").as_deref(),
            Some("3.10.0-1160.el7.x86_64")
        );
        assert!(linux_release("Linux version lacks a release token").is_none());
        assert!(linux_release("Linux version latest #1 SMP").is_none());
        assert!(linux_release("Linux version 6.x-test #1 SMP").is_none());
    }

    #[test]
    fn builds_deterministic_linux_process_trees_and_filters_subtrees() {
        let report = synthetic_process_list_report(vec![
            synthetic_process_record(4, Some(2), "worker"),
            synthetic_process_record(3, Some(99), "orphan"),
            synthetic_process_record(2, Some(1), "service"),
            synthetic_process_record(1, Some(0), "init"),
            synthetic_process_record(6, Some(5), "cycle-b"),
            synthetic_process_record(5, Some(6), "cycle-a"),
            synthetic_process_record(7, Some(7), "self-cycle"),
        ]);
        let tree = build_process_tree(report, None).unwrap();
        assert_eq!(
            tree.records
                .iter()
                .map(|record| (record.pid, record.depth))
                .collect::<Vec<_>>(),
            [(1, 0), (2, 1), (4, 2), (3, 0), (7, 0), (5, 0), (6, 1)]
        );
        assert_eq!(tree.source_process_count, 7);
        assert_eq!(tree.root_count, 4);
        assert_eq!(tree.orphan_count, 1);
        assert_eq!(tree.parent_cycle_count, 3);
        assert!(
            tree.records
                .iter()
                .any(|record| record.pid == 3 && record.orphan_parent)
        );
        assert!(
            tree.records
                .iter()
                .any(|record| record.pid == 7 && record.parent_cycle)
        );

        let filtered = build_process_tree(
            synthetic_process_list_report(vec![
                synthetic_process_record(4, Some(2), "worker"),
                synthetic_process_record(1, Some(0), "init"),
                synthetic_process_record(2, Some(1), "service"),
                synthetic_process_record(3, Some(1), "peer"),
            ]),
            Some(2),
        )
        .unwrap();
        assert_eq!(
            filtered
                .records
                .iter()
                .map(|record| (record.pid, record.depth))
                .collect::<Vec<_>>(),
            [(2, 0), (4, 1)]
        );
        assert_eq!(filtered.filtered_pid, Some(2));
        assert_eq!(filtered.source_process_count, 4);
        assert_eq!(filtered.root_count, 1);
    }

    #[test]
    fn probes_raw_linux_memory_without_trusting_the_file_extension() {
        const VIRTUAL_BASE: u64 = 0xffff_8000_0020_0000;
        const PHYSICAL_BASE: u64 = 0x20_0000;
        const INIT_VA: u64 = VIRTUAL_BASE + 0x1_0000;
        const TASK_VA: u64 = VIRTUAL_BASE + 0x2_0000;
        const INIT_PA: usize = (PHYSICAL_BASE + 0x1_0000) as usize;
        const TASK_PA: usize = (PHYSICAL_BASE + 0x2_0000) as usize;

        let path = temporary_path("raw-probe");
        let mut bytes = vec![0u8; 0x40_0000];
        let pml4_index = ((VIRTUAL_BASE >> 39) & 0x1ff) as usize;
        put_u64(&mut bytes, 0x1000 + pml4_index * 8, 0x2003);
        put_u64(&mut bytes, 0x2000, 0x3003);
        put_u64(&mut bytes, 0x3000 + 8, PHYSICAL_BASE | 0x83);

        let profile = exact_banner_profile(UBUNTU_5_4_0_84_BIONIC).unwrap();
        let head = INIT_VA + profile.tasks;
        let task_link = TASK_VA + profile.tasks;
        write_task(
            &mut bytes,
            INIT_PA,
            &profile,
            INIT_VA,
            0,
            "swapper/0",
            task_link,
            task_link,
            0,
        );
        write_task(
            &mut bytes, TASK_PA, &profile, INIT_VA, 1, "systemd", head, head, 1,
        );
        let banner = format!("{UBUNTU_5_4_0_84_BIONIC}\0");
        bytes[0x10_0000..0x10_0000 + banner.len()].copy_from_slice(banner.as_bytes());
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        assert!(matches!(image.format(), ImageFormat::Raw));
        assert!(is_supported_linux_physical_image(&image));
        assert!(probe_linux_memory(&image).unwrap());
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_linux_probe_rejects_unstructured_swapper_text() {
        let path = temporary_path("raw-probe-unstructured-swapper");
        let mut bytes = vec![0u8; 0x4000];
        let banner = format!("{UBUNTU_5_4_0_84_BIONIC}\0");
        bytes[0x1000..0x1000 + banner.len()].copy_from_slice(banner.as_bytes());
        let text = b"diagnostic: swapper appears in this log\0";
        bytes[0x2000..0x2000 + text.len()].copy_from_slice(text);
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        assert!(!probe_linux_memory(&image).unwrap());
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_linux_probe_requires_a_task_anchor() {
        let path = temporary_path("raw-probe-no-task");
        let mut bytes = vec![0u8; 0x4000];
        let banner = b"Linux version 9.9.9-test (builder@test) #1 SMP\0";
        bytes[0x1000..0x1000 + banner.len()].copy_from_slice(banner);
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        assert!(!probe_linux_memory(&image).unwrap());
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn parses_vmcoreinfo_and_derives_the_physical_page_table() {
        let path = temporary_path("vmcoreinfo");
        fs::write(&path, vec![0u8; 0x4000]).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let evidence = parse_vmcoreinfo(
            0x2000,
            "OSRELEASE=6.8.0-test\nPAGESIZE=4096\nSYMBOL(init_top_pgt)=ffffffff80001000\nSYMBOL(_stext)=ffffffff81000000\nNUMBER(phys_base)=0\nKERNELOFFSET=20000000\nNUMBER(pgtable_l5_enabled)=0\nNUMBER(sme_mask)=0\n",
        )
        .unwrap();
        assert_eq!(evidence.stext_virtual, Some(0xffff_ffff_8100_0000));
        assert_eq!(evidence.kernel_offset, Some(0x2000_0000));
        assert_eq!(
            vmcore_directory_table_base(&image, &evidence).unwrap(),
            0x1000
        );
        drop(image);
        fs::remove_file(path).unwrap();
    }

    /// KASLR 一开，x86_64 的 NUMBER(phys_base) 就是负数（内核的
    /// VMCOREINFO_NUMBER 宏按 `%ld` 输出有符号 long）。此前解析器只试
    /// u64 十进制与 u64 十六进制，两条都吃不下前导负号，整块 VMCOREINFO
    /// 被判无效丢弃，Linux 会话再也开不起来 —— 表现为「匹配 VMCOREINFO=0」。
    ///
    /// 下面的数值全部抄自真实镜像（Debian 5.4.0-4-amd64 的 LiME 采集，
    /// VMCOREINFO 位于物理偏移 0x460f3858）。期望的页表根 0xca0a000 是实测
    /// 能让 lsmod/mountinfo/kallsyms/kmsg/modxview/check-syscall 六个插件
    /// 全部产出数据的那个值。
    #[test]
    fn parses_negative_phys_base_from_a_kaslr_image() {
        let path = temporary_path("vmcoreinfo-kaslr");
        // 页表根落在 0xca0a000，镜像必须覆盖到该物理地址
        fs::write(&path, vec![0u8; 0xd00_0000]).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let evidence = parse_vmcoreinfo(
            0x460f_3858,
            "OSRELEASE=5.4.0-4-amd64\nPAGESIZE=4096\n\
             SYMBOL(swapper_pg_dir)=ffffffffbe80a000\nSYMBOL(_stext)=ffffffffbd800000\n\
             NUMBER(phys_base)=-836763648\nKERNELOFFSET=3c800000\n\
             NUMBER(pgtable_l5_enabled)=0\nNUMBER(sme_mask)=0\n",
        )
        .unwrap();

        // 负值以补码存进 u64；地址运算本就是模运算
        assert_eq!(evidence.phys_base, (-836_763_648i64) as u64);
        assert_eq!(evidence.stext_virtual, Some(0xffff_ffff_bd80_0000));
        assert_eq!(evidence.kernel_offset, Some(0x3c80_0000));
        // KERNELOFFSET 应当与 _stext 相对默认基址的偏移一致，这是自洽性检查
        assert_eq!(
            evidence.stext_virtual.unwrap() - 0xffff_ffff_8100_0000,
            evidence.kernel_offset.unwrap()
        );

        assert_eq!(
            vmcore_directory_table_base(&image, &evidence).unwrap(),
            0xca0_a000,
            "负 phys_base 下的页表根必须走模运算得出"
        );

        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn resolves_stext_through_strict_linux_page_tables_and_verifies_bytes() {
        const VIRTUAL_BASE: u64 = 0xffff_8000_0020_0000;
        const PHYSICAL_BASE: u64 = 0x20_0000;
        const STEXT: u64 = VIRTUAL_BASE + 0x1000;
        const STEXT_PHYSICAL: usize = (PHYSICAL_BASE + 0x1000) as usize;

        let path = temporary_path("stext");
        let mut bytes = vec![0u8; 0x40_0000];
        let pml4_index = ((VIRTUAL_BASE >> 39) & 0x1ff) as usize;
        put_u64(&mut bytes, 0x1000 + pml4_index * 8, 0x2003);
        put_u64(&mut bytes, 0x2000, 0x3003);
        put_u64(&mut bytes, 0x3000 + 8, PHYSICAL_BASE | 0x83);
        bytes[STEXT_PHYSICAL..STEXT_PHYSICAL + 16].copy_from_slice(&[
            0x66, 0x90, 0x0f, 0xae, 0xe8, 0xe9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        ]);
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let discovery = LinuxDiscovery {
            banners: Vec::new(),
            btf_hits: Vec::new(),
            swapper_hits: Vec::new(),
            vmcoreinfo: vec![VmcoreInfoEvidence {
                physical_address: 0x5000,
                release: "test".to_owned(),
                page_table_virtual: X86_KERNEL_IMAGE_BASE + 0x1000,
                phys_base: 0,
                stext_virtual: Some(STEXT),
                kernel_offset: Some(0),
                pgtable_l5_enabled: Some(0),
                sme_mask: Some(0),
            }],
            stats: DiscoveryScanStats {
                bytes_scanned: 0,
                elapsed_seconds: 0.0,
                gib_per_second: 0.0,
            },
        };
        let init = InitTaskCandidate {
            physical_address: STEXT_PHYSICAL as u64,
            virtual_address: STEXT,
            tasks_next: STEXT,
            tasks_prev: STEXT,
        };
        let evidence =
            resolve_kernel_text_evidence(&image, &discovery, 0x1000, Some(0x5000), &init, None)
                .unwrap()
                .unwrap();
        assert_eq!(evidence.virtual_address, STEXT);
        assert_eq!(evidence.physical_address, STEXT_PHYSICAL as u64);
        assert_eq!(evidence.bytes_verified, 16);
        assert_eq!(evidence.first_bytes_hex, "66900faee8e90102030405060708090a");
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn walks_a_linux_task_ring_and_rejects_nonpresent_ptes() {
        const VIRTUAL_BASE: u64 = 0xffff_8000_0020_0000;
        const PHYSICAL_BASE: u64 = 0x20_0000;
        const INIT_VA: u64 = VIRTUAL_BASE + 0x1_0000;
        const TASK1_VA: u64 = VIRTUAL_BASE + 0x2_0000;
        const TASK2_VA: u64 = VIRTUAL_BASE + 0x3_0000;
        const INIT_PA: usize = (PHYSICAL_BASE + 0x1_0000) as usize;
        const TASK1_PA: usize = (PHYSICAL_BASE + 0x2_0000) as usize;
        const TASK2_PA: usize = (PHYSICAL_BASE + 0x3_0000) as usize;

        let path = temporary_path("pslist");
        let mut bytes = vec![0u8; 0x40_0000];
        let pml4_index = ((VIRTUAL_BASE >> 39) & 0x1ff) as usize;
        put_u64(&mut bytes, 0x1000 + pml4_index * 8, 0x2003);
        put_u64(&mut bytes, 0x2000, 0x3003);
        put_u64(&mut bytes, 0x3000 + 8, PHYSICAL_BASE | 0x83);
        // A second root has a Windows-style transition bit but no present bit.
        // The Linux walker must not treat it as resident.
        put_u64(&mut bytes, 0x4000 + pml4_index * 8, 0x2000 | (1 << 11));

        let mut profile = synthetic_profile();
        profile.flags = Some(0x10);
        profile.exit_state = Some(0x60);
        let head = INIT_VA + profile.tasks;
        let task1_link = TASK1_VA + profile.tasks;
        let task2_link = TASK2_VA + profile.tasks;
        write_task(
            &mut bytes,
            INIT_PA,
            &profile,
            INIT_VA,
            0,
            "swapper/0",
            task1_link,
            task2_link,
            0,
        );
        write_task(
            &mut bytes, TASK1_PA, &profile, INIT_VA, 1, "systemd", task2_link, head, 1,
        );
        write_task(
            &mut bytes, TASK2_PA, &profile, INIT_VA, 2, "kthreadd", head, task1_link, 2,
        );
        put_u32(&mut bytes, TASK2_PA + 0x10, 0x0020_0000);
        put_u64(&mut bytes, TASK1_PA + 0x30, 0);
        put_u32(&mut bytes, TASK1_PA + 0x60, 0x20); // zombie 用户进程已释放 mm
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let strict = LinuxX64AddressSpace::new(&image, 0x4000).unwrap();
        assert!(strict.translate(INIT_VA).is_err());

        let kernel = LinuxKernelContext {
            architecture: "x86_64_4level".to_owned(),
            banner: "Linux version synthetic".to_owned(),
            banner_physical_address: 0,
            directory_table_base: 0x1000,
            page_table_source: "test".to_owned(),
            vmcoreinfo_physical_address: None,
            init_task: INIT_VA,
            init_task_physical: INIT_PA as u64,
            profile_source: "test".to_owned(),
            profile_fingerprint: "test".to_owned(),
            btf_physical_address: None,
            task_struct_size: profile.task_size,
            task_struct_offsets: BTreeMap::new(),
            symbol_table: None,
            system_map: None,
        };
        let scan = DiscoveryScanStats {
            bytes_scanned: 0,
            elapsed_seconds: 0.0,
            gib_per_second: 0.0,
        };
        let report = list_processes(&image, &profile, &kernel, &[], &scan, 10).unwrap();
        assert!(report.complete);
        assert_eq!(report.stop_reason, LinuxProcessListStopReason::ListHead);
        assert_eq!(report.processes.len(), 2);
        assert_eq!(report.processes[0].name, "systemd");
        assert_eq!(report.processes[0].ppid, Some(0));
        assert_eq!(report.processes[0].state, "zombie");
        assert_eq!(report.processes[0].kernel_thread, Some(false));
        assert_eq!(report.processes[1].name, "kthreadd");
        assert_eq!(report.processes[1].kernel_thread, Some(true));

        let limited = list_processes(&image, &profile, &kernel, &[], &scan, 1).unwrap();
        assert!(!limited.complete);
        assert_eq!(limited.stop_reason, LinuxProcessListStopReason::Limit);
        assert_eq!(limited.processes.len(), 1);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn infers_a_symbol_less_task_layout_only_from_a_validated_ring() {
        const VIRTUAL_BASE: u64 = 0xffff_8000_0020_0000;
        const PHYSICAL_BASE: u64 = 0x20_0000;
        const INIT_VA: u64 = VIRTUAL_BASE + 0x1_0000;
        const INIT_PA: usize = (PHYSICAL_BASE + 0x1_0000) as usize;

        let path = temporary_path("symbol-less-layout");
        let mut bytes = vec![0u8; 0x40_0000];
        let pml4_index = ((VIRTUAL_BASE >> 39) & 0x1ff) as usize;
        put_u64(&mut bytes, 0x1000 + pml4_index * 8, 0x2003);
        put_u64(&mut bytes, 0x2000, 0x3003);
        put_u64(&mut bytes, 0x3000 + 8, PHYSICAL_BASE | 0x83);

        let profile = LinuxTaskProfile {
            source: "test",
            fingerprint: "test".to_owned(),
            btf_physical_address: None,
            task_size: 0x600,
            state: 0x08,
            state_size: 8,
            tasks: 0x200,
            mm: Some(0x350),
            pid: 0x300,
            tgid: 0x304,
            real_parent: 0x310,
            parent: Some(0x318),
            start_time: Some(LinuxTaskStartTime::Nanoseconds(0x400)),
            comm: 0x500,
            comm_len: 16,
            exit_state: None,
            flags: None,
        };
        let task_virtual = |index: u64| VIRTUAL_BASE + (index + 1) * 0x1_0000;
        let task_physical = |index: usize| (PHYSICAL_BASE + (index as u64 + 1) * 0x1_0000) as usize;
        let head = INIT_VA + profile.tasks;
        let links = (1..=4)
            .map(|index| task_virtual(index) + profile.tasks)
            .collect::<Vec<_>>();
        write_task(
            &mut bytes,
            INIT_PA,
            &profile,
            INIT_VA,
            0,
            "swapper/0",
            links[0],
            links[3],
            0,
        );
        for index in 1..=4usize {
            let previous = if index == 1 { head } else { links[index - 2] };
            let next = if index == 4 { head } else { links[index] };
            write_task(
                &mut bytes,
                task_physical(index),
                &profile,
                INIT_VA,
                index as i32,
                &format!("task{index}"),
                next,
                previous,
                index as u64,
            );
        }
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let space = LinuxX64AddressSpace::new(&image, 0x1000).unwrap();
        let inferred =
            infer_task_layout_at_swapper(&image, &space, INIT_PA as u64 + profile.comm).unwrap();
        assert_eq!(inferred.task_virtual, INIT_VA);
        assert_eq!(inferred.task_physical, INIT_PA as u64);
        assert_eq!(inferred.tasks, profile.tasks);
        assert_eq!(inferred.pid, profile.pid);
        assert_eq!(inferred.tgid, profile.tgid);
        assert_eq!(inferred.real_parent, profile.real_parent);
        assert_eq!(inferred.comm, profile.comm);
        assert_eq!(inferred.state, profile.state);
        assert_eq!(inferred.state_size, profile.state_size);
        assert_eq!(inferred.task_count, 4);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn exact_symbols_preserve_verified_tasks_from_a_torn_tail_without_relaxing_identity() {
        let (root, image_path, _) = synthetic_kernel_global_fixture(false);
        let profile = synthetic_profile();
        let init_va = KERNEL_GLOBAL_VIRTUAL_BASE + 0x10000;
        let first_va = KERNEL_GLOBAL_VIRTUAL_BASE + 0x20000;
        let last_va = KERNEL_GLOBAL_VIRTUAL_BASE + 0x30000;
        let init_pa = KERNEL_GLOBAL_PHYSICAL_BASE as usize + 0x10000;
        let first_pa = KERNEL_GLOBAL_PHYSICAL_BASE as usize + 0x20000;
        let last_pa = KERNEL_GLOBAL_PHYSICAL_BASE as usize + 0x30000;
        let head = init_va + profile.tasks;
        let first = first_va + profile.tasks;
        let last = last_va + profile.tasks;
        let symbol_path = root.join("symbols/linux/kernel.json");
        let mut symbol_json: serde_json::Value =
            serde_json::from_str(&synthetic_kernel_global_isf()).unwrap();
        symbol_json["symbols"]["init_task"] = serde_json::json!({ "address": init_va });
        fs::write(&symbol_path, serde_json::to_vec(&symbol_json).unwrap()).unwrap();
        let isf = crate::linux_symbols::load_linux_isf_for_features(
            &symbol_path,
            [
                LinuxSymbolFeature::Modules,
                LinuxSymbolFeature::IncidentResponse,
            ],
        )
        .unwrap();
        let banner = BannerEvidence {
            physical_address: KERNEL_GLOBAL_PHYSICAL_BASE + 0x1000,
            text: KERNEL_GLOBAL_BANNER_TEXT.to_owned(),
        };
        let init = InitTaskCandidate {
            physical_address: init_pa as u64,
            virtual_address: init_va,
            tasks_next: first,
            tasks_prev: last,
        };
        let mut kernel = synthetic_process_list_report(Vec::new()).kernel;
        kernel.init_task = init_va;
        kernel.init_task_physical = init_pa as u64;
        let scan = DiscoveryScanStats {
            bytes_scanned: 0,
            elapsed_seconds: 0.0,
            gib_per_second: 0.0,
        };
        let mut bytes = fs::read(&image_path).unwrap();
        write_task(
            &mut bytes,
            init_pa,
            &profile,
            init_va,
            0,
            "swapper/0",
            first,
            last,
            0,
        );
        write_task(
            &mut bytes, first_pa, &profile, init_va, 1, "systemd", last, head, 1,
        );
        // An acquisition-torn tail points back into the list instead of closing at init_task.
        write_task(
            &mut bytes, last_pa, &profile, init_va, 2, "kthreadd", first, first, 2,
        );
        fs::write(&image_path, &bytes).unwrap();
        let image = MemoryImage::open(&image_path).unwrap();
        let space = LinuxX64AddressSpace::new(&image, 0x1000).unwrap();
        validate_selected_runtime_context(&space, &profile, &init, Some(&isf), &banner).unwrap();
        assert!(validate_selected_runtime_context(&space, &profile, &init, None, &banner).is_err());
        let report = list_processes(&image, &profile, &kernel, &[], &scan, 100).unwrap();
        assert_eq!(report.processes.len(), 2);
        assert!(!report.complete);
        assert_eq!(report.stop_reason, LinuxProcessListStopReason::Cycle);
        let wrong_banner = BannerEvidence {
            text: "Linux version wrong".into(),
            ..banner.clone()
        };
        assert!(
            validate_selected_runtime_context(&space, &profile, &init, Some(&isf), &wrong_banner)
                .is_err()
        );
        drop(image);
        put_u64(&mut bytes, first_pa + profile.tasks as usize + 8, last);
        fs::write(&image_path, bytes).unwrap();
        let image = MemoryImage::open(&image_path).unwrap();
        let space = LinuxX64AddressSpace::new(&image, 0x1000).unwrap();
        assert!(
            validate_selected_runtime_context(&space, &profile, &init, Some(&isf), &banner)
                .is_err()
        );
        drop(image);
        fs::remove_dir_all(root).unwrap();
    }

    fn synthetic_profile() -> LinuxTaskProfile {
        LinuxTaskProfile {
            source: "test",
            fingerprint: "test".to_owned(),
            btf_physical_address: None,
            task_size: 0x100,
            state: 0x08,
            state_size: 8,
            tasks: 0x20,
            mm: Some(0x30),
            pid: 0x40,
            tgid: 0x44,
            real_parent: 0x48,
            parent: Some(0x50),
            start_time: Some(LinuxTaskStartTime::Nanoseconds(0x58)),
            comm: 0x70,
            comm_len: 16,
            exit_state: None,
            flags: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_task(
        bytes: &mut [u8],
        physical: usize,
        profile: &LinuxTaskProfile,
        parent: u64,
        pid: i32,
        name: &str,
        next: u64,
        previous: u64,
        state: u64,
    ) {
        put_u64(bytes, physical + profile.state as usize, state);
        put_u64(bytes, physical + profile.tasks as usize, next);
        put_u64(bytes, physical + profile.tasks as usize + 8, previous);
        put_u64(
            bytes,
            physical + profile.mm.unwrap() as usize,
            u64::from(pid != 2) * 0x1000,
        );
        put_u32(bytes, physical + profile.pid as usize, pid as u32);
        put_u32(bytes, physical + profile.tgid as usize, pid as u32);
        put_u64(bytes, physical + profile.real_parent as usize, parent);
        put_u64(bytes, physical + profile.parent.unwrap() as usize, parent);
        put_u64(
            bytes,
            physical + profile.start_time.unwrap().offset() as usize,
            pid as u64 * 1000,
        );
        let name_bytes = name.as_bytes();
        bytes
            [physical + profile.comm as usize..physical + profile.comm as usize + name_bytes.len()]
            .copy_from_slice(name_bytes);
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    const KERNEL_GLOBAL_VIRTUAL_BASE: u64 = 0xffff_8000_0020_0000;
    const KERNEL_GLOBAL_PHYSICAL_BASE: u64 = 0x20_0000;
    const KERNEL_GLOBAL_STEXT: u64 = KERNEL_GLOBAL_VIRTUAL_BASE;
    const KERNEL_GLOBAL_BANNER: u64 = KERNEL_GLOBAL_VIRTUAL_BASE + 0x1000;
    const KERNEL_GLOBAL_BANNER_TEXT: &str = "Linux version 6.8.0-starmem-kernel-session #1 SMP";

    fn synthetic_kernel_global_isf() -> String {
        let banner = BASE64_STANDARD.encode(format!("{KERNEL_GLOBAL_BANNER_TEXT}\0"));
        format!(
            r#"{{
                "metadata": {{
                    "format": "6.2.0",
                    "producer": {{"name": "dwarf2json", "version": "test"}},
                    "linux": {{
                        "symbols": [{{"hash_type": "sha256", "hash_value": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}],
                        "types": []
                    }}
                }},
                "base_types": {{
                    "long unsigned int": {{"size": 8}},
                    "char": {{"size": 1}}
                }},
                "user_types": {{
                    "list_head": {{"size": 16, "fields": {{}}}},
                    "module_layout": {{"size": 64, "fields": {{}}}},
                    "module": {{
                        "size": 256,
                        "fields": {{
                            "list": {{"offset": 0, "type": {{"kind": "struct", "name": "list_head"}}}},
                            "name": {{"offset": 24, "type": {{"kind": "array", "count": 56, "subtype": {{"kind": "base", "name": "char"}}}}}},
                            "core_layout": {{"offset": 96, "type": {{"kind": "struct", "name": "module_layout"}}}}
                        }}
                    }}
                }},
                "enums": {{}},
                "symbols": {{
                    "_stext": {{"address": {KERNEL_GLOBAL_STEXT}}},
                    "linux_banner": {{"address": {KERNEL_GLOBAL_BANNER}, "constant_data": "{banner}"}},
                    "modules": {{"address": 18446603336223358976}}
                }}
            }}"#
        )
    }

    fn synthetic_kernel_global_fixture(with_vmcoreinfo: bool) -> (PathBuf, PathBuf, SymbolStore) {
        let root = temporary_path("kernel-global-root").with_extension("");
        let symbol_root = root.join("symbols/linux");
        fs::create_dir_all(&symbol_root).unwrap();
        fs::write(
            symbol_root.join("kernel.json"),
            synthetic_kernel_global_isf(),
        )
        .unwrap();

        let image_path = root.join("memory.raw");
        let mut bytes = vec![0_u8; 0x40_0000];
        let pml4_index = ((KERNEL_GLOBAL_VIRTUAL_BASE >> 39) & 0x1ff) as usize;
        let pdpt_index = ((KERNEL_GLOBAL_VIRTUAL_BASE >> 30) & 0x1ff) as usize;
        let pd_index = ((KERNEL_GLOBAL_VIRTUAL_BASE >> 21) & 0x1ff) as usize;
        put_u64(&mut bytes, 0x1000 + pml4_index * 8, 0x2003);
        put_u64(&mut bytes, 0x2000 + pdpt_index * 8, 0x3003);
        put_u64(
            &mut bytes,
            0x3000 + pd_index * 8,
            KERNEL_GLOBAL_PHYSICAL_BASE | 0x83,
        );
        bytes[KERNEL_GLOBAL_PHYSICAL_BASE as usize] = 0x90;
        let banner_physical = (KERNEL_GLOBAL_PHYSICAL_BASE + 0x1000) as usize;
        bytes[banner_physical..banner_physical + KERNEL_GLOBAL_BANNER_TEXT.len()]
            .copy_from_slice(KERNEL_GLOBAL_BANNER_TEXT.as_bytes());
        bytes[banner_physical + KERNEL_GLOBAL_BANNER_TEXT.len()] = 0;
        if with_vmcoreinfo {
            let vmcoreinfo = format!(
                "OSRELEASE=6.8.0-starmem-kernel-session\nPAGESIZE=4096\nSYMBOL(init_top_pgt)=ffffffff80001000\nSYMBOL(_stext)={KERNEL_GLOBAL_STEXT:x}\nNUMBER(phys_base)=0\nKERNELOFFSET=0\nNUMBER(pgtable_l5_enabled)=0\nNUMBER(sme_mask)=0\n\0"
            );
            bytes[0x6000..0x6000 + vmcoreinfo.len()].copy_from_slice(vmcoreinfo.as_bytes());
        }
        // Deliberately do not place `swapper` or any task_struct in this fixture.
        fs::write(&image_path, bytes).unwrap();
        let store = SymbolStore::new(root.join("cache")).with_search_root(root.join("symbols"));
        (root, image_path, store)
    }

    #[test]
    fn kernel_global_session_auto_opens_from_vmcoreinfo_without_a_task_anchor() {
        let (root, image_path, store) = synthetic_kernel_global_fixture(true);
        let image = MemoryImage::open(&image_path).unwrap();
        assert!(scan_linux_anchors(&image).is_err());

        let opened = open_linux_kernel_session(
            image,
            &store,
            [LinuxSymbolFeature::Modules],
            LinuxKernelSessionOptions::default(),
        )
        .unwrap();
        assert_eq!(opened.evidence.directory_table_base, 0x1000);
        assert_eq!(opened.evidence.page_table_source, "vmcoreinfo");
        assert_eq!(opened.evidence.kernel_slide, 0);
        assert_eq!(
            opened.evidence.kernel_slide_source,
            "vmcoreinfo:SYMBOL(_stext)-isf:_stext"
        );
        assert_eq!(opened.evidence.vmcoreinfo_physical_address, Some(0x6000));
        assert_eq!(
            opened.session.translate(KERNEL_GLOBAL_STEXT).unwrap(),
            KERNEL_GLOBAL_PHYSICAL_BASE
        );
        drop(opened);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn kernel_global_session_explicit_overrides_do_not_require_vmcoreinfo_or_tasks() {
        let (root, image_path, store) = synthetic_kernel_global_fixture(false);
        let image = MemoryImage::open(&image_path).unwrap();
        let opened = open_linux_kernel_session(
            image,
            &store,
            [LinuxSymbolFeature::Modules],
            LinuxKernelSessionOptions {
                directory_table_base: Some(0x1000),
                kernel_slide: Some(0),
            },
        )
        .unwrap();
        assert_eq!(opened.evidence.page_table_source, "explicit_override");
        assert_eq!(opened.evidence.kernel_slide_source, "explicit_override");
        assert_eq!(opened.evidence.vmcoreinfo_physical_address, None);
        assert_eq!(
            opened.evidence.requested_features,
            [LinuxSymbolFeature::Modules]
        );
        drop(opened);
        fs::remove_dir_all(root).unwrap();
    }

    fn synthetic_process_record(pid: i32, ppid: Option<i32>, name: &str) -> LinuxProcessRecord {
        LinuxProcessRecord {
            task: 0xffff_8000_0000_0000 + pid as u64 * 0x1000,
            list_entry: 0xffff_8000_1000_0000 + pid as u64 * 0x1000,
            pid,
            tgid: pid,
            ppid,
            name: name.to_owned(),
            state: "running".to_owned(),
            state_raw: 0,
            exit_state: Some(0),
            flags: Some(0),
            mm: Some(0x1000),
            kernel_thread: Some(false),
            start_time_ns: Some(pid as u64 * 1000),
        }
    }

    fn synthetic_process_list_report(processes: Vec<LinuxProcessRecord>) -> LinuxProcessListReport {
        LinuxProcessListReport {
            kernel: LinuxKernelContext {
                architecture: "x86_64_4level".to_owned(),
                banner: "Linux version 6.18.0-test #1 SMP".to_owned(),
                banner_physical_address: 0,
                directory_table_base: 0x1000,
                page_table_source: "test".to_owned(),
                vmcoreinfo_physical_address: None,
                init_task: 0xffff_8000_0000_0000,
                init_task_physical: 0x2000,
                profile_source: "test".to_owned(),
                profile_fingerprint: "test".to_owned(),
                btf_physical_address: None,
                task_struct_size: 0x1000,
                task_struct_offsets: BTreeMap::new(),
                symbol_table: None,
                system_map: None,
            },
            processes,
            complete: true,
            stop_reason: LinuxProcessListStopReason::ListHead,
            warnings: Vec::new(),
            bytes_scanned: 0,
            scan_seconds: 0.0,
            scan_gib_per_second: 0.0,
        }
    }

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "starmem-linux-{label}-{}-{nonce}.raw",
            std::process::id()
        ))
    }
}
