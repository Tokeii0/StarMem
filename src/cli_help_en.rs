use clap::{Arg, Command};

pub(super) fn localize(mut command: Command) -> Command {
    if let Some(about) = command.get_about() {
        let english = translate(&about.to_string()).to_owned();
        command = command.about(english).long_about(None);
    }
    let name = command.get_name().to_owned();
    command.mut_args(move |argument| localize_argument(argument, &name))
}

fn localize_argument(mut argument: Arg, command: &str) -> Arg {
    let id = argument.get_id().as_str();
    let original = argument.get_help().map(ToString::to_string);
    let help = super::argument_help(command, id)
        .or(original.as_deref())
        .map(|text| translate(text).to_owned())
        .unwrap_or_else(|| format!("Value for {}", id.replace('_', "-")));
    let value_name = super::argument_value_name(id)
        .or_else(|| {
            argument
                .get_value_names()
                .and_then(|names| names.first())
                .map(|name| name.as_str())
        })
        .and_then(translate_value_name);
    argument = argument
        .help(help)
        .long_help(None)
        .hide_possible_values(true);
    if let Some(name) = value_name {
        argument = argument.value_name(name);
    }
    argument
}

fn translate_value_name(name: &str) -> Option<&'static str> {
    Some(match name {
        "镜像文件" => "IMAGE",
        "输入路径" => "INPUT",
        "文件" => "FILE",
        "文件.jsonl" => "FILE.jsonl",
        "SQLite文件" => "SQLITE_FILE",
        "目录" => "DIRECTORY",
        "地址" => "ADDRESS",
        "属性ID" => "ATTRIBUTE_ID",
        "进程ID" => "PID",
        "数量" => "COUNT",
        "线程数" => "THREADS",
        "大小" => "SIZE",
        "兆字节" => "MIB",
        "标签" => "TAG",
        "命令" => "COMMAND",
        "值" => "VALUE",
        "类型" => "KIND",
        "来源" => "SOURCE",
        _ => return None,
    })
}

fn translate(text: &str) -> &str {
    match text {
        "--object 模式跨全部进程最多检查的句柄表项数。" => {
            "Maximum handle table entries to inspect across all processes in --object mode."
        }
        "--owners 最多扫描的句柄表项数。" => {
            "Maximum handle table entries to scan with --owners."
        }
        "Hive 名称或完整注册表根路径" => "Hive name or full registry root path.",
        "Linux 内核应急响应：系统、网络接口、回调、追踪与设备，不依赖活动任务链。" => {
            "Linux kernel incident response for system state, interfaces, callbacks, tracing, and devices. Does not require the active task list."
        }
        "Linux 定位 dentry 时最多保留的驻留 VFS 文件记录数；Windows 忽略" => {
            "Maximum resident VFS file records retained when locating the dentry on Linux. Ignored on Windows."
        }
        "Linux 应急响应：权限、线程、ELF、可疑映射、文件内容、持久化与时间线。" => {
            "Linux incident response for permissions, threads, ELF images, suspicious mappings, file contents, persistence, and timelines."
        }
        "Linux 文件路径；file-content 必填，其他文件模块可按目录收窄。" => {
            "Linux file path. Required for file-content. Other file modules can narrow their scope to a directory."
        }
        "PE 输出文件的最大安全大小" => "Maximum safe PE output size.",
        "QEVM RAMBlock 从物理地址 0 开始映射的字节数；支持十进制或 0x 十六进制。" => {
            "Bytes of the QEVM RAMBlock mapped starting at physical address 0. Accepts decimal or 0x hexadecimal."
        }
        "QEVM 中承载来宾系统内存的 RAMBlock 名称（通常为 pc.ram）。" => {
            "QEVM RAMBlock holding guest RAM, typically pc.ram."
        }
        "QEVM 剩余高端 RAM 的来宾物理基址；支持十进制或 0x 十六进制。" => {
            "Guest physical base address of the remaining high QEVM RAM. Accepts decimal or 0x hexadecimal."
        }
        "Windows filescan/handles 的 FILE_OBJECT，或 Linux filescan 的 dentry 虚拟地址" => {
            "Windows FILE_OBJECT from filescan or handles, or Linux dentry virtual address from filescan."
        }
        "Windows 恢复来源；Linux 物理内存当前仅接受默认 auto，并从页缓存恢复" => {
            "Windows recovery source. Linux accepts the default auto and recovers from the page cache."
        }
        "Windows 扫描文件对象池；Linux 遍历已验证的 superblock/dentry 文件树。" => {
            "Scan file object pools on Windows or walk the validated superblock and dentry trees on Linux."
        }
        "YARA 规则文件；可多次指定" => "YARA rule file. May be specified more than once.",
        "filescan 最多保留的 FILE_OBJECT 数量。" => {
            "Maximum FILE_OBJECT records retained by filescan."
        }
        "filescan 最多保留的 FILE_OBJECT 记录数" => {
            "Maximum FILE_OBJECT records retained by filescan."
        }
        "mftscan 报告的 MFT FILE 记录物理地址" => {
            "Physical address of the MFT FILE record reported by mftscan."
        }
        "services.exe 内存关联允许保留的最大服务记录数。" => {
            "Maximum service records retained when correlating services.exe memory."
        }
        "一次关联驻留文件对象与全部活动进程句柄。" => {
            "Correlate resident file objects with handles across all active processes."
        }
        "一次恢复注册表并输出打印机、策略、安全、WMI、RDP、网络与 WiFi 等系统证据。" => {
            "Recover the registry once and report system evidence for printers, policies, security, WMI, RDP, networking, and Wi-Fi."
        }
        "一次物理扫描 ASCII/UTF-8 与 UTF-16LE 字面字符串，并反查活动进程归属。" => {
            "Scan physical memory once for literal ASCII/UTF-8 and UTF-16LE strings and map hits back to active processes."
        }
        "不扫描 FTK Imager、DumpIt、WinPmem 等采集工具进程及输出句柄。" => {
            "Skip acquisition tool processes and output handles for tools such as FTK Imager, DumpIt, and WinPmem."
        }
        "不把严格 modules 链证明的 module text 纳入可执行范围。" => {
            "Exclude module text validated by the strict modules list from executable ranges."
        }
        "不自动定位并恢复同目录的 -wal、-shm 与 -journal。" => {
            "Skip automatic discovery and recovery of nearby -wal, -shm, and -journal files."
        }
        "不自动生成事件时间线文件" => "Disable automatic event timeline creation.",
        "严格遍历 Linux modules 双向链并验证每个 module 对象。" => {
            "Walk the Linux doubly linked modules list and validate every module object."
        }
        "主数据库 FILE_OBJECT，支持十进制或 0x 十六进制。" => {
            "FILE_OBJECT address of the main database, in decimal or 0x hexadecimal."
        }
        "交叉关联进程、最早活动线程与句柄，检查记录 PPID 是否疑似伪造。" => {
            "Correlate processes, their earliest active threads, and handles to flag possible PPID spoofing."
        }
        "交叉对比 modules list 与 module_kset，显式报告尚不可用的语义扫描视图。" => {
            "Compare the modules list with module_kset and report when the semantic scan view is unavailable."
        }
        "交叉比对链表、内存池和线程归属证据以发现隐藏进程。" => {
            "Cross-check lists, memory pools, and thread ownership to find hidden processes."
        }
        "仅 fbdev：保存完整驻留帧缓冲的 BMP 目录；默认只列设备。" => {
            "fbdev only. Directory for BMP exports of fully resident framebuffers. By default, list devices only."
        }
        "仅保留结构或身份字段能够直接证明的异常，隐藏上下文风险信号。" => {
            "Show anomalies directly supported by structure or identity fields and omit contextual risk signals."
        }
        "仅保留进程名包含此字符串的活动句柄。" => {
            "Keep active handles only for processes whose names contain this string."
        }
        "仅分析微信主进程，跳过辅助进程和小程序运行时" => {
            "Analyze the main WeChat process only, skipping helpers and mini-program runtimes."
        }
        "仅启用指定来源；可重复指定或使用逗号分隔，默认启用全部来源。" => {
            "Enable only the specified sources. Repeat the option or separate sources with commas. Defaults to all sources."
        }
        "仅启用指定来源；可重复指定或逗号分隔，默认启用全部。" => {
            "Enable only the specified sources. Repeat the option or separate sources with commas. Defaults to all sources."
        }
        "仅对指定表执行行数查询；可重复传入。默认只列出全部表结构。" => {
            "Count rows only in the specified tables. May be repeated. By default, list all table schemas."
        }
        "仅生成交互式首屏所需的快速概览，不执行深度网络池与注册表扫描。" => {
            "Produce a fast overview for interactive use and skip deep network-pool and registry scans."
        }
        "仅诊断指定的 Volatility 3 ISF（.json 或 .json.xz）。" => {
            "Diagnose only the specified Volatility 3 ISF (.json or .json.xz)."
        }
        "仅重建指定桌面名称，例如 Default 或 Winlogon。" => {
            "Reconstruct only the named desktop, such as Default or Winlogon."
        }
        "仅重建指定登录会话。" => "Reconstruct only the selected logon session.",
        "从 Chromium History 数据库恢复 URL 访问历史。" => {
            "Recover URL visit history from Chromium History databases."
        }
        "从 DWM/WARP 或系统内存合成表面恢复真实显示帧，并生成窗口布局画布。" => {
            "Recover display frames from DWM/WARP or system-memory composition surfaces and render a window-layout canvas."
        }
        "从 KiProcessorBlock 枚举各处理器的 KPCR/KPRCB 状态。" => {
            "Enumerate each processor's KPCR/KPRCB state through KiProcessorBlock."
        }
        "从 Linux 进程 mm_struct 的参数区间恢复 argv/命令行。" => {
            "Recover argv and command lines from the argument ranges in Linux process mm_struct objects."
        }
        "从 Linux 进程 mm_struct 的环境区间恢复环境变量。" => {
            "Recover environment variables from the environment ranges in Linux process mm_struct objects."
        }
        "从 Windows FILE_OBJECT 或 Linux 已验证页缓存恢复文件内容。" => {
            "Recover file contents from Windows FILE_OBJECTs or the validated Linux page cache."
        }
        "从 Windows 内存聚合进程、线程、MFT、Shimcache 与注册表时间证据。" => {
            "Combine process, thread, MFT, Shimcache, and registry timestamp evidence from Windows memory."
        }
        "从 ahcache.sys 或 NT 内核中恢复结构有效的 Shimcache AVL/LRU 条目。" => {
            "Recover structurally valid Shimcache AVL/LRU entries from ahcache.sys or the NT kernel."
        }
        "从 syscall table 起始验证的指针数。" => {
            "Number of pointers to check from the start of the syscall table."
        }
        "从内核 PDB 生成精简的 _EPROCESS 字段配置。" => {
            "Generate a minimal _EPROCESS field profile from a kernel PDB."
        }
        "从内核模块重建 PE 映像" => "Rebuild the PE image from a kernel module.",
        "从十进制或 0x 十六进制对象地址反查全部活动句柄所有者。" => {
            "Find all active handle owners for a decimal or 0x hexadecimal object address."
        }
        "从各进程 PEB 恢复映像路径和命令行。" => {
            "Recover image paths and command lines from process PEBs."
        }
        "从已验证的内存池恢复活动、已退出和脱链的 EPROCESS 对象。" => {
            "Recover active, exited, and unlinked EPROCESS objects from validated memory pools."
        }
        "从已验证的线程池恢复 ETHREAD 对象。" => {
            "Recover ETHREAD objects from validated thread pools."
        }
        "从微信进程地址空间恢复 SQLCipher 数据库密钥候选及 salt。" => {
            "Recover SQLCipher database key candidates and salts from WeChat process address spaces."
        }
        "从指定 MFT FILE 记录完整导出常驻 $DATA 或备用数据流。" => {
            "Export complete resident $DATA or an alternate data stream from the specified MFT FILE record."
        }
        "从指定虚拟地址重建进程或内核 PE 映像。" => {
            "Rebuild a process or kernel PE image from the specified virtual address."
        }
        "从映像锚点或结构化前驱关系恢复 services.exe 的活动服务链表。" => {
            "Recover the active services.exe service list using image anchors or validated predecessor relationships."
        }
        "从活动 Bash 堆中恢复与 #epoch 时间戳关联的 HIST_ENTRY 命令。" => {
            "Recover HIST_ENTRY commands associated with #epoch timestamps from active Bash heaps."
        }
        "从活动进程的已验证 socket FD 恢复网络与 UNIX socket 端点。" => {
            "Recover network and UNIX socket endpoints from validated file descriptors of active processes."
        }
        "从物理内存恢复经过校验的完整 IP 包，并可导出为 PCAPNG。" => {
            "Recover validated, complete IP packets from physical memory and optionally export them to PCAPNG."
        }
        "从经过精确符号验证的 DWM 合成表面恢复屏幕分辨率。" => {
            "Recover screen resolution from DWM composition surfaces validated with matching symbols."
        }
        "从进程 VAD 中验证标准 DIB 结构，并将完整驻留像素无损导出为 BMP。" => {
            "Validate standard DIB structures in process VADs and export fully resident pixels losslessly as BMP."
        }
        "从驻留 FILE_OBJECT 恢复并解析 Windows Prefetch 执行记录。" => {
            "Recover and parse Windows Prefetch execution records from resident FILE_OBJECTs."
        }
        "从驻留注册表 Hive 恢复 TaskCache 计划任务注册信息。" => {
            "Recover TaskCache scheduled-task registrations from resident registry hives."
        }
        "从驻留的 SECURITY 数据解密域缓存登录哈希。" => {
            "Decrypt cached domain logon hashes from resident SECURITY data."
        }
        "从驻留的 SYSTEM 和 SECURITY Hive 解密 LSA Policy Secrets。" => {
            "Decrypt LSA Policy Secrets from resident SYSTEM and SECURITY hives."
        }
        "以父子树形式显示活动进程。" => {
            "Display active processes as a parent-child tree."
        }
        "使用 PDB 中的 ETHREAD 布局遍历所有进程线程链表。" => {
            "Walk process thread lists using the ETHREAD layout from the PDB."
        }
        "使用 YARA-X 编译规则并扫描驻留的 VAD 区间。" => {
            "Compile rules with YARA-X and scan resident VAD ranges."
        }
        "使用字节正则表达式扫描驻留的 VAD 区间。" => {
            "Scan resident VAD ranges with a byte-oriented regular expression."
        }
        "使用精确 PDB 遍历 tcpip.sys 分区哈希及活动 TCP/UDP 端口池。" => {
            "Walk tcpip.sys partition hashes and active TCP/UDP port pools using matching PDB symbols."
        }
        "使用驻留的 SYSTEM 和 SAM Hive 解密本地 LM/NT 哈希。" => {
            "Decrypt local LM/NT hashes from resident SYSTEM and SAM hives."
        }
        "偏移类型：file 表示镜像文件，physical 表示物理内存" => {
            "Offset type: file for image file offsets, or physical for physical memory offsets."
        }
        "允许从 module core/init 恢复的最大逻辑字节数。" => {
            "Maximum logical bytes to recover from module core and init regions."
        }
        "允许恢复的单个 IP 包最大字节数" => {
            "Maximum recoverable size of one IP packet, in bytes."
        }
        "允许覆盖已存在的输出文件" => {
            "Allow replacement of declared outputs. Protected inputs remain protected."
        }
        "全部 Bash 堆/匿名可写 VMA 的最大扫描字节数。" => {
            "Maximum bytes to scan across Bash heaps and anonymous writable VMAs."
        }
        "全部 VMA 允许导出的最大逻辑大小。" => {
            "Maximum combined logical size of all VMA exports."
        }
        "共享只读符号根；Linux 复用 Volatility 3 ISF，未知构建最后使用远程精确 banner 兜底；可多次指定" => {
            "Shared read-only symbol root. Linux accepts Volatility 3 ISFs and can fall back to an exact remote banner match. May be repeated."
        }
        "关联 services.exe 内存中的服务控制管理器记录。" => {
            "Correlate Service Control Manager records in services.exe memory."
        }
        "关联进程、EJOB 对象及其作业限制。" => {
            "Correlate processes, EJOB objects, and job limits."
        }
        "包含偏移和文本的 strings 输出文件" => {
            "strings output file containing offsets and text."
        }
        "包含全部事件，而非仅保留高价值取证事件" => {
            "Include every event, rather than only high-value forensic events."
        }
        "包含已标记为空闲的池条目" => "Include pool entries marked free.",
        "十六进制字面量锚点最多保留的数量" => {
            "Maximum hexadecimal literal anchors to retain."
        }
        "单个 Cookie 数据库的最大恢复大小，单位为 MiB" => {
            "Maximum recovery size per cookie database, in MiB."
        }
        "单个 History 数据库允许恢复的最大大小，单位为 MiB" => {
            "Maximum recovery size per History database, in MiB."
        }
        "单个 MAM 容器允许的最大解压字节数。" => {
            "Maximum decompressed bytes per MAM container."
        }
        "单个 PSReadLine 历史文件允许恢复的最大大小，单位为 MiB。" => {
            "Maximum recovery size per PSReadLine history file, in MiB."
        }
        "单个 VAD 允许导出的最大字节数。" => "Maximum bytes to export per VAD.",
        "单个 VMA 允许导出的最大逻辑大小。" => "Maximum logical export size per VMA.",
        "单个导出文件的最大逻辑大小" => "Maximum logical size per exported file.",
        "单个数据库、剪切板块或历史文件允许读取的最大大小，单位为 MiB" => {
            "Maximum read size per database, clipboard block, or history file, in MiB."
        }
        "单个活动剪切板数据块的最大读取大小，单位为 MiB" => {
            "Maximum read size per active clipboard data block, in MiB."
        }
        "单个物理页在同一进程页表中最多保留的虚拟别名数。" => {
            "Maximum virtual aliases to retain per physical page in one process page table."
        }
        "单个驻留 Prefetch 文件的最大恢复字节数。" => {
            "Maximum bytes to recover per resident Prefetch file."
        }
        "单张位图允许的最大像素数据大小，单位为 MiB。" => {
            "Maximum pixel data per bitmap, in MiB."
        }
        "单张位图允许的最大边长。" => "Maximum bitmap width or height.",
        "单张桌面画布允许的最大边长。" => "Maximum desktop canvas width or height.",
        "单条 Bash 命令允许读取的最大字节数。" => {
            "Maximum bytes to read per Bash command."
        }
        "单次遍历物理内存并扫描多个池标签。" => {
            "Scan physical memory for multiple pool tags in a single pass."
        }
        "只接受显式 LastArrivalDate；缺失时不使用主存储实例键 LastWrite 代理。" => {
            "Require an explicit LastArrivalDate. Skip the storage instance key's LastWrite fallback."
        }
        "只输出具备直接执行时间语义的 Prefetch、BAM/DAM 与 UserAssist。" => {
            "Include only Prefetch, BAM/DAM, and UserAssist evidence with direct execution timestamps."
        }
        "可写符号缓存目录；同时兼容 --symbol-cache" => {
            "Writable symbol cache directory. Also accepts --symbol-cache."
        }
        "同时包含通常噪声较高的 MFT 文件访问时间。" => {
            "Include MFT file access timestamps, which are often noisy."
        }
        "同时恢复 SYSTEM 注册表中的服务元数据" => {
            "Also recover service metadata from the SYSTEM registry."
        }
        "同时报告未完全驻留的区间；缺页时\"全部页只读\"并未被证明，默认不报。" => {
            "Include partially resident ranges. Missing pages prevent confirming that every page is read-only."
        }
        "同时报告私有且可执行的区间（malfind 同款判据）。" => {
            "Also report private executable ranges using the same criteria as malfind."
        }
        "同时输出分析主机文件系统的创建/修改时间；这些时间不作为采集时间。" => {
            "Include host filesystem creation and modification times as separate metadata."
        }
        "同时输出没有活动句柄所有者的驻留 FILE_OBJECT。" => {
            "Also list resident FILE_OBJECTs with no active handle owner."
        }
        "同时输出非存储类 USB 接口。" => "Include non-storage USB interfaces.",
        "名称" => "Name.",
        "命中两侧各输出的上下文字节数，最大 4096。" => {
            "Context bytes to display on each side of a hit, up to 4096."
        }
        "四字节池标签；可多次指定" => {
            "Four-byte pool tag. May be specified more than once."
        }
        "在内存镜像中定位 RSDS 记录。" => "Locate RSDS records in a memory image.",
        "在已采集的物理内存范围中扫描精确字节序列。" => {
            "Scan captured physical memory ranges for an exact byte sequence."
        }
        "备用数据流名称；不指定时导出无名 $DATA" => {
            "Alternate data stream name. Defaults to the unnamed $DATA stream."
        }
        "字节正则表达式" => "Byte-oriented regular expression.",
        "定位 /etc/passwd 时最多保留的驻留 VFS 文件记录数" => {
            "Maximum resident VFS file records retained when locating /etc/passwd."
        }
        "定位 Linux _stext，并通过已验证页表给出首条内核指令的虚拟/物理地址。" => {
            "Locate Linux _stext and report the first kernel instruction's virtual and physical addresses using validated page tables."
        }
        "定位 PDB 标识并从 Microsoft 符号服务器下载。" => {
            "Find the PDB identity and download the file from Microsoft's symbol server."
        }
        "定位并验证 Windows 内核启动上下文。" => {
            "Locate and validate the Windows kernel bootstrap context."
        }
        "对照内核映像检查各 HHIVE GetCellRoutine 目标。" => {
            "Check each HHIVE GetCellRoutine target against the kernel image."
        }
        "将 --isf 复验后安装到 StarMem 可写符号根。" => {
            "Revalidate --isf and install it in StarMem's writable symbol root."
        }
        "将 DRIVER_OBJECT 映像与已加载模块链表进行关联。" => {
            "Correlate DRIVER_OBJECT images with the loaded module list."
        }
        "将 EPROCESS 创建时间纳入执行证据；--aggregate 且未限定来源时自动启用。" => {
            "Include EPROCESS creation times as execution evidence. Enabled with --aggregate when no sources are specified."
        }
        "将 EVTX 文件解析为筛选后的取证事件时间线。" => {
            "Parse EVTX files into a filtered timeline of forensic events."
        }
        "将发现的 PDB 下载到符号缓存" => {
            "Download the identified PDB to the symbol cache."
        }
        "将可复核原始对象按稳定 evidence_id 排序写为 JSONL。" => {
            "Write reviewable raw objects to JSONL in stable evidence_id order."
        }
        "将当前插件的完整结构化报告写为兼容 Excel 的 UTF-8 CSV；使用 - 输出到标准输出" => {
            "Write the full report as Excel-compatible UTF-8 CSV. Use - for stdout."
        }
        "将恢复的数据包写入 PCAPNG 文件" => "Write recovered packets to a PCAPNG file.",
        "将时间相近且身份一致的原始证据聚合为执行 episode；原 events 仍保留。" => {
            "Group nearby events with matching identities into execution episodes and retain the original events."
        }
        "将预先生成的字符串偏移映射到内核或进程虚拟地址。" => {
            "Map precomputed string offsets to kernel or process virtual addresses."
        }
        "已有的 JSON 符号配置文件" => "Existing JSON symbol profile file.",
        "已由其他证据验证的 task_struct 地址。" => {
            "task_struct address already validated by other evidence."
        }
        "并行工作线程数；0 表示使用全部逻辑处理器" => {
            "Worker threads. Use 0 for all logical processors."
        }
        "强制刷新远程 banner 索引后再解析精确匹配候选。" => {
            "Refresh the remote banner index before resolving an exact match."
        }
        "恢复 Linux /etc/passwd；无存活 dentry 时使用明确标注的反向页缓存候选。" => {
            "Recover Linux /etc/passwd. If no live dentry remains, use a labeled reverse page-cache candidate."
        }
        "恢复 conhost 控制台元数据、屏幕内容和命令历史。" => {
            "Recover conhost console metadata, screen contents, and command history."
        }
        "恢复全部驻留的 Windows 事件日志和 ETL 文件。" => {
            "Recover resident Windows event logs and ETL files."
        }
        "恢复全部驻留的注册表 Hive 和事务文件。" => {
            "Recover resident registry hives and transaction files."
        }
        "恢复内容目标文件；Linux 完整结果使用此路径，不完整结果保留为同名 .partial" => {
            "Destination file. On Linux, incomplete output is saved with the .partial suffix."
        }
        "恢复内核循环记录的已卸载驱动历史。" => {
            "Recover unloaded driver history from the kernel's circular record."
        }
        "恢复各用户的 UserAssist 程序执行记录。" => {
            "Recover UserAssist execution records for each user."
        }
        "恢复完整的进程环境变量块。" => "Recover full process environment blocks.",
        "恢复数据库、sidecar 与页级清单的输出目录。" => {
            "Output directory for the database, sidecars, and page-level recovery manifest."
        }
        "恢复文件的最大逻辑大小" => "Maximum logical size of the recovered file.",
        "恢复新版和旧版 Amcache 的应用、文件及驱动记录。" => {
            "Recover application, file, and driver records from old and new Amcache layouts."
        }
        "恢复来源：auto 自动选择，cache 缓存，data 数据节区，image 映像节区" => {
            "Recovery source: auto selects a source, cache uses cached pages, data uses a data section, and image uses an image section."
        }
        "恢复每个具有非空标题的 GUI 窗口，并关联进程、桌面和父窗口。" => {
            "Recover GUI windows with non-empty titles and associate each with its process, desktop, and parent."
        }
        "恢复浏览器 Cookie、下载 URL 与会话中的域名证据，并关联进程归属。" => {
            "Recover browser cookies, download URLs, and domain evidence from sessions and associate them with processes."
        }
        "恢复浏览器进程内明文 Cookie，并解析驻留的 Chromium、Firefox 和旧式 Cookie 文件。" => {
            "Recover plaintext cookies from browser memory and parse resident Chromium, Firefox, and legacy cookie files."
        }
        "恢复驻留 MFT $DATA 属性的数据预览。" => {
            "Preview data from resident MFT $DATA attributes."
        }
        "恢复驻留 SQLite 主库及 WAL/SHM/Journal，并生成页级缺失清单。" => {
            "Recover resident SQLite databases and WAL, SHM, or journal files, with a manifest of missing pages."
        }
        "所有进程地址空间累计最多保留的反向 alias 数（最大 8000000）。" => {
            "Maximum reverse-mapping aliases retained across process address spaces, up to 8000000."
        }
        "所有进程地址空间累计最多检查的页表 entry 数（最大 67108864）。" => {
            "Maximum page table entries checked across process address spaces, up to 67108864."
        }
        "执行所有无需额外输入的只读插件，并将结构化结果汇总到 SQLite 数据库。" => {
            "Run read-only plugins that require no additional inputs and collect their structured results in SQLite."
        }
        "扫描 TCP/UDP 池分配并恢复网络端点。" => {
            "Scan TCP/UDP pool allocations and recover network endpoints."
        }
        "扫描 services.exe 的 VAD 并恢复结构有效的服务记录。" => {
            "Scan services.exe VADs and recover structurally valid service records."
        }
        "扫描下载命令、URL、远端 IP 和可疑载荷名称。" => {
            "Scan for download commands, URLs, remote IP addresses, and suspicious payload names."
        }
        "扫描已验证的 CM10 大页池并恢复活动及残留 Hive。" => {
            "Scan validated CM10 big-pool allocations for active and residual registry hives."
        }
        "扫描已验证的 Driv 池并恢复 DRIVER_OBJECT 结构。" => {
            "Scan validated Driv pool allocations and recover DRIVER_OBJECT structures."
        }
        "扫描已验证的 MmLd 池分配并查找脱链内核模块。" => {
            "Scan validated MmLd pool allocations for unlinked kernel modules."
        }
        "扫描已验证的 conhost _COMMAND_HISTORY 向量并恢复命令历史。" => {
            "Scan validated conhost _COMMAND_HISTORY vectors and recover command history."
        }
        "扫描已验证的执行体对象池并恢复 Mutant/Mutex 对象。" => {
            "Scan validated executive object pools and recover mutant or mutex objects."
        }
        "扫描已验证的执行体对象池并恢复符号链接对象。" => {
            "Scan validated executive object pools and recover symbolic links."
        }
        "扫描并解析驻留的 NTFS MFT FILE 记录。" => {
            "Scan and parse resident NTFS MFT FILE records."
        }
        "扫描并遍历各 GUI 会话中的 WindowStation 对象。" => {
            "Scan and traverse WindowStation objects in GUI sessions."
        }
        "扫描文件句柄，报告采集时持有 History 数据库的进程（不等同于访问行为人）。" => {
            "Scan file handles to identify processes holding History databases at acquisition time. A handle does not identify who visited a URL."
        }
        "扫描由 NPFS 结构链验证的命名管道，并关联活动进程句柄。" => {
            "Scan named pipes validated through NPFS structures and correlate active process handles."
        }
        "扫描结构有效的传统 MBR 分区扇区。" => {
            "Scan for structurally valid legacy MBR partition sectors."
        }
        "扫描账户创建、删除、改密、启停及本地组变更痕迹。" => {
            "Scan for account creation, deletion, password changes, enabling or disabling, and local group changes."
        }
        "扫描进程 VAD，严格解析并去重 Cobalt Strike Beacon 配置。" => {
            "Scan process VADs to validate and deduplicate Cobalt Strike Beacon configurations."
        }
        "扫描邮箱、URL、IPv4、Windows 路径、命令及用户指定的进程文本残留。" => {
            "Scan process text remnants for email addresses, URLs, IPv4 addresses, Windows paths, commands, and supplied strings."
        }
        "按 ContainerID 筛选。" => "Filter by ContainerID.",
        "按 MFT 属性 ID 精确选择要导出的 $DATA" => {
            "Select the exact $DATA attribute to export by MFT attribute ID."
        }
        "按 PID 将每个 VAD 区间导出为独立文件；缺页结果保留为 .partial。" => {
            "Export each VAD for a PID to a separate file. Ranges with missing pages use the .partial suffix."
        }
        "按 PID/PPID 重建 Linux 活动进程树，并标记孤儿父进程与父链循环。" => {
            "Rebuild the active Linux process tree by PID and PPID and flag orphaned parents and parent-chain cycles."
        }
        "按 VMA 将 Linux 进程驻留虚拟内存导出到目录；缺页结果保留为 .partial。" => {
            "Export resident Linux process virtual memory by VMA. Ranges with missing pages use the .partial suffix."
        }
        "按 Windows 会话 ID 对活动进程分组。" => {
            "Group active processes by Windows session ID."
        }
        "按 mount namespace 遍历 Linux 挂载树，支持 PID/task 或 namespace 筛选。" => {
            "Walk the Linux mount tree by mount namespace. Filter by PID and task or by namespace."
        }
        "按时间从新到旧输出；默认从旧到新。" => {
            "Sort newest first. The default is oldest first."
        }
        "按时间从旧到新输出；默认从新到旧。" => {
            "Sort oldest first. The default is newest first."
        }
        "按模块名或基址重验 Linux 内核模块并恢复为 ELF；缺页时保留 .partial 与 manifest。" => {
            "Revalidate a Linux kernel module by name or base address and recover it as ELF. Missing pages produce .partial output and a manifest."
        }
        "按用户名或 SID 筛选。" => "Filter by user name or SID.",
        "按程序名、路径或规范化程序标识筛选。" => {
            "Filter by program name, path, or normalized program identifier."
        }
        "按设备序列号筛选。" => "Filter by device serial number.",
        "按账户名或 SID 筛选用户 NTUSER.DAT。" => {
            "Select the user's NTUSER.DAT by account name or SID."
        }
        "搜索 PDB 中的公共和全局记录。" => "Search public and global PDB records.",
        "文本、浏览器、微信等插件最多反向映射的进程地址空间数量" => {
            "Maximum process address spaces to reverse-map for text, browser, and WeChat plugins."
        }
        "无需 Linux profile，交叉恢复 hostname、登录用户与内核版本。" => {
            "Cross-check host name, logged-in user, and kernel version without a Linux profile."
        }
        "显式指定 VMware VMSS/VMSN metadata；默认自动发现唯一同 stem sidecar。" => {
            "Explicit VMware VMSS/VMSN metadata file. By default, look for a single sidecar with the same stem."
        }
        "显式指定的页表根地址（DTB/CR3）" => {
            "Explicit page table root address (DTB/CR3)."
        }
        "显式的 Linux KASLR slide（十进制或 0x 十六进制）。" => {
            "Explicit Linux KASLR slide, in decimal or 0x hexadecimal."
        }
        "显示 Windows 崩溃转储头、错误检查信息和采集元数据。" => {
            "Show the Windows crash dump header, bug-check data, and acquisition metadata."
        }
        "显示包含具名 $DATA 备用数据流的 MFT 记录。" => {
            "Show MFT records containing named $DATA alternate data streams."
        }
        "显示启动地址、归属或调试状态异常的线程。" => {
            "Show threads with unusual start addresses, ownership, or debug state."
        }
        "显示启动地址不属于已加载模块的内核线程。" => {
            "Show kernel threads whose start addresses fall outside loaded modules."
        }
        "显示存在挂起或冻结证据的线程。" => {
            "Show threads with evidence of suspension or freezing."
        }
        "显示帮助信息" => "Show help.",
        "显示当前二进制、源码和公共契约的可复现构建身份。" => {
            "Show reproducible build identity for the binary, source, and public contracts."
        }
        "显示当前命令或指定子命令的帮助信息" => {
            "Show help for the current command or a specified subcommand."
        }
        "显示扫描发现但不在活动链表中的服务记录。" => {
            "Show service records found by scanning that are absent from the active list."
        }
        "显示版本信息" => "Show the version.",
        "显示英文帮助" => "Show help in English.",
        "显示采集镜像、物理区间和内核映射统计。" => {
            "Show capture, physical memory range, and kernel mapping statistics."
        }
        "最多保留并导出的时间线事件数" => {
            "Maximum timeline events to retain and export."
        }
        "最多保留的 ETHREAD 记录数。" => "Maximum ETHREAD records to retain.",
        "最多保留的 MFT FILE 记录数。" => "Maximum MFT FILE records to retain.",
        "最多保留的 Shimcache 记录数。" => "Maximum Shimcache records to retain.",
        "最多保留的 URL 摘要与逐次访问记录数量" => {
            "Maximum URL summaries and individual visit records to retain."
        }
        "最多保留的去重 Cookie 数量" => "Maximum unique cookies to retain.",
        "最多保留的去重下载痕迹数量" => "Maximum unique download traces to retain.",
        "最多保留的活动 ETHREAD 记录数。" => "Maximum active ETHREAD records to retain.",
        "最多保留的浏览器会话数量" => "Maximum browser sessions to retain.",
        "最多保留的结果数量" => "Maximum results to retain.",
        "最多分析的网络记录数量" => "Maximum network records to analyze.",
        "最多分析的进程数量" => "Maximum processes to analyze.",
        "最多反向映射的候选文本进程地址空间数量" => {
            "Maximum process address spaces to reverse-map for text candidates."
        }
        "最多反向映射的微信进程地址空间数量" => {
            "Maximum WeChat process address spaces to reverse-map."
        }
        "最多反向映射的浏览器相关进程地址空间数量" => {
            "Maximum browser-related process address spaces to reverse-map."
        }
        "最多尝试恢复的 PSReadLine 历史文件数量。" => {
            "Maximum PSReadLine history files to attempt to recover."
        }
        "最多尝试恢复的 Prefetch 文件数量。" => {
            "Maximum Prefetch files to attempt to recover."
        }
        "最多恢复和解析的 Chromium History 数据库数量" => {
            "Maximum Chromium History databases to recover and parse."
        }
        "最多恢复和解析的 Cookie 数据库及旧式 Cookie 文件数量" => {
            "Maximum cookie databases and legacy cookie files to recover and parse."
        }
        "最多枚举的 Hive 数量。" => "Maximum registry hives to enumerate.",
        "最多读取的本机微信数据库验证文件数量" => {
            "Maximum local WeChat database files to read for verification."
        }
        "本地 PDB 符号文件" => "Local PDB symbol file.",
        "本次导出允许写出的逻辑字节总量。" => {
            "Total logical bytes allowed for this export."
        }
        "本次文件内容读取预算（字节）。" => {
            "File content read budget for this run, in bytes."
        }
        "本次最多尝试导出的匹配取证文件数" => {
            "Maximum matching forensic files to attempt to export."
        }
        "枚举 SepLogonSessions，并按主令牌 AuthenticationId 关联活动进程。" => {
            "Enumerate SepLogonSessions and associate active processes by their primary token AuthenticationId."
        }
        "枚举内核回调数组、链表、注册表回调和池对象。" => {
            "Enumerate kernel callback arrays, lists, registry callbacks, and pool objects."
        }
        "枚举内核大页池跟踪表。" => "Enumerate the kernel big-pool tracking table.",
        "枚举各已验证 Desktop 对象中的 GUI 窗口。" => {
            "Enumerate GUI windows within validated Desktop objects."
        }
        "枚举已加载的内核模块和驱动。" => {
            "Enumerate loaded kernel modules and drivers."
        }
        "枚举已加载的注册表 Hive。" => "Enumerate loaded registry hives.",
        "枚举已验证 WindowStation 关联的 Desktop 对象。" => {
            "Enumerate Desktop objects associated with validated WindowStations."
        }
        "枚举或解析内核及进程模块中的 PE 导出符号。" => {
            "Enumerate or parse PE exports in kernel and process modules."
        }
        "枚举指定进程句柄，或按对象地址反查全部活动句柄所有者。" => {
            "List handles for a process or find all active owners of an object address."
        }
        "查找 VAD 声明保护与 PTE 有效保护不一致的私有已提交区间。" => {
            "Find private committed ranges where the VAD protection and effective PTE protection differ."
        }
        "查找、下载和检查 Microsoft PDB 符号。" => {
            "Find, download, and inspect Microsoft PDB symbols."
        }
        "查找私有或可写的可执行 VAD 并检查驻留字节。" => {
            "Find private or writable executable VADs and inspect resident bytes."
        }
        "根据内核、进程、令牌、时钟和网络证据生成系统取证概况。" => {
            "Build a system forensics overview from kernel, process, token, clock, and network evidence."
        }
        "检查主令牌结构、身份、登录会话、完整性级别和高风险已启用权限。" => {
            "Inspect primary token structure, identity, logon session, integrity level, and enabled high-risk privileges."
        }
        "检查各 DRIVER_OBJECT 的 IRP MajorFunction 目标地址。" => {
            "Inspect IRP MajorFunction target addresses for each DRIVER_OBJECT."
        }
        "检查镜像中的硬件调试寄存器和活动断点。" => {
            "Inspect hardware debug registers and active breakpoints in the image."
        }
        "检测 ETW API 返回/跳转补丁及跨进程实现异常。" => {
            "Detect ETW API return or jump patches and implementation discrepancies across processes."
        }
        "检测 ntdll/win32u 之外已验证的直接系统调用代码块。" => {
            "Detect validated direct syscall blocks outside ntdll and win32u."
        }
        "检测主映像替换以及节区与 PEB 不一致。" => {
            "Detect main image replacement and mismatches between the image section and the PEB."
        }
        "检测映像节区缺少正常文件证据的进程。" => {
            "Detect processes whose image section lacks expected file evidence."
        }
        "检测解析到 ntdll/win32u 系统调用指令的 RIP 相对间接跳转。" => {
            "Detect RIP-relative indirect jumps that resolve to syscall instructions in ntdll or win32u."
        }
        "检测镜像采集格式并显示物理布局。" => {
            "Detect the image container and show its physical memory layout."
        }
        "模块基本名称或完整路径，不区分大小写。" => {
            "Module base name or full path, matched case-insensitively."
        }
        "每个 Prefetch 最多输出和用于关联的引用文件数量。" => {
            "Maximum referenced files to report and use for correlation per Prefetch record."
        }
        "每个 Prefetch 最多输出的引用文件数量。" => {
            "Maximum referenced files to report per Prefetch record."
        }
        "每个去重数据包最多保留的物理证据地址数量" => {
            "Maximum physical evidence addresses retained per unique packet."
        }
        "每个扫描块的大小，单位为 MiB" => "Size of each scan block, in MiB.",
        "每个普通插件最多保留的结果数量" => {
            "Maximum results retained per ordinary plugin."
        }
        "每个池标签最多保留的结果数量" => "Maximum results retained per pool tag.",
        "每个规范化程序只保留最新 episode。" => {
            "Keep only the most recent episode per normalized program."
        }
        "每个进程参数区或环境区允许读取的最大字节数。" => {
            "Maximum bytes to read per process argument or environment range."
        }
        "每个进程最多保留的 VMA 数。" => "Maximum VMAs retained per process.",
        "每个进程最多检查的文件描述符数。" => {
            "Maximum file descriptors inspected per process."
        }
        "每个进程最多遍历的 VAD 数量。" => "Maximum VADs traversed per process.",
        "每个采集工具候选最多检查的句柄数量。" => {
            "Maximum handles inspected per acquisition tool candidate."
        }
        "每次注册表递归最多保留的记录数。" => {
            "Maximum records retained per recursive registry traversal."
        }
        "每种编码最多保留的物理命中数。" => {
            "Maximum physical hits retained per encoding."
        }
        "每类注册表执行来源最多保留的记录数。" => {
            "Maximum records retained per registry execution source."
        }
        "每类注册表时间线来源最多保留的记录数。" => {
            "Maximum records retained per registry timeline source."
        }
        "比对 EPROCESS 标识与 PEB 映像及命令行标识。" => {
            "Compare EPROCESS identity with the image and command line in the PEB."
        }
        "比对 PEB 的三条加载器链表与文件支持的 PE VAD。" => {
            "Compare the three PEB loader lists with file-backed PE VADs."
        }
        "汇总 Linux 活动进程状态与命令行；argv 不可用时明确退化为 comm。" => {
            "Summarize active Linux process status and command lines. Report comm as a fallback when argv is unavailable."
        }
        "汇总注册表 ASEP、自动启动服务/驱动，并可选关联 services.exe 与 TaskCache 候选。" => {
            "Summarize registry ASEPs, auto-start services, and drivers, with optional services.exe and TaskCache correlation."
        }
        "独立扫描并验证 Desktop 内存池对象。" => {
            "Scan and independently validate Desktop objects in memory pools."
        }
        "用于关联 PID 和进程的网络端点数量上限" => {
            "Maximum network endpoints used to correlate PIDs and processes."
        }
        "用候选密钥验证目录中的本机微信数据库；可多次指定" => {
            "Verify candidate keys against local WeChat databases in this directory. May be repeated."
        }
        "由独立证据证明的 Unix epoch 启动时间，单位纳秒。" => {
            "Boot time established by independent evidence, in Unix epoch nanoseconds."
        }
        "直接指定 mnt_namespace 地址。" => "Explicit mnt_namespace address.",
        "相对于所选 Hive 根的键路径" => "Key path relative to the selected hive root.",
        "相邻扫描块的重叠大小，单位为 KiB" => {
            "Overlap between adjacent scan blocks, in KiB."
        }
        "禁止任何远程访问。" => "Disable all remote access.",
        "禁用交互终端中的动态分析进度条" => {
            "Disable interactive analysis progress bars."
        }
        "符号来源：kernel 表示内核模块，processes 表示进程模块" => {
            "Symbol source: kernel for kernel modules, or processes for process modules."
        }
        "精确搜索任意文本；同时匹配 UTF-8 和 UTF-16LE，可多次指定" => {
            "Search for exact text in UTF-8 and UTF-16LE. May be specified more than once."
        }
        "结束 UTC 时间（含）；支持 RFC3339 或 YYYY-MM-DD。" => {
            "Inclusive UTC end time, in RFC3339 or YYYY-MM-DD format."
        }
        "聚合 Prefetch、BAM/DAM、UserAssist、Shimcache 与 Amcache 执行证据。" => {
            "Combine execution evidence from Prefetch, BAM/DAM, UserAssist, Shimcache, and Amcache."
        }
        "聚合 WPS 最近文件逐项时间与 Explorer RecentDocs MRU 顺序。" => {
            "Combine per-file WPS recent-file timestamps with Explorer RecentDocs MRU order."
        }
        "聚合 Windows Terminal、PowerShell、pwsh 和 cmd 的结构化控制台及 PSReadLine 历史。" => {
            "Combine structured console and PSReadLine history from Windows Terminal, PowerShell, pwsh, and cmd."
        }
        "聚合同一执行 episode 的最大时间差，单位毫秒。" => {
            "Maximum time gap within one execution episode, in milliseconds."
        }
        "聚合同一物理 USB 的总线、存储与辅助接口并解释连接时间。" => {
            "Group USB bus, storage, and auxiliary interfaces by physical device and interpret connection times."
        }
        "聚合容器、镜像时钟与采集工具进程，解释内存采集时间边界。" => {
            "Combine container metadata, image clock data, and acquisition-tool process evidence to establish capture time bounds."
        }
        "聚合浏览器进程、Cookie、下载、History 与 Login Data，重建可验证的浏览器会话证据。" => {
            "Combine browser processes, cookies, downloads, History, and Login Data to reconstruct verifiable session evidence."
        }
        "聚合驱动、设备、模块支持关系、IRP 与 Fast I/O 分发表。" => {
            "Combine drivers, devices, module backing, and IRP and Fast I/O dispatch tables."
        }
        "虚拟地址或对象地址" => "Virtual address or object address.",
        "虚拟基址" => "Virtual base address.",
        "要分析的内存镜像文件" => "Memory image file to analyze.",
        "要分析的应急响应模块。" => "Incident-response module to run.",
        "要搜索的 UTF-8 文本" => "UTF-8 text to search for.",
        "要搜索的十六进制字节" => "Hexadecimal bytes to search for.",
        "要搜索的符号文本" => "Symbol text to search for.",
        "要验证的 syscall table ABI。" => "Syscall table ABI to validate.",
        "解析 Window Station、格式数组、句柄和数据块，恢复活动剪切板内容。" => {
            "Recover active clipboard contents from window stations, format arrays, handles, and data blocks."
        }
        "解析原生及影子系统服务描述符表。" => {
            "Parse native and shadow system service descriptor tables."
        }
        "解析各进程主映像的导入地址表。" => {
            "Parse the import address table of each process's main image."
        }
        "解析旧式 log buffer 或新版 printk ring；无启动时间证据时仅输出 monotonic 时间。" => {
            "Parse the legacy log buffer or modern printk ring. Report monotonic time when no boot time is established."
        }
        "解析进程令牌中的用户、组、完整性级别和能力 SID。" => {
            "Parse user, group, integrity-level, and capability SIDs from process tokens."
        }
        "解析进程令牌权限及其状态位。" => {
            "Parse process token privileges and their state bits."
        }
        "解码 Linux 内核 core kallsyms 名称与地址。" => {
            "Decode Linux kernel core kallsyms names and addresses."
        }
        "计算注册表服务对应的确定性 NT SERVICE SID。" => {
            "Compute deterministic NT SERVICE SIDs for registry services."
        }
        "诊断、安装或显式获取与镜像完整 banner 匹配的 Linux ISF。" => {
            "Diagnose, install, or explicitly fetch a Linux ISF that matches the full banner in the image."
        }
        "读取并按需下载已加载内核模块 PE 的符号。" => {
            "Read symbols from a loaded kernel module's PE and optionally download its PDB."
        }
        "起始 UTC 时间（含）；支持 RFC3339 或 YYYY-MM-DD。" => {
            "Inclusive UTC start time, in RFC3339 or YYYY-MM-DD format."
        }
        "跨全部可读进程比对指定的 ntdll 系统调用桩。" => {
            "Compare the selected ntdll syscall stubs across all readable processes."
        }
        "跨全部活动进程最多检查的句柄表项数。" => {
            "Maximum handle table entries inspected across all active processes."
        }
        "跨全部进程最多检查的句柄表项数。" => {
            "Maximum handle table entries inspected across all processes."
        }
        "跨全部进程最多检查的句柄表项数量。" => {
            "Maximum handle table entries inspected across all processes."
        }
        "路径不区分大小写的子串筛选。" => {
            "Filter by a case-insensitive path substring."
        }
        "路径不区分大小写的子串；同时兼容 / 与反斜杠。" => {
            "Case-insensitive path substring. Accepts both forward slashes and backslashes."
        }
        "输入文件或目录" => "Input file or directory.",
        "输出 SQLite 数据库；已有数据库会追加新的分析批次。" => {
            "Output SQLite database. Appends a new analysis run if the database exists."
        }
        "输出 URL 聚合摘要，或 visits 表中的逐次访问事件。" => {
            "Output URL summaries or individual visit events from the visits table."
        }
        "输出便于程序处理的 JSON" => "Output machine-readable JSON.",
        "输出文件或目录" => "Output file or directory.",
        "输出的最低严重级别。" => "Minimum severity to report.",
        "输出驻留 Hive 中指定键、键值及可选的子项。" => {
            "Show a selected key, values, and optional subkeys from a resident registry hive."
        }
        "进程 ID" => "Process ID.",
        "递归输出全部子键" => "Recursively show all subkeys.",
        "通过 filescan 路径子串定位主数据库；与 --file-object 互斥。" => {
            "Locate the main database by a filescan path substring. Conflicts with --file-object."
        }
        "通过各进程 PEB 枚举用户态 DLL。" => {
            "Enumerate user-mode DLLs through each process's PEB."
        }
        "通过镜像中的页表转换 x64 虚拟地址。" => {
            "Translate an x64 virtual address using page tables in the image."
        }
        "遍历 Linux files_struct/fdtable 并解析打开文件路径。" => {
            "Walk Linux files_struct and fdtable structures and resolve open file paths."
        }
        "遍历 Linux 进程 VMA 链表或 Maple Tree，生成 /proc/PID/maps 等价证据。" => {
            "Walk Linux VMA lists or the Maple Tree to report evidence equivalent to /proc/PID/maps."
        }
        "遍历 Windows PsActiveProcessHead 或 Linux task_struct.tasks 活动进程链表。" => {
            "Walk the active process list using Windows PsActiveProcessHead or Linux task_struct.tasks."
        }
        "遍历以已恢复驱动为根的 DEVICE_OBJECT 链。" => {
            "Walk DEVICE_OBJECT chains rooted at recovered drivers."
        }
        "遍历内核页表并输出合并后的虚拟地址映射。" => {
            "Walk kernel page tables and report merged virtual address mappings."
        }
        "遍历各处理器定时器表并将 DPC 例程解析到模块。" => {
            "Walk per-processor timer tables and resolve DPC routines to modules."
        }
        "遍历指定进程页表并输出合并后的用户空间映射。" => {
            "Walk the selected process's page tables and report merged user-space mappings."
        }
        "遍历进程 VAD 树。" => "Walk the process VAD tree.",
        "附加触发器尚未结构化解码的 TaskCache 持久化候选。" => {
            "Include TaskCache persistence candidates whose triggers could not be decoded structurally."
        }
        "需要保留并验证的符号功能集合；可重复或用逗号分隔。" => {
            "Symbol features to retain and validate. Repeat the option or separate features with commas."
        }
        "验证 Linux syscall table handler 是否落在已证明的 kernel/module 可执行范围。" => {
            "Check whether Linux syscall handlers fall within validated kernel or module executable ranges."
        }
        "验证 lsass cryptdll RC4-HMAC 处理表中的 Skeleton Key 挂钩。" => {
            "Check the LSASS cryptdll RC4-HMAC handler table for a Skeleton Key hook."
        }
        "高速内存取证引擎" => "Fast memory forensics engine.",
        "默认在一次物理扫描中同时搜索 UTF-8/ASCII 和 UTF-16LE。" => {
            "Scan physical memory once for both UTF-8/ASCII and UTF-16LE by default."
        }
        _ => text,
    }
}
