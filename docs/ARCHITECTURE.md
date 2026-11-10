# 架构与性能原则

## 分层

1. `image`：负责容器识别、多 source 只读 backing，以及“物理地址 -> source location”的稀疏区段映射。Direct 映射保留 mmap 快路径，EWF 使用线程安全的按块读取器。
2. `address`：基于物理读取实现 x86-64 页表遍历，不知道底层是 raw、LiME 还是 crash dump。
3. `symbols` / `profile`：从 RSDS 获取精确 PDB 身份，下载、缓存并提取符号及类型字段。
4. `windows`：只消费虚拟地址读取器与类型配置，实现进程等取证对象。
5. `linux` / `linux_kernel_plugins` / `linux_info` / `linux_files` / `linux_pagecache` / `linux_process`：独立组合 Linux 物理镜像、功能感知 ISF、live VMCOREINFO、strict-present 四级页表、任务链、内核全局对象、VFS、页缓存和进程地址空间。`LinuxKernelSession` 只验证 DTB、KASLR、`_stext`、运行时 banner 和指定符号 feature，不读 `init_task.tasks`；因此模块、mount、kallsyms、kmsg 和 hook 检查不会被无关的任务链损坏一并禁用。
6. `scan`：对有效物理区段分块并行，忽略容器头和 acquisition gap。
7. `session`：组合只读镜像、`KernelProfile` 与 `WindowsKernelContext`，为嵌入式调用和批量插件执行复用一次初始化结果；不包含 UI 或 Tauri 依赖。
8. `registry` / `system::registry`：把内存中重建的 Hive 转换为键值、系统配置与比赛高频注册表证据。
9. `eventlog`：对恢复后的 EVTX 做离线记录解析、字段归一化、取证分类和时间线导出，不依赖 Windows Event Log 服务。
10. `command_registry`：把 `metadata/leaf-command-manifest.json` 与其他内存取证工具的命令等价表按稳定 ID 严格连接，统一声明叶子命令的 CLI、I/O、Evidence 与 collect 契约；任一侧缺项、别名冲突或 unknown 元数据都会使内置注册表加载失败。

这种边界让新增格式或插件时不必改动其他层，也避免把特定 Windows 版本的结构偏移写死在代码中。

## 多 source 物理映射

`MemoryImage` 的基本单元是物理 span，而不是“单文件 + 线性偏移”。每个 span 绑定
source index 和一种编码：

- `Direct`：source 中的连续字节，可返回精确 `exact_byte_offset` 并复用 mmap 快路径；
- `SnappyFrame`：以有界缓存按需解码，source location 保留容器偏移和解码后偏移，
  但不伪造精确文件偏移；
- `RepeatedByte`：由容器语义证明的重复页，不存在对应的连续源字节。

扫描器始终按 physical address 读取，不再把 file offset 当成物理地址。
`physical_to_file_offset` 只对 Direct 映射返回值；通用溯源使用 `source_location`，存在性检查使用
`contains_physical`。primary/metadata/sidecar、缺失区间和 MMIO 排除区间一同进入 source identity。

容器实现边界如下：

- VMware VMEM 可与 VMSS/VMSN 多 source 组合；`--metadata` 优先，否则只自动发现唯一同 stem
  sidecar，同时出现 VMSS/VMSN 时必须由用户消歧；
- x86-64 little-endian ELF physical core 只消费物理 `PT_LOAD`，`p_memsz` 尾部进入
  missing ranges；只有精确 QEMU note 才记为 QEMU，不把其他 ELF 猜成 QEMU/VirtualBox；
- Xen ELF64 要求 `.xen_pages` 与且仅一个 `.xen_pfn/.xen_p2m`；
- AVML v2 使用 Snappy framed，解码时校验 CRC32C，并使用有界 lazy cache；
- QEVM v3 只支持 RAM section v4 的 raw page 和 repeated-byte，明确拒绝 XBZRLE、mapped-ram
  和未知版本。migration RAMBlock offset 不是 guest physical address，因此必须显式给出
  RAMBlock、低端 RAM 长度和高端物理基址。

当前本地 corpus 盘点只证明 `test.vmem` 这份无 VMSS/VMSN sidecar 的平面 VMware VMEM
能够完成真实回归；它不能替代 metadata 组合验证。VMSS/VMSN metadata、ELF/QEMU、Xen、
AVML 和 QEVM 的解析入口均已有合成边界测试，但没有真实正样本。在每一种格式/组合至少加入
一份真实正样本，并用固定版本的其他内存取证工具对比 physical spans、mapped bytes、关键扫描命中和
`pslist` 集合前，不属于正式支持范围。

Windows 插件默认调用统一的 symbol resolver：从 PE Debug Directory 读取 CodeView 身份，依次查询显式共享符号根、`STARMEM_SYMBOL_PATH` 与可写缓存中的精确 GUID+age 路径，未命中时调用微软符号服务器，并在使用前重新解析 PDB 头校验 GUID 与 age。符号根采用微软符号服务器的 `PDB名/GUID+Age/PDB名` 布局，可直接复用现有目录而无需复制；共享根保持只读，缺失符号只写入 StarMem 缓存。命令行的 `--pdb` 和 `--profile` 只是离线覆盖入口。若目标 PDB 端点确实不存在，可载入本机同系列内核 PDB作为类型布局后备；CR3、内核基址、活动进程头、模块头和 hive 头仍必须从目标镜像独立推导，绝不使用本机 PDB 的全局 RVA 作为未经验证的目标地址。

raw/vmem 的 Windows 引导按证据强度组合三条路径：先检查低物理内存的 Long Mode 启动块；再从物理内存中的 `System\0` 反推 EPROCESS，验证候选 PML4，沿活动进程链识别 `PsActiveProcessHead`；最后尝试明文 KDBG。内核基址与 `PsLoadedModuleList` 可由目标 PE/导出表确认。若采集器清零了进程 KPROCESS CR3，则以 PEB 页为证据并行筛选物理 PML4。候选只有在活动进程链和模块链的目标页实际存在时才会被接受。

Linux 符号解析器支持 dwarf2json 生成的 ISF `5.x/6.x` 格式，支持共享根中的 `.json` 与 `.json.xz`，也接受单文件路径。显式 `--symbol-path`、`STARMEM_SYMBOL_PATH`、兼容的符号环境变量及当前目录下的符号根依次作为只读候选；若给出兼容的 `symbols` 根，只遍历其 `linux` 子树。本地 ISF 和内置完整构建布局均未命中时，解析器才以内置的远程 ISF banner 索引作为最后一级符号源；索引限制为 16 MiB/100,000 条，单个远程 ISF 限制为 256 MiB/16 个同 banner 候选，并使用短连接/总请求超时、HTTPS、默认仓库域与路径约束、临时文件复验和原子缓存。索引缓存 24 小时，刷新失败时可明确标记后使用旧缓存；`STARMEM_LINUX_ISF_URL` 可覆盖兼容索引，`STARMEM_LINUX_ISF_OFFLINE=1` 禁止联网。选择以 ISF `linux_banner.constant_data` 与镜像完整 banner 的字节级相等为第一身份条件，不信任文件名或 release-only 匹配；同 banner 的多份表若 vmlinux SHA-256、关键符号或保留结构布局冲突则拒绝消歧。下载内容在写入 `symbols/linux/remote` 前重新解析并复验完整 banner，选中后还用同一 slide 联合验证 ISF `init_task` 和运行时 `linux_banner`，再进入结构遍历。报告保留下载/缓存诊断、ISF 路径、压缩文件 SHA-256、banner SHA-256、vmlinux SHA-256、格式和生成器版本。

Linux `pslist` 对 Linux 与 Windows 页表语义保持隔离。LiME 直接进入 Linux 路径；RAW/VMEM/physical EWF 必须同时命中有效完整 banner 与 `swapper` 任务锚点，不依赖扩展名。会话扫描 banner、BTF、`swapper` 和 NUL 结尾的 live VMCOREINFO；内存 BTF 优先解析 `task_struct`，其次使用精确匹配且现场验证的 Linux ISF，再使用完整构建 banner 绑定的内置最小布局，最后才尝试由现场任务环推断 `pslist` 基础字段。VMCOREINFO 的 `init_top_pgt/phys_base` 推导物理 DTB，并明确拒绝 LA57 或 SME；缺失时才扫描 PML4 候选。Linux walker 只接受 present PTE，不会把 Windows transition 位当成驻留页。最终还必须证明 `init_task` 虚实映射、PID/TGID 为零、父指针自指，以及任务环首尾与每个 `next/prev` 反向链接一致；中途缺页、坏指针、非头部环或结果上限均保留部分记录并返回 `complete=false`。`linux.kaslr` 只接受 live VMCOREINFO `SYMBOL(_stext)`，或精确 ISF `_stext` 加已验证的 `init_task` slide；页表翻译后还必须证明首 16 字节的虚拟/物理读取一致且非全零。

Linux LiME `filescan` 在输出任何 dentry 前先验证全局 `super_blocks` 链表的完整双向拓扑和头闭环，结果上限不能绕过 profile 锚验证。每个 superblock 再以 `s_root` 为根遍历 positive dentry：4.13/5.4 使用 `d_subdirs/d_child` 双向 list，6.8 使用 `d_children/d_sib` hlist；每条记录必须交叉满足 `dentry.d_sb`、`inode.i_sb`、合法 inode mode 和安全 qstr。链表入边完整时，采集涂抹造成的 `d_parent` 不一致会保留真实 dentry/inode 但令路径未解析；入边已经降级时则必须由 `d_parent==expected` 作为替代成员证明。坏 backlink 后只沿当前驻留节点保存的 forward `next` 容错续走，不根据可疑 `prev` 或邻近字节猜节点，并对连续未通过语义锚的候选设停止预算。所有此类恢复均返回 `complete=false`，同时保留虚拟/物理锚与分项告警计数。

Linux 文件路径只在单个 superblock 内拼接并标为 `superblock_relative`。插件不把不同 mount namespace 合并成虚构的主机全局路径，也不把 negative dentry 或“磁盘上存在但采集时未驻留”的目录项包装成结果。因此这是内存 VFS 文件元数据枚举，不是磁盘目录清单。

Linux `dumpfile` 从已验证 dentry/inode 进入 4.13 的 radix tree 或 5.4/6.8 的 xarray，
只把 present page/folio 计为恢复证据。缺页按逻辑文件偏移合并记录并以零占位保持布局，
但输出只发布为 `.partial`；完整结果和部分结果都带 SHA-256、extent、缺失范围和遍历
完整性。`linux.passwd` 在同一证据链上只选择 `/etc/passwd` 候选，并且部分文件只解析
不与缺失范围相交的完整行。

Linux 进程插件先从 `task_struct.mm -> pgd` 建立进程自己的 strict-present 页表，再读取
argv/env、fdtable 和 VMA。4.13/5.4 校验 VMA 双向链，6.8 校验 Maple Tree 节点类型、
父引用和 `map_count`；记录按用户虚拟地址排序后才检查重叠。`linux.proc.dump` 每个 VMA
独立发布 `.dmp` 或 `.dmp.partial`，`linux.bash` 只接受由时间戳指针、命令指针和历史数组
回指共同证明的活动 `HIST_ENTRY`，不会把普通堆字符串当成历史命令。

VAD 标志的 `VadType`、`Protection` 与 `PrivateMemory` 位位置取自 PDB `_MMVAD_FLAGS`，文件路径先检查 `_MMVAD.FileObject`，再沿 `_MMVAD.Subsection -> _SUBSECTION.ControlArea -> _CONTROL_AREA.FilePointer` 解码 `_EX_FAST_REF`。这使插件能适应 Windows 构建间的 bitfield 与对象关系变化。

GUI 插件对 `Wind`/`Desk` 标签只做一次并行物理扫描，严格验证 pool header、分配尺寸、pool index/type 和对象头，再对候选物理页执行一次共享内核反向映射。对象随后在对应 session 的代表进程页表中解码；WindowStation 名称、session id、Desktop 父链、双向线程链、tagPROCESSINFO→EPROCESS、Desktop→Window 树和窗口自指针相互交叉验证。来自公开 GUI 类型语料的不同 x64 布局仅作为候选，选择完全由现场关系评分完成，不读取 Windows build 号。缺失页和“驻留但结构无效”的链接分别报告，不能互相冒充。

Callback 插件把 `IoFs/IoSh/Cbrb/DbCb/Pnp9/PnpD/PnpC` 七个标签交给一次多模式物理扫描，并对候选页做一次共享内核反向映射。pool header、分配尺寸、pool index/type 是第一层；`LIST_ENTRY` 邻接关系、`DEVICE_OBJECT -> DRIVER_OBJECT`、驱动映像、IRP_MJ_SHUTDOWN、事件类别和 callback routine 模块归属是第二层。`callbacks-x64` 私有结构只提供布局候选，选择依赖现场关系评分，不按 build 号分支。注册表回调的 `CallbackListHead/CmpCallBackCount` 可来自精确 PDB 的模块私有符号流；`_CM_CALLBACK_ENTRY` 的 Function/Altitude 也在多个候选布局间现场竞争。无法归属已加载模块的 routine 不会被删除，而是保留并标记 `suspicious_unbacked`；验证路径上的缺页进入 `missing_pages/missing_bytes` 并令 `complete=false`。

Windows 文件扫描分为四级证据过滤：一次并行扫描同时定位 `File` 与受保护池 `Fil\xe5` 标签；从 pool block 内自适应寻找 `_FILE_OBJECT.Type/Size`；把所有候选物理页一次性反查到内核虚拟地址；最后用可用的 `ObHeaderCookie + ObTypeIndexTable` 解码对象类型并读取 Unicode 文件名。批量反查只遍历一次内核页表，跳过递归 PML4 槽，同时支持 4KB、2MB、1GB 映射。无法通过 cookie 的残留对象不会伪装成已验证对象，而是由 `object_type_verified=false` 明示。

Windows `dumpfile` 保持三种来源语义分离：Cache Manager 路径遍历 `_SHARED_CACHE_MAP` 的初始 VACB 与多级 VACB 数组（VACB 按实际 8 字节对齐保留地址位）；Data/Image 路径遍历 `_CONTROL_AREA -> _SEGMENT -> PrototypePte`，读取 valid/transition 驻留页，并拒绝把 PFN 0 当成有效文件证据。自动模式依次尝试 Cache、Image、Data。Windows 与 Linux 报告都保留逻辑大小、实际输出大小、恢复字节数、缺失字节数和内存 extent；缺页不会被静默算作恢复成功。

注册表主 Hive 走独立于 FILE_OBJECT 的直接恢复路径。加载链提供 CMHIVE，精确 PDB 提供 `_HHIVE.Storage[0] -> _DUAL.Map -> _HMAP_DIRECTORY/_HMAP_TABLE/_HMAP_ENTRY` 布局；base block 从内核地址空间读取，stable bin 在旧版系统可由内核 DTB 读取，在现代 Windows 则用 `Registry` 进程 DTB 翻译 `PermanentBinAddress + BlockOffset`。只导出 stable store，不把 volatile store 拼入磁盘 Hive。每页保持原文件偏移，缺页以 `missing_bytes` 和 `complete=false` 报告。批量导出对 Hive/EVTX/EVT 检查稳定文件签名，签名失败的 FILE_OBJECT 缓存片段不会计作成功恢复。

离线 Hive 语义层解析 `nk`、`li/lf/lh/ri`、`vk`、内联数据与 `db` 大数据分段，支持字符串、多字符串、DWORD、QWORD 和二进制值。它从 SYSTEM/SOFTWARE/SAM/NTUSER 提取 ControlSet、主机/版本/时区、关机时间、用户 Profile、TCP/IP、历史网络、服务、Run/RunOnce、TaskCache、USB/USBSTOR、MountedDevices、BAM/DAM 与本地账户。内存镜像的空洞可能只破坏 RI 索引的一条分支，因此子键遍历会保留可验证分支，同时把缺失 cell、声明数量与恢复数量写入告警，而不是整棵树失败。

EVTX 语义层使用安全的二进制 XML 解析器逐 chunk 读取恢复文件。每条记录规范化 System 元数据和命名 EventData/UserData；随后按 provider、channel 与 Event ID 识别开关机、登录、RDP、进程、服务、计划任务、账户、清日志、PowerShell、Defender、Sysmon、WMI、设备和网络证据。部分日志中的零填充缺页只产生 record/chunk 错误，其他记录继续进入按 UTC 时间排序的 JSON/CSV。默认只保留高价值事件以减少噪声，`--all-events` 才保留全部可解析记录。

网络插件先验证 pool header、标签与分配大小，再按经典或 Windows 11 26100 紧凑布局取证。owner 可直接或经一级对象引用匹配 EPROCESS；owner 无法证明时仍保留端点并显式标为 unknown。私有包装结构未被公开符号描述的字段保持 unspecified，不用启发式字节冒充 IP 地址。

数据包恢复组合两条互补路径。结构路径从捕获的 `ndis.sys` PE 取得精确 CodeView 身份，读取驱动 PDB 的 `_NDIS_GLOBAL_TRIAGE_BLOCK`、`_NET_BUFFER_LIST`、`_NET_BUFFER` 与 `_MDL`；PDB 只导出 MSVC 装饰数据名时会先验证其 `@@3` 全局变量编码，再映射到规范名。现场 triage block 提供 pool、分配头与 NBL 关系，双向链表验证后按 `NBL -> NB -> MDL -> PFN` 恢复跨物理页字节，并交叉检查 NBL 大小和 `SourceHandle` 偏移。旧 PDB 缺少 triage 类型时才使用经签名、大小和 PDB NBL 字段共同验证的稳定 triage 前缀。

物理路径继续使用 SIMD 协议字节定位、分块重叠和 Rayon 并行扫描，只接受 IP 边界、长度、端口、TCP 控制字段与选项边界、UDP 长度和校验和均成立的完整 IPv4/IPv6 TCP、UDP 字节。NDIS 结构已经完整证明的包可以保留硬件卸载尚未完成的非零校验和，单纯物理候选仍执行严格校验。两条路径按包字节与 SHA-256 合并；同一物理地址的双路径互证不会虚增出现次数。PCAPNG 使用 `LINKTYPE_RAW`，剥离已证明的 Ethernet/VLAN/QinQ 头但不构造新头，不根据连接状态伪造数据包，也不填造逐包时间戳。

链表插件采用取证容错语义：初始化或符号错误仍会失败；采集时并发修改造成的中途环、坏指针或不可读节点则保留已经验证的记录，通过结构化 `stop_reason` 和 `warnings` 报告。`LIST_ENTRY.Blink` 会与前一节点交叉检查，防止悄悄接受损坏链。

## 热路径

- Direct source 以只读内存映射打开，启动时间不会随镜像容量线性增长；编码 span 只在物理读取命中时按需解码。
- EWF 后端保持同一物理读取接口，扫描线程各自读取逻辑块；磁盘/卷 EWF 不建立物理 span。
- 扫描器以 64MiB 为默认工作块，Rayon 只分发轻量描述符；数据页由操作系统按需调入。
- Windows dump 优先从 KDBG（模块链为后备）取得内核基址，通过虚拟地址读取 PE Debug Directory；寻找内核 PDB 不必先扫完整镜像。
- 每块增加 `pattern_len - 1` 字节重叠，并只接受核心区起始的命中，既无漏报也无重复。
- 精确字节匹配使用 `memchr::memmem` 的平台优化实现。
- 多个四字节池标签共用一个 Aho-Corasick 自动机，每个物理区段只扫描一次；自动机在 Rayon 工作块间只读共享。
- `windows.process-string` 的 Evidence scope 是活动进程链所证明的用户地址中，已采集的 resident/transition 且物理连续的字面命中子集；它明确排除内核地址、已退出/隐藏进程、prototype/换出/压缩页，以及虚拟连续但 PFN 不连续的跨页匹配。它把 UTF-8/ASCII 与 UTF-16LE 放入同一次物理扫描，再以命中页集合按唯一 DTB 批量反向遍历用户页表；候选归属必须通过对应进程 VA 重读原字节。共享 DTB 只复用遍历，多个 VA alias 与 owner 仍分别留证。`complete=true` 只对这个受限 scope 成立；活动链不完整、DTB 缺失、页表读取失败、source missing range 或 scan/output/process/mapping/traversal 任一 limit 实际触顶都会保留正向证据但令 `complete=false`；归属分类未覆盖所有已保留命中时，`unmapped_physical_hits` 保持未知。
- Windows `filescan` 先把所有物理候选页组成集合，再批量遍历共享内核页表；不会为每个 FILE_OBJECT 重走四级页表。Linux `filescan` 复用已经发现的严格页表根，不进行全镜像对象池扫描。
- 页表读取不构造中间页对象，支持大页并保持跨页虚拟读取正确。

性能结论必须按同一镜像、冷/热缓存和同一插件语义做可重复基准，不能仅凭语言或单次时间声称。当前扫描会输出实际耗时和 GiB/s，便于持续检查性能回归。

## 下一阶段

- Windows：浏览器/执行痕迹、更多令牌异常与恶意代码检测插件。
- raw/vmem：更多 VMware metadata 版本、encoded KDBG 与自引用 PML4 的独立后备发现。
- 网络：按 tcpip 模块版本缓存经过验证的私有结构布局，并补全现代 TCP 远端地址。
- Linux：现有 module kallsyms 与有界 semantic scan 继续扩充真实内核回归；LA57/ARM64、ftrace/BPF、netfilter/IDT 深度检查，以及孤立 socket 与已退出进程恢复仍待实现。
- 扫描：在已有多模式 Aho-Corasick 基础上补掩码模式、YARA 兼容层以及 NUMA/顺序 I/O 调度。
- 容器：为 Xen/AVML/QEVM 补真实 corpus 与其他内存取证工具的横评，再扩展 EWF 多段证据集与更多 acquisition metadata。
- 性能：页表项缓存、批量虚拟预取、插件列式输出和可取消任务。
