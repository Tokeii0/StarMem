# Linux 原生应急响应

StarMem 在经过运行时核对的 Linux 会话中提供进程、网络、文件、内核与应急响应分析。以下入口在进程内调用 Rust 实现，可独立于其他内存取证工具运行。支持范围以报告中的 `scope`、`available`、`complete`、`warnings` 和缺页范围为准；不能将命令正常返回解释为所有来源完整。

## 入口

`linux.ir` 使用活动任务会话，包含 32 个模块：

| 范围 | `--module` |
|---|---|
| 进程与交叉核对 | `pslist`、`threads`、`kthreads`、`psscan`、`psxview` |
| 凭据、调试与性能事件 | `capabilities`、`credentials`、`check-creds`、`ptrace`、`perf-events` |
| 用户映像与线程栈 | `elfs`、`library-list`、`malfind`、`callstack` |
| 文件与应急响应 | `files`、`file-content`、`persistence`、`logs`、`timeline` |
| 规则与统计 | `triage`、`indicators`、`av-edr`、`entropy` |
| 日志与恢复 | `dns`、`journald`、`crash-summary`、`crash-traces`、`crash-events`、`pagecache-recovery` |
| 时间线补充 | `timeline-network`、`timeline-findings`、`timeline-summary` |

`linux.ir-kernel` 使用内核会话，包含 22 个模块：

| 范围 | `--module` |
|---|---|
| 系统 | `system`、`boottime`、`iomem`、`pidhashtable` |
| 网络 | `ip-addr`、`ip-link`、`arp`、`netfilter`、`check-afinfo` |
| 回调与跟踪 | `check-idt`、`keyboard-notifiers`、`tty-check`、`ebpf`、`kprobes`、`ftrace`、`tracepoints` |
| 显示设备 | `fbdev` |
| 系统补充 | `uptime`、`meminfo`、`cpuinfo`、`btf`、`routes` |

原有 `linux.psaux`、`linux.pstree`、`linux.lsof`、`linux.cmdline`、`linux.envars`、`linux.proc.maps`、`linux.proc.dump`、`linux.sockstat`、`linux.bash`、`linux.passwd`、模块、挂载、日志和 syscall 等入口继续使用。

示例（按 shell 调整路径）：

```text
starmem linux.ir image.lime --module capabilities --pid 1234
starmem linux.ir image.lime --module psscan --limit 65536
starmem linux.ir image.lime --module file-content --path /etc/crontab
starmem linux.ir-kernel image.lime --module netfilter
starmem linux.ir-kernel image.lime --module meminfo
starmem linux.ir-kernel image.lime --module btf --limit 262144 --max-bytes 33554432
starmem linux.ir-kernel image.lime --module fbdev --framebuffer-output case/frames --max-bytes 33554432
```

文件路径为各 superblock 内的路径。相同路径可能对应多个文件系统或对象，必须同时保留 `superblock`、`dentry` 和 `inode`，不能仅凭文件名选择恢复对象。BMP 输出默认关闭；指定目录后只写完整可读的 packed-pixel truecolor 16/24/32 位帧缓冲，不覆盖输入或已有文件。缺页会阻止图片发布。

## 可靠性与限制

- `dns` 展示常见解析器配置路径的驻留内容（包括独立 `/run` 挂载的相对路径），提取已核对完整行中的 nameserver/search/domain/options，不解析 DNS 查询历史。符号链接元数据不能代替目标内容。`cpuinfo` 读取启动 CPU 的精确 ISF 字段。`uptime` 是 timekeeper 最后一次更新值，未补算硬件时钟增量；序列正在更新或无法核对会标记不完整。
- `meminfo` 读取 RAM、空闲页、匿名/文件活动页、脏页、回写、共享内存、Slab、内核栈、页表、CMA 和交换区全局计数。`zone_stat_item` / `node_stat_item` 的精确枚举与数组声明共同限定字段，支持统计项在新旧内核间迁移；保留原始计数、虚拟地址、偏移及单位。Slab 全局 `_B` 项内部仍以页计数；内核栈以 KiB 计数，不能统一乘页大小。负 VM 统计值保留原值，按 SMP 全局 page-state 规则归零并告警。
- `Buffers` 汇总经过回链及 superblock 归属核对的块设备 inode 映射；旧内核 `SwapCached` 汇总 `swapper_spaces`，指针数组声明长度为 0 时仅使用同为 `MAX_SWAPFILES` 声明的 `nr_swapper_spaces` 精确长度，非零长度冲突则拒绝。新内核使用 `NR_SWAPCACHE`。参与汇总的对象单独输出 `memory_input` 记录；链不完整、缺页、超过 4096 个映射或总读取预算时，相关总量和依赖它的 `Cached` 均不可用，已读对象保留。`Cached` 按文件页扣除交换缓存和块设备缓存后归零下限，不能直接把 `NR_FILE_PAGES` 标成 Cached。
- `MemAvailable` 按内核 `si_mem_available` 公式给出 `estimated` 结果。完整读取 `node_states[N_ONLINE]` 位图，按精确 `node_data` 指针类型和非零数组长度或 `nr_node_ids` 边界定位节点，并核对节点编号；单节点布局另支持 `contig_page_data`。遍历每个在线节点的完整 `node_zones` 数组，不以 `nr_zones` 截短，也不只保留 populated zones；从精确 `WMARK_LOW` 索引读取旧 `watermark` 或新 `_watermark + watermark_boost`。保留节点位图、槽位、区域、水位和总保留页作为输入记录。支持最多 4096 节点、每节点 64 区域；缺页、边界/编号冲突或依赖指标不可用时不生成前缀估算。估算按基础页做整数除法，在加入可回收页后才对最终有符号结果归零，不代表保证可分配量或 cgroup 限额。参考 [Linux 6.8 公式](https://github.com/torvalds/linux/blob/v6.8/mm/show_mem.c)、[旧内核公式](https://github.com/torvalds/linux/blob/v4.13/mm/page_alloc.c)、[区域遍历与水位规则](https://github.com/torvalds/linux/blob/v6.8/include/linux/mmzone.h)。
- `CommitLimit` 按当前 `sysctl_overcommit_kbytes` 或 RAM 比例分支计算，显式 KiB 额度先向下取整到基础页，再加 `total_swap_pages`。比例分支扣除全部已登记 `hstates` 的 HugeTLB 基础页；`Hugetlb` 独立给出这部分总量，保留每种页大小的地址、阶数和数量。`hugetlb_max_hstate` 必须落在精确数组声明内，最多 64 项；缺失类型/计数不能推定 HugeTLB 为零。显式额度分支不依赖比例或 HugeTLB 可读性。策略编号、比例与显式额度另列 `memory_commit_policy`；额度只在策略 2 参与限制，没有扣除用户/管理员保留及应用限制，不保证单次分配成功，也不是物理内存占用。依据：[vm_commit_limit](https://github.com/torvalds/linux/blob/v6.8/mm/util.c)、[HugeTLB 汇总](https://github.com/torvalds/linux/blob/v5.4/mm/hugetlb.c)、[过量承诺策略](https://www.kernel.org/doc/html/v6.8/mm/overcommit-accounting.html)。
- 提交内存同时给出 `Committed_ASGlobal` 和 `Committed_ASReconstructed`，分别表示 `vm_committed_as.count` 全局基数与合并每 CPU 分量的重建值。原始基数为零不能推出没有承诺内存。重建保留有符号 s64 基数和每 CPU s32 差值，最后才将负的合计归零。按完整 possible/online 位图和 ISF 中存在的 dying 位图去重选取 CPU，再通过 `__per_cpu_offset` 重定位动态 per-CPU 指针；保留指针、偏移槽、最终地址及 CPU 归属。编号必须满足 `nr_cpu_ids`、位图及数组声明的共同边界，最多 8192 个 CPU；地址必须规范、对齐且互不重复。确认为仅含 8 字节 count 的单处理器布局时可直接读取；不以缺少 counters 一项猜测单处理器。
- 提交内存的汇总范围始终明确展示，不按版本号猜测 procfs 实现：[5.4 meminfo](https://github.com/torvalds/linux/blob/v5.4/fs/proc/meminfo.c) 仅读取基数，[5.15 计数器](https://github.com/torvalds/linux/blob/v5.15/lib/percpu_counter.c) 汇总 online，[6.8 计数器](https://github.com/torvalds/linux/blob/v6.8/lib/percpu_counter.c) 还包含 dying。`Committed_ASReconstructed` 不冒充原始 `/proc/meminfo` 的显示值；没有 dying 符号时不覆盖离线过渡 CPU。采集期间的计数折叠、热插拔及跨字段更新仍可能影响一致性。
- `VmallocUsed` 从精确类型的 `nr_vmalloc_pages` 读取后备页用量，`Percpu` 按 `pcpu_nr_populated * pcpu_nr_units` 计算每 CPU 分配器后备页总量，不含分配器元数据。unit 数可能包含布局填充，不能用在线 CPU 数替换。缺少计数器的旧内核明确不可用，不按 procfs 占位值补零。存在 `num_poisoned_pages` 时另读 `HardwareCorrupted`，只表示内核标记的损坏页计数。依据：[Vmalloc 计数](https://github.com/torvalds/linux/blob/v5.4/mm/vmalloc.c)、[每 CPU 分配器](https://github.com/torvalds/linux/blob/v6.8/mm/percpu.c)。
- 默认 HugeTLB 页大小通过 `default_hstate_idx`、已登记数量和 `hstates` 精确数组共同核对。`Hugepagesize` 使用 KiB；`HugePages_Total/Free/Rsvd/Surp` 使用独立的 `value_count` / `unit:huge_pages`，KiB 和字节字段为空，不能把页个数与内存大小相加。每个计数独立读取，保留默认索引、对象地址、页阶数及字段地址；单个缺页不抹掉其他计数。依据：[HugeTLB meminfo](https://github.com/torvalds/linux/blob/v6.8/mm/hugetlb.c)。
- VM page-state 的静态全局计数仍未合并每 CPU 待刷新差值；`SwapTotalGlobal` / `SwapFreeGlobal` 未加入 swapoff 过程中 `si_swapinfo` 的待移除页调整。procfs 承诺量显示口径、Vmalloc 虚拟地址总范围/最大空闲区间和 THP 单位差异尚未重建，不能称为完整 `/proc/meminfo`。`--max-bytes` 包括成功和失败的字段读取；`--limit` 包括摘要、指标和输入对象。公式与单位参考 [Linux 6.8 meminfo](https://github.com/torvalds/linux/blob/v6.8/fs/proc/meminfo.c)、[Linux 5.15 vmstat](https://github.com/torvalds/linux/blob/v5.15/include/linux/vmstat.h)、[Slab 全局单位](https://github.com/torvalds/linux/blob/v5.15/include/linux/mmzone.h)、[块设备汇总](https://github.com/torvalds/linux/blob/v6.8/block/bdev.c)、[旧内核 swapcache](https://github.com/torvalds/linux/blob/v4.13/mm/swap_state.c)。
- `routes` 枚举已登记网络 namespace 的 IPv4/IPv6 FIB 表，输出每条路由的目标/源前缀、表号、度量、下一跳和设备，以及对应对象地址。IPv4 主表/本地表共用树时按 alias 表号归属；IPv6 按精确 ISF 选择 `rt6_info` 或 `fib6_info`，排除继承的查找提示与空路由哨兵。普通、共享及多路径下一跳保留成员归属与权重，未核对完整的成员不进入网关/接口摘要。
- 路由范围包含旧内核 FIB 树内缓存条目，不含独立缓存例外、组播表、策略规则求值、已脱链对象、封装解码或实际数据包路径模拟。当前 IPv4 支持 `key_vector` trie，未实现更早的其他 FIB 布局。`routes` 的 `--max-bytes` 为本次请求读取内核字段的总预算（CLI/宿主内核入口默认 32 MiB；Rust `LinuxIrOptions::default` 为 1 MiB），另有 100 万个节点/指针槽上限；这些限制不改变 `--limit` 的记录数含义。损坏分支、缺页和超限保留已验证前缀，并标记不完整。
- `btf` 从精确 ISF 的 `__start_BTF` / `__stop_BTF` 定位小端 vmlinux BTF，解析 24 字节头部及 19 种类型编码，保留类型编号、名称偏移、编码地址、数组维度、成员位偏移、函数参数、变量与枚举值。编号 0 表示 void；只核对引用编号是否位于已解码范围，不等同于内核验证器的类型语义检查。旧版 ENUM 没有有符号标志语义，因此同时保留 32 位原始值及有/无符号解释；ENUM64 按显式标志解码，64 位数值不降精度。格式依据为 [Linux BTF 文档](https://docs.kernel.org/bpf/btf.html) 与 [Linux 5.15 BTF 文档](https://github.com/torvalds/linux/blob/v5.15/Documentation/bpf/btf.rst)。
- BTF 首条记录为头部，随后为类型；`--limit` 包含这条头部记录。未知编码或无效长度使顺序解码停止，不重新猜测后续类型编号。成员缺页保留已解码成员和已知记录边界；名称缺页保留字段及具体错误，不补零或伪造空名称。读取按 BTF 符号范围内的虚拟页缓存，并受整次 `--max-bytes` 限制；失败页同样计入尝试预算。名称最多核对 4096 字节，单类型正文 2 MiB，全部记录正文 64 MiB，超限保留部分状态；后两者不包含外层格式化缩进、报告告警等元数据。扩展头部的 layout、模块 split BTF、BTF.ext 和生成 ISF 尚未实现，不能把类型表当成内核运行时对象清单。
- syscall 检查将 `--entries` 当作上限，读取范围限制在精确 ISF 声明的数组长度内。数组长度缺失或为 0 时返回边界不可用，不能将表后相邻数据当成 syscall/hook。与采用相邻符号或元数据估计数量的工具相比，扫描范围更严格。可用其他内存取证工具复核此类镜像，并核对其估计范围。
- `triage`/`indicators` 聚合原生映射、凭据、PID 视图、熵、模块与 syscall 规则，并逐项保留来源状态。不是全部威胁规则或恶意概率模型。`av-edr` 的 51 条名称规则保留命中依据，不证明保护有效。`entropy` 统计可执行 VMA 前 16 KiB 中的实际驻留字节，所有 VMA 共用读取预算。
- `journald` 核对标准/compact 文件头、ENTRY_ARRAY、ENTRY/DATA 引用和驻留范围，支持未压缩、LZ4、单 LZMA2 过滤器 XZ 及单帧 ZSTD。XZ 字典和 ZSTD 历史窗口上限均为 16 MiB，单字段解码上限 1 MiB，并受本次剩余解码预算约束。ZSTD 同时支持有/无解压长度声明的帧，拒绝校验错误、截断、尾随字节和额外帧；失败字段保留对象偏移，不返回截断正文。解码响应请求取消，不把取消折叠为字段缺失。未重新计算 journal 内容哈希、验证 FSS 签名或回放文件系统 journal。索引缺页时可列出明确标注的字段候选，不能拼成有归属、有时间的完整日志。
- Journald 路径候选覆盖 `/var/log/journal/`、`/run/log/journal/` 及独立文件系统内的 `/log/journal/`、`/journal/`，之后仍按文件结构验证。报告保留原 superblock 相对路径、dentry/inode，不将相对路径猜测为某个确定的全局挂载路径。
- `crash-*` 从内核消息和驻留文本日志提取规则命中、上下文与摘要；不将重复日志数量当成宕机次数，不推断文本日志缺失的年份/时区。大文件按本次预算恢复前缀，保留原始 inode 大小、实际输出长度、未读后缀与前缀哈希范围；不会为整个文件分配缓冲区。`pagecache-recovery` 在读取预算内核对恢复范围，其余文件保留尚未核对状态；按 dentry 的单文件读取/导出可进一步验证。
- `timeline-network` 和 `timeline-findings` 保留无可靠事件时间的快照记录。`timeline-summary` 分别统计文件/进程、内核、Shell、网络的绝对时间、单调时钟和无时间记录，不将相对时钟直接混成 UTC。文件时间线先保留进程启动记录，避免被大量 inode 时间挤出结果上限。

- 符号匹配使用完整 `linux_banner`，不按相似版本下载或套用 ISF。具有精确 ISF 的任务会话仍核对 banner、页表、init_task 和首个任务回链；后续链断裂保留已经验证的记录并报告不完整。
- `PF_KTHREAD` 决定内核线程身份。用户进程退出后可能 `mm=NULL`，不能据此当成内核线程。
- `psscan` 扫描实际采集的物理区间，按调度类指针、PID/TGID、退出状态和 comm 核对候选。物理残留、活动链记录和 PID 注册表记录有不同范围；差异不直接证明隐藏。
- `psxview` 将初始 PID namespace 注册表与线程组主进程活动链核对。线程、退出过程、缺页都可能产生来源差异。
- `callstack` 读取已验证 SP 和 ISF `thread_union` 范围内的内核栈字，并核对代码范围、给出相邻符号。它不实现 ORC/帧指针展开，也不把任意栈值当成确定的调用关系；缺少可核对边界时不可用。
- `malfind` 保留属性候选、缺页和读取预算；没有读到内容不表示内容为零。JIT 和其他正常程序也可能使用匿名可执行或 RWX 区域。
- 页缓存支持精确 ISF 中的旧 compound page 和新 folio 布局；XArray 并不代表存在新 folio 字段。恢复继续核对 mapping、inode、page index 和物理页，非空文件零字节恢复直接失败。
- 持久化和日志扫描保留文件元数据、驻留片段及读取限制，不跨缺页拼接命令或日志行。规则命中不是恶意结论。进程时间保留启动后单调时钟语义，文件时间保留原始 UTC。
- 文件连续但物理页不连续时，UTF-8 字符可能跨原片段边界。保留原 `content_fragments` 契约；只有合并后能恢复此前无法解码的字符时，额外提供 `content_text_runs`。每段用 `extent_start_index`（从 0 计）和 `extent_count` 引用同一 `recovery.extents` 的连续文件范围，不伪造一个连续物理地址。缺口不合并，无效字节/二进制仍保留原片段状态；没有新增解码内容时不重复输出文本。文本组装继续响应当前请求取消。
- Tracepoint 包括内核和已验证模块链，支持 PREL32；不覆盖脱链模块。fbdev 不等于现代 DRM/Wayland 桌面重建。旧 radix/Netfilter 布局、缺少调试类型的内核以及未采集数据可能需要其他引擎。
- 本实现针对现有 x86_64 四级页表会话，并未宣称所有 Linux 架构、内核版本和其他内存取证工具的插件选项完全等价。

## 回归验证

本地优先运行 `cargo test --locked --lib linux_ir`。实镜像验证可记录内核版本、容器、符号身份、命令、结构化告警与结果范围，详见 [验证指南](VALIDATION.md)。
