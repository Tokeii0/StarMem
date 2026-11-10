# StarMem Linux 进程与内核取证命令

本构建新增以下命令（点号命令均保留连字符别名）：

- `linux.info` / `linux-info`
- `linux.kaslr` / `linux-kaslr`
- `linux.cmdline` / `linux-cmdline`
- `linux.psaux` / `linux-psaux`
- `linux.pstree` / `linux-pstree`
- `linux.envars` / `linux-envars`
- `linux.lsof` / `linux-lsof`
- `linux.sockstat` / `linux-sockstat`
- `linux.proc.maps` / `linux-proc-maps`
- `linux.proc.dump` / `linux-proc-dump`
- `linux.bash` / `linux-bash`
- `linux.lsmod` / `linux-lsmod`
- `linux.module-extract` / `linux-module-extract`
- `linux.mountinfo` / `linux-mountinfo`
- `linux.kallsyms` / `linux-kallsyms`
- `linux.kmsg` / `linux-kmsg`
- `linux.modxview` / `linux-modxview`
- `linux.check-syscall` / `linux-check-syscall`

输入支持 Linux x86-64 LiME、纯 RAW/`.mem`、VMware `.vmem`，以及标记为 physical memory
的 EWF。RAW/VMEM 不按扩展名判断：通用 `pslist`、`filescan`、`dumpfile` 只有在镜像中同时
验证到完整 Linux banner 与 `swapper` 任务锚点后，才会路由到 Linux 分析。

物理映射层也已实现 VMware VMEM + VMSS/VMSN、x86-64 little-endian ELF
physical core、Xen ELF64、AVML v2 和 QEVM v3。QEVM 的 migration RAMBlock 偏移
不是 guest physical address，因此必须同时给出全局参数
`--qevm-ram-block`、`--qevm-below-4g-length` 和 `--qevm-above-4g-base`。
Xen/AVML/QEVM 目前只有合成边界测试；未完成与其他内存取证工具在真实镜像上的
对比前，它们不在正式支持承诺中。

## 快速使用

```powershell
$linuxImage = ".\linux.lime"
$linuxSymbols = "D:\symbols\linux"
starmem.exe linux.info $linuxImage
starmem.exe linux.kaslr $linuxImage
starmem.exe linux.pstree $linuxImage --pid 1 --csv pstree.csv
starmem.exe linux.psaux $linuxImage --pid 24889 --csv psaux.csv
starmem.exe linux.cmdline $linuxImage --symbol-path $linuxSymbols --pid 24889 --csv cmdline.csv
starmem.exe linux.envars $linuxImage --pid 24889 --csv envars.csv
starmem.exe linux.lsof $linuxImage --pid 24889 --max-fds 4096 --csv lsof.csv
starmem.exe linux.sockstat $linuxImage --max-fds 4096 --csv sockstat.csv
starmem.exe linux.proc.maps $linuxImage --pid 24889 --map-limit 10000 --csv maps.csv
starmem.exe linux.bash $linuxImage --pid 24889 --max-scan-bytes 67108864 --csv bash.csv
starmem.exe linux.proc.dump $linuxImage --pid 24889 --output dump-24889 `
  --max-region-size 33554432 --max-total-size 67108864 --csv proc-dump.csv
starmem.exe linux.lsmod $linuxImage --symbol-path $linuxSymbols --limit 65536
starmem.exe linux.module-extract $linuxImage --symbol-path $linuxSymbols `
  --name ext4 --output ext4.ko --max-bytes 1073741824
starmem.exe linux.mountinfo $linuxImage --symbol-path $linuxSymbols --namespace 0xffff888000001000
starmem.exe linux.kallsyms $linuxImage --symbol-path $linuxSymbols --limit 1000000
starmem.exe linux.kmsg $linuxImage --symbol-path $linuxSymbols
starmem.exe linux.modxview $linuxImage --symbol-path $linuxSymbols
starmem.exe linux.check-syscall $linuxImage --symbol-path $linuxSymbols `
  --table x64 --entries 1024
```

不传 `--pid` 时，除 `linux.proc.dump` 外的命令分析全部活动线程组主进程。使用
`--json` 可输出完整 JSON；使用 `--csv -` 可将结构化 CSV 写到标准输出。

## 证据与完整性语义

- `linux.info`：无需 BTF/ISF 或 `task_struct` profile。从完整 kernel banner 提取 release；
  hostname 必须来自 systemd journal `_HOSTNAME`、环境 `HOSTNAME` 或桌面
  `SESSION_MANAGER`，并优先要求跨来源印证；登录用户必须在同一驻留环境窗口内满足
  `USER`、`LOGNAME`、`HOME=/home/...` 至少两项一致，且存在 XDG/桌面/显示/SSH/session ID
  或交互 Shell 会话证据。孤立字符串不作为结论。
- `linux.kaslr`：从 live VMCOREINFO 的 `SYMBOL(_stext)`，或精确 ISF `_stext` 加已验证
  `init_task` slide，恢复第一条内核指令的运行时虚拟地址；再使用已经验证的 Linux DTB 做
  strict-present 页表翻译。只有虚拟读取与物理读取的前 16 字节一致且非全零时才输出结果。
- `linux.cmdline`、`linux.envars`：从进程自己的页表读取 `mm_struct` 中的精确范围。只把
  present 页作为已恢复数据，并报告请求字节、恢复字节、缺失范围、截断状态和完整性。
- `linux.pstree`：复用已经验证的活动任务链，以 PID/PPID 生成稳定进程树；PID 0 作为镜像外
  的内核根处理，非零父 PID 缺失时标记 `orphan_parent`，重复父链标记 `parent_cycle`。
  `--pid` 仅输出该进程及其活动后代。通用 `pstree` 也会自动识别并路由 Linux 镜像。
- `linux.psaux`：把活动线程组主进程的 PID、PPID、状态、启动纳秒值和 argv 汇总到一张表。
  精确 `mm_struct` 布局或驻留 argv 不可用时仍保留进程，并以
  `command_line_source=task_struct.comm_fallback` 明确标记退化证据；已确认的内核线程显示为
  `[comm]`，不会把未知 `mm` 状态误报成内核线程。
- `linux.lsof`：遍历 `files_struct -> fdtable -> file`，重建 mount/dentry 路径，并为每条
  路径保留解析状态、inode、文件类型、访问模式、标志和文件位置。
- `linux.sockstat`：只从 `linux.lsof` 已验证的活动 socket FD 出发，通过
  `sockfs inode -> socket_alloc -> socket -> sock` 解析 AF_UNIX、IPv4 和 IPv6；每条记录
  都要求 `file.private_data`、`socket.file` 与 `sock.sk_socket` 反向链接一致，并报告
  TCP/UDP 协议、端点、状态、socket/task network namespace、证据地址和字段完整性。
  这是活动 FD 视图，不包含已关闭、孤立或仅存于 slab 残留中的 socket。
- `linux.proc.maps`：4.13/5.4 遍历 VMA 链表，6.8 遍历 Maple Tree；校验 VMA 所属
  `mm_struct`、地址范围、排序/重叠、`map_count` 和遍历终止原因。
- `linux.proc.dump`：每个已验证 VMA 写一个文件。全部页均可读时使用 `.dmp`；只要存在
  缺页就使用 `.dmp.partial`。partial 文件在缺页位置写零以保持虚拟地址偏移，同时 CSV/JSON
  明确保存每个缺失范围。每条记录同时包含完整逻辑文件 SHA-256 和实际恢复字节 SHA-256。
- `linux.bash`：只报告活动 Bash 可写匿名/heap VMA 中，通过 `HIST_ENTRY.timestamp`、相邻
  line 指针和历史数组回指验证的 `#epoch` 命令。不会把普通字符串猜成历史命令。

`linux.bash` 有意不声称恢复未启用时间戳的历史、已经退出 Bash 的历史或非驻留页面内容；
这些情况会通过限制说明、缺失范围和 `complete=false` 显式表达。

### Linux 内核全局命令

七个命令使用与进程 task-ring 会话分离的 `LinuxKernelSession`。它们共用镜像位置、
`--cache`、可重复的 `--symbol-path`、可选 `--dtb` 和 `--kernel-slide`。自动候选或
显式覆盖都必须通过 `_stext` 可读性和运行时 `linux_banner` 字节级匹配；所以任务链
损坏不会无关地禁用模块、kmsg 或 kallsyms，但也不会降低内核会话的验证门槛。

- `linux.lsmod --limit N`：严格遍历 `modules` 双向链。头部回链、节点 backlink、
  重复/非法指针、缺页和上限任一失败时，保留已验证模块但设置 `complete=false`。
- `linux.module-extract (--name NAME | --base ADDRESS) --output FILE --max-bytes N`：
  在写出前重读 module 对象并校验名称/基址/大小。只要有缺页、模块宇宙不完整或
  达到字节上限，就只发布 `FILE.partial` 与 `FILE.manifest.json`；全局 `--force`
  只能替换普通输出，不能覆盖镜像或 ISF。
- `linux.mountinfo [--pid PID --task ADDRESS | --task ADDRESS | --namespace ADDRESS] --limit N`：
  kernel-global 会话不为 PID 暗中扫描 task ring，因此 `--pid` 必须配对已验证
  `--task`；未指定筛选时从 `init_task` 的 mount namespace 开始。
- `linux.kallsyms --limit N`：聚合 core kallsyms 与经 modules 双向链、allocation
  范围和 ELF64 symtab 二次验证的 module symbols；旧版 direct 与现代
  `core_kallsyms/kallsyms` 布局均可以显式判定。任一缺页、链不完整或
  module/符号/输出 limit 命中都会 `complete=false`。ftrace 和 BPF 仍从
  scope 排除并明确 `available=false`，不被偷换成已搜索的阴性结果。
- `linux.kmsg [--boot-time-unix-ns N] --limit N`：兼容旧 log buffer 与新 printk ring。
  没有独立启动时间时只输出 `monotonic_ns`；新 ring 的 descriptor state 语义尚未全部证明时
  保持 `complete=false`。
- `linux.modxview --limit N`：交叉 `modules` list、`module_kset` 和受限语义扫描。
  第三视图只扫描运行时 `module_addr_min..module_addr_max`，并对名称、core/init
  bounds、mapped endpoints、list 邻接互指和结构稳定重读全部复验；不做全内存
  字符串命中。无可证边界、缺页或 byte/output limit 时明确降低完整性。
- `linux.check-syscall --table {x64,ia32,x32} --entries N [--no-modules]`：
  handler 只能归属到符号证明且端点可翻译的 kernel text，或严格链与 `text_size`
  共同证明的 module text。module 宇宙不完整时，范围外指针标为不确定而不是直接定性 hook。

所有 JSON 都通过 Evidence Envelope 输出，顶层必有布尔值 `available` 和 `complete`，并附带
`data.kernel_session` 中的 DTB/KASLR/符号身份。镜像、参数或 I/O 初始化错误仍非零退出；
会话已打开但插件所需证据源不可用时，报告 `available=false`。只有与命令 `scope`
一致且 `complete=true` 时，未命中才能在该范围内解读为阴性结果。

## 精确支持范围

进程结构偏移优先来自完整 `linux_banner` 精确匹配并通过运行时验证的 Linux ISF；
内置 profile 只作为已验证样本的离线回退，不按主版本号盲猜。

兼容 Linux ISF 的搜索路径、现场验证流程与实验性容器边界见 [架构说明](docs/ARCHITECTURE.md)。
