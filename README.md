<p align="center">
  <img src="docs/assets/starmem-mascot.png" width="208" alt="StarMem 吉祥物">
</p>

<h1 align="center">StarMem</h1>

<p align="center"><strong>用于 Windows 和 Linux 镜像的 Rust 内存取证引擎</strong></p>

<p align="center">简体中文 · <a href="README.en.md">English</a></p>

<p align="center">中文 CLI · Rust crate · LGPL-3.0-only</p>

<p align="center">
  <a href="#安装">安装</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#支持范围">支持范围</a> ·
  <a href="#文档">文档</a> ·
  <a href="CHANGELOG.md">更新日志</a> ·
  <a href="#开发与贡献">贡献</a>
</p>

StarMem 从物理内存镜像中提取进程、连接、驻留文件与系统活动。它适合用来建立应急排查基线、恢复镜像中仍驻留的字节，以及把结果交给脚本或取证工具复核。结构化报告会记录证据来源、扫描范围、缺页和限制。

## 可视化界面版本 Lovelymemv3

如果不喜欢CLI可以试试收费版本的Lovelymemv3，包含Starmem核心，[下载地址](https://lovely.mzy0.com/lovelymem.v3.exe)

## 安装

需要 Rust **1.89+** 和目标平台的 C/C++ 构建工具链。Windows MSVC 目标需要 Visual Studio C++ Build Tools。可从源码安装。

```sh
git clone https://github.com/Tokeii0/StarMem.git
cd StarMem
cargo install --path . --locked
starmem --version
```

已有检出可直接在仓库根目录运行安装命令。确保 Cargo 的 `bin` 目录在 `PATH` 中。CI 为 Windows x64、Linux x64 和 macOS arm64 构建宿主程序。Windows 和 Linux 发布二进制使用 UPX 压缩，macOS 保持原生可执行格式。运行通过后可在对应的 Actions 页面下载二进制、Cargo 包和校验清单。 [构建记录](https://github.com/Tokeii0/StarMem/actions/workflows/ci.yml)

## 快速开始

先运行 `starmem info <镜像路径>` 确认容器格式和物理内存区段，再按**镜像中的系统**选择命令。下面的路径需要换成实际检材与符号目录。

### Windows 镜像

```powershell
$starmem = "starmem"
$windowsImage = "E:\evidence\windows.raw"
$windowsSymbols = "D:\symbols\windows"

& $starmem info $windowsImage
& $starmem pslist $windowsImage --symbol-path $windowsSymbols
& $starmem netscan $windowsImage --symbol-path $windowsSymbols --csv .\connections.csv
```

先查看活动进程，再把发现的 TCP/UDP 端点导出到 `connections.csv`。

### Linux 镜像

```sh
starmem info ./linux.lime
starmem linux.info ./linux.lime
starmem linux.psaux ./linux.lime --symbol-path /path/to/linux-isf/symbols
starmem linux.sockstat ./linux.lime --symbol-path /path/to/linux-isf/symbols
```

用 `linux.info` 确认内核与主机线索，再查看进程命令行和活动 socket。

默认用 `starmem --help` 查看中文帮助。英文帮助使用 `starmem --help-en` 或 `starmem <命令> --help-en`，也支持嵌套命令，例如 `starmem symbols linux --help-en`。

## 支持范围

| 取证任务 | Windows | Linux |
| --- | --- | --- |
| 系统与进程 | `system-info`、`pslist`、`psxview` | `linux.info`、`linux.psaux`、`linux.pstree` |
| 网络与通信 | `netscan`、`packetscan`、`pipescan` | `linux.sockstat`、`linux.ir-kernel --module routes` |
| 驻留文件 | `filescan`、`dumpfile`、`mftdump`、`sqlite-recover` | `filescan`、`dumpfile`、`linux.lsof` |
| 执行、日志与时间线 | `windows.execution`、`windows.timeline`、`dump-logs` | `linux.bash`、`linux.kmsg`、`linux.ir --module journald` |
| 异常排查 | `check-pslist`、`injected-regions`、`cobaltstrikescan` | `linux.modxview`、`linux.check-syscall`、`linux.ir --module triage` |

### 镜像格式

主要分析路径面向 **x86-64** 来宾系统。部分 Windows 命令可处理 x86 PAE，覆盖范围取决于插件。

| 验证状态 | 格式 |
| --- | --- |
| 有真实镜像验证记录 | RAW / `.mem`、平面 VMware `.vmem`、Windows x64 crash dump、LiME |
| 支持读取物理内存介质 | EWF / E01。磁盘和卷介质会被识别并拒绝进入内存分析。 |
| 合成测试覆盖 | VMware VMEM + VMSS/VMSN、ELF physical core（含 QEMU）、Xen ELF64、AVML v2、QEVM v3 |

高级容器选项可通过 `starmem info --help` 查看。分析和恢复仍取决于页表、符号及已采集的内存页。样本与覆盖范围见 [验证记录](docs/VALIDATION.md)。

### 符号配置

- **Windows**使用 `--symbol-path` 指定 PDB 根目录，或用 `--pdb` / `--profile` 指定文件。自动解析优先按目标内核的 CodeView GUID/age 匹配 PDB。使用兼容布局时，报告会注明回退情况。
- **Linux**使用 `--symbol-path` 指定 其他内存取证工具的兼容 ISF 目录（`symbols` / `symbols/linux`），或单个 `.json` / `.json.xz` ISF。解析器按完整 `linux_banner` 匹配并现场校验所需布局。可用 `starmem symbols linux <镜像> --offline --symbol-path <符号目录>` 诊断本地符号。

`STARMEM_SYMBOL_PATH` 可设置共享只读符号根，`--cache` 或 `STARMEM_SYMBOL_CACHE` 指定可写缓存。Windows 可从 Microsoft 符号服务器补齐精确 PDB。Linux 可按完整 banner 查远程 ISF，`STARMEM_LINUX_ISF_URL` 指定兼容索引，`STARMEM_LINUX_ISF_OFFLINE=1` 关闭 Linux 符号联网。

## 证据与导出

| 输出 | 命令选项 |
| --- | --- |
| JSON 报告 | `--json`。插件结果放在 `data`，外围字段遵循 [Evidence Envelope v1](schemas/evidence-envelope-v1.schema.json)。 |
| CSV 表格 | `--csv <文件>`。报告按区段写为 UTF-8 CSV，`--csv -` 写到标准输出。 |
| 原始证据对象 | `--json --raw-objects <文件.jsonl>`。受支持的对象按 `evidence_id` 排序。见 [Raw Object v1](schemas/raw-object-v1.schema.json)。 |
| SQLite 批量采集 | `collect --db <文件>`。复用镜像上下文，运行适用于本次采集的只读插件。 |

> [!IMPORTANT]
> 空结果需要结合 `available`、`complete`、`scope`、`warnings`、`limits` 和 `missing_ranges` 解读。`complete` 只描述报告声明的扫描范围。归档时应单独计算检材的完整 SHA-256，并保存 `starmem --json build-info` 和实际命令。

```powershell
& $starmem --json --raw-objects .\pslist.objects.jsonl pslist $windowsImage --symbol-path $windowsSymbols
& $starmem collect $windowsImage --symbol-path $windowsSymbols --db .\evidence.sqlite
```

SQLite 会追加独立分析批次。查询插件表时用 `analysis_id` 限定批次，并先查看 `plugin_runs` 的运行状态。

普通导出默认保护输入和已有输出。`--force` 仅可替换声明的普通输出。带 `.partial` 的恢复产物含未恢复区段，复核时应同时查看缺页清单和实际恢复字节数。详见 [证据校验](docs/VALIDATION.md)。

## Rust API

Rust 和 Tauri 宿主可通过 `starmem::api` 查询 `capabilities()` 和 `command_catalog()`，用 `Session::open` 复用镜像会话，再用 `Session::run` 获取结构化结果。耗时任务可在 `spawn_blocking` 中执行，并绑定请求级进度和取消。

Host API v1 当前公开 Windows 只读会话。Linux 入口是 CLI 与低层 Rust 模块。API 版本握手、依赖锁定和 LovelyMem 示例见 [crate 集成指南](docs/CRATE_INTEGRATION.md)。

## 文档

| 需求 | 阅读入口 |
| --- | --- |
| Windows 调查与恢复 | [Windows 取证指南](docs/WINDOWS_FORENSICS.md) |
| Linux 进程、文件与应急排查 | [Linux 进程与文件取证](LINUX_PROCESS_COMMANDS.md) · [Linux 应急响应](docs/LINUX_IR.md) |
| 引擎实现与宿主集成 | [架构与扫描设计](docs/ARCHITECTURE.md) · [crate 集成指南](docs/CRATE_INTEGRATION.md) |
| 验证与复现 | [验证方法与覆盖范围](docs/VALIDATION.md) · [横评复现](benchmarks/README.md) |

## 开发与贡献

欢迎贡献文档、翻译、测试和取证功能。贡献指南包含环境配置、无需真实检材的首个验证、插件开发步骤和 PR 示例。 [参与 StarMem 开发](CONTRIBUTING.md)

## 许可证

StarMem 原创部分采用 GNU Lesser General Public License 3.0，SPDX 标识为 `LGPL-3.0-only`。分发 StarMem 时请一并提供两份许可文本，并遵守相应的源码提供条款。 [LGPL 3.0](LICENSE) · [GPL 3.0](licenses/LICENSE-GPL)
