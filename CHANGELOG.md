# 更新日志

## 0.2.2 — 2026-11-12

- 对齐 Lovelymem V3 的 StarMem 取证引擎，补入 24 个命令：无符号 Windows 分析、物理页文件反查、浏览器页面、应用痕迹、鼠标与交互历史、Linux 进程字符串和 macOS 手动分析等。
- 同步共享页表反向映射优化、x86 文件与进程插件、位图崩溃转储、压缩内存、Linux System.map 与页缓存恢复，以及相关测试和命令契约。
- 新增全局 `--show-warnings`：终端警告默认隐藏，指定参数后显示。JSON/CSV 报告中的警告、完整性和缺失信息继续保留。
- 保留开源版的独立 CLI、双语帮助、许可证与发布检查。
- 修复 VMware 实时读取模块在非 Windows 主机上的条件编译，补齐 macOS 命令 Schema 与符号转换脚本检查。
- 真实 4 GiB VMEM 回归中，`filescan --csv` 整体耗时从约 33 秒降至 3.19 秒；14,745 条文件记录保持一致。耗时随机器与镜像变化。

## 0.2.1 — 2026-11-12

### 修复

- 同步 Windows x86 PAE 兼容性修复，解决 Windows 7 SP1 32 位镜像报“符号配置中不包含符号 PsActiveProcessHead”的问题。
- 识别 x86 PDB 中带前导下划线的 C 数据符号，按实际类型读取指针宽度，并使用 DBI age 匹配镜像 CodeView，避免误用剥离后的 PDB information-stream age。
- 将 PAE 内核定位扩展到精确符号描述的非 XP 内核，验证实际映射的 PE32 内核 GUID/age；拒绝符号身份或 PE 架构不匹配的候选。
- 补齐 x86 进程映像基址、环境变量和系统共享数据读取，使 `pslist` 与 `system-info --quick` 可恢复相应信息。
- 为尚未适配 x86 对象布局的网络、DLL、VAD、Hive、句柄等入口返回明确错误；系统概览保留已有结果及来源不可用的告警。

### 验证

- Windows 7 SP1 x86 PAE 真实 RAW 镜像成功枚举 66 个活动进程，CLI 与进程内 Host API 的进程记录逐条一致。
- 64 位 VMEM 镜像恢复 455 个进程，PID、PPID、EPROCESS、DTB、名称和创建时间与修复前一致。
- 增加合成回归，覆盖非 XP 内核、32 字节对齐 CR3、32 位链表指针、GUID/age 不匹配和 PE32/PE32+ 架构不匹配。
- 新增可选的真实镜像 CLI/Host API 对照测试；私有镜像和符号文件不随源码或包分发。

本次验证覆盖内核定位、活动进程和系统概览，不代表所有插件均支持 x86 PAE。
`system-info --quick` 仍跳过深度网络和注册表扫描；完整性与缺失来源告警继续保留。
复现方法见 [真实镜像验证](docs/VALIDATION.md#windows-7-sp1-x86-pae-回归2026-11-12)。
