# Lovelymem V3 引擎同步记录

本次同步以 Lovelymem V3 3.1.11 的 `src-tauri/vendor/starmem` 工作区为准。
宿主仓库提交为 `a0f1906dde88b2f4c069f01a77fb274a5f50a9a4`，同步包含该工作区尚未提交的引擎改动。
开源比较基准为 v0.2.1：`79bfa77ed919effcb6212bfa88040638fa1e6767`。

## 差异数量

统一换行及 rustfmt 格式后，V3 的 195 个 Rust 源文件中，67 个与开源版相同，
57 个已有文件包含差异，71 个文件尚未进入开源版。这里不计 V3 桌面授权模块，
也不把开源版独有的英文帮助文件视为遗漏。

这些引擎文件、配套测试及命令契约已合入 0.2.2。命令目录从 155 项增加到 179 项，
没有删除原有命令。已有命令的参数扩展也随目录同步，例如剪贴板历史及 Linux System.map。

## 新增命令

| 范围 | 命令 |
| --- | --- |
| 无外部调试符号的 Windows 分析 | `symbolless.pslist`、`symbolless.system-info`、`symbolless.filescan`、`symbolless.dumpfile`、`symbolless.process-context`、`symbolless.process-modules`、`symbolless.registry` |
| 文件与 IPC | `windows.phys2file`、`mailslots` |
| 浏览器与用户交互 | `browser-pages`、`mouse-history`、`windows.interaction` |
| 应用痕迹 | `ai-chat`、`anydesk`、`sunlogin`、`wps`、`bitlocker`、`veracrypt`、`huorong`、`qqscan`、`wechat-chat` |
| Linux | `linux.proc.strings` |
| macOS | `macos.ir`、`macos.dumpfile` |

无符号分析保持 V3 的实验性、手动执行边界。macOS 路径需要显式符号，范围为
OS X 10.8–10.11 x86-64；命令存在不表示任意 macOS 镜像都已验证。
新增功能的具体输入、预算和来源限制以各命令的 `--help` / `--help-en` 为准。

## 同步的已有能力

- 共享空页表缓存、可取消页表遍历、x86 PAE 文件/模块分析及页表扫描。
- 位图崩溃转储、压缩内存读取、文件物理页反查及文件范围恢复。
- Chromium/Firefox 数据库与账号元数据恢复、WCDB 缓存、V8 对象解析。
- TextInputHost 剪贴板历史、桌面像素、控制台、注册表和离线凭据解析。
- Linux System.map、精确 ISF 类型补齐、进程字符串及页缓存恢复。
- VMware 实时读取的 crate 接口与示例；它们保留实时读取的非原子性说明。

## 开源版保留的差异

开源 CLI 独立运行，不依赖 Lovelymem 桌面授权模块。开源许可证、发布流程、
双语帮助及脱敏测试数据继续保留。为通过现有严格检查，部分代码作了等价的
Clippy 调整；这些调整不改变取证算法。新增的反向页表回归覆盖部分读取和读取失败。

全局参数 `--show-warnings` 控制终端警告，默认关闭：

```powershell
starmem system-info memory.raw
starmem system-info memory.raw --show-warnings
```

JSON/CSV 中的警告、完整性与缺失范围始终保留；致命错误仍报告失败退出码。

## 快照身份

同步源 `src/`、`tests/`、`metadata/` 的逐文件 SHA-256，按相对路径排序，
以 `路径 + NUL + SHA-256 + LF` 串联后再次计算 SHA-256（排除桌面授权模块）：

`960ced8793ccbb878ccf1285a710cb8bef9e574ad6b5f9336e38b9dacedc0c90`

真实镜像与扫描结果不随源码分发；版本验证见 [验证记录](VALIDATION.md)。
