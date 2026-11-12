# 验证方法与覆盖范围

StarMem 的验证分为合成回归、命令契约检查和本地镜像复核。公开仓库包含合成测试源码、Schema 与横评配置模板。真实检材与原始报告由贡献者在本地保管。

## 可重复的最小验证

```sh
cargo build --locked --bin starmem
cargo run --locked --bin starmem -- --help-en
python -c "from pathlib import Path; Path('target/validation.raw').write_bytes(bytes(4096))"
cargo run --locked --bin starmem -- --json info target/validation.raw
```

预期报告的 `command` 为 `info`，`source_identity.size` 为 4096，`available` 与 `complete` 均为 `true`。这个样本覆盖 RAW 容器识别与证据报告输出。

## Windows 7 SP1 x86 PAE 回归（2026-11-12）

本次 `test.raw` 为 3,174,035,456 字节，SHA-256 为
`eea6dcbc92ed5f69b7ccbdb98081ef240e9967b93a982d6df57cc230456a7b30`。
系统为 `6.1.7601`，内核构建 `7601.23915.x86fre.win7sp1_ldr.170913-0600`。
精确符号为 `ntkrpamp.pdb/92D32EE7188A4CB3AB23EDA0CB0F9D7B2`，从本地符号根只读复用。

旧版在 `PsActiveProcessHead` 查找时失败。已同步 x86 C 符号前导下划线处理、
PDB 类型实际指针宽度、DBI age、通用 PAE 内核定位、PE32 CodeView 验证和 x86 系统概览。
该 PDB 的 information-stream age 为 5，DBI/镜像 CodeView age 为 2；不能用 5 拒绝匹配的镜像。
活动链表恢复 66 个进程，`available=true`、`complete=true`、`stop_reason=list_head`，无警告；
PID、PPID、EPROCESS、DTB、创建时间、路径和命令行与已验证的宿主构建逐条一致。
`windows-info` 的完整性未声明，`system-info --quick` 主动跳过深度来源，二者保留 `complete=false`。
`netscan` 明确报告 x86 PAE 对象布局尚未支持，不返回伪造的空网络列表。

自动回归 `cargo test --locked --test windows_x86_pae` 覆盖非 XP 内核引导、32 字节对齐 CR3、
32 位链表指针、GUID/age 不匹配及 PE32+ 架构不匹配。真实镜像的 CLI/Host API 对照测试默认忽略，
需要显式设置 `STARMEM_X86_IMAGE`、`STARMEM_X86_PDB`、`STARMEM_X86_CLI_REPORT`，再运行：

```powershell
cargo test --locked --test windows_x86_pae -- --include-ignored --nocapture
```

测试只读使用私有镜像与 PDB；源码、CI 和包中不包含这两个文件。

最终 `0.2.1` Windows release 构建复测上述 RAW 成功；`pslist` 耗时约 1.91 秒，
默认和快速 `system-info` 都保留可恢复的系统信息，未适配来源明确告警。
另以 4,294,967,296 字节的 64 位 VMEM
（SHA-256 `d27e9ba1612dc083e9323a026711481d60ebc313ab46b33dba7fdd34e3921a12`）
复测，完整恢复 455 个进程，PID、PPID、EPROCESS、DTB、名称和创建时间与修复前逐条一致。
定向单元/契约/集成测试共 61 项通过，`cargo check --locked --all-targets` 和源码包清单检查通过。

## 测试范围

| 范围 | 验证重点 |
| --- | --- |
| 容器与地址转换 | 物理区段、页表读取、跨区段读取与采集缺口 |
| 符号与插件 | 精确符号身份、结构验证、回退条件与搜索范围 |
| 报告与恢复 | 证据来源、完整性、缺页、路径安全与部分输出 |
| 命令契约 | 中英文帮助、命令清单、JSON Schema 和宿主接口 |

VMware VMEM + VMSS/VMSN、ELF physical core、Xen ELF64、AVML v2 和 QEVM v3 的公开覆盖主要来自合成测试。具体支持范围按所用版本的 [架构说明](ARCHITECTURE.md) 和实际报告判断。

## 复核真实镜像

1. 记录镜像格式、完整 SHA-256、StarMem 的 `build-info`、符号身份与实际执行的命令。
2. 用 `--json` 留存结果，分别核对正向证据和搜索范围完整性。
3. 比较告警、预算和缺失区间，再核对恢复产物的实际字节数与摘要。
4. 分享验证结论时，提供脱敏的最小复现或相应的合成测试。

[贡献指南](../CONTRIBUTING.md) · [横评复现](../benchmarks/README.md)
