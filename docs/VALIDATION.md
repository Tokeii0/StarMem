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

[贡献指南](../CONTRIBUTING.md) · [横评复现](../benchmarks/README.md) · [证据解释](../starmem-memory-forensics/references/evidence-interpretation.md)
