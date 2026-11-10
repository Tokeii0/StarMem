# StarMem reproducible cross-tool benchmark

This directory is deliberately image-free. Private memory images and symbol stores stay outside Git.

Copy the example manifest, then replace its sample paths, sizes, digests and expected counts with the values for your authorized local fixtures. Validate the completed manifest before running a case.

```sh
cp benchmarks/corpus.example.json benchmarks/corpus.local.json
# Populate the local manifest with your fixture identities and expected results.
export STARMEM_CORPUS_ROOT=/evidence/corpus
export STARMEM_VOL3=/opt/forensics/bin/reference-tool
export STARMEM_WINDOWS_SYMBOL_ROOT=/evidence/symbols/windows
export STARMEM_LINUX_SYMBOL_ROOT=/evidence/symbols/linux
python -X utf8 scripts/starmem_benchmark.py validate benchmarks/corpus.local.json --check-files
python -X utf8 scripts/starmem_benchmark.py run benchmarks/corpus.local.json
```

The launcher setting can be an executable path or a command such as
`python /opt/forensics/reference_tool.py`. Use the reference tool and CLI expected by the case
manifest. `STARMEM_BIN` can override the default `target/release/starmem`. Every run is written beneath
`.local-validation/<UTC-run-id>/`; stdout, stderr, exact argv, exit status, timeout, wall time,
peak RSS, parsed envelopes/warnings, normalized multisets, and differences are retained.

The example shows a damaged process list case and a healthy case. Its placeholder identities and counts describe the manifest shape. Result JSON exposes separate `positive_evidence_pass` and `universe_completeness_pass` gates.

Comparison modes are `exact`, `subset`, `expected_difference`, and `expected_failure`.
Expected differences and failures must contain a reason. Cases requiring both recovery and completeness assertions should
declare separate `positive` and `completeness` gates so a useful recovery can never turn a damaged
search universe into a false claim of completeness.

`metadata/leaf-command-manifest.json` is the authoritative declaration for all leaf command
IDs, paths, aliases, help, arguments, I/O roles, Evidence defaults and `collect` disposition. It is
strictly joined to the command-equivalence table and checked against the live Clap surface in CI.
A newly added, removed, or renamed leaf command therefore requires both a manifest declaration and
an explicit mapping decision, including an intentional `no_equivalent` decision when the reference
tool's built-in plugins have no match.
Every leaf also fixes its adapter and external-tool version, comparable fields, normalized set key,
normalizer, documented non-equivalent fields, and platform/symbol/acquisition prerequisites; none
of these comparison semantics are supplied by an implicit default.

`scripts/generate_leaf_command_manifest.py` only bootstraps a reviewed declaration from audited
Clap/collection JSON snapshots; it is not invoked by the build and never silently rewrites product
metadata. The embedded build ID covers both the leaf manifest and the equivalence table.

Real corpus comparisons are local by design; CI performs schema/coverage checks, Rust quality
gates, package inspection, release builds, and release-manifest verification without accessing
private images or downloading forensic symbols.

## 本地 Linux 与采集格式门禁

真实镜像和其他内存取证工具的输出只能写入 `.local-validation`，不上传 CI。

Linux 内核全局命令 `linux.lsmod`、`linux.module-extract`、`linux.mountinfo`、
`linux.kallsyms`、`linux.kmsg`、`linux.modxview` 和 `linux.check-syscall` 已有显式等价记录。
实参命令必须在 case 中声明参数：共用的 `--symbol-path`/可选 `--dtb`/`--kernel-slide`，
module-extract 的 name/base、output、max-bytes，mountinfo 的 pid/task/namespace，kmsg 的启动时间证据，
以及 check-syscall 的 table/entries/module scope。横评必须同时比较正向集合、`available`、
`complete` 和 warning code；不能因为恢复到正向记录就忽略损坏的搜索宇宙。

平面 VMware VMEM 已有真实镜像回归。VMEM + VMSS/VMSN、ELF physical core、Xen ELF64、AVML v2
和 QEVM v3 当前处于合成测试阶段。ELF 测试需区分带精确 QEMU note 的样本与 generic producer。
每种格式在正式声明前至少需一份真实正样本，并用固定版本的其他内存取证工具
比较 physical spans、mapped bytes、关键扫描命中和 `pslist` 集合。QEVM case 还必须显式记录
RAMBlock、below-4G length 和 above-4G physical base；迁移流偏移绝不作为默认物理地址。

Corpus image paths and optional symbol-material paths are logical relative paths. Images resolve
below `STARMEM_CORPUS_ROOT`; symbol material resolves below the shared, Windows, or Linux symbol
root and is size/SHA-256 checked before either engine starts. Cases may set absolute peak-RSS
ceilings; relative performance gates remain disabled until enough local history exists.
