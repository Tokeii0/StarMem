# 参与 StarMem 开发

StarMem 欢迎文档修订、翻译、回归测试、容器解析和取证插件方面的贡献。第一次参与，可以从修正命令示例、补齐中英文帮助或用合成数据复现一个问题开始。

可以直接克隆仓库、提交 Issue，或 Fork 后向主仓库提交 PR。 [项目 Issues](https://github.com/Tokeii0/StarMem/issues)

StarMem 的原创部分采用 [LGPL 3.0](LICENSE)。第三方材料适用各自的许可。 [第三方声明](licenses/NOTICE.md)

[本地上手](#本地上手) · [代码地图](#代码地图) · [开发取证命令](#开发取证命令) · [验证](#验证) · [提交贡献](#提交贡献) · [English quick start](#english-quick-start)

## 本地上手

需要 Git、Rust **1.89 或更高版本**及目标平台的 C/C++ 构建工具链。Windows MSVC 使用 Visual Studio C++ Build Tools。运行仓库脚本还需要 Python 3。

```sh
git clone https://github.com/Tokeii0/StarMem.git
cd StarMem
rustup component add rustfmt clippy
cargo build --locked --bin starmem
cargo run --locked --bin starmem -- --help
cargo run --locked --bin starmem -- --help-en
```

`rustup component add` 适用于通过 rustup 安装的工具链。`cargo run` 使用当前检出的源码，适合改完代码立刻重试。

有了调试构建，就可以用一个 4 KiB 的合成 RAW 文件验证镜像入口。这段命令在 Git Bash、Bash 和 PowerShell 下均可使用。

```sh
python -c "from pathlib import Path; Path('target/contributor-smoke.raw').write_bytes(bytes(4096))"
cargo run --locked --bin starmem -- --json info target/contributor-smoke.raw
```

预期输出为 `command=info` 的 JSON 报告，`source_identity.size` 为 `4096`，`available` 与 `complete` 均为 `true`。这个样本用于验证 RAW 容器识别和报告输出。涉及 Windows 或 Linux 内核结构时，使用对应模块的合成测试或本地验证样本。 [镜像验证记录](docs/VALIDATION.md)

## 代码地图

| 要改的部分 | 从哪里读起 |
| --- | --- |
| CLI 参数、中英文帮助 | [CLI 入口](src/main.rs) · [英文帮助](src/cli_help_en.rs) |
| 容器、地址转换与符号 | [物理镜像](src/image.rs) · [虚拟地址](src/address.rs) · [Windows 符号](src/symbols.rs) · [Linux ISF](src/linux_symbols.rs) |
| Windows 和 Linux 取证 | [Windows 插件](src/windows/) · [Linux 会话](src/linux.rs) · [Linux 应急响应](src/linux_ir.rs) |
| 进程内宿主与批量采集 | [宿主 API](src/api.rs) · [分析会话](src/session.rs) · [采集调度](src/collection.rs) |
| 证据格式、输出安全与测试 | [Evidence Envelope](src/evidence.rs) · [输出策略](src/output_policy.rs) · [集成测试](tests/) |
| 命令契约与横评 | [叶子命令清单](metadata/leaf-command-manifest.json) · [命令等价表](benchmarks/command-equivalence.json) · [JSON Schema](schemas/) |

了解模块边界后再选实现位置。容器解析负责物理区段，地址层负责页表转换，取证插件消费已经验证的读取器和布局。宿主接口和 CLI 都通过各自入口复用引擎能力。 [架构说明](docs/ARCHITECTURE.md) · [crate 集成](docs/CRATE_INTEGRATION.md)

## 开发取证命令

1. **定义问题和范围。** 说明命令分析哪些镜像与结构、依赖什么符号、能证明什么。用最小合成数据构造正常路径和需要修复的边界。
2. **实现并接入。** 将解析逻辑放到对应引擎模块，在 `src/main.rs` 接入 CLI 并补齐中文与英文帮助。涉及宿主或批量采集时，检查 `src/api.rs` 与 `src/collection.rs` 的适用范围。
3. **同步命令契约。** 新增、删除或改名叶子命令时，同步 `metadata/leaf-command-manifest.json` 和 `benchmarks/command-equivalence.json`。声明 I/O、证据范围、`collect` 处置以及对照关系。没有可比插件时显式标记 `no_equivalent`。保留已有命令 ID 和别名，涉及兼容性变化时在 PR 中说明。
4. **验证正向结果和失败边界。** 对结构验证、缺页、坏链、预算和取消中实际受影响的情况补回归。比较关键字段和证据地址，也验证报告的可用性、完整性和告警。
5. **更新用法。** 写出一个可复制的调用示例，说明参数和输出范围。修改帮助后运行两种语言，确认别名和嵌套命令正常。

Evidence Envelope 的 `available` 表示证据是否可用，`complete` 对声明的 `scope` 生效。达到扫描预算、结构校验失败或页面缺失时，应通过 `limits`、`warnings` 和 `missing_ranges` 表达对应边界。导出类命令应使用现有输出策略保护输入和已有产物。 [Evidence Envelope v1](schemas/evidence-envelope-v1.schema.json)

## 验证

先跑与改动相关的检查，再按需跑完整门禁。

| 改动 | 定向命令 |
| --- | --- |
| CLI、参数、默认行为或帮助 | `cargo test --locked --bin starmem` |
| Linux 符号解析 | `cargo test --locked --lib linux_symbols` |
| 导出路径或覆盖策略 | `cargo test --locked --lib output_policy` |
| 命令清单、宿主 API 或 Evidence Envelope | `cargo test --locked --test command_registry --test crate_api --test evidence_schema` |

Rust 门禁与 CI 一致。

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
```

变更命令清单、Schema 或打包路径时，在开发用 Python 环境中安装 CI 固定的 `jsonschema` 版本并检查工程资产。Windows 上调试二进制路径是 `target/debug/starmem.exe`。

```sh
python -m pip install jsonschema==4.23.0
python -X utf8 scripts/validate_json_schemas.py
python -X utf8 scripts/starmem_benchmark.py validate benchmarks/corpus.example.json
python -X utf8 scripts/check_package.py --source .
```

若要让横评校验同时比对实际 CLI，在最后一次构建后，给 `validate` 命令加上 `--starmem target/debug/starmem`，Windows 使用 `.exe`。真实镜像横评在本地运行。CI 会构建 Windows x64、Linux x64、macOS arm64 宿主产物，并校验 Cargo 归档和发布清单。 [CI 工作流](.github/workflows/ci.yml) · [横评说明](benchmarks/README.md)

## 提交贡献

1. **选择改动。** 小型文档、翻译和测试改进可以直接发 PR。新增功能或修改公共契约时，先用 Issue 对齐预期行为、受影响的平台与验收方式。 [项目 Issues](https://github.com/Tokeii0/StarMem/issues)
2. **在自己的分支开发。** 从目标分支建立工作分支，每个 PR 聚焦一个问题。提交信息写清行为，可参考 `fix(cli): 修正参数校验`。
3. **附上可复现的证据。** Issue 和 PR 记录 `build-info`、宿主平台、镜像格式、命令、预期结果与实际结果。使用合成或脱敏的最小样本。真实镜像、符号、密钥及原始分析输出留在本地。
4. **提交 PR 并跟进。** 列出改动、验证命令和结果，标注涉及的兼容性或证据范围变化。若发现基线已有失败，附上基线和当前分支的对应结果，方便区分回归。

以 `main` 为目标时，可从远端最新的 `main` 建立分支。通过 Fork 提交时，把 Fork 配为可写远端，再推送分支并提交 PR。

```sh
git fetch origin
git switch -c fix/example origin/main
```

引用或改编第三方代码时，请在 PR 中说明来源，并保留适用的许可和署名。 [第三方声明](licenses/NOTICE.md)

PR 描述可使用以下结构。

```markdown
## 改动
- 修复的问题或新增的能力
- 关联 Issue（如有）

## 验证
- 运行的命令、平台和结果
- 合成样本或脱敏后的关键输出

## 兼容性与证据范围
- 受影响的 CLI、宿主 API、报告字段或支持范围（如有）
```

## English quick start

Clone the public repository or fork it to prepare a pull request. Start with a documentation fix, a help translation, or a reproducible test. Build from the repository root using `cargo build --locked --bin starmem`, then run `cargo run --locked --bin starmem -- --help-en`.

Use the [code map](#代码地图) to find the relevant module and the [verification commands](#验证) to test your change. A new CLI leaf needs both help languages, a command manifest entry, and an explicit comparison and collection disposition. Preserve the scope and completeness of evidence in your tests.

Open a focused PR with the problem, the change, the commands you ran, and the results. Use synthetic or sanitized evidence in shared examples. Keep private images, symbol files, and raw case outputs local. [English README](README.en.md) · [Issue tracker](https://github.com/Tokeii0/StarMem/issues)
