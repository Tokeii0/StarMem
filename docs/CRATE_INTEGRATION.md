# StarMem crate / LovelyMem 进程内集成

StarMem 原创部分采用 `LGPL-3.0-only`。分发与 StarMem 链接的组合程序时，按 LGPL 第 4 节
提供许可声明及两份许可文本。对通常静态链接的 Rust crate 集成，第 4(d)(0) 节规定了一种
分发方式，提供最小对应源码与允许接收者重新链接的应用代码材料。应用代码材料可采用
目标代码、源码或两者，具体要求以许可正文为准。 [LGPL 3.0](../LICENSE) · [GPL 3.0](../licenses/LICENSE-GPL)

StarMem 0.2 提供同步、纯 Rust 的 `starmem::api`。该模块是唯一承诺由
`INTEGRATION_API_VERSION` 管理兼容性的宿主入口；StarMem 不依赖 Tauri、Tokio，也不替宿主
管理会话 ID。LovelyMem 应在自己的 `spawn_blocking` 工作线程中打开并缓存一个
`starmem::api::Session`。

> LovelyMem 旧桥接调用 `starmem.exe -i IMAGE --outlovelymem DIR`，并读取
> `starmem/info.txt` 与 `starmem/pslist.csv`。这些遗留参数不是 StarMem 0.2 CLI 契约；新接入
> 应直接使用本页的 crate API。

## 依赖与兼容握手

本地联调时使用精确版本和明确路径：

```toml
[dependencies]
starmem = { version = "=0.2.1", path = "../../mem" }
```

发布后改为 crates.io 精确版本，或使用 Git 的精确 `rev`。不要只锁分支。宿主启动时先读取
`capabilities()`，核对 `integration_api_version`、Evidence/Host API schema 以及可运行命令：

```rust
use starmem::api;

let capabilities = api::capabilities();
assert_eq!(
    capabilities.integration_api_version,
    starmem::INTEGRATION_API_VERSION,
);
```

`VERSION`/`INTEGRATION_API_VERSION` 是兼容判断；`BUILD_ID` 标识具体源码产物，适合作为缓存键，
不应代替 API 版本判断。StarMem 的 build script 只计算自身 crate 输入，不读取 LovelyMem 的
`Cargo.lock` 或 Git 身份。

## 打开并复用会话

API 是同步的。下面的闭包应由 LovelyMem 放进 `tauri::async_runtime::spawn_blocking`；会话由
LovelyMem 自己放入 `Arc` 或 session map：

```rust
use std::path::PathBuf;
use std::sync::Arc;

use starmem::api::{
    ExecutionContext, HostImageOptions, HostSymbolOptions, OpenSessionRequest,
    PlatformHint, ProgressEvent, Session,
};
use starmem::cancellation::CancellationHandle;

let cancellation = CancellationHandle::new();
let token = cancellation.start();
let progress = Arc::new(|event: ProgressEvent| {
    // LovelyMem 在这里把 event 发到对应 request_id 的 Tauri channel。
    let _ = event;
});
let context = ExecutionContext::new(token).with_progress(progress);

let (session, opened) = Session::open(
    OpenSessionRequest {
        integration_api_version: starmem::INTEGRATION_API_VERSION,
        request_id: "open-case-001".to_owned(),
        image_path: PathBuf::from("memory.raw"),
        platform: PlatformHint::Windows,
        image: HostImageOptions::default(),
        symbols: HostSymbolOptions {
            search_roots: vec![PathBuf::from("symbols")],
            ..HostSymbolOptions::default()
        },
    },
    &context,
)?;

assert_eq!(opened.platform, starmem::api::ApiPlatform::Windows);
# Ok::<(), starmem::api::ApiError>(())
```

Host API v1 暂时只公开 Windows session；请求 `PlatformHint::Linux` 会稳定返回
`platform.mismatch`。Linux 内核 session 仍可通过现有低层 Rust 模块使用，待统一宿主契约后再
进入 `starmem::api`。

如果不显式提供 `profile_path` 或 `pdb_path`，Windows session 保留现有的精确符号自动解析
行为。对严格离线部署，应预先准备本地 PDB/profile，并在请求中显式指定。`search_roots` 是
本次会话的只读根，`cache_root` 是 StarMem 自己的可写缓存。

## 运行只读插件

命令只能使用 `command_catalog()` 中的稳定 `command_id`，不接受 CLI alias。Host API v1
支持 Windows 可读 catalog 以及参数化的 `windows.process-string`：

```rust
use serde_json::{Map, Value, json};
use starmem::api::{ExecutionContext, RunRequest};

let arguments = json!({"result_limit": 65536});
let response = session.run(
    RunRequest {
        integration_api_version: starmem::INTEGRATION_API_VERSION,
        request_id: "pslist-001".to_owned(),
        command_id: "pslist".to_owned(),
        arguments: arguments.as_object().cloned().unwrap_or_else(Map::new),
    },
    &ExecutionContext::default(),
)?;

assert_eq!(response.envelope.command, "pslist");
assert!(response.envelope.data.is_object());
# let _: Value = response.envelope.data;
# Ok::<(), starmem::api::ApiError>(())
```

正常的证据源不可用仍是 `Ok(RunResponse)`，由 Envelope 的 `available=false` 表达；参数、I/O、
初始化、取消和执行故障才返回 `ApiError`。每个成功插件都返回完整
`EvidenceEnvelope<Value>`，LovelyMem 不应再从 stdout 或固定 CSV 文件名猜字段。

字符串进程归属使用专门参数 DTO：

```rust
use serde_json::{Map, to_value};
use starmem::api::{ExecutionContext, ProcessStringArguments, RunRequest};

let arguments = to_value(ProcessStringArguments::new("示例表格.xlsx"))?
    .as_object()
    .cloned()
    .unwrap_or_else(Map::new);
let response = session.run(
    RunRequest {
        integration_api_version: starmem::INTEGRATION_API_VERSION,
        request_id: "string-owner-001".to_owned(),
        command_id: "windows.process-string".to_owned(),
        arguments,
    },
    &ExecutionContext::default(),
)?;
# let _ = response;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## 取消、进度与错误

- 每个 LovelyMem 任务创建独立 `CancellationHandle`，把 `start()` 返回的 token 放入
  `ExecutionContext`；不要让并发任务共享同一个 handle。
- `ExecutionContext` 的 `ProgressSink` 是请求级的，事件包含 `request_id`、`command_id`、
  phase、unit、current/total 和 state；每个已启动请求只产生一个终态事件。
- 旧 `starmem::progress::install_progress_observer` 是 CLI 兼容用的进程级单次安装接口，GUI 不应
  用它隔离并发任务。
- 取消是 cooperative。`windows.process-string` 在物理扫描块、DTB、命中、alias 和 owner 循环
  检查 token；一个已经开始的、有界页表遍历会先完成再响应取消。
- 稳定错误码包括 `api.version-mismatch`、`request.invalid`、`command.unknown`、
  `command.unsupported`、`platform.mismatch`、`session.open-failed`、`task.cancelled` 和
  `analysis.failed`。界面逻辑应匹配 `code`，不要匹配本地化 message。

Host API v1 只运行无外部写出的只读命令，因此 `artifacts` 当前为空。后续写出型 runner 只有在
`OutputPolicy` 完成输入别名检查和原子发布后，才允许把文件加入 `artifacts`。

## 发布前集成门禁

1. `cargo test --all-targets --all-features`、Clippy 和 JSON Schema 验证通过；
2. 从最终 `.crate` 解包到一个全新的宿主工程编译，确保不依赖 StarMem 自己的 lockfile 解析；
3. LovelyMem 精确锁定 StarMem 版本或 Git revision；
4. 对 `pslist`、`system-info`、`windows.process-string` 分别验证 Envelope、取消与进度路由；
5. 发布清单分别记录 LovelyMem lockfile 和 StarMem `VERSION`/`BUILD_ID`，不要混为一个身份。
