//! Run native Linux modules sequentially while reusing one session per family.
//! Usage: cargo run --example linux_ir_smoke -- IMAGE OUTPUT_DIR [SYMBOL_ROOT]
use anyhow::{Context, Result};
use serde_json::{Value, json};
use starmem::cancellation::CancellationToken;
use starmem::image::MemoryImage;
use starmem::linux::{LinuxAnalysisSession, LinuxKernelSessionOptions, open_linux_kernel_session};
use starmem::linux_ir::{KERNEL_MODULES, LinuxIrOptions, TASK_MODULES, run_kernel, run_task};
use starmem::linux_symbols::LinuxSymbolFeature;
use starmem::resources::{AnalysisExecutor, AnalysisResourceLimits};
use std::path::PathBuf;

fn main() -> Result<()> {
    let args = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    anyhow::ensure!(args.len() >= 2, "IMAGE OUTPUT_DIR [SYMBOL_ROOT]");
    let image = &args[0];
    let requested = std::env::var("STARMEM_IR_MODULES")
        .ok()
        .map(|text| text.split(',').map(str::to_owned).collect::<Vec<_>>());
    let path_filter = std::env::var("STARMEM_IR_PATH").ok();
    let max_bytes = std::env::var("STARMEM_IR_MAX_BYTES")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .context("STARMEM_IR_MAX_BYTES 必须是字节数")?;
    let record_limit = std::env::var("STARMEM_IR_LIMIT")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .context("STARMEM_IR_LIMIT 必须是记录数")?
        .unwrap_or(65_536);
    anyhow::ensure!(
        (1..=1_000_000).contains(&record_limit),
        "STARMEM_IR_LIMIT 必须为 1..1000000"
    );
    let task_budget = max_bytes.unwrap_or(1024 * 1024);
    let kernel_budget = max_bytes.unwrap_or(32 * 1024 * 1024);
    let selected = |module: &str| {
        requested
            .as_ref()
            .is_none_or(|modules| modules.iter().any(|name| name == module))
    };
    let output = &args[1];
    std::fs::create_dir_all(output)?;
    std::fs::write(
        output.join("run.json"),
        serde_json::to_vec_pretty(&json!({
            "image": image, "engine_version": starmem::VERSION, "engine_build_id": starmem::BUILD_ID,
            "threads": 2, "memory_budget_bytes": 2u64 * 1024 * 1024 * 1024,
            "record_limit": record_limit, "content_budget_bytes": task_budget, "kernel_read_budget_bytes": kernel_budget,
            "path_filter": path_filter,
            "task_modules": TASK_MODULES.iter().filter(|module| selected(module)).collect::<Vec<_>>(),
            "kernel_modules": KERNEL_MODULES.iter().filter(|module| selected(module)).collect::<Vec<_>>(),
        }))?,
    )?;
    let mut symbols = starmem::symbols::default_symbol_store();
    if let Some(root) = args.get(2) {
        symbols.add_search_root(root.clone());
    }
    let executor = AnalysisExecutor::new(AnalysisResourceLimits::new(2, 2 * 1024 * 1024 * 1024)?)?;
    executor.install(|| -> Result<()> {
        let mut summary = Vec::new();
        let mut save = |name: &str, value: Result<Value>| -> Result<()> {
            let value = value.unwrap_or_else(|error| json!({"available":false,"complete":false,"error":format!("{error:#}")}));
            let path = output.join(format!("{name}.json"));
            std::fs::write(path, serde_json::to_vec_pretty(&value)?)?;
            let record_count = ["records","processes","modules","mounts","messages","symbols"]
                .iter().find_map(|key| value.get(key).and_then(Value::as_array).map(Vec::len)).unwrap_or(0);
            let status = json!({"plugin":name,"available":value.get("available").and_then(Value::as_bool).unwrap_or(true),
                "complete":value.get("complete"),"records":record_count,"error":value.get("error"),"warnings":value.get("warnings")});
            println!("{name}: available={} complete={} records={record_count}", status["available"], status["complete"]);
            summary.push(status);
            std::fs::write(output.join("summary.json"), serde_json::to_vec_pretty(&summary)?)?;
            Ok(())
        };
        save("linux-info", starmem::linux_info::analyze_linux_info(&MemoryImage::open(image)?).and_then(|v| Ok(serde_json::to_value(v)?)))?;
        match LinuxAnalysisSession::from_image_with_symbol_store(MemoryImage::open(image)?, &symbols) {
            Ok(session) => {
                for module in TASK_MODULES {
                    if !selected(module) { continue; }
                    let options = LinuxIrOptions { module: (*module).into(), limit: record_limit,
                        path: path_filter.clone().or_else(|| (*module == "file-content").then(|| "/etc/passwd".into())),
                        max_bytes: task_budget, ..Default::default() };
                    save(&format!("linux-ir-{module}"), run_task(&session, &options, &CancellationToken::new()))?;
                }
                if requested.is_none() {
                save("linux-psaux", session.psaux(None, record_limit, 1024 * 1024).and_then(|v| Ok(serde_json::to_value(v)?)))?;
                save("linux-sockstat", session.sockstat(None, record_limit, 4096).and_then(|v| Ok(serde_json::to_value(v)?)))?;
                save("linux-crontab-content", run_task(&session, &LinuxIrOptions {
                    module: "file-content".into(), limit: record_limit, path: Some("/etc/crontab".into()), ..Default::default()
                }, &CancellationToken::new()))?;
                save("linux-bash", session.bash(None, record_limit, 65536, 64 * 1024 * 1024, 16384).and_then(|v| Ok(serde_json::to_value(v)?)))?;
                }
            }
            Err(error) => save("task-session", Err(error))?,
        }
        match open_linux_kernel_session(MemoryImage::open(image)?, &symbols,
            [LinuxSymbolFeature::IncidentResponse, LinuxSymbolFeature::Modules, LinuxSymbolFeature::Mount, LinuxSymbolFeature::Kallsyms, LinuxSymbolFeature::Kmsg, LinuxSymbolFeature::Hooks],
            LinuxKernelSessionOptions::default()) {
            Ok(opened) => {
                std::fs::write(output.join("kernel-session.json"), serde_json::to_vec_pretty(&opened.evidence)?)?;
                for module in KERNEL_MODULES {
                    if !selected(module) { continue; }
                    let options = LinuxIrOptions { module: (*module).into(), limit: record_limit,
                        framebuffer_output: (*module == "fbdev").then(|| output.join("framebuffers")),
                        max_bytes: kernel_budget, ..Default::default() };
                    save(&format!("linux-ir-kernel-{module}"), run_kernel(&opened.session, &options, &CancellationToken::new()).and_then(|v| Ok(serde_json::to_value(v)?)))?;
                }
            }
            Err(error) => save("kernel-session", Err(error))?,
        }
        Ok(())
    }).context("Linux native smoke run")
}
