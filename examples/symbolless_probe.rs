//! An image-only prototype runner. No symbol/profile/cache input exists.
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde_json::json;
use sha2::{Digest, Sha256};
use starmem::cancellation::CancellationToken;
use starmem::image::MemoryImage;
use starmem::output_policy::{OutputPolicy, OutputTarget};
use starmem::windows::symbolless::{ProbeReport, files};

#[derive(Parser)]
#[command(about = "实验性 Windows x64 无外部符号进程解析，仅接受内存镜像")]
struct Args {
    #[arg(long)]
    image: PathBuf,
    #[arg(long)]
    report: PathBuf,
    #[arg(long, default_value_t = 4096)]
    limit: usize,
    /// 扫描有可读名称及有效关联对象的 FILE_OBJECT。
    #[arg(long)]
    filescan: bool,
    #[arg(long, default_value_t = 100_000)]
    file_limit: usize,
    /// 文件名子串，在结果上限和反向映射之前筛选。
    #[arg(long, requires = "filescan")]
    file_filter: Option<String>,
    /// 导出经过归属验证的驻留缓存，并保存逐区间说明。
    #[arg(long, requires = "filescan")]
    export_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 5)]
    export_count: usize,
    #[arg(long, default_value_t = 8)]
    max_file_mib: u64,
}

fn sha256(path: &std::path::Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 64 * 1024];
    loop {
        let read = file.read(&mut bytes)?;
        if read == 0 {
            break;
        }
        hash.update(&bytes[..read]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn export_cache(
    args: &Args,
    image: &MemoryImage,
    kernel: &ProbeReport,
    scan: &files::FileScanReport,
    sources: &serde_json::Value,
    cancel: &CancellationToken,
) -> Result<serde_json::Value> {
    let Some(directory) = &args.export_dir else {
        return Ok(serde_json::Value::Null);
    };
    let mut attempts = Vec::new();
    let mut exported = 0;
    for record in &scan.records {
        if exported == args.export_count || attempts.len() == 256 {
            break;
        }
        if record.shared_cache_map.is_none_or(|value| value == 0) {
            continue;
        }
        let attempt = (|| -> Result<serde_json::Value> {
            let plan = files::plan_cache(
                image,
                kernel,
                record,
                args.max_file_mib * 1024 * 1024,
                cancel,
            )?;
            let suffix = if plan.complete { "bin" } else { "partial" };
            let path = directory.join(format!("{:016x}.cache.{suffix}", record.file_object));
            let metadata =
                directory.join(format!("{:016x}.cache.recovery.json", record.file_object));
            let mut policy = OutputPolicy::new(false);
            for source in image.sources() {
                policy.protect_file("image_source", &source.path);
            }
            policy.protect_file("main_report", &args.report);
            policy
                .output_file("cache_content", &path)
                .output_file("recovery_metadata", &metadata);
            policy.preflight()?;
            let mut valid_hash = String::new();
            policy.write_file_atomic(&path, |file| {
                valid_hash = files::write_cache(image, &plan, file, cancel)?;
                Ok(())
            })?;
            let output_hash = sha256(&path)?;
            let result = json!({"success":true,"output":path,"metadata":metadata,
                "output_sha256":output_hash,"valid_bytes_sha256":valid_hash,
                "valid_hash_scope":"recovered bytes in file-offset order; offsets and holes are in plan",
                "external_debug_symbols_used":false,"source_identity":sources,
                "engine_build_id":starmem::BUILD_ID,"plan":plan});
            policy
                .write_file_atomic(&metadata, |file| {
                    serde_json::to_writer_pretty(file, &result)?;
                    Ok(())
                })
                .with_context(|| format!("内容已写到 {}，恢复说明写入失败", path.display()))?;
            Ok(result)
        })();
        match attempt {
            Ok(result) => {
                attempts.push(result);
                exported += 1;
            }
            Err(error) => attempts.push(json!({"success":false,"file_object":record.file_object,
                "name":record.name,"error":format!("{error:#}")})),
        }
    }
    Ok(
        json!({"success":exported>0,"exported":exported,"requested":args.export_count,"attempt_limit":256,
        "error":if exported==0 {Some("没有成功恢复的缓存文件；查看 attempts 中的原因")} else {None},
        "attempt_limit_reached":attempts.len()==256,"source":"shared_cache_map_only","attempts":attempts}),
    )
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        (1..=32).contains(&args.export_count),
        "导出数量必须为 1..32"
    );
    ensure!(
        (1..=64).contains(&args.max_file_mib),
        "单文件上限必须为 1..64 MiB"
    );
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build_global()?;
    let image = MemoryImage::open(&args.image)?;
    let mut policy = OutputPolicy::new(false);
    for source in image.sources() {
        policy.protect_file("image_source", &source.path);
    }
    policy.output_file("report", &args.report);
    if let Some(directory) = &args.export_dir {
        policy.output(OutputTarget::directory("exports", directory));
    }
    policy.preflight()?;
    policy.prepare_directories()?;
    let mut sources = Vec::new();
    for source in image.sources() {
        sources.push(json!({"source": source, "sha256": sha256(&source.path)?}));
    }
    let sources = json!(sources);
    let started = Instant::now();
    let cancel = CancellationToken::new();
    let result = starmem::windows::symbolless::probe(&image, args.limit, &cancel);
    let mut success = result.is_ok();
    let mut file_scan = serde_json::Value::Null;
    let mut exports = serde_json::Value::Null;
    let result = match result {
        Ok(report) => {
            if args.filescan {
                match files::scan(
                    &image,
                    &report,
                    args.file_limit,
                    args.file_filter.as_deref(),
                    &cancel,
                ) {
                    Ok(scan) => {
                        exports = export_cache(&args, &image, &report, &scan, &sources, &cancel)?;
                        if args.export_dir.is_some() && exports["success"] == false {
                            success = false;
                        }
                        file_scan = serde_json::to_value(scan)?;
                    }
                    Err(error) => {
                        success = false;
                        file_scan = json!({"complete":false,"error":format!("{error:#}")});
                    }
                }
            }
            serde_json::to_value(report)?
        }
        Err(error) => json!({"complete": false, "error": format!("{error:#}")}),
    };
    let output = json!({"schema_version": 2, "success": success,
        "engine_version": starmem::VERSION, "engine_build_id": starmem::BUILD_ID,
        "command": std::env::args_os().map(|arg| arg.to_string_lossy().into_owned()).collect::<Vec<_>>(),
        "threads": 2, "format": image.format(), "sources": sources,
        "elapsed_analysis_ms": started.elapsed().as_secs_f64() * 1000.0,
        "external_symbols": "disabled_by_construction_no_symbol_store_or_profile",
        "report": result,"filescan":file_scan,"exports":exports});
    policy.write_file_atomic(&args.report, |file| {
        serde_json::to_writer_pretty(file, &output)?;
        Ok(())
    })?;
    println!(
        "{}",
        json!({"success":success,"report":args.report,
        "processes":output["report"]["processes"].as_array().map(Vec::len),
        "files":output["filescan"]["records"].as_array().map(Vec::len),
        "exported":output["exports"]["exported"],
        "elapsed_analysis_ms":output["elapsed_analysis_ms"],"error":output["report"]["error"]})
    );
    ensure!(success, "无符号原型未能完成推断，原因已保存到报告");
    Ok(())
}
