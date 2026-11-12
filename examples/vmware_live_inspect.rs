//! Bounded read-only integration probe; no guest execution or memory writes.
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde::Serialize;
use starmem::cancellation::CancellationToken;
use starmem::live::{VmwareLayout, VmwareLiveReader, discover_vmware};
use starmem::live_windows::{LiveProcessIdentity, LiveWindowsSession};
use starmem::resources::{AnalysisExecutor, AnalysisResourceLimits};
use starmem::session::SessionOptions;

#[derive(Parser)]
#[command(about = "VMware 实时只读进程详情 / 模块 / 网络开发验证")]
struct Args {
    #[arg(long)]
    pid: u32,
    #[arg(long)]
    created_filetime: u64,
    #[arg(long, required = true)]
    accept_workstation_layout: bool,
    #[arg(long)]
    pdb: Option<PathBuf>,
    #[arg(long)]
    symbol_path: Option<PathBuf>,
    /// 客户机 PID，仅从本轮实际 pslist 获取其完整身份
    #[arg(long)]
    guest_pid: Option<u64>,
    #[arg(long)]
    network: bool,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=20))]
    samples: u32,
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(100..=60000))]
    interval_ms: u64,
    /// 新目录，保留每轮独立结果及运行终态
    #[arg(long)]
    output: PathBuf,
}

fn save(path: PathBuf, report: &impl Serialize) -> Result<()> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(file, report)?;
    Ok(())
}

fn run(args: &Args) -> Result<()> {
    let token = CancellationToken::new();
    let discovery = discover_vmware(&token)?;
    save(args.output.join("discovery.json"), &discovery)?;
    let target = discovery
        .targets
        .iter()
        .find(|v| v.process.pid == args.pid)
        .context("没有可读取的目标，请查看 discovery.json 的 issues")?;
    ensure!(
        target.process.created_filetime == args.created_filetime,
        "VMware 进程身份已改变"
    );
    let reader = VmwareLiveReader::attach(target, VmwareLayout::Workstation3GbHole, &token)?;
    let mut options = SessionOptions {
        pdb: args.pdb.clone(),
        ..SessionOptions::default()
    };
    if let Some(path) = &args.symbol_path {
        options.symbol_store.add_search_root(path.clone());
    }
    eprintln!("connecting: 定位客户机内核与精确符号");
    let executor = AnalysisExecutor::new(AnalysisResourceLimits::new(2, 512 * 1024 * 1024)?)?;
    executor.install(|| -> Result<()> {
        let started = Instant::now();
        let mut session = LiveWindowsSession::open(reader, options, token)?;
        eprintln!("connected: {} ms", started.elapsed().as_millis());
        let mut identity = None;
        for sample in 1..=args.samples {
            let processes = session.processes(4096)?;
            eprintln!(
                "sample {sample} pslist: {} records, complete={}, {} ms",
                processes.report.processes.len(),
                processes.report.complete,
                processes.elapsed_micros / 1000
            );
            if identity.is_none()
                && let Some(pid) = args.guest_pid
            {
                let record = processes
                    .report
                    .processes
                    .iter()
                    .find(|p| p.pid == pid)
                    .context("客户机 pslist 中没有所选 PID")?;
                identity = Some(LiveProcessIdentity::from_record(
                    &processes.source.session_id,
                    record,
                )?);
            }
            save(
                args.output.join(format!("{sample:02}-processes.json")),
                &processes,
            )?;
            if let Some(identity) = &identity {
                let details = session.process_details(identity, 4096)?;
                eprintln!(
                    "sample {sample} details: {} modules, complete={}, {} ms",
                    details.report.modules.records.len(),
                    details.report.complete,
                    details.elapsed_micros / 1000
                );
                save(
                    args.output.join(format!("{sample:02}-details.json")),
                    &details,
                )?;
            }
            if args.network {
                let network = session.netstat(16_384)?;
                eprintln!(
                    "sample {sample} netstat: {} records, complete={}, {} ms",
                    network.report.records.len(),
                    network.report.complete,
                    network.elapsed_micros / 1000
                );
                save(
                    args.output.join(format!("{sample:02}-network.json")),
                    &network,
                )?;
            }
            if sample < args.samples {
                std::thread::sleep(Duration::from_millis(args.interval_ms));
            }
        }
        session.stop()
    })
}

fn main() -> Result<()> {
    let args = Args::parse();
    std::fs::create_dir(&args.output).context("输出目录必须尚不存在")?;
    let started = Instant::now();
    let result = run(&args);
    let status = serde_json::json!({
        "version": starmem::VERSION, "build_id": starmem::BUILD_ID,
        "read_only": true, "success": result.is_ok(),
        "elapsed_ms": started.elapsed().as_millis(),
        "requested_samples": args.samples,
        "error": result.as_ref().err().map(|e| format!("{e:#}")),
    });
    serde_json::to_writer_pretty(File::create(args.output.join("run.json"))?, &status)?;
    result
}
