use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use starmem::cancellation::CancellationToken;
use starmem::live::{VmwareLayout, VmwareLiveReader, discover_vmware};
use starmem::live_windows::LiveWindowsSession;
use starmem::session::SessionOptions;

#[derive(Parser)]
#[command(about = "从所选 VMware 实时内存刷新 Windows x64 进程列表（实验性布局）")]
struct Args {
    #[arg(long)]
    pid: u32,
    #[arg(long)]
    created_filetime: u64,
    /// 必须显式接受当前原型的 3–4 GiB 空洞布局
    #[arg(long, required = true)]
    accept_workstation_layout: bool,
    #[arg(long)]
    symbol_path: Option<PathBuf>,
    #[arg(long)]
    pdb: Option<PathBuf>,
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..=1000))]
    samples: u32,
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(100..=60000))]
    interval_ms: u64,
    #[arg(long, default_value_t = 4096)]
    limit: usize,
    #[arg(long)]
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!((1..=65_536).contains(&args.limit), "limit 必须为 1–65536");
    let token = CancellationToken::new();
    let discovery = discover_vmware(&token)?;
    let target = discovery
        .targets
        .iter()
        .find(|target| target.process.pid == args.pid)
        .with_context(|| {
            format!(
                "所选 VM 不可用：{}",
                serde_json::to_string(&discovery).unwrap_or_default()
            )
        })?;
    ensure!(
        target.process.created_filetime == args.created_filetime,
        "VM 进程创建时间不匹配，请重新发现目标"
    );
    let reader = VmwareLiveReader::attach(target, VmwareLayout::Workstation3GbHole, &token)?;
    let mut options = SessionOptions {
        pdb: args.pdb,
        ..SessionOptions::default()
    };
    if let Some(path) = args.symbol_path {
        options.symbol_store.add_search_root(path);
    }
    let executor = starmem::resources::AnalysisExecutor::new(
        starmem::resources::AnalysisResourceLimits::new(2, 512 * 1024 * 1024)?,
    )?;
    executor.install(|| -> Result<()> {
        let mut session = LiveWindowsSession::open(reader, options, token)?;
        let mut output = BufWriter::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&args.output)?,
        );
        for index in 0..args.samples {
            let observation = session.processes(args.limit)?;
            eprintln!(
                "sample {}: {} processes, complete={}, {} ms",
                observation.sequence,
                observation.report.processes.len(),
                observation.report.complete,
                observation.elapsed_micros / 1000
            );
            serde_json::to_writer(&mut output, &observation)?;
            output.write_all(b"\n")?;
            output.flush()?;
            if index + 1 < args.samples {
                std::thread::sleep(Duration::from_millis(args.interval_ms));
            }
        }
        session.stop()
    })
}
