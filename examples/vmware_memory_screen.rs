use std::fs::OpenOptions;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use starmem::cancellation::CancellationToken;
use starmem::live::{VmwareLayout, VmwareLiveReader, discover_vmware};
use starmem::live_windows::LiveWindowsSession;
use starmem::session::SessionOptions;

#[derive(Parser)]
#[command(about = "从 VMware 客户机内存恢复 DWM 像素，不调用截屏 API、VNC 或客户机程序")]
struct Args {
    #[arg(long)]
    pid: u32,
    #[arg(long)]
    created_filetime: u64,
    #[arg(long, required = true)]
    accept_workstation_layout: bool,
    #[arg(long)]
    symbol_path: Option<PathBuf>,
    #[arg(long)]
    pdb: Option<PathBuf>,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 4096)]
    max_dimension: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(!args.output.exists(), "输出目录已存在，请指定新的截图目录");
    eprintln!("阶段：发现所选 VMware 进程及内存映射");
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
        eprintln!("阶段：解析客户机精确内核符号并验证启动锚点");
        let mut session = LiveWindowsSession::open(reader, options, token)?;
        eprintln!("阶段：从客户机 DWM 地址空间恢复像素");
        let observation = session.recover_memory_frames(&args.output, args.max_dimension)?;
        let path = args.output.join("live-memory-screen.json");
        let report = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        serde_json::to_writer_pretty(report, &observation)?;
        eprintln!(
            "完成：{} 个像素帧，complete={}，报告 {}",
            observation.report.frames.len(),
            observation.report.complete,
            path.display()
        );
        session.stop()?;
        ensure!(
            !observation.report.frames.is_empty(),
            "没有从当前客户机内存恢复到可验证的 DWM 像素帧；原因已保存到报告"
        );
        Ok(())
    })
}
