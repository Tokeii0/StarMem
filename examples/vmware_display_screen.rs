use std::fs::OpenOptions;
use std::io::BufWriter;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use starmem::cancellation::CancellationToken;
use starmem::live::discover_vmware;
use starmem::live::display::{DisplayGeometry, capture_display_buffer, discover_display_buffers};
use starmem::output_policy::{OutputPolicy, OutputTarget};

#[derive(Parser)]
#[command(about = "只读 VMware 进程显示缓冲内存，导出客户机像素候选；不使用 VNC 或截屏 API")]
struct Args {
    #[arg(long)]
    pid: u32,
    #[arg(long)]
    created_filetime: u64,
    #[arg(long)]
    width: u32,
    #[arg(long)]
    height: u32,
    #[arg(long)]
    stride: Option<u32>,
    /// Restrict capture to an explicitly verified candidate host address.
    #[arg(long, value_parser = parse_address)]
    address: Option<u64>,
    #[arg(long)]
    output: PathBuf,
}

fn parse_address(text: &str) -> Result<u64, String> {
    text.strip_prefix("0x")
        .map_or_else(
            || text.parse::<u64>(),
            |value| u64::from_str_radix(value, 16),
        )
        .map_err(|error| error.to_string())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let geometry = DisplayGeometry {
        width: args.width,
        height: args.height,
        stride: args
            .stride
            .unwrap_or(args.width.checked_mul(4).context("宽度溢出")?),
    };
    let bytes = geometry.byte_length()?;
    ensure!(!args.output.exists(), "输出目录必须尚不存在");
    let token = CancellationToken::new();
    let discovery = discover_vmware(&token)?;
    let target = discovery
        .targets
        .iter()
        .find(|target| target.process.pid == args.pid)
        .with_context(|| {
            format!(
                "所选 VMware 不可用：{}",
                serde_json::to_string(&discovery).unwrap_or_default()
            )
        })?;
    ensure!(
        target.process.created_filetime == args.created_filetime,
        "进程创建时间已改变，请重新发现"
    );
    let candidates = discover_display_buffers(&target.process, geometry, &token)?;
    let selected = candidates
        .iter()
        .filter(|buffer| {
            args.address
                .is_none_or(|address| buffer.host_address == address)
        })
        .collect::<Vec<_>>();
    ensure!(
        bytes * selected.len() <= 128 * 1024 * 1024,
        "本轮候选超过 128 MiB，请用 --address 指定已核对的缓冲区"
    );
    std::fs::create_dir(&args.output)?;
    let mut frames = Vec::new();
    let mut errors = Vec::new();
    for buffer in selected {
        match capture_display_buffer(buffer, &token) {
            Ok(frame) => {
                let path = args.output.join(format!(
                    "vmware-memory-{:016x}-{}x{}.bmp",
                    buffer.host_address, geometry.width, geometry.height
                ));
                let mut policy = OutputPolicy::new(false);
                policy.output(OutputTarget::file("vmware-display-frame", &path));
                policy.preflight()?;
                policy.write_file_atomic(&path, |file| frame.write_bmp(BufWriter::new(file)))?;
                eprintln!(
                    "已读取 {:#x}：{} 字节，{} 微秒，{}",
                    buffer.host_address,
                    frame.read_bytes,
                    frame.elapsed_micros,
                    path.display()
                );
                frames.push(serde_json::json!({ "observation": frame, "output": path }));
            }
            Err(error) => {
                errors.push(serde_json::json!({ "buffer": buffer, "error": format!("{error:#}") }))
            }
        }
    }
    let report = serde_json::json!({ "starmem_version": starmem::VERSION, "build_id": starmem::BUILD_ID,
        "process": target.process, "geometry_source": "caller_supplied", "geometry": geometry,
        "atomic_snapshot": false, "current_scanout_proven": false,
        "warning": "尺寸匹配仅产生像素候选，可能包含备用或残留表面；需核对内容和行跨度，不证明当前 scanout",
        "candidates": candidates, "frames": frames, "errors": errors });
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.output.join("vmware-memory-screen.json"))?;
    serde_json::to_writer_pretty(file, &report)?;
    ensure!(
        !frames.is_empty(),
        "没有读取到像素候选，详见报告；核对分辨率、行跨度及分配方式"
    );
    ensure!(errors.is_empty(), "部分候选读取失败，详见报告");
    Ok(())
}
