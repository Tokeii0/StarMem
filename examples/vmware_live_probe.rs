//! Development probe, not a LovelyMem desktop/CLI command.
//! Each JSONL sample contains fresh bytes and comparison with the prior sample.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::json;
use starmem::cancellation::CancellationToken;
use starmem::live::{LiveReadRequest, VmwareLayout, VmwareLiveReader, discover_vmware};

#[derive(Parser)]
#[command(about = "实验性 VMware Workstation 只读采样；物理映射尚须真实虚拟机校验")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 枚举本机 vmware-vmx.exe 及 .vmem 映射；不读取客户机内容
    List,
    /// 显式选择进程身份和布局，输出有限次采样 JSONL
    Sample {
        #[arg(long)]
        pid: u32,
        /// 必须填写 list 返回的创建 FILETIME，避免 PID 重用后选错虚拟机
        #[arg(long)]
        created_filetime: u64,
        /// 显式接受实验性布局假设，不代表布局已验证
        #[arg(long, value_enum)]
        layout: Layout,
        /// 客户机物理地址:字节数，例如 0x1000:64；可重复
        #[arg(long = "range", required = true, value_parser = parse_range)]
        ranges: Vec<LiveReadRequest>,
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=1000))]
        samples: u32,
        /// 上一次读取结束后等待的毫秒数；不是硬实时采样周期
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(20..=60000))]
        interval_ms: u64,
        /// 新建 JSONL 文件，已存在时拒绝覆盖；省略则输出到 stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Layout {
    Workstation3gbHole,
}

fn parse_number(value: &str) -> Result<u64, String> {
    let number = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    };
    number.map_err(|error| error.to_string())
}

fn parse_range(value: &str) -> Result<LiveReadRequest, String> {
    let (address, length) = value.split_once(':').ok_or("范围格式为 物理地址:字节数")?;
    let length = usize::try_from(parse_number(length)?).map_err(|error| error.to_string())?;
    if length == 0 {
        return Err("读取长度必须大于零".to_owned());
    }
    let physical_address = parse_number(address)?;
    physical_address
        .checked_add(length as u64)
        .ok_or("物理地址范围溢出")?;
    Ok(LiveReadRequest {
        physical_address,
        length,
    })
}

fn emit(output: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *output, value)?;
    output.write_all(b"\n")?;
    // Every completed line survives normal process termination / Ctrl+C.
    output.flush()?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let token = CancellationToken::new();
    match args.command {
        Command::List => {
            let discovery = discover_vmware(&token)?;
            println!("{}", serde_json::to_string_pretty(&discovery)?);
        }
        Command::Sample {
            pid,
            created_filetime,
            layout: Layout::Workstation3gbHole,
            ranges,
            samples,
            interval_ms,
            output,
        } => {
            ensure!(
                ranges.len() <= starmem::live::MAX_LIVE_REQUESTS,
                "读取范围数量超限"
            );
            let total = ranges
                .iter()
                .try_fold(0u64, |total, range| total.checked_add(range.length as u64))
                .context("读取总长度溢出")?;
            ensure!(
                total <= starmem::live::MAX_LIVE_BATCH_BYTES as u64,
                "每批采样超过 16 MiB"
            );
            ensure!(
                total
                    .checked_mul(u64::from(samples))
                    .is_some_and(|bytes| bytes <= 64 * 1024 * 1024),
                "探针一次运行的原始读取预算不能超过 64 MiB，请减少范围或次数"
            );
            let discovery = discover_vmware(&token)?;
            if let Some(issue) = discovery.issues.iter().find(|issue| issue.pid == pid) {
                anyhow::bail!("无法连接所选 VMware PID {pid}：{}", issue.message);
            }
            let target = discovery
                .targets
                .iter()
                .find(|target| target.process.pid == pid)
                .context("所选 VMware PID 已不存在，请重新 list")?;
            ensure!(
                target.process.created_filetime == created_filetime,
                "进程创建时间不匹配，PID 可能已重用，请重新 list"
            );
            let mut reader =
                VmwareLiveReader::attach(target, VmwareLayout::Workstation3GbHole, &token)?;
            let mut output: Box<dyn Write> = match output {
                Some(path) => Box::new(BufWriter::new(
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .with_context(|| format!("无法新建 {}", path.display()))?,
                )),
                None => Box::new(std::io::stdout()),
            };
            emit(
                &mut output,
                &json!({"type":"source", "schema_version":1,
                "engine_version":starmem::VERSION, "engine_build_id":starmem::BUILD_ID, "source":reader.source(),
                "limitations":["物理布局是假设，尚未自动验证", "读取是非原子观察", "same_bytes 仅表示两次观察相同，不能排除中间变化", "本探针尚未解析 Windows 证据对象"]}),
            )?;
            let mut incomplete = 0u32;
            for index in 0..samples {
                match reader.read_batch(&ranges, &token) {
                    Ok(batch) => {
                        incomplete += u32::from(!batch.complete);
                        emit(&mut output, &json!({"type":"sample", "batch":batch}))?;
                    }
                    Err(error) => {
                        reader.stop();
                        emit(
                            &mut output,
                            &json!({"type":"error", "message":format!("{error:#}"), "samples_completed":index}),
                        )?;
                        return Err(error);
                    }
                }
                if index + 1 < samples {
                    std::thread::sleep(Duration::from_millis(interval_ms));
                }
            }
            reader.stop();
            emit(
                &mut output,
                &json!({"type":"finished", "samples_completed":samples, "incomplete_samples":incomplete}),
            )?;
        }
    }
    Ok(())
}
