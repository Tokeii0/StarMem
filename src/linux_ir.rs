//! Linux incident-response analyses built on validated StarMem sessions.
//!
//! Missing symbols/pages remain unavailable or partial evidence. Heuristic findings are
//! leads, never a malware verdict. This module does not invoke any external engine.

mod btf;
mod files;
mod framebuffer;
mod hunting;
mod journal;
mod kernel;
mod meminfo;
mod process;
mod routes;
mod scan;
mod system;
#[cfg(test)]
mod tests;
mod timeline;

use crate::cancellation::CancellationToken;
use crate::linux::{LinuxAnalysisSession, LinuxX64AddressSpace};
use crate::linux_kernel_plugins::LinuxKernelMemory;
use crate::linux_symbols::LinuxIsf;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashSet;

pub const TASK_MODULES: &[&str] = &[
    "pslist",
    "threads",
    "kthreads",
    "capabilities",
    "credentials",
    "check-creds",
    "ptrace",
    "elfs",
    "library-list",
    "malfind",
    "files",
    "file-content",
    "persistence",
    "logs",
    "timeline",
    "psxview",
    "psscan",
    "perf-events",
    "callstack",
    "cwd",
    "dns",
    "triage",
    "indicators",
    "av-edr",
    "entropy",
    "journald",
    "crash-summary",
    "crash-traces",
    "crash-events",
    "pagecache-recovery",
    "timeline-network",
    "timeline-findings",
    "timeline-summary",
];
pub const KERNEL_MODULES: &[&str] = &[
    "system",
    "boottime",
    "iomem",
    "ip-addr",
    "ip-link",
    "arp",
    "check-idt",
    "keyboard-notifiers",
    "tty-check",
    "ebpf",
    "kprobes",
    "ftrace",
    "tracepoints",
    "netfilter",
    "check-afinfo",
    "fbdev",
    "pidhashtable",
    "uptime",
    "meminfo",
    "cpuinfo",
    "btf",
    "routes",
];

#[derive(Debug, Clone)]
pub struct LinuxIrOptions {
    pub module: String,
    pub pid: Option<i32>,
    pub limit: usize,
    pub max_bytes: u64,
    pub path: Option<String>,
    pub framebuffer_output: Option<std::path::PathBuf>,
}

impl Default for LinuxIrOptions {
    fn default() -> Self {
        Self {
            module: "pslist".into(),
            pid: None,
            limit: 65_536,
            max_bytes: 1024 * 1024,
            path: None,
            framebuffer_output: None,
        }
    }
}

impl LinuxIrOptions {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.limit > 0 && self.limit <= 1_000_000,
            "记录上限须为 1..1000000"
        );
        ensure!(
            self.max_bytes > 0 && self.max_bytes <= 64 * 1024 * 1024,
            "单项读取上限须为 1..67108864 字节"
        );
        ensure!(self.pid.is_none_or(|pid| pid >= 0), "PID 不能为负数");
        ensure!(
            self.framebuffer_output.is_none() || self.module == "fbdev",
            "--framebuffer-output 仅适用于 fbdev 模块"
        );
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct LinuxIrReport {
    pub source: &'static str,
    pub module: String,
    pub scope: String,
    pub available: bool,
    pub complete: bool,
    pub record_count: usize,
    pub records: Vec<Value>,
    pub warnings: Vec<String>,
    pub missing_ranges: Vec<Value>,
    pub limit: usize,
    pub limit_reached: bool,
}

impl LinuxIrReport {
    fn new(options: &LinuxIrOptions, scope: &str) -> Self {
        Self {
            source: "StarMem Linux",
            module: options.module.clone(),
            scope: scope.into(),
            available: true,
            complete: true,
            record_count: 0,
            records: Vec::new(),
            warnings: Vec::new(),
            missing_ranges: Vec::new(),
            limit: options.limit,
            limit_reached: false,
        }
    }
    fn warn(&mut self, message: impl Into<String>) {
        self.complete = false;
        if self.warnings.len() < 128 {
            self.warnings.push(message.into());
        }
    }
    fn unavailable(&mut self, message: impl Into<String>) {
        self.available = false;
        self.warn(message);
    }
    fn push(&mut self, value: Value) -> bool {
        if self.records.len() >= self.limit {
            self.limit_reached = true;
            self.complete = false;
            return false;
        }
        self.records.push(value);
        self.record_count = self.records.len();
        true
    }
}

pub fn run_task(
    session: &LinuxAnalysisSession,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    options.validate()?;
    cancel.check_cancelled()?;
    ensure!(
        TASK_MODULES.contains(&options.module.as_str()),
        "未知 Linux 进程/文件分析模块：{}",
        options.module
    );
    match options.module.as_str() {
        "psscan" => scan::tasks(session, options, cancel),
        "pslist" => {
            let mut report = session.processes(options.limit)?;
            if let Some(pid) = options.pid {
                report.processes.retain(|p| p.pid == pid);
            }
            Ok(serde_json::to_value(report)?)
        }
        "files" => Ok(serde_json::to_value(session.files(options.limit)?)?),
        "psxview" => {
            let memory = TaskMemory::new(session)?;
            let mut report = run_kernel(
                &memory,
                &LinuxIrOptions {
                    module: "pidhashtable".into(),
                    ..options.clone()
                },
                cancel,
            )?;
            report.module = "psxview".into();
            let active = session.processes(options.limit)?;
            if !active.complete {
                report.warn("活动进程链不完整；交叉视图差异不能直接解释为隐藏进程");
            }
            let active_tasks: HashSet<_> = active.processes.iter().map(|task| task.task).collect();
            for row in &mut report.records {
                row["in_active_list"] = json!(
                    row["task"]
                        .as_u64()
                        .is_some_and(|task| active_tasks.contains(&task))
                );
                row["active_list_scope"] = json!("线程组主进程");
                row["assessment"] =
                    json!("来源差异需结合线程、退出过程和缺页复核；不能单独确认隐藏");
            }
            Ok(serde_json::to_value(report)?)
        }
        "file-content" | "persistence" | "logs" | "timeline" | "dns" | "pagecache-recovery" => {
            files::analyze(session, options, cancel)
        }
        "triage" | "indicators" | "av-edr" | "entropy" => {
            hunting::analyze(session, options, cancel)
        }
        "journald" | "crash-summary" | "crash-traces" | "crash-events" => {
            journal::analyze(session, options, cancel)
        }
        "timeline-network" | "timeline-findings" | "timeline-summary" => {
            timeline::analyze(session, options, cancel)
        }
        _ => process::analyze(session, options, cancel),
    }
}

pub fn run_kernel(
    memory: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
) -> Result<LinuxIrReport> {
    options.validate()?;
    cancel.check_cancelled()?;
    ensure!(
        KERNEL_MODULES.contains(&options.module.as_str()),
        "未知 Linux 内核分析模块：{}",
        options.module
    );
    let mut report = LinuxIrReport::new(
        options,
        "精确 ISF 与已验证内核页表中的驻留结构；不涵盖交换区或未采集页",
    );
    if let Err(error) = kernel::analyze(memory, options, cancel, &mut report) {
        if crate::cancellation::is_cancellation_error(&error) {
            return Err(error);
        }
        if report.records.is_empty() {
            report.unavailable(format!("{error:#}"));
        } else {
            report.warn(format!("{error:#}"));
        }
    }
    Ok(report)
}

struct TaskMemory<'a> {
    session: &'a LinuxAnalysisSession,
    space: LinuxX64AddressSpace<'a>,
    symbols: &'a LinuxIsf,
    slide: u64,
}

impl<'a> TaskMemory<'a> {
    fn new(session: &'a LinuxAnalysisSession) -> Result<Self> {
        let kernel = session.kernel();
        let symbols = kernel
            .symbol_table
            .as_deref()
            .context("此模块需要与完整 Linux banner 精确匹配的 ISF 类型")?;
        let slide = kernel
            .init_task
            .checked_sub(symbols.symbol_address("init_task")?)
            .context("内核 slide 下溢")?;
        Ok(Self {
            session,
            space: LinuxX64AddressSpace::new(session.image(), kernel.directory_table_base)?,
            symbols,
            slide,
        })
    }
}

impl LinuxKernelMemory for TaskMemory<'_> {
    fn read_virtual(&self, address: u64, bytes: &mut [u8]) -> Result<()> {
        self.space.read_virtual(address, bytes)
    }
    fn translate(&self, address: u64) -> Result<u64> {
        self.space.translate(address)
    }
    fn isf(&self) -> &LinuxIsf {
        self.symbols
    }
    fn kernel_slide(&self) -> u64 {
        self.slide
    }
    fn source_path(&self) -> Option<&std::path::Path> {
        Some(self.session.image().path())
    }
}

fn add(address: u64, offset: u64) -> Result<u64> {
    address.checked_add(offset).context("Linux 结构地址溢出")
}
fn number(memory: &impl LinuxKernelMemory, address: u64, width: u64) -> Result<u64> {
    ensure!(
        matches!(width, 1 | 2 | 4 | 8),
        "不支持的整数字段宽度 {width}"
    );
    let mut bytes = [0u8; 8];
    memory.read_virtual(address, &mut bytes[..width as usize])?;
    Ok(u64::from_le_bytes(bytes))
}
fn field(memory: &impl LinuxKernelMemory, object: u64, ty: &str, name: &str) -> Result<u64> {
    let offset = memory.isf().field_offset(ty, name)?;
    number(
        memory,
        add(object, offset)?,
        memory.isf().field_size(ty, name)?,
    )
}
fn member(memory: &impl LinuxKernelMemory, object: u64, ty: &str, name: &str) -> Result<u64> {
    add(object, memory.isf().field_offset(ty, name)?)
}
fn pointer(address: u64) -> Result<u64> {
    ensure!(
        address >> 47 == 0x1ffff && address & 7 == 0,
        "非规范或未对齐的内核对象指针 {address:#x}"
    );
    Ok(address)
}
fn string(memory: &impl LinuxKernelMemory, address: u64, limit: usize) -> Result<String> {
    let mut bytes = Vec::new();
    for i in 0..limit {
        let byte = number(memory, add(address, i as u64)?, 1)? as u8;
        if byte == 0 {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.push(byte);
    }
    anyhow::bail!("字符串在 {limit} 字节范围内未终止：{address:#x}")
}
fn inline_string(
    memory: &impl LinuxKernelMemory,
    object: u64,
    ty: &str,
    name: &str,
) -> Result<String> {
    string(
        memory,
        member(memory, object, ty, name)?,
        memory.isf().field_size(ty, name)?.min(4096) as usize,
    )
}
fn list(
    memory: &impl LinuxKernelMemory,
    head: u64,
    offset: u64,
    limit: usize,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<Vec<u64>> {
    pointer(head)?;
    let mut next = number(memory, head, 8)?;
    let mut previous = head;
    let mut seen = HashSet::new();
    let mut objects = Vec::new();
    while next != head {
        cancel.check_cancelled()?;
        if objects.len() >= limit {
            report.limit_reached = true;
            report.warn("链表达到遍历上限");
            break;
        }
        if !seen.insert(next) {
            report.warn(format!("链表出现非头部循环：{next:#x}"));
            break;
        }
        let read = (|| -> Result<(u64, u64)> {
            pointer(next)?;
            ensure!(
                number(memory, add(next, 8)?, 8)? == previous,
                "链表回链不匹配：{next:#x}"
            );
            Ok((
                next.checked_sub(offset).context("链表容器地址下溢")?,
                number(memory, next, 8)?,
            ))
        })();
        match read {
            Ok((object, following)) => {
                objects.push(object);
                previous = next;
                next = following;
            }
            Err(error) => {
                report.warn(format!("{error:#}"));
                return Ok(objects);
            }
        }
    }
    if next == head {
        match number(memory, add(head, 8)?, 8) {
            Ok(tail) if tail == previous => {}
            Ok(_) => report.warn("链表头回链不匹配"),
            Err(error) => report.warn(format!("链表头回链无法读取：{error:#}")),
        }
    }
    Ok(objects)
}

fn row_error(report: &mut LinuxIrReport, object: u64, error: anyhow::Error) {
    report.warn(format!("对象 {object:#x}：{error:#}"));
}
