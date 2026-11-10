use super::*;

pub(super) fn analyze(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    match options.module.as_str() {
        "uptime" => uptime(m, report),
        "meminfo" => super::meminfo::analyze(m, options, cancel, report),
        "cpuinfo" => cpuinfo(m, report),
        "btf" => super::btf::analyze(m, options, cancel, report),
        "routes" => super::routes::analyze(m, options, cancel, report),
        _ => anyhow::bail!("未注册的系统分析模块"),
    }
}

fn uptime(m: &impl LinuxKernelMemory, report: &mut LinuxIrReport) -> Result<()> {
    let core = m.runtime_symbol("tk_core")?;
    let ty = m.isf().symbol_type_name("tk_core").unwrap_or("tk_data");
    let tk = member(m, core, ty, "timekeeper")?;
    let mono = member(m, tk, "timekeeper", "tkr_mono")?;
    let base = field(m, mono, "tk_read_base", "base")? as i64;
    let shift = field(m, mono, "tk_read_base", "shift")?;
    ensure!(shift < 64, "timekeeper 纳秒移位无效");
    let fraction = field(m, mono, "tk_read_base", "xtime_nsec")? >> shift;
    let mono_ns = base
        .checked_add(i64::try_from(fraction)?)
        .context("单调时钟溢出")?;
    let suspend_ns = field(m, tk, "timekeeper", "offs_boot")? as i64;
    let uptime_ns = mono_ns.checked_add(suspend_ns).context("运行时间溢出")?;
    ensure!(
        mono_ns >= 0 && suspend_ns >= 0 && uptime_ns >= 0,
        "timekeeper 时钟区间无效"
    );
    let sequence = member(m, core, ty, "seq").and_then(|seq| {
        // seqcount_t and seqcount_raw_spinlock_t wrap the same sequence, but use ISF offsets.
        field(m, seq, "seqcount", "sequence").or_else(|_| {
            let inner = member(m, seq, "seqcount_raw_spinlock", "seqcount")?;
            field(m, inner, "seqcount", "sequence")
        })
    });
    match &sequence {
        Ok(value) if value & 1 != 0 => report.warn("timekeeper 序列为奇数，采集时可能正在更新"),
        Err(error) => report.warn(format!("无法核对 timekeeper 更新序列：{error:#}")),
        _ => {}
    }
    report.scope = "根时间 namespace 的 timekeeper 最后一次更新；未读取硬件时钟增量".into();
    report.push(
        json!({"uptime_ns":uptime_ns,"uptime_seconds":uptime_ns as f64 / 1e9,
        "monotonic_ns":mono_ns,"suspend_ns":suspend_ns,"sequence":sequence.ok(),
        "clock_precision":"coarse_last_update","timekeeper":tk,
        "basis":"tkr_mono.base + (tkr_mono.xtime_nsec >> shift) + offs_boot"}),
    );
    Ok(())
}

fn cpuinfo(m: &impl LinuxKernelMemory, report: &mut LinuxIrReport) -> Result<()> {
    let cpu = m.runtime_symbol("boot_cpu_data")?;
    m.isf().type_size("cpuinfo_x86")?;
    let mut row = json!({"cpuinfo_address":cpu,"cpu_scope":"boot CPU; not all logical CPUs"});
    let mut fields = 0;
    for key in [
        "x86",
        "x86_vendor",
        "x86_model",
        "x86_stepping",
        "x86_cache_size",
    ] {
        match field(m, cpu, "cpuinfo_x86", key) {
            Ok(value) => {
                row[key] = json!(value);
                fields += 1;
            }
            Err(error) => report.warn(format!("{key}: {error:#}")),
        }
    }
    for key in ["x86_vendor_id", "x86_model_id"] {
        match inline_string(m, cpu, "cpuinfo_x86", key) {
            Ok(value) => {
                row[key] = json!(value);
                fields += 1;
            }
            Err(error) => report.warn(format!("{key}: {error:#}")),
        }
    }
    ensure!(fields > 0, "boot_cpu_data 中没有可核对字段");
    report.push(row);
    Ok(())
}

pub(super) fn btf_header(bytes: &[u8], total: u64) -> Result<Value> {
    ensure!(
        bytes.len() >= 24 && bytes[..2] == [0x9f, 0xeb],
        "无有效小端 BTF 标记"
    );
    ensure!(bytes[2] == 1 && bytes[3] == 0, "不支持的 BTF 版本/标志");
    let word = |at: usize| {
        u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded header")) as u64
    };
    let header = word(4);
    let type_offset = word(8);
    let type_size = word(12);
    let str_offset = word(16);
    let str_size = word(20);
    ensure!(
        header >= 24 && header <= total && type_offset % 4 == 0 && str_size > 0,
        "BTF 区段布局无效"
    );
    let type_start = add(header, type_offset)?;
    let type_end = add(type_start, type_size)?;
    let str_start = add(header, str_offset)?;
    let str_end = add(str_start, str_size)?;
    ensure!(
        type_end <= total && str_end <= total && (type_end <= str_start || str_end <= type_start),
        "BTF 区段越界或重叠"
    );
    Ok(
        json!({"version":1,"header_size":header,"type_offset":type_start,"type_bytes":type_size,
        "string_offset":str_start,"string_bytes":str_size,"total_bytes":total}),
    )
}
