//! Resident global memory counters. Formula references: fs/proc/meminfo.c and
//! include/linux/vmstat.h in the Linux source; this does not reproduce procfs.
use super::*;
use std::cell::{Cell, RefCell};

mod allocations;
mod available;
mod commit;
mod mappings;
const PAGE_KIB: u64 = 4;
const MAX_MAPPINGS: usize = 4096;

struct Memory<'a, M> {
    inner: &'a M,
    cancel: &'a CancellationToken,
    budget: u64,
    attempted: Cell<u64>,
    missing: RefCell<Vec<Value>>,
    cancelled: Cell<bool>,
}

impl<M: LinuxKernelMemory> LinuxKernelMemory for Memory<'_, M> {
    fn read_virtual(&self, address: u64, output: &mut [u8]) -> Result<()> {
        self.check_cancelled()?;
        ensure!(address >> 47 == 0x1ffff, "内存统计地址不是规范内核地址");
        add(address, output.len() as u64)?;
        let next = add(self.attempted.get(), output.len() as u64)?;
        ensure!(
            next <= self.budget,
            "内存统计读取预算已用尽（{} 字节）",
            self.budget
        );
        self.attempted.set(next);
        match self.inner.read_virtual(address, output) {
            Ok(()) => self.check_cancelled(),
            Err(error) => {
                if crate::cancellation::is_cancellation_error(&error) {
                    self.cancelled.set(true);
                } else if self.missing.borrow().len() < 128 {
                    self.missing
                        .borrow_mut()
                        .push(json!({"virtual_address":address,
                        "length":output.len(),"reason":format!("{error:#}")}));
                }
                Err(error)
            }
        }
    }
    fn translate(&self, address: u64) -> Result<u64> {
        self.inner.translate(address)
    }
    fn isf(&self) -> &LinuxIsf {
        self.inner.isf()
    }
    fn kernel_slide(&self) -> u64 {
        self.inner.kernel_slide()
    }
    fn source_path(&self) -> Option<&std::path::Path> {
        self.inner.source_path()
    }
}

impl<M: LinuxKernelMemory> Memory<'_, M> {
    fn check_cancelled(&self) -> Result<()> {
        if self.cancelled.get() {
            return Err(crate::cancellation::CancellationError.into());
        }
        self.cancel.check_cancelled()
    }
}

struct Measurement {
    kib: u64,
    source: Value,
}

fn label(metric: &str) -> &str {
    match metric {
        "MemTotal" => "内核管理的内存总量",
        "MemFree" => "空闲内存",
        "MemAvailable" => "可用内存估算",
        "CommitLimit" => "提交内存额度（按当前策略参数计算）",
        "Committed_ASGlobal" => "已承诺虚拟内存（全局基数）",
        "Committed_ASReconstructed" => "已承诺虚拟内存（合并每 CPU 计数）",
        "Hugetlb" => "已分配的 HugeTLB 内存（全部页大小）",
        "Hugepagesize" => "默认 HugeTLB 页大小",
        "HugePages_Total" => "默认大小 HugeTLB 页总数",
        "HugePages_Free" => "默认大小 HugeTLB 空闲页数",
        "HugePages_Rsvd" => "默认大小 HugeTLB 已预留页数",
        "HugePages_Surp" => "默认大小 HugeTLB 超额页数",
        "VmallocUsed" => "Vmalloc 分配的后备页内存",
        "Percpu" => "每 CPU 分配器的后备页内存",
        "HardwareCorrupted" => "内核标记为硬件损坏的页",
        "FilePages" => "文件缓存页（含块设备与交换缓存）",
        "Buffers" => "块设备缓存",
        "Cached" => "文件缓存（扣除块设备与交换缓存）",
        "SwapCached" => "交换缓存",
        "Active" => "活跃页",
        "Inactive" => "非活跃页",
        "Active(anon)" => "活跃匿名页",
        "Inactive(anon)" => "非活跃匿名页",
        "Active(file)" => "活跃文件页",
        "Inactive(file)" => "非活跃文件页",
        "Unevictable" => "不可回收页",
        "Mlocked" => "锁定页",
        "Dirty" => "脏页",
        "Writeback" => "正在回写",
        "WritebackTmp" => "临时回写页",
        "AnonPages" => "已映射匿名页",
        "Mapped" => "已映射文件页",
        "Shmem" => "共享内存页",
        "KernelStack" => "内核栈",
        "PageTables" => "页表",
        "SecPageTables" => "次级页表",
        "SReclaimable" => "可回收 Slab",
        "SUnreclaim" => "不可回收 Slab",
        "Slab" => "Slab 总量",
        "KernelMiscReclaimable" => "其他可回收内核页",
        "KReclaimable" => "可回收内核内存",
        "Bounce" => "回弹缓冲页",
        "CmaFree" => "CMA 空闲页",
        "CmaTotal" => "CMA 总量",
        "SwapTotalGlobal" => "交换区总量（全局计数）",
        "SwapFreeGlobal" => "交换区空闲量（全局计数）",
        _ => metric,
    }
}

fn global(m: &impl LinuxKernelMemory, symbol: &str) -> Result<Measurement> {
    let (offset, width) = m.isf().symbol_counter_layout(symbol)?;
    ensure!(width == 8, "{symbol} 不是 x86-64 long/atomic_long 计数器");
    let address = add(m.runtime_symbol(symbol)?, offset)?;
    let raw = number(m, address, width)?;
    ensure!(raw <= i64::MAX as u64, "{symbol} 是负数或计数溢出");
    Ok(Measurement {
        kib: raw.checked_mul(PAGE_KIB).context("页数换算溢出")?,
        source: json!({"symbol":symbol,"counter_address":address,"counter_width":width,
            "raw_value":raw,"counter_unit":"pages","counter_offset":offset}),
    })
}

fn stat(m: &impl LinuxKernelMemory, item: &str, unit: &str) -> Result<Measurement> {
    let candidates = [
        ("vm_zone_stat", "zone_stat_item", "NR_VM_ZONE_STAT_ITEMS"),
        ("vm_node_stat", "node_stat_item", "NR_VM_NODE_STAT_ITEMS"),
    ];
    let found = candidates
        .into_iter()
        .filter_map(|(symbol, ty, end)| {
            m.isf()
                .enum_constant(ty, item)
                .ok()
                .map(|index| (symbol, ty, end, index))
        })
        .collect::<Vec<_>>();
    ensure!(found.len() == 1, "{item} 没有唯一的 ISF zone/node 枚举归属");
    let (symbol, ty, end, index) = found[0];
    let count = m.isf().symbol_array_count(symbol)?;
    ensure!(
        count <= 4096 && count == m.isf().enum_constant(ty, end)? && index < count,
        "{symbol} 数组长度与 {ty} 枚举边界不一致"
    );
    let (stride, offset, width) = m.isf().symbol_array_counter_layout(symbol)?;
    ensure!(
        stride <= 64 && width == 8,
        "{symbol} 的 atomic_long 数组布局无效"
    );
    let address = add(m.runtime_symbol(symbol)?, add(index * stride, offset)?)?;
    let raw = number(m, address, width)? as i64;
    // The kernel's SMP global page-state helpers clamp negative batched counts.
    // Preserve the signed raw value so this normalization remains inspectable.
    let value = raw.max(0) as u64;
    let kib = value
        .checked_mul(if unit == "kib" { 1 } else { PAGE_KIB })
        .context("统计换算溢出")?;
    Ok(Measurement {
        kib,
        source: json!({"symbol":symbol,"enum_type":ty,"enum_item":item,
        "enum_index":index,"array_entries":count,"element_size":stride,"counter_offset":offset,
        "counter_address":address,"counter_width":width,"raw_value":raw,"counter_unit":unit,
        "negative_clamped":raw < 0}),
    })
}

fn variant(m: &impl LinuxKernelMemory, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find(|name| {
            ["zone_stat_item", "node_stat_item"]
                .iter()
                .any(|ty| m.isf().enum_constant(ty, name).is_ok())
        })
        .map(|name| (*name).to_owned())
}

fn metric(
    rows: &mut Vec<Value>,
    name: &str,
    result: Result<Measurement>,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let result = result.and_then(|value| {
        value.kib.checked_mul(1024).context("统计字节数溢出")?;
        Ok(value)
    });
    match result {
        Ok(value) => {
            let bytes = value.kib * 1024;
            if value.source["negative_clamped"] == true {
                let rule = value.source["normalization_rule"]
                    .as_str()
                    .unwrap_or("SMP page-state");
                report.warn(format!(
                    "{name} 原始计数为负，按 {rule} 规则显示 0；原值仍保留"
                ));
            }
            rows.push(
                json!({"record_kind":"memory_metric","metric":name,"metric_label":label(name),"value_kib":value.kib,
                "value_bytes":bytes,"status":"read","basis":value.source}),
            );
        }
        Err(error) => {
            if crate::cancellation::is_cancellation_error(&error) {
                return Err(error);
            }
            report.warn(format!("{name}: {error:#}"));
            rows.push(
                json!({"record_kind":"memory_metric","metric":name,"metric_label":label(name),"value_kib":Value::Null,
                "value_bytes":Value::Null,"status":"unavailable","reason":format!("{error:#}")}),
            );
        }
    }
    Ok(())
}

fn value(rows: &[Value], name: &str) -> Result<u64> {
    rows.iter()
        .find(|row| row["metric"] == name)
        .and_then(|row| row["value_kib"].as_u64())
        .with_context(|| format!("依赖指标 {name} 不可用"))
}

fn derived(
    rows: &mut Vec<Value>,
    name: &str,
    inputs: &[&str],
    subtract: bool,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let values = inputs
        .iter()
        .map(|name| value(rows, name))
        .collect::<Result<Vec<_>>>();
    let result = values.and_then(|values| {
        let tail = values[1..].iter().try_fold(0u64, |sum, value| {
            sum.checked_add(*value).context("派生指标溢出")
        })?;
        let kib = if subtract {
            values[0].saturating_sub(tail)
        } else {
            values[0].checked_add(tail).context("派生指标溢出")?
        };
        Ok(Measurement {
            kib,
            source: json!({"input_metrics":inputs,
            "formula":if subtract { "max(first - sum(rest), 0)" } else { "sum(inputs)" }}),
        })
    });
    metric(rows, name, result, report)?;
    if let Some(row) = rows.last_mut().filter(|row| row["status"] == "read") {
        row["status"] = json!("derived");
    }
    Ok(())
}

pub(super) fn analyze(
    memory: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let m = Memory {
        inner: memory,
        cancel,
        budget: options.max_bytes,
        attempted: Cell::new(0),
        missing: RefCell::new(Vec::new()),
        cancelled: Cell::new(false),
    };
    let mut rows = Vec::new();
    let mut inputs = Vec::new();
    let total_symbol = if m.isf().symbol_address("_totalram_pages").is_ok() {
        "_totalram_pages"
    } else {
        "totalram_pages"
    };
    metric(
        &mut rows,
        "MemTotal",
        global(&m, total_symbol).and_then(|v| {
            ensure!(v.kib > 0, "totalram_pages 为零");
            Ok(v)
        }),
        report,
    )?;
    for (name, item, unit) in [
        ("MemFree", "NR_FREE_PAGES", "pages"),
        ("FilePages", "NR_FILE_PAGES", "pages"),
        ("Active(anon)", "NR_ACTIVE_ANON", "pages"),
        ("Inactive(anon)", "NR_INACTIVE_ANON", "pages"),
        ("Active(file)", "NR_ACTIVE_FILE", "pages"),
        ("Inactive(file)", "NR_INACTIVE_FILE", "pages"),
        ("Unevictable", "NR_UNEVICTABLE", "pages"),
        ("Mlocked", "NR_MLOCK", "pages"),
        ("Dirty", "NR_FILE_DIRTY", "pages"),
        ("Writeback", "NR_WRITEBACK", "pages"),
        ("AnonPages", "NR_ANON_MAPPED", "pages"),
        ("Mapped", "NR_FILE_MAPPED", "pages"),
        ("Shmem", "NR_SHMEM", "pages"),
        ("KernelStack", "NR_KERNEL_STACK_KB", "kib"),
        ("PageTables", "NR_PAGETABLE", "pages"),
        ("Bounce", "NR_BOUNCE", "pages"),
        ("WritebackTmp", "NR_WRITEBACK_TEMP", "pages"),
    ] {
        metric(&mut rows, name, stat(&m, item, unit), report)?;
    }
    for (name, alternatives) in [
        (
            "SReclaimable",
            ["NR_SLAB_RECLAIMABLE_B", "NR_SLAB_RECLAIMABLE"],
        ),
        (
            "SUnreclaim",
            ["NR_SLAB_UNRECLAIMABLE_B", "NR_SLAB_UNRECLAIMABLE"],
        ),
    ] {
        // Despite the _B name, global slab counters store pages, unlike memcg counters.
        let item = variant(&m, &alternatives).unwrap_or_else(|| alternatives[0].into());
        metric(&mut rows, name, stat(&m, &item, "pages"), report)?;
    }
    for (name, item) in [
        ("KernelMiscReclaimable", "NR_KERNEL_MISC_RECLAIMABLE"),
        ("SecPageTables", "NR_SECONDARY_PAGETABLE"),
        ("CmaFree", "NR_FREE_CMA_PAGES"),
    ] {
        if variant(&m, &[item]).is_some() {
            metric(&mut rows, name, stat(&m, item, "pages"), report)?;
        }
    }
    if m.isf().symbol_address("totalcma_pages").is_ok() {
        metric(&mut rows, "CmaTotal", global(&m, "totalcma_pages"), report)?;
    }
    for (name, symbol) in [
        ("SwapTotalGlobal", "total_swap_pages"),
        ("SwapFreeGlobal", "nr_swap_pages"),
    ] {
        metric(&mut rows, name, global(&m, symbol), report)?;
    }
    let buffers = mappings::buffers(&m, options, &mut inputs);
    m.check_cancelled()?;
    metric(&mut rows, "Buffers", buffers, report)?;
    let swapcache = if variant(&m, &["NR_SWAPCACHE"]).is_some() {
        stat(&m, "NR_SWAPCACHE", "pages")
    } else {
        mappings::swapcache(&m, &mut inputs)
    };
    m.check_cancelled()?;
    metric(&mut rows, "SwapCached", swapcache, report)?;
    for (name, inputs) in [
        ("Active", ["Active(anon)", "Active(file)"]),
        ("Inactive", ["Inactive(anon)", "Inactive(file)"]),
        ("Slab", ["SReclaimable", "SUnreclaim"]),
    ] {
        derived(&mut rows, name, &inputs, false, report)?;
    }
    if variant(&m, &["NR_KERNEL_MISC_RECLAIMABLE"]).is_some() {
        derived(
            &mut rows,
            "KReclaimable",
            &["SReclaimable", "KernelMiscReclaimable"],
            false,
            report,
        )?;
    }
    derived(
        &mut rows,
        "Cached",
        &["FilePages", "SwapCached", "Buffers"],
        true,
        report,
    )?;
    let available = available::estimate(&m, &rows, &mut inputs);
    m.check_cancelled()?;
    metric(&mut rows, "MemAvailable", available, report)?;
    if let Some(row) = rows.last_mut().filter(|row| row["status"] == "read") {
        row["status"] = json!("estimated");
    }
    commit::append(&m, &mut rows, &mut inputs, report)?;
    allocations::append(&m, &mut rows, &mut inputs, report)?;
    report.scope = "精确 ISF 内存计数、映射汇总和提交内存核对；4 KiB 基础页，保留各项来源。VM page-state 全局计数未合并每 CPU 差值；提交内存另列全局基数及每 CPU 汇总。采集可能跨越更新，不是同一时刻完整 /proc/meminfo".into();
    if !rows.iter().any(|row| row["value_kib"].is_u64()) {
        report.available = false;
    }
    let total_kib = value(&rows, "MemTotal").ok();
    let bytes = |name| value(&rows, name).ok().and_then(|v| v.checked_mul(1024));
    report.push(json!({"record_kind":"memory_summary","page_size":4096,
        "total_ram_pages":total_kib.map(|v| v / PAGE_KIB),"total_ram_kib":total_kib,
        "total_ram_bytes":bytes("MemTotal"),"free_bytes":bytes("MemFree"),"cached_bytes":bytes("Cached"),
        "available_bytes":bytes("MemAvailable"),
        "commit_limit_bytes":bytes("CommitLimit"),"committed_global_bytes":bytes("Committed_ASGlobal"),
        "committed_reconstructed_bytes":bytes("Committed_ASReconstructed"),"hugetlb_bytes":bytes("Hugetlb"),
        "vmalloc_used_bytes":bytes("VmallocUsed"),"percpu_bytes":bytes("Percpu"),
        "default_hugepage_size_bytes":bytes("Hugepagesize"),
        "attempted_bytes":m.attempted.get(),"read_budget_bytes":m.budget,
        "swap_scope":"全局 total_swap_pages/nr_swap_pages；未加入 swapoff 中待移除页的 si_swapinfo 调整",
        "uncomputed_metrics":["procfs Committed_AS display variant","Vmalloc virtual address range/free gaps","THP counter-unit variant"],
        "counter_scope":"VM page-state global counters exclude pending per-CPU deltas; committed memory has a separate CPU reconstruction"}));
    for row in rows.into_iter().chain(inputs) {
        if !report.push(row) {
            break;
        }
    }
    report.missing_ranges.extend(m.missing.into_inner());
    Ok(())
}
