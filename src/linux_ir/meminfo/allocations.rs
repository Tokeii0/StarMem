//! Allocator backing pages and default HugeTLB counters, read through exact ISF layouts.
use super::*;

const COUNTS: [(&str, &str); 4] = [
    ("HugePages_Total", "nr_huge_pages"),
    ("HugePages_Free", "free_huge_pages"),
    ("HugePages_Rsvd", "resv_huge_pages"),
    ("HugePages_Surp", "surplus_huge_pages"),
];

fn percpu(m: &impl LinuxKernelMemory, inputs: &mut Vec<Value>) -> Result<Measurement> {
    let pages = commit::scalar(
        m,
        "pcpu_nr_populated",
        8,
        "Percpu",
        "percpu_populated",
        inputs,
    )?;
    let units = commit::scalar(m, "pcpu_nr_units", 4, "Percpu", "percpu_units", inputs)?;
    ensure!(
        pages <= i64::MAX as u64 && units > 0 && units <= i32::MAX as u64,
        "每 CPU 分配器页数或 unit 数无效"
    );
    let kib = pages
        .checked_mul(units)
        .and_then(|pages| pages.checked_mul(PAGE_KIB))
        .context("每 CPU 分配器总量溢出")?;
    Ok(Measurement {
        kib,
        source: json!({"populated_pages_per_unit":pages,"allocator_units":units,
        "formula":"pcpu_nr_populated * pcpu_nr_units * 4 KiB",
        "scope_note":"分配器已填充的后备页，不含分配器元数据。unit 数可能包含布局填充，不能用在线或可能 CPU 数替换；不是每 CPU 承诺内存差值"}),
    })
}

fn default_state(m: &impl LinuxKernelMemory, inputs: &mut Vec<Value>) -> Result<(u64, u64, Value)> {
    ensure!(
        m.isf().symbol_array_struct_type("hstates")? == "hstate",
        "hstates 元素不是 hstate"
    );
    let declared = m.isf().symbol_array_count("hstates")?;
    let stride = m.isf().symbol_array_element_size("hstates")?;
    ensure!(
        declared > 0 && declared <= 64 && stride == m.isf().type_size("hstate")?,
        "hstates 数量或元素大小无效"
    );
    let count = commit::scalar(
        m,
        "hugetlb_max_hstate",
        4,
        "Hugepagesize",
        "default_hstate_count",
        inputs,
    )?;
    let index = commit::scalar(
        m,
        "default_hstate_idx",
        4,
        "Hugepagesize",
        "default_hstate_index",
        inputs,
    )?;
    ensure!(
        count <= declared && index < count,
        "默认 HugeTLB 页索引不属于已登记 hstates"
    );
    let address = add(
        m.runtime_symbol("hstates")?,
        index.checked_mul(stride).context("hstate 偏移溢出")?,
    )?;
    let (offset, width) = m.isf().field_scalar_layout("hstate", "order")?;
    ensure!(width == 4, "hstate.order 不是 32 位标量");
    let order_address = add(address, offset)?;
    let order = number(m, order_address, width)?;
    inputs.push(json!({"record_kind":"memory_input","metric":"Hugepagesize","input_kind":"default_hstate_order",
        "hstate_index":index,"hstate_address":address,"counter_address":order_address,"counter_width":width,"raw_value":order}));
    ensure!(order > 0 && order <= 51, "默认 HugeTLB 页阶数越界");
    let kib = (1u64 << order)
        .checked_mul(PAGE_KIB)
        .context("默认 HugeTLB 页大小溢出")?;
    kib.checked_mul(1024).context("默认 HugeTLB 页字节数溢出")?;
    Ok((
        address,
        kib,
        json!({"symbol":"hstates","hstate_index":index,"hstate_count":count,
        "declared_hstates":declared,"hstate_address":address,"hstate_stride":stride,
        "page_order":order,"order_address":order_address,"page_size_kib":kib,
        "scope_note":"仅 default_hstate_idx 所指向的已登记页大小，其他大小见 Hugetlb；不包含透明大页"}),
    ))
}

fn count_metric(
    rows: &mut Vec<Value>,
    name: &str,
    result: Result<(u64, Value)>,
    report: &mut LinuxIrReport,
) -> Result<()> {
    // HugePages_* 是大页个数。保留独立单位，不把数量放进 KiB/字节列。
    let mut row = json!({"record_kind":"memory_metric","metric":name,"metric_label":label(name),
        "unit":"huge_pages","value_count":Value::Null,"value_kib":Value::Null,"value_bytes":Value::Null});
    match result {
        Ok((count, basis)) => {
            row["value_count"] = json!(count);
            row["status"] = json!("read");
            row["basis"] = basis;
        }
        Err(error) => {
            if crate::cancellation::is_cancellation_error(&error) {
                return Err(error);
            }
            report.warn(format!("{name}: {error:#}"));
            row["status"] = json!("unavailable");
            row["reason"] = json!(format!("{error:#}"));
        }
    }
    rows.push(row);
    Ok(())
}

pub(super) fn append(
    m: &Memory<'_, impl LinuxKernelMemory>,
    rows: &mut Vec<Value>,
    inputs: &mut Vec<Value>,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let mut vmalloc = global(m, "nr_vmalloc_pages");
    if let Ok(value) = &mut vmalloc {
        value.source["scope_note"] = json!(
            "nr_vmalloc_pages 后备页计数；不是 Vmalloc 虚拟地址范围或最大空闲区间。缺少计数器的旧内核不按 procfs 占位数补零"
        );
    }
    metric(rows, "VmallocUsed", vmalloc, report)?;
    let result = percpu(m, inputs);
    m.check_cancelled()?;
    metric(rows, "Percpu", result, report)?;
    if let Some(row) = rows.last_mut().filter(|row| row["status"] == "read") {
        row["status"] = json!("derived");
    }
    if m.isf().symbol_address("num_poisoned_pages").is_ok() {
        metric(
            rows,
            "HardwareCorrupted",
            global(m, "num_poisoned_pages"),
            report,
        )?;
    }
    let state = default_state(m, inputs);
    m.check_cancelled()?;
    match state {
        Ok((address, kib, basis)) => {
            metric(
                rows,
                "Hugepagesize",
                Ok(Measurement {
                    kib,
                    source: basis.clone(),
                }),
                report,
            )?;
            for (name, field) in COUNTS {
                let value = (|| {
                    let (offset, width) = m.isf().field_scalar_layout("hstate", field)?;
                    ensure!(width == 8, "hstate.{field} 不是 64 位计数器");
                    let counter_address = add(address, offset)?;
                    let count = number(m, counter_address, width)?;
                    ensure!(count <= i64::MAX as u64, "hstate.{field} 为负或溢出");
                    let mut source = basis.clone();
                    source["field"] = json!(field);
                    source["counter_address"] = json!(counter_address);
                    source["counter_width"] = json!(width);
                    source["raw_value"] = json!(count);
                    source["counter_unit"] = json!("huge_pages");
                    Ok((count, source))
                })();
                m.check_cancelled()?;
                count_metric(rows, name, value, report)?;
            }
        }
        Err(error) => {
            let message = format!("{error:#}");
            metric(rows, "Hugepagesize", Err(error), report)?;
            for (name, _) in COUNTS {
                count_metric(rows, name, Err(anyhow::anyhow!(message.clone())), report)?;
            }
        }
    }
    Ok(())
}
