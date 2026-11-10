//! Commit accounting inputs, independent of kernel-version-dependent procfs display choices.
use super::*;

mod committed;
mod hugetlb;

pub(super) fn scalar(
    m: &impl LinuxKernelMemory,
    symbol: &str,
    width: u64,
    metric_name: &str,
    input_kind: &str,
    inputs: &mut Vec<Value>,
) -> Result<u64> {
    let (offset, actual_width) = m.isf().symbol_counter_layout(symbol)?;
    ensure!(
        actual_width == width && offset == 0,
        "{symbol} 不是 {width} 字节标量"
    );
    let address = m.runtime_symbol(symbol)?;
    let raw = number(m, address, width)?;
    inputs.push(
        json!({"record_kind":"memory_input","metric":metric_name,"input_kind":input_kind,
        "symbol":symbol,"counter_address":address,"counter_width":width,"raw_value":raw}),
    );
    Ok(raw)
}

fn publish(
    rows: &mut Vec<Value>,
    name: &str,
    value: Result<Measurement>,
    status: &str,
    report: &mut LinuxIrReport,
) -> Result<()> {
    metric(rows, name, value, report)?;
    if let Some(row) = rows.last_mut().filter(|row| row["status"] == "read") {
        row["status"] = json!(status);
    }
    Ok(())
}

pub(super) fn append(
    m: &Memory<'_, impl LinuxKernelMemory>,
    rows: &mut Vec<Value>,
    inputs: &mut Vec<Value>,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let huge = hugetlb::measure(m, inputs);
    m.check_cancelled()?;
    publish(rows, "Hugetlb", huge, "derived", report)?;

    let mut policy = json!({"record_kind":"memory_commit_policy",
        "scope_note":"提交额度仅在 overcommit_memory=2 时参与限制；此处未扣用户/管理员保留或应用单独限制，不能据此保证分配成功，也不表示实际物理内存占用"});
    for (symbol, width, key, maximum) in [
        ("sysctl_overcommit_memory", 4, "overcommit_mode", 2),
        (
            "sysctl_overcommit_ratio",
            4,
            "overcommit_ratio",
            i32::MAX as u64,
        ),
        ("sysctl_overcommit_kbytes", 8, "overcommit_kbytes", u64::MAX),
    ] {
        let value = scalar(m, symbol, width, "CommitLimit", key, inputs).and_then(|value| {
            ensure!(value <= maximum, "{symbol} 超出有效范围");
            Ok(value)
        });
        m.check_cancelled()?;
        match value {
            Ok(value) => policy[key] = json!(value),
            Err(error) => {
                policy[key] = Value::Null;
                policy[format!("{key}_error")] = json!(format!("{error:#}"));
                report.warn(format!("{symbol}: {error:#}"));
            }
        }
    }
    policy["policy_name"] = json!(match policy["overcommit_mode"].as_u64() {
        Some(0) => "启发式判断",
        Some(1) => "允许过量承诺",
        Some(2) => "限制提交额度",
        _ => "未知",
    });
    policy["strict_overcommit"] = json!(policy["overcommit_mode"].as_u64().map(|mode| mode == 2));
    let limit = (|| {
        let kbytes = policy["overcommit_kbytes"]
            .as_u64()
            .context("overcommit_kbytes 不可用")?;
        let swap_pages = value(rows, "SwapTotalGlobal")? / PAGE_KIB;
        let (allowed, mode, inputs) = if kbytes != 0 {
            (
                kbytes / PAGE_KIB,
                "explicit_kbytes",
                json!({"overcommit_kbytes":kbytes,
                "discarded_kib_remainder":kbytes % PAGE_KIB}),
            )
        } else {
            let ratio = policy["overcommit_ratio"]
                .as_u64()
                .context("overcommit_ratio 不可用")?;
            let ram = value(rows, "MemTotal")? / PAGE_KIB;
            let huge = value(rows, "Hugetlb")? / PAGE_KIB;
            let pages = ram
                .checked_sub(huge)
                .context("HugeTLB 页数超过物理内存总页数")?
                .checked_mul(ratio)
                .context("提交额度乘法溢出")?
                / 100;
            (
                pages,
                "ram_ratio",
                json!({"overcommit_ratio":ratio,"total_ram_pages":ram,"hugetlb_pages":huge}),
            )
        };
        let pages = allowed
            .checked_add(swap_pages)
            .context("提交额度页数溢出")?;
        Ok(Measurement {
            kib: pages.checked_mul(PAGE_KIB).context("提交额度换算溢出")?,
            source: json!({"calculation_mode":mode,"inputs":inputs,"swap_pages":swap_pages,
                "formula":"(kbytes != 0 ? floor(kbytes/4) : floor((ram_pages-hugetlb_pages)*ratio/100)) + swap_pages",
                "counter_unit":"pages","scope_note":"由当前参数和驻留计数重建 vm_commit_limit；策略是否执行额度限制另见 memory_commit_policy"}),
        })
    })();
    inputs.push(policy);
    publish(rows, "CommitLimit", limit, "derived", report)?;

    let base = committed::read_base(m, inputs);
    m.check_cancelled()?;
    match base {
        Ok(base) => {
            publish(
                rows,
                "Committed_ASGlobal",
                committed::global(&base),
                "read",
                report,
            )?;
            let sum = committed::sum(m, &base, inputs);
            m.check_cancelled()?;
            publish(rows, "Committed_ASReconstructed", sum, "derived", report)?;
        }
        Err(error) => {
            let message = format!("{error:#}");
            metric(rows, "Committed_ASGlobal", Err(error), report)?;
            metric(
                rows,
                "Committed_ASReconstructed",
                Err(anyhow::anyhow!(message)),
                report,
            )?;
        }
    }
    Ok(())
}
