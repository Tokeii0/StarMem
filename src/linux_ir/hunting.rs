use super::*;
use std::collections::{BTreeMap, HashMap};

mod signatures {
    include!("av_signatures.rs");
}

pub(super) fn analyze(
    session: &LinuxAnalysisSession,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    if options.module == "entropy" {
        return entropy(session, options, cancel);
    }
    if options.module == "av-edr" {
        return av_edr(session, options, cancel);
    }
    let mut report = LinuxIrReport::new(
        options,
        "原生检查的规则线索汇总；不将缺页、未命中或跨视图差异单独判定为入侵",
    );
    let mut checked = 0;
    for module in [
        "malfind",
        "check-creds",
        "credentials",
        "psxview",
        "entropy",
    ] {
        cancel.check_cancelled()?;
        let result = run_task(
            session,
            &LinuxIrOptions {
                module: module.into(),
                ..options.clone()
            },
            cancel,
        );
        match result {
            Ok(child) => {
                checked += usize::from(child["available"] != false);
                source_status(&mut report, module, &child);
                for row in child["records"].as_array().into_iter().flatten() {
                    cancel.check_cancelled()?;
                    if let Some((rule, meaning)) = finding_rule(module, row) {
                        report.push(json!({"kind":"finding","rule":rule,"priority":"review",
                            "source":module,"pid":row.get("pid"),"task":row.get("task"),
                            "summary":meaning,"evidence":row,"verdict":"investigation_lead"}));
                    }
                    if report.limit_reached {
                        break;
                    }
                }
            }
            Err(error) => {
                if crate::cancellation::is_cancellation_error(&error) {
                    return Err(error);
                }
                source_error(&mut report, module, &error);
            }
        }
        if report.limit_reached {
            break;
        }
    }
    if !report.limit_reached {
        match TaskMemory::new(session) {
            Ok(memory) => {
                for (source, child) in [
                    (
                        "modxview",
                        serde_json::to_value(crate::linux_kernel_plugins::linux_modxview(
                            &memory,
                            options.limit,
                        ))?,
                    ),
                    (
                        "check-syscall",
                        serde_json::to_value(crate::linux_kernel_plugins::linux_check_syscall(
                            &memory,
                            &Default::default(),
                        ))?,
                    ),
                ] {
                    cancel.check_cancelled()?;
                    checked += usize::from(child["available"] == true);
                    source_status(&mut report, source, &child);
                    for row in child["records"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|r| r["suspicious"] == true)
                    {
                        report.push(json!({"kind":"finding","source":source,"rule":source,
                            "priority":"review","evidence":row,"verdict":"investigation_lead",
                            "summary":"已验证结构符合源检查规则；结合合法模块、升级过程和采集状态复核"}));
                        if report.limit_reached {
                            break;
                        }
                    }
                }
            }
            Err(error) => source_error(&mut report, "kernel-checks", &error),
        }
    }
    if checked == 0 {
        report.unavailable("所有风险检查来源均不可用");
    }
    if options.module == "triage" {
        let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
        for row in report.records.iter().filter(|r| r["kind"] == "finding") {
            *by_source
                .entry(row["source"].as_str().unwrap_or("unknown").into())
                .or_default() += 1;
        }
        let summary = json!({"kind":"triage_summary","checks_available":checked,
            "findings":by_source.values().sum::<usize>(),"by_source":by_source,
            "complete":report.complete,"assessment":"规则线索数量；零项不能证明主机安全"});
        // Summary must remain visible even when the evidence record limit was reached.
        if report.records.len() >= report.limit {
            report.records.pop();
        }
        report.records.insert(0, summary);
        report.record_count = report.records.len();
    }
    Ok(serde_json::to_value(report)?)
}

pub(super) fn source_status(report: &mut LinuxIrReport, source: &str, child: &Value) {
    let complete = child["complete"] == true;
    let available = child
        .get("available")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !complete || !available {
        report.warn(format!("{source} 来源不完整或不可用；详见来源状态记录"));
    }
    report.push(json!({"kind":"source_status","source":source,"available":available,"complete":complete,
        "scope":child.get("scope"),"warnings":child.get("warnings"),"missing_ranges":child.get("missing_ranges"),
        "records":child["records"].as_array().map(Vec::len),"limit_reached":child.get("limit_reached")}));
}

pub(super) fn source_error(report: &mut LinuxIrReport, source: &str, error: &anyhow::Error) {
    report.warn(format!("{source}: {error:#}"));
    report.push(json!({"kind":"source_status","source":source,"available":false,"complete":false,"error":format!("{error:#}")}));
}

pub(super) fn finding_rule<'a>(module: &'a str, row: &Value) -> Option<(&'a str, &'static str)> {
    match module {
        "malfind" if row["content_status"] == "nonzero_resident_sample" => {
            Some((module, "可执行候选含驻留内容；JIT 等正常用途也可能符合"))
        }
        "check-creds" => Some((module, "多个线程组共享 cred；需要复核凭据继承及提权上下文")),
        "credentials"
            if row["uid"].as_u64().is_some_and(|id| id != 0)
                && row["cap_effective"]
                    .as_str()
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .is_some_and(|v| v != 0) =>
        {
            Some((
                module,
                "非 root 凭据拥有有效 capabilities；服务可能有合法授权",
            ))
        }
        "psxview" if row["in_active_list"] == false && row["leader"] == true => Some((
            module,
            "PID 注册表主进程未见于活动链；退出和采集时序也会导致差异",
        )),
        "entropy"
            if row["sample_bytes"].as_u64().is_some_and(|v| v >= 256)
                && row["entropy_bits_per_byte"]
                    .as_f64()
                    .is_some_and(|v| v >= 7.2) =>
        {
            Some((
                module,
                "可执行映射样本熵 ≥ 7.2 bit/byte；压缩或正常数据也可符合",
            ))
        }
        _ => None,
    }
}

pub(super) fn shannon(counts: &[u64; 256]) -> Option<f64> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return None;
    }
    Some(
        counts
            .iter()
            .filter(|n| **n != 0)
            .map(|n| {
                let p = *n as f64 / total as f64;
                -p * p.log2()
            })
            .sum(),
    )
}

fn entropy(
    session: &LinuxAnalysisSession,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    let maps = session.proc_maps(options.pid, options.limit, options.limit)?;
    let mut report = LinuxIrReport::new(
        options,
        "可执行 VMA 的前 16 KiB 驻留字节样本；每次分析共用读取预算，不把缺页填零用于熵计算",
    );
    report.complete = maps.complete;
    report
        .warnings
        .extend(maps.warnings.iter().take(64).map(|w| w.message.clone()));
    let spaces: HashMap<_, _> = maps
        .processes
        .iter()
        .filter_map(|p| p.pgd_physical.map(|dtb| (p.task, dtb)))
        .collect();
    let mut budget = options.max_bytes;
    for map in maps.records.iter().filter(|m| m.vm_flags & 4 != 0) {
        cancel.check_cancelled()?;
        let mut row = serde_json::to_value(map)?;
        let mut counts = [0u64; 256];
        let mut ranges = Vec::new();
        let mut missing = Vec::new();
        let target = map.length.min(16 * 1024);
        let mut attempted = 0;
        if let Some(dtb) = spaces.get(&map.task) {
            let space = LinuxX64AddressSpace::new(session.image(), *dtb)?;
            while attempted < target && budget > 0 {
                cancel.check_cancelled()?;
                let address = add(map.start, attempted)?;
                let size = (target - attempted)
                    .min(budget)
                    .min(4096 - (address & 4095)) as usize;
                let mut bytes = [0; 4096];
                match space.read_virtual(address, &mut bytes[..size]) {
                    Ok(()) => {
                        for b in &bytes[..size] {
                            counts[*b as usize] += 1;
                        }
                        ranges.push(json!({"start":address,"length":size}));
                    }
                    Err(error) => {
                        missing.push(
                            json!({"start":address,"length":size,"error":format!("{error:#}")}),
                        );
                    }
                }
                attempted += size as u64;
                budget -= size as u64;
            }
        } else {
            row["error"] = json!("没有与 task 对应的已验证进程页表");
        }
        let sample: u64 = counts.iter().sum();
        row["entropy_bits_per_byte"] = json!(shannon(&counts));
        row["sample_bytes"] = json!(sample);
        row["sample_target_bytes"] = json!(target);
        row["sample_ranges"] = json!(ranges);
        row["missing_ranges"] = json!(missing);
        row["content_status"] = json!(if attempted == 0 {
            "not_checked"
        } else if sample == target {
            "sample_complete"
        } else {
            "sample_partial"
        });
        row["interpretation"] = json!("样本统计；不是整个 VMA 的熵或恶意概率");
        if sample != target {
            report.warn("部分可执行映射样本因缺页、页表或总预算不足而未完整核对");
        }
        if !report.push(row) {
            break;
        }
    }
    Ok(serde_json::to_value(report)?)
}

fn av_edr(
    session: &LinuxAnalysisSession,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    let mut report = LinuxIrReport::new(
        options,
        "安全/审计产品的进程名、argv[0] 和模块名规则匹配；不能证明安装状态、保护有效或已被绕过",
    );
    let tasks = session.psaux(options.pid, options.limit, options.max_bytes.min(64 * 1024))?;
    report.complete = tasks.complete;
    report
        .warnings
        .extend(tasks.warnings.iter().take(64).map(|w| w.message.clone()));
    for task in &tasks.records {
        cancel.check_cancelled()?;
        let argv0 = task.arguments.first().map(String::as_str).unwrap_or("");
        for &(needle, kind, vendor, product) in signatures::AV_SIGNATURES {
            if kind & 1 != 0
                && (task.name.to_ascii_lowercase().contains(needle)
                    || argv0.to_ascii_lowercase().contains(needle))
            {
                report.push(json!({"kind":"process_signature","pid":task.pid,"task":task.task,"name":task.name,
                    "argv0":argv0,"command_line_complete":task.command_line_complete,
                    "vendor":vendor,"product":product,"matched_signature":needle,"interpretation":"名称规则命中，需复核二进制身份"}));
                if report.limit_reached {
                    break;
                }
            }
        }
        if report.limit_reached {
            break;
        }
    }
    if !report.limit_reached && options.pid.is_none() {
        match TaskMemory::new(session) {
            Ok(memory) => {
                let modules = crate::linux_kernel_plugins::linux_lsmod(&memory, options.limit);
                if !modules.complete {
                    report.warn("模块枚举不完整；安全产品模块检测范围受限");
                }
                for module in modules.modules {
                    cancel.check_cancelled()?;
                    for &(needle, kind, vendor, product) in signatures::AV_SIGNATURES {
                        if kind & 2 != 0 && module.name.to_ascii_lowercase().contains(needle) {
                            report.push(json!({"kind":"module_signature","module":module.module,"name":module.name,
                                "vendor":vendor,"product":product,"matched_signature":needle,"interpretation":"名称规则命中，需复核模块身份"}));
                        }
                    }
                    if report.limit_reached {
                        break;
                    }
                }
            }
            Err(error) => source_error(&mut report, "modules", &error),
        }
    }
    Ok(serde_json::to_value(report)?)
}
