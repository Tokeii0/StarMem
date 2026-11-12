use super::*;
use std::collections::{BTreeMap, HashMap};

pub(super) fn analyze(
    session: &LinuxAnalysisSession,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    if matches!(options.module.as_str(), "elfs" | "library-list" | "malfind") {
        return mappings(session, options, cancel);
    }
    let processes = session.processes(options.limit)?;
    let mut report = LinuxIrReport::new(
        options,
        "已验证活动进程及其驻留 task_struct/cred；非活动任务不在范围",
    );
    report.complete = processes.complete;
    report
        .warnings
        .extend(processes.warnings.iter().map(|w| w.message.clone()));
    if options.module == "kthreads" {
        let unknown = processes
            .processes
            .iter()
            .filter(|task| task.kernel_thread.is_none())
            .count();
        if unknown > 0 {
            report.warn(format!(
                "{unknown} 个进程缺少 flags，无法判定 PF_KTHREAD；不能凭 mm=NULL 推断内核线程"
            ));
        }
        for task in processes
            .processes
            .iter()
            .filter(|p| p.kernel_thread == Some(true) && options.pid.is_none_or(|pid| p.pid == pid))
        {
            cancel.check_cancelled()?;
            report.push(serde_json::to_value(task)?);
        }
        return Ok(serde_json::to_value(report)?);
    }
    let m = match TaskMemory::new(session) {
        Ok(memory) => memory,
        Err(error) => {
            report.unavailable(format!("{error:#}"));
            return Ok(serde_json::to_value(report)?);
        }
    };
    let required: &[(&str, &str)] = match options.module.as_str() {
        "perf-events" => &[
            ("task_struct", "perf_event_list"),
            ("perf_event", "owner_entry"),
            ("perf_event", "pmu"),
            ("pmu", "name"),
        ],
        "callstack" => &[
            ("task_struct", "stack"),
            ("task_struct", "thread"),
            ("thread_struct", "sp"),
        ],
        "capabilities" | "credentials" | "check-creds" => &[
            ("task_struct", "cred"),
            ("task_struct", "real_cred"),
            ("cred", "uid"),
            ("cred", "euid"),
        ],
        "ptrace" => &[("task_struct", "ptrace"), ("task_struct", "parent")],
        _ => &[],
    };
    for (ty, name) in required {
        if let Err(error) = m.isf().field_offset(ty, name) {
            report.unavailable(format!("{error:#}"));
            return Ok(serde_json::to_value(report)?);
        }
    }
    if options.module == "callstack" && m.isf().type_size("thread_union").is_err() {
        report.unavailable("ISF 缺少 thread_union，无法验证线程栈边界");
        return Ok(serde_json::to_value(report)?);
    }
    let stack_symbols = if options.module == "callstack" {
        let symbols = crate::linux_kernel_plugins::linux_kallsyms(&m, 1_000_000);
        if !symbols.available {
            report.warn("内核符号解码不可用；栈中地址仅按内核正文范围标记");
        }
        let mut rows = symbols.symbols;
        rows.sort_by_key(|row| row.address);
        rows
    } else {
        Vec::new()
    };
    let stack_modules = if options.module == "callstack" {
        let modules = crate::linux_kernel_plugins::linux_lsmod(&m, options.limit);
        if !modules.complete {
            report.warn("模块链不完整，栈地址的模块归属范围可能不全");
        }
        modules.modules
    } else {
        Vec::new()
    };
    let mut shared_creds: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
    for task in processes
        .processes
        .iter()
        .filter(|p| options.pid.is_none_or(|pid| p.pid == pid))
    {
        cancel.check_cancelled()?;
        let addresses = if matches!(
            options.module.as_str(),
            "threads" | "ptrace" | "perf-events" | "callstack"
        ) {
            let mut addresses = vec![task.task];
            let chain = if m
                .isf()
                .optional_field_offset("task_struct", "thread_group")?
                .is_some()
            {
                let offset = m.isf().field_offset("task_struct", "thread_group")?;
                list(
                    &m,
                    add(task.task, offset)?,
                    offset,
                    options.limit,
                    cancel,
                    &mut report,
                )
            } else {
                let signal = pointer(field(&m, task.task, "task_struct", "signal")?)?;
                list(
                    &m,
                    member(&m, signal, "signal_struct", "thread_head")?,
                    m.isf().field_offset("task_struct", "thread_node")?,
                    options.limit,
                    cancel,
                    &mut report,
                )
            };
            match chain {
                Ok(items) => addresses.extend(items),
                Err(error) => row_error(&mut report, task.task, error),
            }
            addresses.sort_unstable();
            addresses.dedup();
            addresses
        } else {
            vec![task.task]
        };
        for address in addresses {
            cancel.check_cancelled()?;
            let read = (|| -> Result<()> {
                let pid = field(&m, address, "task_struct", "pid")?;
                let tgid = field(&m, address, "task_struct", "tgid")?;
                ensure!(tgid == task.tgid as u64, "线程与组主进程的 TGID 不一致");
                let mut row = json!({"task": address, "task_hex": format!("{address:#018x}"), "pid": pid, "tgid": tgid,
                    "name": inline_string(&m, address, "task_struct", "comm")?, "ppid": task.ppid});
                match options.module.as_str() {
                    "cwd" => {
                        let directory = crate::linux_process::process_current_directory(
                            session.image(),
                            session.kernel(),
                            address,
                        )?;
                        row["fs"] = json!(directory.fs);
                        row["mount"] = json!(directory.mount);
                        row["dentry"] = json!(directory.dentry);
                        row["path"] = json!(directory.path);
                        row["path_semantics"] = json!(directory.path_semantics);
                        report.push(row);
                    }
                    "perf-events" => perf_events(&m, address, row, options, cancel, &mut report)?,
                    "callstack" => callstack(
                        &m,
                        address,
                        row,
                        &stack_symbols,
                        &stack_modules,
                        options,
                        cancel,
                        &mut report,
                    )?,
                    "threads" => {
                        row["leader"] = json!(pid == tgid);
                        let state = m
                            .isf()
                            .field_offset_any("task_struct", &["__state", "state"])?;
                        let width = m
                            .isf()
                            .field_size_any("task_struct", &["__state", "state"])?;
                        row["state_raw"] = json!(number(&m, add(address, state)?, width)?);
                        report.push(row);
                    }
                    "ptrace" => {
                        let flags = field(&m, address, "task_struct", "ptrace")?;
                        if flags != 0 {
                            let tracer = pointer(field(&m, address, "task_struct", "parent")?)?;
                            row["ptrace_flags"] = json!(flags);
                            row["tracer_task"] = json!(tracer);
                            row["tracer_tid"] = json!(field(&m, tracer, "task_struct", "pid")?);
                            row["tracer_name"] =
                                json!(inline_string(&m, tracer, "task_struct", "comm")?);
                            row["meaning"] = json!("调试关系；不直接证明恶意行为");
                            report.push(row);
                        }
                    }
                    "capabilities" | "credentials" | "check-creds" => {
                        let cred = pointer(field(&m, address, "task_struct", "cred")?)?;
                        let real = pointer(field(&m, address, "task_struct", "real_cred")?)?;
                        row["cred"] = json!(cred);
                        row["real_cred"] = json!(real);
                        for key in [
                            "uid", "euid", "suid", "fsuid", "gid", "egid", "sgid", "fsgid",
                        ] {
                            row[key] = json!(field(&m, cred, "cred", key)?);
                        }
                        for cap in [
                            "cap_inheritable",
                            "cap_permitted",
                            "cap_effective",
                            "cap_bset",
                            "cap_ambient",
                        ] {
                            if m.isf().optional_field_offset("cred", cap)?.is_none() {
                                row[cap] = Value::Null;
                                continue;
                            }
                            let value = field(&m, real, "cred", cap)?;
                            row[cap] = json!(format!("0x{value:016x}"));
                            row[format!("{cap}_names")] = json!(capability_names(value));
                        }
                        if options.module == "check-creds" {
                            shared_creds.entry(cred).or_default().push(row);
                        } else {
                            report.push(row);
                        }
                    }
                    _ => anyhow::bail!("未知 task 模块"),
                }
                Ok(())
            })();
            if let Err(error) = read {
                row_error(&mut report, address, error);
            }
            if report.limit_reached {
                break;
            }
        }
        if report.limit_reached {
            break;
        }
    }
    for (cred, tasks) in shared_creds
        .into_iter()
        .filter(|(_, tasks)| tasks.len() > 1)
    {
        report.push(
            json!({"cred": cred, "tasks": tasks, "assessment": "shared_credential_pointer",
            "meaning": "不同线程组共享 cred 的调查线索；单独此项不足以确认提权"}),
        );
    }
    Ok(serde_json::to_value(report)?)
}

pub(super) fn perf_events(
    m: &impl LinuxKernelMemory,
    task: u64,
    row: Value,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let head = member(m, task, "task_struct", "perf_event_list")?;
    let offset = m.isf().field_offset("perf_event", "owner_entry")?;
    for event in list(m, head, offset, options.limit, cancel, report)? {
        cancel.check_cancelled()?;
        let mut record = row.clone();
        record["perf_event"] = json!(event);
        let pmu = pointer(field(m, event, "perf_event", "pmu")?)?;
        record["event_name"] = json!(string(m, field(m, pmu, "pmu", "name")?, 256)?);
        if m.isf()
            .optional_field_offset("perf_event", "attr")?
            .is_some()
        {
            let attr = member(m, event, "perf_event", "attr")?;
            record["event_type"] = json!(field(m, attr, "perf_event_attr", "type")?);
            record["event_config"] = json!(field(m, attr, "perf_event_attr", "config")?);
        }
        // Events without an attached BPF program are useful evidence too.
        let program = if m
            .isf()
            .optional_field_offset("perf_event", "prog")?
            .is_some()
        {
            Some(field(m, event, "perf_event", "prog")?)
        } else {
            None
        };
        record["bpf_program"] = json!(program);
        if let Some(program) = program.filter(|p| *p != 0) {
            let names = (|| -> Result<()> {
                pointer(program)?;
                let aux = pointer(field(m, program, "bpf_prog", "aux")?)?;
                record["program_name"] = json!(inline_string(m, aux, "bpf_prog_aux", "name")?);
                if m.isf()
                    .optional_field_offset("bpf_prog_aux", "ksym")?
                    .is_some()
                {
                    let ksym = member(m, aux, "bpf_prog_aux", "ksym")?;
                    record["symbol_name"] = json!(inline_string(m, ksym, "bpf_ksym", "name")?);
                }
                Ok(())
            })();
            if let Err(error) = names {
                record["program_read_error"] = json!(format!("{error:#}"));
                row_error(report, program, error);
            }
        }
        record["assessment"] = json!("性能事件和 BPF 关联；不单独证明恶意行为");
        if !report.push(record) {
            break;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn callstack(
    m: &impl LinuxKernelMemory,
    task: u64,
    row: Value,
    symbols: &[crate::linux_kernel_plugins::LinuxKallsymsRecord],
    modules: &[crate::linux_kernel_plugins::LinuxModuleRecord],
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let base = pointer(field(m, task, "task_struct", "stack")?)?;
    let thread = member(m, task, "task_struct", "thread")?;
    let sp = pointer(field(m, thread, "thread_struct", "sp")?)?;
    let size = m
        .isf()
        .type_size("thread_union")
        .context("ISF 缺少 thread_union，无法验证线程栈范围")?;
    ensure!(
        size.is_power_of_two() && (4096..=65536).contains(&size),
        "线程栈大小越界"
    );
    let top = add(base, size)?;
    ensure!(base <= sp && sp < top, "保存的 SP 不在本线程栈范围内");
    let text_start = m.runtime_symbol("_stext")?;
    let text_end = m.runtime_symbol("_etext")?;
    let length = (top - sp).min(options.max_bytes);
    if length < top - sp {
        report.limit_reached = true;
        report.warn("线程栈读取达到字节上限");
    }
    for position in 0..length / 8 {
        cancel.check_cancelled()?;
        let slot = add(sp, position * 8)?;
        let value = number(m, slot, 8)?;
        let in_core = text_start <= value && value < text_end;
        let module = modules.iter().find(|module| {
            module.core_text_size.is_some_and(|length| {
                module.core_base <= value && value - module.core_base < length
            })
        });
        if !in_core && module.is_none() {
            continue;
        }
        let index = symbols.partition_point(|s| s.address <= value);
        let symbol = index
            .checked_sub(1)
            .and_then(|i| symbols.get(i))
            .filter(|s| {
                s.valid_kernel_address
                    && matches!(s.symbol_type, Some('t' | 'T'))
                    && (in_core && s.module.is_none()
                        || module.is_some_and(|module| s.module == Some(module.module)))
                    && symbols.get(index).is_some_and(|next| value < next.address)
            });
        let mut record = row.clone();
        record["position"] = json!(position);
        record["stack_address"] = json!(slot);
        record["address"] = json!(value);
        record["nearest_symbol"] = json!(symbol.map(|s| &s.name));
        record["module"] = json!(
            module
                .map(|module| module.name.as_str())
                .unwrap_or("kernel")
        );
        record["symbol_offset"] = json!(symbol.map(|s| value - s.address));
        record["basis"] = json!(
            "保存的 SP 至 ISF thread_union 边界内的代码地址；栈字扫描，未进行 ORC/帧指针展开，顺序不等于已验证调用关系"
        );
        if !report.push(record) {
            break;
        }
    }
    report.scope = "驻留线程内核栈中的代码地址候选；不是用户栈，也不保证每个值都是返回地址".into();
    Ok(())
}

pub(super) fn capability_names(bits: u64) -> Vec<String> {
    const NAMES: &[&str] = &[
        "CHOWN",
        "DAC_OVERRIDE",
        "DAC_READ_SEARCH",
        "FOWNER",
        "FSETID",
        "KILL",
        "SETGID",
        "SETUID",
        "SETPCAP",
        "LINUX_IMMUTABLE",
        "NET_BIND_SERVICE",
        "NET_BROADCAST",
        "NET_ADMIN",
        "NET_RAW",
        "IPC_LOCK",
        "IPC_OWNER",
        "SYS_MODULE",
        "SYS_RAWIO",
        "SYS_CHROOT",
        "SYS_PTRACE",
        "SYS_PACCT",
        "SYS_ADMIN",
        "SYS_BOOT",
        "SYS_NICE",
        "SYS_RESOURCE",
        "SYS_TIME",
        "SYS_TTY_CONFIG",
        "MKNOD",
        "LEASE",
        "AUDIT_WRITE",
        "AUDIT_CONTROL",
        "SETFCAP",
        "MAC_OVERRIDE",
        "MAC_ADMIN",
        "SYSLOG",
        "WAKE_ALARM",
        "BLOCK_SUSPEND",
        "AUDIT_READ",
        "PERFMON",
        "BPF",
        "CHECKPOINT_RESTORE",
    ];
    (0..64)
        .filter(|bit| bits & (1 << bit) != 0)
        .map(|bit| {
            NAMES
                .get(bit)
                .map(|name| format!("CAP_{name}"))
                .unwrap_or_else(|| format!("CAP_UNKNOWN_{bit}"))
        })
        .collect()
}

fn mappings(
    session: &LinuxAnalysisSession,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    let maps = session.proc_maps(options.pid, options.limit, options.limit)?;
    let mut report = LinuxIrReport::new(
        options,
        "活动进程的已验证 VMA 与 present 用户页；候选属性不等于已确认注入",
    );
    report.complete = maps.complete;
    report
        .warnings
        .extend(maps.warnings.iter().map(|w| w.message.clone()));
    let spaces: HashMap<i32, u64> = maps
        .processes
        .iter()
        .filter_map(|p| p.pgd_physical.map(|dtb| (p.pid, dtb)))
        .collect();
    let mut linked_pids = HashSet::new();
    let mut content_budget = options.max_bytes;
    for map in &maps.records {
        cancel.check_cancelled()?;
        let Some(dtb) = spaces.get(&map.pid) else {
            report.warn(format!("PID {} 没有已验证页表", map.pid));
            continue;
        };
        let space = LinuxX64AddressSpace::new(session.image(), *dtb)?;
        if options.module == "malfind"
            && !(map.vm_flags & 4 != 0 && (map.vm_flags & 2 != 0 || map.file.is_none()))
        {
            continue;
        }
        if options.module != "malfind" && map.byte_offset != 0 {
            continue;
        }
        if options.module == "malfind" {
            let sample = scan_nonzero(
                map.start,
                map.end,
                &mut content_budget,
                cancel,
                |address, bytes| space.read_virtual(address, bytes),
            )?;
            for (start, length) in &sample.missing {
                report
                    .missing_ranges
                    .push(json!({"pid": map.pid, "start": start, "length": length}));
            }
            if !sample.missing.is_empty() {
                report.warn(format!("PID {} 可执行候选中存在缺页", map.pid));
            }
            if sample.budget_reached {
                report.limit_reached = true;
                report.warn("可执行候选的总内容读取预算已用尽；未核对内容的候选仍保留");
            }
            if sample.value.is_none() && sample.missing.is_empty() && !sample.budget_reached {
                continue;
            }
            let mut row = serde_json::to_value(map)?;
            if let Some((address, bytes)) = sample.value {
                row["sample_address"] = json!(address);
                row["sample_hex"] = json!(hex::encode(bytes));
                row["content_status"] = json!("nonzero_resident_sample");
            } else {
                row["content_status"] = json!(if sample.budget_reached {
                    "not_fully_checked_budget"
                } else {
                    "not_fully_checked_missing_pages"
                });
            }
            row["rule"] = json!(if map.vm_flags & 6 == 6 {
                "VMA 同时可写和可执行"
            } else {
                "匿名可执行 VMA"
            });
            row["assessment"] = json!("属性与内容候选；JIT 等正常用途也可能符合，不直接证明注入");
            if !report.push(row) {
                break;
            }
            continue;
        }
        let mut sample = [0u8; 64];
        if let Err(error) = space.read_virtual(map.start, &mut sample) {
            report
                .missing_ranges
                .push(json!({"pid": map.pid, "start": map.start, "length": 64}));
            report.warn(format!(
                "PID {} VMA {:#x} 首页不可读：{error:#}",
                map.pid, map.start
            ));
            continue;
        }
        if sample.starts_with(b"\x7fELF") {
            if sample[4] != 2 || sample[5] != 1 {
                report.warn("ELF 当前仅解析 ELF64 小端格式");
                continue;
            }
            if options.module == "elfs" {
                let mut row = serde_json::to_value(map)?;
                row["elf_type"] = json!(u16::from_le_bytes(sample[16..18].try_into()?));
                row["machine"] = json!(u16::from_le_bytes(sample[18..20].try_into()?));
                row["entry_link_address"] = json!(u64::from_le_bytes(sample[24..32].try_into()?));
                row["scope"] = json!("经 ELF 头验证的映射，不以扩展名判断");
                report.push(row);
            } else if !linked_pids.contains(&map.pid) {
                match libraries(&space, map.start, &sample, options, cancel, &mut report) {
                    Ok(Some(rows)) => {
                        linked_pids.insert(map.pid);
                        for mut row in rows {
                            row["pid"] = json!(map.pid);
                            row["process_name"] = json!(map.process_name);
                            report.push(row);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => report.warn(format!("PID {} 加载器：{error:#}", map.pid)),
                }
            }
        }
        if report.limit_reached {
            break;
        }
    }
    if options.module == "library-list" {
        for pid in spaces.keys().filter(|pid| !linked_pids.contains(pid)) {
            report.warn(format!(
                "PID {pid} 未找到可验证的 DT_DEBUG/link_map；静态链接或缺页均可能导致该情况"
            ));
        }
        report.scope =
            "经 ELF PT_DYNAMIC/DT_DEBUG 证明的运行时加载器 link_map；不等同于按文件名列举映射"
                .into();
    }
    Ok(serde_json::to_value(report)?)
}

pub(super) struct ResidentSample {
    pub value: Option<(u64, Vec<u8>)>,
    pub missing: Vec<(u64, u64)>,
    pub budget_reached: bool,
}

pub(super) fn scan_nonzero(
    start: u64,
    end: u64,
    budget: &mut u64,
    cancel: &CancellationToken,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<ResidentSample> {
    let mut result = ResidentSample {
        value: None,
        missing: Vec::new(),
        budget_reached: false,
    };
    let mut address = start;
    while address < end {
        cancel.check_cancelled()?;
        if *budget == 0 {
            result.budget_reached = true;
            break;
        }
        let length = (end - address).min(4096 - (address & 4095)).min(*budget) as usize;
        let mut bytes = vec![0u8; length];
        *budget -= length as u64;
        match read(address, &mut bytes) {
            Ok(()) => {
                if let Some(index) = bytes.iter().position(|byte| *byte != 0) {
                    result.value = Some((
                        address + index as u64,
                        bytes[index..(index + 64).min(length)].to_vec(),
                    ));
                    break;
                }
            }
            Err(_) => result.missing.push((address, length as u64)),
        }
        address += length as u64;
    }
    Ok(result)
}

fn libraries(
    space: &LinuxX64AddressSpace<'_>,
    base: u64,
    header: &[u8; 64],
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<Option<Vec<Value>>> {
    let phoff = u64::from_le_bytes(header[32..40].try_into()?);
    let size = u16::from_le_bytes(header[54..56].try_into()?) as u64;
    let count = u16::from_le_bytes(header[56..58].try_into()?) as u64;
    ensure!(
        size == 56 && count > 0 && count <= 1024 && phoff < 1024 * 1024,
        "ELF program header 边界无效"
    );
    let mut bias = None;
    let mut dynamic = None;
    for index in 0..count {
        let mut ph = [0u8; 56];
        space.read_virtual(add(base, phoff + index * size)?, &mut ph)?;
        let kind = u32::from_le_bytes(ph[0..4].try_into()?);
        let offset = u64::from_le_bytes(ph[8..16].try_into()?);
        let va = u64::from_le_bytes(ph[16..24].try_into()?);
        if kind == 1 && offset == 0 {
            bias = base.checked_sub(va);
        }
        if kind == 2 {
            dynamic = Some((va, u64::from_le_bytes(ph[40..48].try_into()?)));
        }
    }
    let Some((dynamic, bytes)) = dynamic else {
        return Ok(None);
    };
    let dynamic = add(bias.context("ELF 缺少零偏移 PT_LOAD")?, dynamic)?;
    ensure!(bytes <= 1024 * 1024, "ELF dynamic table 过大");
    let mut debug = 0;
    for i in 0..bytes / 16 {
        let address = add(dynamic, i * 16)?;
        let tag = space.read_u64(address)?;
        if tag == 0 {
            break;
        }
        if tag == 21 {
            debug = space.read_u64(add(address, 8)?)?;
            break;
        }
    }
    if debug == 0 {
        return Ok(None);
    }
    ensure!(
        debug < 0x8000_0000_0000 && debug & 7 == 0,
        "r_debug 不在用户地址空间"
    );
    ensure!(
        (1..=2).contains(&space.read_u32(debug)?),
        "r_debug 版本无效"
    );
    ensure!(
        space.read_u32(add(debug, 24)?)? == 0,
        "加载器正在变更，link_map 不稳定"
    );
    let mut link = space.read_u64(add(debug, 8)?)?;
    let mut previous = 0;
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    while link != 0 {
        cancel.check_cancelled()?;
        let read = (|| -> Result<()> {
            ensure!(
                link < 0x8000_0000_0000 && link & 7 == 0 && seen.insert(link),
                "link_map 指针无效或循环"
            );
            ensure!(rows.len() < options.limit, "link_map 达到上限");
            ensure!(
                space.read_u64(add(link, 32)?)? == previous,
                "link_map 回链不一致"
            );
            let name_ptr = space.read_u64(add(link, 8)?)?;
            // ld.so 的首个 link_map 使用有效指针指向空字符串表示主程序。
            ensure!(
                name_ptr < 0x8000_0000_0000,
                "link_map 名称指针不在用户地址空间"
            );
            let name = if name_ptr == 0 {
                String::new()
            } else {
                let mut first = [0u8; 1];
                space.read_virtual(name_ptr, &mut first)?;
                if first[0] == 0 {
                    String::new()
                } else {
                    crate::linux_process::read_process_c_string(space, name_ptr, 4096)?
                }
            };
            rows.push(
                json!({"link_map": link, "load_bias": space.read_u64(link)?, "name": name,
            "dynamic": space.read_u64(add(link, 16)?)?, "r_debug": debug}),
            );
            previous = link;
            link = space.read_u64(add(link, 24)?)?;
            Ok(())
        })();
        if let Err(error) = read {
            report.warn(format!(
                "r_debug {debug:#x} / link_map {link:#x} 后续链不可读，保留此前验证记录：{error:#}"
            ));
            break;
        }
    }
    Ok(Some(rows))
}
