use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) fn analyze(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    match options.module.as_str() {
        "system" => system(m, report),
        "boottime" => boottime(m, report),
        "iomem" => iomem(m, options, cancel, report),
        "ip-link" | "ip-addr" => interfaces(m, options, cancel, report),
        "arp" => neighbours(m, options, cancel, report),
        "check-idt" => idt(m, cancel, report),
        "keyboard-notifiers" => notifiers(m, options, cancel, report),
        "tty-check" => tty(m, options, cancel, report),
        "ebpf" => ebpf(m, options, cancel, report),
        "kprobes" => kprobes(m, options, cancel, report),
        "ftrace" => ftrace(m, options, cancel, report),
        "tracepoints" => tracepoints(m, options, cancel, report),
        "netfilter" => netfilter(m, options, cancel, report),
        "check-afinfo" => afinfo(m, cancel, report),
        "fbdev" => fbdev(m, options, cancel, report),
        "pidhashtable" => pids(m, options, cancel, report),
        "uptime" | "meminfo" | "cpuinfo" | "btf" | "routes" => {
            super::system::analyze(m, options, cancel, report)
        }
        _ => anyhow::bail!("未注册的内核模块"),
    }
}

fn pids(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let namespace = m.runtime_symbol("init_pid_ns")?;
    let mut objects = Vec::new();
    let numbers = m.isf().field_offset("pid", "numbers")?;
    if m.isf()
        .optional_field_offset("pid_namespace", "idr")?
        .is_some()
    {
        objects = idr_entries(
            m,
            member(m, namespace, "pid_namespace", "idr")?,
            options,
            cancel,
            report,
        )?;
    } else {
        let shift = number(m, m.runtime_symbol("pidhash_shift")?, 4)?;
        ensure!(shift <= 20, "PID 哈希表桶数无效");
        let table = pointer(number(m, m.runtime_symbol("pid_hash")?, 8)?)?;
        let chain = m.isf().field_offset("upid", "pid_chain")?;
        let mut seen = HashSet::new();
        for index in 0..1u64 << shift {
            cancel.check_cancelled()?;
            let head = add(table, index * 8)?;
            let bucket = (|| -> Result<()> {
                let mut previous = head;
                let mut next = number(m, head, 8)?;
                while next != 0 {
                    cancel.check_cancelled()?;
                    pointer(next)?;
                    ensure!(seen.insert(next), "PID 哈希链出现循环");
                    if seen.len() > options.limit {
                        report.limit_reached = true;
                        report.warn("PID 哈希遍历达到上限");
                        break;
                    }
                    ensure!(
                        number(m, add(next, 8)?, 8)? == previous,
                        "PID 哈希链回链不匹配"
                    );
                    let upid = next.checked_sub(chain).context("upid 容器下溢")?;
                    if field(m, upid, "upid", "ns")? == namespace {
                        objects.push(upid.checked_sub(numbers).context("pid 容器下溢")?);
                    }
                    previous = next;
                    next = number(m, next, 8)?;
                }
                Ok(())
            })();
            if let Err(error) = bucket {
                if crate::cancellation::is_cancellation_error(&error) {
                    return Err(error);
                }
                row_error(report, head, error);
            }
            if report.limit_reached {
                break;
            }
        }
    }
    let task_link_offset = m
        .isf()
        .field_offset_any("task_struct", &["pid_links", "pids"])?;
    let mut tasks = HashSet::new();
    for pid in objects {
        cancel.check_cancelled()?;
        let read = (|| -> Result<()> {
            ensure!(
                field(m, pid, "pid", "level")? <= 32,
                "PID namespace 层级无效"
            );
            let upid = add(pid, numbers)?;
            ensure!(
                field(m, upid, "upid", "ns")? == namespace,
                "PID 不属于初始 namespace"
            );
            let nr = field(m, upid, "upid", "nr")?;
            ensure!(nr > 0 && nr <= 4_194_304, "PID 数值无效");
            if options
                .pid
                .is_some_and(|filter| i64::from(filter) != nr as i64)
            {
                return Ok(());
            }
            let head = member(m, pid, "pid", "tasks")?; // PIDTYPE_PID = 0
            let link = number(m, head, 8)?;
            if link == 0 {
                return Ok(());
            }
            pointer(link)?;
            ensure!(
                number(m, add(link, 8)?, 8)? == head,
                "pid.tasks[PIDTYPE_PID] 回链不符"
            );
            let task = link
                .checked_sub(task_link_offset)
                .context("task 容器下溢")?;
            ensure!(
                field(m, task, "task_struct", "pid")? == nr,
                "PID 注册与 task.pid 不一致"
            );
            if !tasks.insert(task) {
                return Ok(());
            }
            let tgid = field(m, task, "task_struct", "tgid")?;
            ensure!(tgid > 0 && tgid <= 4_194_304, "TGID 无效");
            let name = inline_string(m, task, "task_struct", "comm")?;
            report.push(json!({"task": task, "task_hex": format!("{task:#018x}"), "pid_object": pid,
                "pid": nr, "tgid": tgid, "name": name, "leader": nr == tgid,
                "pid_namespace": namespace, "basis": "pid 注册表、upid namespace、task.pid 与 hlist 回链联合校验"}));
            Ok(())
        })();
        if let Err(error) = read {
            row_error(report, pid, error);
        }
        if report.records.len() >= options.limit {
            report.limit_reached = true;
            break;
        }
    }
    report.scope = "初始 PID namespace 的 PID 注册表；包括线程，不以任务链作为枚举入口".into();
    Ok(())
}

fn system(m: &impl LinuxKernelMemory, report: &mut LinuxIrReport) -> Result<()> {
    let uts = m.runtime_symbol("init_uts_ns")?;
    let name = member(m, uts, "uts_namespace", "name")?;
    let mut row = json!({"uts_namespace": uts, "namespace_scope": "initial UTS namespace"});
    for key in [
        "sysname",
        "nodename",
        "release",
        "version",
        "machine",
        "domainname",
    ] {
        match inline_string(m, name, "new_utsname", key) {
            Ok(value) => row[key] = json!(value),
            Err(error) => report.warn(format!("{key}: {error:#}")),
        }
    }
    report.push(row);
    Ok(())
}

pub(super) fn boot_time_ns(m: &impl LinuxKernelMemory) -> Result<i64> {
    let tk = member(
        m,
        m.runtime_symbol("tk_core")?,
        m.isf().symbol_type_name("tk_core").unwrap_or("tk_data"),
        "timekeeper",
    )?;
    let real = number(m, member(m, tk, "timekeeper", "offs_real")?, 8)? as i64;
    let boot = number(m, member(m, tk, "timekeeper", "offs_boot")?, 8)? as i64;
    let value = real.checked_sub(boot).context("启动时间运算溢出")?;
    ensure!(value > 0, "启动时间不在 Unix 纪元之后");
    Ok(value)
}

fn boottime(m: &impl LinuxKernelMemory, report: &mut LinuxIrReport) -> Result<()> {
    let ns = boot_time_ns(m)?;
    let utc = chrono::DateTime::from_timestamp(ns / 1_000_000_000, (ns % 1_000_000_000) as u32)
        .context("启动时间超出范围")?
        .to_rfc3339();
    report.push(json!({"boot_time_utc": utc, "boot_time_unix_ns": ns,
        "namespace_scope": "root time namespace", "basis": "timekeeper.offs_real - timekeeper.offs_boot"}));
    Ok(())
}

fn iomem(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let root = m.runtime_symbol("iomem_resource")?;
    let mut pending = vec![(root, 0usize, None)];
    let mut seen = HashSet::new();
    while let Some((object, depth, expected_parent)) = pending.pop() {
        cancel.check_cancelled()?;
        if !seen.insert(object) {
            report.warn(format!("resource 树重复节点 {object:#x}"));
            continue;
        }
        if seen.len() > options.limit {
            report.limit_reached = true;
            report.warn("resource 树达到上限");
            break;
        }
        let read = (|| -> Result<()> {
            pointer(object)?;
            if let Some(parent) = expected_parent {
                ensure!(
                    field(m, object, "resource", "parent")? == parent,
                    "resource.parent 不匹配"
                );
            }
            let start = field(m, object, "resource", "start")?;
            let end = field(m, object, "resource", "end")?;
            ensure!(end >= start, "resource 区间反向");
            let name = string(m, field(m, object, "resource", "name")?, 4096)?;
            report.push(json!({"resource": object, "depth": depth, "name": name, "start": start,
                "end_inclusive": end, "flags": field(m, object, "resource", "flags")?, "parent": expected_parent}));
            let sibling = field(m, object, "resource", "sibling")?;
            let child = field(m, object, "resource", "child")?;
            if sibling != 0 {
                pending.push((sibling, depth, expected_parent));
            }
            if child != 0 {
                pending.push((child, depth + 1, Some(object)));
            }
            Ok(())
        })();
        if let Err(error) = read {
            row_error(report, object, error);
        }
    }
    Ok(())
}

fn namespaces(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<Vec<u64>> {
    list(
        m,
        m.runtime_symbol("net_namespace_list")?,
        m.isf().field_offset("net", "list")?,
        options.limit,
        cancel,
        report,
    )
}
fn net_id(m: &impl LinuxKernelMemory, net: u64) -> Result<u64> {
    field(m, member(m, net, "net", "ns")?, "ns_common", "inum")
}
fn devices(
    m: &impl LinuxKernelMemory,
    net: u64,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<Vec<u64>> {
    list(
        m,
        member(m, net, "net", "dev_base_head")?,
        m.isf().field_offset("net_device", "dev_list")?,
        options.limit,
        cancel,
        report,
    )
}

fn interfaces(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    for net in namespaces(m, options, cancel, report)? {
        let id = net_id(m, net)?;
        for dev in devices(m, net, options, cancel, report)? {
            cancel.check_cancelled()?;
            let read = (|| -> Result<()> {
                let name = inline_string(m, dev, "net_device", "name")?;
                let index = field(m, dev, "net_device", "ifindex")?;
                if options.module == "ip-link" {
                    let length = field(m, dev, "net_device", "addr_len")?.min(32) as usize;
                    let mut address = vec![0u8; length];
                    if length > 0 {
                        m.read_virtual(field(m, dev, "net_device", "dev_addr")?, &mut address)?;
                    }
                    report.push(json!({"net_namespace": net, "net_ns_id": id, "device": dev, "name": name,
                        "ifindex": index, "mac": address.iter().map(|v| format!("{v:02x}")).collect::<Vec<_>>().join(":"),
                        "mtu": field(m, dev, "net_device", "mtu")?, "flags": field(m, dev, "net_device", "flags")?,
                        "operstate": field(m, dev, "net_device", "operstate")?}));
                } else {
                    let ipv4 = field(m, dev, "net_device", "ip_ptr")?;
                    if ipv4 != 0 {
                        let mut next = field(m, pointer(ipv4)?, "in_device", "ifa_list")?;
                        let mut seen = HashSet::new();
                        while next != 0 {
                            cancel.check_cancelled()?;
                            ensure!(seen.insert(next), "IPv4 地址链循环");
                            ensure!(seen.len() <= options.limit, "IPv4 地址链达到上限");
                            ensure!(
                                field(m, pointer(next)?, "in_ifaddr", "ifa_dev")? == ipv4,
                                "IPv4 地址设备归属不符"
                            );
                            report.push(json!({"net_ns_id": id, "device": dev, "name": name, "ifindex": index,
                                "address_object": next, "family": "IPv4",
                                "address": Ipv4Addr::from((field(m, next, "in_ifaddr", "ifa_local")? as u32).to_le_bytes()).to_string(),
                                "prefix_length": field(m, next, "in_ifaddr", "ifa_prefixlen")?}));
                            next = field(m, next, "in_ifaddr", "ifa_next")?;
                        }
                    }
                    let ipv6 = field(m, dev, "net_device", "ip6_ptr")?;
                    if ipv6 != 0 {
                        for address in list(
                            m,
                            member(m, pointer(ipv6)?, "inet6_dev", "addr_list")?,
                            m.isf().field_offset("inet6_ifaddr", "if_list")?,
                            options.limit,
                            cancel,
                            report,
                        )? {
                            let mut bytes = [0u8; 16];
                            m.read_virtual(
                                member(m, address, "inet6_ifaddr", "addr")?,
                                &mut bytes,
                            )?;
                            ensure!(
                                field(m, address, "inet6_ifaddr", "idev")? == ipv6,
                                "IPv6 地址设备归属不符"
                            );
                            report.push(json!({"net_ns_id": id, "device": dev, "name": name, "ifindex": index,
                                "address_object": address, "family": "IPv6", "address": Ipv6Addr::from(bytes).to_string(),
                                "prefix_length": field(m, address, "inet6_ifaddr", "prefix_len")?}));
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = read {
                row_error(report, dev, error);
            }
            if report.limit_reached {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn neighbours(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let mut available = 0;
    for (symbol, size) in [("arp_tbl", 4), ("nd_tbl", 16)] {
        let Ok(table) = m.runtime_symbol(symbol) else {
            continue;
        };
        available += 1;
        let hash = pointer(field(m, table, "neigh_table", "nht")?)?;
        let shift = field(m, hash, "neigh_hash_table", "hash_shift")?;
        ensure!(shift <= 20, "邻居哈希表过大");
        let buckets = pointer(field(m, hash, "neigh_hash_table", "hash_buckets")?)?;
        let mut seen = HashSet::new();
        for bucket in 0..1u64 << shift {
            cancel.check_cancelled()?;
            let mut next = number(m, add(buckets, bucket * 8)?, 8)?;
            while next != 0 {
                pointer(next)?;
                ensure!(seen.insert(next), "邻居哈希表重复/循环");
                if seen.len() > options.limit {
                    report.limit_reached = true;
                    report.warn("邻居表达到上限");
                    return Ok(());
                }
                let mut key = vec![0u8; size];
                m.read_virtual(member(m, next, "neighbour", "primary_key")?, &mut key)?;
                let dev = pointer(field(m, next, "neighbour", "dev")?)?;
                let addr_len = field(m, dev, "net_device", "addr_len")?.min(32) as usize;
                let mut mac = vec![0u8; addr_len];
                m.read_virtual(member(m, next, "neighbour", "ha")?, &mut mac)?;
                let address = if size == 4 {
                    Ipv4Addr::from(<[u8; 4]>::try_from(key.as_slice())?).to_string()
                } else {
                    Ipv6Addr::from(<[u8; 16]>::try_from(key.as_slice())?).to_string()
                };
                report.push(json!({"neighbour": next, "table": symbol, "device": dev, "address": address,
                    "interface": inline_string(m, dev, "net_device", "name")?, "mac": hex::encode(mac),
                    "state": field(m, next, "neighbour", "nud_state")?}));
                next = field(m, next, "neighbour", "next")?;
            }
        }
    }
    ensure!(available > 0, "ISF 没有 arp_tbl/nd_tbl");
    Ok(())
}

fn callback(m: &impl LinuxKernelMemory, address: u64) -> Value {
    let kernel = m
        .runtime_symbol("_stext")
        .ok()
        .zip(m.runtime_symbol("_etext").ok());
    let mapped = m.translate(address).is_ok();
    let in_kernel = kernel.is_some_and(|(start, end)| start <= address && address < end && mapped);
    json!({"address": address, "address_hex": format!("{address:#018x}"), "mapped": mapped,
        "in_kernel_text": in_kernel, "assessment": if in_kernel { "kernel_text" } else { "needs_module_attribution" },
        "meaning": "范围之外需核对模块；此标记不等于已确认 hook"})
}

fn idt(
    m: &impl LinuxKernelMemory,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let table = m.runtime_symbol("idt_table")?;
    ensure!(
        ["gate_struct", "gate_struct64", "idt_desc"]
            .iter()
            .any(|ty| m.isf().type_size(ty).ok() == Some(16)),
        "缺少 x86_64 16 字节 IDT gate 类型"
    );
    for index in 0..256u64 {
        cancel.check_cancelled()?;
        let object = add(table, index * 16)?;
        let mut gate = [0u8; 16];
        if let Err(error) = m.read_virtual(object, &mut gate) {
            row_error(report, object, error);
            continue;
        }
        let address = u64::from(u16::from_le_bytes([gate[0], gate[1]]))
            | (u64::from(u16::from_le_bytes([gate[6], gate[7]])) << 16)
            | (u64::from(u32::from_le_bytes(gate[8..12].try_into()?)) << 32);
        report.push(
            json!({"index": index, "gate": object, "present": gate[5] & 0x80 != 0,
            "dpl": (gate[5] >> 5) & 3, "selector": u16::from_le_bytes([gate[2], gate[3]]),
            "handler": callback(m, address)}),
        );
    }
    Ok(())
}

fn notifiers(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let head = m.runtime_symbol("keyboard_notifier_list")?;
    let mut next = field(m, head, "atomic_notifier_head", "head")?;
    let mut seen = HashSet::new();
    while next != 0 {
        cancel.check_cancelled()?;
        pointer(next)?;
        ensure!(seen.insert(next), "键盘通知链出现循环");
        if seen.len() > options.limit {
            report.limit_reached = true;
            report.warn("通知链达到上限");
            break;
        }
        report.push(json!({"notifier": next, "priority": field(m, next, "notifier_block", "priority")? as u32 as i32,
            "callback": callback(m, field(m, next, "notifier_block", "notifier_call")?)}));
        next = field(m, next, "notifier_block", "next")?;
    }
    Ok(())
}

fn tty(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    for driver in list(
        m,
        m.runtime_symbol("tty_drivers")?,
        m.isf().field_offset("tty_driver", "tty_drivers")?,
        options.limit,
        cancel,
        report,
    )? {
        let count = field(m, driver, "tty_driver", "num")?;
        let array = field(m, driver, "tty_driver", "ttys")?;
        if array == 0 {
            continue;
        }
        if count > 1 << 20 {
            report.warn(format!("TTY 驱动 {driver:#x} 的数量超出支持范围：{count}"));
            continue;
        }
        if count > options.limit as u64 {
            report.limit_reached = true;
            report.warn("TTY 驱动槽位遍历达到上限");
        }
        for index in 0..count.min(options.limit as u64) {
            cancel.check_cancelled()?;
            let object = number(m, add(array, index * 8)?, 8)?;
            if object == 0 {
                continue;
            }
            let read = (|| -> Result<()> {
                pointer(object)?;
                let ldisc = pointer(field(m, object, "tty_struct", "ldisc")?)?;
                let ops = pointer(field(m, ldisc, "tty_ldisc", "ops")?)?;
                report.push(json!({"tty": object, "driver": driver, "name": inline_string(m, object, "tty_struct", "name")?,
                    "receive_buf": callback(m, field(m, ops, "tty_ldisc_ops", "receive_buf")?)}));
                Ok(())
            })();
            if let Err(error) = read {
                row_error(report, object, error);
            }
            if report.limit_reached {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Modern IDR uses xarray/radix-tree internal entries. A value, retry or sibling marker is
/// never interpreted as a pointer. Every node is visited at most once and heights decrease.
pub(super) fn idr_entries(
    m: &impl LinuxKernelMemory,
    idr: u64,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<Vec<u64>> {
    let root = member(m, idr, "idr", "idr_rt")?;
    let first = if m
        .isf()
        .optional_field_offset("xarray", "xa_head")
        .ok()
        .flatten()
        .is_some()
    {
        field(m, root, "xarray", "xa_head")?
    } else {
        field(m, root, "radix_tree_root", "rnode")?
    };
    let node_ty = if m.isf().type_size("xa_node").is_ok() {
        "xa_node"
    } else {
        "radix_tree_node"
    };
    let slots_offset = m.isf().field_offset(node_ty, "slots")?;
    let slot_count = m.isf().field_array_count(node_ty, "slots")?;
    ensure!(slot_count > 0 && slot_count <= 256, "IDR 节点槽数无效");
    let mut stack = vec![(first, 64u64)];
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    while let Some((entry, parent_shift)) = stack.pop() {
        cancel.check_cancelled()?;
        if entry == 0 {
            continue;
        }
        ensure!(seen.insert(entry), "IDR 节点/条目重复或循环");
        if seen.len() > options.limit.saturating_mul(8) {
            report.limit_reached = true;
            report.warn("IDR 遍历达到上限");
            break;
        }
        if entry & 3 == 2 && entry > 4096 {
            let node = pointer(entry & !3)?;
            let shift = field(m, node, node_ty, "shift")?;
            ensure!(shift < parent_shift && shift < 64, "IDR 节点高度未下降");
            for index in (0..slot_count).rev() {
                stack.push((number(m, add(node, slots_offset + index * 8)?, 8)?, shift));
            }
        } else if entry & 3 == 0 && entry >> 47 == 0x1ffff {
            if entries.len() >= options.limit {
                report.limit_reached = true;
                report.warn("IDR 输出达到上限");
                break;
            }
            entries.push(pointer(entry)?);
        } else {
            report.warn(format!("IDR 非对象标记未作为对象解引用：{entry:#x}"));
        }
    }
    Ok(entries)
}

fn ebpf(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    for prog in idr_entries(m, m.runtime_symbol("prog_idr")?, options, cancel, report)? {
        let read = (|| -> Result<()> {
            let aux = pointer(field(m, prog, "bpf_prog", "aux")?)?;
            let mut tag = [0u8; 8];
            m.read_virtual(member(m, prog, "bpf_prog", "tag")?, &mut tag)?;
            report.push(json!({"program": prog, "id": field(m, aux, "bpf_prog_aux", "id")?,
                "name": inline_string(m, aux, "bpf_prog_aux", "name")?, "tag": hex::encode(tag),
                "type": field(m, prog, "bpf_prog", "type")?, "instructions": field(m, prog, "bpf_prog", "len")?,
                "function": callback(m, field(m, prog, "bpf_prog", "bpf_func")?)}));
            Ok(())
        })();
        if let Err(error) = read {
            row_error(report, prog, error);
        }
    }
    Ok(())
}

fn kprobes(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let table = m.runtime_symbol("kprobe_table")?;
    // Linux's kprobe hash table has 2^6 buckets (KPROBE_HASH_BITS=6).
    let offset = m.isf().field_offset("kprobe", "hlist")?;
    let mut seen = HashSet::new();
    for bucket in 0..64u64 {
        let mut link = number(m, add(table, bucket * 8)?, 8)?;
        let mut expected_pprev = add(table, bucket * 8)?;
        while link != 0 {
            cancel.check_cancelled()?;
            pointer(link)?;
            ensure!(seen.insert(link), "kprobe 哈希链循环");
            ensure!(
                number(m, add(link, 8)?, 8)? == expected_pprev,
                "kprobe hlist 回链不符"
            );
            if seen.len() > options.limit {
                report.limit_reached = true;
                report.warn("kprobe 上限");
                return Ok(());
            }
            let probe = link.checked_sub(offset).context("kprobe 容器地址下溢")?;
            let mut row = json!({"probe": probe, "address": field(m, probe, "kprobe", "addr")?});
            for handler in [
                "pre_handler",
                "post_handler",
                "fault_handler",
                "break_handler",
            ] {
                if m.isf().optional_field_offset("kprobe", handler)?.is_some() {
                    row[handler] = callback(m, field(m, probe, "kprobe", handler)?);
                }
            }
            report.push(row);
            expected_pprev = link;
            link = number(m, link, 8)?;
        }
    }
    Ok(())
}

fn ftrace(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let mut next = number(m, m.runtime_symbol("ftrace_ops_list")?, 8)?;
    let end = m.runtime_symbol("ftrace_list_end").ok();
    let mut seen = HashSet::new();
    while next != 0 && Some(next) != end {
        cancel.check_cancelled()?;
        pointer(next)?;
        ensure!(seen.insert(next), "ftrace_ops 链循环");
        if seen.len() > options.limit {
            report.limit_reached = true;
            report.warn("ftrace 上限");
            break;
        }
        report.push(json!({"ftrace_ops": next, "callback": callback(m, field(m, next, "ftrace_ops", "func")?),
            "flags": field(m, next, "ftrace_ops", "flags")?, "scope": "registered ftrace callbacks"}));
        next = field(m, next, "ftrace_ops", "next")?;
    }
    Ok(())
}

fn tracepoints(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let pointers = m.runtime_symbol("__start___tracepoints_ptrs").is_ok();
    let (start, end, stride) = if pointers {
        (
            m.runtime_symbol("__start___tracepoints_ptrs")?,
            m.runtime_symbol("__stop___tracepoints_ptrs")?,
            m.isf()
                .symbol_array_element_size("__start___tracepoints_ptrs")?,
        )
    } else {
        (
            m.runtime_symbol("__start___tracepoints")?,
            m.runtime_symbol("__stop___tracepoints")?,
            (m.isf().type_size("tracepoint")? + 31) & !31,
        )
    };
    ensure!(
        stride > 0
            && end >= start
            && end - start <= 64 * 1024 * 1024
            && (end - start) % stride == 0,
        "tracepoint 数组边界无效"
    );
    ensure!(
        !pointers || matches!(stride, 4 | 8),
        "未知 tracepoint_ptr_t 宽度"
    );
    let func_size = m.isf().type_size("tracepoint_func")?;
    ensure!((8..=128).contains(&func_size), "tracepoint_func 大小无效");
    let total = (end - start) / stride;
    if total > options.limit as u64 {
        report.limit_reached = true;
        report.warn("Tracepoint 数组达到遍历上限");
    }
    for index in 0..total.min(options.limit as u64) {
        cancel.check_cancelled()?;
        let slot = add(start, index * stride)?;
        let point = if !pointers {
            slot
        } else if stride == 4 {
            slot.checked_add_signed(number(m, slot, 4)? as u32 as i32 as i64)
                .context("Tracepoint 相对地址溢出")?
        } else {
            number(m, slot, 8)?
        };
        let read = tracepoint_functions(m, point, "kernel", func_size, options, cancel, report);
        if let Err(error) = read {
            row_error(report, point, error);
        }
        if report.limit_reached {
            break;
        }
    }
    let modules = crate::linux_kernel_plugins::linux_lsmod(m, options.limit);
    if !modules.complete {
        report.warn("模块链不完整，模块 Tracepoint 范围可能不全");
    }
    for module in modules.modules {
        if report.limit_reached {
            break;
        }
        let read = (|| -> Result<()> {
            let count = field(m, module.module, "module", "num_tracepoints")?;
            ensure!(
                count <= options.limit as u64,
                "模块 Tracepoint 数量超过上限"
            );
            if count == 0 {
                return Ok(());
            }
            let has_pointers = m
                .isf()
                .optional_field_offset("module", "tracepoints_ptrs")?
                .is_some();
            let array = pointer(field(
                m,
                module.module,
                "module",
                if has_pointers {
                    "tracepoints_ptrs"
                } else {
                    "tracepoints"
                },
            )?)?;
            let module_stride = if has_pointers {
                ensure!(pointers, "模块 Tracepoint 指针宽度无法确认");
                stride
            } else {
                (m.isf().type_size("tracepoint")? + 31) & !31
            };
            for index in 0..count {
                cancel.check_cancelled()?;
                let slot = add(array, index * module_stride)?;
                let point = if !has_pointers {
                    slot
                } else if stride == 4 {
                    slot.checked_add_signed(number(m, slot, 4)? as u32 as i32 as i64)
                        .context("模块 Tracepoint 相对地址溢出")?
                } else {
                    number(m, slot, 8)?
                };
                if let Err(error) =
                    tracepoint_functions(m, point, &module.name, func_size, options, cancel, report)
                {
                    if crate::cancellation::is_cancellation_error(&error) {
                        return Err(error);
                    }
                    row_error(report, point, error);
                }
                if report.limit_reached {
                    break;
                }
            }
            Ok(())
        })();
        if let Err(error) = read {
            if crate::cancellation::is_cancellation_error(&error) {
                return Err(error);
            }
            row_error(report, module.module, error);
        }
    }
    report.scope =
        "内核与已验证模块链中的活动 Tracepoint probes（支持 PREL32）；不覆盖脱链模块".into();
    Ok(())
}

fn tracepoint_functions(
    m: &impl LinuxKernelMemory,
    point: u64,
    owner: &str,
    func_size: u64,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let funcs = field(m, point, "tracepoint", "funcs")?;
    if funcs == 0 {
        return Ok(());
    }
    pointer(funcs)?;
    let name = string(m, field(m, point, "tracepoint", "name")?, 4096)?;
    for i in 0..options.limit {
        cancel.check_cancelled()?;
        let func = add(funcs, i as u64 * func_size)?;
        let handler = field(m, func, "tracepoint_func", "func")?;
        if handler == 0 {
            return Ok(());
        }
        if !report.push(json!({"tracepoint": point, "name": name, "owner": owner,
            "function_entry": func, "callback": callback(m, handler)}))
        {
            return Ok(());
        }
    }
    report.warn("tracepoint 函数数组未在上限内终止");
    Ok(())
}

fn netfilter(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let entry_size = m.isf().type_size("nf_hook_entry")?;
    ensure!((8..=128).contains(&entry_size), "nf_hook_entry 大小无效");
    for net in namespaces(m, options, cancel, report)? {
        let nf = member(m, net, "net", "nf")?;
        // Linux 4.9–4.15 stores a two-dimensional array of singly linked nf_hook_entry.
        if m.isf()
            .optional_field_offset("netns_nf", "hooks")?
            .is_some()
            && m.isf()
                .optional_field_offset("nf_hook_entry", "next")?
                .is_some()
        {
            let families = m.isf().field_array_count("netns_nf", "hooks")?;
            ensure!(families > 0 && families <= 32, "Netfilter family 数量无效");
            let hook_count = m.isf().field_size("netns_nf", "hooks")? / families / 8;
            ensure!(
                hook_count > 0 && hook_count <= 32,
                "Netfilter hooks 维度无效"
            );
            let array = member(m, nf, "netns_nf", "hooks")?;
            for family in 0..families {
                for hook in 0..hook_count {
                    let mut current = number(m, add(array, (family * hook_count + hook) * 8)?, 8)?;
                    let mut seen = HashSet::new();
                    while current != 0 {
                        cancel.check_cancelled()?;
                        pointer(current)?;
                        ensure!(seen.insert(current), "Netfilter hook 链循环");
                        if !report.push(json!({"net_namespace": net, "family_number": family, "hook_index": hook,
                            "entry": current, "callback": callback(m, field(m, current, "nf_hook_entry", "hook")?)})) { return Ok(()); }
                        current = field(m, current, "nf_hook_entry", "next")?;
                    }
                }
            }
            continue;
        }
        let mut families = 0;
        for (array, family) in [
            ("hooks_ipv4", "IPv4"),
            ("hooks_ipv6", "IPv6"),
            ("hooks_arp", "ARP"),
            ("hooks_bridge", "bridge"),
        ] {
            if m.isf().optional_field_offset("netns_nf", array)?.is_none() {
                continue;
            }
            families += 1;
            let count = m.isf().field_array_count("netns_nf", array)?;
            ensure!(count <= 32, "Netfilter hook 数量无效");
            for index in 0..count {
                cancel.check_cancelled()?;
                let entries = number(m, add(member(m, nf, "netns_nf", array)?, index * 8)?, 8)?;
                if entries == 0 {
                    continue;
                }
                pointer(entries)?;
                let hooks = field(m, entries, "nf_hook_entries", "num_hook_entries")?;
                ensure!(hooks <= options.limit as u64, "Netfilter entries 超过上限");
                let start = member(m, entries, "nf_hook_entries", "hooks")?;
                for hook in 0..hooks {
                    let object = add(start, hook * entry_size)?;
                    report.push(json!({"net_namespace": net, "family": family, "hook_index": index,
                        "entry": object, "callback": callback(m, field(m, object, "nf_hook_entry", "hook")?)}));
                }
            }
        }
        ensure!(
            families > 0,
            "此内核使用旧 Netfilter 链表布局，需要备选引擎"
        );
    }
    Ok(())
}

fn afinfo(
    m: &impl LinuxKernelMemory,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let mut found = 0;
    for (name, ty) in [
        ("tcp4_seq_ops", "seq_operations"),
        ("tcp6_seq_ops", "seq_operations"),
        ("udp_seq_ops", "seq_operations"),
        ("udp6_seq_ops", "seq_operations"),
        ("tcp4_seq_afinfo", "tcp_seq_afinfo"),
        ("tcp6_seq_afinfo", "tcp_seq_afinfo"),
        ("udp4_seq_afinfo", "udp_seq_afinfo"),
        ("udp6_seq_afinfo", "udp_seq_afinfo"),
    ] {
        cancel.check_cancelled()?;
        let Ok(object) = m.runtime_symbol(name) else {
            continue;
        };
        let ops = if ty == "seq_operations" {
            object
        } else if m.isf().optional_field_offset(ty, "seq_ops")?.is_some() {
            member(m, object, ty, "seq_ops")?
        } else {
            report.push(
                json!({"symbol": name, "object": object, "operation": "show",
                    "callback": callback(m, field(m, object, ty, "seq_show")?)}),
            );
            found += 1;
            continue;
        };
        found += 1;
        for key in ["start", "stop", "next", "show"] {
            report.push(json!({"symbol": name, "object": object, "operation": key, "callback": callback(m, field(m, ops, "seq_operations", key)?)}));
        }
    }
    ensure!(found > 0, "ISF 没有可核对的 TCP/UDP seq_operations");
    Ok(())
}

fn fbdev(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let count = number(
        m,
        m.runtime_symbol("num_registered_fb")
            .or_else(|_| m.runtime_symbol("nr_registered_fb"))?,
        4,
    )?;
    ensure!(count <= 32, "framebuffer 数量无效");
    let array = m.runtime_symbol("registered_fb")?;
    // registered_fb is a fixed FB_MAX=32 array; holes are valid and nr_registered_fb is a count.
    for index in 0..32u64 {
        cancel.check_cancelled()?;
        let info = number(m, add(array, index * 8)?, 8)?;
        if info == 0 {
            continue;
        }
        pointer(info)?;
        let var = member(m, info, "fb_info", "var")?;
        let fix = member(m, info, "fb_info", "fix")?;
        let mut row = json!({"framebuffer": info, "index": index,
            "id": inline_string(m, fix, "fb_fix_screeninfo", "id")?,
            "width": field(m, var, "fb_var_screeninfo", "xres")?, "height": field(m, var, "fb_var_screeninfo", "yres")?,
            "bits_per_pixel": field(m, var, "fb_var_screeninfo", "bits_per_pixel")?,
            "line_length": field(m, fix, "fb_fix_screeninfo", "line_length")?,
            "screen_base": field(m, info, "fb_info", "screen_base")?,
            "size": field(m, fix, "fb_fix_screeninfo", "smem_len")?});
        if let Some(root) = &options.framebuffer_output {
            let output = root.join(format!("framebuffer-{index}-{info:016x}.bmp"));
            match super::framebuffer::dump(m, info, &output, options.max_bytes, cancel) {
                Ok(bytes) => {
                    row["output_path"] = json!(output);
                    row["output_bytes"] = json!(bytes);
                }
                Err(error) => {
                    if crate::cancellation::is_cancellation_error(&error) {
                        return Err(error);
                    }
                    row["capture_error"] = json!(format!("{error:#}"));
                    row_error(report, info, error);
                }
            }
        }
        row["scope"] = json!("已注册 fbdev；不覆盖 DRM/Wayland 合成表面或未采集显存");
        report.push(row);
    }
    if report.records.len() as u64 != count {
        report.warn("framebuffer 指针数与注册数量不一致");
    }
    Ok(())
}
