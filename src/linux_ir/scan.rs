use super::*;
use std::collections::HashMap;

const CLASSES: &[&str] = &[
    "fair_sched_class",
    "idle_sched_class",
    "rt_sched_class",
    "dl_sched_class",
    "stop_sched_class",
    "ext_sched_class",
];

pub(super) fn tasks(
    session: &LinuxAnalysisSession,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    let mut report = LinuxIrReport::new(
        options,
        "已采集物理区间中的调度类指针与 task_struct 字段候选；残留对象与活动进程不同，未命中活动链不单独证明隐藏",
    );
    let m = match TaskMemory::new(session) {
        Ok(m) => m,
        Err(error) => {
            report.unavailable(format!("{error:#}"));
            return Ok(serde_json::to_value(report)?);
        }
    };
    let layout = (|| -> Result<_> {
        let size = m.isf().type_size("task_struct")?;
        ensure!(size <= 65536, "task_struct 大小越界");
        let offset = m.isf().field_offset("task_struct", "sched_class")?;
        ensure!(offset + 8 <= size, "sched_class 字段越界");
        let seeds: Vec<_> = CLASSES
            .iter()
            .filter_map(|name| {
                m.runtime_symbol(name)
                    .ok()
                    .map(|address| (*name, address.to_le_bytes()))
            })
            .collect();
        ensure!(!seeds.is_empty(), "ISF 没有可用的内核调度类符号");
        Ok((offset, seeds))
    })();
    let (offset, seeds) = match layout {
        Ok(layout) => layout,
        Err(error) => {
            report.unavailable(format!("{error:#}"));
            return Ok(serde_json::to_value(report)?);
        }
    };
    let active = session.processes(options.limit)?;
    let known: HashMap<_, _> = active
        .processes
        .iter()
        .filter_map(|task| {
            m.translate(task.task)
                .ok()
                .map(|physical| (physical, task.task))
        })
        .collect();
    if !active.complete {
        report.warn("活动链不完整，in_active_list=false 只表示本次未交叉命中");
    }
    let patterns: Vec<_> = seeds.iter().map(|(_, bytes)| bytes.as_slice()).collect();
    let found = crate::scan::scan_patterns_streaming_cancellable(
        session.image(),
        &patterns,
        options.limit,
        1024 * 1024,
        cancel,
    )?;
    if found.truncated {
        report.limit_reached = true;
        report.warn("调度类指针命中达到扫描上限");
    }
    if !session.image().missing_ranges().is_empty() {
        report.warn("镜像存在未采集物理区间，扫描仅覆盖实际可读范围");
    }
    for hit in found.hits {
        cancel.check_cancelled()?;
        let Some(physical) = hit
            .physical_address
            .checked_sub(offset)
            .filter(|p| p & 7 == 0)
        else {
            continue;
        };
        let read = |name: &str| -> Result<u64> {
            let at = add(physical, m.isf().field_offset("task_struct", name)?)?;
            let width = m.isf().field_size("task_struct", name)?;
            ensure!(matches!(width, 1 | 2 | 4 | 8), "task 字段宽度不受支持");
            let mut bytes = [0; 8];
            session
                .image()
                .read_physical(at, &mut bytes[..width as usize])?;
            Ok(u64::from_le_bytes(bytes))
        };
        let candidate = (|| -> Result<Value> {
            let pid = read("pid")?;
            let tgid = read("tgid")?;
            let exit = read("exit_state")?;
            let mut comm = [0; 16];
            session.image().read_physical(
                add(physical, m.isf().field_offset("task_struct", "comm")?)?,
                &mut comm,
            )?;
            ensure!(valid_task_fields(pid, tgid, exit, &comm), "非 task 候选");
            let end = comm.iter().position(|b| *b == 0).context("comm 未终止")?;
            Ok(
                json!({"physical_address": physical, "physical_hex": format!("{physical:#018x}"),
                "image_file_offset": session.image().physical_to_file_offset(physical),
                "source_location": session.image().source_location(physical),
                "task": known.get(&physical), "pid": pid, "tgid": tgid,
                "name": String::from_utf8_lossy(&comm[..end]), "exit_state": exit,
                "sched_class": seeds[hit.pattern_index].0, "in_active_list": known.contains_key(&physical),
                "kernel_thread": read("flags").ok().map(|flags| flags & 0x0020_0000 != 0),
                "basis": "精确 ISF 调度类指针、PID/TGID、退出状态与 comm 联合校验；物理残留候选"}),
            )
        })();
        if let Ok(row) = candidate
            && options
                .pid
                .is_none_or(|pid| row["pid"].as_u64() == Some(pid as u64))
            && !report.push(row)
        {
            break;
        }
    }
    Ok(serde_json::to_value(report)?)
}

pub(super) fn valid_task_fields(pid: u64, tgid: u64, exit: u64, comm: &[u8; 16]) -> bool {
    (1..=4_194_304).contains(&pid)
        && (1..=4_194_304).contains(&tgid)
        && matches!(exit, 0 | 16 | 32 | 48)
        && comm
            .iter()
            .position(|b| *b == 0)
            .is_some_and(|end| end > 0 && comm[..end].iter().all(|b| *b >= 32))
}
