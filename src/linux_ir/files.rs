use super::*;
use crate::linux_files::LinuxFileScanRecord;

pub(super) fn persistence_rule(path: &str) -> Option<&'static str> {
    if path == "/etc/crontab"
        || path == "/etc/anacrontab"
        || path.starts_with("/etc/cron.")
        || path.starts_with("/var/spool/cron/")
    {
        Some("cron/at 定时执行配置")
    } else if path.starts_with("/etc/systemd/system/")
        || path.starts_with("/usr/lib/systemd/system/")
        || path.starts_with("/lib/systemd/system/")
    {
        Some("systemd 服务/定时器配置")
    } else if path == "/etc/ld.so.preload"
        || path == "/etc/ld.so.conf"
        || path.starts_with("/etc/ld.so.conf.d/")
    {
        Some("动态链接器配置")
    } else if path == "/etc/rc.local"
        || path.starts_with("/etc/init.d/")
        || path.starts_with("/etc/rc") && path.contains(".d/")
    {
        Some("系统启动脚本")
    } else if path == "/etc/profile"
        || path == "/etc/bash.bashrc"
        || path.starts_with("/etc/profile.d/")
        || ["/.bashrc", "/.bash_profile", "/.profile", "/.zshrc"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
    {
        Some("Shell 启动配置")
    } else if path.contains("/.ssh/") || path.starts_with("/etc/ssh/") {
        Some("SSH 配置/授权文件")
    } else if path.starts_with("/etc/pam.d/") || path.starts_with("/etc/sudoers") {
        Some("认证/权限配置")
    } else if ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"].contains(&path) {
        Some("账户配置")
    } else if path.contains("/.config/autostart/") || path.starts_with("/etc/xdg/autostart/") {
        Some("桌面自启动配置")
    } else {
        None
    }
}

fn log_file(path: &str) -> bool {
    path.starts_with("/var/log/")
        || path.starts_with("/run/log/journal/")
        || [
            "/.bash_history",
            "/.zsh_history",
            "/.mysql_history",
            "/.viminfo",
            "/.local/share/fish/fish_history",
        ]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

pub(super) fn resolver_candidate(path: &str) -> bool {
    [
        "/etc/resolv.conf",
        "/run/systemd/resolve/resolv.conf",
        "/run/systemd/resolve/stub-resolv.conf",
        // A separately mounted /run tmpfs has its own superblock-relative root.
        "/systemd/resolve/resolv.conf",
        "/systemd/resolve/stub-resolv.conf",
    ]
    .contains(&path)
}

pub(super) fn analyze(
    session: &LinuxAnalysisSession,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    if options.module == "file-content" {
        ensure!(
            options.path.as_ref().is_some_and(|p| p.starts_with('/')),
            "file-content 需要 --path /Linux/绝对路径"
        );
    }
    let scan = session.files(options.limit)?;
    let mut report = LinuxIrReport::new(
        options,
        "驻留 VFS 页缓存；路径以所属 superblock 为根，保留 dentry/inode 归属；不证明配置已执行",
    );
    report.complete = scan.complete;
    report.limit_reached = scan.limit_reached;
    report
        .warnings
        .extend(scan.warnings.iter().take(64).map(|w| w.message.clone()));
    if options.module == "timeline" {
        process_timeline(session, options, cancel, &mut report)?;
    }
    let mut content_budget = options.max_bytes;
    for file in &scan.records {
        cancel.check_cancelled()?;
        let Some(path) = file.path.as_deref() else {
            continue;
        };
        if options.path.as_ref().is_some_and(|filter| {
            path != filter && !path.starts_with(&format!("{}/", filter.trim_end_matches('/')))
        }) {
            continue;
        }
        if options.module == "timeline" {
            for (kind, timestamp) in [
                ("ACCESS", &file.accessed_utc),
                ("MODIFY", &file.modified_utc),
                ("CHANGE", &file.changed_utc),
            ] {
                if let Some(timestamp) = timestamp {
                    report.push(json!({"timestamp": timestamp, "event": kind, "description": path,
                        "source": "inode timestamp", "dentry": file.dentry, "inode": file.inode, "superblock": file.superblock,
                        "path_scope": file.path_scope}));
                }
            }
        } else {
            let rule = persistence_rule(path);
            if options.module == "persistence" && rule.is_none() {
                continue;
            }
            if options.module == "logs" && !log_file(path) {
                continue;
            }
            if options.module == "dns" && !resolver_candidate(path) {
                continue;
            }
            if options.module == "pagecache-recovery" && file.mode & 0xf000 != 0x8000 {
                continue;
            }
            let mut row = serde_json::to_value(file)?;
            row["rule"] = json!(rule);
            row["interpretation"] =
                json!("文件元数据/驻留内容；路径符合规则不等于已确认持久化或恶意行为");
            if options.module == "dns" {
                row["interpretation"] = json!("解析器配置的驻留字节；不代表 DNS 查询或响应历史");
            }
            if options.module == "dns" && file.mode & 0xf000 != 0x8000 {
                row["content_status"] = json!("metadata_only");
                row["content_error"] =
                    json!("非普通文件，仅有路径元数据；没有据此读取或确认符号链接目标");
                report.warn(format!(
                    "{path} 仅有非普通文件元数据，不能视为解析器配置已恢复"
                ));
            }
            if file.file_type == "regular" || file.mode & 0xf000 == 0x8000 {
                if content_budget == 0 {
                    row["content_status"] = json!("not_checked");
                    row["content_error"] = json!("本次内容读取预算已用完，可按路径单独核对");
                    report.complete = false;
                } else {
                    content_budget = content_budget.saturating_sub(add_content(
                        session,
                        file,
                        content_budget,
                        &mut row,
                        &mut report,
                        cancel,
                    )?);
                }
            }
            if options.module == "pagecache-recovery" {
                if let Some(row) = row.as_object_mut() {
                    row.remove("content_fragments");
                    row.remove("content_text_runs");
                }
                row["interpretation"] = json!(
                    "按读取预算核对页缓存恢复范围；recovered_bytes 是实际恢复量，缓存页数量不是恢复量；可按 dentry 单独导出"
                );
            }
            report.push(row);
        }
        if report.limit_reached {
            break;
        }
    }
    if options.module == "timeline" {
        report.records.sort_by(|a, b| {
            b.get("timestamp")
                .and_then(Value::as_str)
                .cmp(&a.get("timestamp").and_then(Value::as_str))
        });
    }
    if matches!(options.module.as_str(), "file-content" | "dns") && report.records.is_empty() {
        report.warn("当前驻留 VFS 范围没有该路径；这不证明磁盘上不存在该文件");
    }
    Ok(serde_json::to_value(report)?)
}

fn process_timeline(
    session: &LinuxAnalysisSession,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    // Reserve process evidence before the much larger inode timeline reaches the shared limit.
    // A missing wall clock must not discard a verified relative start_time.
    let boot = TaskMemory::new(session)
        .and_then(|memory| super::kernel::boot_time_ns(&memory))
        .ok();
    match session.processes(options.limit) {
        Ok(tasks) => {
            if !tasks.complete {
                report.warn("进程链不完整，时间线仅含已验证进程");
            }
            for task in tasks
                .processes
                .iter()
                .filter(|p| options.pid.is_none_or(|pid| p.pid == pid))
            {
                cancel.check_cancelled()?;
                let Some(start) = task.start_time_ns else {
                    continue;
                };
                if !report.push(json!({"event":"PROCESS_START","pid":task.pid,"description":task.name,
                    "task":task.task,"monotonic_ns":start,"root_boot_time_unix_ns":boot,"timestamp":Value::Null,
                    "source":"task_struct.start_time (monotonic; suspend adjustment unavailable)"})) { break; }
            }
        }
        Err(error) => {
            if crate::cancellation::is_cancellation_error(&error) {
                return Err(error);
            }
            report.warn(format!("进程时间线不可用：{error:#}"));
        }
    }
    Ok(())
}

fn add_content(
    session: &LinuxAnalysisSession,
    file: &LinuxFileScanRecord,
    budget: u64,
    row: &mut Value,
    report: &mut LinuxIrReport,
    cancel: &CancellationToken,
) -> Result<u64> {
    match crate::linux_pagecache::read_validated_file_prefix(
        session.image(),
        session.kernel(),
        file,
        budget,
    ) {
        Ok(recovered) => {
            if report.module == "dns" {
                let resident = super::journal::Resident::new(
                    &recovered.bytes,
                    recovered
                        .report
                        .extents
                        .iter()
                        .map(|e| (e.file_offset, e.length)),
                );
                if let Ok(resident) = resident {
                    row["resolver_directives"] = json!(super::journal::text_lines(&resident, recovered.report.logical_size)
                        .into_iter().filter_map(|(offset, line)| {
                            let mut words = line.split('#').next().unwrap_or("").split_whitespace();
                            let key = words.next()?;
                            ["nameserver", "search", "domain", "options"].contains(&key).then(|| json!({
                                "file_offset":offset,"directive":key,"values":words.collect::<Vec<_>>()}))
                        }).collect::<Vec<_>>());
                }
            }
            // Only display real extents. The transport buffer contains zero-filled gaps which
            // must never become fabricated file contents or joined log lines.
            let mut fragments = Vec::new();
            for extent in &recovered.report.extents {
                cancel.check_cancelled()?;
                let range = usize::try_from(extent.file_offset)
                    .ok()
                    .zip(usize::try_from(extent.length).ok())
                    .and_then(|(start, length)| start.checked_add(length).map(|end| (start, end)))
                    .and_then(|(start, end)| recovered.bytes.get(start..end));
                if let Some(bytes) = range {
                    let text = std::str::from_utf8(bytes)
                        .ok()
                        .filter(|text| !text.contains('\0'));
                    fragments.push(
                        json!({"file_offset": extent.file_offset, "length": extent.length,
                        "physical_address": extent.physical_address, "text_utf8": text,
                        "preview_hex": hex::encode(&bytes[..bytes.len().min(256)])}),
                    );
                }
            }
            row["content_fragments"] = json!(fragments);
            match content_text_runs(&recovered.bytes, &recovered.report.extents, cancel) {
                Ok(Some(runs)) => row["content_text_runs"] = json!(runs),
                Ok(None) => {}
                Err(error) => {
                    if crate::cancellation::is_cancellation_error(&error) {
                        return Err(error);
                    }
                    row["content_text_error"] = json!(format!("{error:#}"));
                    report.warn(format!("文件连续文本范围无法核对：{error:#}"));
                }
            }
            row["recovery"] = serde_json::to_value(&recovered.report).unwrap_or(Value::Null);
            row["content_status"] = json!(if recovered.report.complete {
                "complete"
            } else {
                "partial"
            });
            if !recovered.report.complete {
                report.warn(format!(
                    "{} 页缓存内容不完整",
                    file.path.as_deref().unwrap_or("未知路径")
                ));
            }
            Ok(recovered.bytes.len() as u64)
        }
        Err(error) => {
            if crate::cancellation::is_cancellation_error(&error) {
                return Err(error);
            }
            row["content_status"] = json!("unavailable");
            row["content_error"] = json!(format!("{error:#}"));
            report.warn(format!("dentry {:#x} 无法核对内容：{error:#}", file.dentry));
            Ok(file
                .size
                .and_then(|size| u64::try_from(size).ok())
                .unwrap_or(budget)
                .min(budget))
        }
    }
}

/// Decode adjacent file bytes even when their physical pages are discontiguous.
/// Keep the original fragment contract. New runs reference recovery.extents by index;
/// no single physical address is invented for a run crossing several physical extents.
/// Emit this optional representation only when it recovers a split UTF-8 character.
pub(super) fn content_text_runs(
    bytes: &[u8],
    extents: &[crate::linux_pagecache::LinuxRecoveredExtent],
    cancel: &CancellationToken,
) -> Result<Option<Vec<Value>>> {
    let mut ranges = Vec::with_capacity(extents.len());
    let mut previous_end = 0;
    for extent in extents {
        cancel.check_cancelled()?;
        let start = usize::try_from(extent.file_offset)?;
        let end = start
            .checked_add(usize::try_from(extent.length)?)
            .context("文本范围溢出")?;
        ensure!(
            end > start && end <= bytes.len() && start >= previous_end,
            "文本物理区段对应的文件范围无效、重叠或乱序"
        );
        extent
            .physical_address
            .checked_add(extent.length)
            .context("文本物理范围溢出")?;
        ranges.push((start, end));
        previous_end = end;
    }
    let text = |start: usize, end: usize| {
        std::str::from_utf8(&bytes[start..end])
            .ok()
            .filter(|text| !text.contains('\0'))
    };
    let emit = |first: usize, last: usize| {
        let (start, end) = (ranges[first].0, ranges[last - 1].1);
        json!({"file_offset":start,"length":end - start,"text_utf8":text(start, end),
            "preview_hex":hex::encode(&bytes[start..end.min(start + 256)]),
            "extent_start_index":first,"extent_count":last - first})
    };
    let mut blocks = Vec::new();
    let mut recovered_split = false;
    let mut first = 0;
    while first < ranges.len() {
        cancel.check_cancelled()?;
        let mut last = first + 1;
        while last < ranges.len() && ranges[last - 1].1 == ranges[last].0 {
            cancel.check_cancelled()?;
            last += 1;
        }
        if text(ranges[first].0, ranges[last - 1].1).is_some() {
            if last - first > 1
                && ranges[first..last]
                    .iter()
                    .any(|&(start, end)| text(start, end).is_none())
            {
                recovered_split = true;
            }
            blocks.push((first, last));
        } else {
            // An unrelated invalid byte must not hide readable original fragments.
            for index in first..last {
                cancel.check_cancelled()?;
                blocks.push((index, index + 1));
            }
        }
        first = last;
    }
    cancel.check_cancelled()?;
    if !recovered_split {
        return Ok(None);
    }
    let mut runs = Vec::with_capacity(blocks.len());
    for (first, last) in blocks {
        cancel.check_cancelled()?;
        runs.push(emit(first, last));
    }
    Ok(Some(runs))
}
