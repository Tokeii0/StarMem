//! Page-cache logs and systemd journal entry arrays. Offsets are file offsets, never physical addresses.
//! Format reference: https://systemd.io/JOURNAL_FILE_FORMAT/ . No filesystem journal replay or FSS verification.
use super::*;
use std::collections::BTreeMap;
use std::io::Read;

pub(super) struct Resident<'a> {
    pub bytes: &'a [u8],
    pub ranges: Vec<(usize, usize)>,
}
impl<'a> Resident<'a> {
    pub(super) fn new(
        bytes: &'a [u8],
        ranges: impl IntoIterator<Item = (u64, u64)>,
    ) -> Result<Self> {
        let mut sorted = Vec::new();
        for (offset, length) in ranges {
            let start = usize::try_from(offset)?;
            let end = start
                .checked_add(usize::try_from(length)?)
                .context("驻留范围溢出")?;
            ensure!(end <= bytes.len(), "驻留范围超出恢复缓冲区");
            if start != end {
                sorted.push((start, end));
            }
        }
        sorted.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in sorted {
            if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        Ok(Self {
            bytes,
            ranges: merged,
        })
    }
    pub(super) fn read(&self, offset: u64, length: u64) -> Result<&'a [u8]> {
        let start = usize::try_from(offset)?;
        let end = start
            .checked_add(usize::try_from(length)?)
            .context("文件区间溢出")?;
        let index = self.ranges.partition_point(|range| range.0 <= start);
        ensure!(
            index > 0 && self.ranges[index - 1].1 >= end,
            "文件区间 {offset:#x}+{length:#x} 未完整驻留"
        );
        self.bytes.get(start..end).context("文件区间越界")
    }
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .context("缺少 64 位字段")?
            .try_into()?,
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("缺少 32 位字段")?
            .try_into()?,
    ))
}

pub(super) fn crash_rule(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    for (rule, needles) in [
        (
            "panic",
            &["kernel panic - not syncing", "panic:", "fatal exception"] as &[&str],
        ),
        (
            "oops",
            &[
                "oops:",
                "kernel bug at",
                "general protection fault:",
                "unable to handle kernel",
            ],
        ),
        ("call_trace", &["call trace:", "call stack:"]),
        (
            "hung_task",
            &[
                "soft lockup",
                "hard lockup",
                "blocked for more than",
                "rcu_sched detected stalls",
            ],
        ),
        (
            "filesystem_error",
            &[
                "ext4-fs error",
                "xfs (",
                "btrfs error",
                "jbd2: error",
                "aborting journal",
            ],
        ),
        (
            "resource_or_io",
            &[
                "out of memory:",
                "oom-kill:",
                "killed process ",
                "i/o error",
                "buffer i/o error",
            ],
        ),
    ] {
        if needles.iter().any(|needle| lower.contains(needle)) {
            if rule == "filesystem_error"
                && lower.contains("xfs (")
                && !lower.contains("error")
                && !lower.contains("corrupt")
            {
                continue;
            }
            return Some(rule);
        }
    }
    None
}

pub(super) fn text_lines(resident: &Resident<'_>, logical_size: u64) -> Vec<(u64, String)> {
    let mut lines = Vec::new();
    for &(start, end) in &resident.ranges {
        let mut cursor = start;
        // At a gap boundary, the first bytes may be the suffix of an earlier line.
        if start != 0 {
            let Some(newline) = resident.bytes[start..end].iter().position(|b| *b == b'\n') else {
                continue;
            };
            cursor += newline + 1;
        }
        while cursor < end {
            let tail = &resident.bytes[cursor..end];
            let newline = tail.iter().position(|b| *b == b'\n');
            if newline.is_none() && end as u64 != logical_size {
                break;
            }
            let size = newline.unwrap_or(tail.len());
            if size <= 16 * 1024
                && let Ok(line) = std::str::from_utf8(&tail[..size])
                && !line.contains('\0')
            {
                lines.push((cursor as u64, line.trim_end_matches('\r').to_owned()));
            }
            cursor += size + usize::from(newline.is_some());
        }
    }
    lines
}

pub(super) fn journal_path(path: &str) -> bool {
    // VFS paths are relative to their superblock; /run or /var/log may be separate mounts.
    [
        "/var/log/journal/",
        "/run/log/journal/",
        "/log/journal/",
        "/journal/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
        && (path.ends_with(".journal") || path.ends_with(".journal~"))
}

pub(super) fn analyze(
    session: &LinuxAnalysisSession,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    let mut report = LinuxIrReport::new(
        options,
        "已验证内核消息及 VFS 页缓存日志；缺口不补造日志，关键字为排查线索",
    );
    let mut readable_sources = 0;
    if options.module != "journald" {
        match TaskMemory::new(session) {
            Ok(memory) => {
                let kmsg = crate::linux_kernel_plugins::linux_kmsg(
                    &memory,
                    &crate::linux_kernel_plugins::LinuxKmsgOptions {
                        limit: options.limit,
                        ..Default::default()
                    },
                );
                readable_sources += usize::from(kmsg.available);
                hunting::source_status(&mut report, "kmsg", &serde_json::to_value(&kmsg)?);
                let mut context_left: usize = 0;
                for item in &kmsg.records {
                    cancel.check_cancelled()?;
                    let rule = crash_rule(&item.text);
                    if rule.is_some() || options.module == "crash-traces" && context_left > 0 {
                        let mut row = serde_json::to_value(item)?;
                        row["kind"] = json!(if rule.is_some() {
                            "crash_indicator"
                        } else {
                            "trace_context"
                        });
                        row["rule"] = json!(rule);
                        row["interpretation"] = json!("内核消息文本；不等于已重建调用栈或确认宕机");
                        report.push(row);
                    }
                    if rule.is_some() {
                        context_left = 32;
                    } else {
                        context_left = context_left.saturating_sub(1);
                    }
                    if report.limit_reached {
                        break;
                    }
                }
            }
            Err(error) => hunting::source_error(&mut report, "kmsg", &error),
        }
    }
    let files = session.files(options.limit)?;
    if !files.complete {
        report.warn("VFS 日志枚举不完整");
    }
    report
        .warnings
        .extend(files.warnings.iter().take(32).map(|w| w.message.clone()));
    let mut budget = options.max_bytes;
    let mut decoded_budget = options.max_bytes;
    for file in files.records.iter().filter(|f| f.mode & 0xf000 == 0x8000) {
        cancel.check_cancelled()?;
        if report.limit_reached {
            break;
        }
        let Some(path) = file.path.as_deref() else {
            continue;
        };
        if options.path.as_ref().is_some_and(|filter| {
            path != filter && !path.starts_with(&format!("{}/", filter.trim_end_matches('/')))
        }) {
            continue;
        }
        let binary = journal_path(path);
        if options.module == "journald" {
            if !binary {
                continue;
            }
        } else if binary
            || !path.starts_with("/var/log/")
            || path.ends_with(".gz")
            || path.ends_with(".xz")
        {
            continue;
        }
        let mut owner = json!({"kind":"file_status","source":"pagecache","path":path,"path_scope":file.path_scope,
            "dentry":file.dentry,"inode":file.inode,"superblock":file.superblock});
        if budget == 0 {
            owner["status"] = json!("not_checked_budget");
            report.push(owner);
            report.complete = false;
            continue;
        }
        let cap = if binary {
            budget
        } else {
            budget.min(256 * 1024)
        };
        let charge = file
            .size
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(cap)
            .min(cap);
        budget = budget.saturating_sub(charge);
        match crate::linux_pagecache::read_validated_file_prefix(
            session.image(),
            session.kernel(),
            file,
            cap,
        ) {
            Ok(recovered) => {
                readable_sources += 1;
                let resident = Resident::new(
                    &recovered.bytes,
                    recovered
                        .report
                        .extents
                        .iter()
                        .map(|e| (e.file_offset, e.length)),
                )?;
                owner["recovery"] = serde_json::to_value(&recovered.report)?;
                owner["status"] = json!(if recovered.report.complete {
                    "complete"
                } else {
                    "partial"
                });
                if !recovered.report.complete {
                    report.warn(format!("{path} 恢复范围不完整"));
                }
                if !report.push(owner.clone()) {
                    break;
                }
                if binary {
                    let before = report.records.len();
                    if let Err(error) = parse_journal(
                        &resident,
                        recovered.report.logical_size,
                        &owner,
                        &mut decoded_budget,
                        options,
                        cancel,
                        &mut report,
                    ) {
                        if crate::cancellation::is_cancellation_error(&error) {
                            return Err(error);
                        }
                        report.warn(format!("{path} journal 结构：{error:#}"));
                    }
                    if report.records.len() == before {
                        field_candidates(
                            &resident,
                            &owner,
                            &mut decoded_budget,
                            cancel,
                            &mut report,
                        )?;
                    }
                } else {
                    let mut context_left: usize = 0;
                    for (offset, line) in text_lines(&resident, recovered.report.logical_size) {
                        cancel.check_cancelled()?;
                        let rule = crash_rule(&line);
                        if rule.is_some() || options.module == "crash-traces" && context_left > 0 {
                            report.push(json!({"kind":if rule.is_some() {"crash_indicator"} else {"trace_context"},
                                "source":"pagecache","path":path,"dentry":file.dentry,"inode":file.inode,"superblock":file.superblock,
                                "path_scope":file.path_scope,"file_offset":offset,"text":line,"rule":rule,
                                "timestamp":Value::Null,"timestamp_basis":"保留原文，未推测文本时间的年份/时区"}));
                        }
                        if rule.is_some() {
                            context_left = 32;
                        } else {
                            context_left = context_left.saturating_sub(1);
                        }
                        if report.limit_reached {
                            break;
                        }
                    }
                }
            }
            Err(error) => {
                if crate::cancellation::is_cancellation_error(&error) {
                    return Err(error);
                }
                owner["status"] = json!("unavailable");
                owner["error"] = json!(format!("{error:#}"));
                report.push(owner);
                report.warn(format!("{path} 页缓存无法读取"));
            }
        }
    }
    if readable_sources == 0 {
        report.unavailable("当前范围没有可读取日志；不能据此排除崩溃或历史日志");
    }
    if options.module == "crash-summary" {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for row in report
            .records
            .iter()
            .filter(|r| r["kind"] == "crash_indicator")
        {
            *counts
                .entry(row["rule"].as_str().unwrap_or("unknown").into())
                .or_default() += 1;
        }
        if report.records.len() >= report.limit {
            report.records.pop();
        }
        report.records.insert(0, json!({"kind":"crash_summary","readable_sources":readable_sources,"indicator_counts":counts,
            "complete":report.complete,"assessment":"日志中的规则命中；重复日志可能记录同一事件，未按命中数推断宕机次数"}));
        report.record_count = report.records.len();
    }
    Ok(serde_json::to_value(report)?)
}

fn object<'a>(
    r: &Resident<'a>,
    offset: u64,
    kind: u8,
    header_size: u64,
    arena_end: u64,
) -> Result<&'a [u8]> {
    ensure!(
        offset >= header_size && offset & 7 == 0,
        "journal 对象偏移未对齐或位于文件头"
    );
    let header = r.read(offset, 16)?;
    ensure!(
        header[0] == kind && header[2..8] == [0; 6],
        "journal 对象类型或保留字段无效"
    );
    let size = u64_at(header, 8)?;
    ensure!(
        size >= 16 && add(offset, size)? <= arena_end,
        "journal 对象大小越界"
    );
    r.read(offset, size)
}

pub(super) fn parse_journal(
    r: &Resident<'_>,
    logical_size: u64,
    owner: &Value,
    budget: &mut u64,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let header = r.read(0, 208)?;
    ensure!(
        &header[..8] == b"LPKSHHRH",
        "systemd journal 文件头标记不符"
    );
    let flags = u32_at(header, 12)?;
    ensure!(
        flags & !31 == 0 && header[16] <= 2 && header[17..24] == [0; 7],
        "未知 journal 不兼容特性或文件状态"
    );
    let compact = flags & 16 != 0;
    let header_size = u64_at(header, 88)?;
    let arena_end = add(header_size, u64_at(header, 96)?)?;
    ensure!(
        header_size >= 208 && header_size & 7 == 0 && arena_end <= logical_size,
        "journal 文件范围无效"
    );
    let expected = u64_at(header, 152)?;
    let mut array = u64_at(header, 176)?;
    let mut arrays = HashSet::new();
    let mut entries = HashSet::new();
    let width = if compact { 4 } else { 8 };
    while array != 0 && (entries.len() as u64) < expected {
        cancel.check_cancelled()?;
        ensure!(
            arrays.insert(array) && arrays.len() <= options.limit,
            "journal entry array 循环或超过遍历上限"
        );
        let data = object(r, array, 6, header_size, arena_end)?;
        ensure!(
            data[1] == 0 && data.len() >= 24 && (data.len() - 24) % width == 0,
            "journal entry array 布局无效"
        );
        for index in (24..data.len()).step_by(width) {
            cancel.check_cancelled()?;
            if entries.len() as u64 >= expected {
                break;
            }
            let entry = if compact {
                u32_at(data, index)? as u64
            } else {
                u64_at(data, index)?
            };
            ensure!(
                entry != 0 && entries.insert(entry),
                "journal entry array 空洞或重复引用"
            );
            let decoded = (|| -> Result<Value> {
                let bytes = object(r, entry, 3, header_size, arena_end)?;
                let item_width = if compact { 4 } else { 16 };
                ensure!(
                    bytes[1] == 0 && bytes.len() >= 64 && (bytes.len() - 64) % item_width == 0,
                    "journal ENTRY 布局无效"
                );
                ensure!(
                    (bytes.len() - 64) / item_width <= 1024,
                    "journal ENTRY 字段数超过上限"
                );
                let mut fields = Vec::new();
                let mut errors = Vec::new();
                for index in (64..bytes.len()).step_by(item_width) {
                    cancel.check_cancelled()?;
                    let offset = if compact {
                        u32_at(bytes, index)? as u64
                    } else {
                        u64_at(bytes, index)?
                    };
                    let field = (|| -> Result<Value> {
                        let data = object(r, offset, 1, header_size, arena_end)?;
                        let payload = data
                            .get(if compact { 72 } else { 64 }..)
                            .context("journal DATA 过短")?;
                        let compression = data[1];
                        ensure!(
                            compression.count_ones() <= 1 && compression & !7 == 0,
                            "journal DATA 压缩标志无效"
                        );
                        ensure!(
                            compression & 1 == 0 || flags & 1 != 0,
                            "XZ 压缩未在 journal 文件头声明"
                        );
                        ensure!(
                            compression & 2 == 0 || flags & 2 != 0,
                            "LZ4 压缩未在 journal 文件头声明"
                        );
                        ensure!(
                            compression & 4 == 0 || flags & 8 != 0,
                            "ZSTD 压缩未在 journal 文件头声明"
                        );
                        if !compact {
                            ensure!(
                                u64_at(bytes, index + 8)? == u64_at(data, 16)?,
                                "ENTRY/DATA 引用哈希字段不匹配"
                            );
                        }
                        let decoded = decompress(
                            payload,
                            compression,
                            (*budget).min(1024 * 1024) as usize,
                            cancel,
                        )?;
                        *budget = budget.saturating_sub(decoded.len() as u64);
                        let equals = decoded
                            .iter()
                            .position(|b| *b == b'=')
                            .context("journal 字段缺少等号")?;
                        ensure!(valid_field_name(&decoded[..equals]), "journal 字段名无效");
                        let value = &decoded[equals + 1..];
                        Ok(
                            json!({"name":std::str::from_utf8(&decoded[..equals])?,"value_utf8":std::str::from_utf8(value).ok(),
                            "value_hex":std::str::from_utf8(value).is_err().then(|| hex::encode(value)),"data_offset":offset,"compression":compression,
                            "compression_algorithm":match compression { 1 => "xz", 2 => "lz4", 4 => "zstd", _ => "none" }}),
                        )
                    })();
                    match field {
                        Ok(value) => fields.push(value),
                        Err(error) => {
                            if crate::cancellation::is_cancellation_error(&error) {
                                return Err(error);
                            }
                            errors.push(json!({"data_offset":offset,"error":format!("{error:#}")}));
                        }
                    }
                }
                let realtime = u64_at(bytes, 24)?;
                let timestamp = i64::try_from(realtime / 1_000_000)
                    .ok()
                    .and_then(|sec| {
                        chrono::DateTime::from_timestamp(sec, (realtime % 1_000_000) as u32 * 1000)
                    })
                    .map(|t| t.to_rfc3339());
                if !errors.is_empty() {
                    report.warn("部分 journal ENTRY 字段缺页、压缩格式不支持或解码预算不足");
                }
                Ok(
                    json!({"kind":"journal_entry","path":owner["path"],"path_scope":owner["path_scope"],
                    "dentry":owner["dentry"],"inode":owner["inode"],"superblock":owner["superblock"],"file_offset":entry,
                    "sequence":u64_at(bytes, 16)?,"timestamp":timestamp,"realtime_us":realtime,"monotonic_us":u64_at(bytes, 32)?,
                    "boot_id":hex::encode(&bytes[40..56]),"fields":fields,"field_errors":errors,"complete":errors.is_empty(),
                    "validation":"文件头、ENTRY_ARRAY、ENTRY/DATA 类型及引用核对；未验证 FSS 签名或重新计算内容哈希"}),
                )
            })();
            match decoded {
                Ok(row) => {
                    if !report.push(row) {
                        return Ok(());
                    }
                }
                Err(error) => {
                    if crate::cancellation::is_cancellation_error(&error) {
                        return Err(error);
                    }
                    report.warn(format!("journal ENTRY {entry:#x}: {error:#}"));
                }
            }
            if entries.len() >= options.limit {
                report.limit_reached = true;
                report.warn("journal ENTRY 遍历达到上限");
                return Ok(());
            }
        }
        array = u64_at(data, 16)?;
    }
    ensure!(
        entries.len() as u64 == expected,
        "journal ENTRY 数量与文件头不符：{} / {expected}",
        entries.len()
    );
    Ok(())
}

fn valid_field_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && (name[0].is_ascii_uppercase() || name[0] == b'_')
        && name
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

pub(super) fn decompress(
    bytes: &[u8],
    compression: u8,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>> {
    cancel.check_cancelled()?;
    ensure!(limit > 0, "journal 字段解码预算已用尽");
    let output = match compression {
        0 => {
            ensure!(bytes.len() <= limit, "journal 字段超过解码预算");
            Ok(bytes.to_vec())
        }
        1 => {
            check_xz_budget(bytes, limit)?;
            read_decoded(&mut lzma_rust2::XzReader::new(bytes, false), limit, cancel)
        }
        2 => {
            let size = usize::try_from(u64_at(bytes, 0)?)?;
            ensure!(
                size > 0 && size <= limit,
                "LZ4 journal 字段解压大小超过预算"
            );
            let mut input = bytes.get(8..).context("LZ4 缺少负载")?;
            let mut output = Vec::with_capacity(size);
            fn length(input: &mut &[u8], initial: usize) -> Result<usize> {
                let mut size = initial;
                if initial == 15 {
                    loop {
                        let byte = *input.first().context("LZ4 长度截断")?;
                        *input = &input[1..];
                        size = size.checked_add(byte as usize).context("LZ4 长度溢出")?;
                        if byte != 255 {
                            break;
                        }
                    }
                }
                Ok(size)
            }
            while let Some(&token) = input.first() {
                cancel.check_cancelled()?;
                input = &input[1..];
                let literals = length(&mut input, (token >> 4) as usize)?;
                ensure!(
                    literals <= input.len() && literals <= size.saturating_sub(output.len()),
                    "LZ4 literal 越界"
                );
                output.extend_from_slice(&input[..literals]);
                input = &input[literals..];
                if input.is_empty() {
                    break;
                }
                let offset =
                    u16::from_le_bytes(input.get(..2).context("LZ4 match 截断")?.try_into()?)
                        as usize;
                input = &input[2..];
                ensure!(offset > 0 && offset <= output.len(), "LZ4 match 偏移无效");
                let count = length(&mut input, (token & 15) as usize)?
                    .checked_add(4)
                    .context("LZ4 match 溢出")?;
                ensure!(
                    count <= size.saturating_sub(output.len()),
                    "LZ4 match 超出解压大小"
                );
                for index in 0..count {
                    if index & 4095 == 0 {
                        cancel.check_cancelled()?;
                    }
                    output.push(output[output.len() - offset]);
                }
            }
            ensure!(output.len() == size, "LZ4 实际解压长度与声明不符");
            Ok(output)
        }
        4 => {
            ensure!(
                bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]),
                "ZSTD journal 字段缺少标准帧头"
            );
            let declared = zstd::zstd_safe::get_frame_content_size(bytes)
                .map_err(|_| anyhow::anyhow!("ZSTD 帧头无效"))?;
            ensure!(
                declared.is_none_or(|size| size <= limit as u64),
                "ZSTD 声明的解压大小超过字段预算"
            );
            let mut decoder = zstd::stream::read::Decoder::with_buffer(bytes)?.single_frame();
            // Limit the image-controlled history window independently of output size.
            decoder.window_log_max(24)?;
            let output =
                read_decoded(&mut decoder, limit, cancel).context("ZSTD journal 字段解码失败")?;
            ensure!(
                decoder.finish().is_empty(),
                "ZSTD journal DATA 包含尾随字节或额外帧，未当作单个完整字段"
            );
            ensure!(
                declared.is_none_or(|size| size == output.len() as u64),
                "ZSTD 实际解压大小与帧头不一致"
            );
            Ok(output)
        }
        _ => anyhow::bail!("不支持的 journal 压缩标志"),
    }?;
    cancel.check_cancelled()?;
    Ok(output)
}

pub(super) fn read_decoded(
    reader: &mut impl Read,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0u8; 8192];
    loop {
        cancel.check_cancelled()?;
        let count = buffer
            .len()
            .min(limit.saturating_sub(output.len()).saturating_add(1));
        let length = reader.read(&mut buffer[..count])?;
        cancel.check_cancelled()?;
        if length == 0 {
            break;
        }
        ensure!(
            length <= limit.saturating_sub(output.len()),
            "journal 字段超过解码预算，未返回截断正文"
        );
        output.extend_from_slice(&buffer[..length]);
    }
    Ok(output)
}

// XzReader has no dictionary limit. Preflight every indexed block before allowing it
// to allocate a dictionary. Journal writers use a single LZMA2 filter; other chains
// remain unsupported instead of silently allocating image-controlled gigabytes.
fn check_xz_budget(bytes: &[u8], limit: usize) -> Result<()> {
    ensure!(
        bytes.len() >= 32 && &bytes[..6] == b"\xfd7zXZ\0" && &bytes[bytes.len() - 2..] == b"YZ",
        "XZ 流头/尾无效"
    );
    let footer = bytes.len() - 12;
    let index_size = (u32_at(bytes, footer + 4)? as usize)
        .checked_add(1)
        .and_then(|n| n.checked_mul(4))
        .context("XZ 索引大小溢出")?;
    let index_start = footer.checked_sub(index_size).context("XZ 索引越界")?;
    ensure!(
        index_start >= 12 && bytes[index_start] == 0,
        "XZ 索引标记无效"
    );
    fn vli(input: &[u8], at: &mut usize) -> Result<u64> {
        let mut value = 0;
        for shift in (0..63).step_by(7) {
            let byte = *input.get(*at).context("XZ VLI 截断")?;
            *at += 1;
            ensure!(shift == 0 || byte != 0, "非规范 XZ VLI");
            value |= u64::from(byte & 127) << shift;
            if byte & 128 == 0 {
                return Ok(value);
            }
        }
        anyhow::bail!("XZ VLI 溢出")
    }
    let index = bytes
        .get(index_start..footer.checked_sub(4).context("XZ 索引过短")?)
        .context("XZ 索引范围无效")?;
    let mut cursor = 1;
    let count = vli(index, &mut cursor)?;
    ensure!(count <= 1024, "XZ 块数超过校验上限");
    let mut block = 12usize;
    let mut total = 0u64;
    for _ in 0..count {
        let unpadded = vli(index, &mut cursor)?;
        let unpacked = vli(index, &mut cursor)?;
        total = total.checked_add(unpacked).context("XZ 解压大小溢出")?;
        ensure!(
            total <= limit as u64 && unpadded >= 8 && block < index_start,
            "XZ 块超过解码预算或文件范围"
        );
        let size = (bytes[block] as usize + 1) * 4;
        let header = bytes
            .get(block..block.checked_add(size).context("XZ 块头溢出")?)
            .context("XZ 块头截断")?;
        ensure!(
            size >= 8
                && size as u64 <= unpadded
                && block + size <= index_start
                && header[1] & 63 == 0,
            "仅支持单 LZMA2 过滤器 XZ 块"
        );
        let mut offset = 2;
        if header[1] & 64 != 0 {
            vli(header, &mut offset)?;
        }
        if header[1] & 128 != 0 {
            ensure!(
                vli(header, &mut offset)? == unpacked,
                "XZ 块声明与索引大小不一致"
            );
        }
        ensure!(
            vli(header, &mut offset)? == 0x21 && vli(header, &mut offset)? == 1,
            "仅支持 LZMA2 XZ 字典属性"
        );
        ensure!(
            offset < size - 4 && header[offset] <= 24,
            "XZ 字典超过 16 MiB 上限"
        );
        block = block
            .checked_add(usize::try_from(add(unpadded, 3)? & !3)?)
            .context("XZ 块边界溢出")?;
    }
    ensure!(block == index_start, "XZ 索引与块范围不一致");
    Ok(())
}

fn field_candidates(
    r: &Resident<'_>,
    owner: &Value,
    budget: &mut u64,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    for &(start, end) in &r.ranges {
        let mut at = start;
        while at < end && *budget > 0 {
            cancel.check_cancelled()?;
            let begin = at;
            while at < end && (r.bytes[at].is_ascii_graphic() || r.bytes[at] == b' ') {
                at += 1;
            }
            let bytes = &r.bytes[begin..at];
            if begin != start
                && at < end
                && bytes.len() <= 16384
                && let Some(equals) = bytes.iter().position(|b| *b == b'=')
                && valid_field_name(&bytes[..equals])
                && bytes.len() as u64 <= *budget
            {
                *budget -= bytes.len() as u64;
                report.warn(
                    "journal 二进制索引无法遍历；以下仅为驻留字段候选，没有重建 ENTRY 归属或时间",
                );
                if !report.push(json!({"kind":"journal_field_candidate","path":owner["path"],"dentry":owner["dentry"],
                    "inode":owner["inode"],"superblock":owner["superblock"],"path_scope":owner["path_scope"],
                    "file_offset":begin,"text":std::str::from_utf8(bytes)?,"timestamp":Value::Null,
                    "entry_association":"unverified"})) { return Ok(()); }
            }
            at = at.saturating_add(1);
        }
    }
    Ok(())
}
