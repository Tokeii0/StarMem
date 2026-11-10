use super::*;
use std::collections::BTreeMap;

pub(super) fn analyze(
    session: &LinuxAnalysisSession,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    if options.module == "timeline-network" {
        let sockets = session.sockstat(options.pid, options.limit, 4096)?;
        let mut report = LinuxIrReport::new(
            options,
            "采集时驻留 socket 快照；没有可靠的连接建立时间，不生成虚构网络事件时间",
        );
        report.complete = sockets.complete;
        report
            .warnings
            .extend(sockets.warnings.iter().take(64).map(|w| w.message.clone()));
        for socket in &sockets.records {
            cancel.check_cancelled()?;
            let mut row = serde_json::to_value(socket)?;
            row["event"] = json!("SOCKET_OBSERVED");
            row["timestamp"] = Value::Null;
            row["clock_basis"] = json!("snapshot; connection time unavailable");
            if !report.push(row) {
                break;
            }
        }
        return Ok(serde_json::to_value(report)?);
    }
    if options.module == "timeline-findings" {
        let mut findings = hunting::analyze(
            session,
            &LinuxIrOptions {
                module: "indicators".into(),
                ..options.clone()
            },
            cancel,
        )?;
        findings["module"] = json!(options.module);
        findings["scope"] = json!("采集状态上的规则评估；规则命中没有独立事件时间");
        if let Some(rows) = findings["records"].as_array_mut() {
            for row in rows.iter_mut().filter(|r| r["kind"] == "finding") {
                row["timestamp"] = Value::Null;
                row["event"] = json!("FINDING_OBSERVED");
                row["clock_basis"] = json!("assessment of snapshot; event time unavailable");
            }
        }
        return Ok(findings);
    }
    let mut report = LinuxIrReport::new(
        options,
        "文件/进程、内核消息、Shell 历史和网络快照的时钟覆盖摘要；绝对、单调和无时间记录分开统计",
    );
    let mut available = 0;
    for source in ["file-process", "network", "kernel", "shell"] {
        cancel.check_cancelled()?;
        let child = match source {
            "file-process" => files::analyze(
                session,
                &LinuxIrOptions {
                    module: "timeline".into(),
                    ..options.clone()
                },
                cancel,
            ),
            "network" => analyze(
                session,
                &LinuxIrOptions {
                    module: "timeline-network".into(),
                    ..options.clone()
                },
                cancel,
            ),
            "kernel" => TaskMemory::new(session).and_then(|memory| {
                Ok(serde_json::to_value(
                    crate::linux_kernel_plugins::linux_kmsg(
                        &memory,
                        &crate::linux_kernel_plugins::LinuxKmsgOptions {
                            limit: options.limit,
                            ..Default::default()
                        },
                    ),
                )?)
            }),
            "shell" => session
                .bash(
                    options.pid,
                    options.limit,
                    options.limit,
                    options.max_bytes,
                    16384,
                )
                .and_then(|v| Ok(serde_json::to_value(v)?)),
            _ => unreachable!(),
        };
        match child {
            Ok(child) => {
                available += usize::from(child["available"] != false);
                hunting::source_status(&mut report, source, &child);
                let rows = child["records"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                let mut clocks: BTreeMap<&str, usize> = BTreeMap::new();
                let mut earliest = None;
                let mut latest = None;
                for row in rows {
                    let timestamp = row
                        .get("timestamp")
                        .or_else(|| row.get("utc"))
                        .or_else(|| row.get("timestamp_utc"))
                        .and_then(Value::as_str)
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
                    let clock = if let Some(timestamp) = timestamp {
                        if earliest.is_none_or(|old| timestamp < old) {
                            earliest = Some(timestamp);
                        }
                        if latest.is_none_or(|old| timestamp > old) {
                            latest = Some(timestamp);
                        }
                        "absolute"
                    } else if row["monotonic_ns"].is_number() || row["monotonic_us"].is_number() {
                        "monotonic"
                    } else {
                        "unavailable"
                    };
                    *clocks.entry(clock).or_default() += 1;
                }
                report.push(json!({"kind":"timeline_summary","source":source,"records":rows.len(),"clocks":clocks,
                    "earliest_absolute":earliest.map(|t| t.to_rfc3339()),"latest_absolute":latest.map(|t| t.to_rfc3339()),
                    "interpretation":"仅统计此来源当前恢复范围；不是系统全部历史的起止时间"}));
            }
            Err(error) => {
                if crate::cancellation::is_cancellation_error(&error) {
                    return Err(error);
                }
                hunting::source_error(&mut report, source, &error);
            }
        }
    }
    if available == 0 {
        report.unavailable("所有时间线来源均不可用");
    }
    Ok(serde_json::to_value(report)?)
}
