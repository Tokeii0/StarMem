use super::{InteractionOptions, InteractionSection, formats};
use crate::{
    cancellation::CancellationToken,
    cookies::{SqlValue, parse_sqlite_table},
    session::AnalysisSession,
    windows::files::{
        DumpSource, RecoveredExtent, recover_file_bytes, scan_files_matching_cancellable,
    },
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn category(path: &str) -> Option<&'static str> {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    let name = p.rsplit('\\').next()?;
    if p.contains("\\microsoft\\windows\\clipboard\\") || name == "activitiescache.db" {
        return Some("clipboard_history");
    }
    if name == "wpndatabase.db" && p.contains("\\notifications\\") {
        return Some("notifications");
    }
    let chromium = [
        "\\google\\chrome\\",
        "\\microsoft\\edge\\",
        "\\chromium\\",
        "\\bravesoftware\\",
        "\\vivaldi\\",
        "\\opera software\\",
    ]
    .iter()
    .any(|v| p.contains(v));
    if chromium
        && ([
            "current session",
            "last session",
            "current tabs",
            "last tabs",
        ]
        .contains(&name)
            || p.contains("\\sessions\\")
                && (name.starts_with("session_") || name.starts_with("tabs_")))
    {
        return Some("browser_tabs");
    }
    if p.contains("\\mozilla\\firefox\\profiles\\")
        && ([
            "sessionstore.js",
            "sessionstore.jsonlz4",
            "recovery.jsonlz4",
            "recovery.baklz4",
            "previous.jsonlz4",
        ]
        .contains(&name)
            || name.starts_with("upgrade.jsonlz4-"))
    {
        return Some("browser_tabs");
    }
    None
}

pub(super) fn range_covered(extents: &[RecoveredExtent], offset: u64, length: u64) -> bool {
    let Some(end) = offset.checked_add(length) else {
        return false;
    };
    let mut pos = offset;
    while pos < end {
        let next = extents
            .iter()
            .filter(|e| e.file_offset <= pos)
            .filter_map(|e| e.file_offset.checked_add(e.length))
            .filter(|e| *e > pos)
            .max();
        let Some(next) = next else {
            return false;
        };
        pos = next.min(end);
    }
    true
}

pub(super) fn analyze(
    session: &AnalysisSession,
    options: &InteractionOptions,
    token: &CancellationToken,
    output: &mut BTreeMap<String, InteractionSection>,
) -> Result<()> {
    let filter = |p: &str| category(p).is_some_and(|name| output.contains_key(name));
    let files = match scan_files_matching_cancellable(
        session.image(),
        session.kernel(),
        session.profile(),
        options.file_limit,
        &filter,
        token,
    ) {
        Ok(r) => r,
        Err(e) => {
            for name in ["clipboard_history", "notifications", "browser_tabs"] {
                if let Some(s) = output.get_mut(name) {
                    s.check("filescan", "unavailable", format!("{e:#}"));
                }
            }
            return Ok(());
        }
    };
    for name in ["clipboard_history", "notifications", "browser_tabs"] {
        if let Some(s) = output.get_mut(name) {
            s.check(
                "file_candidates",
                "checked",
                format!(
                    "路径筛选后的 FILE_OBJECT 候选：{}",
                    files
                        .records
                        .iter()
                        .filter(|f| f.name.as_deref().and_then(category) == Some(name))
                        .count()
                ),
            );
            s.limitations.push(
                "仅解析驻留的主文件；不回放 WAL、Journal 或加密内容，存储状态可能早于内存采集"
                    .into(),
            );
            if !files.complete {
                s.check("filescan", "partial", files.warnings.join("；"));
            }
        }
    }
    for file in &files.records {
        token.check_cancelled()?;
        let Some(path) = &file.name else {
            continue;
        };
        let Some(name) = category(path) else {
            continue;
        };
        let Some(section) = output.get_mut(name) else {
            continue;
        };
        let scope = format!("{:#x}:{path}", file.file_object);
        // Keep the strongest independently recovered view. Never join bytes
        // from two cache/section views, which may represent different versions.
        let mut best = None;
        let mut errors = Vec::new();
        for source in [DumpSource::Cache, DumpSource::Data] {
            token.check_cancelled()?;
            match recover_file_bytes(
                session.image(),
                session.kernel(),
                session.profile(),
                file.file_object,
                source,
                options.max_file_bytes,
            ) {
                Ok((report, bytes)) if report.recovered_bytes > 0 => {
                    let recognized = recognized_header(name, path, &bytes);
                    let better = best.as_ref().is_none_or(
                        |(old, old_bytes): &(crate::windows::files::DumpFileReport, Vec<u8>)| {
                            (recognized, report.complete, report.recovered_bytes)
                                > (
                                    recognized_header(name, path, old_bytes),
                                    old.complete,
                                    old.recovered_bytes,
                                )
                        },
                    );
                    if better {
                        best = Some((report, bytes));
                    }
                }
                Ok(_) => errors.push("没有驻留字节".to_owned()),
                Err(e) => errors.push(format!("{e:#}")),
            }
        }
        let Some((dump, bytes)) = best else {
            section.check(scope, "unavailable", errors.join("；"));
            continue;
        };
        let evidence = json!({"file_object":file.file_object,"original_path":path,"recovery_source":dump.source,
            "recovery_dtb":session.kernel().directory_table_base,
            "logical_size":dump.logical_size,"recovered_bytes":dump.recovered_bytes,"missing_bytes":dump.missing_bytes,
            "source_file_complete":dump.complete,"extents":dump.extents,
            "recovered_buffer_sha256":hex::encode(Sha256::digest(&bytes))});
        if !dump.complete {
            section.check(
                &scope,
                "missing_pages",
                format!(
                    "恢复 {} 字节，缺失 {} 字节；补零不作为有效内容",
                    dump.recovered_bytes, dump.missing_bytes
                ),
            );
        }
        let result = match name {
            "notifications" => sqlite_rows(
                &bytes,
                &dump.extents,
                "Notification",
                name,
                options.limit,
                section,
                &evidence,
            ),
            "clipboard_history" if path.to_ascii_lowercase().ends_with("activitiescache.db") => {
                sqlite_rows(
                    &bytes,
                    &dump.extents,
                    "Activity",
                    name,
                    options.limit,
                    section,
                    &evidence,
                )
            }
            "clipboard_history" => {
                section.check(&scope,"unsupported","已定位 Clipboard 存储文件；私有/加密格式尚无可验证解码器，没有把原始字符串当历史项");
                Ok(())
            }
            "browser_tabs" => {
                // Keep raw URL leads even when SNSS headers/command prefixes are
                // absent. Each fragment is independently bounded by residency;
                // it is never passed to the stored-tab state machine.
                if !dump.complete {
                    match crate::browser_pages::session_fragments(
                        session,
                        &dump,
                        &bytes,
                        options.limit,
                    ) {
                        Ok(fragments) => {
                            if fragments.len() == options.limit {
                                section.check(&scope, "limit_reached", "会话片段达到记录上限");
                            }
                            for fragment in fragments {
                                section.record(
                                    "browser_session_url_fragment",
                                    evidence.clone(),
                                    fragment,
                                );
                            }
                        }
                        Err(error) => section.check(
                            &scope,
                            "unavailable",
                            format!("片段字节复验失败：{error:#}"),
                        ),
                    }
                }
                if !dump.complete || !range_covered(&dump.extents, 0, bytes.len() as u64) {
                    Err(anyhow::anyhow!(
                        "浏览器会话文件存在缺口，未跨补零区解析记录"
                    ))
                } else {
                    let parsed = if bytes.starts_with(b"SNSS") {
                        let base = path
                            .rsplit(['\\', '/'])
                            .next()
                            .unwrap_or(path)
                            .to_ascii_lowercase();
                        if base.starts_with("tabs_")
                            || matches!(base.as_str(), "current tabs" | "last tabs")
                        {
                            Err(anyhow::anyhow!(
                                "TabRestore 的 Tabs 文件命令编号与 SessionService 不同，尚未适配该语义；未套用 Session 解码器"
                            ))
                        } else {
                            formats::snss(&bytes, options.limit)
                        }
                    } else {
                        formats::firefox(&bytes, options.max_file_bytes as usize, options.limit)
                    };
                    parsed.map(|(rows, complete)| {
                        if bytes.starts_with(b"SNSS") {
                            for tab in super::browser::stored_tabs(&rows,complete) {
                                section.record("chromium_stored_tab", evidence.clone(), tab);
                            }
                            let unknown=rows.iter().filter(|row|row["event"]=="unparsed_command").count();
                            if unknown>0 {section.check(&scope,"unsupported",format!("有 {unknown} 条未解释的会话命令；保留字节范围，重建状态不完整"));}
                        }
                        for row in rows {
                            section.record(
                                if bytes.starts_with(b"SNSS") {
                                    "chromium_session_command"
                                } else {
                                    "firefox_session_entry"
                                },
                                evidence.clone(),
                                row,
                            );
                        }
                        if !complete {
                            section.check(&scope, "limit_reached", "浏览器会话记录达到上限");
                        }
                    })
                }
            }
            _ => unreachable!(),
        };
        match result {
            Ok(()) => section.check(scope, "checked", "已执行格式适配与驻留范围校验"),
            Err(e) => section.check(scope, "unsupported", format!("{e:#}")),
        }
    }
    Ok(())
}

fn sqlite_rows(
    b: &[u8],
    extents: &[RecoveredExtent],
    table_name: &str,
    category: &str,
    limit: usize,
    section: &mut InteractionSection,
    evidence: &Value,
) -> Result<()> {
    ensure!(range_covered(extents, 0, 100), "SQLite 头缺页");
    let table = parse_sqlite_table(b, &[table_name], limit)?;
    ensure!(
        table
            .schema_source_ranges
            .iter()
            .all(|r| range_covered(extents, r.file_offset, r.length)),
        "SQLite 表定义包含未恢复字节"
    );
    let handlers = if category == "notifications" {
        notification_handlers(b, extents, limit, section)
    } else {
        BTreeMap::new()
    };
    let columns: BTreeMap<_, _> = table
        .columns
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), *v))
        .collect();
    if category == "notifications" {
        ensure!(
            columns.contains_key("payload") && columns.contains_key("handlerid"),
            "Notification 表结构不受支持"
        );
    } else {
        ensure!(
            columns.contains_key("clipboardpayload"),
            "Activity 表没有 ClipboardPayload 字段"
        );
    }
    if table.damaged_pages > 0 || table.limit_reached {
        section.check(
            table_name,
            "partial",
            format!(
                "损坏页 {}；数量截断 {}",
                table.damaged_pages, table.limit_reached
            ),
        );
    }
    for row in table.rows {
        if !row
            .source_ranges
            .iter()
            .all(|r| range_covered(extents, r.file_offset, r.length))
        {
            section.check(
                format!("{table_name}:{}", row.rowid),
                "missing_pages",
                "该行包含未恢复字节，未输出内容",
            );
            continue;
        }
        if category == "clipboard_history" {
            let index = *columns
                .get("clipboardpayload")
                .context("缺少 ClipboardPayload")?;
            if matches!(row.values.get(index), None | Some(SqlValue::Null)) {
                continue;
            }
            if matches!(row.values.get(index),Some(SqlValue::Text(s)) if s.is_empty()) {
                continue;
            }
            if matches!(row.values.get(index),Some(SqlValue::Blob(b)) if b.is_empty()) {
                continue;
            }
        }
        let mut fields = serde_json::Map::new();
        for (column, index) in &columns {
            let Some(value) = row.values.get(*index) else {
                continue;
            };
            let val = match value {
                SqlValue::Null => Value::Null,
                SqlValue::Integer(n) => json!(n),
                SqlValue::Real => json!({"type":"real","value_unavailable":true}),
                SqlValue::Text(s) if s.len() <= 128 * 1024 => json!(s),
                SqlValue::Text(s) => {
                    json!({"length":s.len(),"sha256":hex::encode(Sha256::digest(s.as_bytes())),"omitted":"field_budget"})
                }
                SqlValue::Blob(data) => {
                    if data.len() <= 128 * 1024 {
                        let text = std::str::from_utf8(data)
                            .ok()
                            .filter(|s| !s.contains('\0'))
                            .map(str::to_owned);
                        json!({"hex":hex::encode(data),"utf8":text})
                    } else {
                        json!({"length":data.len(),"sha256":hex::encode(Sha256::digest(data)),"omitted":"field_budget"})
                    }
                }
            };
            fields.insert(column.clone(), val);
        }
        fields.insert(
            "semantic".into(),
            json!(if category == "notifications" {
                "stored_notification_not_proof_of_display"
            } else {
                "activity_clipboard_payload_not_complete_win_v_history"
            }),
        );
        if category == "notifications" {
            if let Some(handler) = fields
                .get("handlerid")
                .and_then(Value::as_i64)
                .and_then(|id| handlers.get(&id))
            {
                fields.insert("application".into(), handler.clone());
            }
            let mut times = serde_json::Map::new();
            for key in ["arrivaltime", "expirytime"] {
                if let Some(raw) = fields.get(key).and_then(Value::as_u64) {
                    times.insert(key.into(),json!({"raw":raw,"utc":filetime(raw),"unit":"Windows FILETIME (100 ns since 1601 UTC)"}));
                }
            }
            fields.insert("decoded_times".into(), Value::Object(times));
        }
        let mut provenance = evidence.clone();
        provenance["sqlite_table"] = json!(table_name);
        provenance["rowid"] = json!(row.rowid);
        provenance["sqlite_page"] = json!(row.page_number);
        provenance["file_offset"] = json!(row.file_offset);
        provenance["row_source_ranges"] = json!(
            row.source_ranges
                .iter()
                .map(|r| json!({"offset":r.file_offset,"length":r.length}))
                .collect::<Vec<_>>()
        );
        section.record(
            if category == "notifications" {
                "notification"
            } else {
                "clipboard_activity"
            },
            provenance,
            Value::Object(fields),
        );
    }
    Ok(())
}

fn recognized_header(category: &str, path: &str, bytes: &[u8]) -> bool {
    match category {
        "notifications" => bytes.starts_with(b"SQLite format 3\0"),
        "clipboard_history" if path.to_ascii_lowercase().ends_with("activitiescache.db") => {
            bytes.starts_with(b"SQLite format 3\0")
        }
        "browser_tabs" => {
            bytes.starts_with(b"SNSS")
                || bytes.starts_with(b"mozLz40\0")
                || bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{')
        }
        _ => false,
    }
}

fn notification_handlers(
    b: &[u8],
    extents: &[RecoveredExtent],
    limit: usize,
    section: &mut InteractionSection,
) -> BTreeMap<i64, Value> {
    let mut handlers = BTreeMap::new();
    let result = (|| -> Result<()> {
        let table = parse_sqlite_table(b, &["NotificationHandler"], limit)?;
        ensure!(
            table.schema_source_ranges.iter().all(|r| range_covered(
                extents,
                r.file_offset,
                r.length
            )),
            "通知应用表定义缺页"
        );
        let id = *table
            .columns
            .get("recordid")
            .context("NotificationHandler 缺少 RecordId")?;
        let app = *table
            .columns
            .get("primaryid")
            .context("NotificationHandler 缺少 PrimaryId")?;
        let rowid_alias=regex::Regex::new(r#"(?i)(?:\bRecordId\b|\[RecordId\]|"RecordId")\s+INTEGER\s+(?:NOT\s+NULL\s+)?PRIMARY\s+KEY\b"#)?.is_match(&table.create_sql);
        if table.damaged_pages > 0 || table.limit_reached {
            section.check(
                "NotificationHandler",
                "partial",
                "通知应用表有损坏或数量截断",
            );
        }
        for row in table.rows {
            if !row
                .source_ranges
                .iter()
                .all(|r| range_covered(extents, r.file_offset, r.length))
            {
                section.check(
                    "NotificationHandler",
                    "missing_pages",
                    "应用关联行包含未恢复字节",
                );
                continue;
            }
            let key = match row.values.get(id) {
                Some(SqlValue::Integer(n)) => *n,
                Some(SqlValue::Null) if rowid_alias => row.rowid,
                _ => continue,
            };
            let Some(SqlValue::Text(app_id)) = row.values.get(app) else {
                continue;
            };
            if app_id.len() > 16 * 1024 {
                continue;
            }
            let value = json!({"primary_id":app_id,"handler_record_id":key,"sqlite_table":"NotificationHandler",
                "rowid":row.rowid,"file_offset":row.file_offset,"row_source_ranges":row.source_ranges.iter().map(|r|json!({"offset":r.file_offset,"length":r.length})).collect::<Vec<_>>()});
            // Do not choose an arbitrary application if the key is ambiguous.
            if handlers.insert(key, value).is_some() {
                handlers.insert(key, Value::Null);
                section.check(
                    "NotificationHandler",
                    "partial",
                    "应用表包含重复 RecordId，未选择关联",
                );
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        section.check(
            "NotificationHandler",
            "unavailable",
            format!("通知正文仍可恢复，但应用关联不可用：{e:#}"),
        );
    }
    handlers
}

fn filetime(raw: u64) -> Option<String> {
    if raw == 0 || raw == i64::MAX as u64 || raw == u64::MAX {
        return None;
    }
    let ticks = i128::from(raw) - 116_444_736_000_000_000i128;
    let seconds = i64::try_from(ticks.div_euclid(10_000_000)).ok()?;
    chrono::DateTime::<chrono::Utc>::from_timestamp(
        seconds,
        (ticks.rem_euclid(10_000_000) * 100) as u32,
    )
    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_paths_do_not_treat_history_database_as_live_tabs() {
        assert_eq!(
            category(
                r"C:\Users\x\AppData\Local\Google\Chrome\User Data\Default\Sessions\Session_123"
            ),
            Some("browser_tabs")
        );
        assert_eq!(
            category(r"C:\Users\x\AppData\Local\Google\Chrome\User Data\Default\History"),
            None
        );
        assert_eq!(category(r"C:\tmp\Session_123"), None);
        assert_eq!(
            category(r"C:\Users\x\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db"),
            Some("notifications")
        );
    }
    #[test]
    fn gaps_and_overflow_never_become_valid_recovery_ranges() {
        let e = vec![
            RecoveredExtent {
                file_offset: 0,
                length: 8,
                memory_address: 0x1000,
                memory_kind: "physical".into(),
            },
            RecoveredExtent {
                file_offset: 10,
                length: 8,
                memory_address: 0x2000,
                memory_kind: "physical".into(),
            },
        ];
        assert!(range_covered(&e, 0, 8));
        assert!(!range_covered(&e, 0, 11));
        assert!(!range_covered(&e, u64::MAX, 2));
    }
    #[test]
    fn notifications_and_clipboard_require_intact_sqlite_record_bytes() {
        let path = std::env::temp_dir().join(format!(
            "starmem-interaction-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        {
            let c = rusqlite::Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE Notification(Id INTEGER PRIMARY KEY,HandlerId INTEGER,Payload BLOB,ArrivalTime INTEGER); INSERT INTO Notification VALUES(1,7,X'3c746f6173742f3e',133000000000000000); CREATE TABLE NotificationHandler(RecordId INTEGER PRIMARY KEY, PrimaryId TEXT); INSERT INTO NotificationHandler VALUES(7,'test.application'); CREATE TABLE Activity(Id INTEGER PRIMARY KEY,ClipboardPayload TEXT); INSERT INTO Activity VALUES(1,'{\"text\":\"example\"}');").unwrap();
        }
        let b = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let ext = vec![RecoveredExtent {
            file_offset: 0,
            length: b.len() as u64,
            memory_address: 0x1000,
            memory_kind: "physical".into(),
        }];
        let mut s = InteractionSection::new(10);
        sqlite_rows(
            &b,
            &ext,
            "Notification",
            "notifications",
            10,
            &mut s,
            &json!({}),
        )
        .unwrap();
        assert_eq!(s.records.len(), 1);
        assert_eq!(s.records[0].fields["handlerid"], 7);
        assert_eq!(
            s.records[0].fields["application"]["primary_id"],
            "test.application"
        );
        assert!(s.records[0].fields["decoded_times"]["arrivaltime"]["utc"].is_string());
        let mut c = InteractionSection::new(10);
        sqlite_rows(
            &b,
            &ext,
            "Activity",
            "clipboard_history",
            10,
            &mut c,
            &json!({}),
        )
        .unwrap();
        assert_eq!(c.records.len(), 1);
        let short = vec![RecoveredExtent {
            file_offset: 0,
            length: 100,
            memory_address: 0x1000,
            memory_kind: "physical".into(),
        }];
        let mut s = InteractionSection::new(10);
        assert!(
            sqlite_rows(
                &b,
                &short,
                "Notification",
                "notifications",
                10,
                &mut s,
                &json!({})
            )
            .is_err()
        );
        assert!(s.records.is_empty());
    }
}
