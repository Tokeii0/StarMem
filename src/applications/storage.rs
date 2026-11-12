use super::{ApplicationKind, ApplicationOptions, ApplicationRecord, ApplicationReport, ai, wal};
use crate::{
    cancellation::CancellationToken,
    cookies::{SqlValue, parse_sqlite_table, sqlite_table_names},
    session::AnalysisSession,
    windows::files::{
        DumpFileReport, DumpSource, recover_file_bytes, scan_files_matching_cancellable,
    },
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) fn file_kind(kind: ApplicationKind, path: &str) -> Option<&'static str> {
    let p = super::normalized(path);
    let name = super::basename(path);
    if kind.executable(&name) {
        return Some("program_file");
    }
    if !kind.directory(path) {
        return None;
    }
    let base = name.strip_suffix("-wal").unwrap_or(&name);
    if kind == ApplicationKind::Huorong {
        return ["log.db", "quarantineex.db", "applog.db"]
            .contains(&base)
            .then_some("application_database");
    }
    if p.contains("\\indexeddb\\") || p.contains("\\local storage\\leveldb\\") {
        return (name.ends_with(".ldb") || name.ends_with(".log")).then_some("indexed_database");
    }
    if name.ends_with(".jsonl")
        || name.ends_with(".json")
            && [
                "\\conversations\\",
                "\\chats\\",
                "\\sessions\\",
                "\\projects\\",
                "chat_history",
                "history.json",
            ]
            .iter()
            .any(|s| p.contains(s))
    {
        return Some("conversation_file");
    }
    if [
        "workbuddy.db",
        "state.vscdb",
        "storage.db",
        "db.sqlite",
        "db.sqlite3",
        "webui.db",
        "anythingllm.db",
        "chatbox.db",
        "cherry-studio.db",
    ]
    .contains(&base)
    {
        return Some("application_database");
    }
    None
}

pub(super) fn huorong(v: &Value) -> Option<ai::Artifact> {
    let d = v.get("detail").filter(|v| v.is_object()).unwrap_or(v);
    let target = d.get("pathname").and_then(Value::as_str)?;
    let threat = d.get("recname").and_then(Value::as_str)?;
    if target.is_empty() || threat.is_empty() || target.len() > 32768 || threat.len() > 4096 {
        return None;
    }
    Some(ai::Artifact {
        kind: "malware_detection",
        pointer: if v.get("detail").is_some() {
            "/detail".into()
        } else {
            String::new()
        },
        data: json!({
        "target_path":target,"program_name":target.rsplit(['\\','/']).next(),"threat_name":threat,
        "trigger_process":d.get("procname"),"parent_process":d.get("p_procname"),
        "sha256":d.get("sha256"),"sha1":d.get("sha1"),"md5":d.get("md5"),
        "treatment_raw":d.get("treatment"),"result_raw":d.get("result"),"guid":v.get("guid"),
        "semantics":"火绒报毒记录；目标文件与触发进程分列，未将状态码解释为当前隔离状态"}),
    })
}

fn emit(
    report: &mut ApplicationReport,
    source: &str,
    path: &str,
    evidence: &Value,
    a: ai::Artifact,
) {
    let mut e = evidence.clone();
    e["json_pointer"] = json!(a.pointer);
    let summary = if a.kind == "malware_detection" {
        format!(
            "{} · {}",
            a.data["program_name"].as_str().unwrap_or(""),
            a.data["threat_name"].as_str().unwrap_or("")
        )
    } else {
        a.data
            .get("text")
            .or_else(|| a.data.get("title"))
            .and_then(Value::as_str)
            .unwrap_or(a.kind)
            .chars()
            .take(180)
            .collect()
    };
    report.push(ApplicationRecord {
        artifact_kind: a.kind.into(),
        source: source.into(),
        pid: None,
        path: Some(path.into()),
        summary,
        evidence: e,
        data: a.data,
    });
}

pub(super) fn analyze(
    session: &AnalysisSession,
    kind: ApplicationKind,
    options: &ApplicationOptions,
    token: &CancellationToken,
    report: &mut ApplicationReport,
) -> Result<()> {
    let files = match scan_files_matching_cancellable(
        session.image(),
        session.kernel(),
        session.profile(),
        options.file_limit,
        &|p| file_kind(kind, p).is_some(),
        token,
    ) {
        Ok(v) => v,
        Err(e) => {
            report.failure("application_files", e)?;
            return Ok(());
        }
    };
    report.source(
        "application_files",
        true,
        files.complete,
        files.records.len(),
        files.warnings,
        json!({"path_filter_before_limit":true}),
    );
    let mut order: Vec<_> = files.records.iter().collect();
    order.sort_by_key(|f| {
        let p = f.name.as_deref().unwrap_or("");
        (
            f.shared_cache_map == 0 && f.data_section_object == 0,
            match file_kind(kind, p) {
                Some("application_database") => 0,
                Some("conversation_file") => 1,
                _ => 2,
            },
            f.file_object,
        )
    });
    let mut attempts = 0;
    for f in order {
        token.check_cancelled()?;
        let path = f.name.as_deref().unwrap_or("");
        let category = file_kind(kind, path).unwrap_or("file_candidate");
        if !matches!(category, "application_database" | "conversation_file")
            || f.shared_cache_map == 0 && f.data_section_object == 0
        {
            report.push(ApplicationRecord{artifact_kind:category.into(),source:"filescan".into(),pid:None,path:f.name.clone(),
                summary:if category=="indexed_database"{"已定位 IndexedDB/LevelDB；私有二进制结构暂不解析，继续检查进程内存"}else{"文件对象元数据"}.into(),
                evidence:json!({"file_object":f.file_object,"physical_address":f.physical_address}),data:json!({"application":ai::path_app(path),"content_parsed":false})});
            if category == "indexed_database" {
                report.complete = false;
            }
            continue;
        }
        if attempts >= options.max_files {
            report.source(
                "file_budget",
                false,
                false,
                attempts,
                vec!["剩余文件内容尚未核对：达到文件数预算".into()],
                Value::Null,
            );
            break;
        }
        attempts += 1;
        for source in [DumpSource::Cache, DumpSource::Data] {
            if source == DumpSource::Cache && f.shared_cache_map == 0
                || source == DumpSource::Data && f.data_section_object == 0
            {
                continue;
            }
            let sid = format!("file:{:#x}:{source:?}", f.file_object);
            let (dump, b) = match recover_file_bytes(
                session.image(),
                session.kernel(),
                session.profile(),
                f.file_object,
                source,
                options.max_file_bytes,
            ) {
                Ok(v) => v,
                Err(e) => {
                    report.failure(&sid, e)?;
                    continue;
                }
            };
            let e = json!({"file_object":f.file_object,"recovery_source":source,"recovery_dtb":session.kernel().directory_table_base,"recovery":dump,"buffer_sha256":hex::encode(Sha256::digest(&b))});
            report.source(
                &sid,
                dump.recovered_bytes > 0,
                dump.complete,
                b.len(),
                dump.warnings.clone(),
                e.clone(),
            );
            if b.is_empty() {
                continue;
            }
            let result = if category == "conversation_file" {
                parse_json_file(&b, &dump, &sid, path, options, token, report)
            } else if path.to_ascii_lowercase().ends_with("-wal") {
                // Preserve the candidate main object's identity; never silently pair snapshots.
                let main_path = &path[..path.len() - 4];
                let main = files
                    .records
                    .iter()
                    .filter(|m| {
                        m.name
                            .as_deref()
                            .is_some_and(|n| n.eq_ignore_ascii_case(main_path))
                    })
                    .filter(|m| m.shared_cache_map != 0 || m.data_section_object != 0)
                    .min_by_key(|m| m.file_object);
                let mut base = None;
                if let Some(main) = main
                    && attempts < options.max_files
                {
                    attempts += 1;
                    if let Ok((d, bytes)) = recover_file_bytes(
                        session.image(),
                        session.kernel(),
                        session.profile(),
                        main.file_object,
                        source,
                        options.max_file_bytes,
                    ) {
                        base = Some((d, bytes));
                    }
                }
                parse_database(
                    &b,
                    &dump,
                    base.as_ref().map(|(d, b)| (d, b.as_slice())),
                    &sid,
                    path,
                    kind,
                    options,
                    token,
                    report,
                )
            } else {
                parse_database(&b, &dump, None, &sid, path, kind, options, token, report)
            };
            if let Err(e) = result {
                report.failure(&format!("{sid}:parse"), e)?;
            }
        }
    }
    Ok(())
}

fn parse_json_file(
    b: &[u8],
    dump: &DumpFileReport,
    sid: &str,
    path: &str,
    options: &ApplicationOptions,
    token: &CancellationToken,
    report: &mut ApplicationReport,
) -> Result<()> {
    let app = ai::path_app(path).unwrap_or("AI 客户端");
    if dump.complete
        && wal::covered(&dump.extents, 0, b.len() as u64)
        && let Ok(v) = serde_json::from_slice::<Value>(b)
    {
        for a in ai::extract(&v, app) {
            emit(
                report,
                sid,
                path,
                &json!({"file_offset":0,"byte_length":b.len(),"sha256":hex::encode(Sha256::digest(b)),"file_object":dump.file_object}),
                a,
            );
        }
        return Ok(());
    }
    let parsed = super::text::parse_resident_lines(
        b,
        &dump.extents,
        dump.logical_size,
        options.limit,
        token,
    )?;
    report.source(
        &format!("{sid}:jsonl"),
        true,
        parsed.complete,
        parsed.lines.len(),
        vec![],
        Value::Null,
    );
    for line in parsed.lines.into_iter().filter(|l| l.complete) {
        token.check_cancelled()?;
        if let Ok(v) = serde_json::from_str::<Value>(&line.text) {
            for a in ai::extract(&v, app) {
                emit(
                    report,
                    sid,
                    path,
                    &json!({"file_object":dump.file_object,"file_offset":line.offset,"byte_length":line.byte_length,"sha256":line.sha256,"encoding":line.encoding}),
                    a,
                );
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn parse_database(
    b: &[u8],
    dump: &DumpFileReport,
    base: Option<(&DumpFileReport, &[u8])>,
    sid: &str,
    path: &str,
    kind: ApplicationKind,
    options: &ApplicationOptions,
    token: &CancellationToken,
    report: &mut ApplicationReport,
) -> Result<()> {
    let is_wal = path.to_ascii_lowercase().ends_with("-wal");
    let wal = if is_wal {
        Some(wal::inspect(b, &dump.extents, token)?)
    } else {
        None
    };
    let (main, main_dump) = if is_wal {
        base.map_or((&[][..], None), |(d, b)| (b, Some(d)))
    } else {
        (b, Some(dump))
    };
    let ps = if let Some(w) = &wal {
        w.page_size
    } else {
        ensure!(
            main.len() >= 100 && main.starts_with(b"SQLite format 3\0"),
            "没有驻留 SQLite 主库头（可能缺页或为加密/私有格式）"
        );
        let p = u16::from_be_bytes([main[16], main[17]]);
        if p == 1 { 65536 } else { p as usize }
    };
    ensure!(
        (512..=65536).contains(&ps) && ps.is_power_of_two(),
        "SQLite 页大小无效"
    );
    if is_wal && main.len() >= 100 && main.starts_with(b"SQLite format 3\0") {
        let raw = u16::from_be_bytes([main[16], main[17]]);
        let main_ps = if raw == 1 { 65536 } else { raw as usize };
        ensure!(main_ps == ps, "候选主库与 WAL 页大小不一致，拒绝关联");
    }
    let size = wal.as_ref().map_or(main.len(), |w| w.database_pages * ps);
    ensure!(
        (100..=16 * 1024 * 1024).contains(&size),
        "SQLite 视图大小超限或不足"
    );
    let mut view = vec![0; size];
    let mut origins = std::collections::BTreeMap::<usize, Value>::new();
    if let Some(d) = main_dump {
        for off in (0..main.len().min(size)).step_by(ps) {
            if off + ps <= main.len().min(size) && wal::covered(&d.extents, off as u64, ps as u64) {
                view[off..off + ps].copy_from_slice(&main[off..off + ps]);
                origins.insert(off/ps,json!({"file_object":d.file_object,"recovery_source":d.source,"file_offset":off,"kind":"main"}));
            }
        }
    }
    if let Some(w) = &wal {
        for (page, (frame, off)) in &w.pages {
            let start = (*page as usize - 1) * ps;
            view[start..start + ps].copy_from_slice(&b[*off..*off + ps]);
            origins.insert(*page as usize-1,json!({"file_object":dump.file_object,"recovery_source":dump.source,"file_offset":off,"frame":frame,"kind":"wal"}));
        }
        report.source(&format!("{sid}:wal"),true,w.complete,w.pages.len(),
            if w.complete{vec![]}else{vec!["仅解析最后连续验证的提交；尾部未提交、缺页或校验失败部分未应用".into()]},
            json!({"wal":w.diagnostics,"main_candidate":main_dump.map(|d|json!({"file_object":d.file_object,"recovery":d})),
                "association":"同路径主库候选；不证明两对象属于同一时刻。行及表定义分别保留实际字节来源。"}));
    }
    ensure!(
        origins.contains_key(&0) && view.starts_with(b"SQLite format 3\0"),
        "主库与已提交 WAL 均无完整 schema 头页，未拼造结构"
    );
    ensure!(
        view[56..60] == [0, 0, 0, 1],
        "当前 SQLite 会话适配仅支持 UTF-8 文本库"
    );
    let names = sqlite_table_names(&view)?;
    for name in names.into_iter().filter(|n| !n.starts_with("sqlite_")) {
        token.check_cancelled()?;
        if kind == ApplicationKind::Huorong
            && ![
                "hrlogv3_60",
                "hrtraymsg_60",
                "filesv3_60",
                "hrlogv3",
                "filesv3",
            ]
            .contains(&name.to_ascii_lowercase().as_str())
        {
            continue;
        }
        let table = match parse_sqlite_table(&view, &[&name], options.limit) {
            Ok(t) => t,
            Err(e) => {
                report.failure(&format!("{sid}:{name}"), e)?;
                continue;
            }
        };
        let provenance = |ranges: &[crate::cookies::SqliteSourceRange]| -> Option<Vec<Value>> {
            ranges
                .iter()
                .map(|r| {
                    let page = r.file_offset as usize / ps;
                    let mut o = origins.get(&page)?.clone();
                    if (r.file_offset as usize % ps) + r.length as usize > ps {
                        return None;
                    }
                    o["file_offset"] =
                        json!(o["file_offset"].as_u64()? + r.file_offset % ps as u64);
                    o["byte_length"] = json!(r.length);
                    o["page_number"] = json!(r.page_number);
                    o["sha256"] = json!(hex::encode(Sha256::digest(
                        &view[r.file_offset as usize..(r.file_offset + r.length) as usize]
                    )));
                    Some(o)
                })
                .collect()
        };
        let Some(schema) = provenance(&table.schema_source_ranges) else {
            continue;
        };
        report.source(&format!("{sid}:{name}"),true,table.damaged_pages==0 && !table.limit_reached,table.rows.len(),vec![],
            json!({"damaged_pages":table.damaged_pages,"limit_reached":table.limit_reached,"schema":table.create_sql,"schema_ranges":schema}));
        for row in table.rows {
            token.check_cancelled()?;
            let Some(ranges) = provenance(&row.source_ranges) else {
                report.complete = false;
                continue;
            };
            let mut fields = serde_json::Map::new();
            for (col, index) in &table.columns {
                let v = match row.values.get(*index) {
                    Some(SqlValue::Text(s)) => json!(s),
                    Some(SqlValue::Integer(n)) => json!(n),
                    Some(SqlValue::Blob(b)) => std::str::from_utf8(b)
                        .ok()
                        .map_or(Value::Null, |s| json!(s)),
                    _ => Value::Null,
                };
                fields.insert(col.clone(), v);
            }
            let mut fields = Value::Object(fields);
            let e = json!({"file_object":dump.file_object,"table":name,"rowid":row.rowid,"page_number":row.page_number,"cell_offset_in_database_view":row.file_offset,
                "ranges":ranges,"schema_ranges":schema,"wal_commit_frame":wal.as_ref().map(|w|w.commit_frame),
                "view_semantics":if is_wal{"same_path_candidate_reconstruction"}else{"main_database_only"}});
            if kind == ApplicationKind::Huorong {
                for key in ["detail", "msg", "info"] {
                    if let Some(s) = fields.get(key).and_then(Value::as_str)
                        && let Ok(j) = serde_json::from_str::<Value>(s)
                    {
                        fields[key] = j;
                    }
                }
                if let Some(mut a) = huorong(&fields["detail"]).or_else(|| huorong(&fields["msg"]))
                {
                    a.data["timestamp_unix_seconds"] = fields["ts"].clone();
                    a.data["row_id"] = json!(row.rowid);
                    emit(report, sid, path, &e, a);
                } else {
                    report.push(ApplicationRecord {
                        artifact_kind: if name.to_ascii_lowercase().starts_with("files") {
                            "quarantine_record"
                        } else {
                            "antivirus_event"
                        }
                        .into(),
                        source: sid.into(),
                        pid: None,
                        path: Some(path.into()),
                        summary: format!(
                            "{name} · rowid {} · {}",
                            row.rowid,
                            fields["fname"].as_str().unwrap_or("")
                        ),
                        evidence: e,
                        data: fields,
                    });
                }
            } else {
                let app = ai::path_app(path).unwrap_or("AI 客户端");
                // SQLite text/JSON is parsed only inside a known application's storage.
                for (col, index) in &table.columns {
                    if let Some(SqlValue::Text(s)) = row.values.get(*index)
                        && let Ok(v) = serde_json::from_str::<Value>(s)
                    {
                        let mut ce = e.clone();
                        ce["column"] = json!(col);
                        for a in ai::extract(&v, app) {
                            emit(report, sid, path, &ce, a);
                        }
                    }
                }
                for a in ai::extract(&fields, app) {
                    emit(report, sid, path, &e, a);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dump(bytes: &[u8], object: u64) -> DumpFileReport {
        DumpFileReport {
            file_object: object,
            name: None,
            source: DumpSource::Cache,
            logical_size: bytes.len() as u64,
            output_size: bytes.len() as u64,
            recovered_bytes: bytes.len() as u64,
            missing_bytes: 0,
            complete: true,
            extents: vec![crate::windows::files::RecoveredExtent {
                file_offset: 0,
                length: bytes.len() as u64,
                memory_address: 0x1000,
                memory_kind: "physical".into(),
            }],
            warnings: vec![],
            compressed_pages: vec![],
        }
    }
    #[test]
    fn committed_wal_restores_detection_with_separate_schema_and_row_origins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.db");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE HrLogV3_60(id INTEGER PRIMARY KEY, fid INTEGER, fname TEXT, ts INTEGER, detail TEXT, guid INTEGER); PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        let detail=json!({"detail":{"pathname":"C:\\fixture.exe","recname":"Test/Fixture","procname":"C:\\unpack.exe"}}).to_string();
        db.execute(
            "INSERT INTO HrLogV3_60 VALUES(1,1,'filemon',1234,?1,123)",
            [detail],
        )
        .unwrap();
        let main = std::fs::read(&path).unwrap();
        let wal_bytes = std::fs::read(dir.path().join("log.db-wal")).unwrap();
        let md = dump(&main, 1);
        let wd = dump(&wal_bytes, 2);
        let options = ApplicationOptions::default();
        let mut report = ApplicationReport {
            image: "fixture".into(),
            application: ApplicationKind::Huorong,
            options: options.clone(),
            records: vec![],
            sources: vec![],
            available: false,
            complete: true,
            truncated: false,
            warnings: vec![],
            limitations: vec![],
            record_bytes: 0,
        };
        parse_database(
            &wal_bytes,
            &wd,
            Some((&md, &main)),
            "fixture",
            "log.db-wal",
            ApplicationKind::Huorong,
            &options,
            &CancellationToken::new(),
            &mut report,
        )
        .unwrap();
        let row = report
            .records
            .iter()
            .find(|r| r.artifact_kind == "malware_detection")
            .unwrap();
        assert_eq!(row.data["program_name"], "fixture.exe");
        assert_eq!(row.evidence["ranges"][0]["file_object"], 2);
        assert_eq!(row.evidence["schema_ranges"][0]["file_object"], 1);
        let mut broken = wal_bytes.clone();
        broken[60] ^= 1;
        assert!(
            parse_database(
                &broken,
                &wd,
                Some((&md, &main)),
                "bad",
                "log.db-wal",
                ApplicationKind::Huorong,
                &options,
                &CancellationToken::new(),
                &mut report
            )
            .is_err()
        );
    }
    #[test]
    fn threat_target_is_not_the_trigger_process() {
        let a=huorong(&json!({"detail":{"pathname":"C:\\a\\target.exe","procname":"C:\\7z.exe","recname":"Backdoor/Test"}})).unwrap();
        assert_eq!(a.data["program_name"], "target.exe");
        assert_eq!(a.data["trigger_process"], "C:\\7z.exe");
        assert!(huorong(&json!({"procname":"C:\\suspect.exe"})).is_none());
    }
}
