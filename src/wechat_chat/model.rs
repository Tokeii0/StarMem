use super::cache::Cache;
use crate::cookies::{
    SqlRow, SqlValue, SqliteSourceRange, SqliteTable, parse_sqlite_table, sqlite_table_names,
};
use anyhow::Result;
use md5::{Digest, Md5};
use serde_json::{Map, Value, json};
use std::{collections::HashMap, io::Read};

const MAX_CONTENT: usize = 1024 * 1024;
pub(super) struct Artifact {
    pub kind: &'static str,
    pub data: Value,
    pub table: String,
    pub rowid: i64,
    pub ranges: Vec<SqliteSourceRange>,
    pub dependencies: Vec<SqliteSourceRange>,
}

fn text(value: Option<&SqlValue>) -> Option<&str> {
    match value {
        Some(SqlValue::Text(s)) => Some(s),
        _ => None,
    }
}
fn integer(value: Option<&SqlValue>) -> Option<i64> {
    match value {
        Some(SqlValue::Integer(v)) => Some(*v),
        _ => None,
    }
}
fn field<'a>(table: &SqliteTable, row: &'a SqlRow, name: &str) -> Option<&'a SqlValue> {
    table.columns.get(name).and_then(|at| row.values.get(*at))
}
fn covered(cache: &Cache, ranges: &[SqliteSourceRange]) -> bool {
    !ranges.is_empty()
        && ranges
            .iter()
            .all(|r| cache.resident(r.file_offset, r.length))
}
fn raw(table: &SqliteTable, row: &SqlRow) -> Value {
    Value::Object(table.columns.iter().map(|(name, &at)| (name.clone(), match row.values.get(at) {
        Some(SqlValue::Text(s)) => json!(s), Some(SqlValue::Integer(n)) => json!(n.to_string()),
        Some(SqlValue::Blob(b)) => json!({"encoding":"hex","byte_length":b.len(),"hex":hex::encode(&b[..b.len().min(4096)]),"preview_truncated":b.len()>4096}),
        Some(SqlValue::Real) => json!({"type":"real","decoded":false}), _ => Value::Null,
    })).collect())
}

/// Only a typed SQLite TEXT or a bounded Zstd frame is a message body.
/// XML remains raw XML; scripts, URLs and attachment paths are never executed.
fn content(value: Option<&SqlValue>) -> Result<(Option<String>, &'static str)> {
    match value {
        Some(SqlValue::Text(s)) if s.len() <= MAX_CONTENT => {
            Ok((Some(s.clone()), "sqlite_text_utf8"))
        }
        Some(SqlValue::Blob(b)) if b.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) => {
            let decoder = zstd::stream::read::Decoder::new(b.as_slice())?;
            let mut out = Vec::new();
            decoder
                .take((MAX_CONTENT + 1) as u64)
                .read_to_end(&mut out)?;
            anyhow::ensure!(out.len() <= MAX_CONTENT, "微信解压正文超过 1 MiB 上限");
            Ok((Some(String::from_utf8(out)?), "sqlite_blob_zstd_utf8"))
        }
        Some(SqlValue::Null) | None => Ok((None, "not_resident_or_null")),
        _ => Ok((None, "unsupported_or_over_limit")),
    }
}

pub(super) fn parse(
    cache: &Cache,
    remaining: usize,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(Vec<Artifact>, Vec<String>)> {
    let bytes = cache.parser_bytes();
    let names = sqlite_table_names(&bytes)?;
    let mut warnings = Vec::new();
    let mut tables = HashMap::new();
    for name in names {
        check()?;
        if !(matches!(name.as_str(), "Name2Id" | "SessionTable" | "contact")
            || (name.starts_with("Msg_")
                && name.len() == 36
                && name[4..].bytes().all(|b| b.is_ascii_hexdigit())))
        {
            continue;
        }
        match parse_sqlite_table(&bytes, &[&name], remaining.saturating_add(1)) {
            Ok(mut table) if covered(cache, &table.schema_source_ranges) => {
                if table.damaged_pages > 0 {
                    warnings.push(format!(
                        "{name} 有 {} 个缺失或损坏的 B-tree 页面",
                        table.damaged_pages
                    ));
                }
                if table.limit_reached {
                    warnings.push(format!("{name} 达到行数上限"));
                }
                table.rows.retain(|row| covered(cache, &row.source_ranges));
                tables.insert(name, table);
            }
            Ok(_) => warnings.push(format!("{name} 表结构来源未完整驻留，排除该表")),
            Err(error) => warnings.push(format!("{name}：{error}")),
        }
    }
    let mut ids = HashMap::<i64, (String, Vec<SqliteSourceRange>)>::new();
    let mut peers = HashMap::<String, (String, Vec<SqliteSourceRange>)>::new();
    if let Some(table) = tables.get("Name2Id") {
        for row in &table.rows {
            if let Some(name) =
                text(field(table, row, "user_name")).filter(|s| !s.is_empty() && s.len() <= 256)
            {
                let deps = [
                    table.schema_source_ranges.clone(),
                    row.source_ranges.clone(),
                ]
                .concat();
                ids.insert(row.rowid, (name.into(), deps.clone()));
                peers.insert(
                    format!("Msg_{}", hex::encode(Md5::digest(name.as_bytes()))),
                    (name.into(), deps),
                );
            }
        }
    }
    let mut records = Vec::new();
    let mut ordered = tables.keys().cloned().collect::<Vec<_>>();
    ordered.sort();
    for name in ordered {
        check()?;
        let table = &tables[&name];
        for row in &table.rows {
            check()?;
            if records.len() >= remaining {
                warnings.push("微信记录达到本次结果上限".into());
                return Ok((records, warnings));
            }
            let mut dependencies = table.schema_source_ranges.clone();
            let mut data = Map::new();
            data.insert("raw_columns".into(), raw(table, row));
            data.insert("sqlite_rowid".into(), json!(row.rowid.to_string()));
            let kind = if name.starts_with("Msg_") {
                let Some(time) = integer(field(table, row, "create_time"))
                    .filter(|v| (946684800..=4102444800).contains(v))
                else {
                    continue;
                };
                let Some(message_type) = integer(field(table, row, "local_type")) else {
                    continue;
                };
                let body = match content(field(table, row, "message_content")) {
                    Ok(value) => value,
                    Err(error) => {
                        warnings.push(format!("{name}/{} 正文：{error}", row.rowid));
                        (None, "decode_failed")
                    }
                };
                data.insert(
                    "msgId".into(),
                    json!(integer(field(table, row, "server_id")).map(|v| v.to_string())),
                );
                data.insert(
                    "localId".into(),
                    json!(
                        integer(field(table, row, "local_id"))
                            .unwrap_or(row.rowid)
                            .to_string()
                    ),
                );
                data.insert("msgTime".into(), json!(time.to_string()));
                data.insert("msgType".into(), json!(message_type.to_string()));
                data.insert("content".into(), json!(body.0));
                data.insert("content_encoding".into(), json!(body.1));
                data.insert(
                    "content_format".into(),
                    json!(if message_type == 1 {
                        "text"
                    } else {
                        "client_payload"
                    }),
                );
                data.insert("direction".into(), json!("unknown"));
                if let Some((peer, ranges)) = peers.get(&name) {
                    data.insert("peerUid".into(), json!(peer));
                    data.insert(
                        "chatType".into(),
                        json!(if peer.ends_with("@chatroom") { 2 } else { 1 }),
                    );
                    data.insert(
                        "peer_association".into(),
                        json!("same-cache Name2Id UTF-8 MD5 equals message table suffix"),
                    );
                    dependencies.extend(ranges.clone());
                }
                if let Some((sender, ranges)) =
                    integer(field(table, row, "real_sender_id")).and_then(|id| ids.get(&id))
                {
                    data.insert("senderUid".into(), json!(sender));
                    data.insert(
                        "sender_association".into(),
                        json!("same-cache real_sender_id equals Name2Id rowid"),
                    );
                    dependencies.extend(ranges.clone());
                }
                "message"
            } else if name == "contact" {
                let Some(uid) = text(field(table, row, "username")).filter(|s| !s.is_empty())
                else {
                    continue;
                };
                data.insert("uid".into(), json!(uid));
                data.insert("nick".into(), json!(text(field(table, row, "nick_name"))));
                data.insert("remark".into(), json!(text(field(table, row, "remark"))));
                data.insert("alias".into(), json!(text(field(table, row, "alias"))));
                if uid.ends_with("@chatroom") {
                    data.insert("groupCode".into(), json!(uid));
                    data.insert(
                        "groupName".into(),
                        json!(
                            text(field(table, row, "remark"))
                                .filter(|s| !s.is_empty())
                                .or_else(|| text(field(table, row, "nick_name")))
                        ),
                    );
                    "group_profile"
                } else {
                    "profile"
                }
            } else if name == "SessionTable" {
                let Some(peer) = text(field(table, row, "username")) else {
                    continue;
                };
                data.insert("peerUid".into(), json!(peer));
                data.insert("summary".into(), json!(text(field(table, row, "summary"))));
                data.insert(
                    "last_timestamp".into(),
                    json!(integer(field(table, row, "last_timestamp")).map(|n| n.to_string())),
                );
                "session"
            } else {
                data.insert("uid".into(), json!(text(field(table, row, "user_name"))));
                "name_map"
            };
            // Namespace is explicit: different live databases do not silently
            // become the same conversation merely because usernames match.
            data.insert(
                "cache_scope".into(),
                json!(format!(
                    "0x{:x}:0x{:x}",
                    cache.cache_address, cache.pager_address
                )),
            );
            data.insert("table".into(), json!(name));
            records.push(Artifact {
                kind,
                data: Value::Object(data),
                table: name.clone(),
                rowid: row.rowid,
                ranges: row.source_ranges.clone(),
                dependencies,
            });
        }
    }
    Ok((records, warnings))
}

#[cfg(test)]
mod tests {
    use super::super::cache::CachePage;
    use super::*;
    use std::{collections::BTreeMap, fs};
    fn database(with_mapping: bool) -> Cache {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.db");
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("PRAGMA page_size=4096; CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY,is_session INTEGER);").unwrap();
        let peer = "123456789@chatroom";
        let table = format!("Msg_{}", hex::encode(Md5::digest(peer.as_bytes())));
        c.execute_batch(&format!("CREATE TABLE {table}(local_id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER,local_type INTEGER,real_sender_id INTEGER,create_time INTEGER,message_content TEXT);
            INSERT INTO {table} VALUES(1,9223372036854775806,1,7,1790928521,'你好🍔 <script>');")).unwrap();
        if with_mapping {
            c.execute("INSERT INTO Name2Id(rowid,user_name,is_session) VALUES(7,'wxid_sender_test',0),(8,?1,1)",[peer]).unwrap();
        }
        drop(c);
        let b = fs::read(path).unwrap();
        let pages = b
            .chunks_exact(4096)
            .enumerate()
            .map(|(i, p)| {
                (
                    (i + 1) as u32,
                    CachePage {
                        number: (i + 1) as u32,
                        data_address: 0x20000 + i as u64 * 0x4000,
                        header_address: 0,
                        extra_address: 0,
                        bucket_address: 0,
                        bytes: p.to_vec(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        Cache {
            header_address: 0x20000,
            cache_address: 0x10000,
            pager_address: 0x12000,
            pcache_address: 0x11000,
            hash_address: 0x18000,
            page_size: 4096,
            declared_pages: pages.len() as u32,
            pages,
            warnings: Vec::new(),
        }
    }
    #[test]
    fn message_body_ids_and_group_sender_are_bound_to_the_same_cache() {
        let cache = database(true);
        let (records, _) = parse(&cache, 100, &mut || Ok(())).unwrap();
        let m = records.iter().find(|r| r.kind == "message").unwrap();
        assert_eq!(m.data["msgId"], "9223372036854775806");
        assert_eq!(m.data["content"], "你好🍔 <script>");
        assert_eq!(m.data["peerUid"], "123456789@chatroom");
        assert_eq!(m.data["senderUid"], "wxid_sender_test");
        assert_eq!(m.data["chatType"], 2);
        assert_eq!(m.data["direction"], "unknown");
        assert!(!m.dependencies.is_empty());
        assert!(covered(&cache, &m.ranges));
        let other = database(false);
        let (records, _) = parse(&other, 100, &mut || Ok(())).unwrap();
        let m = records.iter().find(|r| r.kind == "message").unwrap();
        assert!(m.data.get("peerUid").is_none());
        assert!(m.data.get("senderUid").is_none());
    }
    #[test]
    fn missing_message_leaf_and_cancel_do_not_return_fabricated_rows() {
        let mut cache = database(true);
        let (records, _) = parse(&cache, 100, &mut || Ok(())).unwrap();
        let page = records.iter().find(|r| r.kind == "message").unwrap().ranges[0].page_number;
        cache.pages.remove(&page);
        let (records, warnings) = parse(&cache, 100, &mut || Ok(())).unwrap();
        assert!(!records.iter().any(|r| r.kind == "message"));
        assert!(!warnings.is_empty());
        assert!(
            parse(&database(true), 100, &mut || Err(anyhow::anyhow!(
                "cancelled"
            )))
            .is_err()
        );
    }
    #[test]
    fn typed_zstd_text_has_a_bounded_output_and_unknown_blobs_remain_unknown() {
        let b = zstd::stream::encode_all("压缩正文🍔".as_bytes(), 1).unwrap();
        assert_eq!(
            content(Some(&SqlValue::Blob(b))).unwrap().0.as_deref(),
            Some("压缩正文🍔")
        );
        assert!(
            content(Some(&SqlValue::Blob(vec![1, 2, 3])))
                .unwrap()
                .0
                .is_none()
        );
        let b = zstd::stream::encode_all(&vec![b'x'; MAX_CONTENT + 1][..], 1).unwrap();
        assert!(content(Some(&SqlValue::Blob(b))).is_err());
    }
}
