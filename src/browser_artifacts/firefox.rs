//! Firefox Places and LoginStore adapters. Schemas and row payloads must be
//! resident; zero-filled holes never provide fields or JSON delimiters.
use super::*;
use crate::cookies::{SqlRow, SqliteTable};
use crate::windows::files::RecoveredExtent;

#[derive(Clone)]
struct Place {
    details: HistoryUrlDetails,
    rowid: i64,
    last_visit: Option<i64>,
    hidden: Option<bool>,
    ranges: Vec<crate::cookies::SqliteSourceRange>,
}

fn unix_time(value: i64, units: i64) -> Option<String> {
    if value <= 0 {
        return None;
    }
    let nanos = u32::try_from(value.rem_euclid(units) * (1_000_000_000 / units)).ok()?;
    chrono::DateTime::<chrono::Utc>::from_timestamp(value.div_euclid(units), nanos)
        .map(|time| time.to_rfc3339())
}

fn resident_ranges(
    extents: &[RecoveredExtent],
    ranges: &[crate::cookies::SqliteSourceRange],
) -> bool {
    !ranges.is_empty()
        && ranges
            .iter()
            .all(|range| file_range_fully_recovered(extents, range.file_offset, range.length))
}

fn trusted_table(
    table: Result<SqliteTable>,
    name: &str,
    extents: &[RecoveredExtent],
    report: &mut ParsedHistoryDatabase,
    required: bool,
) -> Option<SqliteTable> {
    let mut table = match table {
        Ok(table) => table,
        Err(error) => {
            report.complete = false;
            if required {
                push_warning(&mut report.warnings, format!("无法解析 {name}：{error:#}"));
            } else {
                push_warning(
                    &mut report.warnings,
                    format!("未取得 Firefox 下载注释表 {name}，下载范围不完整：{error:#}"),
                );
            }
            return None;
        }
    };
    if !resident_ranges(extents, &table.schema_source_ranges) {
        report.complete = false;
        push_warning(
            &mut report.warnings,
            format!("{name} 表结构字节未完整驻留，不生成该表的已确认记录"),
        );
        return None;
    }
    let original = table.rows.len();
    table
        .rows
        .retain(|row| resident_ranges(extents, &row.source_ranges));
    let missing = original - table.rows.len();
    if missing > 0 {
        table.damaged_pages = table.damaged_pages.saturating_add(missing);
        push_warning(
            &mut report.warnings,
            format!("{name} 有 {missing} 条载荷未完整驻留，已跳过"),
        );
    }
    report.damaged_pages = report.damaged_pages.saturating_add(table.damaged_pages);
    if table.damaged_pages > 0 || table.limit_reached {
        report.complete = false;
        push_warning(
            &mut report.warnings,
            format!("{name} 存在损坏或达到结果上限，读取范围不完整"),
        );
    }
    Some(table)
}

fn place(row: &SqlRow, table: &SqliteTable) -> Option<(i64, Place)> {
    let value = |names: &[&str]| row_value(&row.values, &table.columns, names);
    let id = value(&["id"]).and_then(sql_integer).unwrap_or(row.rowid);
    let url = value(&["url"]).and_then(sql_text).and_then(clean_text)?;
    let mut ranges = table.schema_source_ranges.clone();
    ranges.extend(row.source_ranges.clone());
    Some((
        id,
        Place {
            details: HistoryUrlDetails {
                domain: extract_host(&url),
                title: value(&["title"]).and_then(sql_text).and_then(clean_text),
                aggregate_visit_count: value(&["visit_count"]).and_then(sql_integer),
                url,
            },
            rowid: row.rowid,
            last_visit: value(&["last_visit_date"]).and_then(sql_integer),
            hidden: value(&["hidden"]).and_then(sql_integer).map(|v| v != 0),
            ranges,
        },
    ))
}

fn transition(value: i64) -> String {
    match value {
        1 => "link",
        2 => "typed",
        3 => "bookmark",
        4 => "embed",
        5 => "redirect_permanent",
        6 => "redirect_temporary",
        7 => "download",
        8 => "framed_link",
        9 => "reload",
        _ => "unknown",
    }
    .to_owned()
}

pub(super) fn parse_places_database(
    bytes: &[u8],
    candidate: &ArtifactCandidate,
    extents: &[RecoveredExtent],
    source_database_complete: bool,
    summary_limit: usize,
    event_limit: usize,
    download_limit: usize,
) -> Result<ParsedHistoryDatabase> {
    let mut report = ParsedHistoryDatabase {
        visit_history: Vec::new(),
        visit_events: Vec::new(),
        download_history: Vec::new(),
        damaged_pages: 0,
        complete: source_database_complete,
        warnings: Vec::new(),
    };
    let places = trusted_table(
        parse_sqlite_table_descending(bytes, &["moz_places"], summary_limit.max(1)),
        "moz_places",
        extents,
        &mut report,
        true,
    );
    let visits = trusted_table(
        parse_sqlite_table_descending(bytes, &["moz_historyvisits"], event_limit.max(1)),
        "moz_historyvisits",
        extents,
        &mut report,
        true,
    );
    ensure!(
        places.is_some() || visits.is_some(),
        "places.sqlite 的历史表均不可解析或未驻留"
    );
    let mut by_id = BTreeMap::<i64, Place>::new();
    let mut summary_ids = Vec::new();
    if let Some(table) = &places {
        for row in &table.rows {
            if let Some((id, place)) = place(row, table) {
                summary_ids.push(id);
                by_id.insert(id, place);
            }
        }
    }

    // Firefox keeps download metadata per URL, independent of the bounded
    // visits view. Annotation foreign keys must be joined, never guessed from
    // adjacent strings or carried from an unrelated visit of the same URL.
    let attrs = trusted_table(
        parse_sqlite_table(bytes, &["moz_anno_attributes"], 256),
        "moz_anno_attributes",
        extents,
        &mut report,
        false,
    );
    let annos = trusted_table(
        parse_sqlite_table_descending(
            bytes,
            &["moz_annos"],
            download_limit.saturating_mul(4).max(1),
        ),
        "moz_annos",
        extents,
        &mut report,
        false,
    );
    let mut required_ids = BTreeSet::new();
    if let Some(table) = &visits {
        for row in &table.rows {
            if let Some(id) =
                row_value(&row.values, &table.columns, &["place_id"]).and_then(sql_integer)
            {
                required_ids.insert(id);
            }
        }
    }
    let mut downloads = BTreeMap::<i64, DownloadMetadata>::new();
    if let (Some(attrs), Some(annos)) = (&attrs, &annos) {
        let names = attrs
            .rows
            .iter()
            .filter_map(|row| {
                let name = row_value(&row.values, &attrs.columns, &["name"]).and_then(sql_text)?;
                matches!(name, "downloads/destinationFileURI" | "downloads/metaData")
                    .then_some((row.rowid, (name, row)))
            })
            .collect::<HashMap<_, _>>();
        for row in &annos.rows {
            let value = |names: &[&str]| row_value(&row.values, &annos.columns, names);
            let Some((name, attr_row)) = value(&["anno_attribute_id"])
                .and_then(sql_integer)
                .and_then(|id| names.get(&id))
            else {
                continue;
            };
            let Some(place_id) = value(&["place_id"]).and_then(sql_integer) else {
                continue;
            };
            let Some(content) = value(&["content"]).and_then(sql_text).and_then(clean_text) else {
                continue;
            };
            let entry = downloads.entry(place_id).or_default();
            let parsed = if *name == "downloads/destinationFileURI" && entry.uri.is_none() {
                entry.uri = Some(content);
                true
            } else if *name == "downloads/metaData" && entry.metadata.is_none() {
                match serde_json::from_str::<serde_json::Value>(&content) {
                    Ok(metadata) if metadata.is_object() => {
                        entry.metadata = Some(metadata);
                        true
                    }
                    _ => {
                        report.complete = false;
                        push_warning(
                            &mut report.warnings,
                            "Firefox 下载元数据 JSON 无效，未补全状态或结束时间".to_owned(),
                        );
                        false
                    }
                }
            } else {
                false
            };
            if parsed {
                entry.rowid = row.rowid;
                entry.ranges.extend(annos.schema_source_ranges.clone());
                entry.ranges.extend(row.source_ranges.clone());
                entry.ranges.extend(attrs.schema_source_ranges.clone());
                entry.ranges.extend(attr_row.source_ranges.clone());
                required_ids.insert(place_id);
            }
        }
    }
    let missing: BTreeSet<_> = required_ids
        .iter()
        .filter(|id| !by_id.contains_key(id))
        .copied()
        .collect();
    if !missing.is_empty()
        && let Some(lookup) = trusted_table(
            parse_sqlite_table_by_rowids(bytes, &["moz_places"], &missing),
            "moz_places 外键查找",
            extents,
            &mut report,
            true,
        )
    {
        for row in &lookup.rows {
            if let Some((id, place)) = place(row, &lookup) {
                by_id.insert(id, place);
            }
        }
    }
    let unresolved = required_ids
        .iter()
        .filter(|id| !by_id.contains_key(id))
        .count();
    if unresolved > 0 {
        report.complete = false;
        push_warning(
            &mut report.warnings,
            format!("Firefox 有 {unresolved} 个 place_id 外键无法解析"),
        );
    }

    let mut counts = HashMap::<i64, usize>::new();
    if let Some(table) = &visits {
        for row in &table.rows {
            let value = |names: &[&str]| row_value(&row.values, &table.columns, names);
            let Some(url_id) = value(&["place_id"]).and_then(sql_integer) else {
                report.complete = false;
                continue;
            };
            let details = by_id.get(&url_id);
            let visit_time_raw = value(&["visit_date"]).and_then(sql_integer);
            let transition_raw = value(&["visit_type"]).and_then(sql_integer);
            let mut ranges = table.schema_source_ranges.clone();
            ranges.extend(row.source_ranges.clone());
            if let Some(details) = details {
                ranges.extend(details.ranges.clone());
            }
            let source_ranges = browser_source_ranges(extents, &ranges);
            *counts.entry(url_id).or_default() += 1;
            report.visit_events.push(BrowserVisitEventRecord {
                browser: candidate.browser.clone(),
                profile: candidate.profile.clone(),
                visit_id: value(&["id"]).and_then(sql_integer).unwrap_or(row.rowid),
                url_id,
                url: details.map(|p| p.details.url.clone()),
                domain: details.and_then(|p| p.details.domain.clone()),
                title: details.and_then(|p| p.details.title.clone()),
                visit_time_raw,
                visit_time_basis: "unix_epoch_microseconds",
                visit_time_utc: visit_time_raw.and_then(|v| unix_time(v, 1_000_000)),
                transition_raw,
                transition_core: transition_raw.map(transition),
                transition_qualifiers: Vec::new(),
                from_visit_id: value(&["from_visit"])
                    .and_then(sql_integer)
                    .filter(|v| *v != 0),
                opener_visit_id: None,
                visit_duration_microseconds: None,
                aggregate_visit_count: details.and_then(|p| p.details.aggregate_visit_count),
                recovered_visit_event_count: 0,
                count_status: BrowserVisitCountStatus::Unavailable,
                event_recovery_status: BrowserVisitRecoveryStatus::Unavailable,
                source_file: candidate.path.clone(),
                file_object: candidate.file.file_object,
                database_rowid: row.rowid,
                sqlite_page_number: row.page_number,
                sqlite_page_size: table.page_size,
                database_file_offset: row.file_offset,
                parser_payload_complete: true,
                source_bytes_complete: true,
                source_database_complete,
                physical_addresses: source_ranges
                    .iter()
                    .filter_map(|range| range.physical_address)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                source_ranges,
                database_handle_owner_pids: Vec::new(),
                visit_actor_pid: None,
            });
        }
    }
    let event_status = match &visits {
        None => BrowserVisitRecoveryStatus::Unavailable,
        Some(table)
            if source_database_complete && table.damaged_pages == 0 && !table.limit_reached =>
        {
            BrowserVisitRecoveryStatus::Complete
        }
        _ => BrowserVisitRecoveryStatus::Partial,
    };
    for event in &mut report.visit_events {
        let count = counts.get(&event.url_id).copied().unwrap_or(0);
        event.recovered_visit_event_count = count;
        event.count_status =
            visit_count_status(event.aggregate_visit_count, count, visits.is_some());
        event.event_recovery_status = if event.url.is_none() {
            BrowserVisitRecoveryStatus::Partial
        } else {
            event_status
        };
    }
    for id in summary_ids {
        let place = &by_id[&id];
        let count = counts.get(&id).copied().unwrap_or(0);
        // moz_places also contains bookmarks and never-visited URLs. A place
        // alone is not a visit; Firefox's `typed` column is a flag, not a count.
        if place.details.aggregate_visit_count.is_none_or(|v| v <= 0)
            && place.last_visit.is_none_or(|v| v <= 0)
            && count == 0
        {
            continue;
        }
        report.visit_history.push(BrowserVisitHistoryRecord {
            browser: candidate.browser.clone(),
            profile: candidate.profile.clone(),
            url: place.details.url.clone(),
            domain: place.details.domain.clone(),
            title: place.details.title.clone(),
            url_id: id,
            visit_count: place.details.aggregate_visit_count,
            aggregate_visit_count: place.details.aggregate_visit_count,
            recovered_visit_event_count: count,
            count_status: visit_count_status(
                place.details.aggregate_visit_count,
                count,
                visits.is_some(),
            ),
            event_recovery_status: event_status,
            typed_count: None,
            last_visit_time: place.last_visit.and_then(|v| unix_time(v, 1_000_000)),
            hidden: place.hidden,
            source_file: candidate.path.clone(),
            file_object: candidate.file.file_object,
            database_rowid: place.rowid,
            physical_addresses: browser_source_ranges(extents, &place.ranges)
                .iter()
                .filter_map(|r| r.physical_address)
                .collect(),
            source_database_complete,
            database_handle_owner_pids: Vec::new(),
            visit_actor_pid: None,
        });
    }
    for (id, metadata) in downloads {
        let Some(place) = by_id.get(&id) else {
            continue;
        };
        if metadata.uri.is_none() && metadata.metadata.is_none() {
            continue;
        }
        let get = |key: &str| {
            metadata
                .metadata
                .as_ref()
                .and_then(|v| v.get(key))
                .and_then(serde_json::Value::as_i64)
        };
        let target_path = metadata.uri.as_deref().and_then(file_uri_path);
        let mut ranges = metadata.ranges;
        ranges.extend(place.ranges.clone());
        report.download_history.push(BrowserDownloadHistoryRecord {
            browser: candidate.browser.clone(),
            profile: candidate.profile.clone(),
            download_id: id,
            record_kind: "url_download_metadata",
            source_url: Some(place.details.url.clone()),
            url_chain: Vec::new(),
            website: place.details.domain.clone(),
            file_name: target_path.as_deref().and_then(path_file_name),
            target_path,
            // No causal link ties these latest URL annotations to any earlier
            // download visit; do not manufacture a transaction start time.
            start_time: None,
            end_time: get("endTime").and_then(|v| unix_time(v, 1000)),
            received_bytes: None,
            total_bytes: get("fileSize").filter(|v| *v >= 0),
            state: get("state").map(|v| {
                match v {
                    1 => "complete",
                    2 => "failed",
                    3 => "cancelled",
                    4 => "paused",
                    6 | 8 | 9 => "blocked",
                    _ => "unknown",
                }
                .to_owned()
            }),
            danger_type: None,
            interrupt_reason: None,
            http_method: None,
            referrer: None,
            tab_url: None,
            mime_type: None,
            opened: None,
            source_file: candidate.path.clone(),
            file_object: candidate.file.file_object,
            database_rowid: metadata.rowid,
            physical_addresses: browser_source_ranges(extents, &ranges)
                .iter()
                .filter_map(|r| r.physical_address)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        });
    }
    for (name, count, limit) in [
        ("历史概要", report.visit_history.len(), summary_limit),
        ("访问事件", report.visit_events.len(), event_limit),
        ("下载元数据", report.download_history.len(), download_limit),
    ] {
        if count > limit {
            report.complete = false;
            push_warning(
                &mut report.warnings,
                format!("Firefox {name}达到 {limit} 条上限"),
            );
        }
    }
    report.visit_history.truncate(summary_limit);
    report.visit_events.truncate(event_limit);
    report.download_history.truncate(download_limit);
    Ok(report)
}

#[derive(Default)]
struct DownloadMetadata {
    uri: Option<String>,
    metadata: Option<serde_json::Value>,
    rowid: i64,
    ranges: Vec<crate::cookies::SqliteSourceRange>,
}

fn file_uri_path(uri: &str) -> Option<String> {
    let url = reqwest::Url::parse(uri).ok()?;
    if url.scheme() != "file" {
        return None;
    }
    let raw = url.path().as_bytes();
    let mut decoded = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            decoded.push(
                u8::from_str_radix(std::str::from_utf8(raw.get(i + 1..i + 3)?).ok()?, 16).ok()?,
            );
            i += 3;
        } else {
            decoded.push(raw[i]);
            i += 1;
        }
    }
    let path = String::from_utf8(decoded).ok()?;
    if path.chars().any(char::is_control) {
        return None;
    }
    if let Some(host) = url
        .host_str()
        .filter(|host| !host.is_empty() && *host != "localhost")
    {
        Some(format!("\\\\{host}{}", path.replace('/', "\\")))
    } else if path.as_bytes().get(2) == Some(&b':')
        && path.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic)
    {
        Some(path[1..].replace('/', "\\"))
    } else {
        Some(path)
    }
}

fn login_document(bytes: &[u8]) -> Result<serde_json::Value> {
    let document: serde_json::Value = serde_json::from_slice(bytes)?;
    ensure!(
        document
            .get("logins")
            .is_some_and(serde_json::Value::is_array),
        "缺少 Firefox LoginStore logins 数组"
    );
    ensure!(
        document
            .get("version")
            .and_then(serde_json::Value::as_i64)
            .is_some_and(|v| (1..=3).contains(&v)),
        "未支持的 Firefox LoginStore 版本"
    );
    Ok(document)
}

pub(super) fn valid_login_document(bytes: &[u8]) -> bool {
    login_document(bytes).is_ok()
}

pub(super) fn parse_logins_json(
    bytes: &[u8],
    candidate: &ArtifactCandidate,
    extents: &[RecoveredExtent],
    complete: bool,
    limit: usize,
) -> Result<(Vec<BrowserLoginAccountRecord>, bool, Vec<String>)> {
    ensure!(
        complete && !bytes.is_empty() && file_range_fully_recovered(extents, 0, bytes.len() as u64),
        "logins.json 未完整驻留，不从缺页或补零 JSON 重建账号"
    );
    let document = login_document(bytes)?;
    let logins = document["logins"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("logins 不是数组"))?;
    let mut records = Vec::new();
    let mut malformed = 0;
    for (index, login) in logins.iter().enumerate().take(limit) {
        let text = |name: &str| {
            login
                .get(name)
                .and_then(serde_json::Value::as_str)
                .and_then(clean_text)
        };
        let number = |name: &str| login.get(name).and_then(serde_json::Value::as_i64);
        let (Some(id), Some(website)) = (number("id").filter(|id| *id > 0), text("hostname"))
        else {
            malformed += 1;
            continue;
        };
        let (Some(username), Some(password)) = (
            login
                .get("encryptedUsername")
                .and_then(serde_json::Value::as_str),
            login
                .get("encryptedPassword")
                .and_then(serde_json::Value::as_str),
        ) else {
            malformed += 1;
            continue;
        };
        records.push(BrowserLoginAccountRecord {
            browser: candidate.browser.clone(),
            profile: candidate.profile.clone(),
            domain: extract_host(&website),
            origin_url: Some(website.clone()),
            website,
            action_url: text("formSubmitURL"),
            signon_realm: text("httpRealm"),
            username: String::new(),
            username_kind: if username.is_empty() {
                "not_recorded"
            } else {
                "encrypted_unavailable"
            }
            .to_owned(),
            source_format: "firefox_logins_json",
            source_json_pointer: Some(format!("/logins/{index}")),
            password_stored: !password.is_empty(),
            date_created: number("timeCreated").and_then(|v| unix_time(v, 1000)),
            date_last_used: number("timeLastUsed").and_then(|v| unix_time(v, 1000)),
            times_used: number("timesUsed").filter(|v| *v >= 0),
            confidence: "high".to_owned(),
            source_file: candidate.path.clone(),
            file_object: candidate.file.file_object,
            // For JSON this legacy field carries LoginStore's id, not a SQLite
            // rowid. The JSON Pointer identifies the exact source entry.
            database_rowid: id,
            physical_addresses: Vec::new(),
        });
    }
    let mut warnings = Vec::new();
    if !records.is_empty() {
        warnings.push(
            "Firefox 用户名与密码为加密存储；仅恢复网站和使用元数据，不导出密文或声称已解密账号"
                .to_owned(),
        );
    }
    if malformed > 0 {
        warnings.push(format!(
            "logins.json 有 {malformed} 条记录缺少必要字段，已跳过"
        ));
    }
    if logins.len() > limit {
        warnings.push(format!("logins.json 达到 {limit} 条结果上限"));
    }
    Ok((records, malformed == 0 && logins.len() <= limit, warnings))
}

#[cfg(test)]
mod tests;
