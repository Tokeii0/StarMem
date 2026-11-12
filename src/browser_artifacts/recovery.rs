//! Independent database views and conservative, schema-less URL candidates.
use super::*;
use crate::cookies::{
    SqlRow, SqlValue, recovery_physical_extents_windows, visit_resident_sqlite_leaf_rows,
};
use crate::windows::files::{DumpFileReport, DumpSource, RecoveredExtent, recover_file_bytes};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub struct BrowserDatabaseSource {
    pub browser: String,
    pub profile: Option<String>,
    pub source_file: String,
    pub file_object: u64,
    pub recovery_source: String,
    pub selected: bool,
    pub recovered_bytes: u64,
    pub logical_size: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub header_status: String,
    pub extents: Vec<RecoveredExtent>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserCandidateRange {
    pub file_offset: u64,
    pub length: u64,
    pub physical_address: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserPageCandidate {
    pub browser: String,
    pub profile: Option<String>,
    pub source_file: String,
    pub file_object: u64,
    pub recovery_source: String,
    pub evidence_status: String,
    pub schema_profile: String,
    pub url: String,
    pub title: String,
    pub database_rowid: i64,
    pub aggregate_visit_count: i64,
    pub typed_count: i64,
    pub last_visit_time_raw: i64,
    pub last_visit_time: Option<String>,
    pub hidden: bool,
    pub sqlite_page_number: u32,
    pub sqlite_page_size: usize,
    pub database_file_offset: u64,
    /// Exact payload ranges, split at physical-page boundaries, in read order.
    pub source_ranges: Vec<BrowserCandidateRange>,
    /// SQLite file header and complete leaf page used to locate the cell.
    pub structure_ranges: Vec<BrowserCandidateRange>,
}

fn header_status(bytes: &[u8], extents: &[RecoveredExtent]) -> &'static str {
    if !file_range_fully_recovered(extents, 0, 100) {
        return "header_not_resident";
    }
    if bytes.len() < 100 || !bytes.starts_with(b"SQLite format 3\0") {
        return "invalid_sqlite_header";
    }
    let raw = u16::from_be_bytes([bytes[16], bytes[17]]);
    let size = if raw == 1 { 65536 } else { usize::from(raw) };
    if !(512..=65536).contains(&size) || !size.is_power_of_two() {
        return "invalid_sqlite_header";
    }
    "sqlite_header_present"
}

fn artifact_header_status(
    bytes: &[u8],
    extents: &[RecoveredExtent],
    kind: ArtifactKind,
) -> &'static str {
    if kind != ArtifactKind::FirefoxLogins {
        return header_status(bytes, extents);
    }
    if bytes.is_empty() || !file_range_fully_recovered(extents, 0, bytes.len() as u64) {
        return "json_not_fully_resident";
    }
    if super::firefox::valid_login_document(bytes) {
        "json_document_present"
    } else {
        "invalid_login_json"
    }
}

fn view_score(
    bytes: &[u8],
    extents: &[RecoveredExtent],
    recovered: u64,
    kind: ArtifactKind,
) -> (bool, usize, u64) {
    let status = artifact_header_status(bytes, extents, kind);
    let header = matches!(status, "sqlite_header_present" | "json_document_present");
    if kind == ArtifactKind::FirefoxLogins {
        return (header, usize::from(header), recovered);
    }
    let tables: &[&str] = match kind {
        ArtifactKind::History => &["urls", "visits", "downloads"],
        ArtifactKind::LoginData => &["logins"],
        ArtifactKind::FirefoxPlaces => &["moz_places", "moz_historyvisits", "moz_annos"],
        ArtifactKind::FirefoxLogins => &[],
    };
    let readable_tables = if header {
        tables
            .iter()
            .filter(|name| parse_sqlite_table(bytes, &[name], 1).is_ok())
            .count()
    } else {
        0
    };
    (header, readable_tables, recovered)
}

/// Evaluate cache/data independently. Keep only the strongest byte view in
/// memory for the schema parser; never overlay two potentially stale copies.
pub(super) fn recover_database(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    kernel_space: &WindowsAddressSpace<'_>,
    candidate: &ArtifactCandidate,
    maximum: u64,
    sources: &mut Vec<BrowserDatabaseSource>,
) -> Option<(DumpFileReport, Vec<u8>, Vec<RecoveredExtent>, String)> {
    let mut best = None;
    let mut best_score = (false, 0, 0);
    let mut selected_index = None;
    for (source, name) in [(DumpSource::Cache, "cache"), (DumpSource::Data, "data")] {
        let result = recover_file_bytes(
            image,
            kernel,
            profile,
            candidate.file.file_object,
            source,
            maximum,
        );
        let mut status = BrowserDatabaseSource {
            browser: candidate.browser.clone(),
            profile: candidate.profile.clone(),
            source_file: candidate.path.clone(),
            file_object: candidate.file.file_object,
            recovery_source: name.to_owned(),
            selected: false,
            recovered_bytes: 0,
            logical_size: 0,
            missing_bytes: 0,
            complete: false,
            header_status: "recovery_failed".to_owned(),
            extents: Vec::new(),
            warnings: Vec::new(),
        };
        match result {
            Ok((dump, bytes)) => {
                let extents = recovery_physical_extents_windows(&dump.extents, kernel_space);
                status.recovered_bytes = dump.recovered_bytes;
                status.logical_size = dump.logical_size;
                status.missing_bytes = dump.missing_bytes;
                status.complete = dump.complete;
                status.header_status = if dump.recovered_bytes == 0 {
                    "no_resident_bytes"
                } else {
                    artifact_header_status(&bytes, &extents, candidate.kind)
                }
                .to_owned();
                status.extents = recovery_physical_extents_windows(&dump.extents, kernel_space);
                status.warnings = dump.warnings.clone();
                let score = view_score(&bytes, &extents, dump.recovered_bytes, candidate.kind);
                if dump.recovered_bytes > 0 && (best.is_none() || score > best_score) {
                    best_score = score;
                    selected_index = Some(sources.len());
                    best = Some((dump, bytes, extents, name.to_owned()));
                }
            }
            Err(error) => status.warnings.push(format!("{error:#}")),
        }
        sources.push(status);
    }
    if let Some(index) = selected_index {
        sources[index].selected = true;
    }
    best
}

fn exact_ranges(
    bytes: &[u8],
    extents: &[RecoveredExtent],
    start: u64,
    length: u64,
) -> Option<Vec<BrowserCandidateRange>> {
    let end = start.checked_add(length)?;
    let mut cursor = start;
    let mut result = Vec::new();
    while cursor < end {
        let extent = extents.iter().find(|e| {
            e.memory_kind == "physical"
                && e.file_offset <= cursor
                && e.file_offset
                    .checked_add(e.length)
                    .is_some_and(|end| cursor < end)
        })?;
        let stop = end.min(extent.file_offset.checked_add(extent.length)?);
        let physical_address = extent
            .memory_address
            .checked_add(cursor - extent.file_offset)?;
        let data = bytes.get(usize::try_from(cursor).ok()?..usize::try_from(stop).ok()?)?;
        result.push(BrowserCandidateRange {
            file_offset: cursor,
            length: stop - cursor,
            physical_address,
            sha256: format!("{:x}", Sha256::digest(data)),
        });
        cursor = stop;
    }
    Some(result)
}

fn url_candidate(row: &SqlRow) -> Option<(&str, &str, i64, i64, i64, bool)> {
    // Chromium's seven-column urls layout. An unknown extension is not guessed.
    if row.values.len() != 7 || row.rowid <= 0 || !matches!(row.values[0], SqlValue::Null) {
        return None;
    }
    let url = sql_text(&row.values[1])?;
    let title = sql_text(&row.values[2])?;
    if !["http://", "https://", "file://", "ftp://"]
        .iter()
        .any(|p| url.starts_with(p))
        || url.len() > MAX_TEXT_LENGTH
        || url.chars().any(|c| c.is_control() || c.is_whitespace())
        || title.len() > MAX_TEXT_LENGTH
    {
        return None;
    }
    let visits = sql_integer(&row.values[3])?;
    let typed = sql_integer(&row.values[4])?;
    let time = sql_integer(&row.values[5])?;
    let hidden = sql_integer(&row.values[6])?;
    if visits < 0
        || typed < 0
        || !matches!(hidden, 0 | 1)
        || !(0..=25_000_000_000_000_000).contains(&time)
    {
        return None;
    }
    Some((url, title, visits, typed, time, hidden != 0))
}

pub(super) fn salvage_history(
    bytes: &[u8],
    candidate: &ArtifactCandidate,
    extents: &[RecoveredExtent],
    source: &str,
    limit: usize,
) -> Result<(Vec<BrowserPageCandidate>, bool)> {
    let mut records = Vec::new();
    let mut truncated = false;
    // Page scans must not rescan every recovered extent for every database page.
    let mut ranges: Vec<_> = extents
        .iter()
        .filter(|e| e.memory_kind == "physical")
        .filter_map(|e| {
            e.file_offset
                .checked_add(e.length)
                .map(|end| (e.file_offset, end))
        })
        .collect();
    ranges.sort_unstable();
    let mut coverage: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = coverage.last_mut().filter(|last| start <= last.1) {
            last.1 = last.1.max(end);
        } else {
            coverage.push((start, end));
        }
    }
    let resident = |start: u64, length: u64| {
        let index = coverage.partition_point(|range| range.0 <= start);
        index > 0
            && start
                .checked_add(length)
                .is_some_and(|end| end <= coverage[index - 1].1)
    };
    visit_resident_sqlite_leaf_rows(bytes, resident, |row, page_size| {
        let Some((url, title, visits, typed, time, hidden)) = url_candidate(&row) else {
            return true;
        };
        if records.len() >= limit {
            truncated = true;
            return false;
        }
        let Some(ranges) = row
            .source_ranges
            .iter()
            .map(|r| exact_ranges(bytes, extents, r.file_offset, r.length))
            .collect::<Option<Vec<_>>>()
        else {
            return true;
        };
        let page_start = u64::from(row.page_number - 1) * page_size as u64;
        let Some(mut structure_ranges) = exact_ranges(bytes, extents, 0, 100) else {
            return true;
        };
        let Some(page_ranges) = exact_ranges(bytes, extents, page_start, page_size as u64) else {
            return true;
        };
        structure_ranges.extend(page_ranges);
        records.push(BrowserPageCandidate {
            browser: candidate.browser.clone(),
            profile: candidate.profile.clone(),
            source_file: candidate.path.clone(),
            file_object: candidate.file.file_object,
            recovery_source: source.to_owned(),
            evidence_status: "schema_unverified_candidate".to_owned(),
            schema_profile: "chromium_urls_7_columns".to_owned(),
            url: url.to_owned(),
            title: title.to_owned(),
            database_rowid: row.rowid,
            aggregate_visit_count: visits,
            typed_count: typed,
            last_visit_time_raw: time,
            last_visit_time: (time != 0).then(|| chromium_time(time)).flatten(),
            hidden,
            sqlite_page_number: row.page_number,
            sqlite_page_size: page_size,
            database_file_offset: row.file_offset,
            source_ranges: ranges.into_iter().flatten().collect(),
            structure_ranges,
        });
        true
    })?;
    Ok((records, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(title: &str) -> (Vec<u8>, Vec<RecoveredExtent>, ArtifactCandidate) {
        let path = tempfile::NamedTempFile::new().unwrap();
        let db = rusqlite::Connection::open(path.path()).unwrap();
        db.execute_batch("PRAGMA page_size=4096; CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);").unwrap();
        db.execute(
            "INSERT INTO urls VALUES (1,'https://example.test/证据',?1,2,1,13431151571972050,0)",
            [title],
        )
        .unwrap();
        drop(db);
        let bytes = std::fs::read(path.path()).unwrap();
        let extents = vec![RecoveredExtent {
            file_offset: 0,
            length: bytes.len() as u64,
            memory_address: 0x10000,
            memory_kind: "physical".to_owned(),
        }];
        (
            bytes,
            extents,
            super::super::tests::candidate(ArtifactKind::History, "History"),
        )
    }

    #[test]
    fn leaf_survives_missing_schema_and_has_exact_physical_ranges() {
        let (mut bytes, extents, candidate) = fixture("驻留标题");
        bytes[100..4096].fill(0);
        assert!(parse_sqlite_table(&bytes, &["urls"], 100).is_err());
        let (rows, truncated) = salvage_history(&bytes, &candidate, &extents, "data", 10).unwrap();
        assert!(!truncated);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].title, "驻留标题");
        assert_eq!(rows[0].evidence_status, "schema_unverified_candidate");
        let range = &rows[0].source_ranges[0];
        assert_eq!(range.physical_address, 0x10000 + range.file_offset);
        assert_eq!(
            range.sha256,
            format!(
                "{:x}",
                Sha256::digest(
                    &bytes[range.file_offset as usize..(range.file_offset + range.length) as usize]
                )
            )
        );
    }

    #[test]
    fn missing_header_leaf_or_overflow_never_becomes_candidate() {
        let (bytes, mut extents, candidate) = fixture(&"长".repeat(3000));
        let (rows, _) = salvage_history(&bytes, &candidate, &extents, "data", 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].source_ranges.len() > 1);
        extents[0].length = 8192;
        assert!(
            salvage_history(&bytes, &candidate, &extents, "data", 10)
                .unwrap()
                .0
                .is_empty()
        );
        extents[0].length = 8191;
        assert!(
            salvage_history(&bytes, &candidate, &extents, "data", 10)
                .unwrap()
                .0
                .is_empty()
        );
        extents[0].file_offset = 4096;
        assert!(salvage_history(&bytes, &candidate, &extents, "data", 10).is_err());
    }

    #[test]
    fn view_ranking_prefers_valid_data_over_sparse_cache_without_overlay() {
        let (bytes, extents, _) = fixture("标题");
        let holes = vec![RecoveredExtent {
            file_offset: 4096,
            length: 4096,
            memory_address: 0x11000,
            memory_kind: "physical".to_owned(),
        }];
        assert_eq!(header_status(&bytes, &holes), "header_not_resident");
        assert!(
            view_score(&bytes, &extents, 8192, ArtifactKind::History)
                > view_score(&bytes, &holes, 32768, ArtifactKind::History)
        );
    }

    #[test]
    fn result_limit_is_reported_without_promoting_unknown_rows() {
        let (bytes, extents, candidate) = fixture("标题");
        let (rows, truncated) = salvage_history(&bytes, &candidate, &extents, "data", 0).unwrap();
        assert!(rows.is_empty() && truncated);
        let mut changed = bytes.clone();
        let start = changed.windows(8).position(|s| s == b"https://").unwrap();
        changed[start..start + 8].copy_from_slice(b"content:");
        assert!(
            salvage_history(&changed, &candidate, &extents, "data", 10)
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[test]
    fn bad_cell_pointer_and_one_byte_hole_do_not_produce_records() {
        let (mut bytes, mut extents, candidate) = fixture("标题");
        extents[0].length = 8191;
        assert!(
            salvage_history(&bytes, &candidate, &extents, "data", 10)
                .unwrap()
                .0
                .is_empty()
        );
        extents[0].length = bytes.len() as u64;
        bytes[4104..4106].copy_from_slice(&2u16.to_be_bytes());
        assert!(
            salvage_history(&bytes, &candidate, &extents, "data", 10)
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[test]
    fn provenance_splits_noncontiguous_physical_pages() {
        let bytes = vec![0x41; 8192];
        let extents = vec![
            RecoveredExtent {
                file_offset: 0,
                length: 4096,
                memory_address: 0x9000,
                memory_kind: "physical".to_owned(),
            },
            RecoveredExtent {
                file_offset: 4096,
                length: 4096,
                memory_address: 0x3000,
                memory_kind: "physical".to_owned(),
            },
        ];
        let ranges = exact_ranges(&bytes, &extents, 4090, 20).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!((ranges[0].physical_address, ranges[0].length), (0x9ffa, 6));
        assert_eq!((ranges[1].physical_address, ranges[1].length), (0x3000, 14));
        assert!(exact_ranges(&bytes, &extents[..1], 4090, 20).is_none());
    }
}
