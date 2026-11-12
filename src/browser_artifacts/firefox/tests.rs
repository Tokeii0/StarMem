use super::*;

fn fixture() -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("places.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        r#"
        PRAGMA page_size=4096;
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT,
            rev_host TEXT, visit_count INTEGER, hidden INTEGER, typed INTEGER,
            frecency INTEGER, last_visit_date INTEGER, guid TEXT);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER,
            place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER);
        CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER,
            anno_attribute_id INTEGER, content TEXT, flags INTEGER, expiration INTEGER,
            type INTEGER, dateAdded INTEGER, lastModified INTEGER);
        INSERT INTO moz_places VALUES
            (1,'https://example.test/old','旧页面','',2,0,1,0,1704067200000000,'old'),
            (20,'https://example.test/report.pdf','文件','',1,0,0,0,1704067201000000,'file'),
            (99,'https://example.test/bookmark','未访问书签','',0,0,0,0,NULL,'bookmark');
        INSERT INTO moz_historyvisits VALUES
            (10,0,1,1704067200000000,2,1),
            (11,10,1,1704067200500000,9,1),
            (30,0,20,1704067201000000,7,1);
        INSERT INTO moz_anno_attributes VALUES
            (7,'downloads/metaData'),(9,'downloads/destinationFileURI'),(12,'unrelated');
        INSERT INTO moz_annos VALUES
            (1,20,7,'{"state":1,"endTime":1704067202000,"fileSize":1234}',0,0,0,0,0),
            (2,20,9,'file:///C:/Downloads/%E6%8A%A5%E5%91%8A%20a.pdf',0,0,0,0,0),
            (3,1,12,'file:///C:/wrong.pdf',0,0,0,0,0);
    "#,
    )
    .unwrap();
    drop(db);
    std::fs::read(path).unwrap()
}

fn candidate(base: &str) -> ArtifactCandidate {
    let mut result = super::super::tests::candidate(
        if base == "places.sqlite" {
            ArtifactKind::FirefoxPlaces
        } else {
            ArtifactKind::FirefoxLogins
        },
        base,
    );
    result.browser = "Firefox".to_owned();
    result.profile = Some("test.default-release".to_owned());
    result.path = format!(
        r"\Users\Alice\AppData\Roaming\Mozilla\Firefox\Profiles\test.default-release\{base}"
    );
    result
}

fn extent(start: usize, end: usize) -> RecoveredExtent {
    RecoveredExtent {
        file_offset: start as u64,
        memory_address: 0x9000 + start as u64,
        length: (end - start) as u64,
        memory_kind: "physical".to_owned(),
    }
}

#[test]
fn places_history_uses_unix_epoch_and_excludes_unvisited_bookmarks() {
    let bytes = fixture();
    let report = parse_places_database(
        &bytes,
        &candidate("places.sqlite"),
        &[extent(0, bytes.len())],
        true,
        20,
        20,
        20,
    )
    .unwrap();
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(report.visit_history.len(), 2);
    assert_eq!(report.visit_events.len(), 3);
    let old = report.visit_history.iter().find(|p| p.url_id == 1).unwrap();
    assert_eq!(old.aggregate_visit_count, Some(2));
    assert_eq!(old.recovered_visit_event_count, 2);
    assert_eq!(
        old.typed_count, None,
        "Firefox typed is a flag, not typed_count"
    );
    assert_eq!(
        old.last_visit_time.as_deref(),
        Some("2024-01-01T00:00:00+00:00")
    );
    let typed = report
        .visit_events
        .iter()
        .find(|e| e.visit_id == 10)
        .unwrap();
    assert_eq!(typed.transition_core.as_deref(), Some("typed"));
    assert_eq!(typed.visit_time_basis, "unix_epoch_microseconds");
    assert_eq!(typed.visit_actor_pid, None);
    assert!(typed.source_ranges.iter().all(|r| r.fully_recovered));
    assert_eq!(
        report
            .visit_events
            .iter()
            .find(|e| e.visit_id == 11)
            .unwrap()
            .from_visit_id,
        Some(10)
    );
}

#[test]
fn summary_limit_does_not_break_visit_foreign_keys() {
    let bytes = fixture();
    let report = parse_places_database(
        &bytes,
        &candidate("places.sqlite"),
        &[extent(0, bytes.len())],
        true,
        1,
        20,
        20,
    )
    .unwrap();
    assert!(!report.complete);
    assert!(report.visit_history.len() <= 1);
    assert_eq!(
        report
            .visit_events
            .iter()
            .find(|e| e.visit_id == 10)
            .unwrap()
            .title
            .as_deref(),
        Some("旧页面")
    );
    assert_eq!(report.download_history.len(), 1);
}

#[test]
fn download_annotations_join_ids_without_fabricating_transaction_time() {
    let bytes = fixture();
    let report = parse_places_database(
        &bytes,
        &candidate("places.sqlite"),
        &[extent(0, bytes.len())],
        true,
        20,
        20,
        20,
    )
    .unwrap();
    let download = &report.download_history[0];
    assert_eq!(download.record_kind, "url_download_metadata");
    assert_eq!(
        download.target_path.as_deref(),
        Some(r"C:\Downloads\报告 a.pdf")
    );
    assert_eq!(download.file_name.as_deref(), Some("报告 a.pdf"));
    assert_eq!(
        download.end_time.as_deref(),
        Some("2024-01-01T00:00:02+00:00")
    );
    assert_eq!(download.start_time, None);
    assert_eq!(download.received_bytes, None);
    assert_eq!(download.total_bytes, Some(1234));
    assert_eq!(download.state.as_deref(), Some("complete"));
    assert!(download.url_chain.is_empty());
    assert!(download.physical_addresses.len() >= 3);
}

#[test]
fn nonresident_place_payload_is_never_used_for_visit_or_download_url() {
    let bytes = fixture();
    let table = parse_sqlite_table(&bytes, &["moz_places"], 20).unwrap();
    let row = table.rows.iter().find(|r| r.rowid == 20).unwrap();
    let gap = row.source_ranges[0].file_offset as usize;
    let extents = [extent(0, gap), extent(gap + 1, bytes.len())];
    let report = parse_places_database(
        &bytes,
        &candidate("places.sqlite"),
        &extents,
        false,
        20,
        20,
        20,
    )
    .unwrap();
    assert!(!report.complete);
    assert!(!report.visit_history.iter().any(|r| r.url_id == 20));
    assert!(report.download_history.is_empty());
    let event = report
        .visit_events
        .iter()
        .find(|e| e.visit_id == 30)
        .unwrap();
    assert_eq!(event.url, None);
    assert_eq!(
        event.event_recovery_status,
        BrowserVisitRecoveryStatus::Partial
    );
}

#[test]
fn truncated_events_are_not_presented_as_complete_counts() {
    let bytes = fixture();
    let report = parse_places_database(
        &bytes,
        &candidate("places.sqlite"),
        &[extent(0, bytes.len())],
        true,
        20,
        1,
        20,
    )
    .unwrap();
    assert!(!report.complete);
    assert_eq!(report.visit_events.len(), 1);
    assert!(
        report
            .visit_history
            .iter()
            .all(|r| r.event_recovery_status == BrowserVisitRecoveryStatus::Partial)
    );
}

fn logins() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"version":3, "logins":[
        {"id":1,"hostname":"https://example.test","httpRealm":null,"formSubmitURL":"https://example.test/login",
         "encryptedUsername":"PRIVATE_USERNAME_CIPHERTEXT","encryptedPassword":"PRIVATE_PASSWORD_CIPHERTEXT",
         "timeCreated":1704067200000i64,"timeLastUsed":1704067201000i64,"timesUsed":2},
        {"id":2,"hostname":"https://example.test","encryptedUsername":"SECOND_CIPHERTEXT","encryptedPassword":"SECOND_PASSWORD"}
    ]})).unwrap()
}

#[test]
fn login_json_preserves_encrypted_account_identity_without_exposing_secrets() {
    let bytes = logins();
    let (records, complete, warnings) = parse_logins_json(
        &bytes,
        &candidate("logins.json"),
        &[extent(0, bytes.len())],
        true,
        20,
    )
    .unwrap();
    assert!(complete);
    assert_eq!(records.len(), 2);
    assert!(!warnings.is_empty());
    assert_eq!(records[0].username_kind, "encrypted_unavailable");
    assert_eq!(records[0].source_json_pointer.as_deref(), Some("/logins/0"));
    assert!(records[0].username.is_empty());
    assert!(records[0].password_stored);
    assert_eq!(
        records[0].date_created.as_deref(),
        Some("2024-01-01T00:00:00+00:00")
    );
    let encoded = serde_json::to_string(&records).unwrap();
    assert!(!encoded.contains("CIPHERTEXT"));
    assert!(!encoded.contains("PRIVATE_PASSWORD"));
    assert_ne!(records[0].database_rowid, records[1].database_rowid);
}

#[test]
fn login_json_holes_and_limits_are_reported() {
    let bytes = logins();
    assert!(
        parse_logins_json(
            &bytes,
            &candidate("logins.json"),
            &[extent(0, bytes.len() - 1)],
            true,
            20
        )
        .is_err()
    );
    assert!(
        parse_logins_json(
            &bytes,
            &candidate("logins.json"),
            &[extent(0, bytes.len())],
            false,
            20
        )
        .is_err()
    );
    let (records, complete, _) = parse_logins_json(
        &bytes,
        &candidate("logins.json"),
        &[extent(0, bytes.len())],
        true,
        1,
    )
    .unwrap();
    assert_eq!(records.len(), 1);
    assert!(!complete);
    assert!(!valid_login_document(br#"{"version":99,"logins":[]}"#));
    assert!(!valid_login_document(br#"{"version":3,"users":[]}"#));
}

#[test]
fn mixed_browser_timestamps_compare_using_the_same_epoch() {
    let bytes = fixture();
    let mut report = parse_places_database(
        &bytes,
        &candidate("places.sqlite"),
        &[extent(0, bytes.len())],
        true,
        20,
        20,
        20,
    )
    .unwrap();
    let firefox = report.visit_events.remove(0);
    let mut chrome = firefox.clone();
    chrome.visit_time_basis = "windows_epoch_microseconds";
    chrome.visit_time_raw = firefox
        .visit_time_raw
        .map(|t| t + 11_644_473_600_000_000 - 1);
    assert!(chrome.visit_time_raw > firefox.visit_time_raw);
    assert!(visit_unix_microseconds(&chrome) < visit_unix_microseconds(&firefox));
}

#[test]
fn artifact_selection_covers_common_profiles_without_generic_history_matches() {
    for path in [
        r"C:\Users\a\AppData\Roaming\Opera Software\Opera Stable\History",
        r"D:\360se\User Data\Default\Login Data",
        r"D:\QQBrowser\UserData\Default\History",
        r"D:\Vivaldi\Default\History",
        r"D:\Chromium\Default\History",
        r"D:\SogouExplorer\Default\History",
        r"D:\portable\profile\places.sqlite",
        r"D:\portable\profile\logins.json",
    ] {
        let mut file = candidate("places.sqlite").file;
        file.name = Some(path.to_owned());
        assert!(classify_artifact_file(file).is_some(), "{path}");
    }
    let mut file = candidate("places.sqlite").file;
    file.name = Some(r"C:\unrelated\History".to_owned());
    assert!(classify_artifact_file(file).is_none());
    assert_eq!(
        infer_chromium_profile_from_path(r"C:\Opera Software\Opera Stable\History").as_deref(),
        Some("Opera Stable")
    );
}
