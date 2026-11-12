use super::*;
use crate::system::credentials::recovery_tests::HiveFixture;

#[test]
fn printkey_keeps_hive_and_parent_key_identity_distinct_from_value_cells() {
    let mut h = HiveFixture::new();
    let value = h.value("ImagePath", b"driver.sys");
    let child = h.key("Driver", &[], &[value], None);
    let root = h.key("SYSTEM", &[child], &[], None);
    let hive = h.finish(root);
    let bytes = hive.bytes().to_vec();
    let address = 0xffff_de09_bdc5_6000;
    let report = print_registry_key_from_target(
        RecoveredTargetHive {
            hive: Some(hive),
            cmhive: Some(address),
            complete: true,
            warnings: Vec::new(),
        },
        "SYSTEM",
        "",
        true,
        100,
    );
    assert!(report.complete, "{:?}", report.warnings);
    let key = report
        .records
        .iter()
        .find(|r| r.kind == "key" && r.name == "Driver")
        .unwrap();
    let vk = report.records.iter().find(|r| r.kind == "value").unwrap();
    assert_eq!(key.cmhive, Some(address));
    assert_eq!(key.cell_index, child);
    assert_eq!(vk.cell_index, value);
    assert_ne!(vk.cell_index, vk.key_cell_index);
    assert_eq!(vk.key_cell_index, child);
    assert_eq!(vk.key_identity, key.key_identity);
    assert_eq!(
        key.key_identity,
        Some(format!("ffffde09bdc56000:{child:08x}"))
    );
    let offline = print_registry_hive(
        RegistryHive::from_bytes(bytes).unwrap(),
        "SYSTEM",
        "",
        true,
        100,
    );
    assert!(offline.complete);
    assert!(
        offline
            .records
            .iter()
            .all(|r| r.cmhive.is_none() && r.key_identity.is_none())
    );
}

pub(crate) fn userassist_fixture(extra_missing: bool, length: usize) -> RegistryHive {
    let mut h = HiveFixture::new();
    let mut raw = vec![0; length];
    if length >= 72 {
        raw[4..8].copy_from_slice(&7u32.to_le_bytes());
        raw[8..12].copy_from_slice(&2u32.to_le_bytes());
        raw[12..16].copy_from_slice(&3000u32.to_le_bytes());
        raw[60..68].copy_from_slice(&133_485_408_000_000_000u64.to_le_bytes());
    } else if length == 16 {
        raw[..4].copy_from_slice(&9u32.to_le_bytes());
        raw[4..8].copy_from_slice(&8u32.to_le_bytes());
        raw[8..16].copy_from_slice(&133_485_408_000_000_000u64.to_le_bytes());
    }
    let value = h.value("P:\\grfg.rkr", &raw);
    let mut values = vec![value];
    if extra_missing {
        values.push(0x3e00);
    }
    let mut child = h.key("Count", &[], &values, None);
    for name in [
        "{fixture}",
        "UserAssist",
        "Explorer",
        "CurrentVersion",
        "Windows",
        "Microsoft",
        "Software",
        "NTUSER",
    ] {
        child = h.key(name, &[child], &[], None);
    }
    h.finish(child)
}

pub(crate) fn amcache_fixture(id: &str, extra_missing: bool) -> RegistryHive {
    let mut h = HiveFixture::new();
    let mut text_values = Vec::new();
    for (name, value) in [
        ("LowerCaseLongPath", "c:\\工具\\sample.exe"),
        ("FileId", id),
        ("ProductName", "fixture"),
    ] {
        let bytes: Vec<_> = value
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        text_values.push(h.value(name, &bytes));
    }
    let mut values = text_values.clone();
    if extra_missing {
        values.push(0x3e00);
    }
    let file = h.key("file-1", &[], &values, None);
    let inventory = h.key("InventoryApplicationFile", &[file], &[], None);
    let root = h.key("Root", &[inventory], &[], None);
    let root = h.key("Amcache", &[root], &[], None);
    let mut bytes = h.finish(root).bytes().to_vec();
    for value in text_values {
        let at = 0x1000 + value as usize + 4 + 12;
        bytes[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
    }
    RegistryHive::from_bytes(bytes).unwrap()
}

#[test]
fn userassist_decodes_exact_legacy_and_modern_formats_and_preserves_source() {
    for (length, count, session) in [(16, 3, Some(9)), (72, 7, None)] {
        let r = userassist_from_hive(
            userassist_fixture(false, length),
            "users\\analyst\\NTUSER.DAT",
            100,
        );
        assert!(r.available && r.complete, "{:?}", r.warnings);
        assert_eq!(r.records[0].decoded_name, "C:\\test.exe");
        assert_eq!(r.records[0].run_count, Some(count));
        assert_eq!(r.records[0].session_id, session);
        assert_eq!(r.records[0].hive, "users\\analyst\\NTUSER.DAT");
        assert!(r.records[0].last_execution.is_some());
    }
}

#[test]
fn unreadable_values_do_not_hide_other_userassist_or_amcache_records() {
    let r = userassist_from_hive(userassist_fixture(true, 72), "NTUSER.DAT", 100);
    assert_eq!(r.records.len(), 1);
    assert_eq!(r.records[0].run_count, Some(7));
    assert!(!r.complete && !r.warnings.is_empty());
    let r = amcache_from_hive(amcache_fixture(&"a".repeat(40), true), "Amcache.hve", 100);
    assert_eq!(r.records.len(), 1);
    assert_eq!(r.records[0].path.as_deref(), Some("c:\\工具\\sample.exe"));
    assert!(!r.complete && !r.warnings.is_empty());
}

#[test]
fn userassist_unknown_lengths_preserve_raw_data_without_inventing_counts() {
    for length in [8, 32, 71, 73] {
        let r = userassist_from_hive(userassist_fixture(false, length), "NTUSER.DAT", 100);
        assert_eq!(r.records[0].run_count, None);
        assert_eq!(r.records[0].raw_data_hex.len(), length * 2);
        assert!(!r.complete && !r.warnings.is_empty());
    }
}

#[test]
fn amcache_keeps_zero_prefixed_sha1_and_raw_ids_and_rejects_non_hashes() {
    let hash = format!("00000000{}", "a".repeat(32));
    for id in [&hash, &format!("0000{hash}")] {
        let r = amcache_from_hive(amcache_fixture(id, false), "Amcache.hve", 100);
        assert!(r.complete, "{:?}", r.warnings);
        assert_eq!(r.records[0].sha1.as_deref(), Some(hash.as_str()));
        assert_eq!(r.records[0].sha1_raw.as_deref(), Some(id.as_str()));
        assert_eq!(
            r.records[0].key_path,
            "Root\\InventoryApplicationFile\\file-1"
        );
        assert_eq!(r.records[0].hive, "Amcache.hve");
    }
    let r = amcache_from_hive(amcache_fixture("unsupported-id", false), "Amcache.hve", 100);
    assert_eq!(r.records[0].sha1, None);
    assert_eq!(r.records[0].sha1_raw.as_deref(), Some("unsupported-id"));
    assert!(!r.complete);
}

#[test]
fn missing_branches_and_budgets_are_not_reported_as_complete_empty_results() {
    let hive = userassist_fixture(false, 72);
    let root = hive.root().unwrap().cell_index as usize + 0x1004;
    let mut bytes = hive.bytes().to_vec();
    bytes[root + 0x1c..root + 0x20].copy_from_slice(&0x3f00u32.to_le_bytes());
    let r = userassist_from_hive(RegistryHive::from_bytes(bytes).unwrap(), "NTUSER.DAT", 100);
    assert!(r.records.is_empty() && !r.complete && !r.warnings.is_empty());
    let r = userassist_from_hive(hive, "NTUSER.DAT", 0);
    assert!(r.records.is_empty() && !r.complete);
    let r = amcache_from_hive(userassist_fixture(false, 72), "unknown.hve", 100);
    assert!(r.records.is_empty() && !r.complete && !r.warnings.is_empty());
    let r = amcache_from_hive(amcache_fixture(&"a".repeat(40), false), "Amcache.hve", 0);
    assert!(r.records.is_empty() && !r.complete);
}

#[test]
fn declared_cell_bytes_outside_recovered_ranges_are_unavailable() {
    let hive = userassist_fixture(false, 72);
    let count = hive
        .open_key(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{fixture}\\Count",
        )
        .unwrap()
        .unwrap();
    let value = hive.values(&count).unwrap().remove(0);
    let start = 0x1000 + value.cell_index as usize;
    let size = hive.bytes().len();
    let hive =
        RegistryHive::from_recovered_bytes(hive.bytes().to_vec(), vec![0..start, start + 8..size])
            .unwrap();
    let r = userassist_from_hive(hive, "NTUSER.DAT", 100);
    assert!(r.records.is_empty() && !r.complete && !r.warnings.is_empty());
}

#[test]
fn amcache_application_driver_and_file_groups_share_one_record_limit() {
    let mut h = HiveFixture::new();
    let mut branches = Vec::new();
    let mut text_values = Vec::new();
    for (branch, field, path) in [
        ("InventoryApplication", "RootDirPath", "c:\\app"),
        (
            "InventoryApplicationFile",
            "LowerCaseLongPath",
            "c:\\app\\file.exe",
        ),
        ("InventoryDriverBinary", "DriverName", "driver.sys"),
        ("Programs", "RootDirPath", "c:\\oldapp"),
    ] {
        let bytes: Vec<_> = path
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        let value = h.value(field, &bytes);
        text_values.push(value);
        let key = h.key("entry", &[], &[value], None);
        branches.push(h.key(branch, &[key], &[], None));
    }
    let root = h.key("Root", &branches, &[], None);
    let root = h.key("Amcache", &[root], &[], None);
    let mut bytes = h.finish(root).bytes().to_vec();
    for value in text_values {
        let at = 0x1000 + value as usize + 4 + 12;
        bytes[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
    }
    let hive = RegistryHive::from_bytes(bytes).unwrap();
    let r = amcache_from_hive(hive.clone(), "Amcache.hve", 10);
    assert!(r.complete);
    assert_eq!(
        r.records
            .iter()
            .map(|row| row.entry_type.as_str())
            .collect::<Vec<_>>(),
        ["program", "file", "driver", "program"]
    );
    assert_eq!(r.records[2].path.as_deref(), Some("driver.sys"));
    let r = amcache_from_hive(hive, "Amcache.hve", 2);
    assert_eq!(r.records.len(), 2);
    assert!(!r.complete);
    assert_eq!(r.warnings.iter().filter(|w| w.contains("上限")).count(), 1);
}
