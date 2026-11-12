use super::*;
use crate::system::credentials::recovery_tests::HiveFixture;
use crate::system::credentials::recovery_tests::{sam_fixture, security_fixture, system_fixture};
use crate::windows::symbolless::SymbollessSession;

const BASE: u64 = 0xffff_f800_0000_0000;
const SAM: usize = 0x90240;
const SYSTEM: usize = 0xb0240;

#[test]
fn file_backed_userassist_and_amcache_keep_provenance_and_partial_decoder_state() {
    use crate::system::registry::artifact_tests::{amcache_fixture, userassist_fixture};
    for (action, name, hive) in [
        (
            "userassist",
            "\\Users\\analyst\\NTUSER.DAT",
            userassist_fixture(true, 72),
        ),
        (
            "amcache",
            "\\Windows\\appcompat\\Programs\\Amcache.hve",
            amcache_fixture(&format!("0000{}", "a".repeat(40)), true),
        ),
    ] {
        let mut bytes = fixture(true);
        configure_file(&mut bytes, SAM, 0x90000, name, &valid_header(&hive));
        let report = run(&bytes, &options(action)).unwrap();
        assert_eq!(report["records"].as_array().unwrap().len(), 1);
        assert_eq!(report["records"][0]["source_file"], name);
        assert_eq!(report["records"][0]["hive_file_object"], BASE + SAM as u64);
        assert_eq!(report["hive_sources"].as_array().unwrap().len(), 1);
        assert_eq!(report["decoder_complete"], false);
        assert_eq!(report["external_debug_symbols_used"], false);
        assert_eq!(report["active_hive_verified"], false);
        assert!(!report["warnings"].as_array().unwrap().is_empty());
    }
}

#[test]
fn activity_actions_require_the_right_hive_and_do_not_accept_a_system_pair() {
    for action in ["userassist", "amcache"] {
        assert!(
            run(&fixture(true), &options(action))
                .unwrap_err()
                .to_string()
                .contains("文件对象")
        );
        let mut opts = options(action);
        opts.system_address = Some(BASE + SYSTEM as u64);
        assert!(opts.validate().is_err());
    }
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn valid_header(hive: &RegistryHive) -> Vec<u8> {
    let mut bytes = hive.bytes().to_vec();
    for (at, value) in [
        (4, 1),
        (8, 1),
        (0x14, 1),
        (0x18, 5),
        (0x20, 1),
        (0x28, 0x4000),
    ] {
        put32(&mut bytes, at, value);
    }
    let checksum = bytes[..0x1fc].chunks_exact(4).fold(0, |sum, word| {
        sum ^ u32::from_le_bytes(word.try_into().unwrap())
    });
    put32(
        &mut bytes,
        0x1fc,
        match checksum {
            0 => 1,
            u32::MAX => u32::MAX - 1,
            value => value,
        },
    );
    bytes
}

fn configure_file(bytes: &mut [u8], file: usize, anchor: usize, name: &str, content: &[u8]) {
    let name_bytes: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    put64(bytes, file + 0x18, BASE + anchor as u64 + 0x6000);
    put64(bytes, file + 0x28, BASE + anchor as u64 + 0x2000);
    bytes[file + 0x58..file + 0x5a].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    bytes[file + 0x5a..file + 0x5c].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    put64(bytes, file + 0x60, BASE + anchor as u64 + 0x4000);
    bytes[anchor + 0x4000..anchor + 0x4000 + name_bytes.len()].copy_from_slice(&name_bytes);
    let cache = anchor + 0x3000;
    put64(bytes, anchor + 0x2008, BASE + cache as u64);
    put64(bytes, cache + 8, content.len() as u64);
    put64(bytes, cache + 0xa0, BASE + file as u64);
    put64(bytes, cache + 0x38, BASE + anchor as u64 + 0x5000);
    put64(bytes, cache + 0x58, BASE + cache as u64 + 0x38);
    put64(bytes, anchor + 0x5000, BASE + anchor as u64 + 0x8000);
    put64(bytes, anchor + 0x5008, BASE + cache as u64);
    bytes[anchor + 0x6002..anchor + 0x6004].copy_from_slice(&0x100u16.to_le_bytes());
    put64(bytes, anchor + 0x6020, content.len() as u64);
    bytes[anchor + 0x8000..anchor + 0x8000 + content.len()].copy_from_slice(content);
    bytes[file - 0x18] = 7 ^ (((BASE + file as u64 - 0x30) >> 8) as u8) ^ 0x5a;
}

fn fixture(aes: bool) -> Vec<u8> {
    let mut bytes = files::tests::fixture();
    bytes.copy_within(0x90200..0x90400, 0xb0200);
    configure_file(
        &mut bytes,
        SAM,
        0x90000,
        "\\Windows\\System32\\config\\SAM",
        &valid_header(&sam_fixture(aes, false, false)),
    );
    configure_file(
        &mut bytes,
        SYSTEM,
        0xb0000,
        "\\Windows\\System32\\config\\SYSTEM",
        &valid_header(&system_fixture(false, false)),
    );
    bytes
}

fn options(action: &str) -> RegistryOptions {
    RegistryOptions {
        address: BASE + SAM as u64,
        expected_physical: Some(SAM as u64),
        source: "cache".into(),
        action: action.into(),
        system_address: if matches!(action, "hashdump" | "lsadump" | "cachedump") {
            Some(BASE + SYSTEM as u64)
        } else {
            None
        },
        system_physical: None,
        system_source: "cache".into(),
        key: String::new(),
        recurse: false,
        limit: 100,
        max_bytes: 65536,
    }
}

fn run(bytes: &[u8], options: &RegistryOptions) -> Result<Value> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("synthetic.raw");
    std::fs::write(&path, bytes)?;
    let cancel = CancellationToken::new();
    let session = SymbollessSession::from_image(MemoryImage::open(&path)?, 64, &cancel)?;
    session.registry(options, &cancel)
}

#[test]
fn recovered_file_objects_decode_independent_sam_vectors_without_symbols() {
    for aes in [false, true] {
        let report = run(&fixture(aes), &options("hashdump")).unwrap();
        assert_eq!(
            report["records"][0]["nt_hash"],
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
        assert_eq!(report["records"][0]["username"], "analyst");
        assert_eq!(report["hive_sources"].as_array().unwrap().len(), 2);
        assert_eq!(
            report["hive_sources"][1]["file_object"],
            BASE + SYSTEM as u64
        );
        assert_eq!(report["records"][0]["hive_file_object"], BASE + SAM as u64);
        assert_eq!(report["external_debug_symbols_used"], false);
        assert_eq!(report["decoder_complete"], true);
        assert_eq!(report["complete"], false);
        assert_eq!(report["active_hive_verified"], false);
        assert_eq!(report["hive_sources"][0]["acquisition_complete"], true);
    }
}

#[test]
fn missing_unused_page_is_reported_but_missing_hive_root_is_rejected() {
    let mut bytes = fixture(true);
    put64(&mut bytes, 0xc000 + 0x9a * 8, 0);
    let report = run(&bytes, &options("hashdump")).unwrap();
    assert_eq!(report["hive_sources"][0]["missing_hive_bytes"], 4096);
    assert_eq!(report["hive_sources"][0]["acquisition_complete"], false);
    assert_eq!(report["records"].as_array().unwrap().len(), 1);
    put64(&mut bytes, 0xc000 + 0x99 * 8, 0);
    assert!(
        run(&bytes, &options("hashdump"))
            .unwrap_err()
            .to_string()
            .contains("未完整恢复")
    );
}

#[test]
fn recovered_security_supports_lsa_and_cache_with_explicit_system_pair() {
    let mut bytes = fixture(true);
    configure_file(
        &mut bytes,
        SAM,
        0x90000,
        "\\Windows\\System32\\config\\SECURITY",
        &valid_header(&security_fixture()),
    );
    let lsa = run(&bytes, &options("lsadump")).unwrap();
    assert_eq!(lsa["records"].as_array().unwrap().len(), 2);
    let cache = run(&bytes, &options("cachedump")).unwrap();
    assert_eq!(cache["records"][0]["username"], "analyst");
    assert_eq!(
        cache["records"][0]["hash"],
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    );
    assert_eq!(cache["decoder_complete"], true);
}

#[test]
fn registry_reads_data_section_without_a_shared_cache_map() {
    let mut bytes = fixture(true);
    put64(&mut bytes, 0x92008, 0);
    put64(&mut bytes, 0x92000, BASE + 0xd0000);
    put64(&mut bytes, 0xd0000, BASE + 0xd1000);
    put32(&mut bytes, 0xd0038, 0x80);
    put64(&mut bytes, 0xd0040, BASE + SAM as u64);
    put64(&mut bytes, 0xd1000, BASE + 0xd0000);
    put32(&mut bytes, 0xd1008, 5);
    put64(&mut bytes, 0xd1018, 0x5000);
    put64(&mut bytes, 0xd0080, BASE + 0xd0000);
    put64(&mut bytes, 0xd0088, BASE + 0xd3000);
    put32(&mut bytes, 0xd00a8, 5);
    put32(&mut bytes, 0xd00ac, 5);
    for page in 0..5 {
        put64(&mut bytes, 0xd3000 + page * 8, 0x98001 + page as u64 * 4096);
    }
    let mut opts = options("hashdump");
    opts.source = "data".into();
    let report = run(&bytes, &opts).unwrap();
    assert_eq!(
        report["records"][0]["nt_hash"],
        "8846f7eaee8fb117ad06bdd830b7586c"
    );
    assert_eq!(report["hive_sources"][0]["source"], "data");
    assert_eq!(report["hive_sources"][0]["acquisition_complete"], true);
}

#[test]
fn refuses_changed_object_dirty_header_bad_checksum_and_cross_directory_pair() {
    let mut wrong = options("hashdump");
    wrong.expected_physical = Some(1);
    assert!(
        run(&fixture(true), &wrong)
            .unwrap_err()
            .to_string()
            .contains("物理地址")
    );
    for at in [0x98004, 0x981fc] {
        let mut bytes = fixture(true);
        bytes[at] ^= 1;
        assert!(
            format!("{:#}", run(&bytes, &options("hashdump")).unwrap_err())
                .contains("基块校验失败")
        );
    }
    let mut bytes = fixture(true);
    configure_file(
        &mut bytes,
        SYSTEM,
        0xb0000,
        "\\Windows.old\\System32\\config\\SYSTEM",
        &valid_header(&system_fixture(false, false)),
    );
    assert!(
        run(&bytes, &options("hashdump"))
            .unwrap_err()
            .to_string()
            .contains("目录不一致")
    );
    let mut bytes = fixture(true);
    bytes.copy_within(0x91000..0x91150, 0xb1000);
    put64(&mut bytes, SYSTEM + 8, BASE + 0xb1000);
    assert!(
        run(&bytes, &options("hashdump"))
            .unwrap_err()
            .to_string()
            .contains("同一设备对象")
    );
}

#[test]
fn printkey_reports_truncation_and_overview_keeps_file_provenance() {
    let mut opts = options("printkey");
    opts.limit = 1;
    let report = run(&fixture(true), &opts).unwrap();
    assert_eq!(report["records"].as_array().unwrap().len(), 1);
    assert_eq!(report["decoder_complete"], false);
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("上限"))
    );
    let report = run(&fixture(true), &options("overview")).unwrap();
    assert_eq!(report["source_file"], "\\Windows\\System32\\config\\SAM");
    assert_eq!(report["active_hive_verified"], false);
}

#[test]
fn read_guard_shares_budget_across_clones_and_preserves_cancellation() {
    let token = CancellationToken::new();
    let mut hive = system_fixture(false, false);
    let guard = RegistryReadGuard::new(&token, 1, 65536);
    hive.set_read_guard(guard.clone());
    hive.root().unwrap();
    assert!(hive.clone().root().is_err());
    assert!(
        guard
            .check()
            .unwrap_err()
            .to_string()
            .contains("STARMEM_REGISTRY_BUDGET")
    );
    let guard = RegistryReadGuard::new(&token, 100, 65536);
    hive.set_read_guard(guard);
    token.request_cancel();
    assert!(crate::cancellation::is_cancellation_error(
        &hive.root().unwrap_err()
    ));
    let token = CancellationToken::new();
    let mut fixture = HiveFixture::new();
    let value = fixture.value("Huge", b"bounded");
    let root = fixture.key("ROOT", &[], &[value], None);
    let mut bytes = fixture.finish(root).bytes().to_vec();
    put32(&mut bytes, 0x1000 + value as usize + 8, 0x7fff0000);
    let mut hive = RegistryHive::from_bytes(bytes).unwrap();
    let guard = RegistryReadGuard::new(&token, 100, 65536);
    hive.set_read_guard(guard.clone());
    let _ = hive.values_best_effort(&hive.root().unwrap());
    assert!(
        guard
            .check()
            .unwrap_err()
            .to_string()
            .contains("STARMEM_REGISTRY_BUDGET")
    );
}

#[test]
fn file_backed_overview_reuses_system_software_and_user_artifact_decoders() {
    for (leaf, path, value_name, text) in [
        (
            "SYSTEM",
            "ControlSet001\\Control\\ComputerName\\ComputerName",
            "ComputerName",
            "FIXTURE-PC",
        ),
        (
            "SOFTWARE",
            "Microsoft\\Windows NT\\CurrentVersion",
            "ProductName",
            "Fixture OS",
        ),
        (
            "NTUSER.DAT",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "FixtureStart",
            "C:\\Fixture\\demo.exe",
        ),
    ] {
        let mut hive = HiveFixture::new();
        let text_bytes: Vec<_> = text
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        let value = hive.value(value_name, &text_bytes);
        let parts: Vec<_> = path.split('\\').collect();
        let mut child = hive.key(parts.last().unwrap(), &[], &[value], None);
        for name in parts[..parts.len() - 1].iter().rev() {
            child = hive.key(name, &[child], &[], None);
        }
        let root = hive.key("ROOT", &[child], &[], None);
        let mut content = hive.finish(root).bytes().to_vec();
        put32(&mut content, 0x1000 + value as usize + 4 + 12, 1); // REG_SZ, not REG_BINARY.
        let mut bytes = fixture(true);
        configure_file(
            &mut bytes,
            SAM,
            0x90000,
            &format!("\\fixtures\\{leaf}"),
            &valid_header(&RegistryHive::from_bytes(content).unwrap()),
        );
        let report = run(&bytes, &options("overview")).unwrap();
        match leaf {
            "SYSTEM" => assert!(
                report["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["field"] == "computer_name" && row["value"] == text)
            ),
            "SOFTWARE" => assert!(
                report["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["field"] == "product" && row["value"]["product_name"] == text)
            ),
            _ => {
                let rows = report["autoruns"].as_array().unwrap();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["source_file"], "\\fixtures\\NTUSER.DAT");
                assert_eq!(rows[0]["user_sid"], Value::Null);
            }
        }
    }
}

#[test]
fn parameter_validation_requires_explicit_pair_and_known_sources() {
    let mut opts = options("hashdump");
    opts.system_address = None;
    assert!(opts.validate().is_err());
    opts = options("printkey");
    opts.source = "image".into();
    assert!(opts.validate().is_err());
    opts = options("overview");
    opts.recurse = true;
    assert!(opts.validate().is_err());
}
