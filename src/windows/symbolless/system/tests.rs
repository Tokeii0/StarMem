use super::*;
use crate::image::ImageOpenOptions;
use crate::windows::symbolless::SymbollessSession;

const DATA: usize = 0x90000;
const BUILD: usize = 0x14100;
const NOW: u64 = 133_802_928_000_000_001;

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn clock(bytes: &mut [u8], at: usize, value: u64) {
    put32(bytes, DATA + at, value as u32);
    put32(bytes, DATA + at + 4, (value >> 32) as u32);
    put32(bytes, DATA + at + 8, (value >> 32) as u32);
}
fn fixture() -> Vec<u8> {
    let mut bytes = super::super::tests::fixture();
    put64(
        &mut bytes,
        0x1000 + ((SHARED >> 39) & 0x1ff) as usize * 8,
        0xd003,
    );
    put64(
        &mut bytes,
        0xd000 + ((SHARED >> 30) & 0x1ff) as usize * 8,
        0xe003,
    );
    put64(
        &mut bytes,
        0xe000 + ((SHARED >> 21) & 0x1ff) as usize * 8,
        0xf003,
    );
    put64(
        &mut bytes,
        0xf000 + ((SHARED >> 12) & 0x1ff) as usize * 8,
        DATA as u64 | 3,
    );
    for (index, word) in "C:\\Windows".encode_utf16().enumerate() {
        bytes[DATA + 0x30 + index * 2..DATA + 0x32 + index * 2]
            .copy_from_slice(&word.to_le_bytes());
    }
    put32(&mut bytes, DATA + 0x26c, 10);
    put32(&mut bytes, DATA + 0x264, 1);
    bytes[DATA + 0x268] = 1;
    put32(&mut bytes, DATA + 0x260, 22621);
    clock(&mut bytes, 0x14, NOW);
    clock(&mut bytes, 0x8, 3600 * TICKS);
    clock(&mut bytes, 0x20, (-480_i64 * 600_000_000) as u64);
    // Fifth target PE export, without an RSDS record or any external symbols.
    put32(&mut bytes, 0x11000 + 20, 5);
    put32(&mut bytes, 0x11000 + 24, 5);
    put32(&mut bytes, 0x11050, 0x4100);
    put32(&mut bytes, 0x11070, 0x11c0);
    bytes[0x11088..0x1108a].copy_from_slice(&4_u16.to_le_bytes());
    bytes[0x111c0..0x111cd].copy_from_slice(b"NtBuildNumber");
    put32(&mut bytes, BUILD, 0xf000_0000 | 22621);
    bytes
}

fn with_session(bytes: &[u8], f: impl FnOnce(&SymbollessSession)) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("memory.raw");
    std::fs::write(&path, bytes).unwrap();
    let session = SymbollessSession::open_system_cancellable(
        &path,
        ImageOpenOptions::default(),
        &CancellationToken::new(),
    )
    .unwrap();
    f(&session);
}
fn run(bytes: &[u8]) -> Value {
    let mut report = Value::Null;
    with_session(bytes, |session| {
        report = session.system_info(&CancellationToken::new()).unwrap();
    });
    report
}
fn field<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["field"] == name)
        .unwrap()
}

#[test]
fn reads_target_system_fields_and_preserves_estimates_provenance_and_unavailable_items() {
    let report = run(&fixture());
    assert_eq!(report["source_label"], "无符号推断");
    assert_eq!(report["external_debug_symbols_used"], false);
    assert_eq!(report["process_enumeration_performed"], false);
    assert_eq!(report["capabilities"]["process_list"]["status"], "not_run");
    assert_eq!(report["shared_data_validated"], true);
    assert_eq!(field(&report, "nt_build_number")["value"], 22621);
    assert_eq!(field(&report, "system_root_copy")["value"], "C:\\Windows");
    assert_eq!(
        field(&report, "system_time_utc")["value"],
        timestamp(NOW).unwrap()
    );
    assert_eq!(
        field(&report, "system_time_utc")["raw_value"]["value_100ns"],
        NOW
    );
    assert_eq!(
        field(&report, "system_time_utc")["physical_address"],
        DATA + 0x14
    );
    assert_eq!(field(&report, "utc_offset_minutes")["value"], 480);
    assert_eq!(field(&report, "uptime_seconds")["value"], 3600.0);
    assert_eq!(
        field(&report, "estimated_boot_time_utc")["evidence_status"],
        "estimated"
    );
    assert_eq!(
        field(&report, "estimated_boot_time_utc")["value"],
        timestamp(NOW - 3600 * TICKS).unwrap()
    );
    for name in [
        "computer_name",
        "product_name",
        "update_build_revision",
        "installed_memory_bytes",
    ] {
        assert_eq!(field(&report, name)["value"], Value::Null);
        assert_eq!(field(&report, name)["evidence_status"], "unavailable");
    }
    assert!(
        report["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["source_label"] == "无符号推断")
    );
}

#[test]
fn system_information_does_not_require_a_readable_active_process_list() {
    let mut bytes = fixture();
    // Destroy every fabricated ActiveProcessLinks, retaining System's PID/name.
    for object in [0x40000, 0x42000, 0x44000, 0x46000] {
        bytes[object + 0x90..object + 0xa0].fill(0);
    }
    with_session(&bytes, |session| {
        assert!(super::super::probe(session.image(), 4096, &CancellationToken::new()).is_err());
        let report = session.system_info(&CancellationToken::new()).unwrap();
        assert_eq!(field(&report, "nt_build_number")["value"], 22621);
        assert!(session.processes(&CancellationToken::new()).is_err());
    });
}

#[test]
fn missing_or_invalid_shared_page_preserves_kernel_evidence_without_fabricated_fields() {
    for invalid in 0..3 {
        let mut bytes = fixture();
        match invalid {
            0 => put64(&mut bytes, 0xf000, 0),
            1 => bytes[DATA + 0x268] = 0,
            _ => bytes[DATA + 0x30..DATA + 0x238].fill(0xff),
        }
        let report = run(&bytes);
        assert_eq!(report["shared_data_validated"], false);
        assert_eq!(field(&report, "nt_build_number")["value"], 22621);
        assert_eq!(field(&report, "nt_major_version")["value"], Value::Null);
        assert_eq!(
            field(&report, "system_time_utc")["evidence_status"],
            "unavailable"
        );
        assert_eq!(
            field(&report, "estimated_boot_time_utc")["value"],
            Value::Null
        );
        assert!(report["warnings"].as_array().unwrap().len() > 3);
    }
}

#[test]
fn contradictory_build_sources_are_kept_as_conflict() {
    let mut bytes = fixture();
    put32(&mut bytes, BUILD, 0xf000_0000 | 19045);
    let report = run(&bytes);
    let build = field(&report, "nt_build_number");
    assert_eq!(build["value"], Value::Null);
    assert_eq!(build["evidence_status"], "conflict");
    assert_eq!(build["raw_value"]["shared"], 22621);
    assert_eq!(build["raw_value"]["export"], 0xf000_0000_u32 | 19045);
}

#[test]
fn old_nt_reserved_build_field_is_not_interpreted_and_modern_export_is_optional() {
    let mut bytes = fixture();
    put32(&mut bytes, DATA + 0x26c, 6);
    put32(&mut bytes, DATA + 0x270, 1);
    put32(&mut bytes, BUILD, 0xf000_0000 | 7601);
    let report = run(&bytes);
    assert_eq!(field(&report, "nt_build_number")["value"], 7601);
    assert_eq!(
        field(&report, "nt_build_number")["raw_value"]["shared"],
        Value::Null
    );
    bytes[0x111c0] = b'X';
    assert_eq!(field(&run(&bytes), "nt_build_number")["value"], Value::Null);
    put32(&mut bytes, DATA + 0x26c, 10);
    assert_eq!(field(&run(&bytes), "nt_build_number")["value"], 22621);
}

#[test]
fn torn_clocks_and_invalid_bias_are_not_zero_filled_or_used_to_estimate_boot() {
    let mut bytes = fixture();
    put32(&mut bytes, DATA + 0x1c, 0);
    clock(&mut bytes, 0x20, 1);
    let report = run(&bytes);
    assert_eq!(field(&report, "system_time_utc")["value"], Value::Null);
    assert_eq!(
        field(&report, "estimated_boot_time_utc")["value"],
        Value::Null
    );
    assert_eq!(field(&report, "utc_offset_minutes")["value"], Value::Null);
    assert!(
        field(&report, "system_time_utc")["raw_value"]["ksystem_time_bytes"]
            .as_str()
            .unwrap()
            .len()
            == 24
    );
    assert_eq!(field(&report, "uptime_seconds")["value"], 3600.0);
}

#[test]
fn system_report_honors_cancellation_and_changed_image_identity() {
    with_session(&fixture(), |session| {
        let cancel = CancellationToken::new();
        cancel.request_cancel();
        assert!(session.system_info(&cancel).is_err());
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(session.image().path())
            .unwrap();
        use std::io::Write;
        (&file).write_all(b"changed").unwrap();
        assert!(session.system_info(&CancellationToken::new()).is_err());
    });
}
