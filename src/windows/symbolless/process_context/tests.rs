use super::*;
use crate::windows::symbolless::SymbollessSession;

const BASE: u64 = 0xffff_f800_0000_0000;
fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn utf16(b: &mut [u8], at: usize, value: &str) -> usize {
    let words: Vec<_> = value.encode_utf16().collect();
    for (i, &v) in words.iter().enumerate() {
        put16(b, at + i * 2, v);
    }
    words.len() * 2
}
fn descriptor(b: &mut [u8], at: usize, buffer: usize, value: &str) {
    let length = utf16(b, buffer, value);
    put16(b, at, length as u16);
    put16(b, at + 2, (length + 2) as u16);
    put64(b, at + 8, 0x400000 + buffer as u64);
}
pub(in crate::windows::symbolless) fn fixture() -> Vec<u8> {
    let mut b = super::super::tests::fixture();
    put32(&mut b, 0x11014, 5);
    put32(&mut b, 0x11018, 5);
    put32(&mut b, 0x11050, 0x2060);
    put32(&mut b, 0x11070, 0x11c0);
    put16(&mut b, 0x11088, 4);
    b[0x111c0..0x111cf].copy_from_slice(b"PsGetProcessPeb");
    b[0x12060..0x12068].copy_from_slice(&[0x48, 0x8b, 0x81, 0xb0, 0x01, 0, 0, 0xc3]);
    put64(&mut b, 0x42000 + 0x1b0, 0x485000);
    put64(&mut b, 0x85010, 0x480000);
    put64(&mut b, 0x85020, 0x486000);
    put16(&mut b, 0x80084, 0x8664);
    put32(&mut b, 0x86000, 0x500);
    put32(&mut b, 0x86004, 0x440);
    put32(&mut b, 0x86008, 1);
    descriptor(&mut b, 0x86060, 0x87000, "C:\\案例\\alpha.exe");
    descriptor(
        &mut b,
        0x86070,
        0x87800,
        "\"C:\\案例\\alpha.exe\" --test=你好",
    );
    put64(&mut b, 0x86080, 0x48a000);
    utf16(
        &mut b,
        0x8a000,
        "USERNAME=用户\0=C:=C:\\案例\0VALUE=a=b\0\0",
    );
    b
}
fn options() -> ProcessContextOptions {
    ProcessContextOptions {
        pid: Some(8),
        limit: 32,
        environment_bytes: 65536,
    }
}
fn with_session(b: &[u8], f: impl FnOnce(&SymbollessSession)) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.raw");
    std::fs::write(&path, b).unwrap();
    let session = SymbollessSession::from_image(
        MemoryImage::open(&path).unwrap(),
        4096,
        &CancellationToken::new(),
    )
    .unwrap();
    f(&session);
}
fn run(b: &[u8]) -> Value {
    let mut result = Value::Null;
    with_session(b, |s| {
        result = s
            .process_context(&options(), &CancellationToken::new())
            .unwrap()
    });
    result
}
#[test]
fn reads_owned_utf16_parameters_and_environment_without_external_layouts() {
    let report = run(&fixture());
    let row = &report["records"][0];
    assert_eq!(row["pid"], 8);
    assert_eq!(row["eprocess"], BASE + 0x42000);
    assert_eq!(row["parameters_status"], "complete");
    assert_eq!(row["environment_status"], "complete");
    assert_eq!(row["command_line"], "\"C:\\案例\\alpha.exe\" --test=你好");
    assert_eq!(row["peb_physical"], 0x85000);
    assert_eq!(report["environment"][0]["variable"], "USERNAME");
    assert_eq!(report["environment"][1]["variable"], "=C:");
    assert_eq!(report["environment"][2]["value"], "a=b");
    assert_eq!(report["environment"][0]["source_label"], "无符号推断");
    assert_eq!(report["external_debug_symbols_used"], false);
}
#[test]
fn refuses_foreign_image_peb_relative_parameters_and_wow64() {
    for case in 0..3 {
        let mut b = fixture();
        match case {
            0 => put64(&mut b, 0x85010, 0x490000),
            1 => put32(&mut b, 0x86008, 0),
            _ => put16(&mut b, 0x80098, 0x10b),
        };
        let report = run(&b);
        assert_eq!(report["records"][0]["parameters_status"], "unavailable");
        assert_eq!(report["records"][0]["command_line"], Value::Null);
        assert!(report["environment"].as_array().unwrap().is_empty());
    }
}
#[test]
fn bad_command_line_does_not_erase_image_path_or_environment() {
    let mut b = fixture();
    put16(&mut b, 0x86070, 3);
    let report = run(&b);
    assert_eq!(report["records"][0]["parameters_status"], "partial");
    assert_eq!(report["records"][0]["image_path"], "C:\\案例\\alpha.exe");
    assert_eq!(report["records"][0]["environment_status"], "complete");
}
#[test]
fn environment_missing_page_and_limit_retain_only_terminated_records() {
    let mut b = fixture();
    b[0x8a000..0x8b000].fill(0x41);
    utf16(&mut b, 0x8a000, "GOOD=value\0");
    put64(&mut b, 0xc000 + 0x8b * 8, 0);
    let report = run(&b);
    assert_eq!(report["environment"].as_array().unwrap().len(), 1);
    assert_eq!(report["records"][0]["environment_status"], "partial");
    with_session(&b, |s| {
        let mut opts = options();
        opts.environment_bytes = 4096;
        let r = s.process_context(&opts, &CancellationToken::new()).unwrap();
        assert_eq!(r["records"][0]["environment_status"], "partial");
    });
}
#[test]
fn double_nul_can_cross_a_page_and_empty_environment_is_distinct_from_unreadable() {
    let mut b = fixture();
    put64(&mut b, 0x86080, 0x48aff8);
    utf16(&mut b, 0x8aff8, "A=B\0\0");
    assert_eq!(run(&b)["records"][0]["environment_status"], "complete");
    put64(&mut b, 0x86080, 0x48b100);
    let empty = run(&b);
    assert_eq!(empty["records"][0]["environment_status"], "complete");
    assert!(empty["environment"].as_array().unwrap().is_empty());
    put64(&mut b, 0x86080, 0);
    assert_eq!(run(&b)["records"][0]["environment_status"], "unavailable");
}
#[test]
fn malformed_environment_bounds_warnings_without_losing_later_valid_entries() {
    let mut b = fixture();
    utf16(
        &mut b,
        0x8a000,
        &format!("{}GOOD=value\0\0", "bad\0".repeat(128)),
    );
    let report = run(&b);
    let row = &report["records"][0];
    assert_eq!(row["environment_status"], "partial");
    assert_eq!(
        row["warnings"].as_array().unwrap().len(),
        MAX_INVALID_ENV_WARNINGS + 1
    );
    assert!(
        row["warnings"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .as_str()
            .unwrap()
            .contains("112 条")
    );
    assert_eq!(report["environment"].as_array().unwrap().len(), 1);
    assert_eq!(report["environment"][0]["variable"], "GOOD");
}
#[test]
fn validates_pid_limits_and_honors_cancellation_and_record_budget() {
    with_session(&fixture(), |s| {
        let mut opts = options();
        opts.pid = Some(9999);
        assert!(s.process_context(&opts, &CancellationToken::new()).is_err());
        opts = options();
        opts.limit = 129;
        assert!(s.process_context(&opts, &CancellationToken::new()).is_err());
        let cancel = CancellationToken::new();
        cancel.request_cancel();
        assert!(s.process_context(&options(), &cancel).is_err());
        let k = super::super::probe(s.image(), 4096, &CancellationToken::new()).unwrap();
        let owner = k.processes.iter().find(|r| r.pid == 8).unwrap();
        let space = X64AddressSpace::new(s.image(), owner.directory_table_base.unwrap()).unwrap();
        let (rows, status, _, _) =
            environment(&space, owner, 0x48a000, 4096, 1, &CancellationToken::new()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(status, "partial");
    });
}
