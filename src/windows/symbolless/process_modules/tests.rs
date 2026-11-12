use super::*;
use crate::windows::symbolless::SymbollessSession;

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn name(b: &mut [u8], at: usize, buffer: usize, name: &str) {
    let bytes: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    put16(b, at, bytes.len() as u16);
    put16(b, at + 2, bytes.len() as u16);
    put64(b, at + 8, 0x400000 + buffer as u64);
    b[buffer..buffer + bytes.len()].copy_from_slice(&bytes);
}
fn fixture() -> Vec<u8> {
    let mut b = super::super::process_context::tests::fixture();
    put64(&mut b, 0x85018, 0x48b000);
    put32(&mut b, 0x8b000, 0x58);
    b[0x8b004] = 1;
    put64(&mut b, 0x8b020, 0x48c010);
    put64(&mut b, 0x8b028, 0x48d010);
    for (entry, next, prev, base, filename, buffer) in [
        (0x8c000, 0x48d010, 0x48b020, 0x480000, "alpha.exe", 0x8e000),
        (0x8d000, 0x48b020, 0x48c010, 0x490000, "测试.dll", 0x8f000),
    ] {
        put64(&mut b, entry + 0x10, next);
        put64(&mut b, entry + 0x18, prev);
        put64(&mut b, entry + 0x30, base);
        put32(&mut b, entry + 0x40, 0x1000);
        name(
            &mut b,
            entry + 0x48,
            buffer,
            &format!("C:\\案例\\{filename}"),
        );
        name(&mut b, entry + 0x58, buffer + 0x100, filename);
    }
    put16(&mut b, 0x80094, 0xf0);
    put32(&mut b, 0x800d0, 0x1000);
    b.copy_within(0x80000..0x81000, 0x90000);
    b
}
fn with_session(b: &[u8], f: impl FnOnce(&SymbollessSession)) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.raw");
    std::fs::write(&path, b).unwrap();
    let session = SymbollessSession::from_image(
        MemoryImage::open(&path).unwrap(),
        4096,
        &CancellationToken::new(),
    )
    .unwrap();
    f(&session);
}
fn options() -> ProcessModulesOptions {
    ProcessModulesOptions {
        pid: Some(8),
        limit: 32,
        module_limit: 1024,
    }
}
fn run(b: &[u8], options: &ProcessModulesOptions) -> Value {
    let mut result = Value::Null;
    with_session(b, |s| {
        result = s
            .process_modules(options, &CancellationToken::new())
            .unwrap();
    });
    result
}

#[test]
fn reads_owned_native_modules_without_process_parameters_or_symbols() {
    let mut b = fixture();
    put64(&mut b, 0x85020, 0); // DLL reading must not depend on command-line availability.
    let r = run(&b, &options());
    assert_eq!(r["records"].as_array().unwrap().len(), 2);
    assert_eq!(r["records"][0]["is_main_image"], true);
    assert_eq!(r["records"][1]["base_name"], "测试.dll");
    assert_eq!(r["records"][1]["entry_physical"], 0x8d000);
    assert_eq!(r["records"][1]["pe_status"], "verified");
    assert_eq!(r["process_sources"][0]["module_status"], "complete");
    assert_eq!(r["records"][0]["source_label"], "无符号推断");
    assert_eq!(r["external_debug_symbols_used"], false);
    assert_eq!(r["complete"], false);
}

#[test]
fn missing_names_and_pe_preserve_list_evidence_with_explicit_states() {
    let mut b = fixture();
    put64(&mut b, 0xc000 + 0x8f * 8, 0);
    put64(&mut b, 0xc000 + 0x90 * 8, 0);
    let r = run(&b, &options());
    assert_eq!(r["records"].as_array().unwrap().len(), 2);
    assert_eq!(r["records"][1]["full_name"], Value::Null);
    assert_eq!(r["records"][1]["pe_status"], "unavailable");
    assert_eq!(r["process_sources"][0]["list_traversal_complete"], true);
    assert_eq!(r["process_sources"][0]["module_status"], "partial");
}

#[test]
fn broken_backlink_and_non_head_cycle_do_not_publish_unvalidated_entries() {
    for (at, value, retained) in [(0x8d018, 0x48b020, 0), (0x8d010, 0x48d010, 1)] {
        let mut b = fixture();
        put64(&mut b, at, value);
        let r = run(&b, &options());
        assert_eq!(r["records"].as_array().unwrap().len(), retained);
        assert_eq!(r["process_sources"][0]["list_traversal_complete"], false);
        assert!(
            !r["process_sources"][0]["warnings"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn unreadable_second_entry_retains_preceding_valid_entry() {
    let mut b = fixture();
    // Its link is readable but the claimed image range is invalid.
    put64(&mut b, 0x8d030, u64::MAX);
    let r = run(&b, &options());
    assert_eq!(r["records"].as_array().unwrap().len(), 1);
    assert_eq!(r["process_sources"][0]["module_status"], "partial");
}

#[test]
fn limits_refusals_and_empty_lists_are_distinguished() {
    let mut opts = options();
    opts.module_limit = 1;
    let r = run(&fixture(), &opts);
    assert_eq!(r["records"].as_array().unwrap().len(), 1);
    assert_eq!(r["truncated"], true);
    assert_eq!(r["truncated_by"][0], "module_limit");
    opts.pid = None;
    opts.limit = 1;
    let r = run(&fixture(), &opts);
    assert_eq!(r["process_sources"].as_array().unwrap().len(), 1);
    assert_eq!(r["selected_processes"], 4);
    assert_eq!(r["truncated_by"][0], "process_limit");
    for case in 0..3 {
        let mut b = fixture();
        match case {
            0 => put64(&mut b, 0x85010, 0x490000),
            1 => put16(&mut b, 0x80098, 0x10b),
            _ => b[0x8b004] = 0,
        }
        let r = run(&b, &options());
        assert_eq!(r["available"], false);
        assert_eq!(r["process_sources"][0]["module_status"], "unavailable");
    }
    let mut b = fixture();
    put64(&mut b, 0x8b020, 0x48b020);
    put64(&mut b, 0x8b028, 0x48b020);
    let r = run(&b, &options());
    assert_eq!(r["available"], true);
    assert_eq!(r["process_sources"][0]["records_recovered"], 0);
    assert_eq!(r["process_sources"][0]["list_traversal_complete"], true);
}

#[test]
fn per_process_failures_pid_errors_cancellation_and_pe_mismatch_are_visible() {
    let mut b = fixture();
    put32(&mut b, 0x900d0, 0x2000);
    let mut opts = options();
    opts.pid = None;
    let r = run(&b, &opts);
    assert_eq!(r["process_sources"].as_array().unwrap().len(), 4);
    assert_eq!(r["records"][1]["pe_status"], "unverified");
    assert_eq!(r["process_sources"][0]["module_status"], "unavailable");
    with_session(&b, |s| {
        let cancel = CancellationToken::new();
        let mut opts = options();
        opts.pid = Some(999);
        assert!(s.process_modules(&opts, &cancel).is_err());
        opts = options();
        opts.limit = 0;
        assert!(s.process_modules(&opts, &cancel).is_err());
        cancel.request_cancel();
        assert!(s.process_modules(&options(), &cancel).is_err());
    });
}
