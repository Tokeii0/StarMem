use super::*;
use crate::linux_pagecache::LinuxRecoveredExtent;

fn extent(file_offset: u64, length: u64, physical_address: u64) -> LinuxRecoveredExtent {
    LinuxRecoveredExtent {
        file_offset,
        length,
        first_page_index: file_offset / 4096,
        last_page_index: (file_offset + length.saturating_sub(1)) / 4096,
        physical_address,
        physical_address_hex: format!("{physical_address:#x}"),
    }
}

#[test]
fn file_text_decodes_utf8_across_discontiguous_physical_pages() {
    let source = format!("{}中文😀\r\n", "a".repeat(4095));
    let bytes = source.as_bytes();
    let ranges = [
        extent(0, 4096, 0x1000),
        extent(4096, (bytes.len() - 4096) as u64, 0x9000),
    ];
    let runs = files::content_text_runs(bytes, &ranges, &CancellationToken::new())
        .unwrap()
        .unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["text_utf8"], source);
    assert_eq!(runs[0]["extent_start_index"], 0);
    assert_eq!(runs[0]["extent_count"], 2);
    assert_eq!(runs[0]["length"], bytes.len());
    assert!(runs[0].get("physical_address").is_none());
}

#[test]
fn file_text_never_bridges_missing_bytes_or_replaces_binary_content() {
    // The complete transport buffer spells 中文; byte 1 is explicitly absent.
    let bytes = "中文".as_bytes();
    assert!(
        files::content_text_runs(
            bytes,
            &[extent(0, 1, 0x1000), extent(2, 4, 0x9000)],
            &CancellationToken::new()
        )
        .unwrap()
        .is_none()
    );
    assert!(
        files::content_text_runs(
            b"first\0last",
            &[extent(0, 5, 0x1000), extent(5, 5, 0x9000)],
            &CancellationToken::new()
        )
        .unwrap()
        .is_none()
    );
    assert!(
        files::content_text_runs(
            b"a\xffb",
            &[extent(0, 2, 0x1000), extent(2, 1, 0x9000)],
            &CancellationToken::new()
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn file_text_preserves_good_fragments_in_other_invalid_runs() {
    let bytes = [0xe4, 0xb8, 0xad, 0, b'A', 0xff, b'B'];
    let ranges = [
        extent(0, 1, 0x1000),
        extent(1, 2, 0x9000),
        extent(4, 1, 0xa000),
        extent(5, 1, 0xb000),
        extent(6, 1, 0xc000),
    ];
    let runs = files::content_text_runs(&bytes, &ranges, &CancellationToken::new())
        .unwrap()
        .unwrap();
    assert_eq!(runs.len(), 4);
    assert_eq!(runs[0]["text_utf8"], "中");
    assert_eq!(runs[1]["text_utf8"], "A");
    assert!(runs[2]["text_utf8"].is_null());
    assert_eq!(runs[3]["text_utf8"], "B");
    assert_eq!(runs[3]["extent_start_index"], 4);
}

#[test]
fn file_text_rejects_inconsistent_ranges_and_propagates_cancellation() {
    for ranges in [
        vec![extent(0, 3, 0x1000), extent(2, 1, 0x9000)],
        vec![extent(1, 1, 0x1000), extent(0, 1, 0x9000)],
        vec![extent(0, 4, 0x1000)],
        vec![extent(0, 0, 0x1000)],
        vec![extent(0, 3, u64::MAX)],
    ] {
        assert!(files::content_text_runs(b"abc", &ranges, &CancellationToken::new()).is_err());
    }
    let cancel = CancellationToken::new();
    cancel.request_cancel();
    let error = files::content_text_runs(b"abc", &[], &cancel).unwrap_err();
    assert!(crate::cancellation::is_cancellation_error(&error));
}

#[test]
fn file_text_avoids_duplicate_optional_runs_without_new_decoded_text() {
    assert!(
        files::content_text_runs(
            b"hello\r\n",
            &[extent(0, 2, 0x1000), extent(2, 5, 0x9000)],
            &CancellationToken::new()
        )
        .unwrap()
        .is_none()
    );
    assert!(
        files::content_text_runs(&[], &[], &CancellationToken::new())
            .unwrap()
            .is_none()
    );
}
