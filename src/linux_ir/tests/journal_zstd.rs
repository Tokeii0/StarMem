use super::*;
use std::io::{Read, Write};

fn streamed(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
    encoder.include_contentsize(false).unwrap();
    encoder.include_checksum(true).unwrap();
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn journal_zstd_known_and_unknown_sizes_preserve_unicode_and_binary_values() {
    for text in [
        "MESSAGE=服务已启动\n第二行 😀".as_bytes(),
        b"MESSAGE=a\xffb",
    ] {
        let packed = zstd::bulk::compress(text, 0).unwrap();
        let streamed = streamed(text);
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(&packed).unwrap(),
            Some(text.len() as u64)
        );
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(&streamed).unwrap(),
            None
        );
        for packed in [packed, streamed] {
            assert_eq!(
                journal::decompress(&packed, 4, text.len(), &CancellationToken::new()).unwrap(),
                text
            );
            assert!(
                journal::decompress(&packed, 4, text.len() - 1, &CancellationToken::new()).is_err()
            );
        }
    }
}

#[test]
fn journal_zstd_rejects_truncation_checksum_errors_and_trailing_frames() {
    let packed = streamed(b"MESSAGE=verified bytes");
    let mut corrupt = packed.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    for invalid in [
        packed[..packed.len() - 1].to_vec(),
        corrupt,
        [packed.clone(), packed.clone()].concat(),
        [packed.clone(), vec![0]].concat(),
        vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0],
    ] {
        assert!(journal::decompress(&invalid, 4, 1024, &CancellationToken::new()).is_err());
    }
}

#[test]
fn journal_zstd_limits_output_and_history_window_independently() {
    let text = vec![b'A'; 8193];
    let packed = streamed(&text);
    assert_eq!(
        journal::decompress(&packed, 4, 8193, &CancellationToken::new()).unwrap(),
        text
    );
    assert!(journal::decompress(&packed, 4, 8192, &CancellationToken::new()).is_err());
    let mut window = streamed(b"MESSAGE=small field with a large declared window");
    assert_eq!(window[4] & 0x20, 0); // Window Descriptor follows a non-single-segment frame header.
    window[5] = (25 - 10) << 3; // Valid 32 MiB history, larger than the 16 MiB policy.
    assert_eq!(
        zstd::stream::decode_all(window.as_slice()).unwrap(),
        b"MESSAGE=small field with a large declared window"
    );
    assert!(journal::decompress(&window, 4, 1024, &CancellationToken::new()).is_err());
}

fn compressed_journal(compact: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = journal_fixture(compact);
    let offset = if compact { 360 } else { 368 };
    let header = if compact { 72 } else { 64 };
    let packed = zstd::bulk::compress(payload, 0).unwrap();
    bytes[12] |= 8;
    bytes[offset + 1] = 4;
    bytes[offset + 8..offset + 16].copy_from_slice(&((header + packed.len()) as u64).to_le_bytes());
    bytes[offset + header..offset + header + packed.len()].copy_from_slice(&packed);
    bytes
}

#[test]
fn journal_zstd_classic_and_compact_entries_keep_owner_clock_offsets_and_budget() {
    let payload = "MESSAGE=中文日志\n第二行 😀".as_bytes();
    let options = LinuxIrOptions {
        module: "journald".into(),
        ..Default::default()
    };
    let owner = json!({"path":"/var/log/journal/test/system.journal", "dentry":18446744072611574336u64,
        "inode":42, "superblock":43, "path_scope":"superblock_relative"});
    for compact in [false, true] {
        let bytes = compressed_journal(compact, payload);
        let resident = journal::Resident::new(&bytes, [(0, 1024)]).unwrap();
        let mut report = LinuxIrReport::new(&options, "test");
        let mut budget = 1024;
        journal::parse_journal(
            &resident,
            1024,
            &owner,
            &mut budget,
            &options,
            &CancellationToken::new(),
            &mut report,
        )
        .unwrap();
        let row = &report.records[0];
        assert!(report.complete);
        assert_eq!(row["dentry"], owner["dentry"]);
        assert_eq!(row["file_offset"], 288);
        assert_eq!(row["realtime_us"], 1_700_000_000_123_456u64);
        assert_eq!(row["fields"][0]["value_utf8"], "中文日志\n第二行 😀");
        assert_eq!(
            row["fields"][0]["data_offset"],
            if compact { 360 } else { 368 }
        );
        assert_eq!(row["fields"][0]["compression"], 4);
        assert_eq!(budget, 1024 - payload.len() as u64);
        assert!(row["validation"].as_str().unwrap().contains("未验证 FSS"));
    }
}

#[test]
fn journal_zstd_failures_preserve_entry_without_inventing_complete_fields() {
    let options = LinuxIrOptions {
        module: "journald".into(),
        ..Default::default()
    };
    for compact in [false, true] {
        for missing_flag in [false, true] {
            let mut bytes = compressed_journal(compact, b"MESSAGE=budgeted field");
            if missing_flag {
                bytes[12] &= !8;
            }
            let resident = journal::Resident::new(&bytes, [(0, 1024)]).unwrap();
            let mut report = LinuxIrReport::new(&options, "test");
            let mut budget = if missing_flag { 1024 } else { 3 };
            journal::parse_journal(
                &resident,
                1024,
                &json!({}),
                &mut budget,
                &options,
                &CancellationToken::new(),
                &mut report,
            )
            .unwrap();
            assert!(!report.complete);
            assert_eq!(report.records.len(), 1);
            assert_eq!(report.records[0]["complete"], false);
            assert_eq!(report.records[0]["fields"].as_array().unwrap().len(), 0);
            assert_eq!(
                report.records[0]["field_errors"][0]["data_offset"],
                if compact { 360 } else { 368 }
            );
        }
    }
}

#[test]
fn journal_decoding_cancellation_never_returns_a_partial_field() {
    let cancel = CancellationToken::new();
    struct CancelReader<'a>(&'a CancellationToken);
    impl Read for CancelReader<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.0.request_cancel();
            bytes[..4].copy_from_slice(b"test");
            Ok(4)
        }
    }
    let error = journal::read_decoded(&mut CancelReader(&cancel), 1024, &cancel).unwrap_err();
    assert!(crate::cancellation::is_cancellation_error(&error));
    for compression in [0, 1, 2, 4] {
        assert!(crate::cancellation::is_cancellation_error(
            &journal::decompress(b"", compression, 1024, &cancel).unwrap_err()
        ));
    }
}

#[test]
fn journal_paths_include_separate_run_and_log_superblocks() {
    for path in [
        "/var/log/journal/id/system.journal",
        "/run/log/journal/id/system.journal~",
        "/log/journal/02535ae338024638b68c2187a30936c0/system.journal",
        "/journal/id/user-1000.journal",
    ] {
        assert!(journal::journal_path(path));
    }
    for path in [
        "/systemd/journal/io.systemd.journal",
        "/tmp/example.journal",
        "/log/journalism/system.journal",
        "/var/log/journal/id/system.journal.gz",
        "/var/log/syslog",
    ] {
        assert!(!journal::journal_path(path));
    }
}
