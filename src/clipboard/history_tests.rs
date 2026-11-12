use super::*;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};

const BASE: u64 = 0x100_0000;
const CONTROL: u64 = 0x40000;
const MODEL: u64 = 0x41000;
const VECTOR: u64 = 0x42000;
const STORAGE: u64 = 0x43000;
const ARRAY: u64 = 0x44000;
const ITEM: u64 = 0x45000;
const HSTRING: u64 = 0x46fe4;

fn put(file: &mut File, address: u64, bytes: &[u8]) {
    file.seek(SeekFrom::Start(address)).unwrap();
    file.write_all(bytes).unwrap();
}
fn qword(file: &mut File, address: u64, value: u64) {
    put(file, address, &value.to_le_bytes());
}

fn fixture(change: impl FnOnce(&mut File)) -> (tempfile::TempDir, MemoryImage) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clipboard.raw");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.set_len(32 * 1024 * 1024).unwrap();
    qword(&mut file, 0x1000, 0x2007);
    qword(&mut file, 0x2000, 0x3007);
    qword(&mut file, 0x3000, 0x4007);
    for page in 0..512 {
        qword(&mut file, 0x4000 + page * 8, (page * 4096) | 7);
    }
    for large in 1..16 {
        qword(&mut file, 0x3000 + large * 8, (large * 0x20_0000) | 0x87);
    }
    let layout = &history_layout::LAYOUT;
    for (address, tables) in [
        (CONTROL, layout.control_vtables),
        (MODEL, layout.model_vtables),
        (VECTOR, layout.vector_vtables),
        (ITEM, layout.item_vtables),
    ] {
        for (index, rva) in tables.iter().enumerate() {
            qword(&mut file, address + index as u64 * 8, BASE + rva);
        }
    }
    qword(&mut file, CONTROL + layout.control_model as u64, MODEL);
    qword(&mut file, MODEL + layout.model_items as u64, VECTOR + 8);
    qword(&mut file, VECTOR + layout.vector_storage as u64, STORAGE);
    qword(&mut file, STORAGE, ARRAY);
    qword(&mut file, STORAGE + 8, ARRAY + 8);
    qword(&mut file, STORAGE + 16, ARRAY + 8);
    qword(&mut file, ARRAY, ITEM);
    qword(&mut file, ITEM + layout.item_text as u64, HSTRING);
    qword(
        &mut file,
        ITEM + layout.item_timestamp as u64,
        133801632001234567,
    );
    let text = "fixture@example.test".encode_utf16().collect::<Vec<_>>();
    put(&mut file, HSTRING + 4, &(text.len() as u32).to_le_bytes());
    qword(&mut file, HSTRING + 16, HSTRING + 28);
    put(&mut file, HSTRING + 24, &3u32.to_le_bytes());
    put(
        &mut file,
        HSTRING + 28,
        &text
            .into_iter()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    for check in layout.textinput_code {
        put(&mut file, BASE + check.rva, check.bytes);
    }
    change(&mut file);
    drop(file);
    let image = MemoryImage::open(&path).unwrap();
    (dir, image)
}

fn reader<'a>(image: &'a MemoryImage, token: &'a CancellationToken) -> Reader<'a> {
    Reader {
        image,
        space: X64AddressSpace::new(image, 0x1000).unwrap(),
        token,
    }
}
fn budget() -> Budget {
    Budget {
        scan_bytes: 0,
        text_bytes: 0,
        items: 0,
        item_attempts: 0,
        item_limit: 256,
        scan_limited: false,
        text_limited: false,
        items_limited: false,
        attempts_limited: false,
    }
}
fn process() -> ProcessRecord {
    ProcessRecord {
        eprocess: 0xffff800000000123,
        pid: 44,
        ppid: Some(4),
        name: "TextInputHost.".into(),
        details: Default::default(),
    }
}
fn item(reader: &Reader<'_>) -> ClipboardHistoryRecord {
    let chain = read_chain(reader, BASE, &history_layout::LAYOUT, CONTROL).unwrap();
    read_item(
        reader,
        &process(),
        BASE,
        &history_layout::LAYOUT,
        &chain,
        0,
        32770,
        &mut budget(),
    )
    .unwrap()
}

#[test]
fn history_recovers_only_linked_items_with_exact_sources_and_100ns_time() {
    let (_dir, image) = fixture(|_| {});
    let token = CancellationToken::new();
    let record = item(&reader(&image, &token));
    assert_eq!(record.text.as_deref(), Some("fixture@example.test"));
    assert_eq!(record.text_status, "verified");
    assert_eq!(
        record.timestamp_utc.as_deref(),
        Some("2025-01-01T00:00:00.1234567Z")
    );
    assert_eq!(record.chain.vector_interface_address, VECTOR + 8);
    assert_eq!(record.item_address, ITEM);
    assert_eq!(record.eprocess, 0xffff800000000123);
    let range = record
        .sources
        .iter()
        .find(|r| r.role == "HSTRING.utf16le_with_terminator")
        .unwrap();
    assert_eq!(range.physical_address, HSTRING + 28);
    assert_eq!(range.source_location.exact_byte_offset, Some(HSTRING + 28));
    assert_eq!(
        range.sha256,
        hex::encode(Sha256::digest(hex::decode(&range.bytes_hex).unwrap()))
    );
}

#[test]
fn history_rejects_wrong_class_even_when_text_offset_is_shared() {
    let (_dir, image) = fixture(|f| qword(f, ITEM + 8, BASE + 0x1234));
    let token = CancellationToken::new();
    let reader = reader(&image, &token);
    let chain = read_chain(&reader, BASE, &history_layout::LAYOUT, CONTROL).unwrap();
    assert!(
        read_item(
            &reader,
            &process(),
            BASE,
            &history_layout::LAYOUT,
            &chain,
            0,
            32770,
            &mut budget()
        )
        .is_err()
    );
}

#[test]
fn history_does_not_replace_missing_text_with_empty_or_zero_filled_text() {
    let (_dir, image) = fixture(|f| qword(f, 0x4000 + 0x47 * 8, 0));
    let token = CancellationToken::new();
    let record = item(&reader(&image, &token));
    assert!(record.text.is_none());
    assert_eq!(record.text_status, "unavailable");
    assert!(record.text_error.unwrap().contains("驻留页不完整"));
    assert!(record.sources.iter().any(|s| s.role == "HSTRING.header"));
    assert!(
        !record
            .sources
            .iter()
            .any(|s| s.role == "HSTRING.utf16le_with_terminator")
    );
}

#[test]
fn history_preserves_null_hstring_as_verified_empty() {
    let (_dir, image) = fixture(|f| qword(f, ITEM + 0x50, 0));
    let token = CancellationToken::new();
    let record = item(&reader(&image, &token));
    assert_eq!(record.text.as_deref(), Some(""));
    assert_eq!(record.text_status, "verified");
    assert_eq!(record.text_utf16_units, Some(0));
    assert_eq!(record.text_virtual_address, None);
}

#[test]
fn history_rejects_reference_strings_reused_headers_bad_utf16_and_missing_terminator() {
    for mutation in 0..5 {
        let (_dir, image) = fixture(|f| match mutation {
            0 => put(f, HSTRING, &1u32.to_le_bytes()),
            1 => put(f, HSTRING + 24, &0u32.to_le_bytes()),
            2 => qword(f, HSTRING + 16, HSTRING + 30),
            3 => put(f, HSTRING + 28, &0xd800u16.to_le_bytes()),
            _ => put(f, HSTRING + 28 + 40, &1u16.to_le_bytes()),
        });
        let token = CancellationToken::new();
        let record = item(&reader(&image, &token));
        assert!(record.text.is_none(), "mutation {mutation}");
        assert!(record.text_error.is_some());
    }
}

#[test]
fn history_vector_and_string_budgets_bound_corrupt_allocations() {
    for (begin, end, cap) in [
        (8, 0, 8),
        (0x10000, 0x10009, 0x10010),
        (0x10000, 0x10008, u64::MAX),
        (0, 8, 8),
    ] {
        assert!(vector_count(begin, end, cap).is_err());
    }
    assert_eq!(vector_count(0, 0, 0).unwrap(), 0);
    let (_dir, image) = fixture(|_| {});
    let token = CancellationToken::new();
    let reader = reader(&image, &token);
    let mut limits = budget();
    limits.text_bytes = MAX_TEXT_BYTES;
    assert!(read_hstring(&reader, HSTRING, 32770, &mut limits, &mut Vec::new()).is_err());
    assert!(limits.text_limited);
    assert!(read_hstring(&reader, HSTRING, 2, &mut budget(), &mut Vec::new()).is_err());
}

#[test]
fn history_uses_resident_intersections_and_obeys_scan_budget_and_cancellation() {
    let (_dir, image) = fixture(|_| {});
    let token = CancellationToken::new();
    let reader = reader(&image, &token);
    let mapping = VirtualMapping {
        virtual_start: CONTROL,
        virtual_end: CONTROL + 8191,
        physical_start: CONTROL,
        length: 8192,
        source_page_size: 4096,
        writable: true,
        user_accessible: true,
        executable: false,
        global: false,
    };
    let vad = VadRecord {
        pid: 44,
        process: "TextInputHost.".into(),
        node: 0,
        start: CONTROL,
        end: 0x20_0000_0000,
        protection: 4,
        protection_name: "PAGE_READWRITE".into(),
        vad_type: 0,
        private_memory: true,
        file: None,
    };
    let mut check = ClipboardHistoryCheck::new(Some(&process()));
    let mut limits = budget();
    assert_eq!(
        find_controls(
            &reader,
            std::slice::from_ref(&mapping),
            &[vad],
            BASE + history_layout::LAYOUT.control_vtables[0],
            &mut limits,
            &mut check
        )
        .unwrap(),
        [CONTROL]
    );
    assert_eq!(limits.scan_bytes, 8192); // Not the VAD's 128 GiB logical span.
    limits.scan_bytes = MAX_SCAN_BYTES;
    let vad = VadRecord {
        pid: 44,
        process: "".into(),
        node: 0,
        start: CONTROL,
        end: CONTROL + 8191,
        protection: 4,
        protection_name: "PAGE_READWRITE".into(),
        vad_type: 0,
        private_memory: true,
        file: None,
    };
    assert!(
        find_controls(&reader, &[mapping], &[vad], 1, &mut limits, &mut check)
            .unwrap()
            .is_empty()
    );
    assert!(limits.scan_limited);
    token.request_cancel();
    assert!(is_cancellation_error(
        &read_chain(&reader, BASE, &history_layout::LAYOUT, CONTROL).unwrap_err()
    ));
}

#[test]
fn history_layout_requires_both_exact_pdb_identities_and_code_bytes() {
    let record = |name: &str, key: &str| CodeViewRecord {
        pdb_name: name.into(),
        embedded_path: name.into(),
        guid: "unused".into(),
        age: 1,
        symbol_key: key.into(),
        physical_address: 1,
    };
    let mut textinput = record("TextInput.pdb", history_layout::LAYOUT.textinput_key);
    let mut combase = record("combase.pdb", history_layout::LAYOUT.combase_key);
    assert!(history_layout::select(&textinput, &combase).is_some());
    textinput.symbol_key.push('2');
    assert!(history_layout::select(&textinput, &combase).is_none());
    textinput.symbol_key.pop();
    combase.symbol_key.push('2');
    assert!(history_layout::select(&textinput, &combase).is_none());
    let (_dir, image) = fixture(|f| put(f, BASE + 0x14ff5, &[0x90]));
    let token = CancellationToken::new();
    let module = DllRecord {
        pid: 44,
        process: "".into(),
        entry: 0,
        base: BASE,
        size: 0xc6c000,
        name: "TextInput.dll".into(),
        path: "".into(),
    };
    assert!(
        validate_code(
            &reader(&image, &token),
            &module,
            history_layout::LAYOUT.textinput_code,
            &mut Vec::new()
        )
        .is_err()
    );
    assert!(history_time(u64::MAX).is_none());
    assert!(history_time(0).is_none());
}

#[test]
fn clipboard_streamed_pool_scan_preserves_chunk_boundary_hits_and_cancels() {
    use super::super::{PhysicalScanMode, SCAN_CHUNK_SIZE, scan_physical_candidates};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pool.raw");
    let mut file = File::create(&path).unwrap();
    file.set_len(SCAN_CHUNK_SIZE as u64 + 4096).unwrap();
    let addresses = [
        0x1004,
        SCAN_CHUNK_SIZE as u64 - 2,
        SCAN_CHUNK_SIZE as u64 + 4,
    ];
    for address in addresses {
        put(&mut file, address, b"Uscb");
    }
    drop(file);
    let image = MemoryImage::open(&path).unwrap();
    let token = CancellationToken::new();
    let mode = PhysicalScanMode {
        pool_tags: true,
        residual_text: false,
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    let report = pool
        .install(|| scan_physical_candidates(&image, &[], mode, &token))
        .unwrap();
    assert_eq!(report.pool_tags, addresses);
    assert_eq!(report.bytes_scanned, SCAN_CHUNK_SIZE as u64 + 4096);
    token.request_cancel();
    let error = scan_physical_candidates(&image, &[], mode, &token)
        .err()
        .unwrap();
    assert!(is_cancellation_error(&error));
}
