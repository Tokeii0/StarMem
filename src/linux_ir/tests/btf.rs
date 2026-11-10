use super::*;

const BASE: u64 = 0xffff800000080000;

fn u32s(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}
fn ty(kind: u32, count: u32, flag: bool, name: u32, value: u32, extra: &[u32]) -> Vec<u8> {
    let mut bytes = u32s(&[name, (kind << 24) | count | (u32::from(flag) << 31), value]);
    bytes.extend(u32s(extra));
    bytes
}
fn blob(types: &[u8], strings: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x9f, 0xeb, 1, 0];
    bytes.extend(u32s(&[
        24,
        0,
        types.len() as u32,
        types.len() as u32,
        strings.len() as u32,
    ]));
    bytes.extend_from_slice(types);
    bytes.extend_from_slice(strings);
    bytes
}
fn memory(bytes: &[u8]) -> Memory {
    let mut m = Memory::new(
        json!({}),
        json!({"__start_BTF":{"address":BASE}, "__stop_BTF":{"address":BASE + bytes.len() as u64}}),
    );
    m.put(BASE, bytes);
    m
}
fn analyze(m: &impl LinuxKernelMemory, limit: usize, budget: u64) -> LinuxIrReport {
    run_kernel(
        m,
        &LinuxIrOptions {
            module: "btf".into(),
            limit,
            max_bytes: budget,
            ..Default::default()
        },
        &CancellationToken::new(),
    )
    .unwrap()
}

#[test]
fn native_btf_decodes_all_nineteen_kinds_and_preserves_id_references() {
    let mut types = Vec::new();
    for row in [
        ty(1, 0, false, 1, 4, &[1 << 24 | 32]),
        ty(2, 0, false, 0, 4, &[]),
        ty(3, 0, false, 0, 0, &[1, 1, 9]),
        ty(4, 1, true, 1, 8, &[1, 1, 3 << 24 | 33]),
        ty(5, 1, false, 1, 4, &[1, 1, 0]),
        ty(6, 1, false, 1, 4, &[1, u32::MAX]),
        ty(7, 0, true, 1, 0, &[]),
        ty(8, 0, false, 1, 1, &[]),
        ty(9, 0, false, 0, 1, &[]),
        ty(10, 0, false, 0, 1, &[]),
        ty(11, 0, false, 0, 1, &[]),
        ty(12, 1, false, 1, 13, &[]),
        ty(13, 2, false, 0, 1, &[1, 2, 0, 0]),
        ty(14, 0, false, 1, 3, &[2]),
        ty(15, 1, false, 1, 36, &[14, 0, 36]),
        ty(16, 0, false, 1, 8, &[]),
        ty(17, 0, true, 1, 4, &[u32::MAX]),
        ty(18, 0, true, 1, 2, &[]),
        ty(19, 1, false, 1, 8, &[1, u32::MAX, u32::MAX]),
    ] {
        types.extend(row);
    }
    let bytes = blob(&types, b"\0type_name\0");
    let result = analyze(&memory(&bytes), 100, 1024 * 1024);
    assert!(result.complete, "{:?}", result.warnings);
    assert_eq!(result.records.len(), 20);
    assert_eq!(result.records[0]["types_returned"], 19);
    assert_eq!(result.records[0]["checked_prefix_bytes"], bytes.len());
    for (index, row) in result.records.iter().enumerate().skip(1) {
        assert_eq!(row["type_id"], index);
        assert_eq!(row["reference_id_status"], "within_decoded_table");
        assert_eq!(
            row["btf_address"].as_u64().unwrap(),
            BASE + row["btf_offset"].as_u64().unwrap()
        );
    }
    assert_eq!(result.records[3]["element_count"], 9);
    assert_eq!(result.records[4]["members"][0]["bit_offset"], 33);
    assert_eq!(result.records[4]["members"][0]["bitfield_size"], 3);
    assert_eq!(
        result.records[5]["members"][0]["bitfield_size"],
        Value::Null
    );
    assert_eq!(result.records[6]["values"][0]["signed_value"], -1);
    assert_eq!(result.records[6]["values"][0]["unsigned_value"], u32::MAX);
    assert_eq!(
        result.records[6]["signedness"],
        "unsigned_or_legacy_unspecified"
    );
    assert_eq!(result.records[7]["forward_kind"], "union");
    assert_eq!(result.records[12]["linkage"], 1);
    assert_eq!(result.records[13]["parameters"][1]["variadic"], true);
    assert_eq!(result.records[15]["variables"][0]["target_type_id"], 14);
    assert_eq!(result.records[17]["component_index"], -1);
    assert_eq!(result.records[19]["values"][0]["value"], u64::MAX);
}

#[test]
fn signed_enum64_values_and_utf8_names_cross_virtual_pages() {
    // Header and ENUM64 record are each 24 bytes; the first character straddles a page.
    let offset = 4095 - 24 - 24;
    let types = ty(
        19,
        1,
        true,
        offset as u32,
        8,
        &[offset as u32, u32::MAX, u32::MAX],
    );
    let mut strings = vec![0; offset];
    strings.extend_from_slice("跨页😀\0".as_bytes());
    let result = analyze(&memory(&blob(&types, &strings)), 100, 1 << 20);
    assert!(result.complete, "{:?}", result.warnings);
    assert_eq!(result.records[1]["name"], "跨页😀");
    assert_eq!(result.records[1]["values"][0]["value"], -1);
}

#[test]
fn unknown_or_malformed_types_never_renumber_later_records() {
    let first = ty(1, 0, false, 1, 4, &[32]);
    for corrupt in [
        ty(20, 0, false, 1, 0, &[]),
        ty(4, 1000, false, 1, 4, &[]),
        ty(2, 1, false, 0, 1, &[]),
        ty(1, 0, true, 1, 4, &[32]),
    ] {
        let types = [first.clone(), corrupt, first.clone()].concat();
        let result = analyze(&memory(&blob(&types, b"\0int\0")), 100, 1 << 20);
        assert!(!result.complete);
        assert!(result.available, "{:?}", result.warnings);
        assert_eq!(result.records.len(), 2);
        assert_eq!(result.records[0]["type_headers_complete"], false);
        assert_eq!(result.records[0]["next_type_offset"], 40);
    }
}

#[test]
fn partial_tables_do_not_turn_forward_references_into_invalid_ids() {
    let types = [ty(2, 0, false, 0, 2, &[]), ty(1, 0, false, 1, 4, &[32])].concat();
    let m = memory(&blob(&types, b"\0int\0"));
    let limited = analyze(&m, 2, 1 << 20);
    assert!(limited.limit_reached);
    assert!(!limited.complete);
    assert_eq!(
        limited.records[1]["reference_id_status"],
        "outside_decoded_prefix"
    );
    let complete = analyze(&m, 3, 1 << 20);
    assert!(complete.complete);
    assert!(!complete.limit_reached);
    assert_eq!(
        complete.records[1]["reference_id_status"],
        "within_decoded_table"
    );
    let invalid = analyze(
        &memory(&blob(&ty(2, 0, false, 0, 2, &[]), b"\0")),
        100,
        1 << 20,
    );
    assert!(!invalid.complete);
    assert_eq!(invalid.records[1]["reference_id_status"], "invalid_type_id");
}

#[test]
fn unreadable_names_do_not_erase_readable_type_fields_or_invent_empty_names() {
    let types = [ty(1, 0, false, 1, 4, &[32]), ty(8, 0, false, 9000, 1, &[])].concat();
    let mut strings = vec![0; 10000];
    strings[1..5].copy_from_slice(b"int\0");
    strings[9000..9006].copy_from_slice(b"alias\0");
    let mut m = memory(&blob(&types, &strings));
    for address in BASE + 8192..BASE + 10000 {
        m.bytes.remove(&address);
    }
    let result = analyze(&m, 100, 1 << 20);
    assert!(!result.complete);
    assert!(result.available);
    assert_eq!(result.records.len(), 3);
    assert_eq!(result.records[1]["name"], "int");
    assert_eq!(result.records[2]["name"], Value::Null);
    assert!(result.records[2]["name_error"].is_string());
    assert_eq!(result.records[2]["target_type_id"], 1);
    assert_eq!(result.missing_ranges.len(), 1);
}

#[test]
fn missing_type_members_preserve_known_layout_and_next_type_identity() {
    let types = [
        ty(4, 500, false, 0, 2000, &vec![0; 1500]),
        ty(2, 0, false, 0, 1, &[]),
    ]
    .concat();
    // The missing page contains the following header too: no resynchronisation is attempted.
    // Keep the string table in another page so its first NUL can be independently checked.
    let mut padded = blob(&types, &vec![0; 9000]);
    let string_start = padded.len() - 1;
    padded[16..20].copy_from_slice(&((string_start - 24) as u32).to_le_bytes());
    padded[20..24].copy_from_slice(&1u32.to_le_bytes());
    let mut m = memory(&padded);
    for address in BASE + 4096..BASE + 8192 {
        m.bytes.remove(&address);
    }
    let result = analyze(&m, 100, 1 << 20);
    assert!(!result.complete);
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.records[1]["type_id"], 1);
    assert_eq!(result.records[1]["details_complete"], false);
    assert!(result.records[1]["details_returned"].as_u64().unwrap() > 0);
    assert_eq!(result.records[0]["type_headers_complete"], false);
}

#[test]
fn names_must_terminate_inside_the_declared_string_section() {
    for (name, strings) in [
        (10, b"\0int\0".as_slice()),
        (1, b"\0unterminated".as_slice()),
        (1, b"\0\xff\0".as_slice()),
    ] {
        let result = analyze(
            &memory(&blob(&ty(1, 0, false, name, 4, &[32]), strings)),
            100,
            1 << 20,
        );
        assert!(!result.complete);
        assert_eq!(result.records[1]["name"], Value::Null);
        assert!(result.records[1]["name_error"].is_string());
    }
}

#[test]
fn unsupported_extended_header_and_bad_string_sentinel_keep_probe_evidence() {
    let mut extended = blob(&ty(1, 0, false, 0, 4, &[32]), b"\0");
    extended.splice(24..24, [0u8; 8]);
    extended[4..8].copy_from_slice(&32u32.to_le_bytes());
    for bytes in [extended, blob(&ty(1, 0, false, 0, 4, &[32]), b"wrong\0")] {
        let result = analyze(&memory(&bytes), 100, 1 << 20);
        assert!(result.available);
        assert!(!result.complete);
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0]["type_headers_complete"], false);
        assert_eq!(result.records[0]["types_returned"], 0);
        assert!(result.records[0]["checked_bytes"].as_u64().unwrap() > 0);
    }
}

#[test]
fn per_type_output_limit_is_explicit_and_does_not_change_later_ids() {
    let mut members = Vec::new();
    for _ in 0..600 {
        members.extend([1, 2, 0]);
    }
    let types = [
        ty(4, 600, false, 0, 4, &members),
        ty(1, 0, false, 0, 4, &[32]),
    ]
    .concat();
    let mut strings = vec![b'x'; 4002];
    strings[0] = 0;
    strings[4001] = 0;
    let result = analyze(&memory(&blob(&types, &strings)), 100, 1 << 20);
    assert!(!result.complete);
    assert_eq!(result.records.len(), 3);
    assert_eq!(result.records[1]["details_count"], 600);
    assert!(result.records[1]["details_returned"].as_u64().unwrap() < 600);
    assert_eq!(result.records[1]["details_complete"], false);
    assert_eq!(result.records[2]["type_id"], 2);
}

#[test]
fn read_budget_is_honored_and_cancellation_remains_a_typed_error() {
    use std::cell::Cell;
    struct Counted {
        inner: Memory,
        bytes: Cell<u64>,
        cancel: crate::cancellation::CancellationHandle,
    }
    impl LinuxKernelMemory for Counted {
        fn read_virtual(&self, address: u64, bytes: &mut [u8]) -> Result<()> {
            self.bytes.set(self.bytes.get() + bytes.len() as u64);
            if self.bytes.get() > 4096 {
                self.cancel.cancel();
            }
            self.inner.read_virtual(address, bytes)
        }
        fn translate(&self, address: u64) -> Result<u64> {
            self.inner.translate(address)
        }
        fn isf(&self) -> &LinuxIsf {
            &self.inner.isf
        }
        fn kernel_slide(&self) -> u64 {
            0
        }
        fn source_path(&self) -> Option<&std::path::Path> {
            None
        }
    }
    let types = vec![ty(1, 0, false, 0, 4, &[32]); 1000].concat();
    let m = Counted {
        inner: memory(&blob(&types, b"\0")),
        bytes: Cell::new(0),
        cancel: Default::default(),
    };
    let result = analyze(&m, 10000, 4096);
    assert!(!result.complete);
    assert_eq!(m.bytes.get(), 4096);
    m.bytes.set(0);
    let options = LinuxIrOptions {
        module: "btf".into(),
        max_bytes: 1 << 20,
        ..Default::default()
    };
    let error = run_kernel(&m, &options, &m.cancel.start()).unwrap_err();
    assert!(crate::cancellation::is_cancellation_error(&error));
}
