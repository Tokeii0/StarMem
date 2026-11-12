use super::*;

const BASE: u64 = 0xffff_f800_0000_0000;
const KERNEL: u64 = BASE + 0x10000;
const PID: u64 = 0x88;
const NAME: u64 = 0x178;
const LINKS: u64 = PID + 8;
const DTB: u64 = 0x50;
const SECTION: u64 = 0x160;

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn leaf(offset: u64, address_result: bool) -> Vec<u8> {
    let mut bytes = vec![0x48, if address_result { 0x8d } else { 0x8b }, 0x81];
    bytes.extend_from_slice(&(offset as u32).to_le_bytes());
    bytes.push(0xc3);
    bytes
}

/// Deliberately fabricated offsets, not one of the PDB corpus's layouts.
/// Four independent PML4s, a complete PE export directory, four processes,
/// a kernel list sentinel and a user PE. No PDB/RSDS/profile file exists.
pub(super) fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; 1024 * 1024];
    for root in [0x1000, 0x8000, 0x9000, 0xa000] {
        put64(
            &mut bytes,
            root + ((BASE >> 39) & 0x1ff) as usize * 8,
            0x2003,
        );
        put64(&mut bytes, root, 0x5003);
    }
    put64(&mut bytes, 0x2000, 0x3003);
    put64(&mut bytes, 0x3000, 0xc003);
    put64(&mut bytes, 0x5000, 0x6003);
    put64(&mut bytes, 0x6010, 0xc003);
    for page in 1..256 {
        put64(&mut bytes, 0xc000 + page * 8, (page as u64 * 0x1000) | 3);
    }
    put64(&mut bytes, 0x7000, 0x0000_0001_0006_00e9);
    put64(&mut bytes, 0x7070, KERNEL + 0x8000);
    put64(&mut bytes, 0x70a0, 0x1000);

    bytes[0x10000..0x10002].copy_from_slice(b"MZ");
    put32(&mut bytes, 0x1003c, 0x80);
    bytes[0x10080..0x10084].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 0x10084, 0x8664);
    put16(&mut bytes, 0x10098, 0x20b);
    put32(&mut bytes, 0x10098 + 56, 0x10000);
    put32(&mut bytes, 0x10098 + 0x70, 0x1000);
    put32(&mut bytes, 0x10098 + 0x74, 0x300);
    for (offset, value) in [(20, 4), (24, 4), (28, 0x1040), (32, 0x1060), (36, 0x1080)] {
        put32(&mut bytes, 0x11000 + offset, value);
    }
    for (index, (name, rva)) in [
        ("PsInitialSystemProcess", 0x4000),
        ("PsGetProcessId", 0x2000),
        ("PsGetProcessImageFileName", 0x2020),
        ("PsGetProcessSectionBaseAddress", 0x2040),
    ]
    .into_iter()
    .enumerate()
    {
        put32(&mut bytes, 0x11040 + index * 4, rva);
        put32(
            &mut bytes,
            0x11060 + index * 4,
            (0x1100 + index * 48) as u32,
        );
        put16(&mut bytes, 0x11080 + index * 2, index as u16);
        bytes[0x11100 + index * 48..0x11100 + index * 48 + name.len()]
            .copy_from_slice(name.as_bytes());
    }
    for (address, offset, lea) in [
        (0x12000, PID, false),
        (0x12020, NAME, true),
        (0x12040, SECTION, false),
    ] {
        let code = leaf(offset, lea);
        bytes[address..address + code.len()].copy_from_slice(&code);
    }
    put64(&mut bytes, 0x14000, BASE + 0x40000);
    let head = KERNEL + 0x5000;
    let nodes: Vec<u64> = (0..4)
        .map(|i| BASE + 0x40000 + i * 0x2000 + LINKS)
        .collect();
    put64(&mut bytes, 0x15000, nodes[0]);
    put64(&mut bytes, 0x15008, nodes[3]);
    for (index, name) in ["System", "alpha.exe", "beta.exe", "gamma.exe"]
        .iter()
        .enumerate()
    {
        let object = 0x40000 + index * 0x2000;
        put64(&mut bytes, object + PID as usize, 4 + index as u64 * 4);
        bytes[object + NAME as usize..object + NAME as usize + name.len()]
            .copy_from_slice(name.as_bytes());
        put64(
            &mut bytes,
            object + DTB as usize,
            [0x1000, 0x8000, 0x9000, 0xa000][index],
        );
        put64(
            &mut bytes,
            object + SECTION as usize,
            if index == 0 { 0 } else { 0x480000 },
        );
        put64(
            &mut bytes,
            object + LINKS as usize,
            if index == 3 { head } else { nodes[index + 1] },
        );
        put64(
            &mut bytes,
            object + LINKS as usize + 8,
            if index == 0 { head } else { nodes[index - 1] },
        );
    }
    bytes[0x80000..0x80002].copy_from_slice(b"MZ");
    put32(&mut bytes, 0x8003c, 0x80);
    bytes[0x80080..0x80084].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 0x80098, 0x20b);
    bytes
}

fn run(bytes: &[u8], limit: usize) -> Result<ProbeReport> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("memory.raw");
    std::fs::write(&path, bytes)?;
    probe(&MemoryImage::open(path)?, limit, &CancellationToken::new())
}

#[test]
fn leaf_decoder_rejects_wrong_semantics_and_partial_matches() {
    assert_eq!(decode_accessor(&leaf(0x1b8, false), false), Some(0x1b8));
    assert_eq!(
        decode_accessor(&[0x48, 0x8b, 0x41, 0x50, 0xc3], false),
        Some(0x50)
    );
    assert_eq!(decode_accessor(&leaf(0x178, true), true), Some(0x178));
    assert_eq!(decode_accessor(&leaf(0x178, true), false), None);
    assert_eq!(
        decode_accessor(&[0x48, 0x8b, 0x41, 0xff, 0xc3], false),
        None
    );
    assert_eq!(
        decode_accessor(&[0x90, 0x48, 0x8b, 0x41, 0x50, 0xc3], false),
        None
    );
    let mut unterminated = leaf(0x1b8, false);
    unterminated[7] = 0x90;
    assert_eq!(decode_accessor(&unterminated, false), None);
}

#[test]
fn discovers_unseen_offsets_without_symbol_files() {
    let report = run(&fixture(), 64).unwrap();
    assert_eq!(report.processes.len(), 4);
    assert!(report.list_traversal_complete);
    assert!(
        !report.complete && !report.external_debug_symbols_used && !report.external_layouts_used
    );
    assert_eq!(
        report.fields.iter().map(|f| f.offset).collect::<Vec<_>>(),
        vec![PID, NAME, LINKS, DTB, SECTION]
    );
    assert!(
        report
            .processes
            .iter()
            .all(|row| row.kernel_mapping_verified)
    );
    assert!(
        report.processes[1..]
            .iter()
            .all(|row| row.user_image_pe_verified == Some(true))
    );
}

#[test]
fn refuses_ambiguous_dtb_fields() {
    let mut bytes = fixture();
    for (index, dtb) in [0x1000, 0x8000, 0x9000, 0xa000].into_iter().enumerate() {
        put64(&mut bytes, 0x40000 + index * 0x2000 + 0x60, dtb);
    }
    assert!(
        run(&bytes, 64)
            .unwrap_err()
            .to_string()
            .contains("DTB 字段候选数量为 2")
    );
}

#[test]
fn low_stub_hint_can_be_below_kernel() {
    let mut bytes = fixture();
    put64(&mut bytes, 0x7070, KERNEL - 0x8000);
    assert_eq!(run(&bytes, 64).unwrap().kernel_base, KERNEL);
}

#[test]
fn broken_reciprocal_link_is_not_a_complete_list() {
    let mut bytes = fixture();
    put64(&mut bytes, 0x46000 + LINKS as usize, 0);
    let report = run(&bytes, 64).unwrap();
    assert_eq!(report.processes.len(), 3);
    assert!(!report.list_traversal_complete);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("链表邻接指针无效"))
    );
}

#[test]
fn bounded_walk_keeps_partial_status() {
    let report = run(&fixture(), 3).unwrap();
    assert_eq!(report.processes.len(), 3);
    assert!(!report.list_traversal_complete && !report.complete);
    assert!(report.warnings.iter().any(|w| w.contains("上限")));
}

#[test]
fn unreadable_user_mapping_is_not_reported_as_verified() {
    let mut bytes = fixture();
    put64(&mut bytes, 0x9000, 0);
    let report = run(&bytes, 64).unwrap();
    let row = &report.processes[2];
    assert!(row.kernel_mapping_verified);
    assert_eq!(row.user_image_pe_verified, Some(false));
    assert!(!row.warnings.is_empty());
}

#[test]
fn cancelled_probe_does_not_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.raw");
    std::fs::write(&path, fixture()).unwrap();
    let handle = crate::cancellation::CancellationHandle::new();
    handle.cancel();
    let error = probe(&MemoryImage::open(path).unwrap(), 64, &handle.token()).unwrap_err();
    assert!(crate::cancellation::is_cancellation_error(&error));
}

fn add_other_process_list(bytes: &mut [u8]) {
    let offset = 0x1c0;
    let head = KERNEL + 0x5100;
    let nodes: Vec<u64> = (0..4)
        .map(|i| BASE + 0x40000 + i * 0x2000 + offset)
        .collect();
    put64(bytes, 0x15100, nodes[0]);
    put64(bytes, 0x15108, nodes[3]);
    for index in 0..4 {
        let link = 0x40000 + index * 0x2000 + offset as usize;
        put64(
            bytes,
            link,
            if index == 3 { head } else { nodes[index + 1] },
        );
        put64(
            bytes,
            link + 8,
            if index == 0 { head } else { nodes[index - 1] },
        );
    }
}

#[test]
fn distinguishes_other_valid_process_lists_with_explicit_prior() {
    let mut bytes = fixture();
    add_other_process_list(&mut bytes);
    let report = run(&bytes, 64).unwrap();
    assert_eq!(report.active_process_head, Some(KERNEL + 0x5000));
    assert_eq!(report.alternative_list_offsets, vec![0x1c0]);
    assert_eq!(report.layout_priors.len(), 1);
}

#[test]
fn never_substitutes_another_list_for_a_broken_active_list() {
    let mut bytes = fixture();
    add_other_process_list(&mut bytes);
    put64(&mut bytes, 0x40000 + LINKS as usize, 0);
    assert!(
        run(&bytes, 64)
            .unwrap_err()
            .to_string()
            .contains("不能替代活动列表")
    );
}
