use super::*;
use crate::profile::{FieldProfile, TypeLayout};
use crate::windows::{KernelDiscoveryMethod, WindowsArchitecture};
use std::collections::BTreeMap;

const K: u64 = 0xffff_8000_0000_0000;
const TARGET: u64 = K + 0x180000;
const PTE: u64 = (0x1234u64 << 32) | 0x2010;

fn repeated_page(byte: u8) -> Vec<u8> {
    // Literal, distance-one match of 4095 bytes. Independently constructed
    // MS-XCA stream; contains no data from a user's memory image.
    vec![0, 0, 0, 0x40, byte, 7, 0, 15, 255, 0xfc, 0x0f]
}

#[test]
fn xpress_extended_length_and_overlapping_match() {
    assert_eq!(
        decompress_xpress(&repeated_page(b'A')).unwrap(),
        [b'A'; PAGE]
    );
    let mut stream = repeated_page(b'B');
    stream.splice(9..11, [0, 0, 0xfc, 0x0f, 0, 0]);
    assert_eq!(decompress_xpress(&stream).unwrap(), [b'B'; PAGE]);
}

#[test]
fn xpress_literals_and_optional_terminal_flags() {
    let mut stream = Vec::new();
    let page = std::array::from_fn::<_, PAGE, _>(|i| i as u8);
    for chunk in page.chunks(32) {
        stream.extend([0; 4]);
        stream.extend(chunk);
    }
    assert_eq!(decompress_xpress(&stream).unwrap(), page);
    stream.extend([0xff; 4]);
    assert_eq!(decompress_xpress(&stream).unwrap(), page);
}

#[test]
fn xpress_rejects_truncation_bad_distance_and_overflow() {
    let stream = repeated_page(0);
    for end in 0..stream.len() {
        assert!(decompress_xpress(&stream[..end]).is_err());
    }
    let mut bad = stream.clone();
    bad[5] = 15; // distance 2 with only 1 byte written
    assert!(decompress_xpress(&bad).is_err());
    let mut bad = stream.clone();
    bad[9] = 0xff;
    assert!(decompress_xpress(&bad).is_err());
    let mut bad = stream;
    bad.extend([0; 4]);
    assert!(decompress_xpress(&bad).is_err());
}

#[test]
fn software_pte_keys_require_virtual_pagefile_and_swizzle_mask() {
    assert_eq!(page_key(PTE, 19045, 2, 0x2000).unwrap(), 0x20001234);
    assert_eq!(
        page_key((0x3234u64 << 32) | 0x2000, 19045, 2, 0x2000).unwrap(),
        0x20001234
    );
    for pte in [
        PTE | 1,
        PTE | 0x400,
        PTE | 0x800,
        0,
        (0x1234u64 << 32) | 0x1010,
    ] {
        assert!(page_key(pte, 19045, 2, 0x2000).is_err());
    }
    assert!(StoreLayout::for_build(26100).is_err());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn leaf(bytes: &mut [u8], at: usize, key: u32, value: u32) {
    bytes[at] = 1;
    bytes[at + 2] = 1;
    bytes[at + 3] = 1;
    put32(bytes, at + 16, key);
    put32(bytes, at + 20, value);
}

fn fixture() -> (Vec<u8>, WindowsKernelContext, KernelProfile) {
    let mut bytes = vec![0; 0x200000];
    put64(&mut bytes, 0x1000 + 256 * 8, 0x2001);
    put64(&mut bytes, 0x2000, 0x3001);
    put64(&mut bytes, 0x3000, 0x4001);
    for index in 5..512 {
        put64(&mut bytes, 0x4000 + index * 8, (index as u64 * 4096) | 1);
    }
    put64(&mut bytes, 0x4000 + 0x180 * 8, PTE);
    put32(&mut bytes, 0x6000, 19045);
    put64(&mut bytes, 0x8010, 0x2000u64 << 32); // MiState.Hardware.InvalidPteMask
    put64(&mut bytes, 0x9000, K + 0xa100);
    put32(&mut bytes, 0xa100, 0x42);
    put64(&mut bytes, 0x7000, K + 0xb010);
    bytes[0xb004..0xb008].copy_from_slice(b"smSa");
    put64(&mut bytes, 0x71c0, K + 0xc000);
    put64(&mut bytes, 0xb010, K + 0x10000);
    leaf(&mut bytes, 0xc000, 0x20001234, 0);
    put64(&mut bytes, 0x10050, K + 0xd000);
    leaf(&mut bytes, 0xd000, 0x20001234, 0x40);
    put64(&mut bytes, 0x10110 + 16, K + 0xe000);
    put32(&mut bytes, 0x10218, 4);
    put32(&mut bytes, 0x1021c, 15);
    put32(&mut bytes, 0x10220, 12);
    put64(&mut bytes, 0xe000, K + 0xf000);
    put32(&mut bytes, 0xf000, 0x100);
    bytes[0xf004..0xf006].copy_from_slice(&11u16.to_le_bytes());
    put32(&mut bytes, 0x10378, 0xffff);
    put32(&mut bytes, 0x1037c, 16);
    bytes[0x10430] = 3;
    put64(&mut bytes, 0x11848, K + 0x20000);
    put64(&mut bytes, 0x119b8, K + 0x30000);
    put64(&mut bytes, 0x20000, 0x10000);
    bytes[0x30000..0x3000e].copy_from_slice(b"MemCompression");
    put64(&mut bytes, 0x30010, 888);
    put64(&mut bytes, 0x30018, 4);
    put64(&mut bytes, 0xa000, K + 0x30020);
    put64(&mut bytes, 0x30020, K + 0xa000);
    put64(&mut bytes, 0x30028, 0x40002); // full DTB includes low flags
    put64(&mut bytes, 0x40000, 0x41001);
    put64(&mut bytes, 0x41000, 0x42001);
    put64(&mut bytes, 0x42000, 0x43001);
    put64(&mut bytes, 0x43000 + 17 * 8, 0x51001);
    bytes[0x51000..0x5100b].copy_from_slice(&repeated_page(b'R'));
    let kernel = WindowsKernelContext {
        architecture: WindowsArchitecture::X86_64,
        directory_table_base: 0x1000,
        kernel_base: K + 0x5000,
        ps_active_process_head: K + 0xa000,
        ps_loaded_module_list: 0,
        discovery_method: KernelDiscoveryMethod::LowStub,
    };
    let mut types = BTreeMap::new();
    for (name, fields) in [
        ("_MI_SYSTEM_INFORMATION", vec![("Hardware", 0, None)]),
        ("_MI_HARDWARE_STATE", vec![("InvalidPteMask", 16, None)]),
        ("_MI_PARTITION", vec![("Vp", 0, None)]),
        ("_MI_VISIBLE_PARTITION", vec![("PagingFile", 0, None)]),
        (
            "_MMPAGING_FILE",
            vec![
                ("VirtualStorePagefile", 0, Some((6, 1))),
                ("PageFileNumber", 0, Some((0, 4))),
            ],
        ),
        (
            "_EPROCESS",
            vec![
                ("ImageFileName", 0, None),
                ("UniqueProcessId", 16, None),
                ("InheritedFromUniqueProcessId", 24, None),
                ("ActiveProcessLinks", 32, None),
                ("Pcb", 40, None),
            ],
        ),
        ("_KPROCESS", vec![("DirectoryTableBase", 0, None)]),
    ] {
        types.insert(
            name.to_owned(),
            TypeLayout {
                size: 128,
                fields: fields
                    .into_iter()
                    .map(|(f, offset, bits)| {
                        (
                            f.to_owned(),
                            FieldProfile {
                                offset,
                                size: None,
                                bit_position: bits.map(|b| b.0),
                                bit_length: bits.map(|b| b.1),
                            },
                        )
                    })
                    .collect(),
            },
        );
    }
    let profile = KernelProfile {
        schema_version: 3,
        pdb_guid: "fixture".into(),
        pdb_age: 1,
        type_name: "_EPROCESS".into(),
        type_size: 128,
        fields: BTreeMap::new(),
        types,
        symbols: [
            ("NtBuildNumber", 0x1000),
            ("MiState", 0x3000),
            ("MiSystemPartition", 0x4000),
            ("SmGlobals", 0x2000),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect(),
    };
    (bytes, kernel, profile)
}

fn with_image(bytes: &[u8], test: impl FnOnce(&MemoryImage)) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.raw");
    std::fs::write(&path, bytes).unwrap();
    let image = MemoryImage::open(&path).unwrap();
    test(&image);
}

#[test]
fn recovers_software_pte_from_owned_store_with_physical_provenance() {
    let (bytes, kernel, profile) = fixture();
    with_image(&bytes, |image| {
        let space = X64AddressSpace::new(image, 0x1000).unwrap();
        assert!(space.translate(TARGET).is_err());
        let mut store = CompressedStore::new(image, &kernel, &profile).unwrap();
        let (page, proof) = store.recover_page(&space, TARGET, 0x9000).unwrap();
        assert_eq!(page, [b'R'; PAGE]);
        assert_eq!(proof.hive_file_offset, 0x9000);
        assert_eq!(proof.source_spans[0].physical_address, 0x51000);
        assert_eq!(proof.compressed_size, 11);
        assert_eq!(proof.owner_pid, 888);
        assert_eq!(proof.target_virtual_address, TARGET);
    });
}

#[test]
fn rejects_wrong_owner_missing_payload_and_redirect_cycle() {
    for mutation in 0..3 {
        let (mut bytes, kernel, profile) = fixture();
        match mutation {
            0 => bytes[0x30000] = b'X',
            1 => put64(&mut bytes, 0x43000 + 17 * 8, 0),
            _ => {
                put32(&mut bytes, 0xf000, u32::MAX);
                put32(&mut bytes, 0xf004, 0x40);
            }
        }
        with_image(&bytes, |image| {
            let space = X64AddressSpace::new(image, 0x1000).unwrap();
            let mut store = CompressedStore::new(image, &kernel, &profile).unwrap();
            assert!(store.recover_page(&space, TARGET, 0).is_err());
        });
    }
}

#[test]
fn btree_rejects_unsorted_keys_and_cycles() {
    let (mut bytes, _, _) = fixture();
    bytes[0xc000] = 2;
    put32(&mut bytes, 0xc018, 1);
    with_image(&bytes, |image| {
        let space = X64AddressSpace::new(image, 0x1000).unwrap();
        assert!(search_tree(&space, K + 0xc000, 0x20001234).is_err());
    });
    bytes[0xc000] = 0;
    bytes[0xc002] = 2;
    bytes[0xc003] = 0;
    put64(&mut bytes, 0xc008, K + 0xc000);
    with_image(&bytes, |image| {
        let space = X64AddressSpace::new(image, 0x1000).unwrap();
        assert!(search_tree(&space, K + 0xc000, 0x20001234).is_err());
    });
}

#[test]
fn cacheali_discovery_and_multilevel_tree_use_one_based_heights() {
    let (mut bytes, kernel, mut profile) = fixture();
    profile.symbols.remove("SmGlobals");
    bytes[0x5000..0x5002].copy_from_slice(b"MZ");
    put32(&mut bytes, 0x503c, 0x80);
    put32(&mut bytes, 0x5080, 0x4550);
    bytes[0x5086] = 1;
    bytes[0x5094] = 0xf0;
    bytes[0x5098..0x509a].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[0x5188..0x5190].copy_from_slice(b"CACHEALI");
    put32(&mut bytes, 0x5190, 4096);
    put32(&mut bytes, 0x5194, 0x2000);
    bytes[0xc002] = 2;
    bytes[0xc003] = 0;
    put64(&mut bytes, 0xc008, K + 0x22000);
    put32(&mut bytes, 0xc010, 0x30000000);
    put64(&mut bytes, 0xc018, K + 0x23000);
    leaf(&mut bytes, 0x22000, 0x20001234, 0);
    leaf(&mut bytes, 0x23000, 0x30000000, 17);
    with_image(&bytes, |image| {
        let space = X64AddressSpace::new(image, 0x1000).unwrap();
        let mut store = CompressedStore::new(image, &kernel, &profile).unwrap();
        assert_eq!(
            store.recover_page(&space, TARGET, 0).unwrap().0,
            [b'R'; PAGE]
        );
        assert_eq!(search_tree(&space, K + 0xc000, 0x30000000).unwrap(), 17);
        assert!(search_tree(&space, K + 0xc000, 0x20001235).is_err());
    });
    // A second independently validated candidate must not be chosen by order.
    put64(&mut bytes, 0x7010, K + 0xb010);
    put64(&mut bytes, 0x71d0, K + 0xc000);
    with_image(&bytes, |image| {
        assert!(CompressedStore::new(image, &kernel, &profile).is_err());
    });
}

#[cfg(windows)]
#[test]
fn xpress_matches_windows_native_compressor_on_synthetic_pages() {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetCompressionWorkSpaceSize(
            format: u16,
            workspace: *mut u32,
            fragment: *mut u32,
        ) -> i32;
        fn RtlCompressBuffer(
            format: u16,
            input: *const u8,
            input_len: u32,
            output: *mut u8,
            output_len: u32,
            chunk_size: u32,
            written: *mut u32,
            workspace: *mut u8,
        ) -> i32;
    }
    let (mut size, mut fragment) = (0, 0);
    // Fixed buffers are kept alive across FFI, the native output size is
    // checked before slicing, and only artificial non-secret data is used.
    assert_eq!(
        unsafe { RtlGetCompressionWorkSpaceSize(3, &mut size, &mut fragment) },
        0
    );
    let mut workspace = vec![0u8; size as usize];
    for period in [1, 2, 3, 7, 15, 22, 31, 32, 128, 255, 1024, 4096] {
        let page = std::array::from_fn::<_, PAGE, _>(|i| ((i % period) * 47) as u8);
        let mut encoded = [0u8; 8192];
        let mut written = 0;
        assert_eq!(
            unsafe {
                RtlCompressBuffer(
                    3,
                    page.as_ptr(),
                    PAGE as u32,
                    encoded.as_mut_ptr(),
                    encoded.len() as u32,
                    PAGE as u32,
                    &mut written,
                    workspace.as_mut_ptr(),
                )
            },
            0
        );
        assert!(written as usize <= encoded.len());
        assert_eq!(
            decompress_xpress(&encoded[..written as usize]).unwrap(),
            page,
            "period={period}"
        );
    }
}
