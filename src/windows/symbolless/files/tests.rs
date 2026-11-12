use super::*;

const BASE: u64 = 0xffff_f800_0000_0000;
const FILE: usize = 0x90240;
const CACHE: usize = 0x93000;

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn section_fixture(image: bool, legacy: bool) -> Vec<u8> {
    let mut bytes = fixture();
    let ca = 0xb0000;
    put64(
        &mut bytes,
        0x92000 + if image { 16 } else { 0 },
        BASE + ca as u64,
    );
    put64(&mut bytes, ca, BASE + 0xb1000);
    put32(&mut bytes, ca + 0x38, if image { 0xa0 } else { 0x80 });
    put64(&mut bytes, ca + 0x40, (BASE + FILE as u64) | 3);
    put64(&mut bytes, 0xb1000, BASE + ca as u64);
    put32(&mut bytes, 0xb1008, 3);
    put64(&mut bytes, 0xb1018, 0x3000);
    let (flags, start, full, count) = if legacy {
        (0x28, 0x2c, 0x30, 0x18)
    } else {
        (0x20, 0x24, 0x28, 0x2c)
    };
    for (sub, proto, next, sector, sectors, ptes, tail) in [
        (ca + 0x80, 0xb3000, 0xb2000, 0, 1, 1, 0),
        (
            0xb2000,
            0xb3008,
            0,
            1,
            if image { 10 } else { 1 },
            2,
            if image { 0 } else { 0x500 },
        ),
    ] {
        put64(&mut bytes, sub, BASE + ca as u64);
        put64(&mut bytes, sub + 8, BASE + proto);
        put64(
            &mut bytes,
            sub + 16,
            if next == 0 { 0 } else { BASE + next },
        );
        put32(&mut bytes, sub + flags, tail << 20);
        put32(&mut bytes, sub + start, sector);
        put32(&mut bytes, sub + full, sectors);
        put32(&mut bytes, sub + count, ptes);
    }
    put64(&mut bytes, 0xb3000, 0x98001);
    put64(&mut bytes, 0xb3008, 0x99800); // transition
    put64(&mut bytes, 0xb3010, 0x9a001);
    bytes
}

#[test]
fn sections_use_distinct_sector_units_and_validate_both_layouts() {
    for legacy in [false, true] {
        for image_section in [false, true] {
            with_image(
                &section_fixture(image_section, legacy),
                |image, kernel, report| {
                    let plan = sections::plan_section(
                        image,
                        kernel,
                        &report.records[0],
                        image_section,
                        1024 * 1024,
                        &CancellationToken::new(),
                    )
                    .unwrap();
                    assert!(plan.complete);
                    assert_eq!(plan.sector_bytes, if image_section { 512 } else { 4096 });
                    assert_eq!(
                        plan.logical_size,
                        if image_section { 0x1600 } else { 0x2500 }
                    );
                    assert_eq!(
                        plan.extents[1].file_offset,
                        if image_section { 512 } else { 4096 }
                    );
                    assert_eq!(plan.extents[1].physical_address, 0x99000);
                    assert_eq!(plan.extents[1].page_state, "transition");
                    assert_eq!(
                        plan.extents.last().unwrap().length,
                        if image_section { 1024 } else { 1280 }
                    );
                },
            );
        }
    }
}

#[test]
fn section_missing_pte_retains_holes_and_partial_manifest() {
    let mut bytes = section_fixture(false, false);
    put64(&mut bytes, 0xb3008, 0x99c00); // prototype + transition must not be treated as RAM
    with_session_bytes(&bytes, |session, directory| {
        let result = session
            .recover_file(
                &super::super::RecoveryOptions {
                    address: BASE + FILE as u64,
                    expected_physical: Some(FILE as u64),
                    source: "data".into(),
                    max_bytes: 1024 * 1024,
                    output: directory.join("data.bin"),
                },
                &CancellationToken::new(),
                || Ok(()),
            )
            .unwrap();
        assert_eq!(result["complete"], false);
        assert_eq!(result["missing_bytes"], 4096);
        assert!(result["output"].as_str().unwrap().ends_with(".partial"));
        let output = std::fs::read(result["output"].as_str().unwrap()).unwrap();
        assert_eq!(&output[4096..8192], &[0; 4096]);
        assert_eq!(&output[8192..], &bytes[0x9a000..0x9a500]);
        assert_eq!(result["source"], "data");
    });
}

#[test]
fn section_chain_rejects_cycles_wrong_owner_and_layout_ambiguity() {
    for failure in 0..4 {
        let mut bytes = section_fixture(false, false);
        match failure {
            0 => put64(&mut bytes, 0xb2010, BASE + 0xb0080),
            1 => put64(&mut bytes, 0xb2000, BASE + 0xb4000),
            2 => {
                bytes.copy_within(0xb0080..0xb00b8, 0xb00c0);
            }
            _ => put64(&mut bytes, 0xb0040, BASE + 0xb5000),
        }
        with_image(&bytes, |image, kernel, report| {
            assert!(
                sections::plan_section(
                    image,
                    kernel,
                    &report.records[0],
                    false,
                    1024 * 1024,
                    &CancellationToken::new()
                )
                .is_err()
            )
        });
    }
}

#[test]
fn section_rejects_overlap_size_limit_and_wrong_kind() {
    for failure in 0..3 {
        let mut bytes = section_fixture(true, false);
        if failure == 0 {
            put32(&mut bytes, 0xb2024, 0);
        }
        if failure == 2 {
            put32(&mut bytes, 0xb0038, 0x80);
        }
        with_image(&bytes, |image, kernel, report| {
            assert!(
                sections::plan_section(
                    image,
                    kernel,
                    &report.records[0],
                    true,
                    if failure == 1 { 4096 } else { 1024 * 1024 },
                    &CancellationToken::new()
                )
                .is_err()
            )
        });
    }
}

#[test]
fn reverse_mapping_obeys_cancel_before_returning_any_result() {
    with_image(&fixture(), |image, kernel, _| {
        let cancel = CancellationToken::new();
        cancel.request_cancel();
        let space = X64AddressSpace::new(image, kernel.kernel_dtb).unwrap();
        let result = space.reverse_translate_pages_cancellable(
            &HashSet::from([0x90000]),
            VirtualAddressRegion::Kernel,
            8,
            100000,
            100,
            &cancel,
        );
        assert!(crate::cancellation::is_cancellation_error(
            &result.unwrap_err()
        ));
    });
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub(in crate::windows::symbolless) fn fixture() -> Vec<u8> {
    let mut bytes = super::super::tests::fixture();
    bytes[0x11014..0x11018].copy_from_slice(&6u32.to_le_bytes());
    bytes[0x11018..0x1101c].copy_from_slice(&6u32.to_le_bytes());
    for (index, name, rva) in [
        (4usize, "ObGetObjectType", 0x2060u32),
        (5, "IoFileObjectType", 0x4010),
    ] {
        bytes[0x11040 + index * 4..0x11044 + index * 4].copy_from_slice(&rva.to_le_bytes());
        bytes[0x11060 + index * 4..0x11064 + index * 4]
            .copy_from_slice(&(0x1100u32 + index as u32 * 48).to_le_bytes());
        put16(&mut bytes, 0x11080 + index * 2, index as u16);
        bytes[0x11100 + index * 48..0x11100 + index * 48 + name.len()]
            .copy_from_slice(name.as_bytes());
    }
    let mut accessor = hex::decode(
        "488d41d00fb649e848c1e8080fb6c04833c10fb60d000000004833c1488d0d00000000488b04c1c3",
    )
    .unwrap();
    accessor[21..25].copy_from_slice(&(0xa7000i32 - 0x12060 - 25).to_le_bytes());
    accessor[31..35].copy_from_slice(&(0xa6000i32 - 0x12060 - 35).to_le_bytes());
    bytes[0x12060..0x12060 + accessor.len()].copy_from_slice(&accessor);
    put64(&mut bytes, 0x14010, BASE + 0xa5000);
    put64(&mut bytes, 0xa6000 + 7 * 8, BASE + 0xa5000);
    bytes[0xa7000] = 0x5a;
    bytes[FILE - 0x18] = 7 ^ (((BASE + FILE as u64 - 0x30) >> 8) as u8) ^ 0x5a;
    bytes[0x90202] = 0x20;
    bytes[0x90204..0x90208].copy_from_slice(b"File");
    put16(&mut bytes, FILE, 5);
    put16(&mut bytes, FILE + 2, 0xd8);
    put64(&mut bytes, FILE + 8, BASE + 0x91000);
    put64(&mut bytes, FILE + 0x18, BASE + 0x96000);
    put64(&mut bytes, FILE + 0x28, BASE + 0x92000);
    let name: Vec<u16> = "\\cases\\proof.txt".encode_utf16().collect();
    put16(&mut bytes, FILE + 0x58, name.len() as u16 * 2);
    put16(&mut bytes, FILE + 0x5a, name.len() as u16 * 2);
    put64(&mut bytes, FILE + 0x60, BASE + 0x94000);
    for (i, unit) in name.iter().enumerate() {
        put16(&mut bytes, 0x94000 + i * 2, *unit);
    }
    put16(&mut bytes, 0x91000, 3);
    put16(&mut bytes, 0x91002, 0x150);
    put64(&mut bytes, 0x92008, BASE + CACHE as u64);
    put64(&mut bytes, CACHE + 8, 0x2500);
    // Owner offset is deliberately fabricated; it is discovered by round trip.
    put64(&mut bytes, CACHE + 0xa0, (BASE + FILE as u64) | 3);
    put64(&mut bytes, CACHE + 0x38, BASE + 0x95000);
    put64(&mut bytes, CACHE + 0x58, BASE + CACHE as u64 + 0x38);
    put64(&mut bytes, 0x95000, BASE + 0x98000);
    put64(&mut bytes, 0x95008, BASE + CACHE as u64);
    put64(&mut bytes, 0x95010, 7); // Active count, not a file-offset displacement.
    put16(&mut bytes, 0x96002, 0x100);
    put64(&mut bytes, 0x96020, 0x2500);
    for (i, byte) in bytes[0x98000..0x9a500].iter_mut().enumerate() {
        *byte = (i % 251 + 1) as u8;
    }
    bytes
}

fn with_image<T>(
    bytes: &[u8],
    test: impl FnOnce(&MemoryImage, &ProbeReport, &FileScanReport) -> T,
) -> T {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("memory.raw");
    std::fs::write(&path, bytes).unwrap();
    let image = MemoryImage::open(&path).unwrap();
    let cancel = CancellationToken::new();
    let kernel = super::super::probe(&image, 64, &cancel).unwrap();
    let report = scan(&image, &kernel, 100, None, &cancel).unwrap();
    test(&image, &kernel, &report)
}

#[test]
fn recovers_named_file_and_validates_exact_content_without_symbols() {
    let bytes = fixture();
    with_image(&bytes, |image, kernel, report| {
        assert_eq!(report.records.len(), 1);
        assert!(report.records[0].object_manager_type_verified);
        assert!(
            report
                .object_type_evidence
                .as_ref()
                .unwrap()
                .cookie_address
                .is_some()
        );
        assert!(!report.complete && !report.external_debug_symbols_used);
        let plan = plan_cache(
            image,
            kernel,
            &report.records[0],
            1024 * 1024,
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(plan.complete);
        assert_eq!(plan.cache_file_object_offset, 0xa0);
        assert_eq!(plan.fcb_size_matches, Some(true));
        assert_eq!(plan.recovered_bytes, 0x2500);
        let mut output = tempfile::tempfile().unwrap();
        let hash = write_cache(image, &plan, &mut output, &CancellationToken::new()).unwrap();
        use std::io::Read;
        output.seek(SeekFrom::Start(0)).unwrap();
        let mut content = Vec::new();
        output.read_to_end(&mut content).unwrap();
        assert_eq!(content, bytes[0x98000..0x9a500]);
        assert_eq!(hash, hex::encode(Sha256::digest(&content)));
    });
}

#[test]
fn missing_middle_page_keeps_hole_and_does_not_claim_complete() {
    let mut bytes = fixture();
    put64(&mut bytes, 0xc000 + 0x99 * 8, 0);
    with_image(&bytes, |image, kernel, report| {
        let plan = plan_cache(
            image,
            kernel,
            &report.records[0],
            1024 * 1024,
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(!plan.complete);
        assert_eq!(plan.missing_bytes, 4096);
        assert_eq!(plan.missing_ranges.len(), 1);
        assert_eq!(plan.missing_ranges[0].file_offset, 4096);
        assert_eq!(plan.extents.len(), 2);
        let mut output = tempfile::tempfile().unwrap();
        write_cache(image, &plan, &mut output, &CancellationToken::new()).unwrap();
        use std::io::Read;
        output.seek(SeekFrom::Start(4096)).unwrap();
        let mut hole = [1; 4096];
        output.read_exact(&mut hole).unwrap();
        assert_eq!(hole, [0; 4096]);
        assert_eq!(output.metadata().unwrap().len(), plan.logical_size);
    });
}

#[test]
fn same_name_does_not_authorize_a_different_section_owner() {
    let mut bytes = fixture();
    bytes.copy_within(FILE..FILE + FILE_PREFIX, 0xa0000);
    put64(&mut bytes, 0xa0000 + 0x28, BASE + 0xa1000);
    put64(&mut bytes, CACHE + 0xa0, BASE + 0xa0000);
    with_image(&bytes, |image, kernel, report| {
        let error = plan_cache(
            image,
            kernel,
            &report.records[0],
            1024 * 1024,
            &CancellationToken::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("反向归属候选为 0"));
    });
}

#[test]
fn rejects_conflicting_views_of_the_same_file_offset() {
    let mut bytes = fixture();
    put64(&mut bytes, CACHE + 0x40, BASE + 0x97000);
    put64(&mut bytes, 0x97000, BASE + 0x9c000);
    put64(&mut bytes, 0x97008, BASE + CACHE as u64);
    with_image(&bytes, |image, kernel, report| {
        assert!(
            plan_cache(
                image,
                kernel,
                &report.records[0],
                1024 * 1024,
                &CancellationToken::new()
            )
            .unwrap_err()
            .to_string()
            .contains("歧义内容")
        );
    });
}

#[test]
fn disagreement_in_file_size_is_not_silently_truncated() {
    let mut bytes = fixture();
    put64(&mut bytes, 0x96020, 0x2400);
    with_image(&bytes, |image, kernel, report| {
        assert!(
            plan_cache(
                image,
                kernel,
                &report.records[0],
                1024 * 1024,
                &CancellationToken::new()
            )
            .unwrap_err()
            .to_string()
            .contains("大小不一致")
        );
    });
}

#[test]
fn export_size_limit_and_cancellation_are_preserved() {
    with_image(&fixture(), |image, kernel, report| {
        assert!(
            plan_cache(
                image,
                kernel,
                &report.records[0],
                4096,
                &CancellationToken::new()
            )
            .is_err()
        );
        let handle = crate::cancellation::CancellationHandle::new();
        handle.cancel();
        let error = plan_cache(
            image,
            kernel,
            &report.records[0],
            1024 * 1024,
            &handle.token(),
        )
        .unwrap_err();
        assert!(crate::cancellation::is_cancellation_error(&error));
        assert!(crate::cancellation::is_cancellation_error(
            &scan(image, kernel, 100, None, &handle.token()).unwrap_err()
        ));
    });
}

#[test]
fn zero_recovered_bytes_does_not_create_a_successful_plan() {
    let mut bytes = fixture();
    for page in [0x98, 0x99, 0x9a] {
        put64(&mut bytes, 0xc000 + page * 8, 0);
    }
    with_image(&bytes, |image, kernel, report| {
        assert!(
            plan_cache(
                image,
                kernel,
                &report.records[0],
                1024 * 1024,
                &CancellationToken::new()
            )
            .unwrap_err()
            .to_string()
            .contains("没有可读取")
        );
    });
}

#[test]
fn files_without_cache_remain_visible_and_filters_are_applied() {
    let mut bytes = fixture();
    put64(&mut bytes, 0x92008, 0);
    with_image(&bytes, |image, kernel, report| {
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].shared_cache_map, Some(0));
        let filtered = scan(
            image,
            kernel,
            1,
            Some("not-present"),
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(filtered.records.is_empty());
        assert!(!filtered.output_limit_reached);
    });
}

#[test]
fn reused_name_buffer_with_a_unicode_noncharacter_is_rejected() {
    let mut bytes = fixture();
    // Freed pool links often decode as valid UTF-16 ending in U+FFFF.
    // Preserve the trailing path so a simple path-separator heuristic cannot pass it.
    put16(&mut bytes, 0x94006, 0xffff);
    with_image(&bytes, |_image, _kernel, report| {
        assert!(report.records.is_empty());
    });
}

#[test]
fn valid_file_prefix_cannot_override_a_different_object_manager_type() {
    let mut bytes = fixture();
    bytes[FILE - 0x18] ^= 1;
    with_image(&bytes, |_image, _kernel, report| {
        assert!(report.records.is_empty());
        assert_eq!(report.rejected_virtual_candidates, 1);
    });
}

#[test]
fn supports_uncookied_target_accessor_without_version_lookup() {
    let mut bytes = fixture();
    let mut code = hex::decode("0fb641e8488d0d00000000488b04c1c3").unwrap();
    code[7..11].copy_from_slice(&(0xa6000i32 - 0x12060 - 11).to_le_bytes());
    bytes[0x12060..0x12060 + code.len()].copy_from_slice(&code);
    bytes[FILE - 0x18] = 7;
    with_image(&bytes, |_image, _kernel, report| {
        assert_eq!(report.records.len(), 1);
        assert!(report.records[0].object_manager_type_verified);
        assert!(
            report
                .object_type_evidence
                .as_ref()
                .unwrap()
                .cookie_address
                .is_none()
        );
    });
}

fn with_session(test: impl FnOnce(&super::super::SymbollessSession, &std::path::Path)) {
    with_session_bytes(&fixture(), test);
}

fn with_session_bytes(
    bytes: &[u8],
    test: impl FnOnce(&super::super::SymbollessSession, &std::path::Path),
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.raw");
    std::fs::write(&path, bytes).unwrap();
    let session = super::super::SymbollessSession::open_cancellable(
        &path,
        crate::image::ImageOpenOptions::default(),
        64,
        &CancellationToken::new(),
    )
    .unwrap();
    test(&session, dir.path());
}

fn recovery_options(root: &std::path::Path) -> super::super::RecoveryOptions {
    super::super::RecoveryOptions {
        address: BASE + FILE as u64,
        expected_physical: Some(FILE as u64),
        source: "cache".into(),
        max_bytes: 1024 * 1024,
        output: root.join("proof.bin"),
    }
}

#[test]
fn independent_session_reports_inference_and_recovers_with_source_manifest() {
    with_session(|session, root| {
        let cancel = CancellationToken::new();
        let processes = session.processes(&cancel).unwrap();
        assert_eq!(processes["analysis_mode"], "symbolless");
        assert_eq!(processes["source_label"], "无符号推断");
        assert_eq!(processes["complete"], false);
        assert!(processes["source_identity"]["symbol_identity"].is_null());
        let report = session
            .recover_file(&recovery_options(root), &cancel, || Ok(()))
            .unwrap();
        assert_eq!(
            std::fs::read(root.join("proof.bin")).unwrap(),
            fixture()[0x98000..0x9a500]
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("proof.bin.recovery.json")).unwrap())
                .unwrap();
        assert_eq!(manifest, report);
        assert_eq!(report["complete"], true);
    });
}

#[test]
fn direct_recovery_rejects_wrong_physical_identity_and_never_overwrites() {
    with_session(|session, root| {
        let mut options = recovery_options(root);
        options.expected_physical = Some(0xdead000);
        assert!(
            session
                .recover_file(&options, &CancellationToken::new(), || Ok(()))
                .is_err()
        );
        assert!(!options.output.exists());
        options.expected_physical = Some(FILE as u64);
        std::fs::write(&options.output, b"existing evidence").unwrap();
        assert!(
            session
                .recover_file(&options, &CancellationToken::new(), || Ok(()))
                .is_err()
        );
        assert_eq!(
            std::fs::read(&options.output).unwrap(),
            b"existing evidence"
        );
    });
}

#[test]
fn request_change_between_binary_and_manifest_rolls_back_only_own_output() {
    with_session(|session, root| {
        let calls = std::cell::Cell::new(0);
        let options = recovery_options(root);
        let result = session.recover_file(&options, &CancellationToken::new(), || {
            calls.set(calls.get() + 1);
            ensure!(calls.get() < 3, "镜像请求已切换");
            Ok(())
        });
        assert!(result.is_err());
        assert!(!options.output.exists());
        assert!(!root.join("proof.bin.recovery.json").exists());
    });
}

#[test]
fn competing_manifest_is_preserved_if_publication_fails() {
    with_session(|session, root| {
        let calls = std::cell::Cell::new(0);
        let options = recovery_options(root);
        let sidecar = root.join("proof.bin.recovery.json");
        let result = session.recover_file(&options, &CancellationToken::new(), || {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                std::fs::write(&sidecar, b"another request")?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(!options.output.exists());
        assert_eq!(std::fs::read(&sidecar).unwrap(), b"another request");
    });
}

#[test]
fn session_rejects_changed_source_and_cancelled_export() {
    with_session(|session, root| {
        let cancel = CancellationToken::new();
        cancel.request_cancel();
        assert!(
            session
                .recover_file(&recovery_options(root), &cancel, || Ok(()))
                .is_err()
        );
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(root.join("memory.raw"))
            .unwrap();
        file.write_all(b"changed").unwrap();
        assert!(session.processes(&CancellationToken::new()).is_err());
    });
}
