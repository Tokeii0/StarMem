use super::*;

fn mapping(start: u64, end: u64, writable: bool, executable: bool) -> VirtualMapping {
    VirtualMapping {
        virtual_start: start,
        virtual_end: end,
        physical_start: 0x5000,
        length: end - start,
        source_page_size: PAGE_SIZE,
        writable,
        executable,
        user_accessible: true,
        global: false,
    }
}

#[test]
fn sparse_64_tib_range_counts_only_present_intersections() {
    let end = 64 << 40;
    let mappings = [
        mapping(0x1000, 0x2000, false, true),
        mapping(end - PAGE_SIZE, end, true, false),
    ];
    assert_eq!(
        mapped_page_counts(&mappings, 0, end, &CancellationToken::new()).unwrap(),
        (2, 1, 1)
    );
}

#[test]
fn gigabyte_large_page_does_not_expand_into_page_entries() {
    let mappings = [mapping(0, 1 << 30, true, false)];
    assert_eq!(
        mapped_page_counts(&mappings, 0, 1 << 30, &CancellationToken::new()).unwrap(),
        (262_144, 262_144, 0)
    );
}

#[test]
fn interval_counts_match_page_by_page_reference() {
    let token = CancellationToken::new();
    for seed in 0..16u64 {
        let mappings = (0..64u64)
            .filter(|page| (page + seed) % 3 != 0)
            .map(|page| {
                mapping(
                    page * PAGE_SIZE,
                    (page + 1) * PAGE_SIZE,
                    page % 2 == 0,
                    page % 5 == 0,
                )
            })
            .collect::<Vec<_>>();
        for first in 0..64u64 {
            for last in first + 1..=64 {
                let mut reference = (0, 0, 0);
                for page in first..last {
                    if let Some(found) = mappings
                        .iter()
                        .find(|m| m.virtual_start == page * PAGE_SIZE)
                    {
                        reference.0 += 1;
                        reference.1 += u64::from(found.writable);
                        reference.2 += u64::from(found.executable);
                    }
                }
                assert_eq!(
                    mapped_page_counts(&mappings, first * PAGE_SIZE, last * PAGE_SIZE, &token)
                        .unwrap(),
                    reference
                );
            }
        }
    }
}

#[test]
fn cancelled_page_statistics_returns_typed_cancellation() {
    let token = CancellationToken::new();
    token.request_cancel();
    let error = mapped_page_counts(&[], 0, 1 << 46, &token).unwrap_err();
    assert!(crate::cancellation::is_cancellation_error(&error));
}

fn with_space(bytes: Vec<u8>, check: impl FnOnce(&X64AddressSpace<'_>)) {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "starmem-injected-{}-{nonce}.raw",
        std::process::id()
    ));
    std::fs::write(&path, bytes).unwrap();
    let image = MemoryImage::open(&path).unwrap();
    let space = X64AddressSpace::new(&image, 0x1000).unwrap();
    check(&space);
    drop(image);
    std::fs::remove_file(path).unwrap();
}

fn set_entry(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn unreadable_sample_has_a_bound_even_for_huge_ranges() {
    let mut bytes = vec![0u8; 0x5000];
    set_entry(&mut bytes, 0x1000, 0x2003);
    set_entry(&mut bytes, 0x2000, 0x3003);
    set_entry(&mut bytes, 0x3000, 0x4003);
    // The PTE claims resident data outside the captured image.
    set_entry(&mut bytes, 0x4000, 0x100003);
    with_space(bytes, |space| {
        let mappings = [mapping(0, 64 << 40, false, false)];
        assert_eq!(
            triage_sample(space, &mappings, 0, 64 << 40, &CancellationToken::new()).unwrap(),
            (None, 0, None)
        );
    });
}

#[test]
fn printable_preview_never_joins_bytes_across_an_unmapped_page() {
    let mut bytes = vec![0u8; 0x7000];
    set_entry(&mut bytes, 0x1000, 0x2003);
    set_entry(&mut bytes, 0x2000, 0x3003);
    set_entry(&mut bytes, 0x3000, 0x4003);
    set_entry(&mut bytes, 0x4000, 0x5003);
    set_entry(&mut bytes, 0x4010, 0x6003);
    bytes[0x5ffc..0x6000].copy_from_slice(b"ABCD");
    bytes[0x6000..0x6004].copy_from_slice(b"EFGH");
    with_space(bytes, |space| {
        let mappings = [
            mapping(0, 0x1000, false, false),
            mapping(0x2000, 0x3000, false, false),
        ];
        let (_, sampled, preview) =
            triage_sample(space, &mappings, 0, 0x3000, &CancellationToken::new()).unwrap();
        assert_eq!(sampled, 8192);
        assert_eq!(preview, None);
    });
}

#[test]
fn mapping_walk_propagates_cancellation_before_reading_tables() {
    with_space(vec![0; 0x5000], |space| {
        let token = CancellationToken::new();
        token.request_cancel();
        let error = space
            .enumerate_mappings_cancellable(VirtualAddressRegion::User, 100, &token)
            .unwrap_err();
        assert!(crate::cancellation::is_cancellation_error(&error));
    });
}
