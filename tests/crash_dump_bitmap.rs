use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use starmem::image::MemoryImage;

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "starmem-bitmap-{}-{}.dmp",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn bitmap_dump(signature: &[u8; 8], bitmap_bits: u64, pfns: &[u64]) -> Vec<u8> {
    let bitmap_end = 0x2038 + bitmap_bits.div_ceil(8) as usize;
    let payload = bitmap_end.next_multiple_of(0x1000);
    // Include non-page-aligned secondary data after the physical page payload.
    let mut bytes = vec![0u8; payload + pfns.len() * 0x1000 + 13];
    bytes[..8].copy_from_slice(b"PAGEDU64");
    // Bitmap dumps do not carry a traditional physical run table here.
    bytes[0x88..0x348].copy_from_slice(&b"PAGE".repeat((0x348 - 0x88) / 4));
    bytes[0xf98..0xf9c].copy_from_slice(&5u32.to_le_bytes());
    bytes[0x2000..0x2008].copy_from_slice(signature);
    put_u64(&mut bytes, 0x2020, payload as u64);
    put_u64(&mut bytes, 0x2028, pfns.len() as u64);
    put_u64(&mut bytes, 0x2030, bitmap_bits);
    for (index, &pfn) in pfns.iter().enumerate() {
        bytes[0x2038 + (pfn / 8) as usize] |= 1 << (pfn % 8);
        bytes[payload + index * 0x1000..payload + (index + 1) * 0x1000].fill((index + 1) as u8);
    }
    bytes
}

#[test]
fn bitmap_dump_maps_sparse_pages_and_preserves_source_offsets() {
    let bytes = bitmap_dump(b"FDMPDUMP", 19, &[1, 2, 7, 8, 18]);
    let fixture = Fixture::new(&bytes);
    let image = MemoryImage::open(&fixture.0).unwrap();
    let dump = image.dump64().unwrap();
    assert_eq!(dump.dump_type, 5);
    assert_eq!(dump.number_of_runs, 3);
    assert_eq!(dump.number_of_pages, 5);
    let spans = image.spans();
    assert_eq!(spans.len(), 3);
    assert_eq!(
        (spans[0].start, spans[0].file_offset, spans[0].length),
        (0x1000, 0x3000, 0x2000)
    );
    assert_eq!(
        (spans[1].start, spans[1].file_offset, spans[1].length),
        (0x7000, 0x5000, 0x2000)
    );
    assert_eq!(
        (spans[2].start, spans[2].file_offset, spans[2].length),
        (0x12000, 0x7000, 0x1000)
    );
    let mut output = [0u8; 32];
    image.read_physical(0x1ff0, &mut output).unwrap();
    assert_eq!(output[..16], [1; 16]);
    assert_eq!(output[16..], [2; 16]);
    assert_eq!(image.physical_to_file_offset(0x12023), Some(0x7023));
    assert_eq!(image.file_offset_to_physical(0x7023), Some(0x12023));
    assert_eq!(
        image.source_location(0x12023).unwrap().exact_byte_offset,
        Some(0x7023)
    );
    assert_eq!(image.file_offset_to_physical(0x2000), None);
    assert_eq!(image.file_offset_to_physical(0x8000), None);
    assert_eq!(image.physical_to_file_offset(0x3000), None);
    assert!(image.read_physical(0x3000, &mut output).is_err());
    assert!(image.read_physical(0x2ff0, &mut output).is_err());
}

#[test]
fn bitmap_dump_accepts_summary_signature_and_ignores_unused_bits() {
    let mut bytes = bitmap_dump(b"SDMPDUMP", 10, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    bytes[0x2039] |= 0xfc;
    let fixture = Fixture::new(&bytes);
    let image = MemoryImage::open(&fixture.0).unwrap();
    assert_eq!(image.spans().len(), 1);
    assert_eq!(image.spans()[0].length, 10 * 0x1000);
    assert!(!image.contains_physical(10 * 0x1000));
    assert_eq!(image.dump64().unwrap().number_of_pages, 10);
}

#[test]
fn bitmap_dump_maps_physical_addresses_above_four_gib() {
    let pfn = 0x100003;
    let fixture = Fixture::new(&bitmap_dump(b"FDMPDUMP", pfn + 1, &[pfn]));
    let image = MemoryImage::open(&fixture.0).unwrap();
    assert_eq!(image.spans()[0].start, 0x1_0000_3000);
    assert_eq!(image.read_u32_physical(0x1_0000_3000).unwrap(), 0x01010101);
}

#[test]
fn bitmap_dump_rejects_malformed_headers_and_truncated_payloads() {
    let original = bitmap_dump(b"FDMPDUMP", 17, &[1, 16]);
    let mut cases = Vec::new();
    let mut bytes = original.clone();
    bytes[0x2000] = b'X';
    cases.push(("signature", bytes));
    let mut bytes = original.clone();
    put_u64(&mut bytes, 0x2028, 1);
    cases.push(("page count", bytes));
    let mut bytes = original.clone();
    put_u64(&mut bytes, 0x2028, 0);
    cases.push(("empty bitmap", bytes));
    let mut bytes = original.clone();
    put_u64(&mut bytes, 0x2020, 0x2038);
    cases.push(("overlapping bitmap", bytes));
    let mut bytes = original.clone();
    put_u64(&mut bytes, 0x2020, u64::MAX);
    cases.push(("payload overflow", bytes));
    let mut bytes = original.clone();
    put_u64(&mut bytes, 0x2030, u64::MAX);
    cases.push(("bitmap overflow", bytes));
    let mut bytes = original.clone();
    bytes[0xf98..0xf9c].copy_from_slice(&6u32.to_le_bytes());
    cases.push(("unsupported dump type", bytes));
    for length in [0x1000, 0x2004, 0x2037, 0x203a, 0x4fff] {
        cases.push(("truncation", original[..length].to_vec()));
    }
    for (name, bytes) in cases {
        let fixture = Fixture::new(&bytes);
        assert!(MemoryImage::open(&fixture.0).is_err(), "accepted {name}");
    }
}
