use super::*;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
const DATA_PAGE: usize = 0x5000;
const SUBSECTION: u64 = KERNEL_BASE + 0x100;
const CONTROL_AREA: u64 = KERNEL_BASE + 0x200;
const FILE_OBJECT: u64 = KERNEL_BASE + 0x300;

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn mapped_image(edit: impl FnOnce(&mut [u8]), check: impl FnOnce(&X64AddressSpace<'_>)) {
    struct TemporaryImage(PathBuf);
    impl Drop for TemporaryImage {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temporary = TemporaryImage(std::env::temp_dir().join(format!(
        "starmem-vad-pointer-{}-{nonce}.raw",
        std::process::id()
    )));
    let mut bytes = vec![0; 0x6000];
    put_u64(&mut bytes, 0x1000 + 256 * 8, 0x2003);
    put_u64(&mut bytes, 0x2000, 0x3003);
    put_u64(&mut bytes, 0x3000, 0x4003);
    put_u64(&mut bytes, 0x4000, 0x5003);
    put_u64(&mut bytes, DATA_PAGE + 0x20, SUBSECTION);
    put_u64(&mut bytes, DATA_PAGE + 0x100, CONTROL_AREA);
    put_u64(&mut bytes, DATA_PAGE + 0x240, FILE_OBJECT | 0xf);
    let name: Vec<u8> = "\\Device\\HarddiskVolume1\\sample.dll"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    bytes[DATA_PAGE + 0x358..DATA_PAGE + 0x35a].copy_from_slice(&(name.len() as u16).to_le_bytes());
    bytes[DATA_PAGE + 0x35a..DATA_PAGE + 0x35c].copy_from_slice(&(name.len() as u16).to_le_bytes());
    put_u64(&mut bytes, DATA_PAGE + 0x360, KERNEL_BASE + 0x400);
    bytes[DATA_PAGE + 0x400..DATA_PAGE + 0x400 + name.len()].copy_from_slice(&name);
    edit(&mut bytes);
    fs::write(&temporary.0, bytes).unwrap();
    let image = MemoryImage::open(&temporary.0).unwrap();
    let space = X64AddressSpace::new(&image, 0x1000).unwrap();
    check(&space);
}

#[test]
fn corrupt_control_area_does_not_panic() {
    mapped_image(
        |bytes| put_u64(bytes, DATA_PAGE + 0x100, !0xf),
        |space| {
            let error =
                vad_file_name(space, KERNEL_BASE, None, Some((0x20, 0, 0x40)), 0x58).unwrap_err();
            assert!(format!("{error:#}").contains("地址溢出"));
        },
    );
}

#[test]
fn valid_fast_reference_preserves_the_file_name() {
    mapped_image(
        |_| {},
        |space| {
            assert_eq!(
                vad_file_name(space, KERNEL_BASE, None, Some((0x20, 0, 0x40)), 0x58)
                    .unwrap()
                    .as_deref(),
                Some("\\Device\\HarddiskVolume1\\sample.dll")
            );
        },
    );
}

#[test]
fn eight_byte_aligned_subsection_and_control_area_are_not_rounded_down() {
    mapped_image(
        |bytes| {
            put_u64(bytes, DATA_PAGE + 0x20, SUBSECTION + 8);
            put_u64(bytes, DATA_PAGE + 0x108, CONTROL_AREA + 8);
            put_u64(bytes, DATA_PAGE + 0x248, FILE_OBJECT | 0xf);
        },
        |space| {
            assert!(
                vad_file_name(space, KERNEL_BASE, None, Some((0x20, 0, 0x40)), 0x58)
                    .unwrap()
                    .unwrap()
                    .ends_with("\\sample.dll")
            );
        },
    );
}

#[test]
fn corrupt_and_noncanonical_pointers_are_errors_not_absent_files() {
    for pointer in [1, 0x4000, 0xffff_0000_0000_0000, SUBSECTION | 1, u64::MAX] {
        mapped_image(
            |bytes| put_u64(bytes, DATA_PAGE + 0x20, pointer),
            |space| {
                assert!(
                    vad_file_name(space, KERNEL_BASE, None, Some((0x20, 0, 0x40)), 0x58).is_err()
                );
            },
        );
    }
}

#[test]
fn null_file_association_is_not_an_error() {
    mapped_image(
        |bytes| put_u64(bytes, DATA_PAGE + 0x20, 0),
        |space| {
            assert!(
                vad_file_name(space, KERNEL_BASE, None, Some((0x20, 0, 0x40)), 0x58)
                    .unwrap()
                    .is_none()
            );
        },
    );
}

#[test]
fn direct_file_reference_overflow_does_not_hide_a_valid_subsection() {
    mapped_image(
        |bytes| put_u64(bytes, DATA_PAGE + 0x28, u64::MAX),
        |space| {
            assert!(
                vad_file_name(space, KERNEL_BASE, Some(0x28), Some((0x20, 0, 0x40)), 0x58)
                    .unwrap()
                    .unwrap()
                    .ends_with("\\sample.dll")
            );
        },
    );
}

#[test]
fn corrupt_subsection_does_not_hide_a_valid_direct_file() {
    mapped_image(
        |bytes| {
            put_u64(bytes, DATA_PAGE + 0x20, u64::MAX);
            put_u64(bytes, DATA_PAGE + 0x28, FILE_OBJECT);
        },
        |space| {
            assert!(
                vad_file_name(space, KERNEL_BASE, Some(0x28), Some((0x20, 0, 0x40)), 0x58)
                    .unwrap()
                    .unwrap()
                    .ends_with("\\sample.dll")
            );
        },
    );
}

#[test]
fn every_vad_file_field_offset_is_checked() {
    mapped_image(
        |_| {},
        |space| {
            for (vad, direct, subsection, filename) in [
                (!7, Some(0x20), None, 0x58),
                (KERNEL_BASE, Some(u64::MAX), None, 0x58),
                (KERNEL_BASE, None, Some((u64::MAX, 0, 0x40)), 0x58),
                (KERNEL_BASE, None, Some((0x20, u64::MAX, 0x40)), 0x58),
                (KERNEL_BASE, None, Some((0x20, 0, u64::MAX)), 0x58),
                (KERNEL_BASE, None, Some((0x20, 0, 0x40)), u64::MAX),
            ] {
                assert!(vad_file_name(space, vad, direct, subsection, filename).is_err());
            }
        },
    );
}

#[test]
fn unreadable_file_name_remains_unknown() {
    mapped_image(
        |bytes| put_u64(bytes, DATA_PAGE + 0x360, KERNEL_BASE + 0x1000),
        |space| {
            assert!(vad_file_name(space, KERNEL_BASE, None, Some((0x20, 0, 0x40)), 0x58).is_err());
        },
    );
}

#[test]
fn unreadable_vpn_high_byte_is_not_replaced_with_zero() {
    mapped_image(
        |_| {},
        |space| {
            assert!(read_vpn(space, KERNEL_BASE, 0x80, Some(0x1000)).is_err());
            assert_eq!(read_vpn(space, KERNEL_BASE, 0x80, None).unwrap(), 0);
            assert_eq!(score_vad_tree(space, !7, 0, 8, 0x18, 0x1c, None, None), 0);
        },
    );
}
