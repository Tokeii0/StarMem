//! Strict x86-64 little-endian ELF physical core parser.

use anyhow::{Context, Result, ensure};

const ELF_HEADER_SIZE: usize = 64;
const ELF_PROGRAM_HEADER64_SIZE: usize = 56;
const ET_CORE: u16 = 4;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PN_XNUM: u16 = 0xffff;
const MAX_PROGRAM_HEADERS: usize = 65_534;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ElfProducerHint {
    Qemu,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ElfPhysicalMap {
    pub machine: u16,
    pub program_header_count: u16,
    pub producer: ElfProducerHint,
    pub regions: Vec<ElfRegion>,
    pub missing_ranges: Vec<ElfMissingRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ElfRegion {
    pub physical_start: u64,
    pub file_offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ElfMissingRange {
    pub start: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    file_offset: u64,
    physical_start: u64,
    file_size: u64,
    memory_size: u64,
}

pub(super) fn parse_elf_physical_core(bytes: &[u8], file_length: u64) -> Result<ElfPhysicalMap> {
    ensure!(bytes.len() >= ELF_HEADER_SIZE, "ELF64 header 被截断");
    ensure!(&bytes[..4] == b"\x7fELF", "ELF magic 无效");
    ensure!(bytes[4] == 2, "仅支持 ELFCLASS64 physical core");
    ensure!(bytes[5] == 1, "仅支持 little-endian ELF physical core");
    ensure!(bytes[6] == 1, "ELF ident version 无效");
    ensure!(read_u16(bytes, 16)? == ET_CORE, "ELF 文件不是 ET_CORE");
    let machine = read_u16(bytes, 18)?;
    ensure!(machine == EM_X86_64, "仅支持 x86-64 ELF physical core");
    ensure!(read_u32(bytes, 20)? == 1, "ELF header version 无效");
    let program_offset = read_u64(bytes, 32)?;
    // ELF64 头布局固定；VirtualBox dumpvmcore 等写入器会把 e_ehsize 写错（如 8），
    // 后续解析不依赖该字段，因此不据此拒绝镜像。
    let program_entry_size = read_u16(bytes, 54)?;
    let program_count = read_u16(bytes, 56)?;
    ensure!(
        usize::from(program_entry_size) >= ELF_PROGRAM_HEADER64_SIZE,
        "ELF64 program header size 无效"
    );
    ensure!(
        program_count != PN_XNUM,
        "暂不支持 ELF PN_XNUM 扩展 program header count"
    );
    ensure!(program_count > 0, "ELF core 不包含 program headers");
    ensure!(
        usize::from(program_count) <= MAX_PROGRAM_HEADERS,
        "ELF program header 数量超出安全上限"
    );
    let table_length = u64::from(program_entry_size)
        .checked_mul(u64::from(program_count))
        .context("ELF program header table 长度溢出")?;
    ensure!(
        program_offset
            .checked_add(table_length)
            .is_some_and(|end| end <= file_length),
        "ELF program header table 超出文件末尾"
    );

    let mut headers = Vec::with_capacity(usize::from(program_count));
    for index in 0..usize::from(program_count) {
        let offset = program_offset
            .checked_add((index as u64) * u64::from(program_entry_size))
            .context("ELF program header offset 溢出")?;
        let offset = usize::try_from(offset).context("ELF program header offset 过大")?;
        let header = bytes
            .get(offset..offset + ELF_PROGRAM_HEADER64_SIZE)
            .context("ELF program header 被截断")?;
        let kind = read_u32(header, 0)?;
        let file_offset = read_u64(header, 8)?;
        let physical_start = read_u64(header, 24)?;
        let file_size = read_u64(header, 32)?;
        let memory_size = read_u64(header, 40)?;
        ensure!(
            file_size <= memory_size,
            "ELF segment file size 超出 memory size"
        );
        if matches!(kind, PT_LOAD | PT_NOTE) {
            ensure!(
                file_offset
                    .checked_add(file_size)
                    .is_some_and(|end| end <= file_length),
                "ELF segment {index} 超出文件末尾"
            );
        }
        headers.push(ProgramHeader {
            kind,
            file_offset,
            physical_start,
            file_size,
            memory_size,
        });
    }

    let mut has_qemu_note = false;
    for header in headers.iter().filter(|header| header.kind == PT_NOTE) {
        if note_has_owner(bytes, header.file_offset, header.file_size, b"QEMU")? {
            has_qemu_note = true;
            break;
        }
    }
    let producer = if has_qemu_note {
        ElfProducerHint::Qemu
    } else {
        ElfProducerHint::Generic
    };

    let mut load_extents = Vec::new();
    for header in headers.iter().filter(|header| header.kind == PT_LOAD) {
        if header.memory_size == 0 {
            continue;
        }
        let end = header
            .physical_start
            .checked_add(header.memory_size)
            .context("ELF PT_LOAD memory range 溢出")?;
        load_extents.push((header.physical_start, end));
    }
    load_extents.sort_unstable_by_key(|(start, _)| *start);
    for pair in load_extents.windows(2) {
        ensure!(
            pair[0].1 <= pair[1].0,
            "ELF PT_LOAD physical memory ranges 重叠"
        );
    }

    let mut regions = Vec::new();
    let mut missing_ranges = Vec::new();
    for header in headers.iter().filter(|header| header.kind == PT_LOAD) {
        if header.file_size > 0 {
            header
                .physical_start
                .checked_add(header.file_size)
                .context("ELF physical segment 溢出")?;
            regions.push(ElfRegion {
                physical_start: header.physical_start,
                file_offset: header.file_offset,
                length: header.file_size,
            });
        }
        if header.memory_size > header.file_size {
            missing_ranges.push(ElfMissingRange {
                start: header
                    .physical_start
                    .checked_add(header.file_size)
                    .context("ELF missing tail 地址溢出")?,
                length: header.memory_size - header.file_size,
            });
        }
    }
    ensure!(
        !regions.is_empty(),
        "ELF core 不包含有数据的 PT_LOAD physical segments"
    );
    regions.sort_unstable_by_key(|region| region.physical_start);
    for pair in regions.windows(2) {
        ensure!(
            pair[0].physical_start + pair[0].length <= pair[1].physical_start,
            "ELF PT_LOAD physical segments 重叠"
        );
    }
    missing_ranges.sort_unstable_by_key(|range| range.start);
    Ok(ElfPhysicalMap {
        machine,
        program_header_count: program_count,
        producer,
        regions,
        missing_ranges,
    })
}

fn note_has_owner(bytes: &[u8], offset: u64, length: u64, wanted: &[u8]) -> Result<bool> {
    let start = usize::try_from(offset).context("ELF note offset 过大")?;
    let length = usize::try_from(length).context("ELF note size 过大")?;
    let notes = bytes
        .get(start..start.checked_add(length).context("ELF note 范围溢出")?)
        .context("ELF note segment 被截断")?;
    let mut cursor = 0usize;
    while cursor < notes.len() {
        ensure!(notes.len() - cursor >= 12, "ELF note header 被截断");
        let name_size = usize::try_from(read_u32(notes, cursor)?)?;
        let description_size = usize::try_from(read_u32(notes, cursor + 4)?)?;
        cursor += 12;
        let name_end = cursor
            .checked_add(name_size)
            .context("ELF note name 溢出")?;
        let name = notes
            .get(cursor..name_end)
            .context("ELF note name 被截断")?;
        let name = name.strip_suffix(&[0]).unwrap_or(name);
        cursor = align_four(name_end)?;
        let description_end = cursor
            .checked_add(description_size)
            .context("ELF note description 溢出")?;
        ensure!(
            description_end <= notes.len(),
            "ELF note description 被截断"
        );
        if name == wanted {
            return Ok(true);
        }
        cursor = align_four(description_end)?;
        ensure!(cursor <= notes.len(), "ELF note padding 被截断");
    }
    Ok(false)
}

fn align_four(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .context("ELF note alignment 溢出")
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .context("ELF header 被截断")?
            .try_into()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("ELF header 被截断")?
            .try_into()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .context("ELF header 被截断")?
            .try_into()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sparse_physical_loads_and_missing_tails() {
        let bytes = fixture(b"VBOX", false);
        let parsed = parse_elf_physical_core(&bytes, bytes.len() as u64).unwrap();
        assert_eq!(parsed.producer, ElfProducerHint::Generic);
        assert_eq!(parsed.regions.len(), 2);
        assert_eq!(parsed.regions[0].physical_start, 0x1000);
        assert_eq!(parsed.regions[1].physical_start, 0x8000);
        assert_eq!(parsed.missing_ranges[0].start, 0x1010);
        assert_eq!(parsed.missing_ranges[0].length, 0x10);
    }

    #[test]
    fn qemu_label_requires_an_exact_note_owner() {
        let generic = fixture(b"VirtualBox", false);
        assert_eq!(
            parse_elf_physical_core(&generic, generic.len() as u64)
                .unwrap()
                .producer,
            ElfProducerHint::Generic
        );
        let qemu = fixture(b"QEMU", false);
        assert_eq!(
            parse_elf_physical_core(&qemu, qemu.len() as u64)
                .unwrap()
                .producer,
            ElfProducerHint::Qemu
        );
    }

    #[test]
    fn tolerates_bogus_e_ehsize_from_real_writers() {
        let mut bytes = fixture(b"VBOX", false);
        put_u16(&mut bytes, 52, 8);
        let parsed = parse_elf_physical_core(&bytes, bytes.len() as u64).unwrap();
        assert_eq!(parsed.regions.len(), 2);
    }

    #[test]
    fn rejects_big_endian_truncation_and_overlapping_physical_loads() {
        let mut big_endian = fixture(b"VBOX", false);
        big_endian[5] = 2;
        assert!(parse_elf_physical_core(&big_endian, big_endian.len() as u64).is_err());

        let truncated = fixture(b"VBOX", false);
        assert!(parse_elf_physical_core(&truncated, 0x1008).is_err());

        let overlap = fixture(b"VBOX", true);
        assert!(parse_elf_physical_core(&overlap, overlap.len() as u64).is_err());

        let mut overlaps_missing_tail = fixture(b"VBOX", false);
        let second_physical = ELF_HEADER_SIZE + ELF_PROGRAM_HEADER64_SIZE + 24;
        put_u64(&mut overlaps_missing_tail, second_physical, 0x1018);
        assert!(
            parse_elf_physical_core(&overlaps_missing_tail, overlaps_missing_tail.len() as u64)
                .is_err()
        );
    }

    pub(super) fn fixture(note_owner: &[u8], overlap: bool) -> Vec<u8> {
        let phnum = 3u16;
        let note = make_note(note_owner);
        let mut bytes = vec![0u8; 0x3000 + note.len()];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, ET_CORE);
        put_u16(&mut bytes, 18, EM_X86_64);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 32, ELF_HEADER_SIZE as u64);
        put_u16(&mut bytes, 52, ELF_HEADER_SIZE as u16);
        put_u16(&mut bytes, 54, ELF_PROGRAM_HEADER64_SIZE as u16);
        put_u16(&mut bytes, 56, phnum);

        put_program_header(&mut bytes, 0, PT_LOAD, 0x1000, 0x1000, 0x10, 0x20);
        put_program_header(
            &mut bytes,
            1,
            PT_LOAD,
            0x2000,
            if overlap { 0x1008 } else { 0x8000 },
            0x10,
            0x10,
        );
        put_program_header(
            &mut bytes,
            2,
            PT_NOTE,
            0x3000,
            0,
            note.len() as u64,
            note.len() as u64,
        );
        bytes[0x1000..0x1010].copy_from_slice(b"first-phys-page!");
        bytes[0x2000..0x2010].copy_from_slice(b"second-physical!");
        bytes[0x3000..0x3000 + note.len()].copy_from_slice(&note);
        bytes
    }

    fn put_program_header(
        bytes: &mut [u8],
        index: usize,
        kind: u32,
        offset: u64,
        physical: u64,
        file_size: u64,
        memory_size: u64,
    ) {
        let start = ELF_HEADER_SIZE + index * ELF_PROGRAM_HEADER64_SIZE;
        put_u32(bytes, start, kind);
        put_u64(bytes, start + 8, offset);
        put_u64(bytes, start + 24, physical);
        put_u64(bytes, start + 32, file_size);
        put_u64(bytes, start + 40, memory_size);
        put_u64(bytes, start + 48, 0x1000);
    }

    fn make_note(owner: &[u8]) -> Vec<u8> {
        let mut owner = owner.to_vec();
        owner.push(0);
        let mut note = Vec::new();
        note.extend_from_slice(&(owner.len() as u32).to_le_bytes());
        note.extend_from_slice(&0u32.to_le_bytes());
        note.extend_from_slice(&1u32.to_le_bytes());
        note.extend_from_slice(&owner);
        while note.len() % 4 != 0 {
            note.push(0);
        }
        note
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
