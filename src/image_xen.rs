//! Strict Xen ELF64 dump-core parser.
//!
//! Xen dump-core files use ELF section headers instead of `PT_LOAD` program headers.  Physical
//! pages live in `.xen_pages`; exactly one of `.xen_pfn` and `.xen_p2m` maps each page slot to a
//! guest pseudo-physical frame number.  This parser intentionally validates the Xen notes and
//! mapping universe before returning any [`PhysicalSpan`].

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::image::{MappingEncoding, PhysicalSpan};

const ELF64_HEADER_SIZE: usize = 64;
const ELF64_SECTION_HEADER_SIZE: usize = 64;
const ET_CORE: u16 = 4;
const EM_X86_64: u16 = 62;
const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHN_XINDEX: u16 = 0xffff;
const MAX_SECTION_HEADERS: u64 = 1_000_000;
const MAX_XEN_PAGE_ENTRIES: u64 = 64 * 1024 * 1024;
const MAX_XEN_SPANS: usize = 4 * 1024 * 1024;
const MAX_XEN_NOTE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_XEN_SECTION_NAME_BYTES: u64 = 16 * 1024 * 1024;

const XEN_ELFNOTE_DUMPCORE_NONE: u32 = 0x0200_0000;
const XEN_ELFNOTE_DUMPCORE_HEADER: u32 = 0x0200_0001;
const XEN_ELFNOTE_DUMPCORE_XEN_VERSION: u32 = 0x0200_0002;
const XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION: u32 = 0x0200_0003;
const XC_CORE_MAGIC_PV: u64 = 0xf00f_ebed;
const XC_CORE_MAGIC_HVM: u64 = 0xf00f_ebee;
const XEN_FORMAT_MAJOR: u32 = 0;
const XEN_FORMAT_MINOR: u32 = 1;
const MIN_PAGE_SIZE: u64 = 0x1000;
const MAX_PAGE_SIZE: u64 = 1 << 30;
const INVALID_FRAME_64: u64 = u64::MAX;
// Older consumers (including Volatility 3) also recognize this value as an invalid frame.
const INVALID_FRAME_COMPAT_32: u64 = u32::MAX as u64;

/// Defensive limits for Xen metadata traversal and output descriptor growth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XenParseLimits {
    pub max_section_headers: u64,
    pub max_page_entries: u64,
    pub max_spans: usize,
    pub max_note_bytes: u64,
    pub max_section_name_bytes: u64,
}

impl Default for XenParseLimits {
    fn default() -> Self {
        Self {
            max_section_headers: MAX_SECTION_HEADERS,
            max_page_entries: MAX_XEN_PAGE_ENTRIES,
            max_spans: MAX_XEN_SPANS,
            max_note_bytes: MAX_XEN_NOTE_BYTES,
            max_section_name_bytes: MAX_XEN_SECTION_NAME_BYTES,
        }
    }
}

/// Which Xen section translates `.xen_pages` slots to guest physical frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XenTranslationKind {
    Pfn,
    P2m,
}

/// Domain translation mode encoded by the Xen dump-core header magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XenDomainKind {
    Paravirtualized,
    HardwareVirtualized,
}

/// Stable, serializable description of the Xen mapping that was actually validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XenElf64Summary {
    pub machine: u16,
    pub section_header_count: u64,
    pub translation: XenTranslationKind,
    pub domain: XenDomainKind,
    pub page_size: u64,
    pub declared_pages: u64,
    pub mapped_pages: u64,
    pub invalid_pages: u64,
    pub mapped_bytes: u64,
    pub format_major: u32,
    pub format_minor: u32,
}

/// Validated mappings for one Xen ELF64 dump-core source.
#[derive(Debug, Clone, Serialize)]
pub struct XenElf64Map {
    pub summary: XenElf64Summary,
    pub spans: Vec<PhysicalSpan>,
}

/// Parses an ELF image when it identifies as a Xen dump-core.
///
/// `Ok(None)` means that the ELF section-name table contains none of the Xen dump-core section
/// names.  Once any Xen dump-core section is present, missing/duplicated sections and malformed
/// metadata are hard errors rather than a reason to silently reinterpret the file as a generic
/// physical ELF core.
pub fn parse_xen_elf64(
    bytes: &[u8],
    file_length: u64,
    source_index: usize,
) -> Result<Option<XenElf64Map>> {
    parse_xen_elf64_with_limits(bytes, file_length, source_index, XenParseLimits::default())
}

pub fn parse_xen_elf64_with_limits(
    bytes: &[u8],
    file_length: u64,
    source_index: usize,
    limits: XenParseLimits,
) -> Result<Option<XenElf64Map>> {
    ensure!(
        limits.max_section_headers > 0
            && limits.max_page_entries > 0
            && limits.max_spans > 0
            && limits.max_note_bytes > 0
            && limits.max_section_name_bytes > 0,
        "Xen parser limits 必须全部非零"
    );
    if bytes.get(..4) != Some(b"\x7fELF") {
        return Ok(None);
    }
    ensure!(
        file_length <= bytes.len() as u64,
        "Xen ELF64 parser 未收到完整的文件字节"
    );
    ensure!(
        file_length >= ELF64_HEADER_SIZE as u64,
        "ELF64 header 被截断"
    );
    ensure!(bytes[4] == 2, "Xen dump-core 必须使用 ELFCLASS64");
    ensure!(bytes[5] == 1, "首版仅支持 little-endian Xen ELF64");
    ensure!(bytes[6] == 1, "ELF ident version 无效");
    ensure!(
        read_u16(bytes, 16)? == ET_CORE,
        "Xen dump-core 必须是 ET_CORE"
    );
    let machine = read_u16(bytes, 18)?;
    ensure!(machine == EM_X86_64, "首版仅支持 x86-64 Xen dump-core");
    ensure!(read_u32(bytes, 20)? == 1, "ELF header version 无效");
    // e_ehsize 不参与解析；VirtualBox 等写入器会写错该字段，不能因此阻断后续格式探测。

    let (sections, names_index) =
        parse_section_headers(bytes, file_length, limits.max_section_headers)?;
    if sections.is_empty() {
        return Ok(None);
    }
    let names = parse_section_names(
        bytes,
        &sections,
        names_index,
        file_length,
        limits.max_section_name_bytes,
    )?;
    let is_candidate = names.iter().any(|name| {
        matches!(
            *name,
            b".note.Xen" | b".xen_pages" | b".xen_pfn" | b".xen_p2m"
        )
    });
    if !is_candidate {
        return Ok(None);
    }

    let note = unique_named_section(&sections, &names, b".note.Xen")?
        .context("Xen dump-core 缺少 .note.Xen")?;
    let pages = unique_named_section(&sections, &names, b".xen_pages")?
        .context("Xen dump-core 缺少 .xen_pages")?;
    let pfn = unique_named_section(&sections, &names, b".xen_pfn")?;
    let p2m = unique_named_section(&sections, &names, b".xen_p2m")?;
    ensure!(
        pfn.is_some() ^ p2m.is_some(),
        "Xen dump-core 必须且只能包含 .xen_pfn/.xen_p2m 之一"
    );
    ensure!(note.kind == SHT_NOTE, ".note.Xen 不是 SHT_NOTE");
    ensure!(pages.kind == SHT_PROGBITS, ".xen_pages 不是 SHT_PROGBITS");
    ensure!(note.size <= limits.max_note_bytes, ".note.Xen 超过安全上限");

    let xen_header = parse_xen_notes(section_bytes(bytes, note, file_length)?)?;
    let (translation, mapping, entry_size) = if let Some(section) = pfn {
        ensure!(section.kind == SHT_PROGBITS, ".xen_pfn 不是 SHT_PROGBITS");
        (XenTranslationKind::Pfn, section, 8u64)
    } else {
        let section = p2m.expect("exclusive Xen translation section was checked");
        ensure!(section.kind == SHT_PROGBITS, ".xen_p2m 不是 SHT_PROGBITS");
        (XenTranslationKind::P2m, section, 16u64)
    };
    ensure!(
        mapping.entry_size == 0 || mapping.entry_size == entry_size,
        "Xen translation section 的 sh_entsize 无效"
    );
    ensure!(
        mapping.size.is_multiple_of(entry_size),
        "Xen translation section 尾部存在不完整 entry"
    );
    let entry_count = mapping.size / entry_size;
    ensure!(
        entry_count <= limits.max_page_entries,
        "Xen translation entry count {entry_count} 超过安全上限 {}",
        limits.max_page_entries
    );
    ensure!(
        entry_count == xen_header.page_count,
        "Xen header 页数与 translation entry 数不一致：header={} entries={entry_count}",
        xen_header.page_count
    );
    let expected_pages_size = xen_header
        .page_count
        .checked_mul(xen_header.page_size)
        .context("Xen pages section 长度溢出")?;
    ensure!(
        pages.size == expected_pages_size,
        ".xen_pages 长度与 header 页数/页大小不一致：section={} expected={expected_pages_size}",
        pages.size
    );
    ensure_disjoint_sections(pages, mapping, ".xen_pages", "translation section")?;
    validate_file_section_layout(bytes, &sections, file_length)?;
    ensure!(
        pages.offset.is_multiple_of(xen_header.page_size),
        ".xen_pages 文件偏移未按 Xen page size 对齐"
    );
    ensure!(
        pages.entry_size == 0 || pages.entry_size == xen_header.page_size,
        ".xen_pages sh_entsize 与 Xen page size 不一致"
    );
    ensure!(
        mapping.offset.is_multiple_of(entry_size),
        "Xen translation section 未对齐"
    );
    ensure!(note.offset.is_multiple_of(4), ".note.Xen 未按 4 字节对齐");

    let table = section_bytes(bytes, mapping, file_length)?;
    let mut spans = Vec::new();
    let mut previous_pfn = None;
    let mut saw_invalid = false;
    let mut invalid_pages = 0u64;
    let mut mapped_pages = 0u64;
    for index in 0..entry_count {
        let entry_offset = index
            .checked_mul(entry_size)
            .context("Xen translation entry offset 溢出")?;
        let entry_offset = usize::try_from(entry_offset).context("Xen entry offset 过大")?;
        let pfn_value = read_u64(table, entry_offset)?;
        let invalid = match translation {
            XenTranslationKind::Pfn => is_invalid_frame(pfn_value),
            XenTranslationKind::P2m => {
                let gmfn = read_u64(table, entry_offset + 8)?;
                let pfn_invalid = is_invalid_frame(pfn_value);
                let gmfn_invalid = is_invalid_frame(gmfn);
                ensure!(
                    pfn_invalid == gmfn_invalid,
                    "Xen P2M entry {index} 只有一半使用 invalid sentinel"
                );
                pfn_invalid
            }
        };
        if invalid {
            saw_invalid = true;
            invalid_pages = invalid_pages.checked_add(1).context("invalid 页计数溢出")?;
            continue;
        }
        ensure!(
            !saw_invalid,
            "Xen translation entry {index} 位于 invalid 尾部之后"
        );
        if let Some(previous) = previous_pfn {
            ensure!(
                pfn_value > previous,
                "Xen PFN entries 未严格递增或存在重复物理映射：{pfn_value:#x}"
            );
        }
        previous_pfn = Some(pfn_value);
        let physical_start = pfn_value
            .checked_mul(xen_header.page_size)
            .context("Xen PFN 转换为物理地址时溢出")?;
        physical_start
            .checked_add(xen_header.page_size)
            .context("Xen 物理页末地址溢出")?;
        let page_offset = pages
            .offset
            .checked_add(
                index
                    .checked_mul(xen_header.page_size)
                    .context("Xen page slot offset 溢出")?,
            )
            .context("Xen page source offset 溢出")?;
        ensure!(
            page_offset
                .checked_add(xen_header.page_size)
                .is_some_and(|end| end <= pages.offset + pages.size),
            "Xen page slot {index} 超出 .xen_pages"
        );
        push_or_coalesce_direct_span(
            &mut spans,
            physical_start,
            xen_header.page_size,
            page_offset,
            source_index,
            limits.max_spans,
        )?;
        mapped_pages = mapped_pages.checked_add(1).context("mapped 页计数溢出")?;
    }
    ensure!(mapped_pages > 0, "Xen dump-core 不包含任何有效物理页");
    let mapped_bytes = mapped_pages
        .checked_mul(xen_header.page_size)
        .context("Xen mapped byte 计数溢出")?;

    Ok(Some(XenElf64Map {
        summary: XenElf64Summary {
            machine,
            section_header_count: sections.len() as u64,
            translation,
            domain: xen_header.domain,
            page_size: xen_header.page_size,
            declared_pages: xen_header.page_count,
            mapped_pages,
            invalid_pages,
            mapped_bytes,
            format_major: xen_header.format_major,
            format_minor: xen_header.format_minor,
        },
        spans,
    }))
}

#[derive(Debug, Clone, Copy)]
struct SectionHeader {
    name_offset: u32,
    kind: u32,
    offset: u64,
    size: u64,
    link: u32,
    entry_size: u64,
}

fn parse_section_headers(
    bytes: &[u8],
    file_length: u64,
    max_section_headers: u64,
) -> Result<(Vec<SectionHeader>, usize)> {
    let table_offset = read_u64(bytes, 40)?;
    let entry_size = read_u16(bytes, 58)?;
    let compact_count = read_u16(bytes, 60)?;
    let compact_names_index = read_u16(bytes, 62)?;
    if table_offset == 0 && compact_count == 0 {
        return Ok((Vec::new(), 0));
    }
    ensure!(
        usize::from(entry_size) >= ELF64_SECTION_HEADER_SIZE,
        "ELF64 section header size 无效"
    );
    let section_zero = read_section_header(bytes, table_offset, file_length)?;
    let count = if compact_count == 0 {
        section_zero.size
    } else {
        u64::from(compact_count)
    };
    ensure!(count > 0, "ELF section header count 为零");
    ensure!(
        count <= max_section_headers,
        "ELF section header count {count} 超出安全上限"
    );
    let names_index = if compact_names_index == SHN_XINDEX {
        u64::from(section_zero.link)
    } else {
        u64::from(compact_names_index)
    };
    ensure!(names_index > 0 && names_index < count, "ELF shstrndx 无效");
    let table_size = count
        .checked_mul(u64::from(entry_size))
        .context("ELF section header table 长度溢出")?;
    ensure!(
        table_offset
            .checked_add(table_size)
            .is_some_and(|end| end <= file_length),
        "ELF section header table 超出文件末尾"
    );

    let mut sections = Vec::new();
    sections
        .try_reserve_exact(usize::try_from(count).context("section count 过大")?)
        .context("无法为 ELF section headers 分配内存")?;
    for index in 0..count {
        let offset = table_offset
            .checked_add(
                index
                    .checked_mul(u64::from(entry_size))
                    .context("section header offset 溢出")?,
            )
            .context("section header offset 溢出")?;
        let section = read_section_header(bytes, offset, file_length)?;
        if section.kind != SHT_NOBITS && section.size > 0 {
            ensure!(
                section
                    .offset
                    .checked_add(section.size)
                    .is_some_and(|end| end <= file_length),
                "ELF section {index} 超出文件末尾"
            );
        }
        sections.push(section);
    }
    Ok((
        sections,
        usize::try_from(names_index).context("shstrndx 过大")?,
    ))
}

fn read_section_header(bytes: &[u8], offset: u64, file_length: u64) -> Result<SectionHeader> {
    ensure!(
        offset
            .checked_add(ELF64_SECTION_HEADER_SIZE as u64)
            .is_some_and(|end| end <= file_length),
        "ELF64 section header 被截断"
    );
    let offset = usize::try_from(offset).context("ELF64 section header offset 过大")?;
    Ok(SectionHeader {
        name_offset: read_u32(bytes, offset)?,
        kind: read_u32(bytes, offset + 4)?,
        offset: read_u64(bytes, offset + 24)?,
        size: read_u64(bytes, offset + 32)?,
        link: read_u32(bytes, offset + 40)?,
        entry_size: read_u64(bytes, offset + 56)?,
    })
}

fn parse_section_names<'a>(
    bytes: &'a [u8],
    sections: &[SectionHeader],
    names_index: usize,
    file_length: u64,
    max_name_bytes: u64,
) -> Result<Vec<&'a [u8]>> {
    let names_section = sections
        .get(names_index)
        .context("shstrndx 超出 section table")?;
    ensure!(
        names_section.kind == SHT_STRTAB,
        "shstrndx 未指向 SHT_STRTAB"
    );
    ensure!(
        names_section.size <= max_name_bytes,
        "ELF section string table 超过安全上限"
    );
    let string_table = section_bytes(bytes, names_section, file_length)?;
    ensure!(
        string_table.first() == Some(&0),
        "ELF section string table 缺少初始 NUL"
    );
    sections
        .iter()
        .map(|section| {
            let offset =
                usize::try_from(section.name_offset).context("section name offset 过大")?;
            let tail = string_table
                .get(offset..)
                .context("section name offset 超出 shstrtab")?;
            let length = tail
                .iter()
                .position(|byte| *byte == 0)
                .context("section name 未以 NUL 终止")?;
            Ok(&tail[..length])
        })
        .collect()
}

fn unique_named_section<'a>(
    sections: &'a [SectionHeader],
    names: &[&[u8]],
    wanted: &[u8],
) -> Result<Option<&'a SectionHeader>> {
    let mut matches = sections
        .iter()
        .zip(names)
        .filter_map(|(section, name)| (*name == wanted).then_some(section));
    let first = matches.next();
    ensure!(
        matches.next().is_none(),
        "ELF 中重复出现 section {}",
        String::from_utf8_lossy(wanted)
    );
    Ok(first)
}

fn section_bytes<'a>(
    bytes: &'a [u8],
    section: &SectionHeader,
    file_length: u64,
) -> Result<&'a [u8]> {
    let end = section
        .offset
        .checked_add(section.size)
        .context("ELF section 范围溢出")?;
    ensure!(end <= file_length, "ELF section 超出文件末尾");
    let start = usize::try_from(section.offset).context("ELF section offset 过大")?;
    let end = usize::try_from(end).context("ELF section end 过大")?;
    bytes.get(start..end).context("ELF section 被截断")
}

fn ensure_disjoint_sections(
    left: &SectionHeader,
    right: &SectionHeader,
    left_name: &str,
    right_name: &str,
) -> Result<()> {
    let left_end = left
        .offset
        .checked_add(left.size)
        .context("section 范围溢出")?;
    let right_end = right
        .offset
        .checked_add(right.size)
        .context("section 范围溢出")?;
    ensure!(
        left_end <= right.offset || right_end <= left.offset,
        "{left_name} 与 {right_name} 在文件中重叠"
    );
    Ok(())
}

fn validate_file_section_layout(
    bytes: &[u8],
    sections: &[SectionHeader],
    file_length: u64,
) -> Result<()> {
    let table_offset = read_u64(bytes, 40)?;
    let entry_size = u64::from(read_u16(bytes, 58)?);
    let table_size = u64::try_from(sections.len())
        .context("section count 过大")?
        .checked_mul(entry_size)
        .context("section header table 长度溢出")?;
    let table_end = table_offset
        .checked_add(table_size)
        .context("section header table 范围溢出")?;
    ensure!(
        table_offset >= ELF64_HEADER_SIZE as u64,
        "section header table 与 ELF header 重叠"
    );
    ensure!(
        table_end <= file_length,
        "section header table 超出文件末尾"
    );

    let mut ranges = sections
        .iter()
        .enumerate()
        .filter(|(index, section)| *index != 0 && section.kind != SHT_NOBITS && section.size != 0)
        .map(|(index, section)| -> Result<(u64, u64, usize)> {
            let end = section
                .offset
                .checked_add(section.size)
                .context("ELF section 范围溢出")?;
            ensure!(
                section.offset >= ELF64_HEADER_SIZE as u64,
                "ELF section {index} 与 ELF header 重叠"
            );
            ensure!(
                end <= table_offset || table_end <= section.offset,
                "ELF section {index} 与 section header table 重叠"
            );
            Ok((section.offset, end, index))
        })
        .collect::<Result<Vec<_>>>()?;
    ranges.sort_unstable_by_key(|range| (range.0, range.1, range.2));
    for pair in ranges.windows(2) {
        ensure!(
            pair[0].1 <= pair[1].0,
            "ELF file-backed sections {} and {} overlap",
            pair[0].2,
            pair[1].2
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct XenHeader {
    domain: XenDomainKind,
    page_count: u64,
    page_size: u64,
    format_major: u32,
    format_minor: u32,
}

fn parse_xen_notes(notes: &[u8]) -> Result<XenHeader> {
    let mut cursor = 0usize;
    let mut saw_none = false;
    let mut saw_xen_version = false;
    let mut header = None;
    let mut format = None;
    while cursor < notes.len() {
        // ELF permits zero padding at the end of a note section.
        if notes[cursor..].iter().all(|byte| *byte == 0) {
            break;
        }
        ensure!(notes.len() - cursor >= 12, ".note.Xen note header 被截断");
        let name_size = usize::try_from(read_u32(notes, cursor)?)?;
        let description_size = usize::try_from(read_u32(notes, cursor + 4)?)?;
        let note_type = read_u32(notes, cursor + 8)?;
        cursor += 12;
        let name_end = cursor
            .checked_add(name_size)
            .context("Xen note name 溢出")?;
        let name = notes
            .get(cursor..name_end)
            .context("Xen note name 被截断")?;
        cursor = align_four(name_end)?;
        ensure!(cursor <= notes.len(), "Xen note name padding 被截断");
        let description_end = cursor
            .checked_add(description_size)
            .context("Xen note descriptor 溢出")?;
        let description = notes
            .get(cursor..description_end)
            .context("Xen note descriptor 被截断")?;
        cursor = align_four(description_end)?;
        ensure!(cursor <= notes.len(), "Xen note descriptor padding 被截断");

        if name.trim_ascii_end_matches(0) != b"Xen" {
            continue;
        }
        match note_type {
            XEN_ELFNOTE_DUMPCORE_NONE => {
                ensure!(!saw_none, "重复的 Xen DUMPCORE_NONE note");
                ensure!(description.is_empty(), "Xen DUMPCORE_NONE descriptor 非空");
                saw_none = true;
            }
            XEN_ELFNOTE_DUMPCORE_HEADER => {
                ensure!(header.is_none(), "重复的 Xen DUMPCORE_HEADER note");
                ensure!(description.len() == 32, "Xen header descriptor 长度无效");
                let magic = read_u64(description, 0)?;
                let domain = match magic {
                    XC_CORE_MAGIC_PV => XenDomainKind::Paravirtualized,
                    XC_CORE_MAGIC_HVM => XenDomainKind::HardwareVirtualized,
                    _ => anyhow::bail!("Xen dump-core magic 无效：{magic:#x}"),
                };
                let vcpus = read_u64(description, 8)?;
                let page_count = read_u64(description, 16)?;
                let page_size = read_u64(description, 24)?;
                ensure!(vcpus > 0, "Xen header vCPU 数为零");
                ensure!(page_count > 0, "Xen header 页数为零");
                ensure!(
                    page_size.is_power_of_two()
                        && (MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&page_size),
                    "Xen header 页大小不受支持：{page_size:#x}"
                );
                header = Some((domain, page_count, page_size));
            }
            XEN_ELFNOTE_DUMPCORE_XEN_VERSION => {
                ensure!(!saw_xen_version, "重复的 Xen version note");
                ensure!(!description.is_empty(), "Xen version descriptor 为空");
                saw_xen_version = true;
            }
            XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION => {
                ensure!(format.is_none(), "重复的 Xen format-version note");
                ensure!(
                    description.len() == 8,
                    "Xen format-version descriptor 长度无效"
                );
                let version = read_u64(description, 0)?;
                format = Some(((version >> 32) as u32, version as u32));
            }
            _ => {}
        }
    }
    ensure!(saw_none, ".note.Xen 缺少 DUMPCORE_NONE note");
    ensure!(saw_xen_version, ".note.Xen 缺少 Xen version note");
    let (domain, page_count, page_size) = header.context(".note.Xen 缺少 header note")?;
    let (format_major, format_minor) = format.context(".note.Xen 缺少 format-version note")?;
    ensure!(
        format_major == XEN_FORMAT_MAJOR && format_minor == XEN_FORMAT_MINOR,
        "不支持 Xen dump-core format {format_major}.{format_minor}"
    );
    Ok(XenHeader {
        domain,
        page_count,
        page_size,
        format_major,
        format_minor,
    })
}

trait TrimAsciiEndMatches {
    fn trim_ascii_end_matches(&self, byte: u8) -> &[u8];
}

impl TrimAsciiEndMatches for [u8] {
    fn trim_ascii_end_matches(&self, byte: u8) -> &[u8] {
        let end = self
            .iter()
            .rposition(|candidate| *candidate != byte)
            .map_or(0, |index| index + 1);
        &self[..end]
    }
}

fn is_invalid_frame(value: u64) -> bool {
    matches!(value, INVALID_FRAME_64 | INVALID_FRAME_COMPAT_32)
}

/// This is the only parser-to-image mapping adapter, so a future `MappedSource` shape change is
/// localized to one function.
fn push_or_coalesce_direct_span(
    spans: &mut Vec<PhysicalSpan>,
    physical_start: u64,
    length: u64,
    source_offset: u64,
    source_index: usize,
    max_spans: usize,
) -> Result<()> {
    if let Some(previous) = spans.last_mut() {
        let previous_source_end = previous
            .file_offset
            .checked_add(previous.length)
            .context("Xen source span 末尾溢出")?;
        if previous.end() == physical_start
            && previous_source_end == source_offset
            && previous.source_index == source_index
            && matches!(previous.encoding, MappingEncoding::Direct)
        {
            previous.length = previous
                .length
                .checked_add(length)
                .context("Xen coalesced span 长度溢出")?;
            return Ok(());
        }
    }
    ensure!(
        spans.len() < max_spans,
        "Xen physical span count 超过安全上限 {max_spans}"
    );
    spans.push(PhysicalSpan {
        start: physical_start,
        length,
        file_offset: source_offset,
        source_index,
        encoding: MappingEncoding::Direct,
    });
    Ok(())
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
            .get(offset..offset.checked_add(2).context("读取范围溢出")?)
            .context("ELF/Xen 字段被截断")?
            .try_into()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset.checked_add(4).context("读取范围溢出")?)
            .context("ELF/Xen 字段被截断")?
            .try_into()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset.checked_add(8).context("读取范围溢出")?)
            .context("ELF/Xen 字段被截断")?
            .try_into()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_pfn_pages_and_coalesces_adjacent_slots() {
        let image = fixture(TranslationFixture::Pfn, &[1, 2, 8, INVALID_FRAME_64]);
        let parsed = parse_xen_elf64(&image, image.len() as u64, 3)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.summary.translation, XenTranslationKind::Pfn);
        assert_eq!(parsed.summary.declared_pages, 4);
        assert_eq!(parsed.summary.mapped_pages, 3);
        assert_eq!(parsed.summary.invalid_pages, 1);
        assert_eq!(parsed.summary.mapped_bytes, 0x3000);
        assert_eq!(parsed.spans.len(), 2);
        assert_eq!(parsed.spans[0].start, 0x1000);
        assert_eq!(parsed.spans[0].length, 0x2000);
        assert_eq!(parsed.spans[0].source_index, 3);
        assert_eq!(parsed.spans[1].start, 0x8000);
    }

    #[test]
    fn maps_p2m_by_guest_pfn_not_machine_frame() {
        let image = fixture(TranslationFixture::P2m, &[4, 5]);
        let parsed = parse_xen_elf64(&image, image.len() as u64, 0)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.summary.translation, XenTranslationKind::P2m);
        assert_eq!(parsed.summary.domain, XenDomainKind::Paravirtualized);
        assert_eq!(parsed.spans.len(), 1);
        assert_eq!(parsed.spans[0].start, 0x4000);
        assert_eq!(parsed.spans[0].length, 0x2000);
    }

    #[test]
    fn ordinary_elf_with_named_sections_is_not_claimed() {
        let mut image = fixture(TranslationFixture::Pfn, &[1]);
        rename_section(&mut image, b".xen_pages", b".not_pages");
        rename_section(&mut image, b".xen_pfn", b".not_pfn");
        rename_section(&mut image, b".note.Xen", b".note.NoX");
        assert!(
            parse_xen_elf64(&image, image.len() as u64, 0)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_missing_pages_and_ambiguous_translation_sections() {
        let mut missing = fixture(TranslationFixture::Pfn, &[1]);
        rename_section(&mut missing, b".xen_pages", b".not_pages");
        let error = parse_xen_elf64(&missing, missing.len() as u64, 0)
            .unwrap_err()
            .to_string();
        assert!(error.contains(".xen_pages"));

        let both = fixture(TranslationFixture::Both, &[1]);
        let error = parse_xen_elf64(&both, both.len() as u64, 0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("只能包含"));
    }

    #[test]
    fn rejects_duplicate_and_out_of_order_physical_mappings() {
        let duplicate = fixture(TranslationFixture::Pfn, &[1, 1]);
        assert!(
            parse_xen_elf64(&duplicate, duplicate.len() as u64, 0)
                .unwrap_err()
                .to_string()
                .contains("重复物理映射")
        );

        let descending = fixture(TranslationFixture::P2m, &[8, 7]);
        assert!(parse_xen_elf64(&descending, descending.len() as u64, 0).is_err());

        let invalid_middle = fixture(TranslationFixture::Pfn, &[1, INVALID_FRAME_64, 2]);
        assert!(parse_xen_elf64(&invalid_middle, invalid_middle.len() as u64, 0).is_err());
    }

    #[test]
    fn rejects_section_and_page_slot_out_of_bounds() {
        let image = fixture(TranslationFixture::Pfn, &[1, 2]);
        assert!(parse_xen_elf64(&image, image.len() as u64 - 1, 0).is_err());

        let mut oversized_pages = fixture(TranslationFixture::Pfn, &[1]);
        let pages_header = section_header_for(&oversized_pages, b".xen_pages");
        put_u64(&mut oversized_pages, pages_header + 32, 0x2000);
        assert!(parse_xen_elf64(&oversized_pages, oversized_pages.len() as u64, 0).is_err());
    }

    #[test]
    fn rejects_partial_p2m_sentinel_and_unknown_format() {
        let mut partial = fixture(TranslationFixture::P2m, &[INVALID_FRAME_64]);
        let mapping_header = section_header_for(&partial, b".xen_p2m");
        let mapping_offset = read_u64(&partial, mapping_header + 24).unwrap() as usize;
        put_u64(&mut partial, mapping_offset + 8, 10);
        assert!(
            parse_xen_elf64(&partial, partial.len() as u64, 0)
                .unwrap_err()
                .to_string()
                .contains("一半")
        );

        let mut unknown = fixture(TranslationFixture::Pfn, &[1]);
        let note_header = section_header_for(&unknown, b".note.Xen");
        let note_offset = read_u64(&unknown, note_header + 24).unwrap() as usize;
        let format_description =
            find_note_description(&unknown[note_offset..], XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION);
        put_u64(&mut unknown, note_offset + format_description, 1u64 << 32);
        assert!(
            parse_xen_elf64(&unknown, unknown.len() as u64, 0)
                .unwrap_err()
                .to_string()
                .contains("不支持 Xen dump-core format")
        );
    }

    #[test]
    fn enforces_metadata_page_and_span_limits() {
        let image = fixture(TranslationFixture::Pfn, &[1, 3]);

        let limits = XenParseLimits {
            max_page_entries: 1,
            ..XenParseLimits::default()
        };
        assert!(
            parse_xen_elf64_with_limits(&image, image.len() as u64, 0, limits)
                .unwrap_err()
                .to_string()
                .contains("entry count")
        );

        let limits = XenParseLimits {
            max_spans: 1,
            ..XenParseLimits::default()
        };
        assert!(
            parse_xen_elf64_with_limits(&image, image.len() as u64, 0, limits)
                .unwrap_err()
                .to_string()
                .contains("span count")
        );

        let limits = XenParseLimits {
            max_note_bytes: 1,
            ..XenParseLimits::default()
        };
        assert!(
            parse_xen_elf64_with_limits(&image, image.len() as u64, 0, limits)
                .unwrap_err()
                .to_string()
                .contains(".note.Xen")
        );

        let limits = XenParseLimits {
            max_section_name_bytes: 1,
            ..XenParseLimits::default()
        };
        assert!(
            parse_xen_elf64_with_limits(&image, image.len() as u64, 0, limits)
                .unwrap_err()
                .to_string()
                .contains("string table")
        );

        let limits = XenParseLimits {
            max_section_headers: 5,
            ..XenParseLimits::default()
        };
        assert!(
            parse_xen_elf64_with_limits(&image, image.len() as u64, 0, limits)
                .unwrap_err()
                .to_string()
                .contains("section header count")
        );
    }

    #[test]
    fn rejects_any_file_backed_section_overlapping_pages_or_header_table() {
        let mut pages_overlap = fixture(TranslationFixture::Pfn, &[1]);
        let unused = section_header_for(&pages_overlap, b".unused");
        put_u64(&mut pages_overlap, unused + 24, 0x1000);
        put_u64(&mut pages_overlap, unused + 32, 1);
        assert!(
            parse_xen_elf64(&pages_overlap, pages_overlap.len() as u64, 0)
                .unwrap_err()
                .to_string()
                .contains("overlap")
        );

        let mut table_overlap = fixture(TranslationFixture::Pfn, &[1]);
        let unused = section_header_for(&table_overlap, b".unused");
        put_u64(&mut table_overlap, unused + 24, ELF64_HEADER_SIZE as u64);
        put_u64(&mut table_overlap, unused + 32, 1);
        assert!(
            parse_xen_elf64(&table_overlap, table_overlap.len() as u64, 0)
                .unwrap_err()
                .to_string()
                .contains("section header table")
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum TranslationFixture {
        Pfn,
        P2m,
        Both,
    }

    fn fixture(translation: TranslationFixture, pfns: &[u64]) -> Vec<u8> {
        const SECTION_COUNT: usize = 6;
        const SECTION_TABLE: usize = ELF64_HEADER_SIZE;
        const SHSTRTAB_OFFSET: usize = 0x300;
        const NOTE_OFFSET: usize = 0x400;
        const MAPPING_OFFSET: usize = 0x600;
        const SECOND_MAPPING_OFFSET: usize = 0x800;
        const PAGES_OFFSET: usize = 0x1000;

        let mut names = vec![0];
        let null_name = 0u32;
        let shstrtab_name = append_name(&mut names, b".shstrtab");
        let note_name = append_name(&mut names, b".note.Xen");
        let pages_name = append_name(&mut names, b".xen_pages");
        let pfn_name = append_name(&mut names, b".xen_pfn");
        let p2m_name = append_name(&mut names, b".xen_p2m");

        let notes = make_notes(pfns.len() as u64, 0x1000);
        let file_size = PAGES_OFFSET + pfns.len() * 0x1000;
        let mut bytes = vec![0u8; file_size];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, ET_CORE);
        put_u16(&mut bytes, 18, EM_X86_64);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 40, SECTION_TABLE as u64);
        put_u16(&mut bytes, 52, ELF64_HEADER_SIZE as u16);
        put_u16(&mut bytes, 58, ELF64_SECTION_HEADER_SIZE as u16);
        put_u16(&mut bytes, 60, SECTION_COUNT as u16);
        put_u16(&mut bytes, 62, 1);

        put_section(&mut bytes, 0, null_name, 0, 0, 0, 0);
        put_section(
            &mut bytes,
            1,
            shstrtab_name,
            SHT_STRTAB,
            SHSTRTAB_OFFSET as u64,
            names.len() as u64,
            0,
        );
        put_section(
            &mut bytes,
            2,
            note_name,
            SHT_NOTE,
            NOTE_OFFSET as u64,
            notes.len() as u64,
            0,
        );
        put_section(
            &mut bytes,
            3,
            pages_name,
            SHT_PROGBITS,
            PAGES_OFFSET as u64,
            (pfns.len() * 0x1000) as u64,
            0,
        );
        match translation {
            TranslationFixture::Pfn => {
                put_section(
                    &mut bytes,
                    4,
                    pfn_name,
                    SHT_PROGBITS,
                    MAPPING_OFFSET as u64,
                    (pfns.len() * 8) as u64,
                    8,
                );
                put_section(
                    &mut bytes,
                    5,
                    append_name(&mut names, b".unused"),
                    SHT_PROGBITS,
                    0,
                    0,
                    0,
                );
                for (index, pfn) in pfns.iter().copied().enumerate() {
                    put_u64(&mut bytes, MAPPING_OFFSET + index * 8, pfn);
                }
            }
            TranslationFixture::P2m => {
                put_section(
                    &mut bytes,
                    4,
                    p2m_name,
                    SHT_PROGBITS,
                    MAPPING_OFFSET as u64,
                    (pfns.len() * 16) as u64,
                    16,
                );
                put_section(
                    &mut bytes,
                    5,
                    append_name(&mut names, b".unused"),
                    SHT_PROGBITS,
                    0,
                    0,
                    0,
                );
                for (index, pfn) in pfns.iter().copied().enumerate() {
                    put_u64(&mut bytes, MAPPING_OFFSET + index * 16, pfn);
                    let gmfn = if is_invalid_frame(pfn) {
                        pfn
                    } else {
                        pfn + 0x100
                    };
                    put_u64(&mut bytes, MAPPING_OFFSET + index * 16 + 8, gmfn);
                }
            }
            TranslationFixture::Both => {
                put_section(
                    &mut bytes,
                    4,
                    pfn_name,
                    SHT_PROGBITS,
                    MAPPING_OFFSET as u64,
                    (pfns.len() * 8) as u64,
                    8,
                );
                put_section(
                    &mut bytes,
                    5,
                    p2m_name,
                    SHT_PROGBITS,
                    SECOND_MAPPING_OFFSET as u64,
                    (pfns.len() * 16) as u64,
                    16,
                );
                for (index, pfn) in pfns.iter().copied().enumerate() {
                    put_u64(&mut bytes, MAPPING_OFFSET + index * 8, pfn);
                    put_u64(&mut bytes, SECOND_MAPPING_OFFSET + index * 16, pfn);
                    put_u64(
                        &mut bytes,
                        SECOND_MAPPING_OFFSET + index * 16 + 8,
                        pfn + 0x100,
                    );
                }
            }
        }
        // `names` may grow while writing the optional section; publish it after all names exist.
        let shstrtab_header = SECTION_TABLE + ELF64_SECTION_HEADER_SIZE;
        put_u64(&mut bytes, shstrtab_header + 32, names.len() as u64);
        bytes[SHSTRTAB_OFFSET..SHSTRTAB_OFFSET + names.len()].copy_from_slice(&names);
        bytes[NOTE_OFFSET..NOTE_OFFSET + notes.len()].copy_from_slice(&notes);
        for index in 0..pfns.len() {
            bytes[PAGES_OFFSET + index * 0x1000] = index as u8 + 1;
        }
        bytes
    }

    fn make_notes(page_count: u64, page_size: u64) -> Vec<u8> {
        let mut notes = Vec::new();
        append_note(&mut notes, XEN_ELFNOTE_DUMPCORE_NONE, &[]);
        let mut header = Vec::new();
        header.extend_from_slice(&XC_CORE_MAGIC_PV.to_le_bytes());
        header.extend_from_slice(&1u64.to_le_bytes());
        header.extend_from_slice(&page_count.to_le_bytes());
        header.extend_from_slice(&page_size.to_le_bytes());
        append_note(&mut notes, XEN_ELFNOTE_DUMPCORE_HEADER, &header);
        append_note(&mut notes, XEN_ELFNOTE_DUMPCORE_XEN_VERSION, &[1; 8]);
        append_note(
            &mut notes,
            XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION,
            &1u64.to_le_bytes(),
        );
        notes
    }

    fn append_note(notes: &mut Vec<u8>, kind: u32, description: &[u8]) {
        notes.extend_from_slice(&4u32.to_le_bytes());
        notes.extend_from_slice(&(description.len() as u32).to_le_bytes());
        notes.extend_from_slice(&kind.to_le_bytes());
        notes.extend_from_slice(b"Xen\0");
        notes.extend_from_slice(description);
        while !notes.len().is_multiple_of(4) {
            notes.push(0);
        }
    }

    fn find_note_description(notes: &[u8], wanted: u32) -> usize {
        let mut cursor = 0usize;
        loop {
            let name_size = read_u32(notes, cursor).unwrap() as usize;
            let description_size = read_u32(notes, cursor + 4).unwrap() as usize;
            let kind = read_u32(notes, cursor + 8).unwrap();
            cursor = (cursor + 12 + name_size + 3) & !3;
            if kind == wanted {
                return cursor;
            }
            cursor = (cursor + description_size + 3) & !3;
        }
    }

    fn append_name(names: &mut Vec<u8>, name: &[u8]) -> u32 {
        let offset = names.len() as u32;
        names.extend_from_slice(name);
        names.push(0);
        offset
    }

    fn put_section(
        bytes: &mut [u8],
        index: usize,
        name: u32,
        kind: u32,
        offset: u64,
        size: u64,
        entry_size: u64,
    ) {
        let start = ELF64_HEADER_SIZE + index * ELF64_SECTION_HEADER_SIZE;
        put_u32(bytes, start, name);
        put_u32(bytes, start + 4, kind);
        put_u64(bytes, start + 24, offset);
        put_u64(bytes, start + 32, size);
        put_u64(bytes, start + 48, 8);
        put_u64(bytes, start + 56, entry_size);
    }

    fn section_header_for(bytes: &[u8], name: &[u8]) -> usize {
        let (sections, names_index) =
            parse_section_headers(bytes, bytes.len() as u64, MAX_SECTION_HEADERS).unwrap();
        let names = parse_section_names(
            bytes,
            &sections,
            names_index,
            bytes.len() as u64,
            MAX_XEN_SECTION_NAME_BYTES,
        )
        .unwrap();
        ELF64_HEADER_SIZE
            + names
                .iter()
                .position(|candidate| *candidate == name)
                .unwrap()
                * ELF64_SECTION_HEADER_SIZE
    }

    fn rename_section(bytes: &mut [u8], old: &[u8], new: &[u8]) {
        assert_eq!(old.len(), new.len());
        let position = bytes
            .windows(old.len())
            .position(|window| window == old)
            .unwrap();
        bytes[position..position + old.len()].copy_from_slice(new);
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
