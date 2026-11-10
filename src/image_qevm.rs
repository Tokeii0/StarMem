//! Strict, read-only parser for the subset of QEMU migration streams that can
//! describe memory without decoding device state.
//!
//! This module intentionally does **not** turn a RAMBlock offset into a guest
//! physical address.  QEMU's migration RAM records identify a RAMBlock and an
//! offset within that block; machine-specific aliases (for example the PC PCI
//! hole) are needed to map that pair into guest physical space.  Callers must
//! perform that final mapping explicitly before constructing `PhysicalSpan`s.
//!
//! Protocol constants and layouts follow QEMU's `migration/savevm.h`,
//! `migration/savevm.c`, `migration/ram.h`, `migration/ram.c`, and
//! `scripts/analyze-migration.py`.  Automatic discovery is deliberately
//! conservative: it requires an exact file header, a terminal VMDESCRIPTION,
//! one `ram`/instance-0 declaration, RAM v4, and matching section footers.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::fmt;

use serde::Serialize;

pub const QEVM_FILE_MAGIC: u32 = 0x5145_564d;
pub const QEVM_FILE_VERSION: u32 = 3;
pub const QEVM_RAM_VERSION: u32 = 4;

pub const QEMU_VM_EOF: u8 = 0x00;
pub const QEMU_VM_SECTION_START: u8 = 0x01;
pub const QEMU_VM_SECTION_PART: u8 = 0x02;
pub const QEMU_VM_SECTION_END: u8 = 0x03;
pub const QEMU_VM_SECTION_FULL: u8 = 0x04;
pub const QEMU_VM_SUBSECTION: u8 = 0x05;
pub const QEMU_VM_VMDESCRIPTION: u8 = 0x06;
pub const QEMU_VM_CONFIGURATION: u8 = 0x07;
pub const QEMU_VM_COMMAND: u8 = 0x08;
pub const QEMU_VM_SECTION_FOOTER: u8 = 0x7e;

pub const RAM_SAVE_FLAG_ZERO: u64 = 0x002;
pub const RAM_SAVE_FLAG_MEM_SIZE: u64 = 0x004;
pub const RAM_SAVE_FLAG_PAGE: u64 = 0x008;
pub const RAM_SAVE_FLAG_EOS: u64 = 0x010;
pub const RAM_SAVE_FLAG_CONTINUE: u64 = 0x020;
pub const RAM_SAVE_FLAG_XBZRLE: u64 = 0x040;
pub const RAM_SAVE_FLAG_HOOK: u64 = 0x080;
/// Removed in QEMU 9.1, but retained here so old streams are rejected with a
/// precise error instead of being treated as an unknown bit.
pub const RAM_SAVE_FLAG_COMPRESS_PAGE: u64 = 0x100;
pub const RAM_SAVE_FLAG_MULTIFD_FLUSH: u64 = 0x200;

const KNOWN_RAM_FLAGS: u64 = RAM_SAVE_FLAG_ZERO
    | RAM_SAVE_FLAG_MEM_SIZE
    | RAM_SAVE_FLAG_PAGE
    | RAM_SAVE_FLAG_EOS
    | RAM_SAVE_FLAG_CONTINUE
    | RAM_SAVE_FLAG_XBZRLE
    | RAM_SAVE_FLAG_HOOK
    | RAM_SAVE_FLAG_COMPRESS_PAGE
    | RAM_SAVE_FLAG_MULTIFD_FLUSH;
const MIN_TARGET_PAGE_SIZE: u64 = 1024;
const MAX_TARGET_PAGE_SIZE: u64 = 1024 * 1024;
const MAX_RAM_BLOCKS: usize = 4096;
const MAX_CONFIGURATION_NAME: usize = 4096;
const MAX_CONFIGURATION_CAPABILITIES: usize = 4096;

/// Defensive limits for parser work and descriptor growth.  They are independent from the
/// source length so a sparse/repetitive adversarial stream cannot create an unbounded number of
/// page or section descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QevmParseLimits {
    pub max_vmdescription_bytes: usize,
    pub max_declared_ram_bytes: u64,
    pub max_ram_blocks: usize,
    pub max_ram_sections: usize,
    pub max_page_records: usize,
}

impl Default for QevmParseLimits {
    fn default() -> Self {
        Self {
            max_vmdescription_bytes: 16 * 1024 * 1024,
            max_declared_ram_bytes: 64 * 1024 * 1024 * 1024 * 1024,
            max_ram_blocks: MAX_RAM_BLOCKS,
            max_ram_sections: 1_000_000,
            max_page_records: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QevmMappingSource {
    /// Bytes live directly in the migration stream at `file_offset`.
    Direct { file_offset: u64 },
    /// The page is synthesized by repeating one byte.  Current QEMU emits and
    /// accepts only value zero for `RAM_SAVE_FLAG_ZERO`.
    RepeatedByte { value: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QevmRamMappingDescriptor {
    pub ram_block: String,
    pub block_offset: u64,
    pub length: u64,
    pub source: QevmMappingSource,
}

impl QevmRamMappingDescriptor {
    pub fn end(&self) -> Option<u64> {
        self.block_offset.checked_add(self.length)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QevmRamBlock {
    pub name: String,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QevmRamSection {
    pub marker: u8,
    pub file_offset: u64,
    pub end_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QevmParseResult {
    pub file_version: u32,
    pub ram_version: u32,
    pub page_size: u64,
    pub machine_name: Option<String>,
    pub section_id: u32,
    pub ram_blocks: Vec<QevmRamBlock>,
    pub mappings: Vec<QevmRamMappingDescriptor>,
    pub sections: Vec<QevmRamSection>,
    pub overwritten_pages: u64,
    pub eof_offset: u64,
    pub vmdescription_offset: u64,
}

impl QevmParseResult {
    /// Whether the RAMBlock namespace happens to contain exactly one block.
    /// This does *not* prove that its offsets equal guest physical addresses.
    pub fn has_single_ram_block(&self) -> bool {
        self.ram_blocks.len() == 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QevmErrorKind {
    NotQevm,
    UnsupportedFileVersion,
    MissingTerminalVmDescription,
    InvalidVmDescription,
    InvalidConfiguration,
    UnsupportedMappedRam,
    UnsupportedConfiguration,
    MissingRamSection,
    AmbiguousRamSection,
    UnsupportedRamVersion,
    InvalidRamSection,
    MissingSectionFooter,
    InvalidSectionFooter,
    UnsupportedXbzrle,
    UnsupportedCompressPage,
    UnsupportedHook,
    UnsupportedMultifd,
    UnknownRamFlags,
    LimitExceeded,
    OutOfBounds,
    Overlap,
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QevmParseError {
    pub kind: QevmErrorKind,
    pub offset: u64,
    pub message: String,
}

impl QevmParseError {
    fn new(kind: QevmErrorKind, offset: usize, message: impl Into<String>) -> Self {
        Self {
            kind,
            offset: offset as u64,
            message: message.into(),
        }
    }
}

impl fmt::Display for QevmParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (QEVM stream offset {:#x})",
            self.message, self.offset
        )
    }
}

impl Error for QevmParseError {}

pub type QevmResult<T> = Result<T, QevmParseError>;

#[derive(Debug)]
struct TerminalDescription {
    marker_offset: usize,
    eof_offset: usize,
    page_size: u64,
}

#[derive(Debug, Default)]
struct Configuration {
    end_offset: usize,
    machine_name: Option<String>,
    target_page_bits: Option<u32>,
    capabilities: Vec<String>,
}

#[derive(Debug, Clone)]
struct RamDeclaration {
    marker: u8,
    marker_offset: usize,
    payload_offset: usize,
    section_id: u32,
    instance_id: u32,
    version: u32,
}

#[derive(Debug)]
struct InitialSegment {
    blocks: Vec<QevmRamBlock>,
    end_offset: usize,
    pages: Vec<PageRecord>,
    last_block: Option<usize>,
}

#[derive(Debug, Clone)]
struct PageRecord {
    block_index: usize,
    block_offset: u64,
    source: QevmMappingSource,
}

#[derive(Debug)]
struct ParsedSegment {
    end_offset: usize,
    pages: Vec<PageRecord>,
    last_block: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
struct SegmentParseContext<'a> {
    bytes: &'a [u8],
    end: usize,
    section_id: u32,
    page_size: u64,
    blocks: &'a [QevmRamBlock],
    block_indices: &'a HashMap<String, usize>,
    limits: &'a QevmParseLimits,
}

/// Parses a complete QEVM migration stream using the fail-closed v0.4 subset.
///
/// Supported RAM payloads are raw `PAGE` records and zero-filled `ZERO`
/// records.  XBZRLE, mapped-ram, the removed compressed-page encoding, RDMA
/// hooks, multifd flush records, unknown flags, footerless sections, and
/// unknown versions are rejected.
pub fn parse_qevm(bytes: &[u8]) -> QevmResult<QevmParseResult> {
    parse_qevm_with_limits(bytes, QevmParseLimits::default())
}

pub fn parse_qevm_with_limits(
    bytes: &[u8],
    limits: QevmParseLimits,
) -> QevmResult<QevmParseResult> {
    if limits.max_vmdescription_bytes == 0
        || limits.max_declared_ram_bytes == 0
        || limits.max_ram_blocks == 0
        || limits.max_ram_sections == 0
        || limits.max_page_records == 0
    {
        return Err(QevmParseError::new(
            QevmErrorKind::LimitExceeded,
            0,
            "all QEVM parser limits must be non-zero",
        ));
    }
    let mut header = Cursor::new(bytes, 0);
    let magic = header.be_u32()?;
    if magic != QEVM_FILE_MAGIC {
        return Err(QevmParseError::new(
            QevmErrorKind::NotQevm,
            0,
            format!("not a QEMU migration stream: magic {magic:#010x}"),
        ));
    }
    let version_offset = header.position();
    let file_version = header.be_u32()?;
    if file_version != QEVM_FILE_VERSION {
        return Err(QevmParseError::new(
            QevmErrorKind::UnsupportedFileVersion,
            version_offset,
            format!(
                "unsupported QEMU migration file version {file_version}; expected {QEVM_FILE_VERSION}"
            ),
        ));
    }

    let terminal = parse_terminal_description(bytes, limits.max_vmdescription_bytes)?;
    validate_page_size(terminal.page_size, terminal.marker_offset)?;
    let configuration = parse_configuration(bytes, header.position(), terminal.eof_offset)?;
    if let Some(bits) = configuration.target_page_bits {
        let configured = 1_u64.checked_shl(bits).ok_or_else(|| {
            QevmParseError::new(
                QevmErrorKind::InvalidConfiguration,
                configuration.end_offset,
                format!("configuration target-page-bits {bits} overflows"),
            )
        })?;
        if configured != terminal.page_size {
            return Err(QevmParseError::new(
                QevmErrorKind::InvalidConfiguration,
                configuration.end_offset,
                format!(
                    "configuration page size {configured} disagrees with VMDESCRIPTION page size {}",
                    terminal.page_size
                ),
            ));
        }
    }
    if configuration
        .capabilities
        .iter()
        .any(|capability| capability == "mapped-ram")
    {
        return Err(QevmParseError::new(
            QevmErrorKind::UnsupportedMappedRam,
            configuration.end_offset,
            "mapped-ram migration streams are not supported",
        ));
    }
    if let Some(capability) = configuration
        .capabilities
        .iter()
        .find(|capability| capability.as_str() == "x-ignore-shared")
    {
        return Err(QevmParseError::new(
            QevmErrorKind::UnsupportedConfiguration,
            configuration.end_offset,
            format!("unsupported migration capability {capability}"),
        ));
    }

    let declarations = find_ram_declarations(bytes, configuration.end_offset, terminal.eof_offset)?;
    if declarations.is_empty() {
        return Err(QevmParseError::new(
            QevmErrorKind::MissingRamSection,
            configuration.end_offset,
            "no ram/instance-0 section declaration found",
        ));
    }
    if declarations.len() != 1 {
        return Err(QevmParseError::new(
            QevmErrorKind::AmbiguousRamSection,
            declarations[1].marker_offset,
            format!(
                "found {} RAM section declarations; automatic selection requires exactly one",
                declarations.len()
            ),
        ));
    }
    let declaration = &declarations[0];
    if declaration.instance_id != 0 {
        return Err(QevmParseError::new(
            QevmErrorKind::InvalidRamSection,
            declaration.marker_offset,
            format!(
                "RAM section instance {} is not the required instance 0",
                declaration.instance_id
            ),
        ));
    }
    if declaration.version != QEVM_RAM_VERSION {
        return Err(QevmParseError::new(
            QevmErrorKind::UnsupportedRamVersion,
            declaration.marker_offset,
            format!(
                "unsupported RAM section version {}; expected {QEVM_RAM_VERSION}",
                declaration.version
            ),
        ));
    }

    let mut page_records = 0_usize;
    let initial = parse_initial_segment(
        bytes,
        declaration,
        terminal.page_size,
        terminal.eof_offset,
        &limits,
        &mut page_records,
    )?;
    let mut sections = vec![QevmRamSection {
        marker: declaration.marker,
        file_offset: declaration.marker_offset as u64,
        end_offset: initial.end_offset as u64,
    }];
    let block_indices: HashMap<String, usize> = initial
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.name.clone(), index))
        .collect();
    let mut pages: BTreeMap<(usize, u64), QevmMappingSource> = BTreeMap::new();
    let mut overwritten_pages = 0_u64;
    for record in &initial.pages {
        if pages
            .insert(
                (record.block_index, record.block_offset),
                record.source.clone(),
            )
            .is_some()
        {
            overwritten_pages = overwritten_pages.checked_add(1).ok_or_else(|| {
                QevmParseError::new(
                    QevmErrorKind::OutOfBounds,
                    declaration.marker_offset,
                    "overwritten page counter overflows",
                )
            })?;
        }
    }
    let mut last_block = initial.last_block;

    if declaration.marker == QEMU_VM_SECTION_START {
        let context = SegmentParseContext {
            bytes,
            end: terminal.eof_offset,
            section_id: declaration.section_id,
            page_size: terminal.page_size,
            blocks: &initial.blocks,
            block_indices: &block_indices,
            limits: &limits,
        };
        let parsed = parse_following_segments(
            context,
            initial.end_offset,
            &mut last_block,
            &mut page_records,
        )?;
        for (section, records) in parsed {
            let section_offset = section.file_offset;
            sections.push(section);
            for record in records {
                if pages
                    .insert((record.block_index, record.block_offset), record.source)
                    .is_some()
                {
                    overwritten_pages = overwritten_pages.checked_add(1).ok_or_else(|| {
                        QevmParseError::new(
                            QevmErrorKind::OutOfBounds,
                            usize::try_from(section_offset).unwrap_or(usize::MAX),
                            "overwritten page counter overflows",
                        )
                    })?;
                }
            }
        }
        if !sections
            .iter()
            .any(|section| section.marker == QEMU_VM_SECTION_END)
        {
            return Err(QevmParseError::new(
                QevmErrorKind::InvalidRamSection,
                initial.end_offset,
                "RAM START section has no validated END section",
            ));
        }
    } else {
        // FULL sections may carry page records after MEM_SIZE.  A later
        // PART/END for the same id would make the stream ambiguous.
        if find_section_reference(
            bytes,
            initial.end_offset,
            terminal.eof_offset,
            declaration.section_id,
        )
        .is_some()
        {
            return Err(QevmParseError::new(
                QevmErrorKind::AmbiguousRamSection,
                initial.end_offset,
                "RAM FULL section is followed by PART/END records for the same section id",
            ));
        }
    }

    let mappings = coalesce_pages(&initial.blocks, terminal.page_size, pages)?;
    validate_mapping_bounds(&initial.blocks, &mappings)?;

    Ok(QevmParseResult {
        file_version,
        ram_version: declaration.version,
        page_size: terminal.page_size,
        machine_name: configuration.machine_name,
        section_id: declaration.section_id,
        ram_blocks: initial.blocks,
        mappings,
        sections,
        overwritten_pages,
        eof_offset: terminal.eof_offset as u64,
        vmdescription_offset: terminal.marker_offset as u64,
    })
}

fn parse_terminal_description(
    bytes: &[u8],
    max_description_bytes: usize,
) -> QevmResult<TerminalDescription> {
    let mut candidates = Vec::new();
    let mut oversized_terminal = None;
    for marker_offset in 9..bytes.len().saturating_sub(5) {
        if bytes[marker_offset] != QEMU_VM_VMDESCRIPTION || bytes[marker_offset - 1] != QEMU_VM_EOF
        {
            continue;
        }
        let Some(length_bytes) = bytes.get(marker_offset + 1..marker_offset + 5) else {
            continue;
        };
        let length = u32::from_be_bytes(length_bytes.try_into().expect("four-byte slice")) as usize;
        let Some(json_end) = marker_offset
            .checked_add(5)
            .and_then(|start| start.checked_add(length))
        else {
            continue;
        };
        if json_end != bytes.len() {
            continue;
        }
        if length > max_description_bytes {
            oversized_terminal = Some((marker_offset, length));
            continue;
        }
        let json_bytes = &bytes[marker_offset + 5..json_end];
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(json_bytes) else {
            continue;
        };
        let Some(page_size) = value.get("page_size").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let devices_valid = value
            .get("devices")
            .is_some_and(serde_json::Value::is_array);
        if !devices_valid {
            continue;
        }
        candidates.push(TerminalDescription {
            marker_offset,
            eof_offset: marker_offset - 1,
            page_size,
        });
        if candidates.len() > 1 {
            return Err(QevmParseError::new(
                QevmErrorKind::InvalidVmDescription,
                marker_offset,
                "found more than one terminal VMDESCRIPTION candidate",
            ));
        }
    }

    match candidates.len() {
        1 => Ok(candidates.remove(0)),
        0 if oversized_terminal.is_some() => {
            let (offset, length) = oversized_terminal.expect("checked above");
            Err(QevmParseError::new(
                QevmErrorKind::LimitExceeded,
                offset,
                format!(
                    "terminal VMDESCRIPTION length {length} exceeds safety limit {max_description_bytes}"
                ),
            ))
        }
        0 => Err(QevmParseError::new(
            QevmErrorKind::MissingTerminalVmDescription,
            bytes.len().saturating_sub(1),
            "missing exact terminal EOF + VMDESCRIPTION record",
        )),
        count => Err(QevmParseError::new(
            QevmErrorKind::InvalidVmDescription,
            candidates[1].marker_offset,
            format!("found {count} terminal VMDESCRIPTION candidates"),
        )),
    }
}

fn validate_page_size(page_size: u64, offset: usize) -> QevmResult<()> {
    if !page_size.is_power_of_two()
        || !(MIN_TARGET_PAGE_SIZE..=MAX_TARGET_PAGE_SIZE).contains(&page_size)
    {
        return Err(QevmParseError::new(
            QevmErrorKind::InvalidVmDescription,
            offset,
            format!("invalid target page size {page_size}"),
        ));
    }
    Ok(())
}

fn parse_configuration(bytes: &[u8], start: usize, end: usize) -> QevmResult<Configuration> {
    if bytes.get(start).copied() != Some(QEMU_VM_CONFIGURATION) {
        return Ok(Configuration {
            end_offset: start,
            ..Configuration::default()
        });
    }

    let payload_start = start.checked_add(1).ok_or_else(|| {
        QevmParseError::new(
            QevmErrorKind::OutOfBounds,
            start,
            "configuration payload offset overflows",
        )
    })?;
    let mut cursor = Cursor::bounded(bytes, payload_start, end)?;
    let machine_length_offset = cursor.position();
    let machine_length = usize::try_from(cursor.be_u32()?).map_err(|_| {
        QevmParseError::new(
            QevmErrorKind::InvalidConfiguration,
            machine_length_offset,
            "configuration machine-name length does not fit usize",
        )
    })?;
    if machine_length == 0 || machine_length > MAX_CONFIGURATION_NAME {
        return Err(QevmParseError::new(
            QevmErrorKind::InvalidConfiguration,
            machine_length_offset,
            format!("invalid configuration machine-name length {machine_length}"),
        ));
    }
    let machine_name = read_utf8(&mut cursor, machine_length, "configuration machine name")?;
    let mut configuration = Configuration {
        machine_name: Some(machine_name),
        ..Configuration::default()
    };
    let mut seen = HashSet::new();

    while cursor.peek() == Some(QEMU_VM_SUBSECTION) {
        let subsection_offset = cursor.position();
        cursor.u8()?;
        let name = cursor.counted_utf8("configuration subsection name")?;
        let version = cursor.be_u32()?;
        if !seen.insert(name.clone()) {
            return Err(QevmParseError::new(
                QevmErrorKind::InvalidConfiguration,
                subsection_offset,
                format!("duplicate configuration subsection {name}"),
            ));
        }
        if version != 1 {
            return Err(QevmParseError::new(
                QevmErrorKind::UnsupportedConfiguration,
                subsection_offset,
                format!("unsupported {name} subsection version {version}"),
            ));
        }
        match name.as_str() {
            "configuration/target-page-bits" => {
                configuration.target_page_bits = Some(cursor.be_u32()?);
            }
            "configuration/capabilities" => {
                let count_offset = cursor.position();
                let count = usize::try_from(cursor.be_u32()?).map_err(|_| {
                    QevmParseError::new(
                        QevmErrorKind::InvalidConfiguration,
                        count_offset,
                        "configuration capability count does not fit usize",
                    )
                })?;
                if count > MAX_CONFIGURATION_CAPABILITIES {
                    return Err(QevmParseError::new(
                        QevmErrorKind::InvalidConfiguration,
                        count_offset,
                        format!("configuration capability count {count} exceeds safety limit"),
                    ));
                }
                for _ in 0..count {
                    configuration
                        .capabilities
                        .push(cursor.counted_utf8("migration capability")?);
                }
            }
            "configuration/uuid" => {
                cursor.take(16, "configuration UUID")?;
            }
            _ => {
                return Err(QevmParseError::new(
                    QevmErrorKind::UnsupportedConfiguration,
                    subsection_offset,
                    format!("unsupported configuration subsection {name}"),
                ));
            }
        }
    }
    configuration.end_offset = cursor.position();
    Ok(configuration)
}

fn find_ram_declarations(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> QevmResult<Vec<RamDeclaration>> {
    let mut declarations = Vec::new();
    let mut offset = start;
    while offset < end {
        let marker = bytes[offset];
        if marker != QEMU_VM_SECTION_START && marker != QEMU_VM_SECTION_FULL {
            offset += 1;
            continue;
        }
        let mut cursor = Cursor::bounded(bytes, offset + 1, end)?;
        let header = (|| -> QevmResult<Option<RamDeclaration>> {
            let section_id = cursor.be_u32()?;
            let name = cursor.counted_utf8("section name")?;
            let instance_id = cursor.be_u32()?;
            let version = cursor.be_u32()?;
            if name != "ram" {
                return Ok(None);
            }
            Ok(Some(RamDeclaration {
                marker,
                marker_offset: offset,
                payload_offset: cursor.position(),
                section_id,
                instance_id,
                version,
            }))
        })();
        if let Ok(Some(declaration)) = header {
            declarations.push(declaration);
            if declarations.len() > 1 {
                return Err(QevmParseError::new(
                    QevmErrorKind::AmbiguousRamSection,
                    offset,
                    "found more than one RAM section declaration",
                ));
            }
        }
        offset += 1;
    }
    Ok(declarations)
}

fn parse_initial_segment(
    bytes: &[u8],
    declaration: &RamDeclaration,
    page_size: u64,
    end: usize,
    limits: &QevmParseLimits,
    page_records: &mut usize,
) -> QevmResult<InitialSegment> {
    let mut cursor = Cursor::bounded(bytes, declaration.payload_offset, end)?;
    let record_offset = cursor.position();
    let word = cursor.be_u64()?;
    let flags = word & (page_size - 1);
    let total_length = word & !(page_size - 1);
    validate_known_flags(flags, record_offset)?;
    if flags != RAM_SAVE_FLAG_MEM_SIZE {
        return Err(QevmParseError::new(
            classify_unsupported_flag(flags).unwrap_or(QevmErrorKind::InvalidRamSection),
            record_offset,
            format!("RAM setup must start with MEM_SIZE, found flags {flags:#x}"),
        ));
    }
    if total_length == 0 || !total_length.is_multiple_of(page_size) {
        return Err(QevmParseError::new(
            QevmErrorKind::InvalidRamSection,
            record_offset,
            format!("invalid total RAM length {total_length:#x}"),
        ));
    }
    if total_length > limits.max_declared_ram_bytes {
        return Err(QevmParseError::new(
            QevmErrorKind::LimitExceeded,
            record_offset,
            format!(
                "declared RAM length {total_length:#x} exceeds safety limit {:#x}",
                limits.max_declared_ram_bytes
            ),
        ));
    }

    let mut remaining = total_length;
    let mut blocks = Vec::new();
    let mut names = HashSet::new();
    while remaining != 0 {
        if blocks.len() >= limits.max_ram_blocks {
            return Err(QevmParseError::new(
                QevmErrorKind::LimitExceeded,
                cursor.position(),
                "RAM block count exceeds safety limit",
            ));
        }
        if cursor.peek() == Some(0)
            && looks_like_mapped_ram_header(bytes, cursor.position(), end, page_size)
        {
            return Err(QevmParseError::new(
                QevmErrorKind::UnsupportedMappedRam,
                cursor.position(),
                "mapped-ram header found in RAM block table",
            ));
        }
        let name_offset = cursor.position();
        let name = cursor.counted_utf8("RAMBlock name")?;
        validate_ram_block_name(&name, name_offset)?;
        if !names.insert(name.clone()) {
            return Err(QevmParseError::new(
                QevmErrorKind::InvalidRamSection,
                name_offset,
                format!("duplicate RAMBlock name {name}"),
            ));
        }
        let length_offset = cursor.position();
        let length = cursor.be_u64()?;
        if length == 0 || !length.is_multiple_of(page_size) || length > remaining {
            return Err(QevmParseError::new(
                QevmErrorKind::InvalidRamSection,
                length_offset,
                format!(
                    "RAMBlock {name} length {length:#x} is zero, unaligned, or exceeds remaining total {remaining:#x}"
                ),
            ));
        }
        remaining -= length;
        blocks.push(QevmRamBlock { name, length });
    }
    if blocks.is_empty() {
        return Err(QevmParseError::new(
            QevmErrorKind::InvalidRamSection,
            record_offset,
            "RAM setup contains no blocks",
        ));
    }
    if looks_like_mapped_ram_header(bytes, cursor.position(), end, page_size) {
        return Err(QevmParseError::new(
            QevmErrorKind::UnsupportedMappedRam,
            cursor.position(),
            "mapped-ram header found after RAM block table",
        ));
    }

    let block_indices: HashMap<String, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.name.clone(), index))
        .collect();
    let mut last_block = None;
    let context = SegmentParseContext {
        bytes,
        end,
        section_id: declaration.section_id,
        page_size,
        blocks: &blocks,
        block_indices: &block_indices,
        limits,
    };
    let segment = parse_page_segment(context, cursor.position(), &mut last_block, page_records)?;
    Ok(InitialSegment {
        blocks,
        end_offset: segment.end_offset,
        pages: segment.pages,
        last_block: segment.last_block,
    })
}

fn parse_following_segments(
    context: SegmentParseContext<'_>,
    start: usize,
    last_block: &mut Option<usize>,
    page_records: &mut usize,
) -> QevmResult<Vec<(QevmRamSection, Vec<PageRecord>)>> {
    let mut parsed_sections = Vec::new();
    let mut search = start;
    let mut saw_end = false;

    while let Some(marker_offset) =
        find_section_reference(context.bytes, search, context.end, context.section_id)
    {
        if parsed_sections.len().saturating_add(1) >= context.limits.max_ram_sections {
            return Err(QevmParseError::new(
                QevmErrorKind::LimitExceeded,
                marker_offset,
                format!(
                    "RAM section count exceeds safety limit {}",
                    context.limits.max_ram_sections
                ),
            ));
        }
        let marker = context.bytes[marker_offset];
        if saw_end {
            return Err(QevmParseError::new(
                QevmErrorKind::AmbiguousRamSection,
                marker_offset,
                "RAM PART/END record appears after the validated END section",
            ));
        }
        let mut trial_last_block = *last_block;
        let mut trial_page_records = *page_records;
        match parse_page_segment(
            context,
            marker_offset + 5,
            &mut trial_last_block,
            &mut trial_page_records,
        ) {
            Ok(segment) => {
                *last_block = segment.last_block;
                *page_records = trial_page_records;
                let section = QevmRamSection {
                    marker,
                    file_offset: marker_offset as u64,
                    end_offset: segment.end_offset as u64,
                };
                if marker == QEMU_VM_SECTION_END {
                    saw_end = true;
                }
                search = segment.end_offset;
                parsed_sections.push((section, segment.pages));
            }
            Err(error) => {
                // A matching 32-bit section id inside unrelated device bytes
                // is possible.  Fail closed once the payload proves RAM
                // semantics; otherwise continue searching for a fully framed
                // record and matching footer.
                if is_high_confidence_segment_error(&error) {
                    return Err(error);
                }
                search = marker_offset + 1;
            }
        }
    }

    if !saw_end {
        return Err(QevmParseError::new(
            QevmErrorKind::InvalidRamSection,
            start,
            "could not locate a uniquely validated RAM END section",
        ));
    }
    Ok(parsed_sections)
}

fn find_section_reference(
    bytes: &[u8],
    start: usize,
    end: usize,
    section_id: u32,
) -> Option<usize> {
    let id = section_id.to_be_bytes();
    let mut offset = start;
    while offset.checked_add(5)? <= end {
        let marker = bytes[offset];
        if (marker == QEMU_VM_SECTION_PART || marker == QEMU_VM_SECTION_END)
            && bytes.get(offset + 1..offset + 5) == Some(id.as_slice())
        {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

fn parse_page_segment(
    context: SegmentParseContext<'_>,
    payload_offset: usize,
    last_block: &mut Option<usize>,
    page_records: &mut usize,
) -> QevmResult<ParsedSegment> {
    let mut cursor = Cursor::bounded(context.bytes, payload_offset, context.end)?;
    let mut pages = Vec::new();
    loop {
        let record_offset = cursor.position();
        let word = cursor.be_u64()?;
        let flags = word & (context.page_size - 1);
        let block_offset = word & !(context.page_size - 1);
        validate_known_flags(flags, record_offset)?;

        if let Some(kind) = classify_unsupported_flag(flags) {
            return Err(QevmParseError::new(
                kind,
                record_offset,
                format!("unsupported RAM flags {flags:#x}"),
            ));
        }

        let primary = flags
            & (RAM_SAVE_FLAG_ZERO
                | RAM_SAVE_FLAG_MEM_SIZE
                | RAM_SAVE_FLAG_PAGE
                | RAM_SAVE_FLAG_EOS);
        if primary.count_ones() != 1 {
            return Err(QevmParseError::new(
                QevmErrorKind::UnknownRamFlags,
                record_offset,
                format!("invalid RAM flag combination {flags:#x}"),
            ));
        }
        if primary == RAM_SAVE_FLAG_EOS {
            if flags != RAM_SAVE_FLAG_EOS || block_offset != 0 {
                return Err(QevmParseError::new(
                    QevmErrorKind::UnknownRamFlags,
                    record_offset,
                    format!("EOS must be encoded as the exact word {RAM_SAVE_FLAG_EOS:#x}"),
                ));
            }
            let end_offset = validate_footer(&mut cursor, context.section_id)?;
            return Ok(ParsedSegment {
                end_offset,
                pages,
                last_block: *last_block,
            });
        }
        if primary == RAM_SAVE_FLAG_MEM_SIZE {
            return Err(QevmParseError::new(
                QevmErrorKind::InvalidRamSection,
                record_offset,
                "MEM_SIZE is only valid in the initial RAM setup section",
            ));
        }

        let block_index = if flags & RAM_SAVE_FLAG_CONTINUE != 0 {
            (*last_block).ok_or_else(|| {
                QevmParseError::new(
                    QevmErrorKind::InvalidRamSection,
                    record_offset,
                    "RAM CONTINUE record has no preceding RAMBlock",
                )
            })?
        } else {
            let name_offset = cursor.position();
            let name = cursor.counted_utf8("RAM page block name")?;
            let index = context.block_indices.get(&name).copied().ok_or_else(|| {
                QevmParseError::new(
                    QevmErrorKind::InvalidRamSection,
                    name_offset,
                    format!("RAM page references undeclared RAMBlock {name}"),
                )
            })?;
            *last_block = Some(index);
            index
        };
        let block = &context.blocks[block_index];
        let page_end = block_offset.checked_add(context.page_size).ok_or_else(|| {
            QevmParseError::new(
                QevmErrorKind::OutOfBounds,
                record_offset,
                "RAM page offset overflows",
            )
        })?;
        if page_end > block.length {
            return Err(QevmParseError::new(
                QevmErrorKind::OutOfBounds,
                record_offset,
                format!(
                    "RAM page [{block_offset:#x}, {page_end:#x}) exceeds block {} length {:#x}",
                    block.name, block.length
                ),
            ));
        }

        let source = if primary == RAM_SAVE_FLAG_PAGE {
            let file_offset = cursor.position();
            let page_length = usize::try_from(context.page_size).map_err(|_| {
                QevmParseError::new(
                    QevmErrorKind::OutOfBounds,
                    file_offset,
                    "target page size does not fit usize",
                )
            })?;
            cursor.take(page_length, "raw RAM page")?;
            QevmMappingSource::Direct {
                file_offset: file_offset as u64,
            }
        } else {
            let value_offset = cursor.position();
            let value = cursor.u8()?;
            if value != 0 {
                return Err(QevmParseError::new(
                    QevmErrorKind::InvalidRamSection,
                    value_offset,
                    format!("RAM ZERO record contains non-zero fill byte {value:#04x}"),
                ));
            }
            QevmMappingSource::RepeatedByte { value }
        };
        if *page_records >= context.limits.max_page_records {
            return Err(QevmParseError::new(
                QevmErrorKind::LimitExceeded,
                record_offset,
                format!(
                    "RAM page record count exceeds safety limit {}",
                    context.limits.max_page_records
                ),
            ));
        }
        *page_records += 1;
        pages.push(PageRecord {
            block_index,
            block_offset,
            source,
        });
    }
}

fn validate_footer(cursor: &mut Cursor<'_>, section_id: u32) -> QevmResult<usize> {
    let footer_offset = cursor.position();
    let marker = cursor.u8().map_err(|mut error| {
        error.kind = QevmErrorKind::MissingSectionFooter;
        error.message = "RAM section is missing its footer".to_owned();
        error
    })?;
    if marker != QEMU_VM_SECTION_FOOTER {
        return Err(QevmParseError::new(
            QevmErrorKind::MissingSectionFooter,
            footer_offset,
            format!(
                "RAM section footer marker {QEMU_VM_SECTION_FOOTER:#04x} not found (got {marker:#04x})"
            ),
        ));
    }
    let read_id = cursor.be_u32()?;
    if read_id != section_id {
        return Err(QevmParseError::new(
            QevmErrorKind::InvalidSectionFooter,
            footer_offset,
            format!("RAM section footer id {read_id} does not match {section_id}"),
        ));
    }
    Ok(cursor.position())
}

fn validate_known_flags(flags: u64, offset: usize) -> QevmResult<()> {
    let unknown = flags & !KNOWN_RAM_FLAGS;
    if unknown != 0 {
        return Err(QevmParseError::new(
            QevmErrorKind::UnknownRamFlags,
            offset,
            format!("unknown RAM flag bits {unknown:#x} in {flags:#x}"),
        ));
    }
    Ok(())
}

fn classify_unsupported_flag(flags: u64) -> Option<QevmErrorKind> {
    if flags & RAM_SAVE_FLAG_XBZRLE != 0 {
        Some(QevmErrorKind::UnsupportedXbzrle)
    } else if flags & RAM_SAVE_FLAG_COMPRESS_PAGE != 0 {
        Some(QevmErrorKind::UnsupportedCompressPage)
    } else if flags & RAM_SAVE_FLAG_HOOK != 0 {
        Some(QevmErrorKind::UnsupportedHook)
    } else if flags & RAM_SAVE_FLAG_MULTIFD_FLUSH != 0 {
        Some(QevmErrorKind::UnsupportedMultifd)
    } else {
        None
    }
}

fn is_high_confidence_segment_error(error: &QevmParseError) -> bool {
    matches!(
        error.kind,
        QevmErrorKind::UnsupportedXbzrle
            | QevmErrorKind::UnsupportedCompressPage
            | QevmErrorKind::UnsupportedHook
            | QevmErrorKind::UnsupportedMultifd
            | QevmErrorKind::UnknownRamFlags
            | QevmErrorKind::LimitExceeded
            | QevmErrorKind::OutOfBounds
            | QevmErrorKind::InvalidSectionFooter
            | QevmErrorKind::Truncated
    )
}

fn validate_ram_block_name(name: &str, offset: usize) -> QevmResult<()> {
    if name.is_empty()
        || name
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(QevmParseError::new(
            QevmErrorKind::InvalidRamSection,
            offset,
            "RAMBlock name is empty or contains control bytes",
        ));
    }
    Ok(())
}

fn looks_like_mapped_ram_header(bytes: &[u8], offset: usize, end: usize, page_size: u64) -> bool {
    let Some(header_end) = offset
        .checked_add(28)
        .filter(|header_end| *header_end <= end)
    else {
        return false;
    };
    let Some(header) = bytes.get(offset..header_end) else {
        return false;
    };
    u32::from_be_bytes(header[0..4].try_into().expect("four-byte slice")) == 1
        && u64::from_be_bytes(header[4..12].try_into().expect("eight-byte slice")) == page_size
}

fn coalesce_pages(
    blocks: &[QevmRamBlock],
    page_size: u64,
    pages: BTreeMap<(usize, u64), QevmMappingSource>,
) -> QevmResult<Vec<QevmRamMappingDescriptor>> {
    let mut mappings: Vec<QevmRamMappingDescriptor> = Vec::new();
    for ((block_index, block_offset), source) in pages {
        let block = blocks.get(block_index).ok_or_else(|| {
            QevmParseError::new(
                QevmErrorKind::InvalidRamSection,
                0,
                "internal RAMBlock index is invalid",
            )
        })?;
        if let Some(previous) = mappings.last_mut() {
            let adjacent = previous.ram_block == block.name
                && previous.end() == Some(block_offset)
                && sources_are_contiguous(&previous.source, previous.length, &source);
            if adjacent {
                previous.length = previous.length.checked_add(page_size).ok_or_else(|| {
                    QevmParseError::new(
                        QevmErrorKind::OutOfBounds,
                        0,
                        "coalesced RAM mapping length overflows",
                    )
                })?;
                continue;
            }
        }
        mappings.push(QevmRamMappingDescriptor {
            ram_block: block.name.clone(),
            block_offset,
            length: page_size,
            source,
        });
    }
    Ok(mappings)
}

fn sources_are_contiguous(
    previous: &QevmMappingSource,
    previous_length: u64,
    next: &QevmMappingSource,
) -> bool {
    match (previous, next) {
        (
            QevmMappingSource::Direct {
                file_offset: previous_offset,
            },
            QevmMappingSource::Direct {
                file_offset: next_offset,
            },
        ) => previous_offset.checked_add(previous_length) == Some(*next_offset),
        (
            QevmMappingSource::RepeatedByte { value: previous },
            QevmMappingSource::RepeatedByte { value: next },
        ) => previous == next,
        _ => false,
    }
}

fn validate_mapping_bounds(
    blocks: &[QevmRamBlock],
    mappings: &[QevmRamMappingDescriptor],
) -> QevmResult<()> {
    let block_lengths: HashMap<&str, u64> = blocks
        .iter()
        .map(|block| (block.name.as_str(), block.length))
        .collect();
    let mut previous: HashMap<&str, u64> = HashMap::new();
    for mapping in mappings {
        let end = mapping.end().ok_or_else(|| {
            QevmParseError::new(
                QevmErrorKind::OutOfBounds,
                0,
                format!("mapping in {} overflows", mapping.ram_block),
            )
        })?;
        let block_length = block_lengths
            .get(mapping.ram_block.as_str())
            .copied()
            .ok_or_else(|| {
                QevmParseError::new(
                    QevmErrorKind::InvalidRamSection,
                    0,
                    format!("mapping references unknown block {}", mapping.ram_block),
                )
            })?;
        if end > block_length {
            return Err(QevmParseError::new(
                QevmErrorKind::OutOfBounds,
                0,
                format!("mapping exceeds block {}", mapping.ram_block),
            ));
        }
        if previous
            .insert(mapping.ram_block.as_str(), end)
            .is_some_and(|previous_end| previous_end > mapping.block_offset)
        {
            return Err(QevmParseError::new(
                QevmErrorKind::Overlap,
                0,
                format!("mappings overlap in block {}", mapping.ram_block),
            ));
        }
    }
    Ok(())
}

fn read_utf8(cursor: &mut Cursor<'_>, length: usize, what: &str) -> QevmResult<String> {
    let offset = cursor.position();
    let bytes = cursor.take(length, what)?;
    let value = std::str::from_utf8(bytes).map_err(|error| {
        QevmParseError::new(
            QevmErrorKind::InvalidRamSection,
            offset,
            format!("{what} is not UTF-8: {error}"),
        )
    })?;
    Ok(value.to_owned())
}

#[derive(Debug, Clone, Copy)]
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], position: usize) -> Self {
        Self {
            bytes,
            position,
            end: bytes.len(),
        }
    }

    fn bounded(bytes: &'a [u8], position: usize, end: usize) -> QevmResult<Self> {
        if position > end || end > bytes.len() {
            return Err(QevmParseError::new(
                QevmErrorKind::OutOfBounds,
                position,
                "invalid parser bounds",
            ));
        }
        Ok(Self {
            bytes,
            position,
            end,
        })
    }

    fn position(&self) -> usize {
        self.position
    }

    fn peek(&self) -> Option<u8> {
        (self.position < self.end).then(|| self.bytes[self.position])
    }

    fn take(&mut self, length: usize, what: &str) -> QevmResult<&'a [u8]> {
        let start = self.position;
        let end = start.checked_add(length).ok_or_else(|| {
            QevmParseError::new(
                QevmErrorKind::OutOfBounds,
                start,
                format!("{what} range overflows"),
            )
        })?;
        if end > self.end {
            return Err(QevmParseError::new(
                QevmErrorKind::Truncated,
                start,
                format!("truncated {what}: need {length} bytes"),
            ));
        }
        self.position = end;
        Ok(&self.bytes[start..end])
    }

    fn u8(&mut self) -> QevmResult<u8> {
        Ok(self.take(1, "byte")?[0])
    }

    fn be_u32(&mut self) -> QevmResult<u32> {
        Ok(u32::from_be_bytes(
            self.take(4, "big-endian u32")?
                .try_into()
                .expect("four-byte slice"),
        ))
    }

    fn be_u64(&mut self) -> QevmResult<u64> {
        Ok(u64::from_be_bytes(
            self.take(8, "big-endian u64")?
                .try_into()
                .expect("eight-byte slice"),
        ))
    }

    fn counted_utf8(&mut self, what: &str) -> QevmResult<String> {
        let length = usize::from(self.u8()?);
        read_utf8(self, length, what)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_SIZE: u64 = 4096;
    const SECTION_ID: u32 = 7;

    #[derive(Clone)]
    enum TestRecord {
        Page {
            offset: u64,
            continue_block: bool,
            byte: u8,
        },
        Zero {
            offset: u64,
            continue_block: bool,
            value: u8,
        },
        Flag(u64),
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_counted(out: &mut Vec<u8>, value: &str) {
        out.push(u8::try_from(value.len()).unwrap());
        out.extend_from_slice(value.as_bytes());
    }

    fn push_header(out: &mut Vec<u8>, file_version: u32) {
        push_u32(out, QEVM_FILE_MAGIC);
        push_u32(out, file_version);
    }

    fn push_ram_start(out: &mut Vec<u8>, section_id: u32, ram_version: u32) {
        out.push(QEMU_VM_SECTION_START);
        push_u32(out, section_id);
        push_counted(out, "ram");
        push_u32(out, 0);
        push_u32(out, ram_version);
        push_u64(out, (2 * PAGE_SIZE) | RAM_SAVE_FLAG_MEM_SIZE);
        push_counted(out, "pc.ram");
        push_u64(out, 2 * PAGE_SIZE);
        push_u64(out, RAM_SAVE_FLAG_EOS);
        push_footer(out, section_id);
    }

    fn push_footer(out: &mut Vec<u8>, section_id: u32) {
        out.push(QEMU_VM_SECTION_FOOTER);
        push_u32(out, section_id);
    }

    fn push_segment(out: &mut Vec<u8>, marker: u8, section_id: u32, records: &[TestRecord]) {
        out.push(marker);
        push_u32(out, section_id);
        for record in records {
            match record {
                TestRecord::Page {
                    offset,
                    continue_block,
                    byte,
                } => {
                    let flags = RAM_SAVE_FLAG_PAGE
                        | if *continue_block {
                            RAM_SAVE_FLAG_CONTINUE
                        } else {
                            0
                        };
                    push_u64(out, offset | flags);
                    if !continue_block {
                        push_counted(out, "pc.ram");
                    }
                    out.extend(std::iter::repeat_n(*byte, PAGE_SIZE as usize));
                }
                TestRecord::Zero {
                    offset,
                    continue_block,
                    value,
                } => {
                    let flags = RAM_SAVE_FLAG_ZERO
                        | if *continue_block {
                            RAM_SAVE_FLAG_CONTINUE
                        } else {
                            0
                        };
                    push_u64(out, offset | flags);
                    if !continue_block {
                        push_counted(out, "pc.ram");
                    }
                    out.push(*value);
                }
                TestRecord::Flag(flag) => push_u64(out, *flag),
            }
        }
        push_u64(out, RAM_SAVE_FLAG_EOS);
        push_footer(out, section_id);
    }

    fn finish(out: &mut Vec<u8>) {
        out.push(QEMU_VM_EOF);
        let json = br#"{"page_size":4096,"devices":[]}"#;
        out.push(QEMU_VM_VMDESCRIPTION);
        push_u32(out, json.len() as u32);
        out.extend_from_slice(json);
    }

    fn valid_fixture() -> Vec<u8> {
        let mut out = Vec::new();
        push_header(&mut out, QEVM_FILE_VERSION);
        push_ram_start(&mut out, SECTION_ID, QEVM_RAM_VERSION);
        push_segment(
            &mut out,
            QEMU_VM_SECTION_PART,
            SECTION_ID,
            &[
                TestRecord::Page {
                    offset: 0,
                    continue_block: false,
                    byte: 0x41,
                },
                TestRecord::Zero {
                    offset: PAGE_SIZE,
                    continue_block: true,
                    value: 0,
                },
            ],
        );
        push_segment(&mut out, QEMU_VM_SECTION_END, SECTION_ID, &[]);
        finish(&mut out);
        out
    }

    #[test]
    fn parses_raw_and_repeated_zero_pages() {
        let bytes = valid_fixture();
        let report = parse_qevm(&bytes).unwrap();
        assert_eq!(report.file_version, 3);
        assert_eq!(report.ram_version, 4);
        assert_eq!(report.page_size, PAGE_SIZE);
        assert_eq!(report.ram_blocks.len(), 1);
        assert_eq!(report.sections.len(), 3);
        assert_eq!(report.mappings.len(), 2);
        assert_eq!(report.mappings[0].ram_block, "pc.ram");
        assert_eq!(report.mappings[0].block_offset, 0);
        let QevmMappingSource::Direct { file_offset } = report.mappings[0].source else {
            panic!("expected direct mapping")
        };
        assert_eq!(bytes[file_offset as usize], 0x41);
        assert_eq!(
            report.mappings[1].source,
            QevmMappingSource::RepeatedByte { value: 0 }
        );
    }

    #[test]
    fn later_page_update_wins_without_overlapping_output() {
        let mut out = Vec::new();
        push_header(&mut out, 3);
        push_ram_start(&mut out, SECTION_ID, 4);
        push_segment(
            &mut out,
            QEMU_VM_SECTION_PART,
            SECTION_ID,
            &[TestRecord::Page {
                offset: 0,
                continue_block: false,
                byte: 0x41,
            }],
        );
        push_segment(
            &mut out,
            QEMU_VM_SECTION_END,
            SECTION_ID,
            &[TestRecord::Page {
                offset: 0,
                continue_block: true,
                byte: 0x42,
            }],
        );
        finish(&mut out);
        let report = parse_qevm(&out).unwrap();
        assert_eq!(report.overwritten_pages, 1);
        assert_eq!(report.mappings.len(), 1);
        let QevmMappingSource::Direct { file_offset } = report.mappings[0].source else {
            panic!("expected direct mapping")
        };
        assert_eq!(out[file_offset as usize], 0x42);
    }

    #[test]
    fn rejects_unknown_file_and_ram_versions() {
        let mut file = valid_fixture();
        file[4..8].copy_from_slice(&2_u32.to_be_bytes());
        assert_eq!(
            parse_qevm(&file).unwrap_err().kind,
            QevmErrorKind::UnsupportedFileVersion
        );

        let mut ram = valid_fixture();
        // marker + section id + counted "ram" + instance id
        let version_offset = 8 + 1 + 4 + 1 + 3 + 4;
        ram[version_offset..version_offset + 4].copy_from_slice(&5_u32.to_be_bytes());
        assert_eq!(
            parse_qevm(&ram).unwrap_err().kind,
            QevmErrorKind::UnsupportedRamVersion
        );
    }

    #[test]
    fn rejects_unsupported_ram_encodings_and_flags() {
        for (flag, expected) in [
            (RAM_SAVE_FLAG_XBZRLE, QevmErrorKind::UnsupportedXbzrle),
            (
                RAM_SAVE_FLAG_COMPRESS_PAGE,
                QevmErrorKind::UnsupportedCompressPage,
            ),
            (RAM_SAVE_FLAG_HOOK, QevmErrorKind::UnsupportedHook),
            (
                RAM_SAVE_FLAG_MULTIFD_FLUSH,
                QevmErrorKind::UnsupportedMultifd,
            ),
            (0x400, QevmErrorKind::UnknownRamFlags),
        ] {
            let mut out = Vec::new();
            push_header(&mut out, 3);
            push_ram_start(&mut out, SECTION_ID, 4);
            push_segment(
                &mut out,
                QEMU_VM_SECTION_END,
                SECTION_ID,
                &[TestRecord::Flag(flag)],
            );
            finish(&mut out);
            assert_eq!(parse_qevm(&out).unwrap_err().kind, expected);
        }
    }

    #[test]
    fn unsupported_part_is_not_hidden_by_a_later_valid_end() {
        let mut out = Vec::new();
        push_header(&mut out, 3);
        push_ram_start(&mut out, SECTION_ID, 4);
        push_segment(
            &mut out,
            QEMU_VM_SECTION_PART,
            SECTION_ID,
            &[TestRecord::Flag(RAM_SAVE_FLAG_XBZRLE)],
        );
        push_segment(&mut out, QEMU_VM_SECTION_END, SECTION_ID, &[]);
        finish(&mut out);
        assert_eq!(
            parse_qevm(&out).unwrap_err().kind,
            QevmErrorKind::UnsupportedXbzrle
        );
    }

    #[test]
    fn rejects_mapped_ram_capability() {
        let mut out = Vec::new();
        push_header(&mut out, 3);
        out.push(QEMU_VM_CONFIGURATION);
        push_u32(&mut out, 4);
        out.extend_from_slice(b"pc-q");
        out.push(QEMU_VM_SUBSECTION);
        push_counted(&mut out, "configuration/capabilities");
        push_u32(&mut out, 1);
        push_u32(&mut out, 1);
        push_counted(&mut out, "mapped-ram");
        push_ram_start(&mut out, SECTION_ID, 4);
        push_segment(&mut out, QEMU_VM_SECTION_END, SECTION_ID, &[]);
        finish(&mut out);
        assert_eq!(
            parse_qevm(&out).unwrap_err().kind,
            QevmErrorKind::UnsupportedMappedRam
        );
    }

    #[test]
    fn rejects_mapped_ram_header_even_without_configuration() {
        let mut out = Vec::new();
        push_header(&mut out, 3);
        out.push(QEMU_VM_SECTION_START);
        push_u32(&mut out, SECTION_ID);
        push_counted(&mut out, "ram");
        push_u32(&mut out, 0);
        push_u32(&mut out, 4);
        push_u64(&mut out, PAGE_SIZE | RAM_SAVE_FLAG_MEM_SIZE);
        push_counted(&mut out, "pc.ram");
        push_u64(&mut out, PAGE_SIZE);
        push_u32(&mut out, 1);
        push_u64(&mut out, PAGE_SIZE);
        push_u64(&mut out, 0x1000);
        push_u64(&mut out, 0x2000);
        finish(&mut out);
        assert_eq!(
            parse_qevm(&out).unwrap_err().kind,
            QevmErrorKind::UnsupportedMappedRam
        );
    }

    #[test]
    fn rejects_ambiguous_ram_declarations() {
        let mut out = Vec::new();
        push_header(&mut out, 3);
        push_ram_start(&mut out, SECTION_ID, 4);
        push_ram_start(&mut out, SECTION_ID + 1, 4);
        finish(&mut out);
        assert_eq!(
            parse_qevm(&out).unwrap_err().kind,
            QevmErrorKind::AmbiguousRamSection
        );
    }

    #[test]
    fn rejects_page_outside_declared_ramblock() {
        let mut out = Vec::new();
        push_header(&mut out, 3);
        push_ram_start(&mut out, SECTION_ID, 4);
        push_segment(
            &mut out,
            QEMU_VM_SECTION_END,
            SECTION_ID,
            &[TestRecord::Zero {
                offset: 2 * PAGE_SIZE,
                continue_block: false,
                value: 0,
            }],
        );
        finish(&mut out);
        assert_eq!(
            parse_qevm(&out).unwrap_err().kind,
            QevmErrorKind::OutOfBounds
        );
    }

    #[test]
    fn rejects_non_zero_zero_record() {
        let mut out = Vec::new();
        push_header(&mut out, 3);
        push_ram_start(&mut out, SECTION_ID, 4);
        push_segment(
            &mut out,
            QEMU_VM_SECTION_END,
            SECTION_ID,
            &[TestRecord::Zero {
                offset: 0,
                continue_block: false,
                value: 0x7f,
            }],
        );
        finish(&mut out);
        assert_eq!(
            parse_qevm(&out).unwrap_err().kind,
            QevmErrorKind::InvalidRamSection
        );
    }

    #[test]
    fn rejects_truncated_raw_page() {
        let mut out = Vec::new();
        push_header(&mut out, 3);
        push_ram_start(&mut out, SECTION_ID, 4);
        out.push(QEMU_VM_SECTION_END);
        push_u32(&mut out, SECTION_ID);
        push_u64(&mut out, RAM_SAVE_FLAG_PAGE);
        push_counted(&mut out, "pc.ram");
        out.extend(std::iter::repeat_n(0x41, 64));
        finish(&mut out);
        assert_eq!(parse_qevm(&out).unwrap_err().kind, QevmErrorKind::Truncated);
    }

    #[test]
    fn rejects_missing_footer_and_terminal_description() {
        let mut no_footer = valid_fixture();
        let initial_footer = 8 + 17 + 8 + 1 + 6 + 8 + 8;
        no_footer[initial_footer] = QEMU_VM_SECTION_PART;
        assert_eq!(
            parse_qevm(&no_footer).unwrap_err().kind,
            QevmErrorKind::MissingSectionFooter
        );

        let mut no_description = valid_fixture();
        let marker = no_description
            .iter()
            .rposition(|byte| *byte == QEMU_VM_VMDESCRIPTION)
            .unwrap();
        no_description.truncate(marker - 1);
        assert_eq!(
            parse_qevm(&no_description).unwrap_err().kind,
            QevmErrorKind::MissingTerminalVmDescription
        );
    }

    #[test]
    fn embedded_section_marker_inside_raw_page_is_not_rescanned() {
        let mut out = valid_fixture();
        let report = parse_qevm(&out).unwrap();
        let QevmMappingSource::Direct { file_offset } = report.mappings[0].source else {
            panic!("expected direct mapping")
        };
        let embedded = file_offset as usize + 32;
        out[embedded] = QEMU_VM_SECTION_END;
        out[embedded + 1..embedded + 5].copy_from_slice(&SECTION_ID.to_be_bytes());
        assert!(parse_qevm(&out).is_ok());
    }

    #[test]
    fn enforces_description_section_and_page_record_limits() {
        let bytes = valid_fixture();

        let limits = QevmParseLimits {
            max_vmdescription_bytes: 8,
            ..QevmParseLimits::default()
        };
        assert_eq!(
            parse_qevm_with_limits(&bytes, limits).unwrap_err().kind,
            QevmErrorKind::LimitExceeded
        );

        let limits = QevmParseLimits {
            max_ram_sections: 2,
            ..QevmParseLimits::default()
        };
        assert_eq!(
            parse_qevm_with_limits(&bytes, limits).unwrap_err().kind,
            QevmErrorKind::LimitExceeded
        );

        let limits = QevmParseLimits {
            max_declared_ram_bytes: PAGE_SIZE,
            ..QevmParseLimits::default()
        };
        assert_eq!(
            parse_qevm_with_limits(&bytes, limits).unwrap_err().kind,
            QevmErrorKind::LimitExceeded
        );

        let limits = QevmParseLimits {
            max_page_records: 1,
            ..QevmParseLimits::default()
        };
        assert_eq!(
            parse_qevm_with_limits(&bytes, limits).unwrap_err().kind,
            QevmErrorKind::LimitExceeded
        );

        let limits = QevmParseLimits {
            max_ram_blocks: 0,
            ..QevmParseLimits::default()
        };
        assert_eq!(
            parse_qevm_with_limits(&bytes, limits).unwrap_err().kind,
            QevmErrorKind::LimitExceeded
        );
    }

    #[test]
    fn ram_segment_cannot_consume_footer_beyond_terminal_boundary() {
        let mut bytes = Vec::new();
        push_u64(&mut bytes, RAM_SAVE_FLAG_EOS);
        push_footer(&mut bytes, SECTION_ID);
        let blocks = vec![QevmRamBlock {
            name: "pc.ram".to_owned(),
            length: PAGE_SIZE,
        }];
        let block_indices = HashMap::from([("pc.ram".to_owned(), 0_usize)]);
        let mut last_block = None;
        let mut records = 0;
        let limits = QevmParseLimits {
            max_page_records: 16,
            ..QevmParseLimits::default()
        };
        let context = SegmentParseContext {
            bytes: &bytes,
            end: 8,
            section_id: SECTION_ID,
            page_size: PAGE_SIZE,
            blocks: &blocks,
            block_indices: &block_indices,
            limits: &limits,
        };
        let error = parse_page_segment(context, 0, &mut last_block, &mut records).unwrap_err();
        assert_eq!(error.kind, QevmErrorKind::MissingSectionFooter);
    }
}
