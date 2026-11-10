//! Strict parser for Microsoft AVML v2 compressed memory images.
//!
//! The wire contract implemented here is taken from these primary sources:
//!
//! * Microsoft AVML `src/image.rs` at commit
//!   `633424ca23f977c4f51f34b5bc9ec1c76b062849`: an AVML record starts with a
//!   32-byte little-endian header (`0x4c4d5641`, version 2, physical start,
//!   inclusive physical end, zero padding), followed by a Snappy framed stream.
//! * Microsoft AVML `src/io/snappy.rs` at the same commit: the producer appends
//!   an eight-byte little-endian count of the framed stream bytes after each
//!   stream.
//! * Google's Snappy framing specification: the first chunk is the `sNaPpY`
//!   stream identifier, data chunks carry a masked CRC32C of their uncompressed
//!   bytes, decoded data chunks are at most 65,536 bytes, chunk types 0x02..0x7f
//!   are unskippable, and 0x80..0xfe are skippable.
//!
//! Parsing validates and checksum-verifies every Snappy data chunk, but retains
//! only record/mapping descriptors.  [`AvmlRecordDescriptor::physical_span`]
//! converts a record directly to StarMem's `SnappyFrame` mapping so the common
//! bounded lazy-decode cache remains responsible for materializing record data.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crate::image::{MappingEncoding, PhysicalSpan};

pub const AVML_MAGIC: u32 = 0x4c4d_5641;
pub const AVML_VERSION: u32 = 2;
pub const AVML_HEADER_SIZE: usize = 32;
pub const AVML_TRAILER_SIZE: usize = 8;
pub const SNAPPY_MAX_DECODED_CHUNK_SIZE: usize = 65_536;

const SNAPPY_STREAM_IDENTIFIER: &[u8] = b"sNaPpY";

/// Defensive parser limits.  They bound parser CPU, descriptor memory, and the
/// size of any single record later handed to the common lazy decode cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvmlParseLimits {
    pub max_records: usize,
    pub max_chunks_per_record: usize,
    pub max_decoded_record_bytes: u64,
    pub max_encoded_record_bytes: u64,
    pub max_total_mapped_bytes: u64,
}

impl Default for AvmlParseLimits {
    fn default() -> Self {
        Self {
            max_records: 1 << 20,
            max_chunks_per_record: 1 << 20,
            max_decoded_record_bytes: 256 * 1024 * 1024,
            max_encoded_record_bytes: 512 * 1024 * 1024,
            max_total_mapped_bytes: 64 * 1024 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AvmlErrorKind {
    Truncated,
    InvalidMagic,
    UnsupportedVersion,
    InvalidPadding,
    InvalidRange,
    IntegerOverflow,
    LimitExceeded,
    InvalidSnappyIdentifier,
    InvalidSnappyChunk,
    UnsupportedSnappyChunk,
    ChecksumMismatch,
    LengthMismatch,
    OverlappingPhysicalRanges,
}

/// Structured parse failure with a source-file offset whenever one is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvmlParseError {
    pub kind: AvmlErrorKind,
    pub offset: Option<u64>,
    pub detail: String,
}

impl fmt::Display for AvmlParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(offset) = self.offset {
            write!(f, "AVML parse error at {offset:#x}: {}", self.detail)
        } else {
            write!(f, "AVML parse error: {}", self.detail)
        }
    }
}

impl Error for AvmlParseError {}

pub type AvmlResult<T> = Result<T, AvmlParseError>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AvmlFrameStatistics {
    pub chunks: u64,
    pub stream_identifiers: u64,
    pub compressed_data_chunks: u64,
    pub uncompressed_data_chunks: u64,
    pub skippable_chunks: u64,
    pub checksum_verified_chunks: u64,
}

/// One AVML record in source-file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvmlRecordDescriptor {
    pub record_index: usize,
    pub header_offset: u64,
    pub physical_start: u64,
    pub decoded_length: u64,
    /// Offset of the first Snappy framing byte (the 0xff stream identifier).
    pub frame_offset: u64,
    /// Framed stream length, excluding the AVML header and eight-byte trailer.
    pub encoded_length: u64,
    pub trailer_offset: u64,
    pub frame_statistics: AvmlFrameStatistics,
}

impl AvmlRecordDescriptor {
    pub fn physical_end(&self) -> u64 {
        // The parser proves this addition cannot overflow.
        self.physical_start + self.decoded_length
    }

    /// Convert to the common mapping representation consumed by MemoryImage's
    /// bounded lazy Snappy cache.
    pub fn physical_span(&self, source_index: usize) -> PhysicalSpan {
        PhysicalSpan {
            start: self.physical_start,
            length: self.decoded_length,
            file_offset: self.frame_offset,
            source_index,
            encoding: MappingEncoding::SnappyFrame {
                encoded_length: self.encoded_length,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvmlImageDescriptor {
    pub version: u32,
    pub source_length: u64,
    pub mapped_bytes: u64,
    /// True only when every data chunk was decoded and checksum-verified while
    /// building this descriptor. The lazy-mapping API leaves this false and
    /// requires the consuming decoder to verify CRC32C on materialization.
    pub checksums_verified_during_parse: bool,
    /// Records remain in source-file order for provenance.
    pub records: Vec<AvmlRecordDescriptor>,
}

impl AvmlImageDescriptor {
    /// Produce mappings sorted by physical address, as required by MemoryImage.
    pub fn physical_spans(&self, source_index: usize) -> Vec<PhysicalSpan> {
        let mut spans = self
            .records
            .iter()
            .map(|record| record.physical_span(source_index))
            .collect::<Vec<_>>();
        spans.sort_unstable_by_key(|span| span.start);
        spans
    }
}

pub fn parse_avml_v2(bytes: &[u8]) -> AvmlResult<AvmlImageDescriptor> {
    parse_avml_v2_with_limits(bytes, AvmlParseLimits::default())
}

pub fn parse_avml_v2_with_limits(
    bytes: &[u8],
    limits: AvmlParseLimits,
) -> AvmlResult<AvmlImageDescriptor> {
    parse_avml_v2_internal(bytes, limits, true)
}

/// Build mapping descriptors without eagerly decompressing the entire image.
///
/// This is the integration entry point for `MemoryImage`: its common
/// `SnappyFrame` decoder verifies masked CRC32C when a mapping is first read and
/// retains decoded bytes in its bounded cache. Do not use this API with a
/// consumer that does not checksum-verify materialized mappings.
pub fn map_avml_v2_for_lazy_decode(bytes: &[u8]) -> AvmlResult<AvmlImageDescriptor> {
    map_avml_v2_for_lazy_decode_with_limits(bytes, AvmlParseLimits::default())
}

pub fn map_avml_v2_for_lazy_decode_with_limits(
    bytes: &[u8],
    limits: AvmlParseLimits,
) -> AvmlResult<AvmlImageDescriptor> {
    parse_avml_v2_internal(bytes, limits, false)
}

fn parse_avml_v2_internal(
    bytes: &[u8],
    limits: AvmlParseLimits,
    verify_checksums: bool,
) -> AvmlResult<AvmlImageDescriptor> {
    if bytes.len() < AVML_HEADER_SIZE + AVML_TRAILER_SIZE {
        return Err(at(
            AvmlErrorKind::Truncated,
            0,
            "AVML image does not contain a complete record",
        ));
    }
    if limits.max_records == 0
        || limits.max_chunks_per_record == 0
        || limits.max_decoded_record_bytes == 0
        || limits.max_encoded_record_bytes == 0
        || limits.max_total_mapped_bytes == 0
    {
        return Err(global(
            AvmlErrorKind::LimitExceeded,
            "all AVML parser limits must be non-zero",
        ));
    }

    let source_length = u64::try_from(bytes.len()).map_err(|_| {
        global(
            AvmlErrorKind::IntegerOverflow,
            "source length cannot be represented as u64",
        )
    })?;
    let max_encoded_record_bytes =
        usize::try_from(limits.max_encoded_record_bytes).map_err(|_| {
            global(
                AvmlErrorKind::IntegerOverflow,
                "encoded record limit cannot be represented as usize",
            )
        })?;

    let mut records = Vec::new();
    let mut physical_ranges = BTreeMap::new();
    let mut cursor = 0usize;
    let mut mapped_bytes = 0u64;
    while cursor < bytes.len() {
        if records.len() >= limits.max_records {
            return Err(at(
                AvmlErrorKind::LimitExceeded,
                cursor,
                format!("record count exceeds limit {}", limits.max_records),
            ));
        }
        let header_end = checked_add(cursor, AVML_HEADER_SIZE, cursor, "header end")?;
        if header_end > bytes.len() {
            return Err(at(
                AvmlErrorKind::Truncated,
                cursor,
                "truncated AVML record header",
            ));
        }

        let magic = read_u32(bytes, cursor, "magic")?;
        if magic != AVML_MAGIC {
            return Err(at(
                AvmlErrorKind::InvalidMagic,
                cursor,
                format!("invalid magic {magic:#010x}; expected {AVML_MAGIC:#010x}"),
            ));
        }
        let version = read_u32(bytes, cursor + 4, "version")?;
        if version != AVML_VERSION {
            return Err(at(
                AvmlErrorKind::UnsupportedVersion,
                cursor + 4,
                format!("unsupported AVML version {version}; expected {AVML_VERSION}"),
            ));
        }
        let physical_start = read_u64(bytes, cursor + 8, "physical start")?;
        let physical_end_inclusive = read_u64(bytes, cursor + 16, "physical end")?;
        let padding = read_u64(bytes, cursor + 24, "padding")?;
        if padding != 0 {
            return Err(at(
                AvmlErrorKind::InvalidPadding,
                cursor + 24,
                format!("header padding is non-zero ({padding:#x})"),
            ));
        }
        if physical_end_inclusive < physical_start {
            return Err(at(
                AvmlErrorKind::InvalidRange,
                cursor + 8,
                format!(
                    "inclusive physical range is inverted: {physical_start:#x}..={physical_end_inclusive:#x}"
                ),
            ));
        }
        let decoded_length = physical_end_inclusive
            .checked_sub(physical_start)
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| {
                at(
                    AvmlErrorKind::IntegerOverflow,
                    cursor + 16,
                    "physical range length overflows u64",
                )
            })?;
        let physical_end = physical_start.checked_add(decoded_length).ok_or_else(|| {
            at(
                AvmlErrorKind::IntegerOverflow,
                cursor + 16,
                "exclusive physical range end overflows u64",
            )
        })?;
        validate_and_insert_physical_range(
            &mut physical_ranges,
            physical_start,
            physical_end,
            cursor,
        )?;
        if decoded_length > limits.max_decoded_record_bytes {
            return Err(at(
                AvmlErrorKind::LimitExceeded,
                cursor + 8,
                format!(
                    "decoded record length {decoded_length} exceeds limit {}",
                    limits.max_decoded_record_bytes
                ),
            ));
        }
        mapped_bytes = mapped_bytes.checked_add(decoded_length).ok_or_else(|| {
            at(
                AvmlErrorKind::IntegerOverflow,
                cursor + 8,
                "total mapped byte count overflows u64",
            )
        })?;
        if mapped_bytes > limits.max_total_mapped_bytes {
            return Err(at(
                AvmlErrorKind::LimitExceeded,
                cursor + 8,
                format!(
                    "total mapped bytes {mapped_bytes} exceed limit {}",
                    limits.max_total_mapped_bytes
                ),
            ));
        }

        let expected_decoded_length = usize::try_from(decoded_length).map_err(|_| {
            at(
                AvmlErrorKind::IntegerOverflow,
                cursor + 8,
                "decoded record length cannot be represented as usize",
            )
        })?;
        let frame_offset = header_end;
        let parsed_frame = parse_snappy_framed_stream(
            bytes.get(frame_offset..).ok_or_else(|| {
                at(
                    AvmlErrorKind::Truncated,
                    frame_offset,
                    "missing Snappy framed stream",
                )
            })?,
            frame_offset,
            expected_decoded_length,
            max_encoded_record_bytes,
            limits.max_chunks_per_record,
            verify_checksums,
        )?;
        let trailer_offset = checked_add(
            frame_offset,
            parsed_frame.encoded_length,
            frame_offset,
            "AVML trailer offset",
        )?;
        let trailer_end = checked_add(
            trailer_offset,
            AVML_TRAILER_SIZE,
            trailer_offset,
            "AVML trailer end",
        )?;
        if trailer_end > bytes.len() {
            return Err(at(
                AvmlErrorKind::Truncated,
                trailer_offset,
                "missing eight-byte AVML encoded-length trailer",
            ));
        }
        let declared_encoded_length = read_u64(bytes, trailer_offset, "encoded length trailer")?;
        let encoded_length = u64::try_from(parsed_frame.encoded_length).map_err(|_| {
            at(
                AvmlErrorKind::IntegerOverflow,
                frame_offset,
                "encoded stream length cannot be represented as u64",
            )
        })?;
        if declared_encoded_length != encoded_length {
            return Err(at(
                AvmlErrorKind::LengthMismatch,
                trailer_offset,
                format!(
                    "encoded-length trailer declares {declared_encoded_length}, parsed {encoded_length}"
                ),
            ));
        }

        records.push(AvmlRecordDescriptor {
            record_index: records.len(),
            header_offset: u64::try_from(cursor).map_err(|_| {
                global(
                    AvmlErrorKind::IntegerOverflow,
                    "record offset cannot be represented as u64",
                )
            })?,
            physical_start,
            decoded_length,
            frame_offset: u64::try_from(frame_offset).map_err(|_| {
                global(
                    AvmlErrorKind::IntegerOverflow,
                    "frame offset cannot be represented as u64",
                )
            })?,
            encoded_length,
            trailer_offset: u64::try_from(trailer_offset).map_err(|_| {
                global(
                    AvmlErrorKind::IntegerOverflow,
                    "trailer offset cannot be represented as u64",
                )
            })?,
            frame_statistics: parsed_frame.statistics,
        });
        cursor = trailer_end;
    }

    if records.is_empty() {
        return Err(global(
            AvmlErrorKind::Truncated,
            "AVML image contains no records",
        ));
    }
    Ok(AvmlImageDescriptor {
        version: AVML_VERSION,
        source_length,
        mapped_bytes,
        checksums_verified_during_parse: verify_checksums,
        records,
    })
}

struct ParsedSnappyFrame {
    encoded_length: usize,
    statistics: AvmlFrameStatistics,
}

fn parse_snappy_framed_stream(
    bytes: &[u8],
    absolute_offset: usize,
    expected_decoded_length: usize,
    max_encoded_length: usize,
    max_chunks: usize,
    verify_checksums: bool,
) -> AvmlResult<ParsedSnappyFrame> {
    let mut cursor = 0usize;
    let mut decoded_length = 0usize;
    let mut statistics = AvmlFrameStatistics::default();
    let mut saw_stream_identifier = false;

    while decoded_length < expected_decoded_length {
        if statistics.chunks >= max_chunks as u64 {
            return Err(at(
                AvmlErrorKind::LimitExceeded,
                absolute_offset.saturating_add(cursor),
                format!("Snappy chunk count exceeds limit {max_chunks}"),
            ));
        }
        let header_end = checked_add(
            cursor,
            4,
            absolute_offset.saturating_add(cursor),
            "Snappy chunk header",
        )?;
        if header_end > bytes.len() {
            return Err(at(
                AvmlErrorKind::Truncated,
                absolute_offset.saturating_add(cursor),
                "truncated Snappy chunk header",
            ));
        }
        if header_end > max_encoded_length {
            return Err(at(
                AvmlErrorKind::LimitExceeded,
                absolute_offset.saturating_add(cursor),
                format!("Snappy framed stream exceeds encoded limit {max_encoded_length}"),
            ));
        }
        let chunk_type = bytes[cursor];
        let chunk_length = usize::from(bytes[cursor + 1])
            | (usize::from(bytes[cursor + 2]) << 8)
            | (usize::from(bytes[cursor + 3]) << 16);
        let chunk_end = checked_add(
            header_end,
            chunk_length,
            absolute_offset.saturating_add(cursor),
            "Snappy chunk end",
        )?;
        if chunk_end > bytes.len() {
            return Err(at(
                AvmlErrorKind::Truncated,
                absolute_offset.saturating_add(cursor),
                format!("Snappy chunk payload of {chunk_length} bytes is truncated"),
            ));
        }
        if chunk_end > max_encoded_length {
            return Err(at(
                AvmlErrorKind::LimitExceeded,
                absolute_offset.saturating_add(cursor),
                format!("Snappy framed stream exceeds encoded limit {max_encoded_length}"),
            ));
        }
        let chunk = &bytes[header_end..chunk_end];
        statistics.chunks += 1;

        if statistics.chunks == 1 && chunk_type != 0xff {
            return Err(at(
                AvmlErrorKind::InvalidSnappyIdentifier,
                absolute_offset.saturating_add(cursor),
                "the first Snappy framed chunk is not a stream identifier",
            ));
        }
        match chunk_type {
            0xff => {
                if chunk != SNAPPY_STREAM_IDENTIFIER {
                    return Err(at(
                        AvmlErrorKind::InvalidSnappyIdentifier,
                        absolute_offset.saturating_add(header_end),
                        "invalid Snappy stream identifier",
                    ));
                }
                saw_stream_identifier = true;
                statistics.stream_identifiers += 1;
            }
            0x00 | 0x01 => {
                if !saw_stream_identifier {
                    return Err(at(
                        AvmlErrorKind::InvalidSnappyIdentifier,
                        absolute_offset.saturating_add(cursor),
                        "Snappy data chunk precedes the stream identifier",
                    ));
                }
                if chunk.len() < 4 {
                    return Err(at(
                        AvmlErrorKind::InvalidSnappyChunk,
                        absolute_offset.saturating_add(header_end),
                        "Snappy data chunk does not contain a four-byte CRC32C",
                    ));
                }
                let expected_crc = u32::from_le_bytes(
                    chunk[..4]
                        .try_into()
                        .expect("four-byte slice checked immediately above"),
                );
                let payload_offset = absolute_offset.saturating_add(header_end + 4);
                let decoded_chunk_length;
                let actual_crc = if chunk_type == 0x00 {
                    let checksum = if verify_checksums {
                        let decoded = decode_snappy_block(&chunk[4..], payload_offset)?;
                        decoded_chunk_length = decoded.len();
                        Some(masked_crc32c(&decoded))
                    } else {
                        decoded_chunk_length =
                            snappy_block_declared_length(&chunk[4..], payload_offset)?;
                        None
                    };
                    statistics.compressed_data_chunks += 1;
                    checksum
                } else {
                    if chunk.len() - 4 > SNAPPY_MAX_DECODED_CHUNK_SIZE {
                        return Err(at(
                            AvmlErrorKind::InvalidSnappyChunk,
                            payload_offset,
                            format!(
                                "uncompressed Snappy chunk decodes to {} bytes; maximum is {SNAPPY_MAX_DECODED_CHUNK_SIZE}",
                                chunk.len() - 4
                            ),
                        ));
                    }
                    decoded_chunk_length = chunk.len() - 4;
                    statistics.uncompressed_data_chunks += 1;
                    verify_checksums.then(|| masked_crc32c(&chunk[4..]))
                };
                let new_decoded_length = decoded_length
                    .checked_add(decoded_chunk_length)
                    .ok_or_else(|| {
                        at(
                            AvmlErrorKind::IntegerOverflow,
                            payload_offset,
                            "Snappy decoded byte count overflows usize",
                        )
                    })?;
                if new_decoded_length > expected_decoded_length {
                    return Err(at(
                        AvmlErrorKind::LengthMismatch,
                        payload_offset,
                        format!(
                            "Snappy decoded data exceeds AVML range: {} > {expected_decoded_length}",
                            new_decoded_length
                        ),
                    ));
                }
                if let Some(actual_crc) = actual_crc {
                    if actual_crc != expected_crc {
                        return Err(at(
                            AvmlErrorKind::ChecksumMismatch,
                            absolute_offset.saturating_add(header_end),
                            format!(
                                "masked CRC32C mismatch: stored {expected_crc:#010x}, computed {actual_crc:#010x}"
                            ),
                        ));
                    }
                    statistics.checksum_verified_chunks += 1;
                }
                decoded_length = new_decoded_length;
            }
            0x02..=0x7f => {
                return Err(at(
                    AvmlErrorKind::UnsupportedSnappyChunk,
                    absolute_offset.saturating_add(cursor),
                    format!("unskippable Snappy chunk type {chunk_type:#04x}"),
                ));
            }
            0x80..=0xfe => {
                statistics.skippable_chunks += 1;
            }
        }
        cursor = chunk_end;
    }

    if !saw_stream_identifier {
        return Err(at(
            AvmlErrorKind::InvalidSnappyIdentifier,
            absolute_offset,
            "missing Snappy stream identifier",
        ));
    }
    if decoded_length != expected_decoded_length {
        return Err(at(
            AvmlErrorKind::LengthMismatch,
            absolute_offset.saturating_add(cursor),
            format!(
                "Snappy decoded length {decoded_length} does not match AVML range {expected_decoded_length}"
            ),
        ));
    }
    Ok(ParsedSnappyFrame {
        encoded_length: cursor,
        statistics,
    })
}

fn snappy_block_declared_length(encoded: &[u8], absolute_offset: usize) -> AvmlResult<usize> {
    let (decoded_length, _) = read_varint(encoded, absolute_offset)?;
    let decoded_length = usize::try_from(decoded_length).map_err(|_| {
        at(
            AvmlErrorKind::IntegerOverflow,
            absolute_offset,
            "Snappy block decoded length cannot be represented as usize",
        )
    })?;
    if decoded_length > SNAPPY_MAX_DECODED_CHUNK_SIZE {
        return Err(at(
            AvmlErrorKind::InvalidSnappyChunk,
            absolute_offset,
            format!(
                "compressed Snappy chunk declares {decoded_length} decoded bytes; maximum is {SNAPPY_MAX_DECODED_CHUNK_SIZE}"
            ),
        ));
    }
    Ok(decoded_length)
}

fn decode_snappy_block(encoded: &[u8], absolute_offset: usize) -> AvmlResult<Vec<u8>> {
    let (decoded_length, mut cursor) = read_varint(encoded, absolute_offset)?;
    let decoded_length = usize::try_from(decoded_length).map_err(|_| {
        at(
            AvmlErrorKind::IntegerOverflow,
            absolute_offset,
            "Snappy block decoded length cannot be represented as usize",
        )
    })?;
    if decoded_length > SNAPPY_MAX_DECODED_CHUNK_SIZE {
        return Err(at(
            AvmlErrorKind::InvalidSnappyChunk,
            absolute_offset,
            format!(
                "compressed Snappy chunk decodes to {decoded_length} bytes; maximum is {SNAPPY_MAX_DECODED_CHUNK_SIZE}"
            ),
        ));
    }
    let mut output = Vec::with_capacity(decoded_length);

    while cursor < encoded.len() && output.len() < decoded_length {
        let tag_offset = cursor;
        let tag = encoded[cursor];
        cursor += 1;
        match tag & 0x03 {
            0 => {
                let length_code = usize::from(tag >> 2);
                let literal_length = if length_code < 60 {
                    length_code + 1
                } else {
                    let length_bytes = length_code - 59;
                    if length_bytes > 4 {
                        return Err(at(
                            AvmlErrorKind::InvalidSnappyChunk,
                            absolute_offset.saturating_add(tag_offset),
                            "Snappy literal length field uses more than four bytes",
                        ));
                    }
                    let length_end = checked_add(
                        cursor,
                        length_bytes,
                        absolute_offset.saturating_add(cursor),
                        "Snappy literal length field",
                    )?;
                    let length_raw = encoded.get(cursor..length_end).ok_or_else(|| {
                        at(
                            AvmlErrorKind::Truncated,
                            absolute_offset.saturating_add(cursor),
                            "truncated Snappy literal length field",
                        )
                    })?;
                    cursor = length_end;
                    let mut encoded_length = 0usize;
                    for (index, byte) in length_raw.iter().copied().enumerate() {
                        encoded_length |= usize::from(byte) << (index * 8);
                    }
                    encoded_length.checked_add(1).ok_or_else(|| {
                        at(
                            AvmlErrorKind::IntegerOverflow,
                            absolute_offset.saturating_add(tag_offset),
                            "Snappy literal length overflows usize",
                        )
                    })?
                };
                let literal_end = checked_add(
                    cursor,
                    literal_length,
                    absolute_offset.saturating_add(cursor),
                    "Snappy literal end",
                )?;
                let literal = encoded.get(cursor..literal_end).ok_or_else(|| {
                    at(
                        AvmlErrorKind::Truncated,
                        absolute_offset.saturating_add(cursor),
                        "truncated Snappy literal",
                    )
                })?;
                ensure_decoded_capacity(
                    output.len(),
                    literal.len(),
                    decoded_length,
                    absolute_offset.saturating_add(tag_offset),
                )?;
                output.extend_from_slice(literal);
                cursor = literal_end;
            }
            1 => {
                let length = 4 + usize::from((tag >> 2) & 0x07);
                let low = *encoded.get(cursor).ok_or_else(|| {
                    at(
                        AvmlErrorKind::Truncated,
                        absolute_offset.saturating_add(cursor),
                        "truncated Snappy COPY_1 offset",
                    )
                })?;
                cursor += 1;
                let offset = (usize::from(tag & 0xe0) << 3) | usize::from(low);
                copy_from_history(
                    &mut output,
                    offset,
                    length,
                    decoded_length,
                    absolute_offset.saturating_add(tag_offset),
                )?;
            }
            2 => {
                let offset_end = checked_add(
                    cursor,
                    2,
                    absolute_offset.saturating_add(cursor),
                    "Snappy COPY_2 offset",
                )?;
                let raw: [u8; 2] = encoded
                    .get(cursor..offset_end)
                    .ok_or_else(|| {
                        at(
                            AvmlErrorKind::Truncated,
                            absolute_offset.saturating_add(cursor),
                            "truncated Snappy COPY_2 offset",
                        )
                    })?
                    .try_into()
                    .expect("two-byte slice checked immediately above");
                cursor = offset_end;
                copy_from_history(
                    &mut output,
                    usize::from(u16::from_le_bytes(raw)),
                    1 + usize::from(tag >> 2),
                    decoded_length,
                    absolute_offset.saturating_add(tag_offset),
                )?;
            }
            3 => {
                let offset_end = checked_add(
                    cursor,
                    4,
                    absolute_offset.saturating_add(cursor),
                    "Snappy COPY_4 offset",
                )?;
                let raw: [u8; 4] = encoded
                    .get(cursor..offset_end)
                    .ok_or_else(|| {
                        at(
                            AvmlErrorKind::Truncated,
                            absolute_offset.saturating_add(cursor),
                            "truncated Snappy COPY_4 offset",
                        )
                    })?
                    .try_into()
                    .expect("four-byte slice checked immediately above");
                cursor = offset_end;
                let offset = usize::try_from(u32::from_le_bytes(raw)).map_err(|_| {
                    at(
                        AvmlErrorKind::IntegerOverflow,
                        absolute_offset.saturating_add(tag_offset),
                        "Snappy COPY_4 offset cannot be represented as usize",
                    )
                })?;
                copy_from_history(
                    &mut output,
                    offset,
                    1 + usize::from(tag >> 2),
                    decoded_length,
                    absolute_offset.saturating_add(tag_offset),
                )?;
            }
            _ => unreachable!(),
        }
    }

    if output.len() != decoded_length {
        return Err(at(
            AvmlErrorKind::LengthMismatch,
            absolute_offset.saturating_add(cursor),
            format!(
                "Snappy block decoded {} bytes; preamble declares {decoded_length}",
                output.len()
            ),
        ));
    }
    if cursor != encoded.len() {
        return Err(at(
            AvmlErrorKind::InvalidSnappyChunk,
            absolute_offset.saturating_add(cursor),
            "Snappy block contains trailing bytes",
        ));
    }
    Ok(output)
}

fn read_varint(encoded: &[u8], absolute_offset: usize) -> AvmlResult<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in encoded.iter().copied().take(10).enumerate() {
        let payload = u64::from(byte & 0x7f);
        if index == 9 && payload > 1 {
            return Err(at(
                AvmlErrorKind::IntegerOverflow,
                absolute_offset.saturating_add(index),
                "Snappy decoded-length varint overflows u64",
            ));
        }
        value |= payload << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(at(
        AvmlErrorKind::Truncated,
        absolute_offset,
        "Snappy decoded-length varint is truncated or longer than ten bytes",
    ))
}

fn copy_from_history(
    output: &mut Vec<u8>,
    offset: usize,
    length: usize,
    decoded_length: usize,
    absolute_offset: usize,
) -> AvmlResult<()> {
    if offset == 0 || offset > output.len() {
        return Err(at(
            AvmlErrorKind::InvalidSnappyChunk,
            absolute_offset,
            format!(
                "Snappy copy offset {offset} is invalid for {} decoded bytes",
                output.len()
            ),
        ));
    }
    ensure_decoded_capacity(output.len(), length, decoded_length, absolute_offset)?;
    for _ in 0..length {
        output.push(output[output.len() - offset]);
    }
    Ok(())
}

fn ensure_decoded_capacity(
    current: usize,
    additional: usize,
    declared: usize,
    absolute_offset: usize,
) -> AvmlResult<()> {
    let end = current.checked_add(additional).ok_or_else(|| {
        at(
            AvmlErrorKind::IntegerOverflow,
            absolute_offset,
            "Snappy decoded output length overflows usize",
        )
    })?;
    if end > declared {
        return Err(at(
            AvmlErrorKind::LengthMismatch,
            absolute_offset,
            format!("Snappy operation ends at {end}, beyond declared length {declared}"),
        ));
    }
    Ok(())
}

fn validate_and_insert_physical_range(
    ranges: &mut BTreeMap<u64, (u64, usize)>,
    start: u64,
    end: u64,
    header_offset: usize,
) -> AvmlResult<()> {
    if let Some((&previous_start, &(previous_end, _))) = ranges.range(..=start).next_back()
        && previous_end > start
    {
        return Err(at(
            AvmlErrorKind::OverlappingPhysicalRanges,
            header_offset,
            format!(
                "physical ranges overlap: {previous_start:#x}..{previous_end:#x} and {start:#x}..{end:#x}"
            ),
        ));
    }
    if let Some((&next_start, &(next_end, _))) = ranges.range(start..).next()
        && end > next_start
    {
        return Err(at(
            AvmlErrorKind::OverlappingPhysicalRanges,
            header_offset,
            format!(
                "physical ranges overlap: {start:#x}..{end:#x} and {next_start:#x}..{next_end:#x}"
            ),
        ));
    }
    ranges.insert(start, (end, header_offset));
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize, field: &str) -> AvmlResult<u32> {
    let end = checked_add(offset, 4, offset, field)?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| {
            at(
                AvmlErrorKind::Truncated,
                offset,
                format!("truncated {field}"),
            )
        })?
        .try_into()
        .expect("four-byte slice checked immediately above");
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize, field: &str) -> AvmlResult<u64> {
    let end = checked_add(offset, 8, offset, field)?;
    let raw: [u8; 8] = bytes
        .get(offset..end)
        .ok_or_else(|| {
            at(
                AvmlErrorKind::Truncated,
                offset,
                format!("truncated {field}"),
            )
        })?
        .try_into()
        .expect("eight-byte slice checked immediately above");
    Ok(u64::from_le_bytes(raw))
}

fn checked_add(left: usize, right: usize, error_offset: usize, field: &str) -> AvmlResult<usize> {
    left.checked_add(right).ok_or_else(|| {
        at(
            AvmlErrorKind::IntegerOverflow,
            error_offset,
            format!("{field} offset overflows usize"),
        )
    })
}

fn at(kind: AvmlErrorKind, offset: usize, detail: impl Into<String>) -> AvmlParseError {
    AvmlParseError {
        kind,
        offset: u64::try_from(offset).ok(),
        detail: detail.into(),
    }
}

fn global(kind: AvmlErrorKind, detail: impl Into<String>) -> AvmlParseError {
    AvmlParseError {
        kind,
        offset: None,
        detail: detail.into(),
    }
}

/// Castagnoli CRC32 followed by the masking operation required by the Snappy
/// framing specification.
fn masked_crc32c(bytes: &[u8]) -> u32 {
    crc32c(bytes).rotate_right(15).wrapping_add(0xa282_ead8)
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_records_and_builds_sorted_lazy_mappings() {
        let mut image = record(0x3000, b"second", false);
        image.extend_from_slice(&record(0x1000, b"first", true));
        let parsed = parse_avml_v2(&image).unwrap();

        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.source_length, image.len() as u64);
        assert_eq!(parsed.mapped_bytes, 11);
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[0].physical_start, 0x3000);
        assert_eq!(parsed.records[0].frame_offset, AVML_HEADER_SIZE as u64);
        assert_eq!(
            parsed.records[0].frame_statistics.checksum_verified_chunks,
            1
        );

        let spans = parsed.physical_spans(7);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start, 0x1000);
        assert_eq!(spans[0].source_index, 7);
        assert!(matches!(
            spans[0].encoding,
            MappingEncoding::SnappyFrame { encoded_length } if encoded_length > 0
        ));
        assert_eq!(spans[1].start, 0x3000);
    }

    #[test]
    fn verifies_crc32c_for_compressed_and_uncompressed_chunks() {
        let parsed = parse_avml_v2(&record(0, b"abcdef", true)).unwrap();
        assert_eq!(parsed.records[0].frame_statistics.compressed_data_chunks, 1);

        for compressed in [false, true] {
            let mut corrupt = record(0, b"abcdef", compressed);
            let crc_offset = AVML_HEADER_SIZE + 10 + 4;
            corrupt[crc_offset] ^= 1;
            let error = parse_avml_v2(&corrupt).unwrap_err();
            assert_eq!(error.kind, AvmlErrorKind::ChecksumMismatch);
        }
    }

    #[test]
    fn crc32c_matches_castagnoli_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(
            masked_crc32c(b"123456789"),
            0xe306_9283_u32.rotate_right(15).wrapping_add(0xa282_ead8)
        );
    }

    #[test]
    fn decodes_all_snappy_copy_tag_forms() {
        // COPY_1: literal "abcd", then copy four bytes from offset four.
        assert_eq!(
            decode_snappy_block(&[8, 12, b'a', b'b', b'c', b'd', 1, 4], 0).unwrap(),
            b"abcdabcd"
        );

        // COPY_2: literal "abc", then copy nine bytes from offset three.
        assert_eq!(
            decode_snappy_block(&[12, 8, b'a', b'b', b'c', 34, 3, 0], 0).unwrap(),
            b"abcabcabcabc"
        );

        // COPY_4: literal "x", then copy one byte from offset one.
        assert_eq!(
            decode_snappy_block(&[2, 0, b'x', 3, 1, 0, 0, 0], 0).unwrap(),
            b"xx"
        );
    }

    #[test]
    fn rejects_unknown_version_magic_and_padding() {
        let base = record(0, b"x", false);
        for (offset, bytes, expected) in [
            (0, 0u32.to_le_bytes().to_vec(), AvmlErrorKind::InvalidMagic),
            (
                4,
                3u32.to_le_bytes().to_vec(),
                AvmlErrorKind::UnsupportedVersion,
            ),
            (
                24,
                1u64.to_le_bytes().to_vec(),
                AvmlErrorKind::InvalidPadding,
            ),
        ] {
            let mut image = base.clone();
            image[offset..offset + bytes.len()].copy_from_slice(&bytes);
            assert_eq!(parse_avml_v2(&image).unwrap_err().kind, expected);
        }
    }

    #[test]
    fn rejects_inverted_overflowing_and_overlapping_ranges() {
        let mut inverted = record(5, b"x", false);
        inverted[16..24].copy_from_slice(&4u64.to_le_bytes());
        assert_eq!(
            parse_avml_v2(&inverted).unwrap_err().kind,
            AvmlErrorKind::InvalidRange
        );

        let mut overflowing = record(0, b"x", false);
        overflowing[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        overflowing[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            parse_avml_v2(&overflowing).unwrap_err().kind,
            AvmlErrorKind::IntegerOverflow
        );

        let mut overlapping = record(0x1000, b"abcd", false);
        overlapping.extend_from_slice(&record(0x1002, b"wxyz", false));
        assert_eq!(
            parse_avml_v2(&overlapping).unwrap_err().kind,
            AvmlErrorKind::OverlappingPhysicalRanges
        );

        // Range validation is intentionally performed before decoding the new record.  The
        // overlap therefore wins over this second record's deliberately corrupt CRC.
        let mut corrupt_overlap = record(0x1000, b"abcd", false);
        let second_offset = corrupt_overlap.len();
        corrupt_overlap.extend_from_slice(&record(0x1002, b"wxyz", false));
        corrupt_overlap[second_offset + AVML_HEADER_SIZE + 10 + 4] ^= 1;
        assert_eq!(
            parse_avml_v2(&corrupt_overlap).unwrap_err().kind,
            AvmlErrorKind::OverlappingPhysicalRanges
        );
    }

    #[test]
    fn rejects_truncation_and_mismatched_trailer() {
        let image = record(0, b"payload", false);
        assert_eq!(
            parse_avml_v2(&image[..image.len() - 1]).unwrap_err().kind,
            AvmlErrorKind::Truncated
        );

        let mut mismatched = image;
        let trailer = mismatched.len() - AVML_TRAILER_SIZE;
        mismatched[trailer..].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            parse_avml_v2(&mismatched).unwrap_err().kind,
            AvmlErrorKind::LengthMismatch
        );
    }

    #[test]
    fn rejects_unskippable_chunks_and_bad_first_identifier() {
        let mut unskippable = header(0, 0);
        push_chunk(&mut unskippable, 0xff, SNAPPY_STREAM_IDENTIFIER);
        push_chunk(&mut unskippable, 0x02, b"");
        let mut payload = masked_crc32c(b"x").to_le_bytes().to_vec();
        payload.push(b'x');
        push_chunk(&mut unskippable, 0x01, &payload);
        let encoded = unskippable.len() - AVML_HEADER_SIZE;
        unskippable.extend_from_slice(&(encoded as u64).to_le_bytes());
        assert_eq!(
            parse_avml_v2(&unskippable).unwrap_err().kind,
            AvmlErrorKind::UnsupportedSnappyChunk
        );

        let mut missing_identifier = header(0, 0);
        push_chunk(&mut missing_identifier, 0x01, &payload);
        let encoded = missing_identifier.len() - AVML_HEADER_SIZE;
        missing_identifier.extend_from_slice(&(encoded as u64).to_le_bytes());
        assert_eq!(
            parse_avml_v2(&missing_identifier).unwrap_err().kind,
            AvmlErrorKind::InvalidSnappyIdentifier
        );
    }

    #[test]
    fn accepts_skippable_chunks_but_keeps_them_in_encoded_mapping() {
        let mut image = header(0, 0);
        push_chunk(&mut image, 0xff, SNAPPY_STREAM_IDENTIFIER);
        push_chunk(&mut image, 0x80, b"future metadata");
        let mut payload = masked_crc32c(b"x").to_le_bytes().to_vec();
        payload.push(b'x');
        push_chunk(&mut image, 0x01, &payload);
        let encoded = image.len() - AVML_HEADER_SIZE;
        image.extend_from_slice(&(encoded as u64).to_le_bytes());

        let parsed = parse_avml_v2(&image).unwrap();
        assert_eq!(parsed.records[0].encoded_length, encoded as u64);
        assert_eq!(parsed.records[0].frame_statistics.skippable_chunks, 1);
    }

    #[test]
    fn enforces_record_chunk_and_byte_limits() {
        let image = record(0, b"abcd", false);
        let limits = AvmlParseLimits {
            max_decoded_record_bytes: 3,
            ..AvmlParseLimits::default()
        };
        assert_eq!(
            parse_avml_v2_with_limits(&image, limits).unwrap_err().kind,
            AvmlErrorKind::LimitExceeded
        );

        let limits = AvmlParseLimits {
            max_chunks_per_record: 1,
            ..AvmlParseLimits::default()
        };
        assert_eq!(
            parse_avml_v2_with_limits(&image, limits).unwrap_err().kind,
            AvmlErrorKind::LimitExceeded
        );

        let mut two = image;
        two.extend_from_slice(&record(0x1000, b"z", false));
        let limits = AvmlParseLimits {
            max_records: 1,
            ..AvmlParseLimits::default()
        };
        assert_eq!(
            parse_avml_v2_with_limits(&two, limits).unwrap_err().kind,
            AvmlErrorKind::LimitExceeded
        );

        let image = record(0, b"abcd", false);
        let limits = AvmlParseLimits {
            max_encoded_record_bytes: 10,
            ..AvmlParseLimits::default()
        };
        assert_eq!(
            parse_avml_v2_with_limits(&image, limits).unwrap_err().kind,
            AvmlErrorKind::LimitExceeded
        );

        let limits = AvmlParseLimits {
            max_total_mapped_bytes: 3,
            ..AvmlParseLimits::default()
        };
        assert_eq!(
            parse_avml_v2_with_limits(&image, limits).unwrap_err().kind,
            AvmlErrorKind::LimitExceeded
        );

        let limits = AvmlParseLimits {
            max_records: 0,
            ..AvmlParseLimits::default()
        };
        assert_eq!(
            parse_avml_v2_with_limits(&image, limits).unwrap_err().kind,
            AvmlErrorKind::LimitExceeded
        );
    }

    #[test]
    fn lazy_mapping_defers_but_does_not_claim_crc_verification() {
        let mut corrupt = record(0, b"abcdef", true);
        let crc_offset = AVML_HEADER_SIZE + 10 + 4;
        corrupt[crc_offset] ^= 1;

        let lazy = map_avml_v2_for_lazy_decode(&corrupt).unwrap();
        assert!(!lazy.checksums_verified_during_parse);
        assert_eq!(lazy.records.len(), 1);
        assert_eq!(
            parse_avml_v2(&corrupt).unwrap_err().kind,
            AvmlErrorKind::ChecksumMismatch
        );
    }

    #[test]
    fn rejects_snappy_chunk_decoded_overrun_and_trailing_block_bytes() {
        let mut overrun = header(0, 0);
        push_chunk(&mut overrun, 0xff, SNAPPY_STREAM_IDENTIFIER);
        let mut payload = masked_crc32c(b"xy").to_le_bytes().to_vec();
        payload.extend_from_slice(b"xy");
        push_chunk(&mut overrun, 0x01, &payload);
        let encoded = overrun.len() - AVML_HEADER_SIZE;
        overrun.extend_from_slice(&(encoded as u64).to_le_bytes());
        assert_eq!(
            parse_avml_v2(&overrun).unwrap_err().kind,
            AvmlErrorKind::LengthMismatch
        );

        let mut trailing = header(0, 0);
        push_chunk(&mut trailing, 0xff, SNAPPY_STREAM_IDENTIFIER);
        let mut raw = raw_snappy_literal(b"x");
        raw.push(0);
        let mut payload = masked_crc32c(b"x").to_le_bytes().to_vec();
        payload.extend_from_slice(&raw);
        push_chunk(&mut trailing, 0x00, &payload);
        let encoded = trailing.len() - AVML_HEADER_SIZE;
        trailing.extend_from_slice(&(encoded as u64).to_le_bytes());
        assert_eq!(
            parse_avml_v2(&trailing).unwrap_err().kind,
            AvmlErrorKind::InvalidSnappyChunk
        );
    }

    fn record(start: u64, decoded: &[u8], compressed: bool) -> Vec<u8> {
        assert!(!decoded.is_empty());
        let mut output = header(start, start + decoded.len() as u64 - 1);
        push_chunk(&mut output, 0xff, SNAPPY_STREAM_IDENTIFIER);
        let mut payload = masked_crc32c(decoded).to_le_bytes().to_vec();
        if compressed {
            payload.extend_from_slice(&raw_snappy_literal(decoded));
            push_chunk(&mut output, 0x00, &payload);
        } else {
            payload.extend_from_slice(decoded);
            push_chunk(&mut output, 0x01, &payload);
        }
        let encoded_length = output.len() - AVML_HEADER_SIZE;
        output.extend_from_slice(&(encoded_length as u64).to_le_bytes());
        output
    }

    fn header(start: u64, end_inclusive: u64) -> Vec<u8> {
        let mut output = Vec::with_capacity(AVML_HEADER_SIZE);
        output.extend_from_slice(&AVML_MAGIC.to_le_bytes());
        output.extend_from_slice(&AVML_VERSION.to_le_bytes());
        output.extend_from_slice(&start.to_le_bytes());
        output.extend_from_slice(&end_inclusive.to_le_bytes());
        output.extend_from_slice(&0u64.to_le_bytes());
        output
    }

    fn push_chunk(output: &mut Vec<u8>, chunk_type: u8, payload: &[u8]) {
        assert!(payload.len() <= 0x00ff_ffff);
        output.push(chunk_type);
        output.extend_from_slice(&(payload.len() as u32).to_le_bytes()[..3]);
        output.extend_from_slice(payload);
    }

    fn raw_snappy_literal(decoded: &[u8]) -> Vec<u8> {
        assert!(!decoded.is_empty() && decoded.len() < 60);
        let mut output = Vec::with_capacity(decoded.len() + 2);
        output.push(decoded.len() as u8);
        output.push(((decoded.len() - 1) as u8) << 2);
        output.extend_from_slice(decoded);
        output
    }
}
