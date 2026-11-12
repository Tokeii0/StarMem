//! Windows x64 type-5 bitmap crash dumps. Bit N describes physical page N;
//! only set pages are stored, in PFN order, starting at Summary.HeaderSize.

use anyhow::{Context, Result, ensure};

use super::{MappingEncoding, PhysicalSpan, WindowsDumpBitmap64, read_u64};

const SUMMARY_OFFSET: usize = 0x2000;
const BITMAP_OFFSET: usize = SUMMARY_OFFSET + 0x38;
const PAGE_SIZE: u64 = 0x1000;

pub(super) fn parse(
    bytes: &[u8],
    file_len: u64,
) -> Result<(WindowsDumpBitmap64, Vec<PhysicalSpan>)> {
    let signature = bytes
        .get(SUMMARY_OFFSET..SUMMARY_OFFSET + 8)
        .context("Windows 位图转储头被截断")?;
    ensure!(
        signature == b"FDMPDUMP" || signature == b"SDMPDUMP",
        "Windows 位图转储需要 FDMPDUMP 或 SDMPDUMP 签名"
    );
    let header_size = read_u64(bytes, SUMMARY_OFFSET + 0x20)?;
    let present_pages = read_u64(bytes, SUMMARY_OFFSET + 0x28)?;
    let bitmap_size = read_u64(bytes, SUMMARY_OFFSET + 0x30)?;
    ensure!(
        present_pages > 0 && present_pages <= bitmap_size,
        "Windows 位图转储页数不合理：已保存 {present_pages}，位图 {bitmap_size} 位"
    );
    bitmap_size
        .checked_mul(PAGE_SIZE)
        .context("Windows 位图转储物理地址范围溢出")?;
    let bitmap_len =
        usize::try_from(bitmap_size.div_ceil(8)).context("Windows 转储位图长度超出地址范围")?;
    let bitmap_end = BITMAP_OFFSET
        .checked_add(bitmap_len)
        .context("Windows 转储位图末尾溢出")?;
    ensure!(
        header_size >= bitmap_end as u64 && header_size <= file_len,
        "Windows 位图转储页面数据偏移 {header_size:#x} 与位图或文件边界冲突"
    );
    let bitmap = bytes
        .get(BITMAP_OFFSET..bitmap_end)
        .context("Windows 转储位图被截断")?;
    let payload_end = present_pages
        .checked_mul(PAGE_SIZE)
        .and_then(|length| header_size.checked_add(length))
        .context("Windows 位图转储页面数据范围溢出")?;
    ensure!(
        payload_end <= file_len,
        "Windows 位图转储页面数据超出文件末尾"
    );

    let valid_byte = |index: usize, byte: u8| {
        let bits = (bitmap_size - index as u64 * 8).min(8) as u32;
        byte & ((1u16 << bits) - 1) as u8
    };
    let counted_pages: u64 = bitmap
        .iter()
        .enumerate()
        .map(|(index, &byte)| u64::from(valid_byte(index, byte).count_ones()))
        .sum();
    ensure!(
        counted_pages == present_pages,
        "Windows 位图转储页数与位图不一致：头部={present_pages}，位图={counted_pages}"
    );

    let mut spans: Vec<PhysicalSpan> = Vec::new();
    let mut file_offset = header_size;
    for (index, &byte) in bitmap.iter().enumerate() {
        let mut bits = valid_byte(index, byte);
        while bits != 0 {
            let bit = bits.trailing_zeros();
            let start = (index as u64 * 8 + u64::from(bit)) * PAGE_SIZE;
            if let Some(previous) = spans.last_mut().filter(|span| span.end() == start) {
                previous.length += PAGE_SIZE;
            } else {
                spans.push(PhysicalSpan {
                    start,
                    length: PAGE_SIZE,
                    file_offset,
                    source_index: 0,
                    encoding: MappingEncoding::Direct,
                });
            }
            file_offset += PAGE_SIZE;
            bits &= bits - 1;
        }
    }
    Ok((
        WindowsDumpBitmap64 {
            signature: String::from_utf8_lossy(signature).into_owned(),
            header_size,
            present_pages,
            bitmap_size,
        },
        spans,
    ))
}
