//! Decoders used by non-linear physical mappings.

use anyhow::{Context, Result, bail, ensure};

const SNAPPY_STREAM_IDENTIFIER: &[u8] = b"sNaPpY";

/// Decode one complete Snappy framed stream and verify every data-chunk checksum.
pub(super) fn decode_snappy_frame(encoded: &[u8], expected_length: usize) -> Result<Vec<u8>> {
    let mut cursor = 0usize;
    let mut output = Vec::with_capacity(expected_length);
    let mut saw_stream_identifier = false;

    while cursor < encoded.len() {
        ensure!(
            encoded.len() - cursor >= 4,
            "Snappy framed chunk header 被截断"
        );
        let chunk_type = encoded[cursor];
        let chunk_length = usize::from(encoded[cursor + 1])
            | (usize::from(encoded[cursor + 2]) << 8)
            | (usize::from(encoded[cursor + 3]) << 16);
        cursor += 4;
        let end = cursor
            .checked_add(chunk_length)
            .context("Snappy framed chunk 长度溢出")?;
        let chunk = encoded
            .get(cursor..end)
            .context("Snappy framed chunk 超出映射末尾")?;
        cursor = end;

        match chunk_type {
            0xff => {
                ensure!(
                    chunk == SNAPPY_STREAM_IDENTIFIER,
                    "Snappy stream identifier 无效"
                );
                saw_stream_identifier = true;
            }
            0x00 | 0x01 => {
                ensure!(
                    saw_stream_identifier,
                    "Snappy 数据块出现在 stream identifier 之前"
                );
                ensure!(chunk.len() >= 4, "Snappy 数据块缺少 CRC32C");
                let expected_crc = u32::from_le_bytes(chunk[..4].try_into()?);
                let decoded = if chunk_type == 0x00 {
                    decode_snappy_block(&chunk[4..])?
                } else {
                    chunk[4..].to_vec()
                };
                ensure!(
                    masked_crc32c(&decoded) == expected_crc,
                    "Snappy framed chunk CRC32C 校验失败"
                );
                ensure!(
                    output.len().saturating_add(decoded.len()) <= expected_length,
                    "Snappy 解码结果超出声明长度"
                );
                output.extend_from_slice(&decoded);
            }
            0x80..=0xfe => {
                // Skippable chunks are part of the framed format's forward-compatibility
                // contract and do not contribute decoded bytes.
            }
            _ => bail!("不支持的 Snappy unskippable chunk type {chunk_type:#04x}"),
        }
    }
    ensure!(saw_stream_identifier, "缺少 Snappy stream identifier");
    ensure!(
        output.len() == expected_length,
        "Snappy 解码长度不一致：声明={expected_length}，实际={}",
        output.len()
    );
    Ok(output)
}

fn decode_snappy_block(encoded: &[u8]) -> Result<Vec<u8>> {
    let (decoded_length, mut cursor) = read_varint(encoded)?;
    let decoded_length = usize::try_from(decoded_length).context("Snappy block 太大")?;
    let mut output = Vec::with_capacity(decoded_length);

    while cursor < encoded.len() && output.len() < decoded_length {
        let tag = encoded[cursor];
        cursor += 1;
        match tag & 0x03 {
            0 => {
                let length_code = usize::from(tag >> 2);
                let length = if length_code < 60 {
                    length_code + 1
                } else {
                    let bytes = length_code - 59;
                    ensure!(bytes <= 4, "Snappy literal 长度字段无效");
                    let end = cursor
                        .checked_add(bytes)
                        .context("Snappy literal 长度溢出")?;
                    let raw = encoded
                        .get(cursor..end)
                        .context("Snappy literal 长度被截断")?;
                    cursor = end;
                    let mut value = 0usize;
                    for (shift, byte) in raw.iter().enumerate() {
                        value |= usize::from(*byte) << (shift * 8);
                    }
                    value.checked_add(1).context("Snappy literal 长度溢出")?
                };
                let end = cursor
                    .checked_add(length)
                    .context("Snappy literal 范围溢出")?;
                let literal = encoded.get(cursor..end).context("Snappy literal 被截断")?;
                ensure!(
                    output.len().saturating_add(literal.len()) <= decoded_length,
                    "Snappy literal 超出声明长度"
                );
                output.extend_from_slice(literal);
                cursor = end;
            }
            1 => {
                let length = 4 + usize::from((tag >> 2) & 0x07);
                let low = usize::from(*encoded.get(cursor).context("Snappy COPY_1 被截断")?);
                cursor += 1;
                let offset = (usize::from(tag & 0xe0) << 3) | low;
                copy_from_history(&mut output, offset, length, decoded_length)?;
            }
            2 => {
                let length = 1 + usize::from(tag >> 2);
                let raw: [u8; 2] = encoded
                    .get(cursor..cursor + 2)
                    .context("Snappy COPY_2 被截断")?
                    .try_into()?;
                cursor += 2;
                copy_from_history(
                    &mut output,
                    usize::from(u16::from_le_bytes(raw)),
                    length,
                    decoded_length,
                )?;
            }
            3 => {
                let length = 1 + usize::from(tag >> 2);
                let raw: [u8; 4] = encoded
                    .get(cursor..cursor + 4)
                    .context("Snappy COPY_4 被截断")?
                    .try_into()?;
                cursor += 4;
                let offset = usize::try_from(u32::from_le_bytes(raw))?;
                copy_from_history(&mut output, offset, length, decoded_length)?;
            }
            _ => unreachable!(),
        }
    }
    ensure!(
        output.len() == decoded_length,
        "Snappy block 解码长度不一致：声明={decoded_length}，实际={}",
        output.len()
    );
    ensure!(cursor == encoded.len(), "Snappy block 含有尾随数据");
    Ok(output)
}

fn read_varint(bytes: &[u8]) -> Result<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().copied().take(10).enumerate() {
        let payload = u64::from(byte & 0x7f);
        ensure!(index != 9 || payload <= 1, "Snappy varint 溢出");
        value |= payload << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    bail!("Snappy varint 被截断或过长")
}

fn copy_from_history(
    output: &mut Vec<u8>,
    offset: usize,
    length: usize,
    decoded_length: usize,
) -> Result<()> {
    ensure!(
        offset > 0 && offset <= output.len(),
        "Snappy COPY offset 无效"
    );
    ensure!(
        output.len().saturating_add(length) <= decoded_length,
        "Snappy COPY 超出声明长度"
    );
    for _ in 0..length {
        let value = output[output.len() - offset];
        output.push(value);
    }
    Ok(())
}

pub(super) fn masked_crc32c(bytes: &[u8]) -> u32 {
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
    fn decodes_uncompressed_and_compressed_literal_chunks() {
        let first = b"direct";
        let second = b"snappy";
        let mut frame = Vec::new();
        push_chunk(&mut frame, 0xff, SNAPPY_STREAM_IDENTIFIER);

        let mut uncompressed = masked_crc32c(first).to_le_bytes().to_vec();
        uncompressed.extend_from_slice(first);
        push_chunk(&mut frame, 0x01, &uncompressed);

        let mut raw_block = vec![second.len() as u8, ((second.len() - 1) as u8) << 2];
        raw_block.extend_from_slice(second);
        let mut compressed = masked_crc32c(second).to_le_bytes().to_vec();
        compressed.extend_from_slice(&raw_block);
        push_chunk(&mut frame, 0x00, &compressed);

        assert_eq!(
            decode_snappy_frame(&frame, first.len() + second.len()).unwrap(),
            b"directsnappy"
        );
    }

    #[test]
    fn rejects_checksum_damage_and_invalid_history_offsets() {
        let mut frame = Vec::new();
        push_chunk(&mut frame, 0xff, SNAPPY_STREAM_IDENTIFIER);
        let mut chunk = 0u32.to_le_bytes().to_vec();
        chunk.extend_from_slice(b"bad");
        push_chunk(&mut frame, 0x01, &chunk);
        assert!(decode_snappy_frame(&frame, 3).is_err());
        assert!(decode_snappy_block(&[4, 1, 0]).is_err());
    }

    fn push_chunk(output: &mut Vec<u8>, chunk_type: u8, payload: &[u8]) {
        output.push(chunk_type);
        let length = payload.len() as u32;
        output.extend_from_slice(&length.to_le_bytes()[..3]);
        output.extend_from_slice(payload);
    }
}
