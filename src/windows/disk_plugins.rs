use std::collections::HashSet;

use anyhow::{Result, bail, ensure};
use serde::Serialize;
use sha1::Digest;
use sha2::Sha256;

use super::filetime_to_rfc3339;
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::scan::{scan_exact, scan_exact_4_cancellable};

#[derive(Debug, Clone, Copy)]
pub enum MftView {
    All,
    AlternateDataStreams,
    ResidentData,
}

#[derive(Debug, Serialize)]
pub struct MftScanReport {
    pub records: Vec<MftRecord>,
    pub bytes_scanned: u64,
    pub elapsed_seconds: f64,
    pub gib_per_second: f64,
    pub raw_signature_hits: usize,
    pub validated_records: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MftRecord {
    pub physical_address: u64,
    pub record_number: u32,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub flags: u16,
    pub in_use: bool,
    pub directory: bool,
    pub bytes_in_use: u32,
    pub bytes_allocated: u32,
    pub base_file_reference: u64,
    pub standard_information: Option<NtfsTimestamps>,
    pub file_names: Vec<MftFileNameRecord>,
    pub data_attributes: Vec<MftDataRecord>,
}

#[derive(Debug, Serialize)]
pub struct NtfsTimestamps {
    pub created: Option<String>,
    pub modified: Option<String>,
    pub mft_changed: Option<String>,
    pub accessed: Option<String>,
    pub created_raw: u64,
    pub modified_raw: u64,
    pub mft_changed_raw: u64,
    pub accessed_raw: u64,
}

#[derive(Debug, Serialize)]
pub struct MftFileNameRecord {
    pub parent_record: u64,
    pub parent_sequence: u16,
    pub namespace: u8,
    pub name: String,
    pub allocated_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub timestamps: NtfsTimestamps,
}

#[derive(Debug, Serialize)]
pub struct MftDataRecord {
    pub attribute_id: u16,
    pub name: Option<String>,
    pub alternate_data_stream: bool,
    pub resident: bool,
    pub data_size: u64,
    pub value_hex: Option<String>,
    pub value_truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct MftDumpReport {
    pub mft_physical_address: u64,
    pub record_number: u32,
    pub sequence_number: u16,
    pub attribute_id: u16,
    pub stream_name: Option<String>,
    pub file_name: Option<String>,
    pub data_physical_address: u64,
    pub logical_size: u64,
    pub output_size: u64,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub sha256: String,
}

#[derive(Debug)]
struct ParsedMftRecord {
    record: MftRecord,
    resident_data: Vec<MftResidentValue>,
}

#[derive(Debug)]
struct MftResidentValue {
    attribute_id: u16,
    name: Option<String>,
    physical_address: u64,
    value: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct MbrScanReport {
    pub records: Vec<MbrRecord>,
    pub bytes_scanned: u64,
    pub elapsed_seconds: f64,
    pub gib_per_second: f64,
    pub raw_signature_hits: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MbrRecord {
    pub physical_address: u64,
    pub disk_signature: u32,
    pub boot_code_sha1: String,
    pub partitions: Vec<MbrPartitionRecord>,
}

#[derive(Debug, Serialize)]
pub struct MbrPartitionRecord {
    pub index: u8,
    pub bootable: bool,
    pub partition_type: u8,
    pub start_lba: u32,
    pub sector_count: u32,
    pub byte_offset: u64,
    pub byte_length: u64,
}

pub fn scan_mft(image: &MemoryImage, view: MftView, limit: usize) -> Result<MftScanReport> {
    scan_mft_cancellable(image, view, limit, &CancellationToken::new())
}

pub fn scan_mft_cancellable(
    image: &MemoryImage,
    view: MftView,
    limit: usize,
    cancellation: &CancellationToken,
) -> Result<MftScanReport> {
    cancellation.check_cancelled()?;
    ensure!(limit > 0, "MFT 结果上限必须大于零");
    const RAW_HIT_LIMIT: usize = 4_000_000;
    let scan = scan_exact_4_cancellable(
        image,
        &[*b"FILE"],
        RAW_HIT_LIMIT,
        64 * 1024 * 1024,
        cancellation,
    )?;
    let raw_signature_hits = scan.hits.len();
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for hit in scan.hits {
        cancellation.check_cancelled()?;
        if hit.physical_address & 7 != 0 || !seen.insert(hit.physical_address) {
            continue;
        }
        let Some(record) = parse_mft_record(image, hit.physical_address) else {
            continue;
        };
        let keep = match view {
            MftView::All => true,
            MftView::AlternateDataStreams => record
                .data_attributes
                .iter()
                .any(|data| data.alternate_data_stream),
            MftView::ResidentData => record.data_attributes.iter().any(|data| data.resident),
        };
        if keep {
            records.push(record);
        }
    }
    records.sort_unstable_by_key(|record| (record.record_number, record.physical_address));
    let validated_records = records.len();
    let truncated = records.len() > limit;
    records.truncate(limit);
    let mut warnings = Vec::new();
    if scan.truncated {
        warnings.push(format!("已达到 MFT 原始签名安全上限 {RAW_HIT_LIMIT}"));
    }
    if truncated {
        warnings.push(format!("已达到 MFT 结果上限 {limit}"));
    }
    Ok(MftScanReport {
        records,
        bytes_scanned: scan.bytes_scanned,
        elapsed_seconds: scan.elapsed_seconds,
        gib_per_second: scan.gib_per_second,
        raw_signature_hits,
        validated_records,
        complete: !scan.truncated && !truncated,
        warnings,
    })
}

/// 从指定 MFT FILE 记录恢复完整的常驻 `$DATA` 属性。
///
/// 物理地址必须来自 `mftscan`。非常驻数据只包含磁盘簇映射，内存镜像并不保证
/// 相应磁盘簇存在，因此本函数会明确拒绝，避免将缺失内容伪装成完整文件。
pub fn recover_mft_resident_data(
    image: &MemoryImage,
    physical_address: u64,
    attribute_id: Option<u16>,
    stream_name: Option<&str>,
    max_size: u64,
) -> Result<(MftDumpReport, Vec<u8>)> {
    ensure!(max_size > 0, "最大导出大小必须大于零");
    ensure!(
        attribute_id.is_none() || stream_name.is_none(),
        "属性 ID 和流名称不能同时指定"
    );
    let parsed = parse_mft_record_with_data(image, physical_address).ok_or_else(|| {
        anyhow::anyhow!("物理地址 {physical_address:#x} 不是有效的 MFT FILE 记录")
    })?;
    let normalized_stream = stream_name.and_then(|name| {
        let name = name.trim();
        (!name.is_empty() && !name.eq_ignore_ascii_case("$DATA")).then_some(name)
    });
    let matches_request = |data: &MftDataRecord| {
        if let Some(id) = attribute_id {
            return data.attribute_id == id;
        }
        match normalized_stream {
            Some(name) => data
                .name
                .as_deref()
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name)),
            None => data.name.is_none(),
        }
    };
    let matching = parsed
        .record
        .data_attributes
        .iter()
        .filter(|data| matches_request(data))
        .collect::<Vec<_>>();
    if matching.is_empty() {
        let available = parsed
            .record
            .data_attributes
            .iter()
            .map(|data| {
                format!(
                    "ID={} {} ({})",
                    data.attribute_id,
                    data.name.as_deref().unwrap_or("$DATA"),
                    if data.resident { "常驻" } else { "非常驻" }
                )
            })
            .collect::<Vec<_>>()
            .join("；");
        bail!(
            "记录 {} 中没有匹配的 $DATA 属性；可用属性：{}",
            parsed.record.record_number,
            if available.is_empty() {
                "无".to_owned()
            } else {
                available
            }
        );
    }
    ensure!(
        matching.len() == 1,
        "匹配到多个 $DATA 属性，请改用属性 ID 精确选择"
    );
    let metadata = matching[0];
    ensure!(
        metadata.resident,
        "属性 ID={}（{}）是非常驻数据；内存镜像中没有可证明完整的磁盘簇内容，拒绝伪造导出",
        metadata.attribute_id,
        metadata.name.as_deref().unwrap_or("$DATA")
    );
    ensure!(
        metadata.data_size <= max_size,
        "常驻数据大小 {} 字节超过安全上限 {} 字节",
        metadata.data_size,
        max_size
    );
    let value = parsed
        .resident_data
        .into_iter()
        .find(|value| value.attribute_id == metadata.attribute_id && value.name == metadata.name)
        .ok_or_else(|| anyhow::anyhow!("MFT 常驻数据属性通过验证，但完整属性值不可读取"))?;
    let size = value.value.len() as u64;
    ensure!(
        size == metadata.data_size,
        "MFT 常驻数据长度不一致：声明 {} 字节，实际读取 {} 字节",
        metadata.data_size,
        size
    );
    let file_name = preferred_mft_name(&parsed.record).map(str::to_owned);
    let sha256 = hex::encode(Sha256::digest(&value.value));
    let report = MftDumpReport {
        mft_physical_address: physical_address,
        record_number: parsed.record.record_number,
        sequence_number: parsed.record.sequence_number,
        attribute_id: value.attribute_id,
        stream_name: value.name,
        file_name,
        data_physical_address: value.physical_address,
        logical_size: size,
        output_size: size,
        recovered_bytes: size,
        missing_bytes: 0,
        complete: true,
        sha256,
    };
    Ok((report, value.value))
}

pub fn scan_mbr(image: &MemoryImage, limit: usize) -> Result<MbrScanReport> {
    ensure!(limit > 0, "MBR result limit must be greater than zero");
    const RAW_HIT_LIMIT: usize = 1_000_000;
    let scan = scan_exact(image, &[0x55, 0xaa], RAW_HIT_LIMIT, 64 * 1024 * 1024)?;
    let raw_signature_hits = scan.hits.len();
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for hit in scan.hits.iter() {
        let Some(start) = hit.physical_address.checked_sub(510) else {
            continue;
        };
        if !seen.insert(start) {
            continue;
        }
        let mut sector = [0u8; 512];
        if image.read_physical(start, &mut sector).is_err() {
            continue;
        }
        let Some(partitions) = parse_mbr_partitions(&sector) else {
            continue;
        };
        let digest = sha1::Sha1::digest(&sector[..440]);
        records.push(MbrRecord {
            physical_address: start,
            disk_signature: le_u32(&sector, 440).unwrap_or(0),
            boot_code_sha1: hex::encode(digest),
            partitions,
        });
    }
    records.sort_unstable_by_key(|record| record.physical_address);
    let truncated = records.len() > limit;
    records.truncate(limit);
    let mut warnings = Vec::new();
    if scan.truncated {
        warnings.push(format!(
            "MBR signature safety limit {RAW_HIT_LIMIT} reached"
        ));
    }
    if truncated {
        warnings.push(format!("MBR result limit {limit} reached"));
    }
    Ok(MbrScanReport {
        records,
        bytes_scanned: scan.bytes_scanned,
        elapsed_seconds: scan.elapsed_seconds,
        gib_per_second: scan.gib_per_second,
        raw_signature_hits,
        complete: !scan.truncated && !truncated,
        warnings,
    })
}

fn parse_mft_record(image: &MemoryImage, physical: u64) -> Option<MftRecord> {
    parse_mft_record_with_data(image, physical).map(|parsed| parsed.record)
}

fn parse_mft_record_with_data(image: &MemoryImage, physical: u64) -> Option<ParsedMftRecord> {
    let mut header = [0u8; 64];
    image.read_physical(physical, &mut header).ok()?;
    if &header[..4] != b"FILE" {
        return None;
    }
    let update_sequence_offset = usize::from(le_u16(&header, 4)?);
    let update_sequence_count = usize::from(le_u16(&header, 6)?);
    let sequence_number = le_u16(&header, 16)?;
    let hard_link_count = le_u16(&header, 18)?;
    let first_attribute = usize::from(le_u16(&header, 20)?);
    let flags = le_u16(&header, 22)?;
    let bytes_in_use = le_u32(&header, 24)?;
    let bytes_allocated = le_u32(&header, 28)?;
    let base_file_reference = le_u64(&header, 32)?;
    let record_number = le_u32(&header, 44)?;
    if !(0x28..=0x200).contains(&update_sequence_offset)
        || !(1..=33).contains(&update_sequence_count)
        || !(0x30..=0x400).contains(&first_attribute)
        || bytes_in_use < first_attribute as u32
        || bytes_allocated < bytes_in_use
        || !(512..=65_536).contains(&bytes_allocated)
        || !bytes_allocated.is_power_of_two()
    {
        return None;
    }
    let read_size = usize::try_from(bytes_allocated.min(65_536)).ok()?;
    let mut bytes = vec![0u8; read_size];
    image.read_physical(physical, &mut bytes).ok()?;
    let parse_end = usize::try_from(bytes_in_use).ok()?.min(bytes.len());
    let mut offset = first_attribute;
    let mut standard_information = None;
    let mut file_names = Vec::new();
    let mut data_attributes = Vec::new();
    let mut resident_data = Vec::new();
    let mut attributes_seen = 0usize;
    while offset + 16 <= parse_end && attributes_seen < 1024 {
        attributes_seen += 1;
        let attribute_type = le_u32(&bytes, offset)?;
        if attribute_type == 0xffff_ffff {
            break;
        }
        let length = usize::try_from(le_u32(&bytes, offset + 4)?).ok()?;
        if length < 16 || offset.checked_add(length)? > parse_end {
            return None;
        }
        let nonresident = bytes[offset + 8] != 0;
        let name_length = usize::from(bytes[offset + 9]);
        let name_offset = usize::from(le_u16(&bytes, offset + 10)?);
        let attribute_id = le_u16(&bytes, offset + 14)?;
        let name = if name_length != 0 {
            decode_utf16(&bytes, offset + name_offset, name_length)
        } else {
            None
        };
        if nonresident {
            if attribute_type == 0x80 {
                data_attributes.push(MftDataRecord {
                    attribute_id,
                    alternate_data_stream: name.is_some(),
                    name,
                    resident: false,
                    data_size: le_u64(&bytes, offset + 48).unwrap_or(0),
                    value_hex: None,
                    value_truncated: false,
                });
            }
            offset += length;
            continue;
        }
        if length < 24 {
            return None;
        }
        let value_length = usize::try_from(le_u32(&bytes, offset + 16)?).ok()?;
        let value_offset = usize::from(le_u16(&bytes, offset + 20)?);
        let value_start = offset.checked_add(value_offset)?;
        let value_end = value_start.checked_add(value_length)?;
        if value_start < offset || value_end > offset + length {
            return None;
        }
        let value = &bytes[value_start..value_end];
        match attribute_type {
            0x10 if value.len() >= 32 => standard_information = parse_timestamps(value, 0),
            0x30 if value.len() >= 66 => {
                let file_name_length = usize::from(value[64]);
                if let Some(file_name) = decode_utf16(value, 66, file_name_length) {
                    let parent = le_u64(value, 0).unwrap_or(0);
                    if let Some(timestamps) = parse_timestamps(value, 8) {
                        file_names.push(MftFileNameRecord {
                            parent_record: parent & 0x0000_ffff_ffff_ffff,
                            parent_sequence: (parent >> 48) as u16,
                            namespace: value[65],
                            name: file_name,
                            allocated_size: le_u64(value, 40).unwrap_or(0),
                            real_size: le_u64(value, 48).unwrap_or(0),
                            flags: le_u32(value, 56).unwrap_or(0),
                            timestamps,
                        });
                    }
                }
            }
            0x80 => {
                const PREVIEW_LIMIT: usize = 4096;
                data_attributes.push(MftDataRecord {
                    attribute_id,
                    alternate_data_stream: name.is_some(),
                    name: name.clone(),
                    resident: true,
                    data_size: value.len() as u64,
                    value_hex: Some(hex::encode(&value[..value.len().min(PREVIEW_LIMIT)])),
                    value_truncated: value.len() > PREVIEW_LIMIT,
                });
                resident_data.push(MftResidentValue {
                    attribute_id,
                    name,
                    physical_address: physical.checked_add(value_start as u64)?,
                    value: value.to_vec(),
                });
            }
            _ => {}
        }
        offset += length;
    }
    if attributes_seen == 0 || (standard_information.is_none() && file_names.is_empty()) {
        return None;
    }
    Some(ParsedMftRecord {
        record: MftRecord {
            physical_address: physical,
            record_number,
            sequence_number,
            hard_link_count,
            flags,
            in_use: flags & 1 != 0,
            directory: flags & 2 != 0,
            bytes_in_use,
            bytes_allocated,
            base_file_reference,
            standard_information,
            file_names,
            data_attributes,
        },
        resident_data,
    })
}

fn preferred_mft_name(record: &MftRecord) -> Option<&str> {
    record
        .file_names
        .iter()
        .find(|name| matches!(name.namespace, 1 | 3))
        .or_else(|| record.file_names.first())
        .map(|name| name.name.as_str())
}

fn parse_timestamps(bytes: &[u8], offset: usize) -> Option<NtfsTimestamps> {
    let created_raw = le_u64(bytes, offset)?;
    let modified_raw = le_u64(bytes, offset + 8)?;
    let mft_changed_raw = le_u64(bytes, offset + 16)?;
    let accessed_raw = le_u64(bytes, offset + 24)?;
    Some(NtfsTimestamps {
        created: filetime_to_rfc3339(created_raw),
        modified: filetime_to_rfc3339(modified_raw),
        mft_changed: filetime_to_rfc3339(mft_changed_raw),
        accessed: filetime_to_rfc3339(accessed_raw),
        created_raw,
        modified_raw,
        mft_changed_raw,
        accessed_raw,
    })
}

fn parse_mbr_partitions(sector: &[u8; 512]) -> Option<Vec<MbrPartitionRecord>> {
    if sector[510..] != [0x55, 0xaa] {
        return None;
    }
    let mut partitions = Vec::new();
    let mut active_partitions = 0usize;
    for index in 0..4usize {
        let offset = 446 + index * 16;
        let status = sector[offset];
        let partition_type = sector[offset + 4];
        let start_lba = le_u32(sector, offset + 8)?;
        let sector_count = le_u32(sector, offset + 12)?;
        if status != 0 && status != 0x80 {
            return None;
        }
        if partition_type == 0 && start_lba == 0 && sector_count == 0 {
            continue;
        }
        if partition_type == 0
            || !known_partition_type(partition_type)
            || sector_count == 0
            || (sector_count == u32::MAX && partition_type != 0xee)
            || u64::from(start_lba) + u64::from(sector_count) > u64::from(u32::MAX) + 1
        {
            return None;
        }
        active_partitions += usize::from(status == 0x80);
        partitions.push(MbrPartitionRecord {
            index: index as u8,
            bootable: status == 0x80,
            partition_type,
            start_lba,
            sector_count,
            byte_offset: u64::from(start_lba) * 512,
            byte_length: u64::from(sector_count) * 512,
        });
    }
    if partitions.is_empty() || active_partitions > 1 {
        return None;
    }
    let protective = partitions.len() == 1
        && partitions[0].partition_type == 0xee
        && partitions[0].start_lba == 1;
    if !protective {
        let mut previous_end = 0u64;
        for partition in &partitions {
            let start = u64::from(partition.start_lba);
            if start < previous_end {
                return None;
            }
            previous_end = start + u64::from(partition.sector_count);
        }
        let boot_code = &sector[..440];
        let nonzero = boot_code.iter().filter(|byte| **byte != 0).count();
        let plausible_entry = matches!(boot_code[0], 0x33 | 0xfa | 0xeb | 0xe9 | 0xfc);
        if nonzero < 32 || !plausible_entry {
            return None;
        }
    }
    Some(partitions)
}

fn known_partition_type(partition_type: u8) -> bool {
    matches!(
        partition_type,
        0x01 | 0x04
            | 0x05
            | 0x06
            | 0x07
            | 0x0b
            | 0x0c
            | 0x0e
            | 0x0f
            | 0x11
            | 0x12
            | 0x14
            | 0x16
            | 0x17
            | 0x1b
            | 0x1c
            | 0x1e
            | 0x27
            | 0x42
            | 0x82
            | 0x83
            | 0x85
            | 0x8e
            | 0xa5
            | 0xa6
            | 0xa8
            | 0xa9
            | 0xab
            | 0xaf
            | 0xbe
            | 0xee
            | 0xef
            | 0xfd
    )
}

fn decode_utf16(bytes: &[u8], offset: usize, words: usize) -> Option<String> {
    let length = words.checked_mul(2)?;
    let raw = bytes.get(offset..offset.checked_add(length)?)?;
    let words = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let value = String::from_utf16_lossy(&words);
    (!value.is_empty() && !value.chars().any(char::is_control)).then_some(value)
}

fn le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn append_resident_attribute(
        record: &mut [u8],
        offset: usize,
        attribute_type: u32,
        attribute_id: u16,
        value: &[u8],
    ) -> usize {
        let length = (24 + value.len() + 7) & !7;
        write_u32(record, offset, attribute_type);
        write_u32(record, offset + 4, length as u32);
        write_u16(record, offset + 14, attribute_id);
        write_u32(record, offset + 16, value.len() as u32);
        write_u16(record, offset + 20, 24);
        record[offset + 24..offset + 24 + value.len()].copy_from_slice(value);
        offset + length
    }

    #[test]
    fn rejects_empty_and_malformed_mbr_partition_tables() {
        let mut sector = [0u8; 512];
        sector[510..].copy_from_slice(&[0x55, 0xaa]);
        assert!(parse_mbr_partitions(&sector).is_none());
        sector[446] = 0x7f;
        sector[450] = 7;
        sector[454..458].copy_from_slice(&1u32.to_le_bytes());
        sector[458..462].copy_from_slice(&2u32.to_le_bytes());
        assert!(parse_mbr_partitions(&sector).is_none());
    }

    #[test]
    fn recovers_complete_resident_mft_data() {
        let file_name = "password.txt.txt";
        let name_utf16 = file_name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut file_name_value = vec![0u8; 66 + name_utf16.len()];
        file_name_value[64] = (name_utf16.len() / 2) as u8;
        file_name_value[65] = 1;
        file_name_value[66..].copy_from_slice(&name_utf16);
        let expected =
            "外层 password  KEE09898!  pim 9998\r\n隐藏 password  HHK7876!   pim 778".as_bytes();

        let mut record = vec![0u8; 1024];
        record[..4].copy_from_slice(b"FILE");
        write_u16(&mut record, 4, 0x30);
        write_u16(&mut record, 6, 3);
        write_u16(&mut record, 16, 9);
        write_u16(&mut record, 18, 1);
        write_u16(&mut record, 20, 0x38);
        write_u16(&mut record, 22, 1);
        write_u32(&mut record, 28, 1024);
        write_u32(&mut record, 44, 112_461);
        let offset = append_resident_attribute(&mut record, 0x38, 0x30, 1, &file_name_value);
        let data_attribute = offset;
        let offset = append_resident_attribute(&mut record, offset, 0x80, 2, expected);
        write_u32(&mut record, offset, u32::MAX);
        write_u32(&mut record, 24, (offset + 4) as u32);

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-mftdump-{}-{nonce}.raw",
            std::process::id()
        ));
        fs::write(&path, &record).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let (report, recovered) = recover_mft_resident_data(&image, 0, None, None, 1024).unwrap();

        assert_eq!(recovered, expected);
        assert_eq!(report.record_number, 112_461);
        assert_eq!(report.file_name.as_deref(), Some(file_name));
        assert_eq!(report.attribute_id, 2);
        assert_eq!(report.data_physical_address, (data_attribute + 24) as u64);
        assert_eq!(report.output_size, expected.len() as u64);
        assert_eq!(report.missing_bytes, 0);
        assert!(report.complete);
        assert_eq!(report.sha256, hex::encode(Sha256::digest(expected)));

        drop(image);
        fs::remove_file(path).unwrap();
    }
}
