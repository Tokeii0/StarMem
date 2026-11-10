//! Strict VMware VMSS/VMSN metadata parsing.
//!
//! The layout follows VMware's D0-D3 group/tag container as implemented by the
//! Volatility VMware translation layer.  Only the fields needed to map a separate
//! VMEM are accepted; embedded-memory snapshots are intentionally not inferred.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};

const HEADER_SIZE: usize = 12;
const GROUP_SIZE: usize = 80;
const PAGE_SIZE: u64 = 0x1000;
const MAX_GROUPS: usize = 4096;
const MAX_TAGS: usize = 1_000_000;
const MAX_REGIONS: usize = 1_000_000;
const VMWARE_MAGICS: [[u8; 4]; 4] = [
    [0xd0, 0xbe, 0xd2, 0xbe],
    [0xd1, 0xba, 0xd1, 0xba],
    [0xd2, 0xbe, 0xd2, 0xbe],
    [0xd3, 0xbe, 0xd3, 0xbe],
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VmwareMetadataMap {
    pub version: u8,
    pub regions: Vec<VmwareRegion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VmwareRegion {
    pub physical_start: u64,
    pub file_offset: u64,
    pub length: u64,
}

#[derive(Debug)]
struct Tag<'a> {
    name: &'a str,
    indices: Vec<u32>,
    data: &'a [u8],
}

pub(super) fn parse_vmware_metadata(bytes: &[u8], vmem_length: u64) -> Result<VmwareMetadataMap> {
    ensure!(bytes.len() >= HEADER_SIZE, "VMware metadata header 被截断");
    let magic: [u8; 4] = bytes[..4].try_into()?;
    ensure!(VMWARE_MAGICS.contains(&magic), "VMware metadata magic 无效");
    let version = magic[0] & 0x0f;
    let group_count = usize::try_from(read_u32(bytes, 8)?)?;
    ensure!(
        group_count > 0 && group_count <= MAX_GROUPS,
        "VMware group count {group_count} 不合理"
    );
    let groups_end = HEADER_SIZE
        .checked_add(
            group_count
                .checked_mul(GROUP_SIZE)
                .context("VMware group table 溢出")?,
        )
        .context("VMware group table 溢出")?;
    ensure!(groups_end <= bytes.len(), "VMware group table 被截断");

    let mut groups = BTreeMap::new();
    for index in 0..group_count {
        let offset = HEADER_SIZE + index * GROUP_SIZE;
        let name_bytes = &bytes[offset..offset + 64];
        let name_end = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name_bytes.len());
        let name =
            std::str::from_utf8(&name_bytes[..name_end]).context("VMware group name 不是 UTF-8")?;
        ensure!(!name.is_empty(), "VMware group name 为空");
        let tag_offset = usize::try_from(read_u64(bytes, offset + 64)?)
            .context("VMware tag offset 超出主机范围")?;
        ensure!(
            tag_offset < bytes.len(),
            "VMware group `{name}` tag offset 越界"
        );
        ensure!(
            groups.insert(name.to_owned(), tag_offset).is_none(),
            "VMware group `{name}` 重复"
        );
    }
    let memory_offset = *groups
        .get("memory")
        .context("VMware metadata 缺少 memory group")?;
    let tags = parse_tags(bytes, memory_offset, version)?;
    let regions_count = tag_u64(&tags, "regionsCount", &[])?;
    let regions_count = usize::try_from(regions_count).context("VMware regionsCount 过大")?;
    ensure!(
        regions_count > 0,
        "VMware metadata regionsCount=0；独立 VMEM 无法证明物理映射"
    );
    ensure!(
        regions_count <= MAX_REGIONS,
        "VMware regionsCount 超出安全上限"
    );

    let mut regions = Vec::with_capacity(regions_count);
    for region in 0..regions_count {
        let index = u32::try_from(region)?;
        let ppn = tag_u64(&tags, "regionPPN", &[index])?;
        let page_number = tag_u64(&tags, "regionPageNum", &[index])?;
        let page_count = tag_u64(&tags, "regionSize", &[index])?;
        ensure!(page_count > 0, "VMware region {region} 为空");
        let physical_start = ppn
            .checked_mul(PAGE_SIZE)
            .context("VMware region PPN 溢出")?;
        let file_offset = page_number
            .checked_mul(PAGE_SIZE)
            .context("VMware region page number 溢出")?;
        let length = page_count
            .checked_mul(PAGE_SIZE)
            .context("VMware region size 溢出")?;
        let physical_end = physical_start
            .checked_add(length)
            .context("VMware region 物理范围溢出")?;
        let file_end = file_offset
            .checked_add(length)
            .context("VMware region 文件范围溢出")?;
        ensure!(physical_end > physical_start, "VMware region 物理范围无效");
        ensure!(
            file_end <= vmem_length,
            "VMware region {region} 超出 VMEM：offset={file_offset:#x}, length={length:#x}"
        );
        regions.push(VmwareRegion {
            physical_start,
            file_offset,
            length,
        });
    }
    regions.sort_unstable_by_key(|region| region.physical_start);
    for pair in regions.windows(2) {
        ensure!(
            pair[0].physical_start + pair[0].length <= pair[1].physical_start,
            "VMware metadata 包含重叠物理 region"
        );
    }
    Ok(VmwareMetadataMap { version, regions })
}

fn parse_tags(bytes: &[u8], mut cursor: usize, version: u8) -> Result<Vec<Tag<'_>>> {
    let mut tags = Vec::new();
    loop {
        ensure!(cursor + 2 <= bytes.len(), "VMware tag header 被截断");
        let flags = bytes[cursor];
        let name_length = usize::from(bytes[cursor + 1]);
        cursor += 2;
        if flags == 0 && name_length == 0 {
            break;
        }
        ensure!(tags.len() < MAX_TAGS, "VMware tag 数量超出安全上限");
        let name_end = cursor
            .checked_add(name_length)
            .context("VMware tag name 溢出")?;
        let name = std::str::from_utf8(
            bytes
                .get(cursor..name_end)
                .context("VMware tag name 被截断")?,
        )
        .context("VMware tag name 不是 UTF-8")?;
        ensure!(!name.is_empty(), "VMware tag name 为空");
        cursor = name_end;

        let index_count = usize::from((flags >> 6) & 0x03);
        let mut indices = Vec::with_capacity(index_count);
        for _ in 0..index_count {
            indices.push(read_u32(bytes, cursor)?);
            cursor = cursor.checked_add(4).context("VMware tag index 溢出")?;
        }

        let inline_length = usize::from(flags & 0x3f);
        let data = if matches!(inline_length, 62 | 63) {
            let word_size = if version == 0 { 4 } else { 8 };
            let disk_size = read_sized_u64(bytes, cursor, word_size)?;
            // The second sized word is metadata for the in-memory representation.
            // Volatility's VMware layer deliberately skips it, followed by exactly
            // two reserved bytes.  Those bytes are padding contents, not a variable
            // padding length.
            read_sized_u64(bytes, cursor + word_size, word_size)?;
            cursor = cursor
                .checked_add(word_size * 2)
                .and_then(|value| value.checked_add(2))
                .context("VMware extended tag header 溢出")?;
            ensure!(cursor <= bytes.len(), "VMware extended tag header 被截断");
            let disk_size = usize::try_from(disk_size).context("VMware tag 太大")?;
            let end = cursor
                .checked_add(disk_size)
                .context("VMware tag data 溢出")?;
            let data = bytes
                .get(cursor..end)
                .context("VMware extended tag data 被截断")?;
            cursor = end;
            data
        } else {
            ensure!(
                matches!(inline_length, 1 | 2 | 4 | 8),
                "VMware numeric tag 长度 {inline_length} 不受支持"
            );
            let end = cursor
                .checked_add(inline_length)
                .context("VMware tag data 溢出")?;
            let data = bytes.get(cursor..end).context("VMware tag data 被截断")?;
            cursor = end;
            data
        };
        tags.push(Tag {
            name,
            indices,
            data,
        });
    }
    Ok(tags)
}

fn tag_u64(tags: &[Tag<'_>], name: &str, indices: &[u32]) -> Result<u64> {
    let matching = tags
        .iter()
        .filter(|tag| tag.name == name && tag.indices == indices)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "VMware tag `{name}{indices:?}` 缺失或重复"
    );
    read_sized_u64(matching[0].data, 0, matching[0].data.len())
}

fn read_sized_u64(bytes: &[u8], offset: usize, size: usize) -> Result<u64> {
    match size {
        1 => Ok(u64::from(*bytes.get(offset).context("整数被截断")?)),
        2 => Ok(u64::from(read_u16(bytes, offset)?)),
        4 => Ok(u64::from(read_u32(bytes, offset)?)),
        8 => read_u64(bytes, offset),
        _ => bail!("不支持的 VMware 整数长度 {size}"),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .context("VMware metadata 被截断")?
            .try_into()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("VMware metadata 被截断")?
            .try_into()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .context("VMware metadata 被截断")?
            .try_into()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_d0_and_d3_region_tags() {
        for magic in [VMWARE_MAGICS[0], VMWARE_MAGICS[3]] {
            let metadata = fixture(magic, &[(0, 1, 1), (4, 2, 2)]);
            let parsed = parse_vmware_metadata(&metadata, 0x4000).unwrap();
            assert_eq!(parsed.version, magic[0] & 0x0f);
            assert_eq!(parsed.regions.len(), 2);
            assert_eq!(parsed.regions[0].physical_start, 0);
            assert_eq!(parsed.regions[0].file_offset, 0x1000);
            assert_eq!(parsed.regions[1].physical_start, 0x4000);
            assert_eq!(parsed.regions[1].file_offset, 0x2000);
            assert_eq!(parsed.regions[1].length, 0x2000);
        }
    }

    #[test]
    fn rejects_zero_regions_overlap_and_out_of_bounds_vmem() {
        assert!(parse_vmware_metadata(&fixture(VMWARE_MAGICS[2], &[]), 0x1000).is_err());
        let overlap = fixture(VMWARE_MAGICS[2], &[(0, 0, 2), (1, 2, 1)]);
        assert!(parse_vmware_metadata(&overlap, 0x4000).is_err());
        let outside = fixture(VMWARE_MAGICS[2], &[(0, 2, 2)]);
        assert!(parse_vmware_metadata(&outside, 0x3000).is_err());
    }

    #[test]
    fn extended_tags_use_two_fixed_reserved_bytes() {
        let mut bytes = Vec::new();
        bytes.push(62);
        bytes.push(4);
        bytes.extend_from_slice(b"blob");
        bytes.extend_from_slice(&3u64.to_le_bytes());
        bytes.extend_from_slice(&9u64.to_le_bytes());
        bytes.extend_from_slice(&[0x34, 0x12]);
        bytes.extend_from_slice(b"abc");
        bytes.extend_from_slice(&[0, 0]);

        let tags = parse_tags(&bytes, 0, 3).unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "blob");
        assert_eq!(tags[0].data, b"abc");
    }

    pub(super) fn fixture(magic: [u8; 4], regions: &[(u32, u32, u32)]) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_SIZE + GROUP_SIZE];
        bytes[..4].copy_from_slice(&magic);
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[HEADER_SIZE..HEADER_SIZE + 6].copy_from_slice(b"memory");
        let tags_offset = (HEADER_SIZE + GROUP_SIZE) as u64;
        bytes[HEADER_SIZE + 64..HEADER_SIZE + 72].copy_from_slice(&tags_offset.to_le_bytes());
        push_tag(&mut bytes, "regionsCount", &[], regions.len() as u32);
        for (index, (ppn, page, size)) in regions.iter().copied().enumerate() {
            let index = index as u32;
            push_tag(&mut bytes, "regionPPN", &[index], ppn);
            push_tag(&mut bytes, "regionPageNum", &[index], page);
            push_tag(&mut bytes, "regionSize", &[index], size);
        }
        bytes.extend_from_slice(&[0, 0]);
        bytes
    }

    fn push_tag(output: &mut Vec<u8>, name: &str, indices: &[u32], value: u32) {
        output.push(4 | ((indices.len() as u8) << 6));
        output.push(name.len() as u8);
        output.extend_from_slice(name.as_bytes());
        for index in indices {
            output.extend_from_slice(&index.to_le_bytes());
        }
        output.extend_from_slice(&value.to_le_bytes());
    }
}
