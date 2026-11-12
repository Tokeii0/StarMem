//! Reverse a resident physical page through its PFN and prototype PTE.
//! Pool scanning may miss a FILE_OBJECT whose name has already been removed.
//! No filename inference is used: every edge and the physical frame are checked.
use super::*;
use crate::image::SourceLocation;

#[derive(Debug, Serialize)]
pub struct PhysicalFileReport {
    pub available: bool,
    pub complete: bool,
    pub scope: String,
    pub records: Vec<PhysicalFileRecord>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PhysicalFileRecord {
    pub physical_address: u64,
    pub source_location: Option<SourceLocation>,
    pub pfn: u64,
    pub pfn_virtual_address: u64,
    pub pte_address: u64,
    pub original_pte: u64,
    pub subsection: u64,
    pub control_area: u64,
    pub file_object: u64,
    pub name: Option<String>,
    pub file_offset: u64,
    pub source: DumpSource,
}

/// Locates one byte within a resident data section on Windows x86-64.
/// Valid/transition prototype PTEs must point back to the input physical frame;
/// subsection membership and FILE_OBJECT section backlinks must also agree.
pub fn locate_physical_file(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    physical_address: u64,
    cancellation: &CancellationToken,
) -> Result<PhysicalFileReport> {
    cancellation.check_cancelled()?;
    ensure!(!profile.is_x86(), "物理页文件反查目前只支持 Windows x86-64");
    image
        .read_physical(physical_address, &mut [0u8; 1])
        .context("指定物理字节不在已采集区间中")?;
    let space = kernel.address_space(image)?;
    let database = space.read_pointer(
        kernel
            .kernel_base
            .checked_add(u64::from(profile.symbol_rva("MmPfnDatabase")?))
            .context("PFN 全局地址溢出")?,
    )?;
    ensure!(
        is_kernel_pointer_for(&space, database),
        "MmPfnDatabase 不是有效内核地址"
    );
    let layout = profile.type_layout("_MMPFN")?;
    ensure!(
        (24..=128).contains(&layout.size),
        "不支持的 _MMPFN 符号大小"
    );
    let pfn = physical_address >> 12;
    let pfn_address = database
        .checked_add(pfn.checked_mul(layout.size).context("PFN 索引溢出")?)
        .context("PFN 地址溢出")?;
    let pte_field = profile.type_field("_MMPFN", "PteAddress")?;
    let original_field = profile.type_field("_MMPFN", "OriginalPte")?;
    ensure!(
        pte_field.offset + 8 <= layout.size && original_field.offset + 8 <= layout.size,
        "PFN 字段超出结构范围"
    );
    let pte_address = space.read_pointer(pfn_address + pte_field.offset)?;
    let original = space.read_u64(pfn_address + original_field.offset)?;
    // A subsection software PTE has Prototype=1, Valid=0 and Transition=0.
    ensure!(
        original & 0xc01 == 0x400,
        "该 PFN 的原始 PTE 不是文件子节记录"
    );
    let field = profile.type_field("_MMPTE_SUBSECTION", "SubsectionAddress")?;
    let (position, bits) = field
        .bit_position
        .zip(field.bit_length)
        .context("符号缺少子节地址位域")?;
    ensure!(
        field.offset == 0
            && (32..=48).contains(&bits)
            && u16::from(position) + u16::from(bits) <= 64,
        "不支持的子节地址位域"
    );
    let mask = (1u64 << bits) - 1;
    let raw = (original >> position) & mask;
    let subsection = if raw & (1 << (bits - 1)) != 0 {
        raw | !mask
    } else {
        raw
    };
    ensure!(
        is_kernel_pointer_for(&space, subsection)
            && is_kernel_pointer_for(&space, pte_address)
            && pte_address & 7 == 0,
        "PFN 子节或原型 PTE 地址无效"
    );
    let field_at = |ty: &str, member: &str, address: u64| -> Result<u64> {
        address
            .checked_add(profile.type_field(ty, member)?.offset)
            .context("字段地址溢出")
    };
    let control_area = space.read_pointer(field_at("_SUBSECTION", "ControlArea", subsection)?)?;
    let prototype_base =
        space.read_pointer(field_at("_SUBSECTION", "SubsectionBase", subsection)?)?;
    let pte_count = read_u32(
        &space,
        field_at("_SUBSECTION", "PtesInSubsection", subsection)?,
    )?;
    let sector = read_u32(
        &space,
        field_at("_SUBSECTION", "StartingSector", subsection)?,
    )?;
    ensure!(
        is_kernel_pointer_for(&space, control_area)
            && is_kernel_pointer_for(&space, prototype_base)
            && (1..=4_000_000).contains(&pte_count),
        "子节控制区或原型 PTE 范围无效"
    );
    let delta = pte_address
        .checked_sub(prototype_base)
        .context("PFN 的 PTE 位于子节范围之前")?;
    ensure!(
        delta & 7 == 0 && delta / 8 < u64::from(pte_count),
        "PFN 的 PTE 不属于指定子节"
    );
    let pte = space.read_u64(pte_address)?;
    ensure!(
        (pte & 1 != 0 || pte & 0xc00 == 0x800)
            && (pte & 0x000f_ffff_ffff_f000) == physical_address & !0xfff,
        "原型 PTE 未反向指向指定物理页"
    );
    cancellation.check_cancelled()?;
    let file_object =
        space.read_pointer(field_at("_CONTROL_AREA", "FilePointer", control_area)?)? & !15;
    ensure!(
        is_kernel_pointer_for(&space, file_object),
        "控制区没有有效 FILE_OBJECT"
    );
    ensure!(
        read_u16(&space, field_at("_FILE_OBJECT", "Type", file_object)?)? == 5
            && u64::from(read_u16(
                &space,
                field_at("_FILE_OBJECT", "Size", file_object)?
            )?) >= profile.type_layout("_FILE_OBJECT")?.size,
        "控制区引用的对象不是有效 FILE_OBJECT"
    );
    let section_pointers = space.read_pointer(field_at(
        "_FILE_OBJECT",
        "SectionObjectPointer",
        file_object,
    )?)?;
    ensure!(
        is_kernel_pointer_for(&space, section_pointers),
        "文件节指针无效"
    );
    let data = space.read_pointer(field_at(
        "_SECTION_OBJECT_POINTERS",
        "DataSectionObject",
        section_pointers,
    )?)? & !15;
    let executable = space.read_pointer(field_at(
        "_SECTION_OBJECT_POINTERS",
        "ImageSectionObject",
        section_pointers,
    )?)? & !15;
    // Image sections use a different file-offset scheme; refuse an inferred offset.
    let mismatch = if executable == control_area {
        "映像节文件偏移反查尚未支持"
    } else {
        "FILE_OBJECT 与控制区的反向归属不一致"
    };
    ensure!(data == control_area, "{mismatch}");
    let name = read_file_object_name(
        &space,
        field_at("_FILE_OBJECT", "FileName", file_object)?,
        32 * 1024,
    )
    .ok()
    .filter(|s| !s.is_empty());
    // Data sections measure StartingSector in pages; image sections use sectors.
    let file_offset = u64::from(sector)
        .checked_mul(4096)
        .and_then(|n| n.checked_add((delta / 8).checked_mul(4096)?))
        .and_then(|n| n.checked_add(physical_address & 4095))
        .context("文件偏移溢出")?;
    let warnings = if name.is_none() {
        vec!["文件名称不可读取或已被移除；结果仅证明本次物理字节与该文件对象的数据节归属，未推定文件名".into()]
    } else {
        Vec::new()
    };
    cancellation.check_cancelled()?;
    Ok(PhysicalFileReport { available: true, complete: true,
        scope: "仅核对指定物理字节的 PFN→原型 PTE→子节→控制区→FILE_OBJECT 数据节链；不枚举所有别名，不证明字符串生成来源".into(),
        records: vec![PhysicalFileRecord { physical_address, source_location: image.source_location(physical_address), pfn, pfn_virtual_address: pfn_address,
            pte_address, original_pte: original, subsection, control_area, file_object, name, file_offset, source: DumpSource::Data }], warnings })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{FieldProfile, TypeLayout};
    use crate::windows::{KernelDiscoveryMethod, WindowsArchitecture};
    use std::collections::BTreeMap;

    const BASE: u64 = 0xffff_8000_0000_0000;
    fn put64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> (Vec<u8>, WindowsKernelContext, KernelProfile) {
        let mut b = vec![0; 0x100000];
        put64(&mut b, 0x1800, 0x2003);
        put64(&mut b, 0x2000, 0x3003);
        put64(&mut b, 0x3000, 0x4003);
        for page in 1..512 {
            put64(&mut b, 0x4000 + page * 8, (page as u64 * 4096) | 3);
        }
        put64(&mut b, 0x5000, BASE + 0x10000);
        put64(&mut b, 0x10000 + 0x90 * 48 + 8, BASE + 0x20000);
        put64(
            &mut b,
            0x10000 + 0x90 * 48 + 16,
            ((BASE + 0x30000) << 16) | 0x4c0,
        );
        put64(&mut b, 0x20000, 0x908c0);
        put64(&mut b, 0x30000, BASE + 0x40000);
        put64(&mut b, 0x30008, BASE + 0x20000);
        b[0x30024..0x30028].copy_from_slice(&8u32.to_le_bytes());
        b[0x3002c..0x30030].copy_from_slice(&2u32.to_le_bytes());
        put64(&mut b, 0x40040, BASE + 0x50003);
        b[0x50000..0x50002].copy_from_slice(&5u16.to_le_bytes());
        b[0x50002..0x50004].copy_from_slice(&216u16.to_le_bytes());
        put64(&mut b, 0x50028, BASE + 0x60000);
        put64(&mut b, 0x60000, BASE + 0x40000);
        let mut types = BTreeMap::new();
        for (ty, size, members) in [
            (
                "_MMPFN",
                48,
                vec![("PteAddress", 8, 8), ("OriginalPte", 16, 8)],
            ),
            ("_MMPTE_SUBSECTION", 8, vec![("SubsectionAddress", 0, 8)]),
            (
                "_SUBSECTION",
                56,
                vec![
                    ("ControlArea", 0, 8),
                    ("SubsectionBase", 8, 8),
                    ("StartingSector", 36, 4),
                    ("PtesInSubsection", 44, 4),
                ],
            ),
            ("_CONTROL_AREA", 128, vec![("FilePointer", 64, 8)]),
            (
                "_FILE_OBJECT",
                216,
                vec![
                    ("Type", 0, 2),
                    ("Size", 2, 2),
                    ("SectionObjectPointer", 40, 8),
                    ("FileName", 88, 16),
                ],
            ),
            (
                "_SECTION_OBJECT_POINTERS",
                24,
                vec![("DataSectionObject", 0, 8), ("ImageSectionObject", 16, 8)],
            ),
        ] {
            types.insert(
                ty.into(),
                TypeLayout {
                    size,
                    fields: members
                        .into_iter()
                        .map(|(name, offset, size)| {
                            (
                                name.into(),
                                FieldProfile {
                                    offset,
                                    size: Some(size),
                                    bit_position: None,
                                    bit_length: None,
                                },
                            )
                        })
                        .collect(),
                },
            );
        }
        let address = types
            .get_mut("_MMPTE_SUBSECTION")
            .unwrap()
            .fields
            .get_mut("SubsectionAddress")
            .unwrap();
        address.bit_position = Some(16);
        address.bit_length = Some(48);
        let profile = KernelProfile {
            schema_version: 3,
            pdb_guid: "fixture".into(),
            pdb_age: 1,
            type_name: "_EPROCESS".into(),
            type_size: 0,
            fields: BTreeMap::new(),
            types,
            symbols: BTreeMap::from([("MmPfnDatabase".into(), 0x5000)]),
        };
        let kernel = WindowsKernelContext {
            architecture: WindowsArchitecture::X86_64,
            directory_table_base: 0x1000,
            kernel_base: BASE,
            ps_active_process_head: 0,
            ps_loaded_module_list: 0,
            discovery_method: KernelDiscoveryMethod::LowStub,
        };
        (b, kernel, profile)
    }

    #[test]
    fn pfn_file_owner_requires_every_backlink_and_keeps_removed_names_unknown() {
        let (bytes, kernel, profile) = fixture();
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), &bytes).unwrap();
        let image = MemoryImage::open(temp.path()).unwrap();
        let report = locate_physical_file(
            &image,
            &kernel,
            &profile,
            0x90017,
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(report.complete && report.records[0].name.is_none());
        assert_eq!(report.records[0].file_object, BASE + 0x50000);
        assert_eq!(report.records[0].file_offset, 0x8017);
        assert!(report.records[0].source_location.is_some());
        drop(image);
        for (offset, value) in [
            (0x20000, 0x918c0),
            (0x30008, BASE + 0x20008),
            (0x60000, BASE + 0x41000),
            (0x50000, 0),
        ] {
            let mut damaged = bytes.clone();
            put64(&mut damaged, offset, value);
            std::fs::write(temp.path(), damaged).unwrap();
            let image = MemoryImage::open(temp.path()).unwrap();
            assert!(
                locate_physical_file(
                    &image,
                    &kernel,
                    &profile,
                    0x90017,
                    &CancellationToken::new()
                )
                .is_err(),
                "{offset:x}"
            );
        }
        let handle = crate::cancellation::CancellationHandle::new();
        handle.cancel();
        let image = MemoryImage::open(temp.path()).unwrap();
        assert!(locate_physical_file(&image, &kernel, &profile, 0x90017, &handle.token()).is_err());
        assert!(
            locate_physical_file(
                &image,
                &kernel,
                &profile,
                0x200000,
                &CancellationToken::new()
            )
            .is_err()
        );
    }
}
