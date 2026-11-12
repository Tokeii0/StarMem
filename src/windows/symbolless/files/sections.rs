//! Bounded section recovery with explicit x64 layout priors and target round trips.
//! No profile, symbol store, build number or PDB is consulted at runtime.
use super::*;

#[derive(Debug, Serialize)]
pub struct SectionExtent {
    pub file_offset: u64,
    pub length: u64,
    pub physical_address: u64,
    pub subsection: u64,
    pub prototype_pte: u64,
    pub pte_value: u64,
    pub page_state: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SubsectionEvidence {
    pub address: u64,
    pub prototype_base: u64,
    pub pte_count: u64,
    pub file_offset: u64,
    pub file_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct SectionRecoveryPlan {
    pub file_object: u64,
    pub file_object_physical: u64,
    pub name: String,
    pub source: &'static str,
    pub control_area: u64,
    pub segment: u64,
    pub segment_size: u64,
    pub control_file_object: u64,
    pub control_file_object_offset: u64,
    pub first_subsection_offset: u64,
    pub subsection_layout: &'static str,
    pub sector_bytes: u64,
    pub logical_size: u64,
    pub logical_size_basis: &'static str,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub subsections: Vec<SubsectionEvidence>,
    pub extents: Vec<SectionExtent>,
    pub missing_ranges: Vec<MissingExtent>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy)]
struct Layout {
    flags: u64,
    start: u64,
    full: u64,
    ptes: u64,
    name: &'static str,
}
const LAYOUTS: [Layout; 2] = [
    Layout {
        flags: 0x28,
        start: 0x2c,
        full: 0x30,
        ptes: 0x18,
        name: "x64-subsection-ptes18-flags28",
    },
    Layout {
        flags: 0x20,
        start: 0x24,
        full: 0x28,
        ptes: 0x2c,
        name: "x64-subsection-ptes2c-flags20",
    },
];

fn u32_field(space: &X64AddressSpace<'_>, address: u64) -> Result<u64> {
    let mut bytes = [0; 4];
    space.read_virtual(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes) as u64)
}

#[allow(clippy::too_many_arguments)]
fn chain(
    space: &X64AddressSpace<'_>,
    control: u64,
    first: u64,
    layout: Layout,
    total: u64,
    unit: u64,
    max_bytes: u64,
    cancel: &CancellationToken,
) -> Result<Vec<SubsectionEvidence>> {
    let mut current = first;
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    let mut ptes = 0;
    let mut end = 0;
    while current != 0 {
        cancel.check_cancelled()?;
        ensure!(
            pointer(current) && seen.insert(current) && seen.len() <= 4096,
            "子节链无效、循环或超限"
        );
        ensure!(space.read_u64(current)? == control, "子节引用了其他控制区");
        let base = space.read_u64(current + 8)?;
        let count = u32_field(space, current + layout.ptes)?;
        ensure!(
            pointer(base) && count > 0 && count <= total,
            "子节 PTE 基址/数量无效"
        );
        ptes += count;
        ensure!(ptes <= total, "子节 PTE 总数超过段声明");
        let flags = u32_field(space, current + layout.flags)?;
        // High StartingSector bits are deliberately decoded, not silently discarded.
        let sector = u32_field(space, current + layout.start)? | (((flags >> 6) & 0x3ff) << 32);
        let offset = sector.checked_mul(unit).context("子节偏移溢出")?;
        let tail = flags >> 20;
        ensure!(tail < unit, "子节末尾字节数与扇区单位不符");
        let length = u32_field(space, current + layout.full)?
            .checked_mul(unit)
            .and_then(|n| n.checked_add(tail))
            .context("子节长度溢出")?;
        ensure!(
            length <= count * 4096 && offset <= max_bytes && length <= max_bytes - offset,
            "子节范围无效或超过恢复上限"
        );
        if length > 0 {
            ensure!(offset >= end, "子节文件范围重叠或顺序异常");
            end = offset + length;
        }
        result.push(SubsectionEvidence {
            address: current,
            prototype_base: base,
            pte_count: count,
            file_offset: offset,
            file_bytes: length,
        });
        current = space.read_u64(current + 16)?;
    }
    ensure!(
        ptes == total && end > 0,
        "子节链未覆盖段 PTE 声明或没有文件字节"
    );
    Ok(result)
}

pub fn plan_section(
    image: &MemoryImage,
    kernel: &ProbeReport,
    record: &FileRecord,
    image_section: bool,
    max_bytes: u64,
    cancel: &CancellationToken,
) -> Result<SectionRecoveryPlan> {
    ensure!(
        (1..=64 * 1024 * 1024).contains(&max_bytes),
        "恢复上限必须为 1..64 MiB"
    );
    cancel.check_cancelled()?;
    let space = X64AddressSpace::new(image, kernel.kernel_dtb)?;
    let (prefix, name) = validate_file(&space, record.file_object)?;
    ensure!(
        space.translate(record.file_object)? == record.physical_address
            && name == record.name
            && qword(&prefix, 0x28) == record.section_object_pointer,
        "文件对象或节对象归属改变"
    );
    let source_offset = if image_section { 16 } else { 0 };
    let control = space.read_u64(record.section_object_pointer + source_offset)? & !15;
    let expected = if image_section {
        record.image_section_object
    } else {
        record.data_section_object
    };
    ensure!(
        pointer(control) && expected == Some(control),
        "所选文件节不存在或归属改变"
    );
    // These offsets are disclosed priors. Reciprocal pointers and sizes must agree.
    let segment = space.read_u64(control)?;
    ensure!(
        pointer(segment) && space.read_u64(segment)? == control,
        "段与控制区未双向引用"
    );
    let total = u32_field(&space, segment + 8)?;
    let segment_size = space.read_u64(segment + 0x18)?;
    ensure!(
        total > 0 && total <= 65536 && segment_size == total * 4096,
        "段大小/PTE 声明不符合已支持的布局"
    );
    let flags = u32_field(&space, control + 0x38)?;
    ensure!(
        flags & 0x80 != 0 && (flags & 0x20 != 0) == image_section,
        "控制区文件/映像标记与所选来源不符"
    );
    let unit = if image_section { 512 } else { 4096 };
    let mut candidates = Vec::new();
    for offset in (0x48..=0x100).step_by(8) {
        cancel.check_cancelled()?;
        if space.read_u64(control + offset).ok() != Some(control) {
            continue;
        }
        for layout in LAYOUTS {
            if let Ok(parts) = chain(
                &space,
                control,
                control + offset,
                layout,
                total,
                unit,
                max_bytes,
                cancel,
            ) {
                candidates.push((offset, layout, parts));
            }
        }
    }
    cancel.check_cancelled()?;
    ensure!(
        candidates.len() == 1,
        "子节布局候选为 {}，拒绝缺失或歧义",
        candidates.len()
    );
    let (first_offset, layout, subsections) = candidates.remove(0);
    let resolver = ObjectTypeResolver::load(image, kernel)?;
    let mut owners = Vec::new();
    for offset in (0x28..first_offset).step_by(8) {
        cancel.check_cancelled()?;
        let Ok(owner) = space.read_u64(control + offset).map(|raw| raw & !15) else {
            continue;
        };
        if let Ok((bytes, _)) = validate_file(&space, owner)
            && qword(&bytes, 0x28) == record.section_object_pointer
            && resolver.is_file(&space, owner).unwrap_or(false)
        {
            owners.push((offset, owner));
        }
    }
    ensure!(
        owners.len() == 1,
        "控制区 FilePointer 反向归属候选为 {}",
        owners.len()
    );
    let range_end = subsections
        .iter()
        .filter(|s| s.file_bytes > 0)
        .map(|s| s.file_offset + s.file_bytes)
        .max()
        .context("没有子节文件范围")?;
    let mut logical_size = range_end;
    let mut size_basis = "subsection_file_ranges";
    // Data sections can have a page-rounded span. A readable public FCB header
    // supplies EOF; no name matching or unverified arbitrary size field is used.
    if !image_section {
        let fcb = qword(&prefix, 0x18);
        let mut bytes = [0; 0x30];
        if pointer(fcb) && space.read_virtual(fcb, &mut bytes).is_ok() && u16_at(&bytes, 2) >= 0x30
        {
            let eof = qword(&bytes, 0x20);
            ensure!(
                eof > 0 && eof <= range_end && range_end - eof < 4096,
                "FCB 文件大小与子节范围不一致"
            );
            logical_size = eof;
            size_basis = "validated_fcb_eof";
        }
    }
    let mut extents = Vec::new();
    let mut recovered = 0;
    let mut page = [0; 4096];
    for part in &subsections {
        for relative in (0..part.file_bytes).step_by(4096) {
            cancel.check_cancelled()?;
            let file_offset = part.file_offset + relative;
            if file_offset >= logical_size {
                break;
            }
            let length = 4096
                .min(part.file_bytes - relative)
                .min(logical_size - file_offset);
            let pte_address = part
                .prototype_base
                .checked_add(relative / 4096 * 8)
                .context("PTE 地址溢出")?;
            let Ok(pte) = space.read_u64(pte_address) else {
                continue;
            };
            let (physical, state) = if pte & 1 != 0 {
                (pte & 0x000f_ffff_ffff_f000, "valid")
            } else if pte & 0xc00 == 0x800 {
                (pte & 0x0000_1fff_ffff_f000, "transition")
            } else {
                continue;
            };
            if physical == 0
                || image
                    .read_physical(physical, &mut page[..length as usize])
                    .is_err()
            {
                continue;
            }
            extents.push(SectionExtent {
                file_offset,
                length,
                physical_address: physical,
                subsection: part.address,
                prototype_pte: pte_address,
                pte_value: pte,
                page_state: state,
            });
            recovered += length;
        }
    }
    ensure!(recovered > 0, "文件节没有可读取的驻留字节");
    let mut missing_ranges = Vec::new();
    let mut end = 0;
    for extent in &extents {
        if extent.file_offset > end {
            missing_ranges.push(MissingExtent {
                file_offset: end,
                length: extent.file_offset - end,
            });
        }
        end = extent.file_offset + extent.length;
    }
    if end < logical_size {
        missing_ranges.push(MissingExtent {
            file_offset: end,
            length: logical_size - end,
        });
    }
    Ok(SectionRecoveryPlan {
        file_object: record.file_object, file_object_physical: record.physical_address, name,
        source: if image_section { "image_section" } else { "data_section" },
        control_area: control, segment, segment_size, control_file_object: owners[0].1,
        control_file_object_offset: owners[0].0, first_subsection_offset: first_offset,
        subsection_layout: layout.name, sector_bytes: unit, logical_size, logical_size_basis: size_basis,
        recovered_bytes: recovered, missing_bytes: logical_size - recovered, complete: recovered == logical_size,
        subsections, extents, missing_ranges,
        warnings: vec![
            "无符号推断：使用已公开的 x64 结构先验，并验证文件、节、控制区、段和子节的双向归属；不支持其他布局".into(),
            "仅恢复有效/过渡态驻留 PTE；分页、压缩、原型转发及缺失页面保留为空洞，占位零不是原始字节".into(),
            "完整仅指声明恢复范围内无缺页；不证明等同磁盘文件，映像节不含未映射的证书、覆盖数据等内容".into(),
        ],
    })
}
