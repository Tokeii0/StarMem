use super::*;

pub(super) fn buffers(
    m: &Memory<'_, impl LinuxKernelMemory>,
    options: &LinuxIrOptions,
    inputs: &mut Vec<Value>,
) -> Result<Measurement> {
    let root = m.runtime_symbol("blockdev_superblock")?;
    let sb = pointer(number(m, root, 8)?)?;
    let head = member(m, sb, "super_block", "s_inodes")?;
    let offset = m.isf().field_offset("inode", "i_sb_list")?;
    let mut traversal = LinuxIrReport::new(options, "blockdev inode list");
    let inodes = list(m, head, offset, MAX_MAPPINGS, m.cancel, &mut traversal)?;
    m.check_cancelled()?;
    let mut pages = 0u64;
    for inode in &inodes {
        m.check_cancelled()?;
        ensure!(
            field(m, *inode, "inode", "i_sb")? == sb,
            "块设备 inode 不属于 blockdev_superblock"
        );
        let mapping = pointer(field(m, *inode, "inode", "i_mapping")?)?;
        let address = member(m, mapping, "address_space", "nrpages")?;
        let width = m.isf().field_size("address_space", "nrpages")?;
        ensure!(width == 8, "address_space.nrpages 不是 8 字节页计数");
        let count = number(m, address, width)?;
        pages = pages.checked_add(count).context("块设备缓存页汇总溢出")?;
        inputs.push(
            json!({"record_kind":"memory_input","metric":"Buffers","inode":inode,
            "superblock":sb,"mapping":mapping,"counter_address":address,"counter_width":width,
            "raw_value":count,"counter_unit":"pages","list_head":head}),
        );
    }
    ensure!(
        traversal.complete,
        "块设备 inode 链未完整遍历，未将前缀页数作为总量：{}",
        traversal.warnings.join("；")
    );
    Ok(Measurement {
        kib: pages.checked_mul(PAGE_KIB).context("Buffers 换算溢出")?,
        source: json!({"symbol":"blockdev_superblock","symbol_address":root,"superblock":sb,
            "list_head":head,"mapping_count":inodes.len(),"mapping_limit":MAX_MAPPINGS,
            "formula":"sum(blockdev_superblock.s_inodes[].i_mapping.nrpages)","counter_unit":"pages"}),
    })
}

pub(super) fn swapcache(
    m: &Memory<'_, impl LinuxKernelMemory>,
    inputs: &mut Vec<Value>,
) -> Result<Measurement> {
    let counts = m.runtime_symbol("nr_swapper_spaces")?;
    let pointers = m.runtime_symbol("swapper_spaces")?;
    let count = m.isf().symbol_array_count("nr_swapper_spaces")?;
    ensure!(count <= 256, "nr_swapper_spaces 数组超出支持范围");
    let (stride, offset, width) = m.isf().symbol_array_counter_layout("nr_swapper_spaces")?;
    ensure!(
        stride == 4 && offset == 0 && width == 4,
        "nr_swapper_spaces 不是 u32 数组"
    );
    let declared = m
        .isf()
        .symbol_pointer_array_layout("swapper_spaces", "address_space")?;
    // Both arrays are declared with MAX_SWAPFILES in mm/swap_state.c. A DWARF
    // zero-length pointer declaration uses the exact companion count, not a guess.
    ensure!(
        declared == 0 || declared == count,
        "swapper_spaces 与配套计数数组的长度冲突"
    );
    let size = m.isf().type_size("address_space")?;
    let page_offset = m.isf().field_offset("address_space", "nrpages")?;
    ensure!(
        size > 0
            && size <= 65536
            && m.isf().field_size("address_space", "nrpages")? == 8
            && add(page_offset, 8)? <= size,
        "swap address_space 布局无效"
    );
    let mut pages = 0u64;
    let mut mappings = 0usize;
    for slot in 0..count {
        m.check_cancelled()?;
        let count_address = add(counts, slot * 4)?;
        let nr = number(m, count_address, 4)?;
        let pointer_address = add(pointers, slot * 8)?;
        let base = number(m, pointer_address, 8)?;
        inputs.push(
            json!({"record_kind":"memory_input","metric":"SwapCached","swap_slot":slot,
            "count_address":count_address,"space_count":nr,"pointer_address":pointer_address,
            "mapping":base}),
        );
        if nr == 0 {
            continue;
        }
        pointer(base)?;
        ensure!(
            nr <= (MAX_MAPPINGS - mappings) as u64,
            "swap address_space 达到 {MAX_MAPPINGS} 个遍历上限"
        );
        for index in 0..nr {
            let address = add(base, add(index * size, page_offset)?)?;
            let raw = number(m, address, 8)?;
            pages = pages.checked_add(raw).context("swapcache 页计数溢出")?;
            mappings += 1;
            inputs.push(
                json!({"record_kind":"memory_input","metric":"SwapCached","swap_slot":slot,
                "space_index":index,"counter_address":address,"counter_width":8,"raw_value":raw,
                "counter_unit":"pages","mapping":base + index * size}),
            );
        }
    }
    Ok(Measurement {
        kib: pages.checked_mul(PAGE_KIB).context("swapcache 换算溢出")?,
        source: json!({"symbol":"swapper_spaces","count_symbol":"nr_swapper_spaces","slot_count":count,
            "declared_pointer_slots":declared,"mapping_count":mappings,"mapping_limit":MAX_MAPPINGS,
            "extent_basis":"paired MAX_SWAPFILES arrays; exact nr_swapper_spaces ISF count",
            "formula":"sum(swapper_spaces[i][0..nr_swapper_spaces[i]].nrpages)"}),
    })
}
