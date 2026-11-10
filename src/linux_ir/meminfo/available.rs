//! si_mem_available inputs: online node zones, exact low-watermark enum,
//! reserve pages and already-read global page states. See mm/show_mem.c.
use super::*;

const MAX_NODES: u64 = 4096;

fn array_layout(
    m: &impl LinuxKernelMemory,
    ty: &str,
    field: &str,
    stride: u64,
) -> Result<(u64, u64)> {
    let offset = m.isf().field_offset(ty, field)?;
    let count = m.isf().field_array_count(ty, field)?;
    let size = count.checked_mul(stride).context("数组大小溢出")?;
    ensure!(
        count > 0
            && m.isf().field_size(ty, field)? == size
            && add(offset, size)? <= m.isf().type_size(ty)?,
        "{ty}.{field} 数组布局越界或元素宽度不匹配"
    );
    Ok((offset, count))
}

fn scalar(m: &impl LinuxKernelMemory, symbol: &str, inputs: &mut Vec<Value>) -> Result<u64> {
    let (offset, width) = m.isf().symbol_counter_layout(symbol)?;
    let address = add(m.runtime_symbol(symbol)?, offset)?;
    let raw = number(m, address, width)?;
    inputs.push(json!({"record_kind":"memory_input","metric":"MemAvailable","input_kind":"node_count",
        "symbol":symbol,"counter_address":address,"counter_width":width,"counter_offset":offset,"raw_value":raw}));
    Ok(raw)
}

fn low_watermarks(
    m: &Memory<'_, impl LinuxKernelMemory>,
    inputs: &mut Vec<Value>,
) -> Result<(u64, Value)> {
    let mask_type = m.isf().symbol_array_struct_type("node_states")?;
    let mask_size = m.isf().symbol_array_element_size("node_states")?;
    let (bits_offset, words) = array_layout(m, mask_type, "bits", 8)?;
    let capacity = words.checked_mul(64).context("节点位图容量溢出")?;
    ensure!(capacity <= MAX_NODES, "节点位图超过 {MAX_NODES} 节点范围");
    let states_count = m.isf().symbol_array_count("node_states")?;
    let online = m.isf().enum_constant("node_states", "N_ONLINE")?;
    ensure!(
        states_count <= 64
            && states_count == m.isf().enum_constant("node_states", "NR_NODE_STATES")?
            && online < states_count,
        "node_states 数组与枚举范围冲突"
    );
    let mask = add(m.runtime_symbol("node_states")?, online * mask_size)?;
    let mut nodes = Vec::new();
    for word in 0..words {
        let address = add(mask, add(bits_offset, word * 8)?)?;
        let raw = number(m, address, 8)?;
        inputs.push(json!({"record_kind":"memory_input","metric":"MemAvailable","input_kind":"online_node_mask",
            "symbol":"node_states","enum_item":"N_ONLINE","enum_index":online,
            "word_index":word,"counter_address":address,"counter_width":8,"raw_value":raw}));
        for bit in 0..64 {
            if raw & (1u64 << bit) != 0 {
                nodes.push(word * 64 + bit);
            }
        }
    }
    ensure!(!nodes.is_empty(), "在线节点位图为空，无法核对全部区域水位");
    if m.isf().symbol_address("nr_online_nodes").is_ok() {
        ensure!(
            scalar(m, "nr_online_nodes", inputs)? == nodes.len() as u64,
            "nr_online_nodes 与在线位图冲突"
        );
    }

    let numa = m.isf().symbol_address("node_data").is_ok();
    let (table, pgdat_type, declared, bound, bound_basis) = if numa {
        let (ty, declared) = ["pg_data_t", "pglist_data"]
            .into_iter()
            .find_map(|ty| {
                m.isf()
                    .symbol_pointer_array_layout("node_data", ty)
                    .ok()
                    .map(|count| (ty, count))
            })
            .context("node_data 不是受支持的 pgdat 指针数组")?;
        let (bound, basis) = if m.isf().symbol_address("nr_node_ids").is_ok() {
            (
                scalar(m, "nr_node_ids", inputs)?,
                "nr_node_ids bounded by exact nodemask capacity",
            )
        } else {
            (declared, "exact nonzero node_data ISF array length")
        };
        ensure!(
            bound > 0 && bound <= capacity && (declared == 0 || bound <= declared),
            "node_data 声明、nr_node_ids 与位图容量没有一致边界"
        );
        (m.runtime_symbol("node_data")?, ty, declared, bound, basis)
    } else {
        let ty = m.isf().symbol_type_name("contig_page_data")?;
        ensure!(
            matches!(ty, "pg_data_t" | "pglist_data"),
            "contig_page_data 的类型不受支持"
        );
        ensure!(nodes == [0], "contig_page_data 只能对应单个在线节点 0");
        (
            m.runtime_symbol("contig_page_data")?,
            ty,
            1,
            1,
            "single contig_page_data object",
        )
    };
    ensure!(
        nodes.iter().all(|node| *node < bound),
        "在线节点编号超出可核对的 node_data 边界"
    );
    ensure!(
        m.isf().field_array_struct_type(pgdat_type, "node_zones")? == "zone",
        "node_zones 元素不是 zone"
    );
    let zone_size = m.isf().type_size("zone")?;
    ensure!(zone_size > 0 && zone_size <= 65536, "zone 大小不受支持");
    let (zone_offset, zone_count) = array_layout(m, pgdat_type, "node_zones", zone_size)?;
    let node_id_offset = m.isf().field_offset(pgdat_type, "node_id")?;
    ensure!(
        m.isf().field_size(pgdat_type, "node_id")? == 4
            && add(node_id_offset, 4)? <= m.isf().type_size(pgdat_type)?,
        "pgdat.node_id 字段越界或宽度无效"
    );
    ensure!(
        zone_count <= 64 && zone_count == m.isf().enum_constant("zone_type", "__MAX_NR_ZONES")?,
        "node_zones 长度与 zone_type 枚举冲突"
    );
    let old = m
        .isf()
        .optional_field_offset("zone", "watermark")?
        .is_some();
    let modern = m
        .isf()
        .optional_field_offset("zone", "_watermark")?
        .is_some();
    ensure!(old != modern, "zone 水位布局缺失或存在歧义");
    let field_name = if modern { "_watermark" } else { "watermark" };
    let (watermark_offset, count) = array_layout(m, "zone", field_name, 8)?;
    let low_index = m.isf().enum_constant("zone_watermarks", "WMARK_LOW")?;
    ensure!(
        count <= 16
            && count == m.isf().enum_constant("zone_watermarks", "NR_WMARK")?
            && low_index < count,
        "低水位枚举与数组范围冲突"
    );
    let boost_offset = if modern {
        let offset = m.isf().field_offset("zone", "watermark_boost")?;
        ensure!(
            m.isf().field_size("zone", "watermark_boost")? == 8 && add(offset, 8)? <= zone_size,
            "zone.watermark_boost 布局无效"
        );
        Some(offset)
    } else {
        ensure!(
            m.isf()
                .optional_field_offset("zone", "watermark_boost")?
                .is_none(),
            "旧 watermark 搭配 boost 的布局未经验证"
        );
        None
    };
    let mut total = 0u64;
    let mut seen = HashSet::new();
    for node in &nodes {
        m.check_cancelled()?;
        let slot = if numa {
            Some(add(table, node * 8)?)
        } else {
            None
        };
        let pgdat = pointer(if let Some(slot) = slot {
            number(m, slot, 8)?
        } else {
            table
        })?;
        ensure!(seen.insert(pgdat), "多个在线节点指向相同 pgdat");
        let node_id_address = add(pgdat, node_id_offset)?;
        ensure!(
            number(m, node_id_address, 4)? == *node,
            "pgdat.node_id 与在线节点槽位不一致"
        );
        inputs.push(
            json!({"record_kind":"memory_input","metric":"MemAvailable","input_kind":"online_node",
            "node_id":node,"pgdat":pgdat,"pgdat_type":pgdat_type,"node_id_address":node_id_address,
            "node_slot_address":slot,"zone_count":zone_count}),
        );
        // for_each_zone visits the full array, including unpopulated zones;
        // nr_zones is not the iteration bound for si_mem_available.
        for zone_index in 0..zone_count {
            let zone = add(pgdat, add(zone_offset, zone_index * zone_size)?)?;
            let address = add(zone, add(watermark_offset, low_index * 8)?)?;
            let low = number(m, address, 8)?;
            let boost_address = boost_offset.map(|offset| add(zone, offset)).transpose()?;
            let boost = boost_address
                .map(|address| number(m, address, 8))
                .transpose()?
                .unwrap_or(0);
            let pages = low
                .checked_add(boost)
                .context("zone 低水位与 boost 之和溢出")?;
            total = total.checked_add(pages).context("区域低水位总和溢出")?;
            inputs.push(json!({"record_kind":"memory_input","metric":"MemAvailable","input_kind":"zone_watermark",
                "node_id":node,"pgdat":pgdat,"zone":zone,"zone_index":zone_index,"watermark_field":field_name,
                "enum_item":"WMARK_LOW","enum_index":low_index,"counter_address":address,"counter_width":8,
                "raw_value":low,"boost_address":boost_address,"watermark_boost_pages":boost,
                "low_watermark_pages":pages,"counter_unit":"pages"}));
        }
    }
    Ok((
        total,
        json!({"node_source":if numa { "node_data" } else { "contig_page_data" },
        "online_node_count":nodes.len(),"zone_count_per_node":zone_count,"node_id_bound":bound,
        "node_array_declared_count":declared,"node_bound_basis":bound_basis,"node_mask_capacity":capacity,
        "watermark_field":field_name,"low_watermark_pages":total}),
    ))
}

pub(super) fn estimate(
    m: &Memory<'_, impl LinuxKernelMemory>,
    rows: &[Value],
    inputs: &mut Vec<Value>,
) -> Result<Measurement> {
    let pages = |name| -> Result<u64> {
        let kib = value(rows, name)?;
        ensure!(kib % PAGE_KIB == 0, "{name} 不能无损转换为基础页数");
        Ok(kib / PAGE_KIB)
    };
    let free = pages("MemFree")?;
    let file = pages("Active(file)")?
        .checked_add(pages("Inactive(file)")?)
        .context("文件 LRU 总页数溢出")?;
    let misc_supported = variant(m, &["NR_KERNEL_MISC_RECLAIMABLE"]).is_some();
    let mut dependencies = vec!["MemFree", "Active(file)", "Inactive(file)", "SReclaimable"];
    if misc_supported {
        dependencies.push("KernelMiscReclaimable");
    }
    let misc = if misc_supported {
        pages("KernelMiscReclaimable")?
    } else {
        0
    };
    let reclaimable = pages("SReclaimable")?
        .checked_add(misc)
        .context("可回收总页数溢出")?;
    let reserve = global(m, "totalreserve_pages")?;
    let reserved = reserve.kib / PAGE_KIB;
    let mut reserve_input = reserve.source;
    reserve_input["record_kind"] = json!("memory_input");
    reserve_input["metric"] = json!("MemAvailable");
    reserve_input["input_kind"] = json!("reserved_pages");
    inputs.push(reserve_input);
    let (low, topology) = low_watermarks(m, inputs)?;
    let file_allowance = file - (file / 2).min(low);
    let reclaimable_allowance = reclaimable - (reclaimable / 2).min(low);
    // Do not clamp free-reserved before the additions: that would overestimate.
    let signed_pages = i128::from(free) - i128::from(reserved)
        + i128::from(file_allowance)
        + i128::from(reclaimable_allowance);
    let available = u64::try_from(signed_pages.max(0)).context("MemAvailable 页数溢出")?;
    Ok(Measurement {
        kib: available
            .checked_mul(PAGE_KIB)
            .context("MemAvailable 换算溢出")?,
        source: json!({"formula":"max(free - reserved + file_lru - min(file_lru/2, low) + reclaimable - min(reclaimable/2, low), 0)",
            "arithmetic_unit":"pages; integer division","input_metrics":dependencies,
            "kernel_misc_included":misc_supported,"kernel_misc_pages":misc,"free_pages":free,"reserved_pages":reserved,
            "file_lru_pages":file,"reclaimable_pages":reclaimable,"file_allowance_pages":file_allowance,
            "reclaimable_allowance_pages":reclaimable_allowance,"available_pages":available,"topology":topology,
            "estimate_scope":"kernel si_mem_available formula on resident global counters; not a guaranteed allocation or cgroup limit"}),
    })
}
