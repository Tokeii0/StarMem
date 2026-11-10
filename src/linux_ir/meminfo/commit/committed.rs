use super::*;
use std::collections::BTreeSet;

const MAX_CPUS: u64 = 8192;
const NAME: &str = "Committed_ASReconstructed";

pub(super) struct Base {
    root: u64,
    address: u64,
    raw: i64,
}

pub(super) fn read_base(m: &impl LinuxKernelMemory, inputs: &mut Vec<Value>) -> Result<Base> {
    ensure!(
        m.isf().symbol_struct_type("vm_committed_as")? == "percpu_counter",
        "vm_committed_as 类型不匹配"
    );
    let (offset, width) = m.isf().field_scalar_layout("percpu_counter", "count")?;
    ensure!(width == 8, "percpu_counter.count 不是 s64");
    let root = m.runtime_symbol("vm_committed_as")?;
    let address = add(root, offset)?;
    let raw = number(m, address, 8)? as i64;
    inputs.push(json!({"record_kind":"memory_input","metric":"Committed_ASGlobal","input_kind":"commit_global_counter",
        "symbol":"vm_committed_as","counter_address":address,"counter_offset":offset,"counter_width":8,
        "raw_value":raw,"counter_unit":"pages","signed":true}));
    Ok(Base { root, address, raw })
}

pub(super) fn global(base: &Base) -> Result<Measurement> {
    Ok(Measurement {
        kib: (base.raw.max(0) as u64)
            .checked_mul(PAGE_KIB)
            .context("承诺内存基数换算溢出")?,
        source: json!({"symbol":"vm_committed_as","counter_address":base.address,"counter_width":8,
            "raw_value":base.raw,"counter_unit":"pages","negative_clamped":base.raw<0,
            "normalization_rule":"max(global_signed_pages, 0)","global_base_only":true,
            "scope_note":"只读取全局基数，尚未加入各 CPU 待合并差值；零基数不代表没有承诺内存"}),
    })
}

fn cpu_mask(
    m: &impl LinuxKernelMemory,
    symbol: &str,
    inputs: &mut Vec<Value>,
) -> Result<(BTreeSet<u64>, u64)> {
    let ty = m.isf().symbol_struct_type(symbol)?;
    ensure!(ty == "cpumask", "{symbol} 不是 cpumask");
    let offset = m.isf().field_offset(ty, "bits")?;
    let words = m.isf().field_array_count(ty, "bits")?;
    ensure!(words > 0 && words <= MAX_CPUS / 64, "CPU 位图容量越界");
    let bytes = words * 8;
    ensure!(
        m.isf().field_size(ty, "bits")? == bytes && add(offset, bytes)? <= m.isf().type_size(ty)?,
        "CPU 位图元素宽度或范围无效"
    );
    let root = m.runtime_symbol(symbol)?;
    let mut cpus = BTreeSet::new();
    for word in 0..words {
        let address = add(root, add(offset, word * 8)?)?;
        let raw = number(m, address, 8)?;
        inputs.push(json!({"record_kind":"memory_input","metric":NAME,"input_kind":"cpu_mask",
            "symbol":symbol,"word_index":word,"counter_address":address,"counter_width":8,"raw_value":raw}));
        for bit in 0..64 {
            if raw & (1u64 << bit) != 0 {
                cpus.insert(word * 64 + bit);
            }
        }
    }
    Ok((cpus, words * 64))
}

pub(super) fn sum(
    m: &Memory<'_, impl LinuxKernelMemory>,
    base: &Base,
    inputs: &mut Vec<Value>,
) -> Result<Measurement> {
    if m.isf()
        .optional_field_offset("percpu_counter", "counters")?
        .is_none()
    {
        ensure!(
            m.isf().type_size("percpu_counter")? == 8 && base.address == base.root,
            "缺少 counters，且不是仅含 count 的单处理器布局"
        );
        ensure!(base.raw >= 0, "单处理器承诺内存计数为负");
        let mut value = global(base)?;
        value.source["scope_note"] = json!(
            "精确 ISF 为仅含 s64 count 的单处理器布局，无每 CPU 分量；不判定 procfs 显示实现"
        );
        value.source["calculation_mode"] = json!("single_counter_layout");
        return Ok(value);
    }
    let (possible, capacity) = cpu_mask(m, "__cpu_possible_mask", inputs)?;
    let (online, online_capacity) = cpu_mask(m, "__cpu_online_mask", inputs)?;
    ensure!(
        capacity == online_capacity && !online.is_empty(),
        "CPU 位图容量冲突或在线集合为空"
    );
    let has_dying = m.isf().symbol_address("__cpu_dying_mask").is_ok();
    let dying = if has_dying {
        let (dying, dying_capacity) = cpu_mask(m, "__cpu_dying_mask", inputs)?;
        ensure!(capacity == dying_capacity, "正在离线的 CPU 位图容量冲突");
        dying
    } else {
        BTreeSet::new()
    };
    let ids = scalar(m, "nr_cpu_ids", 4, NAME, "cpu_id_bound", inputs)?;
    ensure!(
        ids > 0 && ids <= capacity && possible.iter().all(|cpu| *cpu < ids),
        "nr_cpu_ids 与可能 CPU 集合冲突"
    );
    let cpus = online.union(&dying).copied().collect::<BTreeSet<_>>();
    ensure!(
        cpus.is_subset(&possible),
        "在线/正在离线的 CPU 不属于可能集合"
    );
    let declared = m.isf().symbol_array_count("__per_cpu_offset")?;
    let (stride, offset, width) = m.isf().symbol_array_counter_layout("__per_cpu_offset")?;
    ensure!(
        declared <= MAX_CPUS && declared >= ids && stride == 8 && offset == 0 && width == 8,
        "__per_cpu_offset 的声明、编号范围或元素布局不匹配"
    );
    let table = m.runtime_symbol("__per_cpu_offset")?;
    let (pointer_offset, element_width) = m
        .isf()
        .field_pointer_scalar_layout("percpu_counter", "counters")?;
    ensure!(
        element_width == 4,
        "percpu_counter.counters 不是 32 位整数指针"
    );
    let pointer_address = add(base.root, pointer_offset)?;
    let pointer = number(m, pointer_address, 8)?;
    ensure!(pointer != 0, "每 CPU 承诺内存计数尚未初始化");
    inputs.push(json!({"record_kind":"memory_input","metric":NAME,"input_kind":"per_cpu_counter_pointer",
        "symbol":"vm_committed_as","counter_address":pointer_address,"counter_width":8,"raw_value":pointer}));
    let mut delta = 0i64;
    let mut addresses = BTreeSet::new();
    for cpu in &cpus {
        let offset_address = add(table, cpu * 8)?;
        let per_cpu_offset = number(m, offset_address, 8)?;
        // Linux per_cpu_ptr applies unsigned pointer relocation. The unrelocated
        // dynamic per-CPU pointer may be a low address; validate the final VA.
        let address = pointer.wrapping_add(per_cpu_offset);
        ensure!(
            address >> 47 == 0x1ffff && address % 4 == 0 && addresses.insert(address),
            "每 CPU 计数地址不是唯一且对齐的规范内核地址"
        );
        let raw = number(m, address, 4)? as i32;
        inputs.push(json!({"record_kind":"memory_input","metric":NAME,"input_kind":"per_cpu_commit_delta",
            "cpu_id":cpu,"online":online.contains(cpu),"dying":dying.contains(cpu),
            "per_cpu_pointer":pointer,"per_cpu_offset_address":offset_address,"per_cpu_offset":per_cpu_offset,
            "counter_address":address,"counter_width":4,"raw_value":raw,"counter_unit":"pages","signed":true}));
        delta = delta
            .checked_add(i64::from(raw))
            .context("每 CPU 差值合计溢出")?;
    }
    let signed_sum = base
        .raw
        .checked_add(delta)
        .context("已承诺内存有符号汇总溢出")?;
    Ok(Measurement {
        kib: (signed_sum.max(0) as u64)
            .checked_mul(PAGE_KIB)
            .context("已承诺内存换算溢出")?,
        source: json!({"symbol":"vm_committed_as","global_counter_address":base.address,"global_raw_pages":base.raw,
            "per_cpu_delta_pages":delta,"signed_sum_pages":signed_sum,"included_cpu_count":cpus.len(),
            "online_cpu_count":online.len(),"dying_cpu_count":dying.len(),"dying_mask_present":has_dying,
            "cpu_id_bound":ids,"declared_per_cpu_offsets":declared,"negative_clamped":signed_sum<0,
            "normalization_rule":"percpu_counter_sum_positive (SMP)","formula":"max(global_signed_pages + sum(included_cpu_signed_pages), 0)",
            "scope_note":"按已捕获 online 位图及 ISF 中存在的 dying 位图去重汇总。不同内核 procfs 可能仅读全局基数或采用不同 CPU 范围；此值是显式重建口径，不冒充原始 /proc/meminfo Committed_AS。采集期间并发折叠和热插拔仍可能影响一致性"}),
    })
}
