use super::*;

pub(super) fn measure(
    m: &Memory<'_, impl LinuxKernelMemory>,
    inputs: &mut Vec<Value>,
) -> Result<Measurement> {
    ensure!(
        m.isf().symbol_array_struct_type("hstates")? == "hstate",
        "hstates 数组元素不是 hstate"
    );
    let declared = m.isf().symbol_array_count("hstates")?;
    ensure!(declared <= 64, "hstates 声明超过 64 项");
    let count = scalar(
        m,
        "hugetlb_max_hstate",
        4,
        "Hugetlb",
        "hugetlb_state_count",
        inputs,
    )?;
    ensure!(count <= declared, "hugetlb_max_hstate 超出 hstates 数组");
    let stride = m.isf().symbol_array_element_size("hstates")?;
    let (order_offset, order_width) = m.isf().field_scalar_layout("hstate", "order")?;
    let (pages_offset, pages_width) = m.isf().field_scalar_layout("hstate", "nr_huge_pages")?;
    ensure!(
        stride == m.isf().type_size("hstate")? && order_width == 4 && pages_width == 8,
        "hstate 的阶数、页数或元素大小不匹配"
    );
    let root = m.runtime_symbol("hstates")?;
    let mut total = 0u64;
    let mut orders = std::collections::BTreeSet::new();
    for index in 0..count {
        let address = add(root, index.checked_mul(stride).context("hstate 偏移溢出")?)?;
        let order_address = add(address, order_offset)?;
        let pages_address = add(address, pages_offset)?;
        let order = number(m, order_address, 4)?;
        let pages = number(m, pages_address, 8)?;
        inputs.push(
            json!({"record_kind":"memory_input","metric":"Hugetlb","input_kind":"hugetlb_state",
            "hstate_index":index,"hstate_address":address,"hstate_stride":stride,
            "order_address":order_address,"page_order":order,"counter_address":pages_address,
            "counter_width":8,"raw_value":pages,"counter_unit":"huge_pages"}),
        );
        ensure!(
            order > 0 && order <= 51 && orders.insert(order),
            "HugeTLB 阶数越界或重复"
        );
        let pages_per_huge = 1u64 << order;
        total = total
            .checked_add(
                pages
                    .checked_mul(pages_per_huge)
                    .context("HugeTLB 页数溢出")?,
            )
            .context("HugeTLB 汇总溢出")?;
    }
    Ok(Measurement {
        kib: total.checked_mul(PAGE_KIB).context("HugeTLB 换算溢出")?,
        source: json!({"symbol":"hstates","hstate_count":count,"declared_hstates":declared,
            "base_pages":total,"formula":"sum(nr_huge_pages * (1 << order))",
            "scope_note":"覆盖 hstates 中已登记的全部 HugeTLB 页大小；不包含透明大页，也不是默认页大小的 HugePages_Total"}),
    })
}
