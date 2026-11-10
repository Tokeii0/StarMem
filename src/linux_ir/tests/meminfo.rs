use super::*;
mod allocations;
mod available;
mod commit;

const BASE: u64 = 0xffff800000100000;
const NODE: u64 = BASE + 0x100;
const ZONE: u64 = BASE + 0x500;
const SB: u64 = BASE + 0x1000;
const INODE: u64 = BASE + 0x2000;
const MAPPING: u64 = BASE + 0x3000;
const SWAP: u64 = BASE + 0x4000;

struct ReadTrace<'a> {
    inner: &'a Memory,
    reads: std::cell::RefCell<Vec<(u64, usize)>>,
    cancel_at: Option<u64>,
}
impl<'a> ReadTrace<'a> {
    fn new(inner: &'a Memory) -> Self {
        Self {
            inner,
            reads: Default::default(),
            cancel_at: None,
        }
    }
    fn bytes_through(&self, address: u64) -> u64 {
        let mut bytes = 0;
        for (observed, size) in self.reads.borrow().iter() {
            bytes += *size as u64;
            if *observed == address {
                return bytes;
            }
        }
        panic!("没有观察到目标读取 {address:#x}");
    }
}
impl LinuxKernelMemory for ReadTrace<'_> {
    fn read_virtual(&self, address: u64, out: &mut [u8]) -> Result<()> {
        self.reads.borrow_mut().push((address, out.len()));
        if self.cancel_at == Some(address) {
            return Err(crate::cancellation::CancellationError.into());
        }
        self.inner.read_virtual(address, out)
    }
    fn translate(&self, address: u64) -> Result<u64> {
        self.inner.translate(address)
    }
    fn isf(&self) -> &LinuxIsf {
        self.inner.isf()
    }
    fn kernel_slide(&self) -> u64 {
        0
    }
    fn source_path(&self) -> Option<&std::path::Path> {
        None
    }
}

fn fixture(legacy: bool) -> Memory {
    fixture_with(legacy, |_, _| {})
}

fn fixture_with(legacy: bool, edit: impl FnOnce(&mut Value, &mut Value)) -> Memory {
    fixture_with_layout(legacy, |_, symbols, enums| edit(symbols, enums))
}

fn fixture_with_layout(
    legacy: bool,
    edit: impl FnOnce(&mut Value, &mut Value, &mut Value),
) -> Memory {
    let base = |name| json!({"kind":"base","name":name});
    let atomic = json!({"kind":"struct","name":"atomic64_t"});
    let symbol = |address, kind: Value| json!({"address":address,"type":kind});
    let array = |kind: Value, count| json!({"kind":"array","count":count,"subtype":kind});
    let ptr = |name| json!({"kind":"pointer","subtype":{"kind":"struct","name":name}});
    let mut types = json!({
        "atomic64_t":{"size":16,"fields":{"counter":u64_field(8)}},
        "list_head":{"size":16,"fields":{"next":u64_field(0),"prev":u64_field(8)}},
        "super_block":{"size":256,"fields":{"s_inodes":{"offset":128,"type":{"kind":"struct","name":"list_head"}}}},
        "inode":{"size":64,"fields":{"i_sb":u64_field(0),"i_mapping":u64_field(8),
            "i_sb_list":{"offset":16,"type":{"kind":"struct","name":"list_head"}}}},
        "address_space":{"size":64,"fields":{"nrpages":u64_field(24)}}
    });
    let mut names = vec![
        "NR_FILE_PAGES",
        "NR_ACTIVE_ANON",
        "NR_INACTIVE_ANON",
        "NR_ACTIVE_FILE",
        "NR_INACTIVE_FILE",
        "NR_UNEVICTABLE",
        "NR_FILE_DIRTY",
        "NR_WRITEBACK",
        "NR_ANON_MAPPED",
        "NR_FILE_MAPPED",
        "NR_SHMEM",
        "NR_WRITEBACK_TEMP",
        "NR_KERNEL_MISC_RECLAIMABLE",
    ];
    names.extend(if legacy {
        vec!["NR_SLAB_RECLAIMABLE", "NR_SLAB_UNRECLAIMABLE"]
    } else {
        vec![
            "NR_SLAB_RECLAIMABLE_B",
            "NR_SLAB_UNRECLAIMABLE_B",
            "NR_KERNEL_STACK_KB",
            "NR_PAGETABLE",
            "NR_SWAPCACHE",
        ]
    });
    let mut zones = vec![
        "NR_FREE_PAGES",
        "NR_MLOCK",
        "NR_BOUNCE",
        "NR_FREE_CMA_PAGES",
    ];
    if legacy {
        zones.extend(["NR_KERNEL_STACK_KB", "NR_PAGETABLE"]);
    }
    let mut enums = json!({});
    for (ty, list, end) in [
        ("node_stat_item", &names, "NR_VM_NODE_STAT_ITEMS"),
        ("zone_stat_item", &zones, "NR_VM_ZONE_STAT_ITEMS"),
    ] {
        let mut constants = serde_json::Map::new();
        for (i, name) in list.iter().enumerate() {
            constants.insert((*name).into(), json!(i));
        }
        constants.insert(end.into(), json!(list.len()));
        enums[ty] = json!({"size":4,"constants":constants});
    }
    let mut symbols = json!({});
    symbols[if legacy {
        "totalram_pages"
    } else {
        "_totalram_pages"
    }] = symbol(
        BASE,
        if legacy {
            base("long unsigned int")
        } else {
            atomic.clone()
        },
    );
    symbols["vm_node_stat"] = symbol(NODE, array(atomic.clone(), names.len()));
    symbols["vm_zone_stat"] = symbol(ZONE, array(atomic.clone(), zones.len()));
    symbols["total_swap_pages"] = symbol(BASE + 0x900, base("long int"));
    symbols["nr_swap_pages"] = symbol(BASE + 0x910, if legacy { atomic } else { base("long int") });
    symbols["blockdev_superblock"] = symbol(BASE + 0x920, ptr("super_block"));
    symbols["nr_swapper_spaces"] = symbol(BASE + 0x930, array(base("unsigned int"), 2));
    symbols["swapper_spaces"] = symbol(BASE + 0x940, array(ptr("address_space"), 0));
    available::add_layout(legacy, &mut types, &mut symbols, &mut enums);
    commit::add_layout(legacy, &mut types, &mut symbols);
    allocations::add_layout(&mut types, &mut symbols);
    edit(&mut types, &mut symbols, &mut enums);
    let mut m = Memory::with_enums(types, symbols, enums);
    m.u64(BASE + if legacy { 0 } else { 8 }, 10000);
    for (i, name) in names.iter().enumerate() {
        m.u64(
            NODE + i as u64 * 16 + 8,
            match *name {
                "NR_FILE_PAGES" => 1000,
                "NR_SWAPCACHE" => 17,
                _ => (i + 100) as u64,
            },
        );
    }
    for (i, _) in zones.iter().enumerate() {
        m.u64(ZONE + i as u64 * 16 + 8, (i + 50) as u64);
    }
    m.u64(BASE + 0x900, 2000);
    m.u64(BASE + 0x910 + if legacy { 8 } else { 0 }, 1500);
    m.u64(BASE + 0x920, SB);
    m.u64(SB + 128, INODE + 16);
    m.u64(SB + 136, INODE + 16);
    m.u64(INODE, SB);
    m.u64(INODE + 8, MAPPING);
    m.u64(INODE + 16, SB + 128);
    m.u64(INODE + 24, SB + 128);
    m.u64(MAPPING + 24, 23);
    m.put(BASE + 0x930, &1u32.to_le_bytes());
    m.put(BASE + 0x934, &0u32.to_le_bytes());
    m.u64(BASE + 0x940, SWAP);
    m.u64(BASE + 0x948, 0);
    m.u64(SWAP + 24, 17);
    available::populate(&mut m, legacy);
    commit::populate(&mut m, legacy);
    allocations::populate(&mut m);
    m
}

fn run(m: &impl LinuxKernelMemory) -> LinuxIrReport {
    run_kernel(
        m,
        &LinuxIrOptions {
            module: "meminfo".into(),
            ..Default::default()
        },
        &CancellationToken::new(),
    )
    .unwrap()
}
fn metric<'a>(report: &'a LinuxIrReport, name: &str) -> &'a Value {
    report
        .records
        .iter()
        .find(|row| row["record_kind"] == "memory_metric" && row["metric"] == name)
        .unwrap()
}

#[test]
fn linux_meminfo_uses_exact_enum_indices_atomic_offsets_and_counter_units() {
    for legacy in [false, true] {
        let report = run(&fixture(legacy));
        assert!(report.available && report.complete, "{:?}", report.warnings);
        assert_eq!(metric(&report, "MemTotal")["value_kib"], 40000);
        assert_eq!(metric(&report, "MemFree")["value_kib"], 200);
        assert_eq!(metric(&report, "Buffers")["value_kib"], 92);
        assert_eq!(metric(&report, "SwapCached")["value_kib"], 68);
        assert_eq!(metric(&report, "Cached")["value_kib"], 3840);
        assert_eq!(metric(&report, "SReclaimable")["value_kib"], 452);
        assert_eq!(
            metric(&report, "KernelStack")["value_kib"],
            if legacy { 54 } else { 115 }
        );
        assert_eq!(
            metric(&report, "KernelStack")["basis"]["symbol"],
            if legacy {
                "vm_zone_stat"
            } else {
                "vm_node_stat"
            }
        );
        assert_eq!(metric(&report, "SwapFreeGlobal")["value_kib"], 6000);
        assert_eq!(metric(&report, "MemFree")["basis"]["element_size"], 16);
        assert_eq!(metric(&report, "MemFree")["basis"]["counter_offset"], 8);
        assert_eq!(report.records[0]["cached_bytes"], 3840 * 1024);
        if legacy {
            assert_eq!(
                metric(&report, "SwapCached")["basis"]["declared_pointer_slots"],
                0
            );
            assert!(
                report
                    .records
                    .iter()
                    .any(|row| row["record_kind"] == "memory_input"
                        && row["counter_address"] == SWAP + 24)
            );
        }
    }
}

#[test]
fn linux_meminfo_missing_counter_does_not_erase_independent_metrics_or_become_zero() {
    let mut m = fixture(false);
    m.bytes.remove(&(NODE + 8));
    let report = run(&m);
    assert!(report.available && !report.complete);
    assert!(metric(&report, "FilePages")["value_kib"].is_null());
    assert!(metric(&report, "Cached")["value_kib"].is_null());
    assert_eq!(metric(&report, "MemTotal")["value_kib"], 40000);
    assert_eq!(report.missing_ranges[0]["virtual_address"], NODE + 8);
}

#[test]
fn linux_meminfo_negative_vmstat_preserves_raw_value_and_marks_normalization() {
    let mut m = fixture(false);
    m.u64(ZONE + 8, (-5i64) as u64);
    let report = run(&m);
    assert!(!report.complete);
    assert_eq!(metric(&report, "MemFree")["value_kib"], 0);
    assert_eq!(metric(&report, "MemFree")["basis"]["raw_value"], -5);
    assert_eq!(
        metric(&report, "MemFree")["basis"]["negative_clamped"],
        true
    );
}

#[test]
fn linux_meminfo_broken_tail_and_foreign_inode_never_publish_buffer_prefix_total() {
    for foreign in [true, false] {
        let mut m = fixture(false);
        m.u64(if foreign { INODE } else { SB + 136 }, BASE + 0x8000);
        let report = run(&m);
        assert!(metric(&report, "Buffers")["value_kib"].is_null());
        assert!(metric(&report, "Cached")["value_kib"].is_null());
        assert_eq!(metric(&report, "SwapCached")["value_kib"], 68);
        assert!(!report.complete);
    }
}

#[test]
fn linux_meminfo_valid_empty_block_device_list_proves_zero_buffers() {
    let mut m = fixture(false);
    m.u64(SB + 128, SB + 128);
    m.u64(SB + 136, SB + 128);
    let report = run(&m);
    assert_eq!(metric(&report, "Buffers")["value_kib"], 0);
    assert_eq!(metric(&report, "Buffers")["status"], "read");
    assert_eq!(metric(&report, "Cached")["value_kib"], 3932);
}

#[test]
fn linux_meminfo_swapcache_bad_pointer_limit_and_missing_page_are_not_zero() {
    for mutation in 0..3 {
        let mut m = fixture(true);
        match mutation {
            0 => m.u64(BASE + 0x940, 0),
            1 => m.put(BASE + 0x930, &4097u32.to_le_bytes()),
            _ => {
                m.bytes.remove(&(SWAP + 24));
            }
        }
        let report = run(&m);
        assert!(metric(&report, "SwapCached")["value_kib"].is_null());
        assert!(metric(&report, "Cached")["value_kib"].is_null());
        assert_eq!(metric(&report, "Buffers")["value_kib"], 92);
    }
}

#[test]
fn linux_meminfo_budget_counts_all_reads_and_limit_retains_summary() {
    let m = fixture(false);
    let report = run_kernel(
        &m,
        &LinuxIrOptions {
            module: "meminfo".into(),
            max_bytes: 16,
            ..Default::default()
        },
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(report.records[0]["attempted_bytes"], 16);
    assert_eq!(metric(&report, "MemTotal")["value_kib"], 40000);
    assert!(metric(&report, "Buffers")["value_kib"].is_null());
    let limited = run_kernel(
        &m,
        &LinuxIrOptions {
            module: "meminfo".into(),
            limit: 1,
            ..Default::default()
        },
        &CancellationToken::new(),
    )
    .unwrap();
    assert!(limited.available && !limited.complete && limited.limit_reached);
    assert_eq!(limited.record_count, 1);
    assert_eq!(limited.records[0]["cached_bytes"], 3840 * 1024);
}

#[test]
fn linux_meminfo_overflow_is_local_to_the_failed_metric() {
    let mut m = fixture(false);
    m.u64(BASE + 8, i64::MAX as u64);
    let report = run(&m);
    assert!(metric(&report, "MemTotal")["value_kib"].is_null());
    assert_eq!(metric(&report, "MemFree")["value_kib"], 200);
    assert!(report.available && !report.complete);
}

#[test]
fn linux_meminfo_typed_cancellation_from_list_read_is_not_swallowed() {
    struct CancelAt {
        inner: Memory,
    }
    impl LinuxKernelMemory for CancelAt {
        fn read_virtual(&self, address: u64, out: &mut [u8]) -> Result<()> {
            if address == INODE + 24 {
                return Err(crate::cancellation::CancellationError.into());
            }
            self.inner.read_virtual(address, out)
        }
        fn translate(&self, address: u64) -> Result<u64> {
            self.inner.translate(address)
        }
        fn isf(&self) -> &LinuxIsf {
            &self.inner.isf
        }
        fn kernel_slide(&self) -> u64 {
            0
        }
        fn source_path(&self) -> Option<&std::path::Path> {
            None
        }
    }
    let error = run_kernel(
        &CancelAt {
            inner: fixture(false),
        },
        &LinuxIrOptions {
            module: "meminfo".into(),
            ..Default::default()
        },
        &CancellationToken::new(),
    )
    .unwrap_err();
    assert!(crate::cancellation::is_cancellation_error(&error));
}

#[test]
fn linux_meminfo_no_readable_counters_is_unavailable_with_reasons() {
    let mut m = fixture(false);
    m.bytes.clear();
    let report = run(&m);
    assert!(!report.available && !report.complete);
    assert!(report.records[0]["free_bytes"].is_null());
    assert!(!report.warnings.is_empty() && !report.missing_ranges.is_empty());
}

#[test]
fn linux_meminfo_rejects_conflicting_enum_extent_and_ambiguous_counter_ownership() {
    for mutation in 0..3 {
        let m = fixture_with(false, |symbols, enums| match mutation {
            0 => symbols["vm_zone_stat"]["type"]["count"] = json!(5),
            1 => enums["zone_stat_item"]["constants"]["NR_FREE_PAGES"] = json!(1000),
            _ => enums["node_stat_item"]["constants"]["NR_FREE_PAGES"] = json!(1),
        });
        let report = run(&m);
        assert!(metric(&report, "MemFree")["value_kib"].is_null());
        assert_eq!(metric(&report, "MemTotal")["value_kib"], 40000);
    }
}

#[test]
fn linux_meminfo_rejects_conflicting_paired_swap_arrays_and_wrong_element_types() {
    for mutation in 0..3 {
        let m = fixture_with(true, |symbols, _| match mutation {
            0 => symbols["swapper_spaces"]["type"]["count"] = json!(1),
            1 => symbols["swapper_spaces"]["type"]["subtype"]["subtype"]["name"] = json!("inode"),
            _ => {
                symbols["nr_swapper_spaces"]["type"]["subtype"]["name"] = json!("long unsigned int")
            }
        });
        let report = run(&m);
        assert!(metric(&report, "SwapCached")["value_kib"].is_null());
        assert!(metric(&report, "Cached")["value_kib"].is_null());
        assert_eq!(metric(&report, "MemFree")["value_kib"], 200);
    }
}
