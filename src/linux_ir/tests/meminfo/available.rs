use super::*;

const MASK: u64 = BASE + 0x5000;
const IDS: u64 = BASE + 0x5100;
const ONLINE: u64 = BASE + 0x5108;
const TABLE: u64 = BASE + 0x5200;
const RESERVE: u64 = BASE + 0x5800;
const PGDAT: u64 = BASE + 0x10000;
const SECOND: u64 = BASE + 0x11000;

pub(super) fn add_layout(legacy: bool, types: &mut Value, symbols: &mut Value, enums: &mut Value) {
    let u32_field = |offset| json!({"offset":offset,"type":{"kind":"base","name":"unsigned int"}});
    let array = |name, count, kind| json!({"kind":"array","count":count,"subtype":{"kind":kind,"name":name}});
    types["nodemask_t"] = json!({"size":16,"fields":{"bits":{"offset":0,"type":array("long unsigned int",2,"base")}}});
    types["pg_data_t"] = json!({"size":256,"fields":{"node_id":u32_field(0),"nr_zones":u32_field(4),
        "node_zones":{"offset":32,"type":array("zone",3,"struct")}}});
    let mut zone_fields = json!({});
    zone_fields[if legacy { "watermark" } else { "_watermark" }] =
        json!({"offset":8,"type":array("long unsigned int",3,"base")});
    if !legacy {
        zone_fields["watermark_boost"] = u64_field(32);
    }
    types["zone"] = json!({"size":64,"fields":zone_fields});
    symbols["node_states"] = json!({"address":MASK,"type":array("nodemask_t",2,"struct")});
    symbols["node_data"] = json!({"address":TABLE,"type":{"kind":"array","count":0,
        "subtype":{"kind":"pointer","subtype":{"kind":"struct","name":"pg_data_t"}}}});
    symbols["nr_node_ids"] = json!({"address":IDS,"type":{"kind":"base","name":"unsigned int"}});
    symbols["nr_online_nodes"] =
        json!({"address":ONLINE,"type":{"kind":"base","name":"unsigned int"}});
    symbols["totalreserve_pages"] =
        json!({"address":RESERVE,"type":{"kind":"base","name":"long unsigned int"}});
    enums["node_states"] =
        json!({"size":4,"constants":{"N_POSSIBLE":0,"N_ONLINE":1,"NR_NODE_STATES":2}});
    // Deliberately put WMARK_LOW at index 2 rather than the usual 1.
    enums["zone_watermarks"] =
        json!({"size":4,"constants":{"WMARK_MIN":0,"WMARK_HIGH":1,"WMARK_LOW":2,"NR_WMARK":3}});
    enums["zone_type"] = json!({"size":4,"constants":{"ZONE_DMA":0,"ZONE_NORMAL":1,"ZONE_MOVABLE":2,"__MAX_NR_ZONES":3}});
}

pub(super) fn populate(m: &mut Memory, legacy: bool) {
    m.u64(MASK + 16, 2);
    m.u64(MASK + 24, 2); // sparse IDs 1 and 65
    m.put(IDS, &66u32.to_le_bytes());
    m.put(ONLINE, &2u32.to_le_bytes());
    m.u64(RESERVE, 100);
    for (id, pgdat, lows, boosts) in [
        (1u64, PGDAT, [2u64, 3, 5], [1u64, 2, 3]),
        (65, SECOND, [7, 11, 13], [4, 5, 6]),
    ] {
        m.u64(TABLE + id * 8, pgdat);
        m.put(pgdat, &(id as u32).to_le_bytes());
        m.put(pgdat + 4, &1u32.to_le_bytes()); // nr_zones must not truncate the full array
        for i in 0..3 {
            let zone = pgdat + 32 + i * 64;
            m.u64(zone + 24, lows[i as usize]);
            if !legacy {
                m.u64(zone + 32, boosts[i as usize]);
            }
        }
    }
}

#[test]
fn linux_memavailable_sparse_online_nodes_all_zones_and_boost_use_exact_layout() {
    for legacy in [true, false] {
        let report = run(&fixture(legacy));
        assert!(report.complete, "{:?}", report.warnings);
        let row = metric(&report, "MemAvailable");
        assert_eq!(row["status"], "estimated");
        assert_eq!(row["value_kib"], if legacy { 1200 } else { 1032 });
        assert_eq!(row["basis"]["topology"]["online_node_count"], 2);
        assert_eq!(row["basis"]["topology"]["node_id_bound"], 66);
        assert_eq!(row["basis"]["topology"]["node_array_declared_count"], 0);
        assert_eq!(
            row["basis"]["topology"]["low_watermark_pages"],
            if legacy { 41 } else { 62 }
        );
        assert_eq!(
            report
                .records
                .iter()
                .filter(|row| row["input_kind"] == "zone_watermark")
                .count(),
            6
        );
        assert_eq!(
            report.records[0]["available_bytes"],
            if legacy { 1200 * 1024 } else { 1032 * 1024 }
        );
    }
}

#[test]
fn linux_memavailable_rounds_half_in_pages_and_clamps_only_final_signed_sum() {
    let mut m = fixture(false);
    for pgdat in [PGDAT, SECOND] {
        for i in 0..3 {
            m.u64(pgdat + 32 + i * 64 + 24, 0);
            m.u64(pgdat + 32 + i * 64 + 32, 0);
        }
    }
    m.u64(PGDAT + 32 + 24, 200);
    let report = run(&m);
    assert_eq!(metric(&report, "MemAvailable")["value_kib"], 668); // (50-100+104+113)*4
    m.u64(RESERVE, 10000);
    let report = run(&m);
    assert_eq!(metric(&report, "MemAvailable")["value_kib"], 0);
    assert_eq!(metric(&report, "MemAvailable")["status"], "estimated");
}

#[test]
fn linux_memavailable_legacy_formula_does_not_invent_misc_reclaimable_pages() {
    let m = fixture_with(true, |_, enums| {
        enums["node_stat_item"]["constants"]
            .as_object_mut()
            .unwrap()
            .remove("NR_KERNEL_MISC_RECLAIMABLE");
    });
    let report = run(&m);
    assert_eq!(metric(&report, "MemAvailable")["value_kib"], 752); // (50-100+166+72)*4
    assert_eq!(
        metric(&report, "MemAvailable")["basis"]["kernel_misc_included"],
        false
    );
}

#[test]
fn linux_memavailable_requires_agreement_between_mask_counts_bounds_and_ownership() {
    for mutation in 0..5 {
        let mut m = fixture(false);
        match mutation {
            0 => m.put(ONLINE, &1u32.to_le_bytes()),
            1 => m.put(IDS, &65u32.to_le_bytes()),
            2 => m.u64(TABLE + 65 * 8, PGDAT),
            3 => m.put(SECOND, &64u32.to_le_bytes()),
            _ => {
                m.u64(MASK + 16, 0);
                m.u64(MASK + 24, 0);
            }
        }
        let report = run(&m);
        assert!(!report.complete);
        assert!(metric(&report, "MemAvailable")["value_kib"].is_null());
        assert_eq!(metric(&report, "MemFree")["value_kib"], 200);
        assert_eq!(metric(&report, "Cached")["value_kib"], 3840);
    }
}

#[test]
fn linux_memavailable_missing_mask_watermark_or_boost_never_yields_prefix_estimate() {
    for address in [MASK + 24, SECOND + 32 + 24, SECOND + 32 + 32, RESERVE] {
        let mut m = fixture(false);
        m.bytes.remove(&address);
        let report = run(&m);
        assert!(metric(&report, "MemAvailable")["value_kib"].is_null());
        assert!(
            report
                .missing_ranges
                .iter()
                .any(|r| r["virtual_address"] == address)
        );
        assert!(report.available && !report.complete);
    }
}

#[test]
fn linux_memavailable_cannot_use_missing_global_dependencies_as_zero() {
    for address in [NODE + 3 * 16 + 8, NODE + 13 * 16 + 8, NODE + 12 * 16 + 8] {
        let mut m = fixture(false);
        m.bytes.remove(&address);
        let report = run(&m);
        assert!(metric(&report, "MemAvailable")["value_kib"].is_null());
        assert_eq!(metric(&report, "MemFree")["value_kib"], 200);
    }
}

#[test]
fn linux_memavailable_rejects_ambiguous_layout_and_enum_array_conflicts() {
    for mutation in 0..5 {
        let m = fixture_with_layout(false, |types, symbols, enums| match mutation {
            0 => enums["zone_watermarks"]["constants"]["WMARK_LOW"] = json!(3),
            1 => enums["zone_type"]["constants"]["__MAX_NR_ZONES"] = json!(2),
            2 => {
                types["zone"]["fields"]["watermark"] = types["zone"]["fields"]["_watermark"].clone()
            }
            3 => {
                types["zone"]["fields"]
                    .as_object_mut()
                    .unwrap()
                    .remove("watermark_boost");
            }
            _ => symbols["node_states"]["type"]["count"] = json!(3),
        });
        let report = run(&m);
        assert!(metric(&report, "MemAvailable")["value_kib"].is_null());
    }
}

#[test]
fn linux_memavailable_zero_declared_node_array_needs_runtime_bound() {
    for declared in [0, 128] {
        let m = fixture_with(false, |symbols, _| {
            symbols.as_object_mut().unwrap().remove("nr_node_ids");
            symbols["node_data"]["type"]["count"] = json!(declared);
        });
        let report = run(&m);
        assert_eq!(
            metric(&report, "MemAvailable")["value_kib"].is_null(),
            declared == 0
        );
    }
}

#[test]
fn linux_memavailable_contiguous_layout_requires_single_node_zero() {
    let mut m = fixture_with(false, |symbols, _| {
        symbols.as_object_mut().unwrap().remove("node_data");
        symbols["contig_page_data"] =
            json!({"address":PGDAT,"type":{"kind":"struct","name":"pg_data_t"}});
    });
    assert!(metric(&run(&m), "MemAvailable")["value_kib"].is_null());
    m.u64(MASK + 16, 1);
    m.u64(MASK + 24, 0);
    m.put(ONLINE, &1u32.to_le_bytes());
    m.put(PGDAT, &0u32.to_le_bytes());
    let report = run(&m);
    assert_eq!(
        metric(&report, "MemAvailable")["basis"]["topology"]["node_source"],
        "contig_page_data"
    );
    assert_eq!(metric(&report, "MemAvailable")["value_kib"], 1400); // (50-100+191+209)*4
}

#[test]
fn linux_memavailable_read_budget_covers_new_topology_and_watermark_reads() {
    let m = fixture(false);
    let trace = ReadTrace::new(&m);
    run(&trace);
    // Cut the budget inside this metric's reserve read, independent of metrics
    // appended after MemAvailable.
    let used = trace.bytes_through(RESERVE);
    let report = run_kernel(
        &m,
        &LinuxIrOptions {
            module: "meminfo".into(),
            max_bytes: used - 1,
            ..Default::default()
        },
        &CancellationToken::new(),
    )
    .unwrap();
    assert!(metric(&report, "MemAvailable")["value_kib"].is_null());
    assert!(report.records[0]["attempted_bytes"].as_u64().unwrap() < used);
    assert_eq!(metric(&report, "Cached")["value_kib"], 3840);
}

#[test]
fn linux_memavailable_typed_cancellation_while_reading_zone_is_propagated() {
    struct CancelAt {
        inner: Memory,
    }
    impl LinuxKernelMemory for CancelAt {
        fn read_virtual(&self, address: u64, out: &mut [u8]) -> Result<()> {
            if address == SECOND + 32 + 24 {
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
fn linux_memavailable_watermark_overflow_and_invalid_node_id_layout_are_unavailable() {
    let mut m = fixture(false);
    m.u64(PGDAT + 32 + 24, u64::MAX);
    assert!(metric(&run(&m), "MemAvailable")["value_kib"].is_null());
    let m = fixture_with_layout(false, |types, _, _| {
        types["pg_data_t"]["fields"]["node_id"] = u64_field(0);
    });
    let report = run(&m);
    assert!(metric(&report, "MemAvailable")["value_kib"].is_null());
    assert_eq!(metric(&report, "MemFree")["value_kib"], 200);
}
