use super::*;

const VMALLOC: u64 = BASE + 0x28000;
const POPULATED: u64 = BASE + 0x28100;
const UNITS: u64 = BASE + 0x28108;
const DEFAULT: u64 = BASE + 0x28110;
const POISON: u64 = BASE + 0x28200;
const HSTATES: u64 = BASE + 0x26000;

pub(super) fn add_layout(types: &mut Value, symbols: &mut Value) {
    for (name, address, kind) in [
        (
            "nr_vmalloc_pages",
            VMALLOC,
            json!({"kind":"struct","name":"atomic64_t"}),
        ),
        (
            "pcpu_nr_populated",
            POPULATED,
            json!({"kind":"base","name":"long unsigned int"}),
        ),
        (
            "pcpu_nr_units",
            UNITS,
            json!({"kind":"base","name":"unsigned int"}),
        ),
        (
            "default_hstate_idx",
            DEFAULT,
            json!({"kind":"base","name":"unsigned int"}),
        ),
        (
            "num_poisoned_pages",
            POISON,
            json!({"kind":"struct","name":"atomic64_t"}),
        ),
    ] {
        symbols[name] = json!({"address":address,"type":kind});
    }
    for (name, offset) in [
        ("free_huge_pages", 24),
        ("resv_huge_pages", 32),
        ("surplus_huge_pages", 40),
    ] {
        types["hstate"]["fields"][name] =
            json!({"offset":offset,"type":{"kind":"base","name":"long unsigned int"}});
    }
}

pub(super) fn populate(m: &mut Memory) {
    m.u64(VMALLOC + 8, 37);
    m.u64(POPULATED, 11);
    m.put(UNITS, &3u32.to_le_bytes());
    m.put(DEFAULT, &0u32.to_le_bytes());
    m.u64(POISON + 8, 7);
    for (address, count) in [
        (HSTATES + 24, 1),
        (HSTATES + 32, 1),
        (HSTATES + 40, 0),
        (HSTATES + 64 + 24, 0),
        (HSTATES + 64 + 32, 0),
        (HSTATES + 64 + 40, 0),
    ] {
        m.u64(address, count);
    }
}

#[test]
fn allocator_units_are_not_cpu_count_and_hugepages_keep_count_units() {
    let report = run(&fixture(false));
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(metric(&report, "VmallocUsed")["value_kib"], 148);
    assert_eq!(metric(&report, "Percpu")["value_kib"], 132);
    assert_eq!(metric(&report, "Percpu")["basis"]["allocator_units"], 3);
    assert_eq!(
        metric(&report, "Committed_ASReconstructed")["basis"]["included_cpu_count"],
        2
    );
    assert_eq!(metric(&report, "HardwareCorrupted")["value_kib"], 28);
    assert_eq!(metric(&report, "Hugepagesize")["value_kib"], 2048);
    for (name, expected) in [
        ("HugePages_Total", 2),
        ("HugePages_Free", 1),
        ("HugePages_Rsvd", 1),
        ("HugePages_Surp", 0),
    ] {
        let row = metric(&report, name);
        assert_eq!(row["value_count"], expected);
        assert_eq!(row["unit"], "huge_pages");
        assert!(row["value_kib"].is_null() && row["value_bytes"].is_null());
    }
    assert_eq!(report.records[0]["vmalloc_used_bytes"], 148 * 1024);
    assert_eq!(report.records[0]["percpu_bytes"], 132 * 1024);
    assert_eq!(report.records[0]["default_hugepage_size_bytes"], 2097152);
}

#[test]
fn default_hstate_index_selects_the_correct_page_size_and_counter_addresses() {
    let mut memory = fixture(false);
    memory.put(DEFAULT, &1u32.to_le_bytes());
    memory.u64(HSTATES + 64 + 32, 2);
    let report = run(&memory);
    let row = metric(&report, "HugePages_Rsvd");
    assert_eq!(row["value_count"], 2);
    assert_eq!(row["basis"]["hstate_index"], 1);
    assert_eq!(row["basis"]["counter_address"], HSTATES + 64 + 32);
    assert_eq!(metric(&report, "Hugepagesize")["value_kib"], 1048576);
    assert_eq!(metric(&report, "Hugetlb")["value_kib"], 4096);
}

#[test]
fn missing_allocator_and_default_hugepage_counter_preserve_other_metrics() {
    let mut memory = fixture_with(false, |symbols, _| {
        symbols.as_object_mut().unwrap().remove("nr_vmalloc_pages");
    });
    memory.bytes.remove(&(HSTATES + 24));
    let report = run(&memory);
    assert!(!report.complete);
    assert_eq!(metric(&report, "VmallocUsed")["status"], "unavailable");
    assert_eq!(metric(&report, "HugePages_Free")["status"], "unavailable");
    assert!(metric(&report, "HugePages_Free")["value_count"].is_null());
    assert_eq!(metric(&report, "HugePages_Total")["value_count"], 2);
    assert_eq!(metric(&report, "Percpu")["value_kib"], 132);
    assert!(
        report
            .missing_ranges
            .iter()
            .any(|range| range["virtual_address"] == HSTATES + 24)
    );
}

#[test]
fn invalid_default_index_layout_order_and_unit_count_do_not_become_zero() {
    for mode in ["index", "order", "width", "units", "overflow"] {
        let mut memory = fixture_with_layout(false, |types, _, _| {
            if mode == "width" {
                types["hstate"]["fields"]["free_huge_pages"]["type"]["name"] =
                    json!("unsigned int");
            }
        });
        match mode {
            "index" => memory.put(DEFAULT, &2u32.to_le_bytes()),
            "order" => memory.put(HSTATES + 4, &52u32.to_le_bytes()),
            "units" => memory.put(UNITS, &u32::MAX.to_le_bytes()),
            "overflow" => memory.u64(POPULATED, i64::MAX as u64),
            _ => {}
        }
        let report = run(&memory);
        let name = if ["units", "overflow"].contains(&mode) {
            "Percpu"
        } else {
            "HugePages_Free"
        };
        assert_eq!(metric(&report, name)["status"], "unavailable", "{mode}");
        assert!(metric(&report, name)["value_kib"].is_null());
        assert_eq!(metric(&report, "VmallocUsed")["value_kib"], 148);
    }
}

#[test]
fn allocator_and_hugepage_reads_obey_cancellation_and_whole_report_budget() {
    let memory = fixture(false);
    for address in [VMALLOC + 8, POPULATED, DEFAULT, HSTATES + 32] {
        let traced = ReadTrace {
            cancel_at: Some(address),
            ..ReadTrace::new(&memory)
        };
        let result = run_kernel(
            &traced,
            &LinuxIrOptions {
                module: "meminfo".into(),
                ..Default::default()
            },
            &CancellationToken::new(),
        );
        assert!(crate::cancellation::is_cancellation_error(
            &result.unwrap_err()
        ));
    }
    let trace = ReadTrace::new(&memory);
    run(&trace);
    let budget = trace.bytes_through(DEFAULT) - 1;
    let report = run_kernel(
        &memory,
        &LinuxIrOptions {
            module: "meminfo".into(),
            max_bytes: budget,
            ..Default::default()
        },
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(metric(&report, "Hugepagesize")["status"], "unavailable");
    assert_eq!(metric(&report, "Percpu")["value_kib"], 132);
    assert!(report.records[0]["attempted_bytes"].as_u64().unwrap() <= budget);
}
