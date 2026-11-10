use super::*;

const FBC: u64 = BASE + 0x20000;
const MODE: u64 = BASE + 0x20100;
const RATIO: u64 = BASE + 0x20108;
const KBYTES: u64 = BASE + 0x20110;
const HCOUNT: u64 = BASE + 0x20120;
const IDS: u64 = BASE + 0x20128;
const POSSIBLE: u64 = BASE + 0x21000;
const ONLINE: u64 = BASE + 0x21040;
const DYING: u64 = BASE + 0x21080;
const OFFSETS: u64 = BASE + 0x22000;
const FIRST: u64 = BASE + 0x24000;
const SECOND: u64 = BASE + 0x25000;
const HSTATES: u64 = BASE + 0x26000;

pub(super) fn add_layout(legacy: bool, types: &mut Value, symbols: &mut Value) {
    let base = |name| json!({"kind":"base","name":name});
    let named = |name| json!({"kind":"struct","name":name});
    let field = |offset, kind| json!({"offset":offset,"type":kind});
    let array = |count, kind| json!({"kind":"array","count":count,"subtype":kind});
    types["percpu_counter"] = json!({"size":48,"fields":{
        "count":field(16,base("long int")),
        "counters":field(40,json!({"kind":"pointer","subtype":base("unsigned int")}))}});
    types["cpumask"] =
        json!({"size":24,"fields":{"bits":field(8,array(2,base("long unsigned int")))}});
    types["hstate"] = json!({"size":64,"fields":{"order":field(4,base("unsigned int")),"nr_huge_pages":field(16,base("long unsigned int"))}});
    for (name, address, kind) in [
        ("vm_committed_as", FBC, named("percpu_counter")),
        ("sysctl_overcommit_memory", MODE, base("unsigned int")),
        ("sysctl_overcommit_ratio", RATIO, base("unsigned int")),
        (
            "sysctl_overcommit_kbytes",
            KBYTES,
            base("long unsigned int"),
        ),
        ("hugetlb_max_hstate", HCOUNT, base("unsigned int")),
        ("nr_cpu_ids", IDS, base("unsigned int")),
        ("__cpu_possible_mask", POSSIBLE, named("cpumask")),
        ("__cpu_online_mask", ONLINE, named("cpumask")),
        (
            "__per_cpu_offset",
            OFFSETS,
            array(128, base("long unsigned int")),
        ),
        ("hstates", HSTATES, array(2, named("hstate"))),
    ] {
        symbols[name] = json!({"address":address,"type":kind});
    }
    if !legacy {
        symbols["__cpu_dying_mask"] = json!({"address":DYING,"type":named("cpumask")});
    }
}

pub(super) fn populate(m: &mut Memory, legacy: bool) {
    m.u64(FBC + 16, 1000);
    m.u64(FBC + 40, 0x1000);
    for (address, value) in [(MODE, 2u32), (RATIO, 50), (HCOUNT, 2), (IDS, 66)] {
        m.put(address, &value.to_le_bytes());
    }
    m.u64(KBYTES, 0);
    for mask in [POSSIBLE, ONLINE] {
        m.u64(mask + 8, 2);
        m.u64(mask + 16, 2);
    }
    if !legacy {
        m.u64(DYING + 8, 0);
        m.u64(DYING + 16, 2);
    }
    m.u64(OFFSETS + 8, FIRST - 0x1000);
    m.u64(OFFSETS + 65 * 8, SECOND - 0x1000);
    m.put(FIRST, &37i32.to_le_bytes());
    m.put(SECOND, &(-11i32).to_le_bytes());
    m.put(HSTATES + 4, &9u32.to_le_bytes());
    m.u64(HSTATES + 16, 2);
    m.put(HSTATES + 64 + 4, &18u32.to_le_bytes());
    m.u64(HSTATES + 64 + 16, 0);
}

#[test]
fn commit_metrics_keep_global_and_cpu_accounting_separate_and_use_all_hstates() {
    for legacy in [false, true] {
        let report = run(&fixture(legacy));
        assert!(report.complete, "{:?}", report.warnings);
        assert_eq!(metric(&report, "Hugetlb")["value_kib"], 4096);
        assert_eq!(metric(&report, "CommitLimit")["value_kib"], 25952);
        assert_eq!(metric(&report, "Committed_ASGlobal")["value_kib"], 4000);
        let sum = metric(&report, "Committed_ASReconstructed");
        assert_eq!(sum["value_kib"], 4104);
        assert_eq!(sum["basis"]["included_cpu_count"], 2);
        assert_eq!(sum["basis"]["dying_cpu_count"], if legacy { 0 } else { 1 });
        let deltas = report
            .records
            .iter()
            .filter(|row| row["input_kind"] == "per_cpu_commit_delta")
            .collect::<Vec<_>>();
        assert_eq!(deltas.len(), 2);
        assert_eq!(deltas[0]["cpu_id"], 1);
        assert_eq!(deltas[1]["cpu_id"], 65);
        assert_eq!(deltas[1]["raw_value"], -11);
        assert_eq!(
            report.records[0]["committed_reconstructed_bytes"],
            4104 * 1024
        );
        assert!(
            report
                .records
                .iter()
                .any(|row| row["record_kind"] == "memory_commit_policy"
                    && row["strict_overcommit"] == true)
        );
    }
}

#[test]
fn signed_global_is_not_clamped_before_folding_cpu_deltas() {
    let mut m = fixture(false);
    m.u64(FBC + 16, (-30i64) as u64);
    m.put(FIRST, &50i32.to_le_bytes());
    let report = run(&m);
    assert_eq!(metric(&report, "Committed_ASGlobal")["value_kib"], 0);
    assert_eq!(
        metric(&report, "Committed_ASReconstructed")["value_kib"],
        36
    );
    assert_eq!(
        metric(&report, "Committed_ASReconstructed")["basis"]["signed_sum_pages"],
        9
    );
    m.put(FIRST, &0i32.to_le_bytes());
    let report = run(&m);
    let sum = metric(&report, "Committed_ASReconstructed");
    assert_eq!(sum["value_kib"], 0);
    assert_eq!(sum["basis"]["signed_sum_pages"], -41);
    assert_eq!(sum["basis"]["negative_clamped"], true);
}

#[test]
fn explicit_kbytes_rounds_to_pages_and_does_not_require_ram_ratio_or_huge_pages() {
    let mut m = fixture_with(false, |symbols, _| {
        symbols
            .as_object_mut()
            .unwrap()
            .remove("sysctl_overcommit_ratio");
        symbols.as_object_mut().unwrap().remove("hstates");
    });
    m.u64(KBYTES, 123);
    m.put(MODE, &0u32.to_le_bytes());
    let report = run(&m);
    let limit = metric(&report, "CommitLimit");
    assert_eq!(limit["value_kib"], 8120);
    assert_eq!(limit["basis"]["calculation_mode"], "explicit_kbytes");
    assert_eq!(limit["basis"]["inputs"]["discarded_kib_remainder"], 3);
    assert!(metric(&report, "Hugetlb")["value_kib"].is_null());
    assert!(report.records.iter().any(
        |row| row["record_kind"] == "memory_commit_policy" && row["strict_overcommit"] == false
    ));
}

#[test]
fn broken_cpu_topology_or_missing_page_does_not_turn_the_sum_into_the_global_base() {
    for kind in [
        "possible",
        "ids",
        "empty_online",
        "missing_delta",
        "duplicate",
        "null_pointer",
        "unaligned",
    ] {
        let mut m = fixture(false);
        match kind {
            "possible" => m.u64(POSSIBLE + 16, 0),
            "ids" => m.put(IDS, &65u32.to_le_bytes()),
            "empty_online" => {
                m.u64(ONLINE + 8, 0);
                m.u64(ONLINE + 16, 0);
            }
            "missing_delta" => {
                m.bytes.remove(&SECOND);
            }
            "duplicate" => m.u64(OFFSETS + 65 * 8, FIRST - 0x1000),
            "null_pointer" => m.u64(FBC + 40, 0),
            _ => m.u64(OFFSETS + 8, FIRST - 0x1000 + 1),
        }
        let report = run(&m);
        assert_eq!(
            metric(&report, "Committed_ASGlobal")["value_kib"],
            4000,
            "{kind}"
        );
        assert!(
            metric(&report, "Committed_ASReconstructed")["value_kib"].is_null(),
            "{kind}"
        );
        assert!(!report.complete);
        assert_eq!(metric(&report, "CommitLimit")["value_kib"], 25952);
        if kind == "missing_delta" {
            assert!(
                report
                    .missing_ranges
                    .iter()
                    .any(|row| row["virtual_address"] == SECOND)
            );
            assert!(
                report
                    .records
                    .iter()
                    .any(|row| row["input_kind"] == "per_cpu_commit_delta" && row["cpu_id"] == 1)
            );
        }
    }
}

#[test]
fn invalid_layouts_and_unbounded_per_cpu_arrays_are_rejected() {
    for kind in [
        "array_zero",
        "array_short",
        "array_large",
        "mask_large",
        "pointer_width",
        "count_pointer",
        "symbol_pointer",
    ] {
        let m = fixture_with_layout(false, |types, symbols, _| match kind {
            "array_zero" => symbols["__per_cpu_offset"]["type"]["count"] = json!(0),
            "array_short" => symbols["__per_cpu_offset"]["type"]["count"] = json!(64),
            "array_large" => symbols["__per_cpu_offset"]["type"]["count"] = json!(8193),
            "mask_large" => types["cpumask"]["fields"]["bits"]["type"]["count"] = json!(129),
            "pointer_width" => {
                types["percpu_counter"]["fields"]["counters"]["type"]["subtype"]["name"] =
                    json!("long int")
            }
            "count_pointer" => {
                types["percpu_counter"]["fields"]["count"]["type"] =
                    json!({"kind":"pointer","subtype":{"kind":"base","name":"long int"}})
            }
            _ => symbols["vm_committed_as"]["type"]["kind"] = json!("pointer"),
        });
        let report = run(&m);
        assert!(
            metric(&report, "Committed_ASReconstructed")["value_kib"].is_null(),
            "{kind}"
        );
    }
}

#[test]
fn percpu_relocation_uses_unsigned_wrapping_but_rejects_invalid_final_addresses() {
    let mut m = fixture(false);
    let pointer = u64::MAX - 1023;
    m.u64(FBC + 40, pointer);
    m.u64(OFFSETS + 8, FIRST.wrapping_sub(pointer));
    m.u64(OFFSETS + 65 * 8, SECOND.wrapping_sub(pointer));
    assert_eq!(
        metric(&run(&m), "Committed_ASReconstructed")["value_kib"],
        4104
    );
    m.u64(OFFSETS + 8, 2048);
    assert!(metric(&run(&m), "Committed_ASReconstructed")["value_kib"].is_null());
}

#[test]
fn invalid_hugetlb_counts_orders_and_sizes_do_not_silently_reduce_the_commit_limit() {
    for kind in ["count", "order", "duplicate", "more_than_ram", "overflow"] {
        let mut m = fixture(false);
        match kind {
            "count" => m.put(HCOUNT, &3u32.to_le_bytes()),
            "order" => m.put(HSTATES + 4, &52u32.to_le_bytes()),
            "duplicate" => m.put(HSTATES + 64 + 4, &9u32.to_le_bytes()),
            "more_than_ram" => m.u64(HSTATES + 16, 20000),
            _ => m.u64(HSTATES + 16, u64::MAX),
        }
        let report = run(&m);
        assert!(
            metric(&report, "CommitLimit")["value_kib"].is_null(),
            "{kind}"
        );
        assert_eq!(
            metric(&report, "Committed_ASReconstructed")["value_kib"],
            4104
        );
    }
}

#[test]
fn single_counter_layout_is_supported_without_guessing_missing_smp_fields() {
    let mut m = fixture_with_layout(false, |types, symbols, _| {
        types["percpu_counter"] = json!({"size":8,"fields":{"count":{"offset":0,"type":{"kind":"base","name":"long int"}}}});
        symbols.as_object_mut().unwrap().remove("__cpu_online_mask");
    });
    m.u64(FBC, 7);
    let report = run(&m);
    let sum = metric(&report, "Committed_ASReconstructed");
    assert_eq!(sum["value_kib"], 28);
    assert_eq!(sum["basis"]["calculation_mode"], "single_counter_layout");
}

#[test]
fn dying_only_cpus_are_included_once_and_keep_their_mask_membership() {
    let mut m = fixture(false);
    m.u64(POSSIBLE + 8, 2 | (1u64 << 63));
    m.u64(DYING + 8, 1u64 << 63);
    let counter = BASE + 0x27000;
    m.u64(OFFSETS + 63 * 8, counter - 0x1000);
    m.put(counter, &7i32.to_le_bytes());
    let report = run(&m);
    let sum = metric(&report, "Committed_ASReconstructed");
    assert_eq!(sum["value_kib"], 4132);
    assert_eq!(sum["basis"]["included_cpu_count"], 3);
    assert!(
        report
            .records
            .iter()
            .any(|row| row["input_kind"] == "per_cpu_commit_delta"
                && row["cpu_id"] == 63
                && row["online"] == false
                && row["dying"] == true)
    );
}

#[test]
fn committed_reads_share_the_metric_budget_and_typed_cancellation() {
    let m = fixture(false);
    let trace = ReadTrace::new(&m);
    run(&trace);
    let budget = trace.bytes_through(SECOND) - 1;
    let report = run_kernel(
        &m,
        &LinuxIrOptions {
            module: "meminfo".into(),
            max_bytes: budget,
            ..Default::default()
        },
        &CancellationToken::new(),
    )
    .unwrap();
    assert!(report.records[0]["attempted_bytes"].as_u64().unwrap() <= budget);
    assert_eq!(metric(&report, "Committed_ASGlobal")["value_kib"], 4000);
    assert!(metric(&report, "Committed_ASReconstructed")["value_kib"].is_null());
    assert!(metric(&report, "MemAvailable")["value_kib"].is_u64());
    let mut cancelled = ReadTrace::new(&m);
    cancelled.cancel_at = Some(FIRST);
    let error = run_kernel(
        &cancelled,
        &LinuxIrOptions {
            module: "meminfo".into(),
            ..Default::default()
        },
        &CancellationToken::new(),
    )
    .unwrap_err();
    assert!(crate::cancellation::is_cancellation_error(&error));
}
