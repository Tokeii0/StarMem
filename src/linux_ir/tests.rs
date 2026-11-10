use super::*;
use base64::Engine;
use std::collections::BTreeMap;

mod btf;
mod file_text;
mod journal_zstd;
mod meminfo;
mod routes;

struct Memory {
    isf: LinuxIsf,
    bytes: BTreeMap<u64, u8>,
}
static FIXTURE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
impl Memory {
    fn new(types: Value, symbols: Value) -> Self {
        Self::with_enums(types, symbols, json!({}))
    }
    fn with_enums(types: Value, symbols: Value, enums: Value) -> Self {
        let path = std::env::temp_dir().join(format!(
            "starmem-ir-test-{}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            FIXTURE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut document = json!({"metadata":{"format":"6.2.0"},
            "base_types":{"long unsigned int":{"size":8},"long int":{"size":8},"unsigned int":{"size":4},"char":{"size":1}},
            "user_types":types,"enums":enums,"symbols":symbols});
        document["symbols"]["_stext"] = json!({"address": 0xffff800000001000u64});
        document["symbols"]["linux_banner"] = json!({"address":0xffff800000002000u64,
            "constant_data":base64::engine::general_purpose::STANDARD.encode(b"Linux version 6.8.0-test #1 SMP\0")});
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        let isf = crate::linux_symbols::load_linux_isf_for_features(
            &path,
            [crate::linux_symbols::LinuxSymbolFeature::IncidentResponse],
        )
        .unwrap();
        std::fs::remove_file(path).unwrap();
        Self {
            isf,
            bytes: BTreeMap::new(),
        }
    }
    fn put(&mut self, address: u64, bytes: &[u8]) {
        for (i, byte) in bytes.iter().enumerate() {
            self.bytes.insert(address + i as u64, *byte);
        }
    }
    fn u64(&mut self, address: u64, value: u64) {
        self.put(address, &value.to_le_bytes());
    }
}
impl LinuxKernelMemory for Memory {
    fn read_virtual(&self, address: u64, output: &mut [u8]) -> Result<()> {
        for (i, byte) in output.iter_mut().enumerate() {
            *byte = *self
                .bytes
                .get(&(address + i as u64))
                .context("synthetic missing byte")?;
        }
        Ok(())
    }
    fn translate(&self, address: u64) -> Result<u64> {
        ensure!(self.bytes.contains_key(&address), "synthetic missing page");
        Ok(address & 0x7fff_ffff)
    }
    fn isf(&self) -> &LinuxIsf {
        &self.isf
    }
    fn kernel_slide(&self) -> u64 {
        0
    }
    fn source_path(&self) -> Option<&std::path::Path> {
        None
    }
}
fn u64_field(offset: u64) -> Value {
    json!({"offset":offset,"type":{"kind":"base","name":"long unsigned int"}})
}

#[test]
fn entropy_excludes_missing_bytes_and_requires_evidence_for_findings() {
    assert_eq!(hunting::shannon(&[0; 256]), None);
    let mut fixed = [0; 256];
    fixed[0] = 1024;
    assert_eq!(hunting::shannon(&fixed), Some(0.0));
    assert_eq!(hunting::shannon(&[1; 256]), Some(8.0));
    assert!(
        hunting::finding_rule(
            "malfind",
            &json!({"content_status":"not_fully_checked_missing_pages"})
        )
        .is_none()
    );
    assert!(
        hunting::finding_rule(
            "entropy",
            &json!({"sample_bytes":8,"entropy_bits_per_byte":8.0})
        )
        .is_none()
    );
    assert!(
        hunting::finding_rule("psxview", &json!({"in_active_list":false,"leader":false})).is_none()
    );
    assert!(
        hunting::finding_rule("psxview", &json!({"in_active_list":false,"leader":true})).is_some()
    );
}

#[test]
fn resolver_paths_include_separate_run_mount_without_losing_path_scope() {
    assert!(files::resolver_candidate("/systemd/resolve/resolv.conf"));
    assert!(files::resolver_candidate(
        "/run/systemd/resolve/stub-resolv.conf"
    ));
    assert!(!files::resolver_candidate("/tmp/etc/resolv.conf"));
}

#[test]
fn resident_file_ranges_join_only_contiguous_verified_bytes() {
    let bytes = b"first\npartial\nfinal\n";
    let contiguous = journal::Resident::new(bytes, [(0, 3), (3, 17)]).unwrap();
    assert_eq!(contiguous.read(0, 20).unwrap(), bytes);
    let holes = journal::Resident::new(bytes, [(0, 9), (12, 8)]).unwrap();
    assert!(holes.read(8, 6).is_err());
    assert_eq!(
        journal::text_lines(&holes, 20),
        vec![(0, "first".into()), (14, "final".into())]
    );
    assert!(journal::Resident::new(bytes, [(u64::MAX, 1)]).is_err());
    assert!(journal::Resident::new(bytes, [(0, 21)]).is_err());
}

fn journal_fixture(compact: bool) -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    bytes[..8].copy_from_slice(b"LPKSHHRH");
    bytes[12] = if compact { 16 } else { 0 };
    let put = |bytes: &mut [u8], at: usize, value: u64| {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes())
    };
    put(&mut bytes, 88, 256);
    put(&mut bytes, 96, 768);
    put(&mut bytes, 152, 1);
    put(&mut bytes, 176, 256);
    bytes[256] = 6;
    put(&mut bytes, 264, if compact { 28 } else { 32 });
    put(&mut bytes, 280, 288);
    bytes[288] = 3;
    put(&mut bytes, 296, if compact { 68 } else { 80 });
    put(&mut bytes, 304, 1);
    put(&mut bytes, 312, 1_700_000_000_123_456);
    put(&mut bytes, 320, 123);
    let data = if compact { 360 } else { 368 };
    put(&mut bytes, 352, data as u64);
    if !compact {
        put(&mut bytes, 360, 42);
    }
    let payload = b"MESSAGE=Kernel panic - not syncing: test";
    let header_size = if compact { 72 } else { 64 };
    bytes[data] = 1;
    put(&mut bytes, data + 8, (header_size + payload.len()) as u64);
    put(&mut bytes, data + 16, 42);
    bytes[data + header_size..data + header_size + payload.len()].copy_from_slice(payload);
    bytes
}

#[test]
fn journal_classic_and_compact_entries_preserve_clock_and_field_ownership() {
    for compact in [false, true] {
        let bytes = journal_fixture(compact);
        let resident = journal::Resident::new(&bytes, [(0, 1024)]).unwrap();
        let options = LinuxIrOptions {
            module: "journald".into(),
            ..Default::default()
        };
        let mut report = LinuxIrReport::new(&options, "test");
        journal::parse_journal(
            &resident,
            1024,
            &json!({"dentry":42}),
            &mut 1024,
            &options,
            &CancellationToken::new(),
            &mut report,
        )
        .unwrap();
        assert!(report.complete);
        assert_eq!(report.record_count, 1);
        assert_eq!(report.records[0]["dentry"], 42);
        assert_eq!(report.records[0]["file_offset"], 288);
        assert_eq!(report.records[0]["realtime_us"], 1_700_000_000_123_456u64);
        assert_eq!(report.records[0]["fields"][0]["name"], "MESSAGE");
    }
}

#[test]
fn journal_missing_data_keeps_entry_but_never_uses_transport_zeros() {
    let bytes = journal_fixture(false);
    let resident = journal::Resident::new(&bytes, [(0, 440), (445, 579)]).unwrap();
    let options = LinuxIrOptions {
        module: "journald".into(),
        ..Default::default()
    };
    let mut report = LinuxIrReport::new(&options, "test");
    journal::parse_journal(
        &resident,
        1024,
        &json!({}),
        &mut 1024,
        &options,
        &CancellationToken::new(),
        &mut report,
    )
    .unwrap();
    assert!(!report.complete);
    assert_eq!(report.record_count, 1);
    assert_eq!(report.records[0]["fields"].as_array().unwrap().len(), 0);
    assert_eq!(
        report.records[0]["field_errors"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn journal_rejects_unknown_features_out_of_arena_objects_and_cycles() {
    let options = LinuxIrOptions {
        module: "journald".into(),
        ..Default::default()
    };
    for mutation in 0..3 {
        let mut bytes = journal_fixture(false);
        match mutation {
            0 => bytes[12] = 128,
            1 => bytes[264..272].copy_from_slice(&u64::MAX.to_le_bytes()),
            _ => {
                bytes[152..160].copy_from_slice(&2u64.to_le_bytes());
                bytes[272..280].copy_from_slice(&256u64.to_le_bytes());
            }
        }
        let resident = journal::Resident::new(&bytes, [(0, 1024)]).unwrap();
        let mut report = LinuxIrReport::new(&options, "test");
        assert!(
            journal::parse_journal(
                &resident,
                1024,
                &json!({}),
                &mut 1024,
                &options,
                &CancellationToken::new(),
                &mut report
            )
            .is_err()
        );
    }
}

#[test]
fn journal_lz4_is_bounded_and_rejects_invalid_backreferences() {
    let mut bytes = 5u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(b"\x50HELLO");
    assert_eq!(
        journal::decompress(&bytes, 2, 5, &CancellationToken::new()).unwrap(),
        b"HELLO"
    );
    assert!(journal::decompress(&bytes, 2, 4, &CancellationToken::new()).is_err());
    let mut bad = 5u64.to_le_bytes().to_vec();
    bad.extend_from_slice(&[0, 0, 0]);
    assert!(journal::decompress(&bad, 2, 1024, &CancellationToken::new()).is_err());
    assert!(journal::decompress(b"MESSAGE=hi", 0, 2, &CancellationToken::new()).is_err());
    assert!(journal::decompress(b"", 4, 1024, &CancellationToken::new()).is_err());
}

#[test]
fn journal_xz_checks_allocation_and_decoded_size_before_decompressing() {
    let bytes = base64::engine::general_purpose::STANDARD.decode("/Td6WFoAAATm1rRGAgAhARYAAAB0L+WjAQAMTUVTU0FHRT1oZWxsbwAAAAC5KRBRJJRVYQABJQ1xGcS2H7bzfQEAAAAABFla").unwrap();
    assert_eq!(
        journal::decompress(&bytes, 1, 1024, &CancellationToken::new()).unwrap(),
        b"MESSAGE=hello"
    );
    assert!(journal::decompress(&bytes, 1, 3, &CancellationToken::new()).is_err());
    let mut oversized = bytes;
    oversized[16] = 40;
    assert!(journal::decompress(&oversized, 1, 1024, &CancellationToken::new()).is_err());
}

#[test]
fn crash_rules_do_not_infer_panic_from_status_or_normal_xfs_messages() {
    assert_eq!(journal::crash_rule("kernel panic detection skipped"), None);
    assert_eq!(
        journal::crash_rule("XFS (sda): Mounting V5 Filesystem"),
        None
    );
    assert_eq!(
        journal::crash_rule("Kernel panic - not syncing: Attempted to kill init!"),
        Some("panic")
    );
}

#[test]
fn btf_probe_rejects_overlapping_or_out_of_bounds_sections() {
    let mut header = [0; 24];
    header[..3].copy_from_slice(&[0x9f, 0xeb, 1]);
    for (at, value) in [(4, 24u32), (8, 0), (12, 16), (16, 16), (20, 1)] {
        header[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    assert!(system::btf_header(&header, 41).is_ok());
    assert!(system::btf_header(&header, 40).is_err());
    header[16..20].copy_from_slice(&8u32.to_le_bytes());
    assert!(system::btf_header(&header, 41).is_err());
}

#[test]
fn uptime_uses_saved_clock_and_marks_mid_update_sequence() {
    const CORE: u64 = 0xffff800000010000;
    let mut m = Memory::new(
        json!({
            "tk_data":{"size":48,"fields":{"timekeeper":u64_field(8),"seq":u64_field(0)}},
            "timekeeper":{"size":40,"fields":{"tkr_mono":u64_field(0),"offs_boot":u64_field(24)}},
            "tk_read_base":{"size":24,"fields":{"base":u64_field(0),"shift":u64_field(8),"xtime_nsec":u64_field(16)}},
            "seqcount":{"size":8,"fields":{"sequence":u64_field(0)}}
        }),
        json!({"tk_core":{"address":CORE,"type":{"kind":"struct","name":"tk_data"}}}),
    );
    m.put(CORE, &[0; 48]);
    m.u64(CORE + 8, 100);
    m.u64(CORE + 16, 3);
    m.u64(CORE + 24, 32);
    m.u64(CORE + 32, 50);
    let options = LinuxIrOptions {
        module: "uptime".into(),
        ..Default::default()
    };
    let stable = run_kernel(&m, &options, &CancellationToken::new()).unwrap();
    assert!(stable.complete);
    assert_eq!(stable.records[0]["uptime_ns"], 154);
    m.u64(CORE, 1);
    let updating = run_kernel(&m, &options, &CancellationToken::new()).unwrap();
    assert!(updating.available);
    assert!(!updating.complete);
}

#[test]
fn physical_task_candidates_include_zombies_but_reject_bad_ids_and_exit_states() {
    let mut comm = [0; 16];
    comm[..4].copy_from_slice(b"bash");
    assert!(scan::valid_task_fields(1807, 1807, 32, &comm));
    assert!(!scan::valid_task_fields(0, 1, 0, &comm));
    assert!(!scan::valid_task_fields(1, 1, 64, &comm));
    assert!(!scan::valid_task_fields(1, 1, 0, &[b'a'; 16]));
    assert!(!scan::valid_task_fields(1, 1, 0, &[0; 16]));
}

#[test]
fn framebuffer_decodes_rgb565_and_never_publishes_missing_pixels() {
    const INFO: u64 = 0xffff800000010000;
    const PIXELS: u64 = INFO + 0x1000;
    let mut m = Memory::new(
        json!({
            "fb_info":{"size":240,"fields":{"var":u64_field(0),"fix":u64_field(160),"screen_base":u64_field(224)}},
            "fb_var_screeninfo":{"size":152,"fields":{"xres":u64_field(0),"yres":u64_field(8),
                "bits_per_pixel":u64_field(16),"xoffset":u64_field(24),"yoffset":u64_field(32),
                "red":u64_field(48),"green":u64_field(80),"blue":u64_field(112)}},
            "fb_fix_screeninfo":{"size":40,"fields":{"type":u64_field(0),"visual":u64_field(8),
                "line_length":u64_field(16),"smem_len":u64_field(24)}},
            "fb_bitfield":{"size":24,"fields":{"offset":u64_field(0),"length":u64_field(8),"msb_right":u64_field(16)}}
        }),
        json!({}),
    );
    m.put(INFO, &[0; 240]);
    m.u64(INFO, 2);
    m.u64(INFO + 8, 1);
    m.u64(INFO + 16, 16);
    m.u64(INFO + 48, 11);
    m.u64(INFO + 56, 5);
    m.u64(INFO + 80, 5);
    m.u64(INFO + 88, 6);
    m.u64(INFO + 120, 5);
    m.u64(INFO + 168, 2);
    m.u64(INFO + 176, 4);
    m.u64(INFO + 184, 4);
    m.u64(INFO + 224, PIXELS);
    m.put(PIXELS, &[0x00, 0xf8, 0xe0, 0x07]);
    let path = std::env::temp_dir().join(format!(
        "starmem-fb-{}-{}.bmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    assert_eq!(
        framebuffer::dump(&m, INFO, &path, 1024, &CancellationToken::new()).unwrap(),
        62
    );
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[..2], b"BM");
    assert_eq!(&bytes[54..], &[0, 0, 255, 255, 0, 255, 0, 255]);
    assert!(framebuffer::dump(&m, INFO, &path, 1024, &CancellationToken::new()).is_err());
    std::fs::remove_file(&path).unwrap();
    m.bytes.remove(&(PIXELS + 1));
    assert!(framebuffer::dump(&m, INFO, &path, 1024, &CancellationToken::new()).is_err());
    assert!(!path.exists());
}

#[test]
fn perf_events_keep_non_bpf_events_and_report_missing_program_pages() {
    const TASK: u64 = 0xffff800000010000;
    const EVENT: u64 = TASK + 0x100;
    const PMU: u64 = TASK + 0x200;
    let mut m = Memory::new(
        json!({
            "task_struct":{"size":32,"fields":{"perf_event_list":u64_field(0)}},
            "perf_event":{"size":32,"fields":{"owner_entry":u64_field(0),"pmu":u64_field(16),"prog":u64_field(24)}},
            "pmu":{"size":8,"fields":{"name":u64_field(0)}}
        }),
        json!({}),
    );
    m.u64(TASK, EVENT);
    m.u64(TASK + 8, EVENT);
    m.u64(EVENT, TASK);
    m.u64(EVENT + 8, TASK);
    m.u64(EVENT + 16, PMU);
    m.u64(EVENT + 24, 0);
    m.u64(PMU, PMU + 16);
    m.put(PMU + 16, b"cpu\0");
    let options = LinuxIrOptions {
        module: "perf-events".into(),
        ..Default::default()
    };
    let mut plain = LinuxIrReport::new(&options, "test");
    process::perf_events(
        &m,
        TASK,
        json!({"pid":1}),
        &options,
        &CancellationToken::new(),
        &mut plain,
    )
    .unwrap();
    assert!(plain.complete);
    assert_eq!(plain.records[0]["bpf_program"], 0);
    m.u64(EVENT + 24, PMU + 0x1000);
    let mut missing = LinuxIrReport::new(&options, "test");
    process::perf_events(
        &m,
        TASK,
        json!({"pid":1}),
        &options,
        &CancellationToken::new(),
        &mut missing,
    )
    .unwrap();
    assert!(!missing.complete);
    assert_eq!(missing.records.len(), 1);
    assert!(missing.records[0]["program_read_error"].is_string());
}

#[test]
fn unavailable_kernel_source_and_cancellation_are_not_empty_successes() {
    let m = Memory::new(json!({}), json!({}));
    let options = LinuxIrOptions {
        module: "system".into(),
        ..Default::default()
    };
    let report = run_kernel(&m, &options, &CancellationToken::new()).unwrap();
    assert!(!report.available && !report.complete && report.records.is_empty());
    assert!(!report.warnings.is_empty());
    let token = CancellationToken::new();
    token.request_cancel();
    assert!(crate::cancellation::is_cancellation_error(
        &run_kernel(&m, &options, &token).unwrap_err()
    ));
    assert!(
        run_kernel(
            &m,
            &LinuxIrOptions {
                limit: 0,
                ..options
            },
            &CancellationToken::new()
        )
        .is_err()
    );
}

#[test]
fn iomem_keeps_prior_evidence_but_marks_cycles_and_wrong_parent_partial() {
    const ROOT: u64 = 0xffff800000010000;
    const CHILD: u64 = ROOT + 0x100;
    const NAME: u64 = ROOT + 0x1000;
    let mut m = Memory::new(
        json!({"resource":{"size":56,"fields":{
        "start":u64_field(0),"end":u64_field(8),"name":u64_field(16),"flags":u64_field(24),
        "parent":u64_field(32),"sibling":u64_field(40),"child":u64_field(48)}}}),
        json!({"iomem_resource":{"address":ROOT}}),
    );
    for addr in [ROOT, CHILD] {
        m.put(addr, &[0; 56]);
        m.u64(addr + 8, 0x1000);
        m.u64(addr + 16, NAME);
    }
    m.put(NAME, b"System RAM\0");
    m.u64(ROOT + 48, CHILD);
    m.u64(CHILD + 32, ROOT);
    let options = LinuxIrOptions {
        module: "iomem".into(),
        ..Default::default()
    };
    let full = run_kernel(&m, &options, &CancellationToken::new()).unwrap();
    assert!(full.available && full.complete);
    assert_eq!(full.records.len(), 2);
    m.u64(CHILD + 48, ROOT);
    let cycle = run_kernel(&m, &options, &CancellationToken::new()).unwrap();
    assert!(cycle.available && !cycle.complete);
    assert_eq!(cycle.records.len(), 2);
    m.u64(CHILD + 48, 0);
    m.u64(CHILD + 32, CHILD);
    let corrupt = run_kernel(&m, &options, &CancellationToken::new()).unwrap();
    assert!(!corrupt.complete);
    assert_eq!(corrupt.records.len(), 1);
}

#[test]
fn idr_internal_markers_are_not_dereferenced_as_program_objects() {
    const IDR: u64 = 0xffff800000010000;
    let mut m = Memory::new(
        json!({
            "idr":{"size":16,"fields":{"idr_rt":u64_field(0)}},
            "xarray":{"size":16,"fields":{"xa_head":u64_field(8)}},
            "xa_node":{"size":24,"fields":{"shift":{"offset":0,"type":{"kind":"base","name":"char"}},
                "slots":{"offset":8,"type":{"kind":"array","count":2,"subtype":{"kind":"base","name":"long unsigned int"}}}}}
        }),
        json!({}),
    );
    m.u64(IDR + 8, 258); // XA_RETRY_ENTRY, not an xa_node or a bpf_prog
    let options = LinuxIrOptions::default();
    let mut report = LinuxIrReport::new(&options, "test");
    let result =
        kernel::idr_entries(&m, IDR, &options, &CancellationToken::new(), &mut report).unwrap();
    assert!(result.is_empty());
    assert!(!report.complete);
}

#[test]
fn permissions_and_persistence_rules_keep_unknown_bits_and_path_boundaries() {
    assert_eq!(
        process::capability_names((1u64 << 39) | (1u64 << 63)),
        ["CAP_BPF", "CAP_UNKNOWN_63"]
    );
    assert_eq!(files::persistence_rule("/tmp/etc/crontab"), None);
    assert!(files::persistence_rule("/etc/crontab").is_some());
    assert_eq!(
        files::persistence_rule("/etc/systemd/system-backup/foo"),
        None
    );
    assert!(files::persistence_rule("/etc/systemd/system/example.service").is_some());
}

#[test]
fn executable_sampling_checks_later_pages_and_does_not_treat_gaps_or_budget_as_zero() {
    let cancel = CancellationToken::new();
    let found = process::scan_nonzero(0x1000, 0x3000, &mut 8192, &cancel, |address, bytes| {
        if address == 0x2000 {
            bytes[7] = 0x90;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(found.value.unwrap().0, 0x2007);
    let limited = process::scan_nonzero(0x1000, 0x3000, &mut 4096, &cancel, |_, _| Ok(())).unwrap();
    assert!(limited.value.is_none() && limited.budget_reached);
    let missing = process::scan_nonzero(0x1000, 0x2000, &mut 4096, &cancel, |_, _| {
        anyhow::bail!("missing page")
    })
    .unwrap();
    assert_eq!(missing.missing, [(0x1000, 4096)]);
    assert!(!missing.budget_reached);
}

#[test]
fn anonymous_timekeeper_and_prel32_tracepoint_types_survive_isf_compaction() {
    const TK: u64 = 0xffff800000010000;
    let mut m = Memory::new(
        json!({
            "unnamed_tk":{"size":32,"fields":{"timekeeper":{"offset":8,"type":{"kind":"struct","name":"timekeeper"}}}},
            "timekeeper":{"size":16,"fields":{"offs_real":u64_field(0),"offs_boot":u64_field(8)}}
        }),
        json!({"tk_core":{"address":TK,"type":{"kind":"struct","name":"unnamed_tk"}},
        "__start___tracepoints_ptrs":{"address":TK+0x100,"type":{"kind":"array","count":1,"subtype":{"kind":"base","name":"unsigned int"}}}}),
    );
    m.u64(TK + 8, 1_700_000_000_000_000_000);
    m.u64(TK + 16, 7_000_000_000);
    assert_eq!(kernel::boot_time_ns(&m).unwrap(), 1_699_999_993_000_000_000);
    assert_eq!(
        m.isf()
            .symbol_array_element_size("__start___tracepoints_ptrs")
            .unwrap(),
        4
    );
}

#[test]
fn corrupt_pid_hash_bucket_does_not_discard_other_verified_tasks() {
    const NS: u64 = 0xffff800000010000;
    const HASH: u64 = NS + 0x100;
    const TABLE: u64 = NS + 0x200;
    const PID: u64 = NS + 0x1000;
    const TASK: u64 = NS + 0x2000;
    const BROKEN: u64 = NS + 0x3000;
    let mut m = Memory::new(
        json!({
            "pid_namespace":{"size":8,"fields":{}},
            "pid":{"size":56,"fields":{"level":u64_field(0),"numbers":u64_field(8),"tasks":u64_field(40)}},
            "upid":{"size":32,"fields":{"nr":u64_field(0),"ns":u64_field(8),"pid_chain":u64_field(16)}},
            "task_struct":{"size":48,"fields":{"pid":u64_field(0),"tgid":u64_field(8),"pids":u64_field(32),
                "comm":{"offset":16,"type":{"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}}}}
        }),
        json!({"init_pid_ns":{"address":NS},"pid_hash":{"address":HASH},"pidhash_shift":{"address":HASH+8}}),
    );
    m.u64(HASH, TABLE);
    m.put(HASH + 8, &1u32.to_le_bytes());
    m.u64(TABLE, PID + 24);
    m.u64(TABLE + 8, BROKEN);
    m.put(PID, &[0; 56]);
    m.u64(PID + 8, 42);
    m.u64(PID + 16, NS);
    m.u64(PID + 32, TABLE);
    m.u64(PID + 40, TASK + 32);
    m.put(TASK, &[0; 48]);
    m.u64(TASK, 42);
    m.u64(TASK + 8, 42);
    m.put(TASK + 16, b"worker\0");
    m.u64(TASK + 40, PID + 40);
    m.u64(BROKEN + 8, 0); // second bucket has an invalid pprev
    let options = LinuxIrOptions {
        module: "pidhashtable".into(),
        ..Default::default()
    };
    let report = run_kernel(&m, &options, &CancellationToken::new()).unwrap();
    assert!(report.available && !report.complete);
    assert_eq!(report.records.len(), 1);
    assert_eq!(report.records[0]["pid"], 42);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("回链"))
    );
}
