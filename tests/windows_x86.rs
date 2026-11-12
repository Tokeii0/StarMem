use std::collections::BTreeMap;
use std::fs;

use starmem::profile::{FieldProfile, KernelProfile, TypeLayout};
use starmem::session::{AnalysisSession, SessionOptions};
use starmem::system::analyze_system_info_quick;
use starmem::windows::WindowsArchitecture;

const KERNEL: u64 = 0x84a0_0000;
const HEAD: u64 = KERNEL + 0x2000;
const MODULES: u64 = KERNEL + 0x2100;
const SYSTEM: u64 = KERNEL + 0x3000;
const EXPLORER: u64 = KERNEL + 0x4000;
const DTB: u64 = 0x1020;
const GUID: &str = "12345678-1234-5678-9ABC-DEF012345678";

struct Fixture {
    bytes: Vec<u8>,
    next_table: usize,
}

impl Fixture {
    fn new() -> Self {
        Self {
            bytes: vec![0; 0x30000],
            next_table: 0x2000,
        }
    }

    fn u32(&mut self, at: usize, value: u32) {
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, at: usize, value: u64) {
        self.bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn table(&mut self, entry: usize) -> usize {
        let current = u64::from_le_bytes(self.bytes[entry..entry + 8].try_into().unwrap());
        if current != 0 {
            return (current & !0xfff) as usize;
        }
        let table = self.next_table;
        self.next_table += 0x1000;
        self.u64(entry, table as u64 | 1);
        table
    }

    fn map(&mut self, virtual_address: u64, physical: u64) {
        let pd = self.table(DTB as usize + ((virtual_address >> 30) & 3) as usize * 8);
        let pt = self.table(pd + ((virtual_address >> 21) & 511) as usize * 8);
        self.u64(
            pt + ((virtual_address >> 12) & 511) as usize * 8,
            physical | 1,
        );
    }

    fn unmap(&mut self, virtual_address: u64) {
        let pd = self.table(DTB as usize + ((virtual_address >> 30) & 3) as usize * 8);
        let pt = self.table(pd + ((virtual_address >> 21) & 511) as usize * 8);
        self.u64(pt + ((virtual_address >> 12) & 511) as usize * 8, 0);
    }

    fn windows7() -> Self {
        let mut f = Self::new();
        for i in 0..5 {
            f.map(KERNEL + i * 0x1000, 0x10000 + i * 0x1000);
        }
        f.map(0x10000, 0x15000);
        f.map(0x11000, 0x16000);
        f.map(0x12000, 0x17000);
        f.map(0xffdf_0000, 0x18000);

        // PE32 debug directory and an RSDS identity belonging to the mapped kernel.
        f.bytes[0x10000..0x10002].copy_from_slice(b"MZ");
        f.u32(0x1003c, 0x80);
        f.bytes[0x10080..0x10084].copy_from_slice(b"PE\0\0");
        f.bytes[0x10084..0x10086].copy_from_slice(&0x14cu16.to_le_bytes());
        f.bytes[0x10098..0x1009a].copy_from_slice(&0x10bu16.to_le_bytes());
        f.u32(0x10098 + 0x60 + 6 * 8, 0x300);
        f.u32(0x10098 + 0x60 + 6 * 8 + 4, 28);
        f.u32(0x10300 + 12, 2);
        f.u32(0x10300 + 16, 37);
        f.u32(0x10300 + 20, 0x400);
        f.bytes[0x10400..0x10404].copy_from_slice(b"RSDS");
        f.bytes[0x10404..0x10414].copy_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
            0x56, 0x78,
        ]);
        f.u32(0x10414, 2);
        f.bytes[0x10418..0x10425].copy_from_slice(b"ntkrpamp.pdb\0");

        f.bytes[0x11010..0x11014].copy_from_slice(b"KDBG");
        f.u32(0x11014, 0x340);
        f.u64(0x11018, KERNEL);
        f.u64(0x11048, MODULES);
        f.u64(0x11050, HEAD);
        f.u32(0x12000, (SYSTEM + 0xb8) as u32);
        f.u32(0x12004, (EXPLORER + 0xb8) as u32);
        f.u32(0x12100, (MODULES + 0x20) as u32);
        f.u32(0x12104, (MODULES + 0x20) as u32);
        f.u32(0x12120, MODULES as u32);
        f.u32(0x12124, MODULES as u32);

        for (physical, pid, ppid, name, previous, next) in [
            (0x13000, 4, 0, "System", HEAD, EXPLORER + 0xb8),
            (0x14000, 100, 4, "explorer.exe", SYSTEM + 0xb8, HEAD),
        ] {
            f.u32(physical + 0x18, DTB as u32);
            f.u32(physical + 0xb4, pid);
            f.u32(physical + 0xb8, next as u32);
            f.u32(physical + 0xbc, previous as u32);
            f.u32(physical + 0x140, ppid);
            f.bytes[physical + 0x16c..physical + 0x16c + name.len()]
                .copy_from_slice(name.as_bytes());
        }
        f.u32(0x141a8, 0x10000);
        f.u32(0x15008, 0x400000);
        f.u32(0x15010, 0x11000);
        f.u32(0x150a4, 6);
        f.u32(0x150a8, 1);
        f.bytes[0x150ac..0x150ae].copy_from_slice(&7601u16.to_le_bytes());
        f.u32(0x151d4, 1);
        let command = "C:\\Windows\\explorer.exe"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        f.bytes[0x16040..0x16042].copy_from_slice(&(command.len() as u16).to_le_bytes());
        f.bytes[0x16042..0x16044].copy_from_slice(&(command.len() as u16).to_le_bytes());
        f.u32(0x16044, 0x12000);
        f.bytes[0x17000..0x17000 + command.len()].copy_from_slice(&command);
        f.u32(0x1826c, 6);
        f.u32(0x18270, 1);
        f.u64(0x18014, 116_444_736_000_000_000);
        f.u32(0x1801c, (116_444_736_000_000_000u64 >> 32) as u32);
        f
    }
}

fn layout(fields: &[(&str, u64, u64)]) -> TypeLayout {
    TypeLayout {
        size: 0x400,
        fields: fields
            .iter()
            .map(|(name, offset, size)| {
                (
                    (*name).to_owned(),
                    FieldProfile {
                        offset: *offset,
                        size: Some(*size),
                        bit_position: None,
                        bit_length: None,
                    },
                )
            })
            .collect(),
    }
}

fn win7_profile() -> KernelProfile {
    let eprocess = layout(&[
        ("Pcb", 0, 0),
        ("UniqueProcessId", 0xb4, 4),
        ("ActiveProcessLinks", 0xb8, 0),
        ("ImageFileName", 0x16c, 15),
        ("InheritedFromUniqueProcessId", 0x140, 4),
        ("Peb", 0x1a8, 4),
    ]);
    KernelProfile {
        schema_version: 3,
        pdb_guid: GUID.to_owned(),
        pdb_age: 2,
        type_name: "_EPROCESS".to_owned(),
        type_size: 0x2c0,
        fields: eprocess.fields.clone(),
        types: BTreeMap::from([
            ("_EPROCESS".to_owned(), eprocess),
            (
                "_KPROCESS".to_owned(),
                layout(&[("DirectoryTableBase", 0x18, 4)]),
            ),
            (
                "_KUSER_SHARED_DATA".to_owned(),
                layout(&[
                    ("NtMajorVersion", 0x26c, 4),
                    ("NtMinorVersion", 0x270, 4),
                    ("SystemTime", 0x14, 12),
                    ("InterruptTime", 8, 12),
                    ("TimeZoneBias", 0x20, 12),
                ]),
            ),
        ]),
        symbols: BTreeMap::from([
            ("PsActiveProcessHead".to_owned(), 0x2000),
            ("PsLoadedModuleList".to_owned(), 0x2100),
        ]),
    }
}

fn open_fixture(
    fixture: Fixture,
    profile: KernelProfile,
) -> anyhow::Result<(AnalysisSession, tempfile::TempDir)> {
    let directory = tempfile::tempdir()?;
    let image = directory.path().join("win7-x86.raw");
    let profile_path = directory.path().join("win7-x86.json");
    fs::write(&image, fixture.bytes)?;
    fs::write(&profile_path, serde_json::to_vec(&profile)?)?;
    let session = AnalysisSession::open(
        image,
        SessionOptions {
            profile: Some(profile_path),
            ..SessionOptions::default()
        },
    )?;
    Ok((session, directory))
}

#[test]
fn win7_x86_pae_bootstraps_and_reads_processes_and_shared_data() {
    let (session, _directory) = open_fixture(Fixture::windows7(), win7_profile()).unwrap();
    assert_eq!(session.kernel().architecture, WindowsArchitecture::X86Pae);
    assert_eq!(session.kernel().directory_table_base, DTB);
    assert_eq!(session.kernel().kernel_base, KERNEL);
    let processes = session.processes(16).unwrap();
    assert!(processes.complete);
    assert!(processes.warnings.is_empty());
    assert_eq!(
        processes
            .processes
            .iter()
            .map(|p| (p.pid, p.name.as_str()))
            .collect::<Vec<_>>(),
        [(4, "System"), (100, "explorer.exe")]
    );
    assert_eq!(
        processes.processes[1].details.command_line.as_deref(),
        Some("C:\\Windows\\explorer.exe")
    );
    let info = analyze_system_info_quick(&session, 16).unwrap();
    let info = serde_json::to_value(info).unwrap();
    assert_eq!(info["kernel"]["architecture"], "x86_pae");
    assert!(info.to_string().contains("6.1.7601"));
    assert!(info.to_string().contains("1970-01-01T00:00:00.000Z"));
}

#[test]
fn win7_x86_pae_rejects_a_different_mapped_kernel_identity() {
    for (guid, age) in [("00000000-0000-0000-0000-000000000000", 2), (GUID, 3)] {
        let mut profile = win7_profile();
        profile.pdb_guid = guid.to_owned();
        profile.pdb_age = age;
        let error = open_fixture(Fixture::windows7(), profile)
            .err()
            .expect("mismatched identity must fail");
        assert!(error.to_string().contains("exact kernel CodeView identity"));
    }
}

#[test]
fn win7_x86_pae_preserves_an_incomplete_process_list() {
    let mut fixture = Fixture::windows7();
    fixture.u32(0x140bc, HEAD as u32);
    let (session, _directory) = open_fixture(fixture, win7_profile()).unwrap();
    let report = session.processes(16).unwrap();
    assert_eq!(report.processes.len(), 2);
    assert!(!report.complete);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.kind == "blink_mismatch")
    );
}

#[test]
fn x86_environment_without_size_requires_resident_double_terminator() {
    let environment = "COMPUTERNAME=TEST-PC\0USERNAME=Alice\0\0";
    let encoded: Vec<u8> = environment
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut fixture = Fixture::windows7();
    fixture.map(0x13000, 0x19000);
    fixture.map(0x14000, 0x1a000);
    // The terminator crosses the page boundary, exercising page-sized reads.
    let start = 0x14000 - (encoded.len() as u64 - 2);
    fixture.u32(0x16048, start as u32);
    let physical = 0x19000 + (start as usize & 4095);
    fixture.bytes[physical..physical + encoded.len()].copy_from_slice(&encoded);
    let (session, _dir) = open_fixture(fixture, win7_profile()).unwrap();
    let processes = session.processes(16).unwrap();
    let details = &processes.processes[1].details;
    assert_eq!(
        details.environment_computer_name.as_deref(),
        Some("TEST-PC")
    );
    assert_eq!(details.environment_user_name.as_deref(), Some("Alice"));
    assert_eq!(details.environment_variable_count, Some(2));
    assert_eq!(details.environment_size, None); // no invented RTL size

    let mut missing = Fixture::windows7();
    missing.map(0x13000, 0x19000);
    missing.u32(0x16048, start as u32);
    missing.bytes[physical..physical + encoded.len() - 2]
        .copy_from_slice(&encoded[..encoded.len() - 2]);
    let (session, _dir) = open_fixture(missing, win7_profile()).unwrap();
    let processes = session.processes(16).unwrap();
    let details = &processes.processes[1].details;
    assert_eq!(details.environment_address, Some(start));
    assert_eq!(details.environment_variable_count, None);
    assert!(details.environment_variables.is_empty());
    let report = starmem::windows::process_plugins::environment_variables(
        session.image(),
        session.kernel(),
        session.profile(),
        16,
    )
    .unwrap();
    assert!(!report.complete);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("环境块"))
    );
}

#[test]
fn win7_x86_pae_reports_unsupported_object_scans_instead_of_empty_evidence() {
    let (session, _directory) = open_fixture(Fixture::windows7(), win7_profile()).unwrap();
    assert!(
        session
            .files(16)
            .unwrap_err()
            .to_string()
            .contains("_FILE_OBJECT")
    );
    for error in [
        session.network(16).unwrap_err(),
        session.drivers(16).unwrap_err(),
        session.hives(16).unwrap_err(),
        session.vads(100, 16).unwrap_err(),
    ] {
        assert!(error.to_string().contains("尚未支持 Windows x86 PAE"));
    }
}

fn browser_file_fixture(payload: &[u8], base: &str) -> (Fixture, KernelProfile, u64) {
    let mut fixture = Fixture::windows7();
    fixture.bytes.resize(0x50000, 0);
    let object = KERNEL + 0x10020;
    for page in 0..8u64 {
        fixture.map(KERNEL + 0x10000 + page * 4096, 0x20000 + page * 4096);
    }
    for page in 0..(payload.len() as u64).div_ceil(4096) {
        fixture.map(0x8500_0000 + page * 4096, 0x30000 + page * 4096);
    }
    fixture.bytes[0x20002] = 32; // 32 eight-byte x86 pool blocks.
    fixture.bytes[0x20004..0x20008].copy_from_slice(b"File");
    fixture.bytes[0x2000c] = 28;
    fixture.bytes[0x20020..0x20022].copy_from_slice(&5u16.to_le_bytes());
    fixture.bytes[0x20022..0x20024].copy_from_slice(&128u16.to_le_bytes());
    fixture.u32(0x20024, (KERNEL + 0x14080) as u32); // DeviceObject
    fixture.u32(0x20028, (KERNEL + 0x11000) as u32); // SectionObjectPointer
    let name = format!(r"\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\{base}");
    let utf16: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    fixture.bytes[0x20050..0x20052].copy_from_slice(&(utf16.len() as u16).to_le_bytes());
    fixture.bytes[0x20052..0x20054].copy_from_slice(&(utf16.len() as u16).to_le_bytes());
    fixture.u32(0x20054, (KERNEL + 0x14000) as u32); // 32-bit UNICODE_STRING Buffer at +4.
    fixture.bytes[0x24000..0x24000 + utf16.len()].copy_from_slice(&utf16);
    fixture.u32(0x21000, (KERNEL + 0x15000) as u32); // DataSectionObject
    fixture.u32(0x21004, (KERNEL + 0x12000) as u32); // SharedCacheMap
    fixture.u64(0x22008, payload.len() as u64);
    fixture.u32(0x22010, (KERNEL + 0x13000) as u32); // inline InitialVacbs[0]
    fixture.u32(0x22020, (KERNEL + 0x12010) as u32); // Vacbs points to inline array
    fixture.u32(0x23000, 0x8500_0000); // VACB BaseAddress
    fixture.u32(0x23004, (KERNEL + 0x12000) as u32); // adjacent 32-bit owner pointer
    fixture.u64(0x23008, 0); // 64-bit file offset
    fixture.u32(0x25000, (KERNEL + 0x16000) as u32); // CONTROL_AREA Segment
    fixture.u32(0x26000, (KERNEL + 0x15000) as u32); // SEGMENT ControlArea
    fixture.u32(0x26008, (payload.len() as u32).div_ceil(4096));
    fixture.u64(0x26010, payload.len() as u64); // segment size remains LARGE_INTEGER
    fixture.u32(0x25020, (KERNEL + 0x15000) as u32); // SUBSECTION owner
    fixture.u32(0x25024, (KERNEL + 0x17000) as u32); // prototype PTE array
    fixture.u32(0x2502c, (payload.len() as u32).div_ceil(4096));
    for page in 0..payload.len().div_ceil(4096) {
        fixture.u64(0x27000 + page * 8, (0x30000 + page * 4096) as u64 | 1);
    }
    fixture.bytes[0x30000..0x30000 + payload.len()].copy_from_slice(payload);
    let mut profile = win7_profile();
    for (name, size, fields) in [
        (
            "_FILE_OBJECT",
            128,
            vec![
                ("Type", 0, 2),
                ("Size", 2, 2),
                ("DeviceObject", 4, 4),
                ("SectionObjectPointer", 8, 4),
                ("FileName", 0x30, 8),
                ("Flags", 0x40, 4),
                ("DeletePending", 0x44, 1),
            ],
        ),
        (
            "_OBJECT_HEADER",
            0x18,
            vec![("TypeIndex", 4, 1), ("Body", 0x18, 0)],
        ),
        ("_OBJECT_TYPE", 8, vec![("Name", 0, 8)]),
        (
            "_SECTION_OBJECT_POINTERS",
            12,
            vec![
                ("DataSectionObject", 0, 4),
                ("SharedCacheMap", 4, 4),
                ("ImageSectionObject", 8, 4),
            ],
        ),
        (
            "_SHARED_CACHE_MAP",
            0x30,
            vec![
                ("FileSize", 8, 8),
                ("InitialVacbs", 0x10, 16),
                ("Vacbs", 0x20, 4),
            ],
        ),
        (
            "_VACB",
            16,
            vec![
                ("BaseAddress", 0, 4),
                ("SharedCacheMap", 4, 4),
                ("Overlay", 8, 8),
            ],
        ),
        ("_CONTROL_AREA", 0x20, vec![("Segment", 0, 4)]),
        (
            "_SEGMENT",
            0x20,
            vec![
                ("ControlArea", 0, 4),
                ("TotalNumberOfPtes", 8, 4),
                ("SizeOfSegment", 0x10, 8),
            ],
        ),
        (
            "_SUBSECTION",
            0x20,
            vec![
                ("ControlArea", 0, 4),
                ("SubsectionBase", 4, 4),
                ("NextSubsection", 8, 4),
                ("PtesInSubsection", 12, 4),
                ("StartingSector", 16, 4),
            ],
        ),
    ] {
        let mut typ = layout(&fields);
        typ.size = size;
        profile.types.insert(name.to_owned(), typ);
    }
    (fixture, profile, object)
}

#[test]
fn win7_x86_browser_file_scan_cache_and_pae_data_recovery_keep_byte_identity() {
    use starmem::windows::files::{DumpSource, recover_file_bytes};
    let payload = b"{".repeat(8200);
    let (fixture, profile, object) = browser_file_fixture(&payload, "History");
    let (session, _dir) = open_fixture(fixture, profile).unwrap();
    let files = session.files(16).unwrap();
    assert!(files.complete, "{:?}", files.warnings);
    assert_eq!(files.records.len(), 1);
    assert_eq!(files.records[0].file_object, object);
    assert!(
        files.records[0]
            .name
            .as_deref()
            .unwrap()
            .ends_with("\\History")
    );
    for source in [DumpSource::Cache, DumpSource::Data] {
        let (report, bytes) = recover_file_bytes(
            session.image(),
            session.kernel(),
            session.profile(),
            object,
            source,
            65536,
        )
        .unwrap();
        assert!(report.complete, "{:?}", report.warnings);
        assert_eq!(bytes, payload);
        assert_eq!(report.file_object, object);
        assert_eq!(report.recovered_bytes, 8200);
    }
    let targets = std::collections::HashSet::from([0x20000]);
    let mappings = session
        .kernel()
        .address_space(session.image())
        .unwrap()
        .reverse_translate_kernel_pages(&targets, 4)
        .unwrap();
    assert!(mappings[&0x20000].contains(&(object & !0xfff)));
}

#[test]
fn file_auto_recovery_uses_complete_data_after_partial_cache() {
    use starmem::windows::files::{DumpSource, recover_file_bytes};
    let payload: Vec<u8> = (0..8200).map(|index| (index % 251) as u8).collect();
    let (mut fixture, profile, object) = browser_file_fixture(&payload, "guess.jpg");
    fixture.unmap(0x8500_0000); // Cache loses the header, but data-section PTEs still map it.
    let (session, dir) = open_fixture(fixture, profile).unwrap();
    let (cache, _) = recover_file_bytes(
        session.image(),
        session.kernel(),
        session.profile(),
        object,
        DumpSource::Cache,
        65536,
    )
    .unwrap();
    assert!(!cache.complete);
    assert_eq!(cache.missing_bytes, 4096);

    let output = dir.path().join("guess.jpg");
    let report = session
        .recover_file(object, &output, DumpSource::Auto, 65536, false)
        .unwrap();
    assert_eq!(report.source, DumpSource::Data);
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(report.file_object, object);
    assert_eq!(report.recovered_bytes, payload.len() as u64);
    assert_eq!(report.missing_bytes, 0);
    assert_eq!(fs::read(output).unwrap(), payload);
}

#[test]
fn file_auto_recovery_retains_the_best_partial_source_without_mixing_bytes() {
    use starmem::windows::files::{DumpSource, recover_file_bytes};
    let payload: Vec<u8> = (0..8200).map(|index| (index % 251) as u8).collect();
    for (cache_pages, data_mask, expected_source, expected_pages) in [
        (2, 0b001, DumpSource::Cache, 2),
        (1, 0b011, DumpSource::Data, 2),
        (2, 0b000, DumpSource::Cache, 2),
        (2, 0b011, DumpSource::Cache, 2),
        (2, 0b100, DumpSource::Cache, 2), // A worse, sparse tail must not extend the winner.
    ] {
        let (mut fixture, profile, object) = browser_file_fixture(&payload, "partial.bin");
        // Use distinct bytes for the two views, so a stale or mixed output fails the test.
        fixture.bytes[0x40000..0x40000 + payload.len()].fill(0xa5);
        for page in 0..3 {
            if page < cache_pages {
                fixture.map(0x8500_0000 + page * 4096, 0x40000 + page * 4096);
            } else {
                fixture.unmap(0x8500_0000 + page * 4096);
            }
            if data_mask & (1 << page) == 0 {
                fixture.u64(0x27000 + page as usize * 8, 0);
            }
        }
        let (session, _dir) = open_fixture(fixture, profile).unwrap();
        let (report, bytes) = recover_file_bytes(
            session.image(),
            session.kernel(),
            session.profile(),
            object,
            DumpSource::Auto,
            65536,
        )
        .unwrap();
        assert_eq!(report.source, expected_source);
        assert!(!report.complete);
        let length = expected_pages * 4096;
        assert_eq!(report.recovered_bytes, length as u64);
        assert_eq!(report.output_size, length as u64);
        assert_eq!(report.missing_bytes, (payload.len() - length) as u64);
        if expected_source == DumpSource::Cache {
            assert_eq!(bytes, vec![0xa5; length]);
        } else {
            assert_eq!(bytes, payload[..length]);
        }
    }
}

#[test]
fn file_auto_recovery_only_uses_image_when_no_file_layout_source_is_readable() {
    use starmem::windows::files::{DumpSource, recover_file_bytes};
    let payload = vec![0x5a; 8200];
    for cache_pages in [0, 2, 3] {
        let (mut fixture, profile, object) = browser_file_fixture(&payload, "mapped.bin");
        fixture.u32(0x21000, 0); // No data control area; the image view remains complete.
        fixture.u32(0x21008, (KERNEL + 0x15000) as u32);
        for page in cache_pages..3 {
            fixture.unmap(0x8500_0000 + page * 4096);
        }
        let (session, _dir) = open_fixture(fixture, profile).unwrap();
        let (report, bytes) = recover_file_bytes(
            session.image(),
            session.kernel(),
            session.profile(),
            object,
            DumpSource::Auto,
            65536,
        )
        .unwrap();
        assert_eq!(
            report.source,
            if cache_pages == 0 {
                DumpSource::Image
            } else {
                DumpSource::Cache
            }
        );
        let length = if cache_pages == 2 {
            8192
        } else {
            payload.len()
        };
        assert_eq!(report.complete, cache_pages != 2);
        assert_eq!(bytes, payload[..length]);
    }
}

#[test]
fn image_subsections_use_sector_offsets_and_preserve_plain_next_pointers() {
    use starmem::windows::files::{DumpSource, recover_file_bytes};
    let payload: Vec<u8> = (0..12288).map(|index| (index / 4096 + 1) as u8).collect();
    for source in [DumpSource::Data, DumpSource::Image] {
        let (mut fixture, profile, object) = browser_file_fixture(&payload, "mapped.dll");
        fixture.u32(0x21008, (KERNEL + 0x15000) as u32);
        fixture.u32(0x25028, (KERNEL + 0x15044) as u32); // Plain pointer, only 4-byte aligned.
        fixture.u32(0x2502c, 1); // First subsection has one page.
        fixture.u32(0x25044, (KERNEL + 0x15000) as u32);
        fixture.u32(0x25048, (KERNEL + 0x17008) as u32);
        fixture.u32(0x2504c, 0);
        fixture.u32(0x25050, 2);
        fixture.u32(0x25054, if source == DumpSource::Image { 2 } else { 1 });
        let (session, _dir) = open_fixture(fixture, profile).unwrap();
        let (report, bytes) = recover_file_bytes(
            session.image(),
            session.kernel(),
            session.profile(),
            object,
            source,
            65536,
        )
        .unwrap();
        if source == DumpSource::Image {
            assert_eq!(bytes.len(), 9216);
            assert_eq!(&bytes[..1024], &payload[..1024]);
            assert_eq!(&bytes[1024..], &payload[4096..]);
            assert_eq!(report.recovered_bytes, 9216);
            assert_eq!(report.missing_bytes, 3072);
            assert!(!report.complete);
            assert!(
                report
                    .extents
                    .windows(2)
                    .all(|pair| pair[0].file_offset + pair[0].length <= pair[1].file_offset)
            );
        } else {
            assert_eq!(bytes, payload);
            assert!(report.complete);
        }
    }
}

#[test]
fn legacy_object_header_resolves_direct_type_pointer_and_rejects_other_types() {
    let (mut fixture, mut profile, object) = browser_file_fixture(b"resident", "test.txt");
    profile.types.insert(
        "_OBJECT_HEADER".to_owned(),
        layout(&[("Type", 4, 4), ("Body", 0x18, 0)]),
    );
    fixture.u32(0x2000c, (KERNEL + 0x18000) as u32);
    fixture.map(KERNEL + 0x18000, 0x28000);
    fixture.map(KERNEL + 0x19000, 0x29000);
    fixture.bytes[0x28000..0x28002].copy_from_slice(&8u16.to_le_bytes());
    fixture.bytes[0x28002..0x28004].copy_from_slice(&8u16.to_le_bytes());
    fixture.u32(0x28004, (KERNEL + 0x19000) as u32);
    let file_name: Vec<u8> = "File".encode_utf16().flat_map(u16::to_le_bytes).collect();
    fixture.bytes[0x29000..0x29008].copy_from_slice(&file_name);
    let (session, _dir) = open_fixture(fixture, profile).unwrap();
    let report = session.files(16).unwrap();
    assert_eq!(report.records.len(), 1);
    assert_eq!(report.records[0].file_object, object);
    assert!(report.records[0].object_type_verified);

    let (mut fixture, mut profile, _) = browser_file_fixture(b"resident", "test.txt");
    profile.types.insert(
        "_OBJECT_HEADER".to_owned(),
        layout(&[("Type", 4, 4), ("Body", 0x18, 0)]),
    );
    fixture.u32(0x2000c, (KERNEL + 0x18000) as u32);
    fixture.map(KERNEL + 0x18000, 0x28000);
    fixture.map(KERNEL + 0x19000, 0x29000);
    fixture.bytes[0x28000..0x28002].copy_from_slice(&8u16.to_le_bytes());
    fixture.bytes[0x28002..0x28004].copy_from_slice(&8u16.to_le_bytes());
    fixture.u32(0x28004, (KERNEL + 0x19000) as u32);
    let other: Vec<u8> = "Evil".encode_utf16().flat_map(u16::to_le_bytes).collect();
    fixture.bytes[0x29000..0x29008].copy_from_slice(&other);
    let (session, _dir) = open_fixture(fixture, profile).unwrap();
    assert!(session.files(16).unwrap().records.is_empty());
}

fn legacy_console_fixture() -> Fixture {
    let mut fixture = Fixture::windows7();
    fixture.bytes[0x1416c..0x1416c + 15].fill(0);
    fixture.bytes[0x1416c..0x1416c + 9].copy_from_slice(b"csrss.exe");
    let history = 0x11080u32;
    fixture.u32(0x16080, 1);
    fixture.u32(0x1608c, 0x12080);
    for (offset, value) in [(0x90, 2i16), (0x92, 1), (0x94, 1), (0x96, 0), (0x98, 50)] {
        fixture.bytes[0x16000 + offset..0x16000 + offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fixture.u32(0x1609c, 0x44);
    fixture.u32(0x160a0, history + 0x20);
    fixture.u32(0x160a4, history + 0x20);
    fixture.u32(0x160a8, 0x12100);
    fixture.u32(0x160ac, 0x12200);
    let app: Vec<u8> = "cmd.exe\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    fixture.bytes[0x17080..0x17080 + app.len()].copy_from_slice(&app);
    for (at, text) in [(0x17100, "echo 测试"), (0x17200, "tool.exe alpha")] {
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        fixture.bytes[at..at + 2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        fixture.bytes[at + 2..at + 2 + bytes.len()].copy_from_slice(&bytes);
    }
    fixture
}

#[test]
fn x86_winsrv_history_validates_pointers_and_list_backlinks() {
    let (session, _dir) = open_fixture(legacy_console_fixture(), win7_profile()).unwrap();
    let report = session.command_histories(16).unwrap();
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(report.records.len(), 1);
    assert_eq!(report.records[0].conhost, "csrss.exe");
    assert_eq!(report.records[0].application.as_deref(), Some("cmd.exe"));
    assert_eq!(
        report.records[0]
            .commands
            .iter()
            .map(|c| c.text.as_str())
            .collect::<Vec<_>>(),
        ["echo 测试", "tool.exe alpha"]
    );
    let mappings = starmem::address::X86PaeAddressSpace::new(session.image(), DTB)
        .unwrap()
        .enumerate_mappings(starmem::address::VirtualAddressRegion::User, 16)
        .unwrap();
    assert!(!mappings.truncated);
    assert_eq!(mappings.mapped_bytes, 0x3000);

    let mut corrupt = legacy_console_fixture();
    corrupt.u32(0x160a4, 0x11084); // invalid popup backlink
    let (session, _dir) = open_fixture(corrupt, win7_profile()).unwrap();
    assert!(session.command_histories(16).unwrap().records.is_empty());
    let handle = starmem::cancellation::CancellationHandle::new();
    handle.cancel();
    assert!(starmem::cancellation::is_cancellation_error(
        &session
            .command_histories_cancellable(16, &handle.token())
            .unwrap_err()
    ));
}

#[test]
fn win7_x86_browser_history_runs_through_file_recovery_and_schema_parser() {
    use starmem::browser_artifacts::{
        BrowserArtifactOptions, parse_browser_history_artifacts_from_file_scan,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("History");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,typed_count INTEGER,last_visit_time INTEGER,hidden INTEGER); CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER,from_visit INTEGER,transition INTEGER); INSERT INTO urls VALUES(1,'https://example.test/win7','Win7',1,1,13348540800000000,0); INSERT INTO visits VALUES(1,1,13348540800000000,0,1);").unwrap();
    drop(db);
    let payload = fs::read(path).unwrap();
    let (fixture, profile, object) = browser_file_fixture(&payload, "History");
    let (session, _dir) = open_fixture(fixture, profile).unwrap();
    let report = parse_browser_history_artifacts_from_file_scan(
        session.image(),
        session.kernel(),
        session.profile(),
        session.files(16).unwrap(),
        &BrowserArtifactOptions {
            result_limit: 16,
            database_limit: 4,
            max_database_size: 65536,
        },
        None,
    )
    .unwrap();
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(report.visit_history.len(), 1);
    assert_eq!(report.visit_events.len(), 1);
    assert_eq!(report.visit_history[0].file_object, object);
    assert_eq!(
        report.visit_history[0].last_visit_time.as_deref(),
        Some("2024-01-01T00:00:00+00:00")
    );
    assert_eq!(report.database_sources.len(), 2);
    assert_eq!(
        report
            .database_sources
            .iter()
            .filter(|s| s.selected)
            .count(),
        1
    );
}

#[test]
fn win7_x86_browser_session_preserves_firefox_accounts_with_mapping_limitations() {
    use starmem::browser_session::BrowserSessionOptions;
    use starmem::cookies::CookieScanOptions;
    let payload = br#"{"version":3,"logins":[{"id":1,"hostname":"https://example.test","encryptedUsername":"cipher-user","encryptedPassword":"cipher-pass"}]}"#;
    let (fixture, profile, _) = browser_file_fixture(payload, "logins.json");
    let (session, _dir) = open_fixture(fixture, profile).unwrap();
    let report = session
        .browser_sessions(
            &BrowserSessionOptions {
                session_limit: 16,
                download_limit: 16,
                cookie: CookieScanOptions {
                    limit: 16,
                    database_limit: 4,
                    file_scan_limit: 16,
                    max_database_size: 65536,
                    process_space_limit: 4,
                },
            },
            |_| {},
        )
        .unwrap();
    assert_eq!(report.login_accounts.len(), 1);
    assert_eq!(report.login_accounts[0].browser, "Firefox");
    assert_eq!(
        report.login_accounts[0].username_kind,
        "encrypted_unavailable"
    );
    assert!(!report.complete);
    assert!(report.warnings.iter().any(|w| w.contains("x86 PAE")));
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("cipher-pass")
    );
}

#[test]
fn win7_x86_pae_dumps_process_executable_and_process_memory() {
    let mut fixture = Fixture::windows7();
    fixture.bytes.resize(0x30000, 0);
    fixture.map(0x40_0000, 0x20000);
    fixture.map(0x40_1000, 0x21000);
    fixture.bytes[0x20000..0x20002].copy_from_slice(b"MZ");
    fixture.u32(0x2003c, 0x80);
    fixture.bytes[0x20080..0x20084].copy_from_slice(b"PE\0\0");
    fixture.bytes[0x20084..0x20086].copy_from_slice(&0x14cu16.to_le_bytes());
    fixture.bytes[0x20086..0x20088].copy_from_slice(&1u16.to_le_bytes());
    fixture.bytes[0x20094..0x20096].copy_from_slice(&0xe0u16.to_le_bytes());
    fixture.bytes[0x20098..0x2009a].copy_from_slice(&0x10bu16.to_le_bytes());
    fixture.u32(0x20098 + 56, 0x2000);
    fixture.u32(0x20098 + 60, 0x200);
    let sec = 0x20098 + 0xe0;
    fixture.bytes[sec..sec + 5].copy_from_slice(b".text");
    fixture.u32(sec + 8, 0x10);
    fixture.u32(sec + 12, 0x1000);
    fixture.u32(sec + 16, 0x200);
    fixture.u32(sec + 20, 0x200);
    fixture.bytes[0x21000..0x21004].copy_from_slice(&[0x55, 0x8b, 0xec, 0xc3]);

    let (session, dir) = open_fixture(fixture, win7_profile()).unwrap();
    let exe_out = dir.path().join("explorer.exe");
    let report = session
        .dump_process_executable(100, &exe_out, false, 1024 * 1024)
        .unwrap();
    assert!(report.complete, "{:?}", report.warnings);
    assert_eq!(report.base, 0x40_0000);
    assert_eq!(report.recovered_bytes, 0x400);
    let exe = fs::read(&exe_out).unwrap();
    assert_eq!(&exe[..2], b"MZ");
    assert_eq!(&exe[0x200..0x204], &[0x55, 0x8b, 0xec, 0xc3]);

    let mem_out = dir.path().join("explorer.raw");
    let mem = session
        .dump_process_memory(100, &mem_out, 1024 * 1024)
        .unwrap();
    assert!(mem.complete, "{:?}", mem.warnings);
    assert!(mem.recovered_bytes >= 0x2000);
}
