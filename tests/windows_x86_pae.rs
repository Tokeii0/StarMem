use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use starmem::image::MemoryImage;
use starmem::profile::{FieldProfile, KernelProfile, TypeLayout};
use starmem::windows::{WindowsArchitecture, WindowsKernelContext, list_processes};

const BASE: u32 = 0x8000_0000;
const GUID: &str = "12345678-9ABC-DEF0-0102-030405060708";

struct Fixture(PathBuf);

impl Fixture {
    fn new(pe_magic: u16) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-win7-pae-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0u8; 0x8000];
        // A 32-byte-aligned CR3, not a page-aligned x64 PML4.
        put64(&mut bytes, 0x1020 + 2 * 8, 0x2001);
        put64(&mut bytes, 0x2000, 0x3001);
        for (index, physical) in [0x4001, 0x5001, 0x6001].into_iter().enumerate() {
            put64(&mut bytes, 0x3000 + index * 8, physical);
        }
        // PE32 kernel with a mapped CodeView record.
        bytes[0x4000..0x4002].copy_from_slice(b"MZ");
        put32(&mut bytes, 0x403c, 0x80);
        bytes[0x4080..0x4084].copy_from_slice(b"PE\0\0");
        bytes[0x4098..0x409a].copy_from_slice(&pe_magic.to_le_bytes());
        put32(&mut bytes, 0x4098 + 0x60 + 6 * 8, 0x300);
        put32(&mut bytes, 0x4098 + 0x60 + 6 * 8 + 4, 28);
        put32(&mut bytes, 0x4300 + 12, 2);
        put32(&mut bytes, 0x4300 + 16, 37);
        put32(&mut bytes, 0x4300 + 20, 0x400);
        bytes[0x4400..0x4404].copy_from_slice(b"RSDS");
        bytes[0x4404..0x4414].copy_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8,
        ]);
        put32(&mut bytes, 0x4414, 2);
        bytes[0x4418..0x4424].copy_from_slice(b"ntkrpamp.pdb");
        // Decoded KDBG and a one-process, circular active list.
        bytes[0x7010..0x7014].copy_from_slice(b"KDBG");
        put32(&mut bytes, 0x7014, 0x100);
        put32(&mut bytes, 0x7018, BASE);
        put32(&mut bytes, 0x7048, BASE + 0x1000);
        put32(&mut bytes, 0x7050, BASE + 0x1100);
        put32(&mut bytes, 0x5000, BASE + 0x1200);
        put32(&mut bytes, 0x5100, BASE + 0x2030);
        put32(&mut bytes, 0x5104, BASE + 0x2030);
        put32(&mut bytes, 0x6018, 0x1020);
        put32(&mut bytes, 0x6020, 4);
        put32(&mut bytes, 0x6030, BASE + 0x1100);
        put32(&mut bytes, 0x6034, BASE + 0x1100);
        bytes[0x6050..0x6057].copy_from_slice(b"System\0");
        fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn field(offset: u64, size: u64) -> FieldProfile {
    FieldProfile {
        offset,
        size: Some(size),
        bit_position: None,
        bit_length: None,
    }
}

fn profile() -> KernelProfile {
    KernelProfile {
        schema_version: 3,
        pdb_guid: GUID.to_owned(),
        pdb_age: 2,
        type_name: "_EPROCESS".to_owned(),
        type_size: 0x100,
        fields: BTreeMap::from([
            ("Pcb".to_owned(), field(0, 0x20)),
            ("UniqueProcessId".to_owned(), field(0x20, 4)),
            ("ActiveProcessLinks".to_owned(), field(0x30, 8)),
            ("ImageFileName".to_owned(), field(0x50, 16)),
        ]),
        types: BTreeMap::from([(
            "_KPROCESS".to_owned(),
            TypeLayout {
                size: 0x20,
                fields: BTreeMap::from([("DirectoryTableBase".to_owned(), field(0x18, 4))]),
            },
        )]),
        // The x86 path obtains list heads from KDBG, not invented x64 globals.
        symbols: BTreeMap::new(),
    }
}

#[test]
fn non_xp_pae_kernel_bootstraps_and_finishes_the_process_list() {
    let fixture = Fixture::new(0x10b);
    let image = MemoryImage::open(&fixture.0).unwrap();
    let profile = profile();
    let kernel = WindowsKernelContext::discover(&image, &profile).unwrap();
    assert_eq!(kernel.architecture, WindowsArchitecture::X86Pae);
    assert_eq!(kernel.directory_table_base, 0x1020);
    let processes = list_processes(&image, &kernel, &profile, 16).unwrap();
    assert!(processes.complete);
    assert!(processes.warnings.is_empty());
    assert_eq!(processes.processes.len(), 1);
    assert_eq!(processes.processes[0].pid, 4);
    assert_eq!(processes.processes[0].name, "System");
    let space = kernel.address_space(&image).unwrap();
    assert_eq!(space.pointer_size(), 4);
    // Adjacent Flink/Blink values must not be combined into one 64-bit pointer.
    assert_eq!(
        space.read_pointer(u64::from(BASE + 0x1100)).unwrap(),
        u64::from(BASE + 0x2030)
    );
    let error = starmem::windows::plugins::scan_network(&image, &kernel, &profile, 16).unwrap_err();
    assert!(error.to_string().contains("x86 PAE"));
}

#[test]
fn pae_bootstrap_rejects_wrong_guid_or_age() {
    let fixture = Fixture::new(0x10b);
    let image = MemoryImage::open(&fixture.0).unwrap();
    for (guid, age) in [(GUID, 5), ("00000000-0000-0000-0000-000000000000", 2)] {
        let mut profile = profile();
        profile.pdb_guid = guid.to_owned();
        profile.pdb_age = age;
        let error = WindowsKernelContext::discover(&image, &profile).unwrap_err();
        assert!(error.to_string().contains("exact kernel CodeView identity"));
    }
}

#[test]
fn pae_bootstrap_rejects_pe32_plus_in_a_32_bit_address_space() {
    let fixture = Fixture::new(0x20b);
    let image = MemoryImage::open(&fixture.0).unwrap();
    assert!(WindowsKernelContext::discover(&image, &profile()).is_err());
}

#[test]
#[ignore = "requires STARMEM_X86_IMAGE, STARMEM_X86_PDB and STARMEM_X86_CLI_REPORT"]
fn real_x86_image_matches_cli_and_host_api() {
    use starmem::INTEGRATION_API_VERSION;
    use starmem::api::{
        ExecutionContext, HostImageOptions, HostSymbolOptions, OpenSessionRequest, PlatformHint,
        RunRequest, Session,
    };

    let input = |name: &str| PathBuf::from(std::env::var_os(name).expect(name));
    let expected: serde_json::Value =
        serde_json::from_slice(&fs::read(input("STARMEM_X86_CLI_REPORT")).unwrap()).unwrap();
    let pdb_path = input("STARMEM_X86_PDB");
    let profile = starmem::profile::build_eprocess_profile(&pdb_path).unwrap();
    assert!(profile.is_x86());
    assert_eq!(profile.field("UniqueProcessId").unwrap().size, Some(4));
    assert_eq!(
        u64::from(profile.pdb_age),
        expected["source_identity"]["symbol_identity"]["details"]["pdb_age"]
            .as_u64()
            .unwrap()
    );
    let context = ExecutionContext::default();
    let (session, _) = Session::open(
        OpenSessionRequest {
            integration_api_version: INTEGRATION_API_VERSION,
            request_id: "x86-open".to_owned(),
            image_path: input("STARMEM_X86_IMAGE"),
            platform: PlatformHint::Windows,
            image: HostImageOptions::default(),
            symbols: HostSymbolOptions {
                pdb_path: Some(pdb_path),
                allow_compatible_local_symbols: false,
                ..HostSymbolOptions::default()
            },
        },
        &context,
    )
    .unwrap();
    let report = session
        .run(
            RunRequest {
                integration_api_version: INTEGRATION_API_VERSION,
                request_id: "x86-pslist".to_owned(),
                command_id: "pslist".to_owned(),
                arguments: serde_json::Map::new(),
            },
            &context,
        )
        .unwrap();
    assert!(report.envelope.available);
    assert!(report.envelope.complete);
    assert_eq!(
        report.envelope.data["processes"],
        expected["data"]["processes"]
    );
    assert!(
        !report.envelope.data["processes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    println!(
        "Host API matches CLI: {} processes",
        report.envelope.data["processes"].as_array().unwrap().len()
    );
}
