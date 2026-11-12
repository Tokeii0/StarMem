//! Explicit PDB baseline for frozen symbolless reports. Never used by the probe.
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use starmem::image::MemoryImage;
use starmem::output_policy::OutputPolicy;
use starmem::profile::build_eprocess_profile;
use starmem::windows::{WindowsKernelContext, files, list_processes};

#[derive(Parser)]
#[command(about = "有符号对照程序：显式精确 PDB，比较已冻结的无符号结果")]
struct Args {
    #[arg(long)]
    image: PathBuf,
    #[arg(long)]
    pdb: PathBuf,
    #[arg(long)]
    probe_report: PathBuf,
    #[arg(long)]
    report: PathBuf,
    #[arg(long)]
    export_dir: PathBuf,
    /// Revalidate the image and exact PDB, then compare only selected exports.
    #[arg(long)]
    exports_only: bool,
}

fn sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 64 * 1024];
    loop {
        let length = file.read(&mut bytes)?;
        if length == 0 {
            break;
        }
        hash.update(&bytes[..length]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn main() -> Result<()> {
    let args = Args::parse();
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build_global()?;
    let probe: Value = serde_json::from_reader(File::open(&args.probe_report)?)?;
    let image = MemoryImage::open(&args.image)?;
    let mut source_hashes = Vec::new();
    for (index, source) in image.sources().enumerate() {
        let hash = sha256(&source.path)?;
        ensure!(
            probe["sources"][index]["sha256"] == hash,
            "检材来源哈希不匹配，拒绝对照"
        );
        source_hashes.push(json!({"source":source,"sha256":hash}));
    }
    ensure!(
        probe["sources"].as_array().context("报告没有来源")?.len() == source_hashes.len(),
        "检材来源数量不匹配"
    );
    let profile = build_eprocess_profile(&args.pdb)?;
    // Independent discovery; inferred process offsets and list heads are not inputs.
    let kernel = WindowsKernelContext::discover(&image, &profile)?;
    let codeview = starmem::symbols::codeview_from_virtual_pe(
        &image,
        kernel.directory_table_base,
        kernel.kernel_base,
    )?;
    let mut pdb = pdb::PDB::open(File::open(&args.pdb)?)?;
    let dbi_age = pdb.debug_information()?.age();
    ensure!(
        codeview.guid.eq_ignore_ascii_case(&profile.pdb_guid)
            && dbi_age.unwrap_or(profile.pdb_age) == codeview.age,
        "显式 PDB 的 GUID/原始 DBI Age 与内存内核不匹配"
    );
    let process_report = if args.exports_only {
        None
    } else {
        Some(list_processes(&image, &kernel, &profile, 65536)?)
    };
    let file_report = if args.exports_only {
        None
    } else {
        Some(files::scan_files(&image, &kernel, &profile, 100_000)?)
    };
    let selected: Vec<u64> = probe["exports"]["attempts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| item["success"] == true)
        .filter_map(|item| item["plan"]["file_object"].as_u64())
        .collect();
    let mut policy = OutputPolicy::new(false);
    for source in image.sources() {
        policy.protect_file("image_source", &source.path);
    }
    policy
        .protect_file("pdb", &args.pdb)
        .protect_file("frozen_report", &args.probe_report);
    policy.output_file("baseline_report", &args.report);
    for address in &selected {
        policy.output_file(
            "baseline_cache",
            args.export_dir.join(format!("{address:016x}.cache.bin")),
        );
    }
    policy.preflight()?;
    let mut dumps = Vec::new();
    for address in selected {
        let path = args.export_dir.join(format!("{address:016x}.cache.bin"));
        let mut recovered = None;
        let result = policy.write_file_atomic(&path, |output| {
            let report = files::dump_file(
                &image,
                &kernel,
                &profile,
                address,
                output,
                files::DumpSource::Cache,
                64 * 1024 * 1024,
            )?;
            ensure!(report.recovered_bytes > 0, "PDB 对照未恢复字节");
            recovered = Some(report);
            Ok(())
        });
        match result {
            Ok(()) => dumps.push(json!({"success":true,"file_object":address,"output":path,
                "sha256":sha256(&path)?,"report":recovered})),
            Err(error) => dumps
                .push(json!({"success":false,"file_object":address,"error":format!("{error:#}")})),
        }
    }
    let mut offsets = serde_json::Map::new();
    for &(ty, field) in &[
        ("_EPROCESS", "UniqueProcessId"),
        ("_EPROCESS", "ActiveProcessLinks"),
        ("_EPROCESS", "ImageFileName"),
        ("_EPROCESS", "SectionBaseAddress"),
        ("_KPROCESS", "DirectoryTableBase"),
        ("_FILE_OBJECT", "Type"),
        ("_FILE_OBJECT", "Size"),
        ("_FILE_OBJECT", "DeviceObject"),
        ("_FILE_OBJECT", "FsContext"),
        ("_FILE_OBJECT", "SectionObjectPointer"),
        ("_FILE_OBJECT", "FileName"),
        ("_SHARED_CACHE_MAP", "FileSize"),
        ("_SHARED_CACHE_MAP", "FileObject"),
        ("_SHARED_CACHE_MAP", "InitialVacbs"),
        ("_SHARED_CACHE_MAP", "Vacbs"),
        ("_VACB", "BaseAddress"),
        ("_VACB", "SharedCacheMap"),
        ("_VACB", "Overlay"),
    ] {
        offsets.insert(
            format!("{ty}.{field}"),
            profile
                .type_field(ty, field)
                .map(|f| json!(f.offset))
                .unwrap_or(Value::Null),
        );
    }
    let output = json!({"method":"explicit_exact_pdb_independent_engine_baseline",
        "exports_only":args.exports_only,
        "engine_build_id":starmem::BUILD_ID,"threads":2,
        "command":std::env::args_os().map(|a|a.to_string_lossy().into_owned()).collect::<Vec<_>>(),
        "source_hashes":source_hashes,"probe_report_sha256":sha256(&args.probe_report)?,
        "pdb":args.pdb,"pdb_sha256":sha256(&args.pdb)?,"pdb_info_age":profile.pdb_age,
        "pdb_dbi_age":dbi_age,"target_codeview":codeview,"kernel":kernel,
        "offsets":offsets,"processes":process_report,"filescan":file_report,"exports":dumps});
    policy.write_file_atomic(&args.report, |file| {
        serde_json::to_writer_pretty(file, &output)?;
        Ok(())
    })?;
    println!(
        "{}",
        json!({"report":args.report,"processes":output["processes"]["processes"].as_array().map(Vec::len),
        "files":output["filescan"]["records"].as_array().map(Vec::len),"exports":output["exports"].as_array().map(Vec::len)})
    );
    Ok(())
}
