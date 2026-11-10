use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::address::{VirtualAddressRegion, X64AddressSpace};
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::profile::KernelProfile;
use crate::windows::{WindowsKernelContext, list_processes};

const COPY_BUFFER_SIZE: usize = 1024 * 1024;
const MAX_MAPPING_RECORDS: usize = 262_144;

#[derive(Debug, Serialize)]
pub struct ProcessMemoryDumpSegment {
    pub virtual_start: u64,
    pub physical_start: u64,
    pub output_offset: u64,
    pub length: u64,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Serialize)]
pub struct ProcessMemoryDumpReport {
    pub pid: u64,
    pub process: String,
    pub directory_table_base: u64,
    pub output: PathBuf,
    pub manifest: PathBuf,
    pub recovered_bytes: u64,
    pub mapped_bytes: u64,
    pub segments: Vec<ProcessMemoryDumpSegment>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

pub fn dump_process_memory(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid: u64,
    output: &Path,
    max_output_size: u64,
    cancellation: &CancellationToken,
) -> Result<ProcessMemoryDumpReport> {
    dump_process_memory_with_force(
        image,
        kernel,
        profile,
        pid,
        output,
        max_output_size,
        false,
        cancellation,
    )
}

/// Dump process memory using the shared output replacement policy.
#[allow(clippy::too_many_arguments)]
pub fn dump_process_memory_with_force(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    pid: u64,
    output: &Path,
    max_output_size: u64,
    force: bool,
    cancellation: &CancellationToken,
) -> Result<ProcessMemoryDumpReport> {
    ensure!(max_output_size > 0, "进程内存导出上限必须大于零");
    cancellation.check_cancelled()?;

    let (output_policy, manifest) = process_dump_output_policy(image, output, force)?;

    let processes = list_processes(image, kernel, profile, 65_536)?;
    let process = processes
        .processes
        .iter()
        .find(|process| process.pid == pid)
        .with_context(|| format!("未找到 PID {pid} 的活动进程"))?;
    let directory_table_base = process
        .details
        .user_directory_table_base
        .or(process.details.directory_table_base)
        .with_context(|| format!("PID {pid} 缺少可用的页表基址"))?;
    let space = X64AddressSpace::new(image, directory_table_base)?;
    let mapping_report =
        space.enumerate_mappings(VirtualAddressRegion::User, MAX_MAPPING_RECORDS)?;

    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    let mut recovered_bytes = 0u64;
    let mut segments = Vec::new();
    let mut warnings = mapping_report.warnings;
    let mut complete = !mapping_report.truncated;

    output_policy.write_file_atomic(output, |file| {
        let mut writer = BufWriter::new(file);
        for mapping in &mapping_report.mappings {
            cancellation.check_cancelled()?;
            if recovered_bytes >= max_output_size {
                complete = false;
                warnings.push(format!("进程内存导出达到 {} 字节上限", max_output_size));
                break;
            }

            let segment_limit = mapping.length.min(max_output_size - recovered_bytes);
            let segment_offset = recovered_bytes;
            let mut copied = 0u64;
            while copied < segment_limit {
                cancellation.check_cancelled()?;
                let take = (segment_limit - copied).min(buffer.len() as u64) as usize;
                if let Err(error) =
                    image.read_physical(mapping.physical_start + copied, &mut buffer[..take])
                {
                    complete = false;
                    warnings.push(format!(
                        "虚拟地址 {:#x} 对应物理内存读取中断：{error:#}",
                        mapping.virtual_start + copied
                    ));
                    break;
                }
                writer.write_all(&buffer[..take])?;
                copied += take as u64;
                recovered_bytes += take as u64;
            }
            if copied > 0 {
                segments.push(ProcessMemoryDumpSegment {
                    virtual_start: mapping.virtual_start,
                    physical_start: mapping.physical_start,
                    output_offset: segment_offset,
                    length: copied,
                    writable: mapping.writable,
                    executable: mapping.executable,
                });
            }
            if copied < mapping.length {
                complete = false;
            }
        }
        writer.flush()?;
        cancellation.check_cancelled()?;
        Ok(())
    })?;

    let report = ProcessMemoryDumpReport {
        pid,
        process: process.name.clone(),
        directory_table_base,
        output: output.to_path_buf(),
        manifest: manifest.clone(),
        recovered_bytes,
        mapped_bytes: mapping_report.mapped_bytes,
        segments,
        complete,
        warnings,
    };
    output_policy.write_file_atomic(&manifest, |file| {
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &report)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    })?;
    Ok(report)
}

fn process_dump_output_policy(
    image: &MemoryImage,
    output: &Path,
    force: bool,
) -> Result<(OutputPolicy, PathBuf)> {
    let manifest = output.with_extension("json");
    let mut policy = OutputPolicy::new(force);
    for source in image.sources() {
        policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    policy.output(OutputTarget::file("process_memory_image", output).with_derived_path(&manifest));
    policy.preflight()?;
    Ok((policy, manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "starmem-process-dump-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn vmware_metadata_fixture() -> Vec<u8> {
        const HEADER: usize = 12;
        const GROUP: usize = 80;
        let mut bytes = vec![0u8; HEADER + GROUP];
        bytes[..4].copy_from_slice(&[0xd2, 0xbe, 0xd2, 0xbe]);
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[HEADER..HEADER + 6].copy_from_slice(b"memory");
        bytes[HEADER + 64..HEADER + 72].copy_from_slice(&((HEADER + GROUP) as u64).to_le_bytes());
        for (name, indices, value) in [
            ("regionsCount", Vec::new(), 1u32),
            ("regionPPN", vec![0u32], 0u32),
            ("regionPageNum", vec![0u32], 0u32),
            ("regionSize", vec![0u32], 1u32),
        ] {
            bytes.push(4 | ((indices.len() as u8) << 6));
            bytes.push(name.len() as u8);
            bytes.extend_from_slice(name.as_bytes());
            for index in indices {
                bytes.extend_from_slice(&index.to_le_bytes());
            }
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        bytes
    }

    #[test]
    fn process_dump_policy_protects_image_and_manifest_aliases() {
        let root = temporary_path("protected");
        fs::create_dir(&root).unwrap();
        let image = root.join("capture.json");
        fs::write(&image, b"evidence").unwrap();
        let memory = MemoryImage::open(&image).unwrap();

        let direct = process_dump_output_policy(&memory, &image, true).unwrap_err();
        assert!(direct.to_string().contains("受保护输入"));

        let output = root.join("capture.raw");
        let derived = process_dump_output_policy(&memory, &output, true).unwrap_err();
        assert!(derived.to_string().contains("受保护输入"));
        assert_eq!(fs::read(&image).unwrap(), b"evidence");

        drop(memory);
        fs::remove_file(image).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn process_dump_policy_rejects_colliding_or_non_regular_outputs() {
        let root = temporary_path("invalid");
        fs::create_dir(&root).unwrap();
        let image = root.join("memory.raw");
        fs::write(&image, b"evidence").unwrap();
        let memory = MemoryImage::open(&image).unwrap();

        let colliding = root.join("dump.json");
        assert!(process_dump_output_policy(&memory, &colliding, true).is_err());

        let directory_output = root.join("dump.raw");
        fs::create_dir(&directory_output).unwrap();
        assert!(process_dump_output_policy(&memory, &directory_output, true).is_err());

        drop(memory);
        fs::remove_dir(directory_output).unwrap();
        fs::remove_file(image).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn process_dump_policy_protects_vmware_sidecar_hard_link_and_hash() {
        let root = temporary_path("vmware-sidecar");
        fs::create_dir(&root).unwrap();
        let primary = root.join("capture.vmem");
        let metadata = root.join("capture.vmss");
        let alias = root.join("dump.dmp");
        fs::write(&primary, vec![0u8; 4096]).unwrap();
        fs::write(&metadata, vmware_metadata_fixture()).unwrap();
        let before = hex::encode(Sha256::digest(fs::read(&metadata).unwrap()));
        let memory = MemoryImage::open(&primary).unwrap();
        assert_eq!(memory.sources().len(), 2);

        if fs::hard_link(&metadata, &alias).is_ok() {
            assert!(process_dump_output_policy(&memory, &alias, true).is_err());
            let after = hex::encode(Sha256::digest(fs::read(&metadata).unwrap()));
            assert_eq!(after, before);
            fs::remove_file(&alias).unwrap();
        }

        drop(memory);
        fs::remove_file(metadata).unwrap();
        fs::remove_file(primary).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
