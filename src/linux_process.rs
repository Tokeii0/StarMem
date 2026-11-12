//! Conservative Linux process-address-space artifacts for exact supported kernels.
//!
//! The profiles in this module are tied to the same full Ubuntu build fingerprints
//! used by `linux.rs`, `linux_files.rs`, and `linux_pagecache.rs`.  Every user-space
//! read is performed through the target process page tables and missing pages remain
//! explicit evidence rather than being silently treated as valid zero bytes.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::image::MemoryImage;
use crate::linux::{
    LinuxKernelContext, LinuxProcessListReport, LinuxProcessRecord, LinuxX64AddressSpace,
    UBUNTU_4_13_0_36_XENIAL, UBUNTU_5_4_0_84_BIONIC, UBUNTU_6_8_0_49_NOBLE, is_kernel_pointer,
};
use crate::output_policy::{OutputPolicy, OutputTarget};

pub mod strings;

const PAGE_SIZE: u64 = 0x1000;
const USER_ADDRESS_LIMIT: u64 = 0x0000_8000_0000_0000;
const MAX_DENTRY_NAME: usize = 255;
const MAX_PATH_COMPONENTS: usize = 4096;
const MAX_PATH_BYTES: usize = 1024 * 1024;
const MAPLE_NODE_POINTER_MASK: u64 = 0xff;
const MAPLE_NODE_TYPE_SHIFT: u64 = 3;
const MAPLE_NODE_TYPE_MASK: u64 = 0x0f;

#[derive(Debug, Clone, Copy)]
struct ExactLinuxProcessProfile {
    source: &'static str,
    fingerprint: &'static str,
    task_files: u64,
    task_signal: u64,
    mm_mmap: Option<u64>,
    mm_maple_tree: Option<u64>,
    mm_pgd: u64,
    mm_map_count: u64,
    mm_start_brk: u64,
    mm_brk: u64,
    mm_start_stack: u64,
    mm_arg_start: u64,
    mm_arg_end: u64,
    mm_env_start: u64,
    mm_env_end: u64,
    vma_start: u64,
    vma_end: u64,
    vma_next: Option<u64>,
    vma_prev: Option<u64>,
    vma_mm: u64,
    vma_flags: u64,
    vma_pgoff: u64,
    vma_file: u64,
    files_fdt: u64,
    fdtable_max_fds: u64,
    fdtable_fd: u64,
    fdtable_close_on_exec: u64,
    fdtable_open_fds: u64,
    file_path: u64,
    file_inode: u64,
    file_flags: u64,
    file_mode: u64,
    file_pos: u64,
    path_mnt: u64,
    path_dentry: u64,
    dentry_parent: u64,
    dentry_name: u64,
    qstr_len: u64,
    qstr_name: u64,
    dentry_inode: u64,
    inode_mode: u64,
    inode_number: u64,
    mount_mnt: u64,
    mount_parent: u64,
    mount_mountpoint: u64,
    vfsmount_root: u64,
}

impl ExactLinuxProcessProfile {
    fn from_isf(isf: &crate::linux_symbols::LinuxIsf) -> Result<Self> {
        let profile = Self {
            source: "volatility3_isf_process",
            fingerprint: "Volatility 3 ISF; exact linux_banner; runtime-validated process layout",
            task_files: isf.field_offset("task_struct", "files")?,
            task_signal: isf.field_offset("task_struct", "signal")?,
            mm_mmap: isf.optional_field_offset("mm_struct", "mmap")?,
            mm_maple_tree: isf.optional_field_offset("mm_struct", "mm_mt")?,
            mm_pgd: isf.field_offset("mm_struct", "pgd")?,
            mm_map_count: isf.field_offset("mm_struct", "map_count")?,
            mm_start_brk: isf.field_offset("mm_struct", "start_brk")?,
            mm_brk: isf.field_offset("mm_struct", "brk")?,
            mm_start_stack: isf.field_offset("mm_struct", "start_stack")?,
            mm_arg_start: isf.field_offset("mm_struct", "arg_start")?,
            mm_arg_end: isf.field_offset("mm_struct", "arg_end")?,
            mm_env_start: isf.field_offset("mm_struct", "env_start")?,
            mm_env_end: isf.field_offset("mm_struct", "env_end")?,
            vma_start: isf.field_offset("vm_area_struct", "vm_start")?,
            vma_end: isf.field_offset("vm_area_struct", "vm_end")?,
            vma_next: isf.optional_field_offset("vm_area_struct", "vm_next")?,
            vma_prev: isf.optional_field_offset("vm_area_struct", "vm_prev")?,
            vma_mm: isf.field_offset("vm_area_struct", "vm_mm")?,
            vma_flags: isf.field_offset("vm_area_struct", "vm_flags")?,
            vma_pgoff: isf.field_offset("vm_area_struct", "vm_pgoff")?,
            vma_file: isf.field_offset("vm_area_struct", "vm_file")?,
            files_fdt: isf.field_offset("files_struct", "fdt")?,
            fdtable_max_fds: isf.field_offset("fdtable", "max_fds")?,
            fdtable_fd: isf.field_offset("fdtable", "fd")?,
            fdtable_close_on_exec: isf.field_offset("fdtable", "close_on_exec")?,
            fdtable_open_fds: isf.field_offset("fdtable", "open_fds")?,
            file_path: isf.field_offset("file", "f_path")?,
            file_inode: isf.field_offset("file", "f_inode")?,
            file_flags: isf.field_offset("file", "f_flags")?,
            file_mode: isf.field_offset("file", "f_mode")?,
            file_pos: isf.field_offset("file", "f_pos")?,
            path_mnt: isf.field_offset("path", "mnt")?,
            path_dentry: isf.field_offset("path", "dentry")?,
            dentry_parent: isf.field_offset("dentry", "d_parent")?,
            dentry_name: isf.field_offset("dentry", "d_name")?,
            qstr_len: isf.field_offset("qstr", "len")?,
            qstr_name: isf.field_offset("qstr", "name")?,
            dentry_inode: isf.field_offset("dentry", "d_inode")?,
            inode_mode: isf.field_offset("inode", "i_mode")?,
            inode_number: isf.field_offset("inode", "i_ino")?,
            mount_mnt: isf.field_offset("mount", "mnt")?,
            mount_parent: isf.field_offset("mount", "mnt_parent")?,
            mount_mountpoint: isf.field_offset("mount", "mnt_mountpoint")?,
            vfsmount_root: isf.field_offset("vfsmount", "mnt_root")?,
        };
        ensure!(
            profile.mm_mmap.is_some() ^ profile.mm_maple_tree.is_some(),
            "Volatility 3 ISF mm_struct 必须且只能包含 mmap 或 mm_mt"
        );
        Ok(profile)
    }

    fn for_banner(banner: &str) -> Option<Self> {
        let common = |fingerprint,
                      task_files,
                      task_signal,
                      mm_mmap,
                      mm_maple_tree,
                      mm_pgd,
                      mm_map_count,
                      mm_start_brk,
                      mm_brk,
                      mm_start_stack,
                      mm_arg_start,
                      mm_arg_end,
                      mm_env_start,
                      mm_env_end,
                      vma_next,
                      vma_prev,
                      vma_mm,
                      vma_flags,
                      vma_pgoff,
                      vma_file,
                      file_path,
                      file_inode,
                      file_flags,
                      file_mode,
                      file_pos| Self {
            source: "exact_banner_process_profile",
            fingerprint,
            task_files,
            task_signal,
            mm_mmap,
            mm_maple_tree,
            mm_pgd,
            mm_map_count,
            mm_start_brk,
            mm_brk,
            mm_start_stack,
            mm_arg_start,
            mm_arg_end,
            mm_env_start,
            mm_env_end,
            vma_start: 0,
            vma_end: 8,
            vma_next,
            vma_prev,
            vma_mm,
            vma_flags,
            vma_pgoff,
            vma_file,
            files_fdt: 0x20,
            fdtable_max_fds: 0,
            fdtable_fd: 8,
            fdtable_close_on_exec: 0x10,
            fdtable_open_fds: 0x18,
            file_path,
            file_inode,
            file_flags,
            file_mode,
            file_pos,
            path_mnt: 0,
            path_dentry: 8,
            dentry_parent: 0x18,
            dentry_name: 0x20,
            qstr_len: 0x04,
            qstr_name: 0x08,
            dentry_inode: 0x30,
            inode_mode: 0,
            inode_number: 0x40,
            mount_mnt: 0x20,
            mount_parent: 0x10,
            mount_mountpoint: 0x18,
            vfsmount_root: 0,
        };
        Some(match banner {
            UBUNTU_4_13_0_36_XENIAL => common(
                "Ubuntu Xenial HWE 4.13.0-36.40; build_id=d9142b737a5bb09c7f1aef87f7dd2834dba7d934; dwarf2json=vmlinux-4.13.0-36-generic",
                0xae8,
                0xaf8,
                Some(0),
                None,
                0x50,
                0x70,
                0x118,
                0x120,
                0x128,
                0x130,
                0x138,
                0x140,
                0x148,
                Some(0x10),
                Some(0x18),
                0x40,
                0x50,
                0x98,
                0xa0,
                0x10,
                0x20,
                0x40,
                0x44,
                0x68,
            ),
            UBUNTU_5_4_0_84_BIONIC => common(
                "Ubuntu Bionic HWE 5.4.0-84.94; build_id=c56268a4878b2c99f78e1fa2d0ace9bc5f6d575d; dwarf2json=vmlinux-5.4.0-84-generic",
                0xac0,
                0xad0,
                Some(0),
                None,
                0x50,
                0x70,
                0x120,
                0x128,
                0x130,
                0x138,
                0x140,
                0x148,
                0x150,
                Some(0x10),
                Some(0x18),
                0x40,
                0x50,
                0x98,
                0xa0,
                0x10,
                0x20,
                0x40,
                0x44,
                0x68,
            ),
            UBUNTU_6_8_0_49_NOBLE => common(
                "Ubuntu Noble 6.8.0-49.49; build_id=9c2aa265a404792954898609a7a72988d9bac935; dwarf2json=vmlinux-6.8.0-49-generic",
                0xc08,
                0xc20,
                None,
                Some(0x40),
                0x80,
                0xa8,
                0x160,
                0x168,
                0x170,
                0x178,
                0x180,
                0x188,
                0x190,
                None,
                None,
                0x10,
                0x20,
                0x80,
                0x88,
                0x98,
                0xa8,
                0x48,
                0x14,
                0x40,
            ),
            _ => return None,
        })
    }

    fn evidence(self, kernel: &LinuxKernelContext) -> LinuxProcessProfileEvidence {
        let mut offsets = BTreeMap::new();
        for (name, value) in [
            ("task_struct.files", Some(self.task_files)),
            ("task_struct.signal", Some(self.task_signal)),
            ("mm_struct.mmap", self.mm_mmap),
            ("mm_struct.mm_mt", self.mm_maple_tree),
            ("mm_struct.pgd", Some(self.mm_pgd)),
            ("mm_struct.map_count", Some(self.mm_map_count)),
            ("mm_struct.arg_start", Some(self.mm_arg_start)),
            ("mm_struct.arg_end", Some(self.mm_arg_end)),
            ("mm_struct.env_start", Some(self.mm_env_start)),
            ("mm_struct.env_end", Some(self.mm_env_end)),
            ("vm_area_struct.vm_start", Some(self.vma_start)),
            ("vm_area_struct.vm_end", Some(self.vma_end)),
            ("vm_area_struct.vm_next", self.vma_next),
            ("vm_area_struct.vm_mm", Some(self.vma_mm)),
            ("vm_area_struct.vm_flags", Some(self.vma_flags)),
            ("vm_area_struct.vm_file", Some(self.vma_file)),
            ("files_struct.fdt", Some(self.files_fdt)),
            ("fdtable.max_fds", Some(self.fdtable_max_fds)),
            ("fdtable.fd", Some(self.fdtable_fd)),
            ("file.f_path", Some(self.file_path)),
            ("file.f_inode", Some(self.file_inode)),
        ] {
            if let Some(value) = value {
                offsets.insert(name.to_owned(), value);
            }
        }
        LinuxProcessProfileEvidence {
            source: self.source.to_owned(),
            fingerprint: if self.source == "volatility3_isf_process" {
                kernel
                    .symbol_table
                    .as_deref()
                    .map(|table| table.fingerprint().to_owned())
                    .unwrap_or_else(|| self.fingerprint.to_owned())
            } else {
                self.fingerprint.to_owned()
            },
            offsets,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxProcessProfileEvidence {
    pub source: String,
    pub fingerprint: String,
    pub offsets: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxProcessArtifactWarning {
    pub kind: String,
    pub message: String,
    pub pid: Option<i32>,
    pub address: Option<u64>,
    pub address_hex: Option<String>,
}

impl LinuxProcessArtifactWarning {
    pub(crate) fn new(
        kind: impl Into<String>,
        message: impl Into<String>,
        pid: Option<i32>,
        address: Option<u64>,
    ) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
            pid,
            address,
            address_hex: address.map(format_address),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxVirtualMissingRange {
    pub virtual_address: u64,
    pub virtual_address_hex: String,
    pub file_offset: u64,
    pub length: u64,
}

struct ProcessAddressSpace<'a> {
    space: LinuxX64AddressSpace<'a>,
    mm: u64,
    pgd: u64,
    pgd_physical: u64,
}

fn open_process_address_space<'a>(
    image: &'a MemoryImage,
    kernel_space: &LinuxX64AddressSpace<'a>,
    profile: ExactLinuxProcessProfile,
    process: &LinuxProcessRecord,
) -> Result<ProcessAddressSpace<'a>> {
    let mm = process.mm.context("进程没有用户态 mm_struct")?;
    ensure!(is_kernel_pointer(mm), "mm_struct 不是规范内核指针");
    let pgd = kernel_space
        .read_u64(mm + profile.mm_pgd)
        .context("无法读取 mm_struct.pgd")?;
    ensure!(is_kernel_pointer(pgd), "mm_struct.pgd 不是规范内核指针");
    ensure!(pgd & (PAGE_SIZE - 1) == 0, "mm_struct.pgd 未按页对齐");
    let pgd_physical = kernel_space
        .translate(pgd)
        .context("无法将 mm_struct.pgd 转换为物理页表根")?;
    ensure!(
        pgd_physical & (PAGE_SIZE - 1) == 0,
        "进程页表物理根未按页对齐"
    );
    Ok(ProcessAddressSpace {
        space: LinuxX64AddressSpace::new(image, pgd_physical)?,
        mm,
        pgd,
        pgd_physical,
    })
}

#[derive(Debug)]
struct RangeRead {
    bytes: Vec<u8>,
    recovered_bytes: u64,
    missing_ranges: Vec<LinuxVirtualMissingRange>,
    truncated: bool,
}

impl RangeRead {
    fn complete(&self) -> bool {
        !self.truncated && self.missing_ranges.is_empty()
    }
}

fn read_user_range(
    space: &LinuxX64AddressSpace<'_>,
    start: u64,
    end: u64,
    max_bytes: u64,
) -> Result<RangeRead> {
    ensure!(max_bytes > 0, "用户态读取上限必须大于零");
    ensure!(start < end, "用户态范围为空或反向");
    ensure!(
        start < USER_ADDRESS_LIMIT && end <= USER_ADDRESS_LIMIT,
        "用户态范围越界"
    );
    let requested = end - start;
    let length = requested.min(max_bytes);
    let length_usize = usize::try_from(length).context("用户态范围无法装入本机地址空间")?;
    let mut bytes = vec![0u8; length_usize];
    let mut recovered_bytes = 0u64;
    let mut missing_ranges = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let address = start + offset as u64;
        let page_remaining = (PAGE_SIZE - (address & (PAGE_SIZE - 1))) as usize;
        let take = page_remaining.min(bytes.len() - offset);
        if space
            .read_virtual(address, &mut bytes[offset..offset + take])
            .is_ok()
        {
            recovered_bytes += take as u64;
        } else {
            push_missing_range(&mut missing_ranges, address, offset as u64, take as u64);
        }
        offset += take;
    }
    Ok(RangeRead {
        bytes,
        recovered_bytes,
        missing_ranges,
        truncated: requested > length,
    })
}

fn push_missing_range(
    ranges: &mut Vec<LinuxVirtualMissingRange>,
    virtual_address: u64,
    file_offset: u64,
    length: u64,
) {
    if let Some(last) = ranges.last_mut()
        && last.virtual_address + last.length == virtual_address
        && last.file_offset + last.length == file_offset
    {
        last.length += length;
        return;
    }
    ranges.push(LinuxVirtualMissingRange {
        virtual_address,
        virtual_address_hex: format_address(virtual_address),
        file_offset,
        length,
    });
}

fn selected_processes(
    report: &LinuxProcessListReport,
    pid: Option<i32>,
    require_mm: bool,
) -> Result<Vec<&LinuxProcessRecord>> {
    if let Some(pid) = pid {
        ensure!(pid >= 0, "PID 不能为负数");
        let process = report
            .processes
            .iter()
            .find(|process| process.pid == pid)
            .with_context(|| format!("活动任务链中未找到 PID {pid}"))?;
        if require_mm {
            ensure!(process.mm.is_some(), "PID {pid} 没有用户态 mm_struct");
        }
        return Ok(vec![process]);
    }
    Ok(report
        .processes
        .iter()
        .filter(|process| process.pid == process.tgid)
        .filter(|process| !require_mm || process.mm.is_some())
        .collect())
}

fn process_list_warnings(report: &LinuxProcessListReport) -> Vec<LinuxProcessArtifactWarning> {
    report
        .warnings
        .iter()
        .map(|warning| {
            LinuxProcessArtifactWarning::new(
                format!("pslist.{}", warning.kind),
                warning.message.clone(),
                None,
                warning.list_entry,
            )
        })
        .collect()
}

fn exact_profile(kernel: &LinuxKernelContext) -> Result<ExactLinuxProcessProfile> {
    ensure!(
        kernel.system_map.is_none() || kernel.symbol_table.is_some(),
        "System.map 不包含进程地址空间类型；自动补齐尚未找到匹配的 Linux ISF"
    );
    if let Some(isf) = kernel.symbol_table.as_deref() {
        return ExactLinuxProcessProfile::from_isf(isf).or_else(|isf_error| {
            ExactLinuxProcessProfile::for_banner(&kernel.banner).with_context(|| {
                format!(
                    "精确匹配的 Volatility 3 ISF 缺少可用进程布局（{isf_error:#}），且当前 Linux 构建没有内置完整 banner/build-id profile"
                )
            })
        });
    }
    ExactLinuxProcessProfile::for_banner(&kernel.banner).context(
        "当前 Linux 构建没有精确匹配的 Volatility 3 ISF 或完整 banner/build-id 进程布局；拒绝按相似版本猜测偏移",
    )
}

pub(crate) fn process_profile_evidence(
    kernel: &LinuxKernelContext,
) -> Result<LinuxProcessProfileEvidence> {
    Ok(exact_profile(kernel)?.evidence(kernel))
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxCmdlineRecord {
    pub task: u64,
    pub task_hex: String,
    pub pid: i32,
    pub tgid: i32,
    pub name: String,
    pub mm: u64,
    pub mm_hex: String,
    pub pgd: u64,
    pub pgd_hex: String,
    pub pgd_physical: u64,
    pub pgd_physical_hex: String,
    pub arg_start: u64,
    pub arg_start_hex: String,
    pub arg_end: u64,
    pub arg_end_hex: String,
    pub requested_bytes: u64,
    pub recovered_bytes: u64,
    pub complete: bool,
    pub truncated: bool,
    pub argument_count: usize,
    pub arguments: Vec<String>,
    pub command_line: String,
    pub missing_ranges: Vec<LinuxVirtualMissingRange>,
}

#[derive(Debug, Serialize)]
pub struct LinuxCmdlineReport {
    pub source: String,
    pub kernel: LinuxKernelContext,
    pub profile: LinuxProcessProfileEvidence,
    pub records: Vec<LinuxCmdlineRecord>,
    pub processes_considered: usize,
    pub records_recovered: usize,
    pub process_list_complete: bool,
    pub complete: bool,
    pub max_bytes: u64,
    pub scope: String,
    pub warnings: Vec<LinuxProcessArtifactWarning>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxPsAuxRecord {
    pub task: u64,
    pub task_hex: String,
    pub pid: i32,
    pub tgid: i32,
    pub ppid: Option<i32>,
    pub name: String,
    pub state: String,
    pub kernel_thread: Option<bool>,
    pub start_time_ns: Option<u64>,
    pub command_line: String,
    pub command_line_source: String,
    pub command_line_complete: bool,
    pub argument_count: usize,
    pub arguments: Vec<String>,
    pub requested_bytes: u64,
    pub recovered_bytes: u64,
    pub missing_ranges: Vec<LinuxVirtualMissingRange>,
}

#[derive(Debug, Serialize)]
pub struct LinuxPsAuxReport {
    pub source: String,
    pub kernel: LinuxKernelContext,
    pub profile: Option<LinuxProcessProfileEvidence>,
    pub records: Vec<LinuxPsAuxRecord>,
    pub processes_considered: usize,
    pub command_lines_recovered: usize,
    pub user_cmdline_fallback_count: usize,
    pub kernel_thread_count: usize,
    pub process_list_complete: bool,
    pub complete: bool,
    pub max_bytes: u64,
    pub scope: String,
    pub warnings: Vec<LinuxProcessArtifactWarning>,
}

pub fn analyze_cmdline(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    processes: &LinuxProcessListReport,
    pid: Option<i32>,
    max_bytes: u64,
) -> Result<LinuxCmdlineReport> {
    ensure!(max_bytes > 0, "cmdline 最大读取字节数必须大于零");
    let profile = exact_profile(kernel)?;
    let selected = selected_processes(processes, pid, true)?;
    let kernel_space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut warnings = process_list_warnings(processes);
    let mut records = Vec::new();
    let mut complete = processes.complete;
    for process in &selected {
        let result = (|| -> Result<LinuxCmdlineRecord> {
            let context = open_process_address_space(image, &kernel_space, profile, process)?;
            let arg_start = kernel_space.read_u64(context.mm + profile.mm_arg_start)?;
            let arg_end = kernel_space.read_u64(context.mm + profile.mm_arg_end)?;
            let range = read_user_range(&context.space, arg_start, arg_end, max_bytes)?;
            let arguments = decode_nul_strings(&range.bytes);
            let command_line = arguments.join(" ");
            Ok(LinuxCmdlineRecord {
                task: process.task,
                task_hex: format_address(process.task),
                pid: process.pid,
                tgid: process.tgid,
                name: process.name.clone(),
                mm: context.mm,
                mm_hex: format_address(context.mm),
                pgd: context.pgd,
                pgd_hex: format_address(context.pgd),
                pgd_physical: context.pgd_physical,
                pgd_physical_hex: format_address(context.pgd_physical),
                arg_start,
                arg_start_hex: format_address(arg_start),
                arg_end,
                arg_end_hex: format_address(arg_end),
                requested_bytes: arg_end - arg_start,
                recovered_bytes: range.recovered_bytes,
                complete: range.complete(),
                truncated: range.truncated,
                argument_count: arguments.len(),
                arguments,
                command_line,
                missing_ranges: range.missing_ranges,
            })
        })();
        match result {
            Ok(record) => {
                complete &= record.complete;
                records.push(record);
            }
            Err(error) => {
                complete = false;
                warnings.push(LinuxProcessArtifactWarning::new(
                    "cmdline_unrecoverable",
                    format!("PID {} cmdline 恢复失败：{error:#}", process.pid),
                    Some(process.pid),
                    process.mm,
                ));
            }
        }
    }
    Ok(LinuxCmdlineReport {
        source: "linux.process.mm.arg_range".to_owned(),
        kernel: kernel.clone(),
        profile: profile.evidence(kernel),
        processes_considered: selected.len(),
        records_recovered: records.len(),
        process_list_complete: processes.complete,
        complete,
        max_bytes,
        scope: "active thread-group leaders with a validated mm_struct; exact arg_start..arg_end ranges; resident present pages only".to_owned(),
        records,
        warnings,
    })
}

pub fn analyze_psaux(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    processes: &LinuxProcessListReport,
    pid: Option<i32>,
    max_bytes: u64,
) -> Result<LinuxPsAuxReport> {
    ensure!(max_bytes > 0, "psaux 最大读取字节数必须大于零");
    let selected = selected_processes(processes, pid, false)?;
    let has_user_process = selected
        .iter()
        .any(|process| process.kernel_thread != Some(true));
    let mut profile = None;
    let mut cmdlines = BTreeMap::new();
    let mut cmdline_profile_available = false;
    let mut warnings;

    if has_user_process {
        match analyze_cmdline(image, kernel, processes, pid, max_bytes) {
            Ok(report) => {
                cmdline_profile_available = true;
                profile = Some(report.profile);
                warnings = report.warnings;
                for record in report.records {
                    cmdlines.insert(record.task, record);
                }
            }
            Err(error) => {
                warnings = process_list_warnings(processes);
                warnings.push(LinuxProcessArtifactWarning::new(
                    "psaux_cmdline_profile_unavailable",
                    format!(
                        "无法使用精确 mm_struct 参数布局；用户进程命令行退化为 task_struct.comm：{error:#}"
                    ),
                    pid,
                    None,
                ));
            }
        }
    } else {
        warnings = process_list_warnings(processes);
    }

    let mut records = Vec::with_capacity(selected.len());
    let mut command_lines_recovered = 0usize;
    let mut user_cmdline_fallback_count = 0usize;
    let mut kernel_thread_count = 0usize;
    let mut complete = processes.complete;
    for process in selected {
        let cmdline = cmdlines.remove(&process.task);
        let fallback_requested = cmdline.as_ref().map_or(0, |record| record.requested_bytes);
        let fallback_recovered = cmdline.as_ref().map_or(0, |record| record.recovered_bytes);
        let fallback_missing = cmdline
            .as_ref()
            .map(|record| record.missing_ranges.clone())
            .unwrap_or_default();
        let is_kernel_thread = process.kernel_thread == Some(true);
        let (
            command_line,
            command_line_source,
            command_line_complete,
            argument_count,
            arguments,
            requested_bytes,
            recovered_bytes,
            missing_ranges,
        ) = if is_kernel_thread {
            kernel_thread_count += 1;
            (
                format!("[{}]", process.name),
                "task_struct.comm_kernel_thread".to_owned(),
                true,
                0,
                Vec::new(),
                0,
                0,
                Vec::new(),
            )
        } else if let Some(record) = cmdline.filter(|record| !record.command_line.trim().is_empty())
        {
            command_lines_recovered += 1;
            complete &= record.complete;
            (
                record.command_line,
                "mm_struct.arg_start_arg_end".to_owned(),
                record.complete,
                record.argument_count,
                record.arguments,
                record.requested_bytes,
                record.recovered_bytes,
                record.missing_ranges,
            )
        } else {
            user_cmdline_fallback_count += 1;
            complete = false;
            if cmdline_profile_available
                && !warnings
                    .iter()
                    .any(|warning| warning.pid == Some(process.pid))
            {
                warnings.push(LinuxProcessArtifactWarning::new(
                    "psaux_cmdline_fallback",
                    format!(
                        "PID {} 没有可用的驻留 argv；仅报告经过验证的 task_struct.comm",
                        process.pid
                    ),
                    Some(process.pid),
                    process.mm,
                ));
            }
            (
                process.name.clone(),
                "task_struct.comm_fallback".to_owned(),
                false,
                0,
                Vec::new(),
                fallback_requested,
                fallback_recovered,
                fallback_missing,
            )
        };
        records.push(LinuxPsAuxRecord {
            task: process.task,
            task_hex: format_address(process.task),
            pid: process.pid,
            tgid: process.tgid,
            ppid: process.ppid,
            name: process.name.clone(),
            state: process.state.clone(),
            kernel_thread: process.kernel_thread,
            start_time_ns: process.start_time_ns,
            command_line,
            command_line_source,
            command_line_complete,
            argument_count,
            arguments,
            requested_bytes,
            recovered_bytes,
            missing_ranges,
        });
    }

    Ok(LinuxPsAuxReport {
        source: "linux.task_struct+mm_struct.arg_range".to_owned(),
        kernel: kernel.clone(),
        profile,
        processes_considered: records.len(),
        command_lines_recovered,
        user_cmdline_fallback_count,
        kernel_thread_count,
        process_list_complete: processes.complete,
        complete,
        max_bytes,
        scope: "active thread-group leaders; validated task metadata for every row; exact resident arg_start..arg_end when available; explicit task_struct.comm fallback otherwise".to_owned(),
        records,
        warnings,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxEnvironmentProcess {
    pub task: u64,
    pub task_hex: String,
    pub pid: i32,
    pub tgid: i32,
    pub name: String,
    pub mm: u64,
    pub mm_hex: String,
    pub env_start: u64,
    pub env_start_hex: String,
    pub env_end: u64,
    pub env_end_hex: String,
    pub requested_bytes: u64,
    pub recovered_bytes: u64,
    pub complete: bool,
    pub truncated: bool,
    pub variable_count: usize,
    pub missing_ranges: Vec<LinuxVirtualMissingRange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxEnvironmentVariable {
    pub pid: i32,
    pub process_name: String,
    pub index: usize,
    pub name: String,
    pub value: String,
    pub raw: String,
    pub has_separator: bool,
}

#[derive(Debug, Serialize)]
pub struct LinuxEnvarsReport {
    pub source: String,
    pub kernel: LinuxKernelContext,
    pub profile: LinuxProcessProfileEvidence,
    pub processes: Vec<LinuxEnvironmentProcess>,
    pub variables: Vec<LinuxEnvironmentVariable>,
    pub processes_considered: usize,
    pub processes_recovered: usize,
    pub variable_count: usize,
    pub process_list_complete: bool,
    pub complete: bool,
    pub max_bytes: u64,
    pub scope: String,
    pub warnings: Vec<LinuxProcessArtifactWarning>,
}

pub fn analyze_envars(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    processes: &LinuxProcessListReport,
    pid: Option<i32>,
    max_bytes: u64,
) -> Result<LinuxEnvarsReport> {
    ensure!(max_bytes > 0, "envars 最大读取字节数必须大于零");
    let profile = exact_profile(kernel)?;
    let selected = selected_processes(processes, pid, true)?;
    let kernel_space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut warnings = process_list_warnings(processes);
    let mut process_records = Vec::new();
    let mut variables = Vec::new();
    let mut complete = processes.complete;
    for process in &selected {
        let result = (|| -> Result<(LinuxEnvironmentProcess, Vec<LinuxEnvironmentVariable>)> {
            let context = open_process_address_space(image, &kernel_space, profile, process)?;
            let env_start = kernel_space.read_u64(context.mm + profile.mm_env_start)?;
            let env_end = kernel_space.read_u64(context.mm + profile.mm_env_end)?;
            let range = read_user_range(&context.space, env_start, env_end, max_bytes)?;
            let strings = decode_nul_strings(&range.bytes);
            let process_variables = strings
                .iter()
                .enumerate()
                .map(|(index, raw)| {
                    let (name, value, has_separator) = raw
                        .split_once('=')
                        .map(|(name, value)| (name.to_owned(), value.to_owned(), true))
                        .unwrap_or_else(|| (raw.clone(), String::new(), false));
                    LinuxEnvironmentVariable {
                        pid: process.pid,
                        process_name: process.name.clone(),
                        index,
                        name,
                        value,
                        raw: raw.clone(),
                        has_separator,
                    }
                })
                .collect::<Vec<_>>();
            let process_record = LinuxEnvironmentProcess {
                task: process.task,
                task_hex: format_address(process.task),
                pid: process.pid,
                tgid: process.tgid,
                name: process.name.clone(),
                mm: context.mm,
                mm_hex: format_address(context.mm),
                env_start,
                env_start_hex: format_address(env_start),
                env_end,
                env_end_hex: format_address(env_end),
                requested_bytes: env_end - env_start,
                recovered_bytes: range.recovered_bytes,
                complete: range.complete(),
                truncated: range.truncated,
                variable_count: process_variables.len(),
                missing_ranges: range.missing_ranges,
            };
            Ok((process_record, process_variables))
        })();
        match result {
            Ok((record, mut recovered)) => {
                complete &= record.complete;
                process_records.push(record);
                variables.append(&mut recovered);
            }
            Err(error) => {
                complete = false;
                warnings.push(LinuxProcessArtifactWarning::new(
                    "envars_unrecoverable",
                    format!("PID {} 环境变量恢复失败：{error:#}", process.pid),
                    Some(process.pid),
                    process.mm,
                ));
            }
        }
    }
    Ok(LinuxEnvarsReport {
        source: "linux.process.mm.env_range".to_owned(),
        kernel: kernel.clone(),
        profile: profile.evidence(kernel),
        processes_considered: selected.len(),
        processes_recovered: process_records.len(),
        variable_count: variables.len(),
        process_list_complete: processes.complete,
        complete,
        max_bytes,
        scope: "active thread-group leaders with a validated mm_struct; exact env_start..env_end ranges; resident present pages only".to_owned(),
        processes: process_records,
        variables,
        warnings,
    })
}

fn decode_nul_strings(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|item| !item.is_empty())
        .map(|item| String::from_utf8_lossy(item).into_owned())
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxProcessMapRecord {
    pub task: u64,
    pub task_hex: String,
    pub pid: i32,
    pub process_name: String,
    pub mm: u64,
    pub mm_hex: String,
    pub vma: u64,
    pub vma_hex: String,
    pub start: u64,
    pub start_hex: String,
    pub end: u64,
    pub end_hex: String,
    pub length: u64,
    pub vm_flags: u64,
    pub permissions: String,
    pub page_offset: u64,
    pub byte_offset: u64,
    pub file: Option<u64>,
    pub file_hex: Option<String>,
    pub dentry: Option<u64>,
    pub dentry_hex: Option<String>,
    pub inode: Option<u64>,
    pub inode_hex: Option<String>,
    pub inode_number: Option<u64>,
    pub path: Option<String>,
    pub path_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxProcessMapSummary {
    pub task: u64,
    pub task_hex: String,
    pub pid: i32,
    pub process_name: String,
    pub mm: u64,
    pub mm_hex: String,
    pub pgd: Option<u64>,
    pub pgd_hex: Option<String>,
    pub pgd_physical: Option<u64>,
    pub pgd_physical_hex: Option<String>,
    pub expected_map_count: Option<u32>,
    pub recovered_map_count: usize,
    pub complete: bool,
    pub stop_reason: String,
}

#[derive(Debug, Serialize)]
pub struct LinuxProcMapsReport {
    pub source: String,
    pub kernel: LinuxKernelContext,
    pub profile: LinuxProcessProfileEvidence,
    pub processes: Vec<LinuxProcessMapSummary>,
    pub records: Vec<LinuxProcessMapRecord>,
    pub processes_considered: usize,
    pub processes_recovered: usize,
    pub record_count: usize,
    pub process_list_complete: bool,
    pub complete: bool,
    pub map_limit: usize,
    pub scope: String,
    pub warnings: Vec<LinuxProcessArtifactWarning>,
}

struct CollectedMapsRef<'a> {
    summary: LinuxProcessMapSummary,
    records: Vec<LinuxProcessMapRecord>,
    context: ProcessAddressSpace<'a>,
}

pub fn analyze_proc_maps(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    processes: &LinuxProcessListReport,
    pid: Option<i32>,
    map_limit: usize,
) -> Result<LinuxProcMapsReport> {
    ensure!(map_limit > 0, "VMA 结果上限必须大于零");
    let profile = exact_profile(kernel)?;
    let selected = selected_processes(processes, pid, true)?;
    let kernel_space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut warnings = process_list_warnings(processes);
    let mut summaries = Vec::new();
    let mut records = Vec::new();
    let mut complete = processes.complete;
    for process in &selected {
        match collect_maps_for_process(
            image,
            &kernel_space,
            profile,
            process,
            map_limit,
            &mut warnings,
        ) {
            Ok(collected) => {
                complete &= collected.summary.complete;
                summaries.push(collected.summary);
                records.extend(collected.records);
            }
            Err(error) => {
                complete = false;
                warnings.push(LinuxProcessArtifactWarning::new(
                    "maps_unrecoverable",
                    format!("PID {} VMA 恢复失败：{error:#}", process.pid),
                    Some(process.pid),
                    process.mm,
                ));
            }
        }
    }
    Ok(LinuxProcMapsReport {
        source: if profile.mm_maple_tree.is_some() {
            "linux.mm.maple_tree"
        } else {
            "linux.mm.mmap_list"
        }
        .to_owned(),
        kernel: kernel.clone(),
        profile: profile.evidence(kernel),
        processes_considered: selected.len(),
        processes_recovered: summaries.len(),
        record_count: records.len(),
        process_list_complete: processes.complete,
        complete,
        map_limit,
        scope: "active thread-group leaders; validated mm_struct and VMA ownership; exact-build layouts; file paths reconstructed from mount/dentry ancestry".to_owned(),
        processes: summaries,
        records,
        warnings,
    })
}

fn collect_maps_for_process<'a>(
    image: &'a MemoryImage,
    kernel_space: &LinuxX64AddressSpace<'a>,
    profile: ExactLinuxProcessProfile,
    process: &LinuxProcessRecord,
    map_limit: usize,
    warnings: &mut Vec<LinuxProcessArtifactWarning>,
) -> Result<CollectedMapsRef<'a>> {
    let context = open_process_address_space(image, kernel_space, profile, process)?;
    let expected_map_count = kernel_space
        .read_u32(context.mm + profile.mm_map_count)
        .ok()
        .filter(|count| *count <= 10_000_000);
    let start_brk = kernel_space
        .read_u64(context.mm + profile.mm_start_brk)
        .ok();
    let brk = kernel_space.read_u64(context.mm + profile.mm_brk).ok();
    let start_stack = kernel_space
        .read_u64(context.mm + profile.mm_start_stack)
        .ok();
    let mut vmas = if let Some(offset) = profile.mm_mmap {
        collect_linked_vmas(
            kernel_space,
            profile,
            context.mm,
            offset,
            map_limit,
            process.pid,
            warnings,
        )?
    } else if let Some(offset) = profile.mm_maple_tree {
        collect_maple_vmas(
            kernel_space,
            context.mm + offset,
            map_limit,
            process.pid,
            warnings,
        )?
    } else {
        bail!("profile 同时缺少 mm_struct.mmap 和 mm_struct.mm_mt")
    };
    vmas.sort_unstable();
    vmas.dedup();
    let limit_reached = vmas.len() >= map_limit
        && expected_map_count.is_some_and(|count| count as usize > vmas.len());
    let mut records = Vec::new();
    let mut structurally_complete = true;
    for vma in vmas {
        match read_vma_record(
            kernel_space,
            profile,
            process,
            context.mm,
            vma,
            start_brk.zip(brk),
            start_stack,
        ) {
            Ok(record) => records.push(record),
            Err(error) => {
                structurally_complete = false;
                warnings.push(LinuxProcessArtifactWarning::new(
                    "invalid_vma",
                    format!("PID {} 的 VMA {vma:#x} 未通过校验：{error:#}", process.pid),
                    Some(process.pid),
                    Some(vma),
                ));
            }
        }
    }
    records.sort_unstable_by_key(|record| (record.start, record.end, record.vma));
    let mut previous_end = 0u64;
    for record in &records {
        if record.start < previous_end {
            structurally_complete = false;
            warnings.push(LinuxProcessArtifactWarning::new(
                "vma_overlap",
                format!(
                    "PID {} 的 VMA {:#x} 从 {:#x} 开始，早于上一 VMA 终点 {:#x}",
                    process.pid, record.vma, record.start, previous_end
                ),
                Some(process.pid),
                Some(record.vma),
            ));
        }
        previous_end = previous_end.max(record.end);
    }
    if let Some(expected) = expected_map_count
        && expected as usize != records.len()
    {
        structurally_complete = false;
        warnings.push(LinuxProcessArtifactWarning::new(
            "map_count_mismatch",
            format!(
                "PID {} 的 mm_struct.map_count={}，恢复到 {} 个有效 VMA",
                process.pid,
                expected,
                records.len()
            ),
            Some(process.pid),
            Some(context.mm),
        ));
    }
    let complete = structurally_complete && !limit_reached;
    let stop_reason = if limit_reached {
        "limit"
    } else if structurally_complete {
        if profile.mm_maple_tree.is_some() {
            "maple_tree_complete"
        } else {
            "null_terminated_list"
        }
    } else {
        "partial"
    };
    Ok(CollectedMapsRef {
        summary: LinuxProcessMapSummary {
            task: process.task,
            task_hex: format_address(process.task),
            pid: process.pid,
            process_name: process.name.clone(),
            mm: context.mm,
            mm_hex: format_address(context.mm),
            pgd: Some(context.pgd),
            pgd_hex: Some(format_address(context.pgd)),
            pgd_physical: Some(context.pgd_physical),
            pgd_physical_hex: Some(format_address(context.pgd_physical)),
            expected_map_count,
            recovered_map_count: records.len(),
            complete,
            stop_reason: stop_reason.to_owned(),
        },
        records,
        context,
    })
}

fn collect_linked_vmas(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxProcessProfile,
    mm: u64,
    mmap_offset: u64,
    limit: usize,
    pid: i32,
    warnings: &mut Vec<LinuxProcessArtifactWarning>,
) -> Result<Vec<u64>> {
    let mut current = space.read_u64(mm + mmap_offset)?;
    let mut previous = 0u64;
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    while current != 0 && output.len() < limit {
        ensure!(is_kernel_pointer(current), "VMA 链指针不是规范内核地址");
        ensure!(seen.insert(current), "VMA 链形成非终止环");
        if let Some(previous_offset) = profile.vma_prev {
            let observed = space.read_u64(current + previous_offset)?;
            if observed != previous {
                warnings.push(LinuxProcessArtifactWarning::new(
                    "vma_prev_mismatch",
                    format!(
                        "PID {pid} 的 VMA {current:#x}.vm_prev={observed:#x}，预期 {previous:#x}"
                    ),
                    Some(pid),
                    Some(current),
                ));
            }
        }
        output.push(current);
        previous = current;
        current = space.read_u64(
            current
                + profile
                    .vma_next
                    .context("链表 profile 缺少 vm_area_struct.vm_next")?,
        )?;
    }
    Ok(output)
}

fn collect_maple_vmas(
    space: &LinuxX64AddressSpace<'_>,
    tree: u64,
    limit: usize,
    pid: i32,
    warnings: &mut Vec<LinuxProcessArtifactWarning>,
) -> Result<Vec<u64>> {
    let flags = space.read_u32(tree + 4)?;
    let expected_depth = (flags & 0x7c) >> 2;
    let root = space.read_u64(tree + 8)?;
    if root == 0 {
        return Ok(Vec::new());
    }
    let mut output = Vec::new();
    let mut seen = HashSet::new();
    parse_maple_entry(
        space,
        root,
        tree & !MAPLE_NODE_POINTER_MASK,
        expected_depth,
        1,
        limit,
        pid,
        &mut seen,
        &mut output,
        warnings,
    )?;
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn parse_maple_entry(
    space: &LinuxX64AddressSpace<'_>,
    entry: u64,
    parent: u64,
    expected_depth: u32,
    depth: u32,
    limit: usize,
    pid: i32,
    seen: &mut HashSet<u64>,
    output: &mut Vec<u64>,
    warnings: &mut Vec<LinuxProcessArtifactWarning>,
) -> Result<()> {
    if output.len() >= limit {
        return Ok(());
    }
    ensure!(seen.insert(entry), "Maple Tree 节点形成环");
    ensure!(depth <= 64, "Maple Tree 深度超过安全上限");
    if depth > expected_depth.max(1) {
        warnings.push(LinuxProcessArtifactWarning::new(
            "maple_depth_mismatch",
            format!("PID {pid} 的 Maple Tree 声明深度 {expected_depth}，遍历到深度 {depth}"),
            Some(pid),
            Some(entry),
        ));
    }
    let pointer = entry & !MAPLE_NODE_POINTER_MASK;
    ensure!(is_kernel_pointer(pointer), "Maple Tree 节点指针无效");
    let parent_entry = space.read_u64(pointer)?;
    ensure!(
        parent_entry & !MAPLE_NODE_POINTER_MASK == parent,
        "Maple Tree parent 反向链接不匹配"
    );
    let node_type = (entry >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK;
    let (slot_offset, slot_count, leaf) = match node_type {
        0 => (0x10, 30usize, true),
        1 => (0x80, 16usize, true),
        2 => (0x80, 16usize, false),
        3 => (0x50, 10usize, false),
        _ => bail!("未知 Maple Tree 节点类型 {node_type}"),
    };
    for index in 0..slot_count {
        if output.len() >= limit {
            break;
        }
        let slot = space.read_u64(pointer + slot_offset + index as u64 * 8)?;
        if slot & !MAPLE_NODE_TYPE_MASK == 0 {
            continue;
        }
        if leaf {
            if is_kernel_pointer(slot) {
                output.push(slot);
            } else {
                warnings.push(LinuxProcessArtifactWarning::new(
                    "invalid_maple_slot",
                    format!("PID {pid} 的 Maple leaf slot 不是内核指针：{slot:#x}"),
                    Some(pid),
                    Some(pointer + slot_offset + index as u64 * 8),
                ));
            }
        } else {
            parse_maple_entry(
                space,
                slot,
                pointer,
                expected_depth,
                depth + 1,
                limit,
                pid,
                seen,
                output,
                warnings,
            )?;
        }
    }
    Ok(())
}

fn read_vma_record(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxProcessProfile,
    process: &LinuxProcessRecord,
    mm: u64,
    vma: u64,
    heap: Option<(u64, u64)>,
    start_stack: Option<u64>,
) -> Result<LinuxProcessMapRecord> {
    ensure!(is_kernel_pointer(vma), "vm_area_struct 指针无效");
    ensure!(
        space.read_u64(vma + profile.vma_mm)? == mm,
        "VMA 不属于目标 mm_struct"
    );
    let start = space.read_u64(vma + profile.vma_start)?;
    let end = space.read_u64(vma + profile.vma_end)?;
    ensure!(start < end, "VMA 起止地址无效");
    ensure!(
        start < USER_ADDRESS_LIMIT && end <= USER_ADDRESS_LIMIT,
        "VMA 超出用户地址范围"
    );
    ensure!(
        start & (PAGE_SIZE - 1) == 0 && end & (PAGE_SIZE - 1) == 0,
        "VMA 未按页对齐"
    );
    let vm_flags = space.read_u64(vma + profile.vma_flags)?;
    let page_offset = space.read_u64(vma + profile.vma_pgoff)?;
    let file = space.read_u64(vma + profile.vma_file)?;
    let mut evidence = if file == 0 {
        FileEvidence::anonymous()
    } else {
        read_file_evidence(space, profile, file)
    };
    if file == 0 {
        if heap.is_some_and(|(start_brk, brk)| start <= start_brk && end >= brk) {
            evidence.path = Some("[heap]".to_owned());
            evidence.path_status = "synthetic_heap_label".to_owned();
        } else if start_stack.is_some_and(|stack| start <= stack && stack < end) {
            evidence.path = Some("[stack]".to_owned());
            evidence.path_status = "synthetic_stack_label".to_owned();
        }
    }
    Ok(LinuxProcessMapRecord {
        task: process.task,
        task_hex: format_address(process.task),
        pid: process.pid,
        process_name: process.name.clone(),
        mm,
        mm_hex: format_address(mm),
        vma,
        vma_hex: format_address(vma),
        start,
        start_hex: format_address(start),
        end,
        end_hex: format_address(end),
        length: end - start,
        vm_flags,
        permissions: format_vm_permissions(vm_flags),
        page_offset,
        byte_offset: page_offset.saturating_mul(PAGE_SIZE),
        file: (file != 0).then_some(file),
        file_hex: (file != 0).then(|| format_address(file)),
        dentry: evidence.dentry,
        dentry_hex: evidence.dentry.map(format_address),
        inode: evidence.inode,
        inode_hex: evidence.inode.map(format_address),
        inode_number: evidence.inode_number,
        path: evidence.path,
        path_status: evidence.path_status,
    })
}

fn format_vm_permissions(flags: u64) -> String {
    format!(
        "{}{}{}{}",
        if flags & 0x1 != 0 { 'r' } else { '-' },
        if flags & 0x2 != 0 { 'w' } else { '-' },
        if flags & 0x4 != 0 { 'x' } else { '-' },
        if flags & 0x8 != 0 { 's' } else { 'p' },
    )
}

#[derive(Debug)]
struct FileEvidence {
    dentry: Option<u64>,
    inode: Option<u64>,
    inode_number: Option<u64>,
    path: Option<String>,
    path_status: String,
}

impl FileEvidence {
    fn anonymous() -> Self {
        Self {
            dentry: None,
            inode: None,
            inode_number: None,
            path: None,
            path_status: "anonymous".to_owned(),
        }
    }
}

fn read_file_evidence(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxProcessProfile,
    file: u64,
) -> FileEvidence {
    if !is_kernel_pointer(file) {
        return FileEvidence {
            dentry: None,
            inode: None,
            inode_number: None,
            path: None,
            path_status: "invalid_file_pointer".to_owned(),
        };
    }
    let mnt = space
        .read_u64(file + profile.file_path + profile.path_mnt)
        .ok();
    let dentry = space
        .read_u64(file + profile.file_path + profile.path_dentry)
        .ok()
        .filter(|address| is_kernel_pointer(*address));
    let inode = space
        .read_u64(file + profile.file_inode)
        .ok()
        .filter(|address| is_kernel_pointer(*address))
        .or_else(|| {
            dentry.and_then(|dentry| {
                space
                    .read_u64(dentry + profile.dentry_inode)
                    .ok()
                    .filter(|address| is_kernel_pointer(*address))
            })
        });
    let inode_number = inode.and_then(|inode| space.read_u64(inode + profile.inode_number).ok());
    let (path, path_status) = match (mnt, dentry) {
        (Some(mnt), Some(dentry)) if is_kernel_pointer(mnt) => {
            match resolve_mounted_path(space, profile, mnt, dentry) {
                Ok(path) => (Some(path), "resolved".to_owned()),
                Err(_) => match resolve_dentry_relative_path(space, profile, dentry) {
                    Ok(path) => (Some(path), "superblock_relative_fallback".to_owned()),
                    Err(_) => (None, "unresolved".to_owned()),
                },
            }
        }
        _ => (None, "invalid_path_pointer".to_owned()),
    };
    FileEvidence {
        dentry,
        inode,
        inode_number,
        path,
        path_status,
    }
}

#[derive(Debug, Serialize)]
pub struct LinuxProcessDirectory {
    pub task: u64,
    pub fs: u64,
    pub mount: u64,
    pub dentry: u64,
    pub path: String,
    pub path_semantics: &'static str,
}

/// Resolve task.fs.pwd using the exact ISF and the existing validated mount walk.
pub fn process_current_directory(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    task: u64,
) -> Result<LinuxProcessDirectory> {
    let isf = kernel
        .symbol_table
        .as_deref()
        .context("工作目录需要精确 Linux ISF")?;
    let profile = exact_profile(kernel)?;
    let space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let fs = space.read_u64(task + isf.field_offset("task_struct", "fs")?)?;
    ensure!(is_kernel_pointer(fs), "task_struct.fs 不可用");
    let pwd = fs + isf.field_offset("fs_struct", "pwd")?;
    let mount = space.read_u64(pwd + profile.path_mnt)?;
    let dentry = space.read_u64(pwd + profile.path_dentry)?;
    let path = resolve_mounted_path(&space, profile, mount, dentry)?;
    Ok(LinuxProcessDirectory {
        task,
        fs,
        mount,
        dentry,
        path,
        path_semantics: "mount_namespace_root_relative; 未根据进程 chroot 裁剪",
    })
}

fn resolve_mounted_path(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxProcessProfile,
    mut mnt: u64,
    mut dentry: u64,
) -> Result<String> {
    ensure!(
        is_kernel_pointer(mnt) && is_kernel_pointer(dentry),
        "path 指针无效"
    );
    let mut components = Vec::new();
    let mut seen = HashSet::new();
    for _ in 0..MAX_PATH_COMPONENTS {
        ensure!(seen.insert((mnt, dentry)), "mount/dentry 祖先链形成环");
        let root = space.read_u64(mnt + profile.vfsmount_root)?;
        ensure!(is_kernel_pointer(root), "vfsmount.mnt_root 无效");
        while dentry != root {
            ensure!(
                components.len() < MAX_PATH_COMPONENTS,
                "路径组件超过安全上限"
            );
            let parent = space.read_u64(dentry + profile.dentry_parent)?;
            ensure!(
                is_kernel_pointer(parent) && parent != dentry,
                "dentry 父链无效"
            );
            components.push(read_dentry_name(space, profile, dentry)?);
            dentry = parent;
        }
        ensure!(mnt >= profile.mount_mnt, "vfsmount 低于 mount.mnt 偏移");
        let mount = mnt - profile.mount_mnt;
        let parent_mount = space.read_u64(mount + profile.mount_parent)?;
        ensure!(is_kernel_pointer(parent_mount), "mount.mnt_parent 无效");
        if parent_mount == mount {
            break;
        }
        dentry = space.read_u64(mount + profile.mount_mountpoint)?;
        ensure!(is_kernel_pointer(dentry), "mount.mnt_mountpoint 无效");
        mnt = parent_mount + profile.mount_mnt;
    }
    assemble_path(components)
}

fn resolve_dentry_relative_path(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxProcessProfile,
    mut dentry: u64,
) -> Result<String> {
    let mut components = Vec::new();
    let mut seen = HashSet::new();
    for _ in 0..MAX_PATH_COMPONENTS {
        ensure!(seen.insert(dentry), "dentry 父链形成环");
        let parent = space.read_u64(dentry + profile.dentry_parent)?;
        ensure!(is_kernel_pointer(parent), "dentry.d_parent 无效");
        if parent == dentry {
            break;
        }
        components.push(read_dentry_name(space, profile, dentry)?);
        dentry = parent;
    }
    assemble_path(components)
}

fn read_dentry_name(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxProcessProfile,
    dentry: u64,
) -> Result<String> {
    let length = usize::try_from(space.read_u32(dentry + profile.dentry_name + profile.qstr_len)?)?;
    ensure!(
        length > 0 && length <= MAX_DENTRY_NAME,
        "dentry qstr 长度无效"
    );
    let pointer = space.read_u64(dentry + profile.dentry_name + profile.qstr_name)?;
    ensure!(is_kernel_pointer(pointer), "dentry qstr.name 指针无效");
    let mut bytes = vec![0u8; length];
    space.read_virtual(pointer, &mut bytes)?;
    ensure!(
        !bytes.iter().any(|byte| *byte == 0 || *byte == b'/'),
        "dentry 名称含 NUL 或路径分隔符"
    );
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn assemble_path(mut components: Vec<String>) -> Result<String> {
    components.reverse();
    let length = components
        .iter()
        .try_fold(1usize, |total, component| {
            total
                .checked_add(component.len())
                .and_then(|value| value.checked_add(1))
        })
        .context("路径长度溢出")?;
    ensure!(length <= MAX_PATH_BYTES, "路径超过安全长度");
    if components.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(format!("/{}", components.join("/")))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxLsofRecord {
    pub task: u64,
    pub task_hex: String,
    pub pid: i32,
    pub process_name: String,
    pub fd: u32,
    pub file: u64,
    pub file_hex: String,
    pub dentry: Option<u64>,
    pub dentry_hex: Option<String>,
    pub inode: Option<u64>,
    pub inode_hex: Option<String>,
    pub inode_number: Option<u64>,
    pub file_type: Option<String>,
    pub file_flags: Option<u32>,
    pub file_mode: Option<u32>,
    pub file_position: Option<i64>,
    pub access_mode: Option<String>,
    pub close_on_exec: Option<bool>,
    pub path: Option<String>,
    pub path_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxLsofProcessSummary {
    pub task: u64,
    pub task_hex: String,
    pub pid: i32,
    pub process_name: String,
    pub files: Option<u64>,
    pub files_hex: Option<String>,
    pub fdtable: Option<u64>,
    pub fdtable_hex: Option<String>,
    pub kernel_max_fds: Option<u32>,
    pub fds_examined: usize,
    pub open_files_recovered: usize,
    pub complete: bool,
    pub stop_reason: String,
}

#[derive(Debug, Serialize)]
pub struct LinuxLsofReport {
    pub source: String,
    pub kernel: LinuxKernelContext,
    pub profile: LinuxProcessProfileEvidence,
    pub processes: Vec<LinuxLsofProcessSummary>,
    pub records: Vec<LinuxLsofRecord>,
    pub processes_considered: usize,
    pub process_count: usize,
    pub record_count: usize,
    pub process_list_complete: bool,
    pub complete: bool,
    pub max_fds: usize,
    pub scope: String,
    pub warnings: Vec<LinuxProcessArtifactWarning>,
}

pub fn analyze_lsof(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    processes: &LinuxProcessListReport,
    pid: Option<i32>,
    max_fds: usize,
) -> Result<LinuxLsofReport> {
    ensure!(max_fds > 0, "FD 扫描上限必须大于零");
    let profile = exact_profile(kernel)?;
    let selected = selected_processes(processes, pid, false)?;
    let space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut warnings = process_list_warnings(processes);
    let mut summaries = Vec::new();
    let mut records = Vec::new();
    let mut complete = processes.complete;
    for process in &selected {
        let result = enumerate_process_fds(&space, profile, process, max_fds);
        match result {
            Ok((summary, mut process_records)) => {
                complete &= summary.complete;
                summaries.push(summary);
                records.append(&mut process_records);
            }
            Err(error) => {
                complete = false;
                warnings.push(LinuxProcessArtifactWarning::new(
                    "fdtable_unrecoverable",
                    format!("PID {} FD 表恢复失败：{error:#}", process.pid),
                    Some(process.pid),
                    Some(process.task),
                ));
            }
        }
    }
    Ok(LinuxLsofReport {
        source: "linux.task.files.fdtable".to_owned(),
        kernel: kernel.clone(),
        profile: profile.evidence(kernel),
        processes_considered: selected.len(),
        process_count: summaries.len(),
        record_count: records.len(),
        process_list_complete: processes.complete,
        complete,
        max_fds,
        scope: "active thread-group leaders; validated files_struct/fdtable pointers; open_fds bitmap and file/path/dentry ancestry".to_owned(),
        processes: summaries,
        records,
        warnings,
    })
}

fn enumerate_process_fds(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactLinuxProcessProfile,
    process: &LinuxProcessRecord,
    max_fds: usize,
) -> Result<(LinuxLsofProcessSummary, Vec<LinuxLsofRecord>)> {
    let files = space.read_u64(process.task + profile.task_files)?;
    if files == 0 {
        return Ok((
            LinuxLsofProcessSummary {
                task: process.task,
                task_hex: format_address(process.task),
                pid: process.pid,
                process_name: process.name.clone(),
                files: None,
                files_hex: None,
                fdtable: None,
                fdtable_hex: None,
                kernel_max_fds: Some(0),
                fds_examined: 0,
                open_files_recovered: 0,
                complete: true,
                stop_reason: "no_files_struct".to_owned(),
            },
            Vec::new(),
        ));
    }
    ensure!(is_kernel_pointer(files), "task_struct.files 指针无效");
    let fdtable = space.read_u64(files + profile.files_fdt)?;
    ensure!(is_kernel_pointer(fdtable), "files_struct.fdt 指针无效");
    let kernel_max_fds = space.read_u32(fdtable + profile.fdtable_max_fds)?;
    ensure!(kernel_max_fds <= 16_777_216, "fdtable.max_fds 超出安全范围");
    let examine = usize::try_from(kernel_max_fds)?.min(max_fds);
    let truncated = usize::try_from(kernel_max_fds)? > examine;
    let fd_array = space.read_u64(fdtable + profile.fdtable_fd)?;
    let open_fds = space.read_u64(fdtable + profile.fdtable_open_fds).ok();
    let close_on_exec = space.read_u64(fdtable + profile.fdtable_close_on_exec).ok();
    if examine > 0 {
        ensure!(is_kernel_pointer(fd_array), "fdtable.fd 指针无效");
    }
    let mut records = Vec::new();
    for fd in 0..examine {
        if let Some(bitmap) = open_fds
            && is_kernel_pointer(bitmap)
            && !read_bitmap_bit(space, bitmap, fd).unwrap_or(true)
        {
            continue;
        }
        let file = space.read_u64(fd_array + fd as u64 * 8)?;
        if file == 0 {
            continue;
        }
        ensure!(is_kernel_pointer(file), "fd[{fd}] FILE 指针无效");
        let evidence = read_file_evidence(space, profile, file);
        let inode_mode = evidence
            .inode
            .and_then(|inode| read_u16(space, inode + profile.inode_mode).ok());
        let file_flags = space.read_u32(file + profile.file_flags).ok();
        let file_mode = space.read_u32(file + profile.file_mode).ok();
        let file_position = space
            .read_u64(file + profile.file_pos)
            .ok()
            .map(|value| value as i64);
        let close_on_exec = close_on_exec
            .filter(|bitmap| is_kernel_pointer(*bitmap))
            .and_then(|bitmap| read_bitmap_bit(space, bitmap, fd).ok());
        records.push(LinuxLsofRecord {
            task: process.task,
            task_hex: format_address(process.task),
            pid: process.pid,
            process_name: process.name.clone(),
            fd: fd as u32,
            file,
            file_hex: format_address(file),
            dentry: evidence.dentry,
            dentry_hex: evidence.dentry.map(format_address),
            inode: evidence.inode,
            inode_hex: evidence.inode.map(format_address),
            inode_number: evidence.inode_number,
            file_type: inode_mode.and_then(inode_type).map(str::to_owned),
            file_flags,
            file_mode,
            file_position,
            access_mode: file_flags.map(file_access_mode),
            close_on_exec,
            path: evidence.path,
            path_status: evidence.path_status,
        });
    }
    Ok((
        LinuxLsofProcessSummary {
            task: process.task,
            task_hex: format_address(process.task),
            pid: process.pid,
            process_name: process.name.clone(),
            files: Some(files),
            files_hex: Some(format_address(files)),
            fdtable: Some(fdtable),
            fdtable_hex: Some(format_address(fdtable)),
            kernel_max_fds: Some(kernel_max_fds),
            fds_examined: examine,
            open_files_recovered: records.len(),
            complete: !truncated,
            stop_reason: if truncated {
                "max_fds_limit"
            } else {
                "max_fds"
            }
            .to_owned(),
        },
        records,
    ))
}

fn read_bitmap_bit(space: &LinuxX64AddressSpace<'_>, bitmap: u64, index: usize) -> Result<bool> {
    let word = space.read_u64(bitmap + (index / 64) as u64 * 8)?;
    Ok(word & (1u64 << (index % 64)) != 0)
}

fn read_u16(space: &LinuxX64AddressSpace<'_>, address: u64) -> Result<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn inode_type(mode: u16) -> Option<&'static str> {
    Some(match mode & 0xf000 {
        0x1000 => "fifo",
        0x2000 => "character_device",
        0x4000 => "directory",
        0x6000 => "block_device",
        0x8000 => "regular",
        0xa000 => "symlink",
        0xc000 => "socket",
        _ => return None,
    })
}

fn file_access_mode(flags: u32) -> String {
    match flags & 3 {
        0 => "read".to_owned(),
        1 => "write".to_owned(),
        2 => "read_write".to_owned(),
        _ => "invalid".to_owned(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxProcessDumpRegion {
    pub pid: i32,
    pub process_name: String,
    pub start: u64,
    pub start_hex: String,
    pub end: u64,
    pub end_hex: String,
    pub permissions: String,
    pub source_path: Option<String>,
    pub output_path: Option<String>,
    pub logical_size: u64,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
    pub complete: bool,
    pub skipped: bool,
    pub skip_reason: Option<String>,
    pub sha256: Option<String>,
    pub sha256_scope: Option<String>,
    pub recovered_sha256: Option<String>,
    pub missing_ranges: Vec<LinuxVirtualMissingRange>,
}

#[derive(Debug, Serialize)]
pub struct LinuxProcDumpReport {
    pub source: String,
    pub kernel: LinuxKernelContext,
    pub profile: LinuxProcessProfileEvidence,
    pub pid: i32,
    pub process_name: String,
    pub output_directory: String,
    pub regions: Vec<LinuxProcessDumpRegion>,
    pub map_count: usize,
    pub regions_written: usize,
    pub regions_complete: usize,
    pub regions_partial: usize,
    pub regions_skipped: usize,
    pub total_logical_bytes: u64,
    pub total_recovered_bytes: u64,
    pub complete: bool,
    pub map_limit: usize,
    pub max_region_size: u64,
    pub max_total_size: u64,
    pub scope: String,
    pub warnings: Vec<LinuxProcessArtifactWarning>,
}

#[allow(clippy::too_many_arguments)]
pub fn dump_process(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    processes: &LinuxProcessListReport,
    pid: i32,
    output_directory: &Path,
    map_limit: usize,
    max_region_size: u64,
    max_total_size: u64,
    force: bool,
) -> Result<LinuxProcDumpReport> {
    ensure!(map_limit > 0, "VMA 结果上限必须大于零");
    ensure!(max_region_size > 0, "单个 VMA 导出上限必须大于零");
    ensure!(max_total_size > 0, "进程导出总上限必须大于零");
    let profile = exact_profile(kernel)?;
    let process = selected_processes(processes, Some(pid), true)?[0];
    let kernel_space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut warnings = process_list_warnings(processes);
    let collected = collect_maps_for_process(
        image,
        &kernel_space,
        profile,
        process,
        map_limit,
        &mut warnings,
    )?;
    let mut output_policy = OutputPolicy::new(force);
    for source in image.sources() {
        output_policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    let mut directory_target = OutputTarget::directory("linux.proc.dump", output_directory);
    for (index, mapping) in collected.records.iter().enumerate() {
        let basename = format!(
            "{index:04}_{:016x}-{:016x}_{}.dmp",
            mapping.start, mapping.end, mapping.permissions
        );
        directory_target = directory_target
            .with_owned_file(&basename)
            .with_owned_file(format!("{basename}.partial"));
    }
    output_policy.output(directory_target);
    output_policy.prepare_directories()?;
    let mut total_logical_bytes = 0u64;
    let mut total_recovered_bytes = 0u64;
    let mut regions = Vec::new();
    for (index, mapping) in collected.records.iter().enumerate() {
        let length = mapping.length;
        let skip_reason = if length > max_region_size {
            Some(format!("VMA 长度 {length} 超过单区上限 {max_region_size}"))
        } else if total_logical_bytes
            .checked_add(length)
            .is_none_or(|total| total > max_total_size)
        {
            Some(format!("加入该 VMA 后超过总上限 {max_total_size}"))
        } else {
            None
        };
        if let Some(reason) = skip_reason {
            regions.push(LinuxProcessDumpRegion {
                pid,
                process_name: process.name.clone(),
                start: mapping.start,
                start_hex: mapping.start_hex.clone(),
                end: mapping.end,
                end_hex: mapping.end_hex.clone(),
                permissions: mapping.permissions.clone(),
                source_path: mapping.path.clone(),
                output_path: None,
                logical_size: length,
                recovered_bytes: 0,
                missing_bytes: length,
                complete: false,
                skipped: true,
                skip_reason: Some(reason),
                sha256: None,
                sha256_scope: None,
                recovered_sha256: None,
                missing_ranges: Vec::new(),
            });
            continue;
        }
        total_logical_bytes += length;
        let basename = format!(
            "{index:04}_{:016x}-{:016x}_{}.dmp",
            mapping.start, mapping.end, mapping.permissions
        );
        let final_path = output_directory.join(&basename);
        let partial_path = output_directory.join(format!("{basename}.partial"));
        let expected_complete = virtual_region_is_fully_mapped(
            image,
            &collected.context.space,
            mapping.start,
            mapping.end,
        );
        let selected_path = if expected_complete {
            &final_path
        } else {
            &partial_path
        };
        let mut dumped = None;
        output_policy.write_file_atomic(selected_path, |output| {
            let result =
                dump_virtual_region(&collected.context.space, mapping.start, mapping.end, output)?;
            ensure!(
                result.complete == expected_complete,
                "VMA 页映射在预检与发布之间发生变化；拒绝发布后缀语义不正确的输出"
            );
            dumped = Some(result);
            Ok(())
        })?;
        let dumped = dumped.context("VMA 导出未生成结果")?;
        let output_path = selected_path.to_path_buf();
        if force {
            let stale_path = if dumped.complete {
                &partial_path
            } else {
                &final_path
            };
            output_policy.remove_owned_file(stale_path)?;
        }
        total_recovered_bytes += dumped.recovered_bytes;
        regions.push(LinuxProcessDumpRegion {
            pid,
            process_name: process.name.clone(),
            start: mapping.start,
            start_hex: mapping.start_hex.clone(),
            end: mapping.end,
            end_hex: mapping.end_hex.clone(),
            permissions: mapping.permissions.clone(),
            source_path: mapping.path.clone(),
            output_path: Some(output_path.display().to_string()),
            logical_size: length,
            recovered_bytes: dumped.recovered_bytes,
            missing_bytes: length - dumped.recovered_bytes,
            complete: dumped.complete,
            skipped: false,
            skip_reason: None,
            sha256: Some(dumped.logical_sha256),
            sha256_scope: Some(
                if dumped.complete {
                    "complete_virtual_region"
                } else {
                    "logical_region_with_zero_filled_missing_pages"
                }
                .to_owned(),
            ),
            recovered_sha256: Some(dumped.recovered_sha256),
            missing_ranges: dumped.missing_ranges,
        });
    }
    let regions_written = regions.iter().filter(|region| !region.skipped).count();
    let regions_complete = regions
        .iter()
        .filter(|region| !region.skipped && region.complete)
        .count();
    let regions_partial = regions
        .iter()
        .filter(|region| !region.skipped && !region.complete)
        .count();
    let regions_skipped = regions.iter().filter(|region| region.skipped).count();
    let complete = processes.complete
        && collected.summary.complete
        && regions_partial == 0
        && regions_skipped == 0;
    Ok(LinuxProcDumpReport {
        source: "linux.process.present_pages.vma_dump".to_owned(),
        kernel: kernel.clone(),
        profile: profile.evidence(kernel),
        pid,
        process_name: process.name.clone(),
        output_directory: output_directory.display().to_string(),
        map_count: collected.records.len(),
        regions_written,
        regions_complete,
        regions_partial,
        regions_skipped,
        total_logical_bytes,
        total_recovered_bytes,
        complete,
        map_limit,
        max_region_size,
        max_total_size,
        scope: "one sparse-safe file per validated VMA; present pages copied, missing pages zero-filled and retained only in .partial outputs".to_owned(),
        regions,
        warnings,
    })
}

struct DumpedRegion {
    recovered_bytes: u64,
    complete: bool,
    logical_sha256: String,
    recovered_sha256: String,
    missing_ranges: Vec<LinuxVirtualMissingRange>,
}

fn dump_virtual_region(
    space: &LinuxX64AddressSpace<'_>,
    start: u64,
    end: u64,
    output: &mut File,
) -> Result<DumpedRegion> {
    ensure!(start < end, "导出 VMA 范围为空");
    let mut writer = BufWriter::new(output);
    let mut logical_hasher = Sha256::new();
    let mut recovered_hasher = Sha256::new();
    let zero_page = [0u8; PAGE_SIZE as usize];
    let mut buffer = [0u8; PAGE_SIZE as usize];
    let mut address = start;
    let mut recovered_bytes = 0u64;
    let mut missing_ranges = Vec::new();
    while address < end {
        let take = usize::try_from((end - address).min(PAGE_SIZE))?;
        let file_offset = address - start;
        if space.read_virtual(address, &mut buffer[..take]).is_ok() {
            writer.write_all(&buffer[..take])?;
            logical_hasher.update(&buffer[..take]);
            recovered_hasher.update(&buffer[..take]);
            recovered_bytes += take as u64;
        } else {
            writer.write_all(&zero_page[..take])?;
            logical_hasher.update(&zero_page[..take]);
            push_missing_range(&mut missing_ranges, address, file_offset, take as u64);
        }
        address += take as u64;
    }
    writer.flush()?;
    Ok(DumpedRegion {
        recovered_bytes,
        complete: missing_ranges.is_empty(),
        logical_sha256: hex::encode(logical_hasher.finalize()),
        recovered_sha256: hex::encode(recovered_hasher.finalize()),
        missing_ranges,
    })
}

fn virtual_region_is_fully_mapped(
    image: &MemoryImage,
    space: &LinuxX64AddressSpace<'_>,
    start: u64,
    end: u64,
) -> bool {
    let mut address = start;
    while address < end {
        let take = (end - address).min(PAGE_SIZE);
        let Ok(physical) = space.translate(address) else {
            return false;
        };
        let Some(last_physical) = physical.checked_add(take - 1) else {
            return false;
        };
        if !image.contains_physical(physical) || !image.contains_physical(last_physical) {
            return false;
        }
        address += take;
    }
    true
}

pub(crate) struct BashProcessMemory<'a> {
    pub process: &'a LinuxProcessRecord,
    pub maps: Vec<LinuxProcessMapRecord>,
    pub space: LinuxX64AddressSpace<'a>,
}

pub(crate) fn bash_process_memory<'a>(
    image: &'a MemoryImage,
    kernel: &LinuxKernelContext,
    processes: &'a LinuxProcessListReport,
    pid: Option<i32>,
    map_limit: usize,
    warnings: &mut Vec<LinuxProcessArtifactWarning>,
) -> Result<Vec<BashProcessMemory<'a>>> {
    let profile = exact_profile(kernel)?;
    let selected = selected_processes(processes, pid, true)?;
    let kernel_space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let mut output = Vec::new();
    for process in selected
        .into_iter()
        .filter(|process| process.name == "bash")
    {
        let collected =
            collect_maps_for_process(image, &kernel_space, profile, process, map_limit, warnings)?;
        output.push(BashProcessMemory {
            process,
            maps: collected.records,
            space: collected.context.space,
        });
    }
    Ok(output)
}

pub(crate) fn read_process_range_for_bash(
    space: &LinuxX64AddressSpace<'_>,
    start: u64,
    end: u64,
    max_bytes: u64,
) -> Result<(Vec<u8>, u64, Vec<LinuxVirtualMissingRange>, bool)> {
    let read = read_user_range(space, start, end, max_bytes)?;
    Ok((
        read.bytes,
        read.recovered_bytes,
        read.missing_ranges,
        read.truncated,
    ))
}

pub(crate) fn read_process_c_string(
    space: &LinuxX64AddressSpace<'_>,
    address: u64,
    max_bytes: usize,
) -> Result<String> {
    ensure!(
        address > 0 && address < USER_ADDRESS_LIMIT,
        "字符串指针不在用户地址范围"
    );
    ensure!(max_bytes > 0, "字符串上限必须大于零");
    let mut bytes = Vec::new();
    for index in 0..max_bytes {
        let mut byte = [0u8; 1];
        space.read_virtual(address + index as u64, &mut byte)?;
        if byte[0] == 0 {
            break;
        }
        ensure!(
            byte[0] >= 0x20 || matches!(byte[0], b'\t' | b'\n' | b'\r'),
            "字符串包含非文本控制字节"
        );
        bytes.push(byte[0]);
    }
    ensure!(!bytes.is_empty(), "字符串为空");
    ensure!(bytes.len() < max_bytes, "字符串未在上限内终止");
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn format_address(address: u64) -> String {
    format!("0x{address:016x}")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn exact_profiles_keep_dwarf_offsets() {
        let old = ExactLinuxProcessProfile::for_banner(UBUNTU_4_13_0_36_XENIAL).unwrap();
        assert_eq!(old.task_files, 0xae8);
        assert_eq!(old.mm_arg_start, 0x130);
        assert_eq!(old.vma_file, 0xa0);
        let middle = ExactLinuxProcessProfile::for_banner(UBUNTU_5_4_0_84_BIONIC).unwrap();
        assert_eq!(middle.task_files, 0xac0);
        assert_eq!(middle.mm_env_end, 0x150);
        let new = ExactLinuxProcessProfile::for_banner(UBUNTU_6_8_0_49_NOBLE).unwrap();
        assert_eq!(new.task_files, 0xc08);
        assert_eq!(new.mm_maple_tree, Some(0x40));
        assert_eq!(new.file_path, 0x98);
        assert!(ExactLinuxProcessProfile::for_banner("Linux version similar").is_none());
    }

    #[test]
    fn decodes_nul_separated_process_strings() {
        assert_eq!(
            decode_nul_strings(b"bash\0-c\0echo ok\0\0"),
            ["bash", "-c", "echo ok"]
        );
    }

    #[test]
    fn merges_adjacent_missing_pages() {
        let mut ranges = Vec::new();
        push_missing_range(&mut ranges, 0x4000, 0, 0x1000);
        push_missing_range(&mut ranges, 0x5000, 0x1000, 0x1000);
        push_missing_range(&mut ranges, 0x7000, 0x3000, 0x1000);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].length, 0x2000);
    }

    #[test]
    fn formats_linux_vma_permissions() {
        assert_eq!(format_vm_permissions(0), "---p");
        assert_eq!(format_vm_permissions(0x1 | 0x2 | 0x4), "rwxp");
        assert_eq!(format_vm_permissions(0x1 | 0x8), "r--s");
    }

    #[test]
    fn assembles_root_and_nested_paths() {
        assert_eq!(assemble_path(Vec::new()).unwrap(), "/");
        assert_eq!(
            assemble_path(vec!["passwd".to_owned(), "etc".to_owned()]).unwrap(),
            "/etc/passwd"
        );
    }

    #[test]
    fn psaux_keeps_process_rows_when_exact_argv_layout_is_unavailable() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-linux-psaux-{}-{nonce}.raw",
            std::process::id()
        ));
        fs::write(&path, vec![0u8; 0x2000]).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let kernel = LinuxKernelContext {
            architecture: "x86_64_4level".to_owned(),
            banner: "Linux version 6.18.0-test #1 SMP".to_owned(),
            banner_physical_address: 0,
            directory_table_base: 0x1000,
            page_table_source: "test".to_owned(),
            vmcoreinfo_physical_address: None,
            init_task: 0xffff_8000_0000_0000,
            init_task_physical: 0,
            profile_source: "test".to_owned(),
            profile_fingerprint: "test".to_owned(),
            btf_physical_address: None,
            task_struct_size: 0x1000,
            task_struct_offsets: BTreeMap::new(),
            symbol_table: None,
            system_map: None,
        };
        let process = |pid, ppid, name: &str, mm| LinuxProcessRecord {
            task: 0xffff_8000_0000_0000 + pid as u64 * 0x1000,
            list_entry: 0xffff_8000_1000_0000 + pid as u64 * 0x1000,
            pid,
            tgid: pid,
            ppid,
            name: name.to_owned(),
            state: "running".to_owned(),
            state_raw: 0,
            exit_state: Some(0),
            flags: Some(0),
            mm,
            kernel_thread: Some(mm.is_none()),
            start_time_ns: Some(pid as u64 * 1000),
        };
        let processes = LinuxProcessListReport {
            kernel: kernel.clone(),
            processes: vec![
                process(1, Some(0), "systemd", Some(0xffff_8000_2000_0000)),
                process(2, Some(0), "kthreadd", None),
            ],
            complete: true,
            stop_reason: crate::linux::LinuxProcessListStopReason::ListHead,
            warnings: Vec::new(),
            bytes_scanned: 0,
            scan_seconds: 0.0,
            scan_gib_per_second: 0.0,
        };

        let report = analyze_psaux(&image, &kernel, &processes, None, 4096).unwrap();
        assert_eq!(report.records.len(), 2);
        assert_eq!(report.user_cmdline_fallback_count, 1);
        assert_eq!(report.kernel_thread_count, 1);
        assert_eq!(report.command_lines_recovered, 0);
        assert_eq!(report.records[0].command_line, "systemd");
        assert_eq!(report.records[1].command_line, "[kthreadd]");
        assert!(!report.complete);
        assert_eq!(
            report
                .warnings
                .iter()
                .filter(|warning| warning.kind == "psaux_cmdline_profile_unavailable")
                .count(),
            1
        );
        drop(image);
        fs::remove_file(path).unwrap();
    }
}
