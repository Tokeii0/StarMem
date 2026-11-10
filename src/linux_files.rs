use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use crate::image::MemoryImage;
use crate::linux::{
    LinuxKernelContext, LinuxX64AddressSpace, UBUNTU_4_13_0_36_XENIAL, UBUNTU_5_4_0_84_BIONIC,
    UBUNTU_6_8_0_49_NOBLE, is_kernel_pointer,
};

const MAX_DENTRY_NAME: usize = 255;
const MAX_FILESYSTEM_NAME: usize = 64;
const MAX_SUPERBLOCK_ID: usize = 32;
const MAX_PATH_BYTES: usize = 32 * 1024;
const MAX_REPORTED_WARNINGS: usize = 256;
const MAX_WARNING_SAMPLES_PER_KIND: usize = 8;
const MAX_CHILD_LINKS_PER_DIRECTORY: usize = 1_000_000;
const MAX_CONSECUTIVE_UNTRUSTED_CHILDREN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxFileScanStopReason {
    SuperBlockListHead,
    Limit,
    Partial,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxFileScanWarning {
    pub kind: String,
    pub message: String,
    pub address: Option<u64>,
    pub address_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxFileScanRecord {
    pub source: String,
    pub superblock: u64,
    pub superblock_hex: String,
    pub superblock_physical: Option<u64>,
    pub superblock_physical_hex: Option<String>,
    pub filesystem: Option<String>,
    pub superblock_id: Option<String>,
    pub device: String,
    pub device_raw: u32,
    pub device_major: u32,
    pub device_minor: u32,
    pub dentry: u64,
    pub dentry_hex: String,
    pub dentry_physical: Option<u64>,
    pub dentry_physical_hex: Option<String>,
    pub parent_dentry: u64,
    pub parent_dentry_hex: String,
    pub observed_parent_dentry: Option<u64>,
    pub observed_parent_dentry_hex: Option<String>,
    pub inode: u64,
    pub inode_hex: String,
    pub inode_physical: Option<u64>,
    pub inode_physical_hex: Option<String>,
    pub inode_number: Option<u64>,
    pub name: Option<String>,
    pub name_bytes_hex: Option<String>,
    pub name_utf8_valid: Option<bool>,
    pub name_status: String,
    /// A path rooted at this record's superblock, not an invented host-global path.
    pub path: Option<String>,
    pub path_status: String,
    pub path_scope: String,
    pub membership_status: String,
    pub file_type: String,
    pub mode: u16,
    pub mode_string: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub link_count: Option<u32>,
    pub size: Option<i64>,
    pub cached_pages: Option<u64>,
    pub accessed_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub changed_utc: Option<String>,
    pub metadata_complete: bool,
    pub deleted: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct LinuxFileScanReport {
    pub kernel: LinuxKernelContext,
    pub source: String,
    pub scope: String,
    pub path_semantics: String,
    pub profile_source: String,
    pub profile_fingerprint: String,
    pub record_count: usize,
    pub records: Vec<LinuxFileScanRecord>,
    pub complete: bool,
    pub structural_complete: bool,
    pub limit_reached: bool,
    pub stop_reason: LinuxFileScanStopReason,
    pub superblocks_seen: usize,
    pub superblocks_walked: usize,
    pub dentries_seen: usize,
    pub negative_dentries: usize,
    pub invalid_dentries: usize,
    pub dentry_validation_anomalies: usize,
    pub unique_inodes: usize,
    pub warning_count: usize,
    pub warning_counts: BTreeMap<String, usize>,
    pub warnings: Vec<LinuxFileScanWarning>,
    pub bytes_scanned: u64,
    pub discovery_scan_seconds: f64,
    pub discovery_scan_gib_per_second: f64,
    pub traversal_seconds: f64,
}

#[derive(Debug, Clone, Copy)]
enum DentryChildrenKind {
    List,
    HList,
}

#[derive(Debug, Clone, Copy)]
struct LinuxVfsProfile {
    source: &'static str,
    fingerprint: &'static str,
    init_task_symbol: u64,
    super_blocks_symbol: u64,
    super_block_size: u64,
    super_block_root: u64,
    super_block_device: u64,
    super_block_type: u64,
    file_system_type_name: u64,
    super_block_id: u64,
    dentry_size: u64,
    dentry_parent: u64,
    dentry_name: u64,
    qstr_len: u64,
    qstr_name: u64,
    dentry_inode: u64,
    dentry_super_block: u64,
    dentry_child_node: u64,
    dentry_children_head: u64,
    dentry_children_kind: DentryChildrenKind,
    inode_size: u64,
    inode_mode: u64,
    inode_uid: u64,
    inode_gid: u64,
    inode_super_block: u64,
    inode_mapping: u64,
    inode_number: u64,
    inode_link_count: u64,
    inode_file_size: u64,
    inode_access_time: u64,
    inode_modify_time: u64,
    inode_change_time: u64,
    address_space_nrpages: u64,
}

impl LinuxVfsProfile {
    fn from_isf(isf: &crate::linux_symbols::LinuxIsf) -> Result<Self> {
        let (dentry_child_node, dentry_children_head, dentry_children_kind) =
            if let (Some(child), Some(children)) = (
                isf.optional_field_offset("dentry", "d_child")?,
                isf.optional_field_offset("dentry", "d_subdirs")?,
            ) {
                (child, children, DentryChildrenKind::List)
            } else {
                (
                    isf.field_offset("dentry", "d_sib")?,
                    isf.field_offset("dentry", "d_children")?,
                    DentryChildrenKind::HList,
                )
            };
        Ok(Self {
            source: "volatility3_isf_vfs",
            fingerprint: "Volatility 3 ISF; exact linux_banner; runtime-validated VFS layout",
            init_task_symbol: isf.symbol_address("init_task")?,
            super_blocks_symbol: isf.symbol_address("super_blocks")?,
            super_block_size: isf.type_size("super_block")?,
            super_block_root: isf.field_offset("super_block", "s_root")?,
            super_block_device: isf.field_offset("super_block", "s_dev")?,
            super_block_type: isf.field_offset("super_block", "s_type")?,
            file_system_type_name: isf.field_offset("file_system_type", "name")?,
            super_block_id: isf.field_offset("super_block", "s_id")?,
            dentry_size: isf.type_size("dentry")?,
            dentry_parent: isf.field_offset("dentry", "d_parent")?,
            dentry_name: isf.field_offset("dentry", "d_name")?,
            qstr_len: isf.field_offset("qstr", "len")?,
            qstr_name: isf.field_offset("qstr", "name")?,
            dentry_inode: isf.field_offset("dentry", "d_inode")?,
            dentry_super_block: isf.field_offset("dentry", "d_sb")?,
            dentry_child_node,
            dentry_children_head,
            dentry_children_kind,
            inode_size: isf.type_size("inode")?,
            inode_mode: isf.field_offset("inode", "i_mode")?,
            inode_uid: isf.field_offset("inode", "i_uid")?,
            inode_gid: isf.field_offset("inode", "i_gid")?,
            inode_super_block: isf.field_offset("inode", "i_sb")?,
            inode_mapping: isf.field_offset("inode", "i_mapping")?,
            inode_number: isf.field_offset("inode", "i_ino")?,
            inode_link_count: isf.field_offset("inode", "i_nlink")?,
            inode_file_size: isf.field_offset("inode", "i_size")?,
            inode_access_time: isf.field_offset_any("inode", &["i_atime", "__i_atime"])?,
            inode_modify_time: isf.field_offset_any("inode", &["i_mtime", "__i_mtime"])?,
            inode_change_time: isf.field_offset_any("inode", &["i_ctime", "__i_ctime"])?,
            address_space_nrpages: isf.field_offset("address_space", "nrpages")?,
        })
    }

    fn validate(self) -> Result<Self> {
        ensure!(
            is_kernel_pointer(self.init_task_symbol),
            "init_task 链接地址无效"
        );
        ensure!(
            is_kernel_pointer(self.super_blocks_symbol),
            "super_blocks 链接地址无效"
        );
        ensure!(
            self.super_block_root + 8 <= self.super_block_size
                && self.super_block_id + MAX_SUPERBLOCK_ID as u64 <= self.super_block_size,
            "super_block 布局越界"
        );
        ensure!(
            self.dentry_inode + 8 <= self.dentry_size
                && self.dentry_super_block + 8 <= self.dentry_size
                && self.dentry_children_head + 8 <= self.dentry_size,
            "dentry 布局越界"
        );
        ensure!(
            self.inode_change_time + 16 <= self.inode_size,
            "inode 布局越界"
        );
        Ok(self)
    }
}

#[derive(Default)]
struct FileScanStats {
    superblocks_seen: usize,
    superblocks_walked: usize,
    dentries_seen: usize,
    negative_dentries: usize,
    invalid_dentries: usize,
}

#[derive(Default)]
struct WarningState {
    records: Vec<LinuxFileScanWarning>,
    samples_per_kind: BTreeMap<String, usize>,
    total: usize,
    structural: bool,
}

impl WarningState {
    fn push(
        &mut self,
        kind: impl Into<String>,
        message: impl Into<String>,
        address: Option<u64>,
        structural: bool,
    ) {
        let kind = kind.into();
        self.total += 1;
        self.structural |= structural;
        let samples = self.samples_per_kind.entry(kind.clone()).or_default();
        *samples += 1;
        if self.records.len() < MAX_REPORTED_WARNINGS && *samples <= MAX_WARNING_SAMPLES_PER_KIND {
            self.records.push(LinuxFileScanWarning {
                kind,
                message: message.into(),
                address,
                address_hex: address.map(format_address),
            });
        }
    }

    fn finish(&mut self) {
        if self.total > self.records.len() {
            let omitted = self.total - self.records.len();
            self.records.push(LinuxFileScanWarning {
                kind: "warning_limit".to_owned(),
                message: format!("另有 {omitted} 条重复结构告警未展开"),
                address: None,
                address_hex: None,
            });
        }
    }
}

struct SuperBlockEvidence {
    address: u64,
    physical: Option<u64>,
    filesystem: Option<String>,
    id: Option<String>,
    device_raw: u32,
}

struct PendingDentry {
    address: u64,
    parent: u64,
    parent_path: Option<String>,
    membership_trusted: bool,
    depth: usize,
}

struct ChildLinkCandidate {
    address: u64,
    membership_trusted: bool,
}

struct DecodedName {
    text: String,
    utf8_valid: bool,
    bytes_hex: String,
}

struct DentryRecordEvidence {
    observed_parent: Option<u64>,
    name: Option<DecodedName>,
    path: Option<String>,
    path_status: String,
    inode: u64,
    mode: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DentryEvidenceQuality {
    SemanticRecovery,
    TrustedUnresolved,
    Resolved,
}

struct VisitedDentry {
    quality: DentryEvidenceQuality,
    record_index: Option<usize>,
}

struct FileScanner<'a> {
    space: LinuxX64AddressSpace<'a>,
    profile: LinuxVfsProfile,
    limit: usize,
    records: Vec<LinuxFileScanRecord>,
    visited_dentries: HashMap<u64, VisitedDentry>,
    stats: FileScanStats,
    warnings: WarningState,
    limit_reached: bool,
}

pub fn scan_files(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    bytes_scanned: u64,
    discovery_scan_seconds: f64,
    discovery_scan_gib_per_second: f64,
    limit: usize,
) -> Result<LinuxFileScanReport> {
    let profile = if let Some(isf) = kernel.symbol_table.as_deref() {
        LinuxVfsProfile::from_isf(isf).or_else(|isf_error| {
            exact_vfs_profile(&kernel.banner).with_context(|| {
                format!(
                    "精确匹配的 Volatility 3 ISF 缺少可用 VFS 布局（{isf_error:#}），且当前 Linux 构建没有内置完整 banner VFS profile"
                )
            })
        })?
    } else {
        exact_vfs_profile(&kernel.banner)
            .context("当前 Linux 构建没有精确匹配的 Volatility 3 ISF 或完整 banner VFS profile")?
    }
    .validate()?;
    scan_files_with_profile(
        image,
        kernel,
        profile,
        bytes_scanned,
        discovery_scan_seconds,
        discovery_scan_gib_per_second,
        limit,
    )
}

fn scan_files_with_profile(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    profile: LinuxVfsProfile,
    bytes_scanned: u64,
    discovery_scan_seconds: f64,
    discovery_scan_gib_per_second: f64,
    limit: usize,
) -> Result<LinuxFileScanReport> {
    ensure!(limit > 0, "文件结果数量上限必须大于零");
    let started = Instant::now();
    let slide = kernel
        .init_task
        .checked_sub(profile.init_task_symbol)
        .context("运行时 init_task 低于 profile 链接地址")?;
    ensure!(slide & 0xfff == 0, "Linux 内核运行时 slide 未按页对齐");
    ensure!(slide <= 0x4000_0000, "Linux 内核运行时 slide 超出安全范围");
    let super_blocks = profile
        .super_blocks_symbol
        .checked_add(slide)
        .context("运行时 super_blocks 地址溢出")?;
    ensure!(
        is_kernel_pointer(super_blocks),
        "运行时 super_blocks 地址无效"
    );

    let mut scanner = FileScanner {
        space: LinuxX64AddressSpace::new(image, kernel.directory_table_base)?,
        profile,
        limit,
        records: Vec::new(),
        visited_dentries: HashMap::new(),
        stats: FileScanStats::default(),
        warnings: WarningState::default(),
        limit_reached: false,
    };
    let (profile_warning_kind, profile_warning) = if profile.source == "volatility3_isf_vfs" {
        (
            "volatility3_isf",
            format!(
                "使用与完整 linux_banner 精确匹配的 Volatility 3 VFS 布局（{}）；super_blocks、super_block、dentry 与 inode 均在遍历时进行现场指针和反向链接校验",
                kernel
                    .symbol_table
                    .as_deref()
                    .map(|table| table.fingerprint())
                    .unwrap_or(profile.fingerprint)
            ),
        )
    } else {
        (
            "embedded_exact_profile",
            format!(
                "使用与完整 Ubuntu 构建指纹绑定的 VFS 布局（{}）；super_blocks、super_block、dentry 与 inode 均在遍历时进行现场指针和反向链接校验",
                profile.fingerprint
            ),
        )
    };
    scanner
        .warnings
        .push(profile_warning_kind, profile_warning, None, false);
    scanner.walk_superblocks(super_blocks)?;
    if scanner.limit_reached {
        scanner.warnings.push(
            "result_limit",
            format!("Linux 文件结果达到 {limit} 条上限，未继续遍历其余 dentry"),
            None,
            false,
        );
    }
    scanner.records.sort_unstable_by(|left, right| {
        left.superblock
            .cmp(&right.superblock)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.dentry.cmp(&right.dentry))
    });
    scanner.warnings.finish();
    let record_count = scanner.records.len();
    let unique_inodes = scanner
        .records
        .iter()
        .map(|record| record.inode)
        .collect::<HashSet<_>>()
        .len();

    let structural_complete = !scanner.warnings.structural;
    let stop_reason = if scanner.limit_reached {
        LinuxFileScanStopReason::Limit
    } else if scanner.warnings.structural {
        LinuxFileScanStopReason::Partial
    } else {
        LinuxFileScanStopReason::SuperBlockListHead
    };
    let complete = stop_reason == LinuxFileScanStopReason::SuperBlockListHead;
    Ok(LinuxFileScanReport {
        kernel: kernel.clone(),
        source: "superblock_dentry_tree".to_owned(),
        scope: "resident positive dentries reachable from the validated global super_blocks list; this is not an on-disk directory inventory"
            .to_owned(),
        path_semantics:
            "superblock_relative; mount namespaces are not merged into an invented host-global path"
                .to_owned(),
        profile_source: profile.source.to_owned(),
        profile_fingerprint: if profile.source == "volatility3_isf_vfs" {
            kernel
                .symbol_table
                .as_deref()
                .map(|table| table.fingerprint().to_owned())
                .unwrap_or_else(|| profile.fingerprint.to_owned())
        } else {
            profile.fingerprint.to_owned()
        },
        record_count,
        records: scanner.records,
        complete,
        structural_complete,
        limit_reached: scanner.limit_reached,
        stop_reason,
        superblocks_seen: scanner.stats.superblocks_seen,
        superblocks_walked: scanner.stats.superblocks_walked,
        dentries_seen: scanner.stats.dentries_seen,
        negative_dentries: scanner.stats.negative_dentries,
        invalid_dentries: scanner.stats.invalid_dentries,
        dentry_validation_anomalies: scanner.stats.invalid_dentries,
        unique_inodes,
        warning_count: scanner.warnings.total,
        warning_counts: scanner.warnings.samples_per_kind.clone(),
        warnings: scanner.warnings.records,
        bytes_scanned,
        discovery_scan_seconds,
        discovery_scan_gib_per_second,
        traversal_seconds: started.elapsed().as_secs_f64(),
    })
}

impl FileScanner<'_> {
    fn walk_superblocks(&mut self, head: u64) -> Result<()> {
        self.space
            .translate(head)
            .context("super_blocks 链表头没有驻留映射")?;
        let mut current = self
            .space
            .read_u64(head)
            .context("无法读取 super_blocks.next")?;
        let head_previous = self
            .space
            .read_u64(head + 8)
            .context("无法读取 super_blocks.prev")?;
        ensure!(
            current != head,
            "super_blocks 是空链，无法验证 VFS filescan profile"
        );
        ensure!(
            is_kernel_pointer(current) && current & 7 == 0,
            "super_blocks.next 不是对齐的内核指针"
        );
        ensure!(
            is_kernel_pointer(head_previous) && head_previous & 7 == 0,
            "super_blocks.prev 不是对齐的内核指针"
        );
        ensure!(
            self.space.read_u64(current + 8).ok() == Some(head),
            "super_blocks.next.prev 不指向链表头"
        );
        ensure!(
            self.space.read_u64(head_previous).ok() == Some(head),
            "super_blocks.prev.next 不指向链表头"
        );

        // Validate and close the complete global topology before emitting any
        // dentry records.  Otherwise a low result limit could make a wrong
        // profile anchor look like a plausible partial file tree.
        let mut previous = head;
        let mut seen = HashSet::new();
        let mut superblocks = Vec::new();
        while current != head {
            ensure!(
                is_kernel_pointer(current) && current & 7 == 0 && seen.insert(current),
                "super_blocks 链表出现坏指针、未对齐节点或非头部环：{current:#x}"
            );
            ensure!(seen.len() <= 65_536, "super_blocks 节点数超过安全上限");
            let next = self
                .space
                .read_u64(current)
                .with_context(|| format!("无法读取 super_block.s_list.next：{current:#x}"))?;
            ensure!(
                self.space.read_u64(current + 8).ok() == Some(previous),
                "super_blocks 节点 prev 反向链接不一致：{current:#x}"
            );
            ensure!(
                next == head || (is_kernel_pointer(next) && next & 7 == 0),
                "super_blocks 节点 next 不是对齐的内核指针：{current:#x}"
            );
            ensure!(
                next == head || self.space.read_u64(next + 8).ok() == Some(current),
                "super_blocks 节点 next.prev 反向链接不一致：{current:#x}"
            );
            superblocks.push(current);
            previous = current;
            current = next;
        }
        ensure!(
            previous == head_previous,
            "super_blocks 链表头的 prev 不指向最后节点"
        );

        self.stats.superblocks_seen = superblocks.len();
        for superblock in superblocks {
            if self.limit_reached {
                break;
            }
            self.walk_superblock(superblock);
        }
        Ok(())
    }

    fn walk_superblock(&mut self, address: u64) {
        let root = match self.space.read_u64(address + self.profile.super_block_root) {
            Ok(value) if is_kernel_pointer(value) => value,
            _ => {
                self.warnings.push(
                    "unusable_superblock",
                    "super_block.s_root 缺失或不是驻留内核指针",
                    Some(address),
                    true,
                );
                return;
            }
        };
        if self.space.read_u64(root + self.profile.dentry_parent).ok() != Some(root) {
            self.warnings.push(
                "invalid_superblock_root",
                "super_block.s_root 的 d_parent 不自指",
                Some(root),
                true,
            );
            return;
        }
        if self
            .space
            .read_u64(root + self.profile.dentry_super_block)
            .ok()
            != Some(address)
        {
            self.warnings.push(
                "invalid_superblock_root",
                "super_block.s_root 的 dentry.d_sb 与当前 super_block 不一致",
                Some(root),
                true,
            );
            return;
        }
        let root_inode = match self.space.read_u64(root + self.profile.dentry_inode) {
            Ok(value) if is_kernel_pointer(value) => value,
            _ => {
                self.warnings.push(
                    "invalid_superblock_root_inode",
                    "super_block.s_root 没有有效 inode",
                    Some(root),
                    true,
                );
                return;
            }
        };
        if self
            .space
            .read_u64(root_inode + self.profile.inode_super_block)
            .ok()
            != Some(address)
        {
            self.warnings.push(
                "root_inode_superblock_mismatch",
                "根 dentry 的 inode.i_sb 与 super_block 不一致",
                Some(root_inode),
                true,
            );
            return;
        }

        let device_raw = self
            .space
            .read_u32(address + self.profile.super_block_device)
            .unwrap_or(0);
        let filesystem = self.read_filesystem_name(address);
        let id = read_fixed_string(
            &self.space,
            address + self.profile.super_block_id,
            MAX_SUPERBLOCK_ID,
        );
        let evidence = SuperBlockEvidence {
            address,
            physical: self.space.translate(address).ok(),
            filesystem,
            id: id.filter(|value| !value.is_empty()),
            device_raw,
        };
        self.stats.superblocks_walked += 1;
        self.walk_dentry_tree(&evidence, root);
    }

    fn read_filesystem_name(&mut self, superblock: u64) -> Option<String> {
        let fs_type = self
            .space
            .read_u64(superblock + self.profile.super_block_type)
            .ok()?;
        if !is_kernel_pointer(fs_type) {
            return None;
        }
        let name = self
            .space
            .read_u64(fs_type + self.profile.file_system_type_name)
            .ok()?;
        if !is_kernel_pointer(name) {
            return None;
        }
        read_c_string(&self.space, name, MAX_FILESYSTEM_NAME)
    }

    fn walk_dentry_tree(&mut self, superblock: &SuperBlockEvidence, root: u64) {
        let mut pending = VecDeque::from([PendingDentry {
            address: root,
            parent: root,
            parent_path: Some("/".to_owned()),
            membership_trusted: true,
            depth: 0,
        }]);
        while let Some(item) = pending.pop_back() {
            if self.limit_reached {
                break;
            }
            if item.depth > 4096 {
                self.stats.invalid_dentries += 1;
                self.warnings.push(
                    "dentry_cycle",
                    "dentry 树深度超过 4096",
                    Some(item.address),
                    true,
                );
                continue;
            }
            if self
                .space
                .read_u64(item.address + self.profile.dentry_super_block)
                .ok()
                != Some(superblock.address)
            {
                self.invalid_dentry(item.address, "dentry.d_sb 与当前 super_block 不一致");
                continue;
            }
            let observed_parent = match self
                .space
                .read_u64(item.address + self.profile.dentry_parent)
            {
                Ok(value) => Some(value),
                Err(error) => {
                    self.invalid_dentry(
                        item.address,
                        format!("无法读取 dentry.d_parent：{error:#}"),
                    );
                    None
                }
            };
            if !item.membership_trusted && observed_parent != Some(item.parent) {
                self.invalid_dentry(
                    item.address,
                    "降级链表成员的 dentry.d_parent 无法证明其属于当前父目录",
                );
                continue;
            }
            let parent_status = if observed_parent.is_none() {
                Some("parent_unreadable")
            } else if observed_parent != Some(item.parent) {
                self.invalid_dentry(item.address, "dentry.d_parent 与遍历父节点不一致");
                Some("parent_mismatch")
            } else {
                None
            };
            let already_seen = self.visited_dentries.contains_key(&item.address);
            if !already_seen {
                self.stats.dentries_seen += 1;
            }
            let inode = match self
                .space
                .read_u64(item.address + self.profile.dentry_inode)
            {
                Ok(0) => {
                    if already_seen {
                        self.invalid_dentry(item.address, "negative dentry 在树中重复出现");
                    } else {
                        self.stats.negative_dentries += 1;
                        self.visited_dentries.insert(
                            item.address,
                            VisitedDentry {
                                quality: if item.membership_trusted {
                                    DentryEvidenceQuality::TrustedUnresolved
                                } else {
                                    DentryEvidenceQuality::SemanticRecovery
                                },
                                record_index: None,
                            },
                        );
                    }
                    continue;
                }
                Ok(value) if is_kernel_pointer(value) => value,
                _ => {
                    self.invalid_dentry(item.address, "dentry.d_inode 不是有效内核指针");
                    continue;
                }
            };
            if self
                .space
                .read_u64(inode + self.profile.inode_super_block)
                .ok()
                != Some(superblock.address)
            {
                self.invalid_dentry(item.address, "inode.i_sb 与当前 super_block 不一致");
                continue;
            }
            let mode = match read_u16(&self.space, inode + self.profile.inode_mode) {
                Ok(value) if inode_type(value).is_some() => value,
                _ => {
                    self.invalid_dentry(item.address, "inode.i_mode 文件类型无效");
                    continue;
                }
            };

            let mut name = if item.depth == 0 {
                Some(DecodedName {
                    text: "/".to_owned(),
                    utf8_valid: true,
                    bytes_hex: "2f".to_owned(),
                })
            } else {
                self.read_dentry_name(item.address)
            };
            if name
                .as_ref()
                .is_some_and(|name| name.text == "." || name.text == "..")
            {
                self.invalid_dentry(item.address, "dentry 子节点名称不能是 . 或 ..");
                name = None;
            }
            if name.is_none() {
                self.invalid_dentry(
                    item.address,
                    "dentry 名称缺失、未驻留或不满足安全 qstr 边界；保留 inode 并继续无路径子树",
                );
            }
            let (path, path_status) = if let Some(status) = parent_status {
                (None, status.to_owned())
            } else if item.depth == 0 {
                (Some("/".to_owned()), "resolved".to_owned())
            } else if let Some(name) = name.as_ref() {
                if let Some(parent_path) = item.parent_path.as_deref() {
                    match join_superblock_path(parent_path, &name.text) {
                        Some(value) => (Some(value), "resolved".to_owned()),
                        None => {
                            self.invalid_dentry(item.address, "dentry 路径超过安全长度");
                            (None, "path_too_long".to_owned())
                        }
                    }
                } else {
                    (None, "ancestor_unresolved".to_owned())
                }
            } else {
                (None, "name_unreadable".to_owned())
            };
            let quality = if path.is_some() {
                DentryEvidenceQuality::Resolved
            } else if item.membership_trusted {
                DentryEvidenceQuality::TrustedUnresolved
            } else {
                DentryEvidenceQuality::SemanticRecovery
            };
            let existing = self
                .visited_dentries
                .get(&item.address)
                .map(|visited| (visited.quality, visited.record_index));
            let replacement_index = match existing {
                Some((previous_quality, Some(index))) if quality > previous_quality => {
                    self.warnings.push(
                        "dentry_evidence_upgrade",
                        "同一 dentry 后来从更可信的父链恢复，已升级记录和路径证据",
                        Some(item.address),
                        true,
                    );
                    Some(index)
                }
                Some(_) => {
                    self.invalid_dentry(item.address, "dentry 树出现重复节点或非头部环");
                    continue;
                }
                None => None,
            };
            if replacement_index.is_none() && self.records.len() >= self.limit {
                self.limit_reached = true;
                break;
            }
            let record = self.make_record(
                superblock,
                &item,
                DentryRecordEvidence {
                    observed_parent,
                    name,
                    path: path.clone(),
                    path_status,
                    inode,
                    mode,
                },
            );
            let record_index = if let Some(index) = replacement_index {
                self.records[index] = record;
                index
            } else {
                let index = self.records.len();
                self.records.push(record);
                index
            };
            self.visited_dentries.insert(
                item.address,
                VisitedDentry {
                    quality,
                    record_index: Some(record_index),
                },
            );
            if mode & 0xf000 != 0x4000 {
                continue;
            }

            for child in self
                .children(item.address, superblock.address)
                .into_iter()
                .rev()
            {
                pending.push_back(PendingDentry {
                    address: child.address,
                    parent: item.address,
                    parent_path: path.clone(),
                    membership_trusted: child.membership_trusted,
                    depth: item.depth + 1,
                });
            }
        }
    }

    fn invalid_dentry(&mut self, address: u64, message: impl Into<String>) {
        self.stats.invalid_dentries += 1;
        self.warnings
            .push("invalid_dentry", message, Some(address), true);
    }

    fn children(&mut self, parent: u64, superblock: u64) -> Vec<ChildLinkCandidate> {
        match self.profile.dentry_children_kind {
            DentryChildrenKind::List => self.list_children(parent, superblock),
            DentryChildrenKind::HList => self.hlist_children(parent, superblock),
        }
    }

    fn list_children(&mut self, parent: u64, superblock: u64) -> Vec<ChildLinkCandidate> {
        let head = parent + self.profile.dentry_children_head;
        let head_previous = self.space.read_u64(head + 8).ok();
        let mut current = match self.space.read_u64(head) {
            Ok(value) => value,
            Err(error) => {
                self.child_list_warning(parent, format!("无法读取 list_head.next：{error:#}"));
                return Vec::new();
            }
        };
        let mut previous = head;
        let mut chain_trusted = true;
        let mut consecutive_untrusted = 0usize;
        let mut seen = HashSet::new();
        let mut children = Vec::new();
        while current != head {
            if !is_kernel_pointer(current) || current & 7 != 0 || !seen.insert(current) {
                self.child_list_warning(current, "list_head 子链出现坏指针或非头部环");
                break;
            }
            if seen.len() > MAX_CHILD_LINKS_PER_DIRECTORY {
                self.child_list_warning(current, "list_head 子链超过单目录安全节点上限");
                break;
            }
            let backlink_matches = self.space.read_u64(current + 8).ok() == Some(previous);
            let membership_trusted = chain_trusted && backlink_matches;
            if !backlink_matches {
                self.child_list_warning(current, "list_head.prev 反向链接不一致");
            }
            let Some(child) = current.checked_sub(self.profile.dentry_child_node) else {
                self.child_list_warning(current, "dentry child 节点地址下溢");
                break;
            };
            if !is_kernel_pointer(child) {
                self.child_list_warning(child, "子 dentry 地址无效");
                break;
            }
            let semantic_anchor = self.candidate_has_tree_anchor(child, parent, superblock);
            let member_proven = membership_trusted || semantic_anchor;
            if member_proven {
                children.push(ChildLinkCandidate {
                    address: child,
                    membership_trusted,
                });
            } else {
                self.invalid_dentry(
                    child,
                    "降级 list_head 候选未通过 dentry.d_sb 与 d_parent 成员校验",
                );
            }
            if member_proven {
                consecutive_untrusted = 0;
            } else {
                consecutive_untrusted += 1;
                if consecutive_untrusted >= MAX_CONSECUTIVE_UNTRUSTED_CHILDREN {
                    self.child_list_warning(
                        current,
                        "连续降级候选未通过语义成员校验，停止当前子链",
                    );
                    break;
                }
            }
            let next = match self.space.read_u64(current) {
                Ok(value) => value,
                Err(error) => {
                    self.child_list_warning(current, format!("无法读取 list_head.next：{error:#}"));
                    break;
                }
            };
            let next_backlink_matches = if next != head {
                if !is_kernel_pointer(next) || next & 7 != 0 {
                    self.child_list_warning(next, "list_head.next 不是有效内核指针");
                    break;
                }
                match self.space.read_u64(next + 8) {
                    Ok(backlink) if backlink == current => true,
                    Ok(_) => {
                        self.child_list_warning(next, "list_head.next 的反向链接不一致");
                        false
                    }
                    Err(error) => {
                        self.child_list_warning(
                            next,
                            format!("无法读取 list_head.next 的反向链接：{error:#}"),
                        );
                        break;
                    }
                }
            } else {
                true
            };
            chain_trusted = member_proven && next_backlink_matches;
            previous = current;
            current = next;
        }
        if current == head && head_previous != Some(previous) {
            self.child_list_warning(head, "dentry 子链头的 prev 不一致");
        }
        children
    }

    fn hlist_children(&mut self, parent: u64, superblock: u64) -> Vec<ChildLinkCandidate> {
        let head = parent + self.profile.dentry_children_head;
        let mut current = match self.space.read_u64(head) {
            Ok(value) => value,
            Err(error) => {
                self.child_list_warning(parent, format!("无法读取 hlist.first：{error:#}"));
                return Vec::new();
            }
        };
        let mut expected_previous_link = head;
        let mut chain_trusted = true;
        let mut consecutive_untrusted = 0usize;
        let mut seen = HashSet::new();
        let mut children = Vec::new();
        while current != 0 {
            if !is_kernel_pointer(current) || current & 7 != 0 || !seen.insert(current) {
                self.child_list_warning(current, "hlist 子链出现坏指针或环");
                break;
            }
            if seen.len() > MAX_CHILD_LINKS_PER_DIRECTORY {
                self.child_list_warning(current, "hlist 子链超过单目录安全节点上限");
                break;
            }
            let backlink_matches =
                self.space.read_u64(current + 8).ok() == Some(expected_previous_link);
            let membership_trusted = chain_trusted && backlink_matches;
            if !backlink_matches {
                self.child_list_warning(current, "hlist.pprev 反向链接不一致");
            }
            let Some(child) = current.checked_sub(self.profile.dentry_child_node) else {
                self.child_list_warning(current, "dentry sibling 节点地址下溢");
                break;
            };
            if !is_kernel_pointer(child) {
                self.child_list_warning(child, "子 dentry 地址无效");
                break;
            }
            let semantic_anchor = self.candidate_has_tree_anchor(child, parent, superblock);
            let member_proven = membership_trusted || semantic_anchor;
            if member_proven {
                children.push(ChildLinkCandidate {
                    address: child,
                    membership_trusted,
                });
            } else {
                self.invalid_dentry(
                    child,
                    "降级 hlist 候选未通过 dentry.d_sb 与 d_parent 成员校验",
                );
            }
            if member_proven {
                consecutive_untrusted = 0;
            } else {
                consecutive_untrusted += 1;
                if consecutive_untrusted >= MAX_CONSECUTIVE_UNTRUSTED_CHILDREN {
                    self.child_list_warning(
                        current,
                        "连续降级候选未通过语义成员校验，停止当前子链",
                    );
                    break;
                }
            }
            let next = match self.space.read_u64(current) {
                Ok(value) => value,
                Err(error) => {
                    self.child_list_warning(current, format!("无法读取 hlist.next：{error:#}"));
                    break;
                }
            };
            let next_backlink_matches = if next != 0 {
                if !is_kernel_pointer(next) || next & 7 != 0 {
                    self.child_list_warning(next, "hlist.next 不是有效内核指针");
                    break;
                }
                match self.space.read_u64(next + 8) {
                    Ok(backlink) if backlink == current => true,
                    Ok(_) => {
                        self.child_list_warning(next, "hlist.next 的反向链接不一致");
                        false
                    }
                    Err(error) => {
                        self.child_list_warning(
                            next,
                            format!("无法读取 hlist.next 的反向链接：{error:#}"),
                        );
                        break;
                    }
                }
            } else {
                true
            };
            chain_trusted = member_proven && next_backlink_matches;
            expected_previous_link = current;
            current = next;
        }
        children
    }

    fn candidate_has_tree_anchor(&self, dentry: u64, parent: u64, superblock: u64) -> bool {
        self.space
            .read_u64(dentry + self.profile.dentry_super_block)
            .ok()
            == Some(superblock)
            && self
                .space
                .read_u64(dentry + self.profile.dentry_parent)
                .ok()
                == Some(parent)
    }

    fn child_list_warning(&mut self, address: u64, message: impl Into<String>) {
        self.warnings
            .push("dentry_children_corrupt", message, Some(address), true);
    }

    fn read_dentry_name(&self, dentry: u64) -> Option<DecodedName> {
        let length = usize::try_from(
            self.space
                .read_u32(dentry + self.profile.dentry_name + self.profile.qstr_len)
                .ok()?,
        )
        .ok()?;
        if length == 0 || length > MAX_DENTRY_NAME {
            return None;
        }
        let pointer = self
            .space
            .read_u64(dentry + self.profile.dentry_name + self.profile.qstr_name)
            .ok()?;
        if !is_kernel_pointer(pointer) {
            return None;
        }
        let mut bytes = vec![0u8; length];
        self.space.read_virtual(pointer, &mut bytes).ok()?;
        if bytes.iter().any(|byte| *byte == 0 || *byte == b'/') {
            return None;
        }
        Some(DecodedName {
            utf8_valid: std::str::from_utf8(&bytes).is_ok(),
            text: String::from_utf8_lossy(&bytes).into_owned(),
            bytes_hex: hex::encode(&bytes),
        })
    }

    fn make_record(
        &mut self,
        superblock: &SuperBlockEvidence,
        dentry: &PendingDentry,
        evidence: DentryRecordEvidence,
    ) -> LinuxFileScanRecord {
        let DentryRecordEvidence {
            observed_parent,
            name,
            path,
            path_status,
            inode,
            mode,
        } = evidence;
        let major = superblock.device_raw >> 20;
        let minor = superblock.device_raw & 0x000f_ffff;
        let mapping = self
            .space
            .read_u64(inode + self.profile.inode_mapping)
            .ok()
            .filter(|address| is_kernel_pointer(*address));
        let cached_pages = mapping
            .and_then(|address| {
                self.space
                    .read_u64(address + self.profile.address_space_nrpages)
                    .ok()
            })
            .filter(|pages| *pages <= (1u64 << 52));
        let inode_number = self.read_inode_u64(inode, self.profile.inode_number, "i_ino");
        let uid = self.read_inode_u32(inode, self.profile.inode_uid, "i_uid");
        let gid = self.read_inode_u32(inode, self.profile.inode_gid, "i_gid");
        let link_count = self.read_inode_u32(inode, self.profile.inode_link_count, "i_nlink");
        let size = self
            .read_inode_u64(inode, self.profile.inode_file_size, "i_size")
            .map(|value| value as i64);
        let metadata_complete = inode_number.is_some()
            && uid.is_some()
            && gid.is_some()
            && link_count.is_some()
            && size.is_some();
        let superblock_physical = superblock.physical;
        let dentry_physical = self.space.translate(dentry.address).ok();
        let inode_physical = self.space.translate(inode).ok();
        LinuxFileScanRecord {
            source: "superblock_dentry_tree".to_owned(),
            superblock: superblock.address,
            superblock_hex: format_address(superblock.address),
            superblock_physical,
            superblock_physical_hex: superblock_physical.map(format_address),
            filesystem: superblock.filesystem.clone(),
            superblock_id: superblock.id.clone(),
            device: format!("{major}:{minor}"),
            device_raw: superblock.device_raw,
            device_major: major,
            device_minor: minor,
            dentry: dentry.address,
            dentry_hex: format_address(dentry.address),
            dentry_physical,
            dentry_physical_hex: dentry_physical.map(format_address),
            parent_dentry: dentry.parent,
            parent_dentry_hex: format_address(dentry.parent),
            observed_parent_dentry: observed_parent,
            observed_parent_dentry_hex: observed_parent.map(format_address),
            inode,
            inode_hex: format_address(inode),
            inode_physical,
            inode_physical_hex: inode_physical.map(format_address),
            inode_number,
            name: name.as_ref().map(|name| name.text.clone()),
            name_bytes_hex: name.as_ref().map(|name| name.bytes_hex.clone()),
            name_utf8_valid: name.as_ref().map(|name| name.utf8_valid),
            name_status: if name.is_some() {
                "decoded"
            } else {
                "unreadable"
            }
            .to_owned(),
            path,
            path_status,
            path_scope: "superblock_relative".to_owned(),
            membership_status: if dentry.depth == 0 {
                "superblock_root"
            } else if dentry.membership_trusted {
                "validated_link"
            } else {
                "semantic_recovery"
            }
            .to_owned(),
            file_type: inode_type(mode).unwrap_or("unknown").to_owned(),
            mode,
            mode_string: format_mode(mode),
            uid,
            gid,
            link_count,
            size,
            cached_pages,
            accessed_utc: read_timestamp(&self.space, inode + self.profile.inode_access_time),
            modified_utc: read_timestamp(&self.space, inode + self.profile.inode_modify_time),
            changed_utc: read_timestamp(&self.space, inode + self.profile.inode_change_time),
            metadata_complete,
            deleted: link_count.map(|count| count == 0),
        }
    }

    fn read_inode_u64(&mut self, inode: u64, offset: u64, field: &str) -> Option<u64> {
        match self.space.read_u64(inode + offset) {
            Ok(value) => Some(value),
            Err(error) => {
                self.warnings.push(
                    "inode_field_unreadable",
                    format!("无法读取 inode.{field}：{error:#}；字段保留为 null"),
                    Some(inode + offset),
                    true,
                );
                None
            }
        }
    }

    fn read_inode_u32(&mut self, inode: u64, offset: u64, field: &str) -> Option<u32> {
        match self.space.read_u32(inode + offset) {
            Ok(value) => Some(value),
            Err(error) => {
                self.warnings.push(
                    "inode_field_unreadable",
                    format!("无法读取 inode.{field}：{error:#}；字段保留为 null"),
                    Some(inode + offset),
                    true,
                );
                None
            }
        }
    }
}

fn exact_vfs_profile(banner: &str) -> Option<LinuxVfsProfile> {
    let (
        fingerprint,
        init_task_symbol,
        super_blocks_symbol,
        super_block_size,
        super_block_id,
        inode_size,
        address_space_nrpages,
        dentry_super_block,
        dentry_child_node,
        dentry_children_head,
        dentry_children_kind,
    ) = match banner {
        UBUNTU_5_4_0_84_BIONIC => (
            "Ubuntu Bionic HWE 5.4.0-84.94; build_id=c56268a4878b2c99f78e1fa2d0ace9bc5f6d575d",
            0xffff_ffff_8261_3780,
            0xffff_ffff_826f_f1d0,
            0x5c0,
            0x3e8,
            0x258,
            0x58,
            0x68,
            0x90,
            0xa0,
            DentryChildrenKind::List,
        ),
        UBUNTU_4_13_0_36_XENIAL => (
            "Ubuntu Xenial HWE 4.13.0-36.40; build_id=d9142b737a5bb09c7f1aef87f7dd2834dba7d934",
            0xffff_ffff_8221_2480,
            0xffff_ffff_8231_9740,
            0x5c0,
            0x3d0,
            0x250,
            0x50,
            0x68,
            0x90,
            0xa0,
            DentryChildrenKind::List,
        ),
        UBUNTU_6_8_0_49_NOBLE => (
            "Ubuntu Noble 6.8.0-49.49; build_id=9c2aa265a404792954898609a7a72988d9bac935",
            0xffff_ffff_8340_fcc0,
            0xffff_ffff_8365_75f0,
            0x580,
            0x3c0,
            0x278,
            0x58,
            0x70,
            0x98,
            0xa8,
            DentryChildrenKind::HList,
        ),
        _ => return None,
    };
    Some(LinuxVfsProfile {
        source: "exact_banner_vfs_profile",
        fingerprint,
        init_task_symbol,
        super_blocks_symbol,
        super_block_size,
        super_block_root: 0x68,
        super_block_device: 0x10,
        super_block_type: 0x28,
        file_system_type_name: 0,
        super_block_id,
        dentry_size: 0xc0,
        dentry_parent: 0x18,
        dentry_name: 0x20,
        qstr_len: 0x04,
        qstr_name: 0x08,
        dentry_inode: 0x30,
        dentry_super_block,
        dentry_child_node,
        dentry_children_head,
        dentry_children_kind,
        inode_size,
        inode_mode: 0x00,
        inode_uid: 0x04,
        inode_gid: 0x08,
        inode_super_block: 0x28,
        inode_mapping: 0x30,
        inode_number: 0x40,
        inode_link_count: 0x48,
        inode_file_size: 0x50,
        inode_access_time: 0x58,
        inode_modify_time: 0x68,
        inode_change_time: 0x78,
        address_space_nrpages,
    })
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

pub(crate) fn format_mode(mode: u16) -> String {
    let kind = match mode & 0xf000 {
        0x1000 => 'p',
        0x2000 => 'c',
        0x4000 => 'd',
        0x6000 => 'b',
        0x8000 => '-',
        0xa000 => 'l',
        0xc000 => 's',
        _ => '?',
    };
    let mut output = String::with_capacity(10);
    output.push(kind);
    for (read, write, execute) in [
        (0o400, 0o200, 0o100),
        (0o040, 0o020, 0o010),
        (0o004, 0o002, 0o001),
    ] {
        output.push(if mode & read != 0 { 'r' } else { '-' });
        output.push(if mode & write != 0 { 'w' } else { '-' });
        output.push(if mode & execute != 0 { 'x' } else { '-' });
    }
    output
}

fn join_superblock_path(parent: &str, name: &str) -> Option<String> {
    let length = parent.len().checked_add(name.len())?.checked_add(1)?;
    if length > MAX_PATH_BYTES {
        return None;
    }
    if parent == "/" {
        Some(format!("/{name}"))
    } else {
        Some(format!("{parent}/{name}"))
    }
}

fn format_address(address: u64) -> String {
    format!("{address:#018x}")
}

fn read_u16(space: &LinuxX64AddressSpace<'_>, address: u64) -> Result<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_fixed_string(
    space: &LinuxX64AddressSpace<'_>,
    address: u64,
    length: usize,
) -> Option<String> {
    let mut bytes = vec![0u8; length];
    space.read_virtual(address, &mut bytes).ok()?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn read_c_string(
    space: &LinuxX64AddressSpace<'_>,
    address: u64,
    max_length: usize,
) -> Option<String> {
    let mut bytes = vec![0u8; max_length];
    space.read_virtual(address, &mut bytes).ok()?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn read_timestamp(space: &LinuxX64AddressSpace<'_>, address: u64) -> Option<String> {
    let seconds = space.read_u64(address).ok()? as i64;
    let nanos = space.read_u64(address + 8).ok()?;
    let nanos = u32::try_from(nanos).ok()?;
    DateTime::<Utc>::from_timestamp(seconds, nanos)
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    const VIRTUAL_BASE: u64 = 0xffff_8000_0020_0000;
    const PHYSICAL_BASE: u64 = 0x20_0000;
    const HEAD: u64 = VIRTUAL_BASE + 0x1000;
    const SUPERBLOCK: u64 = VIRTUAL_BASE + 0x2000;
    const ROOT: u64 = VIRTUAL_BASE + 0x3000;
    const CHILD: u64 = VIRTUAL_BASE + 0x4000;
    const ROOT_INODE: u64 = VIRTUAL_BASE + 0x5000;
    const CHILD_INODE: u64 = VIRTUAL_BASE + 0x6000;
    const FS_TYPE: u64 = VIRTUAL_BASE + 0x7000;
    const FS_NAME: u64 = VIRTUAL_BASE + 0x7100;
    const CHILD_NAME: u64 = VIRTUAL_BASE + 0x7200;
    const ROOT_MAPPING: u64 = VIRTUAL_BASE + 0x7300;
    const CHILD_MAPPING: u64 = VIRTUAL_BASE + 0x7400;
    const GRANDCHILD: u64 = VIRTUAL_BASE + 0xc000;
    const GRANDCHILD_INODE: u64 = VIRTUAL_BASE + 0xd000;
    const GRANDCHILD_NAME: u64 = VIRTUAL_BASE + 0xe000;
    const GRANDCHILD_MAPPING: u64 = VIRTUAL_BASE + 0xf000;

    #[test]
    fn walks_list_and_hlist_dentry_trees() {
        for kind in [DentryChildrenKind::List, DentryChildrenKind::HList] {
            let path = temporary_path(match kind {
                DentryChildrenKind::List => "files-list",
                DentryChildrenKind::HList => "files-hlist",
            });
            let profile = synthetic_profile(kind);
            let mut bytes = synthetic_image(&profile);
            fs::write(&path, &bytes).unwrap();
            bytes.fill(0);
            let image = MemoryImage::open(&path).unwrap();
            let kernel = synthetic_kernel();
            let report =
                scan_files_with_profile(&image, &kernel, profile, 0, 0.0, 0.0, 10).unwrap();
            assert!(report.complete);
            assert_eq!(
                report.stop_reason,
                LinuxFileScanStopReason::SuperBlockListHead
            );
            assert_eq!(report.superblocks_walked, 1);
            assert_eq!(report.records.len(), 2);
            assert_eq!(report.records[0].path.as_deref(), Some("/"));
            assert_eq!(report.records[1].path.as_deref(), Some("/passwd"));
            assert_eq!(report.records[1].file_type, "regular");
            assert_eq!(report.records[1].cached_pages, Some(2));
            assert_eq!(report.records[1].device, "8:1");
            assert_eq!(report.records[1].dentry_hex, format_address(CHILD));

            let exact = scan_files_with_profile(&image, &kernel, profile, 0, 0.0, 0.0, 2).unwrap();
            assert!(exact.complete);
            assert!(!exact.limit_reached);
            assert_eq!(exact.records.len(), 2);

            let limited =
                scan_files_with_profile(&image, &kernel, profile, 0, 0.0, 0.0, 1).unwrap();
            assert!(!limited.complete);
            assert_eq!(limited.stop_reason, LinuxFileScanStopReason::Limit);
            assert_eq!(limited.records.len(), 1);
            drop(image);
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn rejects_an_unaligned_superblock_head_before_honoring_limit() {
        let path = temporary_path("files-bad-head");
        let profile = synthetic_profile(DentryChildrenKind::List);
        let mut bytes = synthetic_image(&profile);
        put_virtual_u64(&mut bytes, HEAD + 8, VIRTUAL_BASE + 0x123);
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let error = scan_files_with_profile(&image, &synthetic_kernel(), profile, 0, 0.0, 0.0, 1)
            .unwrap_err();
        assert!(format!("{error:#}").contains("super_blocks.prev 不是对齐"));
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn unreadable_directory_name_preserves_inode_and_descendants() {
        for kind in [DentryChildrenKind::List, DentryChildrenKind::HList] {
            let path = temporary_path(match kind {
                DentryChildrenKind::List => "files-unreadable-name-list",
                DentryChildrenKind::HList => "files-unreadable-name-hlist",
            });
            let profile = synthetic_profile(kind);
            let mut bytes = synthetic_image(&profile);
            append_grandchild(&mut bytes, &profile);
            put_virtual_u16(&mut bytes, CHILD_INODE + profile.inode_mode, 0o040755);
            put_virtual_u64(
                &mut bytes,
                CHILD + profile.dentry_name + profile.qstr_name,
                VIRTUAL_BASE + 0x30_0000,
            );
            fs::write(&path, bytes).unwrap();
            let image = MemoryImage::open(&path).unwrap();
            let report =
                scan_files_with_profile(&image, &synthetic_kernel(), profile, 0, 0.0, 0.0, 10)
                    .unwrap();
            assert!(!report.complete);
            assert_eq!(report.records.len(), 3);
            let directory = report
                .records
                .iter()
                .find(|record| record.dentry == CHILD)
                .unwrap();
            assert_eq!(directory.name, None);
            assert_eq!(directory.path_status, "name_unreadable");
            let descendant = report
                .records
                .iter()
                .find(|record| record.dentry == GRANDCHILD)
                .unwrap();
            assert_eq!(descendant.name.as_deref(), Some("shadow"));
            assert_eq!(descendant.path, None);
            assert_eq!(descendant.path_status, "ancestor_unresolved");
            drop(image);
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn unreadable_inode_fields_remain_null_instead_of_becoming_deleted_zeroes() {
        let path = temporary_path("files-unreadable-inode-field");
        let mut profile = synthetic_profile(DentryChildrenKind::List);
        let bytes = synthetic_image(&profile);
        profile.inode_number = 0x30_0000;
        profile.inode_link_count = 0x30_0008;
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let report =
            scan_files_with_profile(&image, &synthetic_kernel(), profile, 0, 0.0, 0.0, 10).unwrap();
        assert!(!report.complete);
        assert!(
            report
                .records
                .iter()
                .all(|record| record.inode_number.is_none() && record.deleted.is_none())
        );
        assert!(
            report
                .records
                .iter()
                .all(|record| !record.metadata_complete)
        );
        assert!(report.warning_counts.contains_key("inode_field_unreadable"));
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn preserves_verified_children_but_marks_a_smeared_tail_partial() {
        let path = temporary_path("files-smeared-tail");
        let profile = synthetic_profile(DentryChildrenKind::List);
        let mut bytes = synthetic_image(&profile);
        let child_node = CHILD + profile.dentry_child_node;
        put_virtual_u64(&mut bytes, child_node + 8, child_node);
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let report =
            scan_files_with_profile(&image, &synthetic_kernel(), profile, 0, 0.0, 0.0, 10).unwrap();
        assert!(!report.complete);
        assert_eq!(report.stop_reason, LinuxFileScanStopReason::Partial);
        assert_eq!(report.records.len(), 2);
        assert_eq!(report.records[1].path.as_deref(), Some("/passwd"));
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_a_child_from_a_different_superblock() {
        let path = temporary_path("files-wrong-dentry-sb");
        let profile = synthetic_profile(DentryChildrenKind::List);
        let mut bytes = synthetic_image(&profile);
        put_virtual_u64(
            &mut bytes,
            CHILD + profile.dentry_super_block,
            SUPERBLOCK + 0x1000,
        );
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let report =
            scan_files_with_profile(&image, &synthetic_kernel(), profile, 0, 0.0, 0.0, 10).unwrap();
        assert!(!report.complete);
        assert_eq!(report.records.len(), 1);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.message.contains("dentry.d_sb"))
        );
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn keeps_inode_evidence_when_a_parent_path_is_untrusted() {
        let path = temporary_path("files-parent-mismatch");
        let profile = synthetic_profile(DentryChildrenKind::List);
        let mut bytes = synthetic_image(&profile);
        put_virtual_u64(&mut bytes, CHILD + profile.dentry_parent, SUPERBLOCK);
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let report =
            scan_files_with_profile(&image, &synthetic_kernel(), profile, 0, 0.0, 0.0, 10).unwrap();
        assert!(!report.complete);
        assert_eq!(report.records.len(), 2);
        let child = report
            .records
            .iter()
            .find(|record| record.dentry == CHILD)
            .unwrap();
        assert_eq!(child.path, None);
        assert_eq!(child.path_status, "parent_mismatch");
        assert_eq!(child.observed_parent_dentry, Some(SUPERBLOCK));
        drop(image);
        fs::remove_file(path).unwrap();
    }

    fn synthetic_profile(kind: DentryChildrenKind) -> LinuxVfsProfile {
        let (node, head) = match kind {
            DentryChildrenKind::List => (0x90, 0xa0),
            DentryChildrenKind::HList => (0x98, 0xa8),
        };
        LinuxVfsProfile {
            source: "test",
            fingerprint: "test",
            init_task_symbol: VIRTUAL_BASE,
            super_blocks_symbol: HEAD,
            super_block_size: 0x500,
            super_block_root: 0x68,
            super_block_device: 0x10,
            super_block_type: 0x28,
            file_system_type_name: 0,
            super_block_id: 0x300,
            dentry_size: 0xc0,
            dentry_parent: 0x18,
            dentry_name: 0x20,
            qstr_len: 0x04,
            qstr_name: 0x08,
            dentry_inode: 0x30,
            dentry_super_block: 0x68,
            dentry_child_node: node,
            dentry_children_head: head,
            dentry_children_kind: kind,
            inode_size: 0x200,
            inode_mode: 0,
            inode_uid: 4,
            inode_gid: 8,
            inode_super_block: 0x28,
            inode_mapping: 0x30,
            inode_number: 0x40,
            inode_link_count: 0x48,
            inode_file_size: 0x50,
            inode_access_time: 0x58,
            inode_modify_time: 0x68,
            inode_change_time: 0x78,
            address_space_nrpages: 0x58,
        }
    }

    fn synthetic_kernel() -> LinuxKernelContext {
        LinuxKernelContext {
            architecture: "x86_64_4level".to_owned(),
            banner: "Linux version synthetic".to_owned(),
            banner_physical_address: 0,
            directory_table_base: 0x1000,
            page_table_source: "test".to_owned(),
            vmcoreinfo_physical_address: None,
            init_task: VIRTUAL_BASE,
            init_task_physical: PHYSICAL_BASE,
            profile_source: "test".to_owned(),
            profile_fingerprint: "test".to_owned(),
            btf_physical_address: None,
            task_struct_size: 0,
            task_struct_offsets: Default::default(),
            symbol_table: None,
        }
    }

    fn synthetic_image(profile: &LinuxVfsProfile) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x40_0000];
        let pml4_index = ((VIRTUAL_BASE >> 39) & 0x1ff) as usize;
        put_u64(&mut bytes, 0x1000 + pml4_index * 8, 0x2003);
        put_u64(&mut bytes, 0x2000, 0x3003);
        put_u64(&mut bytes, 0x3000 + 8, PHYSICAL_BASE | 0x83);

        put_virtual_u64(&mut bytes, HEAD, SUPERBLOCK);
        put_virtual_u64(&mut bytes, HEAD + 8, SUPERBLOCK);
        put_virtual_u64(&mut bytes, SUPERBLOCK, HEAD);
        put_virtual_u64(&mut bytes, SUPERBLOCK + 8, HEAD);
        put_virtual_u32(
            &mut bytes,
            SUPERBLOCK + profile.super_block_device,
            (8 << 20) | 1,
        );
        put_virtual_u64(&mut bytes, SUPERBLOCK + profile.super_block_type, FS_TYPE);
        put_virtual_u64(&mut bytes, SUPERBLOCK + profile.super_block_root, ROOT);
        put_virtual_bytes(&mut bytes, SUPERBLOCK + profile.super_block_id, b"sda1\0");
        put_virtual_u64(&mut bytes, FS_TYPE, FS_NAME);
        put_virtual_bytes(&mut bytes, FS_NAME, b"ext4\0");

        write_inode(
            &mut bytes,
            profile,
            ROOT_INODE,
            0o040755,
            2,
            ROOT_MAPPING,
            1,
        );
        write_inode(
            &mut bytes,
            profile,
            CHILD_INODE,
            0o100644,
            42,
            CHILD_MAPPING,
            2,
        );
        write_dentry(&mut bytes, profile, ROOT, ROOT, ROOT_INODE);
        write_dentry(&mut bytes, profile, CHILD, ROOT, CHILD_INODE);
        put_virtual_u32(
            &mut bytes,
            CHILD + profile.dentry_name + profile.qstr_len,
            6,
        );
        put_virtual_u64(
            &mut bytes,
            CHILD + profile.dentry_name + profile.qstr_name,
            CHILD_NAME,
        );
        put_virtual_bytes(&mut bytes, CHILD_NAME, b"passwd");

        match profile.dentry_children_kind {
            DentryChildrenKind::List => {
                let root_head = ROOT + profile.dentry_children_head;
                let child_node = CHILD + profile.dentry_child_node;
                put_virtual_u64(&mut bytes, root_head, child_node);
                put_virtual_u64(&mut bytes, root_head + 8, child_node);
                put_virtual_u64(&mut bytes, child_node, root_head);
                put_virtual_u64(&mut bytes, child_node + 8, root_head);
                let child_head = CHILD + profile.dentry_children_head;
                put_virtual_u64(&mut bytes, child_head, child_head);
                put_virtual_u64(&mut bytes, child_head + 8, child_head);
            }
            DentryChildrenKind::HList => {
                let root_head = ROOT + profile.dentry_children_head;
                let child_node = CHILD + profile.dentry_child_node;
                put_virtual_u64(&mut bytes, root_head, child_node);
                put_virtual_u64(&mut bytes, child_node, 0);
                put_virtual_u64(&mut bytes, child_node + 8, root_head);
                put_virtual_u64(&mut bytes, CHILD + profile.dentry_children_head, 0);
            }
        }
        bytes
    }

    fn append_grandchild(bytes: &mut [u8], profile: &LinuxVfsProfile) {
        write_inode(
            bytes,
            profile,
            GRANDCHILD_INODE,
            0o100600,
            43,
            GRANDCHILD_MAPPING,
            1,
        );
        write_dentry(bytes, profile, GRANDCHILD, CHILD, GRANDCHILD_INODE);
        put_virtual_u32(
            bytes,
            GRANDCHILD + profile.dentry_name + profile.qstr_len,
            6,
        );
        put_virtual_u64(
            bytes,
            GRANDCHILD + profile.dentry_name + profile.qstr_name,
            GRANDCHILD_NAME,
        );
        put_virtual_bytes(bytes, GRANDCHILD_NAME, b"shadow");

        match profile.dentry_children_kind {
            DentryChildrenKind::List => {
                let child_head = CHILD + profile.dentry_children_head;
                let grandchild_node = GRANDCHILD + profile.dentry_child_node;
                put_virtual_u64(bytes, child_head, grandchild_node);
                put_virtual_u64(bytes, child_head + 8, grandchild_node);
                put_virtual_u64(bytes, grandchild_node, child_head);
                put_virtual_u64(bytes, grandchild_node + 8, child_head);
                let grandchild_head = GRANDCHILD + profile.dentry_children_head;
                put_virtual_u64(bytes, grandchild_head, grandchild_head);
                put_virtual_u64(bytes, grandchild_head + 8, grandchild_head);
            }
            DentryChildrenKind::HList => {
                let child_head = CHILD + profile.dentry_children_head;
                let grandchild_node = GRANDCHILD + profile.dentry_child_node;
                put_virtual_u64(bytes, child_head, grandchild_node);
                put_virtual_u64(bytes, grandchild_node, 0);
                put_virtual_u64(bytes, grandchild_node + 8, child_head);
                put_virtual_u64(bytes, GRANDCHILD + profile.dentry_children_head, 0);
            }
        }
    }

    fn write_dentry(
        bytes: &mut [u8],
        profile: &LinuxVfsProfile,
        address: u64,
        parent: u64,
        inode: u64,
    ) {
        put_virtual_u64(bytes, address + profile.dentry_parent, parent);
        put_virtual_u64(bytes, address + profile.dentry_inode, inode);
        put_virtual_u64(bytes, address + profile.dentry_super_block, SUPERBLOCK);
    }

    fn write_inode(
        bytes: &mut [u8],
        profile: &LinuxVfsProfile,
        address: u64,
        mode: u16,
        inode_number: u64,
        mapping: u64,
        cached_pages: u64,
    ) {
        put_virtual_u16(bytes, address + profile.inode_mode, mode);
        put_virtual_u32(bytes, address + profile.inode_uid, 1000);
        put_virtual_u32(bytes, address + profile.inode_gid, 1000);
        put_virtual_u64(bytes, address + profile.inode_super_block, SUPERBLOCK);
        put_virtual_u64(bytes, address + profile.inode_mapping, mapping);
        put_virtual_u64(bytes, address + profile.inode_number, inode_number);
        put_virtual_u32(bytes, address + profile.inode_link_count, 1);
        put_virtual_u64(bytes, address + profile.inode_file_size, 4096);
        put_virtual_u64(bytes, mapping + profile.address_space_nrpages, cached_pages);
        for timestamp in [
            profile.inode_access_time,
            profile.inode_modify_time,
            profile.inode_change_time,
        ] {
            put_virtual_u64(bytes, address + timestamp, 1_700_000_000);
            put_virtual_u64(bytes, address + timestamp + 8, 123);
        }
    }

    fn virtual_to_physical(address: u64) -> usize {
        (PHYSICAL_BASE + (address - VIRTUAL_BASE)) as usize
    }

    fn put_virtual_bytes(bytes: &mut [u8], address: u64, value: &[u8]) {
        let physical = virtual_to_physical(address);
        bytes[physical..physical + value.len()].copy_from_slice(value);
    }

    fn put_virtual_u16(bytes: &mut [u8], address: u64, value: u16) {
        put_virtual_bytes(bytes, address, &value.to_le_bytes());
    }

    fn put_virtual_u32(bytes: &mut [u8], address: u64, value: u32) {
        put_virtual_bytes(bytes, address, &value.to_le_bytes());
    }

    fn put_virtual_u64(bytes: &mut [u8], address: u64, value: u64) {
        put_virtual_bytes(bytes, address, &value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "starmem-linux-{label}-{}-{nonce}.raw",
            std::process::id()
        ))
    }
}
