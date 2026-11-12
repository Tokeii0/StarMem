//! Conservative Linux page-cache file recovery for the exact kernels supported by StarMem.
//!
//! This module deliberately does not fall back to guessed layouts.  A `filescan` record is
//! revalidated against the live dentry/inode/address_space before any page bytes are trusted.
//! Missing or structurally ambiguous cache entries remain zero in the returned reconstruction
//! and are always described by `missing_ranges`; an incomplete dump is only published with a
//! `.partial` suffix.

use std::collections::{BTreeMap, HashSet};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::linux::{
    LinuxKernelContext, LinuxX64AddressSpace, UBUNTU_4_13_0_36_XENIAL, UBUNTU_5_4_0_84_BIONIC,
    UBUNTU_6_8_0_49_NOBLE, is_kernel_pointer,
};
use crate::linux_files::{LinuxFileScanRecord, format_mode};
use crate::output_policy::{OutputPolicy, OutputTarget};

const PAGE_SIZE: u64 = 0x1000;
const PAGE_STRUCT_SIZE: u64 = 0x40;
const TREE_MAP_SHIFT: u8 = 6;
const TREE_MAP_SIZE: usize = 1 << TREE_MAP_SHIFT;
const TREE_SLOTS_OFFSET: usize = 0x28;
const MAX_FOLIO_ORDER: u8 = 20;
const MAX_FOLIO_PAGES: u64 = 1 << MAX_FOLIO_ORDER;
const MAX_TREE_NODES: usize = 1_000_000;
const MAX_TREE_ENTRIES: usize = 8_000_000;
const MAX_REPORTED_WARNINGS: usize = 256;
const MAX_WARNING_SAMPLES_PER_KIND: usize = 16;

// Verified against the signed RHEL 7.0 kernel and kernel-devel RPMs. These
// compile-time bases predate the runtime globals; never select by release alone.
const RHEL_3_10_0_123: &str = "Linux version 3.10.0-123.el7.x86_64 (mockbuild@x86-017.build.eng.bos.redhat.com) (gcc version 4.8.2 20140120 (Red Hat 4.8.2-16) (GCC) ) #1 SMP Mon May 5 11:16:57 EDT 2014";

fn static_page_bases(banner: &str) -> Option<(u64, u64)> {
    (banner == RHEL_3_10_0_123).then_some((0xffff_ea00_0000_0000, 0xffff_8800_0000_0000))
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxRecoveredExtent {
    pub file_offset: u64,
    pub length: u64,
    pub first_page_index: u64,
    pub last_page_index: u64,
    pub physical_address: u64,
    pub physical_address_hex: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LinuxMissingRange {
    pub file_offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxPageCacheWarning {
    pub kind: String,
    pub message: String,
    pub address: Option<u64>,
    pub address_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxDumpFileSelection {
    pub requested_limit: usize,
    pub record_count: usize,
    pub complete: bool,
    pub structural_complete: bool,
    pub limit_reached: bool,
    pub stop_reason: crate::linux_files::LinuxFileScanStopReason,
    pub warning_count: usize,
    pub warning_counts: BTreeMap<String, usize>,
    pub warnings: Vec<crate::linux_files::LinuxFileScanWarning>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxDumpFileReport {
    pub source: String,
    pub scope: String,
    pub profile_source: String,
    pub profile_fingerprint: String,
    pub tree_kind: String,
    pub path: Option<String>,
    pub path_scope: String,
    pub path_status: String,
    pub membership_status: String,
    pub superblock: u64,
    pub superblock_hex: String,
    pub filesystem: Option<String>,
    pub superblock_id: Option<String>,
    pub device: String,
    pub deleted: Option<bool>,
    pub dentry: u64,
    pub dentry_hex: String,
    pub inode: u64,
    pub inode_hex: String,
    pub inode_number: Option<u64>,
    pub mapping: u64,
    pub mapping_hex: String,
    pub vmemmap_base: u64,
    pub vmemmap_base_hex: String,
    pub page_offset_base: u64,
    pub page_offset_base_hex: String,
    pub max_pfn: u64,
    pub logical_size: u64,
    pub output_size: u64,
    pub recovered_bytes: u64,
    pub missing_bytes: u64,
    pub expected_pages: u64,
    pub cached_pages_reported: u64,
    pub cached_pages_validated: u64,
    pub tree_nodes_seen: usize,
    pub tree_entries_seen: usize,
    pub folios_seen: usize,
    pub pages_recovered: u64,
    pub tree_complete: bool,
    pub complete: bool,
    pub extents: Vec<LinuxRecoveredExtent>,
    pub missing_ranges: Vec<LinuxMissingRange>,
    pub warning_count: usize,
    pub warnings: Vec<LinuxPageCacheWarning>,
    pub filescan_selection: Option<LinuxDumpFileSelection>,
    pub sha256: String,
    pub sha256_scope: String,
    pub output_path: Option<String>,
    pub recovery_report_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LinuxRecoveredFile {
    pub bytes: Vec<u8>,
    pub report: LinuxDumpFileReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxReversePageCacheEvidence {
    pub trigger_physical_address: u64,
    pub trigger_physical_address_hex: String,
    pub trigger_file_offset: u64,
    pub struct_page: u64,
    pub struct_page_hex: String,
    pub page_index: u64,
    pub inode: u64,
    pub inode_hex: String,
    pub mapping: u64,
    pub mapping_hex: String,
    pub superblock: u64,
    pub superblock_hex: String,
}

#[derive(Debug, Clone)]
pub struct LinuxReverseRecoveredFile {
    pub file: LinuxRecoveredFile,
    pub record: LinuxFileScanRecord,
    pub evidence: LinuxReversePageCacheEvidence,
}

/// Recover a regular file from validated Linux page-cache entries.
///
/// The returned byte vector always has the live `inode.i_size`.  Bytes which could not be
/// recovered are zero only as a transport representation; they are evidence gaps explicitly
/// covered by `report.missing_ranges`, and `report.complete` is false.
pub fn read_validated_file(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    record: &LinuxFileScanRecord,
    max_size: u64,
) -> Result<LinuxRecoveredFile> {
    let profile = pagecache_profile(kernel)?;
    profile.validate()?;
    ensure!(max_size > 0, "页缓存文件恢复上限必须大于零");

    let space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let validated = validate_file_anchors(&space, profile, kernel, record, max_size)?;
    let mut recoverer = PageCacheRecoverer::new(image, space, profile, kernel, &validated)?;
    recoverer.walk(validated.tree_head)?;
    recoverer.finish(record, validated)
}

/// Read a bounded prefix without changing the inode identity or claiming full recovery.
/// The report retains the live logical size and marks the unread suffix separately
/// through missing_ranges plus the prefix_read_limit warning. Only extents are evidence.
pub fn read_validated_file_prefix(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    record: &LinuxFileScanRecord,
    max_bytes: u64,
) -> Result<LinuxRecoveredFile> {
    ensure!(
        max_bytes > 0 && max_bytes <= 64 * 1024 * 1024,
        "页缓存前缀上限必须为 1..67108864 字节"
    );
    let profile = pagecache_profile(kernel)?;
    profile.validate()?;
    let space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let validated = validate_file_anchors(&space, profile, kernel, record, u64::MAX)?;
    let mut recoverer = PageCacheRecoverer::new(image, space, profile, kernel, &validated)?;
    recoverer.output_limit = max_bytes.min(validated.logical_size);
    recoverer.walk(validated.tree_head)?;
    recoverer.finish(record, validated)
}

/// Recover a file by reversing one physical content address through `struct page`.
///
/// This path proves page-cache and inode membership, but it deliberately does not invent a
/// pathname when no live dentry survives. Callers must independently validate the recovered
/// file semantics before assigning any inferred role such as `/etc/passwd`.
pub fn read_validated_file_from_physical_page(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    physical_address: u64,
    max_size: u64,
) -> Result<LinuxReverseRecoveredFile> {
    let profile = pagecache_profile(kernel)?;
    profile.validate()?;
    ensure!(max_size > 0, "页缓存文件恢复上限必须大于零");

    let space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let runtime = load_runtime_layout(&space, profile, kernel)?;
    let physical_page = physical_address & !(PAGE_SIZE - 1);
    let offset_in_page = physical_address - physical_page;
    let pfn = physical_page / PAGE_SIZE;
    ensure!(pfn < runtime.max_pfn, "内容物理页 PFN 超出 max_pfn");
    let struct_page = runtime
        .vmemmap_base
        .checked_add(
            pfn.checked_mul(PAGE_STRUCT_SIZE)
                .context("struct page PFN 偏移溢出")?,
        )
        .context("struct page 地址溢出")?;
    ensure!(
        is_kernel_pointer(struct_page) && struct_page & (PAGE_STRUCT_SIZE - 1) == 0,
        "反向推导的 struct page 地址无效"
    );

    let mapping = space.read_u64(checked_add(
        struct_page,
        profile.page_mapping,
        "page.mapping",
    )?)?;
    ensure!(
        is_kernel_pointer(mapping),
        "内容页的 page.mapping 不是文件 address_space 指针"
    );
    let page_index = space.read_u64(checked_add(struct_page, profile.page_index, "page.index")?)?;
    let inode = space.read_u64(checked_add(
        mapping,
        profile.address_space_host,
        "address_space.host",
    )?)?;
    ensure!(
        is_kernel_pointer(inode),
        "address_space.host 不是有效 inode 指针"
    );
    ensure!(
        space.read_u64(checked_add(
            inode,
            profile.inode_mapping,
            "inode.i_mapping",
        )?)? == mapping,
        "inode.i_mapping 未反向指回内容页 mapping"
    );
    let mode = read_u16(
        &space,
        checked_add(inode, profile.inode_mode, "inode.i_mode")?,
    )?;
    ensure!(mode & 0xf000 == 0x8000, "反向页缓存候选不是常规文件");
    let superblock =
        space.read_u64(checked_add(inode, profile.inode_super_block, "inode.i_sb")?)?;
    ensure!(is_kernel_pointer(superblock), "inode.i_sb 不是有效内核指针");
    let logical_size =
        space.read_u64(checked_add(inode, profile.inode_file_size, "inode.i_size")?)?;
    ensure!(logical_size > 0, "反向页缓存候选为空文件");
    ensure!(
        logical_size <= i64::MAX as u64,
        "inode.i_size 为负数或超出支持范围"
    );
    ensure!(
        logical_size <= max_size,
        "文件大小 {logical_size} 超过恢复上限 {max_size}"
    );
    let expected_pages = logical_size.saturating_add(PAGE_SIZE - 1) / PAGE_SIZE;
    ensure!(page_index < expected_pages, "内容页索引超出 inode.i_size");
    let trigger_file_offset = page_index
        .checked_mul(PAGE_SIZE)
        .and_then(|offset| offset.checked_add(offset_in_page))
        .context("内容命中的文件偏移溢出")?;
    ensure!(
        trigger_file_offset < logical_size,
        "内容命中位于文件逻辑末尾之外"
    );
    let cached_pages = space.read_u64(checked_add(
        mapping,
        profile.address_space_nrpages,
        "address_space.nrpages",
    )?)?;
    ensure!(cached_pages > 0, "address_space.nrpages 为零");
    ensure!(
        cached_pages <= expected_pages.saturating_add(MAX_FOLIO_PAGES),
        "address_space.nrpages 超出文件大小可解释范围"
    );
    let tree_root = checked_add(mapping, profile.address_space_tree, "address_space 页树根")?;
    let tree_head = space.read_u64(checked_add(tree_root, profile.tree_head, "页树 head")?)?;
    let validated = ValidatedFile {
        mapping,
        logical_size,
        expected_pages,
        cached_pages,
        tree_head,
        vmemmap_base: runtime.vmemmap_base,
        max_pfn: runtime.max_pfn,
        page_offset_base: runtime.page_offset_base,
    };
    let inode_number =
        Some(space.read_u64(checked_add(inode, profile.inode_number, "inode.i_ino")?)?);
    let inode_physical = space.translate(inode).ok();
    let superblock_physical = space.translate(superblock).ok();
    let record = LinuxFileScanRecord {
        source: "reverse_page_cache".to_owned(),
        superblock,
        superblock_hex: format_address(superblock),
        superblock_physical,
        superblock_physical_hex: superblock_physical.map(format_address),
        filesystem: None,
        superblock_id: None,
        device: "unknown".to_owned(),
        device_raw: 0,
        device_major: 0,
        device_minor: 0,
        dentry: 0,
        dentry_hex: format_address(0),
        dentry_physical: None,
        dentry_physical_hex: None,
        parent_dentry: 0,
        parent_dentry_hex: format_address(0),
        observed_parent_dentry: None,
        observed_parent_dentry_hex: None,
        inode,
        inode_hex: format_address(inode),
        inode_physical,
        inode_physical_hex: inode_physical.map(format_address),
        inode_number,
        name: None,
        name_bytes_hex: None,
        name_utf8_valid: None,
        name_status: "not_recovered".to_owned(),
        path: None,
        path_status: "not_recovered_reverse_page_cache".to_owned(),
        path_scope: "none".to_owned(),
        membership_status: "reverse_page_cache_anchor".to_owned(),
        file_type: "regular".to_owned(),
        mode,
        mode_string: format_mode(mode),
        uid: None,
        gid: None,
        link_count: None,
        size: Some(logical_size as i64),
        cached_pages: Some(cached_pages),
        accessed_utc: None,
        modified_utc: None,
        changed_utc: None,
        metadata_complete: false,
        deleted: None,
    };

    let mut recoverer = PageCacheRecoverer::new(image, space, profile, kernel, &validated)?;
    recoverer.walk(validated.tree_head)?;
    let mut file = recoverer.finish(&record, validated)?;
    let trigger_was_tree_validated = file.report.extents.iter().any(|extent| {
        physical_address >= extent.physical_address
            && physical_address < extent.physical_address.saturating_add(extent.length)
            && extent.file_offset + (physical_address - extent.physical_address)
                == trigger_file_offset
    });
    ensure!(
        trigger_was_tree_validated,
        "内容物理页未在 address_space 页树中通过双向校验"
    );
    file.report.source = "linux.pagecache.reverse".to_owned();
    file.report.scope =
        "validated reverse struct-page/address-space/inode/page-tree evidence; pathname not recovered"
            .to_owned();
    let evidence = LinuxReversePageCacheEvidence {
        trigger_physical_address: physical_address,
        trigger_physical_address_hex: format_address(physical_address),
        trigger_file_offset,
        struct_page,
        struct_page_hex: format_address(struct_page),
        page_index,
        inode,
        inode_hex: format_address(inode),
        mapping,
        mapping_hex: format_address(mapping),
        superblock,
        superblock_hex: format_address(superblock),
    };
    Ok(LinuxReverseRecoveredFile {
        file,
        record,
        evidence,
    })
}

/// Recover and safely publish a regular file.
///
/// Complete results are atomically published to `output`. Incomplete results are atomically
/// published to `output + ".partial"`. The default wrapper refuses every existing output;
/// callers which expose the common `--force` flag can use [`dump_validated_file_with_force`].
pub fn dump_validated_file(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    record: &LinuxFileScanRecord,
    output: &Path,
    max_size: u64,
) -> Result<LinuxDumpFileReport> {
    dump_validated_file_with_force(image, kernel, record, output, max_size, false)
}

/// Recover a validated page-cache file with the shared output replacement policy.
pub fn dump_validated_file_with_force(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    record: &LinuxFileScanRecord,
    output: &Path,
    max_size: u64,
    force: bool,
) -> Result<LinuxDumpFileReport> {
    dump_validated_file_cancellable(
        image,
        kernel,
        record,
        output,
        max_size,
        force,
        &CancellationToken::new(),
    )
}

/// Plan validated extents, then stream them into an atomic output. Neither pass allocates
/// the logical file size. The second pass verifies the planned hash before publication.
pub fn dump_validated_file_cancellable(
    image: &MemoryImage,
    kernel: &LinuxKernelContext,
    record: &LinuxFileScanRecord,
    output: &Path,
    max_size: u64,
    force: bool,
    cancellation: &CancellationToken,
) -> Result<LinuxDumpFileReport> {
    cancellation.check_cancelled()?;
    let partial = partial_output_path(output)?;
    let mut output_policy = OutputPolicy::new(force);
    for source in image.sources() {
        output_policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    output_policy.output(OutputTarget::file("recovered_file", output).with_derived_path(&partial));
    output_policy.preflight()?;

    ensure!(max_size > 0, "页缓存文件恢复上限必须大于零");
    let profile = pagecache_profile(kernel)?;
    profile.validate()?;
    let space = LinuxX64AddressSpace::new(image, kernel.directory_table_base)?;
    let validated = validate_file_anchors(&space, profile, kernel, record, max_size)?;
    let mut recoverer = PageCacheRecoverer::new(image, space, profile, kernel, &validated)?;
    recoverer.cancellation = cancellation.clone();
    recoverer.walk(validated.tree_head)?;
    let mut report = recoverer.finish_to(record, validated, &mut std::io::sink())?;
    let actual_path = if report.complete {
        output
    } else {
        partial.as_path()
    };
    output_policy.write_file_atomic(actual_path, |file| {
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);
        stream_reconstruction(image, &report, &mut writer, cancellation)?;
        writer.flush()?;
        cancellation.check_cancelled()
    })?;
    report.output_path = Some(actual_path.display().to_string());
    Ok(report)
}

pub(crate) fn write_recovery_sidecar(
    image: &MemoryImage,
    report: &mut LinuxDumpFileReport,
    actual: &Path,
    policy: &OutputPolicy,
) -> Result<()> {
    #[derive(Serialize)]
    struct Artifact<'a> {
        image_sources: Vec<String>,
        recovery: &'a LinuxDumpFileReport,
    }
    let path = crate::output_policy::append_path_suffix(actual, ".recovery.json");
    report.recovery_report_path = Some(path.display().to_string());
    let artifact = Artifact {
        image_sources: image
            .sources()
            .map(|source| source.path.display().to_string())
            .collect(),
        recovery: report,
    };
    policy
        .write_file_atomic(&path, |file| {
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, &artifact)?;
            writer.flush()?;
            Ok(())
        })
        .with_context(|| {
            format!(
                "文件内容已保存到 {}，但恢复范围说明未能保存到 {}",
                actual.display(),
                path.display()
            )
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeKind {
    Radix,
    XArray,
}

impl TreeKind {
    fn label(self) -> &'static str {
        match self {
            Self::Radix => "radix_tree",
            Self::XArray => "xarray",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum FolioLayout {
    BasePageOnly,
    CompoundPage54 {
        head_flag_bit: u8,
        tail_compound_head_offset: u64,
        tail_order_offset: u64,
    },
    Folio68 {
        head_flag_bit: u8,
        flags_1_offset: u64,
        nr_pages_offset: u64,
    },
}

#[derive(Debug, Clone, Copy)]
struct ExactPageCacheProfile {
    source: &'static str,
    fingerprint: &'static str,
    init_task_symbol: u64,
    vmemmap_base_symbol: u64,
    max_pfn_symbol: u64,
    page_offset_base_symbol: u64,
    static_bases: Option<(u64, u64)>,
    legacy_radix_path: bool,
    dentry_parent: u64,
    dentry_inode: u64,
    dentry_super_block: u64,
    inode_mode: u64,
    inode_super_block: u64,
    inode_mapping: u64,
    inode_number: u64,
    inode_file_size: u64,
    address_space_host: u64,
    address_space_nrpages: u64,
    address_space_tree: u64,
    tree_head: u64,
    page_mapping: u64,
    page_index: u64,
    tree: TreeKind,
    folio: FolioLayout,
}

impl ExactPageCacheProfile {
    fn from_isf(isf: &crate::linux_symbols::LinuxIsf) -> Result<Self> {
        ensure!(
            isf.type_size("page")? == PAGE_STRUCT_SIZE,
            "Volatility 3 ISF struct page 大小不是 {PAGE_STRUCT_SIZE:#x}"
        );
        let (tree, address_space_tree, tree_head, folio) =
            if let Some(offset) = isf.optional_field_offset("address_space", "page_tree")? {
                (
                    TreeKind::Radix,
                    offset,
                    isf.field_offset("radix_tree_root", "rnode")?,
                    FolioLayout::BasePageOnly,
                )
            } else {
                let offset = isf.field_offset("address_space", "i_pages")?;
                let tree_head = isf.field_offset("xarray", "xa_head")?;
                (
                    TreeKind::XArray,
                    offset,
                    tree_head,
                    FolioLayout::from_isf(isf)?,
                )
            };
        let legacy_radix_path = tree == TreeKind::Radix
            && isf
                .optional_field_offset("radix_tree_node", "path")?
                .is_some();
        if legacy_radix_path {
            // 64-slot path/height radix layout from the exact ISF. Old internal
            // child pointers are untagged, and private_data is not a root owner.
            for (field, offset, size) in [
                ("path", 0, 4),
                ("count", 4, 4),
                ("parent", 8, 8),
                (
                    "slots",
                    TREE_SLOTS_OFFSET as u64,
                    (TREE_MAP_SIZE * 8) as u64,
                ),
            ] {
                ensure!(
                    isf.field_offset("radix_tree_node", field)? == offset
                        && isf.field_size("radix_tree_node", field)? == size,
                    "旧 radix_tree_node.{field} 布局不受支持"
                );
            }
            ensure!(
                isf.field_size("radix_tree_root", "height")? == 4,
                "旧 radix_tree_root.height 不是 32 位字段"
            );
        }
        let static_bases = static_page_bases(isf.banner());
        let (vmemmap_base_symbol, page_offset_base_symbol) = if static_bases.is_some() {
            (0, 0)
        } else {
            (
                isf.symbol_address("vmemmap_base")?,
                isf.symbol_address("page_offset_base")?,
            )
        };
        Ok(Self {
            source: "volatility3_isf_pagecache",
            fingerprint: "Volatility 3 ISF; exact linux_banner; runtime-validated page-cache layout",
            init_task_symbol: isf.symbol_address("init_task")?,
            vmemmap_base_symbol,
            max_pfn_symbol: isf.symbol_address("max_pfn")?,
            page_offset_base_symbol,
            static_bases,
            legacy_radix_path,
            dentry_parent: isf.field_offset("dentry", "d_parent")?,
            dentry_inode: isf.field_offset("dentry", "d_inode")?,
            dentry_super_block: isf.field_offset("dentry", "d_sb")?,
            inode_mode: isf.field_offset("inode", "i_mode")?,
            inode_super_block: isf.field_offset("inode", "i_sb")?,
            inode_mapping: isf.field_offset("inode", "i_mapping")?,
            inode_number: isf.field_offset("inode", "i_ino")?,
            inode_file_size: isf.field_offset("inode", "i_size")?,
            address_space_host: isf.field_offset("address_space", "host")?,
            address_space_nrpages: isf.field_offset("address_space", "nrpages")?,
            address_space_tree,
            tree_head,
            page_mapping: isf.field_offset("page", "mapping")?,
            page_index: isf.field_offset("page", "index")?,
            tree,
            folio,
        })
    }

    fn for_banner(banner: &str) -> Option<Self> {
        Some(match banner {
            UBUNTU_4_13_0_36_XENIAL => Self {
                source: "exact_banner_pagecache_profile",
                fingerprint: "Ubuntu Xenial HWE 4.13.0-36.40; build_id=d9142b737a5bb09c7f1aef87f7dd2834dba7d934",
                init_task_symbol: 0xffff_ffff_8221_2480,
                vmemmap_base_symbol: 0xffff_ffff_8224_8a80,
                max_pfn_symbol: 0xffff_ffff_8285_1d70,
                page_offset_base_symbol: 0xffff_ffff_8224_8a90,
                static_bases: None,
                legacy_radix_path: false,
                dentry_parent: 0x18,
                dentry_inode: 0x30,
                dentry_super_block: 0x68,
                inode_mode: 0,
                inode_super_block: 0x28,
                inode_mapping: 0x30,
                inode_number: 0x40,
                inode_file_size: 0x50,
                address_space_host: 0,
                address_space_nrpages: 0x50,
                address_space_tree: 0x08,
                tree_head: 0x08,
                page_mapping: 0x08,
                page_index: 0x10,
                tree: TreeKind::Radix,
                folio: FolioLayout::BasePageOnly,
            },
            UBUNTU_5_4_0_84_BIONIC => Self {
                source: "exact_banner_pagecache_profile",
                fingerprint: "Ubuntu Bionic HWE 5.4.0-84.94; build_id=c56268a4878b2c99f78e1fa2d0ace9bc5f6d575d",
                init_task_symbol: 0xffff_ffff_8261_3780,
                // This is the official System.map symbol for the supported build.  A commonly
                // circulated community JSON profile points at a different build and is unsafe.
                vmemmap_base_symbol: 0xffff_ffff_8243_e330,
                max_pfn_symbol: 0xffff_ffff_82cb_08d8,
                page_offset_base_symbol: 0xffff_ffff_8243_e340,
                static_bases: None,
                legacy_radix_path: false,
                dentry_parent: 0x18,
                dentry_inode: 0x30,
                dentry_super_block: 0x68,
                inode_mode: 0,
                inode_super_block: 0x28,
                inode_mapping: 0x30,
                inode_number: 0x40,
                inode_file_size: 0x50,
                address_space_host: 0,
                address_space_nrpages: 0x58,
                address_space_tree: 0x08,
                tree_head: 0x08,
                page_mapping: 0x18,
                page_index: 0x20,
                tree: TreeKind::XArray,
                folio: FolioLayout::CompoundPage54 {
                    head_flag_bit: 16,
                    // Both offsets are relative to the compound head.  They point into page[1].
                    tail_compound_head_offset: PAGE_STRUCT_SIZE + 0x08,
                    tail_order_offset: PAGE_STRUCT_SIZE + 0x11,
                },
            },
            UBUNTU_6_8_0_49_NOBLE => Self {
                source: "exact_banner_pagecache_profile",
                fingerprint: "Ubuntu Noble 6.8.0-49.49; build_id=9c2aa265a404792954898609a7a72988d9bac935",
                init_task_symbol: 0xffff_ffff_8340_fcc0,
                vmemmap_base_symbol: 0xffff_ffff_82d3_8558,
                max_pfn_symbol: 0xffff_ffff_83ea_c018,
                page_offset_base_symbol: 0xffff_ffff_82d3_8568,
                static_bases: None,
                legacy_radix_path: false,
                dentry_parent: 0x18,
                dentry_inode: 0x30,
                dentry_super_block: 0x70,
                inode_mode: 0,
                inode_super_block: 0x28,
                inode_mapping: 0x30,
                inode_number: 0x40,
                inode_file_size: 0x50,
                address_space_host: 0,
                address_space_nrpages: 0x58,
                address_space_tree: 0x08,
                tree_head: 0x08,
                page_mapping: 0x18,
                page_index: 0x20,
                tree: TreeKind::XArray,
                folio: FolioLayout::Folio68 {
                    head_flag_bit: 6,
                    flags_1_offset: 0x40,
                    nr_pages_offset: 0x64,
                },
            },
            _ => return None,
        })
    }

    fn validate(self) -> Result<()> {
        for (name, address) in [
            ("init_task", self.init_task_symbol),
            ("max_pfn", self.max_pfn_symbol),
        ] {
            ensure!(is_kernel_pointer(address), "profile {name} 符号地址无效");
        }
        if let Some((vmemmap, direct)) = self.static_bases {
            ensure!(
                is_kernel_pointer(vmemmap) && is_kernel_pointer(direct),
                "静态页基址无效"
            );
        } else {
            ensure!(
                is_kernel_pointer(self.vmemmap_base_symbol)
                    && is_kernel_pointer(self.page_offset_base_symbol),
                "页基址符号地址无效"
            );
        }
        ensure!(
            self.page_mapping + 8 <= PAGE_STRUCT_SIZE,
            "page.mapping 布局越界"
        );
        ensure!(
            self.page_index + 8 <= PAGE_STRUCT_SIZE,
            "page.index 布局越界"
        );
        Ok(())
    }
}

impl FolioLayout {
    fn from_isf(isf: &crate::linux_symbols::LinuxIsf) -> Result<Self> {
        let head_flag_bit = u8::try_from(isf.enum_constant("pageflags", "PG_head")?)
            .context("pageflags.PG_head 无法转换为位号")?;
        ensure!(head_flag_bit < 64, "pageflags.PG_head 超过 flags 位宽");
        if let (Some(flags_1_offset), Some(nr_pages_offset)) = (
            isf.optional_field_offset("folio", "_flags_1")?,
            isf.optional_field_offset("folio", "_folio_nr_pages")?,
        ) {
            ensure!(
                isf.field_size("folio", "_flags_1")? == 8
                    && isf.field_size("folio", "_folio_nr_pages")? == 4,
                "folio order/nr_pages 字段宽度不受支持"
            );
            return Ok(Self::Folio68 {
                head_flag_bit,
                flags_1_offset,
                nr_pages_offset,
            });
        }
        // XArray predates struct folio. Derive the older compound-page layout from
        // the exact ISF, not from a guessed kernel version or a similar banner.
        let head = isf.field_offset("page", "compound_head")?;
        let order = isf.field_offset("page", "compound_order")?;
        ensure!(
            head + 8 <= PAGE_STRUCT_SIZE
                && order < PAGE_STRUCT_SIZE
                && isf.field_size("page", "compound_head")? == 8
                && isf.field_size("page", "compound_order")? == 1,
            "page compound 字段布局不受支持"
        );
        Ok(Self::CompoundPage54 {
            head_flag_bit,
            tail_compound_head_offset: PAGE_STRUCT_SIZE + head,
            tail_order_offset: PAGE_STRUCT_SIZE + order,
        })
    }
}

fn pagecache_profile(kernel: &LinuxKernelContext) -> Result<ExactPageCacheProfile> {
    ensure!(
        kernel.system_map.is_none() || kernel.symbol_table.is_some(),
        "System.map 不包含页缓存类型；自动补齐尚未找到匹配的 Linux ISF"
    );
    if let Some(isf) = kernel.symbol_table.as_deref() {
        return ExactPageCacheProfile::from_isf(isf).or_else(|isf_error| {
            ExactPageCacheProfile::for_banner(&kernel.banner).with_context(|| {
                format!(
                    "精确匹配的 Volatility 3 ISF 缺少可用页缓存布局（{isf_error:#}），且当前 Linux 构建没有内置完整 banner profile"
                )
            })
        });
    }
    ExactPageCacheProfile::for_banner(&kernel.banner)
        .context("当前 Linux 构建没有精确匹配的 Volatility 3 ISF 或完整 banner 页缓存布局")
}

struct ValidatedFile {
    mapping: u64,
    logical_size: u64,
    expected_pages: u64,
    cached_pages: u64,
    tree_head: u64,
    vmemmap_base: u64,
    max_pfn: u64,
    page_offset_base: u64,
}

#[derive(Debug, Clone, Copy)]
struct RuntimePageCacheLayout {
    vmemmap_base: u64,
    max_pfn: u64,
    page_offset_base: u64,
}

fn load_runtime_layout(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactPageCacheProfile,
    kernel: &LinuxKernelContext,
) -> Result<RuntimePageCacheLayout> {
    let slide = kernel
        .init_task
        .checked_sub(profile.init_task_symbol)
        .context("运行时 init_task 低于 exact-banner profile 链接地址")?;
    ensure!(
        slide & (PAGE_SIZE - 1) == 0,
        "Linux 内核运行时 slide 未按页对齐"
    );
    ensure!(slide <= 0x4000_0000, "Linux 内核运行时 slide 超出安全范围");
    let runtime_symbol = |symbol: u64, name: &str| {
        symbol
            .checked_add(slide)
            .with_context(|| format!("{name} 运行时地址溢出"))
    };
    let (vmemmap_base, page_offset_base) = if let Some(bases) = profile.static_bases {
        let physical = space.translate(kernel.init_task)?;
        let alias = bases
            .1
            .checked_add(physical)
            .context("静态直接映射地址溢出")?;
        ensure!(
            space.translate(alias)? == physical,
            "静态直接映射基址未通过 init_task 物理页复验"
        );
        bases
    } else {
        (
            space.read_u64(runtime_symbol(profile.vmemmap_base_symbol, "vmemmap_base")?)?,
            space.read_u64(runtime_symbol(
                profile.page_offset_base_symbol,
                "page_offset_base",
            )?)?,
        )
    };
    ensure!(
        is_kernel_pointer(vmemmap_base),
        "vmemmap_base 值不是规范内核地址"
    );
    ensure!(
        vmemmap_base & (PAGE_STRUCT_SIZE - 1) == 0,
        "vmemmap_base 未按 struct page 对齐"
    );
    let max_pfn = space.read_u64(runtime_symbol(profile.max_pfn_symbol, "max_pfn")?)?;
    ensure!(max_pfn > 0, "max_pfn 为零");
    ensure!(max_pfn <= u64::MAX / PAGE_SIZE, "max_pfn 超出物理地址范围");
    ensure!(
        is_kernel_pointer(page_offset_base),
        "page_offset_base 值不是规范内核地址"
    );
    ensure!(
        page_offset_base & (PAGE_SIZE - 1) == 0,
        "page_offset_base 未按页对齐"
    );
    Ok(RuntimePageCacheLayout {
        vmemmap_base,
        max_pfn,
        page_offset_base,
    })
}

fn validate_file_anchors(
    space: &LinuxX64AddressSpace<'_>,
    profile: ExactPageCacheProfile,
    kernel: &LinuxKernelContext,
    record: &LinuxFileScanRecord,
    max_size: u64,
) -> Result<ValidatedFile> {
    ensure!(record.mode & 0xf000 == 0x8000, "仅支持恢复常规文件");
    ensure!(record.file_type == "regular", "filescan 记录不是常规文件");
    ensure!(
        matches!(
            record.membership_status.as_str(),
            "superblock_root" | "validated_link"
        ),
        "filescan 记录没有经过目录成员关系验证"
    );
    for (name, address) in [
        ("dentry", record.dentry),
        ("inode", record.inode),
        ("super_block", record.superblock),
    ] {
        ensure!(is_kernel_pointer(address), "filescan {name} 地址无效");
    }

    ensure!(
        space.read_u64(checked_add(
            record.dentry,
            profile.dentry_parent,
            "dentry.d_parent",
        )?)? == record.parent_dentry,
        "dentry.d_parent 与 filescan 记录不一致"
    );
    ensure!(
        space.read_u64(checked_add(
            record.dentry,
            profile.dentry_inode,
            "dentry.d_inode",
        )?)? == record.inode,
        "dentry.d_inode 与 filescan 记录不一致"
    );
    ensure!(
        space.read_u64(checked_add(
            record.dentry,
            profile.dentry_super_block,
            "dentry.d_sb",
        )?)? == record.superblock,
        "dentry.d_sb 与 filescan 记录不一致"
    );
    ensure!(
        space.read_u64(checked_add(
            record.inode,
            profile.inode_super_block,
            "inode.i_sb",
        )?)? == record.superblock,
        "inode.i_sb 与 filescan 记录不一致"
    );
    ensure!(
        read_u16(
            space,
            checked_add(record.inode, profile.inode_mode, "inode.i_mode")?,
        )? == record.mode,
        "inode.i_mode 与 filescan 记录不一致"
    );
    if let Some(number) = record.inode_number {
        ensure!(
            space.read_u64(checked_add(
                record.inode,
                profile.inode_number,
                "inode.i_ino",
            )?)? == number,
            "inode.i_ino 与 filescan 记录不一致"
        );
    }

    let mapping = space.read_u64(checked_add(
        record.inode,
        profile.inode_mapping,
        "inode.i_mapping",
    )?)?;
    ensure!(
        is_kernel_pointer(mapping),
        "inode.i_mapping 不是有效内核指针"
    );
    ensure!(
        space.read_u64(checked_add(
            mapping,
            profile.address_space_host,
            "address_space.host",
        )?)? == record.inode,
        "address_space.host 未指回 filescan inode"
    );

    let raw_size = space.read_u64(checked_add(
        record.inode,
        profile.inode_file_size,
        "inode.i_size",
    )?)?;
    ensure!(
        raw_size <= i64::MAX as u64,
        "inode.i_size 为负数或超出支持范围"
    );
    let recorded_size = record.size.context("filescan 记录缺少 inode.i_size")?;
    ensure!(recorded_size >= 0, "filescan 记录中的 inode.i_size 为负数");
    ensure!(
        raw_size == recorded_size as u64,
        "inode.i_size 与 filescan 记录不一致"
    );
    ensure!(
        raw_size <= max_size,
        "文件大小 {raw_size} 超过恢复上限 {max_size}"
    );
    let _output_len = usize::try_from(raw_size).context("文件过大，无法分配恢复缓冲区")?;
    let expected_pages = raw_size.saturating_add(PAGE_SIZE - 1) / PAGE_SIZE;

    let cached_pages = space.read_u64(checked_add(
        mapping,
        profile.address_space_nrpages,
        "address_space.nrpages",
    )?)?;
    if let Some(recorded) = record.cached_pages {
        ensure!(
            cached_pages == recorded,
            "address_space.nrpages 与 filescan 记录不一致"
        );
    } else {
        bail!("filescan 记录缺少 address_space.nrpages");
    }
    ensure!(
        cached_pages <= expected_pages.saturating_add(MAX_FOLIO_PAGES),
        "address_space.nrpages 超出文件大小可解释范围"
    );

    let runtime = load_runtime_layout(space, profile, kernel)?;

    let tree_root = checked_add(mapping, profile.address_space_tree, "address_space 页树根")?;
    let tree_head = space.read_u64(checked_add(tree_root, profile.tree_head, "页树 head")?)?;
    Ok(ValidatedFile {
        mapping,
        logical_size: raw_size,
        expected_pages,
        cached_pages,
        tree_head,
        vmemmap_base: runtime.vmemmap_base,
        max_pfn: runtime.max_pfn,
        page_offset_base: runtime.page_offset_base,
    })
}

#[derive(Debug, Clone)]
struct ValidatedFolio {
    page: u64,
    index: u64,
    order: u8,
    pages: u64,
    pfn: u64,
}

struct PendingNode {
    address: u64,
    parent: Option<u64>,
    parent_slot: u8,
    expected_shift: Option<u8>,
    base_index: u64,
}

struct WarningState {
    records: Vec<LinuxPageCacheWarning>,
    samples: BTreeMap<String, usize>,
    total: usize,
    tree_complete: bool,
}

impl Default for WarningState {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            samples: BTreeMap::new(),
            total: 0,
            tree_complete: true,
        }
    }
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
        self.tree_complete &= !structural;
        let count = self.samples.entry(kind.clone()).or_default();
        *count += 1;
        if self.records.len() < MAX_REPORTED_WARNINGS && *count <= MAX_WARNING_SAMPLES_PER_KIND {
            self.records.push(LinuxPageCacheWarning {
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
            self.records.push(LinuxPageCacheWarning {
                kind: "warning_limit".to_owned(),
                message: format!("另有 {omitted} 条重复页缓存告警未展开"),
                address: None,
                address_hex: None,
            });
        }
    }
}

struct PageCacheRecoverer<'a> {
    cancellation: CancellationToken,
    image: &'a MemoryImage,
    space: LinuxX64AddressSpace<'a>,
    profile: ExactPageCacheProfile,
    profile_fingerprint: String,
    mapping: u64,
    logical_size: u64,
    output_limit: u64,
    expected_pages: u64,
    cached_pages: u64,
    vmemmap_base: u64,
    max_pfn: u64,
    page_offset_base: u64,
    tree_root: u64,
    folios: BTreeMap<u64, ValidatedFolio>,
    visited_nodes: HashSet<u64>,
    warnings: WarningState,
    tree_nodes_seen: usize,
    tree_entries_seen: usize,
    cached_pages_validated: u64,
}

impl<'a> PageCacheRecoverer<'a> {
    fn new(
        image: &'a MemoryImage,
        space: LinuxX64AddressSpace<'a>,
        profile: ExactPageCacheProfile,
        kernel: &LinuxKernelContext,
        file: &ValidatedFile,
    ) -> Result<Self> {
        Ok(Self {
            cancellation: CancellationToken::new(),
            image,
            space,
            profile,
            profile_fingerprint: if profile.source == "volatility3_isf_pagecache" {
                kernel
                    .symbol_table
                    .as_deref()
                    .map(|table| table.fingerprint().to_owned())
                    .unwrap_or_else(|| profile.fingerprint.to_owned())
            } else {
                profile.fingerprint.to_owned()
            },
            mapping: file.mapping,
            logical_size: file.logical_size,
            output_limit: file.logical_size,
            expected_pages: file.expected_pages,
            cached_pages: file.cached_pages,
            vmemmap_base: file.vmemmap_base,
            max_pfn: file.max_pfn,
            page_offset_base: file.page_offset_base,
            tree_root: checked_add(
                file.mapping,
                profile.address_space_tree,
                "address_space 页树根",
            )?,
            folios: BTreeMap::new(),
            visited_nodes: HashSet::new(),
            warnings: WarningState::default(),
            tree_nodes_seen: 0,
            tree_entries_seen: 0,
            cached_pages_validated: 0,
        })
    }

    fn walk(&mut self, head: u64) -> Result<()> {
        self.cancellation.check_cancelled()?;
        match self.profile.tree {
            TreeKind::Radix => self.walk_radix(head),
            TreeKind::XArray => self.walk_xarray(head),
        }
    }

    fn walk_radix(&mut self, head: u64) -> Result<()> {
        if head == 0 {
            return Ok(());
        }
        if head & 1 == 0 {
            if head & 2 != 0 {
                self.warnings.push(
                    "radix_exceptional_root",
                    format!("radix 根为 exceptional entry {head:#x}"),
                    None,
                    self.expected_pages > 0,
                );
            } else {
                self.accept_leaf(head, 0, 0, None);
            }
            return Ok(());
        }
        let root = head & !1;
        if root == 0 {
            self.warnings
                .push("radix_retry_root", "radix 根为 retry entry", None, true);
            return Ok(());
        }
        self.walk_nodes(vec![PendingNode {
            address: root,
            parent: None,
            parent_slot: 0,
            expected_shift: None,
            base_index: 0,
        }])
    }

    fn walk_xarray(&mut self, head: u64) -> Result<()> {
        if head == 0 {
            return Ok(());
        }
        match head & 3 {
            0 => {
                self.accept_leaf(head, 0, 0, None);
                Ok(())
            }
            1 | 3 => {
                self.warnings.push(
                    "xarray_value_root",
                    format!("xarray 根为 value entry {head:#x}"),
                    None,
                    self.expected_pages > 0,
                );
                Ok(())
            }
            2 if head > 0x1000 => self.walk_nodes(vec![PendingNode {
                address: head & !3,
                parent: None,
                parent_slot: 0,
                expected_shift: None,
                base_index: 0,
            }]),
            2 => {
                self.warnings.push(
                    "xarray_internal_root",
                    format!("xarray 根为非节点 internal entry {head:#x}"),
                    None,
                    true,
                );
                Ok(())
            }
            _ => unreachable!(),
        }
    }

    fn walk_nodes(&mut self, mut pending: Vec<PendingNode>) -> Result<()> {
        while let Some(node) = pending.pop() {
            self.cancellation.check_cancelled()?;
            if self.tree_nodes_seen >= MAX_TREE_NODES {
                self.warnings.push(
                    "tree_node_limit",
                    format!("页树节点超过安全上限 {MAX_TREE_NODES}"),
                    Some(node.address),
                    true,
                );
                break;
            }
            if !is_kernel_pointer(node.address) {
                self.warnings.push(
                    "tree_node_pointer",
                    "页树节点不是规范且对齐的内核指针",
                    Some(node.address),
                    true,
                );
                continue;
            }
            if !self.visited_nodes.insert(node.address) {
                self.warnings.push(
                    "tree_node_cycle",
                    "页树节点发生环或被多个父节点引用",
                    Some(node.address),
                    true,
                );
                continue;
            }
            self.tree_nodes_seen += 1;

            let node_size = TREE_SLOTS_OFFSET + TREE_MAP_SIZE * 8;
            let mut bytes = vec![0u8; node_size];
            if let Err(error) = self.space.read_virtual(node.address, &mut bytes) {
                self.warnings.push(
                    "tree_node_unreadable",
                    format!("无法读取页树节点：{error:#}"),
                    Some(node.address),
                    true,
                );
                continue;
            }
            let (shift, offset, count, exceptional_count) = if self.profile.legacy_radix_path {
                let header = u64_at(&bytes, 0)?;
                let path = header as u32;
                let height = path & 0xfff; // RADIX_TREE_HEIGHT_MASK for 64 slots.
                let offset = path >> 12;
                if !(1..=11).contains(&height) || offset >= TREE_MAP_SIZE as u32 {
                    self.warnings.push(
                        "tree_node_height",
                        "旧 radix 节点 path/height 无效",
                        Some(node.address),
                        true,
                    );
                    continue;
                }
                let count = (header >> 32) as usize;
                (
                    ((height - 1) * 6) as u8,
                    offset as u8,
                    count & 0x7f,
                    count >> 7,
                )
            } else {
                (bytes[0], bytes[1], bytes[2] as usize, bytes[3] as usize)
            };
            if shift > 60 || !shift.is_multiple_of(TREE_MAP_SHIFT) {
                self.warnings.push(
                    "tree_node_shift",
                    format!("页树节点 shift={shift} 无效"),
                    Some(node.address),
                    true,
                );
                continue;
            }
            if let Some(expected) = node.expected_shift
                && shift != expected
            {
                self.warnings.push(
                    "tree_node_shift",
                    format!("子节点 shift={shift}，期望 {expected}"),
                    Some(node.address),
                    true,
                );
                continue;
            }
            if node.parent.is_some() && offset != node.parent_slot {
                self.warnings.push(
                    "tree_node_offset",
                    format!("子节点 offset={offset}，父槽为 {}", node.parent_slot),
                    Some(node.address),
                    true,
                );
                continue;
            }
            if shift < 64 && node.base_index & low_mask(shift.saturating_add(6)) != 0 {
                self.warnings.push(
                    "tree_node_base",
                    "页树节点路径基址未按节点覆盖范围对齐",
                    Some(node.address),
                    true,
                );
                continue;
            }

            let raw_parent = u64_at(&bytes, 0x08)?;
            if raw_parent != node.parent.unwrap_or(0) {
                self.warnings.push(
                    "tree_node_parent",
                    format!(
                        "页树节点 parent={raw_parent:#x}，期望 {:#x}",
                        node.parent.unwrap_or(0)
                    ),
                    Some(node.address),
                    true,
                );
                continue;
            }
            let owner = u64_at(&bytes, 0x10)?;
            if !self.profile.legacy_radix_path && owner != self.tree_root {
                self.warnings.push(
                    "tree_node_owner",
                    format!(
                        "页树节点 owner/root={owner:#x} 未指向 {:#x}",
                        self.tree_root
                    ),
                    Some(node.address),
                    true,
                );
                continue;
            }

            let mut slots = [0u64; TREE_MAP_SIZE];
            for (slot, value) in slots.iter_mut().enumerate() {
                *value = u64_at(&bytes, TREE_SLOTS_OFFSET + slot * 8)?;
            }
            let nonzero = slots.iter().filter(|entry| **entry != 0).count();
            if count != nonzero {
                self.warnings.push(
                    "tree_node_count",
                    format!("页树节点 count={count}，实际非空槽={nonzero}"),
                    Some(node.address),
                    true,
                );
            }
            if self.profile.tree == TreeKind::Radix && exceptional_count > count {
                self.warnings.push(
                    "radix_exceptional_count",
                    "radix exceptional 计数大于总计数",
                    Some(node.address),
                    true,
                );
            }
            if self.profile.tree == TreeKind::XArray && bytes[3] as usize > count {
                self.warnings.push(
                    "xarray_value_count",
                    "xarray value 计数大于总计数",
                    Some(node.address),
                    true,
                );
            }

            let mut valid_xarray_canonical = HashSet::new();
            for slot in 0..TREE_MAP_SIZE {
                let entry = slots[slot];
                if entry == 0 {
                    continue;
                }
                if self.tree_entries_seen >= MAX_TREE_ENTRIES {
                    self.warnings.push(
                        "tree_entry_limit",
                        format!("页树非空条目超过安全上限 {MAX_TREE_ENTRIES}"),
                        Some(node.address),
                        true,
                    );
                    return Ok(());
                }
                self.tree_entries_seen += 1;
                let Some(index) = compose_index(node.base_index, slot as u8, shift) else {
                    self.warnings.push(
                        "tree_index_overflow",
                        "页树路径索引溢出",
                        Some(node.address + TREE_SLOTS_OFFSET as u64 + slot as u64 * 8),
                        true,
                    );
                    continue;
                };

                match self.profile.tree {
                    TreeKind::Radix => {
                        if self.profile.legacy_radix_path && entry & 1 != 0 {
                            self.warnings.push(
                                "radix_retry_entry",
                                "旧 radix 缩树重试指针不能作为有效叶子或子节点",
                                Some(entry),
                                true,
                            );
                        } else if self.profile.legacy_radix_path && entry & 3 == 0 && shift > 0 {
                            pending.push(PendingNode {
                                address: entry,
                                parent: Some(node.address),
                                parent_slot: slot as u8,
                                expected_shift: Some(shift - TREE_MAP_SHIFT),
                                base_index: index,
                            });
                        } else if entry & 1 != 0 {
                            let target = entry & !1;
                            let slot_start = node.address + TREE_SLOTS_OFFSET as u64;
                            let slot_end = slot_start + (TREE_MAP_SIZE * 8) as u64;
                            if target >= slot_start && target < slot_end && target & 7 == 0 {
                                let canonical = ((target - slot_start) / 8) as usize;
                                if canonical >= slot || slots[canonical] & 3 != 0 {
                                    self.warnings.push(
                                        "radix_sibling",
                                        "radix sibling 未引用更早的规范叶子槽",
                                        Some(
                                            node.address
                                                + TREE_SLOTS_OFFSET as u64
                                                + slot as u64 * 8,
                                        ),
                                        true,
                                    );
                                }
                            } else if target == 0 {
                                self.warnings.push(
                                    "radix_retry_entry",
                                    "radix retry entry 表明快照遍历状态不稳定",
                                    Some(node.address + TREE_SLOTS_OFFSET as u64 + slot as u64 * 8),
                                    true,
                                );
                            } else if shift == 0 {
                                self.warnings.push(
                                    "radix_child_at_leaf",
                                    "radix shift=0 节点包含子节点",
                                    Some(target),
                                    true,
                                );
                            } else {
                                pending.push(PendingNode {
                                    address: target,
                                    parent: Some(node.address),
                                    parent_slot: slot as u8,
                                    expected_shift: Some(shift - TREE_MAP_SHIFT),
                                    base_index: index,
                                });
                            }
                        } else if entry & 2 != 0 {
                            self.warnings.push(
                                "radix_exceptional_entry",
                                format!("跳过 radix exceptional entry {entry:#x}"),
                                Some(node.address + TREE_SLOTS_OFFSET as u64 + slot as u64 * 8),
                                index < self.expected_pages,
                            );
                        } else if shift != 0 {
                            self.warnings.push(
                                "radix_leaf_level",
                                format!("基础页叶子出现在 shift={shift} 节点"),
                                Some(entry),
                                true,
                            );
                        } else {
                            self.accept_leaf(entry, index, shift, None);
                        }
                    }
                    TreeKind::XArray => match entry & 3 {
                        0 => {
                            let folio = self.validate_folio(entry, index, shift);
                            if let Some(folio) = folio
                                && self.validate_xarray_siblings(
                                    &slots,
                                    slot,
                                    shift,
                                    &folio,
                                    node.address,
                                )
                            {
                                valid_xarray_canonical.insert(slot);
                                self.insert_folio(folio);
                            }
                        }
                        1 | 3 => self.warnings.push(
                            "xarray_value_entry",
                            format!("跳过 xarray value entry {entry:#x}"),
                            Some(node.address + TREE_SLOTS_OFFSET as u64 + slot as u64 * 8),
                            index < self.expected_pages,
                        ),
                        2 if entry > 0x1000 => {
                            if shift == 0 {
                                self.warnings.push(
                                    "xarray_child_at_leaf",
                                    "xarray shift=0 节点包含子节点",
                                    Some(entry & !3),
                                    true,
                                );
                            } else {
                                pending.push(PendingNode {
                                    address: entry & !3,
                                    parent: Some(node.address),
                                    parent_slot: slot as u8,
                                    expected_shift: Some(shift - TREE_MAP_SHIFT),
                                    base_index: index,
                                });
                            }
                        }
                        2 => {
                            let internal = entry >> 2;
                            if internal < 256 {
                                let canonical = internal as usize;
                                if canonical >= slot || !valid_xarray_canonical.contains(&canonical)
                                {
                                    self.warnings.push(
                                        "xarray_sibling",
                                        format!("xarray sibling 指向未验证槽 {canonical}"),
                                        Some(
                                            node.address
                                                + TREE_SLOTS_OFFSET as u64
                                                + slot as u64 * 8,
                                        ),
                                        true,
                                    );
                                }
                            } else {
                                self.warnings.push(
                                    "xarray_internal_entry",
                                    format!("跳过非节点 xarray internal entry {entry:#x}"),
                                    Some(node.address + TREE_SLOTS_OFFSET as u64 + slot as u64 * 8),
                                    true,
                                );
                            }
                        }
                        _ => unreachable!(),
                    },
                }
            }
        }
        Ok(())
    }

    fn validate_xarray_siblings(
        &mut self,
        slots: &[u64; TREE_MAP_SIZE],
        slot: usize,
        shift: u8,
        folio: &ValidatedFolio,
        node: u64,
    ) -> bool {
        if folio.order < shift {
            self.warnings.push(
                "folio_tree_level",
                format!(
                    "order={} folio 不能覆盖 shift={shift} xarray 槽",
                    folio.order
                ),
                Some(folio.page),
                true,
            );
            return false;
        }
        let delta = folio.order - shift;
        if delta > TREE_MAP_SHIFT {
            self.warnings.push(
                "folio_tree_level",
                format!("order={} folio 应位于更高层 xarray 节点", folio.order),
                Some(folio.page),
                true,
            );
            return false;
        }
        let covered_slots = 1usize << delta;
        if !slot.is_multiple_of(covered_slots) || slot + covered_slots > TREE_MAP_SIZE {
            self.warnings.push(
                "folio_slot_alignment",
                "folio 的 xarray 规范槽未按 order 对齐",
                Some(folio.page),
                true,
            );
            return false;
        }
        let sibling = ((slot as u64) << 2) | 2;
        for (sibling_slot, entry) in slots
            .iter()
            .enumerate()
            .skip(slot + 1)
            .take(covered_slots - 1)
        {
            if *entry != sibling {
                self.warnings.push(
                    "folio_sibling_range",
                    format!(
                        "folio order={} 缺少 xarray sibling 槽 {sibling_slot}",
                        folio.order
                    ),
                    Some(node + TREE_SLOTS_OFFSET as u64 + sibling_slot as u64 * 8),
                    true,
                );
                return false;
            }
        }
        true
    }

    fn accept_leaf(&mut self, page: u64, index: u64, shift: u8, _slot: Option<u8>) {
        if let Some(folio) = self.validate_folio(page, index, shift) {
            self.insert_folio(folio);
        }
    }

    fn validate_folio(&mut self, page: u64, index: u64, shift: u8) -> Option<ValidatedFolio> {
        if !is_kernel_pointer(page) || page & (PAGE_STRUCT_SIZE - 1) != 0 {
            self.warnings.push(
                "page_pointer",
                "页树叶子不是对齐的 struct page 内核地址",
                Some(page),
                true,
            );
            return None;
        }
        let Some(delta) = page.checked_sub(self.vmemmap_base) else {
            self.warnings.push(
                "page_below_vmemmap",
                "struct page 地址低于 vmemmap_base",
                Some(page),
                true,
            );
            return None;
        };
        if delta % PAGE_STRUCT_SIZE != 0 {
            self.warnings.push(
                "page_vmemmap_alignment",
                "struct page 地址无法整除 sizeof(struct page)",
                Some(page),
                true,
            );
            return None;
        }
        let pfn = delta / PAGE_STRUCT_SIZE;
        if pfn >= self.max_pfn {
            self.warnings.push(
                "page_pfn_range",
                format!(
                    "struct page 推导 PFN {pfn:#x} 不小于 max_pfn {:#x}",
                    self.max_pfn
                ),
                Some(page),
                true,
            );
            return None;
        }

        let flags = match self.space.read_u64(page) {
            Ok(value) => value,
            Err(error) => {
                self.warnings.push(
                    "page_unreadable",
                    format!("无法读取 struct page.flags：{error:#}"),
                    Some(page),
                    true,
                );
                return None;
            }
        };
        let mapping = match self
            .space
            .read_u64(page.checked_add(self.profile.page_mapping)?)
        {
            Ok(value) => value,
            Err(error) => {
                self.warnings.push(
                    "page_unreadable",
                    format!("无法读取 struct page.mapping：{error:#}"),
                    Some(page),
                    true,
                );
                return None;
            }
        };
        if mapping != self.mapping {
            self.warnings.push(
                "page_mapping_mismatch",
                format!("page.mapping={mapping:#x}，期望 {:#x}", self.mapping),
                Some(page),
                true,
            );
            return None;
        }
        let page_index = match self
            .space
            .read_u64(page.checked_add(self.profile.page_index)?)
        {
            Ok(value) => value,
            Err(error) => {
                self.warnings.push(
                    "page_unreadable",
                    format!("无法读取 struct page.index：{error:#}"),
                    Some(page),
                    true,
                );
                return None;
            }
        };
        if page_index != index {
            self.warnings.push(
                "page_index_mismatch",
                format!("page.index={page_index:#x}，页树路径索引={index:#x}"),
                Some(page),
                true,
            );
            return None;
        }

        let order = match self.folio_order(page, flags) {
            Ok(order) => order,
            Err(error) => {
                self.warnings.push(
                    "folio_layout",
                    format!("无法验证 folio：{error:#}"),
                    Some(page),
                    true,
                );
                return None;
            }
        };
        if order > MAX_FOLIO_ORDER {
            self.warnings.push(
                "folio_order",
                format!("folio order={order} 超过安全上限 {MAX_FOLIO_ORDER}"),
                Some(page),
                true,
            );
            return None;
        }
        let pages = 1u64 << order;
        if index & (pages - 1) != 0 {
            self.warnings.push(
                "folio_index_alignment",
                format!("folio index={index:#x} 未按 {pages} 页对齐"),
                Some(page),
                true,
            );
            return None;
        }
        if shift > order && self.profile.tree == TreeKind::XArray {
            self.warnings.push(
                "folio_tree_level",
                format!("order={order} folio 出现在 shift={shift} xarray 节点"),
                Some(page),
                true,
            );
            return None;
        }
        let Some(pfn_end) = pfn.checked_add(pages) else {
            self.warnings
                .push("folio_pfn_overflow", "folio PFN 范围溢出", Some(page), true);
            return None;
        };
        if pfn_end > self.max_pfn {
            self.warnings.push(
                "folio_pfn_range",
                "folio PFN 范围超过 max_pfn",
                Some(page),
                true,
            );
            return None;
        }
        if index.checked_add(pages).is_none() {
            self.warnings.push(
                "folio_index_overflow",
                "folio 索引范围溢出",
                Some(page),
                true,
            );
            return None;
        }
        Some(ValidatedFolio {
            page,
            index,
            order,
            pages,
            pfn,
        })
    }

    fn folio_order(&self, page: u64, flags: u64) -> Result<u8> {
        match self.profile.folio {
            FolioLayout::BasePageOnly => Ok(0),
            FolioLayout::CompoundPage54 {
                head_flag_bit,
                tail_compound_head_offset,
                tail_order_offset,
            } => {
                if flags & (1u64 << head_flag_bit) == 0 {
                    return Ok(0);
                }
                let encoded_head = self.space.read_u64(checked_add(
                    page,
                    tail_compound_head_offset,
                    "page[1].compound_head",
                )?)?;
                ensure!(
                    encoded_head == page | 1,
                    "page[1].compound_head 未编码回 head page"
                );
                let order = read_u8(
                    &self.space,
                    checked_add(page, tail_order_offset, "page[1].compound_order")?,
                )?;
                ensure!(order > 0, "PG_head 已设置但 compound_order 为零");
                Ok(order)
            }
            FolioLayout::Folio68 {
                head_flag_bit,
                flags_1_offset,
                nr_pages_offset,
            } => {
                if flags & (1u64 << head_flag_bit) == 0 {
                    return Ok(0);
                }
                let flags_1 =
                    self.space
                        .read_u64(checked_add(page, flags_1_offset, "folio._flags_1")?)?;
                let order = (flags_1 & 0xff) as u8;
                ensure!(order > 0, "PG_head 已设置但 folio order 为零");
                ensure!(order <= MAX_FOLIO_ORDER, "folio order 超出安全上限");
                let nr_pages = self.space.read_u32(checked_add(
                    page,
                    nr_pages_offset,
                    "folio._folio_nr_pages",
                )?)? as u64;
                ensure!(
                    nr_pages == 1u64 << order,
                    "folio._folio_nr_pages 与 order 不一致"
                );
                Ok(order)
            }
        }
    }

    fn insert_folio(&mut self, folio: ValidatedFolio) {
        let end = folio.index + folio.pages;
        if let Some((_, previous)) = self.folios.range(..=folio.index).next_back()
            && previous.index + previous.pages > folio.index
        {
            self.warnings.push(
                "folio_overlap",
                format!("folio [{:#x}, {end:#x}) 与既有范围重叠", folio.index),
                Some(folio.page),
                true,
            );
            return;
        }
        if let Some((next, _)) = self.folios.range(folio.index..).next()
            && *next < end
        {
            self.warnings.push(
                "folio_overlap",
                format!("folio [{:#x}, {end:#x}) 与既有范围重叠", folio.index),
                Some(folio.page),
                true,
            );
            return;
        }
        self.cached_pages_validated = self.cached_pages_validated.saturating_add(folio.pages);
        self.folios.insert(folio.index, folio);
    }

    fn finish(
        self,
        record: &LinuxFileScanRecord,
        file: ValidatedFile,
    ) -> Result<LinuxRecoveredFile> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(usize::try_from(self.output_limit)?)
            .context("无法为页缓存文件恢复分配逻辑输出缓冲区")?;
        let report = self.finish_to(record, file, &mut bytes)?;
        Ok(LinuxRecoveredFile { bytes, report })
    }

    fn finish_to(
        mut self,
        record: &LinuxFileScanRecord,
        file: ValidatedFile,
        writer: &mut impl Write,
    ) -> Result<LinuxDumpFileReport> {
        if self.cached_pages_validated != self.cached_pages {
            self.warnings.push(
                "cached_page_count_mismatch",
                format!(
                    "address_space.nrpages={}，页树强校验后覆盖 {} 页",
                    self.cached_pages, self.cached_pages_validated
                ),
                Some(self.mapping),
                true,
            );
        }

        let output_pages = self.output_limit.saturating_add(PAGE_SIZE - 1) / PAGE_SIZE;
        let mut output = RecoveryWriter::new(writer, &self.cancellation);
        let mut missing_ranges = Vec::new();
        let mut extents = Vec::new();
        let mut pages_recovered = 0u64;
        let folios: Vec<_> = self.folios.values().cloned().collect();
        for folio in folios {
            if folio.index >= output_pages {
                continue;
            }
            let pages_in_file = folio.pages.min(output_pages - folio.index);
            for offset in 0..pages_in_file {
                self.cancellation.check_cancelled()?;
                let index = folio.index + offset;
                let pfn = folio.pfn + offset;
                let physical = pfn.checked_mul(PAGE_SIZE).context("恢复页物理地址溢出")?;
                let mut page_bytes = [0u8; PAGE_SIZE as usize];
                if let Err(error) = self.image.read_physical(physical, &mut page_bytes) {
                    self.warnings.push(
                        "physical_page_unreadable",
                        format!("PFN {pfn:#x} 不完整或位于采集缺口：{error:#}"),
                        Some(physical),
                        false,
                    );
                    continue;
                }
                let file_offset = index.checked_mul(PAGE_SIZE).context("恢复文件偏移溢出")?;
                let take = PAGE_SIZE.min(self.output_limit - file_offset);
                if file_offset > output.offset {
                    missing_ranges.push(LinuxMissingRange {
                        file_offset: output.offset,
                        length: file_offset - output.offset,
                    });
                }
                output.zeros_until(file_offset)?;
                output.write(&page_bytes[..take as usize])?;
                pages_recovered += 1;
                push_extent(&mut extents, file_offset, take, index, physical);
            }
        }

        if output.offset < self.logical_size {
            missing_ranges.push(LinuxMissingRange {
                file_offset: output.offset,
                length: self.logical_size - output.offset,
            });
        }
        output.zeros_until(self.output_limit)?;
        if self.output_limit < self.logical_size {
            self.warnings.push(
                "prefix_read_limit",
                format!(
                    "仅核对文件前缀 0..{}；后续 {} 字节未在本次预算内读取",
                    self.output_limit,
                    self.logical_size - self.output_limit
                ),
                None,
                false,
            );
        }
        let missing_bytes = missing_ranges.iter().map(|range| range.length).sum::<u64>();
        let recovered_bytes = self.logical_size - missing_bytes;
        ensure!(
            self.logical_size == 0 || recovered_bytes > 0,
            "非空文件未能从经过强校验的页缓存中恢复任何字节；拒绝生成全零重建文件"
        );
        self.warnings.finish();
        let tree_complete = self.warnings.tree_complete;
        let complete = missing_bytes == 0 && tree_complete;
        let sha256 = hex::encode(output.hash.finalize());
        let sha256_scope = if complete {
            "complete_recovered_file"
        } else if self.output_limit < self.logical_size {
            "bounded_prefix_buffer_only; missing_prefix_pages_zero_filled; unread_suffix_not_in_buffer"
        } else if missing_bytes > 0 {
            "reconstruction_with_zero_filled_reported_missing_ranges"
        } else {
            "all_logical_bytes_recovered_but_page_tree_structurally_incomplete"
        }
        .to_owned();
        let report = LinuxDumpFileReport {
            source: "linux.pagecache.dump".to_owned(),
            scope: "validated_page_cache_only; no filesystem-block fallback".to_owned(),
            profile_source: self.profile.source.to_owned(),
            profile_fingerprint: self.profile_fingerprint,
            tree_kind: self.profile.tree.label().to_owned(),
            path: record.path.clone(),
            path_scope: record.path_scope.clone(),
            path_status: record.path_status.clone(),
            membership_status: record.membership_status.clone(),
            superblock: record.superblock,
            superblock_hex: record.superblock_hex.clone(),
            filesystem: record.filesystem.clone(),
            superblock_id: record.superblock_id.clone(),
            device: record.device.clone(),
            deleted: record.deleted,
            dentry: record.dentry,
            dentry_hex: format_address(record.dentry),
            inode: record.inode,
            inode_hex: format_address(record.inode),
            inode_number: record.inode_number,
            mapping: self.mapping,
            mapping_hex: format_address(self.mapping),
            vmemmap_base: self.vmemmap_base,
            vmemmap_base_hex: format_address(self.vmemmap_base),
            page_offset_base: self.page_offset_base,
            page_offset_base_hex: format_address(self.page_offset_base),
            max_pfn: self.max_pfn,
            logical_size: self.logical_size,
            output_size: self.output_limit,
            recovered_bytes,
            missing_bytes,
            expected_pages: self.expected_pages,
            cached_pages_reported: self.cached_pages,
            cached_pages_validated: self.cached_pages_validated,
            tree_nodes_seen: self.tree_nodes_seen,
            tree_entries_seen: self.tree_entries_seen,
            folios_seen: self.folios.len(),
            pages_recovered,
            tree_complete,
            complete,
            extents,
            missing_ranges,
            warning_count: self.warnings.total,
            warnings: self.warnings.records,
            filescan_selection: None,
            sha256,
            sha256_scope,
            output_path: None,
            recovery_report_path: None,
        };
        debug_assert_eq!(file.mapping, report.mapping);
        Ok(report)
    }
}

/// The byte buffer is bounded even when an inode has a large sparse logical size.
struct RecoveryWriter<'a, W: Write> {
    writer: &'a mut W,
    cancellation: &'a CancellationToken,
    hash: Sha256,
    offset: u64,
}

impl<'a, W: Write> RecoveryWriter<'a, W> {
    fn new(writer: &'a mut W, cancellation: &'a CancellationToken) -> Self {
        Self {
            writer,
            cancellation,
            hash: Sha256::new(),
            offset: 0,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.cancellation.check_cancelled()?;
        self.writer.write_all(bytes)?;
        self.hash.update(bytes);
        self.offset += bytes.len() as u64;
        Ok(())
    }

    fn zeros_until(&mut self, offset: u64) -> Result<()> {
        ensure!(offset >= self.offset, "页缓存导出范围重叠或倒退");
        if offset == self.offset {
            return Ok(());
        }
        let zeros = [0u8; 64 * 1024];
        while self.offset < offset {
            self.write(&zeros[..(offset - self.offset).min(zeros.len() as u64) as usize])?;
        }
        Ok(())
    }
}

fn stream_reconstruction(
    image: &MemoryImage,
    report: &LinuxDumpFileReport,
    writer: &mut impl Write,
    cancellation: &CancellationToken,
) -> Result<()> {
    let progress = crate::progress::start_progress("Linux 文件内容导出", report.output_size);
    let mut output = RecoveryWriter::new(writer, cancellation);
    let mut bytes = vec![0u8; 1024 * 1024];
    for extent in &report.extents {
        let previous = output.offset;
        output.zeros_until(extent.file_offset)?;
        progress.advance(output.offset - previous);
        let mut copied = 0;
        while copied < extent.length {
            cancellation.check_cancelled()?;
            let take = (extent.length - copied).min(bytes.len() as u64) as usize;
            image.read_physical(extent.physical_address + copied, &mut bytes[..take])?;
            output.write(&bytes[..take])?;
            copied += take as u64;
            progress.advance(take as u64);
        }
    }
    let previous = output.offset;
    output.zeros_until(report.output_size)?;
    progress.advance(output.offset - previous);
    ensure!(
        hex::encode(output.hash.finalize()) == report.sha256,
        "镜像内容在恢复核对后发生变化，拒绝发布文件"
    );
    cancellation.check_cancelled()?;
    progress.finish();
    Ok(())
}

fn push_extent(
    extents: &mut Vec<LinuxRecoveredExtent>,
    file_offset: u64,
    length: u64,
    page_index: u64,
    physical: u64,
) {
    if let Some(last) = extents.last_mut()
        && last.file_offset + last.length == file_offset
        && last.physical_address + last.length == physical
    {
        last.length += length;
        last.last_page_index = page_index;
        return;
    }
    extents.push(LinuxRecoveredExtent {
        file_offset,
        length,
        first_page_index: page_index,
        last_page_index: page_index,
        physical_address: physical,
        physical_address_hex: format_address(physical),
    });
}

#[cfg(test)]
fn build_missing_ranges(recovered: &[bool], logical_size: u64) -> Vec<LinuxMissingRange> {
    let mut ranges = Vec::new();
    let mut start = None;
    for (index, present) in recovered.iter().copied().enumerate() {
        if !present && start.is_none() {
            start = Some(index as u64 * PAGE_SIZE);
        }
        if present && let Some(offset) = start.take() {
            ranges.push(LinuxMissingRange {
                file_offset: offset,
                length: index as u64 * PAGE_SIZE - offset,
            });
        }
    }
    if let Some(offset) = start {
        ranges.push(LinuxMissingRange {
            file_offset: offset,
            length: logical_size - offset,
        });
    }
    ranges
}

/// Return the sibling path used for an incomplete, explicitly zero-gap reconstruction.
pub fn partial_output_path(output: &Path) -> Result<PathBuf> {
    let name = output.file_name().context("输出路径必须包含文件名")?;
    ensure!(!name.is_empty(), "输出文件名不能为空");
    let mut partial_name = name.to_os_string();
    partial_name.push(".partial");
    let mut partial = output.to_path_buf();
    partial.set_file_name(partial_name);
    Ok(partial)
}

fn checked_add(base: u64, offset: u64, field: &str) -> Result<u64> {
    base.checked_add(offset)
        .with_context(|| format!("{field} 地址溢出"))
}

fn read_u8(space: &LinuxX64AddressSpace<'_>, address: u64) -> Result<u8> {
    let mut bytes = [0u8; 1];
    space.read_virtual(address, &mut bytes)?;
    Ok(bytes[0])
}

fn read_u16(space: &LinuxX64AddressSpace<'_>, address: u64) -> Result<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .context("页树节点字段越界")?
        .try_into()
        .expect("长度已经验证");
    Ok(u64::from_le_bytes(raw))
}

fn compose_index(base: u64, slot: u8, shift: u8) -> Option<u64> {
    let slot = slot as u64;
    if shift >= 64 || slot > (u64::MAX >> shift) {
        return None;
    }
    base.checked_add(slot << shift)
}

fn low_mask(bits: u8) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else if bits == 0 {
        0
    } else {
        (1u64 << bits) - 1
    }
}

fn format_address(address: u64) -> String {
    format!("{address:#018x}")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    const TEST_DENTRY: u64 = 0xffff_8880_1000_0000;
    const TEST_INODE: u64 = 0xffff_8880_1000_1000;
    const TEST_MAPPING: u64 = 0xffff_8880_1000_2000;
    const TEST_NODE: u64 = 0xffff_8880_1000_3000;
    const TEST_SUPERBLOCK: u64 = 0xffff_8880_1000_4000;
    const TEST_VMEMMAP: u64 = 0xffff_ea00_0000_0000;
    const TEST_PAGE_OFFSET: u64 = 0xffff_8880_0000_0000;
    const TEST_MAX_PFN: u64 = 0x1000;

    #[test]
    fn xarray_without_folio_uses_exact_compound_page_fields() {
        use base64::Engine;
        use serde_json::json;
        let path = std::env::temp_dir().join(format!(
            "starmem-page-layout-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let document = json!({"metadata":{"format":"6.2.0"},
            "base_types":{"long unsigned int":{"size":8},"u8":{"size":1}},
            "user_types":{"page":{"size":64,"fields":{
                "compound_head":{"offset":8,"type":{"kind":"base","name":"long unsigned int"}},
                "compound_order":{"offset":17,"type":{"kind":"base","name":"u8"}}
            }}},
            "enums":{"pageflags":{"size":8,"constants":{"PG_head":16}}},
            "symbols":{"_stext":{"address":0xffff_ffff_8100_0000u64},
                "linux_banner":{"address":0xffff_ffff_8100_1000u64,
                    "constant_data":base64::engine::general_purpose::STANDARD.encode(b"Linux version 5.4.0-test #1 SMP\0")}}});
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        let isf = crate::linux_symbols::load_linux_isf_for_features(
            &path,
            [crate::linux_symbols::LinuxSymbolFeature::Vfs],
        )
        .unwrap();
        fs::remove_file(path).unwrap();
        let layout = FolioLayout::from_isf(&isf).unwrap();
        assert!(matches!(
            layout,
            FolioLayout::CompoundPage54 {
                head_flag_bit: 16,
                tail_compound_head_offset: 72,
                tail_order_offset: 81
            }
        ));
    }

    #[test]
    fn exact_profiles_pin_official_symbols_and_layouts() {
        let p413 = ExactPageCacheProfile::for_banner(UBUNTU_4_13_0_36_XENIAL).unwrap();
        assert_eq!(p413.vmemmap_base_symbol, 0xffff_ffff_8224_8a80);
        assert_eq!(p413.max_pfn_symbol, 0xffff_ffff_8285_1d70);
        assert_eq!(p413.page_mapping, 0x08);
        assert_eq!(p413.page_index, 0x10);
        assert_eq!(p413.tree, TreeKind::Radix);

        let p54 = ExactPageCacheProfile::for_banner(UBUNTU_5_4_0_84_BIONIC).unwrap();
        assert_eq!(p54.vmemmap_base_symbol, 0xffff_ffff_8243_e330);
        assert_eq!(p54.max_pfn_symbol, 0xffff_ffff_82cb_08d8);
        assert_eq!(p54.page_mapping, 0x18);
        assert_eq!(p54.page_index, 0x20);
        assert_eq!(p54.tree, TreeKind::XArray);

        let p68 = ExactPageCacheProfile::for_banner(UBUNTU_6_8_0_49_NOBLE).unwrap();
        assert_eq!(p68.vmemmap_base_symbol, 0xffff_ffff_82d3_8558);
        assert_eq!(p68.max_pfn_symbol, 0xffff_ffff_83ea_c018);
        assert_eq!(p68.page_mapping, 0x18);
        assert_eq!(p68.page_index, 0x20);
        assert_eq!(p68.tree, TreeKind::XArray);
        assert!(ExactPageCacheProfile::for_banner("Linux version similar-but-not-exact").is_none());
    }

    #[test]
    fn coalesces_explicit_missing_ranges_without_hiding_partial_tail() {
        let ranges = build_missing_ranges(&[true, false, false, true, false], 0x4123);
        assert_eq!(
            ranges,
            vec![
                LinuxMissingRange {
                    file_offset: 0x1000,
                    length: 0x2000,
                },
                LinuxMissingRange {
                    file_offset: 0x4000,
                    length: 0x123,
                },
            ]
        );
    }

    #[test]
    fn xarray_sibling_encoding_is_not_mistaken_for_a_node() {
        for slot in 0..64u64 {
            let sibling = (slot << 2) | 2;
            assert_eq!(sibling & 3, 2);
            assert!(sibling <= 0x1000);
        }
    }

    #[test]
    fn output_always_uses_a_sibling_partial_name() {
        let path = Path::new("evidence/passwd");
        assert_eq!(
            partial_output_path(path).unwrap(),
            PathBuf::from("evidence/passwd.partial")
        );
    }

    #[test]
    fn recovers_a_68_order_two_folio_and_validates_sibling_slots() {
        let fixture = xarray_68_fixture(0, 4, "xarray-folio");
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let recovered = read_validated_file(
            &image,
            &fixture.kernel,
            &fixture.record,
            fixture.record.size.unwrap() as u64,
        )
        .unwrap();

        assert!(recovered.report.complete);
        assert!(recovered.report.tree_complete);
        assert_eq!(recovered.report.cached_pages_validated, 4);
        assert_eq!(recovered.report.pages_recovered, 4);
        assert!(recovered.report.missing_ranges.is_empty());
        assert_eq!(&recovered.bytes[..0x1000], vec![0x31; 0x1000]);
        assert_eq!(&recovered.bytes[0x1000..0x2000], vec![0x32; 0x1000]);
        assert_eq!(&recovered.bytes[0x2000..0x3000], vec![0x33; 0x1000]);
        assert!(recovered.bytes[0x3000..].iter().all(|byte| *byte == 0x34));
        assert_eq!(recovered.report.extents.len(), 1);

        drop(image);
        fs::remove_file(fixture.image_path).unwrap();
    }

    #[test]
    fn structurally_incomplete_xarray_keeps_partial_publication() {
        let fixture = xarray_68_fixture(0, 3, "xarray-count-mismatch");
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let output = temporary_path("pagecache-output").with_extension("dump");
        let partial = partial_output_path(&output).unwrap();
        let report = dump_validated_file(
            &image,
            &fixture.kernel,
            &fixture.record,
            &output,
            fixture.record.size.unwrap() as u64,
        )
        .unwrap();

        assert!(!report.complete);
        assert_eq!(report.recovered_bytes, report.logical_size);
        assert_eq!(report.missing_bytes, 0);
        assert_eq!(
            report.sha256_scope,
            "all_logical_bytes_recovered_but_page_tree_structurally_incomplete"
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.kind == "tree_node_count")
        );
        assert!(!output.exists());
        assert!(partial.exists());
        assert_eq!(report.output_path, Some(partial.display().to_string()));

        drop(image);
        fs::remove_file(fixture.image_path).unwrap();
        fs::remove_file(partial).unwrap();
    }

    #[test]
    fn bounded_prefix_keeps_inode_size_and_never_allocates_or_hashes_the_unread_tail() {
        let fixture = xarray_68_fixture(0, 4, "bounded-prefix");
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let recovered =
            read_validated_file_prefix(&image, &fixture.kernel, &fixture.record, 100).unwrap();
        assert_eq!(recovered.bytes.len(), 100);
        assert!(recovered.bytes.iter().all(|b| *b == 0x31));
        assert_eq!(
            recovered.report.logical_size,
            fixture.record.size.unwrap() as u64
        );
        assert_eq!(recovered.report.output_size, 100);
        assert_eq!(recovered.report.recovered_bytes, 100);
        assert_eq!(recovered.report.extents[0].length, 100);
        assert_eq!(recovered.report.missing_ranges[0].file_offset, 100);
        assert_eq!(
            recovered.report.missing_bytes,
            recovered.report.logical_size - 100
        );
        assert!(!recovered.report.complete);
        assert!(
            recovered
                .report
                .sha256_scope
                .starts_with("bounded_prefix_buffer_only")
        );
        assert!(read_validated_file(&image, &fixture.kernel, &fixture.record, 100).is_err());
        drop(image);
        fs::remove_file(fixture.image_path).unwrap();
    }

    #[test]
    fn complete_dump_creates_parent_directories_and_publishes_final_path() {
        let fixture = xarray_68_fixture(0, 4, "xarray-parent-output");
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let root = temporary_path("pagecache-parent");
        let output = root.join("nested").join("passwd");
        let partial = partial_output_path(&output).unwrap();
        let report = dump_validated_file(
            &image,
            &fixture.kernel,
            &fixture.record,
            &output,
            fixture.record.size.unwrap() as u64,
        )
        .unwrap();

        assert!(report.complete);
        assert!(output.exists());
        assert!(!partial.exists());
        assert_eq!(report.output_path, Some(output.display().to_string()));
        let expected = read_validated_file(
            &image,
            &fixture.kernel,
            &fixture.record,
            report.logical_size,
        )
        .unwrap();
        assert_eq!(fs::read(&output).unwrap(), expected.bytes);
        assert_eq!(report.sha256, expected.report.sha256);

        drop(image);
        fs::remove_file(fixture.image_path).unwrap();
        fs::remove_file(output).unwrap();
        fs::remove_dir(root.join("nested")).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn existing_output_is_rejected_before_recovery_and_never_overwritten() {
        let fixture = xarray_68_fixture(0, 4, "xarray-existing-output");
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let output = temporary_path("pagecache-existing").with_extension("dump");
        fs::write(&output, b"preserve-existing-evidence").unwrap();

        let error = dump_validated_file(
            &image,
            &fixture.kernel,
            &fixture.record,
            &output,
            fixture.record.size.unwrap() as u64,
        )
        .unwrap_err();
        assert!(error.to_string().contains("已存在"));
        assert_eq!(fs::read(&output).unwrap(), b"preserve-existing-evidence");

        drop(image);
        fs::remove_file(fixture.image_path).unwrap();
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn force_replaces_only_a_regular_pagecache_output() {
        let fixture = xarray_68_fixture(0, 4, "xarray-force-output");
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let output = temporary_path("pagecache-force").with_extension("dump");
        fs::write(&output, b"old-output").unwrap();

        let report = dump_validated_file_with_force(
            &image,
            &fixture.kernel,
            &fixture.record,
            &output,
            fixture.record.size.unwrap() as u64,
            true,
        )
        .unwrap();
        assert!(report.complete);
        assert_ne!(fs::read(&output).unwrap(), b"old-output");

        drop(image);
        fs::remove_file(fixture.image_path).unwrap();
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn force_never_replaces_the_input_image() {
        let fixture = xarray_68_fixture(0, 4, "xarray-protected-image");
        let original = fs::read(&fixture.image_path).unwrap();
        let image = MemoryImage::open(&fixture.image_path).unwrap();

        let error = dump_validated_file_with_force(
            &image,
            &fixture.kernel,
            &fixture.record,
            &fixture.image_path,
            fixture.record.size.unwrap() as u64,
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("受保护输入"));
        assert_eq!(fs::read(&fixture.image_path).unwrap(), original);

        drop(image);
        fs::remove_file(fixture.image_path).unwrap();
    }

    #[test]
    fn refuses_to_return_an_all_zero_reconstruction_for_a_nonempty_file() {
        let fixture = xarray_68_fixture(4, 4, "xarray-index-mismatch");
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let error = read_validated_file(
            &image,
            &fixture.kernel,
            &fixture.record,
            fixture.record.size.unwrap() as u64,
        )
        .unwrap_err();
        assert!(error.to_string().contains("未能从经过强校验的页缓存"));

        drop(image);
        fs::remove_file(fixture.image_path).unwrap();
    }

    #[test]
    fn recovers_a_413_tagged_radix_node_leaf() {
        let fixture = radix_413_fixture("radix-leaf");
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let recovered = read_validated_file(
            &image,
            &fixture.kernel,
            &fixture.record,
            fixture.record.size.unwrap() as u64,
        )
        .unwrap();

        assert!(recovered.report.complete);
        assert_eq!(recovered.report.tree_kind, "radix_tree");
        assert_eq!(recovered.report.tree_nodes_seen, 1);
        assert_eq!(recovered.report.pages_recovered, 1);
        assert!(recovered.bytes.iter().all(|byte| *byte == 0x5a));

        drop(image);
        fs::remove_file(fixture.image_path).unwrap();
    }

    #[test]
    fn legacy_radix_reads_path_height_and_untagged_children_but_rejects_retry_nodes() {
        for retry in [false, true] {
            let mut profile = ExactPageCacheProfile::for_banner(UBUNTU_4_13_0_36_XENIAL).unwrap();
            profile.legacy_radix_path = true;
            let child = TEST_NODE + 0x10_0000;
            let index = 3 * 64 + 2;
            let logical_size = (index + 1) * PAGE_SIZE;
            let pfn = 0x900;
            let page = TEST_VMEMMAP + pfn * PAGE_STRUCT_SIZE;
            let mut memory = SyntheticMemory::new();
            map_common_objects(&mut memory, profile, page);
            memory.map_new_page(child);
            write_common_anchors(&mut memory, profile, logical_size, 1, TEST_NODE | 1);
            memory.put_virtual_u64(TEST_NODE, 2 | (1 << 32));
            memory.put_virtual_u64(
                TEST_NODE + TREE_SLOTS_OFFSET as u64 + 3 * 8,
                child | u64::from(retry),
            );
            memory.put_virtual_u64(child, (3 << 12) | 1 | (1 << 32));
            memory.put_virtual_u64(child + 8, TEST_NODE);
            // Old private_data is zero, not the modern owner/root pointer.
            memory.put_virtual_u64(child + TREE_SLOTS_OFFSET as u64 + 2 * 8, page);
            memory.put_virtual_u64(page + profile.page_mapping, TEST_MAPPING);
            memory.put_virtual_u64(page + profile.page_index, index);
            memory.fill_physical(pfn * PAGE_SIZE, PAGE_SIZE, 0x5a);
            let path = memory.publish("legacy-radix");
            let image = MemoryImage::open(&path).unwrap();
            let space = LinuxX64AddressSpace::new(&image, 0x1000).unwrap();
            let kernel = synthetic_kernel(RHEL_3_10_0_123, profile);
            let record = synthetic_record(logical_size, 1);
            let file =
                validate_file_anchors(&space, profile, &kernel, &record, logical_size).unwrap();
            let mut recoverer =
                PageCacheRecoverer::new(&image, space, profile, &kernel, &file).unwrap();
            recoverer.walk(file.tree_head).unwrap();
            if retry {
                assert!(recoverer.folios.is_empty());
                assert!(!recoverer.warnings.tree_complete);
                assert!(
                    recoverer
                        .warnings
                        .records
                        .iter()
                        .any(|warning| warning.kind == "radix_retry_entry")
                );
            } else {
                assert_eq!(recoverer.folios.len(), 1);
                assert_eq!(recoverer.folios[&index].pfn, pfn);
                let recovered = recoverer.finish(&record, file).unwrap();
                assert!(recovered.report.tree_complete);
                assert!(!recovered.report.complete); // Earlier file pages are absent.
                assert_eq!(recovered.report.recovered_bytes, PAGE_SIZE);
                assert!(
                    recovered.bytes[index as usize * PAGE_SIZE as usize..]
                        .iter()
                        .all(|byte| *byte == 0x5a)
                );
            }
            drop(image);
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn rhel_static_bases_require_exact_banner_and_matching_direct_map_alias() {
        assert_eq!(
            static_page_bases(RHEL_3_10_0_123),
            Some((0xffff_ea00_0000_0000, 0xffff_8800_0000_0000))
        );
        assert!(static_page_bases("Linux version 3.10.0-123.el7.x86_64").is_none());
        assert!(static_page_bases(&RHEL_3_10_0_123.replace("Mon May 5", "Mon Jun 30")).is_none());
        for valid_alias in [false, true] {
            let mut profile = ExactPageCacheProfile::for_banner(UBUNTU_4_13_0_36_XENIAL).unwrap();
            profile.static_bases = Some((TEST_VMEMMAP, TEST_PAGE_OFFSET));
            let mut memory = SyntheticMemory::new();
            let physical_page = memory.map_new_page(profile.init_task_symbol);
            memory.map_page(
                TEST_PAGE_OFFSET + physical_page,
                physical_page + if valid_alias { 0 } else { PAGE_SIZE },
            );
            memory.map_new_page(profile.max_pfn_symbol);
            memory.put_virtual_u64(profile.max_pfn_symbol, TEST_MAX_PFN);
            let path = memory.publish("static-page-bases");
            let image = MemoryImage::open(&path).unwrap();
            let space = LinuxX64AddressSpace::new(&image, 0x1000).unwrap();
            let kernel = synthetic_kernel(RHEL_3_10_0_123, profile);
            let layout = load_runtime_layout(&space, profile, &kernel);
            assert_eq!(layout.is_ok(), valid_alias);
            drop(image);
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn reverses_a_physical_content_address_through_page_cache_anchors() {
        let fixture = radix_413_fixture("radix-reverse-page");
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let trigger = 0x900 * PAGE_SIZE + 0x20;
        let recovered = read_validated_file_from_physical_page(
            &image,
            &fixture.kernel,
            trigger,
            fixture.record.size.unwrap() as u64,
        )
        .unwrap();

        assert_eq!(recovered.evidence.trigger_physical_address, trigger);
        assert_eq!(recovered.evidence.trigger_file_offset, 0x20);
        assert_eq!(recovered.evidence.page_index, 0);
        assert_eq!(recovered.evidence.inode, TEST_INODE);
        assert_eq!(recovered.evidence.mapping, TEST_MAPPING);
        assert_eq!(recovered.record.dentry, 0);
        assert_eq!(recovered.record.source, "reverse_page_cache");
        assert_eq!(recovered.file.report.source, "linux.pagecache.reverse");
        assert!(recovered.file.report.complete);

        drop(image);
        fs::remove_file(fixture.image_path).unwrap();
    }

    struct SyntheticFixture {
        image_path: PathBuf,
        kernel: LinuxKernelContext,
        record: LinuxFileScanRecord,
    }

    fn xarray_68_fixture(page_index: u64, declared_count: u8, label: &str) -> SyntheticFixture {
        xarray_68_fixture_sized(page_index, declared_count, label, PAGE_SIZE * 4 - 17)
    }

    fn xarray_68_fixture_sized(
        page_index: u64,
        declared_count: u8,
        label: &str,
        logical_size: u64,
    ) -> SyntheticFixture {
        let profile = ExactPageCacheProfile::for_banner(UBUNTU_6_8_0_49_NOBLE).unwrap();
        let pfn = 0x800;
        let page = TEST_VMEMMAP + pfn * PAGE_STRUCT_SIZE;
        let mut memory = SyntheticMemory::new();
        map_common_objects(&mut memory, profile, page);
        write_common_anchors(&mut memory, profile, logical_size, 4, TEST_NODE | 2);

        memory.put_virtual_u8(TEST_NODE, 0);
        memory.put_virtual_u8(TEST_NODE + 1, 0);
        memory.put_virtual_u8(TEST_NODE + 2, declared_count);
        memory.put_virtual_u8(TEST_NODE + 3, 0);
        memory.put_virtual_u64(TEST_NODE + 8, 0);
        memory.put_virtual_u64(TEST_NODE + 0x10, TEST_MAPPING + 8);
        memory.put_virtual_u64(TEST_NODE + TREE_SLOTS_OFFSET as u64, page);
        for slot in 1..4u64 {
            memory.put_virtual_u64(TEST_NODE + TREE_SLOTS_OFFSET as u64 + slot * 8, 2);
        }

        memory.put_virtual_u64(page, 1 << 6);
        memory.put_virtual_u64(page + profile.page_mapping, TEST_MAPPING);
        memory.put_virtual_u64(page + profile.page_index, page_index);
        memory.put_virtual_u64(page + 0x40, 2);
        memory.put_virtual_u32(page + 0x64, 4);
        for offset in 0..4u64 {
            memory.fill_physical((pfn + offset) * PAGE_SIZE, PAGE_SIZE, 0x31 + offset as u8);
        }

        let image_path = memory.publish(label);
        SyntheticFixture {
            image_path,
            kernel: synthetic_kernel(UBUNTU_6_8_0_49_NOBLE, profile),
            record: synthetic_record(logical_size, 4),
        }
    }

    #[test]
    fn streaming_dump_exceeds_64_mib_and_preserves_missing_tail() {
        use std::io::{Read, Seek, SeekFrom};
        let size = 65 * 1024 * 1024 + 17;
        let fixture = xarray_68_fixture_sized(0, 4, "large-streaming-dump", size);
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let output = temporary_path("large-streaming-output");
        let report =
            dump_validated_file(&image, &fixture.kernel, &fixture.record, &output, size).unwrap();
        let partial = partial_output_path(&output).unwrap();
        assert!(!output.exists());
        assert!(!report.complete);
        assert_eq!(report.output_size, size);
        assert_eq!(report.recovered_bytes, PAGE_SIZE * 4);
        assert_eq!(
            report.missing_ranges,
            vec![LinuxMissingRange {
                file_offset: PAGE_SIZE * 4,
                length: size - PAGE_SIZE * 4
            }]
        );
        assert_eq!(fs::metadata(&partial).unwrap().len(), size);
        let mut file = fs::File::open(&partial).unwrap();
        let mut head = [0u8; 16];
        file.read_exact(&mut head).unwrap();
        assert_eq!(head, [0x31; 16]);
        file.seek(SeekFrom::End(-16)).unwrap();
        file.read_exact(&mut head).unwrap();
        assert_eq!(head, [0; 16]);
        drop(file);
        drop(image);
        fs::remove_file(partial).unwrap();
        fs::remove_file(fixture.image_path).unwrap();
    }

    #[test]
    fn cancelled_streaming_dump_does_not_publish_or_replace_outputs() {
        let fixture = xarray_68_fixture(0, 4, "cancel-streaming-dump");
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let output = temporary_path("cancel-streaming-output");
        fs::write(&output, b"existing").unwrap();
        let token = CancellationToken::new();
        token.request_cancel();
        let error = dump_validated_file_cancellable(
            &image,
            &fixture.kernel,
            &fixture.record,
            &output,
            64 * 1024 * 1024,
            true,
            &token,
        )
        .unwrap_err();
        assert!(crate::cancellation::is_cancellation_error(&error));
        assert_eq!(fs::read(&output).unwrap(), b"existing");
        assert!(!partial_output_path(&output).unwrap().exists());
        drop(image);
        fs::remove_file(output).unwrap();
        fs::remove_file(fixture.image_path).unwrap();
    }

    #[test]
    fn streaming_writer_observes_cancellation_between_chunks() {
        struct CancelWriter(CancellationToken);
        impl Write for CancelWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.request_cancel();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let token = CancellationToken::new();
        let mut sink = CancelWriter(token.clone());
        let mut writer = RecoveryWriter::new(&mut sink, &token);
        let error = writer.zeros_until(128 * 1024).unwrap_err();
        assert!(crate::cancellation::is_cancellation_error(&error));
        assert_eq!(writer.offset, 64 * 1024);
    }

    #[test]
    fn recovery_sidecar_keeps_source_identity_hash_and_partial_ranges() {
        let size = PAGE_SIZE * 6;
        let fixture = xarray_68_fixture_sized(0, 4, "sidecar", size);
        let image = MemoryImage::open(&fixture.image_path).unwrap();
        let output = temporary_path("sidecar-output");
        let mut report =
            dump_validated_file(&image, &fixture.kernel, &fixture.record, &output, size).unwrap();
        let actual = partial_output_path(&output).unwrap();
        let path = crate::output_policy::append_path_suffix(&actual, ".recovery.json");
        let mut policy = OutputPolicy::new(false);
        policy.protect_file("image", &fixture.image_path);
        policy.output_file("sidecar", &path);
        write_recovery_sidecar(&image, &mut report, &actual, &policy).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            json["image_sources"][0],
            fixture.image_path.display().to_string()
        );
        assert_eq!(json["recovery"]["dentry_hex"], fixture.record.dentry_hex);
        assert_eq!(json["recovery"]["sha256"], report.sha256);
        assert_eq!(
            json["recovery"]["missing_ranges"][0]["file_offset"],
            PAGE_SIZE * 4
        );
        assert_eq!(
            json["recovery"]["missing_ranges"][0]["length"],
            PAGE_SIZE * 2
        );
        assert_eq!(json["recovery"]["complete"], false);
        assert_eq!(
            json["recovery"]["output_path"],
            actual.display().to_string()
        );
        drop(image);
        fs::remove_file(actual).unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_file(fixture.image_path).unwrap();
    }

    fn radix_413_fixture(label: &str) -> SyntheticFixture {
        let profile = ExactPageCacheProfile::for_banner(UBUNTU_4_13_0_36_XENIAL).unwrap();
        let logical_size = 0x731;
        let pfn = 0x900;
        let page = TEST_VMEMMAP + pfn * PAGE_STRUCT_SIZE;
        let mut memory = SyntheticMemory::new();
        map_common_objects(&mut memory, profile, page);
        write_common_anchors(&mut memory, profile, logical_size, 1, TEST_NODE | 1);

        memory.put_virtual_u8(TEST_NODE, 0);
        memory.put_virtual_u8(TEST_NODE + 1, 0);
        memory.put_virtual_u8(TEST_NODE + 2, 1);
        memory.put_virtual_u8(TEST_NODE + 3, 0);
        memory.put_virtual_u64(TEST_NODE + 8, 0);
        memory.put_virtual_u64(TEST_NODE + 0x10, TEST_MAPPING + 8);
        memory.put_virtual_u64(TEST_NODE + TREE_SLOTS_OFFSET as u64, page);
        memory.put_virtual_u64(page, 0);
        memory.put_virtual_u64(page + profile.page_mapping, TEST_MAPPING);
        memory.put_virtual_u64(page + profile.page_index, 0);
        memory.fill_physical(pfn * PAGE_SIZE, PAGE_SIZE, 0x5a);

        let image_path = memory.publish(label);
        SyntheticFixture {
            image_path,
            kernel: synthetic_kernel(UBUNTU_4_13_0_36_XENIAL, profile),
            record: synthetic_record(logical_size, 1),
        }
    }

    fn map_common_objects(memory: &mut SyntheticMemory, profile: ExactPageCacheProfile, page: u64) {
        for address in [
            TEST_DENTRY,
            TEST_INODE,
            TEST_MAPPING,
            TEST_NODE,
            TEST_SUPERBLOCK,
            profile.vmemmap_base_symbol,
            profile.max_pfn_symbol,
            profile.page_offset_base_symbol,
            page,
        ] {
            memory.map_new_page(address);
        }
        memory.put_virtual_u64(profile.vmemmap_base_symbol, TEST_VMEMMAP);
        memory.put_virtual_u64(profile.max_pfn_symbol, TEST_MAX_PFN);
        memory.put_virtual_u64(profile.page_offset_base_symbol, TEST_PAGE_OFFSET);
    }

    fn write_common_anchors(
        memory: &mut SyntheticMemory,
        profile: ExactPageCacheProfile,
        logical_size: u64,
        cached_pages: u64,
        tree_head: u64,
    ) {
        memory.put_virtual_u64(TEST_DENTRY + 0x18, TEST_DENTRY);
        memory.put_virtual_u64(TEST_DENTRY + 0x30, TEST_INODE);
        memory.put_virtual_u64(TEST_DENTRY + profile.dentry_super_block, TEST_SUPERBLOCK);
        memory.put_virtual_u16(TEST_INODE, 0o100644);
        memory.put_virtual_u64(TEST_INODE + 0x28, TEST_SUPERBLOCK);
        memory.put_virtual_u64(TEST_INODE + 0x30, TEST_MAPPING);
        memory.put_virtual_u64(TEST_INODE + 0x40, 42);
        memory.put_virtual_u64(TEST_INODE + 0x50, logical_size);
        memory.put_virtual_u64(TEST_MAPPING, TEST_INODE);
        memory.put_virtual_u64(TEST_MAPPING + 0x10, tree_head);
        memory.put_virtual_u64(TEST_MAPPING + profile.address_space_nrpages, cached_pages);
    }

    fn synthetic_kernel(banner: &str, profile: ExactPageCacheProfile) -> LinuxKernelContext {
        LinuxKernelContext {
            architecture: "x86_64_4level".to_owned(),
            banner: banner.to_owned(),
            banner_physical_address: 0,
            directory_table_base: 0x1000,
            page_table_source: "synthetic_test".to_owned(),
            vmcoreinfo_physical_address: None,
            init_task: profile.init_task_symbol,
            init_task_physical: 0,
            profile_source: "synthetic_test".to_owned(),
            profile_fingerprint: profile.fingerprint.to_owned(),
            btf_physical_address: None,
            task_struct_size: 0,
            task_struct_offsets: BTreeMap::new(),
            symbol_table: None,
            system_map: None,
        }
    }

    fn synthetic_record(logical_size: u64, cached_pages: u64) -> LinuxFileScanRecord {
        LinuxFileScanRecord {
            source: "synthetic_test".to_owned(),
            superblock: TEST_SUPERBLOCK,
            superblock_hex: format_address(TEST_SUPERBLOCK),
            superblock_physical: None,
            superblock_physical_hex: None,
            filesystem: Some("ext4".to_owned()),
            superblock_id: Some("test".to_owned()),
            device: "8:1".to_owned(),
            device_raw: (8 << 20) | 1,
            device_major: 8,
            device_minor: 1,
            dentry: TEST_DENTRY,
            dentry_hex: format_address(TEST_DENTRY),
            dentry_physical: None,
            dentry_physical_hex: None,
            parent_dentry: TEST_DENTRY,
            parent_dentry_hex: format_address(TEST_DENTRY),
            observed_parent_dentry: Some(TEST_DENTRY),
            observed_parent_dentry_hex: Some(format_address(TEST_DENTRY)),
            inode: TEST_INODE,
            inode_hex: format_address(TEST_INODE),
            inode_physical: None,
            inode_physical_hex: None,
            inode_number: Some(42),
            name: Some("passwd".to_owned()),
            name_bytes_hex: Some(hex::encode("passwd")),
            name_utf8_valid: Some(true),
            name_status: "decoded".to_owned(),
            path: Some("/etc/passwd".to_owned()),
            path_status: "resolved".to_owned(),
            path_scope: "superblock_relative".to_owned(),
            membership_status: "validated_link".to_owned(),
            file_type: "regular".to_owned(),
            mode: 0o100644,
            mode_string: "-rw-r--r--".to_owned(),
            uid: Some(0),
            gid: Some(0),
            link_count: Some(1),
            size: Some(logical_size as i64),
            cached_pages: Some(cached_pages),
            accessed_utc: None,
            modified_utc: None,
            changed_utc: None,
            metadata_complete: true,
            deleted: Some(false),
        }
    }

    struct SyntheticMemory {
        bytes: Vec<u8>,
        next_table: u64,
        next_object: u64,
        virtual_pages: BTreeMap<u64, u64>,
    }

    impl SyntheticMemory {
        fn new() -> Self {
            Self {
                bytes: vec![0u8; 0x100_0000],
                next_table: 0x2000,
                next_object: 0x10_0000,
                virtual_pages: BTreeMap::new(),
            }
        }

        fn map_new_page(&mut self, address: u64) -> u64 {
            let virtual_page = address & !(PAGE_SIZE - 1);
            if let Some(physical) = self.virtual_pages.get(&virtual_page) {
                return *physical;
            }
            let physical = self.next_object;
            self.next_object += PAGE_SIZE;
            self.map_page(virtual_page, physical);
            self.virtual_pages.insert(virtual_page, physical);
            physical
        }

        fn map_page(&mut self, virtual_page: u64, physical_page: u64) {
            let mut table = 0x1000;
            for shift in [39, 30, 21] {
                let index = (virtual_page >> shift) & 0x1ff;
                let entry_address = table + index * 8;
                let entry = self.get_u64(entry_address);
                table = if entry & 1 != 0 {
                    entry & 0x000f_ffff_ffff_f000
                } else {
                    let child = self.next_table;
                    self.next_table += PAGE_SIZE;
                    self.put_physical_u64(entry_address, child | 3);
                    child
                };
            }
            let pte = table + ((virtual_page >> 12) & 0x1ff) * 8;
            self.put_physical_u64(pte, physical_page | 3);
        }

        fn put_virtual_u8(&mut self, address: u64, value: u8) {
            let physical = self.virtual_to_physical(address);
            self.bytes[physical] = value;
        }

        fn put_virtual_u16(&mut self, address: u64, value: u16) {
            self.put_virtual_bytes(address, &value.to_le_bytes());
        }

        fn put_virtual_u32(&mut self, address: u64, value: u32) {
            self.put_virtual_bytes(address, &value.to_le_bytes());
        }

        fn put_virtual_u64(&mut self, address: u64, value: u64) {
            self.put_virtual_bytes(address, &value.to_le_bytes());
        }

        fn put_virtual_bytes(&mut self, address: u64, value: &[u8]) {
            for (offset, byte) in value.iter().copied().enumerate() {
                let physical = self.virtual_to_physical(address + offset as u64);
                self.bytes[physical] = byte;
            }
        }

        fn virtual_to_physical(&self, address: u64) -> usize {
            let page = address & !(PAGE_SIZE - 1);
            let physical = self.virtual_pages.get(&page).unwrap();
            (physical + (address & (PAGE_SIZE - 1))) as usize
        }

        fn fill_physical(&mut self, address: u64, length: u64, value: u8) {
            let start = address as usize;
            let end = (address + length) as usize;
            self.bytes[start..end].fill(value);
        }

        fn get_u64(&self, address: u64) -> u64 {
            u64::from_le_bytes(
                self.bytes[address as usize..address as usize + 8]
                    .try_into()
                    .unwrap(),
            )
        }

        fn put_physical_u64(&mut self, address: u64, value: u64) {
            self.bytes[address as usize..address as usize + 8]
                .copy_from_slice(&value.to_le_bytes());
        }

        fn publish(self, label: &str) -> PathBuf {
            let path = temporary_path(label);
            fs::write(&path, self.bytes).unwrap();
            path
        }
    }

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "starmem-linux-pagecache-{label}-{}-{nonce}.raw",
            std::process::id()
        ))
    }
}
