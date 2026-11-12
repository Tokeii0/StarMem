use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::{Context, Result, ensure};
use rayon::prelude::*;
use serde::Serialize;

use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;

const PAGE_SIZE: u64 = 0x1000;
const ADDRESS_MASK_4K: u64 = 0x000f_ffff_ffff_f000;
// Windows stores transition-page PFNs below bit 45. Bit 45 belongs to the
// transition PTE state and must not be carried into the physical address.
const TRANSITION_ADDRESS_MASK_4K: u64 = 0x0000_dfff_ffff_f000;
const ADDRESS_MASK_2M: u64 = 0x000f_ffff_ffe0_0000;
const ADDRESS_MASK_1G: u64 = 0x000f_ffff_c000_0000;
const MAX_DENSE_TARGET_BITMAP_BYTES: usize = 64 * 1024 * 1024;
const MAX_REVERSE_READ_FAILURE_DETAILS: usize = 128;
pub const DEFAULT_REVERSE_TRANSLATION_ENTRY_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtualAddressRegion {
    User,
    Kernel,
    All,
}

#[derive(Debug, Clone, Serialize)]
pub struct VirtualMapping {
    pub virtual_start: u64,
    pub virtual_end: u64,
    pub physical_start: u64,
    pub length: u64,
    pub source_page_size: u64,
    pub writable: bool,
    pub user_accessible: bool,
    pub executable: bool,
    pub global: bool,
}

#[derive(Debug, Serialize)]
pub struct VirtualMappingReport {
    pub directory_table_base: u64,
    pub region: String,
    pub mapped_bytes: u64,
    pub mapping_count: usize,
    pub page_table_pages_read: u64,
    pub truncated: bool,
    pub mappings: Vec<VirtualMapping>,
    pub warnings: Vec<String>,
}

/// One page-table page that could not be read during a reverse translation.
///
/// Reverse translation is deliberately best-effort below the root PML4: one
/// missing subtree must not discard mappings recovered from other subtrees.
/// Callers must nevertheless treat any reported failure as an incomplete
/// search universe.
#[derive(Debug, Clone, Serialize)]
pub struct ReverseTranslationReadFailure {
    pub level: String,
    pub table_physical_address: u64,
    pub virtual_prefix: u64,
    pub message: String,
}

/// Detailed result of one batched physical-to-virtual page-table traversal.
#[derive(Debug, Clone, Serialize)]
pub struct ReverseTranslationReport {
    pub mappings: HashMap<u64, Vec<u64>>,
    pub target_pages: usize,
    pub mapped_target_pages: usize,
    /// Successful page-table read operations, including repeated reads if a
    /// malformed hierarchy references the same table more than once.
    pub page_table_pages_read: u64,
    /// Failed page-table read operations below the root PML4.
    pub page_table_read_failures: u64,
    pub read_failures: Vec<ReverseTranslationReadFailure>,
    pub read_failure_details_truncated: bool,
    pub page_table_entries_examined: u64,
    pub page_table_entry_limit: usize,
    pub traversal_limit_reached: bool,
    pub max_mappings_per_page: usize,
    /// Exact when `mapping_limit_exceeded=false`; otherwise this is the proven
    /// lower bound `max_mappings_per_page + 1`. Alias storage itself is bounded.
    pub max_mappings_observed_lower_bound: usize,
    /// True only when at least one physical page had more aliases than the
    /// configured limit. Equality alone does not count as truncation.
    pub mapping_limit_exceeded: bool,
    pub mapping_limit_exceeded_pages: Vec<u64>,
    /// True when the globally bounded API could not retain every physical-page
    /// identifier whose per-page alias limit was exceeded. The boolean above
    /// remains authoritative even when this detail list is truncated.
    pub mapping_limit_exceeded_pages_truncated: bool,
    /// Optional hard bound on the number of alias entries retained while the
    /// page-table walk is running. `None` preserves the historical wrapper
    /// behaviour and does not impose a command-global storage limit.
    pub alias_storage_limit: Option<usize>,
    /// Peak alias entries retained during the walk. This includes the one
    /// extra sentinel retained per physical page to prove a per-page overflow,
    /// so it can be larger than the number of returned mappings.
    pub alias_storage_entries_retained: usize,
    /// True only when another distinct alias would have required storage past
    /// `alias_storage_limit`. Merely filling the limit does not mark the
    /// result incomplete.
    pub alias_storage_limit_exceeded: bool,
}

pub struct X64AddressSpace<'a> {
    image: &'a MemoryImage,
    directory_table_base: u64,
}

/// Windows virtual reads must keep the guest's paging mode and pointer width together.
pub enum WindowsAddressSpace<'a> {
    X64(X64AddressSpace<'a>),
    X86Pae(X86PaeAddressSpace<'a>),
}

impl WindowsAddressSpace<'_> {
    pub fn pointer_size(&self) -> u64 {
        match self {
            Self::X64(_) => 8,
            Self::X86Pae(_) => 4,
        }
    }

    pub fn translate(&self, address: u64) -> Result<u64> {
        match self {
            Self::X64(space) => space.translate(address),
            Self::X86Pae(space) => space.translate(address),
        }
    }

    pub fn read_virtual(&self, address: u64, out: &mut [u8]) -> Result<()> {
        match self {
            Self::X64(space) => space.read_virtual(address, out),
            Self::X86Pae(space) => space.read_virtual(address, out),
        }
    }

    pub fn read_u32(&self, address: u64) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.read_virtual(address, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_u64(&self, address: u64) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.read_virtual(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn read_pointer(&self, address: u64) -> Result<u64> {
        match self {
            Self::X64(space) => space.read_u64(address),
            Self::X86Pae(space) => space.read_u32(address).map(u64::from),
        }
    }

    pub fn enumerate_mappings_cancellable(
        &self,
        region: VirtualAddressRegion,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<VirtualMappingReport> {
        match self {
            Self::X64(space) => space.enumerate_mappings_cancellable(region, limit, cancellation),
            Self::X86Pae(space) => {
                space.enumerate_mappings_cancellable(region, limit, cancellation)
            }
        }
    }

    pub fn reverse_translate_kernel_pages(
        &self,
        physical_pages: &HashSet<u64>,
        max_mappings_per_page: usize,
    ) -> Result<HashMap<u64, Vec<u64>>> {
        match self {
            Self::X64(space) => {
                space.reverse_translate_kernel_pages(physical_pages, max_mappings_per_page)
            }
            Self::X86Pae(space) => {
                space.reverse_translate_kernel_pages(physical_pages, max_mappings_per_page)
            }
        }
    }
}

/// Windows x86 PAE address space.
///
/// PAE uses a four-entry PDPT selected by bits 31..30, followed by 512-entry
/// page-directory and page-table levels. Entries are 64-bit even though the
/// virtual address and pointers stored by the guest are 32-bit.
pub struct X86PaeAddressSpace<'a> {
    image: &'a MemoryImage,
    directory_table_base: u64,
}

impl<'a> X86PaeAddressSpace<'a> {
    pub fn new(image: &'a MemoryImage, directory_table_base: u64) -> Result<Self> {
        ensure!(directory_table_base != 0, "PAE 页表基址为零");
        let directory_table_base = directory_table_base & 0xffff_ffe0;
        ensure!(
            image.contains_physical(directory_table_base),
            "PAE 页表基址 {directory_table_base:#x} 不在镜像中"
        );
        Ok(Self {
            image,
            directory_table_base,
        })
    }

    pub fn directory_table_base(&self) -> u64 {
        self.directory_table_base
    }

    pub fn translate(&self, virtual_address: u64) -> Result<u64> {
        ensure!(
            virtual_address <= u32::MAX as u64,
            "x86 PAE 虚拟地址 {virtual_address:#x} 超出 32 位范围"
        );
        let pdpt_index = (virtual_address >> 30) & 0x3;
        let pd_index = (virtual_address >> 21) & 0x1ff;
        let pt_index = (virtual_address >> 12) & 0x1ff;

        let pdpte = self.entry(self.directory_table_base, pdpt_index, "PDPTE")?;
        let pde = self.entry(pdpte.physical, pd_index, "PDE")?;
        if !pde.transition && pde.value & (1 << 7) != 0 {
            return Ok((pde.value & ADDRESS_MASK_2M) | (virtual_address & 0x1f_ffff));
        }
        let pte = self.entry(pde.physical, pt_index, "PTE")?;
        Ok(pte.physical | (virtual_address & 0xfff))
    }

    pub fn read_virtual(&self, mut address: u64, mut out: &mut [u8]) -> Result<()> {
        while !out.is_empty() {
            let physical = self.translate(address)?;
            let page_remaining = (PAGE_SIZE - (address & (PAGE_SIZE - 1))) as usize;
            let take = page_remaining.min(out.len());
            self.image
                .read_physical(physical, &mut out[..take])
                .with_context(|| format!("读取 x86 PAE 虚拟地址 {address:#x} 时失败"))?;
            address = address.checked_add(take as u64).context("地址计算溢出")?;
            out = &mut out[take..];
        }
        Ok(())
    }

    pub fn read_u32(&self, address: u64) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.read_virtual(address, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_u64(&self, address: u64) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.read_virtual(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn enumerate_mappings(
        &self,
        region: VirtualAddressRegion,
        limit: usize,
    ) -> Result<VirtualMappingReport> {
        self.enumerate_mappings_cancellable(region, limit, &CancellationToken::new())
    }

    pub fn enumerate_mappings_cancellable(
        &self,
        region: VirtualAddressRegion,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<VirtualMappingReport> {
        ensure!(limit > 0, "地址映射结果上限必须大于零");
        cancellation.check_cancelled()?;
        let mut pdpt = [0u8; 32];
        self.image
            .read_physical(self.directory_table_base, &mut pdpt)?;
        let indices = match region {
            VirtualAddressRegion::User => 0..2usize,
            VirtualAddressRegion::Kernel => 2..4usize,
            VirtualAddressRegion::All => 0..4usize,
        };
        let budget = AtomicUsize::new(limit.saturating_add(1));
        let mut state = MappingWalkState::default();
        for index in indices {
            cancellation.check_cancelled()?;
            let entry = u64::from_le_bytes(pdpt[index * 8..index * 8 + 8].try_into()?);
            if entry & 1 == 0 {
                continue;
            }
            // PAE PDPTE bits 1/2 are reserved, not inherited access flags.
            walk_mapping_pd(
                self.image,
                (index as u64) << 30,
                entry & ADDRESS_MASK_4K,
                PageFlags::root(),
                &budget,
                cancellation,
                &mut state,
            );
        }
        cancellation.check_cancelled()?;
        state
            .mappings
            .sort_unstable_by_key(|mapping| mapping.virtual_start);
        let mut mappings = merge_mappings(state.mappings);
        let truncated =
            state.truncated || budget.load(Ordering::Relaxed) == 0 || mappings.len() > limit;
        mappings.truncate(limit);
        if truncated {
            push_mapping_warning(
                &mut state.warnings,
                format!("PAE 地址映射结果已按 {limit} 条硬上限截断"),
            );
        }
        Ok(VirtualMappingReport {
            directory_table_base: self.directory_table_base,
            region: match region {
                VirtualAddressRegion::User => "用户空间",
                VirtualAddressRegion::Kernel => "内核空间",
                VirtualAddressRegion::All => "全部地址空间",
            }
            .to_owned(),
            mapped_bytes: mappings.iter().map(|mapping| mapping.length).sum(),
            mapping_count: mappings.len(),
            page_table_pages_read: state.page_table_pages + 1,
            truncated,
            mappings,
            warnings: state.warnings,
        })
    }

    /// PAE entries remain 64-bit even for a 32-bit guest. Walk the upper two
    /// PDPT slots and retain only requested resident frames, with bounded aliases.
    pub fn reverse_translate_kernel_pages(
        &self,
        physical_pages: &HashSet<u64>,
        max_mappings_per_page: usize,
    ) -> Result<HashMap<u64, Vec<u64>>> {
        ensure!(max_mappings_per_page > 0, "物理页反向映射上限必须大于零");
        let mut mappings = HashMap::<u64, Vec<u64>>::new();
        if physical_pages.is_empty() {
            return Ok(mappings);
        }
        for pdpt in 2..4u64 {
            let Ok(directory) = self.entry(self.directory_table_base, pdpt, "PDPTE") else {
                continue;
            };
            for pd in 0..512u64 {
                let Ok(entry) = self.entry(directory.physical, pd, "PDE") else {
                    continue;
                };
                let base_va = (pdpt << 30) | (pd << 21);
                if !entry.transition && entry.value & (1 << 7) != 0 {
                    let base_pa = entry.value & ADDRESS_MASK_2M;
                    for &physical in physical_pages {
                        if physical >= base_pa && physical - base_pa < 0x20_0000 {
                            let aliases = mappings.entry(physical).or_default();
                            if aliases.len() < max_mappings_per_page {
                                aliases.push(base_va + physical - base_pa);
                            }
                        }
                    }
                    continue;
                }
                let mut table = [0u8; 4096];
                if self
                    .image
                    .read_physical(entry.physical, &mut table)
                    .is_err()
                {
                    continue;
                }
                for (pt, bytes) in table.chunks_exact(8).enumerate() {
                    let raw = u64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]);
                    let Some(entry) = resident_page_table_entry(raw) else {
                        continue;
                    };
                    if physical_pages.contains(&entry.physical) {
                        let aliases = mappings.entry(entry.physical).or_default();
                        if aliases.len() < max_mappings_per_page {
                            aliases.push(base_va | ((pt as u64) << 12));
                        }
                    }
                }
            }
        }
        Ok(mappings)
    }

    fn entry(&self, table: u64, index: u64, level: &str) -> Result<ResidentPageTableEntry> {
        let value = self
            .image
            .read_u64_physical(table + index * 8)
            .with_context(|| format!("无法读取 PAE {level}"))?;
        resident_page_table_entry(value)
            .with_context(|| format!("PAE {level} 不存在或不是驻留/转换页：{value:#x}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResidentPageTableEntry {
    value: u64,
    physical: u64,
    transition: bool,
}

impl<'a> X64AddressSpace<'a> {
    pub fn new(image: &'a MemoryImage, directory_table_base: u64) -> Result<Self> {
        ensure!(directory_table_base != 0, "页表基址为零");
        Ok(Self {
            image,
            directory_table_base: directory_table_base & ADDRESS_MASK_4K,
        })
    }

    pub fn directory_table_base(&self) -> u64 {
        self.directory_table_base
    }

    /// Inspect the terminal 4 KiB PTE without interpreting a software PTE as
    /// a physical address. Upper levels must still be resident. Compressed
    /// pages need a separate, Windows-specific reconstruction path.
    pub(crate) fn leaf_pte(&self, virtual_address: u64) -> Result<(u64, u64)> {
        ensure!(
            is_canonical(virtual_address),
            "non-canonical virtual address"
        );
        let mut table = self.directory_table_base;
        for (shift, level) in [(39, "PML4E"), (30, "PDPTE"), (21, "PDE")] {
            let entry = self.entry(table, (virtual_address >> shift) & 0x1ff, level)?;
            ensure!(
                shift == 39 || entry.transition || entry.value & 0x80 == 0,
                "large page does not have a terminal 4 KiB PTE"
            );
            table = entry.physical;
        }
        let physical = table + ((virtual_address >> 12) & 0x1ff) * 8;
        Ok((physical, self.image.read_u64_physical(physical)?))
    }

    pub fn translate(&self, virtual_address: u64) -> Result<u64> {
        ensure!(
            is_canonical(virtual_address),
            "x64 虚拟地址 {virtual_address:#x} 不是规范地址"
        );

        let pml4_index = (virtual_address >> 39) & 0x1ff;
        let pdpt_index = (virtual_address >> 30) & 0x1ff;
        let pd_index = (virtual_address >> 21) & 0x1ff;
        let pt_index = (virtual_address >> 12) & 0x1ff;

        let pml4e = self.entry(self.directory_table_base, pml4_index, "PML4E")?;
        let pdpte = self.entry(pml4e.physical, pdpt_index, "PDPTE")?;
        if !pdpte.transition && pdpte.value & (1 << 7) != 0 {
            return Ok((pdpte.value & ADDRESS_MASK_1G) | (virtual_address & 0x3fff_ffff));
        }

        let pde = self.entry(pdpte.physical, pd_index, "PDE")?;
        if !pde.transition && pde.value & (1 << 7) != 0 {
            return Ok((pde.value & ADDRESS_MASK_2M) | (virtual_address & 0x1f_ffff));
        }

        let pte = self.entry(pde.physical, pt_index, "PTE")?;
        Ok(pte.physical | (virtual_address & 0xfff))
    }

    pub fn read_virtual(&self, mut address: u64, mut out: &mut [u8]) -> Result<()> {
        while !out.is_empty() {
            let physical = self.translate(address)?;
            let page_remaining = (PAGE_SIZE - (address & (PAGE_SIZE - 1))) as usize;
            let take = page_remaining.min(out.len());
            self.image
                .read_physical(physical, &mut out[..take])
                .with_context(|| format!("读取虚拟地址 {address:#x} 时失败"))?;
            address = address.checked_add(take as u64).context("地址计算溢出")?;
            out = &mut out[take..];
        }
        Ok(())
    }

    pub fn read_u64(&self, address: u64) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.read_virtual(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Enumerates present x64 mappings in one page-table traversal and merges
    /// adjacent leaves that have identical permissions and physical layout.
    /// This shared primitive powers virtmap, process memmap and memory
    /// statistics without translating every virtual page independently.
    pub fn enumerate_mappings(
        &self,
        region: VirtualAddressRegion,
        limit: usize,
    ) -> Result<VirtualMappingReport> {
        self.enumerate_mappings_cancellable(region, limit, &CancellationToken::new())
    }

    pub fn enumerate_mappings_cancellable(
        &self,
        region: VirtualAddressRegion,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<VirtualMappingReport> {
        ensure!(limit > 0, "地址映射结果上限必须大于零");
        cancellation.check_cancelled()?;
        let pml4 = read_page_table(self.image, self.directory_table_base)?;
        let indices = match region {
            VirtualAddressRegion::User => 0usize..256,
            VirtualAddressRegion::Kernel => 256usize..512,
            VirtualAddressRegion::All => 0usize..512,
        };
        // The output limit must also bound the walk itself. Applying it only after
        // collecting every leaf lets corrupted/self-referential page tables grow a
        // VirtualMapping Vec into multiple GiB before truncate() can run.
        let mapping_budget = AtomicUsize::new(limit.saturating_add(1));
        let partial = indices
            .into_par_iter()
            .filter_map(|index| {
                if cancellation.is_cancelled() || mapping_budget.load(Ordering::Relaxed) == 0 {
                    return None;
                }
                let entry = pml4[index];
                if entry & 1 == 0 {
                    return None;
                }
                let table = entry & ADDRESS_MASK_4K;
                if table == self.directory_table_base {
                    return None;
                }
                let mut state = MappingWalkState::default();
                let flags = PageFlags::root().combine(entry);
                let prefix = canonicalize_48((index as u64) << 39);
                walk_mapping_pdpt(
                    self.image,
                    prefix,
                    table,
                    flags,
                    &mapping_budget,
                    cancellation,
                    &mut state,
                );
                Some(state)
            })
            .collect::<Vec<_>>();
        cancellation.check_cancelled()?;
        let mut mappings = Vec::new();
        let mut warnings = Vec::new();
        let mut page_table_pages_read = 1u64;
        let mut walk_truncated = false;
        for state in partial {
            page_table_pages_read = page_table_pages_read.saturating_add(state.page_table_pages);
            walk_truncated |= state.truncated;
            mappings.extend(state.mappings);
            for warning in state.warnings {
                push_mapping_warning(&mut warnings, warning);
            }
        }
        mappings.sort_unstable_by_key(|mapping| mapping.virtual_start);
        let mappings = merge_mappings(mappings);
        let truncated =
            walk_truncated || mapping_budget.load(Ordering::Relaxed) == 0 || mappings.len() > limit;
        let mut mappings = mappings;
        mappings.truncate(limit);
        if truncated {
            push_mapping_warning(
                &mut warnings,
                format!("地址映射结果已按 {limit} 条硬上限截断"),
            );
        }
        let mapped_bytes = mappings
            .iter()
            .fold(0u64, |total, mapping| total.saturating_add(mapping.length));
        Ok(VirtualMappingReport {
            directory_table_base: self.directory_table_base,
            region: match region {
                VirtualAddressRegion::User => "用户空间",
                VirtualAddressRegion::Kernel => "内核空间",
                VirtualAddressRegion::All => "全部地址空间",
            }
            .to_owned(),
            mapped_bytes,
            mapping_count: mappings.len(),
            page_table_pages_read,
            truncated,
            mappings,
            warnings,
        })
    }

    /// Finds canonical kernel virtual pages that map any of the requested
    /// physical pages. The page tables are traversed once for the whole target
    /// set, which is substantially cheaper than reversing each object
    /// independently.
    pub fn reverse_translate_kernel_pages(
        &self,
        physical_pages: &HashSet<u64>,
        max_mappings_per_page: usize,
    ) -> Result<HashMap<u64, Vec<u64>>> {
        Ok(self
            .reverse_translate_pages_detailed_internal(
                physical_pages,
                VirtualAddressRegion::Kernel,
                max_mappings_per_page,
                usize::MAX,
                None,
                None,
            )?
            .mappings)
    }

    /// Detailed counterpart to [`Self::reverse_translate_kernel_pages`].
    pub fn reverse_translate_kernel_pages_detailed(
        &self,
        physical_pages: &HashSet<u64>,
        max_mappings_per_page: usize,
    ) -> Result<ReverseTranslationReport> {
        self.reverse_translate_pages_detailed(
            physical_pages,
            VirtualAddressRegion::Kernel,
            max_mappings_per_page,
        )
    }

    /// Finds virtual pages in the selected half of an address space that map
    /// any requested physical page. All targets share one page-table walk.
    pub fn reverse_translate_pages(
        &self,
        physical_pages: &HashSet<u64>,
        region: VirtualAddressRegion,
        max_mappings_per_page: usize,
    ) -> Result<HashMap<u64, Vec<u64>>> {
        Ok(self
            .reverse_translate_pages_detailed_internal(
                physical_pages,
                region,
                max_mappings_per_page,
                usize::MAX,
                None,
                None,
            )?
            .mappings)
    }

    /// Detailed reverse translation that preserves partial positive mappings
    /// while reporting every unreadable page-table subtree and whether the
    /// per-physical-page alias limit was actually exceeded.
    pub fn reverse_translate_pages_detailed(
        &self,
        physical_pages: &HashSet<u64>,
        region: VirtualAddressRegion,
        max_mappings_per_page: usize,
    ) -> Result<ReverseTranslationReport> {
        self.reverse_translate_pages_detailed_with_budget(
            physical_pages,
            region,
            max_mappings_per_page,
            DEFAULT_REVERSE_TRANSLATION_ENTRY_LIMIT,
        )
    }

    /// Reverse translation with an explicit hard budget for page-table entries
    /// inspected across the complete parallel walk.
    pub fn reverse_translate_pages_detailed_with_budget(
        &self,
        physical_pages: &HashSet<u64>,
        region: VirtualAddressRegion,
        max_mappings_per_page: usize,
        page_table_entry_limit: usize,
    ) -> Result<ReverseTranslationReport> {
        self.reverse_translate_pages_detailed_internal(
            physical_pages,
            region,
            max_mappings_per_page,
            page_table_entry_limit,
            None,
            None,
        )
    }

    /// Reverse translation with hard bounds for both page-table work and the
    /// total number of alias entries retained across all target pages.
    ///
    /// Callers that require bounded memory should use this API and treat
    /// `alias_storage_limit_exceeded` as an incomplete search universe. The
    /// older map-returning wrappers deliberately remain unbounded globally so
    /// this resource policy cannot silently change their results.
    pub fn reverse_translate_pages_detailed_with_limits(
        &self,
        physical_pages: &HashSet<u64>,
        region: VirtualAddressRegion,
        max_mappings_per_page: usize,
        page_table_entry_limit: usize,
        alias_storage_limit: usize,
    ) -> Result<ReverseTranslationReport> {
        ensure!(alias_storage_limit > 0, "反向 alias 存储上限必须大于零");
        self.reverse_translate_pages_detailed_internal(
            physical_pages,
            region,
            max_mappings_per_page,
            page_table_entry_limit,
            Some(alias_storage_limit),
            None,
        )
    }

    /// Bounded reverse mapping that checks cancellation during page-table traversal.
    pub fn reverse_translate_pages_cancellable(
        &self,
        physical_pages: &HashSet<u64>,
        region: VirtualAddressRegion,
        max_mappings_per_page: usize,
        page_table_entry_limit: usize,
        alias_storage_limit: usize,
        cancel: &crate::cancellation::CancellationToken,
    ) -> Result<ReverseTranslationReport> {
        ensure!(alias_storage_limit > 0, "反向 alias 存储上限必须大于零");
        cancel.check_cancelled()?;
        self.reverse_translate_pages_detailed_internal(
            physical_pages,
            region,
            max_mappings_per_page,
            page_table_entry_limit,
            Some(alias_storage_limit),
            Some(cancel),
        )
    }

    fn reverse_translate_pages_detailed_internal(
        &self,
        physical_pages: &HashSet<u64>,
        region: VirtualAddressRegion,
        max_mappings_per_page: usize,
        page_table_entry_limit: usize,
        alias_storage_limit: Option<usize>,
        cancel: Option<&crate::cancellation::CancellationToken>,
    ) -> Result<ReverseTranslationReport> {
        ensure!(max_mappings_per_page > 0, "反向地址映射结果上限必须大于零");
        ensure!(page_table_entry_limit > 0, "反向页表遍历工作上限必须大于零");
        if physical_pages.is_empty() {
            return Ok(ReverseTranslationReport {
                mappings: HashMap::new(),
                target_pages: 0,
                mapped_target_pages: 0,
                page_table_pages_read: 0,
                page_table_read_failures: 0,
                read_failures: Vec::new(),
                read_failure_details_truncated: false,
                page_table_entries_examined: 0,
                page_table_entry_limit,
                traversal_limit_reached: false,
                max_mappings_per_page,
                max_mappings_observed_lower_bound: 0,
                mapping_limit_exceeded: false,
                mapping_limit_exceeded_pages: Vec::new(),
                mapping_limit_exceeded_pages_truncated: false,
                alias_storage_limit,
                alias_storage_entries_retained: 0,
                alias_storage_limit_exceeded: false,
            });
        }
        let target_lookup = PhysicalPageLookup::new(physical_pages);
        let pml4 = read_page_table(self.image, self.directory_table_base)?;
        let mut traversal_budget = ReverseTraversalBudget::new(page_table_entry_limit);
        traversal_budget.cancel = cancel.cloned();
        // Windows can alias an empty PT thousands of times. Only memoize PTs
        // fully checked against this call's target set; a positive or partial
        // table must still be walked under every virtual prefix.
        let empty_target_pts = Mutex::new(HashSet::new());
        let aliases = Mutex::new(ReverseAliasAccumulator::new(
            max_mappings_per_page,
            alias_storage_limit,
        ));
        let (start, end) = match region {
            VirtualAddressRegion::User => (0usize, 256usize),
            VirtualAddressRegion::Kernel => (256usize, 512usize),
            VirtualAddressRegion::All => (0usize, 512usize),
        };
        // Windows normally concentrates most kernel mappings below only one or
        // two PML4 entries. Parallelizing at that level therefore leaves almost
        // every Rayon worker idle. Expand the small PML4/PDPT frontier first,
        // then walk independent PD subtrees in parallel.
        let mut pdpt_frontier = Vec::new();
        let mut state = ReverseWalkState {
            page_table_pages_read: 1,
            ..ReverseWalkState::default()
        };
        for (relative_index, entry) in pml4[start..end].iter().enumerate() {
            if !traversal_budget.consume_entry() {
                break;
            }
            let Some(entry) = resident_page_table_entry(*entry) else {
                continue;
            };
            if entry.physical == self.directory_table_base {
                // Skip Windows' recursive PML4 slot. It maps page-table pages
                // themselves and would recursively revisit the root.
                continue;
            }
            let pml4_index = start as u64 + relative_index as u64;
            let pdpt = match read_page_table(self.image, entry.physical) {
                Ok(table) => table,
                Err(error) => {
                    state.record_read_failure("pdpt", entry.physical, pml4_index << 39, error);
                    continue;
                }
            };
            state.page_table_pages_read = state.page_table_pages_read.saturating_add(1);
            for (pdpt_index, pdpt_entry) in pdpt.into_iter().enumerate() {
                if !traversal_budget.consume_entry() {
                    break;
                }
                let Some(pdpt_entry) = resident_page_table_entry(pdpt_entry) else {
                    continue;
                };
                pdpt_frontier.push((pml4_index, pdpt_index as u64, pdpt_entry));
            }
        }
        let partial = pdpt_frontier
            .par_iter()
            .fold(ReverseWalkState::default, |mut partial, tuple| {
                let (pml4_index, pdpt_index, entry) = tuple;
                let virtual_prefix = (pml4_index << 39) | (pdpt_index << 30);
                if !entry.transition && entry.value & (1 << 7) != 0 {
                    record_large_page_targets(
                        entry.value & ADDRESS_MASK_1G,
                        1 << 30,
                        virtual_prefix,
                        &target_lookup,
                        &aliases,
                    );
                } else {
                    walk_pd_for_targets(
                        self.image,
                        virtual_prefix,
                        entry.physical,
                        &target_lookup,
                        &aliases,
                        &traversal_budget,
                        &empty_target_pts,
                        &mut partial,
                    );
                }
                partial
            })
            .reduce(ReverseWalkState::default, |mut left, right| {
                left.merge(right);
                left
            });
        state.merge(partial);
        if let Some(cancel) = cancel {
            cancel.check_cancelled()?;
        }

        let aliases = aliases
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let ReverseAliasResult {
            mappings,
            max_mappings_observed_lower_bound,
            mapping_limit_exceeded,
            mapping_limit_exceeded_pages,
            mapping_limit_exceeded_pages_truncated,
            alias_storage_entries_retained,
            alias_storage_limit_exceeded,
        } = aliases.finish();

        let mapped_target_pages = mappings.len();
        Ok(ReverseTranslationReport {
            mappings,
            target_pages: physical_pages.len(),
            mapped_target_pages,
            page_table_pages_read: state.page_table_pages_read,
            page_table_read_failures: state.page_table_read_failures,
            read_failures: state.read_failures,
            read_failure_details_truncated: state.read_failure_details_truncated,
            page_table_entries_examined: u64::try_from(traversal_budget.entries_examined())
                .unwrap_or(u64::MAX),
            page_table_entry_limit,
            traversal_limit_reached: traversal_budget.exceeded(),
            max_mappings_per_page,
            max_mappings_observed_lower_bound,
            mapping_limit_exceeded,
            mapping_limit_exceeded_pages,
            mapping_limit_exceeded_pages_truncated,
            alias_storage_limit,
            alias_storage_entries_retained,
            alias_storage_limit_exceeded,
        })
    }

    fn entry(&self, table: u64, index: u64, level: &str) -> Result<ResidentPageTableEntry> {
        let address = table.checked_add(index * 8).context("页表地址计算溢出")?;
        let value = self
            .image
            .read_u64_physical(address)
            .with_context(|| format!("无法在物理地址 {address:#x} 读取 {level}"))?;
        let entry = resident_page_table_entry(value)
            .with_context(|| format!("{level} 页表项无效或不驻留（表项 {value:#x}）"))?;
        ensure!(
            self.image.contains_physical(entry.physical),
            "{level} 驻留页的物理地址 {:#x} 不在镜像中（表项 {value:#x}）",
            entry.physical
        );
        Ok(entry)
    }
}

/// A Windows transition PTE still contains a valid PFN while the page is on a
/// standby or modified list. Prototype PTEs require a different resolution
/// path and must not be treated as resident physical pages.
fn resident_page_table_entry(entry: u64) -> Option<ResidentPageTableEntry> {
    let valid = entry & 1 != 0;
    let prototype = entry & (1 << 10) != 0;
    let transition = entry & (1 << 11) != 0;
    let (physical, transition) = if valid {
        (entry & ADDRESS_MASK_4K, false)
    } else if transition && !prototype {
        (entry & TRANSITION_ADDRESS_MASK_4K, true)
    } else {
        return None;
    };
    (physical != 0).then_some(ResidentPageTableEntry {
        value: entry,
        physical,
        transition,
    })
}

struct PhysicalPageLookup {
    bitmap: Option<Vec<u64>>,
    sorted_pages: Vec<u64>,
}

impl PhysicalPageLookup {
    fn new(pages: &HashSet<u64>) -> Self {
        let mut sorted_pages = pages.iter().copied().collect::<Vec<_>>();
        sorted_pages.sort_unstable();
        let Some(max_page) = pages.iter().map(|physical| physical >> 12).max() else {
            return Self {
                bitmap: None,
                sorted_pages,
            };
        };
        let Some(word_count) = max_page
            .checked_div(64)
            .and_then(|word| word.checked_add(1))
            .and_then(|words| usize::try_from(words).ok())
        else {
            return Self {
                bitmap: None,
                sorted_pages,
            };
        };
        let Some(bytes) = word_count.checked_mul(std::mem::size_of::<u64>()) else {
            return Self {
                bitmap: None,
                sorted_pages,
            };
        };
        if bytes > MAX_DENSE_TARGET_BITMAP_BYTES {
            return Self {
                bitmap: None,
                sorted_pages,
            };
        }
        let mut bitmap = vec![0u64; word_count];
        for physical in pages {
            let page = physical >> 12;
            bitmap[(page / 64) as usize] |= 1u64 << (page % 64);
        }
        Self {
            bitmap: Some(bitmap),
            sorted_pages,
        }
    }

    #[inline]
    fn contains(&self, physical: u64) -> bool {
        if let Some(bitmap) = &self.bitmap {
            let page = physical >> 12;
            return bitmap
                .get((page / 64) as usize)
                .is_some_and(|word| word & (1u64 << (page % 64)) != 0);
        }
        self.sorted_pages.binary_search(&physical).is_ok()
    }

    /// Returns only targets inside `[physical_start, physical_end)`. Both
    /// bounds are found by binary search, so a 1 GiB/2 MiB leaf does not scan
    /// the complete target universe.
    fn pages_in_range(&self, physical_start: u64, physical_end: u64) -> &[u64] {
        let start = self
            .sorted_pages
            .partition_point(|physical| *physical < physical_start);
        let end = self
            .sorted_pages
            .partition_point(|physical| *physical < physical_end);
        &self.sorted_pages[start..end]
    }
}

struct ReverseTraversalBudget {
    configured: usize,
    remaining: AtomicUsize,
    exceeded: AtomicBool,
    cancel: Option<crate::cancellation::CancellationToken>,
}

impl ReverseTraversalBudget {
    fn new(configured: usize) -> Self {
        Self {
            configured,
            remaining: AtomicUsize::new(configured),
            exceeded: AtomicBool::new(false),
            cancel: None,
        }
    }

    fn consume_entry(&self) -> bool {
        if self.cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
            return false;
        }
        if self
            .remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            true
        } else {
            self.exceeded.store(true, Ordering::Relaxed);
            false
        }
    }

    fn has_capacity(&self) -> bool {
        if self.cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
            return false;
        }
        if self.remaining.load(Ordering::Relaxed) > 0 {
            true
        } else {
            self.exceeded.store(true, Ordering::Relaxed);
            false
        }
    }

    fn entries_examined(&self) -> usize {
        self.configured
            .saturating_sub(self.remaining.load(Ordering::Relaxed))
    }

    fn exceeded(&self) -> bool {
        self.exceeded.load(Ordering::Relaxed)
    }
}

struct ReverseAliasAccumulator {
    retained: HashMap<u64, Vec<u64>>,
    /// Present only for globally bounded walks. Besides exact duplicate
    /// detection, this keeps the retained set deterministic under Rayon: when
    /// full, the lexicographically largest `(physical, virtual)` alias is
    /// replaced by a smaller candidate regardless of worker lock order.
    retained_alias_order: Option<BTreeSet<(u64, u64)>>,
    exceeded_pages: HashSet<u64>,
    mapping_limit_exceeded: bool,
    exceeded_page_details_truncated: bool,
    max_mappings_per_page: usize,
    alias_storage_limit: Option<usize>,
    alias_storage_entries_retained: usize,
    alias_storage_limit_exceeded: bool,
}

struct ReverseAliasResult {
    mappings: HashMap<u64, Vec<u64>>,
    max_mappings_observed_lower_bound: usize,
    mapping_limit_exceeded: bool,
    mapping_limit_exceeded_pages: Vec<u64>,
    mapping_limit_exceeded_pages_truncated: bool,
    alias_storage_entries_retained: usize,
    alias_storage_limit_exceeded: bool,
}

impl ReverseAliasAccumulator {
    fn new(max_mappings_per_page: usize, alias_storage_limit: Option<usize>) -> Self {
        Self {
            retained: HashMap::new(),
            retained_alias_order: alias_storage_limit.map(|_| BTreeSet::new()),
            exceeded_pages: HashSet::new(),
            mapping_limit_exceeded: false,
            exceeded_page_details_truncated: false,
            max_mappings_per_page,
            alias_storage_limit,
            alias_storage_entries_retained: 0,
            alias_storage_limit_exceeded: false,
        }
    }

    fn record(&mut self, physical: u64, virtual_address: u64) {
        let retained_limit = self.max_mappings_per_page.saturating_add(1);
        let alias = (physical, virtual_address);
        let duplicate = self.retained_alias_order.as_ref().map_or_else(
            || {
                self.retained
                    .get(&physical)
                    .is_some_and(|values| values.contains(&virtual_address))
            },
            |aliases| aliases.contains(&alias),
        );
        if duplicate {
            return;
        }

        let can_retain_another = self
            .retained
            .get(&physical)
            .is_none_or(|values| values.len() < retained_limit);
        if can_retain_another {
            if let Some(limit) = self.alias_storage_limit
                && self.alias_storage_entries_retained >= limit
            {
                self.alias_storage_limit_exceeded = true;
                let largest = self
                    .retained_alias_order
                    .as_ref()
                    .and_then(BTreeSet::last)
                    .copied()
                    .expect("a positive full alias limit must retain one alias");
                if alias >= largest {
                    return;
                }
                self.remove_retained_alias(largest);
            }
            self.insert_retained_alias(alias);
        } else {
            self.record_mapping_limit_exceeded(physical);
            let values = self
                .retained
                .get_mut(&physical)
                .expect("a full per-page alias list must already exist");
            if let Some((largest_index, largest)) =
                values.iter().enumerate().max_by_key(|(_, value)| **value)
                && virtual_address < *largest
            {
                let replaced = (physical, *largest);
                values[largest_index] = virtual_address;
                if let Some(aliases) = &mut self.retained_alias_order {
                    aliases.remove(&replaced);
                    aliases.insert(alias);
                }
            }
        }
        if self
            .retained
            .get(&physical)
            .is_some_and(|values| values.len() > self.max_mappings_per_page)
        {
            self.record_mapping_limit_exceeded(physical);
        }
    }

    fn record_mapping_limit_exceeded(&mut self, physical: u64) {
        self.mapping_limit_exceeded = true;
        let Some(limit) = self.alias_storage_limit else {
            self.exceeded_pages.insert(physical);
            return;
        };
        if self.exceeded_pages.contains(&physical) {
            return;
        }
        if self.exceeded_pages.len() < limit {
            self.exceeded_pages.insert(physical);
            return;
        }
        self.exceeded_page_details_truncated = true;
        let largest = self
            .exceeded_pages
            .iter()
            .max()
            .copied()
            .expect("a positive full detail limit must retain one page");
        if physical < largest {
            self.exceeded_pages.remove(&largest);
            self.exceeded_pages.insert(physical);
        }
    }

    fn insert_retained_alias(&mut self, (physical, virtual_address): (u64, u64)) {
        self.retained
            .entry(physical)
            .or_default()
            .push(virtual_address);
        if let Some(aliases) = &mut self.retained_alias_order {
            let inserted = aliases.insert((physical, virtual_address));
            debug_assert!(inserted, "duplicate alias passed insertion guard");
        }
        self.alias_storage_entries_retained = self.alias_storage_entries_retained.saturating_add(1);
    }

    fn remove_retained_alias(&mut self, (physical, virtual_address): (u64, u64)) {
        let remove_page = {
            let values = self
                .retained
                .get_mut(&physical)
                .expect("ordered alias index must reference retained page");
            let index = values
                .iter()
                .position(|value| *value == virtual_address)
                .expect("ordered alias index must reference retained address");
            values.swap_remove(index);
            values.is_empty()
        };
        if remove_page {
            self.retained.remove(&physical);
        }
        if let Some(aliases) = &mut self.retained_alias_order {
            let removed = aliases.remove(&(physical, virtual_address));
            debug_assert!(removed, "retained alias missing from ordered index");
        }
        self.alias_storage_entries_retained = self.alias_storage_entries_retained.saturating_sub(1);
    }

    fn finish(mut self) -> ReverseAliasResult {
        debug_assert_eq!(
            self.alias_storage_entries_retained,
            self.retained.values().map(Vec::len).sum::<usize>()
        );
        let mut max_mappings_observed_lower_bound =
            self.retained.values().map(Vec::len).max().unwrap_or(0);
        if self.mapping_limit_exceeded {
            max_mappings_observed_lower_bound =
                max_mappings_observed_lower_bound.max(self.max_mappings_per_page.saturating_add(1));
        }
        for values in self.retained.values_mut() {
            values.sort_unstable();
            values.truncate(self.max_mappings_per_page);
        }
        let mut mapping_limit_exceeded_pages = self.exceeded_pages.into_iter().collect::<Vec<_>>();
        mapping_limit_exceeded_pages.sort_unstable();
        ReverseAliasResult {
            mappings: self.retained,
            max_mappings_observed_lower_bound,
            mapping_limit_exceeded: self.mapping_limit_exceeded,
            mapping_limit_exceeded_pages,
            mapping_limit_exceeded_pages_truncated: self.exceeded_page_details_truncated,
            alias_storage_entries_retained: self.alias_storage_entries_retained,
            alias_storage_limit_exceeded: self.alias_storage_limit_exceeded,
        }
    }
}

#[derive(Clone, Copy)]
struct PageFlags {
    writable: bool,
    user_accessible: bool,
    executable: bool,
    global: bool,
}

impl PageFlags {
    fn root() -> Self {
        Self {
            writable: true,
            user_accessible: true,
            executable: true,
            global: false,
        }
    }

    fn combine(self, entry: u64) -> Self {
        Self {
            writable: self.writable && entry & (1 << 1) != 0,
            user_accessible: self.user_accessible && entry & (1 << 2) != 0,
            executable: self.executable && entry & (1u64 << 63) == 0,
            global: self.global || entry & (1 << 8) != 0,
        }
    }
}

#[derive(Default)]
struct MappingWalkState {
    mappings: Vec<VirtualMapping>,
    page_table_pages: u64,
    warnings: Vec<String>,
    truncated: bool,
}

#[derive(Default)]
struct ReverseWalkState {
    page_table_pages_read: u64,
    page_table_read_failures: u64,
    read_failures: Vec<ReverseTranslationReadFailure>,
    read_failure_details_truncated: bool,
}

impl ReverseWalkState {
    fn record_read_failure(
        &mut self,
        level: &str,
        table_physical_address: u64,
        virtual_prefix: u64,
        error: anyhow::Error,
    ) {
        self.page_table_read_failures = self.page_table_read_failures.saturating_add(1);
        if self.read_failures.len() < MAX_REVERSE_READ_FAILURE_DETAILS {
            self.read_failures.push(ReverseTranslationReadFailure {
                level: level.to_owned(),
                table_physical_address,
                virtual_prefix: canonicalize_48(virtual_prefix),
                message: format!("{error:#}"),
            });
        } else {
            self.read_failure_details_truncated = true;
        }
    }

    fn merge(&mut self, other: Self) {
        self.page_table_pages_read = self
            .page_table_pages_read
            .saturating_add(other.page_table_pages_read);
        self.page_table_read_failures = self
            .page_table_read_failures
            .saturating_add(other.page_table_read_failures);
        self.read_failure_details_truncated |= other.read_failure_details_truncated;
        let remaining = MAX_REVERSE_READ_FAILURE_DETAILS.saturating_sub(self.read_failures.len());
        if other.read_failures.len() > remaining {
            self.read_failure_details_truncated = true;
        }
        self.read_failures
            .extend(other.read_failures.into_iter().take(remaining));
    }
}

fn walk_mapping_pdpt(
    image: &MemoryImage,
    virtual_prefix: u64,
    table: u64,
    parent_flags: PageFlags,
    mapping_budget: &AtomicUsize,
    cancellation: &CancellationToken,
    state: &mut MappingWalkState,
) {
    if cancellation.is_cancelled() {
        return;
    }
    if mapping_budget.load(Ordering::Relaxed) == 0 {
        state.truncated = true;
        return;
    }
    let pdpt = match read_page_table(image, table) {
        Ok(table) => table,
        Err(error) => {
            push_mapping_warning(
                &mut state.warnings,
                format!("无法读取 PDPT {table:#x}：{error:#}"),
            );
            return;
        }
    };
    state.page_table_pages += 1;
    for (index, entry) in pdpt.into_iter().enumerate() {
        if cancellation.is_cancelled() {
            return;
        }
        if mapping_budget.load(Ordering::Relaxed) == 0 {
            state.truncated = true;
            break;
        }
        if entry & 1 == 0 {
            continue;
        }
        let start = canonicalize_48(virtual_prefix | (index as u64) << 30);
        let flags = parent_flags.combine(entry);
        if entry & (1 << 7) != 0 {
            push_mapping_bounded(
                state,
                mapping_from_leaf(start, entry & ADDRESS_MASK_1G, 1 << 30, flags),
                mapping_budget,
            );
        } else {
            walk_mapping_pd(
                image,
                start,
                entry & ADDRESS_MASK_4K,
                flags,
                mapping_budget,
                cancellation,
                state,
            );
        }
    }
}

fn walk_mapping_pd(
    image: &MemoryImage,
    virtual_prefix: u64,
    table: u64,
    parent_flags: PageFlags,
    mapping_budget: &AtomicUsize,
    cancellation: &CancellationToken,
    state: &mut MappingWalkState,
) {
    if cancellation.is_cancelled() {
        return;
    }
    if mapping_budget.load(Ordering::Relaxed) == 0 {
        state.truncated = true;
        return;
    }
    let pd = match read_page_table(image, table) {
        Ok(table) => table,
        Err(error) => {
            push_mapping_warning(
                &mut state.warnings,
                format!("无法读取 PD {table:#x}：{error:#}"),
            );
            return;
        }
    };
    state.page_table_pages += 1;
    for (index, entry) in pd.into_iter().enumerate() {
        if cancellation.is_cancelled() {
            return;
        }
        if mapping_budget.load(Ordering::Relaxed) == 0 {
            state.truncated = true;
            break;
        }
        if entry & 1 == 0 {
            continue;
        }
        let start = canonicalize_48(virtual_prefix | (index as u64) << 21);
        let flags = parent_flags.combine(entry);
        if entry & (1 << 7) != 0 {
            push_mapping_bounded(
                state,
                mapping_from_leaf(start, entry & ADDRESS_MASK_2M, 1 << 21, flags),
                mapping_budget,
            );
        } else {
            walk_mapping_pt(
                image,
                start,
                entry & ADDRESS_MASK_4K,
                flags,
                mapping_budget,
                cancellation,
                state,
            );
        }
    }
}

fn walk_mapping_pt(
    image: &MemoryImage,
    virtual_prefix: u64,
    table: u64,
    parent_flags: PageFlags,
    mapping_budget: &AtomicUsize,
    cancellation: &CancellationToken,
    state: &mut MappingWalkState,
) {
    if cancellation.is_cancelled() {
        return;
    }
    if mapping_budget.load(Ordering::Relaxed) == 0 {
        state.truncated = true;
        return;
    }
    let pt = match read_page_table(image, table) {
        Ok(table) => table,
        Err(error) => {
            push_mapping_warning(
                &mut state.warnings,
                format!("无法读取 PT {table:#x}：{error:#}"),
            );
            return;
        }
    };
    state.page_table_pages += 1;
    for (index, entry) in pt.into_iter().enumerate() {
        if cancellation.is_cancelled() {
            return;
        }
        if mapping_budget.load(Ordering::Relaxed) == 0 {
            state.truncated = true;
            break;
        }
        if entry & 1 == 0 {
            continue;
        }
        let start = canonicalize_48(virtual_prefix | (index as u64) << 12);
        push_mapping_bounded(
            state,
            mapping_from_leaf(
                start,
                entry & ADDRESS_MASK_4K,
                PAGE_SIZE,
                parent_flags.combine(entry),
            ),
            mapping_budget,
        );
    }
}

fn push_mapping_bounded(
    state: &mut MappingWalkState,
    mapping: VirtualMapping,
    mapping_budget: &AtomicUsize,
) -> bool {
    if mapping_budget
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
            remaining.checked_sub(1)
        })
        .is_err()
    {
        state.truncated = true;
        return false;
    }
    state.mappings.push(mapping);
    true
}

fn mapping_from_leaf(
    virtual_start: u64,
    physical_start: u64,
    page_size: u64,
    flags: PageFlags,
) -> VirtualMapping {
    VirtualMapping {
        virtual_start,
        virtual_end: virtual_start.saturating_add(page_size),
        physical_start,
        length: page_size,
        source_page_size: page_size,
        writable: flags.writable,
        user_accessible: flags.user_accessible,
        executable: flags.executable,
        global: flags.global,
    }
}

fn merge_mappings(mappings: Vec<VirtualMapping>) -> Vec<VirtualMapping> {
    let mut merged: Vec<VirtualMapping> = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        if let Some(previous) = merged.last_mut()
            && previous.virtual_end == mapping.virtual_start
            && previous.physical_start.saturating_add(previous.length) == mapping.physical_start
            && previous.source_page_size == mapping.source_page_size
            && previous.writable == mapping.writable
            && previous.user_accessible == mapping.user_accessible
            && previous.executable == mapping.executable
            && previous.global == mapping.global
        {
            previous.virtual_end = mapping.virtual_end;
            previous.length = previous.length.saturating_add(mapping.length);
            continue;
        }
        merged.push(mapping);
    }
    merged
}

fn push_mapping_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 128 {
        warnings.push(warning);
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_pd_for_targets(
    image: &MemoryImage,
    virtual_prefix: u64,
    table: u64,
    targets: &PhysicalPageLookup,
    aliases: &Mutex<ReverseAliasAccumulator>,
    traversal_budget: &ReverseTraversalBudget,
    empty_target_pts: &Mutex<HashSet<u64>>,
    state: &mut ReverseWalkState,
) {
    if !traversal_budget.has_capacity() {
        return;
    }
    let pd = match read_page_table(image, table) {
        Ok(table) => table,
        Err(error) => {
            state.record_read_failure("pd", table, virtual_prefix, error);
            return;
        }
    };
    state.page_table_pages_read = state.page_table_pages_read.saturating_add(1);
    for (pd_index, entry) in pd.into_iter().enumerate() {
        if !traversal_budget.consume_entry() {
            break;
        }
        let Some(entry) = resident_page_table_entry(entry) else {
            continue;
        };
        let virtual_prefix = virtual_prefix | (pd_index as u64) << 21;
        if !entry.transition && entry.value & (1 << 7) != 0 {
            record_large_page_targets(
                entry.value & ADDRESS_MASK_2M,
                1 << 21,
                virtual_prefix,
                targets,
                aliases,
            );
            continue;
        }
        walk_pt_for_targets(
            image,
            virtual_prefix,
            entry.physical,
            targets,
            aliases,
            traversal_budget,
            empty_target_pts,
            state,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_pt_for_targets(
    image: &MemoryImage,
    virtual_prefix: u64,
    table: u64,
    targets: &PhysicalPageLookup,
    aliases: &Mutex<ReverseAliasAccumulator>,
    traversal_budget: &ReverseTraversalBudget,
    empty_target_pts: &Mutex<HashSet<u64>>,
    state: &mut ReverseWalkState,
) {
    if empty_target_pts
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains(&table)
    {
        return;
    }
    if !traversal_budget.has_capacity() {
        return;
    }
    let pt = match read_page_table(image, table) {
        Ok(table) => table,
        Err(error) => {
            state.record_read_failure("pt", table, virtual_prefix, error);
            return;
        }
    };
    state.page_table_pages_read = state.page_table_pages_read.saturating_add(1);
    let mut matches = Vec::new();
    let mut complete = true;
    for (pt_index, entry) in pt.into_iter().enumerate() {
        if !traversal_budget.consume_entry() {
            complete = false;
            break;
        }
        let Some(entry) = resident_page_table_entry(entry) else {
            continue;
        };
        let physical = entry.physical;
        if targets.contains(physical) {
            matches.push((
                physical,
                canonicalize_48(virtual_prefix | (pt_index as u64) << 12),
            ));
        }
    }
    if matches.is_empty() && complete {
        let mut empty = empty_target_pts.lock().unwrap_or_else(|p| p.into_inner());
        if empty.len() < 65_536 {
            empty.insert(table);
        }
    } else if !matches.is_empty() {
        let mut aliases = aliases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (physical, virtual_address) in matches {
            aliases.record(physical, virtual_address);
        }
    }
}

fn record_large_page_targets(
    physical_base: u64,
    page_size: u64,
    virtual_base: u64,
    targets: &PhysicalPageLookup,
    aliases: &Mutex<ReverseAliasAccumulator>,
) {
    let physical_end = physical_base.saturating_add(page_size);
    let matches = targets.pages_in_range(physical_base, physical_end);
    if !matches.is_empty() {
        let mut aliases = aliases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for physical in matches {
            aliases.record(
                *physical,
                canonicalize_48(virtual_base + (*physical - physical_base)),
            );
        }
    }
}

fn read_page_table(image: &MemoryImage, physical: u64) -> Result<[u64; 512]> {
    let mut bytes = [0u8; PAGE_SIZE as usize];
    image.read_physical(physical, &mut bytes)?;
    let mut entries = [0u64; 512];
    for (entry, raw) in entries.iter_mut().zip(bytes.chunks_exact(8)) {
        *entry = u64::from_le_bytes(raw.try_into().expect("fixed page-table entry width"));
    }
    Ok(entries)
}

fn canonicalize_48(address: u64) -> u64 {
    if address & (1 << 47) != 0 {
        address | 0xffff_0000_0000_0000
    } else {
        address
    }
}

fn is_canonical(address: u64) -> bool {
    let upper = address >> 48;
    upper == 0 || upper == 0xffff
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn canonical_addresses() {
        assert!(is_canonical(0x0000_7fff_ffff_ffff));
        assert!(is_canonical(0xffff_8000_0000_0000));
        assert!(!is_canonical(0x0001_0000_0000_0000));
    }

    #[test]
    fn transition_pte_uses_windows_pfn_mask() {
        assert_eq!(
            resident_page_table_entry(0x0000_2000_40c1_5880),
            Some(ResidentPageTableEntry {
                value: 0x0000_2000_40c1_5880,
                physical: 0x40c1_5000,
                transition: true,
            })
        );
        assert_eq!(resident_page_table_entry(0x0000_2000_40c1_5c80), None);
        assert_eq!(resident_page_table_entry(0x2084), None);
    }

    #[test]
    fn mapping_walk_budget_bounds_allocated_records() {
        let budget = AtomicUsize::new(2);
        let mut state = MappingWalkState::default();
        for index in 0..3 {
            push_mapping_bounded(
                &mut state,
                mapping_from_leaf(
                    index * PAGE_SIZE,
                    index * PAGE_SIZE,
                    PAGE_SIZE,
                    PageFlags::root(),
                ),
                &budget,
            );
        }
        assert_eq!(state.mappings.len(), 2);
        assert!(state.truncated);
        assert_eq!(budget.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn reverse_empty_aliases_do_not_starve_later_targets_or_leak_across_calls() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-empty-alias-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0; 0x8000];
        put_u64(&mut bytes, 0x1000, 0x2003);
        put_u64(&mut bytes, 0x2000, 0x3003);
        // A heavily shared PT contains only a non-target mapping.
        for i in 0..510 {
            put_u64(&mut bytes, 0x3000 + i * 8, 0x4003);
        }
        put_u64(&mut bytes, 0x4000, 0x7003);
        for i in 510..512 {
            put_u64(&mut bytes, 0x3000 + i * 8, 0x5003);
        }
        put_u64(&mut bytes, 0x5000, 0x6003);
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 0x1000).unwrap();
        let report = space
            .reverse_translate_pages_detailed_with_budget(
                &HashSet::from([0x6000]),
                VirtualAddressRegion::User,
                8,
                4096,
            )
            .unwrap();
        assert!(!report.traversal_limit_reached);
        assert_eq!(report.mappings[&0x6000], vec![510 << 21, 511 << 21]);
        // A new target set must revisit the previously negative PT.
        let other = space
            .reverse_translate_pages_detailed_with_budget(
                &HashSet::from([0x7000]),
                VirtualAddressRegion::User,
                2,
                1_000_000,
            )
            .unwrap();
        assert_eq!(other.mappings[&0x7000], vec![0, 1 << 21]);
        assert!(other.mapping_limit_exceeded);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn reverse_negative_cache_does_not_hide_partial_or_unreadable_tables() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-partial-pt-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0; 0x3000];
        put_u64(&mut bytes, 0x1000 + 511 * 8, 0x2003);
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let targets = PhysicalPageLookup::new(&HashSet::from([0x2000]));
        let aliases = Mutex::new(ReverseAliasAccumulator::new(8, None));
        let empty = Mutex::new(HashSet::new());
        let budget = ReverseTraversalBudget::new(511);
        let mut partial = ReverseWalkState::default();
        walk_pt_for_targets(
            &image,
            0,
            0x1000,
            &targets,
            &aliases,
            &budget,
            &empty,
            &mut partial,
        );
        assert!(budget.exceeded());
        assert!(empty.lock().unwrap().is_empty());
        assert!(aliases.lock().unwrap().retained.is_empty());

        let budget = ReverseTraversalBudget::new(512);
        let mut complete = ReverseWalkState::default();
        walk_pt_for_targets(
            &image,
            0,
            0x1000,
            &targets,
            &aliases,
            &budget,
            &empty,
            &mut complete,
        );
        assert!(!budget.exceeded());
        assert_eq!(aliases.lock().unwrap().retained[&0x2000], vec![511 << 12]);
        assert!(empty.lock().unwrap().is_empty());

        let budget = ReverseTraversalBudget::new(512);
        let mut unreadable = ReverseWalkState::default();
        for _ in 0..2 {
            walk_pt_for_targets(
                &image,
                0,
                0x4000,
                &targets,
                &aliases,
                &budget,
                &empty,
                &mut unreadable,
            );
        }
        assert_eq!(unreadable.page_table_read_failures, 2);
        assert!(empty.lock().unwrap().is_empty());
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn reverses_a_kernel_page_for_a_target_set() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-reverse-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0u8; 0x6000];
        put_u64(&mut bytes, 0x1000 + 256 * 8, 0x2003);
        put_u64(&mut bytes, 0x2000, 0x3003);
        put_u64(&mut bytes, 0x3000, 0x4003);
        put_u64(&mut bytes, 0x4000, 0x5003);
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 0x1000).unwrap();
        let targets = HashSet::from([0x5000]);
        let mappings = space.reverse_translate_kernel_pages(&targets, 8).unwrap();
        assert_eq!(mappings[&0x5000], vec![0xffff_8000_0000_0000]);
        let report = space
            .enumerate_mappings(VirtualAddressRegion::Kernel, 16)
            .unwrap();
        assert_eq!(report.mapping_count, 1);
        assert_eq!(report.mappings[0].virtual_start, 0xffff_8000_0000_0000);
        assert_eq!(report.mappings[0].physical_start, 0x5000);
        assert_eq!(report.mappings[0].length, 0x1000);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn reverse_report_only_marks_a_limit_after_a_real_overflow() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-reverse-limit-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0u8; 0x7000];
        put_u64(&mut bytes, 0x1000, 0x2003);
        put_u64(&mut bytes, 0x2000, 0x3003);
        put_u64(&mut bytes, 0x3000, 0x4003);
        put_u64(&mut bytes, 0x4000, 0x5003);
        put_u64(&mut bytes, 0x4000 + 8, 0x6003);
        put_u64(&mut bytes, 0x4000 + 16, 0x6003);
        fs::write(&path, bytes).unwrap();

        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 0x1000).unwrap();
        let exactly_at_limit = space
            .reverse_translate_pages_detailed(
                &HashSet::from([0x5000]),
                VirtualAddressRegion::User,
                1,
            )
            .unwrap();
        assert_eq!(exactly_at_limit.max_mappings_observed_lower_bound, 1);
        assert!(!exactly_at_limit.mapping_limit_exceeded);
        assert!(exactly_at_limit.mapping_limit_exceeded_pages.is_empty());

        let overflow = space
            .reverse_translate_pages_detailed(
                &HashSet::from([0x5000, 0x6000]),
                VirtualAddressRegion::User,
                1,
            )
            .unwrap();
        assert_eq!(overflow.max_mappings_observed_lower_bound, 2);
        assert!(overflow.mapping_limit_exceeded);
        assert_eq!(overflow.mapping_limit_exceeded_pages, vec![0x6000]);
        assert_eq!(overflow.mappings[&0x5000], vec![0]);
        assert_eq!(overflow.mappings[&0x6000], vec![0x1000]);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn reverse_alias_storage_is_bounded_to_limit_plus_one() {
        let mut aliases = ReverseAliasAccumulator::new(1, None);
        for virtual_page in (0..10_000u64).rev() {
            aliases.record(0x5000, virtual_page * PAGE_SIZE);
        }
        assert_eq!(aliases.retained[&0x5000].len(), 2);
        let result = aliases.finish();
        assert_eq!(result.max_mappings_observed_lower_bound, 2);
        assert_eq!(result.mapping_limit_exceeded_pages, vec![0x5000]);
        assert_eq!(result.mappings[&0x5000], vec![0]);
    }

    #[test]
    fn physical_page_lookup_uses_sorted_ranges_for_large_pages() {
        let pages = HashSet::from([
            0x1000,
            0x20_0000,
            0x20_1000,
            0x3f_f000,
            0x40_0000,
            0x000f_ffff_ffff_f000,
        ]);
        let lookup = PhysicalPageLookup::new(&pages);
        assert_eq!(
            lookup.pages_in_range(0x20_0000, 0x40_0000),
            &[0x20_0000, 0x20_1000, 0x3f_f000]
        );
        assert!(lookup.contains(0x20_1000));
        assert!(!lookup.contains(0x20_2000));
    }

    #[test]
    fn large_page_reverse_mapping_records_only_binary_searched_range() {
        let pages = HashSet::from([
            0x1f_f000,
            0x20_0000,
            0x20_1000,
            0x3f_f000,
            0x40_0000,
            0x000f_ffff_ffff_f000,
        ]);
        let lookup = PhysicalPageLookup::new(&pages);
        let aliases = Mutex::new(ReverseAliasAccumulator::new(8, Some(8)));
        record_large_page_targets(0x20_0000, 1 << 21, 0x4000_0000, &lookup, &aliases);
        let result = aliases.into_inner().unwrap().finish();
        assert_eq!(result.mappings.len(), 3);
        assert_eq!(result.mappings[&0x20_0000], vec![0x4000_0000]);
        assert_eq!(result.mappings[&0x20_1000], vec![0x4000_1000]);
        assert_eq!(result.mappings[&0x3f_f000], vec![0x401f_f000]);
        assert!(!result.mappings.contains_key(&0x1f_f000));
        assert!(!result.mappings.contains_key(&0x40_0000));
        assert_eq!(result.alias_storage_entries_retained, 3);
        assert!(!result.alias_storage_limit_exceeded);
    }

    #[test]
    fn reverse_alias_global_storage_limit_requires_real_overflow() {
        let mut aliases = ReverseAliasAccumulator::new(8, Some(2));
        aliases.record(0x5000, 0);
        aliases.record(0x6000, PAGE_SIZE);
        assert_eq!(aliases.alias_storage_entries_retained, 2);
        assert!(!aliases.alias_storage_limit_exceeded);

        aliases.record(0x7000, PAGE_SIZE * 2);
        assert_eq!(aliases.alias_storage_entries_retained, 2);
        assert!(aliases.alias_storage_limit_exceeded);
        assert_eq!(aliases.retained.len(), 2);

        let result = aliases.finish();
        assert_eq!(result.alias_storage_entries_retained, 2);
        assert!(result.alias_storage_limit_exceeded);
        assert_eq!(result.mappings.len(), 2);

        let mut reverse_order = ReverseAliasAccumulator::new(8, Some(2));
        reverse_order.record(0x7000, PAGE_SIZE * 2);
        reverse_order.record(0x6000, PAGE_SIZE);
        reverse_order.record(0x5000, 0);
        let reverse_order = reverse_order.finish();
        assert!(reverse_order.alias_storage_limit_exceeded);
        assert_eq!(
            reverse_order
                .mappings
                .keys()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0x5000, 0x6000])
        );
    }

    #[test]
    fn reverse_alias_global_limit_also_bounds_overflow_page_details() {
        let mut aliases = ReverseAliasAccumulator::new(1, Some(2));
        for physical in [0x7000, 0x6000, 0x5000] {
            aliases.record(physical, 0);
            aliases.record(physical, PAGE_SIZE);
        }
        let result = aliases.finish();
        assert!(result.mapping_limit_exceeded);
        assert!(result.mapping_limit_exceeded_pages_truncated);
        assert_eq!(result.mapping_limit_exceeded_pages, vec![0x5000, 0x6000]);
        assert_eq!(result.max_mappings_observed_lower_bound, 2);
        assert_eq!(result.alias_storage_entries_retained, 2);
    }

    #[test]
    fn reverse_report_hard_bounds_total_alias_storage() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-reverse-alias-budget-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0u8; 0x8000];
        put_u64(&mut bytes, 0x1000, 0x2003);
        put_u64(&mut bytes, 0x2000, 0x3003);
        put_u64(&mut bytes, 0x3000, 0x4003);
        put_u64(&mut bytes, 0x4000, 0x5003);
        put_u64(&mut bytes, 0x4000 + 8, 0x6003);
        put_u64(&mut bytes, 0x4000 + 16, 0x7003);
        fs::write(&path, bytes).unwrap();

        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 0x1000).unwrap();
        let report = space
            .reverse_translate_pages_detailed_with_limits(
                &HashSet::from([0x5000, 0x6000, 0x7000]),
                VirtualAddressRegion::User,
                8,
                DEFAULT_REVERSE_TRANSLATION_ENTRY_LIMIT,
                2,
            )
            .unwrap();
        assert_eq!(report.alias_storage_limit, Some(2));
        assert_eq!(report.alias_storage_entries_retained, 2);
        assert!(report.alias_storage_limit_exceeded);
        assert!(!report.mapping_limit_exceeded_pages_truncated);
        assert_eq!(report.mappings.len(), 2);
        assert_eq!(report.mappings[&0x5000], vec![0]);
        assert_eq!(report.mappings[&0x6000], vec![PAGE_SIZE]);

        // The legacy wrapper remains globally unbounded and therefore returns
        // every target page instead of silently applying the new hard limit.
        let legacy = space
            .reverse_translate_pages(
                &HashSet::from([0x5000, 0x6000, 0x7000]),
                VirtualAddressRegion::User,
                8,
            )
            .unwrap();
        assert_eq!(legacy.len(), 3);

        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn reverse_report_hard_bounds_page_table_entry_work() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-reverse-budget-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0u8; 0x6000];
        put_u64(&mut bytes, 0x1000, 0x2003);
        put_u64(&mut bytes, 0x2000, 0x3003);
        put_u64(&mut bytes, 0x3000, 0x4003);
        put_u64(&mut bytes, 0x4000, 0x5003);
        fs::write(&path, bytes).unwrap();

        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 0x1000).unwrap();
        let report = space
            .reverse_translate_pages_detailed_with_budget(
                &HashSet::from([0x5000]),
                VirtualAddressRegion::User,
                8,
                3,
            )
            .unwrap();
        assert_eq!(report.page_table_entry_limit, 3);
        assert_eq!(report.page_table_entries_examined, 3);
        assert!(report.traversal_limit_reached);
        assert!(report.mappings.is_empty());
        let legacy = space
            .reverse_translate_pages(&HashSet::from([0x5000]), VirtualAddressRegion::User, 8)
            .unwrap();
        assert_eq!(legacy[&0x5000], vec![0]);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn reverse_report_counts_unreadable_page_table_subtrees() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-reverse-missing-table-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0u8; 0x3000];
        put_u64(&mut bytes, 0x1000, 0x5003);
        fs::write(&path, bytes).unwrap();

        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 0x1000).unwrap();
        let report = space
            .reverse_translate_pages_detailed(
                &HashSet::from([0x2000]),
                VirtualAddressRegion::User,
                8,
            )
            .unwrap();
        assert!(report.mappings.is_empty());
        assert_eq!(report.page_table_pages_read, 1);
        assert_eq!(report.page_table_read_failures, 1);
        assert_eq!(report.read_failures.len(), 1);
        assert_eq!(report.read_failures[0].level, "pdpt");
        assert_eq!(report.read_failures[0].table_physical_address, 0x5000);
        assert!(!report.read_failure_details_truncated);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn reads_through_intermediate_transition_page_tables() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-transition-tables-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0u8; 0x6000];
        put_u64(&mut bytes, 0x1000, 0x2800);
        put_u64(&mut bytes, 0x2000, 0x3800);
        put_u64(&mut bytes, 0x3000, 0x4800);
        put_u64(&mut bytes, 0x4000, 0x5800);
        bytes[0x5000..0x5004].copy_from_slice(b"REGF");
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let space = X64AddressSpace::new(&image, 0x1000).unwrap();
        let mut output = [0u8; 4];
        space.read_virtual(0, &mut output).unwrap();
        assert_eq!(&output, b"REGF");
        let reverse = space
            .reverse_translate_pages_detailed(
                &HashSet::from([0x5000]),
                VirtualAddressRegion::User,
                8,
            )
            .unwrap();
        assert_eq!(reverse.mappings[&0x5000], vec![0]);
        assert_eq!(reverse.page_table_read_failures, 0);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn translates_x86_pae_4k_and_large_pages() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-x86-pae-{}-{nonce}.raw",
            std::process::id()
        ));
        let mut bytes = vec![0u8; 0x80_0000];
        // CR3 -> PDPT[2] -> PD[5] -> PT[3] -> physical 0x5000.
        put_u64(&mut bytes, 0x1000 + 2 * 8, 0x2001);
        put_u64(&mut bytes, 0x2000 + 5 * 8, 0x3001);
        put_u64(&mut bytes, 0x3000 + 3 * 8, 0x5001);
        bytes[0x5abc..0x5ac0].copy_from_slice(b"PAE!");
        // PDPT[3] -> PD[0], whose first PDE maps one 2 MiB large page.
        put_u64(&mut bytes, 0x1000 + 3 * 8, 0x4001);
        put_u64(&mut bytes, 0x4000, 0x60_0081);
        bytes[0x60_1234..0x60_1238].copy_from_slice(b"2MiB");
        fs::write(&path, bytes).unwrap();

        let image = MemoryImage::open(&path).unwrap();
        let space = X86PaeAddressSpace::new(&image, 0x1000).unwrap();
        let mut output = [0u8; 4];
        space.read_virtual(0x80a0_3abc, &mut output).unwrap();
        assert_eq!(&output, b"PAE!");
        space.read_virtual(0xc000_1234, &mut output).unwrap();
        assert_eq!(&output, b"2MiB");
        assert!(space.translate(0x1_0000_0000).is_err());
        drop(image);
        fs::remove_file(path).unwrap();
    }

    fn put_u64(output: &mut [u8], offset: usize, value: u64) {
        output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
