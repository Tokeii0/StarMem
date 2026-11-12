use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use rayon::prelude::*;
use serde::Serialize;

use crate::address::{WindowsAddressSpace, X64AddressSpace, X86PaeAddressSpace};
use crate::image::MemoryImage;
use crate::profile::{KernelProfile, is_x86_pae_legacy_profile};
use crate::scan::scan_exact;
use crate::symbols::{
    codeview_from_address_space, codeview_from_virtual_pe, export_rva_from_virtual_pe,
};

pub mod autorun_plugins;
pub mod check_pslist;
pub mod console_plugins;
pub mod desktop_reconstruct;
pub mod disk_plugins;
pub mod dwm_surfaces;
pub mod files;
pub mod gdi_bitmap;
pub mod gui_plugins;
pub mod injected_regions;
pub mod kernel_plugins;
pub mod logon_plugins;
pub mod malware_plugins;
pub mod netstat_plugins;
pub mod object_plugins;
pub mod open_files;
pub mod pe_plugins;
pub mod pipe_plugins;
pub mod plugins;
pub mod prefetch_plugins;
pub mod process_plugins;
pub mod process_string;
pub mod registry;
pub mod service_plugins;
pub mod shimcache_plugins;
pub mod syscall_plugins;
pub mod system_plugins;
pub mod token_plugins;
pub mod usb_history;
pub mod vad_dump;
pub mod vad_scan;

#[derive(Debug, Clone, Serialize)]
pub struct WindowsKernelContext {
    pub architecture: WindowsArchitecture,
    pub directory_table_base: u64,
    pub kernel_base: u64,
    pub ps_active_process_head: u64,
    pub ps_loaded_module_list: u64,
    pub discovery_method: KernelDiscoveryMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsArchitecture {
    X86_64,
    X86Pae,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelDiscoveryMethod {
    CrashDumpHeader,
    LowStub,
    PhysicalSystemProcess,
    DecodedKdbg,
    DecodedKdbgX86Pae,
}

impl WindowsKernelContext {
    pub fn address_space_for_dtb<'a>(
        &self,
        image: &'a MemoryImage,
        directory_table_base: u64,
    ) -> Result<WindowsAddressSpace<'a>> {
        match self.architecture {
            WindowsArchitecture::X86_64 => {
                X64AddressSpace::new(image, directory_table_base).map(WindowsAddressSpace::X64)
            }
            WindowsArchitecture::X86Pae => X86PaeAddressSpace::new(image, directory_table_base)
                .map(WindowsAddressSpace::X86Pae),
        }
    }

    pub fn address_space<'a>(&self, image: &'a MemoryImage) -> Result<WindowsAddressSpace<'a>> {
        self.address_space_for_dtb(image, self.directory_table_base)
    }

    pub fn is_x86_pae(&self) -> bool {
        self.architecture == WindowsArchitecture::X86Pae
    }

    pub(crate) fn x64_address_space<'a>(
        &self,
        image: &'a MemoryImage,
    ) -> Result<X64AddressSpace<'a>> {
        ensure!(
            !self.is_x86_pae(),
            "该插件尚未支持 Windows x86 PAE 的对象布局；请使用支持 x86 的分析引擎补充，不能将此限制解释为零条证据"
        );
        X64AddressSpace::new(image, self.directory_table_base)
    }

    pub fn discover(image: &MemoryImage, profile: &KernelProfile) -> Result<Self> {
        if image.dump64().is_some() {
            Self::from_dump(image, profile)
        } else {
            Self::from_raw(image, profile)
        }
    }

    pub fn from_dump(image: &MemoryImage, profile: &KernelProfile) -> Result<Self> {
        let dump = image
            .dump64()
            .context("this plugin currently requires a 64-bit Windows crash dump")?;
        let address_space = X64AddressSpace::new(image, dump.directory_table_base)?;
        let kernel_base = profile
            .symbols
            .get("PsActiveProcessHead")
            .and_then(|rva| dump.ps_active_process_head.checked_sub(u64::from(*rva)))
            .or_else(|| {
                address_space
                    .read_u64(dump.kd_debugger_data_block + 0x18)
                    .ok()
            })
            .context("cannot determine Windows kernel base")?;
        ensure!(
            kernel_base >> 48 == 0xffff && kernel_base & 0xfff == 0,
            "invalid Windows kernel base {kernel_base:#x}"
        );
        Ok(Self {
            architecture: WindowsArchitecture::X86_64,
            directory_table_base: dump.directory_table_base,
            kernel_base,
            ps_active_process_head: dump.ps_active_process_head,
            ps_loaded_module_list: dump.ps_loaded_module_list,
            discovery_method: KernelDiscoveryMethod::CrashDumpHeader,
        })
    }

    fn from_raw(image: &MemoryImage, profile: &KernelProfile) -> Result<Self> {
        if profile.is_x86() {
            return discover_x86_pae_raw_context(image, profile);
        }
        let ps_active_rva = u64::from(profile.symbol_rva("PsActiveProcessHead")?);
        let ps_loaded_rva = u64::from(profile.symbol_rva("PsLoadedModuleList")?);

        let low_stubs = low_stub_candidates(image);
        for (directory_table_base, kernel_hint) in low_stubs.iter().copied() {
            if let Some(kernel_base) = locate_kernel_from_hint(
                image,
                directory_table_base,
                kernel_hint,
                &profile.pdb_guid,
                ps_active_rva,
                ps_loaded_rva,
            ) {
                let actual_ps_active =
                    discover_active_process_head(image, profile, directory_table_base, kernel_base)
                        .unwrap_or(kernel_base + ps_active_rva);
                let actual_ps_loaded_rva = export_rva_from_virtual_pe(
                    image,
                    directory_table_base,
                    kernel_base,
                    "PsLoadedModuleList",
                )
                .ok()
                .flatten()
                .map(u64::from)
                .unwrap_or(ps_loaded_rva);
                let context = Self {
                    architecture: WindowsArchitecture::X86_64,
                    directory_table_base,
                    kernel_base,
                    ps_active_process_head: actual_ps_active,
                    ps_loaded_module_list: kernel_base + actual_ps_loaded_rva,
                    discovery_method: KernelDiscoveryMethod::LowStub,
                };
                if validate_readable_kernel_context(image, &context) {
                    return Ok(context);
                }
            }
        }

        let (system_context, physical_system_candidates) =
            discover_from_physical_system_process(image, profile, ps_active_rva, ps_loaded_rva)?;
        if let Some(context) = system_context {
            return Ok(context);
        }

        let kernel_bases = decoded_kdbg_kernel_bases(image)?;
        if kernel_bases.is_empty() {
            let vmware_hint = if image
                .path()
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("vmem"))
            {
                "; VMware .vmem analysis may require its matching .vmss/.vmsn physical-map metadata"
            } else {
                ""
            };
            anyhow::bail!(
                "Windows bootstrap failed: {} Low Stub candidate(s) were stale or invalid, {} physical System EPROCESS candidate(s) did not yield a complete kernel address space, and no decoded physical KDBG was found{vmware_hint}",
                low_stubs.len(),
                physical_system_candidates,
            );
        }

        let kdbg_candidate_count = kernel_bases.len();
        for kernel_base in kernel_bases {
            let ps_active_process_head = kernel_base + ps_active_rva;
            let ps_loaded_module_list = kernel_base + ps_loaded_rva;
            if let Some(directory_table_base) = discover_directory_table_base(
                image,
                kernel_base,
                ps_active_process_head,
                ps_loaded_module_list,
            )? {
                let context = Self {
                    architecture: WindowsArchitecture::X86_64,
                    directory_table_base,
                    kernel_base,
                    ps_active_process_head,
                    ps_loaded_module_list,
                    discovery_method: KernelDiscoveryMethod::DecodedKdbg,
                };
                if validate_readable_kernel_context(image, &context) {
                    return Ok(context);
                }
            }
        }
        anyhow::bail!(
            "Windows bootstrap failed: {} Low Stub candidate(s), {} physical System EPROCESS candidate(s), and {} decoded KDBG kernel-base candidate(s) were found, but none mapped a complete and internally consistent kernel",
            low_stubs.len(),
            physical_system_candidates,
            kdbg_candidate_count,
        )
    }
}

fn discover_x86_pae_raw_context(
    image: &MemoryImage,
    profile: &KernelProfile,
) -> Result<WindowsKernelContext> {
    let name_offset = profile.field("ImageFileName")?.offset;
    let pid_offset = profile.field("UniqueProcessId")?.offset;
    let links_offset = profile.field("ActiveProcessLinks")?.offset;
    let pcb_offset = profile.field("Pcb")?.offset;
    let dtb_offset = profile
        .type_field("_KPROCESS", "DirectoryTableBase")?
        .offset;
    let kdbg_report = scan_exact(image, b"KDBG", 4096, 64 * 1024 * 1024)?;
    let system_report = scan_exact(image, b"System\0", 16_384, 64 * 1024 * 1024)?;
    let mut kdbg_candidates = 0usize;
    let mut system_candidates = 0usize;

    for kdbg_hit in kdbg_report.hits {
        let Some(kdbg) = kdbg_hit.physical_address.checked_sub(0x10) else {
            continue;
        };
        if image.read_u32_physical(kdbg + 0x10).ok() != Some(u32::from_le_bytes(*b"KDBG")) {
            continue;
        }
        let size = match image.read_u32_physical(kdbg + 0x14) {
            Ok(size) if (0x100..=0x2000).contains(&size) => size,
            _ => continue,
        };
        let _ = size;
        let kernel_base = u64::from(image.read_u32_physical(kdbg + 0x18)?);
        let ps_loaded_module_list = u64::from(image.read_u32_physical(kdbg + 0x48)?);
        let ps_active_process_head = u64::from(image.read_u32_physical(kdbg + 0x50)?);
        if kernel_base & 0xfff != 0
            || !is_x86_kernel_pointer(kernel_base)
            || !is_x86_kernel_pointer(ps_loaded_module_list)
            || !is_x86_kernel_pointer(ps_active_process_head)
        {
            continue;
        }
        kdbg_candidates += 1;

        for hit in &system_report.hits {
            let Some(eprocess_physical) = hit.physical_address.checked_sub(name_offset) else {
                continue;
            };
            if image.read_u32_physical(eprocess_physical + pid_offset).ok() != Some(4) {
                continue;
            }
            let directory_table_base =
                match image.read_u32_physical(eprocess_physical + pcb_offset + dtb_offset) {
                    Ok(value) => u64::from(value) & 0xffff_ffe0,
                    Err(_) => continue,
                };
            if directory_table_base == 0 || !image.contains_physical(directory_table_base) {
                continue;
            }
            system_candidates += 1;
            let Ok(space) = X86PaeAddressSpace::new(image, directory_table_base) else {
                continue;
            };
            let space = WindowsAddressSpace::X86Pae(space);
            let mut mz = [0u8; 2];
            if space.read_virtual(kernel_base, &mut mz).is_err() || mz != *b"MZ" {
                continue;
            }
            let Ok(first_link) = space.read_u32(ps_active_process_head).map(u64::from) else {
                continue;
            };
            let Ok(last_link) = space.read_u32(ps_active_process_head + 4).map(u64::from) else {
                continue;
            };
            let Ok(first_module) = space.read_u32(ps_loaded_module_list).map(u64::from) else {
                continue;
            };
            if !is_x86_kernel_pointer(first_link)
                || !is_x86_kernel_pointer(last_link)
                || !is_x86_kernel_pointer(first_module)
                || first_link < links_offset
            {
                continue;
            }
            let first_eprocess = first_link - links_offset;
            if space.read_u32(first_eprocess + pid_offset).ok() != Some(4) {
                continue;
            }
            let mut name = vec![0u8; 16];
            if space
                .read_virtual(first_eprocess + name_offset, &mut name)
                .is_err()
                || !name.starts_with(b"System\0")
                || space.read_u32(first_link + 4).ok().map(u64::from)
                    != Some(ps_active_process_head)
            {
                continue;
            }
            // Validate the mapped kernel, rather than an unrelated physical RSDS hit.
            let Ok(codeview) = codeview_from_address_space(&space, kernel_base) else {
                continue;
            };
            if !codeview
                .guid
                .replace('-', "")
                .eq_ignore_ascii_case(&profile.pdb_guid.replace('-', ""))
                || codeview.age != profile.pdb_age
            {
                continue;
            }
            return Ok(WindowsKernelContext {
                architecture: WindowsArchitecture::X86Pae,
                directory_table_base,
                kernel_base,
                ps_active_process_head,
                ps_loaded_module_list,
                discovery_method: KernelDiscoveryMethod::DecodedKdbgX86Pae,
            });
        }
    }
    anyhow::bail!(
        "Windows x86 PAE bootstrap failed: found {kdbg_candidates} decoded KDBG candidate(s) and {system_candidates} physical System EPROCESS candidate(s), but none formed a consistent PAE address space with the exact kernel CodeView identity"
    )
}

fn is_x86_kernel_pointer(address: u64) -> bool {
    (0x8000_0000..=u32::MAX as u64).contains(&address) && address & 3 == 0
}

fn low_stub_candidates(image: &MemoryImage) -> Vec<(u64, u64)> {
    const SIGNATURE: u64 = 0x0000_0001_0006_00e9;
    const SIGNATURE_MASK: u64 = 0xffff_ffff_ffff_00ff;
    let mut candidates = Vec::new();
    for offset in (0x1000..0x10_0000).step_by(0x1000) {
        let Ok(value) = image.read_u64_physical(offset) else {
            continue;
        };
        if value & SIGNATURE_MASK != SIGNATURE {
            continue;
        }
        let Ok(directory_table_base) = image.read_u64_physical(offset + 0xa0) else {
            continue;
        };
        let Ok(kernel_hint) = image.read_u64_physical(offset + 0x70) else {
            continue;
        };
        let directory_table_base = directory_table_base & 0x000f_ffff_ffff_f000;
        if directory_table_base != 0
            && image.contains_physical(directory_table_base)
            && kernel_hint >> 48 == 0xffff
            && kernel_hint & 3 == 0
        {
            candidates.push((directory_table_base, kernel_hint));
        }
    }
    candidates
}

fn locate_kernel_from_hint(
    image: &MemoryImage,
    directory_table_base: u64,
    kernel_hint: u64,
    expected_guid: &str,
    ps_active_rva: u64,
    ps_loaded_rva: u64,
) -> Option<u64> {
    let space = X64AddressSpace::new(image, directory_table_base).ok()?;
    let hint_page = kernel_hint & !0xfff;
    for distance in (0..=32 * 1024 * 1024u64).step_by(0x1000) {
        let Some(candidate) = hint_page.checked_sub(distance) else {
            break;
        };
        let mut magic = [0u8; 2];
        if space.read_virtual(candidate, &mut magic).is_err() || magic != *b"MZ" {
            continue;
        }
        let codeview_matches = codeview_from_virtual_pe(image, directory_table_base, candidate)
            .is_ok_and(|codeview| codeview.guid == expected_guid);
        let codeview_is_kernel = codeview_from_virtual_pe(image, directory_table_base, candidate)
            .is_ok_and(|codeview| codeview.pdb_name.eq_ignore_ascii_case("ntkrnlmp.pdb"));
        let globals_validate = || {
            let active = candidate.checked_add(ps_active_rva)?;
            let modules = candidate.checked_add(ps_loaded_rva)?;
            let active_flink = space.read_u64(active).ok()?;
            let module_flink = space.read_u64(modules).ok()?;
            if !is_kernel_pointer(active_flink) || !is_kernel_pointer(module_flink) {
                return None;
            }
            space.translate(active_flink).ok()?;
            Some(())
        };
        if codeview_matches || codeview_is_kernel || globals_validate().is_some() {
            return Some(candidate);
        }
    }
    None
}

fn discover_active_process_head(
    image: &MemoryImage,
    profile: &KernelProfile,
    directory_table_base: u64,
    kernel_base: u64,
) -> Option<u64> {
    let name_offset = profile.field("ImageFileName").ok()?.offset;
    let pid_offset = profile.field("UniqueProcessId").ok()?.offset;
    let links_offset = profile.field("ActiveProcessLinks").ok()?.offset;
    let space = X64AddressSpace::new(image, directory_table_base).ok()?;
    let report = scan_exact(image, b"System\0", 16_384, 64 * 1024 * 1024).ok()?;
    for hit in report.hits {
        let Some(eprocess_physical) = hit.physical_address.checked_sub(name_offset) else {
            continue;
        };
        if image.read_u64_physical(eprocess_physical + pid_offset).ok() != Some(4) {
            continue;
        }
        let flink = image
            .read_u64_physical(eprocess_physical + links_offset)
            .ok()?;
        let blink = image
            .read_u64_physical(eprocess_physical + links_offset + 8)
            .ok()?;
        if !is_kernel_pointer(flink) || !is_kernel_pointer(blink) {
            continue;
        }
        // The first process entry points back to the list head through Blink.
        // Recover the System entry VA from the following entry's Blink and
        // validate both sides of the links before accepting the head.
        let system_link = space.read_u64(flink + 8).ok()?;
        if !is_kernel_pointer(system_link)
            || space.read_u64(system_link).ok() != Some(flink)
            || space.read_u64(system_link + 8).ok() != Some(blink)
            || space.read_u64(blink).ok() != Some(system_link)
            || blink < kernel_base
            || blink - kernel_base > 0x1000_0000
        {
            continue;
        }
        return Some(blink);
    }
    None
}

fn validate_kernel_context(
    image: &MemoryImage,
    context: &WindowsKernelContext,
    profile: &KernelProfile,
) -> bool {
    let Ok(space) = X64AddressSpace::new(image, context.directory_table_base) else {
        return false;
    };
    let Some(active_flink) = space.read_u64(context.ps_active_process_head).ok() else {
        return false;
    };
    let Some(active_blink) = space.read_u64(context.ps_active_process_head + 8).ok() else {
        return false;
    };
    if !is_kernel_pointer(active_flink) || !is_kernel_pointer(active_blink) {
        return false;
    }
    let Ok(links_offset) = profile
        .field("ActiveProcessLinks")
        .map(|field| field.offset)
    else {
        return false;
    };
    let Some(first_eprocess) = active_flink.checked_sub(links_offset) else {
        return false;
    };
    let Ok(pid_offset) = profile.field("UniqueProcessId").map(|field| field.offset) else {
        return false;
    };
    let Some(pid) = space.read_u64(first_eprocess + pid_offset).ok() else {
        return false;
    };
    if pid > u32::MAX as u64
        || space.read_u64(active_flink + 8).ok() != Some(context.ps_active_process_head)
    {
        return false;
    }
    let Ok(name_field) = profile.field("ImageFileName") else {
        return false;
    };
    let mut name = [0u8; 15];
    if space
        .read_virtual(first_eprocess + name_field.offset, &mut name)
        .is_err()
        || name[0] == 0
        || name
            .iter()
            .take_while(|byte| **byte != 0)
            .any(|byte| !byte.is_ascii_graphic() && *byte != b' ')
    {
        return false;
    }

    let Some(module_flink) = space.read_u64(context.ps_loaded_module_list).ok() else {
        return false;
    };
    let Some(module_blink) = space.read_u64(context.ps_loaded_module_list + 8).ok() else {
        return false;
    };
    if !is_kernel_pointer(module_flink) || !is_kernel_pointer(module_blink) {
        return false;
    }
    if space.read_u64(module_flink + 8).ok() != Some(context.ps_loaded_module_list) {
        return false;
    }
    let Ok(module_links) = profile
        .type_field("_KLDR_DATA_TABLE_ENTRY", "InLoadOrderLinks")
        .map(|field| field.offset)
    else {
        return false;
    };
    let Ok(dll_base) = profile
        .type_field("_KLDR_DATA_TABLE_ENTRY", "DllBase")
        .map(|field| field.offset)
    else {
        return false;
    };
    let Some(first_module) = module_flink.checked_sub(module_links) else {
        return false;
    };
    space.read_u64(first_module + dll_base).ok() == Some(context.kernel_base)
}

fn validate_readable_kernel_context(image: &MemoryImage, context: &WindowsKernelContext) -> bool {
    let Ok(space) = X64AddressSpace::new(image, context.directory_table_base) else {
        return false;
    };
    let Some(active_flink) = space.read_u64(context.ps_active_process_head).ok() else {
        return false;
    };
    let Some(module_flink) = space.read_u64(context.ps_loaded_module_list).ok() else {
        return false;
    };
    is_kernel_pointer(active_flink)
        && is_kernel_pointer(module_flink)
        && space.read_u64(active_flink).is_ok()
        && space.read_u64(module_flink).is_ok()
}

fn discover_from_physical_system_process(
    image: &MemoryImage,
    profile: &KernelProfile,
    ps_active_rva: u64,
    ps_loaded_rva: u64,
) -> Result<(Option<WindowsKernelContext>, usize)> {
    let name_offset = profile.field("ImageFileName")?.offset;
    let pid_offset = profile.field("UniqueProcessId")?.offset;
    let links_offset = profile.field("ActiveProcessLinks")?.offset;
    let pcb_offset = profile.field("Pcb")?.offset;
    let dtb_offset = profile
        .type_field("_KPROCESS", "DirectoryTableBase")?
        .offset;
    let report = scan_exact(image, b"System\0", 16_384, 64 * 1024 * 1024)?;
    let mut candidates = 0usize;
    for hit in report.hits {
        let Some(eprocess_physical) = hit.physical_address.checked_sub(name_offset) else {
            continue;
        };
        if image.read_u64_physical(eprocess_physical + pid_offset).ok() != Some(4) {
            continue;
        }
        let directory_table_base =
            match image.read_u64_physical(eprocess_physical + pcb_offset + dtb_offset) {
                Ok(value) => value & 0x000f_ffff_ffff_f000,
                Err(_) => continue,
            };
        if directory_table_base == 0 || !image.contains_physical(directory_table_base) {
            continue;
        }
        let flink = match image.read_u64_physical(eprocess_physical + links_offset) {
            Ok(value) if is_kernel_pointer(value) => value,
            _ => continue,
        };
        let blink = match image.read_u64_physical(eprocess_physical + links_offset + 8) {
            Ok(value) if is_kernel_pointer(value) => value,
            _ => continue,
        };
        candidates += 1;
        let space = X64AddressSpace::new(image, directory_table_base)?;
        for head in list_head_candidates(&space, [flink, blink], ps_active_rva) {
            let Some(kernel_base) = head.checked_sub(ps_active_rva) else {
                continue;
            };
            if kernel_base >> 48 != 0xffff || kernel_base & 0xfff != 0 {
                continue;
            }
            let Some(ps_loaded_module_list) = kernel_base.checked_add(ps_loaded_rva) else {
                continue;
            };
            let context = WindowsKernelContext {
                architecture: WindowsArchitecture::X86_64,
                directory_table_base,
                kernel_base,
                ps_active_process_head: head,
                ps_loaded_module_list,
                discovery_method: KernelDiscoveryMethod::PhysicalSystemProcess,
            };
            if validate_kernel_context(image, &context, profile) {
                return Ok((Some(context), candidates));
            }
        }
    }
    Ok((None, candidates))
}

fn list_head_candidates(
    space: &X64AddressSpace<'_>,
    starts: [u64; 2],
    ps_active_rva: u64,
) -> Vec<u64> {
    const MAX_LINKS: usize = 4096;
    let expected_page_offset = ps_active_rva & 0xfff;
    let mut heads = Vec::new();
    for (start, next_offset) in [(starts[0], 0u64), (starts[1], 8u64)] {
        let mut current = start;
        let mut visited = HashSet::new();
        for _ in 0..MAX_LINKS {
            if !visited.insert(current) || !is_kernel_pointer(current) {
                break;
            }
            if current & 0xfff == expected_page_offset {
                heads.push(current);
            }
            current = match space.read_u64(current + next_offset) {
                Ok(next) => next,
                Err(_) => break,
            };
        }
    }
    heads.sort_unstable();
    heads.dedup();
    heads
}

fn decoded_kdbg_kernel_bases(image: &MemoryImage) -> Result<Vec<u64>> {
    let report = scan_exact(image, b"KDBG", 4096, 64 * 1024 * 1024)?;
    let mut bases = Vec::new();
    for hit in report.hits {
        let Some(start) = hit.physical_address.checked_sub(0x10) else {
            continue;
        };
        let mut header = [0u8; 0x20];
        if image.read_physical(start, &mut header).is_err() || &header[0x10..0x14] != b"KDBG" {
            continue;
        }
        let size = u32::from_le_bytes(header[0x14..0x18].try_into().unwrap());
        let kernel_base = u64::from_le_bytes(header[0x18..0x20].try_into().unwrap());
        if (0x100..=0x2000).contains(&size)
            && kernel_base >> 48 == 0xffff
            && kernel_base & 0xfff == 0
        {
            bases.push(kernel_base);
        }
    }
    bases.sort_unstable();
    bases.dedup();
    Ok(bases)
}

fn discover_directory_table_base(
    image: &MemoryImage,
    kernel_base: u64,
    ps_active_process_head: u64,
    ps_loaded_module_list: u64,
) -> Result<Option<u64>> {
    let pml4_index = (kernel_base >> 39) & 0x1ff;
    let mut pages = Vec::new();
    for span in image.spans() {
        let mut page = (span.start + 0xfff) & !0xfff;
        while page.saturating_add(0x1000) <= span.end() {
            pages.push(page);
            page += 0x1000;
        }
    }
    let mut candidates: Vec<u64> = pages
        .par_iter()
        .filter_map(|page| {
            let pml4e = image.read_u64_physical(*page + pml4_index * 8).ok()?;
            if pml4e & 1 == 0 || !image.contains_physical(pml4e & 0x000f_ffff_ffff_f000) {
                return None;
            }
            let space = X64AddressSpace::new(image, *page).ok()?;
            let mut magic = [0u8; 2];
            space.read_virtual(kernel_base, &mut magic).ok()?;
            if magic != *b"MZ" {
                return None;
            }
            let active_flink = space.read_u64(ps_active_process_head).ok()?;
            let module_flink = space.read_u64(ps_loaded_module_list).ok()?;
            (is_kernel_pointer(active_flink) && is_kernel_pointer(module_flink)).then_some(*page)
        })
        .collect();
    candidates.sort_unstable();
    Ok(candidates.into_iter().next())
}

fn is_kernel_pointer(address: u64) -> bool {
    address >> 48 == 0xffff && address & 7 == 0
}

fn is_kernel_address(address: u64) -> bool {
    address >= 0xffff_8000_0000_0000
}

#[derive(Debug, Serialize)]
pub struct ProcessRecord {
    pub eprocess: u64,
    pub pid: u64,
    pub ppid: Option<u64>,
    pub name: String,
    #[serde(flatten)]
    pub details: ProcessDetails,
}

#[derive(Debug, Default, Serialize)]
pub struct ProcessDetails {
    pub state: String,
    pub directory_table_base: Option<u64>,
    pub user_directory_table_base: Option<u64>,
    pub peb: Option<u64>,
    pub image_base: Option<u64>,
    pub section_base_address: Option<u64>,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
    pub current_directory: Option<String>,
    pub dll_path: Option<String>,
    pub window_title: Option<String>,
    pub desktop_info: Option<String>,
    pub environment_address: Option<u64>,
    pub environment_size: Option<u64>,
    pub environment_variable_count: Option<usize>,
    pub environment_variables: BTreeMap<String, String>,
    pub environment_computer_name: Option<String>,
    pub environment_user_name: Option<String>,
    pub environment_user_domain: Option<String>,
    pub environment_user_profile: Option<String>,
    pub user_name: Option<String>,
    pub user_domain: Option<String>,
    pub user_name_source: Option<String>,
    pub environment_system_root: Option<String>,
    pub environment_temp: Option<String>,
    pub being_debugged: Option<bool>,
    pub nt_global_flag: Option<u32>,
    pub session_id: Option<u32>,
    pub create_time_raw: Option<u64>,
    pub create_time: Option<String>,
    pub exit_time_raw: Option<u64>,
    pub exit_time: Option<String>,
    pub exit_status: Option<i32>,
    pub active_threads: Option<u32>,
    pub handle_count: Option<u32>,
    pub peak_virtual_size: Option<u64>,
    pub virtual_size: Option<u64>,
    pub peak_working_set_size: Option<u64>,
    pub working_set_private_size: Option<u64>,
    pub minimum_working_set_size: Option<u64>,
    pub maximum_working_set_size: Option<u64>,
    pub commit_charge: Option<u64>,
    pub commit_charge_peak: Option<u64>,
    pub private_page_count: Option<u64>,
    pub hard_fault_count: Option<u32>,
    pub vad_count: Option<u32>,
    pub token: Option<u64>,
    pub token_id: Option<u64>,
    pub token_authentication_id: Option<u64>,
    pub token_parent_id: Option<u64>,
    pub token_modified_id: Option<u64>,
    pub token_originating_logon_session: Option<u64>,
    pub token_logon_session: Option<u64>,
    pub token_source: Option<String>,
    pub user_sid: Option<String>,
    pub token_user_group_count: Option<u32>,
    pub token_groups_recovered: Option<usize>,
    pub token_groups_truncated: Option<bool>,
    pub token_groups: Vec<ProcessTokenGroup>,
    pub logon_sid: Option<String>,
    pub integrity_level_index: Option<u32>,
    pub integrity_sid: Option<String>,
    pub integrity_level: Option<String>,
    pub token_session_id: Option<u32>,
    pub token_type: Option<String>,
    pub token_impersonation_level: Option<String>,
    pub token_in_use: Option<bool>,
    pub token_flags: Option<u32>,
    pub privileges_present: Option<u64>,
    pub privileges_enabled: Option<u64>,
    pub privileges_enabled_by_default: Option<u64>,
    pub object_table: Option<u64>,
    pub debug_port: Option<u64>,
    pub exception_port: Option<u64>,
    pub wow64: Option<bool>,
    pub process_architecture: Option<String>,
    pub protection_level: Option<u8>,
    pub protection_type: Option<String>,
    pub protection_signer: Option<String>,
    pub protection_audit: Option<bool>,
    pub signature_level: Option<u8>,
    pub section_signature_level: Option<u8>,
    pub peb_os_major_version: Option<u32>,
    pub peb_os_minor_version: Option<u32>,
    pub peb_os_build_number: Option<u16>,
    pub peb_number_of_processors: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ProcessTokenGroup {
    pub sid: String,
    pub attributes: u32,
    pub attribute_names: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProcessListReport {
    pub processes: Vec<ProcessRecord>,
    pub complete: bool,
    pub stop_reason: ProcessListStopReason,
    pub warnings: Vec<ProcessListWarning>,
}

pub fn write_process_csv<W: Write>(report: &ProcessListReport, mut output: W) -> Result<()> {
    output.write_all(b"\xef\xbb\xbf")?;
    let mut writer = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_writer(output);
    let Some(first) = report.processes.first() else {
        writer.write_record(["EPROCESS", "PID", "PPID", "Name"])?;
        writer.flush()?;
        return Ok(());
    };
    let first = serde_json::to_value(first)?;
    let object = first
        .as_object()
        .context("process record did not serialize as an object")?;
    let mut keys = ["eprocess", "pid", "ppid", "name"]
        .into_iter()
        .filter(|key| object.contains_key(*key))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let remaining = object
        .keys()
        .filter(|key| !keys.contains(key))
        .cloned()
        .collect::<Vec<_>>();
    keys.extend(remaining);
    writer.write_record(keys.iter().map(|key| process_csv_header(key)))?;
    for process in &report.processes {
        let value = serde_json::to_value(process)?;
        let object = value
            .as_object()
            .context("process record did not serialize as an object")?;
        writer.write_record(
            keys.iter()
                .map(|key| json_cell(key, object.get(key).unwrap_or(&serde_json::Value::Null))),
        )?;
    }
    writer.flush()?;
    Ok(())
}

fn process_csv_header(key: &str) -> &str {
    match key {
        "eprocess" => "EPROCESS",
        "pid" => "PID",
        "ppid" => "PPID",
        "name" => "Name",
        "user_name" => "UserName",
        "user_domain" => "UserDomain",
        "user_sid" => "UserSID",
        _ => key,
    }
}

fn json_cell(key: &str, value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) if process_address_field(key) => value
            .as_u64()
            .map(|value| format!("{value:#018x}"))
            .unwrap_or_else(|| value.to_string()),
        serde_json::Value::Number(value) => value.to_string(),
        value => value.to_string(),
    }
}

fn process_address_field(key: &str) -> bool {
    matches!(
        key,
        "eprocess"
            | "directory_table_base"
            | "user_directory_table_base"
            | "peb"
            | "image_base"
            | "section_base_address"
            | "environment_address"
            | "token"
            | "object_table"
            | "debug_port"
            | "exception_port"
    )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessListStopReason {
    ListHead,
    Limit,
    Cycle,
    InvalidPointer,
    UnreadableEntry,
}

#[derive(Debug, Serialize)]
pub struct ProcessListWarning {
    pub kind: String,
    pub message: String,
    pub list_entry: Option<u64>,
}

pub fn list_processes(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<ProcessListReport> {
    ensure!(limit > 0, "process limit must be greater than zero");
    if kernel.is_x86_pae() {
        return list_processes_x86_pae(image, kernel, profile, limit);
    }
    let address_space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let links_offset = profile.field("ActiveProcessLinks")?.offset;
    let pid_offset = profile.field("UniqueProcessId")?.offset;
    let name_field = profile.field("ImageFileName")?;
    let name_length = name_field.size.unwrap_or(15).clamp(1, 64) as usize;
    let ppid_offset = profile
        .fields
        .get("InheritedFromUniqueProcessId")
        .map(|field| field.offset);
    let head = kernel.ps_active_process_head;
    let mut link = address_space
        .read_u64(head)
        .context("cannot read PsActiveProcessHead.Flink")?;
    let mut visited = HashMap::new();
    let mut processes = Vec::new();
    let mut warnings = Vec::new();
    let mut previous_link = head;
    let mut stop_reason = ProcessListStopReason::Limit;

    while link != head && processes.len() < limit {
        if let Some(first_index) = visited.get(&link) {
            push_warning(
                &mut warnings,
                "cycle",
                format!(
                    "active process list returned to entry {link:#x}, first visited at process index {first_index}; preserving {} parsed processes",
                    processes.len()
                ),
                Some(link),
            );
            stop_reason = ProcessListStopReason::Cycle;
            break;
        }
        if !is_canonical(link) || link < links_offset || link & 7 != 0 {
            push_warning(
                &mut warnings,
                "invalid_pointer",
                format!(
                    "invalid ActiveProcessLinks pointer {link:#x}; preserving {} parsed processes",
                    processes.len()
                ),
                Some(link),
            );
            stop_reason = ProcessListStopReason::InvalidPointer;
            break;
        }
        visited.insert(link, processes.len());

        match address_space.read_u64(link + 8) {
            Ok(blink) if !is_kernel_list_pointer(blink) => {
                push_warning(
                    &mut warnings,
                    "invalid_blink",
                    format!(
                        "entry {link:#x} has invalid Blink {blink:#x}; preserving {} parsed processes",
                        processes.len()
                    ),
                    Some(link),
                );
                stop_reason = ProcessListStopReason::InvalidPointer;
                break;
            }
            Ok(blink) if blink != previous_link => push_warning(
                &mut warnings,
                "blink_mismatch",
                format!("entry {link:#x} has Blink {blink:#x}, expected {previous_link:#x}"),
                Some(link),
            ),
            Err(error) => push_warning(
                &mut warnings,
                "unreadable_blink",
                format!("cannot read Blink for entry {link:#x}: {error:#}"),
                Some(link),
            ),
            _ => {}
        }

        let eprocess = link - links_offset;
        let parsed = (|| -> Result<ProcessRecord> {
            let pid = address_space.read_u64(eprocess + pid_offset)?;
            let ppid = ppid_offset
                .map(|offset| address_space.read_u64(eprocess + offset))
                .transpose()?
                .filter(|value| *value != 0);
            let mut name_bytes = vec![0u8; name_length];
            address_space.read_virtual(eprocess + name_field.offset, &mut name_bytes)?;
            let name_end = name_bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name_bytes.len());
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
            let details = read_process_details(image, &address_space, profile, eprocess);
            Ok(ProcessRecord {
                eprocess,
                pid,
                ppid,
                name,
                details,
            })
        })();
        let process = match parsed {
            Ok(process) => process,
            Err(error) => {
                push_warning(
                    &mut warnings,
                    "unreadable_entry",
                    format!(
                        "cannot parse EPROCESS {eprocess:#x}: {error:#}; preserving {} parsed processes",
                        processes.len()
                    ),
                    Some(link),
                );
                stop_reason = ProcessListStopReason::UnreadableEntry;
                break;
            }
        };
        if process.pid > u32::MAX as u64 || process.ppid.is_some_and(|ppid| ppid > u32::MAX as u64)
        {
            push_warning(
                &mut warnings,
                "invalid_process_id",
                format!(
                    "EPROCESS {eprocess:#x} has implausible PID/PPID; preserving {} parsed processes",
                    processes.len()
                ),
                Some(link),
            );
            stop_reason = ProcessListStopReason::InvalidPointer;
            break;
        }
        processes.push(process);
        let next_link = match address_space.read_u64(link) {
            Ok(next_link) => next_link,
            Err(error) => {
                push_warning(
                    &mut warnings,
                    "unreadable_flink",
                    format!(
                        "cannot read Flink for entry {link:#x}: {error:#}; preserving {} parsed processes",
                        processes.len()
                    ),
                    Some(link),
                );
                stop_reason = ProcessListStopReason::UnreadableEntry;
                break;
            }
        };
        previous_link = link;
        link = next_link;
    }

    if link == head {
        stop_reason = ProcessListStopReason::ListHead;
        if let Ok(head_blink) = address_space.read_u64(head + 8)
            && head_blink != previous_link
        {
            push_warning(
                &mut warnings,
                "head_blink_mismatch",
                format!(
                    "list head has Blink {head_blink:#x}, expected final entry {previous_link:#x}"
                ),
                Some(head),
            );
        }
    }
    resolve_process_user_names(&mut processes);
    let complete = process_list_is_complete(&stop_reason, &warnings);
    Ok(ProcessListReport {
        processes,
        complete,
        stop_reason,
        warnings,
    })
}

fn list_processes_x86_pae(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<ProcessListReport> {
    let address_space = X86PaeAddressSpace::new(image, kernel.directory_table_base)?;
    let links_offset = profile.field("ActiveProcessLinks")?.offset;
    let pid_offset = profile.field("UniqueProcessId")?.offset;
    let name_field = profile.field("ImageFileName")?;
    let name_length = name_field.size.unwrap_or(16).clamp(1, 64) as usize;
    let ppid_offset = profile
        .fields
        .get("InheritedFromUniqueProcessId")
        .map(|field| field.offset);
    let head = kernel.ps_active_process_head;
    let mut link = u64::from(
        address_space
            .read_u32(head)
            .context("cannot read x86 PsActiveProcessHead.Flink")?,
    );
    let mut visited = HashMap::new();
    let mut processes = Vec::new();
    let mut warnings = Vec::new();
    if is_x86_pae_legacy_profile(profile) {
        warnings.push(ProcessListWarning {
            kind: "legacy_x86_pae".to_owned(),
            message: "Windows XP SP2 x86 PAE baseline uses an exact CodeView-fingerprinted EPROCESS layout; fields requiring newer x64-only structures are intentionally unavailable"
                .to_owned(),
            list_entry: None,
        });
    }
    let mut previous_link = head;
    let mut stop_reason = ProcessListStopReason::Limit;

    while link != head && processes.len() < limit {
        if let Some(first_index) = visited.get(&link) {
            push_warning(
                &mut warnings,
                "cycle",
                format!(
                    "x86 active process list returned to entry {link:#x}, first visited at process index {first_index}; preserving {} parsed processes",
                    processes.len()
                ),
                Some(link),
            );
            stop_reason = ProcessListStopReason::Cycle;
            break;
        }
        if !is_x86_kernel_pointer(link) || link < links_offset {
            push_warning(
                &mut warnings,
                "invalid_pointer",
                format!(
                    "invalid x86 ActiveProcessLinks pointer {link:#x}; preserving {} parsed processes",
                    processes.len()
                ),
                Some(link),
            );
            stop_reason = ProcessListStopReason::InvalidPointer;
            break;
        }
        visited.insert(link, processes.len());

        match address_space.read_u32(link + 4).map(u64::from) {
            Ok(blink) if !is_x86_kernel_pointer(blink) => {
                push_warning(
                    &mut warnings,
                    "invalid_blink",
                    format!(
                        "x86 entry {link:#x} has invalid Blink {blink:#x}; preserving {} parsed processes",
                        processes.len()
                    ),
                    Some(link),
                );
                stop_reason = ProcessListStopReason::InvalidPointer;
                break;
            }
            Ok(blink) if blink != previous_link => push_warning(
                &mut warnings,
                "blink_mismatch",
                format!("x86 entry {link:#x} has Blink {blink:#x}, expected {previous_link:#x}"),
                Some(link),
            ),
            Err(error) => push_warning(
                &mut warnings,
                "unreadable_blink",
                format!("cannot read x86 Blink for entry {link:#x}: {error:#}"),
                Some(link),
            ),
            _ => {}
        }

        let eprocess = link - links_offset;
        let parsed = (|| -> Result<ProcessRecord> {
            let pid = u64::from(address_space.read_u32(eprocess + pid_offset)?);
            let ppid = ppid_offset
                .map(|offset| address_space.read_u32(eprocess + offset))
                .transpose()?
                .map(u64::from)
                .filter(|value| *value != 0);
            let mut name_bytes = vec![0u8; name_length];
            address_space.read_virtual(eprocess + name_field.offset, &mut name_bytes)?;
            let name_end = name_bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name_bytes.len());
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
            Ok(ProcessRecord {
                eprocess,
                pid,
                ppid,
                name,
                details: read_x86_process_details(image, &address_space, profile, eprocess),
            })
        })();
        let process = match parsed {
            Ok(process) => process,
            Err(error) => {
                push_warning(
                    &mut warnings,
                    "unreadable_entry",
                    format!(
                        "cannot parse x86 EPROCESS {eprocess:#x}: {error:#}; preserving {} parsed processes",
                        processes.len()
                    ),
                    Some(link),
                );
                stop_reason = ProcessListStopReason::UnreadableEntry;
                break;
            }
        };
        processes.push(process);
        let next_link = match address_space.read_u32(link).map(u64::from) {
            Ok(next_link) => next_link,
            Err(error) => {
                push_warning(
                    &mut warnings,
                    "unreadable_flink",
                    format!(
                        "cannot read x86 Flink for entry {link:#x}: {error:#}; preserving {} parsed processes",
                        processes.len()
                    ),
                    Some(link),
                );
                stop_reason = ProcessListStopReason::UnreadableEntry;
                break;
            }
        };
        previous_link = link;
        link = next_link;
    }

    if link == head {
        stop_reason = ProcessListStopReason::ListHead;
        if let Ok(head_blink) = address_space.read_u32(head + 4).map(u64::from)
            && head_blink != previous_link
        {
            push_warning(
                &mut warnings,
                "head_blink_mismatch",
                format!(
                    "x86 list head has Blink {head_blink:#x}, expected final entry {previous_link:#x}"
                ),
                Some(head),
            );
        }
    }
    let complete = process_list_is_complete(&stop_reason, &warnings);
    Ok(ProcessListReport {
        processes,
        complete,
        stop_reason,
        warnings,
    })
}

fn read_x86_process_details(
    image: &MemoryImage,
    space: &X86PaeAddressSpace<'_>,
    profile: &KernelProfile,
    eprocess: u64,
) -> ProcessDetails {
    let mut details = ProcessDetails {
        state: "running".to_owned(),
        process_architecture: Some("x86".to_owned()),
        wow64: Some(false),
        ..ProcessDetails::default()
    };
    let field_u32 = |name: &str| {
        profile
            .fields
            .get(name)
            .and_then(|field| space.read_u32(eprocess + field.offset).ok())
    };
    let field_u64 = |name: &str| {
        profile
            .fields
            .get(name)
            .and_then(|field| space.read_u64(eprocess + field.offset).ok())
    };
    let pcb = profile
        .fields
        .get("Pcb")
        .map(|field| field.offset)
        .unwrap_or(0);
    details.directory_table_base = profile
        .type_field("_KPROCESS", "DirectoryTableBase")
        .ok()
        .and_then(|field| space.read_u32(eprocess + pcb + field.offset).ok())
        .map(u64::from)
        .filter(|value| *value != 0);
    details.section_base_address = field_u32("SectionBaseAddress")
        .map(u64::from)
        .filter(|value| *value != 0);
    details.peb = field_u32("Peb").map(u64::from).filter(|value| *value != 0);
    details.object_table = field_u32("ObjectTable")
        .map(u64::from)
        .filter(|value| *value != 0);
    details.token = field_u32("Token")
        .map(|value| u64::from(value & !0x7))
        .filter(|value| *value != 0);
    details.active_threads = field_u32("ActiveThreads");
    details.create_time_raw = field_u64("CreateTime").filter(|value| *value != 0);
    details.create_time = details.create_time_raw.and_then(filetime_to_rfc3339);
    details.exit_time_raw = field_u64("ExitTime").filter(|value| *value != 0);
    details.exit_time = details.exit_time_raw.and_then(filetime_to_rfc3339);
    if details.exit_time_raw.is_some() {
        details.state = "exited".to_owned();
    }
    if let (Some(dtb), Some(peb)) = (details.directory_table_base, details.peb)
        && peb <= u32::MAX as u64
        && let Ok(process_space) = X86PaeAddressSpace::new(image, dtb)
    {
        details.being_debugged = read_x86_u8(&process_space, peb + 0x02).map(|value| value != 0);
        details.image_base = process_space
            .read_u32(peb + 0x08)
            .ok()
            .map(u64::from)
            .filter(|value| *value != 0);
        details.peb_number_of_processors = process_space.read_u32(peb + 0x64).ok();
        details.nt_global_flag = process_space.read_u32(peb + 0x68).ok();
        details.peb_os_major_version = process_space.read_u32(peb + 0xa4).ok();
        details.peb_os_minor_version = process_space.read_u32(peb + 0xa8).ok();
        details.peb_os_build_number = read_x86_u16(&process_space, peb + 0xac);
        details.session_id = process_space.read_u32(peb + 0x1d4).ok();

        if let Ok(parameters) = process_space.read_u32(peb + 0x10).map(u64::from)
            && parameters != 0
        {
            details.dll_path =
                read_x86_unicode_string(&process_space, parameters + 0x30, 64 * 1024);
            details.image_path =
                read_x86_unicode_string(&process_space, parameters + 0x38, 64 * 1024);
            details.command_line =
                read_x86_unicode_string(&process_space, parameters + 0x40, 64 * 1024);
            details.current_directory =
                read_x86_unicode_string(&process_space, parameters + 0x24, 64 * 1024);
            details.window_title =
                read_x86_unicode_string(&process_space, parameters + 0x70, 64 * 1024);
            details.desktop_info =
                read_x86_unicode_string(&process_space, parameters + 0x78, 64 * 1024);
            // The 32-bit RTL parameters prefix is stable on XP through Win7.
            // XP has no EnvironmentSize; require the double UTF-16 terminator
            // rather than reading an invented size or padding missing pages.
            details.environment_address = process_space
                .read_u32(parameters + 0x48)
                .ok()
                .map(u64::from)
                .filter(|address| *address != 0);
            if let Some(address) = details.environment_address
                && let Some(environment) = read_x86_environment_variables(&process_space, address)
            {
                apply_environment_variables(&mut details, environment);
            }
        }
    }
    details
}

fn read_x86_u8(space: &X86PaeAddressSpace<'_>, address: u64) -> Option<u8> {
    let mut bytes = [0u8; 1];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(bytes[0])
}

fn read_x86_environment_variables(
    space: &X86PaeAddressSpace<'_>,
    address: u64,
) -> Option<BTreeMap<String, String>> {
    const MAX_BYTES: usize = 1024 * 1024;
    if address == 0 || address >= 0x8000_0000 || !address.is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::new();
    let mut previous_zero = false;
    while bytes.len() < MAX_BYTES {
        let cursor = address.checked_add(bytes.len() as u64)?;
        if cursor >= 0x8000_0000 {
            return None;
        }
        let length = (4096 - (cursor & 4095) as usize).min(MAX_BYTES - bytes.len());
        let mut page = vec![0u8; length];
        space.read_virtual(cursor, &mut page).ok()?;
        for word in page.chunks_exact(2) {
            bytes.extend_from_slice(word);
            let zero = word == [0, 0];
            if zero && previous_zero {
                return Some(decode_environment_variables(&bytes));
            }
            previous_zero = zero;
        }
    }
    None
}

fn read_x86_u16(space: &X86PaeAddressSpace<'_>, address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_x86_unicode_string(
    space: &X86PaeAddressSpace<'_>,
    descriptor: u64,
    max_bytes: usize,
) -> Option<String> {
    let length = usize::from(read_x86_u16(space, descriptor)?) & !1;
    if length == 0 || length > max_bytes {
        return None;
    }
    let buffer = u64::from(space.read_u32(descriptor + 4).ok()?);
    if buffer == 0 {
        return None;
    }
    let mut bytes = vec![0u8; length];
    space.read_virtual(buffer, &mut bytes).ok()?;
    let words = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let value = String::from_utf16_lossy(&words)
        .trim_end_matches('\0')
        .to_owned();
    (!value.is_empty()).then_some(value)
}

fn resolve_process_user_names(processes: &mut [ProcessRecord]) {
    let mut sid_accounts = HashMap::<String, (String, Option<String>)>::new();
    let mut conflicting_sids = HashSet::<String>::new();

    for process in processes.iter() {
        let details = &process.details;
        let Some(sid) = details.user_sid.as_deref() else {
            continue;
        };
        if well_known_process_account(sid).is_some() {
            continue;
        }
        let Some(candidate) = environment_account_candidate(details) else {
            continue;
        };
        if let Some(existing) = sid_accounts.get_mut(sid) {
            let domain_conflict = match (&existing.1, &candidate.1) {
                (Some(left), Some(right)) => !left.eq_ignore_ascii_case(right),
                _ => false,
            };
            if !existing.0.eq_ignore_ascii_case(&candidate.0) || domain_conflict {
                conflicting_sids.insert(sid.to_owned());
            } else if existing.1.is_none() {
                existing.1 = candidate.1;
            }
        } else {
            sid_accounts.insert(sid.to_owned(), candidate);
        }
    }
    for sid in conflicting_sids {
        sid_accounts.remove(&sid);
    }

    for process in processes {
        let details = &mut process.details;
        let Some(sid) = details.user_sid.as_deref() else {
            continue;
        };
        let (name, domain, source) = if let Some((domain, name)) = well_known_process_account(sid) {
            (name.to_owned(), Some(domain.to_owned()), "well_known_sid")
        } else if let Some((name, domain)) = sid_accounts.get(sid) {
            (name.clone(), domain.clone(), "environment_profile")
        } else {
            continue;
        };
        details.user_name = Some(name);
        details.user_domain = domain;
        details.user_name_source = Some(source.to_owned());
    }
}

fn environment_account_candidate(details: &ProcessDetails) -> Option<(String, Option<String>)> {
    let name = details.environment_user_name.as_deref()?.trim();
    let profile = details.environment_user_profile.as_deref()?.trim();
    if name.is_empty() || name.starts_with("S-1-") || name.chars().any(char::is_control) {
        return None;
    }
    let profile_name = profile
        .trim_end_matches(['\\', '/'])
        .rsplit(['\\', '/'])
        .next()?;
    if !profile_name.eq_ignore_ascii_case(name) {
        return None;
    }
    let domain = details
        .environment_user_domain
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Some((name.to_owned(), domain))
}

fn well_known_process_account(sid: &str) -> Option<(&'static str, &'static str)> {
    match sid {
        "S-1-5-18" => Some(("NT AUTHORITY", "SYSTEM")),
        "S-1-5-19" => Some(("NT AUTHORITY", "LOCAL SERVICE")),
        "S-1-5-20" => Some(("NT AUTHORITY", "NETWORK SERVICE")),
        _ => None,
    }
}

fn read_process_details(
    image: &MemoryImage,
    kernel_space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    eprocess: u64,
) -> ProcessDetails {
    let mut details = ProcessDetails {
        state: "running".to_owned(),
        ..ProcessDetails::default()
    };

    let pcb_offset = profile
        .fields
        .get("Pcb")
        .map(|field| field.offset)
        .unwrap_or(0);
    details.directory_table_base = profile
        .type_field("_KPROCESS", "DirectoryTableBase")
        .ok()
        .and_then(|field| {
            kernel_space
                .read_u64(eprocess + pcb_offset + field.offset)
                .ok()
        })
        .filter(|value| *value != 0);
    details.user_directory_table_base = profile
        .type_field("_KPROCESS", "UserDirectoryTableBase")
        .ok()
        .and_then(|field| {
            kernel_space
                .read_u64(eprocess + pcb_offset + field.offset)
                .ok()
        })
        .filter(|value| *value != 0);

    details.peb = eprocess_u64(kernel_space, profile, eprocess, "Peb").filter(|value| *value != 0);
    details.section_base_address =
        eprocess_u64(kernel_space, profile, eprocess, "SectionBaseAddress")
            .filter(|value| *value != 0);
    details.object_table =
        eprocess_u64(kernel_space, profile, eprocess, "ObjectTable").filter(|value| *value != 0);
    details.debug_port =
        eprocess_u64(kernel_space, profile, eprocess, "DebugPort").filter(|value| *value != 0);
    details.exception_port = eprocess_u64(kernel_space, profile, eprocess, "ExceptionPort")
        .map(|value| value & !0x7)
        .filter(|value| *value != 0);

    let wow64_pointer = eprocess_u64(kernel_space, profile, eprocess, "WoW64Process");
    details.wow64 = wow64_pointer.map(|value| value != 0);
    details.process_architecture = details
        .wow64
        .map(|wow64| if wow64 { "x86" } else { "x64" }.to_owned());
    details.active_threads = eprocess_u32(kernel_space, profile, eprocess, "ActiveThreads");
    details.handle_count = eprocess_u32(kernel_space, profile, eprocess, "HandleCount");
    details.exit_status = eprocess_i32(kernel_space, profile, eprocess, "ExitStatus");
    details.peak_virtual_size = eprocess_u64(kernel_space, profile, eprocess, "PeakVirtualSize");
    details.virtual_size = eprocess_u64(kernel_space, profile, eprocess, "VirtualSize");
    details.peak_working_set_size =
        eprocess_u64(kernel_space, profile, eprocess, "PeakWorkingSetSize");
    details.working_set_private_size =
        eprocess_u64(kernel_space, profile, eprocess, "WorkingSetPrivateSize");
    details.minimum_working_set_size =
        eprocess_u64(kernel_space, profile, eprocess, "MinimumWorkingSetSize");
    details.maximum_working_set_size =
        eprocess_u64(kernel_space, profile, eprocess, "MaximumWorkingSetSize");
    details.commit_charge = eprocess_u64(kernel_space, profile, eprocess, "CommitCharge");
    details.commit_charge_peak = eprocess_u64(kernel_space, profile, eprocess, "CommitChargePeak");
    details.private_page_count = eprocess_u64(kernel_space, profile, eprocess, "PrivatePageCount")
        .or_else(|| eprocess_u64(kernel_space, profile, eprocess, "NumberOfPrivatePages"));
    details.hard_fault_count = eprocess_u32(kernel_space, profile, eprocess, "HardFaultCount");
    details.vad_count = eprocess_u32(kernel_space, profile, eprocess, "VadCount");

    details.create_time_raw =
        eprocess_u64(kernel_space, profile, eprocess, "CreateTime").filter(|value| *value != 0);
    details.create_time = details.create_time_raw.and_then(filetime_to_rfc3339);
    details.exit_time_raw =
        eprocess_u64(kernel_space, profile, eprocess, "ExitTime").filter(|value| *value != 0);
    details.exit_time = details.exit_time_raw.and_then(filetime_to_rfc3339);
    if details.exit_time_raw.is_some() {
        details.state = "exited".to_owned();
    }

    let protection = eprocess_u8(kernel_space, profile, eprocess, "Protection");
    if let Some(level) = protection {
        details.protection_level = Some(level);
        details.protection_type = Some(protection_type(level & 0x7).to_owned());
        details.protection_audit = Some(level & 0x8 != 0);
        details.protection_signer = Some(protection_signer(level >> 4).to_owned());
    }
    details.signature_level = eprocess_u8(kernel_space, profile, eprocess, "SignatureLevel");
    details.section_signature_level =
        eprocess_u8(kernel_space, profile, eprocess, "SectionSignatureLevel");

    let token = eprocess_u64(kernel_space, profile, eprocess, "Token")
        .map(|value| value & !0xf)
        .filter(|value| is_kernel_pointer(*value));
    details.token = token;
    if let Some(token) = token {
        read_token_details(kernel_space, profile, token, &mut details);
    }

    if let Some(peb) = details.peb {
        let mut roots = Vec::with_capacity(2);
        if let Some(dtb) = details.user_directory_table_base {
            roots.push(dtb);
        }
        if let Some(dtb) = details.directory_table_base
            && !roots.contains(&dtb)
        {
            roots.push(dtb);
        }
        for dtb in roots {
            let Ok(process_space) = X64AddressSpace::new(image, dtb) else {
                continue;
            };
            if read_peb_details(&process_space, profile, peb, &mut details) {
                break;
            }
        }
    }

    details
}

fn read_peb_details(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    peb: u64,
    details: &mut ProcessDetails,
) -> bool {
    let Some(process_parameters_offset) = type_offset(profile, "_PEB", "ProcessParameters") else {
        return false;
    };
    let mut evidence = false;
    details.image_base =
        type_u64(space, profile, "_PEB", peb, "ImageBaseAddress").filter(|value| *value != 0);
    evidence |= details.image_base.is_some();
    details.being_debugged =
        type_u8(space, profile, "_PEB", peb, "BeingDebugged").map(|value| value != 0);
    details.nt_global_flag = type_u32(space, profile, "_PEB", peb, "NtGlobalFlag");
    details.peb_os_major_version = type_u32(space, profile, "_PEB", peb, "OSMajorVersion");
    details.peb_os_minor_version = type_u32(space, profile, "_PEB", peb, "OSMinorVersion");
    details.peb_os_build_number = type_u16(space, profile, "_PEB", peb, "OSBuildNumber");
    details.peb_number_of_processors = type_u32(space, profile, "_PEB", peb, "NumberOfProcessors");
    details.session_id = type_u32(space, profile, "_PEB", peb, "SessionId");

    let Ok(parameters) = space.read_u64(peb + process_parameters_offset) else {
        return evidence;
    };
    if parameters == 0 || !is_canonical(parameters) {
        return evidence;
    }
    details.image_path = read_type_unicode(
        space,
        profile,
        "_RTL_USER_PROCESS_PARAMETERS",
        parameters,
        "ImagePathName",
    );
    details.command_line = read_type_unicode(
        space,
        profile,
        "_RTL_USER_PROCESS_PARAMETERS",
        parameters,
        "CommandLine",
    );
    details.dll_path = read_type_unicode(
        space,
        profile,
        "_RTL_USER_PROCESS_PARAMETERS",
        parameters,
        "DllPath",
    );
    details.window_title = read_type_unicode(
        space,
        profile,
        "_RTL_USER_PROCESS_PARAMETERS",
        parameters,
        "WindowTitle",
    );
    details.desktop_info = read_type_unicode(
        space,
        profile,
        "_RTL_USER_PROCESS_PARAMETERS",
        parameters,
        "DesktopInfo",
    );
    details.current_directory =
        type_offset(profile, "_RTL_USER_PROCESS_PARAMETERS", "CurrentDirectory")
            .and_then(|current| type_offset(profile, "_CURDIR", "DosPath").map(|dos| current + dos))
            .and_then(|offset| read_unicode_string(space, profile, parameters + offset, 64 * 1024));
    details.environment_address = type_u64(
        space,
        profile,
        "_RTL_USER_PROCESS_PARAMETERS",
        parameters,
        "Environment",
    )
    .filter(|value| *value != 0);
    details.environment_size = type_u64(
        space,
        profile,
        "_RTL_USER_PROCESS_PARAMETERS",
        parameters,
        "EnvironmentSize",
    );
    if let (Some(address), Some(size)) = (details.environment_address, details.environment_size)
        && let Some(environment) = read_environment_variables(space, address, size)
    {
        apply_environment_variables(details, environment);
    }
    evidence
        || details.image_path.is_some()
        || details.command_line.is_some()
        || details.current_directory.is_some()
}

fn read_environment_variables(
    space: &X64AddressSpace<'_>,
    address: u64,
    reported_size: u64,
) -> Option<BTreeMap<String, String>> {
    const MAX_ENVIRONMENT_BYTES: u64 = 1024 * 1024;
    if address == 0 || !is_canonical(address) || reported_size == 0 {
        return None;
    }
    let byte_length = reported_size.min(MAX_ENVIRONMENT_BYTES) & !1;
    let byte_length = usize::try_from(byte_length).ok()?;
    let mut bytes = vec![0u8; byte_length];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(decode_environment_variables(&bytes))
}

fn apply_environment_variables(
    details: &mut ProcessDetails,
    environment: BTreeMap<String, String>,
) {
    details.environment_variable_count = Some(environment.len());
    details.environment_computer_name = environment.get("COMPUTERNAME").cloned();
    details.environment_user_name = environment.get("USERNAME").cloned();
    details.environment_user_domain = environment.get("USERDOMAIN").cloned();
    details.environment_user_profile = environment.get("USERPROFILE").cloned();
    details.environment_system_root = environment
        .get("SYSTEMROOT")
        .or_else(|| environment.get("WINDIR"))
        .cloned();
    details.environment_temp = environment
        .get("TEMP")
        .or_else(|| environment.get("TMP"))
        .cloned();
    details.environment_variables = environment;
}

fn decode_environment_variables(bytes: &[u8]) -> BTreeMap<String, String> {
    let words = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let block = String::from_utf16_lossy(&words);
    let mut variables = BTreeMap::new();
    for entry in block.split('\0').take(4096) {
        if entry.is_empty() {
            continue;
        }
        let Some((name, value)) = entry.split_once('=') else {
            continue;
        };
        if name.is_empty() || name.starts_with('=') {
            continue;
        }
        variables
            .entry(name.to_ascii_uppercase())
            .or_insert_with(|| value.to_owned());
    }
    variables
}

fn read_token_details(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    token: u64,
    details: &mut ProcessDetails,
) {
    details.token_id = type_u64(space, profile, "_TOKEN", token, "TokenId");
    details.token_authentication_id = type_u64(space, profile, "_TOKEN", token, "AuthenticationId");
    details.token_parent_id = type_u64(space, profile, "_TOKEN", token, "ParentTokenId");
    details.token_modified_id = type_u64(space, profile, "_TOKEN", token, "ModifiedId");
    details.token_originating_logon_session =
        type_u64(space, profile, "_TOKEN", token, "OriginatingLogonSession");
    details.token_logon_session = type_u64(space, profile, "_TOKEN", token, "LogonSession")
        .filter(|value| is_kernel_pointer(*value));
    details.token_source = type_offset(profile, "_TOKEN", "TokenSource")
        .and_then(|offset| read_ascii_fixed(space, token + offset, 8));
    details.token_session_id = type_u32(space, profile, "_TOKEN", token, "SessionId");
    details.token_flags = type_u32(space, profile, "_TOKEN", token, "TokenFlags");
    let token_type = type_u32(space, profile, "_TOKEN", token, "TokenType");
    details.token_type = token_type.map(|value| match value {
        1 => "primary".to_owned(),
        2 => "impersonation".to_owned(),
        _ => format!("unknown_{value}"),
    });
    if token_type == Some(2) {
        details.token_impersonation_level =
            type_u32(space, profile, "_TOKEN", token, "ImpersonationLevel").map(
                |value| match value {
                    0 => "anonymous".to_owned(),
                    1 => "identification".to_owned(),
                    2 => "impersonation".to_owned(),
                    3 => "delegation".to_owned(),
                    _ => format!("unknown_{value}"),
                },
            );
    }
    details.token_in_use =
        type_u8(space, profile, "_TOKEN", token, "TokenInUse").map(|value| value != 0);

    if let Some(privileges) = type_offset(profile, "_TOKEN", "Privileges") {
        details.privileges_present = type_u64(
            space,
            profile,
            "_SEP_TOKEN_PRIVILEGES",
            token + privileges,
            "Present",
        );
        details.privileges_enabled = type_u64(
            space,
            profile,
            "_SEP_TOKEN_PRIVILEGES",
            token + privileges,
            "Enabled",
        );
        details.privileges_enabled_by_default = type_u64(
            space,
            profile,
            "_SEP_TOKEN_PRIVILEGES",
            token + privileges,
            "EnabledByDefault",
        );
    }

    let user_groups = type_u64(space, profile, "_TOKEN", token, "UserAndGroups")
        .filter(|value| is_kernel_pointer(*value));
    let declared_group_count = type_u32(space, profile, "_TOKEN", token, "UserAndGroupCount");
    details.token_user_group_count = declared_group_count;
    let group_count = declared_group_count.unwrap_or(0).min(4096);
    details.token_groups_truncated = declared_group_count.map(|count| count > group_count);
    let entry_size = profile
        .types
        .get("_SID_AND_ATTRIBUTES")
        .map(|layout| layout.size)
        .filter(|size| *size >= 12)
        .unwrap_or(16);
    if let Some(groups) = user_groups {
        details.user_sid = type_u64(space, profile, "_SID_AND_ATTRIBUTES", groups, "Sid")
            .and_then(|sid| read_sid(space, sid));

        for index in 0..group_count {
            let entry = groups + u64::from(index) * entry_size;
            let Some(sid) = type_u64(space, profile, "_SID_AND_ATTRIBUTES", entry, "Sid")
                .and_then(|sid| read_sid(space, sid))
            else {
                continue;
            };
            let attributes =
                type_u32(space, profile, "_SID_AND_ATTRIBUTES", entry, "Attributes").unwrap_or(0);
            details.token_groups.push(ProcessTokenGroup {
                sid: sid.clone(),
                attributes,
                attribute_names: sid_attribute_names(attributes),
            });
            if attributes & 0xc000_0000 == 0xc000_0000 && details.logon_sid.is_none() {
                details.logon_sid = Some(sid);
            }
        }

        let integrity_index = type_u32(space, profile, "_TOKEN", token, "IntegrityLevelIndex")
            .filter(|index| *index < group_count);
        details.integrity_level_index = integrity_index;
        details.integrity_sid = type_u64(space, profile, "_TOKEN", token, "IntegrityLevelSidValue")
            .filter(|sid| is_kernel_pointer(*sid))
            // Modern kernels expose IntegrityLevelSidValue as a direct PSID,
            // not as a PSID_AND_ATTRIBUTES entry.  Keep the second branch for
            // profiles whose public type information models the older shape.
            .and_then(|value| {
                read_sid(space, value).or_else(|| {
                    type_u64(space, profile, "_SID_AND_ATTRIBUTES", value, "Sid")
                        .and_then(|sid| read_sid(space, sid))
                })
            })
            .or_else(|| {
                integrity_index.and_then(|index| {
                    type_u64(
                        space,
                        profile,
                        "_SID_AND_ATTRIBUTES",
                        groups + u64::from(index) * entry_size,
                        "Sid",
                    )
                    .and_then(|sid| read_sid(space, sid))
                })
            });
        details.integrity_level = details
            .integrity_sid
            .as_deref()
            .map(integrity_level_name)
            .map(str::to_owned);
    }
    details.token_groups_recovered = Some(details.token_groups.len());
}

fn sid_attribute_names(attributes: u32) -> Vec<String> {
    const FLAGS: &[(u32, &str)] = &[
        (0x0000_0001, "mandatory"),
        (0x0000_0002, "enabled_by_default"),
        (0x0000_0004, "enabled"),
        (0x0000_0008, "owner"),
        (0x0000_0010, "use_for_deny_only"),
        (0x0000_0020, "integrity"),
        (0x0000_0040, "integrity_enabled"),
        (0x2000_0000, "resource"),
    ];
    let mut names = FLAGS
        .iter()
        .filter(|(flag, _)| attributes & flag != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect::<Vec<_>>();
    if attributes & 0xc000_0000 == 0xc000_0000 {
        names.push("logon_id".to_owned());
    }
    names
}

fn read_ascii_fixed(space: &X64AddressSpace<'_>, address: u64, length: usize) -> Option<String> {
    let mut bytes = vec![0u8; length];
    space.read_virtual(address, &mut bytes).ok()?;
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(length);
    let value = std::str::from_utf8(&bytes[..end]).ok()?.trim();
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() && byte != b' ')
    {
        return None;
    }
    Some(value.to_owned())
}

fn read_type_unicode(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field_name: &str,
) -> Option<String> {
    let offset = type_offset(profile, type_name, field_name)?;
    read_unicode_string(space, profile, base + offset, 64 * 1024)
}

fn read_unicode_string(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    address: u64,
    max_bytes: usize,
) -> Option<String> {
    let length_offset = type_offset(profile, "_UNICODE_STRING", "Length").unwrap_or(0);
    let buffer_offset = type_offset(profile, "_UNICODE_STRING", "Buffer").unwrap_or(8);
    let length = usize::from(read_u16_at(space, address + length_offset)?);
    if length == 0 {
        return Some(String::new());
    }
    if length > max_bytes || length % 2 != 0 {
        return None;
    }
    let buffer = space.read_u64(address + buffer_offset).ok()?;
    if buffer == 0 || !is_canonical(buffer) {
        return None;
    }
    let mut bytes = vec![0u8; length];
    space.read_virtual(buffer, &mut bytes).ok()?;
    let words = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    Some(
        String::from_utf16_lossy(&words)
            .trim_end_matches('\0')
            .to_owned(),
    )
}

fn read_sid(space: &X64AddressSpace<'_>, address: u64) -> Option<String> {
    // SID allocations are only guaranteed to be DWORD aligned. Integrity
    // SIDs in particular often live at an address ending in 0x4/0xc, so the
    // stricter 8-byte structure-pointer check would discard valid evidence.
    if !is_kernel_address(address) {
        return None;
    }
    let mut header = [0u8; 8];
    space.read_virtual(address, &mut header).ok()?;
    let revision = header[0];
    let count = usize::from(header[1]);
    if revision == 0 || count > 15 {
        return None;
    }
    let authority = header[2..8]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    let mut raw = vec![0u8; count * 4];
    space.read_virtual(address + 8, &mut raw).ok()?;
    let mut sid = format!("S-{revision}-{authority}");
    for bytes in raw.chunks_exact(4) {
        let value = u32::from_le_bytes(bytes.try_into().ok()?);
        sid.push('-');
        sid.push_str(&value.to_string());
    }
    Some(sid)
}

fn integrity_level_name(sid: &str) -> &'static str {
    let rid = sid
        .rsplit('-')
        .next()
        .and_then(|value| value.parse::<u32>().ok());
    match rid {
        Some(0) => "untrusted",
        Some(4096) => "low",
        Some(8192) => "medium",
        Some(8448) => "medium_plus",
        Some(12288) => "high",
        Some(16384) => "system",
        Some(20480) => "protected",
        Some(28672) => "secure",
        _ => "unknown",
    }
}

fn protection_type(value: u8) -> &'static str {
    match value {
        0 => "none",
        1 => "protected_light",
        2 => "protected",
        _ => "unknown",
    }
}

fn protection_signer(value: u8) -> &'static str {
    match value {
        0 => "none",
        1 => "authenticode",
        2 => "codegen",
        3 => "antimalware",
        4 => "lsa",
        5 => "windows",
        6 => "wintcb",
        7 => "winsystem",
        8 => "app",
        _ => "unknown",
    }
}

fn filetime_to_rfc3339(value: u64) -> Option<String> {
    const WINDOWS_TO_UNIX_SECONDS: i128 = 11_644_473_600;
    const TICKS_PER_SECOND: i128 = 10_000_000;
    let value = i128::from(value);
    let unix_ticks = value.checked_sub(WINDOWS_TO_UNIX_SECONDS * TICKS_PER_SECOND)?;
    let seconds = unix_ticks.div_euclid(TICKS_PER_SECOND);
    let nanos = unix_ticks.rem_euclid(TICKS_PER_SECOND) * 100;
    let seconds = i64::try_from(seconds).ok()?;
    let nanos = u32::try_from(nanos).ok()?;
    DateTime::<Utc>::from_timestamp(seconds, nanos)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn eprocess_u64(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    eprocess: u64,
    field_name: &str,
) -> Option<u64> {
    let offset = profile.fields.get(field_name)?.offset;
    space.read_u64(eprocess + offset).ok()
}

fn eprocess_u32(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    eprocess: u64,
    field_name: &str,
) -> Option<u32> {
    let offset = profile.fields.get(field_name)?.offset;
    read_u32_at(space, eprocess + offset)
}

fn eprocess_i32(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    eprocess: u64,
    field_name: &str,
) -> Option<i32> {
    eprocess_u32(space, profile, eprocess, field_name).map(|value| value as i32)
}

fn eprocess_u8(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    eprocess: u64,
    field_name: &str,
) -> Option<u8> {
    let offset = profile.fields.get(field_name)?.offset;
    read_u8_at(space, eprocess + offset)
}

fn type_offset(profile: &KernelProfile, type_name: &str, field_name: &str) -> Option<u64> {
    profile
        .type_field(type_name, field_name)
        .ok()
        .map(|field| field.offset)
}

fn type_u64(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field_name: &str,
) -> Option<u64> {
    space
        .read_u64(base + type_offset(profile, type_name, field_name)?)
        .ok()
}

fn type_u32(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field_name: &str,
) -> Option<u32> {
    read_u32_at(space, base + type_offset(profile, type_name, field_name)?)
}

fn type_u16(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field_name: &str,
) -> Option<u16> {
    read_u16_at(space, base + type_offset(profile, type_name, field_name)?)
}

fn type_u8(
    space: &X64AddressSpace<'_>,
    profile: &KernelProfile,
    type_name: &str,
    base: u64,
    field_name: &str,
) -> Option<u8> {
    read_u8_at(space, base + type_offset(profile, type_name, field_name)?)
}

fn read_u8_at(space: &X64AddressSpace<'_>, address: u64) -> Option<u8> {
    let mut bytes = [0u8; 1];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(bytes[0])
}

fn read_u16_at(space: &X64AddressSpace<'_>, address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32_at(space: &X64AddressSpace<'_>, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    space.read_virtual(address, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn is_canonical(address: u64) -> bool {
    matches!(address >> 48, 0 | 0xffff)
}

fn is_kernel_list_pointer(address: u64) -> bool {
    address >> 48 == 0xffff && address & 7 == 0
}

fn push_warning(
    warnings: &mut Vec<ProcessListWarning>,
    kind: &str,
    message: String,
    list_entry: Option<u64>,
) {
    const MAX_WARNINGS: usize = 64;
    if warnings.len() < MAX_WARNINGS {
        warnings.push(ProcessListWarning {
            kind: kind.to_owned(),
            message,
            list_entry,
        });
    }
}

fn process_list_is_complete(
    stop_reason: &ProcessListStopReason,
    warnings: &[ProcessListWarning],
) -> bool {
    matches!(stop_reason, ProcessListStopReason::ListHead)
        && !warnings
            .iter()
            .any(|warning| process_list_warning_is_structural(&warning.kind))
}

fn process_list_warning_is_structural(kind: &str) -> bool {
    matches!(
        kind,
        "cycle"
            | "invalid_pointer"
            | "invalid_blink"
            | "blink_mismatch"
            | "unreadable_blink"
            | "unreadable_entry"
            | "invalid_process_id"
            | "unreadable_flink"
            | "head_blink_mismatch"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_filetime_converts_to_utc() {
        assert_eq!(
            filetime_to_rfc3339(116_444_736_000_000_000).as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );
    }

    #[test]
    fn process_list_head_blink_damage_is_incomplete_after_reaching_the_head() {
        for message in [
            "list head has Blink 0xffff800000001000, expected final entry 0xffff800000002000",
            "x86 list head has Blink 0x81234000, expected final entry 0x81235000",
        ] {
            let warnings = vec![ProcessListWarning {
                kind: "head_blink_mismatch".to_owned(),
                message: message.to_owned(),
                list_entry: Some(0xffff_8000_0000_0000),
            }];

            assert!(!process_list_is_complete(
                &ProcessListStopReason::ListHead,
                &warnings
            ));
        }
    }

    #[test]
    fn process_list_entry_link_damage_is_incomplete_after_reaching_the_head() {
        for kind in ["blink_mismatch", "unreadable_blink"] {
            let warnings = vec![ProcessListWarning {
                kind: kind.to_owned(),
                message: "damaged backward-link evidence".to_owned(),
                list_entry: Some(0xffff_8000_0000_1000),
            }];

            assert!(!process_list_is_complete(
                &ProcessListStopReason::ListHead,
                &warnings
            ));
        }
    }

    #[test]
    fn process_list_nonstructural_warnings_do_not_lower_completeness() {
        let warnings = vec![
            ProcessListWarning {
                kind: "legacy_x86_pae".to_owned(),
                message: "legacy layout notice".to_owned(),
                list_entry: None,
            },
            ProcessListWarning {
                kind: "process_name_decode".to_owned(),
                message: "lossy process name".to_owned(),
                list_entry: Some(0xffff_8000_0000_1000),
            },
        ];

        assert!(process_list_is_complete(
            &ProcessListStopReason::ListHead,
            &warnings
        ));
        assert!(!process_list_is_complete(
            &ProcessListStopReason::Limit,
            &warnings
        ));
    }

    #[test]
    fn enriched_process_csv_has_bom_and_hex_addresses() {
        let report = ProcessListReport {
            processes: vec![ProcessRecord {
                eprocess: 0xffff_8000_1234_5000,
                pid: 42,
                ppid: Some(4),
                name: "sample.exe".to_owned(),
                details: ProcessDetails {
                    state: "running".to_owned(),
                    directory_table_base: Some(0x1aa000),
                    command_line: Some("sample.exe --test".to_owned()),
                    ..ProcessDetails::default()
                },
            }],
            complete: true,
            stop_reason: ProcessListStopReason::ListHead,
            warnings: Vec::new(),
        };
        let mut output = Vec::new();
        write_process_csv(&report, &mut output).unwrap();
        assert!(output.starts_with(b"\xef\xbb\xbf"));
        let csv = String::from_utf8(output[3..].to_vec()).unwrap();
        assert!(csv.starts_with("EPROCESS,PID,PPID,Name,"));
        assert!(csv.contains("0xffff800012345000"));
        assert!(csv.contains("0x00000000001aa000"));
        assert!(csv.contains("sample.exe --test"));
    }

    #[test]
    fn process_user_names_prefer_token_identity_over_misleading_environment() {
        let mut processes = vec![ProcessRecord {
            eprocess: 0xffff_8000_1000_0000,
            pid: 4,
            ppid: None,
            name: "System".to_owned(),
            details: ProcessDetails {
                state: "running".to_owned(),
                user_sid: Some("S-1-5-18".to_owned()),
                environment_user_name: Some("SERVER-2008$".to_owned()),
                environment_user_domain: Some("WORKGROUP".to_owned()),
                environment_user_profile: Some(
                    r"C:\Windows\System32\config\systemprofile".to_owned(),
                ),
                ..ProcessDetails::default()
            },
        }];

        resolve_process_user_names(&mut processes);

        assert_eq!(processes[0].details.user_name.as_deref(), Some("SYSTEM"));
        assert_eq!(
            processes[0].details.user_domain.as_deref(),
            Some("NT AUTHORITY")
        );
        assert_eq!(
            processes[0].details.user_name_source.as_deref(),
            Some("well_known_sid")
        );
    }

    #[test]
    fn process_user_names_require_profile_corroboration_and_fill_same_sid() {
        let sid = "S-1-5-21-1-2-3-1001";
        let mut processes = vec![
            ProcessRecord {
                eprocess: 0xffff_8000_1000_0000,
                pid: 100,
                ppid: Some(4),
                name: "explorer.exe".to_owned(),
                details: ProcessDetails {
                    state: "running".to_owned(),
                    user_sid: Some(sid.to_owned()),
                    environment_user_name: Some("alice".to_owned()),
                    environment_user_domain: Some("WORKSTATION".to_owned()),
                    environment_user_profile: Some(r"C:\Users\alice".to_owned()),
                    ..ProcessDetails::default()
                },
            },
            ProcessRecord {
                eprocess: 0xffff_8000_2000_0000,
                pid: 101,
                ppid: Some(100),
                name: "old.exe".to_owned(),
                details: ProcessDetails {
                    state: "exited".to_owned(),
                    user_sid: Some(sid.to_owned()),
                    ..ProcessDetails::default()
                },
            },
        ];

        resolve_process_user_names(&mut processes);

        for process in &processes {
            assert_eq!(process.details.user_name.as_deref(), Some("alice"));
            assert_eq!(process.details.user_domain.as_deref(), Some("WORKSTATION"));
            assert_eq!(
                process.details.user_name_source.as_deref(),
                Some("environment_profile")
            );
        }
    }

    #[test]
    fn process_user_names_reject_uncorroborated_environment_claims() {
        let mut processes = vec![ProcessRecord {
            eprocess: 0xffff_8000_1000_0000,
            pid: 100,
            ppid: Some(4),
            name: "service.exe".to_owned(),
            details: ProcessDetails {
                state: "running".to_owned(),
                user_sid: Some("S-1-5-21-1-2-3-1001".to_owned()),
                environment_user_name: Some("SYSTEM".to_owned()),
                environment_user_profile: Some(
                    r"C:\Windows\System32\config\systemprofile".to_owned(),
                ),
                ..ProcessDetails::default()
            },
        }];

        resolve_process_user_names(&mut processes);

        assert!(processes[0].details.user_name.is_none());
        assert!(processes[0].details.user_domain.is_none());
        assert!(processes[0].details.user_name_source.is_none());
    }

    #[test]
    fn sid_attributes_require_the_full_logon_id_mask() {
        assert!(
            sid_attribute_names(0x0000_0080)
                .iter()
                .all(|name| name != "logon_id")
        );
        assert!(
            sid_attribute_names(0x8000_0000)
                .iter()
                .all(|name| name != "logon_id")
        );
        assert!(
            sid_attribute_names(0xc000_0000)
                .iter()
                .any(|name| name == "logon_id")
        );
    }
}
