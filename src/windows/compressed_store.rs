//! Reconstruct a Windows software PTE from the captured compression store.
//!
//! Reads are deliberately separate from physical address translation: decoded
//! bytes have no plaintext physical address. All metadata and compressed input
//! must be resident in this image; no pagefile, live machine or guessed page is
//! substituted. Store layouts are version gated and validated against their
//! B+trees, pool allocations and active owner process. See docs/HASHDUMP.md.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::WindowsKernelContext;
use crate::address::X64AddressSpace;
use crate::image::MemoryImage;
use crate::profile::KernelProfile;

const PAGE: usize = 4096;

#[derive(Debug, Serialize)]
pub struct CompressedPageEvidence {
    pub hive_file_offset: u64,
    pub target_virtual_address: u64,
    pub target_dtb: u64,
    pub pte_physical_address: u64,
    pub pte_value: u64,
    pub page_key: u32,
    pub sm_globals: u64,
    pub store_index: u32,
    pub store_address: u64,
    pub region_key: u32,
    pub page_record_address: u64,
    pub owner_eprocess: u64,
    pub owner_pid: u64,
    pub owner_dtb: u64,
    pub compressed_virtual_address: u64,
    pub compressed_size: usize,
    pub encoding: &'static str,
    pub source_spans: Vec<CompressedSourceSpan>,
    pub decoded_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct CompressedSourceSpan {
    pub physical_address: u64,
    pub length: usize,
}

#[derive(Clone, Copy)]
struct StoreLayout {
    algorithm: u64,
    regions: u64,
    owner: u64,
}

impl StoreLayout {
    fn for_build(build: u32) -> Result<Self> {
        let (algorithm, regions, owner) = match build {
            14393 => (0x420, 0x17a8, 0x1918),
            15063 => (0x420, 0x1828, 0x1988),
            16299 | 17134 | 17763 | 18362 | 18363 => (0x430, 0x1848, 0x19a8),
            19041..=19045 | 22000 => (0x430, 0x1848, 0x19b8),
            _ => bail!("Windows build {build} 的压缩存储布局尚未支持"),
        };
        Ok(Self {
            algorithm,
            regions,
            owner,
        })
    }
}

#[derive(Clone, Copy)]
struct Store {
    address: u64,
    owner: u64,
    pid: u64,
    dtb: u64,
    pages_tree: u64,
    regions: u64,
    region_shift: u32,
    region_mask: u32,
}

pub(crate) struct CompressedStore<'a> {
    image: &'a MemoryImage,
    space: X64AddressSpace<'a>,
    kernel: &'a WindowsKernelContext,
    profile: &'a KernelProfile,
    build: u32,
    layout: StoreLayout,
    virtual_pagefile: u32,
    invalid_pte_mask: u32,
    globals: u64,
    tree: u64,
    stores: HashMap<u32, Store>,
}

impl<'a> CompressedStore<'a> {
    pub(crate) fn new(
        image: &'a MemoryImage,
        kernel: &'a WindowsKernelContext,
        profile: &'a KernelProfile,
    ) -> Result<Self> {
        ensure!(!kernel.is_x86_pae(), "压缩存储目前仅支持 x64");
        let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
        let global = |name| -> Result<u64> {
            kernel
                .kernel_base
                .checked_add(u64::from(profile.symbol_rva(name)?))
                .context("kernel symbol address overflow")
        };
        let build = read_u32(&space, global("NtBuildNumber")?)? & 0xffff;
        let layout = StoreLayout::for_build(build)?;
        let invalid_pte_mask = if build >= 17134 {
            (space.read_u64(
                global("MiState")?
                    + profile
                        .type_field("_MI_SYSTEM_INFORMATION", "Hardware")?
                        .offset
                    + profile
                        .type_field("_MI_HARDWARE_STATE", "InvalidPteMask")?
                        .offset,
            )? >> 32) as u32
        } else {
            0
        };
        let paging_files = global("MiSystemPartition")?
            + profile.type_field("_MI_PARTITION", "Vp")?.offset
            + profile
                .type_field("_MI_VISIBLE_PARTITION", "PagingFile")?
                .offset;
        let flag = profile.type_field("_MMPAGING_FILE", "VirtualStorePagefile")?;
        let number = profile.type_field("_MMPAGING_FILE", "PageFileNumber")?;
        let mut virtual_files = HashSet::new();
        for index in 0..16 {
            let pointer = space.read_u64(paging_files + index * 8)?;
            if pointer == 0 {
                continue;
            }
            require_kernel(pointer, 8)?;
            let value = read_u32(&space, pointer + flag.offset)?;
            if bits(value, flag.bit_position, flag.bit_length)? == 1 {
                let value = read_u32(&space, pointer + number.offset)?;
                virtual_files.insert(bits(value, number.bit_position, number.bit_length)?);
            }
        }
        ensure!(
            virtual_files.len() == 1,
            "无法唯一确定 VirtualStorePagefile"
        );
        let virtual_pagefile = *virtual_files.iter().next().context("no virtual pagefile")?;
        ensure!(virtual_pagefile < 16, "invalid virtual pagefile number");
        let globals = locate_globals(&space, kernel, profile)?;
        let tree = space.read_u64(globals + 0x1c0)?;
        require_kernel(tree, PAGE as u64)?;
        Ok(Self {
            image,
            space,
            kernel,
            profile,
            build,
            layout,
            virtual_pagefile,
            invalid_pte_mask,
            globals,
            tree,
            stores: HashMap::new(),
        })
    }

    pub(crate) fn recover_page(
        &mut self,
        target: &X64AddressSpace<'_>,
        address: u64,
        hive_file_offset: u64,
    ) -> Result<([u8; PAGE], CompressedPageEvidence)> {
        ensure!(address & 0xfff == 0, "compressed read must be page aligned");
        let (pte_address, pte) = target.leaf_pte(address)?;
        let key = page_key(
            pte,
            self.build,
            self.virtual_pagefile,
            self.invalid_pte_mask,
        )?;
        let store_value = search_tree(&self.space, self.tree, key)?;
        ensure!(
            store_value & 0x0100_0000 == 0,
            "page is not in an active compression store"
        );
        let index = store_value & 0x3ff;
        let store = if let Some(store) = self.stores.get(&index) {
            *store
        } else {
            let store = self.load_store(index)?;
            self.stores.insert(index, store);
            store
        };
        let mut region_key = search_tree(&self.space, store.pages_tree, key)?;
        let mut visited = HashSet::new();
        let (record_address, record_key, encoded_size) = loop {
            ensure!(
                visited.len() < 32 && visited.insert(region_key),
                "page-record redirect cycle/limit"
            );
            let record = page_record_address(&self.space, store.address + 0x110, region_key)?;
            let record_key = read_u32(&self.space, record)?;
            if record_key == u32::MAX {
                region_key = read_u32(&self.space, record + 4)?;
                continue;
            }
            break (record, record_key, read_u16(&self.space, record + 4)?);
        };
        let size = if encoded_size == 0x1000 {
            PAGE
        } else {
            usize::from(encoded_size & 0xfff)
        };
        let region_index = record_key >> store.region_shift;
        ensure!(
            region_index < 0x10_0000,
            "compressed region index exceeds bound"
        );
        let region = self
            .space
            .read_u64(store.regions + u64::from(region_index) * 8)?
            & 0x7fff_ffff_ffff_0000;
        ensure!(
            region != 0 && region < 0x0000_8000_0000_0000,
            "invalid compressed region pointer"
        );
        let payload_va = region
            .checked_add(u64::from(record_key & store.region_mask) * 16)
            .context("compressed region offset overflow")?;
        ensure!(
            payload_va + size as u64 <= 0x0000_8000_0000_0000,
            "compressed input outside user space"
        );
        let owner_space = X64AddressSpace::new(self.image, store.dtb)?;
        let mut input = vec![0; size];
        // Strict resident reads only: recursively decompressing a store's own
        // backing pages could follow corrupt/cyclic references indefinitely.
        owner_space.read_virtual(payload_va, &mut input)?;
        let mut spans = Vec::new();
        let mut offset = 0;
        while offset < size {
            let at = payload_va + offset as u64;
            let take = (PAGE - (at as usize & 0xfff)).min(size - offset);
            spans.push(CompressedSourceSpan {
                physical_address: owner_space.translate(at)?,
                length: take,
            });
            offset += take;
        }
        let (page, encoding) = match size {
            0 => ([0; PAGE], "store_zero_page"),
            PAGE => (input.as_slice().try_into()?, "store_uncompressed"),
            _ => (decompress_xpress(&input)?, "xpress_lz77"),
        };
        let evidence = CompressedPageEvidence {
            hive_file_offset,
            target_virtual_address: address,
            target_dtb: target.directory_table_base(),
            pte_physical_address: pte_address,
            pte_value: pte,
            page_key: key,
            sm_globals: self.globals,
            store_index: index,
            store_address: store.address,
            region_key,
            page_record_address: record_address,
            owner_eprocess: store.owner,
            owner_pid: store.pid,
            owner_dtb: store.dtb,
            compressed_virtual_address: payload_va,
            compressed_size: size,
            encoding,
            source_spans: spans,
            decoded_sha256: hex::encode(Sha256::digest(page)),
        };
        Ok((page, evidence))
    }

    fn load_store(&self, index: u32) -> Result<Store> {
        let metadata = self
            .space
            .read_u64(self.globals + u64::from(index >> 5) * 8)?;
        require_pool(&self.space, metadata, b"smSa")?;
        let address = self
            .space
            .read_u64(metadata + u64::from(index & 31) * 0x28)?;
        require_kernel(address, PAGE as u64)?;
        ensure!(
            read_u16(&self.space, address + self.layout.algorithm)? == 3,
            "unsupported store compression algorithm"
        );
        let owner = self.space.read_u64(address + self.layout.owner)?;
        let (pid, dtb) = self.validate_owner(owner)?;
        let pages_tree = self.space.read_u64(address + 0x50)?;
        require_kernel(pages_tree, 16)?;
        let regions = self.space.read_u64(address + self.layout.regions)?;
        require_kernel(regions, 8)?;
        let region_shift = read_u32(&self.space, address + 0x37c)? & 0xff;
        let region_mask = read_u32(&self.space, address + 0x378)?;
        ensure!(
            region_shift < 32 && region_mask == (1u32 << region_shift) - 1,
            "invalid compression region masks"
        );
        Ok(Store {
            address,
            owner,
            pid,
            dtb,
            pages_tree,
            regions,
            region_shift,
            region_mask,
        })
    }

    fn validate_owner(&self, owner: u64) -> Result<(u64, u64)> {
        require_kernel(owner, 16)?;
        let field = |name| self.profile.type_field("_EPROCESS", name).map(|f| f.offset);
        let mut name = [0; 15];
        self.space
            .read_virtual(owner + field("ImageFileName")?, &mut name)?;
        let name = &name[..name.iter().position(|b| *b == 0).unwrap_or(name.len())];
        let pid = self.space.read_u64(owner + field("UniqueProcessId")?)?;
        let parent = self
            .space
            .read_u64(owner + field("InheritedFromUniqueProcessId")?)?;
        ensure!(
            (name == b"MemCompression" && parent == 4) || (name == b"System" && pid == 4),
            "compression store owner is not MemCompression/System"
        );
        let link_offset = field("ActiveProcessLinks")?;
        let head = self.kernel.ps_active_process_head;
        let mut link = self.space.read_u64(head)?;
        let mut visited = HashSet::new();
        while link != head && link != owner + link_offset {
            require_kernel(link, 8)?;
            ensure!(
                visited.len() < 32_768 && visited.insert(link),
                "active process list cycle/limit"
            );
            link = self.space.read_u64(link)?;
        }
        ensure!(
            link == owner + link_offset,
            "compression owner is absent from active process list"
        );
        let dtb = self.space.read_u64(
            owner
                + field("Pcb")?
                + self
                    .profile
                    .type_field("_KPROCESS", "DirectoryTableBase")?
                    .offset,
        )?;
        ensure!(
            dtb & 0x000f_ffff_ffff_f000 != 0,
            "compression owner has an empty full DTB"
        );
        Ok((pid, dtb))
    }
}

fn page_key(pte: u64, build: u32, virtual_pagefile: u32, mask: u32) -> Result<u32> {
    ensure!(
        pte & 0xc01 == 0 && pte >> 32 != 0,
        "PTE is not a stored software page"
    );
    let number_shift = if build >= 17134 { 12 } else { 1 };
    let number = ((pte >> number_shift) & 15) as u32;
    ensure!(
        number == virtual_pagefile,
        "PTE belongs to a disk pagefile, not the compression store"
    );
    let mut offset = (pte >> 32) as u32;
    if build >= 17134 && pte & 0x10 == 0 {
        offset &= !mask;
    }
    ensure!(
        offset != 0 && offset < 0x1000_0000,
        "invalid compressed page key"
    );
    Ok((number << 28) | offset)
}

fn locate_globals(
    space: &X64AddressSpace<'_>,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
) -> Result<u64> {
    if let Ok(rva) = profile.symbol_rva("SmGlobals") {
        let address = kernel.kernel_base + u64::from(rva);
        validate_globals(space, address)?;
        return Ok(address);
    }
    // Public PDBs may omit SmGlobals. Search only the first CACHEALI page in
    // this exact kernel, with independent pool/tree validation and uniqueness.
    let base = kernel.kernel_base;
    ensure!(
        read_u16(space, base)? == 0x5a4d,
        "kernel DOS header missing"
    );
    let pe = read_u32(space, base + 0x3c)?;
    ensure!(pe <= 0x1000, "invalid kernel PE offset");
    let pe = base + u64::from(pe);
    ensure!(
        read_u32(space, pe)? == 0x4550 && read_u16(space, pe + 24)? == 0x20b,
        "invalid kernel PE32+ header"
    );
    let count = read_u16(space, pe + 6)?;
    let optional_size = read_u16(space, pe + 20)?;
    ensure!(
        count <= 96 && optional_size <= 0x1000,
        "invalid kernel section table"
    );
    let mut candidates = Vec::new();
    for index in 0..count {
        let section = pe + 24 + u64::from(optional_size) + u64::from(index) * 40;
        let mut header = [0; 40];
        space.read_virtual(section, &mut header)?;
        if &header[..8] != b"CACHEALI" {
            continue;
        }
        let size = u32::from_le_bytes(header[8..12].try_into()?);
        let rva = u32::from_le_bytes(header[12..16].try_into()?);
        ensure!(size >= 0x1c8 && rva < 0x1000_0000, "invalid CACHEALI range");
        let mut page = vec![0; (size as usize).min(PAGE)];
        space.read_virtual(base + u64::from(rva), &mut page)?;
        for offset in (0..=page.len() - 0x1c8).step_by(8) {
            let pointer = u64::from_le_bytes(page[offset..offset + 8].try_into()?);
            if require_kernel(pointer, 16).is_err() {
                continue;
            }
            let address = base + u64::from(rva) + offset as u64;
            if validate_globals(space, address).is_ok() {
                candidates.push(address);
            }
        }
    }
    ensure!(
        candidates.len() == 1,
        "SmGlobals search did not produce one validated candidate ({})",
        candidates.len()
    );
    Ok(candidates[0])
}

fn validate_globals(space: &X64AddressSpace<'_>, address: u64) -> Result<()> {
    require_kernel(address, 8)?;
    require_pool(space, space.read_u64(address)?, b"smSa")?;
    let tree = space.read_u64(address + 0x1c0)?;
    require_kernel(tree, PAGE as u64)?;
    let mut node = [0; PAGE];
    space.read_virtual(tree, &mut node)?;
    validate_node(&node)?;
    Ok(())
}

fn search_tree(space: &X64AddressSpace<'_>, mut address: u64, key: u32) -> Result<u32> {
    let mut seen = HashSet::new();
    let mut expected_level = None;
    for _ in 0..16 {
        require_kernel(address, 16)?;
        ensure!(seen.insert(address), "compression B+tree cycle");
        let mut node = [0; PAGE];
        space.read_virtual(address, &mut node)?;
        let (count, leaf, level) = validate_node(&node)?;
        if let Some(expected) = expected_level {
            ensure!(level == expected, "B+tree level mismatch");
        }
        let stride = if leaf { 8 } else { 16 };
        let mut child = u64::from_le_bytes(node[8..16].try_into()?);
        for index in 0..count {
            let at = 16 + index * stride;
            let candidate = u32::from_le_bytes(node[at..at + 4].try_into()?);
            if candidate > key {
                break;
            }
            if leaf && candidate == key {
                return Ok(u32::from_le_bytes(node[at + 4..at + 8].try_into()?));
            }
            if !leaf {
                child = u64::from_le_bytes(node[at + 8..at + 16].try_into()?);
            }
        }
        ensure!(!leaf, "compressed page key {key:#x} absent from B+tree");
        expected_level = Some(
            level
                .checked_sub(1)
                .context("invalid B+tree branch level")?,
        );
        address = child;
    }
    bail!("compression B+tree depth limit")
}

fn validate_node(node: &[u8; PAGE]) -> Result<(usize, bool, u8)> {
    let count = usize::from(u16::from_le_bytes([node[0], node[1]]));
    let level = node[2];
    ensure!(node[3] <= 1, "invalid B+tree leaf flag");
    let leaf = node[3] == 1;
    let stride = if leaf { 8 } else { 16 };
    ensure!(
        count <= (PAGE - 16) / stride && (1..16).contains(&level) && leaf == (level == 1),
        "invalid B+tree header"
    );
    let mut previous = None;
    for index in 0..count {
        let at = 16 + index * stride;
        let key = u32::from_le_bytes(node[at..at + 4].try_into()?);
        ensure!(
            previous.is_none_or(|previous| previous < key),
            "B+tree keys are not strictly ordered"
        );
        previous = Some(key);
    }
    Ok((count, leaf, level))
}

fn page_record_address(space: &X64AddressSpace<'_>, metadata: u64, key: u32) -> Result<u64> {
    let shift = read_u32(space, metadata + 0x108)? & 0xff;
    ensure!(shift < 32, "invalid chunk shift");
    let encoded = key >> shift;
    ensure!(encoded != 0, "empty chunk index");
    let highest = 31 - encoded.leading_zeros();
    let index = encoded ^ (1 << highest);
    ensure!(index <= 0x400, "chunk pointer array bound");
    let chunk = space.read_u64(metadata + u64::from(highest) * 8)?;
    require_kernel(chunk, 16)?;
    if chunk & 0xfff != 0 {
        require_pool(space, chunk, b"smBA")?;
    }
    let array = space.read_u64(chunk + u64::from(index) * 16)?;
    require_kernel(array, PAGE as u64)?;
    let mask = read_u32(space, metadata + 0x10c)?;
    let size = read_u32(space, metadata + 0x110)?;
    let header = read_u32(space, metadata + 0x118)?;
    ensure!(
        (12..=256).contains(&size) && header <= 0x1000 && mask < 0x10_0000,
        "invalid chunk record geometry"
    );
    let offset = u64::from(header) + u64::from(size) * u64::from(key & mask);
    ensure!(offset < 0x100_0000, "page record offset exceeds bound");
    array
        .checked_add(offset)
        .context("page record address overflow")
}

fn require_kernel(address: u64, alignment: u64) -> Result<()> {
    ensure!(
        (0xffff_8000_0000_0000..=0xffff_ffff_fe00_0000).contains(&address)
            && address.is_multiple_of(alignment),
        "invalid kernel pointer {address:#x}"
    );
    Ok(())
}

fn require_pool(space: &X64AddressSpace<'_>, address: u64, tag: &[u8; 4]) -> Result<()> {
    require_kernel(address, 16)?;
    let mut actual = [0; 4];
    space.read_virtual(address - 12, &mut actual)?;
    ensure!(
        &actual == tag,
        "compression metadata pool tag mismatch at {address:#x}"
    );
    Ok(())
}

fn read_u32(space: &X64AddressSpace<'_>, address: u64) -> Result<u32> {
    let mut bytes = [0; 4];
    space.read_virtual(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u16(space: &X64AddressSpace<'_>, address: u64) -> Result<u16> {
    let mut bytes = [0; 2];
    space.read_virtual(address, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn bits(value: u32, position: Option<u8>, length: Option<u8>) -> Result<u32> {
    let position = u32::from(position.context("PDB bit position missing")?);
    let length = u32::from(length.context("PDB bit length missing")?);
    ensure!(
        length > 0 && length < 32 && position + length <= 32,
        "invalid PDB bitfield"
    );
    Ok((value >> position) & ((1 << length) - 1))
}

/// Plain XPRESS LZ77, MS-XCA 2.4.4 (not XPRESS-Huffman). Decode one 4 KiB
/// store page, rejecting truncated input, invalid backreferences and overflow.
fn decompress_xpress(input: &[u8]) -> Result<[u8; PAGE]> {
    let mut cursor = 0;
    let mut flags = 0u32;
    let mut remaining = 0;
    let mut high_nibble = None;
    let mut page = [0; PAGE];
    let mut written = 0;
    while written < PAGE {
        if remaining == 0 {
            flags = take_integer(input, &mut cursor, 4)?;
            remaining = 32;
        }
        remaining -= 1;
        if flags & (1 << remaining) == 0 {
            page[written] = take_integer(input, &mut cursor, 1)? as u8;
            written += 1;
            continue;
        }
        let token = take_integer(input, &mut cursor, 2)?;
        let distance = (token >> 3) as usize + 1;
        let mut length = token & 7;
        if length == 7 {
            length = if let Some(nibble) = high_nibble.take() {
                nibble
            } else {
                let byte = take_integer(input, &mut cursor, 1)?;
                high_nibble = Some(byte >> 4);
                byte & 15
            };
            if length == 15 {
                length = take_integer(input, &mut cursor, 1)?;
                if length == 255 {
                    length = take_integer(input, &mut cursor, 2)?;
                    if length == 0 {
                        length = take_integer(input, &mut cursor, 4)?;
                    }
                    ensure!(length >= 22, "invalid XPRESS extended length");
                    length -= 22;
                }
                length = length.checked_add(15).context("XPRESS length overflow")?;
            }
            length = length.checked_add(7).context("XPRESS length overflow")?;
        }
        let length = usize::try_from(length.checked_add(3).context("XPRESS length overflow")?)?;
        ensure!(
            distance <= written && length <= PAGE - written,
            "XPRESS backreference/output bound"
        );
        for _ in 0..length {
            page[written] = page[written - distance];
            written += 1;
        }
    }
    // A store record's length binds the whole compressed payload. Some XPRESS
    // streams include a final flag word when the last token filled 32 flags.
    if cursor != input.len() {
        ensure!(
            remaining == 0 && input.len() - cursor == 4 && input[cursor..] == [0xff; 4],
            "unexpected trailing XPRESS bytes"
        );
    }
    Ok(page)
}

fn take_integer(input: &[u8], cursor: &mut usize, count: usize) -> Result<u32> {
    let end = cursor
        .checked_add(count)
        .context("XPRESS cursor overflow")?;
    let bytes = input.get(*cursor..end).context("truncated XPRESS input")?;
    let mut value = [0; 4];
    value[..count].copy_from_slice(bytes);
    *cursor = end;
    Ok(u32::from_le_bytes(value))
}

#[cfg(test)]
#[path = "compressed_store_tests.rs"]
mod tests;
