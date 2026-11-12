use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{Read, copy};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, bail, ensure};
use pdb::FallibleIterator;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::address::{WindowsAddressSpace, X64AddressSpace};
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::output_policy::{OutputPolicy, OutputTarget};
use crate::scan::scan_patterns_cancellable;

const DEFAULT_CHUNK_SIZE: usize = 64 * 1024 * 1024;
const CODEVIEW_CACHE_SCHEMA: u32 = 1;
const MAX_CACHED_CODEVIEW_BYTES: usize = 4096;
const MAX_PDB_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CodeViewRecord {
    pub pdb_name: String,
    pub embedded_path: String,
    pub guid: String,
    pub age: u32,
    pub symbol_key: String,
    pub physical_address: u64,
}

#[derive(Debug, Serialize)]
pub struct SymbolMatch {
    pub name: String,
    pub kind: String,
    pub rva: Option<u32>,
    pub section: u16,
    pub section_offset: u32,
}

#[derive(Debug, Serialize)]
pub struct PdbSummary {
    pub guid: String,
    pub age: u32,
    pub matches: Vec<SymbolMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedPdb {
    pub record: CodeViewRecord,
    pub path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedKernelCodeView {
    schema: u32,
    source_file_len: u64,
    image_logical_len: u64,
    modified_unix_nanos: u128,
    record: CodeViewRecord,
}

/// A Microsoft-compatible symbol store with zero or more shared read-only roots
/// and one writable download cache.
///
/// Every root uses the Microsoft symbol-server layout:
/// `<root>/<pdb name>/<GUID+age>/<pdb name>`.
#[derive(Debug, Clone)]
pub struct SymbolStore {
    search_roots: Vec<PathBuf>,
    writable_root: PathBuf,
    linux_isf: Option<PathBuf>,
    linux_system_map: Option<PathBuf>,
}

impl SymbolStore {
    pub fn new(writable_root: PathBuf) -> Self {
        Self {
            search_roots: Vec::new(),
            writable_root,
            linux_isf: None,
            linux_system_map: None,
        }
    }

    /// Add a shared symbol root. Earlier roots have higher priority.
    pub fn add_search_root(&mut self, root: PathBuf) {
        if root.as_os_str().is_empty()
            || self
                .search_roots
                .iter()
                .any(|existing| paths_equal(existing, &root))
            || paths_equal(&self.writable_root, &root)
        {
            return;
        }
        self.search_roots.push(root);
    }

    pub fn with_search_root(mut self, root: PathBuf) -> Self {
        self.add_search_root(root);
        self
    }

    pub fn search_roots(&self) -> &[PathBuf] {
        &self.search_roots
    }

    pub fn writable_root(&self) -> &Path {
        &self.writable_root
    }

    /// Pin Linux analysis to one user-supplied ISF, without changing Windows PDB resolution.
    pub fn with_linux_isf(mut self, path: PathBuf) -> Self {
        self.linux_isf = Some(path);
        self
    }

    pub fn linux_isf(&self) -> Option<&Path> {
        self.linux_isf.as_deref()
    }

    /// Pin Linux addresses. Type completion must verify this map against an exact ISF.
    pub fn with_linux_system_map(mut self, path: PathBuf) -> Self {
        self.linux_system_map = Some(path);
        self
    }

    pub fn linux_system_map(&self) -> Option<&Path> {
        self.linux_system_map.as_deref()
    }

    /// Search the configured roots without the explicit Linux input. Callers must
    /// validate any candidate against that input before using it.
    pub fn without_linux_selection(&self) -> Self {
        let mut store = self.clone();
        store.linux_isf = None;
        store.linux_system_map = None;
        store
    }

    /// Locate an already cached PDB without mutating any symbol store.
    pub fn find(&self, record: &CodeViewRecord) -> Result<Option<PathBuf>> {
        validate_symbol_record_path(record)?;
        for root in self
            .search_roots
            .iter()
            .chain(std::iter::once(&self.writable_root))
        {
            let candidate = symbol_file_path(root, record);
            if pdb_matches_record(&candidate, record)? {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    /// Resolve a PDB from shared caches first, downloading into the writable
    /// cache only when no matching local symbol exists.
    pub fn resolve(&self, record: &CodeViewRecord) -> Result<PathBuf> {
        self.resolve_protecting(record, &[])
    }

    /// Resolve a PDB while guaranteeing that cache publication cannot replace any supplied
    /// evidence input, even when a cache path is a relative, symbolic-link, or hard-link alias.
    pub fn resolve_protecting(
        &self,
        record: &CodeViewRecord,
        protected_inputs: &[(&str, &Path)],
    ) -> Result<PathBuf> {
        if let Some(path) = self.find(record)? {
            return Ok(path);
        }
        download_symbol(record, &self.writable_root, protected_inputs)
    }
}

pub fn discover_codeview(image: &MemoryImage, pdb_name: &str) -> Result<Vec<CodeViewRecord>> {
    discover_codeviews(image, &[pdb_name], &CancellationToken::new())
}

fn discover_codeviews(
    image: &MemoryImage,
    pdb_names: &[&str],
    cancellation: &CancellationToken,
) -> Result<Vec<CodeViewRecord>> {
    cancellation.check_cancelled()?;
    if let Ok(Some(record)) = discover_kernel_codeview(image)
        && pdb_names
            .iter()
            .any(|name| record.pdb_name.eq_ignore_ascii_case(name))
    {
        return Ok(vec![record]);
    }

    let patterns = pdb_names
        .iter()
        .map(|name| name.as_bytes())
        .collect::<Vec<_>>();
    let report =
        scan_patterns_cancellable(image, &patterns, 128, DEFAULT_CHUNK_SIZE, cancellation)?;
    let mut records = Vec::new();
    for hit in report.hits {
        cancellation.check_cancelled()?;
        let pdb_name = pdb_names[hit.pattern_index];
        let Some(span) = image
            .spans()
            .iter()
            .find(|span| hit.physical_address >= span.start && hit.physical_address < span.end())
        else {
            continue;
        };
        let window_start = hit.physical_address.saturating_sub(1024).max(span.start);
        let window_end = hit
            .physical_address
            .saturating_add(pdb_name.len() as u64 + 512)
            .min(span.end());
        let mut bytes = vec![0u8; usize::try_from(window_end - window_start)?];
        image.read_physical(window_start, &mut bytes)?;
        let filename_relative = usize::try_from(hit.physical_address - window_start)?;

        for rsds_relative in (0..filename_relative.saturating_sub(23)).rev() {
            if bytes.get(rsds_relative..rsds_relative + 4) != Some(b"RSDS") {
                continue;
            }
            let path_start = rsds_relative + 24;
            if path_start > filename_relative {
                continue;
            }
            let Some(nul_relative) = bytes[path_start..].iter().position(|byte| *byte == 0) else {
                continue;
            };
            let path_bytes = &bytes[path_start..path_start + nul_relative];
            if !path_bytes.is_ascii() || path_bytes.iter().any(|byte| byte.is_ascii_control()) {
                continue;
            }
            let embedded_path = String::from_utf8_lossy(path_bytes).into_owned();
            let Some(embedded_name) = embedded_path.rsplit(['\\', '/']).next() else {
                continue;
            };
            if !embedded_name.eq_ignore_ascii_case(pdb_name) {
                continue;
            }

            let guid_bytes: [u8; 16] = bytes[rsds_relative + 4..rsds_relative + 20]
                .try_into()
                .expect("fixed CodeView GUID width");
            let age = u32::from_le_bytes(
                bytes[rsds_relative + 20..rsds_relative + 24]
                    .try_into()
                    .expect("fixed CodeView age width"),
            );
            let guid = format_guid(guid_bytes);
            let symbol_key = format!("{}{:X}", guid.replace('-', ""), age);
            let physical_address = window_start + rsds_relative as u64;
            records.push(CodeViewRecord {
                pdb_name: embedded_name.to_owned(),
                embedded_path,
                guid,
                age,
                symbol_key,
                physical_address,
            });
            break;
        }
    }
    // Keep the historical kernel-name preference, then the first physical copy.
    records.sort_by_key(|record| {
        (
            pdb_names
                .iter()
                .position(|name| record.pdb_name.eq_ignore_ascii_case(name)),
            record.physical_address,
        )
    });
    let mut identities = HashSet::new();
    records.retain(|record| {
        identities.insert((
            record.pdb_name.to_ascii_lowercase(),
            record.symbol_key.clone(),
        ))
    });
    Ok(records)
}

fn discover_kernel_codeview(image: &MemoryImage) -> Result<Option<CodeViewRecord>> {
    let Some(dump) = image.dump64() else {
        return Ok(None);
    };
    let address_space = X64AddressSpace::new(image, dump.directory_table_base)?;
    let kernel_base = kernel_base_from_kdbg(&address_space, dump.kd_debugger_data_block)
        .or_else(|_| kernel_base_from_module_list(&address_space, dump.ps_loaded_module_list))?;
    Ok(Some(codeview_from_address_space(
        &WindowsAddressSpace::X64(address_space),
        kernel_base,
    )?))
}

pub fn codeview_from_virtual_pe(
    image: &MemoryImage,
    directory_table_base: u64,
    image_base: u64,
) -> Result<CodeViewRecord> {
    let address_space = X64AddressSpace::new(image, directory_table_base)?;
    codeview_from_address_space(&WindowsAddressSpace::X64(address_space), image_base)
}

pub fn export_rva_from_virtual_pe(
    image: &MemoryImage,
    directory_table_base: u64,
    image_base: u64,
    export_name: &str,
) -> Result<Option<u32>> {
    let address_space = X64AddressSpace::new(image, directory_table_base)?;
    let mut dos = [0u8; 64];
    address_space.read_virtual(image_base, &mut dos)?;
    ensure!(dos.starts_with(b"MZ"), "映像没有 DOS 文件头");
    let pe_offset = u64::from(read_u32(&dos, 0x3c)?);
    ensure!(pe_offset <= 0x1000, "PE 文件头偏移不合理");
    let mut headers = vec![0u8; 0x200];
    address_space.read_virtual(image_base + pe_offset, &mut headers)?;
    ensure!(headers.starts_with(b"PE\0\0"), "PE 签名无效");
    ensure!(read_u16(&headers, 24)? == 0x20b, "映像不是 PE32+");
    let export_rva = u64::from(read_u32(&headers, 24 + 0x70)?);
    let export_size = u64::from(read_u32(&headers, 24 + 0x74)?);
    if export_rva == 0 || export_size < 40 {
        return Ok(None);
    }
    let mut directory = [0u8; 40];
    address_space.read_virtual(image_base + export_rva, &mut directory)?;
    let function_count = read_u32(&directory, 20)?;
    let name_count = read_u32(&directory, 24)?;
    let functions_rva = u64::from(read_u32(&directory, 28)?);
    let names_rva = u64::from(read_u32(&directory, 32)?);
    let ordinals_rva = u64::from(read_u32(&directory, 36)?);
    ensure!(
        name_count <= 65_536 && function_count <= 65_536,
        "PE 导出表不合理"
    );
    for index in 0..name_count {
        let name_rva = read_virtual_u32(
            &address_space,
            image_base + names_rva + u64::from(index) * 4,
        )?;
        let name = read_virtual_c_string(&address_space, image_base + u64::from(name_rva), 512)?;
        if name != export_name {
            continue;
        }
        let ordinal = read_virtual_u16(
            &address_space,
            image_base + ordinals_rva + u64::from(index) * 2,
        )?;
        ensure!(u32::from(ordinal) < function_count, "PE 导出序号超出范围");
        let rva = read_virtual_u32(
            &address_space,
            image_base + functions_rva + u64::from(ordinal) * 4,
        )?;
        return Ok(Some(rva));
    }
    Ok(None)
}

fn read_virtual_c_string(
    address_space: &X64AddressSpace<'_>,
    address: u64,
    limit: usize,
) -> Result<String> {
    let mut bytes = Vec::with_capacity(64);
    for index in 0..limit {
        let mut byte = [0u8; 1];
        address_space.read_virtual(address + index as u64, &mut byte)?;
        if byte[0] == 0 {
            return Ok(String::from_utf8(bytes)?);
        }
        ensure!(byte[0].is_ascii(), "PE 导出名称不是 ASCII");
        bytes.push(byte[0]);
    }
    bail!("PE 导出名称没有终止符")
}

fn read_virtual_u16(address_space: &X64AddressSpace<'_>, address: u64) -> Result<u16> {
    let mut bytes = [0u8; 2];
    address_space.read_virtual(address, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_virtual_u32(address_space: &X64AddressSpace<'_>, address: u64) -> Result<u32> {
    let mut bytes = [0u8; 4];
    address_space.read_virtual(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

pub(crate) fn codeview_from_address_space(
    address_space: &WindowsAddressSpace<'_>,
    image_base: u64,
) -> Result<CodeViewRecord> {
    let mut dos = [0u8; 64];
    address_space.read_virtual(image_base, &mut dos)?;
    ensure!(dos.starts_with(b"MZ"), "映像基址处没有 MZ 文件头");
    let pe_offset = read_u32(&dos, 0x3c)? as u64;
    ensure!(pe_offset <= 0x1000, "内核 PE 文件头偏移不合理");
    let mut nt_headers = vec![0u8; 0x200];
    address_space.read_virtual(image_base + pe_offset, &mut nt_headers)?;
    ensure!(nt_headers.starts_with(b"PE\0\0"), "内核 PE 签名无效");
    let optional_offset = 24usize;
    let directory_offset = match (
        address_space.pointer_size(),
        read_u16(&nt_headers, optional_offset)?,
    ) {
        (4, 0x10b) => 0x60,
        (8, 0x20b) => 0x70,
        _ => bail!("PE optional header 与目标地址空间架构不匹配"),
    };
    let debug_directory_offset = optional_offset + directory_offset + 6 * 8;
    let debug_rva = read_u32(&nt_headers, debug_directory_offset)? as u64;
    let debug_size = read_u32(&nt_headers, debug_directory_offset + 4)? as usize;
    ensure!(debug_rva != 0 && debug_size >= 28, "PE 映像没有调试目录");
    ensure!(debug_size <= 28 * 1024, "内核调试目录大小不合理");
    let mut directories = vec![0u8; debug_size];
    address_space.read_virtual(image_base + debug_rva, &mut directories)?;

    for directory in directories.chunks_exact(28) {
        if read_u32(directory, 12)? != 2 {
            continue;
        }
        let data_size = read_u32(directory, 16)? as usize;
        let data_rva = read_u32(directory, 20)? as u64;
        if !(25..=4096).contains(&data_size) || data_rva == 0 {
            continue;
        }
        let mut codeview = vec![0u8; data_size];
        address_space.read_virtual(image_base + data_rva, &mut codeview)?;
        if !codeview.starts_with(b"RSDS") {
            continue;
        }
        let path_end = codeview[24..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|relative| relative + 24)
            .unwrap_or(codeview.len());
        let path_bytes = &codeview[24..path_end];
        if !path_bytes.is_ascii() || path_bytes.iter().any(|byte| byte.is_ascii_control()) {
            continue;
        }
        let embedded_path = String::from_utf8_lossy(path_bytes).into_owned();
        let pdb_name = embedded_path
            .rsplit(['\\', '/'])
            .next()
            .context("CodeView 记录没有 PDB 名称")?
            .to_owned();
        let guid_bytes: [u8; 16] = codeview[4..20]
            .try_into()
            .expect("validated CodeView width");
        let age = read_u32(&codeview, 20)?;
        let guid = format_guid(guid_bytes);
        let symbol_key = format!("{}{:X}", guid.replace('-', ""), age);
        let codeview_va = image_base + data_rva;
        let physical_address = address_space.translate(codeview_va).unwrap_or(0);
        return Ok(CodeViewRecord {
            pdb_name,
            embedded_path,
            guid,
            age,
            symbol_key,
            physical_address,
        });
    }
    bail!("PE 映像不包含可用的 RSDS CodeView 记录")
}

fn kernel_base_from_kdbg(address_space: &X64AddressSpace<'_>, kdbg: u64) -> Result<u64> {
    ensure!(kdbg != 0, "转储中没有 KDBG 指针");
    let mut header = [0u8; 32];
    address_space.read_virtual(kdbg, &mut header)?;
    ensure!(
        &header[0x10..0x14] == b"KDBG",
        "KDBG 所有者标签已编码或不存在"
    );
    let kernel_base = read_u64(&header, 0x18)?;
    ensure!(kernel_base != 0, "KDBG 的内核基址为零");
    Ok(kernel_base)
}

fn kernel_base_from_module_list(
    address_space: &X64AddressSpace<'_>,
    loaded_module_list: u64,
) -> Result<u64> {
    ensure!(loaded_module_list != 0, "转储中没有已加载模块链表指针");
    let first_entry = address_space.read_u64(loaded_module_list)?;
    ensure!(first_entry != loaded_module_list, "已加载模块链表为空");
    // InLoadOrderLinks is the first field and DllBase is the stable bootstrap field at +0x30
    // in the x64 KLDR_DATA_TABLE_ENTRY used by supported Windows crash dumps.
    let kernel_base = address_space.read_u64(first_entry + 0x30)?;
    ensure!(kernel_base != 0, "首个已加载模块的基址为零");
    Ok(kernel_base)
}

pub fn default_symbol_cache() -> PathBuf {
    if let Some(path) = env::var_os("STARMEM_SYMBOL_CACHE").filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".starmem-cache"))
        .join("starmem")
        .join("symbols")
}

/// Build the default store used by the CLI and the future LovelyMem bridge.
///
/// `STARMEM_SYMBOL_PATH` may contain multiple platform-separated shared roots
/// (semicolon-separated on Windows). `STARMEM_SYMBOL_CACHE` selects the
/// writable cache used for symbols missing from every shared root.
pub fn default_symbol_store() -> SymbolStore {
    symbol_store(default_symbol_cache(), std::iter::empty::<PathBuf>())
}

/// Build a symbol store from explicit shared roots plus `STARMEM_SYMBOL_PATH`.
/// Explicit roots are searched first and remain read-only.
pub fn symbol_store(
    writable_root: PathBuf,
    search_roots: impl IntoIterator<Item = PathBuf>,
) -> SymbolStore {
    let mut store = SymbolStore::new(writable_root);
    for root in search_roots {
        store.add_search_root(root);
    }
    if let Some(paths) = env::var_os("STARMEM_SYMBOL_PATH") {
        for root in env::split_paths(&paths) {
            store.add_search_root(root);
        }
    }
    store
}

pub fn fetch_symbol(record: &CodeViewRecord, cache: &Path) -> Result<PathBuf> {
    SymbolStore::new(cache.to_path_buf()).resolve(record)
}

fn download_symbol(
    record: &CodeViewRecord,
    cache: &Path,
    protected_inputs: &[(&str, &Path)],
) -> Result<PathBuf> {
    validate_symbol_record_path(record)?;
    let directory = cache.join(&record.pdb_name).join(&record.symbol_key);
    let destination = directory.join(&record.pdb_name);
    if pdb_matches_record(&destination, record)? {
        return Ok(destination);
    }

    let url = format!(
        "https://msdl.microsoft.com/download/symbols/{}/{}/{}",
        record.pdb_name, record.symbol_key, record.pdb_name
    );
    let response = reqwest::blocking::Client::builder()
        .user_agent(concat!("starmem/", env!("CARGO_PKG_VERSION")))
        .build()?
        .get(&url)
        .send()
        .with_context(|| format!("符号下载失败：{url}"))?;
    ensure!(
        response.status().is_success(),
        "符号服务器为 {url} 返回状态 {}",
        response.status()
    );
    if let Some(length) = response.content_length() {
        ensure!(
            length <= MAX_PDB_DOWNLOAD_BYTES,
            "符号服务器声明的 PDB 长度 {length} 超过 {} 字节安全上限",
            MAX_PDB_DOWNLOAD_BYTES
        );
    }
    let mut policy = OutputPolicy::new(true);
    for (role, path) in protected_inputs {
        policy.protect_file(*role, *path);
    }
    policy.output(OutputTarget::file("pdb_cache", &destination));
    policy.preflight()?;
    let mut response = response.take(MAX_PDB_DOWNLOAD_BYTES + 1);
    policy.write_file_atomic_validated(
        &destination,
        |output| {
            let copied = copy(&mut response, output)?;
            ensure!(
                copied <= MAX_PDB_DOWNLOAD_BYTES,
                "下载的 PDB 超过 {} 字节安全上限",
                MAX_PDB_DOWNLOAD_BYTES
            );
            Ok(())
        },
        |staged| {
            ensure!(
                pdb_matches_record(staged, record)?,
                "下载的 PDB 标识与 {} 不一致",
                record.symbol_key
            );
            Ok(())
        },
    )?;
    Ok(destination)
}

pub fn resolve_kernel_pdb(image: &MemoryImage, cache: &Path) -> Result<ResolvedPdb> {
    resolve_kernel_pdb_with_store(image, &SymbolStore::new(cache.to_path_buf()))
}

pub fn resolve_kernel_pdb_with_store(
    image: &MemoryImage,
    store: &SymbolStore,
) -> Result<ResolvedPdb> {
    resolve_kernel_pdb_with_store_policy(image, store, true)
}

/// Resolve the same exact kernel identity while honoring the host's offline policy.
/// Offline operation still validates a local PDB against the image's CodeView record.
pub fn resolve_kernel_pdb_with_store_policy(
    image: &MemoryImage,
    store: &SymbolStore,
    allow_download: bool,
) -> Result<ResolvedPdb> {
    let cached = cached_kernel_codeview(image, store);
    let discovered = cached.is_none();
    let record = match cached {
        Some(record) => record,
        None => {
            let mut matches = Vec::new();
            for name in KERNEL_PDB_NAMES {
                matches.extend(discover_codeview(image, name)?);
                if !matches.is_empty() {
                    break;
                }
            }
            select_unique_record(&matches)?.clone()
        }
    };
    let path = resolve_kernel_record(image, store, &record, allow_download)?;
    if discovered {
        persist_kernel_codeview_cache(image, store, &record);
    }
    Ok(ResolvedPdb { record, path })
}

const KERNEL_PDB_NAMES: &[&str] = &[
    "ntkrnlmp.pdb",
    "ntkrnlpa.pdb",
    "ntoskrnl.pdb",
    "ntkrpamp.pdb",
];

/// Revalidated per-image cache of the kernel identity confirmed by an earlier bootstrap.
pub fn cached_kernel_codeview(image: &MemoryImage, store: &SymbolStore) -> Option<CodeViewRecord> {
    KERNEL_PDB_NAMES
        .iter()
        .find_map(|name| load_cached_kernel_codeview(image, store, name))
}

/// Every distinct kernel CodeView identity found in physical memory, across all kernel PDB
/// names. Physical RSDS hits may come from cached kernel files of other builds or
/// architectures, so callers must confirm a candidate against the running kernel.
pub fn discover_kernel_codeviews(image: &MemoryImage) -> Result<Vec<CodeViewRecord>> {
    discover_kernel_codeviews_cancellable(image, &CancellationToken::new())
}

pub fn discover_kernel_codeviews_cancellable(
    image: &MemoryImage,
    cancellation: &CancellationToken,
) -> Result<Vec<CodeViewRecord>> {
    // One physical pass retains every kernel identity for the bootstrap verifier.
    discover_codeviews(image, KERNEL_PDB_NAMES, cancellation)
}

pub fn resolve_kernel_record(
    image: &MemoryImage,
    store: &SymbolStore,
    record: &CodeViewRecord,
    allow_download: bool,
) -> Result<PathBuf> {
    if allow_download {
        let protected = image
            .sources()
            .map(|source| ("memory_image_or_sidecar", source.path.as_path()))
            .collect::<Vec<_>>();
        store.resolve_protecting(record, &protected)
    } else {
        store.find(record)?.with_context(|| {
            format!(
                "离线模式缺少匹配的本地 PDB：{} / {}",
                record.pdb_name, record.symbol_key
            )
        })
    }
}

/// Publish a kernel identity only after it bootstrapped the running kernel.
pub fn remember_kernel_codeview(image: &MemoryImage, store: &SymbolStore, record: &CodeViewRecord) {
    persist_kernel_codeview_cache(image, store, record);
}

fn load_cached_kernel_codeview(
    image: &MemoryImage,
    store: &SymbolStore,
    pdb_name: &str,
) -> Option<CodeViewRecord> {
    if image.is_live() {
        return None;
    }
    let (cache_path, source_file_len, modified_unix_nanos) =
        kernel_codeview_cache_locator(image, store)?;
    let bytes = fs::read(cache_path).ok()?;
    let cached: CachedKernelCodeView = serde_json::from_slice(&bytes).ok()?;
    if cached.schema != CODEVIEW_CACHE_SCHEMA
        || cached.source_file_len != source_file_len
        || cached.image_logical_len != image.logical_len()
        || cached.modified_unix_nanos != modified_unix_nanos
        || !cached.record.pdb_name.eq_ignore_ascii_case(pdb_name)
        || !cached_codeview_matches_image(image, &cached.record)
    {
        return None;
    }
    Some(cached.record)
}

fn persist_kernel_codeview_cache(
    image: &MemoryImage,
    store: &SymbolStore,
    record: &CodeViewRecord,
) {
    if image.is_live() {
        return;
    }
    let Some((cache_path, source_file_len, modified_unix_nanos)) =
        kernel_codeview_cache_locator(image, store)
    else {
        return;
    };
    let cached = CachedKernelCodeView {
        schema: CODEVIEW_CACHE_SCHEMA,
        source_file_len,
        image_logical_len: image.logical_len(),
        modified_unix_nanos,
        record: record.clone(),
    };
    let Ok(bytes) = serde_json::to_vec(&cached) else {
        return;
    };
    let mut policy = OutputPolicy::new(true);
    for source in image.sources() {
        policy.protect_file("memory_image_or_sidecar", &source.path);
    }
    policy.output(OutputTarget::file("codeview_cache", &cache_path));
    // This is only a performance cache. Publication failures are deliberately ignored, while
    // successful writes are synchronized and every later cache hit is revalidated against the
    // image bytes.
    let _ = policy.write_bytes_atomic(&cache_path, &bytes);
}

fn validate_symbol_record_path(record: &CodeViewRecord) -> Result<()> {
    ensure!(
        !record.pdb_name.is_empty()
            && record.pdb_name != "."
            && record.pdb_name != ".."
            && !record.pdb_name.contains(['/', '\\', ':'])
            && !record.pdb_name.chars().any(char::is_control),
        "PDB 名称不是安全的单一路径组件"
    );
    ensure!(
        !record.symbol_key.is_empty()
            && record.symbol_key.len() <= 128
            && record
                .symbol_key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "PDB symbol key 不是有界的十六进制路径组件"
    );
    Ok(())
}

fn kernel_codeview_cache_locator(
    image: &MemoryImage,
    store: &SymbolStore,
) -> Option<(PathBuf, u64, u128)> {
    let metadata = fs::metadata(image.path()).ok()?;
    let modified_unix_nanos = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let canonical = fs::canonicalize(image.path()).unwrap_or_else(|_| image.path().to_path_buf());
    #[cfg(windows)]
    let path_text = canonical.to_string_lossy().to_ascii_lowercase();
    #[cfg(not(windows))]
    let path_text = canonical.to_string_lossy();
    let path_hash = hex::encode(Sha256::digest(path_text.as_bytes()));
    let cache_path = store
        .writable_root()
        .join(".starmem-cache")
        .join("codeview-v1")
        .join(format!("{path_hash}.json"));
    Some((cache_path, metadata.len(), modified_unix_nanos))
}

fn cached_codeview_matches_image(image: &MemoryImage, expected: &CodeViewRecord) -> bool {
    let address = expected.physical_address;
    let Some(span) = image
        .spans()
        .iter()
        .find(|span| address >= span.start && address < span.end())
    else {
        return false;
    };
    let available = span.end().saturating_sub(address);
    let read_len = usize::try_from(available.min(MAX_CACHED_CODEVIEW_BYTES as u64)).unwrap_or(0);
    if read_len < 25 {
        return false;
    }
    let mut bytes = vec![0u8; read_len];
    if image.read_physical(address, &mut bytes).is_err() {
        return false;
    }
    parse_codeview_record(&bytes, address).is_some_and(|actual| actual == *expected)
}

fn parse_codeview_record(bytes: &[u8], physical_address: u64) -> Option<CodeViewRecord> {
    if bytes.get(..4)? != b"RSDS" || bytes.len() < 25 {
        return None;
    }
    let path_end = bytes[24..].iter().position(|byte| *byte == 0)? + 24;
    let path_bytes = &bytes[24..path_end];
    if path_bytes.is_empty()
        || !path_bytes.is_ascii()
        || path_bytes.iter().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    let embedded_path = String::from_utf8_lossy(path_bytes).into_owned();
    let pdb_name = embedded_path.rsplit(['\\', '/']).next()?.to_owned();
    let guid_bytes: [u8; 16] = bytes[4..20].try_into().ok()?;
    let age = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
    let guid = format_guid(guid_bytes);
    let symbol_key = format!("{}{:X}", guid.replace('-', ""), age);
    Some(CodeViewRecord {
        pdb_name,
        embedded_path,
        guid,
        age,
        symbol_key,
        physical_address,
    })
}

pub fn inspect_pdb(path: &Path, query: &str, limit: usize) -> Result<PdbSummary> {
    ensure!(limit > 0, "符号结果上限必须大于零");
    let file = File::open(path).with_context(|| format!("无法打开 PDB {}", path.display()))?;
    let mut pdb = pdb::PDB::open(file)?;
    let (guid, age) = {
        let info = pdb.pdb_information()?;
        (info.guid.to_string().to_uppercase(), info.age)
    };
    let address_map = pdb.address_map()?;
    let symbols = pdb.global_symbols()?;
    let mut iterator = symbols.iter();
    let query_lower = query.to_ascii_lowercase();
    let mut matches = Vec::new();
    while let Some(symbol) = iterator.next()? {
        let parsed = match symbol.parse() {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        let (name, kind, offset) = match parsed {
            pdb::SymbolData::Public(data) => (data.name, "公共符号", data.offset),
            pdb::SymbolData::Data(data) => (data.name, "数据", data.offset),
            pdb::SymbolData::Procedure(data) => (data.name, "过程", data.offset),
            _ => continue,
        };
        let name = name.to_string().into_owned();
        if !name.to_ascii_lowercase().contains(&query_lower) {
            continue;
        }
        matches.push(SymbolMatch {
            name,
            kind: kind.to_owned(),
            rva: offset.to_rva(&address_map).map(|rva| rva.0),
            section: offset.section,
            section_offset: offset.offset,
        });
        if matches.len() == limit {
            break;
        }
    }
    Ok(PdbSummary { guid, age, matches })
}

fn valid_pdb_file(path: &Path) -> Result<bool> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let mut magic = [0u8; 32];
    let read = file.read(&mut magic)?;
    Ok(read >= 24 && magic.starts_with(b"Microsoft C/C++ MSF"))
}

fn pdb_matches_record(path: &Path, record: &CodeViewRecord) -> Result<bool> {
    if !valid_pdb_file(path)? {
        return Ok(false);
    }
    let file = File::open(path)?;
    let mut pdb = match pdb::PDB::open(file) {
        Ok(pdb) => pdb,
        Err(_) => return Ok(false),
    };
    let info = match pdb.pdb_information() {
        Ok(info) => info,
        Err(_) => return Ok(false),
    };
    let guid = info.guid.to_string().to_uppercase();
    Ok(guid == record.guid && info.age >= record.age)
}

fn symbol_file_path(root: &Path, record: &CodeViewRecord) -> PathBuf {
    root.join(&record.pdb_name)
        .join(&record.symbol_key)
        .join(&record.pdb_name)
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn format_guid(bytes: [u8; 16]) -> String {
    let data1 = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let data2 = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    let data3 = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
    format!(
        "{data1:08X}-{data2:04X}-{data3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .context("结构被截断")?
        .try_into()?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .context("结构被截断")?
        .try_into()?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .context("结构被截断")?
        .try_into()?;
    Ok(u64::from_le_bytes(raw))
}

pub fn select_unique_record(records: &[CodeViewRecord]) -> Result<&CodeViewRecord> {
    match records {
        [] => bail!("物理内存中没有找到匹配的 RSDS CodeView 记录"),
        [record] => Ok(record),
        _ => bail!(
            "发现 {} 个不同的 PDB 标识；请使用 `symbols id` 检查",
            records.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_record() -> CodeViewRecord {
        CodeViewRecord {
            pdb_name: "ntkrnlmp.pdb".to_owned(),
            embedded_path: r"C:\symbols\ntkrnlmp.pdb".to_owned(),
            guid: "12345678-9ABC-DEF0-0102-030405060708".to_owned(),
            age: 1,
            symbol_key: "123456789ABCDEF001020304050607081".to_owned(),
            physical_address: 0,
        }
    }

    #[test]
    fn offline_kernel_resolution_reports_exact_missing_pdb_without_downloading() {
        let directory = std::env::temp_dir().join(format!(
            "starmem-offline-pdb-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).expect("test directory");
        let image_path = directory.join("kernel.raw");
        let mut bytes = vec![0u8; 8192];
        let offset = 0x400;
        bytes[offset..offset + 4].copy_from_slice(b"RSDS");
        bytes[offset + 4..offset + 20].copy_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8,
        ]);
        bytes[offset + 20..offset + 24].copy_from_slice(&10u32.to_le_bytes());
        bytes[offset + 24..offset + 36].copy_from_slice(b"ntkrnlmp.pdb");
        fs::write(&image_path, bytes).expect("fixture");
        let image = MemoryImage::open(&image_path).expect("memory image");
        let cache = directory.join("symbols");
        let error =
            resolve_kernel_pdb_with_store_policy(&image, &SymbolStore::new(cache.clone()), false)
                .expect_err("offline missing PDB must fail");
        let message = format!("{error:#}");
        drop(image);
        fs::remove_file(&image_path).expect("remove fixture");
        assert!(message.contains("离线模式缺少匹配的本地 PDB"), "{message}");
        assert!(
            message.contains("123456789ABCDEF00102030405060708A"),
            "{message}"
        );
        assert!(
            !cache.exists(),
            "offline lookup must not download or publish a PDB"
        );
        fs::remove_dir(directory).expect("remove empty fixture directory");
    }

    #[test]
    fn kernel_candidates_keep_identities_from_every_kernel_pdb_name() {
        // A cached x64 ntoskrnl.pdb file must not hide the running x86 ntkrpamp.pdb kernel.
        let directory = std::env::temp_dir().join(format!(
            "starmem-kernel-candidates-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).expect("test directory");
        let image_path = directory.join("kernel.raw");
        let mut bytes = vec![0u8; 0x3000];
        for (offset, name, age) in [
            (0x400, &b"ntoskrnl.pdb"[..], 1u32),
            (0x2400, &b"ntkrpamp.pdb"[..], 2),
        ] {
            bytes[offset..offset + 4].copy_from_slice(b"RSDS");
            bytes[offset + 4..offset + 20].copy_from_slice(&[age as u8; 16]);
            bytes[offset + 20..offset + 24].copy_from_slice(&age.to_le_bytes());
            bytes[offset + 24..offset + 24 + name.len()].copy_from_slice(name);
        }
        fs::write(&image_path, bytes).expect("fixture");
        let image = MemoryImage::open(&image_path).expect("memory image");
        let names = discover_kernel_codeviews(&image)
            .expect("candidate discovery")
            .into_iter()
            .map(|record| (record.pdb_name, record.age, record.physical_address))
            .collect::<Vec<_>>();
        drop(image);
        fs::remove_file(&image_path).expect("remove fixture");
        fs::remove_dir(&directory).expect("remove fixture directory");
        assert_eq!(
            names,
            [
                ("ntoskrnl.pdb".to_owned(), 1, 0x400),
                ("ntkrpamp.pdb".to_owned(), 2, 0x2400)
            ]
        );
    }

    #[test]
    fn kernel_candidate_scan_respects_cancellation_before_reading() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cancel.raw");
        fs::write(&path, vec![0u8; 4096]).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let handle = crate::cancellation::CancellationHandle::new();
        handle.cancel();
        let error = discover_kernel_codeviews_cancellable(&image, &handle.token()).unwrap_err();
        assert!(crate::cancellation::is_cancellation_error(&error));
    }

    #[test]
    fn codeview_guid_uses_windows_endianness() {
        let bytes = [
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        assert_eq!(format_guid(bytes), "12345678-9ABC-DEF0-0102-030405060708");
    }

    #[test]
    fn cached_codeview_parser_preserves_exact_identity() {
        let mut bytes = Vec::from(&b"RSDS"[..]);
        bytes.extend_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8,
        ]);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(br"C:\symbols\ntkrnlmp.pdb");
        bytes.push(0);

        let parsed = parse_codeview_record(&bytes, 0x1234).expect("valid CodeView record");
        let mut expected = test_record();
        expected.physical_address = 0x1234;
        assert_eq!(parsed, expected);

        bytes[20..24].copy_from_slice(&2u32.to_le_bytes());
        assert_ne!(
            parse_codeview_record(&bytes, 0x1234).expect("valid changed record"),
            expected
        );
    }

    #[test]
    fn cached_codeview_parser_rejects_unterminated_path() {
        let mut bytes = Vec::from(&b"RSDS"[..]);
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(b"ntkrnlmp.pdb");
        assert!(parse_codeview_record(&bytes, 0x1000).is_none());
    }

    #[test]
    fn symbol_store_uses_microsoft_cache_layout() {
        let record = test_record();
        assert_eq!(
            symbol_file_path(Path::new("symbols"), &record),
            Path::new("symbols")
                .join("ntkrnlmp.pdb")
                .join("123456789ABCDEF001020304050607081")
                .join("ntkrnlmp.pdb")
        );
    }

    #[test]
    fn symbol_store_preserves_shared_root_priority() {
        let writable = PathBuf::from("starmem-cache");
        let mut store = SymbolStore::new(writable.clone());
        store.add_search_root(PathBuf::from("shared-symbols"));
        store.add_search_root(PathBuf::from("secondary-symbols"));
        store.add_search_root(PathBuf::from("shared-symbols"));
        store.add_search_root(writable);

        assert_eq!(
            store.search_roots(),
            &[
                PathBuf::from("shared-symbols"),
                PathBuf::from("secondary-symbols")
            ]
        );
    }

    #[test]
    fn symbol_cache_rejects_path_components_from_untrusted_codeview() {
        for pdb_name in ["..", ".", "../kernel.pdb", r"..\kernel.pdb", "C:kernel.pdb"] {
            let mut record = test_record();
            record.pdb_name = pdb_name.to_owned();
            assert!(validate_symbol_record_path(&record).is_err(), "{pdb_name}");
        }

        let mut record = test_record();
        record.symbol_key = "../../escape".to_owned();
        assert!(validate_symbol_record_path(&record).is_err());
    }
}
