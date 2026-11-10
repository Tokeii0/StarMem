use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail, ensure};
use ewf::EwfReader;
use memmap2::{Mmap, MmapOptions};
use serde::Serialize;

use crate::image_avml;
use crate::image_qevm::{self, QevmMappingSource};
use crate::image_xen::{self, XenElf64Summary};
use crate::scan::ScanEngine;

#[path = "image_codec.rs"]
mod codec;
#[path = "image_elf.rs"]
mod elf;
#[path = "image_vmware.rs"]
mod vmware;

const LIME_MAGIC: u32 = 0x4c69_4d45;
const LIME_HEADER_SIZE: u64 = 32;
const DUMP_HEADER64_SIZE: u64 = 0x2000;
const DEFAULT_DECODE_CACHE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SNAPPY_MAPPING_DECODE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SNAPPY_MAPPING_ENCODED_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ImageOpenOptions {
    /// Explicit VMware VMSS/VMSN metadata. Explicit metadata always wins over discovery.
    pub metadata_path: Option<PathBuf>,
    /// Discover one same-stem `.vmss` or `.vmsn`. Two candidates are an error.
    pub auto_discover_sidecars: bool,
    /// Maximum retained decoded Snappy bytes. Oversized individual mappings are decoded but
    /// are not retained; every individual mapping also has a fixed 256 MiB safety ceiling.
    pub decode_cache_bytes: usize,
    /// Explicit machine mapping for a QEVM RAMBlock. Migration offsets are not guest physical
    /// addresses, so QEVM input is rejected unless this layout is supplied.
    pub qevm_layout: Option<QevmPhysicalLayout>,
}

impl Default for ImageOpenOptions {
    fn default() -> Self {
        Self {
            metadata_path: None,
            auto_discover_sidecars: true,
            decode_cache_bytes: DEFAULT_DECODE_CACHE_BYTES,
            qevm_layout: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QevmPhysicalLayout {
    /// RAMBlock whose offsets represent guest system RAM (commonly `pc.ram`).
    pub ram_block: String,
    /// Number of RAMBlock bytes placed starting at guest physical address zero.
    pub below_4g_length: u64,
    /// Guest physical base for bytes following `below_4g_length`.
    pub above_4g_physical_base: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MappingEncoding {
    #[default]
    Direct,
    SnappyFrame {
        encoded_length: u64,
    },
    RepeatedByte {
        value: u8,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct PhysicalSpan {
    pub start: u64,
    pub length: u64,
    /// Source-relative offset. It is an exact byte offset only for a Direct mapping backed by
    /// an ordinary file; use [`MemoryImage::source_location`] for unambiguous provenance.
    pub file_offset: u64,
    #[serde(default)]
    pub source_index: usize,
    #[serde(default)]
    pub encoding: MappingEncoding,
}

impl PhysicalSpan {
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.length)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceLocation {
    pub source_index: usize,
    pub mapping_container_offset: u64,
    pub decoded_offset: u64,
    /// Exact source-file byte offset. `None` for decoded, synthetic, and EWF logical sources.
    pub exact_byte_offset: Option<u64>,
    pub encoding: MappingEncoding,
}

impl SourceLocation {
    /// Compatibility value for reports whose old schema requires a numeric file offset.
    /// Consumers which need exact provenance must use `exact_byte_offset` instead.
    pub fn legacy_offset(&self) -> u64 {
        self.exact_byte_offset.unwrap_or_else(|| {
            self.mapping_container_offset
                .saturating_add(self.decoded_offset)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSourceRole {
    Primary,
    Metadata,
    Sidecar,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageSourceInfo {
    pub index: usize,
    pub path: PathBuf,
    pub role: ImageSourceRole,
    pub container_len: u64,
    pub logical_len: u64,
    pub exact_byte_offsets: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhysicalMissingRange {
    pub start: u64,
    pub length: u64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImageFormat {
    Raw,
    VmwareVmem {
        pci_hole_start: u64,
        pci_hole_size: u64,
        metadata: Option<VmwareMetadataSummary>,
    },
    ElfPhysicalCore {
        machine: u16,
        program_headers: u16,
        producer: ElfCoreProducer,
    },
    XenElf64(XenElf64Summary),
    AvmlV2 {
        version: u32,
        record_count: usize,
        mapped_bytes: u64,
        /// AVML records are checksum-verified when the common lazy decoder first reads them.
        checksum_validation: &'static str,
    },
    QevmV3 {
        file_version: u32,
        ram_version: u32,
        page_size: u64,
        machine_name: Option<String>,
        ram_block: String,
        ram_block_length: u64,
        below_4g_length: u64,
        above_4g_physical_base: u64,
        pci_hole_start: u64,
        pci_hole_size: u64,
        mapping_count: usize,
        ignored_ram_blocks: Vec<String>,
        overwritten_pages: u64,
    },
    Lime {
        version: u32,
    },
    WindowsCrashDump64(WindowsDump64),
    ExpertWitness {
        logical_size: u64,
        chunk_size: u64,
        media: ExpertWitnessMedia,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElfCoreProducer {
    Qemu,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VmwareMetadataSummary {
    pub version: u8,
    pub region_count: usize,
    pub source_index: usize,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpertWitnessMedia {
    PhysicalMemory,
    DiskOrVolume,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowsDump64 {
    pub major_version: u32,
    pub minor_version: u32,
    pub directory_table_base: u64,
    pub pfn_database: u64,
    pub ps_loaded_module_list: u64,
    pub ps_active_process_head: u64,
    pub machine_type: u32,
    pub number_processors: u32,
    pub bug_check_code: u32,
    pub bug_check_parameters: [u64; 4],
    pub kd_debugger_data_block: u64,
    pub number_of_runs: u32,
    pub number_of_pages: u64,
    pub dump_type: u32,
    pub required_dump_space: u64,
    pub system_time_raw: u64,
    pub comment: String,
    pub system_uptime_100ns: u64,
    pub mini_dump_fields: u32,
    pub secondary_data_state: u32,
    pub product_type: u32,
    pub suite_mask: u32,
    pub writer_status: u32,
}

#[derive(Clone)]
pub struct MemoryImage {
    path: PathBuf,
    sources: Arc<[ImageSource]>,
    container_len: u64,
    logical_len: u64,
    format: ImageFormat,
    spans: Arc<[PhysicalSpan]>,
    missing_ranges: Arc<[PhysicalMissingRange]>,
    decode_cache: Arc<Mutex<DecodeCache>>,
    scan_engine: ScanEngine,
}

#[derive(Clone)]
enum ImageBacking {
    Mmap(Arc<Mmap>),
    Ewf(Arc<EwfReader>),
}

#[derive(Clone)]
struct ImageSource {
    info: ImageSourceInfo,
    backing: ImageBacking,
}

struct DecodeCacheEntry {
    bytes: Arc<[u8]>,
    last_used: u64,
}

struct DecodeCache {
    budget: usize,
    retained: usize,
    clock: u64,
    entries: HashMap<usize, DecodeCacheEntry>,
}

impl DecodeCache {
    fn new(budget: usize) -> Self {
        Self {
            budget,
            retained: 0,
            clock: 0,
            entries: HashMap::new(),
        }
    }
}

impl MemoryImage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_options(path, ImageOpenOptions::default())
    }

    pub fn open_with_options(path: impl AsRef<Path>, options: ImageOpenOptions) -> Result<Self> {
        let path = path.as_ref();
        let file =
            File::open(path).with_context(|| format!("无法打开内存镜像 {}", path.display()))?;
        let file_len = file.metadata()?.len();
        ensure!(file_len >= 8, "镜像文件过小");

        // SAFETY: the mapping is read-only and the file handle remains represented by the map.
        // Forensic inputs are never modified by StarMem while a mapping exists.
        let mmap = unsafe { MmapOptions::new().map(&file) }
            .with_context(|| format!("无法建立文件内存映射 {}", path.display()))?;
        if mmap.starts_with(b"EVF\x09\x0d\x0a\xff\0") {
            let reader = EwfReader::open(path)
                .with_context(|| format!("无法解析 EWF 镜像 {}", path.display()))?;
            let logical_len = reader.total_size();
            ensure!(logical_len >= 512, "EWF 逻辑镜像过小");
            let mut probe = vec![0u8; 4096.min(logical_len as usize)];
            let read = reader
                .read_at(&mut probe, 0)
                .context("无法读取 EWF 逻辑介质头")?;
            ensure!(read == probe.len(), "EWF 逻辑介质头读取不完整");
            let media = if looks_like_disk_or_volume(&probe) {
                ExpertWitnessMedia::DiskOrVolume
            } else {
                ExpertWitnessMedia::PhysicalMemory
            };
            let spans = match media {
                ExpertWitnessMedia::PhysicalMemory => vec![PhysicalSpan {
                    start: 0,
                    length: logical_len,
                    file_offset: 0,
                    source_index: 0,
                    encoding: MappingEncoding::Direct,
                }],
                ExpertWitnessMedia::DiskOrVolume => Vec::new(),
            };
            let chunk_size = reader.chunk_size();
            return Self::from_parts(
                path.to_path_buf(),
                vec![ImageSource {
                    info: ImageSourceInfo {
                        index: 0,
                        path: path.to_path_buf(),
                        role: ImageSourceRole::Primary,
                        container_len: file_len,
                        logical_len,
                        exact_byte_offsets: false,
                    },
                    backing: ImageBacking::Ewf(Arc::new(reader)),
                }],
                file_len,
                logical_len,
                ImageFormat::ExpertWitness {
                    logical_size: logical_len,
                    chunk_size,
                    media,
                },
                spans,
                Vec::new(),
                options.decode_cache_bytes,
            );
        }

        let primary_mmap = Arc::new(mmap);
        let mut sources = vec![ImageSource {
            info: ImageSourceInfo {
                index: 0,
                path: path.to_path_buf(),
                role: ImageSourceRole::Primary,
                container_len: file_len,
                logical_len: file_len,
                exact_byte_offsets: true,
            },
            backing: ImageBacking::Mmap(Arc::clone(&primary_mmap)),
        }];

        let metadata_path = resolve_vmware_metadata(path, &options)?;
        let detected = if let Some(metadata_path) = metadata_path {
            ensure!(
                path.extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("vmem")),
                "VMware --metadata 只能与 VMEM 主文件配合使用"
            );
            ensure!(
                !matches!(same_file::is_same_file(path, &metadata_path), Ok(true)),
                "VMware metadata 不能与 VMEM 主文件相同"
            );
            let metadata_source =
                open_mmap_source(&metadata_path, sources.len(), ImageSourceRole::Metadata)?;
            let metadata_bytes = match &metadata_source.backing {
                ImageBacking::Mmap(bytes) => bytes.as_ref(),
                ImageBacking::Ewf(_) => unreachable!(),
            };
            let parsed = vmware::parse_vmware_metadata(metadata_bytes, file_len)
                .with_context(|| format!("无法解析 VMware metadata {}", metadata_path.display()))?;
            let source_index = metadata_source.info.index;
            sources.push(metadata_source);
            let spans = parsed
                .regions
                .iter()
                .map(|region| PhysicalSpan {
                    start: region.physical_start,
                    length: region.length,
                    file_offset: region.file_offset,
                    source_index: 0,
                    encoding: MappingEncoding::Direct,
                })
                .collect::<Vec<_>>();
            let (pci_hole_start, pci_hole_size) = inferred_largest_gap(&spans);
            DetectedMapping {
                format: ImageFormat::VmwareVmem {
                    pci_hole_start,
                    pci_hole_size,
                    metadata: Some(VmwareMetadataSummary {
                        version: parsed.version,
                        region_count: spans.len(),
                        source_index,
                    }),
                },
                spans,
                missing_ranges: Vec::new(),
            }
        } else {
            detect_and_map_full(path, &primary_mmap, file_len, &options)?
        };

        Self::from_parts(
            path.to_path_buf(),
            sources,
            file_len,
            file_len,
            detected.format,
            detected.spans,
            detected.missing_ranges,
            options.decode_cache_bytes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        path: PathBuf,
        sources: Vec<ImageSource>,
        container_len: u64,
        logical_len: u64,
        format: ImageFormat,
        mut spans: Vec<PhysicalSpan>,
        mut missing_ranges: Vec<PhysicalMissingRange>,
        decode_cache_bytes: usize,
    ) -> Result<Self> {
        ensure!(!sources.is_empty(), "内存镜像至少需要一个 source");
        for (index, source) in sources.iter().enumerate() {
            ensure!(
                source.info.index == index,
                "source identity index 不连续：期望 {index}，实际 {}",
                source.info.index
            );
        }
        spans.sort_unstable_by_key(|span| span.start);
        validate_mappings(&sources, &spans)?;
        missing_ranges.sort_unstable_by_key(|range| range.start);
        validate_missing_ranges(&spans, &missing_ranges)?;
        Ok(Self {
            path,
            sources: sources.into(),
            container_len,
            logical_len,
            format,
            spans: spans.into(),
            missing_ranges: missing_ranges.into(),
            decode_cache: Arc::new(Mutex::new(DecodeCache::new(decode_cache_bytes))),
            scan_engine: ScanEngine::new(),
        })
    }

    pub fn scan_engine(&self) -> &ScanEngine {
        &self.scan_engine
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file_len(&self) -> u64 {
        self.container_len
    }

    pub fn logical_len(&self) -> u64 {
        self.logical_len
    }

    pub fn format(&self) -> &ImageFormat {
        &self.format
    }

    pub fn spans(&self) -> &[PhysicalSpan] {
        &self.spans
    }

    pub fn sources(&self) -> impl ExactSizeIterator<Item = &ImageSourceInfo> {
        self.sources.iter().map(|source| &source.info)
    }

    pub fn missing_ranges(&self) -> &[PhysicalMissingRange] {
        &self.missing_ranges
    }

    pub fn mapped_bytes(&self) -> u64 {
        self.spans.iter().map(|span| span.length).sum()
    }

    pub fn direct_bytes(&self) -> Option<&[u8]> {
        let directly_primary = self
            .spans
            .iter()
            .all(|span| span.source_index == 0 && matches!(span.encoding, MappingEncoding::Direct));
        if !directly_primary {
            return None;
        }
        match &self.sources.first()?.backing {
            ImageBacking::Mmap(mmap) => Some(mmap.as_ref()),
            ImageBacking::Ewf(_) => None,
        }
    }

    pub fn read_backing(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        self.read_source(0, offset, out)
    }

    pub fn read_source(&self, source_index: usize, offset: u64, out: &mut [u8]) -> Result<()> {
        let source = self
            .sources
            .get(source_index)
            .with_context(|| format!("source index {source_index} 不存在"))?;
        let end = offset
            .checked_add(out.len() as u64)
            .context("source 读取范围溢出")?;
        ensure!(
            end <= source.info.logical_len,
            "读取范围超出 source 逻辑末尾"
        );
        match &source.backing {
            ImageBacking::Mmap(mmap) => {
                let start = usize::try_from(offset)?;
                let end = start.checked_add(out.len()).context("文件偏移计算溢出")?;
                out.copy_from_slice(mmap.get(start..end).context("source 后备存储被截断")?);
            }
            ImageBacking::Ewf(reader) => {
                let read = reader
                    .read_at(out, offset)
                    .with_context(|| format!("无法读取 EWF 逻辑偏移 {offset:#x}"))?;
                ensure!(read == out.len(), "EWF 在逻辑偏移 {offset:#x} 处读取不完整");
            }
        }
        Ok(())
    }

    pub fn dump64(&self) -> Option<&WindowsDump64> {
        match &self.format {
            ImageFormat::WindowsCrashDump64(dump) => Some(dump),
            _ => None,
        }
    }

    pub fn physical_to_file_offset(&self, address: u64) -> Option<u64> {
        self.source_location(address)?.exact_byte_offset
    }

    pub fn file_offset_to_physical(&self, offset: u64) -> Option<u64> {
        self.source_offset_to_physical(0, offset)
    }

    pub fn source_offset_to_physical(&self, source_index: usize, offset: u64) -> Option<u64> {
        self.spans.iter().find_map(|span| {
            let direct = matches!(span.encoding, MappingEncoding::Direct)
                && self
                    .sources
                    .get(span.source_index)
                    .is_some_and(|source| source.info.exact_byte_offsets);
            (direct
                && span.source_index == source_index
                && offset >= span.file_offset
                && offset < span.file_offset.saturating_add(span.length))
            .then(|| span.start + (offset - span.file_offset))
        })
    }

    pub fn contains_physical(&self, address: u64) -> bool {
        self.mapping_index(address).is_some()
    }

    pub fn source_location(&self, address: u64) -> Option<SourceLocation> {
        let index = self.mapping_index(address)?;
        let span = &self.spans[index];
        let decoded_offset = address - span.start;
        let exact_byte_offset = matches!(span.encoding, MappingEncoding::Direct)
            .then(|| {
                self.sources
                    .get(span.source_index)
                    .filter(|source| source.info.exact_byte_offsets)
                    .map(|_| span.file_offset + decoded_offset)
            })
            .flatten();
        Some(SourceLocation {
            source_index: span.source_index,
            mapping_container_offset: span.file_offset,
            decoded_offset,
            exact_byte_offset,
            encoding: span.encoding,
        })
    }

    pub fn read_physical(&self, mut address: u64, mut out: &mut [u8]) -> Result<()> {
        while !out.is_empty() {
            let Some(index) = self.mapping_index(address) else {
                bail!("镜像中不存在物理地址 {address:#x}");
            };
            let span = &self.spans[index];
            ensure!(
                address >= span.start && address < span.end(),
                "物理地址 {address:#x} 位于采集缺口中"
            );
            let available = (span.end() - address) as usize;
            let take = available.min(out.len());
            let decoded_offset = address - span.start;
            match span.encoding {
                MappingEncoding::Direct => self.read_source(
                    span.source_index,
                    span.file_offset + decoded_offset,
                    &mut out[..take],
                )?,
                MappingEncoding::RepeatedByte { value } => out[..take].fill(value),
                MappingEncoding::SnappyFrame { .. } => {
                    let decoded = self.decode_snappy_mapping(index, span)?;
                    let start = usize::try_from(decoded_offset)?;
                    let end = start.checked_add(take).context("Snappy slice 范围溢出")?;
                    out[..take].copy_from_slice(
                        decoded
                            .get(start..end)
                            .context("Snappy decoded mapping 被截断")?,
                    );
                }
            }
            address += take as u64;
            out = &mut out[take..];
        }
        Ok(())
    }

    pub fn read_u64_physical(&self, address: u64) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.read_physical(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn read_u32_physical(&self, address: u64) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.read_physical(address, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn mapping_index(&self, address: u64) -> Option<usize> {
        let index = self.spans.partition_point(|span| span.end() <= address);
        self.spans
            .get(index)
            .is_some_and(|span| address >= span.start && address < span.end())
            .then_some(index)
    }

    fn decode_snappy_mapping(
        &self,
        mapping_index: usize,
        span: &PhysicalSpan,
    ) -> Result<Arc<[u8]>> {
        // Keep cache misses serialized.  Otherwise a parallel scanner can make every
        // worker decode the same large frame concurrently before the first insertion,
        // defeating the process-wide decode-memory bound.
        let mut cache = self
            .decode_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Snappy decode cache 锁已损坏"))?;
        cache.clock = cache.clock.wrapping_add(1);
        let now = cache.clock;
        if let Some(entry) = cache.entries.get_mut(&mapping_index) {
            entry.last_used = now;
            return Ok(Arc::clone(&entry.bytes));
        }

        let MappingEncoding::SnappyFrame { encoded_length } = span.encoding else {
            bail!("mapping 不是 SnappyFrame")
        };
        ensure!(
            span.length <= MAX_SNAPPY_MAPPING_DECODE_BYTES,
            "单个 Snappy mapping 解码长度 {} 超出 {} 字节安全上限",
            span.length,
            MAX_SNAPPY_MAPPING_DECODE_BYTES
        );
        let mut encoded = vec![0u8; usize::try_from(encoded_length)?];
        self.read_source(span.source_index, span.file_offset, &mut encoded)?;
        let decoded: Arc<[u8]> = codec::decode_snappy_frame(
            &encoded,
            usize::try_from(span.length).context("Snappy decoded length 过大")?,
        )?
        .into();

        if decoded.len() <= cache.budget {
            while cache.retained.saturating_add(decoded.len()) > cache.budget {
                let Some(oldest) = cache
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_used)
                    .map(|(index, _)| *index)
                else {
                    break;
                };
                if let Some(removed) = cache.entries.remove(&oldest) {
                    cache.retained = cache.retained.saturating_sub(removed.bytes.len());
                }
            }
            cache.clock = cache.clock.wrapping_add(1);
            let now = cache.clock;
            cache.retained = cache.retained.saturating_add(decoded.len());
            cache.entries.insert(
                mapping_index,
                DecodeCacheEntry {
                    bytes: Arc::clone(&decoded),
                    last_used: now,
                },
            );
        }
        Ok(decoded)
    }
}

struct DetectedMapping {
    format: ImageFormat,
    spans: Vec<PhysicalSpan>,
    missing_ranges: Vec<PhysicalMissingRange>,
}

fn open_mmap_source(path: &Path, index: usize, role: ImageSourceRole) -> Result<ImageSource> {
    let file = File::open(path).with_context(|| format!("无法打开 source {}", path.display()))?;
    let length = file.metadata()?.len();
    ensure!(length > 0, "source {} 为空", path.display());
    // SAFETY: mappings are read-only and StarMem never modifies forensic sources.
    let mmap = unsafe { MmapOptions::new().map(&file) }
        .with_context(|| format!("无法映射 source {}", path.display()))?;
    Ok(ImageSource {
        info: ImageSourceInfo {
            index,
            path: path.to_path_buf(),
            role,
            container_len: length,
            logical_len: length,
            exact_byte_offsets: true,
        },
        backing: ImageBacking::Mmap(Arc::new(mmap)),
    })
}

fn resolve_vmware_metadata(path: &Path, options: &ImageOpenOptions) -> Result<Option<PathBuf>> {
    if let Some(metadata) = &options.metadata_path {
        ensure!(
            metadata
                .extension()
                .is_some_and(|extension| matches_ignore_ascii_case(extension, &["vmss", "vmsn"])),
            "显式 VMware metadata 必须是 .vmss 或 .vmsn"
        );
        ensure!(
            metadata
                .try_exists()
                .with_context(|| format!("无法检查 metadata {}", metadata.display()))?,
            "显式 VMware metadata 不存在：{}",
            metadata.display()
        );
        return Ok(Some(metadata.clone()));
    }
    if !options.auto_discover_sidecars
        || !path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("vmem"))
    {
        return Ok(None);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stem = path.file_stem().context("VMEM 文件名缺少 stem")?;
    let mut candidates = Vec::new();
    for entry in fs::read_dir(parent)
        .with_context(|| format!("无法枚举 VMware sidecar 目录 {}", parent.display()))?
    {
        let candidate = entry
            .with_context(|| format!("无法读取 VMware sidecar 目录项 {}", parent.display()))?
            .path();
        if candidate
            .file_stem()
            .is_some_and(|candidate_stem| candidate_stem.eq_ignore_ascii_case(stem))
            && candidate
                .extension()
                .is_some_and(|extension| matches_ignore_ascii_case(extension, &["vmss", "vmsn"]))
        {
            candidates.push(candidate);
        }
    }
    candidates.sort();
    candidates.dedup();
    ensure!(
        candidates.len() <= 1,
        "同 stem 同时存在 VMSS 与 VMSN；必须使用 --metadata 明确选择"
    );
    Ok(candidates.into_iter().next())
}

fn matches_ignore_ascii_case(extension: &std::ffi::OsStr, expected: &[&str]) -> bool {
    expected
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
}

fn validate_mappings(sources: &[ImageSource], spans: &[PhysicalSpan]) -> Result<()> {
    for (index, span) in spans.iter().enumerate() {
        ensure!(span.length > 0, "物理 mapping {index} 为空");
        span.start
            .checked_add(span.length)
            .context("物理 mapping 地址溢出")?;
        let source = sources
            .get(span.source_index)
            .with_context(|| format!("物理 mapping {index} 引用了不存在的 source"))?;
        match span.encoding {
            MappingEncoding::Direct => ensure!(
                span.file_offset
                    .checked_add(span.length)
                    .is_some_and(|end| end <= source.info.logical_len),
                "Direct mapping {index} 超出 source {}",
                source.info.path.display()
            ),
            MappingEncoding::SnappyFrame { encoded_length } => {
                ensure!(encoded_length > 0, "Snappy mapping {index} 编码长度为零");
                ensure!(
                    encoded_length <= MAX_SNAPPY_MAPPING_ENCODED_BYTES,
                    "Snappy mapping {index} 编码长度超出安全上限"
                );
                ensure!(
                    span.file_offset
                        .checked_add(encoded_length)
                        .is_some_and(|end| end <= source.info.logical_len),
                    "Snappy mapping {index} 超出 source {}",
                    source.info.path.display()
                );
                ensure!(
                    span.length <= MAX_SNAPPY_MAPPING_DECODE_BYTES,
                    "Snappy mapping {index} 解码长度超出安全上限"
                );
            }
            MappingEncoding::RepeatedByte { .. } => {}
        }
    }
    for pair in spans.windows(2) {
        ensure!(pair[0].end() <= pair[1].start, "物理 mappings 重叠");
    }
    Ok(())
}

fn validate_missing_ranges(spans: &[PhysicalSpan], ranges: &[PhysicalMissingRange]) -> Result<()> {
    for (index, range) in ranges.iter().enumerate() {
        ensure!(range.length > 0, "缺失物理范围 {index} 为空");
        ensure!(!range.source.is_empty(), "缺失物理范围 {index} 未声明来源");
        let end = range
            .start
            .checked_add(range.length)
            .context("缺失物理范围地址溢出")?;
        ensure!(end > range.start, "缺失物理范围 {index} 无效");
    }
    for pair in ranges.windows(2) {
        ensure!(
            pair[0].start + pair[0].length <= pair[1].start,
            "缺失物理范围重叠"
        );
    }
    for range in ranges {
        let end = range.start + range.length;
        let candidate = spans.partition_point(|span| span.end() <= range.start);
        if let Some(span) = spans.get(candidate) {
            ensure!(span.start >= end, "缺失物理范围与已采集 mapping 重叠");
        }
    }
    Ok(())
}

fn inferred_largest_gap(spans: &[PhysicalSpan]) -> (u64, u64) {
    spans
        .windows(2)
        .filter_map(|pair| {
            let start = pair[0].end();
            (pair[1].start > start).then_some((start, pair[1].start - start))
        })
        .max_by_key(|(_, length)| *length)
        .unwrap_or((0, 0))
}

type ResolvedQevmPhysicalLayout = (
    Vec<PhysicalSpan>,
    Vec<PhysicalMissingRange>,
    u64,
    Vec<String>,
);

fn resolve_qevm_physical_layout(
    parsed: &image_qevm::QevmParseResult,
    layout: &QevmPhysicalLayout,
) -> Result<ResolvedQevmPhysicalLayout> {
    ensure!(!layout.ram_block.is_empty(), "QEVM RAMBlock 名称不能为空");
    let block = parsed
        .ram_blocks
        .iter()
        .find(|block| block.name == layout.ram_block)
        .with_context(|| {
            format!(
                "QEVM 不包含 RAMBlock {:?}；可用：{}",
                layout.ram_block,
                parsed
                    .ram_blocks
                    .iter()
                    .map(|block| block.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    ensure!(
        layout.below_4g_length > 0 && layout.below_4g_length <= block.length,
        "QEVM below-4g length 必须位于 1..={} 字节",
        block.length
    );
    ensure!(
        layout.below_4g_length.is_multiple_of(parsed.page_size)
            && layout
                .above_4g_physical_base
                .is_multiple_of(parsed.page_size),
        "QEVM 物理布局边界必须按 target page size {:#x} 对齐",
        parsed.page_size
    );
    ensure!(
        layout.above_4g_physical_base >= layout.below_4g_length,
        "QEVM 高端 RAM 基址不能低于低端 RAM 末尾"
    );
    if block.length > layout.below_4g_length {
        ensure!(
            layout.above_4g_physical_base >= 0x1_0000_0000,
            "QEVM 存在高端 RAM 时 --qevm-above-4g-base 必须不小于 4 GiB"
        );
        layout
            .above_4g_physical_base
            .checked_add(block.length - layout.below_4g_length)
            .context("QEVM 高端 RAM 物理末地址溢出")?;
    }

    let mut selected = parsed
        .mappings
        .iter()
        .filter(|mapping| mapping.ram_block == layout.ram_block)
        .collect::<Vec<_>>();
    ensure!(
        !selected.is_empty(),
        "QEVM 选定 RAMBlock 不包含 PAGE/ZERO mappings"
    );
    selected.sort_unstable_by_key(|mapping| mapping.block_offset);
    let mut cursor = 0_u64;
    let mut spans = Vec::new();
    let mut missing_ranges = Vec::new();
    for mapping in selected {
        ensure!(
            mapping.block_offset >= cursor,
            "QEVM 选定 RAMBlock mappings 重叠或乱序"
        );
        if mapping.block_offset > cursor {
            push_qevm_missing_parts(
                &mut missing_ranges,
                cursor,
                mapping.block_offset - cursor,
                layout,
            )?;
        }
        for (physical_start, source_delta, length) in
            qevm_physical_parts(mapping.block_offset, mapping.length, layout)?
        {
            let (file_offset, encoding) = match &mapping.source {
                QevmMappingSource::Direct { file_offset } => (
                    file_offset
                        .checked_add(source_delta)
                        .context("QEVM PAGE source offset 溢出")?,
                    MappingEncoding::Direct,
                ),
                QevmMappingSource::RepeatedByte { value } => {
                    (0, MappingEncoding::RepeatedByte { value: *value })
                }
            };
            spans.push(PhysicalSpan {
                start: physical_start,
                length,
                file_offset,
                source_index: 0,
                encoding,
            });
        }
        cursor = mapping
            .block_offset
            .checked_add(mapping.length)
            .context("QEVM mapping 末地址溢出")?;
    }
    ensure!(cursor <= block.length, "QEVM mapping 超出 RAMBlock 末尾");
    if cursor < block.length {
        push_qevm_missing_parts(&mut missing_ranges, cursor, block.length - cursor, layout)?;
    }
    spans.sort_unstable_by_key(|span| span.start);
    missing_ranges.sort_unstable_by_key(|range| range.start);
    let ignored_ram_blocks = parsed
        .ram_blocks
        .iter()
        .filter(|candidate| candidate.name != layout.ram_block)
        .map(|candidate| candidate.name.clone())
        .collect();
    Ok((spans, missing_ranges, block.length, ignored_ram_blocks))
}

fn qevm_physical_parts(
    block_offset: u64,
    length: u64,
    layout: &QevmPhysicalLayout,
) -> Result<Vec<(u64, u64, u64)>> {
    ensure!(length > 0, "QEVM mapping 长度不能为零");
    let end = block_offset
        .checked_add(length)
        .context("QEVM RAMBlock range 溢出")?;
    let low_end = end.min(layout.below_4g_length);
    let mut parts = Vec::with_capacity(2);
    if block_offset < low_end {
        parts.push((block_offset, 0, low_end - block_offset));
    }
    if end > layout.below_4g_length {
        let high_offset = block_offset.max(layout.below_4g_length);
        let physical = layout
            .above_4g_physical_base
            .checked_add(high_offset - layout.below_4g_length)
            .context("QEVM 高端 RAM 地址溢出")?;
        parts.push((physical, high_offset - block_offset, end - high_offset));
    }
    Ok(parts)
}

fn push_qevm_missing_parts(
    output: &mut Vec<PhysicalMissingRange>,
    block_offset: u64,
    length: u64,
    layout: &QevmPhysicalLayout,
) -> Result<()> {
    for (start, _, length) in qevm_physical_parts(block_offset, length, layout)? {
        output.push(PhysicalMissingRange {
            start,
            length,
            source: format!("qevm:{}:ram_page_not_present", layout.ram_block),
        });
    }
    Ok(())
}

#[cfg(test)]
fn detect_and_map(
    path: &Path,
    bytes: &[u8],
    file_len: u64,
) -> Result<(ImageFormat, Vec<PhysicalSpan>)> {
    let detected = detect_and_map_full(path, bytes, file_len, &ImageOpenOptions::default())?;
    Ok((detected.format, detected.spans))
}

fn detect_and_map_full(
    path: &Path,
    bytes: &[u8],
    file_len: u64,
    options: &ImageOpenOptions,
) -> Result<DetectedMapping> {
    if bytes.starts_with(b"PAGEDU64") {
        let (format, spans) = parse_dump64(bytes, file_len)?;
        return Ok(DetectedMapping {
            format,
            spans,
            missing_ranges: Vec::new(),
        });
    }
    if read_u32(bytes, 0)? == image_avml::AVML_MAGIC {
        // A matching magic is authoritative: malformed and unsupported AVML inputs are rejected
        // instead of silently degrading to a flat RAW interpretation.
        let parsed = image_avml::map_avml_v2_for_lazy_decode(bytes)?;
        let spans = parsed.physical_spans(0);
        return Ok(DetectedMapping {
            format: ImageFormat::AvmlV2 {
                version: parsed.version,
                record_count: parsed.records.len(),
                mapped_bytes: parsed.mapped_bytes,
                checksum_validation: "lazy_on_read",
            },
            spans,
            missing_ranges: Vec::new(),
        });
    }
    if bytes.starts_with(b"QEVM") {
        let parsed = image_qevm::parse_qevm(bytes)?;
        let layout = options.qevm_layout.as_ref().context(
            "QEVM RAMBlock offset 不是来宾物理地址；必须提供 --qevm-ram-block、\
             --qevm-below-4g-length 与 --qevm-above-4g-base",
        )?;
        let (spans, missing_ranges, selected_length, ignored_ram_blocks) =
            resolve_qevm_physical_layout(&parsed, layout)?;
        let pci_hole_size = layout
            .above_4g_physical_base
            .saturating_sub(layout.below_4g_length);
        return Ok(DetectedMapping {
            format: ImageFormat::QevmV3 {
                file_version: parsed.file_version,
                ram_version: parsed.ram_version,
                page_size: parsed.page_size,
                machine_name: parsed.machine_name,
                ram_block: layout.ram_block.clone(),
                ram_block_length: selected_length,
                below_4g_length: layout.below_4g_length,
                above_4g_physical_base: layout.above_4g_physical_base,
                pci_hole_start: layout.below_4g_length,
                pci_hole_size,
                mapping_count: spans.len(),
                ignored_ram_blocks,
                overwritten_pages: parsed.overwritten_pages,
            },
            spans,
            missing_ranges,
        });
    }
    if read_u32(bytes, 0)? == LIME_MAGIC {
        let (format, spans) = parse_lime(bytes, file_len)?;
        return Ok(DetectedMapping {
            format,
            spans,
            missing_ranges: Vec::new(),
        });
    }
    if bytes.starts_with(b"\x7fELF") {
        // Xen dump-cores use section-based page mappings rather than PT_LOAD.  A file carrying
        // any Xen dump-core section is therefore either accepted by the strict Xen parser or
        // rejected as malformed; it must never fall through to the generic ELF mapper.
        if let Some(parsed) = image_xen::parse_xen_elf64(bytes, file_len, 0)? {
            return Ok(DetectedMapping {
                format: ImageFormat::XenElf64(parsed.summary),
                spans: parsed.spans,
                missing_ranges: Vec::new(),
            });
        }
        let parsed = elf::parse_elf_physical_core(bytes, file_len)?;
        let producer = match parsed.producer {
            elf::ElfProducerHint::Qemu => ElfCoreProducer::Qemu,
            elf::ElfProducerHint::Generic => ElfCoreProducer::Generic,
        };
        return Ok(DetectedMapping {
            format: ImageFormat::ElfPhysicalCore {
                machine: parsed.machine,
                program_headers: parsed.program_header_count,
                producer,
            },
            spans: parsed
                .regions
                .into_iter()
                .map(|region| PhysicalSpan {
                    start: region.physical_start,
                    length: region.length,
                    file_offset: region.file_offset,
                    source_index: 0,
                    encoding: MappingEncoding::Direct,
                })
                .collect(),
            missing_ranges: parsed
                .missing_ranges
                .into_iter()
                .map(|range| PhysicalMissingRange {
                    start: range.start,
                    length: range.length,
                    source: "elf_pt_load_memsz_tail".to_owned(),
                })
                .collect(),
        });
    }
    if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("vmem"))
        && file_len == 0x1_0000_0000
    {
        // A common VMware 4 GiB guest layout keeps 3 GiB below the PCI aperture
        // and relocates the final GiB above 4 GiB. The flat .vmem stores both
        // ranges contiguously, so guest physical addresses differ from file
        // offsets after 0xc0000000.
        const PCI_HOLE_START: u64 = 0xc000_0000;
        const PCI_HOLE_SIZE: u64 = 0x4000_0000;
        return Ok(DetectedMapping {
            format: ImageFormat::VmwareVmem {
                pci_hole_start: PCI_HOLE_START,
                pci_hole_size: PCI_HOLE_SIZE,
                metadata: None,
            },
            spans: vec![
                PhysicalSpan {
                    start: 0,
                    length: PCI_HOLE_START,
                    file_offset: 0,
                    source_index: 0,
                    encoding: MappingEncoding::Direct,
                },
                PhysicalSpan {
                    start: 0x1_0000_0000,
                    length: file_len - PCI_HOLE_START,
                    file_offset: PCI_HOLE_START,
                    source_index: 0,
                    encoding: MappingEncoding::Direct,
                },
            ],
            missing_ranges: Vec::new(),
        });
    }

    Ok(DetectedMapping {
        format: ImageFormat::Raw,
        spans: vec![PhysicalSpan {
            start: 0,
            length: file_len,
            file_offset: 0,
            source_index: 0,
            encoding: MappingEncoding::Direct,
        }],
        missing_ranges: Vec::new(),
    })
}

fn looks_like_disk_or_volume(bytes: &[u8]) -> bool {
    let mbr = bytes.get(510..512) == Some(&[0x55, 0xaa])
        && bytes
            .get(446..510)
            .is_some_and(|table| table.chunks_exact(16).any(|entry| entry[4] != 0));
    let gpt = bytes.get(512..520) == Some(b"EFI PART");
    let filesystem = bytes.get(3..11).is_some_and(|oem| {
        matches!(oem, b"NTFS    " | b"EXFAT   ")
            || oem.starts_with(b"MSDOS")
            || oem.starts_with(b"mkfs.fat")
    });
    mbr || gpt || filesystem
}

fn parse_lime(bytes: &[u8], file_len: u64) -> Result<(ImageFormat, Vec<PhysicalSpan>)> {
    let version = read_u32(bytes, 4)?;
    let mut cursor = 0u64;
    let mut spans = Vec::new();
    while cursor < file_len {
        let header = usize::try_from(cursor)?;
        ensure!(
            cursor + LIME_HEADER_SIZE <= file_len,
            "文件偏移 {cursor:#x} 处的 LiME 区间头被截断"
        );
        ensure!(
            read_u32(bytes, header)? == LIME_MAGIC,
            "文件偏移 {cursor:#x} 处的 LiME 魔数无效"
        );
        let range_version = read_u32(bytes, header + 4)?;
        ensure!(range_version == version, "LiME 区间头版本不一致");
        let start = read_u64(bytes, header + 8)?;
        let end_inclusive = read_u64(bytes, header + 16)?;
        ensure!(end_inclusive >= start, "LiME 物理地址区间无效");
        let length = end_inclusive
            .checked_sub(start)
            .and_then(|n| n.checked_add(1))
            .context("LiME 区间长度计算溢出")?;
        let file_offset = cursor + LIME_HEADER_SIZE;
        ensure!(
            file_offset + length <= file_len,
            "{cursor:#x} 处的 LiME 区间超出镜像末尾"
        );
        spans.push(PhysicalSpan {
            start,
            length,
            file_offset,
            source_index: 0,
            encoding: MappingEncoding::Direct,
        });
        cursor = file_offset + length;
    }
    spans.sort_unstable_by_key(|span| span.start);
    ensure!(!spans.is_empty(), "LiME 镜像不包含任何物理区间");
    Ok((ImageFormat::Lime { version }, spans))
}

fn parse_dump64(bytes: &[u8], file_len: u64) -> Result<(ImageFormat, Vec<PhysicalSpan>)> {
    ensure!(
        file_len >= DUMP_HEADER64_SIZE,
        "64 位 Windows 崩溃转储头被截断"
    );
    let number_of_runs = read_u32(bytes, 0x88)?;
    ensure!(
        number_of_runs > 0 && number_of_runs <= 0x1000,
        "崩溃转储的物理区间数量 {number_of_runs} 不合理"
    );
    let number_of_pages = read_u64(bytes, 0x90)?;
    let mut spans = Vec::with_capacity(number_of_runs as usize);
    let mut file_offset = DUMP_HEADER64_SIZE;
    let mut counted_pages = 0u64;
    for run_index in 0..number_of_runs as usize {
        let run_offset = 0x98 + run_index * 16;
        let base_page = read_u64(bytes, run_offset)?;
        let page_count = read_u64(bytes, run_offset + 8)?;
        ensure!(page_count > 0, "物理区间 {run_index} 为空");
        let start = base_page
            .checked_mul(0x1000)
            .context("物理区间地址计算溢出")?;
        let length = page_count
            .checked_mul(0x1000)
            .context("物理区间长度计算溢出")?;
        spans.push(PhysicalSpan {
            start,
            length,
            file_offset,
            source_index: 0,
            encoding: MappingEncoding::Direct,
        });
        file_offset = file_offset
            .checked_add(length)
            .context("转储大小计算溢出")?;
        counted_pages = counted_pages
            .checked_add(page_count)
            .context("页数计算溢出")?;
    }
    ensure!(
        counted_pages == number_of_pages,
        "转储头页数与物理区间不一致：头部={number_of_pages}，区间合计={counted_pages}"
    );
    ensure!(file_offset <= file_len, "转储的物理区间超出文件末尾");

    let dump = WindowsDump64 {
        major_version: read_u32(bytes, 8)?,
        minor_version: read_u32(bytes, 12)?,
        directory_table_base: read_u64(bytes, 0x10)?,
        pfn_database: read_u64(bytes, 0x18)?,
        ps_loaded_module_list: read_u64(bytes, 0x20)?,
        ps_active_process_head: read_u64(bytes, 0x28)?,
        machine_type: read_u32(bytes, 0x30)?,
        number_processors: read_u32(bytes, 0x34)?,
        bug_check_code: read_u32(bytes, 0x38)?,
        bug_check_parameters: [
            read_u64(bytes, 0x40)?,
            read_u64(bytes, 0x48)?,
            read_u64(bytes, 0x50)?,
            read_u64(bytes, 0x58)?,
        ],
        kd_debugger_data_block: read_u64(bytes, 0x80)?,
        number_of_runs,
        number_of_pages,
        dump_type: read_u32(bytes, 0xf98)?,
        required_dump_space: read_u64(bytes, 0xfa0)?,
        system_time_raw: read_u64(bytes, 0xfa8)?,
        comment: read_c_string(bytes, 0xfb0, 128)?,
        system_uptime_100ns: read_u64(bytes, 0x1030)?,
        mini_dump_fields: read_u32(bytes, 0x1038)?,
        secondary_data_state: read_u32(bytes, 0x103c)?,
        product_type: read_u32(bytes, 0x1040)?,
        suite_mask: read_u32(bytes, 0x1044)?,
        writer_status: read_u32(bytes, 0x1048)?,
    };
    Ok((ImageFormat::WindowsCrashDump64(dump), spans))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .context("镜像头被截断")?
        .try_into()?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .context("镜像头被截断")?
        .try_into()?;
    Ok(u64::from_le_bytes(raw))
}

fn read_c_string(bytes: &[u8], offset: usize, length: usize) -> Result<String> {
    let raw = bytes
        .get(offset..offset + length)
        .context("镜像头字符串被截断")?;
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(&raw[..end]).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::scan::scan_exact;

    #[test]
    fn raw_mapping_is_identity() {
        let bytes = [0u8; 16];
        let (format, spans) =
            detect_and_map(Path::new("memory.raw"), &bytes, bytes.len() as u64).unwrap();
        assert!(matches!(format, ImageFormat::Raw));
        assert_eq!(spans[0].file_offset, spans[0].start);
        assert_eq!(spans[0].length, 16);
    }

    #[test]
    fn vmware_four_gib_mapping_skips_pci_hole() {
        let bytes = [0u8; 8];
        let (format, spans) =
            detect_and_map(Path::new("memory.vmem"), &bytes, 0x1_0000_0000).unwrap();
        assert!(matches!(format, ImageFormat::VmwareVmem { .. }));
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[0].length, 0xc000_0000);
        assert_eq!(spans[1].start, 0x1_0000_0000);
        assert_eq!(spans[1].file_offset, 0xc000_0000);
        assert_eq!(spans[1].length, 0x4000_0000);
    }

    #[test]
    fn lime_ranges_skip_each_header() {
        let mut bytes = Vec::new();
        push_lime_range(&mut bytes, 0x1000, &[1, 2, 3, 4]);
        push_lime_range(&mut bytes, 0x3000, &[5, 6, 7]);
        let (format, spans) =
            detect_and_map(Path::new("memory.lime"), &bytes, bytes.len() as u64).unwrap();
        assert!(matches!(format, ImageFormat::Lime { version: 1 }));
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start, 0x1000);
        assert_eq!(spans[0].length, 4);
        assert_eq!(spans[0].file_offset, 32);
        assert_eq!(spans[1].start, 0x3000);
        assert_eq!(spans[1].file_offset, 68);
    }

    #[test]
    fn avml_v2_maps_snappy_records_and_verifies_crc_on_read() {
        let root = temporary_directory("avml-v2");
        let path = root.join("capture.avml");
        let payload = b"avml-memory";
        let frame = snappy_uncompressed_frame(payload);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&image_avml::AVML_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&image_avml::AVML_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0x5000_u64.to_le_bytes());
        bytes.extend_from_slice(&(0x5000_u64 + payload.len() as u64 - 1).to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&frame);
        bytes.extend_from_slice(&(frame.len() as u64).to_le_bytes());
        fs::write(&path, &bytes).unwrap();

        let image = MemoryImage::open(&path).unwrap();
        assert!(matches!(
            image.format(),
            ImageFormat::AvmlV2 {
                version: 2,
                record_count: 1,
                checksum_validation: "lazy_on_read",
                ..
            }
        ));
        assert!(image.contains_physical(0x5000));
        assert_eq!(image.physical_to_file_offset(0x5000), None);
        let mut recovered = vec![0_u8; payload.len()];
        image.read_physical(0x5000, &mut recovered).unwrap();
        assert_eq!(recovered, payload);
        drop(image);

        // Mapping stays lazy, but a bad CRC can never produce evidence bytes.
        let crc_offset = image_avml::AVML_HEADER_SIZE + 10 + 4;
        bytes[crc_offset] ^= 1;
        fs::write(&path, &bytes).unwrap();
        let corrupt = MemoryImage::open(&path).unwrap();
        assert!(corrupt.read_physical(0x5000, &mut recovered).is_err());
        drop(corrupt);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn qevm_layout_resolves_pci_hole_and_reports_unsent_pages() {
        use crate::image_qevm::{
            QevmMappingSource, QevmParseResult, QevmRamBlock, QevmRamMappingDescriptor,
        };

        let parsed = QevmParseResult {
            file_version: 3,
            ram_version: 4,
            page_size: 0x1000,
            machine_name: Some("pc-q35-test".to_owned()),
            section_id: 7,
            ram_blocks: vec![
                QevmRamBlock {
                    name: "pc.ram".to_owned(),
                    length: 0x5000,
                },
                QevmRamBlock {
                    name: "vga.vram".to_owned(),
                    length: 0x1000,
                },
            ],
            mappings: vec![
                QevmRamMappingDescriptor {
                    ram_block: "pc.ram".to_owned(),
                    block_offset: 0,
                    length: 0x1000,
                    source: QevmMappingSource::Direct { file_offset: 0x80 },
                },
                QevmRamMappingDescriptor {
                    ram_block: "pc.ram".to_owned(),
                    block_offset: 0x2000,
                    length: 0x1000,
                    source: QevmMappingSource::RepeatedByte { value: 0 },
                },
                QevmRamMappingDescriptor {
                    ram_block: "pc.ram".to_owned(),
                    block_offset: 0x3000,
                    length: 0x2000,
                    source: QevmMappingSource::Direct { file_offset: 0x180 },
                },
            ],
            sections: Vec::new(),
            overwritten_pages: 1,
            eof_offset: 0,
            vmdescription_offset: 0,
        };
        let layout = QevmPhysicalLayout {
            ram_block: "pc.ram".to_owned(),
            below_4g_length: 0x3000,
            above_4g_physical_base: 0x1_0000_0000,
        };
        let (spans, missing, length, ignored) =
            resolve_qevm_physical_layout(&parsed, &layout).unwrap();
        assert_eq!(length, 0x5000);
        assert_eq!(ignored, ["vga.vram"]);
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[1].start, 0x2000);
        assert!(matches!(
            spans[1].encoding,
            MappingEncoding::RepeatedByte { value: 0 }
        ));
        assert_eq!(spans[2].start, 0x1_0000_0000);
        assert_eq!(spans[2].file_offset, 0x180);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].start, 0x1000);
        assert_eq!(missing[0].length, 0x1000);
    }

    #[test]
    fn dump_runs_map_after_header() {
        let mut bytes = vec![0u8; DUMP_HEADER64_SIZE as usize + 3 * 0x1000];
        bytes[..8].copy_from_slice(b"PAGEDU64");
        put_u32(&mut bytes, 0x88, 2);
        put_u64(&mut bytes, 0x90, 3);
        put_u64(&mut bytes, 0x98, 1);
        put_u64(&mut bytes, 0xa0, 1);
        put_u64(&mut bytes, 0xa8, 4);
        put_u64(&mut bytes, 0xb0, 2);
        let (format, spans) =
            detect_and_map(Path::new("memory.dmp"), &bytes, bytes.len() as u64).unwrap();
        assert!(matches!(format, ImageFormat::WindowsCrashDump64(_)));
        assert_eq!(spans[0].start, 0x1000);
        assert_eq!(spans[0].file_offset, DUMP_HEADER64_SIZE);
        assert_eq!(spans[1].start, 0x4000);
        assert_eq!(spans[1].file_offset, DUMP_HEADER64_SIZE + 0x1000);
        assert_eq!(spans[1].length, 0x2000);
    }

    #[test]
    fn decoded_mappings_cross_sources_and_scan_by_physical_address() {
        let root = temporary_directory("decoded-mappings");
        let primary_path = root.join("primary.bin");
        let sidecar_path = root.join("sidecar.bin");
        let frame = snappy_uncompressed_frame(b"snappy");
        let mut primary = b"ABCD".to_vec();
        primary.extend_from_slice(&frame);
        fs::write(&primary_path, primary).unwrap();
        fs::write(&sidecar_path, b"WXYZ").unwrap();
        let sources = vec![
            open_mmap_source(&primary_path, 0, ImageSourceRole::Primary).unwrap(),
            open_mmap_source(&sidecar_path, 1, ImageSourceRole::Sidecar).unwrap(),
        ];
        let image = MemoryImage::from_parts(
            primary_path.clone(),
            sources,
            fs::metadata(&primary_path).unwrap().len(),
            fs::metadata(&primary_path).unwrap().len(),
            ImageFormat::Raw,
            vec![
                PhysicalSpan {
                    start: 0,
                    length: 4,
                    file_offset: 0,
                    source_index: 0,
                    encoding: MappingEncoding::Direct,
                },
                PhysicalSpan {
                    start: 4,
                    length: 6,
                    file_offset: 4,
                    source_index: 0,
                    encoding: MappingEncoding::SnappyFrame {
                        encoded_length: frame.len() as u64,
                    },
                },
                PhysicalSpan {
                    start: 10,
                    length: 4,
                    file_offset: 0,
                    source_index: 0,
                    encoding: MappingEncoding::RepeatedByte { value: b'Z' },
                },
                PhysicalSpan {
                    start: 14,
                    length: 4,
                    file_offset: 0,
                    source_index: 1,
                    encoding: MappingEncoding::Direct,
                },
            ],
            Vec::new(),
            8,
        )
        .unwrap();

        let mut decoded = vec![0u8; 18];
        image.read_physical(0, &mut decoded).unwrap();
        assert_eq!(decoded, b"ABCDsnappyZZZZWXYZ");
        assert_eq!(image.physical_to_file_offset(0), Some(0));
        assert_eq!(image.physical_to_file_offset(4), None);
        assert_eq!(image.physical_to_file_offset(10), None);
        assert_eq!(image.physical_to_file_offset(14), Some(0));
        assert_eq!(image.source_offset_to_physical(1, 0), Some(14));
        assert_eq!(image.source_location(14).unwrap().source_index, 1);
        assert!(image.contains_physical(17));
        assert!(!image.contains_physical(18));

        let report = scan_exact(&image, b"pyZZ", 10, 4).unwrap();
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].physical_address, 8);

        drop(image);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn vmware_same_stem_metadata_maps_regions_and_explicit_choice_wins() {
        let root = temporary_directory("vmware-metadata");
        let vmem = root.join("guest.vmem");
        let vmss = root.join("guest.VMSS");
        let vmsn = root.join("guest.vmsn");
        let mut memory = vec![0u8; 4 * 0x1000];
        memory[0x1000..0x2000].fill(0x41);
        memory[0x2000..0x3000].fill(0x42);
        fs::write(&vmem, memory).unwrap();
        fs::write(&vmss, vmware_metadata_fixture(&[(0, 1, 1), (4, 2, 1)])).unwrap();

        let image = MemoryImage::open(&vmem).unwrap();
        assert!(matches!(
            image.format(),
            ImageFormat::VmwareVmem {
                metadata: Some(VmwareMetadataSummary {
                    region_count: 2,
                    ..
                }),
                ..
            }
        ));
        assert_eq!(image.sources().len(), 2);
        assert_eq!(image.read_u32_physical(0).unwrap(), 0x4141_4141);
        assert_eq!(image.read_u32_physical(0x4000).unwrap(), 0x4242_4242);
        assert!(!image.contains_physical(0x2000));
        assert_eq!(image.physical_to_file_offset(0), Some(0x1000));
        drop(image);

        fs::write(&vmsn, b"not selected").unwrap();
        assert!(MemoryImage::open(&vmem).is_err());
        let explicit = MemoryImage::open_with_options(
            &vmem,
            ImageOpenOptions {
                metadata_path: Some(vmss.clone()),
                ..ImageOpenOptions::default()
            },
        )
        .unwrap();
        assert_eq!(explicit.spans().len(), 2);
        drop(explicit);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn elf64_core_maps_only_file_backed_physical_bytes_and_reports_tail() {
        let root = temporary_directory("elf-core");
        let path = root.join("guest.elf");
        let bytes = elf_fixture();
        fs::write(&path, &bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        assert!(matches!(
            image.format(),
            ImageFormat::ElfPhysicalCore {
                producer: ElfCoreProducer::Generic,
                ..
            }
        ));
        let mut recovered = [0u8; 16];
        image.read_physical(0x2000, &mut recovered).unwrap();
        assert_eq!(&recovered, b"physical-memory!");
        assert!(!image.contains_physical(0x2010));
        assert_eq!(image.physical_to_file_offset(0x2000), Some(0x1000));
        assert_eq!(image.missing_ranges().len(), 1);
        assert_eq!(image.missing_ranges()[0].start, 0x2010);
        assert_eq!(image.missing_ranges()[0].length, 0x10);
        drop(image);
        fs::remove_dir_all(root).unwrap();
    }

    fn push_lime_range(output: &mut Vec<u8>, start: u64, payload: &[u8]) {
        output.extend_from_slice(&LIME_MAGIC.to_le_bytes());
        output.extend_from_slice(&1u32.to_le_bytes());
        output.extend_from_slice(&start.to_le_bytes());
        output.extend_from_slice(&(start + payload.len() as u64 - 1).to_le_bytes());
        output.extend_from_slice(&[0u8; 8]);
        output.extend_from_slice(payload);
    }

    fn put_u32(output: &mut [u8], offset: usize, value: u32) {
        output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(output: &mut [u8], offset: usize, value: u64) {
        output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u16(output: &mut [u8], offset: usize, value: u16) {
        output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-image-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn snappy_uncompressed_frame(decoded: &[u8]) -> Vec<u8> {
        let mut frame = vec![0xff, 6, 0, 0];
        frame.extend_from_slice(b"sNaPpY");
        let mut payload = codec::masked_crc32c(decoded).to_le_bytes().to_vec();
        payload.extend_from_slice(decoded);
        frame.push(0x01);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes()[..3]);
        frame.extend_from_slice(&payload);
        frame
    }

    fn vmware_metadata_fixture(regions: &[(u32, u32, u32)]) -> Vec<u8> {
        const HEADER: usize = 12;
        const GROUP: usize = 80;
        let mut bytes = vec![0u8; HEADER + GROUP];
        bytes[..4].copy_from_slice(&[0xd2, 0xbe, 0xd2, 0xbe]);
        put_u32(&mut bytes, 8, 1);
        bytes[HEADER..HEADER + 6].copy_from_slice(b"memory");
        put_u64(&mut bytes, HEADER + 64, (HEADER + GROUP) as u64);
        push_vmware_tag(&mut bytes, "regionsCount", &[], regions.len() as u32);
        for (index, (ppn, page, size)) in regions.iter().copied().enumerate() {
            let index = index as u32;
            push_vmware_tag(&mut bytes, "regionPPN", &[index], ppn);
            push_vmware_tag(&mut bytes, "regionPageNum", &[index], page);
            push_vmware_tag(&mut bytes, "regionSize", &[index], size);
        }
        bytes.extend_from_slice(&[0, 0]);
        bytes
    }

    fn push_vmware_tag(output: &mut Vec<u8>, name: &str, indices: &[u32], value: u32) {
        output.push(4 | ((indices.len() as u8) << 6));
        output.push(name.len() as u8);
        output.extend_from_slice(name.as_bytes());
        for index in indices {
            output.extend_from_slice(&index.to_le_bytes());
        }
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn elf_fixture() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x1010];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, 4);
        put_u16(&mut bytes, 18, 62);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 32, 64);
        put_u16(&mut bytes, 52, 64);
        put_u16(&mut bytes, 54, 56);
        put_u16(&mut bytes, 56, 1);
        put_u32(&mut bytes, 64, 1);
        put_u64(&mut bytes, 72, 0x1000);
        put_u64(&mut bytes, 88, 0x2000);
        put_u64(&mut bytes, 96, 0x10);
        put_u64(&mut bytes, 104, 0x20);
        put_u64(&mut bytes, 112, 0x1000);
        bytes[0x1000..0x1010].copy_from_slice(b"physical-memory!");
        bytes
    }
}
