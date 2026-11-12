//! Experimental, read-only VMware Workstation acquisition.
//!
//! Reads are live, non-atomic observations and never enter file-image caches.
//! A private MemoryImage bridge serves the narrow live Windows observer. There
//! is no page cache; callers own polling, cancellation and persistence.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::cancellation::CancellationToken;

pub mod display;

#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

const PAGE_SIZE: u64 = 4096;
const LOW_MEMORY_END: u64 = 0xc000_0000;
const HIGH_MEMORY_START: u64 = 0x1_0000_0000;
pub const MAX_LIVE_BATCH_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LIVE_REQUESTS: usize = 256;
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VmwareProcessIdentity {
    pub pid: u32,
    /// Windows process creation FILETIME, not guest boot time.
    pub created_filetime: u64,
    pub executable: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VmwareRegion {
    pub host_address: u64,
    pub length: u64,
    pub mapped_file: String,
    /// Eligible contiguous read/write mapping. Attachment requires exactly one
    /// eligible region; smaller or split aliases remain in the discovery data.
    pub supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VmwareTarget {
    pub process: VmwareProcessIdentity,
    pub regions: Vec<VmwareRegion>,
}

#[derive(Debug, Serialize)]
pub struct VmwareDiscoveryIssue {
    pub pid: u32,
    pub message: String,
}

#[derive(Debug, Default, Serialize)]
pub struct VmwareDiscovery {
    pub targets: Vec<VmwareTarget>,
    /// An inaccessible/disappearing VM is not silently reported as zero VMs.
    pub issues: Vec<VmwareDiscoveryIssue>,
}

/// List vmware-vmx.exe processes without selecting the first VM automatically.
pub fn discover_vmware(cancellation: &CancellationToken) -> Result<VmwareDiscovery> {
    cancellation.check_cancelled()?;
    #[cfg(windows)]
    {
        windows::discover(cancellation)
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("VMware 实时读取目前仅支持 64 位 Windows 主机")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VmwareLayout {
    /// Explicit experimental assumption, matching the observed LeechCore
    /// layout. This is not a verified map for every Workstation version/VM.
    Workstation3GbHole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LivePhysicalRange {
    pub physical_start: u64,
    pub host_start: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveSource {
    pub session_id: String,
    pub target: VmwareTarget,
    pub region: VmwareRegion,
    pub layout: VmwareLayout,
    pub layout_verified: bool,
    pub physical_ranges: Vec<LivePhysicalRange>,
}

#[derive(Debug, Clone, Copy)]
pub struct LiveReadRequest {
    pub physical_address: u64,
    pub length: usize,
}

#[derive(Debug, Serialize)]
pub struct LiveReadFragment {
    pub physical_address: u64,
    pub requested_length: usize,
    /// Only bytes actually copied. A missing/partial page is never zero-padded.
    #[serde(rename = "bytes_hex", serialize_with = "serialize_bytes")]
    pub bytes: Vec<u8>,
    pub error: Option<String>,
}

fn serialize_bytes<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}

#[derive(Debug, Serialize)]
pub struct LiveReadRange {
    pub physical_address: u64,
    pub requested_length: usize,
    pub complete: bool,
    /// Hash of exactly the requested bytes; unavailable for incomplete reads.
    pub sha256: Option<String>,
    pub comparison: LiveComparison,
    pub previous_sequence: Option<u64>,
    pub fragments: Vec<LiveReadFragment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveComparison {
    NoBaseline,
    /// Only the two observed byte strings match. Intervening changes may exist.
    SameBytes,
    DifferentBytes,
    Incomplete,
}

#[derive(Debug, Serialize)]
pub struct LiveReadBatch {
    pub source: LiveSource,
    /// An observation number within this attachment, not a guest snapshot ID.
    pub sequence: u64,
    pub started_unix_ms: u64,
    pub finished_unix_ms: u64,
    /// Monotonic duration, unaffected by host wall clock adjustments.
    pub elapsed_micros: u64,
    pub atomic_snapshot: bool,
    /// Read coverage only; does not certify the assumed physical layout.
    pub complete: bool,
    pub ranges: Vec<LiveReadRange>,
}

struct HostRead {
    copied: usize,
    error: Option<String>,
}

// Kept private: no second public backend framework alongside MemoryImage.
trait ProcessReader: Send {
    fn validate(&self, region: &VmwareRegion) -> Result<()>;
    fn read(&self, host_address: u64, output: &mut [u8]) -> HostRead;
}

pub struct VmwareLiveReader {
    source: LiveSource,
    process: Option<Box<dyn ProcessReader>>,
    sequence: u64,
    // Hashes only, bounded to the immediately preceding successful batch. No
    // memory bytes are cached or served by the acquisition path.
    previous: BTreeMap<(u64, usize), (u64, String)>,
}

impl VmwareLiveReader {
    /// Reopens and verifies the selected process creation time and complete
    /// candidate map. PID reuse and discovery/attachment races fail closed.
    pub fn attach(
        target: &VmwareTarget,
        layout: VmwareLayout,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        cancellation.check_cancelled()?;
        #[cfg(windows)]
        {
            Self::from_process(
                target.clone(),
                layout,
                windows::attach(target, cancellation)?,
            )
        }
        #[cfg(not(windows))]
        {
            let _ = (target, layout);
            anyhow::bail!("VMware 实时读取目前仅支持 64 位 Windows 主机")
        }
    }

    fn from_process(
        target: VmwareTarget,
        layout: VmwareLayout,
        process: Box<dyn ProcessReader>,
    ) -> Result<Self> {
        let mut supported = target.regions.iter().filter(|region| region.supported);
        let region = supported.next().context("当前 .vmem 映射属性不受支持")?;
        ensure!(
            supported.next().is_none(),
            "存在多个可用 .vmem 区域，不能猜测客户机 RAM 映射"
        );
        let physical_ranges = physical_ranges(region, layout)?;
        process.validate(region)?;
        let region = region.clone();
        let session_id = format!(
            "vmware-{}-{}-{}-{}-{}",
            std::process::id(),
            target.process.pid,
            target.process.created_filetime,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            NEXT_SESSION.fetch_add(1, Ordering::Relaxed)
        );
        Ok(Self {
            source: LiveSource {
                session_id,
                target,
                region,
                layout,
                layout_verified: false,
                physical_ranges,
            },
            process: Some(process),
            sequence: 0,
            previous: BTreeMap::new(),
        })
    }

    pub fn source(&self) -> &LiveSource {
        &self.source
    }

    /// Releases the owned process handle. Idempotent; does not stop the VM.
    pub fn stop(&mut self) {
        self.process = None;
        self.previous.clear();
    }

    pub fn is_open(&self) -> bool {
        self.process.is_some()
    }

    // Byte reader used by the narrowly scoped live Windows observer. This does
    // not retain data or update the user-facing raw-sampling comparison state.
    fn read_mapped_exact(
        &mut self,
        offset: u64,
        output: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let region = &self.source.region;
        let end = offset
            .checked_add(output.len() as u64)
            .context("实时映射范围溢出")?;
        ensure!(end <= region.length, "读取超出实时映射末尾");
        let base = region.host_address + offset;
        cancellation.check_cancelled()?;
        self.validate_source()?;
        for (index, chunk) in output.chunks_mut(64 * 1024).enumerate() {
            cancellation.check_cancelled()?;
            self.validate_source()?;
            let read = self
                .process
                .as_ref()
                .context("实时读取已停止")?
                .read(base + (index * 64 * 1024) as u64, chunk);
            ensure!(
                read.error.is_none() && read.copied == chunk.len(),
                "实时读取不完整：{}/{} 字节，{}",
                read.copied,
                chunk.len(),
                read.error.as_deref().unwrap_or("短读取")
            );
        }
        self.validate_source()?;
        cancellation.check_cancelled()
    }

    fn validate_source(&mut self) -> Result<()> {
        let result = self
            .process
            .as_ref()
            .context("STARMEM_LIVE_CLOSED: 实时读取已停止，请重新选择虚拟机")?
            .validate(&self.source.region);
        if let Err(error) = result {
            self.stop();
            return Err(error.context(
                "STARMEM_LIVE_SOURCE_CHANGED: 进程已退出或映射已改变；本批次作废，请重新连接",
            ));
        }
        Ok(())
    }

    /// Fresh page-sized reads, bounded to 16 MiB / 256 ranges per batch.
    /// Cancellation or a detected source change returns no batch. Individual
    /// inaccessible pages remain explicit fragments so later pages can succeed.
    pub fn read_batch(
        &mut self,
        requests: &[LiveReadRequest],
        cancellation: &CancellationToken,
    ) -> Result<LiveReadBatch> {
        cancellation.check_cancelled()?;
        validate_requests(requests)?;
        let started_unix_ms = unix_ms()?;
        let started = Instant::now();
        self.validate_source()?;
        self.sequence = self.sequence.checked_add(1).context("实时采样序号溢出")?;
        let previous = std::mem::take(&mut self.previous);
        let mut next_baseline = BTreeMap::new();
        let mut ranges = Vec::with_capacity(requests.len());
        for request in requests {
            let mut address = request.physical_address;
            let mut remaining = request.length;
            let mut fragments = Vec::new();
            while remaining > 0 {
                cancellation.check_cancelled()?;
                // Recheck before each page, not just before a long batch.
                self.validate_source()?;
                let length = remaining.min((PAGE_SIZE - address % PAGE_SIZE) as usize);
                let mapped = self.source.physical_ranges.iter().find(|range| {
                    address >= range.physical_start && address - range.physical_start < range.length
                });
                let fragment = if let Some(mapped) = mapped {
                    let offset = address - mapped.physical_start;
                    let length = length.min((mapped.length - offset) as usize);
                    let mut bytes = vec![0; length];
                    let read = self
                        .process
                        .as_ref()
                        .context("实时读取已停止")?
                        .read(mapped.host_start + offset, &mut bytes);
                    ensure!(read.copied <= length, "实时读取后端返回超出请求的字节数");
                    bytes.truncate(read.copied);
                    let error = read
                        .error
                        .or_else(|| (read.copied != length).then(|| "读取不完整".to_owned()));
                    LiveReadFragment {
                        physical_address: address,
                        requested_length: length,
                        bytes,
                        error,
                    }
                } else {
                    LiveReadFragment {
                        physical_address: address,
                        requested_length: length,
                        bytes: Vec::new(),
                        error: Some("物理地址未映射（包括假定的 3–4 GB 空洞）".to_owned()),
                    }
                };
                address += fragment.requested_length as u64;
                remaining -= fragment.requested_length;
                fragments.push(fragment);
            }
            let complete = fragments.iter().all(|part| part.error.is_none());
            let key = (request.physical_address, request.length);
            let (sha256, comparison, previous_sequence) = if complete {
                let mut hash = Sha256::new();
                for fragment in &fragments {
                    hash.update(&fragment.bytes);
                }
                let hash = hex::encode(hash.finalize());
                let (comparison, sequence) = match previous.get(&key) {
                    Some((sequence, old)) => (
                        if old == &hash {
                            LiveComparison::SameBytes
                        } else {
                            LiveComparison::DifferentBytes
                        },
                        Some(*sequence),
                    ),
                    None => (LiveComparison::NoBaseline, None),
                };
                next_baseline.insert(key, (self.sequence, hash.clone()));
                (Some(hash), comparison, sequence)
            } else {
                (None, LiveComparison::Incomplete, None)
            };
            ranges.push(LiveReadRange {
                physical_address: request.physical_address,
                requested_length: request.length,
                complete,
                sha256,
                comparison,
                previous_sequence,
                fragments,
            });
        }
        cancellation.check_cancelled()?;
        self.validate_source()?;
        cancellation.check_cancelled()?;
        let batch = LiveReadBatch {
            source: self.source.clone(),
            sequence: self.sequence,
            started_unix_ms,
            finished_unix_ms: unix_ms()?,
            elapsed_micros: started.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
            atomic_snapshot: false,
            complete: ranges.iter().all(|range| range.complete),
            ranges,
        };
        self.previous = next_baseline;
        Ok(batch)
    }
}

/// Internal bridge used only by the live Windows observer, never by file-path
/// session lookup. Its mutex also makes the OS handle usable by scan workers.
pub(crate) struct LiveImageReader {
    source: LiveSource,
    reader: Mutex<VmwareLiveReader>,
    cancellation: CancellationToken,
}

impl LiveImageReader {
    pub(crate) fn new(reader: VmwareLiveReader, cancellation: CancellationToken) -> Self {
        Self {
            source: reader.source.clone(),
            reader: Mutex::new(reader),
            cancellation,
        }
    }

    pub(crate) fn source(&self) -> &LiveSource {
        &self.source
    }

    pub(crate) fn read_source(&self, offset: u64, output: &mut [u8]) -> Result<()> {
        self.reader
            .lock()
            .map_err(|_| anyhow::anyhow!("实时读取锁已损坏"))?
            .read_mapped_exact(offset, output, &self.cancellation)
    }

    pub(crate) fn stop(&self) -> Result<()> {
        self.reader
            .lock()
            .map_err(|_| anyhow::anyhow!("实时读取锁已损坏"))?
            .stop();
        Ok(())
    }
}

fn unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()
        .context("宿主时间超出记录范围")
}

fn validate_requests(requests: &[LiveReadRequest]) -> Result<()> {
    ensure!(
        !requests.is_empty() && requests.len() <= MAX_LIVE_REQUESTS,
        "每批必须有 1–{MAX_LIVE_REQUESTS} 个读取范围"
    );
    let mut total = 0usize;
    for request in requests {
        ensure!(request.length > 0, "读取长度必须大于零");
        request
            .physical_address
            .checked_add(request.length as u64)
            .context("物理地址范围溢出")?;
        total = total
            .checked_add(request.length)
            .context("读取总长度溢出")?;
        ensure!(
            total <= MAX_LIVE_BATCH_BYTES,
            "每批读取不能超过 {MAX_LIVE_BATCH_BYTES} 字节"
        );
    }
    Ok(())
}

fn physical_ranges(region: &VmwareRegion, layout: VmwareLayout) -> Result<Vec<LivePhysicalRange>> {
    ensure!(
        region.length > 0
            && region.length.is_multiple_of(PAGE_SIZE)
            && region.host_address.is_multiple_of(PAGE_SIZE),
        ".vmem 映射必须非空且按页对齐"
    );
    region
        .host_address
        .checked_add(region.length)
        .context("宿主映射范围溢出")?;
    match layout {
        VmwareLayout::Workstation3GbHole => {
            let mut ranges = vec![LivePhysicalRange {
                physical_start: 0,
                host_start: region.host_address,
                length: region.length.min(LOW_MEMORY_END),
            }];
            if region.length > LOW_MEMORY_END {
                let length = region.length - LOW_MEMORY_END;
                HIGH_MEMORY_START
                    .checked_add(length)
                    .context("客户机物理范围溢出")?;
                ranges.push(LivePhysicalRange {
                    physical_start: HIGH_MEMORY_START,
                    host_start: region.host_address + LOW_MEMORY_END,
                    length,
                });
            }
            Ok(ranges)
        }
    }
}
