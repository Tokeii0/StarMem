use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aho_corasick::AhoCorasickBuilder;
use anyhow::{Context, Result, ensure};
use memchr::{memchr_iter, memmem};
use rayon::prelude::*;
use serde::Serialize;

use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::progress::start_progress;

// Keep all parallel scan buffers inside a predictable process-wide envelope.
const PARALLEL_SCAN_BUFFER_BUDGET_BYTES: usize = 128 * 1024 * 1024;
const SCAN_CACHE_BUDGET_BYTES: usize = 64 * 1024 * 1024;
const COMMON_POOL_CACHE_LIMIT: usize = 1_000_000;
const COMMON_POOL_SEED_MAX_IMAGE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

fn should_seed_common_pool_cache(patterns: &[[u8; 4]], mapped_bytes: u64) -> bool {
    patterns == [*b"Proc"] && mapped_bytes <= COMMON_POOL_SEED_MAX_IMAGE_BYTES
}

/// Shared pool-tag batch used by broad triage. Running this once seeds the
/// session cache for process, file, network, thread, driver, atom and GUI
/// plugins instead of rereading the image once per subsystem.
pub const COMMON_POOL_TAGS: [[u8; 4]; 16] = [
    *b"Proc",
    *b"Thre",
    *b"File",
    [b'F', b'i', b'l', b'e' | 0x80],
    *b"FILE",
    *b"Driv",
    *b"Muta",
    *b"MmLd",
    *b"Symb",
    *b"CM10",
    *b"AtmT",
    *b"TcpE",
    *b"TcpL",
    *b"UdpA",
    *b"Wind",
    *b"Desk",
];

#[derive(Debug, Clone, Serialize)]
pub struct ScanHit {
    pub physical_address: u64,
    pub file_offset: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub bytes_scanned: u64,
    pub elapsed_seconds: f64,
    pub gib_per_second: f64,
    pub hits: Vec<ScanHit>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MultiScanHit {
    pub pattern_index: usize,
    pub physical_address: u64,
    pub file_offset: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MultiScanReport {
    pub bytes_scanned: u64,
    pub elapsed_seconds: f64,
    pub gib_per_second: f64,
    pub hits: Vec<MultiScanHit>,
    pub truncated: bool,
    pub truncated_patterns: Vec<bool>,
}

#[derive(Clone)]
pub struct ScanEngine {
    inner: Arc<ScanEngineInner>,
}

struct ScanEngineInner {
    fixed_cache: Mutex<Vec<FixedScanCacheEntry>>,
    physical_scan_gate: Mutex<()>,
}

struct FixedScanCacheEntry {
    patterns: Vec<[u8; 4]>,
    limit_per_pattern: usize,
    bytes_scanned: u64,
    hits_by_pattern: Vec<Vec<ScanHit>>,
    truncated_patterns: Vec<bool>,
    retained_bytes: usize,
}

#[derive(Default)]
struct ScanWorkerBuffer {
    bytes: Vec<u8>,
}

impl ScanWorkerBuffer {
    fn read_chunk<'a>(&'a mut self, image: &MemoryImage, chunk: &WorkChunk) -> Result<&'a [u8]> {
        self.bytes.resize(chunk.scan_len, 0);
        image.read_physical(chunk.physical_start, &mut self.bytes)?;
        Ok(&self.bytes)
    }
}

impl ScanEngine {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ScanEngineInner {
                fixed_cache: Mutex::new(Vec::new()),
                physical_scan_gate: Mutex::new(()),
            }),
        }
    }

    fn lock_physical_scan(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.inner
            .physical_scan_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("物理内存扫描调度锁已损坏"))
    }

    fn scan_exact(
        &self,
        image: &MemoryImage,
        needle: &[u8],
        limit: usize,
        chunk_size: usize,
        cancellation: &CancellationToken,
    ) -> Result<ScanReport> {
        let _scan_guard = self.lock_physical_scan()?;
        cancellation.check_cancelled()?;
        scan_exact_cpu_cancellable(image, needle, limit, chunk_size, cancellation)
    }

    fn scan_fixed_4(
        &self,
        image: &MemoryImage,
        patterns: &[[u8; 4]],
        limit_per_pattern: usize,
        chunk_size: usize,
        cancellation: &CancellationToken,
    ) -> Result<MultiScanReport> {
        if let Some(report) = self.cached_fixed_scan(patterns, limit_per_pattern)? {
            cancellation.check_cancelled()?;
            return Ok(report);
        }
        let _scan_guard = self.lock_physical_scan()?;
        cancellation.check_cancelled()?;
        // A concurrent caller may have populated the shared cache while this
        // request waited. Recheck under the single-flight scan gate.
        if let Some(report) = self.cached_fixed_scan(patterns, limit_per_pattern)? {
            return Ok(report);
        }
        let expand_common_pool_tags = should_seed_common_pool_cache(patterns, image.mapped_bytes());
        let scan_patterns = if expand_common_pool_tags {
            COMMON_POOL_TAGS.as_slice()
        } else {
            patterns
        };
        let scan_limit = if expand_common_pool_tags {
            limit_per_pattern.max(COMMON_POOL_CACHE_LIMIT)
        } else {
            limit_per_pattern
        };
        let report = scan_exact_4_cpu_cancellable(
            image,
            scan_patterns,
            scan_limit,
            chunk_size,
            cancellation,
        )?;
        self.retain_fixed_scan(scan_patterns, scan_limit, &report)?;
        if scan_patterns == patterns && scan_limit == limit_per_pattern {
            Ok(report)
        } else {
            project_fixed_report(scan_patterns, &report, patterns, limit_per_pattern, true)
        }
    }

    fn cached_fixed_scan(
        &self,
        patterns: &[[u8; 4]],
        limit_per_pattern: usize,
    ) -> Result<Option<MultiScanReport>> {
        let cache = self
            .inner
            .fixed_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("扫描缓存锁已损坏"))?;
        let Some(entry) = cache.iter().find(|entry| {
            entry.limit_per_pattern >= limit_per_pattern
                && patterns
                    .iter()
                    .all(|pattern| entry.patterns.contains(pattern))
        }) else {
            return Ok(None);
        };
        project_cached_fixed_report(entry, patterns, limit_per_pattern).map(Some)
    }

    fn retain_fixed_scan(
        &self,
        patterns: &[[u8; 4]],
        limit_per_pattern: usize,
        report: &MultiScanReport,
    ) -> Result<()> {
        let estimated = report
            .hits
            .len()
            .saturating_mul(std::mem::size_of::<ScanHit>());
        if estimated > SCAN_CACHE_BUDGET_BYTES {
            return Ok(());
        }
        let mut cache = self
            .inner
            .fixed_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("扫描缓存锁已损坏"))?;
        cache.retain(|entry| {
            !(entry.limit_per_pattern <= limit_per_pattern
                && entry
                    .patterns
                    .iter()
                    .all(|pattern| patterns.contains(pattern)))
        });
        let current: usize = cache.iter().map(|entry| entry.retained_bytes).sum();
        if current.saturating_add(estimated) <= SCAN_CACHE_BUDGET_BYTES {
            let mut hit_counts = vec![0usize; report.truncated_patterns.len()];
            for hit in &report.hits {
                hit_counts[hit.pattern_index] += 1;
            }
            let mut hits_by_pattern = hit_counts
                .into_iter()
                .map(Vec::with_capacity)
                .collect::<Vec<_>>();
            for hit in &report.hits {
                hits_by_pattern[hit.pattern_index].push(ScanHit {
                    physical_address: hit.physical_address,
                    file_offset: hit.file_offset,
                });
            }
            let retained_bytes = hits_by_pattern
                .iter()
                .map(|hits| {
                    hits.capacity()
                        .saturating_mul(std::mem::size_of::<ScanHit>())
                })
                .sum();
            cache.push(FixedScanCacheEntry {
                patterns: patterns.to_vec(),
                limit_per_pattern,
                bytes_scanned: report.bytes_scanned,
                hits_by_pattern,
                truncated_patterns: report.truncated_patterns.clone(),
                retained_bytes,
            });
        }
        Ok(())
    }
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn project_cached_fixed_report(
    source: &FixedScanCacheEntry,
    requested_patterns: &[[u8; 4]],
    limit_per_pattern: usize,
) -> Result<MultiScanReport> {
    let mut hits = Vec::new();
    let mut truncated_patterns = Vec::with_capacity(requested_patterns.len());
    for (requested_index, pattern) in requested_patterns.iter().enumerate() {
        let source_index = source
            .patterns
            .iter()
            .position(|cached| cached == pattern)
            .context("扫描缓存模式映射缺失")?;
        let source_hits = &source.hits_by_pattern[source_index];
        hits.extend(
            source_hits
                .iter()
                .take(limit_per_pattern)
                .map(|hit| MultiScanHit {
                    pattern_index: requested_index,
                    physical_address: hit.physical_address,
                    file_offset: hit.file_offset,
                }),
        );
        truncated_patterns
            .push(source.truncated_patterns[source_index] || source_hits.len() > limit_per_pattern);
    }
    hits.sort_unstable_by_key(|hit| (hit.physical_address, hit.pattern_index));
    Ok(MultiScanReport {
        bytes_scanned: source.bytes_scanned,
        elapsed_seconds: 0.0,
        gib_per_second: 0.0,
        truncated: truncated_patterns.iter().any(|value| *value),
        hits,
        truncated_patterns,
    })
}

fn project_fixed_report(
    source_patterns: &[[u8; 4]],
    source: &MultiScanReport,
    requested_patterns: &[[u8; 4]],
    limit_per_pattern: usize,
    preserve_timings: bool,
) -> Result<MultiScanReport> {
    let mut source_indexes = Vec::with_capacity(requested_patterns.len());
    for pattern in requested_patterns {
        source_indexes.push(
            source_patterns
                .iter()
                .position(|cached| cached == pattern)
                .context("扫描缓存模式映射缺失")?,
        );
    }
    let mut source_counts = vec![0usize; requested_patterns.len()];
    let mut retained = vec![0usize; requested_patterns.len()];
    let mut hits = Vec::new();
    for hit in &source.hits {
        for (requested_index, source_index) in source_indexes.iter().enumerate() {
            if *source_index != hit.pattern_index {
                continue;
            }
            source_counts[requested_index] += 1;
            if retained[requested_index] < limit_per_pattern {
                retained[requested_index] += 1;
                hits.push(MultiScanHit {
                    pattern_index: requested_index,
                    physical_address: hit.physical_address,
                    file_offset: hit.file_offset,
                });
            }
        }
    }
    hits.sort_unstable_by_key(|hit| (hit.physical_address, hit.pattern_index));
    let truncated_patterns = source_indexes
        .iter()
        .enumerate()
        .map(|(requested_index, source_index)| {
            source.truncated_patterns[*source_index]
                || source_counts[requested_index] > limit_per_pattern
        })
        .collect::<Vec<_>>();
    Ok(MultiScanReport {
        bytes_scanned: source.bytes_scanned,
        elapsed_seconds: if preserve_timings {
            source.elapsed_seconds
        } else {
            0.0
        },
        gib_per_second: if preserve_timings {
            source.gib_per_second
        } else {
            0.0
        },
        hits,
        truncated: truncated_patterns.iter().any(|value| *value),
        truncated_patterns,
    })
}

pub struct ScanPatternSet<'a> {
    pub patterns: &'a [&'a [u8]],
    pub limit_per_pattern: usize,
    pub ascii_case_insensitive: bool,
}

/// Scans several arbitrary byte patterns in one pass over every acquired span.
pub fn scan_patterns(
    image: &MemoryImage,
    patterns: &[&[u8]],
    limit_per_pattern: usize,
    chunk_size: usize,
) -> Result<MultiScanReport> {
    scan_patterns_cancellable(
        image,
        patterns,
        limit_per_pattern,
        chunk_size,
        &CancellationToken::new(),
    )
}

/// Cancellable variant of [`scan_patterns`]. Cancellation is checked before
/// work is scheduled and at every parallel memory chunk boundary.
pub fn scan_patterns_cancellable(
    image: &MemoryImage,
    patterns: &[&[u8]],
    limit_per_pattern: usize,
    chunk_size: usize,
    cancellation: &CancellationToken,
) -> Result<MultiScanReport> {
    scan_patterns_with_case_cancellable(
        image,
        patterns,
        limit_per_pattern,
        chunk_size,
        false,
        cancellation,
    )
}

/// Scans several ASCII or UTF-16LE byte patterns without regard to ASCII
/// letter case. UTF-16LE command text is supported because case folding is
/// applied independently to the non-zero ASCII bytes.
pub fn scan_patterns_ascii_case_insensitive(
    image: &MemoryImage,
    patterns: &[&[u8]],
    limit_per_pattern: usize,
    chunk_size: usize,
) -> Result<MultiScanReport> {
    scan_patterns_with_case_cancellable(
        image,
        patterns,
        limit_per_pattern,
        chunk_size,
        true,
        &CancellationToken::new(),
    )
}

/// Scans several exact byte patterns through a bounded reusable buffer.
///
/// Unlike the parallel scanner, this path deliberately does not touch the
/// image's full read-only mapping. It is intended for large fallback scans
/// where predictable resident memory matters more than maximum throughput.
pub fn scan_patterns_streaming_cancellable(
    image: &MemoryImage,
    patterns: &[&[u8]],
    limit_per_pattern: usize,
    chunk_size: usize,
    cancellation: &CancellationToken,
) -> Result<MultiScanReport> {
    cancellation.check_cancelled()?;
    let _scan_guard = image.scan_engine().lock_physical_scan()?;
    cancellation.check_cancelled()?;
    ensure!(!patterns.is_empty(), "扫描模式不能为空");
    ensure!(
        patterns.iter().all(|pattern| !pattern.is_empty()),
        "扫描模式不能为空"
    );
    ensure!(limit_per_pattern > 0, "扫描结果数量上限必须大于零");
    let longest = patterns.iter().map(|pattern| pattern.len()).max().unwrap();
    ensure!(chunk_size >= longest, "扫描块小于最长扫描模式");
    let matcher = AhoCorasickBuilder::new().build(patterns)?;
    let mut buffer = Vec::with_capacity(chunk_size + longest.saturating_sub(1));
    let mut hits = Vec::new();
    let mut seen = vec![0usize; patterns.len()];
    let mut truncated_patterns = vec![false; patterns.len()];
    let mut bytes_scanned = 0u64;
    let started = Instant::now();
    let progress = start_progress(physical_scan_label(image), image.mapped_bytes());
    'spans: for (range_start, range_length) in acquired_ranges(image) {
        let mut consumed = 0u64;
        while consumed < range_length {
            cancellation.check_cancelled()?;
            if seen.iter().all(|count| *count >= limit_per_pattern) {
                truncated_patterns.fill(true);
                break 'spans;
            }
            let core_len = usize::try_from((range_length - consumed).min(chunk_size as u64))?;
            let overlap = longest
                .saturating_sub(1)
                .min(usize::try_from(range_length - consumed - core_len as u64)?);
            let scan_len = core_len + overlap;
            buffer.resize(scan_len, 0);
            let physical_start = range_start + consumed;
            image.read_physical(physical_start, &mut buffer)?;
            bytes_scanned += core_len as u64;
            progress.advance(core_len as u64);
            for matched in matcher.find_overlapping_iter(&buffer) {
                if matched.start() >= core_len {
                    break;
                }
                let pattern_index = matched.pattern().as_usize();
                if seen[pattern_index] >= limit_per_pattern {
                    truncated_patterns[pattern_index] = true;
                    continue;
                }
                seen[pattern_index] += 1;
                hits.push(MultiScanHit {
                    pattern_index,
                    physical_address: physical_start + matched.start() as u64,
                    file_offset: legacy_scan_offset(image, physical_start + matched.start() as u64),
                });
            }
            consumed += core_len as u64;
        }
    }
    hits.sort_unstable_by_key(|hit| (hit.physical_address, hit.pattern_index));
    let elapsed = started.elapsed();
    progress.finish();
    Ok(MultiScanReport {
        bytes_scanned,
        elapsed_seconds: duration_seconds(elapsed),
        gib_per_second: throughput(bytes_scanned, elapsed),
        truncated: truncated_patterns.iter().any(|truncated| *truncated),
        hits,
        truncated_patterns,
    })
}

fn scan_patterns_with_case_cancellable(
    image: &MemoryImage,
    patterns: &[&[u8]],
    limit_per_pattern: usize,
    chunk_size: usize,
    ascii_case_insensitive: bool,
    cancellation: &CancellationToken,
) -> Result<MultiScanReport> {
    scan_pattern_sets_cancellable(
        image,
        &[ScanPatternSet {
            patterns,
            limit_per_pattern,
            ascii_case_insensitive,
        }],
        chunk_size,
        cancellation,
    )
}

/// Scans pattern groups with independent case and result-limit policies while
/// reading each acquired memory chunk only once.
pub fn scan_pattern_sets(
    image: &MemoryImage,
    sets: &[ScanPatternSet<'_>],
    chunk_size: usize,
) -> Result<MultiScanReport> {
    scan_pattern_sets_cancellable(image, sets, chunk_size, &CancellationToken::new())
}

/// Cancellable variant of [`scan_pattern_sets`]. Cancellation is checked
/// before work is scheduled and at every parallel memory chunk boundary.
pub fn scan_pattern_sets_cancellable(
    image: &MemoryImage,
    sets: &[ScanPatternSet<'_>],
    chunk_size: usize,
    cancellation: &CancellationToken,
) -> Result<MultiScanReport> {
    cancellation.check_cancelled()?;
    let _scan_guard = image.scan_engine().lock_physical_scan()?;
    cancellation.check_cancelled()?;
    scan_pattern_sets_cpu_cancellable(image, sets, chunk_size, cancellation)
}

fn scan_pattern_sets_cpu_cancellable(
    image: &MemoryImage,
    sets: &[ScanPatternSet<'_>],
    chunk_size: usize,
    cancellation: &CancellationToken,
) -> Result<MultiScanReport> {
    cancellation.check_cancelled()?;
    ensure!(!sets.is_empty(), "至少需要一组扫描模式");
    ensure!(
        sets.iter().all(|set| !set.patterns.is_empty()),
        "扫描模式组不能为空"
    );
    ensure!(
        sets.iter()
            .flat_map(|set| set.patterns.iter())
            .all(|pattern| !pattern.is_empty()),
        "扫描模式不能为空"
    );
    ensure!(
        sets.iter().all(|set| set.limit_per_pattern > 0),
        "扫描结果数量上限必须大于零"
    );
    let longest = sets
        .iter()
        .flat_map(|set| set.patterns.iter())
        .map(|pattern| pattern.len())
        .max()
        .unwrap();
    ensure!(chunk_size >= longest, "扫描块小于最长扫描模式");
    let mut pattern_offset = 0usize;
    let mut limits = Vec::new();
    let mut matchers = Vec::with_capacity(sets.len());
    for set in sets {
        matchers.push((
            pattern_offset,
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(set.ascii_case_insensitive)
                .build(set.patterns)?,
        ));
        pattern_offset += set.patterns.len();
        limits.extend(std::iter::repeat_n(
            set.limit_per_pattern,
            set.patterns.len(),
        ));
    }
    let chunks = work_chunks(image, longest, chunk_size)?;
    let total_bytes = chunks
        .iter()
        .map(|chunk| chunk.core_len as u64)
        .sum::<u64>();
    let progress = start_progress(physical_scan_label(image), total_bytes);
    let started = Instant::now();
    let seen: Vec<AtomicUsize> = limits.iter().map(|_| AtomicUsize::new(0)).collect();
    let scanned = AtomicU64::new(0);
    let stopped_early = AtomicBool::new(false);
    let mut hits: Vec<MultiScanHit> = chunks
        .par_iter()
        .map_init(
            ScanWorkerBuffer::default,
            |worker, chunk| -> Result<Vec<MultiScanHit>> {
                cancellation.check_cancelled()?;
                if seen
                    .iter()
                    .zip(&limits)
                    .all(|(count, limit)| count.load(Ordering::Relaxed) >= *limit)
                {
                    stopped_early.store(true, Ordering::Relaxed);
                    return Ok(Vec::new());
                }
                let haystack = worker.read_chunk(image, chunk)?;
                scanned.fetch_add(chunk.core_len as u64, Ordering::Relaxed);
                progress.advance(chunk.core_len as u64);
                let mut local = Vec::new();
                for (offset, matcher) in &matchers {
                    cancellation.check_cancelled()?;
                    for matched in matcher.find_overlapping_iter(haystack) {
                        let relative = matched.start();
                        if relative >= chunk.core_len {
                            break;
                        }
                        let pattern_index = offset + matched.pattern().as_usize();
                        let slot = seen[pattern_index].fetch_add(1, Ordering::Relaxed);
                        if slot < limits[pattern_index] {
                            let physical_address = chunk.physical_start + relative as u64;
                            local.push(MultiScanHit {
                                pattern_index,
                                physical_address,
                                file_offset: legacy_scan_offset(image, physical_address),
                            });
                        } else {
                            stopped_early.store(true, Ordering::Relaxed);
                        }
                    }
                }
                Ok(local)
            },
        )
        .try_reduce(Vec::new, |mut retained, local| {
            retained.extend(local);
            Ok(retained)
        })?;
    cancellation.check_cancelled()?;
    hits.sort_unstable_by_key(|hit| (hit.physical_address, hit.pattern_index));
    let elapsed = started.elapsed();
    let bytes_scanned = scanned.load(Ordering::Relaxed);
    let mut retained = vec![0usize; seen.len()];
    for hit in &hits {
        retained[hit.pattern_index] += 1;
    }
    let stopped_early = stopped_early.load(Ordering::Relaxed);
    let truncated_patterns = seen
        .iter()
        .enumerate()
        .map(|(index, count)| {
            count.load(Ordering::Relaxed) > retained[index]
                || (stopped_early && count.load(Ordering::Relaxed) >= limits[index])
        })
        .collect::<Vec<_>>();
    let truncated = truncated_patterns.iter().any(|truncated| *truncated);
    progress.finish();
    Ok(MultiScanReport {
        bytes_scanned,
        elapsed_seconds: duration_seconds(elapsed),
        gib_per_second: throughput(bytes_scanned, elapsed),
        hits,
        truncated,
        truncated_patterns,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct WorkChunk {
    pub(crate) physical_start: u64,
    pub(crate) core_len: usize,
    pub(crate) scan_len: usize,
}

pub fn scan_exact(
    image: &MemoryImage,
    needle: &[u8],
    limit: usize,
    chunk_size: usize,
) -> Result<ScanReport> {
    scan_exact_cancellable(image, needle, limit, chunk_size, &CancellationToken::new())
}

/// Cancellable variant of [`scan_exact`]. Cancellation is checked before work
/// is scheduled and at every parallel memory chunk boundary.
pub fn scan_exact_cancellable(
    image: &MemoryImage,
    needle: &[u8],
    limit: usize,
    chunk_size: usize,
    cancellation: &CancellationToken,
) -> Result<ScanReport> {
    image
        .scan_engine()
        .scan_exact(image, needle, limit, chunk_size, cancellation)
}

fn scan_exact_cpu_cancellable(
    image: &MemoryImage,
    needle: &[u8],
    limit: usize,
    chunk_size: usize,
    cancellation: &CancellationToken,
) -> Result<ScanReport> {
    cancellation.check_cancelled()?;
    ensure!(!needle.is_empty(), "扫描模式不能为空");
    ensure!(chunk_size >= needle.len(), "扫描块小于扫描模式");
    ensure!(limit > 0, "扫描结果数量上限必须大于零");

    let chunks = work_chunks(image, needle.len(), chunk_size)?;
    let total_bytes = chunks
        .iter()
        .map(|chunk| chunk.core_len as u64)
        .sum::<u64>();
    let progress = start_progress(physical_scan_label(image), total_bytes);

    let started = Instant::now();
    let seen = AtomicUsize::new(0);
    let scanned = AtomicU64::new(0);
    let stopped_early = AtomicBool::new(false);
    let mut hits: Vec<ScanHit> = chunks
        .par_iter()
        .map_init(
            ScanWorkerBuffer::default,
            |worker, chunk| -> Result<Vec<ScanHit>> {
                cancellation.check_cancelled()?;
                if seen.load(Ordering::Relaxed) >= limit {
                    stopped_early.store(true, Ordering::Relaxed);
                    return Ok(Vec::new());
                }
                let haystack = worker.read_chunk(image, chunk)?;
                scanned.fetch_add(chunk.core_len as u64, Ordering::Relaxed);
                progress.advance(chunk.core_len as u64);
                let mut local = Vec::new();
                let mut record_hit = |relative: usize| -> bool {
                    if relative >= chunk.core_len {
                        return false;
                    }
                    let slot = seen.fetch_add(1, Ordering::Relaxed);
                    if slot >= limit {
                        stopped_early.store(true, Ordering::Relaxed);
                        return false;
                    }
                    let physical_address = chunk.physical_start + relative as u64;
                    local.push(ScanHit {
                        physical_address,
                        file_offset: legacy_scan_offset(image, physical_address),
                    });
                    true
                };
                if needle.len() == 1 {
                    for relative in memchr_iter(needle[0], haystack) {
                        if !record_hit(relative) {
                            break;
                        }
                    }
                } else if needle.len() == 2 {
                    for relative in memchr_iter(needle[0], haystack) {
                        if haystack.get(relative + 1) == Some(&needle[1]) && !record_hit(relative) {
                            break;
                        }
                    }
                } else {
                    for relative in memmem::find_iter(haystack, needle) {
                        if !record_hit(relative) {
                            break;
                        }
                    }
                }
                Ok(local)
            },
        )
        .try_reduce(Vec::new, |mut retained, local| {
            retained.extend(local);
            Ok(retained)
        })?;
    cancellation.check_cancelled()?;
    hits.sort_unstable_by_key(|hit| hit.physical_address);
    hits.truncate(limit);
    let elapsed = started.elapsed();
    let bytes_scanned = scanned.load(Ordering::Relaxed);
    progress.finish();
    Ok(ScanReport {
        bytes_scanned,
        elapsed_seconds: duration_seconds(elapsed),
        gib_per_second: throughput(bytes_scanned, elapsed),
        truncated: stopped_early.load(Ordering::Relaxed)
            || seen.load(Ordering::Relaxed) > hits.len(),
        hits,
    })
}

/// Scans for several four-byte signatures in one pass over every work chunk.
///
/// A single Aho-Corasick automaton is shared by all parallel chunks. This is
/// intended for small sets of pool tags and avoids rereading a multi-gigabyte
/// image once per tag.
pub fn scan_exact_4(
    image: &MemoryImage,
    patterns: &[[u8; 4]],
    limit_per_pattern: usize,
    chunk_size: usize,
) -> Result<MultiScanReport> {
    scan_exact_4_cancellable(
        image,
        patterns,
        limit_per_pattern,
        chunk_size,
        &CancellationToken::new(),
    )
}

/// Cancellable variant of [`scan_exact_4`].
pub fn scan_exact_4_cancellable(
    image: &MemoryImage,
    patterns: &[[u8; 4]],
    limit_per_pattern: usize,
    chunk_size: usize,
    cancellation: &CancellationToken,
) -> Result<MultiScanReport> {
    cancellation.check_cancelled()?;
    ensure!(!patterns.is_empty(), "扫描模式不能为空");
    ensure!(limit_per_pattern > 0, "扫描结果数量上限必须大于零");
    image
        .scan_engine()
        .scan_fixed_4(image, patterns, limit_per_pattern, chunk_size, cancellation)
}

fn scan_exact_4_cpu_cancellable(
    image: &MemoryImage,
    patterns: &[[u8; 4]],
    limit_per_pattern: usize,
    chunk_size: usize,
    cancellation: &CancellationToken,
) -> Result<MultiScanReport> {
    let patterns: Vec<&[u8]> = patterns.iter().map(|pattern| pattern.as_slice()).collect();
    scan_pattern_sets_cpu_cancellable(
        image,
        &[ScanPatternSet {
            patterns: &patterns,
            limit_per_pattern,
            ascii_case_insensitive: false,
        }],
        chunk_size,
        cancellation,
    )
}

pub(crate) fn work_chunks(
    image: &MemoryImage,
    pattern_len: usize,
    chunk_size: usize,
) -> Result<Vec<WorkChunk>> {
    let worker_count = rayon::current_num_threads().max(1);
    let per_worker_budget = PARALLEL_SCAN_BUFFER_BUDGET_BYTES
        .checked_div(worker_count)
        .unwrap_or(pattern_len)
        .max(pattern_len);
    let chunk_size = chunk_size.min(per_worker_budget);
    let mut chunks = Vec::new();
    for (range_start, range_length) in acquired_ranges(image) {
        let mut consumed = 0u64;
        while consumed < range_length {
            let core_len = (range_length - consumed).min(chunk_size as u64) as usize;
            let overlap =
                (pattern_len - 1).min((range_length - consumed - core_len as u64) as usize);
            chunks.push(WorkChunk {
                physical_start: range_start + consumed,
                core_len,
                scan_len: core_len + overlap,
            });
            consumed += core_len as u64;
        }
    }
    Ok(chunks)
}

fn acquired_ranges(image: &MemoryImage) -> Vec<(u64, u64)> {
    let mut ranges = Vec::<(u64, u64)>::new();
    for span in image.spans() {
        if let Some((start, length)) = ranges.last_mut()
            && start.saturating_add(*length) == span.start
        {
            *length = length.saturating_add(span.length);
        } else {
            ranges.push((span.start, span.length));
        }
    }
    ranges
}

fn legacy_scan_offset(image: &MemoryImage, physical_address: u64) -> u64 {
    image
        .source_location(physical_address)
        .map(|location| location.legacy_offset())
        .unwrap_or(physical_address)
}

fn duration_seconds(elapsed: Duration) -> f64 {
    elapsed.as_secs_f64().max(f64::EPSILON)
}

fn throughput(bytes: u64, elapsed: Duration) -> f64 {
    bytes as f64 / 1024f64.powi(3) / duration_seconds(elapsed)
}

fn physical_scan_label(image: &MemoryImage) -> String {
    let name = image
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("内存镜像");
    format!("物理扫描 {name}")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn finds_pattern_crossing_chunk_boundary_once() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("starmem-scan-{}-{nonce}.raw", std::process::id()));
        fs::write(&path, b"xxxxABCDEFyyyy").unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let report = scan_exact(&image, b"ABCDEF", 10, 7).unwrap();
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].physical_address, 4);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn cancelled_scan_returns_typed_error_before_work() {
        use crate::cancellation::{CancellationHandle, is_cancellation_error};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-cancelled-scan-{}-{nonce}.raw",
            std::process::id()
        ));
        fs::write(&path, vec![0u8; 1024 * 1024]).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let handle = CancellationHandle::new();
        let cancellation = handle.start();
        handle.cancel();

        let error = scan_exact_cancellable(&image, b"needle", 10, 4096, &cancellation)
            .expect_err("pre-cancelled scan must not start");
        assert!(is_cancellation_error(&error));

        let patterns: [&[u8]; 2] = [b"needle", b"n\0e\0e\0d\0l\0e\0"];
        let error = scan_patterns_cancellable(&image, &patterns, 10, 4096, &cancellation)
            .expect_err("pre-cancelled multi-pattern scan must not start");
        assert!(is_cancellation_error(&error));
        assert!(error.to_string().contains("STARMEM_CANCELLED"));

        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn two_byte_fast_path_preserves_overlap_and_duplicate_rules() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-two-byte-scan-{}-{nonce}.raw",
            std::process::id()
        ));
        fs::write(&path, b"ababa________").unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let report = scan_exact(&image, b"ab", 10, 2).unwrap();
        assert_eq!(
            report
                .hits
                .iter()
                .map(|hit| hit.physical_address)
                .collect::<Vec<_>>(),
            [0, 2]
        );
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn mixed_pattern_sets_keep_independent_case_rules() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-mixed-scan-{}-{nonce}.raw",
            std::process::id()
        ));
        fs::write(&path, b"cookie: File file").unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let insensitive = [b"Cookie:".as_slice()];
        let exact = [b"File".as_slice()];
        let report = scan_pattern_sets(
            &image,
            &[
                ScanPatternSet {
                    patterns: &insensitive,
                    limit_per_pattern: 10,
                    ascii_case_insensitive: true,
                },
                ScanPatternSet {
                    patterns: &exact,
                    limit_per_pattern: 10,
                    ascii_case_insensitive: false,
                },
            ],
            8,
        )
        .unwrap();
        assert_eq!(
            report
                .hits
                .iter()
                .map(|hit| (hit.pattern_index, hit.physical_address))
                .collect::<Vec<_>>(),
            [(0, 0), (1, 8)]
        );
        assert_eq!(report.truncated_patterns, [false, false]);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn streaming_multi_scan_preserves_chunk_overlap_and_pattern_indexes() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-streaming-scan-{}-{nonce}.raw",
            std::process::id()
        ));
        fs::write(&path, b"xxxxActiveSize.cx__ActiveSize.cy").unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let patterns: [&[u8]; 2] = [b"ActiveSize.cx", b"ActiveSize.cy"];
        let report = scan_patterns_streaming_cancellable(
            &image,
            &patterns,
            10,
            13,
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(
            report
                .hits
                .iter()
                .map(|hit| (hit.pattern_index, hit.physical_address))
                .collect::<Vec<_>>(),
            [(0, 4), (1, 19)]
        );
        assert_eq!(report.bytes_scanned, 32);
        assert!(!report.truncated);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn multi_scan_finds_pool_tags_in_one_pass() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-multiscan-{}-{nonce}.raw",
            std::process::id()
        ));
        fs::write(&path, b"xxTcpExxTcpLxxUdpAxx").unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let report = scan_exact_4(&image, &[*b"TcpE", *b"TcpL", *b"UdpA"], 10, 7).unwrap();
        assert_eq!(report.hits.len(), 3);
        assert_eq!(report.hits[0].pattern_index, 0);
        assert_eq!(report.hits[1].pattern_index, 1);
        assert_eq!(report.hits[2].pattern_index, 2);
        assert_eq!(report.bytes_scanned, 20);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn scan_engine_reuses_superset_pool_cache() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-engine-cache-{}-{nonce}.raw",
            std::process::id()
        ));
        fs::write(&path, b"xxProcxxFilexxFil\xe5xxTcpExx").unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let first = scan_exact_4(&image, &[*b"Proc"], 10, 8).unwrap();
        assert_eq!(first.hits.len(), 1);
        assert!(first.elapsed_seconds > 0.0);

        let cached =
            scan_exact_4(&image, &[*b"File", [b'F', b'i', b'l', b'e' | 0x80]], 10, 8).unwrap();
        assert_eq!(cached.hits.len(), 2);
        assert_eq!(cached.hits[0].pattern_index, 0);
        assert_eq!(cached.hits[0].physical_address, 8);
        assert_eq!(cached.hits[1].pattern_index, 1);
        assert_eq!(cached.hits[1].physical_address, 14);
        assert_eq!(cached.elapsed_seconds, 0.0);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn multi_scan_accepts_mixed_pattern_lengths() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "starmem-mixed-scan-{}-{nonce}.raw",
            std::process::id()
        ));
        fs::write(&path, b"xxhttp://example.test yyh\0t\0t\0p\0s\0:\0/\0/\0zz").unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let patterns: [&[u8]; 2] = [b"http://", b"h\0t\0t\0p\0s\0:\0/\0/\0"];
        let report = scan_patterns(&image, &patterns, 10, 19).unwrap();
        assert_eq!(report.hits.len(), 2);
        assert_eq!(report.bytes_scanned, 42);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn common_pool_cache_is_seeded_only_by_process_scan() {
        assert!(should_seed_common_pool_cache(&[*b"Proc"], 4 * 1024 * 1024));
        assert!(!should_seed_common_pool_cache(
            &[*b"Proc"],
            COMMON_POOL_SEED_MAX_IMAGE_BYTES + 1
        ));
        assert!(!should_seed_common_pool_cache(&[*b"File"], 4 * 1024 * 1024));
        assert!(!should_seed_common_pool_cache(
            &[*b"Proc", *b"File"],
            4 * 1024 * 1024
        ));
    }
}
