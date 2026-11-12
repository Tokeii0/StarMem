//! WeChat chat evidence recovered from resident WCDB/SQLite process caches.
//! This does not need a database key and never opens a live user's databases.
mod cache;
mod model;

use crate::{
    address::{VirtualAddressRegion, X64AddressSpace},
    cancellation::CancellationToken,
    cookies::SqliteSourceRange,
    qq::{QqEvidence, QqSourceRange, read_prefix},
    scan::scan_patterns_cancellable,
    session::AnalysisSession,
    windows::plugins::list_vads_cancellable,
};
use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    time::Instant,
};

const READ_BUDGET: usize = 128 * 1024 * 1024;
const REPORT_BUDGET: usize = 64 * 1024 * 1024;
const WARNING_LIMIT: usize = 128;

#[derive(Debug, Clone)]
pub struct WechatChatOptions {
    pub pid: Option<u64>,
    pub limit: usize,
    pub anchor_limit: usize,
    pub process_space_limit: usize,
    pub cache_limit: usize,
    pub cache_page_limit: usize,
}
impl Default for WechatChatOptions {
    fn default() -> Self {
        Self {
            pid: None,
            limit: 2048,
            anchor_limit: 4096,
            process_space_limit: 16,
            cache_limit: 64,
            cache_page_limit: 4096,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct WechatChatEvidence {
    #[serde(flatten)]
    pub memory: QqEvidence,
    pub sqlite_table: String,
    pub sqlite_rowid: String,
    pub pcache1_address: u64,
    pub pager_address: u64,
    pub sha256_scope: &'static str,
    /// Cache metadata, schema and Name2Id sources used for this row. These are
    /// separate from the row bytes included in sha256.
    pub dependency_ranges: Vec<QqSourceRange>,
}
#[derive(Debug, Serialize)]
pub struct WechatChatRecord {
    pub artifact_kind: String,
    pub data: Value,
    pub evidence: Vec<WechatChatEvidence>,
    pub evidence_truncated: bool,
}
#[derive(Debug, Serialize)]
pub struct WechatChatReport {
    pub records: Vec<WechatChatRecord>,
    pub processes: Vec<Value>,
    pub caches: Vec<Value>,
    pub kind_counts: BTreeMap<String, usize>,
    pub raw_anchor_hits: usize,
    pub rejected_candidates: usize,
    pub bytes_scanned: u64,
    pub virtual_bytes_read: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
    pub elapsed_seconds: f64,
}
fn warn(report: &mut WechatChatReport, message: impl Into<String>) {
    report.complete = false;
    if report.warnings.len() < WARNING_LIMIT {
        report.warnings.push(message.into());
    }
}

fn row_ranges(cache: &cache::Cache, ranges: &[SqliteSourceRange]) -> Vec<(u64, usize)> {
    let mut out = Vec::new();
    for r in ranges {
        let mut offset = r.file_offset;
        let mut left = r.length;
        while left > 0 {
            let number = (offset / cache.page_size as u64 + 1) as u32;
            let Some(page) = cache.pages.get(&number) else {
                return Vec::new();
            };
            let within = offset % cache.page_size as u64;
            let len = left.min(cache.page_size as u64 - within) as usize;
            out.push((page.data_address + within, len));
            offset += len as u64;
            left -= len as u64;
        }
    }
    out
}

pub fn scan_wechat_chat(
    session: &AnalysisSession,
    options: &WechatChatOptions,
    token: &CancellationToken,
    progress: &mut impl FnMut(&str),
) -> Result<WechatChatReport> {
    ensure!(
        !session.kernel().is_x86_pae() && session.symbol_layout_exactness().is_exact(),
        "微信进程缓存解析需要 Windows x64 与精确内核符号"
    );
    ensure!(
        (1..=16384).contains(&options.limit) && (1..=16384).contains(&options.anchor_limit),
        "微信结果或锚点上限必须为 1..16384"
    );
    ensure!(
        (1..=64).contains(&options.process_space_limit)
            && (1..=128).contains(&options.cache_limit)
            && (1..=16384).contains(&options.cache_page_limit),
        "微信进程、缓存或页数上限无效"
    );
    let started = Instant::now();
    let image = session.image();
    let mut report = WechatChatReport { records:Vec::new(), processes:Vec::new(), caches:Vec::new(),
        kind_counts:BTreeMap::new(), raw_anchor_hits:0, rejected_candidates:0,
        bytes_scanned:0, virtual_bytes_read:0, complete:true, warnings:Vec::new(),
        limitations: vec![
            "已验证微信 Windows 4.1.15.13 的 x64 WCDB 默认 SQLite 页缓存布局；其他版本、定制页缓存及旧版消息表可能不支持。".into(),
            "结果仅覆盖采集时完整驻留且可互指验证的缓存页，不是完整聊天历史；未解密落盘数据库或内存压缩存储。".into(),
            "消息会话通过同一缓存 Name2Id 用户名的 UTF-8 MD5 与 Msg_ 表名关联；发送者通过同一缓存的 real_sender_id 与 rowid 关联。缺映射时不借用其他缓存或附近账号。".into(),
            "联系人、Name2Id 和会话摘要不证明当前登录身份或好友关系；消息方向未从首行 ID、状态码或附近资料推定。".into(),
            "正文支持 SQLite UTF-8 TEXT 与有完整 Zstd 帧的 UTF-8 内容；其他编码、压缩字典和非文本附件本体不恢复。XML 保持客户端原始内容。".into(),
            "单库逻辑范围最多 64 MiB，进程读取共 128 MiB，报告约 64 MiB；缓存缺页不补为证据，报告保留结构、地址、精确范围及哈希。".into(),
        ], elapsed_seconds:0.0 };
    progress("正在枚举活动微信进程");
    let processes = session.processes_cancellable(65536, token)?;
    if !processes.complete {
        warn(&mut report, "活动进程枚举不完整");
    }
    let mut selected = processes
        .processes
        .iter()
        .filter(|p| {
            p.details.exit_time.is_none()
                && options.pid.map_or_else(
                    || {
                        ["weixin.exe", "wechat.exe"]
                            .iter()
                            .any(|name| p.name.eq_ignore_ascii_case(name))
                    },
                    |pid| pid == p.pid,
                )
        })
        .collect::<Vec<_>>();
    selected.sort_by_key(|p| p.pid);
    if selected.len() > options.process_space_limit {
        warn(
            &mut report,
            format!(
                "微信地址空间 {} 个，仅检查前 {} 个",
                selected.len(),
                options.process_space_limit
            ),
        );
        selected.truncate(options.process_space_limit);
    }
    if selected.is_empty() {
        warn(&mut report, "未找到选定活动微信进程，不能据此排除微信残留");
        return Ok(report);
    }
    progress("正在定位 SQLite 缓存文件头");
    let scan = scan_patterns_cancellable(
        image,
        &[b"SQLite format 3\0"],
        options.anchor_limit,
        16 * 1024 * 1024,
        token,
    )?;
    report.bytes_scanned = scan.bytes_scanned;
    report.raw_anchor_hits = scan.hits.len();
    if scan.truncated {
        warn(&mut report, "SQLite 物理锚点达到本次上限，剩余候选未检查");
    }
    let pages = scan
        .hits
        .iter()
        .map(|h| h.physical_address & !4095)
        .collect::<HashSet<_>>();
    let mut seen_caches = HashSet::new();
    let mut retained = 0usize;
    'processes: for process in selected {
        token.check_cancelled()?;
        let dtb = process
            .details
            .user_directory_table_base
            .filter(|v| *v != 0)
            .or(process.details.directory_table_base)
            .unwrap_or(0);
        let space = X64AddressSpace::new(image, dtb)?;
        progress(&format!(
            "正在核对微信 PID {} 的页表与缓存归属",
            process.pid
        ));
        let mapping = space.reverse_translate_pages_detailed_with_limits(
            &pages,
            VirtualAddressRegion::User,
            8,
            2_000_000,
            131_072,
        )?;
        token.check_cancelled()?;
        let vads = list_vads_cancellable(
            image,
            session.kernel(),
            session.profile(),
            process.pid,
            65536,
            token,
        )?;
        let mut diagnostic = json!({"pid":process.pid,"name":process.name,"eprocess":process.eprocess,
            "directory_table_base":dtb,"image_path":process.details.image_path,"mapped_target_pages":mapping.mapped_target_pages,
            "page_table_read_failures":mapping.page_table_read_failures,"vad_complete":vads.complete,
            "traversal_limit_reached":mapping.traversal_limit_reached,"mapping_limit_exceeded":mapping.mapping_limit_exceeded,
            "alias_storage_limit_exceeded":mapping.alias_storage_limit_exceeded,"caches_checked":0});
        if !vads.complete
            || mapping.page_table_read_failures > 0
            || mapping.traversal_limit_reached
            || mapping.mapping_limit_exceeded
            || mapping.alias_storage_limit_exceeded
        {
            warn(
                &mut report,
                format!("PID {} 页表或 VAD 范围不完整，详见进程诊断", process.pid),
            );
        }
        let mut cache_count = 0;
        for hit in &scan.hits {
            let Some(aliases) = mapping.mappings.get(&(hit.physical_address & !4095)) else {
                continue;
            };
            for &page in aliases {
                token.check_cancelled()?;
                let va = page + (hit.physical_address & 4095);
                let Some(_vad) = vads.records.iter().find(|v| v.start <= va && va <= v.end) else {
                    continue;
                };
                if space.translate(va).ok() != Some(hit.physical_address) {
                    continue;
                }
                if report.virtual_bytes_read >= READ_BUDGET
                    || report.caches.len() >= options.cache_limit
                {
                    warn(&mut report, "微信缓存数量或读取预算达到上限");
                    report.processes.push(diagnostic);
                    break 'processes;
                }
                let mut read = |at: u64, len: usize| -> Result<Option<Vec<u8>>> {
                    token.check_cancelled()?;
                    if len > READ_BUDGET.saturating_sub(report.virtual_bytes_read) {
                        return Ok(None);
                    }
                    let Some(end) = at.checked_add(len as u64) else {
                        return Ok(None);
                    };
                    if !vads
                        .records
                        .iter()
                        .any(|v| v.start <= at && end <= v.end.saturating_add(1))
                    {
                        return Ok(None);
                    }
                    let (b, _) = read_prefix(image, &space, at, len, token)?;
                    report.virtual_bytes_read += b.len();
                    Ok((b.len() == len).then_some(b))
                };
                let recovered = cache::recover(va, options.cache_page_limit, &mut read);
                let cache = match recovered {
                    Ok(c) => c,
                    Err(error) => {
                        token.check_cancelled()?;
                        report.rejected_candidates += 1;
                        // Constants in executable pages and stale headers are
                        // rejected candidates, not failures to read chat history.
                        let _ = error;
                        continue;
                    }
                };
                if !seen_caches.insert((process.pid, cache.cache_address, cache.pager_address)) {
                    continue;
                }
                cache_count += 1;
                progress(&format!(
                    "正在解析微信 PID {} 缓存 {}，已恢复 {} 条证据",
                    process.pid,
                    cache_count,
                    report.records.len()
                ));
                for w in &cache.warnings {
                    warn(
                        &mut report,
                        format!("PID {} / 0x{:x}：{w}", process.pid, cache.cache_address),
                    );
                }
                let cache_diag = json!({"pid":process.pid,"cache_address":cache.cache_address,"pager_address":cache.pager_address,
                    "pcache_address":cache.pcache_address,"sqlite_header_va":cache.header_address,"hash_address":cache.hash_address,
                    "page_size":cache.page_size,"declared_cache_pages":cache.declared_pages,"resident_cache_pages":cache.pages.len(),
                    "warnings":cache.warnings,"pages":cache.pages.values().map(|p|json!({"number":p.number,
                    "data_va":p.data_address,"header_va":p.header_address,"pghdr_va":p.extra_address,"bucket_va":p.bucket_address,
                    "sha256":hex::encode(Sha256::digest(&p.bytes))})).collect::<Vec<_>>()});
                let diag_len = serde_json::to_vec(&cache_diag)?.len();
                if diag_len > REPORT_BUDGET.saturating_sub(retained) {
                    warn(&mut report, "微信缓存诊断达到报告存储预算");
                    report.processes.push(diagnostic);
                    break 'processes;
                }
                retained += diag_len;
                report.caches.push(cache_diag);
                let (artifacts, warnings) = match model::parse(
                    &cache,
                    options.limit.saturating_sub(report.records.len()),
                    &mut || token.check_cancelled(),
                ) {
                    Ok(v) => v,
                    Err(error) => {
                        token.check_cancelled()?;
                        warn(
                            &mut report,
                            format!(
                                "PID {} / 缓存 0x{:x} 解析失败：{error}",
                                process.pid, cache.cache_address
                            ),
                        );
                        continue;
                    }
                };
                for w in warnings {
                    warn(
                        &mut report,
                        format!("PID {} / 0x{:x}：{w}", process.pid, cache.cache_address),
                    );
                }
                for artifact in artifacts {
                    token.check_cancelled()?;
                    let row_spans = row_ranges(&cache, &artifact.ranges);
                    if row_spans.is_empty() {
                        warn(&mut report, "消息行范围缺失，排除该记录");
                        continue;
                    }
                    let mut dependencies = row_ranges(&cache, &artifact.dependencies);
                    dependencies.push((cache.header_address, 100));
                    dependencies.push((cache.cache_address, 72));
                    let mut dependency_pages = artifact
                        .ranges
                        .iter()
                        .chain(&artifact.dependencies)
                        .map(|r| r.page_number)
                        .collect::<HashSet<_>>();
                    dependency_pages.insert(1);
                    for n in dependency_pages {
                        if let Some(p) = cache.pages.get(&n) {
                            dependencies.extend([
                                (p.header_address, 56),
                                (p.extra_address, 72),
                                (p.bucket_address, 8),
                            ]);
                        }
                    }
                    dependencies.sort_unstable();
                    dependencies.dedup();
                    let proof_bytes = row_spans
                        .iter()
                        .chain(&dependencies)
                        .map(|(_, len)| *len)
                        .sum::<usize>();
                    if proof_bytes > READ_BUDGET.saturating_sub(report.virtual_bytes_read) {
                        warn(&mut report, "微信证据来源重读达到读取预算");
                        report.processes.push(diagnostic);
                        break 'processes;
                    }
                    let mut bytes = Vec::new();
                    let mut ranges = Vec::new();
                    for &(at, len) in &row_spans {
                        let (b, r) = read_prefix(image, &space, at, len, token)?;
                        ensure!(b.len() == len, "已核对缓存行无法重读");
                        bytes.extend(b);
                        ranges.extend(r);
                    }
                    let mut dependency_ranges = Vec::new();
                    for (at, len) in dependencies {
                        let (b, r) = read_prefix(image, &space, at, len, token)?;
                        ensure!(b.len() == len, "缓存关联来源无法重读");
                        dependency_ranges.extend(r);
                    }
                    report.virtual_bytes_read += proof_bytes;
                    let first = &ranges[0];
                    let row_vad = vads
                        .records
                        .iter()
                        .find(|v| {
                            v.start <= first.virtual_address && first.virtual_address <= v.end
                        })
                        .ok_or_else(|| anyhow::anyhow!("消息行不在已核对的 VAD 中"))?;
                    let evidence = WechatChatEvidence {
                        memory: QqEvidence {
                            pid: process.pid,
                            process: process.name.clone(),
                            eprocess: process.eprocess,
                            directory_table_base: dtb,
                            virtual_address: first.virtual_address,
                            physical_address: first.physical_address,
                            vad_start: row_vad.start,
                            vad_end: row_vad.end,
                            encoding: "sqlite_pcache_x64".into(),
                            byte_length: bytes.len(),
                            sha256: hex::encode(Sha256::digest(&bytes)),
                            ranges,
                            structure_complete: true,
                            stop_reason: None,
                            value_path: "/raw_columns".into(),
                        },
                        sqlite_table: artifact.table,
                        sqlite_rowid: artifact.rowid.to_string(),
                        pcache1_address: cache.cache_address,
                        pager_address: cache.pager_address,
                        sha256_scope: "row ranges concatenated in listed order",
                        dependency_ranges,
                    };
                    let mut data = artifact.data;
                    data["cache_scope"] = json!(format!(
                        "{}:0x{:x}:0x{:x}",
                        process.pid, cache.cache_address, cache.pager_address
                    ));
                    let record = WechatChatRecord {
                        artifact_kind: artifact.kind.into(),
                        data,
                        evidence: vec![evidence],
                        evidence_truncated: false,
                    };
                    let len = serde_json::to_vec(&record)?.len();
                    if len > REPORT_BUDGET.saturating_sub(retained) {
                        warn(&mut report, "微信报告达到 64 MiB 存储预算");
                        report.processes.push(diagnostic);
                        break 'processes;
                    }
                    retained += len;
                    *report
                        .kind_counts
                        .entry(record.artifact_kind.clone())
                        .or_default() += 1;
                    report.records.push(record);
                }
                if report.records.len() >= options.limit {
                    warn(&mut report, "微信记录达到结果上限，剩余缓存未检查");
                    report.processes.push(diagnostic);
                    break 'processes;
                }
            }
        }
        diagnostic["caches_checked"] = json!(cache_count);
        report.processes.push(diagnostic);
    }
    if report.virtual_bytes_read >= READ_BUDGET {
        warn(&mut report, "微信读取预算耗尽");
    }
    if report.caches.is_empty() {
        warn(
            &mut report,
            "未恢复可验证的微信 SQLite 页缓存；未驻留或未支持的布局不代表没有聊天记录",
        );
    }
    report.elapsed_seconds = started.elapsed().as_secs_f64();
    Ok(report)
}
