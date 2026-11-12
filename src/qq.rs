//! QQNT artifacts recovered from resident process memory, without opening the
//! live QQ client or assuming that its encrypted database has been recovered.
mod protobuf;
mod v8;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::address::{VirtualAddressRegion, X64AddressSpace};
use crate::cancellation::CancellationToken;
use crate::image::{MemoryImage, SourceLocation};
use crate::scan::scan_patterns_cancellable;
use crate::session::AnalysisSession;
use crate::windows::plugins::list_vads_cancellable;

const MAX_OBJECT_BYTES: usize = 64 * 1024;
const READ_BUDGET: usize = 128 * 1024 * 1024;
const REPORT_BUDGET: usize = 64 * 1024 * 1024;
const MAX_SOURCES: usize = 16;
const MAX_WARNINGS: usize = 128;

#[derive(Debug, Clone)]
pub struct QqScanOptions {
    pub pid: Option<u64>,
    pub limit: usize,
    pub anchor_limit: usize,
    pub process_space_limit: usize,
}

impl Default for QqScanOptions {
    fn default() -> Self {
        Self {
            pid: None,
            limit: 2048,
            anchor_limit: 4096,
            process_space_limit: 16,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QqSourceRange {
    pub virtual_address: u64,
    pub physical_address: u64,
    pub byte_length: usize,
    pub source: Option<SourceLocation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QqEvidence {
    pub pid: u64,
    pub process: String,
    pub eprocess: u64,
    pub directory_table_base: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub vad_start: u64,
    pub vad_end: u64,
    pub encoding: String,
    pub byte_length: usize,
    pub sha256: String,
    pub ranges: Vec<QqSourceRange>,
    pub structure_complete: bool,
    pub stop_reason: Option<String>,
    /// JSON Pointer within the decoded object; @json: denotes a UTF-8 byte
    /// offset inside a decoded log string, never a physical memory offset.
    pub value_path: String,
}

#[derive(Debug, Serialize)]
pub struct QqRecord {
    pub artifact_kind: String,
    pub data: Value,
    pub evidence: Vec<QqEvidence>,
    pub evidence_truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct QqScanReport {
    pub records: Vec<QqRecord>,
    pub processes: Vec<Value>,
    pub kind_counts: BTreeMap<String, usize>,
    pub raw_anchor_hits: usize,
    pub process_candidates_examined: usize,
    pub decoded_candidates: usize,
    pub rejected_candidates: usize,
    pub unassigned_anchors: usize,
    pub bytes_scanned: u64,
    pub virtual_bytes_read: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
    pub elapsed_seconds: f64,
}

fn warn(report: &mut QqScanReport, message: String) {
    report.complete = false;
    if report.warnings.len() < MAX_WARNINGS {
        report.warnings.push(message);
    }
}

/// QQ-specific signatures; no account numbers or case-specific text are used.
fn patterns() -> Vec<Vec<u8>> {
    vec![
        b"o\"\x05msgId".to_vec(),
        b"\"\x09senderUid".to_vec(),
        b"\xff\x0fA\x02o\"\x04type".to_vec(),
        b"{\"uid\":\"u_".to_vec(),
        "{\"uid\":\"u_"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect(),
        b"{\"req\":{\"msgId\"".to_vec(),
        b"{\"msgId\"".to_vec(),
        b"{\"account\":\"".to_vec(),
        // Native numbered message fields: msgId, or msgRandom when the
        // allocation header overwrote msgId; and independently framed elements.
        b"\x88\xc4\x13".to_vec(),
        b"\x90\xc4\x13".to_vec(),
        b"\x82\xf6\x13".to_vec(),
        b"\xc8\xfc\x15".to_vec(),
        b"\xd0\xfc\x15\x01\xea\x82\x16".to_vec(),
        b"{\"groupCode\":".to_vec(),
        "{\"groupCode\":"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect(),
    ]
}

pub fn scan_qq(
    session: &AnalysisSession,
    options: &QqScanOptions,
    cancellation: &CancellationToken,
) -> Result<QqScanReport> {
    ensure!(
        !session.kernel().is_x86_pae(),
        "qqscan 当前仅支持 Windows x64 的 QQNT 驻留结构"
    );
    ensure!(
        session.symbol_layout_exactness().is_exact(),
        "QQ 进程归属需要镜像对应的精确内核符号"
    );
    ensure!(
        (1..=16_384).contains(&options.limit),
        "QQ 结果上限必须为 1..16384"
    );
    ensure!(
        (1..=16_384).contains(&options.anchor_limit),
        "QQ 每类锚点上限必须为 1..16384"
    );
    ensure!(
        (1..=64).contains(&options.process_space_limit),
        "QQ 进程上限必须为 1..64"
    );
    let started = Instant::now();
    let image = session.image();
    let mut report = QqScanReport {
        records: Vec::new(), processes: Vec::new(), kind_counts: BTreeMap::new(),
        raw_anchor_hits: 0, process_candidates_examined: 0, decoded_candidates: 0,
        rejected_candidates: 0, unassigned_anchors: 0, bytes_scanned: 0,
        virtual_bytes_read: 0, complete: true, warnings: Vec::new(),
        limitations: vec![
            "结果是采集时驻留的 QQNT V8/JSON、原生 Protobuf 字段和客户端日志；不是完整聊天历史，也不证明实际发送、接收或执行。".into(),
            "仅在指定/自动识别的活动 QQ 进程内按页表和 VAD 核对；进程映射不单独证明数据由该进程创建。".into(),
            "遇缺页、覆盖、未知 V8 类型或对象引用即停止，不跨断点拼接；未解密 QQ 数据库，未解压 Windows 内存压缩存储。".into(),
            "同内容副本合并并保留来源；同消息 ID 的不同内容不合并，日志与消息正文分开。字段时间和状态码保持客户端原值。".into(),
            "原生 Protobuf 消息的外层分配长度可能已丢失，只恢复连续字段；独立文本元素不借用附近账号、消息 ID 或时间，字段号映射仅在已验证的 QQNT 样本范围内适用。".into(),
            "每对象最多 64 KiB，虚拟读取共 128 MiB，报告保留约 64 MiB，每记录最多 16 个来源；完整性仅指本次范围。".into(),
        ], elapsed_seconds: 0.0,
    };
    let processes = session.processes_cancellable(65536, cancellation)?;
    if !processes.complete {
        warn(&mut report, "活动进程枚举不完整".into());
    }
    for warning in &processes.warnings {
        warn(
            &mut report,
            format!("进程枚举/{}：{}", warning.kind, warning.message),
        );
    }
    let mut selected = processes
        .processes
        .iter()
        .filter(|p| {
            p.details.exit_time.is_none()
                && options
                    .pid
                    .map_or_else(|| p.name.eq_ignore_ascii_case("qq.exe"), |pid| p.pid == pid)
        })
        .collect::<Vec<_>>();
    selected.sort_by_key(|p| p.pid);
    if selected.len() > options.process_space_limit {
        warn(
            &mut report,
            format!(
                "候选 QQ 进程 {} 个，按 PID 顺序仅检查前 {} 个",
                selected.len(),
                options.process_space_limit
            ),
        );
        selected.truncate(options.process_space_limit);
    }
    if selected.is_empty() {
        warn(
            &mut report,
            "未找到选定的活动 QQ 进程；不能据此排除 QQ 残留".into(),
        );
        report.elapsed_seconds = started.elapsed().as_secs_f64();
        return Ok(report);
    }
    let patterns = patterns();
    let scan = scan_patterns_cancellable(
        image,
        &patterns.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        options.anchor_limit,
        16 * 1024 * 1024,
        cancellation,
    )?;
    report.bytes_scanned = scan.bytes_scanned;
    report.raw_anchor_hits = scan.hits.len();
    if scan.truncated {
        warn(
            &mut report,
            format!(
                "物理锚点扫描达到上限；各类截断状态：{:?}",
                scan.truncated_patterns
            ),
        );
    }
    let target_pages = scan
        .hits
        .iter()
        .map(|h| h.physical_address & !0xfff)
        .collect::<HashSet<_>>();
    let mut assigned = HashSet::new();
    let mut record_index = HashMap::new();
    let mut retained = 0;
    let mut budget_stopped = false;
    'processes: for process in selected {
        cancellation.check_cancelled()?;
        let dtb = process
            .details
            .user_directory_table_base
            .filter(|v| *v != 0)
            .or(process.details.directory_table_base)
            .unwrap_or(0);
        let mut diagnostic = json!({"pid":process.pid, "ppid":process.ppid, "name":process.name,
            "eprocess":process.eprocess, "directory_table_base":dtb,
            "image_path":process.details.image_path, "command_line":process.details.command_line});
        let space = match X64AddressSpace::new(image, dtb) {
            Ok(space) => space,
            Err(error) => {
                warn(&mut report, format!("PID {} 页表：{error}", process.pid));
                continue;
            }
        };
        let mapping = match space.reverse_translate_pages_detailed_with_limits(
            &target_pages,
            VirtualAddressRegion::User,
            8,
            2_000_000,
            131_072,
        ) {
            Ok(mapping) => mapping,
            Err(error) => {
                warn(
                    &mut report,
                    format!("PID {} 反向映射：{error}", process.pid),
                );
                continue;
            }
        };
        cancellation.check_cancelled()?;
        diagnostic["mapping"] = json!({"mapped_target_pages":mapping.mapped_target_pages,
            "page_table_read_failures":mapping.page_table_read_failures,
            "page_table_entries_examined":mapping.page_table_entries_examined,
            "traversal_limit_reached":mapping.traversal_limit_reached,
            "mapping_limit_exceeded":mapping.mapping_limit_exceeded,
            "alias_storage_limit_exceeded":mapping.alias_storage_limit_exceeded});
        if mapping.page_table_read_failures > 0
            || mapping.traversal_limit_reached
            || mapping.mapping_limit_exceeded
            || mapping.alias_storage_limit_exceeded
        {
            warn(
                &mut report,
                format!(
                    "PID {} 反向映射不完整，详见 processes[].mapping",
                    process.pid
                ),
            );
        }
        if mapping.mappings.is_empty() {
            report.processes.push(diagnostic);
            continue;
        }
        let vads = match list_vads_cancellable(
            image,
            session.kernel(),
            session.profile(),
            process.pid,
            65536,
            cancellation,
        ) {
            Ok(vads) => vads,
            Err(error) => {
                warn(&mut report, format!("PID {} VAD：{error}", process.pid));
                report.processes.push(diagnostic);
                continue;
            }
        };
        diagnostic["vad_complete"] = json!(vads.complete);
        diagnostic["vad_warnings"] = json!(vads.warnings);
        if !vads.complete {
            warn(
                &mut report,
                format!("PID {} VAD 或文件关联不完整，保留可核对区域", process.pid),
            );
        }
        report.processes.push(diagnostic);
        let mut candidate_order = scan.hits.iter().collect::<Vec<_>>();
        // Inspect message starts first, so a senderUid anchor inside the same
        // verified prefix does not produce a second, artificially ID-less row.
        candidate_order.sort_by_key(|h| (h.pattern_index, h.physical_address));
        let mut covered_messages = Vec::<(u64, u64)>::new();
        let mut covered_protobuf = Vec::<(u64, u64)>::new();
        for hit in candidate_order {
            let Some(aliases) = mapping.mappings.get(&(hit.physical_address & !0xfff)) else {
                continue;
            };
            let mut aliases = aliases.clone();
            aliases.sort_unstable();
            for virtual_page in aliases {
                cancellation.check_cancelled()?;
                let va = virtual_page + (hit.physical_address & 0xfff);
                let Some(vad) = vads.records.iter().find(|v| v.start <= va && va <= v.end) else {
                    continue;
                };
                // Revalidate the forward mapping before trusting a reverse alias.
                if space.translate(va).ok() != Some(hit.physical_address) {
                    continue;
                }
                assigned.insert((hit.pattern_index, hit.physical_address));
                if hit.pattern_index == 1
                    && covered_messages
                        .iter()
                        .any(|(start, end)| *start <= va && va < *end)
                {
                    continue;
                }
                if matches!(hit.pattern_index, 9..=12)
                    && covered_protobuf
                        .iter()
                        .any(|(start, end)| *start <= va && va < *end)
                {
                    continue;
                }
                if report.virtual_bytes_read >= READ_BUDGET || retained >= REPORT_BUDGET {
                    budget_stopped = true;
                    break 'processes;
                }
                let max_bytes = ((vad.end - va + 1).min(MAX_OBJECT_BYTES as u64) as usize)
                    .min(READ_BUDGET - report.virtual_bytes_read);
                let (bytes, ranges) = read_prefix(image, &space, va, max_bytes, cancellation)?;
                report.virtual_bytes_read += bytes.len();
                report.process_candidates_examined += 1;
                let decoded = decode_candidate(&bytes, hit.pattern_index);
                let (decoded, encoding) = match decoded {
                    Ok(result) => result,
                    Err(_) => {
                        report.rejected_candidates += 1;
                        continue;
                    }
                };
                report.decoded_candidates += 1;
                let len = decoded.consumed;
                if hit.pattern_index == 0 && numeric_text(decoded.value.get("msgId")) {
                    covered_messages.push((va, va + len as u64));
                }
                if matches!(hit.pattern_index, 8..=12) {
                    covered_protobuf.push((va, va + len as u64));
                }
                let mut ranges = ranges;
                ranges.retain(|r| r.virtual_address < va + len as u64);
                if let Some(last) = ranges.last_mut() {
                    last.byte_length = last
                        .byte_length
                        .min((va + len as u64 - last.virtual_address) as usize);
                }
                let source = QqEvidence {
                    pid: process.pid,
                    process: process.name.clone(),
                    eprocess: process.eprocess,
                    directory_table_base: dtb,
                    virtual_address: va,
                    physical_address: hit.physical_address,
                    vad_start: vad.start,
                    vad_end: vad.end,
                    encoding: encoding.into(),
                    byte_length: len,
                    sha256: hex::encode(Sha256::digest(&bytes[..len])),
                    ranges,
                    structure_complete: decoded.complete,
                    stop_reason: decoded.stop_reason,
                    value_path: String::new(),
                };
                let mut artifacts = Vec::new();
                if matches!(hit.pattern_index, 10..=12) {
                    artifacts.push((
                        "message_element".into(),
                        decoded.value.clone(),
                        String::new(),
                    ));
                } else {
                    extract(&decoded.value, "", 0, &mut artifacts);
                }
                if artifacts.len() >= 256 {
                    warn(
                        &mut report,
                        "单对象提取达到 256 项上限，嵌套产物可能未全部列出".into(),
                    );
                }
                for (kind, data, path) in artifacts {
                    let mut evidence = source.clone();
                    evidence.value_path = path;
                    if !retain_record(
                        &mut report,
                        &mut record_index,
                        &mut retained,
                        options.limit,
                        kind,
                        data,
                        evidence,
                    )? {
                        budget_stopped = true;
                        break 'processes;
                    }
                }
            }
        }
    }
    if budget_stopped {
        warn(
            &mut report,
            "QQ 记录、读取或报告存储预算达到上限，剩余候选尚未核对".into(),
        );
    }
    if report.rejected_candidates > 0 {
        let message = format!(
            "{} 个已映射候选损坏、缺页或使用未支持的序列化类型，未补造字段",
            report.rejected_candidates
        );
        warn(&mut report, message);
    }
    if report
        .records
        .iter()
        .any(|r| r.evidence.iter().any(|s| !s.structure_complete))
    {
        warn(
            &mut report,
            "包含不完整消息结构；每项保留停止原因和已验证字节区间".into(),
        );
    }
    report.unassigned_anchors = scan.hits.len().saturating_sub(assigned.len());
    for record in &report.records {
        *report
            .kind_counts
            .entry(record.artifact_kind.clone())
            .or_default() += 1;
    }
    report.elapsed_seconds = started.elapsed().as_secs_f64();
    Ok(report)
}

pub(crate) fn read_prefix(
    image: &MemoryImage,
    space: &X64AddressSpace<'_>,
    start: u64,
    max: usize,
    cancellation: &CancellationToken,
) -> Result<(Vec<u8>, Vec<QqSourceRange>)> {
    let mut bytes = Vec::new();
    let mut ranges = Vec::new();
    while bytes.len() < max {
        cancellation.check_cancelled()?;
        let va = start + bytes.len() as u64;
        let len = (max - bytes.len()).min(4096 - (va as usize & 4095));
        let Ok(pa) = space.translate(va) else {
            break;
        };
        let mut page = vec![0; len];
        if image.read_physical(pa, &mut page).is_err() {
            break;
        }
        bytes.extend_from_slice(&page);
        ranges.push(QqSourceRange {
            virtual_address: va,
            physical_address: pa,
            byte_length: len,
            source: image.source_location(pa),
        });
    }
    Ok((bytes, ranges))
}

fn decode_candidate(bytes: &[u8], pattern: usize) -> Result<(v8::Decoded, &'static str), String> {
    match pattern {
        0 | 1 => {
            let decoded = v8::decode_message_prefix(bytes, pattern == 0);
            if !valid_uid(decoded.value.get("senderUid"))
                || !valid_peer(&decoded.value)
                || !numeric_text(decoded.value.get("msgTime"))
            {
                return Err("消息必需字段未完整恢复".into());
            }
            Ok((decoded, "v8_message_fields"))
        }
        2 => v8::decode_ipc(bytes).map(|v| (v, "v8_wire_v15")),
        8 | 9 => {
            protobuf::decode_message(bytes, pattern == 8).map(|v| (v, "qqnt_protobuf_message"))
        }
        10 => protobuf::decode_element(bytes).map(|v| (v, "qqnt_protobuf_element")),
        11 | 12 => protobuf::decode_text_prefix(bytes, pattern == 11)
            .map(|v| (v, "qqnt_protobuf_text_fragment")),
        4 | 14 => {
            // Stop decoding text at the first invalid UTF-16 code unit. A valid
            // JSON prefix can survive even if the following heap bytes cannot.
            let units = bytes
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]));
            let text = char::decode_utf16(units)
                .map_while(|unit| unit.ok())
                .collect::<String>();
            let (value, end) = json_prefix(&text)?;
            let consumed = text[..end].encode_utf16().count() * 2;
            Ok((
                v8::Decoded {
                    value,
                    consumed,
                    complete: true,
                    stop_reason: None,
                },
                "json_utf16le",
            ))
        }
        _ => {
            let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
            let value = stream
                .next()
                .ok_or("缺少 JSON 对象")?
                .map_err(|e| e.to_string())?;
            Ok((
                v8::Decoded {
                    value,
                    consumed: stream.byte_offset(),
                    complete: true,
                    stop_reason: None,
                },
                "json_utf8",
            ))
        }
    }
}

fn json_prefix(text: &str) -> Result<(Value, usize), String> {
    let mut stream = serde_json::Deserializer::from_str(text).into_iter::<Value>();
    let value = stream
        .next()
        .ok_or("缺少 JSON 对象")?
        .map_err(|e| e.to_string())?;
    Ok((value, stream.byte_offset()))
}

fn valid_uid(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|s| {
        s.starts_with("u_")
            && (8..=64).contains(&s.len())
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    })
}

fn numeric_text(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty() && s.len() <= 24 && s.bytes().all(|c| c.is_ascii_digit()))
}

/// A QQNT group uses its numeric group code as peerUid. Do not accept a
/// numeric private-chat peer, or infer a group merely from a number.
fn valid_peer(value: &Value) -> bool {
    valid_uid(value.get("peerUid"))
        || (value.get("chatType").and_then(Value::as_u64) == Some(2)
            && valid_group_code(value.get("peerUid")))
}

fn valid_group_code(value: Option<&Value>) -> bool {
    numeric_text(value)
        && value
            .and_then(Value::as_str)
            .is_some_and(|s| (5..=20).contains(&s.len()) && s.parse::<u64>().is_ok_and(|v| v > 0))
}

fn pointer(path: &str, key: &str) -> String {
    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"))
}

fn extract(value: &Value, path: &str, depth: usize, out: &mut Vec<(String, Value, String)>) {
    if depth > 24 || out.len() >= 256 {
        return;
    }
    if let Some(object) = value.as_object() {
        let kind = if valid_uid(object.get("senderUid"))
            && valid_peer(value)
            && numeric_text(object.get("msgTime"))
        {
            Some(if numeric_text(object.get("msgId")) {
                "message"
            } else {
                "message_fragment"
            })
        } else if valid_group_code(object.get("groupCode"))
            && object.get("groupName").is_some_and(Value::is_string)
        {
            Some("group_profile")
        } else if valid_group_code(object.get("groupCode"))
            && valid_uid(object.get("uid"))
            && ["cardName", "nick", "role"]
                .iter()
                .any(|key| object.contains_key(*key))
        {
            Some("group_member")
        } else if valid_uid(object.get("uid"))
            && numeric_text(object.get("uin"))
            && ["nick", "nickName", "coreInfo", "baseInfo"]
                .iter()
                .any(|k| object.contains_key(*k))
        {
            Some("profile")
        } else if object
            .get("req")
            .is_some_and(|r| numeric_text(r.get("msgId")) && valid_peer(r))
            && object.contains_key("filePath")
        {
            Some("file_transfer")
        } else if numeric_text(object.get("msgId"))
            && valid_peer(value)
            && numeric_text(object.get("elementId"))
        {
            Some("transfer_request")
        } else if object.get("categoryId").is_some_and(Value::is_number)
            && object.get("categroyName").is_some_and(Value::is_string)
            && object
                .get("buddyUids")
                .and_then(Value::as_array)
                .is_some_and(|uids| uids.iter().all(|uid| valid_uid(Some(uid))))
        {
            Some("contact_group")
        } else {
            None
        };
        if let Some(kind) = kind {
            out.push((kind.into(), value.clone(), path.into()));
            return;
        }
        for (key, child) in object {
            extract(child, &pointer(path, key), depth + 1, out);
        }
    } else if let Some(array) = value.as_array() {
        if array.len() == 2
            && array[0].get("eventName").and_then(Value::as_str) == Some("ntApi")
            && array[1]
                .get("cmdName")
                .and_then(Value::as_str)
                .is_some_and(|cmd| {
                    cmd.starts_with("nodeIKernelMsgService/")
                        || cmd.starts_with("nodeIKernelFlashTransferService/")
                })
        {
            out.push(("ipc_request".into(), value.clone(), path.into()));
        }
        if array.len() == 2
            && array[0].get("eventName").and_then(Value::as_str) == Some("LogApi")
            && let Some(payload) = array[1].get("payload").and_then(Value::as_array)
        {
            for (i, text) in payload.iter().enumerate().filter(|(_, v)| v.is_string()) {
                if out.len() >= 256 {
                    break;
                }
                out.push((
                    "client_log".into(),
                    json!({"event_name":"LogApi", "command":array[1].get("cmdName"), "text":text}),
                    format!("{path}/1/payload/{i}"),
                ));
            }
        }
        for (i, child) in array.iter().enumerate() {
            extract(child, &format!("{path}/{i}"), depth + 1, out);
        }
    } else if let Some(text) = value.as_str() {
        // Extract only independently valid JSON values from log strings. This
        // is a nested textual source, not another physical memory occurrence.
        let mut offset = 0;
        for _ in 0..32 {
            let Some(relative) = text[offset..].find('{') else {
                break;
            };
            let start = offset + relative;
            match json_prefix(&text[start..]) {
                Ok((nested, consumed)) => {
                    extract(&nested, &format!("{path}/@json:{start}"), depth + 1, out);
                    offset = start + consumed;
                }
                Err(_) => offset = start + 1,
            }
        }
    }
}

fn retain_record(
    report: &mut QqScanReport,
    index: &mut HashMap<String, usize>,
    retained: &mut usize,
    limit: usize,
    kind: String,
    data: Value,
    source: QqEvidence,
) -> Result<bool> {
    let canonical = serde_json::to_vec(&data)?;
    let key = format!("{kind}:{}", hex::encode(Sha256::digest(&canonical)));
    let source_bytes = serde_json::to_vec(&source)?.len();
    if let Some(&at) = index.get(&key) {
        let record = &mut report.records[at];
        if record.evidence.iter().any(|e| {
            e.pid == source.pid
                && e.virtual_address == source.virtual_address
                && e.value_path == source.value_path
        }) {
            return Ok(true);
        }
        if record.evidence.len() >= MAX_SOURCES {
            record.evidence_truncated = true;
            report.complete = false;
            return Ok(true);
        }
        if *retained + source_bytes > REPORT_BUDGET {
            return Ok(false);
        }
        *retained += source_bytes;
        record.evidence.push(source);
    } else {
        if report.records.len() >= limit
            || *retained + canonical.len() + source_bytes > REPORT_BUDGET
        {
            return Ok(false);
        }
        *retained += canonical.len() + source_bytes;
        index.insert(key, report.records.len());
        report.records.push(QqRecord {
            artifact_kind: kind,
            data,
            evidence: vec![source],
            evidence_truncated: false,
        });
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_profile_and_transfer_keep_separate_source_paths() {
        let value = json!([{"eventName":"LogApi"}, {"cmdName":"info", "payload":[
            "[AuthStore] {\"uid\":\"u_abcdefgh\",\"uin\":\"12345678\",\"nickName\":\"小明\"}",
            "file {\"req\":{\"msgId\":\"100\",\"peerUid\":\"u_abcdefgh\"},\"filePath\":\"C:/demo.zip\"}"
        ]}]);
        let mut out = Vec::new();
        extract(&value, "", 0, &mut out);
        assert_eq!(out.iter().filter(|r| r.0 == "client_log").count(), 2);
        assert!(
            out.iter()
                .any(|r| r.0 == "profile" && r.2 == "/1/payload/0/@json:12")
        );
        assert!(out.iter().any(|r| r.0 == "file_transfer"));
    }

    #[test]
    fn fragment_never_borrows_message_id_from_neighbor_or_element() {
        let value = json!({"senderUid":"u_abcdefgh", "peerUid":"u_ijklmnop", "msgTime":"1759702026", "elements":[{"elementId":"555", "textElement":{"content":"你好"}}], "neighbor":{"msgId":"999"}});
        let mut out = Vec::new();
        extract(&value, "", 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "message_fragment");
        assert!(out[0].1.get("msgId").is_none());
    }

    #[test]
    fn json_utf16_counts_bytes_and_ignores_unrelated_invalid_tail() {
        let text = "{\"uid\":\"u_abcdefgh\",\"uin\":\"123456\",\"nick\":\"🍔\"}";
        let mut bytes = text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let length = bytes.len();
        bytes.extend_from_slice(&[0, 0xd8]);
        let (value, _) = decode_candidate(&bytes, 4).unwrap();
        assert_eq!(value.consumed, length);
        assert_eq!(value.value["nick"], "🍔");
    }

    #[test]
    fn generic_strings_and_broken_uid_do_not_become_profiles() {
        let mut out = Vec::new();
        extract(
            &json!({"uid":"not-a-qq-uid", "uin":"123", "nick":"example"}),
            "",
            0,
            &mut out,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn buddy_groups_and_read_requests_preserve_observed_semantics() {
        let mut out = Vec::new();
        extract(
            &json!({"categoryId":0,"categroyName":"我的好友","buddyUids":["u_abcdefgh"]}),
            "",
            0,
            &mut out,
        );
        assert_eq!(out[0].0, "contact_group");
        out.clear();
        extract(
            &json!([{"eventName":"ntApi"},{"cmdName":"nodeIKernelMsgService/setMsgRead","payload":[{"peerUid":"u_abcdefgh"}]}]),
            "",
            0,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "ipc_request");
        assert!(out[0].1.get("read_success").is_none());
    }

    #[test]
    fn numeric_group_peer_requires_explicit_group_chat_type() {
        let message = json!({"senderUid":"u_abcdefgh","peerUid":"123456789",
            "chatType":2,"msgTime":"1790931579","msgId":"9223372036854775809"});
        let mut out = Vec::new();
        extract(&message, "", 0, &mut out);
        assert_eq!(out[0].0, "message");
        assert_eq!(out[0].1["peerUid"], "123456789");
        for chat_type in [json!(1), json!(null), json!("2")] {
            let mut invalid = message.clone();
            invalid["chatType"] = chat_type;
            out.clear();
            extract(&invalid, "", 0, &mut out);
            assert!(out.is_empty());
        }
    }

    #[test]
    fn group_profiles_in_logs_are_distinct_from_buddy_categories() {
        let log = json!(
            "[Render][ContactGroupStore] onGroupListUpdate: list = [{\"groupCode\":\"123456789\",\"groupName\":\"测试群\",\"memberCount\":12}]"
        );
        let mut out = Vec::new();
        extract(&log, "/1/payload/0", 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "group_profile");
        assert!(out[0].2.contains("@json:"));
        assert!(out[0].1.get("buddyUids").is_none());
        out.clear();
        extract(
            &json!({"groupCode":"123456789","uid":"u_abcdefgh","uin":"123456789","nick":"成员昵称","cardName":"群内名片"}),
            "",
            0,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "group_member");
        assert_eq!(out[0].1["cardName"], "群内名片");
        let bytes = "{\"groupCode\":\"123456789\",\"groupName\":\"🍔群\"}"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            decode_candidate(&bytes, 14).unwrap().0.consumed,
            bytes.len()
        );
    }
}
