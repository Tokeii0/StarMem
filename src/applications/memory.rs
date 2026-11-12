//! Anchor discovery is physical; attribution and decoding use validated process
//! page tables and a containing VAD. Missing pages terminate each object.
use super::{
    ApplicationKind, ApplicationOptions, ApplicationRecord, ApplicationReport, ai, office, remote,
    storage,
};
use crate::{
    address::{VirtualAddressRegion, X64AddressSpace},
    cancellation::CancellationToken,
    scan::scan_patterns_cancellable,
    session::AnalysisSession,
    windows::plugins::list_vads_cancellable,
};
use anyhow::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

fn anchors(kind: ApplicationKind) -> Vec<&'static str> {
    match kind {
        ApplicationKind::Ai => vec![
            "\"role\"",
            "\"conversation_id\"",
            "\"sessionId\"",
            "\"bubbleId\"",
            "\"user_message\"",
            "\"agent_message\"",
            "\"messageType\"",
            "\"req_id\"",
            "\"biz_id\"",
            "\"serviceid\"",
            "\"local_message_id\"",
        ],
        ApplicationKind::Huorong => vec!["\"recname\"", "\"pathname\"", "QUARAN_restore"],
        ApplicationKind::Anydesk | ApplicationKind::Sunlogin => remote::anchors(kind),
        ApplicationKind::Veracrypt => {
            vec!["<volume", "Volume=", "VeraCrypt.xml", "Favorite Volumes"]
        }
        ApplicationKind::Bitlocker => vec![
            "BitLocker",
            "FVE-FS",
            "RecoveryKeyId",
            "Volume{",
            "EncryptionMethod",
        ],
        ApplicationKind::Wps => vec![
            "<w:t",
            "<a:t",
            "<t>",
            "<t ",
            "\"user_id\"",
            "\"userid\"",
            "\"nickname\"",
            "\"email\"",
            "\"username\"",
            "\\Documents\\",
            "\\Desktop\\",
            "file:///",
            "RecentFiles",
            "Recent File List",
            "\"filePath\"",
            "\"file_path\"",
            "\"document\"",
            ".docx",
            ".xlsx",
            ".wps",
        ],
    }
}

pub(super) fn analyze(
    session: &AnalysisSession,
    kind: ApplicationKind,
    options: &ApplicationOptions,
    token: &CancellationToken,
    report: &mut ApplicationReport,
) -> Result<()> {
    if session.kernel().is_x86_pae() || !session.symbol_layout_exactness().is_exact() {
        report.source(
            "process_memory",
            false,
            false,
            0,
            vec!["进程内存解析需要 Windows x64 与精确内核符号".into()],
            Value::Null,
        );
        return Ok(());
    }
    let processes = match session.processes_cancellable(65536, token) {
        Ok(p) => p,
        Err(e) => {
            report.failure("process_memory", e)?;
            return Ok(());
        }
    };
    let mut selected: Vec<_> = processes
        .processes
        .iter()
        .filter(|p| {
            p.details.exit_time.is_none()
                && options.pid.map_or_else(
                    || {
                        kind.executable(&p.name)
                            || kind == ApplicationKind::Ai
                                && p.details
                                    .image_path
                                    .as_deref()
                                    .and_then(ai::path_app)
                                    .is_some()
                    },
                    |pid| p.pid == pid,
                )
        })
        .collect();
    selected.sort_by_key(|p| p.pid);
    let count = selected.len();
    selected.truncate(options.process_limit);
    report.source(
        "memory_process_selection",
        true,
        processes.complete && count <= options.process_limit,
        count,
        if count == 0 {
            vec![
                "未发现活动目标进程；可用 --pid 明确指定进程，未扫描的退出进程不作为无痕迹结论"
                    .into(),
            ]
        } else {
            vec![]
        },
        json!({"selected":selected.len(),"explicit_pid":options.pid}),
    );
    if selected.is_empty() {
        if options.pid.is_none()
            && matches!(kind, ApplicationKind::Sunlogin | ApplicationKind::Anydesk)
        {
            physical_remote(session, kind, options, token, report)?;
        }
        return Ok(());
    }
    let texts = anchors(kind);
    let mut patterns = Vec::new();
    for t in &texts {
        patterns.push(t.as_bytes().to_vec());
        patterns.push(t.encode_utf16().flat_map(u16::to_le_bytes).collect());
    }
    let scan = scan_patterns_cancellable(
        session.image(),
        &patterns.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        options.anchor_limit,
        16 * 1024 * 1024,
        token,
    )?;
    report.source("memory_anchors",true,!scan.truncated,scan.hits.len(),
        if scan.truncated{vec!["某些锚点达到上限，后续同类内容可能遗漏；可提高 --anchor-limit".into()]}else{vec![]},
        json!({"bytes_scanned":scan.bytes_scanned,"truncated_patterns":scan.truncated_patterns,"patterns":texts}));
    let target_pages = scan
        .hits
        .iter()
        .map(|h| h.physical_address & !4095)
        .collect::<HashSet<_>>();
    let mut budget = 128 * 1024 * 1024usize;
    let selected_count = selected.len();
    for (process_index, p) in selected.into_iter().enumerate() {
        token.check_cancelled()?;
        if budget == 0 || report.truncated {
            report.source(
                "memory_budget",
                false,
                false,
                0,
                vec!["进程内存读取或报告预算已到达，剩余候选未检查".into()],
                Value::Null,
            );
            break;
        }
        let dtb = p
            .details
            .user_directory_table_base
            .filter(|v| *v != 0)
            .or(p.details.directory_table_base)
            .unwrap_or(0);
        let sid = format!("process_memory:{}:{:#x}", p.pid, p.eprocess);
        let space = match X64AddressSpace::new(session.image(), dtb) {
            Ok(s) => s,
            Err(e) => {
                report.failure(&sid, e)?;
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
            Ok(m) => m,
            Err(e) => {
                report.failure(&sid, e)?;
                continue;
            }
        };
        token.check_cancelled()?;
        let vads = match list_vads_cancellable(
            session.image(),
            session.kernel(),
            session.profile(),
            p.pid,
            65536,
            token,
        ) {
            Ok(v) => v,
            Err(e) => {
                report.failure(&sid, e)?;
                continue;
            }
        };
        report.source(&sid,true,vads.complete && mapping.page_table_read_failures==0 && !mapping.traversal_limit_reached && !mapping.mapping_limit_exceeded && !mapping.alias_storage_limit_exceeded,
            mapping.mapped_target_pages,vads.warnings,json!({"pid":p.pid,"eprocess":p.eprocess,"directory_table_base":dtb,"image_path":p.details.image_path,
                "page_table_read_failures":mapping.page_table_read_failures,"traversal_limit_reached":mapping.traversal_limit_reached,"mapping_limit_exceeded":mapping.mapping_limit_exceeded}));
        let app = ai::path_app(p.details.image_path.as_deref().unwrap_or(""))
            .or_else(|| ai::process_app(&p.name))
            .unwrap_or("指定进程");
        if kind == ApplicationKind::Ai {
            super::v8::analyze(
                session,
                &space,
                p.pid,
                p.eprocess,
                p.details.image_path.as_deref(),
                app,
                token,
                report,
            )?;
        }
        let mut retained = HashSet::new();
        let mut checked = HashSet::new();
        let mut rejected = 0;
        let mut process_budget = (budget / (selected_count - process_index)).min(32 * 1024 * 1024);
        let mut budget_hit = false;
        'hits: for hit in &scan.hits {
            let Some(aliases) = mapping.mappings.get(&(hit.physical_address & !4095)) else {
                continue;
            };
            for page in aliases {
                token.check_cancelled()?;
                if process_budget == 0 || budget == 0 || report.truncated {
                    budget_hit = true;
                    break 'hits;
                }
                let va = *page + (hit.physical_address & 4095);
                if space.translate(va).ok() != Some(hit.physical_address) {
                    continue;
                }
                let Some(vad) = vads.records.iter().find(|v| v.start <= va && va <= v.end) else {
                    continue;
                };
                let utf16 = hit.pattern_index % 2 == 1;
                // A small look-behind finds the enclosing JSON object; fallback
                // to the anchor's page when a preceding page is not resident.
                let mut start = va.saturating_sub(2048).max(vad.start);
                if utf16 {
                    start += (va - start) % 2;
                }
                if space.translate(start).is_err() {
                    start = va & !4095;
                }
                if !checked.insert((start, utf16)) {
                    continue;
                }
                let max = ((vad.end - start + 1).min(32 * 1024) as usize)
                    .min(budget)
                    .min(process_budget);
                let (bytes, ranges) = read_prefix(session, &space, start, max, token)?;
                budget = budget.saturating_sub(bytes.len());
                process_budget = process_budget.saturating_sub(bytes.len());
                if bytes.len() <= (va - start) as usize {
                    continue;
                }
                let anchor = (va - start) as usize;
                let mut decoded = Vec::new();
                let candidates = json_objects(&bytes, anchor, utf16);
                let mut found = false;
                for (offset, len, value) in candidates {
                    let items = if kind == ApplicationKind::Ai {
                        ai::extract(&value, app)
                    } else if kind == ApplicationKind::Huorong {
                        storage::huorong(&value).into_iter().collect()
                    } else if matches!(kind, ApplicationKind::Sunlogin | ApplicationKind::Anydesk) {
                        remote::extract(kind, &value)
                    } else if kind == ApplicationKind::Wps {
                        office::extract(&value)
                    } else {
                        Vec::new()
                    };
                    decoded.extend(items.into_iter().map(|item| (offset, len, item)));
                }
                if kind == ApplicationKind::Wps
                    && let Some(a) = office::xml_run(&bytes, anchor, utf16)
                {
                    decoded.push(a);
                }
                if matches!(kind, ApplicationKind::Sunlogin | ApplicationKind::Anydesk)
                    && let Some(a) = remote::nul_pair(kind, &bytes, anchor, utf16)
                {
                    decoded.push(a);
                }
                if let Some((off, len, line)) = line_fragment(&bytes, anchor, utf16) {
                    let step = if utf16 { 2 } else { 1 };
                    let boundary = |i: usize| {
                        bytes.get(i).is_some_and(|b| matches!(b, 0 | b'\n'))
                            && (!utf16 || bytes.get(i + 1) == Some(&0))
                    };
                    if boundary(off + len)
                        && (off >= step && boundary(off - step) || off == 0 && start == vad.start)
                    {
                        let fields = if kind == ApplicationKind::Wps {
                            office::text(&line)
                        } else if matches!(
                            kind,
                            ApplicationKind::Sunlogin | ApplicationKind::Anydesk
                        ) {
                            remote::text(kind, &line)
                        } else {
                            vec![]
                        };
                        for (s, n, a) in fields {
                            let begin = if utf16 {
                                line[..s].encode_utf16().count() * 2
                            } else {
                                s
                            };
                            let size = if utf16 {
                                line[s..s + n].encode_utf16().count() * 2
                            } else {
                                n
                            };
                            decoded.push((off + begin, size, a));
                        }
                    }
                }
                for (offset, len, a) in decoded {
                    let hash = hex::encode(Sha256::digest(&bytes[offset..offset + len]));
                    if !retained.insert((start + offset as u64, a.pointer.clone(), a.kind)) {
                        continue;
                    }
                    let evidence = evidence(
                        p.pid,
                        p.eprocess,
                        dtb,
                        start + offset as u64,
                        len,
                        vad.start,
                        vad.end,
                        utf16,
                        &hash,
                        &ranges,
                        &a.pointer,
                    );
                    let summary = a
                        .data
                        .get("text")
                        .or_else(|| a.data.get("program_name"))
                        .or_else(|| a.data.get("label"))
                        .or_else(|| a.data.get("document_path"))
                        .and_then(Value::as_str)
                        .unwrap_or(a.kind)
                        .chars()
                        .take(180)
                        .collect();
                    report.push(ApplicationRecord {
                        artifact_kind: a.kind.into(),
                        source: sid.clone(),
                        pid: Some(p.pid),
                        path: p.details.image_path.clone(),
                        summary,
                        evidence,
                        data: a.data,
                    });
                    found = true;
                }
                if !found && !matches!(kind, ApplicationKind::Ai | ApplicationKind::Huorong) {
                    if let Some((off, len, text)) = line_fragment(&bytes, anchor, utf16)
                        && retained.insert((
                            start + off as u64,
                            String::new(),
                            "memory_text_fragment",
                        ))
                    {
                        let hash = hex::encode(Sha256::digest(&bytes[off..off + len]));
                        let e = evidence(
                            p.pid,
                            p.eprocess,
                            dtb,
                            start + off as u64,
                            len,
                            vad.start,
                            vad.end,
                            utf16,
                            &hash,
                            &ranges,
                            "",
                        );
                        // Raw key material is not exposed through broad context extraction.
                        let text = redact_keys(&text);
                        report.push(ApplicationRecord{artifact_kind:"memory_text_fragment".into(),source:sid.clone(),pid:Some(p.pid),path:p.details.image_path.clone(),summary:text.chars().take(180).collect(),evidence:e,
                                data:json!({"text":text,"anchor":texts[hit.pattern_index/2],"semantics":"进程驻留文本片段；未确认配置生效、成功连接、卷状态或文档编辑"})});
                    }
                } else if !found {
                    rejected += 1;
                }
            }
        }
        if budget_hit {
            report.source(
                &format!("{sid}:budget"),
                true,
                false,
                checked.len(),
                vec!["该进程候选读取达到公平分配的预算；其余进程继续核对".into()],
                Value::Null,
            );
        }
        if rejected > 0 {
            report.source(&format!("{sid}:decode"),true,false,rejected,vec!["部分锚点未形成支持的完整结构：可能缺页、对象格式不同或只是普通文本；未补造会话".into()],Value::Null);
        }
    }
    report.limitations.push("进程内存：每类物理锚点有界，最多读取 128 MiB JSON 候选上下文。AI 另查支持的 V8 堆布局，每进程最多 512 MiB 读取、131072 驻留页和每堆 4096 对象候选；缺页、未知布局/属性、循环和预算中止保留范围说明，不补造内容。".into());
    Ok(())
}

// Closed clients may leave resident configuration without a surviving process.
// Only app-specific field names qualify; attribution remains explicitly unknown.
fn physical_remote(
    session: &AnalysisSession,
    kind: ApplicationKind,
    options: &ApplicationOptions,
    token: &CancellationToken,
    report: &mut ApplicationReport,
) -> Result<()> {
    let texts = if kind == ApplicationKind::Anydesk {
        vec!["ad.anynet.id=", "ad.anynet.alias=", "ad.security."]
    } else {
        vec!["fastcode=", "encry_pwd=", "fastcode\0", "encry_pwd\0"]
    };
    let patterns: Vec<Vec<u8>> = texts
        .iter()
        .flat_map(|s| {
            [
                s.as_bytes().to_vec(),
                s.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            ]
        })
        .collect();
    let scan = scan_patterns_cancellable(
        session.image(),
        &patterns.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        options.anchor_limit,
        16 * 1024 * 1024,
        token,
    )?;
    let mut seen = HashSet::new();
    let mut unreadable = 0;
    for hit in &scan.hits {
        token.check_cancelled()?;
        if report.truncated {
            break;
        }
        let page = hit.physical_address & !4095;
        let mut bytes = [0; 4096];
        if session.image().read_physical(page, &mut bytes).is_err() {
            unreadable += 1;
            continue;
        }
        let utf16 = hit.pattern_index % 2 == 1;
        for (off, len, mut a) in
            physical_remote_fields(kind, &bytes, (hit.physical_address - page) as usize, utf16)
        {
            let pa = page + off as u64;
            if !seen.insert((pa, a.data["field"].to_string())) {
                continue;
            }
            a.data["semantics"] = json!(
                "单个实际驻留物理页中的应用专属字段；未归属进程或文件，可能为历史/缓存/示例文本，不证明已安装、连接或当前有效"
            );
            a.data["attribution"] = json!("unattributed_physical");
            report.push(ApplicationRecord { artifact_kind:a.kind.into(),source:"physical_memory_fields".into(),pid:None,path:None,
                summary:format!("未归属片段 · {}",a.data["label"].as_str().unwrap_or(a.kind)),
                evidence:json!({"physical_address":pa,"byte_length":len,"encoding":if utf16{"UTF-16LE"}else{"UTF-8"},
                    "source_location":session.image().source_location(pa),"sha256":hex::encode(Sha256::digest(&bytes[off..off+len])),"attribution":"unattributed_physical"}),data:a.data });
        }
    }
    report.source("physical_memory_fields",true,!scan.truncated && unreadable==0 && !report.truncated,scan.hits.len(),
        vec!["未发现活动目标进程，改查应用专属配置字段；仅解析单页完整字段，不推定进程/用户归属".into()],
        json!({"bytes_scanned":scan.bytes_scanned,"anchor_scan_truncated":scan.truncated,"unreadable_pages":unreadable,"scope":"single_physical_page","attribution":"unknown"}));
    Ok(())
}

fn physical_remote_fields(
    kind: ApplicationKind,
    bytes: &[u8],
    anchor: usize,
    utf16: bool,
) -> Vec<(usize, usize, ai::Artifact)> {
    let step = if utf16 { 2 } else { 1 };
    let boundary = |i| {
        bytes.get(i).is_some_and(|b| matches!(b, 0 | b'\n' | b'\r'))
            && (!utf16 || bytes.get(i + 1) == Some(&0))
    };
    let mut out = Vec::new();
    if anchor >= step
        && boundary(anchor - step)
        && let Some(a) = remote::nul_pair(kind, bytes, anchor, utf16)
    {
        out.push(a);
    }
    if let Some((off, len, line)) = line_fragment(bytes, anchor, utf16)
        && off >= step
        && boundary(off - step)
        && boundary(off + len)
    {
        for (s, n, a) in remote::text(kind, &line) {
            let k = a.data["field"].as_str().unwrap_or("");
            let specific = if kind == ApplicationKind::Anydesk {
                k.starts_with("ad.anynet.") || k.starts_with("ad.security.")
            } else {
                matches!(k, "fastcode" | "fastcodepsw" | "encry_pwd")
            };
            if specific {
                let begin = if utf16 {
                    line[..s].encode_utf16().count() * 2
                } else {
                    s
                };
                let size = if utf16 {
                    line[s..s + n].encode_utf16().count() * 2
                } else {
                    n
                };
                out.push((off + begin, size, a));
            }
        }
    }
    out
}

type Range = (u64, u64, usize, Value);
fn read_prefix(
    session: &AnalysisSession,
    space: &X64AddressSpace<'_>,
    start: u64,
    max: usize,
    token: &CancellationToken,
) -> Result<(Vec<u8>, Vec<Range>)> {
    let mut bytes = Vec::new();
    let mut ranges = Vec::new();
    while bytes.len() < max {
        token.check_cancelled()?;
        let va = start + bytes.len() as u64;
        let n = (max - bytes.len()).min(4096 - (va as usize & 4095));
        let Ok(pa) = space.translate(va) else {
            break;
        };
        let mut b = vec![0; n];
        if session.image().read_physical(pa, &mut b).is_err() {
            break;
        }
        bytes.extend(b);
        ranges.push((va, pa, n, json!(session.image().source_location(pa))));
    }
    Ok((bytes, ranges))
}

#[allow(clippy::too_many_arguments)]
fn evidence(
    pid: u64,
    eprocess: u64,
    dtb: u64,
    va: u64,
    len: usize,
    vs: u64,
    ve: u64,
    utf16: bool,
    hash: &str,
    ranges: &[Range],
    pointer: &str,
) -> Value {
    let end = va + len as u64;
    let exact:Vec<_>=ranges.iter().filter_map(|(v,p,n,s)|{let start=va.max(*v);let end=end.min(*v+*n as u64);(start<end).then(||json!({"virtual_address":start,"physical_address":p+(start-v),"byte_length":end-start,"source_page":s}))}).collect();
    json!({"pid":pid,"eprocess":eprocess,"directory_table_base":dtb,"virtual_address":va,"byte_length":len,"vad_start":vs,"vad_end":ve,
        "encoding":if utf16{"UTF-16LE"}else{"UTF-8"},"sha256":hash,"ranges":exact,"json_pointer":pointer,"attribution":"验证页表与 VAD 的驻留关系，非生成者证明"})
}

fn json_objects(bytes: &[u8], anchor: usize, utf16: bool) -> Vec<(usize, usize, Value)> {
    let mut out = Vec::new();
    let step = if utf16 { 2 } else { 1 };
    let low = anchor.saturating_sub(2048);
    let mut tried = 0;
    for off in (low..=anchor).rev() {
        if !(anchor - off).is_multiple_of(step)
            || bytes[off] != b'{'
            || utf16 && bytes.get(off + 1) != Some(&0)
        {
            continue;
        }
        tried += 1;
        if tried > 64 {
            break;
        }
        let decoded;
        let input = if utf16 {
            let units = bytes[off..]
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .take_while(|v| *v != 0);
            decoded = char::decode_utf16(units)
                .map_while(std::result::Result::ok)
                .collect::<String>();
            decoded.as_bytes()
        } else {
            &bytes[off..]
        };
        let mut stream = serde_json::Deserializer::from_slice(input).into_iter::<Value>();
        if let Some(Ok(v)) = stream.next() {
            let consumed = stream.byte_offset();
            let len = if utf16 {
                std::str::from_utf8(&input[..consumed]).map_or(0, |s| s.encode_utf16().count() * 2)
            } else {
                consumed
            };
            if off + len > anchor {
                out.push((off, len, v));
            }
        }
    }
    // Prefer the largest enclosing object; its JSON Pointer preserves context.
    out.sort_by_key(|(off, len, _)| (*off, std::cmp::Reverse(*len)));
    let mut filtered = Vec::new();
    for item in out {
        if !filtered
            .iter()
            .any(|(s, n, _): &(usize, usize, Value)| *s <= item.0 && *s + *n >= item.0 + item.1)
        {
            filtered.push(item);
        }
    }
    filtered
}

fn line_fragment(bytes: &[u8], anchor: usize, utf16: bool) -> Option<(usize, usize, String)> {
    let step = if utf16 { 2 } else { 1 };
    let mut start = anchor;
    let mut end = anchor;
    let delimiter = |i: usize| {
        bytes[i] == 0 && (!utf16 || bytes.get(i + 1) == Some(&0))
            || bytes[i] == b'\n' && (!utf16 || bytes.get(i + 1) == Some(&0))
    };
    while start >= step && anchor - start < 512 && !delimiter(start - step) {
        start -= step;
    }
    while end + step <= bytes.len() && end - anchor < 1536 && !delimiter(end) {
        end += step;
    }
    if end <= start {
        return None;
    }
    let s = if utf16 {
        String::from_utf16(
            &bytes[start..end]
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect::<Vec<_>>(),
        )
        .ok()?
    } else {
        std::str::from_utf8(&bytes[start..end]).ok()?.to_owned()
    };
    if s.chars()
        .any(|c| c.is_control() && !matches!(c, '\r' | '\n' | '\t'))
    {
        return None;
    }
    Some((start, end - start, s))
}

fn redact_keys(text: &str) -> String {
    // Recovery passwords are recognizable without publishing their raw value.
    let re = regex::Regex::new(r"\b\d{6}(?:-\d{6}){7}\b");
    re.map_or_else(
        |_| text.to_owned(),
        |r| {
            r.replace_all(text, "[BitLocker 恢复密码已遮蔽]")
                .into_owned()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_fields_reject_generic_secrets_and_page_edge_fragments() {
        let b = b"\0ad.anynet.id=123456789 password=secret\n";
        let r = physical_remote_fields(ApplicationKind::Anydesk, b, 1, false);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].2.data["field"], "ad.anynet.id");
        assert_eq!(&b[r[0].0..r[0].0 + r[0].1], b"ad.anynet.id=123456789");
        assert!(
            physical_remote_fields(ApplicationKind::Anydesk, &b[..b.len() - 1], 1, false)
                .is_empty()
        );
        assert!(physical_remote_fields(ApplicationKind::Anydesk, &b[1..], 0, false).is_empty());
    }
    #[test]
    fn json_decoding_requires_closed_structure_and_exact_bytes() {
        let b = br#"xxxx{"sessionId":"s","message":{"role":"user","content":"hello"}}tail"#;
        let pos = b.windows(6).position(|w| w == b"\"role\"").unwrap();
        let r = json_objects(b, pos, false);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0, 4);
        assert_eq!(ai::extract(&r[0].2, "WorkBuddy")[0].pointer, "/message");
        assert!(json_objects(&b[..pos + 8], pos, false).is_empty());
        let text = "垃圾{\"role\":\"assistant\",\"content\":\"中文回复\"}";
        let b: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let r = json_objects(&b, 8, true);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0, 4);
        assert_eq!(r[0].1, b.len() - 4);
    }
}
