//! Browser page leads, with independent runtime, window and stored-session evidence.
//! A URL's presence (even in several sources) never proves a live selected tab.
use crate::{
    address::{VirtualAddressRegion, X64AddressSpace},
    cancellation::{CancellationToken, is_cancellation_error},
    session::AnalysisSession,
    windows::{
        ProcessRecord,
        files::{DumpFileReport, RecoveredExtent},
        plugins::list_vads_cancellable,
    },
    windows_interaction::{InteractionOptions, InteractionSource, analyze_windows_interaction},
};
use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

const URL_BYTES: usize = 8192;
const BLOCK: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BrowserPagesOptions {
    pub pid: Option<u64>,
    pub limit: usize,
    pub process_limit: usize,
    pub max_process_bytes: u64,
    pub file_limit: usize,
    pub max_file_bytes: u64,
}
impl Default for BrowserPagesOptions {
    fn default() -> Self {
        Self {
            pid: None,
            limit: 4096,
            process_limit: 16,
            max_process_bytes: 64 * 1024 * 1024,
            file_limit: 64,
            max_file_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Serialize, Default)]
pub struct BrowserPagesReport {
    pub pages: Vec<Value>,
    pub windows: Vec<Value>,
    pub processes: Vec<Value>,
    pub memory_urls: Vec<Value>,
    pub session_records: Vec<Value>,
    pub source_checks: Vec<Value>,
    pub complete: bool,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}
impl BrowserPagesReport {
    fn check(&mut self, source: &str, complete: bool, details: Value) {
        self.complete &= complete;
        self.source_checks
            .push(json!({"source":source,"complete":complete,"details":details}));
    }
    fn failure(&mut self, source: &str, error: anyhow::Error) -> Result<()> {
        if is_cancellation_error(&error) {
            return Err(error);
        }
        self.check(source, false, json!({"error":format!("{error:#}")}));
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct UrlHit {
    pub offset: usize,
    pub length: usize,
    pub url: String,
    pub domain: String,
    pub encoding: &'static str,
    pub terminated: bool,
    pub resource: bool,
}

/// Only parse actual contiguous bytes. The caller supplies residency and ownership.
pub(crate) fn urls(bytes: &[u8], limit: usize) -> Vec<UrlHit> {
    let mut hits = Vec::new();
    for (prefix, wide) in [
        (b"http://".as_slice(), false),
        (b"https://".as_slice(), false),
        (b"h\0t\0t\0p\0:\0/\0/\0".as_slice(), true),
        (b"h\0t\0t\0p\0s\0:\0/\0/\0".as_slice(), true),
    ] {
        let before = hits.len();
        for offset in memchr::memmem::find_iter(bytes, prefix) {
            if hits.len() - before == limit {
                break;
            }
            let step = if wide { 2 } else { 1 };
            let mut end = offset;
            let mut terminated = false;
            while end + step <= bytes.len() && end - offset < URL_BYTES {
                let ch = if wide {
                    u16::from_le_bytes([bytes[end], bytes[end + 1]])
                } else {
                    u16::from(bytes[end])
                };
                if ch <= 32
                    || ch == 127
                    || [b'"', b'\'', b'<', b'>', b'\\', b'`'].contains(&(ch as u8)) && ch < 128
                {
                    terminated = true;
                    break;
                }
                end += step;
            }
            let raw = &bytes[offset..end];
            let text = if wide {
                String::from_utf16(
                    &raw.chunks_exact(2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .collect::<Vec<_>>(),
                )
                .ok()
            } else {
                std::str::from_utf8(raw).ok().map(str::to_owned)
            };
            let Some(url) = text else {
                continue;
            };
            let Ok(parsed) = reqwest::Url::parse(&url) else {
                continue;
            };
            let Some(domain) = parsed.host_str() else {
                continue;
            };
            if !matches!(parsed.scheme(), "http" | "https")
                || !domain.contains('.') && !domain.contains(':')
            {
                continue;
            }
            let path = parsed.path().to_ascii_lowercase();
            let resource = [
                ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
                ".map",
            ]
            .iter()
            .any(|suffix| path.ends_with(suffix));
            hits.push(UrlHit {
                offset,
                length: end - offset,
                domain: domain.to_owned(),
                url,
                encoding: if wide { "UTF-16LE" } else { "UTF-8" },
                terminated,
                resource,
            });
        }
    }
    hits.sort_by_key(|h| h.offset);
    hits.truncate(limit);
    hits
}

fn browser(p: &ProcessRecord) -> Option<&'static str> {
    match p.name.to_ascii_lowercase().as_str() {
        "msedge.exe" => Some("Microsoft Edge"),
        "chrome.exe" => Some("Chrome"),
        "chromium.exe" => Some("Chromium"),
        "firefox.exe" => Some("Firefox"),
        "brave.exe" => Some("Brave"),
        "vivaldi.exe" => Some("Vivaldi"),
        "opera.exe" => Some("Opera"),
        "360chrome.exe" | "360chrome" | "360chromex.exe" => Some("360 极速浏览器"),
        "360se.exe" => Some("360 安全浏览器"),
        "qqbrowser.exe" => Some("QQ 浏览器"),
        // Windows EPROCESS ImageFileName is limited to 15 bytes.
        "sogouexplorer.exe" | "sogouexplorer.e" | "sogouexplorer.ex" => Some("搜狗浏览器"),
        // WebView/Electron clients are deliberately not identified as Edge.
        _ => None,
    }
}
fn role(p: &ProcessRecord) -> &'static str {
    let cmd = p.details.command_line.as_deref().unwrap_or("");
    if cmd.contains("--type=renderer") || cmd.contains("-contentproc") {
        "renderer"
    } else if cmd.contains("--type=") {
        "auxiliary"
    } else {
        "browser"
    }
}
fn root<'a>(p: &'a ProcessRecord, processes: &'a [ProcessRecord]) -> &'a ProcessRecord {
    let mut current = p;
    let mut seen = HashSet::new();
    while seen.insert(current.eprocess) {
        let parents: Vec<_> = processes
            .iter()
            .filter(|parent| {
                Some(parent.pid) == current.ppid
                    && parent.name.eq_ignore_ascii_case(&current.name)
                    && parent.details.exit_time.is_none()
                    && parent
                        .details
                        .create_time_raw
                        .zip(current.details.create_time_raw)
                        .is_some_and(|(a, b)| a <= b)
                    && parent.details.image_path == current.details.image_path
            })
            .collect();
        if parents.len() != 1 {
            break;
        }
        current = parents[0];
    }
    current
}

fn memory_ranges(
    session: &AnalysisSession,
    space: &X64AddressSpace<'_>,
    va: u64,
    bytes: &[u8],
) -> Result<Vec<Value>> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let address = va + offset as u64;
        let pa = space.translate(address)?;
        let n = (4096 - (address as usize & 4095)).min(bytes.len() - offset);
        let mut original = vec![0; n];
        session.image().read_physical(pa, &mut original)?;
        ensure!(original == bytes[offset..offset + n], "驻留字节复验失败");
        ranges.push(json!({"virtual_address":address,"physical_address":pa,"byte_length":n,
            "source_location":session.image().source_location(pa),"sha256":hex::encode(Sha256::digest(&original))}));
        offset += n;
    }
    Ok(ranges)
}

/// Recover URLs only inside contiguous resident file intervals; zero-filled gaps
/// cannot supply terminators, SNSS headers, lengths, or navigation selection.
fn resident_intervals(extents: &[RecoveredExtent], length: usize) -> Vec<(usize, usize)> {
    let mut intervals: Vec<(usize, usize)> = Vec::new();
    let mut extents: Vec<_> = extents.iter().collect();
    extents.sort_by_key(|e| e.file_offset);
    for e in &extents {
        let start = usize::try_from(e.file_offset).unwrap_or(length);
        let end = start
            .saturating_add(usize::try_from(e.length).unwrap_or(length))
            .min(length);
        if start >= end {
            continue;
        }
        if let Some(last) = intervals.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        intervals.push((start, end));
    }
    intervals
}
pub(crate) fn session_fragments(
    session: &AnalysisSession,
    dump: &DumpFileReport,
    bytes: &[u8],
    limit: usize,
) -> Result<Vec<Value>> {
    let intervals = resident_intervals(&dump.extents, bytes.len());
    let extents = &dump.extents;
    let kernel = X64AddressSpace::new(session.image(), session.kernel().directory_table_base)?;
    let mut out = Vec::new();
    for (start, end) in intervals {
        for h in urls(&bytes[start..end], limit.saturating_sub(out.len())) {
            let off = start + h.offset;
            let stop = off + h.length;
            let mut ranges = Vec::new();
            for e in extents {
                let a = (off as u64).max(e.file_offset);
                let b = (stop as u64).min(e.file_offset + e.length);
                if a >= b {
                    continue;
                }
                let mut at = a;
                while at < b {
                    let address = e.memory_address + (at - e.file_offset);
                    let pa = if e.memory_kind == "physical" {
                        address
                    } else {
                        kernel.translate(address)?
                    };
                    let n = (b - at).min(4096 - (address & 4095));
                    let original = &bytes[at as usize..(at + n) as usize];
                    let mut verify = vec![0; n as usize];
                    session.image().read_physical(pa, &mut verify)?;
                    ensure!(verify == original, "Session 片段字节复验失败");
                    ranges.push(json!({"file_offset":at,"physical_address":pa,"byte_length":n,
                        "source_location":session.image().source_location(pa),"sha256":hex::encode(Sha256::digest(original))}));
                    at += n;
                }
            }
            out.push(json!({"url":h.url,"domain":h.domain,"file_offset":off,"byte_length":h.length,
                "encoding":h.encoding,"url_terminated":h.terminated,"resource_candidate":h.resource,"source_ranges":ranges,
                "sha256":hex::encode(Sha256::digest(&bytes[off..stop])),"semantic":"resident_session_url_fragment_not_selected_tab"}));
        }
    }
    Ok(out)
}

pub fn analyze(
    session: &AnalysisSession,
    options: &BrowserPagesOptions,
    token: &CancellationToken,
) -> Result<BrowserPagesReport> {
    ensure!(
        !session.image().is_live() && !session.kernel().is_x86_pae(),
        "浏览器页面解析目前支持离线 Windows x64 镜像"
    );
    ensure!(
        (1..=16384).contains(&options.limit) && (1..=64).contains(&options.process_limit),
        "记录上限为 1–16384；进程上限为 1–64"
    );
    ensure!(
        (1024 * 1024..=256 * 1024 * 1024).contains(&options.max_process_bytes),
        "单进程驻留读取预算为 1–256 MiB"
    );
    ensure!(
        (1..=4096).contains(&options.file_limit)
            && (4096..=256 * 1024 * 1024).contains(&options.max_file_bytes),
        "文件候选为 1–4096；单文件读取预算为 4 KiB–256 MiB"
    );
    let mut report=BrowserPagesReport { complete:true, limitations:vec![
        "页面关联是证据线索；同进程、同域名、出现次数或文件时间均不能证明某个 URL 是当前选中的标签页。".into(),
        "只检查活动浏览器的驻留私有 VAD；不读取换出页、DLL 常量、GPU/网络辅助进程。支持 HTTP(S) 的 UTF-8/UTF-16LE URL。".into(),
        "Session 保存状态可能早于采集；缺页片段不重建选中标签页。窗口最小化与系统前台焦点分别看待。".into()],..Default::default() };
    token.check_cancelled()?;
    let processes = session.processes_cancellable(65536, token)?;
    report.check(
        "process_enumeration",
        processes.complete,
        json!({"warnings":processes.warnings}),
    );
    let roots: BTreeSet<_> = processes
        .processes
        .iter()
        .filter(|p| {
            browser(p).is_some()
                && p.details.exit_time.is_none()
                && options.pid.is_none_or(|pid| pid == p.pid)
        })
        .map(|p| root(p, &processes.processes).eprocess)
        .collect();
    let mut selected: Vec<_> = processes
        .processes
        .iter()
        .filter(|p| {
            browser(p).is_some()
                && p.details.exit_time.is_none()
                && role(p) != "auxiliary"
                && roots.contains(&root(p, &processes.processes).eprocess)
        })
        .collect();
    selected.sort_by_key(|p| (role(p) != "renderer", p.pid));
    let total = selected.len();
    selected.truncate(options.process_limit);
    if selected.is_empty() {
        report.check("browser_processes",false,json!({"reason":"未找到匹配的活动浏览器进程；退出进程及 WebView 不在本次运行时扫描范围内。"}));
    }
    report.check(
        "process_selection",
        total <= options.process_limit,
        json!({"matched":total,"selected":selected.len(),"requested_pid":options.pid}),
    );
    match session.window_titles(16384) {
        Ok(w) => {
            report.check("windows", w.complete, json!({"warnings":w.warnings}));
            for window in w.records {
                if let Some(p) = processes.processes.iter().find(|p| {
                    Some(p.pid) == window.pid
                        && p.details.exit_time.is_none()
                        && roots.contains(&p.eprocess)
                }) {
                    report.windows.push(json!({"browser":browser(p),"pid":p.pid,"eprocess":p.eprocess,"title":window.title,
                        "address":window.address,"visible":window.visible,"minimized":window.window_rect.as_ref().map(|r|r.left<=-30000&&r.top<=-30000),
                        "window_rect":window.window_rect,"tree_depth":window.tree_depth,"desktop":window.desktop,"session_id":window.session_id,
                        "semantic":"window_title_not_foreground_or_url_proof"}));
                }
            }
        }
        Err(e) => report.failure("windows", e)?,
    }
    for p in &selected {
        token.check_cancelled()?;
        let owner = root(p, &processes.processes);
        report.processes.push(json!({"browser":browser(p),"pid":p.pid,"ppid":p.ppid,"eprocess":p.eprocess,"role":role(p),
            "root_pid":owner.pid,"root_eprocess":owner.eprocess,"image_path":p.details.image_path,"create_time":p.details.create_time}));
        if let Err(e) = scan_process(
            session,
            p,
            owner,
            options,
            (options.limit / selected.len().max(1)).max(1),
            token,
            &mut report,
        ) {
            report.failure(&format!("process:{}", p.pid), e)?;
        }
    }
    token.check_cancelled()?;
    match analyze_windows_interaction(
        session,
        &InteractionOptions {
            sources: vec![InteractionSource::BrowserTabs],
            limit: options.limit,
            file_limit: options.file_limit,
            max_file_bytes: options.max_file_bytes,
        },
        token,
    ) {
        Ok(mut r) => {
            if let Some(s) = r.sources.remove("browser_tabs") {
                report.check("stored_sessions",s.complete,json!({"checks":s.checks,"checks_truncated":s.checks_truncated,"limitations":s.limitations}));
                report.session_records = s
                    .records
                    .into_iter()
                    .map(|r| json!({"kind":r.kind,"evidence":r.evidence,"fields":r.fields}))
                    .collect();
            }
        }
        Err(e) => report.failure("stored_sessions", e)?,
    }
    // Bind sessions to a root only by an actual FILE_OBJECT handle, never by a
    // matching browser name, PID reuse, hostname, or similar profile path.
    let objects: HashSet<_> = report
        .session_records
        .iter()
        .filter_map(|r| r["evidence"]["file_object"].as_u64())
        .collect();
    let mut owners = BTreeMap::<u64, BTreeSet<u64>>::new();
    for owner in processes
        .processes
        .iter()
        .filter(|p| roots.contains(&p.eprocess))
    {
        token.check_cancelled()?;
        if objects.is_empty() {
            break;
        }
        match session.handles(owner.pid, 65536) {
            Ok(h) => {
                report.check(
                    &format!("session_handles:{}", owner.pid),
                    h.complete,
                    json!({"warnings":h.warnings}),
                );
                for handle in h
                    .records
                    .iter()
                    .filter(|h| h.object_type == "File" && objects.contains(&h.object))
                {
                    for record in report
                        .session_records
                        .iter_mut()
                        .filter(|r| r["evidence"]["file_object"].as_u64() == Some(handle.object))
                    {
                        let owners = record
                            .as_object_mut()
                            .expect("session record object")
                            .entry("verified_handle_owners")
                            .or_insert_with(|| json!([]));
                        if let Some(owners) = owners.as_array_mut() {
                            owners.push(json!({"pid":owner.pid,"eprocess":owner.eprocess,"process_create_time":owner.details.create_time,
                                "handle":handle.handle,"handle_table_entry":handle.entry,"file_object":handle.object,"object_type":handle.object_type}));
                        }
                    }
                    owners
                        .entry(handle.object)
                        .or_default()
                        .insert(owner.eprocess);
                }
            }
            Err(e) => report.failure("session_handles", e)?,
        }
    }
    report.pages = relate(
        &report.memory_urls,
        &report.windows,
        &report.session_records,
        &owners,
    );
    if !report.complete {
        report
            .warnings
            .push("部分来源缺页、未完成或达到预算；请查看来源检查。".into());
    }
    Ok(report)
}

fn scan_process(
    session: &AnalysisSession,
    p: &ProcessRecord,
    owner: &ProcessRecord,
    options: &BrowserPagesOptions,
    quota: usize,
    token: &CancellationToken,
    report: &mut BrowserPagesReport,
) -> Result<()> {
    let dtb = p
        .details
        .user_directory_table_base
        .filter(|n| *n != 0)
        .or(p.details.directory_table_base)
        .unwrap_or(0);
    let space = X64AddressSpace::new(session.image(), dtb)?;
    let mappings =
        space.enumerate_mappings_cancellable(VirtualAddressRegion::User, 262144, token)?;
    let vads = list_vads_cancellable(
        session.image(),
        session.kernel(),
        session.profile(),
        p.pid,
        65536,
        token,
    )?;
    let mut bytes_read = 0u64;
    let mut bytes_attempted = 0u64;
    let mut read_errors = 0u64;
    let mut capped = false;
    let mut url_candidates_truncated = false;
    let mut seen = HashSet::new();
    let mut retained = 0usize;
    for vad in vads
        .records
        .iter()
        .filter(|v| v.private_memory && v.file.is_none())
    {
        let mut tail = Vec::new();
        let mut previous_end = 0;
        for mapping in mappings
            .mappings
            .iter()
            .filter(|m| m.virtual_start <= vad.end && m.virtual_end > vad.start)
        {
            let mut at = mapping.virtual_start.max(vad.start);
            let end = mapping.virtual_end.min(vad.end.saturating_add(1));
            while at < end {
                token.check_cancelled()?;
                if bytes_attempted >= options.max_process_bytes
                    || retained >= quota
                    || report.memory_urls.len() >= options.limit
                {
                    capped = true;
                    break;
                }
                let n = (end - at)
                    .min(BLOCK as u64)
                    .min(options.max_process_bytes - bytes_attempted)
                    as usize;
                let mut block = vec![0; n];
                bytes_attempted += n as u64;
                if previous_end != at {
                    tail.clear();
                }
                if space.read_virtual(at, &mut block).is_err() {
                    read_errors += 1;
                    tail.clear();
                    at += n as u64;
                    continue;
                }
                bytes_read += n as u64;
                let base = at - tail.len() as u64;
                tail.extend_from_slice(&block);
                let candidate_limit = quota.saturating_sub(retained) + 1;
                let candidates = urls(&tail, candidate_limit);
                // Overlap duplicates and unterminated candidates can consume this
                // bound without filling the output quota. Keep that scope partial.
                url_candidates_truncated |= candidates.len() == candidate_limit;
                for hit in candidates {
                    let va = base + hit.offset as u64;
                    if !hit.terminated {
                        continue;
                    }
                    if retained >= quota || report.memory_urls.len() >= options.limit {
                        capped = true;
                        break;
                    }
                    if !seen.insert((va, hit.encoding)) {
                        continue;
                    }
                    let raw = &tail[hit.offset..hit.offset + hit.length];
                    let ranges = memory_ranges(session, &space, va, raw)?;
                    report.memory_urls.push(json!({"browser":browser(p),"pid":p.pid,"eprocess":p.eprocess,"role":role(p),"root_pid":owner.pid,"root_eprocess":owner.eprocess,
                        "url":hit.url,"domain":hit.domain,"resource_candidate":hit.resource,"url_terminated":true,"virtual_address":va,"byte_length":hit.length,
                        "encoding":hit.encoding,"directory_table_base":dtb,"vad_start":vad.start,"vad_end":vad.end,"source_ranges":ranges,
                        "sha256":hex::encode(Sha256::digest(raw)),"semantic":"process_resident_url_not_navigation_proof"}));
                    retained += 1;
                }
                let keep = tail.len().saturating_sub(URL_BYTES);
                tail.drain(..keep);
                at += n as u64;
                previous_end = at;
            }
            if capped {
                break;
            }
        }
        if capped {
            break;
        }
    }
    report.check(&format!("memory:{}",p.pid),!capped&&!url_candidates_truncated&&read_errors==0&&!mappings.truncated&&mappings.warnings.is_empty()&&vads.complete,
        json!({"pid":p.pid,"bytes_read":bytes_read,"bytes_attempted":bytes_attempted,"read_errors":read_errors,"budget_reached":capped,"url_candidates_truncated":url_candidates_truncated,"retained":retained,
            "mapping_warnings":mappings.warnings,"vad_warnings":vads.warnings,"scope":"present_page_table_mappings_in_private_vads"}));
    Ok(())
}

fn relate(
    memory: &[Value],
    windows: &[Value],
    sessions: &[Value],
    owners: &BTreeMap<u64, BTreeSet<u64>>,
) -> Vec<Value> {
    let mut session_urls = BTreeMap::<String, Vec<usize>>::new();
    for (i, s) in sessions.iter().enumerate() {
        if s["fields"]["url_terminated"] == false {
            continue;
        }
        if let Some(url) = s["fields"]["url"]
            .as_str()
            .or_else(|| s["fields"]["current_navigation"]["url"].as_str())
        {
            session_urls.entry(url.to_owned()).or_default().push(i);
        }
    }
    let mut groups = BTreeMap::<(u64, String), Vec<usize>>::new();
    for (i, m) in memory.iter().enumerate() {
        if let (Some(root), Some(url)) = (m["root_eprocess"].as_u64(), m["url"].as_str()) {
            groups.entry((root, url.to_owned())).or_default().push(i);
        }
    }
    let mut rows = Vec::new();
    for ((root, url), indices) in groups {
        let first = &memory[indices[0]];
        let mut session_indices = Vec::new();
        let mut unassigned_session_indices = Vec::new();
        for i in session_urls.get(&url).into_iter().flatten() {
            match sessions[*i]["evidence"]["file_object"]
                .as_u64()
                .and_then(|o| owners.get(&o))
            {
                Some(roots) if roots.contains(&root) => session_indices.push(*i),
                None => unassigned_session_indices.push(*i),
                _ => (),
            }
        }
        let has_renderer_evidence = indices.iter().any(|i| memory[*i]["role"] == "renderer");
        let window_indices: Vec<_> = windows
            .iter()
            .enumerate()
            .filter(|(_, w)| {
                w["eprocess"].as_u64() == Some(root)
                    && w["tree_depth"].as_u64() == Some(1)
                    && w["visible"].as_bool() == Some(true)
            })
            .map(|(i, _)| i)
            .collect();
        rows.push(json!({"browser":first["browser"],"root_pid":first["root_pid"],"root_eprocess":root,"domain":first["domain"],"url":url,
            "state":if !session_indices.is_empty(){"runtime_and_owned_session"}else{"runtime_only"},
            "resource_candidate":first["resource_candidate"],"window_titles":window_indices.iter().map(|i|&windows[*i]["title"]).collect::<Vec<_>>(),
            "memory_indices":indices,"session_indices":session_indices,"unassigned_session_indices":unassigned_session_indices,"window_indices":window_indices,
            "has_renderer_evidence":has_renderer_evidence,
            "current_tab_confirmed":false,"relation_basis":"exact_url_and_file_object_handle; windows_share_browser_root_only"}));
    }
    rows.sort_by_key(|r| {
        (
            r["resource_candidate"].as_bool() == Some(true),
            r["state"] != "runtime_and_owned_session",
            r["unassigned_session_indices"]
                .as_array()
                .is_none_or(Vec::is_empty),
            r["has_renderer_evidence"] != true,
            r["url"].as_str().unwrap_or("").to_owned(),
        )
    });
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn common_browser_names_include_truncated_windows_process_names() {
        for (name, expected) in [
            ("chrome.exe", "Chrome"),
            ("chromium.exe", "Chromium"),
            ("firefox.exe", "Firefox"),
            ("brave.exe", "Brave"),
            ("vivaldi.exe", "Vivaldi"),
            ("opera.exe", "Opera"),
            ("360chromex.exe", "360 极速浏览器"),
            ("360se.exe", "360 安全浏览器"),
            ("QQBrowser.exe", "QQ 浏览器"),
            ("sogouexplorer.e", "搜狗浏览器"),
        ] {
            let process = ProcessRecord {
                eprocess: 0x1000,
                pid: 10,
                ppid: None,
                name: name.to_owned(),
                details: Default::default(),
            };
            assert_eq!(browser(&process), Some(expected), "{name}");
        }
        let webview = ProcessRecord {
            eprocess: 0x1000,
            pid: 10,
            ppid: None,
            name: "msedgewebview2.exe".to_owned(),
            details: Default::default(),
        };
        assert_eq!(browser(&webview), None);
    }
    #[test]
    fn urls_preserve_full_host_encoding_and_resource_role() {
        let mut b =
            b"https://www.example.test/path?q=1\0https://cdn.example.test/app.js\0".to_vec();
        b.extend(
            "https://sub.example.test/中文\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        let h = urls(&b, 20);
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].domain, "www.example.test");
        assert!(!h[0].resource);
        assert!(h[1].resource);
        assert_eq!(h[2].encoding, "UTF-16LE");
        assert_eq!(h[2].url, "https://sub.example.test/中文");
    }
    #[test]
    fn cut_url_is_never_declared_terminated() {
        assert!(!urls(b"https://example.test/cut", 2)[0].terminated);
    }
    #[test]
    fn sparse_intervals_do_not_join_gaps_or_accept_missing_terminators() {
        let bytes = b"https://www.example.test\0/path\0https://other.test/\0";
        let extents = [
            RecoveredExtent {
                file_offset: 0,
                length: 24,
                memory_address: 100,
                memory_kind: "physical".into(),
            },
            RecoveredExtent {
                file_offset: 25,
                length: (bytes.len() - 25) as u64,
                memory_address: 500,
                memory_kind: "physical".into(),
            },
        ];
        let spans = resident_intervals(&extents, bytes.len());
        assert_eq!(spans, vec![(0, 24), (25, bytes.len())]);
        assert!(!urls(&bytes[0..24], 4)[0].terminated);
        let second = urls(&bytes[25..], 4);
        assert_eq!(second[0].domain, "other.test");
        assert!(second[0].terminated);
    }
    #[test]
    fn parent_pid_reuse_cannot_bind_new_process_to_old_child() {
        let make = |pid, ppid, time| ProcessRecord {
            eprocess: pid + 100,
            pid,
            ppid: Some(ppid),
            name: "msedge.exe".into(),
            details: crate::windows::ProcessDetails {
                create_time_raw: Some(time),
                ..Default::default()
            },
        };
        let ps = vec![make(10, 1, 200), make(20, 10, 100)];
        assert_eq!(root(&ps[1], &ps).pid, 20);
    }
    #[test]
    fn same_url_without_exact_file_owner_is_not_correlated_or_current() {
        let memory = vec![
            json!({"root_eprocess":101,"root_pid":10,"url":"https://example.test/","domain":"example.test"}),
        ];
        let sessions =
            vec![json!({"evidence":{"file_object":20},"fields":{"url":"https://example.test/"}})];
        let mut owners = BTreeMap::new();
        owners.insert(20, BTreeSet::from([102]));
        assert_eq!(
            relate(&memory, &[], &sessions, &owners)[0]["state"],
            "runtime_only"
        );
        owners.insert(20, BTreeSet::from([101]));
        let r = relate(&memory, &[], &sessions, &owners);
        assert_eq!(r[0]["state"], "runtime_and_owned_session");
        assert_eq!(r[0]["current_tab_confirmed"], false);
        let unassigned = relate(&memory, &[], &sessions, &BTreeMap::new());
        assert_eq!(unassigned[0]["state"], "runtime_only");
        assert_eq!(unassigned[0]["session_indices"], json!([]));
        assert_eq!(unassigned[0]["unassigned_session_indices"], json!([0]));
    }
}
