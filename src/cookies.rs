use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::time::Instant;

use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::address::{VirtualAddressRegion, WindowsAddressSpace, X64AddressSpace};
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::scan::{ScanPatternSet, scan_pattern_sets};
use crate::windows::files::{
    DumpSource, RecoveredExtent, recover_file_bytes, scan_files_matching_from_pool_hits,
};
use crate::windows::{WindowsKernelContext, list_processes};

const DEFAULT_CHUNK_SIZE: usize = 64 * 1024 * 1024;
const CONTEXT_BEFORE: u64 = 4096;
const CONTEXT_AFTER: u64 = 16 * 1024;
const MAX_HEADER_CHARS: usize = 16 * 1024;
const MAX_COOKIE_NAME: usize = 512;
const MAX_COOKIE_VALUE: usize = 16 * 1024;
const MAX_WARNING_COUNT: usize = 64;
const MAX_COOKIE_OWNERS: usize = 8;

const COOKIE_PATTERNS: [&[u8]; 4] = [
    b"Cookie:",
    b"Set-Cookie:",
    b"C\0o\0o\0k\0i\0e\0:\0",
    b"S\0e\0t\0-\0C\0o\0o\0k\0i\0e\0:\0",
];
const FILE_POOL_PATTERNS: [&[u8]; 2] = [b"File", b"Fil\xe5"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieScanStage {
    RuntimeHeaders,
    FileObjects,
    Databases,
    ProcessOwners,
}

#[derive(Debug, Clone, Copy)]
pub struct CookieScanOptions {
    pub limit: usize,
    pub database_limit: usize,
    pub file_scan_limit: usize,
    pub max_database_size: u64,
    pub process_space_limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CookieSource {
    RequestHeader,
    ResponseHeader,
    ChromiumDatabase,
    FirefoxDatabase,
    LegacyCookieFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CookieEncoding {
    Ascii,
    Utf16Le,
    Sqlite,
    TextFile,
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieOwner {
    pub pid: u64,
    pub process: String,
    pub virtual_address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserCookieRecord {
    pub browser: String,
    pub profile: Option<String>,
    pub source: CookieSource,
    pub encoding: CookieEncoding,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub name: String,
    pub value: Option<String>,
    pub encrypted_value_hex: Option<String>,
    pub encrypted: bool,
    pub expires: Option<String>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<String>,
    pub confidence: String,
    pub occurrences: usize,
    pub physical_addresses: Vec<u64>,
    pub owners: Vec<CookieOwner>,
    pub source_file: Option<String>,
    pub file_object: Option<u64>,
    pub database_rowid: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CookieScanReport {
    pub records: Vec<BrowserCookieRecord>,
    pub complete: bool,
    pub runtime_header_hits: usize,
    pub cookie_files_found: usize,
    pub cookie_databases_parsed: usize,
    pub process_address_spaces: usize,
    pub bytes_scanned: u64,
    pub combined_scan_seconds: f64,
    pub file_scan_seconds: f64,
    pub database_parse_seconds: f64,
    pub owner_mapping_seconds: f64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub warnings: Vec<String>,
    /// 与 Cookie 文件在同一轮 FILE_OBJECT 扫描中发现的 Chromium
    /// History/Login Data；仅供浏览器会话聚合复用，不属于 Cookie 报告输出。
    #[serde(skip)]
    pub(crate) browser_artifact_files: Vec<crate::windows::files::FileScanRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CookieFileKind {
    Chromium,
    Firefox,
    LegacyText,
    UnsupportedEse,
}

struct CookieFileCandidate<'a> {
    kind: CookieFileKind,
    browser: String,
    profile: Option<String>,
    path: String,
    file: &'a crate::windows::files::FileScanRecord,
}

pub fn scan_browser_cookies<F>(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    options: &CookieScanOptions,
    mut progress: F,
) -> Result<CookieScanReport>
where
    F: FnMut(CookieScanStage),
{
    let started = Instant::now();
    let CookieScanOptions {
        limit,
        database_limit,
        file_scan_limit,
        max_database_size,
        process_space_limit,
    } = *options;
    ensure!(limit > 0, "Cookie 结果数量上限必须大于零");
    ensure!(database_limit > 0, "Cookie 数据库数量上限必须大于零");
    ensure!(file_scan_limit > 0, "文件扫描数量上限必须大于零");
    ensure!(max_database_size > 0, "Cookie 数据库最大恢复大小必须大于零");
    ensure!(
        process_space_limit > 0,
        "浏览器进程地址空间数量上限必须大于零"
    );

    progress(CookieScanStage::RuntimeHeaders);
    let combined_scan_started = Instant::now();
    let raw_limit = limit.saturating_mul(64).clamp(65_536, 1_000_000);
    let raw = scan_pattern_sets(
        image,
        &[
            ScanPatternSet {
                patterns: &COOKIE_PATTERNS,
                limit_per_pattern: raw_limit,
                ascii_case_insensitive: true,
            },
            ScanPatternSet {
                patterns: &FILE_POOL_PATTERNS,
                limit_per_pattern: 1_000_000,
                ascii_case_insensitive: false,
            },
        ],
        DEFAULT_CHUNK_SIZE,
    )?;
    let cookie_hits = raw
        .hits
        .iter()
        .filter(|hit| hit.pattern_index < COOKIE_PATTERNS.len())
        .cloned()
        .collect::<Vec<_>>();
    let pool_tag_hits = raw
        .hits
        .iter()
        .filter(|hit| hit.pattern_index >= COOKIE_PATTERNS.len())
        .map(|hit| hit.physical_address)
        .collect::<Vec<_>>();
    let cookie_scan_truncated = raw.truncated_patterns[..COOKIE_PATTERNS.len()]
        .iter()
        .any(|truncated| *truncated);
    let pool_scan_truncated = raw.truncated_patterns[COOKIE_PATTERNS.len()..]
        .iter()
        .any(|truncated| *truncated);
    let runtime_header_hits = cookie_hits.len();
    let mut records = parse_runtime_headers(image, &cookie_hits);
    let mut warnings = Vec::new();
    let mut complete = !cookie_scan_truncated;
    if cookie_scan_truncated {
        warnings.push("Cookie 请求或响应头原始命中达到安全上限".to_owned());
    }
    let combined_scan_seconds = combined_scan_started.elapsed().as_secs_f64();

    progress(CookieScanStage::FileObjects);
    let file_scan_started = Instant::now();
    let files = scan_files_matching_from_pool_hits(
        image,
        kernel,
        profile,
        file_scan_limit,
        &is_browser_evidence_file_path,
        &pool_tag_hits,
        pool_scan_truncated,
    )?;
    complete &= files.complete;
    warnings.extend(
        files
            .warnings
            .iter()
            .map(|warning| format!("文件扫描：{warning}")),
    );
    let mut candidates = files
        .records
        .iter()
        .filter_map(classify_cookie_file)
        .collect::<Vec<_>>();
    candidates.sort_unstable_by(|left, right| {
        left.path
            .to_ascii_lowercase()
            .cmp(&right.path.to_ascii_lowercase())
            .then_with(|| {
                left.file
                    .data_section_object
                    .cmp(&right.file.data_section_object)
            })
            .then_with(|| left.file.shared_cache_map.cmp(&right.file.shared_cache_map))
    });
    candidates.dedup_by(|left, right| {
        left.path.eq_ignore_ascii_case(&right.path)
            && left.file.data_section_object == right.file.data_section_object
            && left.file.shared_cache_map == right.file.shared_cache_map
    });
    let cookie_files_found = candidates.len();
    if candidates.len() > database_limit {
        candidates.truncate(database_limit);
        complete = false;
        warnings.push(format!("Cookie 数据库候选达到 {database_limit} 个上限"));
    }
    let file_scan_seconds = file_scan_started.elapsed().as_secs_f64();

    progress(CookieScanStage::Databases);
    let database_parse_started = Instant::now();
    let mut cookie_databases_parsed = 0usize;
    let kernel_space = kernel.address_space(image)?;
    for candidate in candidates {
        if records.len() >= limit.saturating_mul(4) {
            complete = false;
            warnings.push("Cookie 中间结果达到安全上限".to_owned());
            break;
        }
        if candidate.kind == CookieFileKind::UnsupportedEse {
            push_warning(
                &mut warnings,
                format!(
                    "{} 使用 ESE WebCache 数据库；当前已覆盖其进程内明文 Cookie，尚未结构化解析磁盘表",
                    candidate.path
                ),
            );
            complete = false;
            continue;
        }
        let recovered = recover_file_bytes(
            image,
            kernel,
            profile,
            candidate.file.file_object,
            DumpSource::Auto,
            max_database_size,
        );
        let (dump, bytes) = match recovered {
            Ok(value) => value,
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("无法恢复 Cookie 文件 {}：{error:#}", candidate.path),
                );
                continue;
            }
        };
        if dump.recovered_bytes == 0 || bytes.is_empty() {
            complete = false;
            push_warning(
                &mut warnings,
                format!("Cookie 文件 {} 没有驻留内容", candidate.path),
            );
            continue;
        }
        if !dump.complete {
            complete = false;
            push_warning(
                &mut warnings,
                format!(
                    "Cookie 文件 {} 仅恢复 {}/{} 字节",
                    candidate.path, dump.recovered_bytes, dump.logical_size
                ),
            );
        }
        let physical_extents = recovery_physical_extents_windows(&dump.extents, &kernel_space);
        let remaining = limit.saturating_mul(4).saturating_sub(records.len());
        let parsed = match candidate.kind {
            CookieFileKind::Chromium | CookieFileKind::Firefox => {
                parse_cookie_sqlite(&bytes, &candidate, &physical_extents, remaining)
                    .map(|parsed| (parsed.records, parsed.damaged_pages))
            }
            CookieFileKind::LegacyText => {
                parse_legacy_cookie_text(&bytes, &candidate, &physical_extents, remaining)
                    .map(|records| (records, 0))
            }
            CookieFileKind::UnsupportedEse => unreachable!(),
        };
        match parsed {
            Ok((mut parsed, damaged_pages)) => {
                cookie_databases_parsed += 1;
                if damaged_pages > 0 {
                    complete = false;
                    push_warning(
                        &mut warnings,
                        format!(
                            "Cookie 文件 {} 有 {damaged_pages} 个 SQLite 页面或单元损坏，已保留其他可恢复记录",
                            candidate.path
                        ),
                    );
                }
                records.append(&mut parsed);
            }
            Err(error) => {
                complete = false;
                push_warning(
                    &mut warnings,
                    format!("无法解析 Cookie 文件 {}：{error:#}", candidate.path),
                );
            }
        }
    }
    let database_parse_seconds = database_parse_started.elapsed().as_secs_f64();

    progress(CookieScanStage::ProcessOwners);
    let owner_mapping_started = Instant::now();
    let process_address_spaces = if kernel.is_x86_pae() {
        complete = false;
        push_warning(&mut warnings, "x86 PAE 已解析驻留 Cookie 文件；运行时 Cookie 的进程反查尚未覆盖，不能据此归属到某个浏览器进程".to_owned());
        0
    } else {
        associate_process_owners(
            image,
            kernel,
            profile,
            &mut records,
            &mut warnings,
            &mut complete,
            process_space_limit,
        )?
    };
    let owner_mapping_seconds = owner_mapping_started.elapsed().as_secs_f64();
    infer_record_browsers(&mut records);
    records.retain(has_sufficient_runtime_evidence);
    for record in &mut records {
        if record.browser == "未知浏览器" {
            record.browser = "浏览器（进程未关联）".to_owned();
        }
    }
    let mut records = merge_cookie_records(records);
    records.sort_unstable_by(|left, right| {
        confidence_rank(&right.confidence)
            .cmp(&confidence_rank(&left.confidence))
            .then_with(|| left.browser.cmp(&right.browser))
            .then_with(|| left.domain.cmp(&right.domain))
            .then_with(|| left.name.cmp(&right.name))
    });
    if records.len() > limit {
        records.truncate(limit);
        complete = false;
        warnings.push(format!("Cookie 结果达到 {limit} 条上限"));
    }
    let elapsed_seconds = started.elapsed().as_secs_f64().max(f64::EPSILON);
    let total_bytes_scanned = raw.bytes_scanned;
    Ok(CookieScanReport {
        records,
        complete,
        runtime_header_hits,
        cookie_files_found,
        cookie_databases_parsed,
        process_address_spaces,
        bytes_scanned: total_bytes_scanned,
        combined_scan_seconds,
        file_scan_seconds,
        database_parse_seconds,
        owner_mapping_seconds,
        scan_seconds: elapsed_seconds,
        scan_gib_per_second: combined_throughput(total_bytes_scanned, elapsed_seconds),
        warnings,
        browser_artifact_files: files
            .records
            .into_iter()
            .filter(|file| {
                file.name
                    .as_deref()
                    .is_some_and(is_browser_artifact_file_path)
            })
            .collect(),
    })
}

fn parse_runtime_headers(
    image: &MemoryImage,
    hits: &[crate::scan::MultiScanHit],
) -> Vec<BrowserCookieRecord> {
    let mut records = Vec::new();
    let mut seen_lines = HashSet::new();
    for hit in hits {
        let encoding = if hit.pattern_index < 2 {
            CookieEncoding::Ascii
        } else {
            CookieEncoding::Utf16Le
        };
        let Some((bytes, hit_offset, context_start)) = read_context(image, hit.physical_address)
        else {
            continue;
        };
        let Some((line, line_byte_offset)) = extract_header_line(&bytes, hit_offset, encoding)
        else {
            continue;
        };
        let line_address = context_start.saturating_add(line_byte_offset as u64);
        if !seen_lines.insert((line_address, encoding as u8)) {
            continue;
        }
        let context = decode_context(&bytes, hit_offset, encoding);
        let host = find_context_host(&context);
        let browser = infer_browser_from_text(&context).unwrap_or_else(|| "未知浏览器".to_owned());
        records.extend(parse_cookie_header(
            &line,
            host,
            browser,
            encoding,
            line_address,
        ));
    }
    records
}

fn read_context(image: &MemoryImage, address: u64) -> Option<(Vec<u8>, usize, u64)> {
    let span = image
        .spans()
        .iter()
        .find(|span| address >= span.start && address < span.end())?;
    let start = address.saturating_sub(CONTEXT_BEFORE).max(span.start);
    let end = address.saturating_add(CONTEXT_AFTER).min(span.end());
    let mut bytes = vec![0u8; usize::try_from(end.checked_sub(start)?).ok()?];
    image.read_physical(start, &mut bytes).ok()?;
    Some((bytes, usize::try_from(address - start).ok()?, start))
}

fn extract_header_line(
    bytes: &[u8],
    hit_offset: usize,
    encoding: CookieEncoding,
) -> Option<(String, usize)> {
    match encoding {
        CookieEncoding::Ascii => {
            let start = bytes[..hit_offset.min(bytes.len())]
                .iter()
                .rposition(|byte| is_line_boundary(*byte) || !is_header_ascii(*byte))
                .map_or(0, |index| index + 1);
            let end = bytes[hit_offset.min(bytes.len())..]
                .iter()
                .position(|byte| is_line_boundary(*byte) || !is_header_ascii(*byte))
                .map_or(bytes.len(), |index| hit_offset + index)
                .min(start.saturating_add(MAX_HEADER_CHARS));
            let line = std::str::from_utf8(bytes.get(start..end)?).ok()?.trim();
            header_kind(line).map(|_| (line.to_owned(), start))
        }
        CookieEncoding::Utf16Le => {
            let parity = hit_offset & 1;
            let units = bytes[parity..]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            let hit_unit = (hit_offset.saturating_sub(parity) / 2).min(units.len());
            let start = units[..hit_unit]
                .iter()
                .rposition(|unit| is_wide_line_boundary(*unit) || !is_header_wide(*unit))
                .map_or(0, |index| index + 1);
            let end = units[hit_unit..]
                .iter()
                .position(|unit| is_wide_line_boundary(*unit) || !is_header_wide(*unit))
                .map_or(units.len(), |index| hit_unit + index)
                .min(start.saturating_add(MAX_HEADER_CHARS));
            let line = String::from_utf16(units.get(start..end)?).ok()?;
            let line = line.trim();
            header_kind(line).map(|_| (line.to_owned(), parity + start * 2))
        }
        CookieEncoding::Sqlite | CookieEncoding::TextFile => None,
    }
}

fn decode_context(bytes: &[u8], hit_offset: usize, encoding: CookieEncoding) -> String {
    match encoding {
        CookieEncoding::Ascii => bytes
            .iter()
            .map(|byte| {
                if matches!(byte, b'\t' | b'\r' | b'\n' | 0x20..=0x7e) {
                    char::from(*byte)
                } else {
                    '\n'
                }
            })
            .collect(),
        CookieEncoding::Utf16Le => {
            let parity = hit_offset & 1;
            let units = bytes[parity..]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            String::from_utf16_lossy(&units)
        }
        CookieEncoding::Sqlite | CookieEncoding::TextFile => String::new(),
    }
}

fn parse_cookie_header(
    line: &str,
    context_host: Option<String>,
    browser: String,
    encoding: CookieEncoding,
    physical_address: u64,
) -> Vec<BrowserCookieRecord> {
    let Some((source, value)) = header_kind(line) else {
        return Vec::new();
    };
    match source {
        CookieSource::ResponseHeader => {
            parse_set_cookie(value, context_host, browser, encoding, physical_address)
                .into_iter()
                .collect()
        }
        CookieSource::RequestHeader => {
            parse_request_cookies(value, context_host, browser, encoding, physical_address)
        }
        _ => Vec::new(),
    }
}

fn header_kind(line: &str) -> Option<(CookieSource, &str)> {
    let line = line.trim_start();
    if line
        .get(..11)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Set-Cookie:"))
    {
        return Some((CookieSource::ResponseHeader, line[11..].trim()));
    }
    if line
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Cookie:"))
    {
        return Some((CookieSource::RequestHeader, line[7..].trim()));
    }
    None
}

fn parse_request_cookies(
    value: &str,
    domain: Option<String>,
    browser: String,
    encoding: CookieEncoding,
    physical_address: u64,
) -> Vec<BrowserCookieRecord> {
    value
        .split(';')
        .filter_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            let name = name.trim();
            let value = value.trim();
            if name.starts_with('$') || !plausible_cookie_pair(name, value) {
                return None;
            }
            Some(BrowserCookieRecord {
                browser: browser.clone(),
                profile: None,
                source: CookieSource::RequestHeader,
                encoding,
                domain: domain.clone(),
                path: None,
                name: name.to_owned(),
                value: Some(value.to_owned()),
                encrypted_value_hex: None,
                encrypted: false,
                expires: None,
                secure: None,
                http_only: None,
                same_site: None,
                confidence: if domain.is_some() { "high" } else { "medium" }.to_owned(),
                occurrences: 1,
                physical_addresses: vec![physical_address],
                owners: Vec::new(),
                source_file: None,
                file_object: None,
                database_rowid: None,
            })
        })
        .collect()
}

fn parse_set_cookie(
    value: &str,
    context_host: Option<String>,
    browser: String,
    encoding: CookieEncoding,
    physical_address: u64,
) -> Option<BrowserCookieRecord> {
    let mut parts = value.split(';');
    let (name, cookie_value) = parts.next()?.trim().split_once('=')?;
    let name = name.trim();
    let cookie_value = cookie_value.trim();
    if !plausible_cookie_pair(name, cookie_value) {
        return None;
    }
    let mut domain = context_host;
    let mut path = None;
    let mut expires = None;
    let mut secure = false;
    let mut http_only = false;
    let mut same_site = None;
    for attribute in parts {
        let attribute = attribute.trim();
        let (key, attribute_value) = attribute
            .split_once('=')
            .map_or((attribute, None), |(key, value)| (key, Some(value.trim())));
        if key.eq_ignore_ascii_case("domain") {
            domain = attribute_value.map(normalize_domain);
        } else if key.eq_ignore_ascii_case("path") {
            path = attribute_value.map(ToOwned::to_owned);
        } else if key.eq_ignore_ascii_case("expires") {
            expires = attribute_value.map(ToOwned::to_owned);
        } else if key.eq_ignore_ascii_case("max-age") && expires.is_none() {
            expires = attribute_value.map(|value| format!("Max-Age={value}"));
        } else if key.eq_ignore_ascii_case("secure") {
            secure = true;
        } else if key.eq_ignore_ascii_case("httponly") {
            http_only = true;
        } else if key.eq_ignore_ascii_case("samesite") {
            same_site = attribute_value.map(ToOwned::to_owned);
        }
    }
    Some(BrowserCookieRecord {
        browser,
        profile: None,
        source: CookieSource::ResponseHeader,
        encoding,
        domain: domain.clone(),
        path,
        name: name.to_owned(),
        value: Some(cookie_value.to_owned()),
        encrypted_value_hex: None,
        encrypted: false,
        expires,
        secure: Some(secure),
        http_only: Some(http_only),
        same_site,
        confidence: if domain.is_some() { "high" } else { "medium" }.to_owned(),
        occurrences: 1,
        physical_addresses: vec![physical_address],
        owners: Vec::new(),
        source_file: None,
        file_object: None,
        database_rowid: None,
    })
}

fn plausible_cookie_pair(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_COOKIE_NAME
        && value.len() <= MAX_COOKIE_VALUE
        && !contains_format_placeholder(name)
        && !contains_format_placeholder(value)
        && name
            .bytes()
            .all(|byte| matches!(byte, 0x21..=0x7e) && !b"()<>@,;:\\\"/[]?={} \t".contains(&byte))
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\u{fffd}')
}

fn contains_format_placeholder(value: &str) -> bool {
    let bytes = value.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] == b'%'
            && bytes
                .get(index + 1)
                .is_some_and(|next| b"cdeEfgGiopsuxX".contains(next))
        {
            return true;
        }
        if bytes[index] == b'{' {
            let mut cursor = index + 1;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                cursor += 1;
            }
            if cursor > index + 1 && bytes.get(cursor) == Some(&b'}') {
                return true;
            }
        }
    }
    false
}

fn find_context_host(context: &str) -> Option<String> {
    for line in context.lines() {
        let line = line.trim();
        if line
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Host:"))
        {
            let host = line[5..].split_whitespace().next()?;
            let host = host
                .strip_prefix('[')
                .and_then(|value| value.split_once(']').map(|(host, _)| host))
                .or_else(|| host.split_once(':').map(|(host, _)| host))
                .unwrap_or(host);
            if plausible_domain(host) {
                return Some(normalize_domain(host));
            }
        }
    }
    None
}

fn normalize_domain(value: &str) -> String {
    value
        .trim()
        .trim_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn plausible_domain(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']');
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    if value.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return false;
    }
    let labels = value.split('.').collect::<Vec<_>>();
    if labels.len() == 1
        && (value.len() < 2 || !value.bytes().any(|byte| byte.is_ascii_alphabetic()))
    {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
    }) && value.bytes().any(|byte| byte.is_ascii_alphabetic())
}

fn is_line_boundary(byte: u8) -> bool {
    matches!(byte, 0 | b'\r' | b'\n')
}

fn is_header_ascii(byte: u8) -> bool {
    matches!(byte, b'\t' | 0x20..=0x7e)
}

fn is_wide_line_boundary(unit: u16) -> bool {
    matches!(unit, 0 | 0x0d | 0x0a)
}

fn is_header_wide(unit: u16) -> bool {
    unit == 9 || unit >= 0x20 && !matches!(unit, 0xfffd | 0xfdd0..=0xfdef)
}

fn classify_cookie_file(
    file: &crate::windows::files::FileScanRecord,
) -> Option<CookieFileCandidate<'_>> {
    let path = file.name.as_ref()?;
    let normalized = path.replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();
    let kind = cookie_file_kind(&lower)?;
    let browser = infer_browser_from_path(&lower, kind);
    let profile = infer_profile_from_path(&normalized, kind);
    Some(CookieFileCandidate {
        kind,
        browser,
        profile,
        path: normalized,
        file,
    })
}

fn is_cookie_file_path(path: &str) -> bool {
    cookie_file_kind(&path.replace('/', "\\").to_ascii_lowercase()).is_some()
}

fn is_browser_evidence_file_path(path: &str) -> bool {
    is_cookie_file_path(path) || is_browser_artifact_file_path(path)
}

pub(crate) fn is_browser_artifact_file_path(path: &str) -> bool {
    is_chromium_artifact_file_path(path) || is_firefox_artifact_file_path(path)
}

pub(crate) fn is_firefox_artifact_file_path(path: &str) -> bool {
    // These names also work for portable/custom Firefox profiles. The parser
    // must still verify the Places tables or LoginStore JSON schema.
    matches!(
        path.rsplit(['\\', '/'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str(),
        "places.sqlite" | "logins.json"
    )
}

pub(crate) fn is_chromium_artifact_file_path(path: &str) -> bool {
    let normalized = path.replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();
    let Some(base) = lower.rsplit('\\').next() else {
        return false;
    };
    matches!(base, "history" | "login data")
        && (lower.contains("\\user data\\")
            || lower.contains("\\ebwebview\\")
            || lower.contains("\\webview2\\")
            || lower.contains("\\cef\\")
            || [
                "opera software",
                "360chrome",
                "360se",
                "qqbrowser",
                "sogouexplorer",
                "bravesoftware",
                "vivaldi",
                "chromium",
            ]
            .iter()
            .any(|component| lower.split('\\').any(|part| part == *component)))
}

pub(crate) fn infer_chromium_browser_from_path(path: &str) -> String {
    infer_browser_from_path(
        &path.replace('/', "\\").to_ascii_lowercase(),
        CookieFileKind::Chromium,
    )
}

pub(crate) fn infer_chromium_profile_from_path(path: &str) -> Option<String> {
    infer_profile_from_path(&path.replace('/', "\\"), CookieFileKind::Chromium)
}

pub(crate) fn infer_firefox_profile_from_path(path: &str) -> Option<String> {
    infer_profile_from_path(&path.replace('/', "\\"), CookieFileKind::Firefox)
}

fn cookie_file_kind(lower_path: &str) -> Option<CookieFileKind> {
    let base = lower_path.rsplit('\\').next()?;
    if base == "cookies.sqlite" {
        Some(CookieFileKind::Firefox)
    } else if base == "cookies" || base == "cookies.db" {
        Some(CookieFileKind::Chromium)
    } else if base == "webcachev01.dat" {
        Some(CookieFileKind::UnsupportedEse)
    } else if base.ends_with(".txt") && lower_path.contains("\\cookies\\") {
        Some(CookieFileKind::LegacyText)
    } else {
        None
    }
}

fn infer_browser_from_path(path: &str, kind: CookieFileKind) -> String {
    if let Some(application) = infer_embedded_application(path) {
        return application.to_owned();
    }
    [
        ("google\\chrome", "Chrome"),
        ("microsoft\\edge", "Edge"),
        ("bravesoftware\\brave-browser", "Brave"),
        ("vivaldi", "Vivaldi"),
        ("opera software", "Opera"),
        ("chromium", "Chromium"),
        ("mozilla\\firefox", "Firefox"),
        ("360chrome", "360 极速浏览器"),
        ("360se", "360 安全浏览器"),
        ("qqbrowser", "QQ 浏览器"),
        ("sogouexplorer", "搜狗浏览器"),
        ("internet explorer", "Internet Explorer"),
        ("webcache", "Internet Explorer/旧版 Edge"),
    ]
    .into_iter()
    .find_map(|(needle, browser)| path.contains(needle).then(|| browser.to_owned()))
    .unwrap_or_else(|| match kind {
        CookieFileKind::Firefox => "Firefox 系浏览器".to_owned(),
        CookieFileKind::Chromium => "Chromium 系浏览器".to_owned(),
        CookieFileKind::LegacyText => "Internet Explorer".to_owned(),
        CookieFileKind::UnsupportedEse => "Internet Explorer/旧版 Edge".to_owned(),
    })
}

fn infer_embedded_application(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("ebwebview")
        && (lower.contains("microsoftwindows.client.cbs")
            || lower.contains("microsoftwindows.client.webexperience"))
    {
        return Some("Windows WebView2");
    }
    let application = [
        ("doubao", "豆包"),
        ("kingsoft", "WPS 内嵌浏览器"),
        ("\\wps\\", "WPS 内嵌浏览器"),
        ("qqmusic", "QQ音乐内嵌浏览器"),
        ("xwechat", "微信内嵌浏览器"),
        ("wechat", "微信内嵌浏览器"),
        ("weixin", "微信内嵌浏览器"),
        ("quark", "夸克"),
        ("\\codex\\", "Codex 内嵌浏览器"),
        ("codex.exe", "Codex 内嵌浏览器"),
        ("claude", "Claude"),
        ("postman", "Postman"),
        ("steamwebhelper", "Steam 内嵌浏览器"),
        ("\\steam\\", "Steam 内嵌浏览器"),
        ("baidunetdisk", "百度网盘内嵌浏览器"),
        ("baidu netdisk", "百度网盘内嵌浏览器"),
        ("netease\\uu", "网易 UU 内嵌浏览器"),
        ("\\uu\\", "网易 UU 内嵌浏览器"),
        ("qqex", "QQ 内嵌浏览器"),
        ("\\tencent\\qq\\", "QQ 内嵌浏览器"),
        ("\\roaming\\qq\\", "QQ 内嵌浏览器"),
        ("dog.ctf.lovelymem.luxe", "LovelyMem.Luxe 内嵌浏览器"),
        ("nvidia overlay", "NVIDIA Overlay"),
        ("nvidia share", "NVIDIA Overlay"),
    ]
    .into_iter()
    .find_map(|(needle, application)| lower.contains(needle).then_some(application));
    application.or_else(|| {
        (lower.contains("ebwebview") || lower.contains("msedgewebview2")).then_some("WebView2")
    })
}

fn infer_profile_from_path(path: &str, kind: CookieFileKind) -> Option<String> {
    let parts = path.split('\\').collect::<Vec<_>>();
    match kind {
        CookieFileKind::Chromium => parts
            .windows(2)
            .find(|window| window[0].eq_ignore_ascii_case("User Data"))
            .filter(|window| {
                !matches!(
                    window[1].to_ascii_lowercase().as_str(),
                    "history" | "login data" | "cookies"
                )
            })
            .map(|window| window[1].to_owned())
            .or_else(|| {
                parts
                    .iter()
                    .rev()
                    .skip(1)
                    .find(|part| {
                        part.eq_ignore_ascii_case("Default")
                            || part.to_ascii_lowercase().starts_with("profile ")
                    })
                    .map(|part| (*part).to_owned())
            })
            .or_else(|| {
                parts
                    .iter()
                    .rev()
                    .find(|part| {
                        part.to_ascii_lowercase().starts_with("opera ")
                            && !part.eq_ignore_ascii_case("Opera Software")
                    })
                    .map(|part| (*part).to_owned())
            }),
        CookieFileKind::Firefox => parts
            .windows(2)
            .find(|window| window[0].eq_ignore_ascii_case("Profiles"))
            .map(|window| window[1].to_owned()),
        CookieFileKind::LegacyText | CookieFileKind::UnsupportedEse => parts
            .windows(2)
            .find(|window| window[0].eq_ignore_ascii_case("Users"))
            .map(|window| window[1].to_owned()),
    }
}

#[derive(Debug, Clone)]
pub(crate) enum SqlValue {
    Null,
    Integer(i64),
    Real,
    Blob(Vec<u8>),
    Text(String),
}

#[derive(Debug)]
pub(crate) struct SqlRow {
    pub(crate) rowid: i64,
    pub(crate) values: Vec<SqlValue>,
    /// One-based SQLite b-tree page containing the leaf cell.
    pub(crate) page_number: u32,
    /// File offset of the leaf cell, not merely the start of its page.
    pub(crate) file_offset: u64,
    /// Exact byte ranges consumed to reconstruct the record header and payload,
    /// including overflow-page headers and fragments.
    pub(crate) source_ranges: Vec<SqliteSourceRange>,
}

#[derive(Debug, Clone)]
pub(crate) struct SqliteSourceRange {
    pub(crate) page_number: u32,
    pub(crate) file_offset: u64,
    pub(crate) length: u64,
}

struct SqliteDatabase<'a> {
    bytes: &'a [u8],
    page_size: usize,
    usable_size: usize,
}

struct SqliteRows {
    rows: Vec<SqlRow>,
    damaged_pages: usize,
    limit_reached: bool,
}

struct SqliteCellPayload {
    bytes: Vec<u8>,
    source_ranges: Vec<SqliteSourceRange>,
}

#[derive(Debug, Clone, Copy)]
enum SqliteRowOrder {
    Ascending,
    Descending,
}

const MAX_SQLITE_CELL_PAYLOAD: usize = 64 * 1024 * 1024;

struct CookieSqliteParse {
    records: Vec<BrowserCookieRecord>,
    damaged_pages: usize,
}

pub(crate) struct SqliteTable {
    pub(crate) columns: HashMap<String, usize>,
    pub(crate) rows: Vec<SqlRow>,
    pub(crate) damaged_pages: usize,
    /// Indicates that a one-row sentinel beyond the requested safety limit was
    /// recovered and additional records were therefore hidden.
    pub(crate) limit_reached: bool,
    pub(crate) page_size: usize,
    /// Exact sqlite_schema record ranges used to name and decode this table.
    pub(crate) schema_source_ranges: Vec<SqliteSourceRange>,
    pub(crate) create_sql: String,
}

pub(crate) fn parse_sqlite_table(
    bytes: &[u8],
    wanted: &[&str],
    limit: usize,
) -> Result<SqliteTable> {
    parse_sqlite_table_ordered(bytes, wanted, limit, SqliteRowOrder::Ascending)
}

/// Visit allocated table-leaf cells without claiming a table name. This is a
/// salvage path for missing sqlite_schema pages, not a substitute schema.
/// The caller supplies resident-byte coverage; sparse recovery zeroes cannot
/// satisfy either a page or an overflow payload. No index/free-space carving.
pub(crate) fn visit_resident_sqlite_leaf_rows(
    bytes: &[u8],
    resident: impl Fn(u64, u64) -> bool,
    mut visit: impl FnMut(SqlRow, usize) -> bool,
) -> Result<()> {
    ensure!(resident(0, 100), "SQLite 文件头未完整驻留");
    ensure!(
        bytes.len() >= 100 && bytes.starts_with(b"SQLite format 3\0"),
        "SQLite 文件头无效"
    );
    let raw = u16::from_be_bytes([bytes[16], bytes[17]]);
    let page_size = if raw == 1 { 65536 } else { usize::from(raw) };
    ensure!(
        (512..=65536).contains(&page_size) && page_size.is_power_of_two(),
        "SQLite 页大小无效"
    );
    ensure!(
        bytes[56..60] == [0, 0, 0, 1],
        "叶页恢复目前只支持 UTF-8 SQLite"
    );
    let usable_size = page_size - usize::from(bytes[20]);
    ensure!(usable_size >= 480, "SQLite 可用页大小无效");
    let db = SqliteDatabase {
        bytes,
        page_size,
        usable_size,
    };
    for (index, page) in bytes.chunks_exact(page_size).enumerate() {
        let file_offset = (index * page_size) as u64;
        let header = if index == 0 { 100 } else { 0 };
        if !resident(file_offset, page_size as u64) || page[header] != 0x0d {
            continue;
        }
        let count = usize::from(read_be_u16(page, header + 3)?);
        let pointers_end = header + 8 + count * 2;
        let raw_start = usize::from(read_be_u16(page, header + 5)?);
        let content_start = if raw_start == 0 { 65536 } else { raw_start };
        if pointers_end > content_start || content_start > usable_size || page[header + 7] > 60 {
            continue;
        }
        let page_number = u32::try_from(index + 1)?;
        let mut cells = Vec::with_capacity(count);
        let mut intervals = Vec::with_capacity(count);
        let mut valid = true;
        let mut payload_budget = 8 * 1024 * 1024;
        for cell_index in 0..count {
            let cell = usize::from(read_be_u16(page, header + 8 + cell_index * 2)?);
            if cell < content_start || cell >= usable_size {
                valid = false;
                break;
            }
            // Limit each unclassified cell before allocating its payload.
            let Some((size, _)) = read_sqlite_varint(page, cell) else {
                valid = false;
                break;
            };
            if size > 1024 * 1024 || size > payload_budget {
                valid = false;
                break;
            }
            payload_budget -= size;
            let Some(row) = db.parse_leaf_cell(
                page,
                page_number,
                file_offset,
                cell,
                file_offset + cell as u64,
            ) else {
                valid = false;
                break;
            };
            let local = &row.source_ranges[0];
            if local.file_offset + local.length > file_offset + usable_size as u64 {
                valid = false;
                break;
            }
            intervals.push((local.file_offset, local.file_offset + local.length));
            if row
                .source_ranges
                .iter()
                .all(|r| resident(r.file_offset, r.length))
            {
                cells.push(row);
            }
        }
        intervals.sort_unstable();
        if !valid || intervals.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            continue;
        }
        for row in cells {
            if !visit(row, page_size) {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Enumerate schema names for bounded application-specific adapters. Callers
/// must validate recovered page coverage before using this byte view.
pub(crate) fn sqlite_table_names(bytes: &[u8]) -> Result<Vec<String>> {
    ensure!(
        bytes.len() >= 100 && bytes.starts_with(b"SQLite format 3\0"),
        "SQLite 头不完整"
    );
    let raw = u16::from_be_bytes([bytes[16], bytes[17]]);
    let page_size = if raw == 1 { 65536 } else { usize::from(raw) };
    ensure!(
        (512..=65536).contains(&page_size) && page_size.is_power_of_two(),
        "SQLite 页大小无效"
    );
    let db = SqliteDatabase {
        bytes,
        page_size,
        usable_size: page_size - usize::from(bytes[20]),
    };
    Ok(db
        .table_rows(1, 256)
        .rows
        .into_iter()
        .filter_map(|r| {
            (sql_text(r.values.first()?)? == "table")
                .then(|| sql_text(r.values.get(1)?).map(str::to_owned))
                .flatten()
        })
        .collect())
}

pub(crate) fn parse_sqlite_table_descending(
    bytes: &[u8],
    wanted: &[&str],
    limit: usize,
) -> Result<SqliteTable> {
    parse_sqlite_table_ordered(bytes, wanted, limit, SqliteRowOrder::Descending)
}

/// Resolve a bounded set of INTEGER PRIMARY KEY / rowid values without
/// walking and retaining the entire table. Chromium History uses this for the
/// `visits.url -> urls.id` foreign key after the bounded visits view has been
/// selected.
pub(crate) fn parse_sqlite_table_by_rowids(
    bytes: &[u8],
    wanted: &[&str],
    rowids: &BTreeSet<i64>,
) -> Result<SqliteTable> {
    parse_sqlite_table_selected(bytes, wanted, SqliteRowSelection::Rowids(rowids))
}

fn parse_sqlite_table_ordered(
    bytes: &[u8],
    wanted: &[&str],
    limit: usize,
    order: SqliteRowOrder,
) -> Result<SqliteTable> {
    parse_sqlite_table_selected(bytes, wanted, SqliteRowSelection::Ordered { limit, order })
}

#[derive(Debug, Clone, Copy)]
enum SqliteRowSelection<'a> {
    Ordered { limit: usize, order: SqliteRowOrder },
    Rowids(&'a BTreeSet<i64>),
}

fn parse_sqlite_table_selected(
    bytes: &[u8],
    wanted: &[&str],
    selection: SqliteRowSelection<'_>,
) -> Result<SqliteTable> {
    ensure!(
        bytes.len() >= 100 && bytes.starts_with(b"SQLite format 3\0"),
        "文件头不是 SQLite 3 数据库"
    );
    let page_size_raw = usize::from(u16::from_be_bytes([bytes[16], bytes[17]]));
    let page_size = if page_size_raw == 1 {
        65_536
    } else {
        page_size_raw
    };
    ensure!(
        (512..=65_536).contains(&page_size) && page_size.is_power_of_two(),
        "SQLite 页面大小无效：{page_size}"
    );
    let reserved = usize::from(bytes[20]);
    ensure!(reserved < page_size, "SQLite 保留区大小无效");
    let database = SqliteDatabase {
        bytes,
        page_size,
        usable_size: page_size - reserved,
    };
    let master = database.table_rows(1, 16_384);
    let mut damaged_pages = master.damaged_pages;
    let table = master.rows.into_iter().find_map(|row| {
        let object_type = sql_text(row.values.first()?)?;
        let name = sql_text(row.values.get(1)?)?;
        let root = sql_integer(row.values.get(3)?)?;
        let sql = sql_text(row.values.get(4)?)?;
        (object_type.eq_ignore_ascii_case("table")
            && wanted
                .iter()
                .any(|wanted| name.eq_ignore_ascii_case(wanted))
            && root > 0)
            .then(|| (root as u32, sql.to_owned(), row.source_ranges.clone()))
    });
    let (root_page, schema, schema_source_ranges) =
        table.ok_or_else(|| anyhow::anyhow!("没有找到数据表：{}", wanted.join("/")))?;
    let columns = parse_create_columns(&schema);
    ensure!(!columns.is_empty(), "无法解析 SQLite 数据表字段");
    let rows = match selection {
        SqliteRowSelection::Ordered { limit, order } => {
            database.table_rows_ordered(root_page, limit, order)
        }
        SqliteRowSelection::Rowids(rowids) => database.table_rows_by_rowids(root_page, rowids),
    };
    damaged_pages = damaged_pages.saturating_add(rows.damaged_pages);
    Ok(SqliteTable {
        columns: columns
            .iter()
            .enumerate()
            .map(|(index, name)| (name.to_ascii_lowercase(), index))
            .collect(),
        rows: rows.rows,
        damaged_pages,
        limit_reached: rows.limit_reached,
        page_size,
        schema_source_ranges,
        create_sql: schema,
    })
}

fn parse_cookie_sqlite(
    bytes: &[u8],
    candidate: &CookieFileCandidate<'_>,
    extents: &[RecoveredExtent],
    limit: usize,
) -> Result<CookieSqliteParse> {
    let wanted = match candidate.kind {
        CookieFileKind::Chromium => ["cookies", "Cookies"].as_slice(),
        CookieFileKind::Firefox => ["moz_cookies", "cookies"].as_slice(),
        _ => &[],
    };
    let table = parse_sqlite_table(bytes, wanted, limit)?;
    Ok(CookieSqliteParse {
        records: table
            .rows
            .into_iter()
            .filter_map(|row| cookie_from_sql_row(&row, &table.columns, candidate, extents))
            .collect(),
        damaged_pages: table.damaged_pages,
    })
}

impl SqliteDatabase<'_> {
    fn table_rows(&self, root_page: u32, limit: usize) -> SqliteRows {
        self.table_rows_ordered(root_page, limit, SqliteRowOrder::Ascending)
    }

    fn table_rows_ordered(
        &self,
        root_page: u32,
        limit: usize,
        order: SqliteRowOrder,
    ) -> SqliteRows {
        let mut rows = Vec::new();
        let mut visited = HashSet::new();
        let mut damaged_pages = 0usize;
        let scan_limit = limit.saturating_add(1);
        self.walk_table(
            root_page,
            scan_limit,
            order,
            &mut visited,
            &mut rows,
            &mut damaged_pages,
        );
        let limit_reached = rows.len() > limit;
        rows.truncate(limit);
        SqliteRows {
            limit_reached,
            rows,
            damaged_pages,
        }
    }

    fn table_rows_by_rowids(&self, root_page: u32, rowids: &BTreeSet<i64>) -> SqliteRows {
        let mut rows = Vec::with_capacity(rowids.len());
        let mut damaged_pages = HashSet::new();
        for rowid in rowids {
            let mut visited = HashSet::new();
            if let Some(row) =
                self.table_row_by_rowid(root_page, *rowid, &mut visited, &mut damaged_pages)
            {
                rows.push(row);
            }
        }
        SqliteRows {
            rows,
            damaged_pages: damaged_pages.len(),
            // The requested key set is itself the bound; no unseen table rows
            // are relevant to this lookup.
            limit_reached: false,
        }
    }

    fn table_row_by_rowid(
        &self,
        page_number: u32,
        target: i64,
        visited: &mut HashSet<u32>,
        damaged_pages: &mut HashSet<u32>,
    ) -> Option<SqlRow> {
        if page_number == 0 || !visited.insert(page_number) {
            damaged_pages.insert(page_number);
            return None;
        }
        let (page, page_file_offset) = match self.page(page_number) {
            Ok(page) => page,
            Err(_) => {
                damaged_pages.insert(page_number);
                return None;
            }
        };
        let header = if page_number == 1 { 100 } else { 0 };
        let Some(&page_type) = page.get(header) else {
            damaged_pages.insert(page_number);
            return None;
        };
        let cell_count = match read_be_u16(page, header.saturating_add(3)).map(usize::from) {
            Ok(count) => count,
            Err(_) => {
                damaged_pages.insert(page_number);
                return None;
            }
        };
        match page_type {
            0x05 => {
                let pointer_start = match header.checked_add(12) {
                    Some(value) => value,
                    None => {
                        damaged_pages.insert(page_number);
                        return None;
                    }
                };
                if cell_count > page.len().saturating_sub(pointer_start) / 2 {
                    damaged_pages.insert(page_number);
                    return None;
                }
                for index in 0..cell_count {
                    let pointer_offset = match pointer_start.checked_add(index.saturating_mul(2)) {
                        Some(value) => value,
                        None => {
                            damaged_pages.insert(page_number);
                            return None;
                        }
                    };
                    let pointer = match read_be_u16(page, pointer_offset).map(usize::from) {
                        Ok(value) => value,
                        Err(_) => {
                            damaged_pages.insert(page_number);
                            return None;
                        }
                    };
                    let child = match read_be_u32(page, pointer) {
                        Ok(value) => value,
                        Err(_) => {
                            damaged_pages.insert(page_number);
                            return None;
                        }
                    };
                    let key_offset = match pointer.checked_add(4) {
                        Some(value) => value,
                        None => {
                            damaged_pages.insert(page_number);
                            return None;
                        }
                    };
                    let Some((key, _)) = read_sqlite_varint(page, key_offset) else {
                        damaged_pages.insert(page_number);
                        return None;
                    };
                    if target <= key as i64 {
                        return self.table_row_by_rowid(child, target, visited, damaged_pages);
                    }
                }
                let right = match read_be_u32(page, header.saturating_add(8)) {
                    Ok(value) => value,
                    Err(_) => {
                        damaged_pages.insert(page_number);
                        return None;
                    }
                };
                self.table_row_by_rowid(right, target, visited, damaged_pages)
            }
            0x0d => {
                let pointer_start = match header.checked_add(8) {
                    Some(value) => value,
                    None => {
                        damaged_pages.insert(page_number);
                        return None;
                    }
                };
                if cell_count > page.len().saturating_sub(pointer_start) / 2 {
                    damaged_pages.insert(page_number);
                    return None;
                }
                for index in 0..cell_count {
                    let pointer_offset = match pointer_start.checked_add(index.saturating_mul(2)) {
                        Some(value) => value,
                        None => {
                            damaged_pages.insert(page_number);
                            return None;
                        }
                    };
                    let pointer = match read_be_u16(page, pointer_offset).map(usize::from) {
                        Ok(value) => value,
                        Err(_) => {
                            damaged_pages.insert(page_number);
                            return None;
                        }
                    };
                    let Some((_, payload_varint)) = read_sqlite_varint(page, pointer) else {
                        damaged_pages.insert(page_number);
                        return None;
                    };
                    let rowid_offset = match pointer.checked_add(payload_varint) {
                        Some(value) => value,
                        None => {
                            damaged_pages.insert(page_number);
                            return None;
                        }
                    };
                    let Some((rowid, _)) = read_sqlite_varint(page, rowid_offset) else {
                        damaged_pages.insert(page_number);
                        return None;
                    };
                    let rowid = rowid as i64;
                    if rowid == target {
                        return self
                            .parse_leaf_cell(
                                page,
                                page_number,
                                page_file_offset,
                                pointer,
                                page_file_offset.saturating_add(pointer as u64),
                            )
                            .or_else(|| {
                                damaged_pages.insert(page_number);
                                None
                            });
                    }
                    if rowid > target {
                        return None;
                    }
                }
                None
            }
            _ => {
                damaged_pages.insert(page_number);
                None
            }
        }
    }

    fn walk_table(
        &self,
        page_number: u32,
        limit: usize,
        order: SqliteRowOrder,
        visited: &mut HashSet<u32>,
        rows: &mut Vec<SqlRow>,
        damaged_pages: &mut usize,
    ) {
        if rows.len() >= limit {
            return;
        }
        if page_number == 0 || !visited.insert(page_number) {
            *damaged_pages = damaged_pages.saturating_add(1);
            return;
        }
        let Ok((page, page_file_offset)) = self.page(page_number) else {
            *damaged_pages = damaged_pages.saturating_add(1);
            return;
        };
        let header = if page_number == 1 { 100 } else { 0 };
        if header >= page.len() {
            *damaged_pages = damaged_pages.saturating_add(1);
            return;
        }
        let page_type = page[header];
        let Ok(cell_count) = read_be_u16(page, header + 3).map(usize::from) else {
            *damaged_pages = damaged_pages.saturating_add(1);
            return;
        };
        match page_type {
            0x05 => {
                let pointer_start = header + 12;
                if cell_count > page.len().saturating_sub(pointer_start) / 2 {
                    *damaged_pages = damaged_pages.saturating_add(1);
                    return;
                }
                let right = read_be_u32(page, header + 8);
                if matches!(order, SqliteRowOrder::Descending) {
                    match right {
                        Ok(right) => {
                            self.walk_table(right, limit, order, visited, rows, damaged_pages)
                        }
                        Err(_) => *damaged_pages = damaged_pages.saturating_add(1),
                    }
                    if rows.len() >= limit {
                        return;
                    }
                }
                let indices: Box<dyn Iterator<Item = usize>> = match order {
                    SqliteRowOrder::Ascending => Box::new(0..cell_count),
                    SqliteRowOrder::Descending => Box::new((0..cell_count).rev()),
                };
                for index in indices {
                    let pointer_offset = pointer_start + index * 2;
                    let Ok(pointer) = read_be_u16(page, pointer_offset).map(usize::from) else {
                        *damaged_pages = damaged_pages.saturating_add(1);
                        continue;
                    };
                    let Ok(child) = read_be_u32(page, pointer) else {
                        *damaged_pages = damaged_pages.saturating_add(1);
                        continue;
                    };
                    self.walk_table(child, limit, order, visited, rows, damaged_pages);
                    if rows.len() >= limit {
                        return;
                    }
                }
                if matches!(order, SqliteRowOrder::Ascending) {
                    match right {
                        Ok(right) => {
                            self.walk_table(right, limit, order, visited, rows, damaged_pages)
                        }
                        Err(_) => *damaged_pages = damaged_pages.saturating_add(1),
                    }
                }
            }
            0x0d => {
                let pointer_start = header + 8;
                if cell_count > page.len().saturating_sub(pointer_start) / 2 {
                    *damaged_pages = damaged_pages.saturating_add(1);
                    return;
                }
                let indices: Box<dyn Iterator<Item = usize>> = match order {
                    SqliteRowOrder::Ascending => Box::new(0..cell_count),
                    SqliteRowOrder::Descending => Box::new((0..cell_count).rev()),
                };
                for index in indices {
                    if rows.len() >= limit {
                        break;
                    }
                    let Ok(pointer) = read_be_u16(page, pointer_start + index * 2).map(usize::from)
                    else {
                        *damaged_pages = damaged_pages.saturating_add(1);
                        continue;
                    };
                    if let Some(row) = self.parse_leaf_cell(
                        page,
                        page_number,
                        page_file_offset,
                        pointer,
                        page_file_offset + pointer as u64,
                    ) {
                        rows.push(row);
                    } else {
                        *damaged_pages = damaged_pages.saturating_add(1);
                    }
                }
            }
            _ => *damaged_pages = damaged_pages.saturating_add(1),
        }
    }

    fn page(&self, page_number: u32) -> Result<(&[u8], u64)> {
        let start =
            usize::try_from(u64::from(page_number.saturating_sub(1)) * self.page_size as u64)?;
        let end = start
            .checked_add(self.page_size)
            .ok_or_else(|| anyhow::anyhow!("SQLite 页面范围溢出"))?;
        ensure!(
            end <= self.bytes.len(),
            "SQLite 页面 {page_number} 不驻留或已截断"
        );
        Ok((&self.bytes[start..end], start as u64))
    }

    fn parse_leaf_cell(
        &self,
        page: &[u8],
        page_number: u32,
        page_file_offset: u64,
        cell_offset: usize,
        file_offset: u64,
    ) -> Option<SqlRow> {
        let (payload_size, first) = read_sqlite_varint(page, cell_offset)?;
        let (rowid, second) = read_sqlite_varint(page, cell_offset + first)?;
        let payload_start = cell_offset.checked_add(first)?.checked_add(second)?;
        let payload_size = usize::try_from(payload_size).ok()?;
        if payload_size > MAX_SQLITE_CELL_PAYLOAD || payload_size > self.bytes.len() {
            return None;
        }
        let payload = self.read_cell_payload(
            page,
            page_number,
            page_file_offset,
            cell_offset,
            payload_start,
            payload_size,
        )?;
        let values = parse_sql_record(&payload.bytes)?;
        Some(SqlRow {
            rowid: rowid as i64,
            values,
            page_number,
            file_offset,
            source_ranges: payload.source_ranges,
        })
    }

    fn read_cell_payload(
        &self,
        page: &[u8],
        page_number: u32,
        page_file_offset: u64,
        cell_offset: usize,
        payload_start: usize,
        payload_size: usize,
    ) -> Option<SqliteCellPayload> {
        let max_local = self.usable_size.checked_sub(35)?;
        let min_local = (self.usable_size.checked_sub(12)? * 32 / 255).checked_sub(23)?;
        let local = if payload_size <= max_local {
            payload_size
        } else {
            let candidate = min_local + (payload_size - min_local) % (self.usable_size - 4);
            if candidate <= max_local {
                candidate
            } else {
                min_local
            }
        };
        let local_end = payload_start.checked_add(local)?;
        let mut payload = page.get(payload_start..local_end)?.to_vec();
        let local_source_end = if local == payload_size {
            local_end
        } else {
            local_end.checked_add(4)?
        };
        page.get(cell_offset..local_source_end)?;
        let local_source_length = local_source_end.checked_sub(cell_offset)?;
        let mut source_ranges = vec![SqliteSourceRange {
            page_number,
            file_offset: page_file_offset.checked_add(cell_offset as u64)?,
            length: u64::try_from(local_source_length).ok()?,
        }];
        if local == payload_size {
            return Some(SqliteCellPayload {
                bytes: payload,
                source_ranges,
            });
        }
        let mut overflow = read_be_u32(page, local_end).ok()?;
        let mut visited_overflow = HashSet::new();
        visited_overflow.insert(page_number);
        while payload.len() < payload_size && overflow != 0 {
            let overflow_page_number = overflow;
            if !visited_overflow.insert(overflow_page_number) {
                return None;
            }
            let (overflow_page, overflow_file_offset) = self.page(overflow_page_number).ok()?;
            overflow = read_be_u32(overflow_page, 0).ok()?;
            let take = (payload_size - payload.len()).min(self.usable_size - 4);
            payload.extend_from_slice(overflow_page.get(4..4 + take)?);
            source_ranges.push(SqliteSourceRange {
                page_number: overflow_page_number,
                file_offset: overflow_file_offset,
                length: u64::try_from(4usize.checked_add(take)?).ok()?,
            });
        }
        if overflow != 0 {
            return None;
        }
        (payload.len() == payload_size).then_some(SqliteCellPayload {
            bytes: payload,
            source_ranges,
        })
    }
}

fn parse_sql_record(payload: &[u8]) -> Option<Vec<SqlValue>> {
    let (header_size, header_varint) = read_sqlite_varint(payload, 0)?;
    let header_size = usize::try_from(header_size).ok()?;
    if header_size < header_varint || header_size > payload.len() {
        return None;
    }
    let mut serials = Vec::new();
    let mut cursor = header_varint;
    while cursor < header_size {
        let (serial, length) = read_sqlite_varint(payload, cursor)?;
        serials.push(serial);
        cursor += length;
    }
    let mut data = header_size;
    let mut values = Vec::with_capacity(serials.len());
    for serial in serials {
        let length = serial_type_length(serial)?;
        let end = data.checked_add(length)?;
        let bytes = payload.get(data..end)?;
        values.push(decode_sql_value(serial, bytes)?);
        data = end;
    }
    Some(values)
}

fn serial_type_length(serial: u64) -> Option<usize> {
    Some(match serial {
        0 | 8 | 9 | 10 | 11 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 6,
        6 | 7 => 8,
        value if value >= 12 => usize::try_from((value - 12) / 2).ok()?,
        _ => return None,
    })
}

fn decode_sql_value(serial: u64, bytes: &[u8]) -> Option<SqlValue> {
    Some(match serial {
        0 | 10 | 11 => SqlValue::Null,
        1..=6 => SqlValue::Integer(decode_signed_be(bytes)),
        7 => {
            let _ = f64::from_bits(u64::from_be_bytes(bytes.try_into().ok()?));
            SqlValue::Real
        }
        8 => SqlValue::Integer(0),
        9 => SqlValue::Integer(1),
        value if value >= 12 && value % 2 == 0 => SqlValue::Blob(bytes.to_vec()),
        value if value >= 13 && value % 2 == 1 => {
            SqlValue::Text(std::str::from_utf8(bytes).ok()?.to_owned())
        }
        _ => return None,
    })
}

fn decode_signed_be(bytes: &[u8]) -> i64 {
    let mut value = if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        -1i64
    } else {
        0
    };
    for byte in bytes {
        value = (value << 8) | i64::from(*byte);
    }
    value
}

fn read_sqlite_varint(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for index in 0..9 {
        let byte = *bytes.get(offset.checked_add(index)?)?;
        if index == 8 {
            value = (value << 8) | u64::from(byte);
            return Some((value, 9));
        }
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

fn read_be_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| anyhow::anyhow!("SQLite u16 字段越界"))?;
    Ok(u16::from_be_bytes(value.try_into()?))
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| anyhow::anyhow!("SQLite u32 字段越界"))?;
    Ok(u32::from_be_bytes(value.try_into()?))
}

fn parse_create_columns(sql: &str) -> Vec<String> {
    let Some(start) = sql.find('(') else {
        return Vec::new();
    };
    let Some(end) = sql.rfind(')') else {
        return Vec::new();
    };
    if end <= start {
        return Vec::new();
    }
    split_sql_definitions(&sql[start + 1..end])
        .into_iter()
        .filter_map(|definition| {
            let definition = definition.trim();
            let first = sql_first_token(definition)?;
            let normalized = first
                .trim_matches(|character| matches!(character, '"' | '`' | '[' | ']'))
                .to_owned();
            let lower = normalized.to_ascii_lowercase();
            (!["constraint", "primary", "unique", "check", "foreign"]
                .iter()
                .any(|keyword| lower == *keyword || lower.starts_with(&format!("{keyword}("))))
            .then_some(normalized)
        })
        .collect()
}

fn split_sql_definitions(input: &str) -> Vec<&str> {
    let mut output = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    let characters = input.char_indices().collect::<Vec<_>>();
    for (index, character) in characters {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => quote = Some(character),
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                output.push(&input[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    output.push(&input[start..]);
    output
}

fn sql_first_token(input: &str) -> Option<&str> {
    let input = input.trim_start();
    let first = input.chars().next()?;
    if matches!(first, '"' | '`' | '[') {
        let closing = if first == '[' { ']' } else { first };
        let end = input[1..].find(closing)? + 2;
        input.get(..end)
    } else {
        input.split_whitespace().next()
    }
}

fn cookie_from_sql_row(
    row: &SqlRow,
    columns: &HashMap<String, usize>,
    candidate: &CookieFileCandidate<'_>,
    extents: &[RecoveredExtent],
) -> Option<BrowserCookieRecord> {
    let value = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| columns.get(*name).and_then(|index| row.values.get(*index)))
    };
    let name = sql_text(value(&["name"])?)?.to_owned();
    let domain = sql_text(value(&["host_key", "host"])?)
        .filter(|domain| plausible_domain(domain))
        .map(normalize_domain);
    if name.is_empty() || name.len() > MAX_COOKIE_NAME || domain.is_none() {
        return None;
    }
    let plain = value(&["value"])
        .and_then(sql_text)
        .filter(|value| !value.is_empty())
        .filter(|value| value.len() <= MAX_COOKIE_VALUE)
        .map(ToOwned::to_owned);
    let encrypted = value(&["encrypted_value"])
        .and_then(sql_blob)
        .filter(|value| !value.is_empty());
    let path = value(&["path"])
        .and_then(sql_text)
        .filter(|path| path.len() <= 4096)
        .map(ToOwned::to_owned);
    let expires = match candidate.kind {
        CookieFileKind::Chromium => value(&["expires_utc"])
            .and_then(sql_integer)
            .and_then(chromium_time),
        CookieFileKind::Firefox => value(&["expiry"])
            .and_then(sql_integer)
            .and_then(unix_seconds),
        _ => None,
    };
    let secure = value(&["is_secure", "issecure"])
        .and_then(sql_integer)
        .map(|value| value != 0);
    let http_only = value(&["is_httponly", "ishttponly"])
        .and_then(sql_integer)
        .map(|value| value != 0);
    let same_site = value(&["samesite", "same_site"])
        .and_then(sql_integer)
        .map(same_site_name);
    Some(BrowserCookieRecord {
        browser: candidate.browser.clone(),
        profile: candidate.profile.clone(),
        source: match candidate.kind {
            CookieFileKind::Chromium => CookieSource::ChromiumDatabase,
            CookieFileKind::Firefox => CookieSource::FirefoxDatabase,
            _ => return None,
        },
        encoding: CookieEncoding::Sqlite,
        domain,
        path,
        name,
        value: plain,
        encrypted_value_hex: encrypted.map(|bytes| limited_hex(bytes, 512)),
        encrypted: encrypted.is_some(),
        expires,
        secure,
        http_only,
        same_site,
        confidence: "high".to_owned(),
        occurrences: 1,
        physical_addresses: physical_for_file_offset(extents, row.file_offset)
            .into_iter()
            .collect(),
        owners: Vec::new(),
        source_file: Some(candidate.path.clone()),
        file_object: Some(candidate.file.file_object),
        database_rowid: Some(row.rowid),
    })
}

pub(crate) fn sql_text(value: &SqlValue) -> Option<&str> {
    match value {
        SqlValue::Text(value) => Some(value),
        _ => None,
    }
}

pub(crate) fn sql_integer(value: &SqlValue) -> Option<i64> {
    match value {
        SqlValue::Integer(value) => Some(*value),
        _ => None,
    }
}

pub(crate) fn sql_blob(value: &SqlValue) -> Option<&[u8]> {
    match value {
        SqlValue::Blob(value) => Some(value),
        _ => None,
    }
}

pub(crate) fn chromium_time(microseconds: i64) -> Option<String> {
    if microseconds <= 0 {
        return None;
    }
    let unix_microseconds = microseconds.checked_sub(11_644_473_600_000_000)?;
    let seconds = unix_microseconds.div_euclid(1_000_000);
    let nanos = u32::try_from(unix_microseconds.rem_euclid(1_000_000) * 1000).ok()?;
    DateTime::<Utc>::from_timestamp(seconds, nanos).map(|time| time.to_rfc3339())
}

fn unix_seconds(seconds: i64) -> Option<String> {
    (seconds > 0)
        .then(|| DateTime::<Utc>::from_timestamp(seconds, 0))
        .flatten()
        .map(|time| time.to_rfc3339())
}

fn same_site_name(value: i64) -> String {
    match value {
        -1 => "未指定",
        0 => "无",
        1 => "宽松",
        2 => "严格",
        3 => "宽松（强制）",
        _ => "未知",
    }
    .to_owned()
}

fn limited_hex(bytes: &[u8], limit: usize) -> String {
    let take = bytes.len().min(limit);
    let mut output = hex::encode(&bytes[..take]);
    if bytes.len() > take {
        output.push('…');
    }
    output
}

fn parse_legacy_cookie_text(
    bytes: &[u8],
    candidate: &CookieFileCandidate<'_>,
    extents: &[RecoveredExtent],
    limit: usize,
) -> Result<Vec<BrowserCookieRecord>> {
    let text = if bytes.starts_with(&[0xff, 0xfe]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    let mut records = Vec::new();
    let mut file_offset = 0u64;
    for block in text.split("\n*\n") {
        if records.len() == limit {
            break;
        }
        let lines = block
            .lines()
            .map(|line| line.trim_end_matches('\r'))
            .collect::<Vec<_>>();
        if lines.len() < 3 || !plausible_cookie_pair(lines[0], lines[1]) {
            file_offset = file_offset.saturating_add(block.len() as u64 + 3);
            continue;
        }
        let domain_path = lines[2];
        let split = domain_path.find('/').unwrap_or(domain_path.len());
        let domain = normalize_domain(&domain_path[..split]);
        if !plausible_domain(&domain) {
            file_offset = file_offset.saturating_add(block.len() as u64 + 3);
            continue;
        }
        let path = (split < domain_path.len()).then(|| domain_path[split..].to_owned());
        records.push(BrowserCookieRecord {
            browser: candidate.browser.clone(),
            profile: candidate.profile.clone(),
            source: CookieSource::LegacyCookieFile,
            encoding: CookieEncoding::TextFile,
            domain: Some(domain),
            path,
            name: lines[0].to_owned(),
            value: Some(lines[1].to_owned()),
            encrypted_value_hex: None,
            encrypted: false,
            expires: None,
            secure: None,
            http_only: None,
            same_site: None,
            confidence: "high".to_owned(),
            occurrences: 1,
            physical_addresses: physical_for_file_offset(extents, file_offset)
                .into_iter()
                .collect(),
            owners: Vec::new(),
            source_file: Some(candidate.path.clone()),
            file_object: Some(candidate.file.file_object),
            database_rowid: None,
        });
        file_offset = file_offset.saturating_add(block.len() as u64 + 3);
    }
    Ok(records)
}

pub(crate) fn recovery_physical_extents_windows(
    extents: &[RecoveredExtent],
    kernel_space: &WindowsAddressSpace<'_>,
) -> Vec<RecoveredExtent> {
    let mut output = Vec::new();
    for extent in extents {
        if extent.memory_kind == "physical" {
            output.push(RecoveredExtent {
                file_offset: extent.file_offset,
                length: extent.length,
                memory_address: extent.memory_address,
                memory_kind: "physical".to_owned(),
            });
            continue;
        }
        if extent.memory_kind != "virtual" {
            continue;
        }
        let mut relative = 0u64;
        while relative < extent.length {
            let Some(virtual_address) = extent.memory_address.checked_add(relative) else {
                break;
            };
            let page_remaining = 0x1000 - (virtual_address & 0xfff);
            let length = (extent.length - relative).min(page_remaining);
            if let Ok(physical_address) = kernel_space.translate(virtual_address) {
                output.push(RecoveredExtent {
                    file_offset: extent.file_offset + relative,
                    length,
                    memory_address: physical_address,
                    memory_kind: "physical".to_owned(),
                });
            }
            relative += length;
        }
    }
    output
}

pub(crate) fn physical_for_file_offset(extents: &[RecoveredExtent], offset: u64) -> Option<u64> {
    extents.iter().find_map(|extent| {
        let end = extent.file_offset.checked_add(extent.length)?;
        (extent.memory_kind == "physical" && (extent.file_offset..end).contains(&offset))
            .then(|| extent.memory_address + (offset - extent.file_offset))
    })
}

struct ProcessOwnerCandidate {
    pid: u64,
    process: String,
    browser: String,
    priority: u8,
    working_set: u64,
}

fn associate_process_owners(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    records: &mut [BrowserCookieRecord],
    warnings: &mut Vec<String>,
    complete: &mut bool,
    process_space_limit: usize,
) -> Result<usize> {
    let targets = records
        .iter()
        .filter(|record| is_runtime_record(record))
        .flat_map(|record| record.physical_addresses.iter())
        .map(|address| address & !0xfff)
        .collect::<HashSet<_>>();
    if targets.is_empty() {
        return Ok(0);
    }
    let processes = list_processes(image, kernel, profile, 65_536)?;
    *complete &= processes.complete;
    for warning in processes.warnings {
        push_warning(
            warnings,
            format!(
                "进程枚举出现{}{}",
                process_warning_name(&warning.kind),
                warning
                    .list_entry
                    .map(|entry| format!("，链表项 {entry:#x}"))
                    .unwrap_or_default()
            ),
        );
    }

    let mut address_spaces = HashMap::<u64, Vec<ProcessOwnerCandidate>>::new();
    for process in processes.processes {
        let Some(browser) = infer_browser_from_process_context(
            &process.name,
            process.details.image_path.as_deref(),
            process.details.command_line.as_deref(),
        ) else {
            continue;
        };
        if let Some(dtb) = process
            .details
            .user_directory_table_base
            .or(process.details.directory_table_base)
            .map(|dtb| dtb & 0x000f_ffff_ffff_f000)
            .filter(|dtb| *dtb != 0)
        {
            address_spaces
                .entry(dtb)
                .or_default()
                .push(ProcessOwnerCandidate {
                    pid: process.pid,
                    process: process.name,
                    priority: browser_priority(&browser),
                    browser,
                    working_set: process.details.working_set_private_size.unwrap_or(0),
                });
        }
    }
    let mut address_spaces = address_spaces.into_iter().collect::<Vec<_>>();
    address_spaces.sort_unstable_by(|(left_dtb, left), (right_dtb, right)| {
        address_space_priority(right)
            .cmp(&address_space_priority(left))
            .then_with(|| address_space_working_set(right).cmp(&address_space_working_set(left)))
            .then_with(|| left_dtb.cmp(right_dtb))
    });
    if address_spaces.len() > process_space_limit {
        *complete = false;
        push_warning(
            warnings,
            format!(
                "发现 {} 个浏览器相关进程地址空间；为保证速度，本次按相关性优先分析前 {process_space_limit} 个",
                address_spaces.len()
            ),
        );
        address_spaces.truncate(process_space_limit);
    }

    let mut records_by_page = HashMap::<u64, Vec<(usize, u64)>>::new();
    for (record_index, record) in records.iter().enumerate() {
        if !is_runtime_record(record) {
            continue;
        }
        for physical in &record.physical_addresses {
            records_by_page
                .entry(physical & !0xfff)
                .or_default()
                .push((record_index, physical & 0xfff));
        }
    }
    let runtime_record_count = records
        .iter()
        .filter(|record| is_runtime_record(record))
        .count();
    let mut mapped_records = HashSet::new();
    let mut owner_browser = vec![None::<(u8, String)>; records.len()];
    let mut examined = 0usize;
    for (dtb, owners) in &address_spaces {
        examined += 1;
        let reverse = match X64AddressSpace::new(image, *dtb).and_then(|space| {
            space.reverse_translate_pages(&targets, VirtualAddressRegion::User, 4)
        }) {
            Ok(reverse) => reverse,
            Err(error) => {
                *complete = false;
                push_warning(
                    warnings,
                    format!("无法反向映射进程 DTB {dtb:#x}：{error:#}"),
                );
                continue;
            }
        };
        for (page, virtual_pages) in reverse {
            let Some(record_refs) = records_by_page.get(&page) else {
                continue;
            };
            for (record_index, delta) in record_refs {
                mapped_records.insert(*record_index);
                for owner in owners {
                    if owner_browser[*record_index]
                        .as_ref()
                        .is_none_or(|(priority, _)| owner.priority > *priority)
                    {
                        owner_browser[*record_index] =
                            Some((owner.priority, owner.browser.clone()));
                    }
                    for virtual_page in &virtual_pages {
                        records[*record_index].owners.push(CookieOwner {
                            pid: owner.pid,
                            process: owner.process.clone(),
                            virtual_address: virtual_page + *delta,
                        });
                    }
                }
            }
        }
        if mapped_records.len() >= runtime_record_count {
            break;
        }
    }
    for (index, record) in records.iter_mut().enumerate() {
        record
            .owners
            .sort_unstable_by_key(|owner| (owner.pid, owner.virtual_address));
        record
            .owners
            .dedup_by_key(|owner| (owner.pid, owner.virtual_address));
        record.owners.truncate(MAX_COOKIE_OWNERS);
        if let Some((_, browser)) = owner_browser[index].take()
            && should_owner_override(&record.browser)
        {
            record.browser = browser;
            record.confidence = "high".to_owned();
        }
    }
    Ok(examined)
}

fn infer_record_browsers(records: &mut [BrowserCookieRecord]) {
    for record in records {
        if let Some(browser) = record
            .owners
            .iter()
            .find_map(|owner| infer_browser_from_process(&owner.process))
            && should_owner_override(&record.browser)
        {
            record.browser = browser;
            record.confidence = "high".to_owned();
        }
    }
}

fn infer_browser_from_process(process: &str) -> Option<String> {
    infer_browser_from_process_context(process, None, None)
}

pub(crate) fn infer_browser_from_process_context(
    process: &str,
    image_path: Option<&str>,
    command_line: Option<&str>,
) -> Option<String> {
    let process = process.to_ascii_lowercase();
    let context = format!(
        "{process}\n{}\n{}",
        image_path.unwrap_or_default(),
        command_line.unwrap_or_default()
    )
    .to_ascii_lowercase();
    if process == "qq.exe" {
        return Some("QQ 内嵌浏览器".to_owned());
    }
    if process == "wps.exe" || process.starts_with("wpspdf") {
        return Some("WPS 内嵌浏览器".to_owned());
    }
    if let Some(application) = infer_embedded_application(&context) {
        return Some(application.to_owned());
    }
    [
        ("chrome.exe", "Chrome"),
        ("chromium.exe", "Chromium"),
        ("msedge.exe", "Edge"),
        ("firefox.exe", "Firefox"),
        ("brave.exe", "Brave"),
        ("opera.exe", "Opera"),
        ("vivaldi.exe", "Vivaldi"),
        ("iexplore.exe", "Internet Explorer"),
        ("microsoftedge", "旧版 Edge"),
        ("msedgewebview2", "WebView2"),
        ("360chrome.exe", "360 极速浏览器"),
        ("360chromex.exe", "360 极速浏览器"),
        ("360se.exe", "360 安全浏览器"),
        ("qqbrowser.exe", "QQ 浏览器"),
        ("sogouexplorer.exe", "搜狗浏览器"),
        ("sogouexplorer.e", "搜狗浏览器"),
    ]
    .into_iter()
    .find_map(|(needle, browser)| process.contains(needle).then(|| browser.to_owned()))
    .or_else(|| {
        [
            "--type=renderer",
            "--type=utility",
            "--user-data-dir",
            "electron",
            "\\cef\\",
        ]
        .into_iter()
        .any(|marker| context.contains(marker))
        .then(|| "内嵌浏览器".to_owned())
    })
}

fn is_runtime_record(record: &BrowserCookieRecord) -> bool {
    matches!(
        record.source,
        CookieSource::RequestHeader | CookieSource::ResponseHeader
    )
}

fn has_sufficient_runtime_evidence(record: &BrowserCookieRecord) -> bool {
    !is_runtime_record(record)
        || !record.owners.is_empty()
        || (record.source == CookieSource::ResponseHeader && record.domain.is_some())
}

fn should_owner_override(browser: &str) -> bool {
    matches!(
        browser,
        "未知浏览器"
            | "浏览器（进程未关联）"
            | "Chrome/Chromium"
            | "Chromium 系浏览器"
            | "Internet Explorer"
            | "WebView2"
            | "内嵌浏览器"
    )
}

fn browser_priority(browser: &str) -> u8 {
    match browser {
        "内嵌浏览器" | "WebView2" => 1,
        "Chrome" | "Edge" | "Firefox" | "Brave" | "Opera" | "Vivaldi" => 2,
        _ => 3,
    }
}

fn address_space_priority(owners: &[ProcessOwnerCandidate]) -> u8 {
    owners.iter().map(|owner| owner.priority).max().unwrap_or(0)
}

fn address_space_working_set(owners: &[ProcessOwnerCandidate]) -> u64 {
    owners
        .iter()
        .map(|owner| owner.working_set)
        .max()
        .unwrap_or(0)
}

fn process_warning_name(kind: &str) -> &'static str {
    match kind {
        "cycle" => "活动进程链表循环",
        "invalid_pointer" => "活动进程链表指针无效",
        "invalid_blink" | "blink_mismatch" | "head_blink_mismatch" => "活动进程链表反向链接异常",
        "unreadable_blink" | "unreadable_flink" | "unreadable_entry" => "活动进程链表内容不可读",
        "invalid_process_id" => "进程标识无效",
        _ => "未知异常",
    }
}

fn infer_browser_from_text(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    [
        ("edg/", "Edge"),
        ("opr/", "Opera"),
        ("vivaldi/", "Vivaldi"),
        ("firefox/", "Firefox"),
        ("chrome/", "Chrome/Chromium"),
        ("trident/", "Internet Explorer"),
        ("msie ", "Internet Explorer"),
    ]
    .into_iter()
    .find_map(|(needle, browser)| lower.contains(needle).then(|| browser.to_owned()))
}

fn merge_cookie_records(records: Vec<BrowserCookieRecord>) -> Vec<BrowserCookieRecord> {
    let mut merged = BTreeMap::<String, BrowserCookieRecord>::new();
    for mut record in records {
        let key = format!(
            "{}\u{1f}{:?}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            record.browser,
            record.source,
            record.domain.as_deref().unwrap_or(""),
            record.path.as_deref().unwrap_or(""),
            record.name,
            record.value.as_deref().unwrap_or(""),
            record.encrypted_value_hex.as_deref().unwrap_or("")
        );
        if let Some(existing) = merged.get_mut(&key) {
            existing.occurrences += record.occurrences;
            existing
                .physical_addresses
                .append(&mut record.physical_addresses);
            existing.owners.append(&mut record.owners);
            existing.physical_addresses.sort_unstable();
            existing.physical_addresses.dedup();
            existing
                .owners
                .sort_unstable_by_key(|owner| (owner.pid, owner.virtual_address));
            existing
                .owners
                .dedup_by_key(|owner| (owner.pid, owner.virtual_address));
            existing.owners.truncate(MAX_COOKIE_OWNERS);
        } else {
            merged.insert(key, record);
        }
    }
    merged.into_values().collect()
}

fn confidence_rank(confidence: &str) -> u8 {
    match confidence {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

fn combined_throughput(bytes: u64, seconds: f64) -> f64 {
    bytes as f64 / 1024f64.powi(3) / seconds.max(f64::EPSILON)
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNING_COUNT {
        warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_cookie_pairs_without_attributes() {
        let records = parse_request_cookies(
            "session=abc123; theme=light; $Path=/",
            Some("example.test".to_owned()),
            "Firefox".to_owned(),
            CookieEncoding::Ascii,
            0x1234,
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].name, "session");
        assert_eq!(records[0].value.as_deref(), Some("abc123"));
        assert_eq!(records[1].name, "theme");
    }

    #[test]
    fn parses_set_cookie_security_attributes() {
        let record = parse_set_cookie(
            "sid=secret; Domain=.example.test; Path=/admin; Secure; HttpOnly; SameSite=Strict",
            None,
            "Chrome".to_owned(),
            CookieEncoding::Ascii,
            0x2000,
        )
        .unwrap();
        assert_eq!(record.domain.as_deref(), Some("example.test"));
        assert_eq!(record.path.as_deref(), Some("/admin"));
        assert_eq!(record.secure, Some(true));
        assert_eq!(record.http_only, Some(true));
        assert_eq!(record.same_site.as_deref(), Some("Strict"));
    }

    #[test]
    fn rejects_format_templates_and_truncated_domains() {
        assert!(!plausible_cookie_pair("%s", "%s"));
        assert!(!plausible_cookie_pair("token", "{0}"));
        assert!(!plausible_domain("s"));
        assert!(!plausible_domain("18"));
        assert!(!plausible_domain("18.2"));
        assert!(plausible_domain("localhost"));
        assert!(plausible_domain("intranet"));
        assert!(plausible_domain("192.168.60.150"));
        assert!(plausible_domain("2001:db8::1"));
    }

    #[test]
    fn filters_only_supported_cookie_file_paths() {
        assert!(is_cookie_file_path(
            "\\Users\\Alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"
        ));
        assert!(is_cookie_file_path(
            "\\Users\\Alice\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\x\\cookies.sqlite"
        ));
        assert!(is_cookie_file_path(
            "\\Users\\Alice\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat"
        ));
        assert!(!is_cookie_file_path(
            "\\Users\\Alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
        ));
    }

    #[test]
    fn recognizes_embedded_browser_applications() {
        assert_eq!(
            infer_browser_from_path(
                "\\users\\alice\\appdata\\roaming\\doubao\\network\\cookies",
                CookieFileKind::Chromium,
            ),
            "豆包"
        );
        assert_eq!(
            infer_browser_from_path(
                "\\packages\\microsoftwindows.client.cbs_abc\\localstate\\ebwebview\\default\\network\\cookies",
                CookieFileKind::Chromium,
            ),
            "Windows WebView2"
        );
        assert_eq!(
            infer_browser_from_process_context("QQMusic.exe", None, None).as_deref(),
            Some("QQ音乐内嵌浏览器")
        );
        assert_eq!(
            infer_browser_from_path(
                "\\users\\alice\\appdata\\roaming\\netease\\uu\\webview2cache\\ebwebview\\default\\network\\cookies",
                CookieFileKind::Chromium,
            ),
            "网易 UU 内嵌浏览器"
        );
    }

    #[test]
    fn parses_quoted_sqlite_schema_columns() {
        let columns = parse_create_columns(
            "CREATE TABLE cookies (creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, UNIQUE(host_key, name))",
        );
        assert_eq!(
            columns,
            [
                "creation_utc",
                "host_key",
                "name",
                "value",
                "encrypted_value"
            ]
        );
    }

    #[test]
    fn decodes_sqlite_varints_and_signed_integers() {
        assert_eq!(read_sqlite_varint(&[0x7f], 0), Some((127, 1)));
        assert_eq!(read_sqlite_varint(&[0x81, 0x00], 0), Some((128, 2)));
        assert_eq!(decode_signed_be(&[0xff]), -1);
        assert_eq!(decode_signed_be(&[0x01, 0x00]), 256);
    }

    #[test]
    fn chromium_epoch_conversion_is_exact() {
        assert_eq!(
            chromium_time(11_644_473_600_000_000).as_deref(),
            Some("1970-01-01T00:00:00+00:00")
        );
    }

    #[test]
    fn parses_a_complete_chromium_sqlite_btree() {
        let bytes = chromium_sqlite_fixture();
        let file = crate::windows::files::FileScanRecord {
            file_object: 0xffff_8000_0000_1000,
            physical_address: 0x1000,
            object_header: 0xffff_8000_0000_0fd0,
            pool_header_physical: 0xf80,
            pool_allocation_size: 0x150,
            name: Some("\\Users\\Alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies".to_owned()),
            device_object: 0,
            section_object_pointer: 0,
            data_section_object: 0,
            shared_cache_map: 0,
            image_section_object: 0,
            flags: 0,
            delete_pending: false,
            object_type_verified: true,
        };
        let candidate = classify_cookie_file(&file).unwrap();
        let parsed = parse_cookie_sqlite(&bytes, &candidate, &[], 10).unwrap();
        assert_eq!(parsed.damaged_pages, 0);
        assert_eq!(parsed.records.len(), 1);
        let record = &parsed.records[0];
        assert_eq!(record.browser, "Chrome");
        assert_eq!(record.profile.as_deref(), Some("Default"));
        assert_eq!(record.domain.as_deref(), Some("example.test"));
        assert_eq!(record.path.as_deref(), Some("/"));
        assert_eq!(record.name, "sid");
        assert_eq!(record.value, None);
        assert!(record.encrypted);
        assert_eq!(record.encrypted_value_hex.as_deref(), Some("763130010203"));
        assert_eq!(record.secure, Some(true));
        assert_eq!(record.http_only, Some(true));
        assert_eq!(record.same_site.as_deref(), Some("严格"));
    }

    #[test]
    fn preserves_valid_sqlite_siblings_when_one_page_is_damaged() {
        let bytes = partial_chromium_sqlite_fixture();
        let file = crate::windows::files::FileScanRecord {
            file_object: 0xffff_8000_0000_1000,
            physical_address: 0x1000,
            object_header: 0xffff_8000_0000_0fd0,
            pool_header_physical: 0xf80,
            pool_allocation_size: 0x150,
            name: Some("\\Users\\Alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies".to_owned()),
            device_object: 0,
            section_object_pointer: 0,
            data_section_object: 0,
            shared_cache_map: 0,
            image_section_object: 0,
            flags: 0,
            delete_pending: false,
            object_type_verified: true,
        };
        let candidate = classify_cookie_file(&file).unwrap();
        let parsed = parse_cookie_sqlite(&bytes, &candidate, &[], 10).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert!(parsed.damaged_pages > 0);
        assert_eq!(parsed.records[0].name, "sid");
    }

    #[test]
    fn sqlite_limit_uses_a_sentinel_instead_of_flagging_an_exact_fit() {
        let bytes = chromium_sqlite_fixture();
        let parsed = parse_sqlite_table(&bytes, &["cookies"], 1).unwrap();
        assert_eq!(parsed.rows.len(), 1);
        assert!(!parsed.limit_reached);

        let parsed = parse_sqlite_table(&bytes, &["cookies"], 0).unwrap();
        assert!(parsed.rows.is_empty());
        assert!(parsed.limit_reached);
    }

    #[test]
    fn sqlite_overflow_chain_rejects_a_cycle_back_to_the_leaf_page() {
        const PAGE_SIZE: usize = 512;
        let mut bytes = vec![0u8; PAGE_SIZE * 2];
        let payload_size = 500usize;
        let usable_size = PAGE_SIZE;
        let max_local = usable_size - 35;
        let min_local = ((usable_size - 12) * 32 / 255) - 23;
        let candidate = min_local + (payload_size - min_local) % (usable_size - 4);
        let local = if candidate <= max_local {
            candidate
        } else {
            min_local
        };
        let payload_start = 16usize;
        let local_end = payload_start + local;
        bytes[local_end..local_end + 4].copy_from_slice(&1u32.to_be_bytes());
        let database = SqliteDatabase {
            bytes: &bytes,
            page_size: PAGE_SIZE,
            usable_size,
        };
        assert!(
            database
                .read_cell_payload(&bytes[..PAGE_SIZE], 1, 0, 14, payload_start, payload_size,)
                .is_none()
        );
    }

    enum FixtureValue<'a> {
        Integer(i64),
        Text(&'a str),
        Blob(&'a [u8]),
    }

    fn chromium_sqlite_fixture() -> Vec<u8> {
        const PAGE_SIZE: usize = 512;
        let schema = "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER)";
        let master = encode_fixture_record(&[
            FixtureValue::Text("table"),
            FixtureValue::Text("cookies"),
            FixtureValue::Text("cookies"),
            FixtureValue::Integer(2),
            FixtureValue::Text(schema),
        ]);
        let cookie = encode_fixture_record(&[
            FixtureValue::Text(".example.test"),
            FixtureValue::Text("sid"),
            FixtureValue::Text(""),
            FixtureValue::Blob(b"v10\x01\x02\x03"),
            FixtureValue::Text("/"),
            FixtureValue::Integer(0),
            FixtureValue::Integer(1),
            FixtureValue::Integer(1),
            FixtureValue::Integer(2),
        ]);
        let mut database = vec![0u8; PAGE_SIZE * 2];
        database[..16].copy_from_slice(b"SQLite format 3\0");
        database[16..18].copy_from_slice(&(PAGE_SIZE as u16).to_be_bytes());
        database[18] = 1;
        database[19] = 1;
        database[20] = 0;
        database[28..32].copy_from_slice(&2u32.to_be_bytes());
        place_leaf_cell(&mut database[..PAGE_SIZE], 100, &master, 1);
        place_leaf_cell(&mut database[PAGE_SIZE..], 0, &cookie, 1);
        database
    }

    fn partial_chromium_sqlite_fixture() -> Vec<u8> {
        const PAGE_SIZE: usize = 512;
        let complete = chromium_sqlite_fixture();
        let mut database = vec![0u8; PAGE_SIZE * 4];
        database[..PAGE_SIZE].copy_from_slice(&complete[..PAGE_SIZE]);
        database[28..32].copy_from_slice(&4u32.to_be_bytes());
        database[PAGE_SIZE * 2..PAGE_SIZE * 3].copy_from_slice(&complete[PAGE_SIZE..PAGE_SIZE * 2]);

        let interior = &mut database[PAGE_SIZE..PAGE_SIZE * 2];
        interior[0] = 0x05;
        interior[3..5].copy_from_slice(&1u16.to_be_bytes());
        interior[8..12].copy_from_slice(&4u32.to_be_bytes());
        interior[12..14].copy_from_slice(&500u16.to_be_bytes());
        interior[500..504].copy_from_slice(&3u32.to_be_bytes());
        database
    }

    fn encode_fixture_record(values: &[FixtureValue<'_>]) -> Vec<u8> {
        let mut serials = Vec::new();
        let mut data = Vec::new();
        for value in values {
            let serial = match value {
                FixtureValue::Integer(0) => 8,
                FixtureValue::Integer(1) => 9,
                FixtureValue::Integer(value) => {
                    assert!((-128..=127).contains(value));
                    data.push(*value as i8 as u8);
                    1
                }
                FixtureValue::Text(value) => {
                    data.extend_from_slice(value.as_bytes());
                    13 + value.len() as u64 * 2
                }
                FixtureValue::Blob(value) => {
                    data.extend_from_slice(value);
                    12 + value.len() as u64 * 2
                }
            };
            serials.extend(encode_fixture_varint(serial));
        }
        let header_size = 1 + serials.len();
        assert!(header_size < 128);
        let mut payload = vec![header_size as u8];
        payload.extend(serials);
        payload.extend(data);
        payload
    }

    fn place_leaf_cell(page: &mut [u8], header: usize, payload: &[u8], rowid: u64) {
        let mut cell = encode_fixture_varint(payload.len() as u64);
        cell.extend(encode_fixture_varint(rowid));
        cell.extend_from_slice(payload);
        let cell_offset = page.len() - cell.len();
        assert!(cell_offset > header + 10);
        page[header] = 0x0d;
        page[header + 3..header + 5].copy_from_slice(&1u16.to_be_bytes());
        page[header + 5..header + 7].copy_from_slice(&(cell_offset as u16).to_be_bytes());
        page[header + 8..header + 10].copy_from_slice(&(cell_offset as u16).to_be_bytes());
        page[cell_offset..].copy_from_slice(&cell);
    }

    fn encode_fixture_varint(mut value: u64) -> Vec<u8> {
        let mut groups = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value != 0 {
            groups.push((value & 0x7f) as u8);
            value >>= 7;
        }
        groups.reverse();
        let last = groups.len() - 1;
        for byte in &mut groups[..last] {
            *byte |= 0x80;
        }
        groups
    }
}
