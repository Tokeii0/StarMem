use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use anyhow::{Result, ensure};
use serde::Serialize;

use crate::browser_session::{BrowserSessionOptions, BrowserSessionReport};
use crate::session::AnalysisSession;

#[derive(Debug, Clone, Copy)]
pub struct DnsScanOptions {
    pub limit: usize,
    pub browser: BrowserSessionOptions,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsEvidenceRecord {
    pub domain: String,
    pub record_type: String,
    pub answer: Option<String>,
    pub pid: Option<u64>,
    pub process: Option<String>,
    pub evidence_type: String,
    pub confidence: String,
    pub occurrences: usize,
    pub physical_addresses: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct DnsScanReport {
    pub records: Vec<DnsEvidenceRecord>,
    pub complete: bool,
    pub bytes_scanned: u64,
    pub truncated: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default)]
struct RecordBuilder {
    answers: BTreeSet<String>,
    evidence: BTreeSet<String>,
    confidence: BTreeSet<String>,
    occurrences: usize,
    physical_addresses: BTreeSet<u64>,
}

/// Recover domain evidence from browser runtime headers, resident browser
/// databases and download URLs, then retain process ownership when it can be
/// proven through a mapped process address space.
///
/// This deliberately reports domain *references*, not a fabricated DNS cache:
/// an empty `answer` means StarMem found a domain but no IP literal associated
/// with the same evidence item.
pub fn scan_dns_evidence<F>(
    session: &AnalysisSession,
    options: &DnsScanOptions,
    progress: F,
) -> Result<DnsScanReport>
where
    F: FnMut(crate::browser_session::BrowserSessionStage),
{
    ensure!(options.limit > 0, "DNS 证据结果数量上限必须大于零");
    let report = session.browser_sessions(&options.browser, progress)?;
    Ok(aggregate_dns_evidence(report, options.limit))
}

fn aggregate_dns_evidence(report: BrowserSessionReport, limit: usize) -> DnsScanReport {
    let mut records = BTreeMap::<(String, Option<u64>, Option<String>), RecordBuilder>::new();

    for cookie in &report.cookies {
        let Some(domain) = cookie.domain.as_deref().and_then(normalize_domain) else {
            continue;
        };
        if cookie.owners.is_empty() {
            add_evidence(
                &mut records,
                domain,
                None,
                None,
                "browser_cookie",
                &cookie.confidence,
                cookie.occurrences,
                &cookie.physical_addresses,
                None,
            );
        } else {
            for owner in &cookie.owners {
                add_evidence(
                    &mut records,
                    domain.clone(),
                    Some(owner.pid),
                    Some(owner.process.clone()),
                    "browser_cookie",
                    &cookie.confidence,
                    cookie.occurrences,
                    &cookie.physical_addresses,
                    None,
                );
            }
        }
    }

    for download in &report.downloads {
        let Some(domain) = normalize_domain(&download.host) else {
            continue;
        };
        if download.owners.is_empty() {
            add_evidence(
                &mut records,
                domain,
                None,
                None,
                "download_url",
                &download.confidence,
                download.occurrences,
                &download.physical_addresses,
                download.ip_address.as_deref(),
            );
        } else {
            for owner in &download.owners {
                add_evidence(
                    &mut records,
                    domain.clone(),
                    Some(owner.pid),
                    Some(owner.process.clone()),
                    "download_url",
                    &download.confidence,
                    download.occurrences,
                    &download.physical_addresses,
                    download.ip_address.as_deref(),
                );
            }
        }
    }

    for browser_session in &report.sessions {
        for domain in &browser_session.domains {
            let Some(domain) = normalize_domain(domain) else {
                continue;
            };
            add_evidence(
                &mut records,
                domain,
                browser_session.pid,
                browser_session.process.clone(),
                "browser_session",
                &browser_session.confidence,
                browser_session.evidence_count,
                &[],
                None,
            );
        }
    }

    let total = records.len();
    let records = records
        .into_iter()
        .take(limit)
        .map(|((domain, pid, process), builder)| {
            let record_type = dns_record_type(&domain).to_owned();
            DnsEvidenceRecord {
                domain,
                record_type,
                answer: (!builder.answers.is_empty())
                    .then(|| builder.answers.into_iter().collect::<Vec<_>>().join(", ")),
                pid,
                process,
                evidence_type: builder.evidence.into_iter().collect::<Vec<_>>().join(" + "),
                confidence: strongest_confidence(&builder.confidence).to_owned(),
                occurrences: builder.occurrences,
                physical_addresses: builder.physical_addresses.into_iter().collect(),
            }
        })
        .collect();
    let truncated = total > limit;
    let mut warnings = report.warnings;
    if truncated {
        warnings.push(format!("DNS/域名证据超过 {limit} 条，结果已截断"));
    }
    DnsScanReport {
        records,
        complete: report.complete && !truncated,
        bytes_scanned: report.statistics.bytes_scanned,
        truncated,
        warnings,
    }
}

#[allow(clippy::too_many_arguments)]
fn add_evidence(
    records: &mut BTreeMap<(String, Option<u64>, Option<String>), RecordBuilder>,
    domain: String,
    pid: Option<u64>,
    process: Option<String>,
    evidence: &str,
    confidence: &str,
    occurrences: usize,
    physical_addresses: &[u64],
    answer: Option<&str>,
) {
    let builder = records.entry((domain, pid, process)).or_default();
    builder.evidence.insert(evidence.to_owned());
    builder.confidence.insert(confidence.to_owned());
    builder.occurrences = builder.occurrences.saturating_add(occurrences.max(1));
    builder
        .physical_addresses
        .extend(physical_addresses.iter().copied());
    if let Some(answer) = answer.filter(|value| !value.trim().is_empty()) {
        builder.answers.insert(answer.to_owned());
    }
}

fn normalize_domain(value: &str) -> Option<String> {
    let domain = value
        .trim()
        .trim_matches('.')
        .trim_matches(|character: char| character == '[' || character == ']')
        .to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || domain.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | ':' | '_'))
        })
    {
        return None;
    }
    Some(domain)
}

fn strongest_confidence(values: &BTreeSet<String>) -> &str {
    if values
        .iter()
        .any(|value| value.eq_ignore_ascii_case("high"))
    {
        "high"
    } else if values
        .iter()
        .any(|value| value.eq_ignore_ascii_case("medium"))
    {
        "medium"
    } else {
        "low"
    }
}

fn dns_record_type(domain: &str) -> &'static str {
    match domain.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => "A",
        Ok(IpAddr::V6(_)) => "AAAA",
        Err(_) => "DOMAIN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_domain_without_inventing_dns_answers() {
        assert_eq!(
            normalize_domain(".Example.COM."),
            Some("example.com".to_owned())
        );
        assert_eq!(normalize_domain("bad domain"), None);
        assert_eq!(dns_record_type("192.0.2.1"), "A");
        assert_eq!(dns_record_type("2001:db8::1"), "AAAA");
        assert_eq!(dns_record_type("example.com"), "DOMAIN");
    }

    #[test]
    fn merges_sources_for_the_same_domain_and_process() {
        let mut records = BTreeMap::new();
        add_evidence(
            &mut records,
            "example.com".to_owned(),
            Some(42),
            Some("browser.exe".to_owned()),
            "browser_cookie",
            "medium",
            1,
            &[0x1000],
            None,
        );
        add_evidence(
            &mut records,
            "example.com".to_owned(),
            Some(42),
            Some("browser.exe".to_owned()),
            "download_url",
            "high",
            2,
            &[0x2000],
            Some("192.0.2.1"),
        );
        let builder = records.values().next().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(builder.occurrences, 3);
        assert_eq!(strongest_confidence(&builder.confidence), "high");
        assert!(builder.answers.contains("192.0.2.1"));
    }
}
