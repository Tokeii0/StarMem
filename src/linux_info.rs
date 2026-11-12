//! Symbol-independent Linux host identity triage.
//!
//! This module deliberately does not require `task_struct` offsets.  It joins
//! a live kernel banner with resident systemd journal hostname metadata and
//! internally consistent login-session environment blocks.  A bare `USER=`
//! or hostname-looking string is never sufficient on its own.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::linux::linux_release;
use crate::scan::scan_patterns_cancellable;

const SCAN_CHUNK_SIZE: usize = 64 * 1024 * 1024;
const LIMIT_PER_PATTERN: usize = 100_000;
const ENVIRONMENT_BEFORE: u64 = 2048;
const ENVIRONMENT_AFTER: u64 = 6144;

const LINUX_BANNER: &[u8] = b"Linux version ";
const JOURNAL_HOSTNAME: &[u8] = b"_HOSTNAME=";
const ENV_HOSTNAME: &[u8] = b"HOSTNAME=";
const SESSION_MANAGER: &[u8] = b"SESSION_MANAGER=local/";
const ENV_USER: &[u8] = b"USER=";
const ENV_LOGNAME: &[u8] = b"LOGNAME=";
const ENV_HOME: &[u8] = b"HOME=/home/";

#[derive(Debug, Clone, Serialize)]
pub struct LinuxIdentityCandidate {
    pub value: String,
    pub score: u64,
    pub evidence_count: usize,
    pub sources: Vec<String>,
    pub physical_addresses: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxInfoWarning {
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxInfoReport {
    pub kernel_banner: String,
    pub kernel_banner_physical_address: u64,
    pub linux_version: String,
    pub hostname: Option<String>,
    pub logged_in_username: Option<String>,
    pub hostname_candidates: Vec<LinuxIdentityCandidate>,
    pub username_candidates: Vec<LinuxIdentityCandidate>,
    pub complete: bool,
    pub scope: String,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub warnings: Vec<LinuxInfoWarning>,
}

#[derive(Default)]
struct CandidateAggregate {
    score: u64,
    addresses: BTreeSet<u64>,
    sources: BTreeSet<String>,
}

pub fn analyze_linux_info(image: &MemoryImage) -> Result<LinuxInfoReport> {
    analyze_linux_info_cancellable(image, &CancellationToken::new())
}

pub fn analyze_linux_info_cancellable(
    image: &MemoryImage,
    cancellation: &CancellationToken,
) -> Result<LinuxInfoReport> {
    cancellation.check_cancelled()?;
    let patterns: &[&[u8]] = &[
        LINUX_BANNER,
        JOURNAL_HOSTNAME,
        ENV_HOSTNAME,
        SESSION_MANAGER,
        ENV_USER,
        ENV_LOGNAME,
        ENV_HOME,
    ];
    let scan = scan_patterns_cancellable(
        image,
        patterns,
        LIMIT_PER_PATTERN,
        SCAN_CHUNK_SIZE,
        cancellation,
    )?;
    let mut banners = BTreeMap::<String, BTreeSet<u64>>::new();
    let mut hostnames = BTreeMap::<String, CandidateAggregate>::new();
    let mut usernames = BTreeMap::<String, CandidateAggregate>::new();

    for hit in &scan.hits {
        cancellation.check_cancelled()?;
        match hit.pattern_index {
            0 => {
                if let Some(banner) = read_ascii_c_string(image, hit.physical_address, 512)
                    && linux_release(&banner).is_some()
                {
                    banners
                        .entry(banner)
                        .or_default()
                        .insert(hit.physical_address);
                }
            }
            1 => {
                if let Some(value) =
                    read_prefixed_value(image, hit.physical_address, "_HOSTNAME=", valid_hostname)
                {
                    add_candidate(
                        &mut hostnames,
                        value,
                        "systemd_journal:_HOSTNAME",
                        hit.physical_address,
                        12,
                    );
                }
            }
            2 => {
                if previous_byte(image, hit.physical_address) != Some(b'_')
                    && is_string_boundary(image, hit.physical_address)
                    && let Some(value) = read_prefixed_value(
                        image,
                        hit.physical_address,
                        "HOSTNAME=",
                        valid_hostname,
                    )
                {
                    add_candidate(
                        &mut hostnames,
                        value,
                        "environment:HOSTNAME",
                        hit.physical_address,
                        8,
                    );
                }
            }
            3 => {
                if is_string_boundary(image, hit.physical_address)
                    && let Some(text) = read_ascii_c_string(image, hit.physical_address, 512)
                    && let Some(value) = session_manager_hostname(&text)
                {
                    add_candidate(
                        &mut hostnames,
                        value,
                        "desktop_session:SESSION_MANAGER",
                        hit.physical_address,
                        10,
                    );
                }
            }
            4..=6 => {
                if is_string_boundary(image, hit.physical_address)
                    && let Some(context) = login_environment_context(image, hit.physical_address)
                {
                    add_candidate(
                        &mut usernames,
                        context.username,
                        &context.source,
                        context.block_physical_address,
                        context.score,
                    );
                }
            }
            _ => unreachable!(),
        }
    }

    let (kernel_banner, kernel_banner_physical_address) = banners
        .into_iter()
        .max_by(|(left, left_addresses), (right, right_addresses)| {
            left.len()
                .cmp(&right.len())
                .then_with(|| left_addresses.len().cmp(&right_addresses.len()))
                .then_with(|| right.cmp(left))
        })
        .and_then(|(banner, addresses)| addresses.first().copied().map(|address| (banner, address)))
        .context("Linux 物理内存中未找到有效的 Linux version banner")?;
    let linux_version = linux_release(&kernel_banner).context("Linux banner 缺少版本字段")?;
    let hostname_candidates = finalize_candidates(hostnames);
    let username_candidates = finalize_candidates(usernames);
    let hostname = hostname_candidates.first().map(|entry| entry.value.clone());
    let logged_in_username = username_candidates.first().map(|entry| entry.value.clone());

    let mut warnings = Vec::new();
    if scan.truncated {
        warnings.push(LinuxInfoWarning {
            kind: "scan_limit".to_owned(),
            message: "一个或多个身份锚点达到每类 100000 条上限；候选排序可能不完整".to_owned(),
        });
    }
    if hostname.is_none() {
        warnings.push(LinuxInfoWarning {
            kind: "hostname_not_found".to_owned(),
            message: "未找到由 systemd journal、环境块或桌面 SESSION_MANAGER 验证的 hostname"
                .to_owned(),
        });
    }
    if logged_in_username.is_none() {
        warnings.push(LinuxInfoWarning {
            kind: "logged_in_user_not_found".to_owned(),
            message: "未找到 USER、LOGNAME、HOME 与登录会话标记相互一致的驻留环境块".to_owned(),
        });
    }
    let hostname_corroborated = hostname_candidates
        .first()
        .is_some_and(|candidate| candidate.sources.len() >= 2);
    if hostname.is_some() && !hostname_corroborated {
        warnings.push(LinuxInfoWarning {
            kind: "hostname_single_source".to_owned(),
            message: "最高 hostname 候选只有一种驻留来源，未形成跨来源印证".to_owned(),
        });
    }
    let username_corroborated = username_candidates.first().is_some_and(|candidate| {
        candidate.evidence_count >= 2
            && candidate
                .sources
                .iter()
                .any(|source| source.contains("session"))
    });
    if logged_in_username.is_some() && !username_corroborated {
        warnings.push(LinuxInfoWarning {
            kind: "username_weak_corroboration".to_owned(),
            message: "最高用户候选没有形成至少两个登录会话环境块证据".to_owned(),
        });
    }
    let complete = !scan.truncated
        && hostname.is_some()
        && logged_in_username.is_some()
        && hostname_corroborated
        && username_corroborated;
    Ok(LinuxInfoReport {
        kernel_banner,
        kernel_banner_physical_address,
        linux_version,
        hostname,
        logged_in_username,
        hostname_candidates,
        username_candidates,
        complete,
        scope: "驻留 Linux banner、systemd journal hostname 元数据，以及内部一致的登录会话环境块；不是磁盘账户清单".to_owned(),
        bytes_scanned: scan.bytes_scanned,
        scan_seconds: scan.elapsed_seconds,
        scan_gib_per_second: scan.gib_per_second,
        warnings,
    })
}

fn add_candidate(
    candidates: &mut BTreeMap<String, CandidateAggregate>,
    value: String,
    source: &str,
    physical_address: u64,
    score: u64,
) {
    let candidate = candidates.entry(value).or_default();
    if candidate.addresses.insert(physical_address) {
        candidate.score = candidate.score.saturating_add(score);
    }
    candidate.sources.insert(source.to_owned());
}

fn finalize_candidates(
    candidates: BTreeMap<String, CandidateAggregate>,
) -> Vec<LinuxIdentityCandidate> {
    let mut output = candidates
        .into_iter()
        .map(|(value, candidate)| LinuxIdentityCandidate {
            value,
            score: candidate.score,
            evidence_count: candidate.addresses.len(),
            sources: candidate.sources.into_iter().collect(),
            physical_addresses: candidate.addresses.into_iter().collect(),
        })
        .collect::<Vec<_>>();
    output.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| right.evidence_count.cmp(&left.evidence_count))
            .then_with(|| left.value.cmp(&right.value))
    });
    output
}

struct LoginEnvironmentContext {
    username: String,
    source: String,
    score: u64,
    block_physical_address: u64,
}

fn login_environment_context(image: &MemoryImage, anchor: u64) -> Option<LoginEnvironmentContext> {
    let environment = read_environment_window(image, anchor)?;
    let variables = &environment.variables;
    let anchor_text = read_ascii_c_string(image, anchor, 256)?;
    let username = if let Some(value) = anchor_text.strip_prefix("USER=") {
        value.to_owned()
    } else if let Some(value) = anchor_text.strip_prefix("LOGNAME=") {
        value.to_owned()
    } else {
        anchor_text
            .strip_prefix("HOME=/home/")?
            .split('/')
            .next()?
            .to_owned()
    };
    if !valid_username(&username) {
        return None;
    }
    let user = variable_matches(variables, "USER", &username);
    let logname = variable_matches(variables, "LOGNAME", &username);
    let home = variable_matches(variables, "HOME", &format!("/home/{username}"));
    let identity_count = usize::from(user) + usize::from(logname) + usize::from(home);
    if identity_count < 2 {
        return None;
    }
    let xdg_user = variable_matches(variables, "XDG_SESSION_CLASS", "user");
    let desktop = variable_present(variables, "DESKTOP_SESSION")
        || variable_present(variables, "GDMSESSION")
        || variable_present(variables, "XDG_SESSION_DESKTOP");
    let graphical =
        variable_present(variables, "DISPLAY") || variable_present(variables, "WAYLAND_DISPLAY");
    let remote =
        variable_present(variables, "SSH_CONNECTION") || variable_present(variables, "SSH_TTY");
    let session_id = variable_present(variables, "XDG_SESSION_ID");
    let shell = variables.iter().any(|(key, value)| {
        key == "SHELL"
            && matches!(
                value.as_str(),
                "/bin/sh" | "/bin/bash" | "/bin/zsh" | "/bin/fish"
            )
    });
    let session = xdg_user || desktop || graphical || remote || session_id || (shell && home);
    if !session {
        return None;
    }
    let mut factors = Vec::new();
    for (present, name) in [
        (user, "USER"),
        (logname, "LOGNAME"),
        (home, "HOME"),
        (xdg_user, "session:XDG_SESSION_CLASS"),
        (desktop, "session:desktop"),
        (graphical, "session:display"),
        (remote, "session:ssh"),
        (session_id, "session:id"),
        (shell, "session:shell"),
    ] {
        if present {
            factors.push(name);
        }
    }
    let score = (identity_count as u64) * 4
        + u64::from(xdg_user) * 5
        + u64::from(desktop) * 3
        + u64::from(graphical) * 2
        + u64::from(remote) * 3
        + u64::from(session_id) * 2
        + u64::from(shell);
    Some(LoginEnvironmentContext {
        username,
        source: format!("environment:{}", factors.join("+")),
        score,
        block_physical_address: environment.block_physical_address,
    })
}

struct EnvironmentWindow {
    variables: Vec<(String, String)>,
    block_physical_address: u64,
}

fn read_environment_window(image: &MemoryImage, anchor: u64) -> Option<EnvironmentWindow> {
    let span = image
        .spans()
        .iter()
        .find(|span| anchor >= span.start && anchor < span.end())?;
    let start = anchor.saturating_sub(ENVIRONMENT_BEFORE).max(span.start);
    let end = anchor.checked_add(ENVIRONMENT_AFTER)?.min(span.end());
    let length = usize::try_from(end.checked_sub(start)?).ok()?;
    let mut bytes = vec![0u8; length];
    image.read_physical(start, &mut bytes).ok()?;
    let anchor_offset = usize::try_from(anchor.checked_sub(start)?).ok()?;
    let block_offset = environment_block_start(&bytes, anchor_offset);
    let block_physical_address = start.checked_add(block_offset as u64)?;
    let mut variables = Vec::new();
    for raw in bytes.split(|byte| *byte == 0) {
        let Some((key, value)) = parse_environment_entry(raw) else {
            continue;
        };
        if !value.is_empty() {
            variables.push((key.to_owned(), value.to_owned()));
        }
    }
    (!variables.is_empty()).then_some(EnvironmentWindow {
        variables,
        block_physical_address,
    })
}

fn environment_block_start(bytes: &[u8], anchor_offset: usize) -> usize {
    let mut current = anchor_offset;
    while current > 1 && bytes[current - 1] == 0 && bytes[current - 2] != 0 {
        let previous_end = current - 1;
        let previous_start = bytes[..previous_end]
            .iter()
            .rposition(|byte| *byte == 0)
            .map_or(0, |offset| offset + 1);
        if parse_environment_entry(&bytes[previous_start..previous_end]).is_none() {
            break;
        }
        current = previous_start;
    }
    current
}

fn parse_environment_entry(raw: &[u8]) -> Option<(&str, &str)> {
    if raw.is_empty() || raw.len() > 1024 || !raw.iter().all(|byte| matches!(byte, 0x20..=0x7e)) {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?;
    let (key, value) = text.split_once('=')?;
    valid_environment_key(key).then_some((key, value))
}

fn variable_matches(variables: &[(String, String)], key: &str, expected: &str) -> bool {
    variables
        .iter()
        .any(|(candidate, value)| candidate == key && value == expected)
}

fn variable_present(variables: &[(String, String)], key: &str) -> bool {
    variables.iter().any(|(candidate, _)| candidate == key)
}

fn valid_environment_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn read_prefixed_value(
    image: &MemoryImage,
    address: u64,
    prefix: &str,
    validator: impl Fn(&str) -> bool,
) -> Option<String> {
    let text = read_ascii_c_string(image, address, 512)?;
    let value = text.strip_prefix(prefix)?.trim();
    validator(value).then(|| value.to_owned())
}

fn read_ascii_c_string(image: &MemoryImage, address: u64, max_len: usize) -> Option<String> {
    let mut bytes = Vec::with_capacity(max_len.min(512));
    for index in 0..max_len {
        let mut byte = [0u8; 1];
        image
            .read_physical(address.checked_add(index as u64)?, &mut byte)
            .ok()?;
        if byte[0] == 0 || matches!(byte[0], b'\n' | b'\r') {
            break;
        }
        if !matches!(byte[0], 0x20..=0x7e) {
            return None;
        }
        bytes.push(byte[0]);
    }
    if bytes.is_empty() {
        None
    } else {
        String::from_utf8(bytes).ok()
    }
}

fn session_manager_hostname(text: &str) -> Option<String> {
    let value = text.strip_prefix("SESSION_MANAGER=local/")?;
    let hostname = value.split([':', '@', '/']).next()?.trim();
    valid_hostname(hostname).then(|| hostname.to_owned())
}

fn valid_hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.eq_ignore_ascii_case("localhost") {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn previous_byte(image: &MemoryImage, address: u64) -> Option<u8> {
    let mut byte = [0u8; 1];
    image
        .read_physical(address.checked_sub(1)?, &mut byte)
        .ok()?;
    Some(byte[0])
}

fn is_string_boundary(image: &MemoryImage, address: u64) -> bool {
    previous_byte(image, address).is_none_or(|byte| byte == 0 || matches!(byte, b'\n' | b'\r'))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn recovers_only_corroborated_host_and_login_identity() {
        let path = temporary_path("linux-info");
        let mut bytes = vec![0u8; 0x20_000];
        put(
            &mut bytes,
            0x1000,
            b"Linux version 5.4.0-4-amd64 (debian@test) #1 SMP\0",
        );
        put(&mut bytes, 0x4000, b"_HOSTNAME=testbox.local\0");
        put(
            &mut bytes,
            0x8000,
            b"USER=Tester\0LOGNAME=Tester\0HOME=/home/Tester\0SHELL=/bin/bash\0XDG_SESSION_CLASS=user\0DESKTOP_SESSION=xfce\0DISPLAY=:0\0SESSION_MANAGER=local/testbox.local:@/tmp/.ICE-unix/1000\0\0",
        );
        put(
            &mut bytes,
            0x12_000,
            b"USER=Tester\0LOGNAME=Tester\0HOME=/home/Tester\0SHELL=/bin/bash\0XDG_SESSION_CLASS=user\0XDG_SESSION_ID=2\0\0",
        );
        put(
            &mut bytes,
            0x18_000,
            b"USER=root\0LOGNAME=root\0HOME=/root\0\0",
        );
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let report = analyze_linux_info(&image).unwrap();
        assert_eq!(report.linux_version, "5.4.0-4-amd64");
        assert_eq!(report.hostname.as_deref(), Some("testbox.local"));
        assert_eq!(report.logged_in_username.as_deref(), Some("Tester"));
        assert!(report.complete);
        assert!(report.hostname_candidates[0].sources.len() >= 2);
        assert!(report.username_candidates[0].evidence_count >= 2);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_an_uncorroborated_user_string() {
        let path = temporary_path("linux-info-weak-user");
        let mut bytes = vec![0u8; 0x10_000];
        put(
            &mut bytes,
            0x1000,
            b"Linux version 1.2.3-test (builder@test) #1 SMP\0",
        );
        put(&mut bytes, 0x4000, b"USER=mallory\0random text\0");
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let report = analyze_linux_info(&image).unwrap();
        assert!(report.logged_in_username.is_none());
        assert!(!report.complete);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn ignores_long_prose_that_only_looks_like_a_linux_banner() {
        let path = temporary_path("linux-info-false-banner");
        let mut bytes = vec![0u8; 0x10_000];
        put(
            &mut bytes,
            0x1000,
            b"Linux version lacks the metadata required by this diagnostic message and is not a kernel banner\0",
        );
        put(
            &mut bytes,
            0x4000,
            b"Linux version 6.8.0-test (builder@test) #1 SMP\0",
        );
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let report = analyze_linux_info(&image).unwrap();
        assert_eq!(report.linux_version, "6.8.0-test");
        assert_eq!(
            report.kernel_banner,
            "Linux version 6.8.0-test (builder@test) #1 SMP"
        );
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn counts_one_environment_block_as_one_login_evidence() {
        let path = temporary_path("linux-info-single-environment");
        let mut bytes = vec![0u8; 0x10_000];
        put(
            &mut bytes,
            0x1000,
            b"Linux version 1.2.3-test (builder@test) #1 SMP\0",
        );
        put(&mut bytes, 0x3000, b"_HOSTNAME=testbox.local\0");
        put(
            &mut bytes,
            0x6000,
            b"USER=Tester\0LOGNAME=Tester\0HOME=/home/Tester\0SHELL=/bin/bash\0XDG_SESSION_CLASS=user\0SESSION_MANAGER=local/testbox.local:@/tmp/.ICE-unix/1000\0\0",
        );
        fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        let report = analyze_linux_info(&image).unwrap();
        assert_eq!(report.logged_in_username.as_deref(), Some("Tester"));
        assert_eq!(report.username_candidates[0].evidence_count, 1);
        assert_eq!(report.username_candidates[0].physical_addresses, [0x6000]);
        assert!(!report.complete);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.kind == "username_weak_corroboration")
        );
        drop(image);
        fs::remove_file(path).unwrap();
    }

    fn put(bytes: &mut [u8], offset: usize, value: &[u8]) {
        bytes[offset..offset + value.len()].copy_from_slice(value);
    }

    fn temporary_path(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "starmem-{label}-{}-{stamp}.mem",
            std::process::id()
        ))
    }
}
