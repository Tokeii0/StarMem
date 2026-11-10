use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;
use std::time::Instant;

use anyhow::{Result, ensure};
use regex::Regex;
use serde::Serialize;

use crate::address::{VirtualAddressRegion, X64AddressSpace};
use crate::image::MemoryImage;
use crate::profile::KernelProfile;
use crate::scan::scan_patterns_ascii_case_insensitive;
use crate::windows::{ProcessListReport, WindowsKernelContext, list_processes};

const DEFAULT_CHUNK_SIZE: usize = 64 * 1024 * 1024;
const CONTEXT_BEFORE: u64 = 1024;
const CONTEXT_AFTER: u64 = 2048;
const MAX_CONTEXT_CHARACTERS: usize = 1024;
const MAX_PHYSICAL_ADDRESSES: usize = 32;

// Native commands are located from their action switches. PowerShell, ADSI
// and WMI are located from stable API/cmdlet tokens. The matcher is ASCII
// case-insensitive, including for the non-zero bytes in UTF-16LE patterns.
const ACCOUNT_PATTERNS: [&[u8]; 20] = [
    b"/add",
    b"/delete",
    b"/active:",
    b"-localuser",
    b"-localgroupmember",
    b"-aduser",
    b"-adgroupmember",
    b"-adaccount",
    b".create(",
    b"useraccount",
    b"/\0a\0d\0d\0",
    b"/\0d\0e\0l\0e\0t\0e\0",
    b"/\0a\0c\0t\0i\0v\0e\0:\0",
    b"-\0l\0o\0c\0a\0l\0u\0s\0e\0r\0",
    b"-\0l\0o\0c\0a\0l\0g\0r\0o\0u\0p\0m\0e\0m\0b\0e\0r\0",
    b"-\0a\0d\0u\0s\0e\0r\0",
    b"-\0a\0d\0g\0r\0o\0u\0p\0m\0e\0m\0b\0e\0r\0",
    b"-\0a\0d\0a\0c\0c\0o\0u\0n\0t\0",
    b".\0c\0r\0e\0a\0t\0e\0(\0",
    b"u\0s\0e\0r\0a\0c\0c\0o\0u\0n\0t\0",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountAction {
    CreateUser,
    DeleteUser,
    EnableUser,
    DisableUser,
    ModifyUser,
    ChangePassword,
    AddToGroup,
    RemoveFromGroup,
    CreateGroup,
    DeleteGroup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountTextEncoding {
    Ascii,
    Utf16Le,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountTraceOwner {
    pub pid: u64,
    pub process: String,
    pub virtual_address: u64,
    pub executor_sid: Option<String>,
    pub executor_user: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AccountTraceRecord {
    pub action: AccountAction,
    pub username: Option<String>,
    pub group: Option<String>,
    pub command: String,
    pub confidence: String,
    pub encodings: Vec<AccountTextEncoding>,
    pub occurrences: usize,
    pub physical_addresses: Vec<u64>,
    pub owners: Vec<AccountTraceOwner>,
}

#[derive(Debug, Serialize)]
pub struct AccountFinding {
    pub username: String,
    pub sid: Option<String>,
    pub created: bool,
    pub deleted: bool,
    pub administrator: bool,
    pub groups: Vec<String>,
    pub process_count: usize,
    pub evidence_count: usize,
    pub confidence: String,
}

#[derive(Debug, Serialize)]
pub struct AccountScanReport {
    pub findings: Vec<AccountFinding>,
    pub records: Vec<AccountTraceRecord>,
    pub complete: bool,
    pub raw_anchor_hits: usize,
    pub parsed_command_hits: usize,
    pub mapped_evidence_count: usize,
    pub address_spaces_examined: usize,
    pub bytes_scanned: u64,
    pub scan_seconds: f64,
    pub scan_gib_per_second: f64,
    pub total_seconds: f64,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
struct ParsedCommand {
    action: AccountAction,
    username: Option<String>,
    group: Option<String>,
    command: String,
}

#[derive(Default)]
struct FindingBuilder {
    display_name: String,
    created: bool,
    deleted: bool,
    administrator: bool,
    groups: BTreeSet<String>,
    evidence_count: usize,
}

#[derive(Default)]
struct ProcessIdentity {
    sid: Option<String>,
    process_count: usize,
    administrator: bool,
}

pub fn scan_account_traces(
    image: &MemoryImage,
    kernel: &WindowsKernelContext,
    profile: &KernelProfile,
    limit: usize,
) -> Result<AccountScanReport> {
    ensure!(limit > 0, "账户扫描结果上限必须大于零");
    let total_started = Instant::now();
    let raw_limit = limit.saturating_mul(64).clamp(4096, 100_000);
    let scan = scan_patterns_ascii_case_insensitive(
        image,
        &ACCOUNT_PATTERNS,
        raw_limit,
        DEFAULT_CHUNK_SIZE,
    )?;
    let raw_anchor_hits = scan.hits.len();
    let mut parsed_command_hits = 0usize;
    let mut records = BTreeMap::<String, AccountTraceRecord>::new();

    for hit in &scan.hits {
        let encoding = if ACCOUNT_PATTERNS[hit.pattern_index].contains(&0) {
            AccountTextEncoding::Utf16Le
        } else {
            AccountTextEncoding::Ascii
        };
        let Some((bytes, hit_offset)) = read_context(image, hit.physical_address) else {
            continue;
        };
        let evidence = match encoding {
            AccountTextEncoding::Ascii => extract_ascii_run(&bytes, hit_offset),
            AccountTextEncoding::Utf16Le => extract_utf16_run(&bytes, hit_offset),
        };
        for parsed in parse_account_commands(&evidence) {
            parsed_command_hits += 1;
            let key = format!(
                "{:?}\u{1f}{}\u{1f}{}\u{1f}{}",
                parsed.action,
                parsed
                    .username
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                parsed
                    .group
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                parsed.command.to_ascii_lowercase()
            );
            let entry = records.entry(key).or_insert_with(|| AccountTraceRecord {
                action: parsed.action,
                username: parsed.username.clone(),
                group: parsed.group.clone(),
                command: parsed.command.clone(),
                confidence: confidence_for_action(parsed.action).to_owned(),
                encodings: Vec::new(),
                occurrences: 0,
                physical_addresses: Vec::new(),
                owners: Vec::new(),
            });
            entry.occurrences += 1;
            if !entry.encodings.contains(&encoding) {
                entry.encodings.push(encoding);
            }
            if entry.physical_addresses.len() < MAX_PHYSICAL_ADDRESSES
                && !entry.physical_addresses.contains(&hit.physical_address)
            {
                entry.physical_addresses.push(hit.physical_address);
            }
        }
    }

    let mut records: Vec<AccountTraceRecord> = records.into_values().collect();
    records.sort_unstable_by(|left, right| {
        action_rank(right.action)
            .cmp(&action_rank(left.action))
            .then_with(|| right.occurrences.cmp(&left.occurrences))
            .then_with(|| left.command.cmp(&right.command))
    });
    let records_truncated = records.len() > limit;
    records.truncate(limit);

    let processes = list_processes(image, kernel, profile, 65_536)?;
    let mut warnings = process_warnings(&processes);
    let (address_spaces_examined, mapped_evidence_count, mapping_complete) =
        map_record_owners(image, &processes, &mut records, &mut warnings);
    let identities = collect_process_identities(&processes);
    let findings = build_findings(&records, &identities);

    if scan.truncated {
        warnings.push("账户操作原始锚点达到安全上限，报告可能不完整".to_owned());
    }
    if records_truncated {
        warnings.push(format!("账户操作结果达到 {limit} 条上限"));
    }
    Ok(AccountScanReport {
        findings,
        records,
        complete: !scan.truncated && !records_truncated && processes.complete && mapping_complete,
        raw_anchor_hits,
        parsed_command_hits,
        mapped_evidence_count,
        address_spaces_examined,
        bytes_scanned: scan.bytes_scanned,
        scan_seconds: scan.elapsed_seconds,
        scan_gib_per_second: scan.gib_per_second,
        total_seconds: total_started.elapsed().as_secs_f64(),
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

fn extract_ascii_run(bytes: &[u8], hit_offset: usize) -> String {
    let hit = hit_offset.min(bytes.len());
    let lower_bound = hit.saturating_sub(MAX_CONTEXT_CHARACTERS);
    let upper_bound = (hit + MAX_CONTEXT_CHARACTERS).min(bytes.len());
    let start = bytes[lower_bound..hit]
        .iter()
        .rposition(|byte| !is_ascii_command_byte(*byte))
        .map_or(lower_bound, |index| lower_bound + index + 1);
    let end = bytes[hit..upper_bound]
        .iter()
        .position(|byte| !is_ascii_command_byte(*byte))
        .map_or(upper_bound, |index| hit + index);
    normalize_evidence(&String::from_utf8_lossy(&bytes[start..end]))
}

fn extract_utf16_run(bytes: &[u8], hit_offset: usize) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let hit = (hit_offset / 2).min(units.len());
    let lower_bound = hit.saturating_sub(MAX_CONTEXT_CHARACTERS);
    let upper_bound = (hit + MAX_CONTEXT_CHARACTERS).min(units.len());
    let start = units[lower_bound..hit]
        .iter()
        .rposition(|unit| !is_utf16_command_unit(*unit))
        .map_or(lower_bound, |index| lower_bound + index + 1);
    let end = units[hit..upper_bound]
        .iter()
        .position(|unit| !is_utf16_command_unit(*unit))
        .map_or(upper_bound, |index| hit + index);
    normalize_evidence(&String::from_utf16_lossy(&units[start..end]))
}

fn is_ascii_command_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\r' | b'\n' | 0x20..=0x7e)
}

fn is_utf16_command_unit(unit: u16) -> bool {
    unit != 0
        && unit != 0xfffd
        && (matches!(unit, 9 | 10 | 13) || unit >= 0x20 && !(0xd800..=0xdfff).contains(&unit))
}

fn normalize_evidence(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\t' | '\r' | '\n') {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
}

fn parse_account_commands(text: &str) -> Vec<ParsedCommand> {
    let mut parsed = Vec::new();
    parsed.extend(parse_native_commands(text));
    parsed.extend(parse_powershell_commands(text));
    parsed.extend(parse_adsi_commands(text));
    parsed.extend(parse_wmic_commands(text));
    parsed
}

fn native_command_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b(?:net1?|net1?\.exe)\s+(user|localgroup|group)\s+").unwrap()
    })
}

fn native_action_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?i)/(?:add|delete|active\s*:\s*(?:yes|no))\b").unwrap())
}

fn parse_native_commands(text: &str) -> Vec<ParsedCommand> {
    let mut output = Vec::new();
    for captures in native_command_regex().captures_iter(text) {
        let Some(whole) = captures.get(0) else {
            continue;
        };
        let tail_end = command_tail_end(&text[whole.end()..]);
        let candidate_end = whole.end() + tail_end;
        let candidate = &text[whole.start()..candidate_end];
        let Some(action_match) = native_action_regex().find(candidate) else {
            continue;
        };
        let command = normalize_command(&candidate[..action_match.end()]);
        let tokens = command_tokens(&command);
        if tokens.len() < 3 {
            continue;
        }
        let subcommand = tokens[1].to_ascii_lowercase();
        let switch = tokens
            .iter()
            .position(|token| token.starts_with('/'))
            .unwrap_or(tokens.len());
        let switch_value = tokens
            .get(switch)
            .map(|token| token.to_ascii_lowercase())
            .unwrap_or_default();
        if subcommand == "user" {
            let Some(username) = tokens.get(2).map(|value| clean_account_name(value)) else {
                continue;
            };
            let action = if switch_value == "/add" {
                AccountAction::CreateUser
            } else if switch_value == "/delete" {
                AccountAction::DeleteUser
            } else if switch_value.replace(' ', "") == "/active:yes" {
                AccountAction::EnableUser
            } else if switch_value.replace(' ', "") == "/active:no" {
                AccountAction::DisableUser
            } else {
                continue;
            };
            output.push(ParsedCommand {
                action,
                username: Some(username),
                group: None,
                command,
            });
        } else {
            let Some(group) = tokens.get(2).map(|value| clean_account_name(value)) else {
                continue;
            };
            let member = (switch > 3)
                .then(|| tokens.get(3))
                .flatten()
                .map(|value| clean_account_name(value));
            let action = match (switch_value.as_str(), member.is_some()) {
                ("/add", true) => AccountAction::AddToGroup,
                ("/delete", true) => AccountAction::RemoveFromGroup,
                ("/add", false) => AccountAction::CreateGroup,
                ("/delete", false) => AccountAction::DeleteGroup,
                _ => continue,
            };
            output.push(ParsedCommand {
                action,
                username: member,
                group: Some(group),
                command,
            });
        }
    }
    output
}

fn powershell_command_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:new-localuser|remove-localuser|set-localuser|enable-localuser|disable-localuser|add-localgroupmember|remove-localgroupmember|new-aduser|remove-aduser|enable-adaccount|disable-adaccount|set-adaccountpassword|add-adgroupmember|remove-adgroupmember)\b",
        )
        .unwrap()
    })
}

fn parse_powershell_commands(text: &str) -> Vec<ParsedCommand> {
    let mut output = Vec::new();
    for matched in powershell_command_regex().find_iter(text) {
        let tail_end = command_tail_end(&text[matched.start()..]);
        let command = normalize_command(&text[matched.start()..matched.start() + tail_end]);
        let tokens = command_tokens(&command);
        let Some(name) = tokens.first().map(|value| value.to_ascii_lowercase()) else {
            continue;
        };
        let action = match name.as_str() {
            "new-localuser" | "new-aduser" => AccountAction::CreateUser,
            "remove-localuser" | "remove-aduser" => AccountAction::DeleteUser,
            "enable-localuser" | "enable-adaccount" => AccountAction::EnableUser,
            "disable-localuser" | "disable-adaccount" => AccountAction::DisableUser,
            "set-adaccountpassword" => AccountAction::ChangePassword,
            "set-localuser" => AccountAction::ModifyUser,
            "add-localgroupmember" | "add-adgroupmember" => AccountAction::AddToGroup,
            "remove-localgroupmember" | "remove-adgroupmember" => AccountAction::RemoveFromGroup,
            _ => continue,
        };
        let group = matches!(
            action,
            AccountAction::AddToGroup | AccountAction::RemoveFromGroup
        )
        .then(|| argument_value(&tokens, &["-group", "-identity"]))
        .flatten()
        .map(clean_account_name);
        let username = if matches!(
            action,
            AccountAction::AddToGroup | AccountAction::RemoveFromGroup
        ) {
            argument_value(&tokens, &["-member", "-members"])
        } else {
            argument_value(
                &tokens,
                &["-name", "-samaccountname", "-identity", "-username"],
            )
        }
        .or_else(|| positional_argument(&tokens))
        .map(clean_account_name);
        if username.is_none() {
            continue;
        }
        output.push(ParsedCommand {
            action,
            username,
            group,
            command,
        });
    }
    output
}

fn adsi_command_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)\.(create|delete)\s*\(\s*["']user["']\s*,\s*["']([^"']+)["']"#).unwrap()
    })
}

fn parse_adsi_commands(text: &str) -> Vec<ParsedCommand> {
    adsi_command_regex()
        .captures_iter(text)
        .filter_map(|captures| {
            let whole = captures.get(0)?;
            let action = if captures.get(1)?.as_str().eq_ignore_ascii_case("create") {
                AccountAction::CreateUser
            } else {
                AccountAction::DeleteUser
            };
            Some(ParsedCommand {
                action,
                username: Some(clean_account_name(captures.get(2)?.as_str())),
                group: None,
                command: normalize_command(whole.as_str()),
            })
        })
        .collect()
}

fn wmic_command_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?i)\bwmic(?:\.exe)?\s+useraccount\b").unwrap())
}

fn wmic_name_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"(?i)\bname\s*=\s*["']([^"']+)["']"#).unwrap())
}

fn parse_wmic_commands(text: &str) -> Vec<ParsedCommand> {
    let mut output = Vec::new();
    for matched in wmic_command_regex().find_iter(text) {
        let tail_end = command_tail_end(&text[matched.start()..]);
        let command = normalize_command(&text[matched.start()..matched.start() + tail_end]);
        let Some(captures) = wmic_name_regex().captures(&command) else {
            continue;
        };
        let action = if command.to_ascii_lowercase().contains(" delete") {
            AccountAction::DeleteUser
        } else {
            AccountAction::ModifyUser
        };
        output.push(ParsedCommand {
            action,
            username: Some(clean_account_name(captures.get(1).unwrap().as_str())),
            group: None,
            command,
        });
    }
    output
}

fn command_tail_end(text: &str) -> usize {
    for (offset, character) in text.char_indices() {
        if offset >= 2048 || matches!(character, '\0' | '\r' | '\n' | ';') {
            return offset;
        }
    }
    text.len()
}

fn normalize_command(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn command_tokens(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for character in value.chars() {
        match (quote, character) {
            (Some(active), value) if value == active => quote = None,
            (None, '"' | '\'') => quote = Some(character),
            (None, value) if value.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn argument_value<'a>(tokens: &'a [String], names: &[&str]) -> Option<&'a str> {
    tokens.windows(2).find_map(|window| {
        names
            .iter()
            .any(|name| window[0].eq_ignore_ascii_case(name))
            .then_some(window[1].as_str())
    })
}

fn positional_argument(tokens: &[String]) -> Option<&str> {
    tokens.iter().skip(1).find_map(|token| {
        (!token.starts_with('-') && !token.starts_with('(')).then_some(token.as_str())
    })
}

fn clean_account_name(value: &str) -> String {
    let value = value
        .trim()
        .trim_matches(|character| matches!(character, '"' | '\'' | ',' | ')' | '('));
    value
        .strip_prefix(".\\")
        .unwrap_or(value)
        .rsplit_once('\\')
        .map_or(value, |(_, user)| user)
        .to_owned()
}

fn map_record_owners(
    image: &MemoryImage,
    processes: &ProcessListReport,
    records: &mut [AccountTraceRecord],
    warnings: &mut Vec<String>,
) -> (usize, usize, bool) {
    let target_pages: HashSet<u64> = records
        .iter()
        .flat_map(|record| record.physical_addresses.iter())
        .map(|address| address & !0xfff)
        .collect();
    if target_pages.is_empty() {
        return (0, 0, true);
    }
    let target_names: HashSet<String> = records
        .iter()
        .filter_map(|record| record.username.as_deref())
        .map(normalized_account_key)
        .collect();
    let mut address_spaces = BTreeMap::<u64, Vec<_>>::new();
    for process in &processes.processes {
        let username = process
            .details
            .environment_user_name
            .as_deref()
            .or_else(|| {
                process
                    .details
                    .environment_variables
                    .get("USERNAME")
                    .map(String::as_str)
            });
        let belongs_to_target = username
            .map(normalized_account_key)
            .is_some_and(|name| target_names.contains(&name));
        if !is_account_command_host(&process.name) && !belongs_to_target {
            continue;
        }
        if let Some(dtb) = process
            .details
            .user_directory_table_base
            .or(process.details.directory_table_base)
        {
            address_spaces
                .entry(dtb & 0x000f_ffff_ffff_f000)
                .or_default()
                .push(process);
        }
    }

    let mut reverse_maps = Vec::new();
    let mut complete = true;
    for (dtb, owners) in &address_spaces {
        match X64AddressSpace::new(image, *dtb).and_then(|space| {
            space.reverse_translate_pages(&target_pages, VirtualAddressRegion::User, 16)
        }) {
            Ok(reverse) => reverse_maps.push((owners, reverse)),
            Err(error) => {
                complete = false;
                if warnings.len() < 64 {
                    warnings.push(format!("无法反向映射进程页表 {dtb:#x}：{error:#}"));
                }
            }
        }
    }

    let mut mapped = 0usize;
    for record in records {
        for physical in &record.physical_addresses {
            let page = physical & !0xfff;
            let delta = physical & 0xfff;
            for (processes, reverse) in &reverse_maps {
                let Some(addresses) = reverse.get(&page) else {
                    continue;
                };
                for process in processes.iter() {
                    for address in addresses {
                        record.owners.push(AccountTraceOwner {
                            pid: process.pid,
                            process: process.name.clone(),
                            virtual_address: address + delta,
                            executor_sid: process.details.user_sid.clone(),
                            executor_user: executor_name(process.details.user_sid.as_deref())
                                .map(str::to_owned)
                                .or_else(|| process.details.environment_user_name.clone()),
                        });
                    }
                }
            }
        }
        record
            .owners
            .sort_unstable_by_key(|owner| (owner.pid, owner.virtual_address));
        record
            .owners
            .dedup_by_key(|owner| (owner.pid, owner.virtual_address));
        mapped += usize::from(!record.owners.is_empty());
    }
    (address_spaces.len(), mapped, complete)
}

fn is_account_command_host(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "cmd",
        "conhost",
        "powershell",
        "pwsh",
        "wscript",
        "cscript",
        "wmiprvse",
        "wmic",
        "net.exe",
        "net1.exe",
        "python",
        "perl",
        "ruby",
        "php",
        "mshta",
        "rundll32",
        "regsvr32",
        "explorer",
        "services",
        "taskhost",
        "taskeng",
        "wsmprovhost",
        "winrs",
        "psexec",
    ]
    .iter()
    .any(|candidate| name.contains(candidate))
}

fn executor_name(sid: Option<&str>) -> Option<&'static str> {
    match sid? {
        "S-1-5-18" => Some("SYSTEM"),
        "S-1-5-19" => Some("LOCAL SERVICE"),
        "S-1-5-20" => Some("NETWORK SERVICE"),
        _ => None,
    }
}

fn collect_process_identities(processes: &ProcessListReport) -> HashMap<String, ProcessIdentity> {
    let mut identities = HashMap::<String, ProcessIdentity>::new();
    for process in &processes.processes {
        let Some(username) = process
            .details
            .environment_user_name
            .as_deref()
            .or_else(|| {
                process
                    .details
                    .environment_variables
                    .get("USERNAME")
                    .map(String::as_str)
            })
        else {
            continue;
        };
        let identity = identities
            .entry(normalized_account_key(username))
            .or_default();
        identity.process_count += 1;
        if identity.sid.is_none() {
            identity.sid = process.details.user_sid.clone();
        }
        identity.administrator |= process
            .details
            .token_groups
            .iter()
            .any(|group| group.sid == "S-1-5-32-544" && group.attributes & 0x4 != 0);
    }
    identities
}

fn build_findings(
    records: &[AccountTraceRecord],
    identities: &HashMap<String, ProcessIdentity>,
) -> Vec<AccountFinding> {
    let mut builders = BTreeMap::<String, FindingBuilder>::new();
    for record in records {
        let Some(username) = record.username.as_deref() else {
            continue;
        };
        let key = normalized_account_key(username);
        let builder = builders.entry(key).or_insert_with(|| FindingBuilder {
            display_name: username.to_owned(),
            ..FindingBuilder::default()
        });
        builder.created |= record.action == AccountAction::CreateUser;
        builder.deleted |= record.action == AccountAction::DeleteUser;
        builder.evidence_count += record.occurrences;
        if let Some(group) = &record.group
            && record.action == AccountAction::AddToGroup
        {
            builder.groups.insert(group.clone());
            builder.administrator |= is_administrator_group(group);
        }
    }
    let mut findings = builders
        .into_iter()
        .map(|(key, mut builder)| {
            let identity = identities.get(&key);
            builder.administrator |= identity.is_some_and(|value| value.administrator);
            AccountFinding {
                username: builder.display_name,
                sid: identity.and_then(|value| value.sid.clone()),
                created: builder.created,
                deleted: builder.deleted,
                administrator: builder.administrator,
                groups: builder.groups.into_iter().collect(),
                process_count: identity.map_or(0, |value| value.process_count),
                evidence_count: builder.evidence_count,
                confidence: if builder.created {
                    "high".to_owned()
                } else {
                    "medium".to_owned()
                },
            }
        })
        .collect::<Vec<_>>();
    findings.sort_unstable_by(|left, right| {
        (right.created, right.administrator, right.evidence_count)
            .cmp(&(left.created, left.administrator, left.evidence_count))
            .then_with(|| left.username.cmp(&right.username))
    });
    findings
}

fn is_administrator_group(group: &str) -> bool {
    matches!(
        group.trim().to_ascii_lowercase().as_str(),
        "administrators" | "administratoren" | "administrateurs" | "administradores" | "管理员"
    )
}

fn normalized_account_key(value: &str) -> String {
    clean_account_name(value).to_lowercase()
}

fn confidence_for_action(action: AccountAction) -> &'static str {
    match action {
        AccountAction::CreateUser
        | AccountAction::DeleteUser
        | AccountAction::AddToGroup
        | AccountAction::RemoveFromGroup => "high",
        _ => "medium",
    }
}

fn action_rank(action: AccountAction) -> usize {
    match action {
        AccountAction::CreateUser => 10,
        AccountAction::AddToGroup => 9,
        AccountAction::EnableUser => 8,
        AccountAction::ChangePassword => 7,
        AccountAction::ModifyUser => 6,
        AccountAction::RemoveFromGroup => 5,
        AccountAction::DisableUser => 4,
        AccountAction::DeleteUser => 3,
        AccountAction::CreateGroup => 2,
        AccountAction::DeleteGroup => 1,
    }
}

fn process_warnings(processes: &ProcessListReport) -> Vec<String> {
    processes
        .warnings
        .iter()
        .map(|warning| format!("进程枚举/{}：{}", warning.kind, warning.message))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_native_create_and_administrator_commands() {
        let create = parse_account_commands("cmd.exe - net  user ASP.NET pn8kMawy /add");
        assert_eq!(create.len(), 1);
        assert_eq!(create[0].action, AccountAction::CreateUser);
        assert_eq!(create[0].username.as_deref(), Some("ASP.NET"));

        let group = parse_account_commands("net localgroup administrators ASP.NET /add");
        assert_eq!(group.len(), 1);
        assert_eq!(group[0].action, AccountAction::AddToGroup);
        assert_eq!(group[0].group.as_deref(), Some("administrators"));
        assert_eq!(group[0].username.as_deref(), Some("ASP.NET"));
    }

    #[test]
    fn parses_powershell_account_commands() {
        let create =
            parse_account_commands("New-LocalUser -Name 'backup-admin' -Password $password");
        assert_eq!(create.len(), 1);
        assert_eq!(create[0].action, AccountAction::CreateUser);
        assert_eq!(create[0].username.as_deref(), Some("backup-admin"));

        let group = parse_account_commands(
            "Add-LocalGroupMember -Group Administrators -Member backup-admin",
        );
        assert_eq!(group.len(), 1);
        assert_eq!(group[0].action, AccountAction::AddToGroup);
        assert_eq!(group[0].username.as_deref(), Some("backup-admin"));
    }

    #[test]
    fn extracts_utf16_command_around_anchor() {
        let command = "net user 测试用户 Password1! /add";
        let mut bytes = vec![0u8; 20];
        bytes.extend(command.encode_utf16().flat_map(u16::to_le_bytes));
        bytes.extend([0, 0]);
        let action = command.find("/add").unwrap();
        let hit_offset = 20 + command[..action].encode_utf16().count() * 2;
        let decoded = extract_utf16_run(&bytes, hit_offset);
        assert_eq!(decoded, command);
        let parsed = parse_account_commands(&decoded);
        assert_eq!(parsed[0].username.as_deref(), Some("测试用户"));
    }
}
