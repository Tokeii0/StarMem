use super::ApplicationKind;
use crate::{cancellation::CancellationToken, windows::files::RecoveredExtent};
use anyhow::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) struct ResidentLine {
    pub offset: u64,
    pub byte_length: usize,
    pub text: String,
    pub encoding: &'static str,
    pub complete: bool,
    pub sha256: String,
}
pub(super) struct ParsedLines {
    pub lines: Vec<ResidentLine>,
    pub complete: bool,
}

// Merge only adjacent file offsets from this single recovery view. Gaps remain gaps.
fn ranges(extents: &[RecoveredExtent], size: usize) -> Vec<(usize, usize)> {
    let mut spans: Vec<_> = extents
        .iter()
        .filter_map(|e| {
            let start = usize::try_from(e.file_offset).ok()?;
            let end = usize::try_from(e.file_offset.checked_add(e.length)?)
                .ok()?
                .min(size);
            (start < end).then_some((start, end))
        })
        .collect();
    spans.sort_unstable();
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (start, end) in spans {
        if let Some(last) = out.last_mut().filter(|last| start <= last.1) {
            last.1 = last.1.max(end);
        } else {
            out.push((start, end));
        }
    }
    out
}

pub(super) fn parse_resident_lines(
    bytes: &[u8],
    extents: &[RecoveredExtent],
    logical_size: u64,
    limit: usize,
    token: &CancellationToken,
) -> Result<ParsedLines> {
    let spans = ranges(extents, bytes.len());
    // The encoding decision must be based on recovered bytes, never zero-filled holes.
    let prefix = spans
        .first()
        .map(|(s, e)| &bytes[*s..(*e).min(*s + 256)])
        .unwrap_or(&[]);
    let utf16 = prefix.starts_with(&[0xff, 0xfe])
        || prefix.len() >= 8
            && prefix
                .chunks_exact(2)
                .filter(|p| p[1] == 0 && p[0].is_ascii())
                .count()
                * 4
                > prefix.len();
    let mut out = ParsedLines {
        lines: Vec::new(),
        complete: true,
    };
    for (start, end) in spans {
        token.check_cancelled()?;
        let step = if utf16 { 2 } else { 1 };
        let mut pos = start;
        if utf16 && pos % 2 != 0 {
            pos += 1;
            out.complete = false;
        }
        while pos < end {
            token.check_cancelled()?;
            if out.lines.len() >= limit {
                out.complete = false;
                return Ok(out);
            }
            let newline = (pos..end)
                .step_by(step)
                .find(|&i| bytes[i] == b'\n' && (!utf16 || i + 1 < end && bytes[i + 1] == 0));
            let next = newline.map_or(end, |n| n + step);
            let raw = &bytes[pos..next];
            let complete = (pos > start || start == 0)
                && (newline.is_some() || next as u64 == logical_size)
                && raw.len() <= 16 * 1024;
            let shown = &raw[..raw.len().min(16 * 1024)];
            let decoded = if utf16 {
                if !shown.len().is_multiple_of(2) {
                    None
                } else {
                    String::from_utf16(
                        &shown
                            .chunks_exact(2)
                            .map(|p| u16::from_le_bytes([p[0], p[1]]))
                            .collect::<Vec<_>>(),
                    )
                    .ok()
                }
            } else {
                std::str::from_utf8(shown).ok().map(str::to_owned)
            };
            match decoded {
                Some(text)
                    if !text
                        .chars()
                        .any(|c| c.is_control() && !matches!(c, '\t' | '\r' | '\n')) =>
                {
                    let text = text.trim_matches(['\u{feff}', '\r', '\n']).to_owned();
                    if !text.trim().is_empty() {
                        out.lines.push(ResidentLine {
                            offset: pos as u64,
                            byte_length: shown.len(),
                            text,
                            encoding: if utf16 { "UTF-16LE" } else { "UTF-8" },
                            complete,
                            sha256: hex::encode(Sha256::digest(shown)),
                        });
                    }
                    out.complete &= complete;
                }
                _ => out.complete = false,
            }
            pos = next;
        }
    }
    Ok(out)
}

pub(super) fn interpret(
    kind: ApplicationKind,
    path: &str,
    text: &str,
    complete: bool,
) -> Option<(&'static str, Value)> {
    if !complete {
        return None;
    }
    let value = text.trim();
    match kind {
        ApplicationKind::Anydesk => {
            if let Some((key, value)) = value.split_once('=')
                && matches!(
                    key.trim(),
                    "ad.anynet.id" | "ad.anynet.alias" | "ad.anynet.aliases"
                )
                && !value.trim().is_empty()
            {
                return Some((
                    "anydesk_identity",
                    json!({"key":key.trim(),"value":value.trim(),"role":"配置中的本机标识，非远端操作者"}),
                ));
            }
            if super::basename(path) == "connection_trace.txt" {
                return Some((
                    "connection_trace",
                    json!({"raw":value,"meaning":"连接请求原文；状态、方向和设备号需按原文复核"}),
                ));
            }
        }
        ApplicationKind::Veracrypt => {
            if matches!(
                super::basename(path).as_str(),
                "history.xml" | "favorite volumes.xml"
            ) {
                let mut volumes = Vec::new();
                for (start, _) in value.match_indices("<volume") {
                    let tag = &value[start..];
                    if !tag
                        .as_bytes()
                        .get(7)
                        .is_some_and(|c| *c == b'>' || c.is_ascii_whitespace())
                    {
                        continue;
                    }
                    // Require a complete element on one resident line; never cross a gap.
                    if let Some(begin) = tag.find('>')
                        && let Some(end) = tag[begin + 1..].find("</volume>")
                    {
                        let volume = &tag[begin + 1..begin + 1 + end];
                        if !volume.contains('<') && !volume.trim().is_empty() {
                            volumes.push(volume);
                        }
                    }
                }
                if !volumes.is_empty() {
                    return Some((
                        "volume_history",
                        json!({"paths_xml_text":volumes,"meaning":"挂载尝试/收藏项，不证明挂载成功或当前仍挂载"}),
                    ));
                }
            }
        }
        ApplicationKind::Sunlogin => {
            if let Some((key, value)) = value.split_once('=')
                && matches!(
                    key.trim().to_ascii_lowercase().as_str(),
                    "clientid" | "client_id" | "fastcode" | "sunlogincode" | "device_id"
                )
                && !value.trim().is_empty()
            {
                return Some((
                    "sunlogin_identity",
                    json!({"key":key.trim(),"value":value.trim(),"role":"配置标识，非成功会话"}),
                ));
            }
        }
        _ => {}
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn extent(offset: u64, len: u64) -> RecoveredExtent {
        RecoveredExtent {
            file_offset: offset,
            length: len,
            memory_address: 0x1000 + offset,
            memory_kind: "physical".into(),
        }
    }
    #[test]
    fn gaps_cannot_manufacture_identity_or_xml() {
        let bytes = b"ad.anynet.id=123456\n";
        let p = parse_resident_lines(
            bytes,
            &[extent(0, 12), extent(14, 5)],
            19,
            100,
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(!p.complete);
        assert!(p.lines.iter().all(|l| {
            interpret(
                ApplicationKind::Anydesk,
                "service.conf",
                &l.text,
                l.complete,
            )
            .is_none()
        }));
        assert!(
            interpret(
                ApplicationKind::Veracrypt,
                "History.xml",
                "<volume>x</volume>",
                false
            )
            .is_none()
        );
    }
    #[test]
    fn adjacent_pages_and_utf16_preserve_offsets() {
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend(
            "ad.anynet.id=123456789\r\n中文\n"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        let p = parse_resident_lines(
            &bytes,
            &[extent(20, (bytes.len() - 20) as u64), extent(0, 20)],
            bytes.len() as u64,
            100,
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(p.complete);
        assert_eq!(p.lines.len(), 2);
        assert_eq!(p.lines[0].encoding, "UTF-16LE");
        assert_eq!(p.lines[1].offset, 50);
        assert_eq!(p.lines[1].text, "中文");
        assert_eq!(
            interpret(
                ApplicationKind::Anydesk,
                "service.conf",
                &p.lines[0].text,
                true
            )
            .unwrap()
            .0,
            "anydesk_identity"
        );
    }
    #[test]
    fn truncation_and_cancel_are_not_success() {
        let bytes = b"a\nb\n";
        let p =
            parse_resident_lines(bytes, &[extent(0, 4)], 4, 1, &CancellationToken::new()).unwrap();
        assert!(!p.complete);
        assert_eq!(p.lines.len(), 1);
        let token = CancellationToken::new();
        token.request_cancel();
        assert!(parse_resident_lines(bytes, &[extent(0, 4)], 4, 10, &token).is_err());
        let (_, value) = interpret(
            ApplicationKind::Veracrypt,
            "History.xml",
            "<volumeshistory><volume>x</volume><volume favorite=\"1\">y</volume></volumeshistory>",
            true,
        )
        .unwrap();
        assert_eq!(value["paths_xml_text"], json!(["x", "y"]));
    }
}
