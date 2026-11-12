//! Bounded document/account evidence. Text runs stay unassigned to a document
//! unless the same recovered object explicitly identifies it.
use super::{ApplicationKind, ai::Artifact, remote};
use serde_json::{Value, json};

pub(super) fn extract(v: &Value) -> Vec<Artifact> {
    let mut out = remote::extract(ApplicationKind::Wps, v);
    out.retain(|a| a.kind == "remote_account");
    for a in &mut out {
        a.kind = "office_account";
        a.data["semantics"] = json!("WPS 驻留对象中的账户字段；不证明当前登录或实际操作者");
    }
    fn walk(v: &Value, p: &str, depth: usize, out: &mut Vec<Artifact>) {
        if depth > 12 || out.len() >= 128 {
            return;
        }
        if let Some(m) = v.as_object() {
            for (k, val) in m {
                let path = format!("{p}/{}", k.replace('~', "~0").replace('/', "~1"));
                if matches!(
                    k.as_str(),
                    "filePath" | "file_path" | "path" | "url" | "document_path"
                ) && let Some(s) = val.as_str().filter(|s| is_document_path(s))
                {
                    out.push(Artifact{kind:"office_document_path",pointer:path.clone(),data:json!({"document_path":s,"title":v.get("title"),"document_id":v.get("fileid").or_else(||v.get("document_id")),"semantics":"同一驻留对象内的文档路径；不证明已打开、编辑或保存"})});
                }
                if !val.is_string() {
                    walk(val, &path, depth + 1, out);
                }
            }
        } else if let Some(a) = v.as_array() {
            for (i, v) in a.iter().take(128).enumerate() {
                walk(v, &format!("{p}/{i}"), depth + 1, out);
            }
        }
    }
    walk(v, "", 0, &mut out);
    out
}

fn is_document_path(s: &str) -> bool {
    let lower = s.to_lowercase();
    s.len() <= 4096
        && (s.contains(":\\")
            || s.starts_with("\\\\")
            || s.starts_with("file://")
            || s.starts_with("https://"))
        && super::is_office_document(lower.split(['?', '#']).next().unwrap_or(&lower))
}

pub(super) fn text(s: &str) -> Vec<(usize, usize, Artifact)> {
    use std::sync::OnceLock;
    static PATH: OnceLock<regex::Regex> = OnceLock::new();
    let re=PATH.get_or_init(||regex::Regex::new(r#"(?i)(?:[a-z]:\\|file:///|\\\\)[^\r\n\x00"<>|]{1,512}\.(?:docx?|xlsx?|pptx?|wps|et|dps|pdf|ofd)\b"#).expect("constant document path regex"));
    re.find_iter(s).take(32).map(|m|(m.start(),m.len(),Artifact{kind:"office_document_path",pointer:String::new(),data:json!({"document_path":m.as_str(),"semantics":"WPS 进程或专属文件内的路径片段；不证明打开/编辑，也不据此绑定其他正文"})})).collect()
}

pub(super) fn xml_run(
    bytes: &[u8],
    anchor: usize,
    utf16: bool,
) -> Option<(usize, usize, Artifact)> {
    let step = if utf16 { 2 } else { 1 };
    let max = (bytes.len() - anchor).min(16 * 1024);
    let decoded = if utf16 {
        char::decode_utf16(
            bytes[anchor..anchor + max]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]])),
        )
        .map_while(Result::ok)
        .take_while(|c| *c != '\0')
        .collect::<String>()
    } else {
        let b = &bytes[anchor..anchor + max];
        let n = std::str::from_utf8(b)
            .err()
            .map_or(b.len(), |e| e.valid_up_to());
        std::str::from_utf8(&b[..n])
            .ok()?
            .split('\0')
            .next()?
            .to_owned()
    };
    let (prefix, closing) = if decoded.starts_with("<w:t") {
        ("<w:t", "</w:t>")
    } else if decoded.starts_with("<a:t") {
        ("<a:t", "</a:t>")
    } else if decoded.starts_with("<t>") || decoded.starts_with("<t ") {
        ("<t", "</t>")
    } else {
        return None;
    };
    if !matches!(decoded.as_bytes().get(prefix.len()), Some(b'>' | b' ')) {
        return None;
    }
    let begin = decoded.find('>')? + 1;
    let end = decoded[begin..].find(closing)? + begin;
    let body = &decoded[begin..end];
    if body.contains('<')
        || body.is_empty()
        || body
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
    {
        return None;
    }
    let consumed = &decoded[..end + closing.len()];
    let len = if step == 2 {
        consumed.encode_utf16().count() * 2
    } else {
        consumed.len()
    };
    let text = body
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&");
    Some((
        anchor,
        len,
        Artifact {
            kind: "office_text",
            pointer: String::new(),
            data: json!({"text":text,"raw_xml":consumed,"format":prefix,"document_id":Value::Null,"semantics":"完整驻留 OOXML 文本节点；未绑定文件，可能是正文、模板或历史副本"}),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_nodes_require_closure_and_preserve_encoding_length() {
        let s = "<w:t xml:space=\"preserve\">中文 &amp; 内容</w:t>";
        let b: Vec<_> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let (_, len, a) = xml_run(&b, 0, true).unwrap();
        assert_eq!(len, b.len());
        assert_eq!(a.data["text"], "中文 & 内容");
        assert!(xml_run(b"<w:t>partial", 0, false).is_none());
        assert!(xml_run(b"<w:table>x</w:t>", 0, false).is_none());
        assert!(text("C:\\Users\\a\\报告.docx").len() == 1);
    }
}
