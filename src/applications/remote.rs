//! Named fields only: a hash, ciphertext or arbitrary six-character string is
//! never reported as a working password. No recovered content is executed.
use super::{ApplicationKind, ai::Artifact};
use serde_json::{Value, json};

pub(super) fn anchors(kind: ApplicationKind) -> Vec<&'static str> {
    let mut a = vec![
        "password",
        "\"account\"",
        "\"username\"",
        "\"user_name\"",
        "\"userid\"",
        "\"user_id\"",
        "\"nickname\"",
        "\"email\"",
        "\"mobile\"",
        "\"loginname\"",
        "\"remote_id\"",
        "\"peer_id\"",
    ];
    if kind == ApplicationKind::Sunlogin {
        a.extend([
            "fastcode",
            "encry_pwd",
            "sunlogincode",
            "clientid",
            "client_id",
            "verifycode",
            "passcode",
            "--pwd=",
            "\"pwd\"",
        ]);
    } else {
        a.extend([
            "ad.anynet.id=",
            "ad.anynet.alias=",
            "ad.security.",
            "Incoming session",
            "Session closed",
            "Logged in",
        ]);
    }
    a
}

fn field(kind: ApplicationKind, key: &str, value: &str, pointer: String) -> Option<Artifact> {
    let k = key.trim_start_matches('-').to_ascii_lowercase();
    let value = value.trim();
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(char::is_control)
        || value.contains(['<', '>', '{', '}'])
        || value.contains("%s")
    {
        return None;
    }
    let (artifact, representation, label, sensitive) = match k.as_str() {
        "fastcode" | "ad.anynet.id" => {
            let digits = value.trim_start_matches('k');
            if !(5..=20).contains(&digits.len()) || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            ("remote_identity", "identifier", "设备识别码", false)
        }
        "clientid" | "client_id" | "new_clientid" | "ad.anynet.alias" | "ad.anynet.aliases" => {
            ("remote_identity", "identifier", "客户端标识", false)
        }
        "sunlogincode" => ("remote_identity", "identifier", "账户绑定标识", false),
        "encry_pwd" | "encrypted_password" => {
            ("remote_credential", "encrypted", "加密验证码", true)
        }
        "fastcodepsw" | "password_hash" | "pwd_hash" => (
            "remote_credential",
            "hash_or_verifier",
            "口令校验材料",
            true,
        ),
        "password" | "pwd" | "passcode" | "verifycode" | "verification_code"
        | "access_password" => (
            "remote_credential",
            "named_secret",
            "具名秘密字段（格式待核对）",
            true,
        ),
        "username" | "user_name" | "userid" | "user_id" | "nickname" | "loginname" | "account"
        | "email" | "mobile" | "phone" | "realname" => {
            ("remote_account", "profile_field", "账户字段", false)
        }
        "remote_id" | "peer_id" | "partner_id" | "remote_ip" | "session_id" => {
            ("remote_session_field", "session_field", "连接字段", false)
        }
        _ if kind == ApplicationKind::Anydesk && k.starts_with("ad.security.") => {
            if k.ends_with("salt") {
                ("remote_credential", "salt", "口令盐值", true)
            } else if k.ends_with("pwd") || k.ends_with("pwd_hash") || k.ends_with("password") {
                ("remote_credential", "hash", "无人值守口令哈希", true)
            } else {
                return None;
            }
        }
        _ => return None,
    };
    Some(Artifact {
        kind: artifact,
        pointer,
        data: json!({"field":key,"value":value,"representation":representation,
        "label":label,"sensitive":sensitive,"validation":"unverified",
        "semantics":"具名字段的驻留值；可能属于配置、请求或历史副本，未验证当前有效性和账户归属；哈希/密文不是明文密码"}),
    })
}

pub(super) fn extract(kind: ApplicationKind, value: &Value) -> Vec<Artifact> {
    fn walk(kind: ApplicationKind, v: &Value, path: &str, depth: usize, out: &mut Vec<Artifact>) {
        if depth > 12 || out.len() >= 128 {
            return;
        }
        if let Some(m) = v.as_object() {
            // AweSun's get_config reply uses a name/section/value envelope.
            if let (Some(name), Some(value)) = (
                v.get("name").and_then(Value::as_str),
                v.get("value").and_then(Value::as_str),
            ) && v.get("section").is_some()
                && let Some(a) = field(kind, name, value, format!("{path}/value"))
            {
                out.push(a);
            }
            for (k, val) in m {
                if out.len() >= 128 {
                    break;
                }
                let p = format!("{path}/{}", k.replace('~', "~0").replace('/', "~1"));
                if let Some(s) = val.as_str() {
                    if let Some(mut a) = field(kind, k, s, p.clone()) {
                        // AweSun uses "password" for protocol authentication
                        // material too. The field name does not establish plaintext.
                        if kind == ApplicationKind::Sunlogin
                            && k == "password"
                            && m.contains_key("fastcode")
                            && (m.contains_key("sign") || m.contains_key("server"))
                        {
                            a.data["representation"] = json!("authentication_material");
                            a.data["label"] = json!("协议认证材料");
                            a.data["context"] = json!({"fastcode":m.get("fastcode"),
                                "server":m.get("server"),"signed_request":m.contains_key("sign")});
                        }
                        out.push(a);
                    }
                } else if val.is_number()
                    && let Some(a) = field(kind, k, &val.to_string(), p.clone())
                {
                    out.push(a);
                }
                if !matches!(k.as_str(), "text" | "content" | "prompt" | "script") {
                    walk(kind, val, &p, depth + 1, out);
                }
            }
        } else if let Some(a) = v.as_array() {
            for (i, v) in a.iter().take(128).enumerate() {
                walk(kind, v, &format!("{path}/{i}"), depth + 1, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(kind, value, "", 0, &mut out);
    out
}

/// Return source-relative byte ranges, not just a parsed value detached from its source.
pub(super) fn text(kind: ApplicationKind, text: &str) -> Vec<(usize, usize, Artifact)> {
    use std::sync::OnceLock;
    static PAIR: OnceLock<regex::Regex> = OnceLock::new();
    let re=PAIR.get_or_init(||regex::Regex::new(r#"(?:^|[\s&;,])(-{0,2}[A-Za-z_][A-Za-z0-9_.-]{1,100})\s*=\s*(?:"([^"\r\n]+)"|([^\s&;"<>]+))"#).expect("constant field regex"));
    let mut out = Vec::new();
    for c in re.captures_iter(text).take(128) {
        let Some(k) = c.get(1) else {
            continue;
        };
        let Some(v) = c.get(2).or_else(|| c.get(3)) else {
            continue;
        };
        if let Some(a) = field(kind, k.as_str(), v.as_str(), String::new()) {
            out.push((k.start(), v.end() - k.start(), a));
        }
    }
    out
}

pub(super) fn nul_pair(
    kind: ApplicationKind,
    bytes: &[u8],
    anchor: usize,
    utf16: bool,
) -> Option<(usize, usize, Artifact)> {
    let step = if utf16 { 2 } else { 1 };
    let unit = |i: usize| -> Option<u16> {
        if utf16 {
            Some(u16::from_le_bytes([*bytes.get(i)?, *bytes.get(i + 1)?]))
        } else {
            Some(*bytes.get(i)? as u16)
        }
    };
    let mut pos = anchor;
    let mut k = Vec::new();
    while k.len() < 100 {
        let u = unit(pos)?;
        pos += step;
        if u == 0 {
            break;
        }
        if u > 127 || (!(u as u8).is_ascii_alphanumeric() && u != 95 && u != 46) {
            return None;
        }
        k.push(u);
    }
    let key = String::from_utf16(&k).ok()?;
    let mut v = Vec::new();
    while v.len() < 4096 {
        let u = unit(pos)?;
        pos += step;
        if u == 0 {
            break;
        }
        v.push(u);
    }
    // A key/value adjacency alone is insufficient. Require the observed config
    // serialization's NUL + line boundary, not two unrelated heap strings.
    if !matches!(unit(pos)?, 10 | 13) {
        return None;
    }
    let value = String::from_utf16(&v).ok()?;
    field(kind, &key, &value, String::new()).map(|a| (anchor, pos - anchor, a))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinguish_secret_representations_and_reject_templates() {
        let a = text(
            ApplicationKind::Anydesk,
            "ad.anynet.id=123456789\nad.security.permission_profiles._unattended_access.pwd=012345abcdef\nad.security.permission_profiles._unattended_access.salt=abcdef123456",
        );
        assert_eq!(a.len(), 3);
        assert_eq!(a[1].2.data["representation"], "hash");
        assert_eq!(a[2].2.data["representation"], "salt");
        assert!(
            text(
                ApplicationKind::Sunlogin,
                "fastcode=%s password=<placeholder>"
            )
            .is_empty()
        );
        let a = extract(
            ApplicationKind::Sunlogin,
            &json!({"name":"encry_pwd","section":"base","value":"base64cipher="}),
        );
        assert_eq!(a[0].data["representation"], "encrypted");
        let a = text(
            ApplicationKind::Sunlogin,
            "fastcode=k123456789 password=Ab12Cd",
        );
        assert_eq!(a.len(), 2);
        assert_eq!(a[1].2.data["representation"], "named_secret");
    }

    #[test]
    fn api_password_is_authentication_material_not_plaintext() {
        let a = extract(
            ApplicationKind::Sunlogin,
            &json!({
                "fastcode":"123456789", "password":"abcdef0123456789abcdef0123456789",
                "sign":"a-signature", "t":1700000000
            }),
        );
        let password = a.iter().find(|a| a.data["field"] == "password").unwrap();
        assert_eq!(password.data["representation"], "authentication_material");
        assert_eq!(password.pointer, "/password");
        let a = extract(ApplicationKind::Sunlogin, &json!({"password":"abcdef"}));
        assert_eq!(a[0].data["representation"], "named_secret");
    }

    #[test]
    fn nul_configuration_requires_boundaries_and_preserves_utf16_byte_range() {
        let s = "fastcode\0k123456789\0\n";
        let utf16: Vec<_> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let (start, size, a) = nul_pair(ApplicationKind::Sunlogin, &utf16, 0, true).unwrap();
        assert_eq!((start, size), (0, utf16.len() - 2));
        assert_eq!(a.data["value"], "k123456789");
        assert!(
            nul_pair(
                ApplicationKind::Sunlogin,
                b"fastcode\0k123456789\0other",
                0,
                false
            )
            .is_none()
        );
        assert!(nul_pair(ApplicationKind::Sunlogin, b"fastcode\0k12345", 0, false).is_none());
    }
}
