//! QQNT numbered message fields found in native resident buffers.
//! Outer allocation/framing is often gone: only continuous, validated fields
//! are retained. A separately framed element never inherits a nearby sender.
use super::v8::Decoded;
use serde_json::{Map, Value, json};

const MAX_FIELDS: usize = 256;
const MAX_BYTES: usize = 64 * 1024;

#[derive(Debug)]
struct Field<'a> {
    number: u32,
    wire: u8,
    start: usize,
    end: usize,
    integer: Option<u64>,
    bytes: &'a [u8],
}

fn varint(bytes: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*pos).ok_or("Protobuf varint 缺页或截断")?;
        *pos += 1;
        if shift == 63 && byte > 1 {
            return Err("Protobuf varint 溢出".into());
        }
        value |= u64::from(byte & 127) << shift;
        if byte < 128 {
            if shift > 0 && byte == 0 {
                return Err("Protobuf varint 非最短编码".into());
            }
            return Ok(value);
        }
    }
    Err("Protobuf varint 无终止".into())
}

fn field<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<Field<'a>, String> {
    let start = *pos;
    let key = varint(bytes, pos)?;
    let number = key >> 3;
    if number == 0 || number > 0x1fff_ffff {
        return Err("Protobuf 字段号无效或已到缓冲区尾部".into());
    }
    let wire = (key & 7) as u8;
    let (integer, raw) = match wire {
        0 => (Some(varint(bytes, pos)?), &bytes[0..0]),
        1 | 2 | 5 => {
            let len = match wire {
                1 => 8,
                5 => 4,
                _ => usize::try_from(varint(bytes, pos)?).map_err(|_| "字段长度溢出")?,
            };
            if len > MAX_BYTES {
                return Err("Protobuf 字段超过读取上限".into());
            }
            let end = pos.checked_add(len).ok_or("Protobuf 字段范围溢出")?;
            let raw = bytes.get(*pos..end).ok_or("Protobuf 字段缺页或截断")?;
            *pos = end;
            (None, raw)
        }
        _ => return Err(format!("未支持的 Protobuf wire type {wire}")),
    };
    Ok(Field {
        number: number as u32,
        wire,
        start,
        end: *pos,
        integer,
        bytes: raw,
    })
}

fn raw_fields(fields: &[Field<'_>]) -> Value {
    Value::Array(
        fields
            .iter()
            .map(|f| {
                json!({
                    "number":f.number,"wire_type":f.wire,"object_byte_offset":f.start,
                    "byte_length":f.end-f.start,"integer":f.integer,
                    "bytes_hex":if f.wire == 0 {None} else {Some(hex::encode(f.bytes))},
                })
            })
            .collect(),
    )
}

fn integer(fields: &[Field<'_>], number: u32) -> Option<u64> {
    fields
        .iter()
        .find(|f| f.number == number && f.wire == 0)?
        .integer
}

fn string<'a>(fields: &[Field<'a>], number: u32) -> Option<&'a str> {
    let f = fields.iter().find(|f| f.number == number && f.wire == 2)?;
    std::str::from_utf8(f.bytes).ok()
}

fn uid(fields: &[Field<'_>], number: u32) -> Result<String, String> {
    let text = string(fields, number).ok_or("缺少 QQ UID 字符串")?;
    if !text.starts_with("u_")
        || !(8..=64).contains(&text.len())
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("QQ UID 结构无效".into());
    }
    Ok(text.into())
}

fn element(bytes: &[u8]) -> Result<Value, String> {
    let mut pos = 0;
    let mut fields = Vec::new();
    while pos < bytes.len() {
        if fields.len() >= MAX_FIELDS {
            return Err("QQ 元素字段数量超限".into());
        }
        let f = field(bytes, &mut pos)?;
        if !(40000..=59999).contains(&f.number)
            || fields.iter().any(|p: &Field<'_>| p.number == f.number)
        {
            return Err("QQ 元素字段范围或重复字段不支持".into());
        }
        fields.push(f);
    }
    element_value(&fields, true)
}

fn element_value(fields: &[Field<'_>], require_id: bool) -> Result<Value, String> {
    let id = integer(fields, 45001).filter(|v| *v > 0);
    if require_id && id.is_none() {
        return Err("QQ 元素缺少 elementId".into());
    }
    let kind = integer(fields, 45002)
        .filter(|v| (1..=128).contains(v))
        .ok_or("QQ 元素类型无效")?;
    let mut out = json!({"elementType":kind,"protobuf_fields":raw_fields(fields)});
    if let Some(id) = id {
        out["elementId"] = json!(id.to_string());
    }
    if kind == 1 {
        let content = string(fields, 45101).ok_or("QQ 文本元素缺少有效 UTF-8 正文")?;
        if content.contains('\0') {
            return Err("QQ 正文含非法 NUL".into());
        }
        out["textElement"] = json!({"content":content});
        if let Some(at_type) = integer(fields, 45102) {
            out["textElement"]["atType"] = json!(at_type);
        }
    }
    Ok(out)
}

pub(super) fn decode_text_prefix(bytes: &[u8], has_id: bool) -> Result<Decoded, String> {
    let mut pos = 0;
    let mut fields = Vec::new();
    let mut valid_end = 0;
    while pos < bytes.len().min(MAX_BYTES) && fields.len() < MAX_FIELDS {
        let f = match field(bytes, &mut pos) {
            Ok(f) => f,
            Err(_) => break,
        };
        if !(45001..=59999).contains(&f.number)
            || fields
                .last()
                .is_some_and(|p: &Field<'_>| f.number <= p.number)
        {
            break;
        }
        if fields.is_empty() && f.number != if has_id { 45001 } else { 45002 } {
            return Err("QQ 正文片段起点无效".into());
        }
        valid_end = f.end;
        fields.push(f);
    }
    let element = element_value(&fields, has_id)?;
    if element.get("textElement").is_none() {
        return Err("QQ 片段不是文本元素".into());
    }
    Ok(Decoded {
        value: json!({"record_format":"qqnt_protobuf_text_fragment","elements":[element]}),
        consumed: valid_end,
        complete: false,
        stop_reason: Some("QQ 文本字段连续且长度有效，但外层元素长度和会话归属未恢复".into()),
    })
}

/// An exact length-delimited 40800 element remains useful even when its
/// enclosing message header has been overwritten. No account/time is inferred.
pub(super) fn decode_element(bytes: &[u8]) -> Result<Decoded, String> {
    let mut pos = 0;
    let f = field(bytes, &mut pos)?;
    if f.number != 40800 || f.wire != 2 {
        return Err("不是 QQ 元素长度字段".into());
    }
    let element = element(f.bytes)?;
    // Detached non-text elements are too ambiguous to present as chat content.
    if element.get("textElement").is_none() {
        return Err("独立 QQ 元素不是文本".into());
    }
    Ok(Decoded {
        value: json!({"record_format":"qqnt_protobuf_element","elements":[element]}),
        consumed: pos,
        complete: true,
        stop_reason: None,
    })
}

pub(super) fn decode_message(bytes: &[u8], has_id: bool) -> Result<Decoded, String> {
    let bytes = &bytes[..bytes.len().min(MAX_BYTES)];
    let mut pos = 0;
    let mut fields = Vec::new();
    let mut valid_end = 0;
    let mut stop = "未恢复外层缓冲区长度，仅保留连续 QQ 字段".to_string();
    let mut elements = Vec::new();
    while pos < bytes.len() {
        if fields.len() >= MAX_FIELDS {
            stop = "QQ 消息字段数量超限".into();
            break;
        }
        let f = match field(bytes, &mut pos) {
            Ok(f) => f,
            Err(e) => {
                stop = e;
                break;
            }
        };
        if !(40001..=40999).contains(&f.number)
            || fields
                .last()
                .is_some_and(|p: &Field<'_>| f.number < p.number)
            || (f.number != 40800
                && f.number != 40801
                && fields.iter().any(|p| p.number == f.number))
        {
            stop = "QQ 字段顺序结束或出现重复字段，未拼接后续数据".into();
            break;
        }
        if fields.is_empty() && f.number != if has_id { 40001 } else { 40002 } {
            return Err("QQ 消息起点不匹配".into());
        }
        if f.number == 40800 {
            if f.wire != 2 {
                stop = "QQ 元素 wire type 错误".into();
                break;
            }
            match element(f.bytes) {
                Ok(value) => elements.push(value),
                Err(e) => {
                    stop = e;
                    break;
                }
            }
        }
        valid_end = f.end;
        fields.push(f);
    }
    let sender = uid(&fields, 40020)?;
    let time = integer(&fields, 40050)
        .filter(|v| (946684800..=4102444800).contains(v))
        .ok_or("QQ msgTime 无效")?;
    let chat_type = integer(&fields, 40010)
        .filter(|v| (1..=32).contains(v))
        .ok_or("QQ chatType 无效")?;
    let peer = string(&fields, 40021).ok_or("QQ peerUid 缺失或编码无效")?;
    if !super::valid_peer(&json!({"peerUid":peer,"chatType":chat_type})) {
        return Err("QQ peerUid 不符合当前会话类型".into());
    }
    let msg_type = integer(&fields, 40011)
        .filter(|v| (1..=1024).contains(v))
        .ok_or("QQ msgType 无效")?;
    // Require sequence and metadata together, beyond a chance text/tag match.
    if has_id && integer(&fields, 40001).is_none_or(|id| id == 0) {
        return Err("QQ msgId 字段类型或值无效".into());
    }
    integer(&fields, 40002).ok_or("QQ msgRandom 字段缺失或类型无效")?;
    integer(&fields, 40003).ok_or("QQ 消息序号缺失")?;
    integer(&fields, 40012).ok_or("QQ subMsgType 缺失")?;
    integer(&fields, 40013).ok_or("QQ sendType 缺失")?;
    let mut out = Map::new();
    out.insert("record_format".into(), json!("qqnt_protobuf_message"));
    out.insert("senderUid".into(), json!(sender));
    out.insert("peerUid".into(), json!(peer));
    out.insert("msgTime".into(), json!(time.to_string()));
    out.insert("chatType".into(), json!(chat_type));
    out.insert("msgType".into(), json!(msg_type));
    for (number, name, decimal_string) in [
        (40001, "msgId", true),
        (40002, "msgRandom", true),
        (40003, "msgSeq", true),
        (40012, "subMsgType", false),
        (40013, "sendType", false),
        // Unlike 40020/40021 (sender/peer UID), the numbered UIN fields
        // are peer first, then sender. Verified against V8 message fields.
        (40030, "peerUin", true),
        (40033, "senderUin", true),
    ] {
        if let Some(value) = integer(&fields, number) {
            if name == "msgId" && value == 0 {
                return Err("QQ msgId 为零".into());
            }
            out.insert(
                name.into(),
                if decimal_string {
                    json!(value.to_string())
                } else {
                    json!(value)
                },
            );
        }
    }
    out.insert("elements".into(), json!(elements));
    out.insert("protobuf_fields".into(), raw_fields(&fields));
    Ok(Decoded {
        value: Value::Object(out),
        consumed: valid_end,
        complete: false,
        stop_reason: Some(format!(
            "{stop}；外层长度未验证{}",
            if has_id { "" } else { "，消息 ID 缺失" }
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(mut n: u64) -> Vec<u8> {
        let mut v = Vec::new();
        while n >= 128 {
            v.push((n as u8) | 128);
            n >>= 7;
        }
        v.push(n as u8);
        v
    }
    fn num(n: u32, v: u64) -> Vec<u8> {
        [var(u64::from(n) * 8), var(v)].concat()
    }
    fn buf(n: u32, v: &[u8]) -> Vec<u8> {
        [var(u64::from(n) * 8 + 2), var(v.len() as u64), v.to_vec()].concat()
    }
    fn text_element() -> Vec<u8> {
        [
            num(45001, 7557886039425727585),
            num(45002, 1),
            buf(45101, "你好🍔".as_bytes()),
            num(45102, 0),
        ]
        .concat()
    }
    fn message(with_id: bool) -> Vec<u8> {
        [
            if with_id {
                num(40001, 7557886039425727586)
            } else {
                vec![]
            },
            num(40002, 123),
            num(40003, 20),
            num(40010, 1),
            num(40011, 2),
            num(40012, 1),
            num(40013, 0),
            buf(40020, b"u_sender01"),
            buf(40021, b"u_peer0001"),
            num(40030, 100001),
            num(40033, 200002),
            num(40050, 1759704348),
            buf(40800, &text_element()),
            buf(40900, b""),
        ]
        .concat()
    }
    #[test]
    fn numbered_message_preserves_long_id_unicode_and_raw_fields() {
        let bytes = message(true);
        let d = decode_message(&bytes, true).unwrap();
        assert_eq!(d.value["msgId"], "7557886039425727586");
        assert_eq!(d.value["elements"][0]["textElement"]["content"], "你好🍔");
        assert!(!d.complete);
        assert_eq!(d.consumed, bytes.len());
        assert_eq!(
            d.value["protobuf_fields"][0]["integer"],
            json!(7557886039425727586_u64)
        );
    }
    #[test]
    fn lost_id_is_never_reconstructed_from_element_id() {
        let d = decode_message(&message(false), false).unwrap();
        assert!(d.value.get("msgId").is_none());
        assert_eq!(d.value["msgSeq"], "20");
    }
    #[test]
    fn sender_and_peer_uins_use_their_own_numbered_fields() {
        let d = decode_message(&message(true), true).unwrap();
        assert_eq!(d.value["senderUid"], "u_sender01");
        assert_eq!(d.value["senderUin"], "200002");
        assert_eq!(d.value["peerUid"], "u_peer0001");
        assert_eq!(d.value["peerUin"], "100001");
    }
    #[test]
    fn numeric_group_peer_is_not_rejected_as_a_private_uid() {
        let bytes = message(true);
        let replace = |input: Vec<u8>, from: &[u8], to: &[u8]| {
            let offset = input.windows(from.len()).position(|w| w == from).unwrap();
            [
                input[..offset].to_vec(),
                to.to_vec(),
                input[offset + from.len()..].to_vec(),
            ]
            .concat()
        };
        let bytes = replace(bytes, &buf(40021, b"u_peer0001"), &buf(40021, b"123456789"));
        assert!(decode_message(&bytes, true).is_err());
        let bytes = replace(bytes, &num(40010, 1), &num(40010, 2));
        let decoded = decode_message(&bytes, true).unwrap();
        assert_eq!(decoded.value["peerUid"], "123456789");
        assert_eq!(decoded.value["senderUid"], "u_sender01");
        assert_eq!(
            decoded.value["elements"][0]["textElement"]["content"],
            "你好🍔"
        );
    }
    #[test]
    fn framed_detached_text_does_not_inherit_sender_or_time() {
        let bytes = buf(40800, &text_element());
        let d = decode_element(&bytes).unwrap();
        assert!(d.complete);
        assert_eq!(d.consumed, bytes.len());
        assert!(d.value.get("senderUid").is_none());
        assert!(d.value.get("msgTime").is_none());
        assert!(decode_element(&bytes[..bytes.len() - 1]).is_err());
    }
    #[test]
    fn text_field_prefix_does_not_invent_missing_element_id() {
        let bytes = [
            num(45002, 1),
            buf(45101, "正文".as_bytes()),
            num(45102, 0),
            vec![0, 255],
        ]
        .concat();
        let d = decode_text_prefix(&bytes, false).unwrap();
        assert!(!d.complete);
        assert_eq!(d.consumed, bytes.len() - 2);
        assert_eq!(d.value["elements"][0]["textElement"]["content"], "正文");
        assert!(d.value["elements"][0].get("elementId").is_none());
        assert!(decode_text_prefix(&bytes, true).is_err());
    }
    #[test]
    fn corruption_stops_without_splicing_later_text() {
        let mut bytes = message(true);
        let start = bytes.windows(3).position(|w| w == b"\x82\xf6\x13").unwrap();
        bytes[start] = 0;
        let d = decode_message(&bytes, true).unwrap();
        assert_eq!(d.consumed, start);
        assert_eq!(d.value["elements"], json!([]));
    }
    #[test]
    fn duplicate_header_cannot_join_adjacent_messages() {
        let first = message(true);
        let mut bytes = first.clone();
        bytes.extend(message(true));
        let d = decode_message(&bytes, true).unwrap();
        assert_eq!(d.consumed, first.len());
    }
    #[test]
    fn bad_tags_lengths_ids_and_utf8_are_rejected() {
        assert!(decode_message(&buf(40020, b"u_sender01"), false).is_err());
        assert!(varint(&[255; 10], &mut 0).is_err());
        assert!(varint(&[128, 0], &mut 0).is_err());
        let bad = [num(45001, 1), num(45002, 1), buf(45101, &[255])].concat();
        assert!(decode_element(&buf(40800, &bad)).is_err());
        assert!(decode_element(&[0x82, 0xf6, 0x13, 255, 255, 127]).is_err());
        let bad_id = [buf(40001, b"wrong-wire"), message(false)].concat();
        assert!(decode_message(&bad_id, true).is_err());
    }
}
