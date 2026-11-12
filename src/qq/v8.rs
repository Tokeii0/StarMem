//! Bounded, data-only reader for the V8 wire types observed in QQNT IPC.
//! No JavaScript, host objects or object references are executed/resolved.
use serde_json::{Map, Value, json};

type ReadResult<T> = Result<T, String>;
const MAX_ITEMS: usize = 4096;
const MAX_NODES: usize = 32768;
const MAX_DEPTH: usize = 32;

pub(super) struct Decoded {
    pub value: Value,
    pub consumed: usize,
    pub complete: bool,
    pub stop_reason: Option<String>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    nodes: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> ReadResult<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or("长度溢出")?;
        let bytes = self.bytes.get(self.pos..end).ok_or("数据在字段中途结束")?;
        self.pos = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> ReadResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn varint(&mut self) -> ReadResult<u32> {
        let mut value = 0;
        for shift in (0..35).step_by(7) {
            let byte = self.byte()?;
            if shift == 28 && byte > 15 {
                return Err("varint 超过 u32".into());
            }
            value |= u32::from(byte & 127) << shift;
            if byte < 128 {
                return Ok(value);
            }
        }
        Err("无终止的 varint".into())
    }

    fn peek(&mut self) -> ReadResult<u8> {
        // Alignment padding is normally a single byte. Do not walk arbitrary
        // zero-filled/corrupt pages looking for a later plausible value.
        for _ in 0..8 {
            let byte = *self.bytes.get(self.pos).ok_or("数据结束")?;
            if byte != 0 {
                return Ok(byte);
            }
            self.pos += 1;
        }
        Err("连续填充超出 V8 对齐范围".into())
    }

    fn count(&mut self, expected: usize) -> ReadResult<()> {
        if self.varint()? as usize != expected {
            return Err("集合尾部计数不匹配".into());
        }
        Ok(())
    }

    fn key(&mut self, depth: usize) -> ReadResult<String> {
        match self.value(depth)? {
            Value::String(s) => Ok(s),
            Value::Number(n) => Ok(n.to_string()),
            _ => Err("对象属性名不是字符串或数字".into()),
        }
    }

    fn properties(&mut self, end_tag: u8, depth: usize) -> ReadResult<Map<String, Value>> {
        let mut out = Map::new();
        while self.peek()? != end_tag {
            if out.len() >= MAX_ITEMS {
                return Err("属性数量达到上限".into());
            }
            let key = self.key(depth + 1)?;
            if out.contains_key(&key) {
                return Err("重复的对象属性".into());
            }
            out.insert(key, self.value(depth + 1)?);
        }
        self.byte()?;
        self.count(out.len())?;
        Ok(out)
    }

    fn value(&mut self, depth: usize) -> ReadResult<Value> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return Err("V8 解析预算达到上限".into());
        }
        self.peek()?;
        let tag = self.byte()?;
        match tag {
            b'0' | b'_' | b'-' => Ok(Value::Null),
            b'T' => Ok(Value::Bool(true)),
            b'F' => Ok(Value::Bool(false)),
            b'I' => {
                let n = self.varint()?;
                Ok(json!(((n >> 1) as i32) ^ -((n & 1) as i32)))
            }
            b'U' => Ok(json!(self.varint()?)),
            b'N' => {
                let raw: [u8; 8] = self.take(8)?.try_into().map_err(|_| "double 长度错误")?;
                let n = f64::from_le_bytes(raw);
                if !n.is_finite() {
                    return Err("不支持非有限数值".into());
                }
                Ok(json!(n))
            }
            b'"' | b'S' | b'c' => {
                let len = self.varint()? as usize;
                let raw = self.take(len)?;
                let text = match tag {
                    b'"' => raw.iter().map(|b| char::from(*b)).collect(),
                    b'S' => std::str::from_utf8(raw)
                        .map_err(|_| "非法 UTF-8")?
                        .to_owned(),
                    _ => {
                        if !len.is_multiple_of(2) {
                            return Err("UTF-16 字节长度为奇数".into());
                        }
                        String::from_utf16(
                            &raw.chunks_exact(2)
                                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                                .collect::<Vec<_>>(),
                        )
                        .map_err(|_| "非法 UTF-16 代理项")?
                    }
                };
                Ok(Value::String(text))
            }
            b'o' => Ok(Value::Object(self.properties(b'{', depth)?)),
            b'a' | b'A' => {
                let length = self.varint()? as usize;
                if length > MAX_ITEMS {
                    return Err("数组长度达到上限".into());
                }
                let mut items = vec![Value::Null; length];
                if tag == b'A' {
                    for item in &mut items {
                        *item = self.value(depth + 1)?;
                    }
                }
                let props = self.properties(if tag == b'A' { b'$' } else { b'@' }, depth)?;
                self.count(length)?;
                for (key, value) in props {
                    let index = key.parse::<usize>().map_err(|_| "不支持数组的命名属性")?;
                    if index >= length {
                        return Err("数组索引越界".into());
                    }
                    items[index] = value;
                }
                Ok(Value::Array(items))
            }
            b';' => {
                let mut entries = Vec::new();
                while self.peek()? != b':' {
                    if entries.len() >= MAX_ITEMS {
                        return Err("Map 长度达到上限".into());
                    }
                    entries.push(json!([self.value(depth + 1)?, self.value(depth + 1)?]));
                }
                self.byte()?;
                self.count(entries.len() * 2)?;
                Ok(json!({"v8_type": "map", "entries": entries}))
            }
            b'B' => {
                let len = self.varint()? as usize;
                let bytes = self.take(len)?;
                let mut out = json!({"v8_type": "array_buffer", "hex": hex::encode(bytes)});
                if self.bytes.get(self.pos) == Some(&b'V') {
                    self.byte()?;
                    let kind = self.byte()?;
                    if !b"bBCwWdDfFqQ?".contains(&kind) {
                        return Err("未知的 ArrayBufferView 类型".into());
                    }
                    let offset = self.varint()? as usize;
                    let length = self.varint()? as usize;
                    let flags = self.varint()?;
                    if offset.checked_add(length).is_none_or(|end| end > len) || flags != 0 {
                        return Err("ArrayBufferView 边界或标志不支持".into());
                    }
                    out["view"] = json!({"kind":char::from(kind).to_string(),"offset":offset,"length":length});
                }
                Ok(out)
            }
            b'^' => Err("对象引用依赖外层序列化上下文，未猜测引用目标".into()),
            _ => Err(format!("不支持或已损坏的 V8 类型 0x{tag:02x}")),
        }
    }
}

pub(super) fn decode_ipc(bytes: &[u8]) -> ReadResult<Decoded> {
    if !bytes.starts_with(&[0xff, 15]) {
        return Err("不支持的 V8 wire 版本".into());
    }
    let mut reader = Reader {
        bytes,
        pos: 2,
        nodes: 0,
    };
    let value = reader.value(0)?;
    Ok(Decoded {
        value,
        consumed: reader.pos,
        complete: true,
        stop_reason: None,
    })
}

/// Salvage only fully parsed top-level fields, stopping at the first error.
/// Never resynchronize beyond corruption or borrow fields from another object.
pub(super) fn decode_message_prefix(bytes: &[u8], has_start: bool) -> Decoded {
    let mut reader = Reader {
        bytes,
        pos: usize::from(has_start),
        nodes: 0,
    };
    let mut fields = Map::new();
    let mut valid_end = reader.pos;
    let stop = loop {
        let next = match reader.peek() {
            Ok(tag) => tag,
            Err(e) => break e,
        };
        if next == b'{' {
            reader.pos += 1;
            if has_start {
                match reader.count(fields.len()) {
                    Ok(()) => {
                        return Decoded {
                            value: Value::Object(fields),
                            consumed: reader.pos,
                            complete: true,
                            stop_reason: None,
                        };
                    }
                    Err(e) => break e,
                }
            }
            break "消息开头缺失，只保留结构连续的字段片段".into();
        }
        if fields.len() >= MAX_ITEMS {
            break "属性数量达到上限".into();
        }
        let key = match reader.key(1) {
            Ok(k) => k,
            Err(e) => break e,
        };
        if fields.contains_key(&key) {
            break "重复的消息字段".into();
        }
        match reader.value(1) {
            Ok(value) => {
                fields.insert(key, value);
                valid_end = reader.pos;
            }
            Err(e) => break e,
        }
    };
    Decoded {
        value: Value::Object(fields),
        consumed: valid_end,
        complete: false,
        stop_reason: Some(stop),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_array_and_utf16_are_data_not_code() {
        let bytes = b"\xff\x0fa\x01I\0o\"\x07content\0c\x04\x60\x4f\x7d\x59{\x01@\x01\x01";
        let result = decode_ipc(bytes).unwrap();
        assert_eq!(result.value, json!([{"content":"你好"}]));
        assert_eq!(result.consumed, bytes.len());
    }

    #[test]
    fn malformed_counts_refs_and_oversized_collections_fail() {
        for bytes in [
            &b"\xff\x0fo\"\x01xI\x02{\x02"[..],
            &b"\xff\x0f^\0"[..],
            &b"\xff\x0fA\xff\xff\x7f"[..],
            &b"\xff\x0fI\xff\xff\xff\xff\xff"[..],
        ] {
            assert!(decode_ipc(bytes).is_err());
        }
    }

    #[test]
    fn corruption_cannot_splice_later_fields_into_message() {
        let bytes = b"o\"\x05msgId\"\x03321\"\x09senderUid\"\x03u_a\x99\"\x07content\"\x06forged";
        let result = decode_message_prefix(bytes, true);
        assert!(!result.complete);
        assert_eq!(result.value, json!({"msgId":"321", "senderUid":"u_a"}));
        assert_eq!(bytes[result.consumed], 0x99);
    }

    #[test]
    fn truncated_strings_are_not_recovered() {
        let result = decode_message_prefix(b"o\"\x05msgId\"\x04321", true);
        assert_eq!(result.value, json!({}));
        assert!(!result.complete);
        assert!(decode_ipc(b"\xff\x0fc\x02\x00\xd8").is_err());
    }

    #[test]
    fn buffer_view_bounds_are_validated() {
        assert!(decode_ipc(b"\xff\x0fB\x02abVB\0\x02\0").is_ok());
        assert!(decode_ipc(b"\xff\x0fB\x02abVB\x01\x02\0").is_err());
    }
}
