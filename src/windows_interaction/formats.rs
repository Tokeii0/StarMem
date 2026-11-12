//! Parsers accept only bounded bytes already proved resident by their caller.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

pub(super) fn u16le(b: &[u8], o: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(o..o.checked_add(2).context("offset overflow")?)
            .context("truncated u16")?
            .try_into()?,
    ))
}
pub(super) fn u32le(b: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(o..o.checked_add(4).context("offset overflow")?)
            .context("truncated u32")?
            .try_into()?,
    ))
}
pub(super) fn u64le(b: &[u8], o: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(o..o.checked_add(8).context("offset overflow")?)
            .context("truncated u64")?
            .try_into()?,
    ))
}
pub(super) fn utf16(b: &[u8]) -> Result<String> {
    ensure!(b.len().is_multiple_of(2), "UTF-16 被截断");
    let units: Vec<_> = b
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    Ok(String::from_utf16(&units)?)
}

pub(super) fn hdrop(b: &[u8]) -> Result<Value> {
    ensure!(b.len() >= 20, "DROPFILES 头不完整");
    let offset = u32le(b, 0)? as usize;
    let wide = u32le(b, 16)?;
    ensure!(
        offset >= 20 && offset < b.len() && wide <= 1,
        "DROPFILES 偏移或编码标记无效"
    );
    let data = &b[offset..];
    let mut paths = Vec::new();
    let mut pos = 0usize;
    if wide == 1 {
        ensure!(
            offset.is_multiple_of(2) && data.len().is_multiple_of(2),
            "DROPFILES UTF-16 对齐无效"
        );
        while pos + 2 <= data.len() {
            if u16le(data, pos)? == 0 {
                break;
            }
            let start = pos;
            while pos + 2 <= data.len() && u16le(data, pos)? != 0 {
                pos += 2;
            }
            ensure!(pos + 4 <= data.len(), "DROPFILES 缺少双 NUL 终止符");
            paths.push(utf16(&data[start..pos])?);
            pos += 2;
            ensure!(paths.len() <= 4096, "DROPFILES 文件数超过上限");
        }
        ensure!(
            pos + 2 <= data.len() && u16le(data, pos)? == 0,
            "DROPFILES 文件列表未终止"
        );
    } else {
        while pos < data.len() && data[pos] != 0 {
            let start = pos;
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }
            ensure!(pos + 1 < data.len(), "DROPFILES 缺少双 NUL 终止符");
            ensure!(
                data[start..pos].is_ascii(),
                "ANSI 文件列表缺少可验证的代码页，未猜测编码"
            );
            paths.push(String::from_utf8(data[start..pos].to_vec())?);
            pos += 1;
            ensure!(paths.len() <= 4096, "DROPFILES 文件数超过上限");
        }
        ensure!(
            pos < data.len() && data[pos] == 0,
            "DROPFILES 文件列表未终止"
        );
    }
    ensure!(
        !paths.is_empty() && paths.iter().all(|p| !p.chars().any(|c| c.is_control())),
        "DROPFILES 路径无效"
    );
    Ok(
        json!({"paths":paths,"unicode":wide==1,"drop_point":{"x":u32le(b,4)? as i32,"y":u32le(b,8)? as i32},
        "nonclient":u32le(b,12)? != 0,"preferred_drop_effect":null,"operation_completed":null}),
    )
}

pub(super) fn composition_string(b: &[u8]) -> Result<Value> {
    ensure!(
        b.len() >= 100 && b.len() <= 2 * 1024 * 1024,
        "COMPOSITIONSTRING 大小无效"
    );
    ensure!(
        u32le(b, 0)? as usize == b.len(),
        "COMPOSITIONSTRING 声明大小不符"
    );
    let string = |len_offset, pointer_offset| -> Result<String> {
        let n = u32le(b, len_offset)? as usize;
        let offset = u32le(b, pointer_offset)? as usize;
        if n == 0 {
            return Ok(String::new());
        }
        ensure!(
            offset >= 100 && offset.is_multiple_of(2),
            "组合文字范围无效"
        );
        let end = offset
            .checked_add(n.checked_mul(2).context("组合文字长度溢出")?)
            .context("组合文字范围溢出")?;
        utf16(b.get(offset..end).context("组合文字超出对象")?)
    };
    let text = string(44, 48)?;
    let reading = string(20, 24)?;
    let result = string(84, 88)?;
    let result_reading = string(68, 72)?;
    let cursor = u32le(b, 52)?;
    let delta = u32le(b, 56)?;
    ensure!(
        cursor <= u32le(b, 44)? && delta <= u32le(b, 44)?,
        "组合态光标位置无效"
    );
    for (len, off) in [
        (4, 8),
        (12, 16),
        (28, 32),
        (36, 40),
        (60, 64),
        (76, 80),
        (92, 96),
    ] {
        let n = u32le(b, len)? as usize;
        let offset = u32le(b, off)? as usize;
        if n > 0 {
            ensure!(
                offset >= 100 && offset.checked_add(n).is_some_and(|e| e <= b.len()),
                "组合态属性范围越界"
            );
        }
    }
    Ok(
        json!({"composition_text":text,"reading_text":reading,"result_text":result,"result_reading_text":result_reading,
        "cursor_utf16":cursor,"delta_start_utf16":delta,"encoding":"UTF-16LE",
        "semantic":"IMM 组合状态；结果字段不证明目标程序已处理文字"}),
    )
}

/// Firefox's mozLz4 uses an unframed LZ4 block after magic + decoded length.
fn moz_lz4(b: &[u8], budget: usize) -> Result<Vec<u8>> {
    ensure!(b.starts_with(b"mozLz40\0"), "不是 Firefox mozLz4");
    let expected = u32le(b, 8)? as usize;
    ensure!(
        expected > 0 && expected <= budget,
        "mozLz4 解压大小超出预算"
    );
    let mut out = Vec::with_capacity(expected);
    let mut p = 12;
    fn length(b: &[u8], p: &mut usize, initial: usize, max: usize) -> Result<usize> {
        let mut n = initial;
        if initial == 15 {
            loop {
                let v = *b.get(*p).context("LZ4 长度截断")? as usize;
                *p += 1;
                n = n.checked_add(v).context("LZ4 长度溢出")?;
                ensure!(n <= max, "LZ4 长度超预算");
                if v != 255 {
                    break;
                }
            }
        }
        Ok(n)
    }
    while p < b.len() {
        let token = b[p];
        p += 1;
        let literal = length(b, &mut p, (token >> 4) as usize, expected)?;
        ensure!(
            out.len()
                .checked_add(literal)
                .is_some_and(|e| e <= expected),
            "LZ4 字面量超预算"
        );
        out.extend_from_slice(
            b.get(p..p.checked_add(literal).context("LZ4 范围溢出")?)
                .context("LZ4 字面量截断")?,
        );
        p += literal;
        if p == b.len() {
            break;
        }
        let distance = u16le(b, p)? as usize;
        p += 2;
        ensure!(distance > 0 && distance <= out.len(), "LZ4 引用偏移无效");
        let count = length(b, &mut p, (token & 15) as usize, expected)?
            .checked_add(4)
            .context("LZ4 长度溢出")?;
        ensure!(
            out.len().checked_add(count).is_some_and(|e| e <= expected),
            "LZ4 复制超预算"
        );
        for _ in 0..count {
            out.push(out[out.len() - distance]);
        }
    }
    ensure!(out.len() == expected, "mozLz4 解压长度不符");
    Ok(out)
}

pub(super) fn firefox(b: &[u8], budget: usize, limit: usize) -> Result<(Vec<Value>, bool)> {
    let decoded;
    let bytes = if b.starts_with(b"mozLz40\0") {
        decoded = moz_lz4(b, budget)?;
        decoded.as_slice()
    } else {
        b
    };
    ensure!(bytes.len() <= budget, "Firefox 状态超出预算");
    let value: Value = serde_json::from_slice(bytes)?;
    let windows = value
        .get("windows")
        .and_then(Value::as_array)
        .context("没有 Firefox sessionstore windows 数组")?;
    let selected_window = value.get("selectedWindow").and_then(Value::as_u64);
    let mut result = Vec::new();
    for (wi, window) in windows.iter().enumerate() {
        let tabs = window
            .get("tabs")
            .and_then(Value::as_array)
            .context("Firefox window 缺少 tabs")?;
        for (ti, tab) in tabs.iter().enumerate() {
            let entries = tab
                .get("entries")
                .and_then(Value::as_array)
                .context("Firefox tab 缺少 entries")?;
            let selected_entry = tab.get("index").and_then(Value::as_u64);
            for (ni, entry) in entries.iter().enumerate() {
                if result.len() == limit {
                    return Ok((result, false));
                }
                let url = entry
                    .get("url")
                    .and_then(Value::as_str)
                    .context("Firefox 导航项缺少 URL")?;
                result.push(json!({"window_index":wi+1,"tab_index":ti+1,"navigation_index":ni+1,
                    "url":url,"title":entry.get("title"),"selected_navigation":selected_entry.map(|n|n==ni as u64+1),
                    "selected_tab":window.get("selected").and_then(Value::as_u64).map(|n|n==ti as u64+1),
                    "selected_window":selected_window.map(|n|n==wi as u64+1),
                    "tab_formdata":tab.get("formdata"),"entry_formdata":entry.get("formdata"),
                    "semantic":"stored_firefox_session_state_not_live_visibility"}));
            }
        }
    }
    Ok((result, true))
}

struct Pickle<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Pickle<'a> {
    fn new(b: &'a [u8]) -> Result<Self> {
        let n = u32le(b, 0)? as usize;
        ensure!(n.checked_add(4) == Some(b.len()), "Pickle 声明长度不符");
        Ok(Self { b, p: 4 })
    }
    fn int(&mut self) -> Result<i32> {
        let value = u32le(self.b, self.p)? as i32;
        self.p += 4;
        Ok(value)
    }
    fn string(&mut self, wide: bool) -> Result<String> {
        let n = self.int()?;
        ensure!(n >= 0, "Pickle 字符串长度为负");
        let length = (n as usize)
            .checked_mul(if wide { 2 } else { 1 })
            .context("Pickle 长度溢出")?;
        let end = self.p.checked_add(length).context("Pickle 范围溢出")?;
        let b = self.b.get(self.p..end).context("Pickle 字符串截断")?;
        self.p = end.checked_add(3).context("Pickle 对齐溢出")? & !3;
        ensure!(self.p <= self.b.len(), "Pickle padding 截断");
        if wide {
            utf16(b)
        } else {
            Ok(String::from_utf8(b.to_vec())?)
        }
    }
}

pub(super) fn snss(b: &[u8], limit: usize) -> Result<(Vec<Value>, bool)> {
    let version = u32le(b, 4)?;
    ensure!(
        b.starts_with(b"SNSS") && matches!(version, 1 | 3),
        "仅支持明文 SNSS v1/v3；未知或加密版本未解析"
    );
    let mut pos = 8;
    let mut records = Vec::new();
    let mut marker = version == 1;
    while pos < b.len() {
        let length = u16le(b, pos)? as usize;
        ensure!(length >= 1, "SNSS 命令长度无效");
        let end = pos.checked_add(2 + length).context("SNSS 长度溢出")?;
        let command = b.get(pos + 2..end).context("SNSS 命令被截断")?;
        let id = command[0];
        let data = &command[1..];
        let mut fields = match id {
            6 => {
                let mut p = Pickle::new(data)?;
                let tab = p.int()?;
                let index = p.int()?;
                let url = p.string(false)?;
                let title = p.string(true)?;
                // PageState is serialized separately and is not assumed to be text/form data.
                json!({"event":"navigation","tab_id":tab,"navigation_index":index,"url":url,"title":title,
                    "page_state_decoded":false})
            }
            0 | 2 | 7 | 8 if data.len() == 8 => {
                json!({"event":match id {0=>"tab_window",2=>"tab_index",7=>"selected_navigation",_=>"selected_tab"},
                "first_id":u32le(data,0)? as i32,"second_id_or_index":u32le(data,4)? as i32})
            }
            3 | 4 | 16 | 17 if data.len() == 12 || data.len() == 16 => {
                json!({"event":"close_command","id":u32le(data,0)? as i32})
            }
            5 | 11 if data.len() == 8 => {
                json!({"event":"prune_navigation","tab_id":u32le(data,0)? as i32,"index_or_count":u32le(data,4)? as i32})
            }
            24 if data.len() == 12 => {
                json!({"event":"prune_navigation","tab_id":u32le(data,0)? as i32,"index":u32le(data,4)? as i32,"count":u32le(data,8)? as i32})
            }
            20 if data.len() == 4 => {
                json!({"event":"active_window","window_id":u32le(data,0)? as i32})
            }
            255 if version == 3 && data.is_empty() => {
                marker = true;
                json!({"event":"initial_state_marker"})
            }
            _ => json!({"event":"unparsed_command","payload_length":data.len()}),
        };
        if records.len() == limit {
            return Ok((records, false));
        }
        fields["file_offset"] = json!(pos);
        fields["record_length"] = json!(end - pos);
        fields["command_id"] = json!(id);
        fields["semantic"] = json!("stored_session_command_not_current_tab_visibility");
        fields["snss_version"] = json!(version);
        records.push(fields);
        pos = end;
    }
    ensure!(marker, "SNSS v3 缺少初始状态完成标记");
    Ok((records, true))
}

/// Decode common filesystem PIDLs. Unknown shell namespaces stay explicit.
pub(super) fn shell_pidl(b: &[u8], application_prefix: bool) -> Result<Value> {
    ensure!(b.len() <= 64 * 1024, "PIDL 超过预算");
    let mut pos = 0usize;
    let application = if application_prefix {
        let (name, consumed) = wide_z(b)?;
        pos = consumed;
        Some(name)
    } else {
        None
    };
    let mut items = Vec::new();
    let mut parts = Vec::<String>::new();
    let mut complete = true;
    let mut absolute = false;
    loop {
        let size = u16le(b, pos)? as usize;
        if size == 0 {
            pos += 2;
            break;
        }
        ensure!(size >= 3 && items.len() < 256, "PIDL 项大小或数量无效");
        let item = b
            .get(pos..pos.checked_add(size).context("PIDL 长度溢出")?)
            .context("PIDL 项越界")?;
        let class = item[2];
        let mut fields = json!({"offset":pos,"size":size,"class":class});
        if class == 0x1f && size >= 20 {
            fields["kind"] = json!("root_guid");
            fields["guid_le_hex"] = json!(hex::encode(&item[4..20]));
            // My Computer / This PC. Other namespace roots need separate mapping.
            if item[4..20]
                != [
                    0xe0, 0x4f, 0xd0, 0x20, 0xea, 0x3a, 0x69, 0x10, 0xa2, 0xd8, 0x08, 0x00, 0x2b,
                    0x30, 0x30, 0x9d,
                ]
            {
                complete = false;
            }
        } else if class & 0x70 == 0x20 && class & 1 != 0 && size >= 25 {
            let end = item[3..23]
                .iter()
                .position(|v| *v == 0)
                .context("卷名称未终止")?
                + 3;
            let name = std::str::from_utf8(&item[3..end])?;
            fields["kind"] = json!("volume");
            fields["name"] = json!(name);
            if (name.len() == 2 || name.len() == 3 && name.ends_with('\\'))
                && name.as_bytes()[0].is_ascii_alphabetic()
                && name.as_bytes()[1] == b':'
                && !absolute
                && parts.is_empty()
            {
                parts.push(name.trim_end_matches('\\').to_owned());
                absolute = true;
            } else {
                complete = false;
            }
        } else if class & 0x70 == 0x30 && size >= 16 {
            fields["kind"] = json!("file_entry");
            let primary = if class & 4 != 0 {
                wide_z(&item[14..]).ok().map(|v| v.0)
            } else {
                item[14..].iter().position(|v| *v == 0).and_then(|n| {
                    let raw = &item[14..14 + n];
                    raw.is_ascii()
                        .then(|| String::from_utf8_lossy(raw).into_owned())
                })
            };
            fields["primary_name"] = json!(primary);
            let ext_offset = u16le(item, size - 2)? as usize;
            let mut long = None;
            if (14..size - 2).contains(&ext_offset) {
                let ext_size = u16le(item, ext_offset)? as usize;
                if ext_size >= 20 && ext_offset.checked_add(ext_size).is_some_and(|e| e <= size) {
                    let ext = &item[ext_offset..ext_offset + ext_size];
                    if u32le(ext, 4)? == 0xbeef0004 && matches!(u16le(ext, 2)?, 3 | 7 | 8 | 9) {
                        let offset = u16le(ext, 16)? as usize;
                        if offset >= 18 && offset.is_multiple_of(2) {
                            long = ext
                                .get(offset..ext_size - 2)
                                .and_then(|v| wide_z(v).ok())
                                .map(|v| v.0);
                        }
                    }
                }
            }
            fields["long_name"] = json!(long);
            if let Some(name) = long.or(primary).filter(|s| {
                !s.is_empty()
                    && s != "."
                    && s != ".."
                    && !s
                        .chars()
                        .any(|c| c.is_control() || matches!(c, '\\' | '/' | ':'))
            }) {
                parts.push(name);
            } else {
                complete = false;
            }
        } else {
            fields["kind"] = json!("unsupported_shell_item");
            complete = false;
        }
        items.push(fields);
        pos += size;
    }
    if b[pos..].iter().any(|v| *v != 0) {
        complete = false;
    }
    let path = (absolute && complete).then(|| {
        let mut p = parts.join("\\");
        if parts.len() == 1 {
            p.push('\\');
        }
        p
    });
    Ok(
        json!({"application":application,"items":items,"path":path,"path_decoded":path.is_some(),"pidl_complete":complete,
        "trailing_bytes":b.len()-pos,"semantic":"stored_shell_mru_not_current_selection"}),
    )
}

fn wide_z(b: &[u8]) -> Result<(String, usize)> {
    let end = b
        .chunks_exact(2)
        .position(|p| p == [0, 0])
        .context("UTF-16 字符串未终止")?
        * 2;
    Ok((utf16(&b[..end])?, end + 2))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hdrop_unicode_paths_and_truncation() {
        let mut b = vec![0; 20];
        b[..4].copy_from_slice(&20u32.to_le_bytes());
        b[16] = 1;
        for c in "C:\\文档.txt\0D:\\a.txt\0\0".encode_utf16() {
            b.extend_from_slice(&c.to_le_bytes());
        }
        let v = hdrop(&b).unwrap();
        assert_eq!(v["paths"][0], "C:\\文档.txt");
        assert_eq!(v["paths"].as_array().unwrap().len(), 2);
        b.truncate(b.len() - 2);
        assert!(hdrop(&b).is_err());
        b[..4].copy_from_slice(&0xfffffff0u32.to_le_bytes());
        assert!(hdrop(&b).is_err());
    }
    #[test]
    fn composition_checks_ranges_and_cursor() {
        let mut b = vec![0; 104];
        b[..4].copy_from_slice(&104u32.to_le_bytes());
        b[44..48].copy_from_slice(&2u32.to_le_bytes());
        b[48..52].copy_from_slice(&100u32.to_le_bytes());
        b[100..104].copy_from_slice(&[0x2d, 0x4e, 0x87, 0x65]);
        assert_eq!(composition_string(&b).unwrap()["composition_text"], "中文");
        b[52] = 3;
        assert!(composition_string(&b).is_err());
    }
    #[test]
    fn firefox_preserves_navigation_selection_and_formdata() {
        let b=br#"{"windows":[{"selected":1,"tabs":[{"index":2,"entries":[{"url":"https://a"},{"url":"https://b"}],"formdata":{"id":{"draft":"unsent"}}}]}]}"#;
        let (r, c) = firefox(b, 4096, 8).unwrap();
        assert!(c);
        assert_eq!(r[1]["selected_navigation"], true);
        assert_eq!(r[1]["tab_formdata"]["id"]["draft"], "unsent");
        assert!(!firefox(b, 4096, 1).unwrap().1);
    }
    #[test]
    fn moz_lz4_checks_backreferences_and_size() {
        let mut b = b"mozLz40\0".to_vec();
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(b"\x50hello");
        assert_eq!(moz_lz4(&b, 100).unwrap(), b"hello");
        assert!(moz_lz4(&b, 4).is_err());
        b.truncate(12);
        b.extend_from_slice(&[0, 0, 0]);
        assert!(moz_lz4(&b, 100).is_err());
    }
    #[test]
    fn snss_frames_are_bounded_and_version_checked() {
        let mut b = b"SNSS\x01\0\0\0".to_vec();
        b.extend_from_slice(&9u16.to_le_bytes());
        b.push(0);
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes());
        let (r, c) = snss(&b, 4).unwrap();
        assert!(c);
        assert_eq!(r[0]["event"], "tab_window");
        b.pop();
        assert!(snss(&b, 4).is_err());
        b[4] = 5;
        assert!(snss(&b, 4).is_err());
        let mut v3 = b"SNSS\x03\0\0\0".to_vec();
        assert!(snss(&v3, 4).is_err());
        v3.extend_from_slice(&[1, 0, 255]);
        assert_eq!(snss(&v3, 4).unwrap().0[0]["event"], "initial_state_marker");
    }
    #[test]
    fn shell_pidl_decodes_only_valid_filesystem_components() {
        let mut b = vec![0u8; 25];
        b[0] = 25;
        b[2] = 0x2f;
        b[3..6].copy_from_slice(b"C:\\");
        let mut item = vec![0u8; 14];
        item[2] = 0x35;
        for ch in "文档.txt\0".encode_utf16() {
            item.extend_from_slice(&ch.to_le_bytes());
        }
        let length = item.len() as u16;
        item[..2].copy_from_slice(&length.to_le_bytes());
        b.extend_from_slice(&item);
        b.extend_from_slice(&[0, 0]);
        let value = shell_pidl(&b, false).unwrap();
        assert_eq!(value["path"], "C:\\文档.txt");
        b.pop();
        assert!(shell_pidl(&b, false).is_err());
        assert!(shell_pidl(&[255, 255, 0x31], false).is_err());
    }
}
