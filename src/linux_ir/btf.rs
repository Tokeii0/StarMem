//! Decode resident vmlinux BTF types without treating type metadata as runtime objects.
//! Encoding reference: https://docs.kernel.org/bpf/btf.html
use super::*;
mod reader;
use reader::Reader;

const RECORD_BYTES: usize = 2 * 1024 * 1024;
const OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const KINDS: [&str; 20] = [
    "UNKNOWN",
    "INT",
    "PTR",
    "ARRAY",
    "STRUCT",
    "UNION",
    "ENUM",
    "FWD",
    "TYPEDEF",
    "VOLATILE",
    "CONST",
    "RESTRICT",
    "FUNC",
    "FUNC_PROTO",
    "VAR",
    "DATASEC",
    "FLOAT",
    "DECL_TAG",
    "TYPE_TAG",
    "ENUM64",
];

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded BTF field"))
}

fn payload_size(kind: u32, count: u32, flag: bool) -> Result<u64> {
    ensure!(
        (1..=19).contains(&kind),
        "不支持的 BTF 类型 kind={kind}，不能继续分配后续类型编号"
    );
    ensure!(
        !flag || matches!(kind, 4..=7 | 17..=19),
        "此 BTF kind 不支持 kind_flag"
    );
    match kind {
        4 | 5 | 15 | 19 => Ok(count as u64 * 12),
        6 | 13 => Ok(count as u64 * 8),
        12 => {
            ensure!(count <= 2, "BTF 函数 linkage 无效");
            Ok(0)
        }
        _ => {
            ensure!(count == 0, "此 BTF kind 的 vlen 必须为零");
            Ok(match kind {
                1 | 14 | 17 => 4,
                3 => 12,
                _ => 0,
            })
        }
    }
}

fn named<M: LinuxKernelMemory>(
    reader: &mut Reader<'_, M>,
    strings: (u64, u64),
    offset: u32,
    report: &mut LinuxIrReport,
) -> Result<Value> {
    match reader.name(strings.0, strings.1, offset) {
        Ok(name) => Ok(json!({"name":name,"name_offset":offset})),
        Err(error) => {
            if crate::cancellation::is_cancellation_error(&error) {
                return Err(error);
            }
            report.warn(format!("BTF 名称 {offset:#x} 未完整解码：{error:#}"));
            Ok(json!({"name":Value::Null,"name_offset":offset,"name_error":format!("{error:#}")}))
        }
    }
}

fn decode<M: LinuxKernelMemory>(
    reader: &mut Reader<'_, M>,
    offset: u64,
    type_end: u64,
    strings: (u64, u64),
    id: u32,
    report: &mut LinuxIrReport,
) -> Result<(Value, u64)> {
    ensure!(add(offset, 12)? <= type_end, "BTF 类型头越过类型区段结尾");
    let header = reader.read(offset, 12)?;
    let info = word(&header, 4);
    let kind = (info >> 24) & 0x7f;
    let count = info & 0x00ff_ffff;
    let flag = info >> 31 != 0;
    let value = word(&header, 8);
    let extra = payload_size(kind, count, flag)?;
    let next = add(add(offset, 12)?, extra)?;
    ensure!(next <= type_end, "BTF 类型成员越过类型区段结尾");
    let mut row = named(reader, strings, word(&header, 0), report)?;
    row["record_kind"] = json!("btf_type");
    row["type_id"] = json!(id);
    row["type_kind"] = json!(KINDS[kind as usize]);
    row["kind_flag"] = json!(flag);
    row["btf_offset"] = json!(offset);
    row["btf_address"] = json!(add(reader.start, offset)?);
    row["encoded_bytes"] = json!(next - offset);
    row["details_complete"] = json!(true);
    // Reserve the longest final status before applying the serialized output budget.
    row["reference_id_status"] = json!("outside_decoded_prefix");
    if matches!(kind, 1 | 4..=6 | 15 | 16 | 19) {
        row["size_bytes"] = json!(value);
    }
    if matches!(kind, 2 | 8..=14 | 17 | 18) {
        row["target_type_id"] = json!(value);
    }
    match kind {
        1 => {
            let encoding = word(&reader.read(offset + 12, 4)?, 0);
            let bits = encoding & 0xff;
            let bit_offset = (encoding >> 16) & 0xff;
            ensure!(
                encoding & !0x07ff_00ff == 0
                    && bits > 0
                    && bits <= 128
                    && matches!(value, 1 | 2 | 4 | 8 | 16)
                    && bit_offset + bits <= value * 8,
                "BTF 整数编码无效"
            );
            row["bits"] = json!(bits);
            row["bit_offset"] = json!(bit_offset);
            row["signed"] = json!(encoding & (1 << 24) != 0);
            row["char"] = json!(encoding & (1 << 25) != 0);
            row["bool"] = json!(encoding & (1 << 26) != 0);
        }
        3 => {
            let array = reader.read(offset + 12, 12)?;
            row["target_type_id"] = json!(word(&array, 0));
            row["index_type_id"] = json!(word(&array, 4));
            row["element_count"] = json!(word(&array, 8));
        }
        7 => row["forward_kind"] = json!(if flag { "union" } else { "struct" }),
        12 => row["linkage"] = json!(count),
        14 => {
            let linkage = word(&reader.read(offset + 12, 4)?, 0);
            ensure!(linkage <= 2, "BTF 变量 linkage 无效");
            row["linkage"] = json!(linkage);
        }
        16 => ensure!(matches!(value, 2 | 4 | 8 | 12 | 16), "BTF 浮点大小无效"),
        17 => row["component_index"] = json!(word(&reader.read(offset + 12, 4)?, 0) as i32),
        _ => {}
    }
    if matches!(kind, 6 | 19) {
        ensure!(matches!(value, 1 | 2 | 4 | 8), "BTF 枚举大小无效");
    }
    if matches!(kind, 4..=6 | 13 | 15 | 19) {
        let (key, width) = match kind {
            4 | 5 => ("members", 12),
            6 => ("values", 8),
            13 => ("parameters", 8),
            15 => ("variables", 12),
            _ => ("values", 12),
        };
        let mut parts = Vec::new();
        let mut size = row.to_string().len() + 4096;
        for index in 0..count {
            let at = offset + 12 + index as u64 * width;
            let raw = match reader.read(at, width as usize) {
                Ok(raw) => raw,
                Err(error) => {
                    if crate::cancellation::is_cancellation_error(&error) {
                        return Err(error);
                    }
                    row["details_error"] = json!(format!("成员 {index}：{error:#}"));
                    break;
                }
            };
            let mut part = if kind == 15 {
                json!({})
            } else {
                named(reader, strings, word(&raw, 0), report)?
            };
            part["index"] = json!(index);
            if matches!(kind, 4 | 5 | 13) {
                part["target_type_id"] = json!(word(&raw, 4));
            }
            match kind {
                4 | 5 => {
                    let encoded = word(&raw, 8);
                    part["bit_offset"] = json!(if flag { encoded & 0x00ff_ffff } else { encoded });
                    // Legacy bitfields keep their width in the referenced INT type.
                    part["bitfield_size"] = if flag {
                        json!(encoded >> 24)
                    } else {
                        Value::Null
                    };
                }
                6 => {
                    let bits = word(&raw, 4);
                    part["value_bits"] = json!(bits);
                    part["signed_value"] = json!(bits as i32);
                    part["unsigned_value"] = json!(bits);
                    row["signedness"] = json!(if flag {
                        "signed"
                    } else {
                        "unsigned_or_legacy_unspecified"
                    });
                }
                13 => {
                    part["variadic"] =
                        json!(index + 1 == count && word(&raw, 0) == 0 && word(&raw, 4) == 0)
                }
                15 => {
                    part["target_type_id"] = json!(word(&raw, 0));
                    part["section_offset"] = json!(word(&raw, 4));
                    part["size_bytes"] = json!(word(&raw, 8));
                }
                19 => {
                    let bits = word(&raw, 4) as u64 | ((word(&raw, 8) as u64) << 32);
                    part["value"] = if flag {
                        json!(bits as i64)
                    } else {
                        json!(bits)
                    };
                    row["signed"] = json!(flag);
                }
                _ => {}
            }
            size += part.to_string().len() + 1;
            if size > RECORD_BYTES {
                row["details_error"] = json!("单个 BTF 类型的成员正文超过 2 MiB 输出上限");
                break;
            }
            parts.push(part);
        }
        let complete = parts.len() == count as usize;
        row["details_complete"] = json!(complete);
        row["details_count"] = json!(count);
        row["details_returned"] = json!(parts.len());
        row[key] = json!(parts);
        if !complete {
            report.warn(format!("BTF 类型 {id} 的 {key} 仅解码了部分成员"));
        }
    }
    Ok((row, next))
}

fn reference_ids(row: &Value) -> Vec<u64> {
    let mut ids = ["target_type_id", "index_type_id"]
        .iter()
        .filter_map(|key| row[*key].as_u64())
        .collect::<Vec<_>>();
    for key in ["members", "parameters", "variables"] {
        if let Some(parts) = row[key].as_array() {
            ids.extend(
                parts
                    .iter()
                    .filter_map(|part| part["target_type_id"].as_u64()),
            );
        }
    }
    ids
}

pub(super) fn analyze(
    m: &impl LinuxKernelMemory,
    options: &LinuxIrOptions,
    cancel: &CancellationToken,
    report: &mut LinuxIrReport,
) -> Result<()> {
    let start = m.runtime_symbol("__start_BTF")?;
    let total = m
        .runtime_symbol("__stop_BTF")?
        .checked_sub(start)
        .context("BTF 范围反向")?;
    ensure!(
        (24..=256 * 1024 * 1024).contains(&total),
        "BTF 范围超过校验上限"
    );
    let mut reader = Reader::new(m, cancel, start, total, options.max_bytes);
    let mut header = super::system::btf_header(&reader.read(0, 24)?, total)?;
    header["record_kind"] = json!("btf_header");
    header["address"] = json!(start);
    header["interpretation"] = json!(
        "vmlinux BTF 类型编码与引用编号；不代表运行时对象，不生成 ISF，不执行内核验证器的语义检查"
    );
    header["output_budget_bytes"] = json!(OUTPUT_BYTES);
    report.push(header.clone());
    let strings = (
        header["string_offset"].as_u64().context("BTF 字符串偏移")?,
        header["string_bytes"].as_u64().context("BTF 字符串长度")?,
    );
    let begin = header["type_offset"].as_u64().context("BTF 类型偏移")?;
    let end = add(
        begin,
        header["type_bytes"].as_u64().context("BTF 类型长度")?,
    )?;
    let mut cursor = begin;
    let mut output_size = header.to_string().len() + 4096;
    let decoded = (|| -> Result<()> {
        // Extended layouts can redefine payload sizes; do not silently use the legacy layout.
        ensure!(
            header["header_size"] == 24,
            "BTF 扩展头部尚未支持类型布局解析，已保留头部"
        );
        ensure!(
            reader.read(strings.0, 1)? == [0],
            "BTF 字符串表未以 NUL 起始"
        );
        while cursor < end {
            cancel.check_cancelled()?;
            if report.records.len() >= report.limit {
                report.limit_reached = true;
                report.warn("BTF 类型记录达到本次记录上限");
                break;
            }
            let id = report.records.len() as u32;
            match decode(&mut reader, cursor, end, strings, id, report) {
                Ok((row, next)) => {
                    output_size += row.to_string().len() + 1;
                    if output_size > OUTPUT_BYTES {
                        report.warn("BTF 类型正文超过 64 MiB 输出上限");
                        break;
                    }
                    report.push(row);
                    cursor = next;
                }
                Err(error) => {
                    if crate::cancellation::is_cancellation_error(&error) {
                        return Err(error);
                    }
                    report.warn(format!(
                        "BTF 类型 {id}（偏移 {cursor:#x}）无法解码：{error:#}"
                    ));
                    break;
                }
            }
        }
        Ok(())
    })();
    let full = decoded.is_ok() && cursor == end;
    if let Err(error) = decoded {
        if crate::cancellation::is_cancellation_error(&error) {
            return Err(error);
        }
        report.warn(format!("BTF 类型解析未完成：{error:#}"));
    }
    let count = report.records.len() - 1;
    let mut invalid = 0;
    for row in report.records.iter_mut().skip(1) {
        cancel.check_cancelled()?;
        let outside = reference_ids(row).iter().any(|id| *id > count as u64);
        row["reference_id_status"] = json!(if !outside {
            "within_decoded_table"
        } else if full {
            invalid += 1;
            "invalid_type_id"
        } else {
            "outside_decoded_prefix"
        });
    }
    if invalid > 0 {
        report.warn(format!("{invalid} 个 BTF 类型含超出完整类型表的引用编号"));
    }
    let row = &mut report.records[0];
    row["type_headers_complete"] = json!(full);
    row["types_returned"] = json!(count);
    row["next_type_offset"] = if full { Value::Null } else { json!(cursor) };
    row["checked_prefix_bytes"] = json!(reader.checked_prefix());
    row["checked_bytes"] = json!(reader.checked);
    row["attempted_bytes"] = json!(reader.attempted);
    row["read_budget_bytes"] = json!(options.max_bytes);
    row["missing_range_count"] = json!(reader.missing_count);
    report.missing_ranges = reader.missing;
    report.scope = "精确 ISF 定位的 __start_BTF 至 __stop_BTF；小端 vmlinux BTF 24 字节头部，类型编号从 1 开始，0 为 void；引用仅核对编号范围，未解析模块 split BTF 或 BTF.ext".into();
    Ok(())
}
