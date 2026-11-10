use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::output_policy::{OutputPolicy, OutputTarget};

const SECTION_COLUMN: &str = "数据区段";
const ROW_COLUMN: &str = "行号";
const SUMMARY_SECTION: &str = "摘要";
const RECORD_SECTION: &str = "记录";
const EVIDENCE_METADATA_SECTION: &str = "Evidence 元数据";

#[derive(Debug)]
struct CsvRow {
    section: String,
    row_number: usize,
    cells: BTreeMap<String, String>,
}

pub fn write_csv_report_path(path: &Path, value: &impl Serialize) -> Result<()> {
    write_csv_report_path_with_force(path, value, false)
}

/// Write a CSV report through the shared output policy.
///
/// The compatibility entry point above deliberately defaults to no overwrite.  CLI callers
/// which expose the common `--force` switch may opt in here, but even forced publication still
/// cannot replace a path registered as an evidence input by their command-level policy.
pub fn write_csv_report_path_with_force(
    path: &Path,
    value: &impl Serialize,
    force: bool,
) -> Result<()> {
    if path == Path::new("-") {
        return write_csv_report(std::io::stdout().lock(), value);
    }
    let mut policy = OutputPolicy::new(force);
    policy.output(OutputTarget::file("csv_report", path));
    policy.preflight()?;
    policy.write_file_atomic(path, |file| write_csv_report(BufWriter::new(file), value))
}

pub fn write_csv_report<W: Write>(mut output: W, value: &impl Serialize) -> Result<()> {
    let value = serde_json::to_value(value).context("无法将报告转换为 CSV 中间结构")?;
    let rows = report_rows(&value);
    let mut columns = BTreeSet::new();
    for row in &rows {
        columns.extend(row.cells.keys().cloned());
    }
    let columns = columns.into_iter().collect::<Vec<_>>();

    output.write_all(b"\xef\xbb\xbf")?;
    let mut writer = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_writer(output);
    let mut header = vec![SECTION_COLUMN.to_owned(), ROW_COLUMN.to_owned()];
    header.extend(columns.iter().cloned());
    writer.write_record(header)?;
    for row in rows {
        let mut record = vec![row.section, row.row_number.to_string()];
        record.extend(
            columns
                .iter()
                .map(|column| row.cells.get(column).cloned().unwrap_or_default()),
        );
        writer.write_record(record)?;
    }
    writer.flush()?;
    Ok(())
}

fn report_rows(value: &Value) -> Vec<CsvRow> {
    match value {
        Value::Object(object)
            if object
                .get("schema_version")
                .and_then(Value::as_u64)
                .is_some()
                && object.contains_key("data") =>
        {
            envelope_report_rows(object)
        }
        Value::Object(object) => object_report_rows(object),
        Value::Array(items) => array_rows(RECORD_SECTION, items),
        value => vec![CsvRow {
            section: SUMMARY_SECTION.to_owned(),
            row_number: 1,
            cells: BTreeMap::from([("值".to_owned(), scalar_cell(value))]),
        }],
    }
}

fn envelope_report_rows(object: &Map<String, Value>) -> Vec<CsvRow> {
    let mut metadata = BTreeMap::new();
    for key in [
        "schema_version",
        "command",
        "engine_identity",
        "source_identity",
        "available",
        "complete",
        "scope",
        "raw_evidence",
    ] {
        if let Some(value) = object.get(key) {
            flatten_value(key, value, &mut metadata);
        }
    }
    let mut rows = vec![CsvRow {
        section: EVIDENCE_METADATA_SECTION.to_owned(),
        row_number: 1,
        cells: metadata,
    }];
    for (key, label) in [
        ("warnings", "Evidence 警告"),
        ("limits", "Evidence 限制"),
        ("missing_ranges", "Evidence 缺失区间"),
    ] {
        if let Some(items) = object.get(key).and_then(Value::as_array) {
            rows.extend(array_rows(label, items));
        }
    }
    if let Some(data) = object.get("data") {
        rows.extend(report_rows(data));
    }
    rows
}

fn object_report_rows(object: &Map<String, Value>) -> Vec<CsvRow> {
    let mut summary = BTreeMap::new();
    let mut sections = Vec::new();
    for (key, value) in object {
        if let Value::Array(items) = value {
            summary.insert(format!("{key}.数量"), items.len().to_string());
            sections.extend(array_rows(key, items));
        } else {
            flatten_value(key, value, &mut summary);
        }
    }
    let mut rows = Vec::new();
    if !summary.is_empty() || sections.is_empty() {
        rows.push(CsvRow {
            section: SUMMARY_SECTION.to_owned(),
            row_number: 1,
            cells: summary,
        });
    }
    rows.extend(sections);
    rows
}

fn array_rows(section: &str, items: &[Value]) -> Vec<CsvRow> {
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let mut cells = BTreeMap::new();
            match item {
                Value::Object(object) => {
                    for (key, value) in object {
                        flatten_value(key, value, &mut cells);
                    }
                }
                value => {
                    cells.insert("值".to_owned(), scalar_cell(value));
                }
            }
            CsvRow {
                section: section.to_owned(),
                row_number: index + 1,
                cells,
            }
        })
        .collect()
}

fn flatten_value(prefix: &str, value: &Value, output: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(object) => {
            if object.is_empty() {
                output.insert(prefix.to_owned(), "{}".to_owned());
            } else {
                for (key, value) in object {
                    flatten_value(&format!("{prefix}.{key}"), value, output);
                }
            }
        }
        Value::Array(_) => {
            output.insert(
                prefix.to_owned(),
                serde_json::to_string(value).unwrap_or_default(),
            );
        }
        value => {
            output.insert(prefix.to_owned(), scalar_cell(value));
        }
    }
}

fn scalar_cell(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => {
            if matches!(
                value.chars().next(),
                Some('=' | '+' | '-' | '@' | '\t' | '\r' | '\n')
            ) {
                format!("'{value}")
            } else {
                value.clone()
            }
        }
        value => serde_json::to_string(value).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_csv(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "starmem-csv-{name}-{}-{nonce}.csv",
            std::process::id()
        ))
    }

    fn rows(output: &[u8]) -> Vec<csv::StringRecord> {
        assert!(output.starts_with(b"\xef\xbb\xbf"));
        csv::Reader::from_reader(&output[3..])
            .records()
            .map(|record| record.unwrap())
            .collect()
    }

    #[test]
    fn writes_single_table_with_summary_and_nested_evidence() {
        let report = json!({
            "records": [{
                "pid": 42,
                "name": "浏览器.exe",
                "owners": [{"pid": 42, "address": 4096}]
            }],
            "complete": true,
            "warnings": []
        });
        let mut output = Vec::new();
        write_csv_report(&mut output, &report).unwrap();
        let text = String::from_utf8(output.clone()).unwrap();
        assert!(text.contains("数据区段,行号"));
        assert!(text.contains("records"));
        assert!(text.contains("浏览器.exe"));
        let mut reader = csv::Reader::from_reader(&output[3..]);
        let headers = reader.headers().unwrap().clone();
        let records = reader
            .records()
            .map(|record| record.unwrap())
            .collect::<Vec<_>>();
        let owners = headers
            .iter()
            .position(|header| header == "owners")
            .unwrap();
        let owners: Value = serde_json::from_str(records[1].get(owners).unwrap()).unwrap();
        assert_eq!(owners, json!([{"address": 4096, "pid": 42}]));
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn keeps_every_top_level_table_in_one_csv() {
        let report = json!({
            "sessions": [{"browser": "Edge", "pid": 100}],
            "cookies": [{"domain": "example.test", "name": "sid"}],
            "downloads": [{"url": "https://example.test/a.exe"}],
            "timing": {"total_seconds": 1.25}
        });
        let mut output = Vec::new();
        write_csv_report(&mut output, &report).unwrap();
        let records = rows(&output);
        assert_eq!(records.len(), 4);
        let sections = records
            .iter()
            .map(|record| record.get(0).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(sections, ["摘要", "sessions", "cookies", "downloads"]);
    }

    #[test]
    fn keeps_safe_scalar_strings_unchanged() {
        assert_eq!(scalar_cell(&json!("普通中文")), "普通中文");
        assert_eq!(scalar_cell(&json!("")), "");
    }

    #[test]
    fn prefixes_formula_like_scalar_strings_with_an_apostrophe() {
        for dangerous in [
            "=1+1",
            "+SUM(A1:A2)",
            "-1+2",
            "@SUM(A1:A2)",
            "\t=1+1",
            "\r=1+1",
            "\n=1+1",
        ] {
            assert_eq!(scalar_cell(&json!(dangerous)), format!("'{dangerous}"));
        }
    }

    #[test]
    fn envelope_keeps_metadata_and_plugin_tables_separate() {
        let envelope = json!({
            "schema_version": 1,
            "command": "windows.pslist",
            "engine_identity": {"version": "0.2.0", "build_id": "abc", "integration_api_version": 3},
            "source_identity": {"format": "raw", "size": 1, "mtime": null,
                "sample_digest": {"algorithm": "test", "value": "00"}, "symbol_identity": null},
            "available": true,
            "complete": false,
            "scope": {"kind": "active_process_list", "description": null, "constraints": {}},
            "warnings": [{"code": "head_blink_mismatch"}],
            "limits": [],
            "missing_ranges": [],
            "raw_evidence": {"count": 0, "storage": "none", "references": []},
            "data": {"processes": [{"pid": 4}], "complete": false}
        });
        let mut output = Vec::new();
        write_csv_report(&mut output, &envelope).unwrap();
        let records = rows(&output);
        let sections = records
            .iter()
            .map(|record| record.get(0).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            sections,
            ["Evidence 元数据", "Evidence 警告", "摘要", "processes"]
        );
    }

    #[test]
    fn path_writer_refuses_overwrite_without_force() {
        let path = temporary_csv("refuse-overwrite");
        fs::write(&path, b"existing evidence").unwrap();

        let error = write_csv_report_path(&path, &json!({"records": []})).unwrap_err();

        assert!(error.to_string().contains("已存在"));
        assert_eq!(fs::read(&path).unwrap(), b"existing evidence");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn forced_path_writer_publishes_valid_csv() {
        let path = temporary_csv("forced-overwrite");
        fs::write(&path, b"old").unwrap();

        write_csv_report_path_with_force(&path, &json!({"records": [{"pid": 4}]}), true).unwrap();

        let bytes = fs::read(&path).unwrap();
        assert!(bytes.starts_with(b"\xef\xbb\xbf"));
        assert!(String::from_utf8_lossy(&bytes).contains("pid"));
        fs::remove_file(path).unwrap();
    }
}
