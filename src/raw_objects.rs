//! Deterministic raw-object snapshots and aggregate-to-source relationships.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::evidence::{
    DigestReference, MissingRange, RawEvidenceReference, RawEvidenceStorage, RawEvidenceSummary,
    SourceIdentity,
};
use crate::output_policy::{OutputPolicy, OutputTarget};

pub const RAW_OBJECT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawObjectValidation {
    pub valid: Option<bool>,
    pub method: String,
    #[serde(default)]
    pub checks: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawObjectProvenance {
    pub source: String,
    pub locator: Option<String>,
    pub relation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawObject {
    pub schema_version: u32,
    pub evidence_id: String,
    pub plugin_id: String,
    pub object_type: String,
    pub address_space: String,
    /// Fixed-width hexadecimal representation used for exact JSON/SQLite joins.
    pub address: String,
    pub semantic_key: String,
    pub fields: Value,
    pub validation: RawObjectValidation,
    #[serde(default)]
    pub provenance: Vec<RawObjectProvenance>,
    #[serde(default)]
    pub missing_ranges: Vec<MissingRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateEvidence {
    pub plugin_id: String,
    pub aggregate_type: String,
    pub aggregate_key: String,
    pub source_evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RawObjectBundle {
    pub objects: Vec<RawObject>,
    pub aggregates: Vec<AggregateEvidence>,
}

impl RawObjectBundle {
    pub fn normalize(&mut self) {
        for object in &mut self.objects {
            object.fields = canonical_value(&object.fields);
            object.provenance.sort_by(|left, right| {
                left.source
                    .cmp(&right.source)
                    .then_with(|| left.locator.cmp(&right.locator))
                    .then_with(|| left.relation.cmp(&right.relation))
            });
            object.provenance.dedup();
            object.missing_ranges.sort_by(|left, right| {
                left.address_space
                    .cmp(&right.address_space)
                    .then_with(|| left.start.cmp(&right.start))
                    .then_with(|| left.length.cmp(&right.length))
                    .then_with(|| left.source.cmp(&right.source))
            });
            object.missing_ranges.dedup();
        }
        self.objects
            .sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        self.objects
            .dedup_by(|left, right| left.evidence_id == right.evidence_id);
        let object_ids = self
            .objects
            .iter()
            .map(|object| object.evidence_id.clone())
            .collect::<BTreeSet<_>>();
        for aggregate in &mut self.aggregates {
            aggregate
                .source_evidence_ids
                .retain(|evidence_id| object_ids.contains(evidence_id));
            aggregate.source_evidence_ids.sort();
            aggregate.source_evidence_ids.dedup();
        }
        self.aggregates
            .retain(|aggregate| !aggregate.source_evidence_ids.is_empty());
        self.aggregates.sort_by(|left, right| {
            left.aggregate_type
                .cmp(&right.aggregate_type)
                .then_with(|| left.aggregate_key.cmp(&right.aggregate_key))
        });
        self.aggregates.dedup_by(|left, right| {
            left.aggregate_type == right.aggregate_type
                && left.aggregate_key == right.aggregate_key
                && left.source_evidence_ids == right.source_evidence_ids
        });
    }
}

pub fn evidence_id(
    source_identity: &SourceIdentity,
    plugin_id: &str,
    object_type: &str,
    address: u64,
    semantic_key: &str,
) -> Result<String> {
    ensure!(!plugin_id.trim().is_empty(), "plugin_id 不能为空");
    ensure!(!object_type.trim().is_empty(), "object_type 不能为空");
    let canonical = serde_json::to_vec(&serde_json::json!({
        "source_identity": source_identity,
        "plugin_id": plugin_id,
        "object_type": object_type,
        "address": format!("0x{address:016x}"),
        "semantic_key": semantic_key,
    }))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

/// Extract decoded source objects without promoting report/aggregate objects to raw evidence.
///
/// Known plugins use field-aware adapters. Unknown plugins use a deliberately conservative
/// fallback which only retains records carrying an explicit memory-object address. In
/// particular, a report root or aggregate record without an address never becomes an
/// `address=0` pseudo object.
pub fn extract_raw_objects(
    plugin_id: &str,
    source_identity: &SourceIdentity,
    report: &Value,
) -> Result<RawObjectBundle> {
    let data = report.get("data").unwrap_or(report);
    let mut adapter = RawObjectAdapter::new(plugin_id, source_identity, data);
    match plugin_id {
        "windows.execution" => adapt_windows_execution(&mut adapter, data)?,
        "windows.timeline" => adapt_windows_timeline(&mut adapter, data)?,
        "usb-history" => adapt_usb_history(&mut adapter, data)?,
        "windows.recent-files" => adapt_windows_recent_files(&mut adapter, data)?,
        "browser-session" => adapt_browser_session(&mut adapter, data)?,
        "clipboardscan" => adapt_clipboard_history(&mut adapter, data)?,
        "windows.process-string" => adapt_windows_process_string(&mut adapter, data)?,
        "linux.lsmod" => adapt_linux_lsmod(&mut adapter, data)?,
        "linux.module-extract" => adapt_linux_module_extract(&mut adapter, data)?,
        "linux.mountinfo" => adapt_linux_mountinfo(&mut adapter, data)?,
        "linux.kallsyms" => adapt_linux_kallsyms(&mut adapter, data)?,
        "linux.kmsg" => {
            // The decoded kmsg record currently exposes sequence/time/text, but not its ring
            // record address. Do not disguise the decoded log line as a source object.
        }
        "linux.modxview" => adapt_linux_modxview(&mut adapter, data)?,
        "linux.check-syscall" => adapt_linux_check_syscall(&mut adapter, data)?,
        _ => {
            conservative_walk(&mut adapter, data, "data")?;
        }
    }
    Ok(adapter.finish())
}

struct RawObjectAdapter<'a> {
    plugin_id: &'a str,
    source_identity: &'a SourceIdentity,
    report_available: Option<bool>,
    report_complete: Option<bool>,
    report_missing_ranges: Vec<MissingRange>,
    objects: BTreeMap<String, RawObject>,
    aggregates: Vec<AggregateEvidence>,
}

fn adapt_clipboard_history(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    if let Some(formats) = data.get("formats") {
        conservative_walk(adapter, formats, "data.formats")?;
    }
    for (index, record) in data
        .get("history")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(address) = record.get("item_address").and_then(json_u64) else {
            continue;
        };
        let Some(pid) = record.get("pid").and_then(json_u64) else {
            continue;
        };
        let Some(eprocess) = record.get("eprocess").and_then(json_u64) else {
            continue;
        };
        let semantic_key = selected_key(
            record,
            "clipboard_history_item",
            &["pid", "eprocess", "item_index", "item_id"],
        )?;
        let mut checks = BTreeMap::new();
        for key in ["layout", "pdb_key", "text_status", "text_error"] {
            if let Some(value) = record.get(key) {
                checks.insert(key.to_owned(), value.clone());
            }
        }
        if let Some(id) = adapter.insert(RawObjectSpec {
            object_type: "windows.clipboard_history_item".to_owned(),
            address_space: format!("process_virtual:pid={pid}:eprocess={eprocess:#x}"),
            address,
            semantic_key: semantic_key.clone(),
            fields: canonical_value(record),
            // The item chain is validated even when its text pages are absent. Text has its own status.
            valid: (record.get("evidence_kind").and_then(Value::as_str)
                == Some("textinputhost_clipboard_history"))
            .then_some(true),
            validation_method: "textinputhost_clipboard_chain_v1".to_owned(),
            validation_checks: checks,
            provenance_source: "TextInputHost ClipboardControl.Model.ClipboardItems".to_owned(),
            locator: format!("data.history[{index}]"),
            relation: "member_of_validated_clipboard_vector".to_owned(),
            missing_ranges: Vec::new(),
        })? {
            adapter.aggregate("clipboard.history_item", semantic_key, vec![id]);
        }
    }
    Ok(())
}

struct RawObjectSpec {
    object_type: String,
    address_space: String,
    address: u64,
    semantic_key: String,
    fields: Value,
    valid: Option<bool>,
    validation_method: String,
    validation_checks: BTreeMap<String, Value>,
    provenance_source: String,
    locator: String,
    relation: String,
    missing_ranges: Vec<MissingRange>,
}

impl<'a> RawObjectAdapter<'a> {
    fn new(plugin_id: &'a str, source_identity: &'a SourceIdentity, data: &Value) -> Self {
        Self {
            plugin_id,
            source_identity,
            report_available: data.get("available").and_then(Value::as_bool),
            report_complete: data.get("complete").and_then(Value::as_bool),
            report_missing_ranges: data
                .get("missing_ranges")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok())
                .unwrap_or_default(),
            objects: BTreeMap::new(),
            aggregates: Vec::new(),
        }
    }

    fn insert(&mut self, mut spec: RawObjectSpec) -> Result<Option<String>> {
        // Null kernel pointers and sentinel zero values are not independently locatable raw
        // evidence. This is also the final guard against the old semantic-address adapter.
        if spec.address == 0 {
            return Ok(None);
        }
        spec.semantic_key = format!("{}|address_space={}", spec.semantic_key, spec.address_space);
        spec.validation_checks.insert(
            "report_available".to_owned(),
            self.report_available.map_or(Value::Null, Value::Bool),
        );
        spec.validation_checks.insert(
            "report_complete".to_owned(),
            self.report_complete.map_or(Value::Null, Value::Bool),
        );
        spec.missing_ranges
            .extend(self.report_missing_ranges.iter().cloned());
        let id = evidence_id(
            self.source_identity,
            self.plugin_id,
            &spec.object_type,
            spec.address,
            &spec.semantic_key,
        )?;
        let candidate = RawObject {
            schema_version: RAW_OBJECT_SCHEMA_VERSION,
            evidence_id: id.clone(),
            plugin_id: self.plugin_id.to_owned(),
            object_type: spec.object_type,
            address_space: spec.address_space,
            address: format!("0x{:016x}", spec.address),
            semantic_key: spec.semantic_key,
            fields: canonical_value(&spec.fields),
            validation: RawObjectValidation {
                valid: spec.valid,
                method: spec.validation_method,
                checks: spec.validation_checks,
            },
            provenance: vec![RawObjectProvenance {
                source: spec.provenance_source,
                locator: Some(spec.locator),
                relation: spec.relation,
            }],
            missing_ranges: spec.missing_ranges,
        };
        match self.objects.entry(id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let existing = entry.get_mut();
                existing.provenance.extend(candidate.provenance);
                existing.missing_ranges.extend(candidate.missing_ranges);
                for (key, value) in candidate.validation.checks {
                    existing.validation.checks.entry(key).or_insert(value);
                }
                existing.validation.valid =
                    merge_validity(existing.validation.valid, candidate.validation.valid);
                // Multiple aggregates can point to the same source object. Retain a deterministic
                // decoded snapshot regardless of input record order.
                if compact_value(&candidate.fields) < compact_value(&existing.fields) {
                    existing.fields = candidate.fields;
                }
            }
        }
        Ok(Some(id))
    }

    fn aggregate(&mut self, aggregate_type: &str, aggregate_key: String, ids: Vec<String>) {
        if !ids.is_empty() {
            self.aggregates.push(AggregateEvidence {
                plugin_id: self.plugin_id.to_owned(),
                aggregate_type: aggregate_type.to_owned(),
                aggregate_key,
                source_evidence_ids: ids,
            });
        }
    }

    fn finish(self) -> RawObjectBundle {
        let mut bundle = RawObjectBundle {
            objects: self.objects.into_values().collect(),
            aggregates: self.aggregates,
        };
        bundle.normalize();
        bundle
    }
}

fn merge_validity(left: Option<bool>, right: Option<bool>) -> Option<bool> {
    match (left, right) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), Some(true)) => Some(true),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn adapt_windows_execution(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    if let Some(events) = data.get("events").and_then(Value::as_array) {
        for event in events {
            let ids = execution_record_objects(adapter, event, "events")?;
            adapter.aggregate(
                "windows.execution.event",
                stable_record_key(event, "execution_event")?,
                ids,
            );
        }
    }
    if let Some(episodes) = data.get("episodes").and_then(Value::as_array) {
        for episode in episodes {
            let mut ids = Vec::new();
            if let Some(evidence) = episode.get("evidence").and_then(Value::as_array) {
                for record in evidence {
                    ids.extend(execution_record_objects(
                        adapter,
                        record,
                        "episodes.evidence",
                    )?);
                }
            }
            adapter.aggregate(
                "windows.execution.episode",
                selected_key(
                    episode,
                    "execution_episode",
                    &["program_key", "canonical_timestamp", "pid", "user_sid"],
                )?,
                ids,
            );
        }
    }
    Ok(())
}

fn adapt_windows_process_string(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    let Some(records) = data.get("records").and_then(Value::as_array) else {
        return Ok(());
    };
    for record in records {
        let mut ids = Vec::new();
        if let Some(eprocess) = record.get("eprocess").and_then(json_u64)
            && let Some(id) = adapter.insert(RawObjectSpec {
                object_type: "windows.eprocess".to_owned(),
                address_space: "kernel_virtual".to_owned(),
                address: eprocess,
                semantic_key: selected_key(record, "process_string_owner", &["pid", "process"])?,
                fields: selected_fields(record, &["pid", "process", "eprocess"]),
                valid: Some(true),
                validation_method: "active_process_record_v1".to_owned(),
                validation_checks: BTreeMap::from([(
                    "owner_mapping_revalidated".to_owned(),
                    Value::Bool(true),
                )]),
                provenance_source: "windows.active_process_list".to_owned(),
                locator: "records.eprocess".to_owned(),
                relation: "owns_verified_virtual_alias".to_owned(),
                missing_ranges: Vec::new(),
            })?
        {
            ids.push(id);
        }
        if let (Some(eprocess), Some(virtual_address)) = (
            record.get("eprocess").and_then(json_u64),
            record.get("virtual_address").and_then(json_u64),
        ) && let Some(id) = adapter.insert(RawObjectSpec {
            object_type: "windows.memory.virtual_string_alias".to_owned(),
            address_space: format!("process_virtual_eprocess_0x{eprocess:016x}"),
            address: virtual_address,
            semantic_key: selected_key(
                record,
                "process_string_virtual_alias",
                &["eprocess", "physical_address", "encoding", "match_length"],
            )?,
            fields: selected_fields(
                record,
                &[
                    "eprocess",
                    "pid",
                    "process",
                    "virtual_address",
                    "physical_address",
                    "encoding",
                    "match_length",
                    "context",
                    "context_complete",
                ],
            ),
            valid: Some(true),
            validation_method: "process_virtual_literal_reread_v1".to_owned(),
            validation_checks: BTreeMap::from([(
                "process_virtual_reread_matched".to_owned(),
                Value::Bool(true),
            )]),
            provenance_source: "process_page_table".to_owned(),
            locator: "records.virtual_address".to_owned(),
            relation: "verified_alias_of_physical_literal_match".to_owned(),
            missing_ranges: Vec::new(),
        })? {
            ids.push(id);
        }
        if let Some(physical_address) = record.get("physical_address").and_then(json_u64)
            && let Some(id) = adapter.insert(RawObjectSpec {
                object_type: "windows.memory.string_match".to_owned(),
                address_space: "physical".to_owned(),
                address: physical_address,
                semantic_key: selected_key(
                    record,
                    "process_string_match",
                    &["physical_address", "encoding", "match_length"],
                )?,
                fields: selected_fields(
                    record,
                    &[
                        "physical_address",
                        "file_offset",
                        "source_location",
                        "encoding",
                        "match_length",
                    ],
                ),
                valid: Some(true),
                validation_method: "physical_literal_bytes_matched_v1".to_owned(),
                validation_checks: BTreeMap::from([(
                    "literal_bytes_matched".to_owned(),
                    Value::Bool(true),
                )]),
                provenance_source: "physical_literal_scan".to_owned(),
                locator: "records.physical_address".to_owned(),
                relation: "exact_literal_match".to_owned(),
                missing_ranges: Vec::new(),
            })?
        {
            ids.push(id);
        }
        adapter.aggregate(
            "windows.process-string.match",
            selected_key(
                record,
                "process_string_match",
                &[
                    "eprocess",
                    "pid",
                    "virtual_address",
                    "physical_address",
                    "encoding",
                ],
            )?,
            ids,
        );
    }
    Ok(())
}

fn execution_record_objects(
    adapter: &mut RawObjectAdapter<'_>,
    record: &Value,
    locator: &str,
) -> Result<Vec<String>> {
    let Some(address) = record.get("object_address").and_then(json_u64) else {
        return Ok(Vec::new());
    };
    let artifact = record
        .get("artifact")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let source = record
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("windows.execution");
    let object_type = if artifact == "process" || source.contains("eprocess") {
        "windows.eprocess"
    } else if artifact == "prefetch" || source.contains("prefetch") {
        "windows.file_object"
    } else if source.contains("userassist") {
        "windows.registry.userassist_entry"
    } else if source.contains("shimcache") {
        "windows.registry.shimcache_entry"
    } else if source.contains("amcache") {
        "windows.registry.amcache_entry"
    } else if source.contains("bam") || source.contains("dam") {
        "windows.registry.bam_dam_entry"
    } else {
        "windows.execution.source_object"
    };
    let id = adapter.insert(RawObjectSpec {
        object_type: object_type.to_owned(),
        address_space: "kernel_virtual".to_owned(),
        address,
        semantic_key: selected_key(
            record,
            object_type,
            &["source", "artifact", "executable", "path"],
        )?,
        fields: evidence_locus_fields(record, "object_address"),
        valid: None,
        validation_method: "execution_source_locus_v1".to_owned(),
        validation_checks: BTreeMap::new(),
        provenance_source: source.to_owned(),
        locator: locator.to_owned(),
        relation: "decoded_from_addressed_source_record".to_owned(),
        missing_ranges: Vec::new(),
    })?;
    Ok(id.into_iter().collect())
}

fn adapt_windows_timeline(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    let Some(events) = data.get("events").and_then(Value::as_array) else {
        return Ok(());
    };
    for event in events {
        let source = event
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("windows.timeline");
        let object_type = timeline_object_type(source);
        let mut ids = Vec::new();
        if let Some(address) = event.get("object_address").and_then(json_u64)
            && let Some(id) = adapter.insert(RawObjectSpec {
                object_type: object_type.to_owned(),
                address_space: "kernel_virtual".to_owned(),
                address,
                semantic_key: selected_key(event, object_type, &["pid", "tid", "path", "process"])?,
                fields: evidence_locus_fields(event, "object_address"),
                valid: None,
                validation_method: "timeline_source_locus_v1".to_owned(),
                validation_checks: BTreeMap::new(),
                provenance_source: source.to_owned(),
                locator: "events".to_owned(),
                relation: "decoded_from_memory_object".to_owned(),
                missing_ranges: Vec::new(),
            })?
        {
            ids.push(id);
        }
        for address in physical_addresses(event) {
            if let Some(id) = adapter.insert(RawObjectSpec {
                object_type: object_type.to_owned(),
                address_space: "physical".to_owned(),
                address,
                semantic_key: selected_key(event, object_type, &["pid", "tid", "path", "process"])?,
                fields: evidence_locus_fields(event, "physical_address"),
                valid: None,
                validation_method: "timeline_physical_locus_v1".to_owned(),
                validation_checks: BTreeMap::new(),
                provenance_source: source.to_owned(),
                locator: "events".to_owned(),
                relation: "decoded_from_physical_source_record".to_owned(),
                missing_ranges: Vec::new(),
            })? {
                ids.push(id);
            }
        }
        adapter.aggregate(
            "windows.timeline.event",
            stable_record_key(event, "timeline_event")?,
            ids,
        );
    }
    Ok(())
}

fn timeline_object_type(source: &str) -> &'static str {
    if source.contains("pslist") || source.contains("psscan") {
        "windows.eprocess"
    } else if source.contains("thrdscan") {
        "windows.ethread"
    } else if source.contains("mft") {
        "windows.ntfs.mft_record"
    } else if source.contains("shimcache") {
        "windows.registry.shimcache_entry"
    } else if source.contains("registry") {
        "windows.registry.cell"
    } else {
        "windows.timeline.source_object"
    }
}

fn adapt_usb_history(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    let Some(cmhive) = data.get("registry_system_cmhive").and_then(json_u64) else {
        // Interface/key paths have no cell addresses in the current report contract.
        return Ok(());
    };
    let mut checks = BTreeMap::new();
    if let Some(value) = data.get("registry_source_complete") {
        checks.insert("registry_source_complete".to_owned(), value.clone());
    }
    let hive_id = adapter.insert(RawObjectSpec {
        object_type: "windows.registry.cmhive".to_owned(),
        address_space: "kernel_virtual".to_owned(),
        address: cmhive,
        semantic_key: "system_hive".to_owned(),
        fields: selected_fields(
            data,
            &[
                "registry_system_cmhive",
                "control_set_used",
                "registry_source_complete",
                "property_source_available",
            ],
        ),
        valid: Some(true),
        validation_method: "recovered_system_hive_v1".to_owned(),
        validation_checks: checks,
        provenance_source: "registry.system_hive".to_owned(),
        locator: "registry_system_cmhive".to_owned(),
        relation: "decoded_registry_source".to_owned(),
        missing_ranges: Vec::new(),
    })?;
    let Some(hive_id) = hive_id else {
        return Ok(());
    };
    if let Some(records) = data.get("records").and_then(Value::as_array) {
        for record in records {
            let mut ids = vec![hive_id.clone()];
            if let Some(interfaces) = record.get("interfaces").and_then(Value::as_array) {
                for interface in interfaces {
                    let Some(cell_index) = interface.get("registry_cell_index").and_then(json_u64)
                    else {
                        continue;
                    };
                    let source = interface
                        .get("enum_branch")
                        .and_then(Value::as_str)
                        .unwrap_or("registry.usb_enum");
                    if let Some(id) = adapter.insert(RawObjectSpec {
                        object_type: "windows.registry.key_cell".to_owned(),
                        address_space: "registry_hive_cell".to_owned(),
                        address: cell_index,
                        semantic_key: selected_key(
                            interface,
                            "usb_registry_key",
                            &["registry_path", "instance_id"],
                        )?,
                        fields: canonical_value(interface),
                        valid: Some(true),
                        validation_method: "registry_key_cell_decode_v1".to_owned(),
                        validation_checks: BTreeMap::new(),
                        provenance_source: source.to_owned(),
                        locator: "records.interfaces".to_owned(),
                        relation: "decoded_registry_key_cell".to_owned(),
                        missing_ranges: Vec::new(),
                    })? {
                        ids.push(id);
                    }
                }
            }
            adapter.aggregate(
                "usb-history.device",
                selected_key(
                    record,
                    "usb_device",
                    &["group_key", "container_id", "serial"],
                )?,
                ids,
            );
        }
    }
    Ok(())
}

fn adapt_windows_recent_files(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    let mut source_ids = BTreeMap::<(String, Option<String>), String>::new();
    if let Some(sources) = data.get("sources").and_then(Value::as_array) {
        for source in sources {
            let Some(cmhive) = source.get("cmhive").and_then(json_u64) else {
                continue;
            };
            let source_name = source
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("registry.recent_files");
            let user_sid = source
                .get("user_sid")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let mut checks = selected_checks(source, &["available", "complete"]);
            checks.insert("cell_addresses_exposed".to_owned(), Value::Bool(false));
            if let Some(id) = adapter.insert(RawObjectSpec {
                object_type: "windows.registry.cmhive".to_owned(),
                address_space: "kernel_virtual".to_owned(),
                address: cmhive,
                semantic_key: selected_key(source, "ntuser_hive", &["user_sid", "user_name"])?,
                fields: selected_fields(
                    source,
                    &["cmhive", "user_sid", "user_name", "available", "complete"],
                ),
                valid: source.get("available").and_then(Value::as_bool),
                validation_method: "recovered_ntuser_hive_v1".to_owned(),
                validation_checks: checks,
                provenance_source: source_name.to_owned(),
                locator: "sources".to_owned(),
                relation: "decoded_registry_source_hive".to_owned(),
                missing_ranges: Vec::new(),
            })? {
                source_ids.insert((source_name.to_owned(), user_sid), id);
            }
        }
    }
    if let Some(records) = data.get("records").and_then(Value::as_array) {
        for record in records {
            let source_name = record
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let user_sid = record
                .get("user_sid")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let id = source_ids
                .get(&(source_name.to_owned(), user_sid))
                .or_else(|| {
                    source_ids
                        .iter()
                        .find(|((candidate, _), _)| candidate == source_name)
                        .map(|(_, id)| id)
                });
            if let Some(id) = id {
                adapter.aggregate(
                    "windows.recent-files.record",
                    selected_key(
                        record,
                        "recent_file",
                        &[
                            "source",
                            "user_sid",
                            "registry_key",
                            "registry_value",
                            "path",
                        ],
                    )?,
                    vec![id.clone()],
                );
            }
        }
    }
    Ok(())
}

fn adapt_browser_session(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    let cookie_ids = adapt_browser_records(
        adapter,
        data,
        "cookies",
        "browser.cookie",
        "browser.cookie.memory_fragment",
        &[
            "browser",
            "profile",
            "domain",
            "path",
            "name",
            "database_rowid",
        ],
    )?;
    let download_ids = adapt_browser_records(
        adapter,
        data,
        "downloads",
        "browser.download_trace",
        "browser.download_trace.memory_fragment",
        &["url", "host", "file_name"],
    )?;
    for (field, aggregate_type, fragment_type, keys) in [
        (
            "visit_history",
            "browser.visit_history",
            "browser.sqlite.visit_history_record",
            &[
                "browser",
                "profile",
                "source_file",
                "database_rowid",
                "url_id",
            ][..],
        ),
        (
            "visit_events",
            "browser.visit_event",
            "browser.sqlite.visit_event_record",
            &[
                "browser",
                "profile",
                "source_file",
                "database_rowid",
                "visit_id",
            ][..],
        ),
        (
            "download_history",
            "browser.download_history",
            "browser.sqlite.download_record",
            &[
                "browser",
                "profile",
                "source_file",
                "database_rowid",
                "download_id",
            ][..],
        ),
        (
            "login_accounts",
            "browser.login_account",
            "browser.sqlite.login_record",
            &[
                "browser",
                "profile",
                "source_file",
                "database_rowid",
                "website",
                "username",
            ][..],
        ),
    ] {
        adapt_browser_records(adapter, data, field, aggregate_type, fragment_type, keys)?;
    }
    adapt_browser_artifact_owners(adapter, data)?;

    if let Some(sessions) = data.get("sessions").and_then(Value::as_array) {
        for session in sessions {
            let mut ids = indexed_source_ids(session, "cookie_indices", &cookie_ids);
            ids.extend(indexed_source_ids(
                session,
                "download_indices",
                &download_ids,
            ));
            adapter.aggregate(
                "browser.session",
                selected_key(
                    session,
                    "browser_session",
                    &["kind", "browser", "profile", "pid", "user_sid"],
                )?,
                ids,
            );
        }
    }
    if let Some(relations) = data.get("domain_relations").and_then(Value::as_array) {
        for relation in relations {
            let mut ids = indexed_source_ids(relation, "cookie_indices", &cookie_ids);
            ids.extend(indexed_source_ids(
                relation,
                "download_indices",
                &download_ids,
            ));
            adapter.aggregate(
                "browser.domain_relation",
                selected_key(relation, "domain_relation", &["download_host"])?,
                ids,
            );
        }
    }
    Ok(())
}

fn adapt_browser_records(
    adapter: &mut RawObjectAdapter<'_>,
    data: &Value,
    field: &str,
    aggregate_type: &str,
    fragment_type: &str,
    semantic_fields: &[&str],
) -> Result<Vec<Vec<String>>> {
    let mut indexed = Vec::new();
    let Some(records) = data.get(field).and_then(Value::as_array) else {
        return Ok(indexed);
    };
    for record in records {
        let source = record
            .get("source_file")
            .and_then(Value::as_str)
            .or_else(|| record.get("source").and_then(Value::as_str))
            .unwrap_or(field);
        let mut ids = Vec::new();
        if let Some(address) = record.get("file_object").and_then(json_u64)
            && let Some(id) = adapter.insert(RawObjectSpec {
                object_type: "windows.file_object".to_owned(),
                address_space: "kernel_virtual".to_owned(),
                address,
                semantic_key: selected_key(record, "windows.file_object", &["source_file"])?,
                fields: selected_fields(
                    record,
                    &["source_file", "file_object", "browser", "profile"],
                ),
                valid: None,
                validation_method: "browser_file_object_reference_v1".to_owned(),
                validation_checks: BTreeMap::new(),
                provenance_source: source.to_owned(),
                locator: field.to_owned(),
                relation: "database_backing_file_object".to_owned(),
                missing_ranges: Vec::new(),
            })?
        {
            ids.push(id);
        }
        let record_missing = browser_record_missing_ranges(record, source);
        for address in physical_addresses(record) {
            let mut checks = BTreeMap::new();
            for check in [
                "parser_payload_complete",
                "source_bytes_complete",
                "source_database_complete",
            ] {
                if let Some(value) = record.get(check) {
                    checks.insert(check.to_owned(), value.clone());
                }
            }
            let parser_complete = record
                .get("parser_payload_complete")
                .and_then(Value::as_bool);
            let source_bytes_complete =
                record.get("source_bytes_complete").and_then(Value::as_bool);
            let valid = match (parser_complete, source_bytes_complete) {
                (Some(parser), Some(source_bytes)) => Some(parser && source_bytes),
                (None, Some(source_bytes)) => Some(source_bytes),
                // `source_database_complete` describes the search universe, not whether this
                // particular recovered row is valid.
                _ => None,
            };
            if let Some(id) = adapter.insert(RawObjectSpec {
                object_type: fragment_type.to_owned(),
                address_space: "physical".to_owned(),
                address,
                semantic_key: selected_key(record, fragment_type, semantic_fields)?,
                fields: evidence_locus_fields(record, "physical_addresses"),
                valid,
                validation_method: if fragment_type.contains("sqlite") {
                    "sqlite_record_recovery_v1"
                } else {
                    "physical_pattern_recovery_v1"
                }
                .to_owned(),
                validation_checks: checks,
                provenance_source: source.to_owned(),
                locator: field.to_owned(),
                relation: "decoded_from_physical_source_bytes".to_owned(),
                missing_ranges: record_missing.clone(),
            })? {
                ids.push(id);
            }
        }
        if let Some(owners) = record.get("owners").and_then(Value::as_array) {
            for owner in owners {
                let Some(address) = owner.get("virtual_address").and_then(json_u64) else {
                    continue;
                };
                if let Some(id) = adapter.insert(RawObjectSpec {
                    object_type: format!("{aggregate_type}.process_virtual_record"),
                    address_space: "process_virtual".to_owned(),
                    address,
                    semantic_key: selected_key(owner, aggregate_type, &["pid", "process"])?,
                    fields: canonical_value(owner),
                    valid: None,
                    validation_method: "process_address_space_mapping_v1".to_owned(),
                    validation_checks: BTreeMap::new(),
                    provenance_source: source.to_owned(),
                    locator: format!("{field}.owners"),
                    relation: "mapped_process_virtual_occurrence".to_owned(),
                    missing_ranges: Vec::new(),
                })? {
                    ids.push(id);
                }
            }
        }
        adapter.aggregate(
            aggregate_type,
            stable_record_key(record, aggregate_type)?,
            ids.clone(),
        );
        indexed.push(ids);
    }
    Ok(indexed)
}

fn adapt_browser_artifact_owners(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    let Some(records) = data.get("artifact_owners").and_then(Value::as_array) else {
        return Ok(());
    };
    for record in records {
        let source = record
            .get("source_file")
            .and_then(Value::as_str)
            .unwrap_or("browser.artifact_owner");
        let mut ids = Vec::new();
        for (field, object_type) in [
            ("handle_entry", "windows.handle_table_entry"),
            ("object_header", "windows.object_header"),
            ("file_object", "windows.file_object"),
        ] {
            let Some(address) = record.get(field).and_then(json_u64) else {
                continue;
            };
            let semantic_fields = match field {
                "handle_entry" => &["pid", "handle_value"][..],
                "object_header" | "file_object" => &["source_file"][..],
                _ => &["source_file", "pid", "handle_value"][..],
            };
            if let Some(id) = adapter.insert(RawObjectSpec {
                object_type: object_type.to_owned(),
                address_space: "kernel_virtual".to_owned(),
                address,
                semantic_key: selected_key(record, object_type, semantic_fields)?,
                fields: evidence_locus_fields(record, field),
                valid: None,
                validation_method: "handle_owner_relationship_v1".to_owned(),
                validation_checks: BTreeMap::new(),
                provenance_source: source.to_owned(),
                locator: "artifact_owners".to_owned(),
                relation: format!("browser_artifact_{field}"),
                missing_ranges: Vec::new(),
            })? {
                ids.push(id);
            }
        }
        adapter.aggregate(
            "browser.artifact_owner",
            stable_record_key(record, "artifact_owner")?,
            ids,
        );
    }
    Ok(())
}

fn adapt_linux_lsmod(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    if let Some(modules) = data.get("modules").and_then(Value::as_array) {
        for module in modules {
            let ids = linux_module_object(adapter, module, "modules", "strict_module_list_v1")?;
            adapter.aggregate(
                "linux.lsmod.module",
                selected_key(module, "linux_module", &["name", "module", "core_base"])?,
                ids,
            );
        }
    }
    Ok(())
}

fn adapt_linux_module_extract(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    let Some(module) = data.get("module").filter(|value| value.is_object()) else {
        return Ok(());
    };
    let ids = linux_module_object(adapter, module, "module", "module_extract_revalidation_v1")?;
    adapter.aggregate(
        "linux.module-extract.output",
        selected_key(
            module,
            "linux_module_extract",
            &["name", "module", "core_base"],
        )?,
        ids,
    );
    Ok(())
}

fn linux_module_object(
    adapter: &mut RawObjectAdapter<'_>,
    module: &Value,
    locator: &str,
    method: &str,
) -> Result<Vec<String>> {
    let Some(address) = module.get("module").and_then(json_u64) else {
        return Ok(Vec::new());
    };
    let id = adapter.insert(RawObjectSpec {
        object_type: "linux.module".to_owned(),
        address_space: "kernel_virtual".to_owned(),
        address,
        semantic_key: selected_key(module, "linux.module", &["name", "core_base"])?,
        fields: canonical_value(module),
        valid: Some(true),
        validation_method: method.to_owned(),
        validation_checks: BTreeMap::new(),
        provenance_source: "linux.modules".to_owned(),
        locator: locator.to_owned(),
        relation: "decoded_struct_module".to_owned(),
        missing_ranges: Vec::new(),
    })?;
    Ok(id.into_iter().collect())
}

fn adapt_linux_mountinfo(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    let namespace_id = if let Some(address) = data.get("namespace").and_then(json_u64) {
        adapter.insert(RawObjectSpec {
            object_type: "linux.mnt_namespace".to_owned(),
            address_space: "kernel_virtual".to_owned(),
            address,
            semantic_key: format!("mnt_namespace=0x{address:016x}"),
            fields: selected_fields(data, &["namespace", "source", "stop_reason"]),
            valid: Some(true),
            validation_method: "mount_namespace_resolution_v1".to_owned(),
            validation_checks: BTreeMap::new(),
            provenance_source: "linux.mount_namespace".to_owned(),
            locator: "namespace".to_owned(),
            relation: "decoded_mnt_namespace".to_owned(),
            missing_ranges: Vec::new(),
        })?
    } else {
        None
    };
    if let Some(mounts) = data.get("mounts").and_then(Value::as_array) {
        for mount in mounts {
            let Some(address) = mount.get("mount").and_then(json_u64) else {
                continue;
            };
            let mut ids = namespace_id.iter().cloned().collect::<Vec<_>>();
            if let Some(id) = adapter.insert(RawObjectSpec {
                object_type: "linux.mount".to_owned(),
                address_space: "kernel_virtual".to_owned(),
                address,
                semantic_key: selected_key(
                    mount,
                    "linux.mount",
                    &["namespace", "mount_id", "mount_point", "file_system"],
                )?,
                fields: canonical_value(mount),
                valid: Some(true),
                validation_method: "strict_mount_list_v1".to_owned(),
                validation_checks: BTreeMap::new(),
                provenance_source: "linux.mount_list".to_owned(),
                locator: "mounts".to_owned(),
                relation: "decoded_struct_mount".to_owned(),
                missing_ranges: Vec::new(),
            })? {
                ids.push(id);
            }
            adapter.aggregate(
                "linux.mountinfo.mount",
                selected_key(mount, "linux_mount", &["namespace", "mount_id", "mount"])?,
                ids,
            );
        }
    }
    Ok(())
}

fn adapt_linux_kallsyms(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    if let Some(symbols) = data.get("symbols").and_then(Value::as_array) {
        for symbol in symbols {
            let Some(address) = symbol.get("address").and_then(json_u64) else {
                continue;
            };
            let valid = symbol.get("valid_kernel_address").and_then(Value::as_bool);
            let source = symbol
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("linux.kallsyms");
            let id = adapter.insert(RawObjectSpec {
                object_type: "linux.kallsyms.symbol_target".to_owned(),
                address_space: "kernel_virtual".to_owned(),
                address,
                semantic_key: selected_key(
                    symbol,
                    "linux_symbol",
                    &["source", "index", "name", "module"],
                )?,
                fields: canonical_value(symbol),
                valid,
                validation_method: "kallsyms_target_address_v1".to_owned(),
                validation_checks: BTreeMap::new(),
                provenance_source: source.to_owned(),
                locator: "symbols".to_owned(),
                relation: "decoded_symbol_target_not_table_entry".to_owned(),
                missing_ranges: Vec::new(),
            })?;
            adapter.aggregate(
                "linux.kallsyms.symbol",
                selected_key(symbol, "linux_symbol", &["source", "index", "name"])?,
                id.into_iter().collect(),
            );
        }
    }
    Ok(())
}

fn adapt_linux_modxview(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    if let Some(records) = data.get("records").and_then(Value::as_array) {
        for record in records {
            let Some(address) = record.get("module").and_then(json_u64) else {
                continue;
            };
            let valid = match (
                record.get("in_modules_list").and_then(Value::as_bool),
                record.get("in_module_kset").and_then(Value::as_bool),
                record.get("in_semantic_scan").and_then(Value::as_bool),
            ) {
                (None, None, None) => None,
                (modules, kset, semantic) => Some(
                    modules.unwrap_or(false) || kset.unwrap_or(false) || semantic.unwrap_or(false),
                ),
            };
            let id = adapter.insert(RawObjectSpec {
                object_type: "linux.module".to_owned(),
                address_space: "kernel_virtual".to_owned(),
                address,
                semantic_key: selected_key(record, "linux.module", &["name"])?,
                fields: canonical_value(record),
                valid,
                validation_method: "module_cross_view_v1".to_owned(),
                validation_checks: selected_checks(
                    record,
                    &[
                        "in_modules_list",
                        "in_module_kset",
                        "in_semantic_scan",
                        "suspicious",
                    ],
                ),
                provenance_source: "linux.module_cross_view".to_owned(),
                locator: "records".to_owned(),
                relation: "cross_view_struct_module_candidate".to_owned(),
                missing_ranges: Vec::new(),
            })?;
            adapter.aggregate(
                "linux.modxview.module",
                selected_key(record, "linux_module_cross_view", &["module", "name"])?,
                id.into_iter().collect(),
            );
        }
    }
    Ok(())
}

fn adapt_linux_check_syscall(adapter: &mut RawObjectAdapter<'_>, data: &Value) -> Result<()> {
    let table = data
        .get("table")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if let Some(records) = data.get("records").and_then(Value::as_array) {
        for record in records {
            let Some(address) = record.get("entry_address").and_then(json_u64) else {
                continue;
            };
            let readable = record.get("handler").is_some_and(|value| !value.is_null());
            let mut checks = selected_checks(record, &["handler", "classification", "suspicious"]);
            checks.insert("table".to_owned(), Value::String(table.to_owned()));
            let id = adapter.insert(RawObjectSpec {
                object_type: "linux.syscall_table_entry".to_owned(),
                address_space: "kernel_virtual".to_owned(),
                address,
                semantic_key: selected_key(record, table, &["index"])?,
                fields: canonical_value(record),
                valid: Some(readable),
                validation_method: "syscall_entry_pointer_validation_v1".to_owned(),
                validation_checks: checks,
                provenance_source: format!("linux.{table}"),
                locator: "records".to_owned(),
                relation: "decoded_syscall_table_entry".to_owned(),
                missing_ranges: Vec::new(),
            })?;
            adapter.aggregate(
                "linux.check-syscall.entry",
                selected_key(record, "syscall_entry", &["index", "entry_address"])?,
                id.into_iter().collect(),
            );
        }
    }
    Ok(())
}

fn conservative_walk(
    adapter: &mut RawObjectAdapter<'_>,
    value: &Value,
    path: &str,
) -> Result<Vec<String>> {
    match value {
        Value::Array(items) => {
            let mut all = Vec::new();
            for item in items {
                let ids = conservative_walk(adapter, item, path)?;
                adapter.aggregate(
                    &format!("{}.addressed_record", adapter.plugin_id),
                    stable_record_key(item, "addressed_record")?,
                    ids.clone(),
                );
                all.extend(ids);
            }
            Ok(all)
        }
        Value::Object(object) => {
            let mut ids = Vec::new();
            for (field, address_space, object_type) in
                conservative_address_fields(adapter.plugin_id)
            {
                let Some(address) = object.get(field).and_then(json_u64) else {
                    continue;
                };
                let source = object
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or("conservative_report_adapter");
                if let Some(id) = adapter.insert(RawObjectSpec {
                    object_type,
                    address_space: address_space.to_owned(),
                    address,
                    semantic_key: selected_key(value, field, &["source", "name", "pid", "tid"])?,
                    fields: evidence_locus_fields(value, field),
                    valid: object.get("valid").and_then(Value::as_bool),
                    validation_method: "conservative_address_snapshot_v1".to_owned(),
                    validation_checks: BTreeMap::new(),
                    provenance_source: source.to_owned(),
                    locator: path.to_owned(),
                    relation: "address_bearing_report_record".to_owned(),
                    missing_ranges: object
                        .get("missing_ranges")
                        .cloned()
                        .and_then(|ranges| serde_json::from_value(ranges).ok())
                        .unwrap_or_default(),
                })? {
                    ids.push(id);
                }
            }
            for (key, child) in object {
                if matches!(child, Value::Array(_) | Value::Object(_)) && key != "missing_ranges" {
                    ids.extend(conservative_walk(adapter, child, &format!("{path}.{key}"))?);
                }
            }
            Ok(ids)
        }
        _ => Ok(Vec::new()),
    }
}

fn conservative_address_fields(plugin_id: &str) -> Vec<(&'static str, &'static str, String)> {
    [
        ("eprocess", "kernel_virtual", "windows.eprocess"),
        ("ethread", "kernel_virtual", "windows.ethread"),
        ("file_object", "kernel_virtual", "windows.file_object"),
        ("cmhive", "kernel_virtual", "windows.registry.cmhive"),
        (
            "handle_entry",
            "kernel_virtual",
            "windows.handle_table_entry",
        ),
        ("object_header", "kernel_virtual", "windows.object_header"),
        ("physical_address", "physical", "memory.physical_record"),
        ("object_address", "kernel_virtual", "memory.kernel_object"),
        ("virtual_address", "virtual", "memory.virtual_record"),
    ]
    .into_iter()
    .map(|(field, space, kind)| {
        let object_type = if kind.starts_with("memory.") {
            format!("{plugin_id}.{}", kind.trim_start_matches("memory."))
        } else {
            kind.to_owned()
        };
        (field, space, object_type)
    })
    .collect()
}

fn json_u64(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value.as_str().and_then(|text| {
            let compact = text.trim().replace('_', "");
            compact
                .strip_prefix("0x")
                .or_else(|| compact.strip_prefix("0X"))
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                .or_else(|| compact.parse().ok())
        })
    })
}

fn stable_record_key(value: &Value, prefix: &str) -> Result<String> {
    let canonical = serde_json::to_vec(&canonical_value(value))?;
    Ok(format!(
        "{prefix}|sha256={}",
        hex::encode(Sha256::digest(canonical))
    ))
}

fn selected_key(value: &Value, prefix: &str, fields: &[&str]) -> Result<String> {
    let selected = selected_fields(value, fields);
    let Some(object) = selected.as_object() else {
        return stable_record_key(value, prefix);
    };
    if object.is_empty() {
        return stable_record_key(value, prefix);
    }
    Ok(format!(
        "{prefix}|{}",
        object
            .iter()
            .map(|(key, value)| format!("{key}={}", compact_value(value)))
            .collect::<Vec<_>>()
            .join("|")
    ))
}

fn selected_fields(value: &Value, fields: &[&str]) -> Value {
    let Some(object) = value.as_object() else {
        return Value::Object(Default::default());
    };
    Value::Object(
        fields
            .iter()
            .filter_map(|key| {
                object
                    .get(*key)
                    .filter(|value| !value.is_null())
                    .map(|value| ((*key).to_owned(), canonical_value(value)))
            })
            .collect(),
    )
}

fn selected_checks(value: &Value, fields: &[&str]) -> BTreeMap<String, Value> {
    let Some(object) = value.as_object() else {
        return BTreeMap::new();
    };
    fields
        .iter()
        .filter_map(|key| {
            object
                .get(*key)
                .map(|value| ((*key).to_owned(), canonical_value(value)))
        })
        .collect()
}

fn evidence_locus_fields(record: &Value, address_field: &str) -> Value {
    serde_json::json!({
        "address_field": address_field,
        "decoded_record": canonical_value(record),
    })
}

fn physical_addresses(record: &Value) -> Vec<u64> {
    let mut addresses = BTreeSet::new();
    if let Some(address) = record.get("physical_address").and_then(json_u64) {
        addresses.insert(address);
    }
    if let Some(values) = record.get("physical_addresses").and_then(Value::as_array) {
        addresses.extend(values.iter().filter_map(json_u64));
    }
    if let Some(ranges) = record.get("source_ranges").and_then(Value::as_array) {
        addresses.extend(ranges.iter().filter_map(|range| {
            range
                .get("physical_address")
                .filter(|address| !address.is_null())
                .and_then(json_u64)
        }));
    }
    addresses.into_iter().collect()
}

fn browser_record_missing_ranges(record: &Value, source: &str) -> Vec<MissingRange> {
    record
        .get("source_ranges")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|range| {
            !range
                .get("fully_recovered")
                .and_then(Value::as_bool)
                .unwrap_or(true)
        })
        .filter_map(|range| {
            let length = range.get("length").and_then(json_u64)?.max(1);
            if let Some(start) = range.get("physical_address").and_then(json_u64) {
                Some(MissingRange {
                    address_space: "physical".to_owned(),
                    start,
                    length,
                    source: format!("{source}:sqlite_source_range"),
                })
            } else {
                Some(MissingRange {
                    address_space: "source_file".to_owned(),
                    start: range.get("file_offset").and_then(json_u64)?,
                    length,
                    source: format!("{source}:sqlite_source_range"),
                })
            }
        })
        .collect()
}

fn indexed_source_ids(aggregate: &Value, field: &str, source_ids: &[Vec<String>]) -> Vec<String> {
    aggregate
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(json_u64)
        .filter_map(|index| usize::try_from(index).ok())
        .filter_map(|index| source_ids.get(index))
        .flatten()
        .cloned()
        .collect()
}

fn compact_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), canonical_value(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        value => value.clone(),
    }
}

pub fn write_raw_objects_jsonl(
    path: &Path,
    source_path: Option<&Path>,
    force: bool,
    bundle: &RawObjectBundle,
) -> Result<RawEvidenceSummary> {
    let mut policy = OutputPolicy::new(force);
    if let Some(source_path) = source_path {
        policy.protect_file("evidence_source", source_path);
    }
    policy.output(OutputTarget::file("raw_objects.jsonl", path));
    policy.preflight()?;
    write_raw_objects_jsonl_with_policy(&policy, path, bundle)
}

pub fn write_raw_objects_jsonl_with_policy(
    policy: &OutputPolicy,
    path: &Path,
    bundle: &RawObjectBundle,
) -> Result<RawEvidenceSummary> {
    let mut bundle = bundle.clone();
    bundle.normalize();
    let mut digest = Sha256::new();
    policy.write_file_atomic(path, |file| {
        let mut writer = BufWriter::new(file);
        for object in &bundle.objects {
            let mut line = serde_json::to_vec(object)?;
            line.push(b'\n');
            digest.update(&line);
            writer.write_all(&line)?;
        }
        writer.flush()?;
        Ok(())
    })?;
    Ok(RawEvidenceSummary {
        count: bundle.objects.len() as u64,
        storage: RawEvidenceStorage::Jsonl,
        references: vec![RawEvidenceReference {
            path: Some(path.display().to_string()),
            hash: Some(DigestReference::new(
                "sha256",
                hex::encode(digest.finalize()),
            )),
        }],
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::evidence::{DigestReference, SourceIdentity};

    fn source() -> SourceIdentity {
        SourceIdentity {
            format: "synthetic".to_owned(),
            size: 16,
            mtime: None,
            sample_digest: DigestReference::new("sha256", "00".repeat(32)),
            symbol_identity: None,
            components: Vec::new(),
            physical_layout: None,
        }
    }

    #[test]
    fn evidence_id_is_stable_and_path_independent() {
        let first = evidence_id(&source(), "windows.timeline", "event", 0x1234, "key").unwrap();
        let second = evidence_id(&source(), "windows.timeline", "event", 0x1234, "key").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn clipboard_history_raw_objects_keep_process_ownership_and_text_read_status() {
        let report = serde_json::json!({ "complete": false, "formats": [], "history": [
            { "pid": 40, "eprocess": 0xffff800000001000u64, "item_address": 0x30000,
              "evidence_kind": "textinputhost_clipboard_history", "text_status": "verified", "text": "example.test",
              "chain": { "control_address": 0x10000 }, "sources": [{ "physical_address": 0x50000, "bytes_hex": "6100" }] },
            { "pid": 50, "eprocess": 0xffff800000002000u64, "item_address": 0x30000,
              "evidence_kind": "textinputhost_clipboard_history", "text_status": "unavailable", "text": null }
        ] });
        let bundle = extract_raw_objects("clipboardscan", &source(), &report).unwrap();
        assert_eq!(bundle.objects.len(), 2);
        assert_ne!(bundle.objects[0].evidence_id, bundle.objects[1].evidence_id);
        assert_ne!(
            bundle.objects[0].address_space,
            bundle.objects[1].address_space
        );
        assert_eq!(bundle.aggregates.len(), 2);
        let good = bundle
            .objects
            .iter()
            .find(|o| o.fields["pid"] == 40)
            .unwrap();
        assert_eq!(good.fields["sources"][0]["bytes_hex"], "6100");
        assert_eq!(good.validation.valid, Some(true));
        let missing = bundle
            .objects
            .iter()
            .find(|o| o.fields["pid"] == 50)
            .unwrap();
        assert_eq!(missing.validation.checks["text_status"], "unavailable");
        assert!(missing.fields["text"].is_null());
    }

    #[test]
    fn extraction_is_deterministic_and_links_aggregates() {
        let value = serde_json::json!({
            "records": [
                {"physical_address": 0x2000, "name": "second", "source": "list"},
                {"physical_address": 0x1000, "name": "first", "source": "scan"}
            ]
        });
        let first = extract_raw_objects("test.plugin", &source(), &value).unwrap();
        let second = extract_raw_objects("test.plugin", &source(), &value).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.aggregates.len(), 2);
        assert!(
            first
                .objects
                .windows(2)
                .all(|pair| pair[0].evidence_id <= pair[1].evidence_id)
        );
        assert!(
            first
                .objects
                .iter()
                .all(|object| object.address.len() == 18)
        );
        assert!(
            first
                .objects
                .iter()
                .all(|object| object.address_space != "semantic")
        );
        let object_ids = first
            .objects
            .iter()
            .map(|object| object.evidence_id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(first.aggregates.iter().all(|aggregate| {
            aggregate
                .source_evidence_ids
                .iter()
                .all(|id| object_ids.contains(id.as_str()))
        }));
    }

    #[test]
    fn aggregate_only_reports_do_not_become_zero_address_objects() {
        let value = serde_json::json!({
            "available": true,
            "complete": true,
            "records": [{"pid": 4, "name": "System", "source": "aggregate"}],
            "statistics": {"matched": 1}
        });
        let bundle = extract_raw_objects("test.aggregate", &source(), &value).unwrap();
        assert!(bundle.objects.is_empty());
        assert!(bundle.aggregates.is_empty());

        let recent = serde_json::json!({
            "complete": true,
            "records": [{
                "source": "registry.recentdocs",
                "path": "C:\\\\示例表格.xlsx",
                "registry_key": "RecentDocs",
                "registry_value": "0"
            }]
        });
        let bundle = extract_raw_objects("windows.recent-files", &source(), &recent).unwrap();
        assert!(bundle.objects.is_empty());
        assert!(bundle.aggregates.is_empty());
    }

    #[test]
    fn timeline_adapter_retains_real_loci_and_report_missing_ranges() {
        let value = serde_json::json!({
            "available": true,
            "complete": false,
            "missing_ranges": [{
                "address_space": "physical",
                "start": 36864,
                "length": 4096,
                "source": "psscan"
            }],
            "events": [{
                "timestamp": "2023-06-20T16:56:57Z",
                "category": "process",
                "action": "created",
                "source": "psscan",
                "pid": 88,
                "process": "chrome.exe",
                "object_address": "0xffff800000001000",
                "physical_address": 8192,
                "physical_addresses": [12288, 8192]
            }]
        });
        let bundle = extract_raw_objects("windows.timeline", &source(), &value).unwrap();
        assert_eq!(bundle.objects.len(), 3);
        assert_eq!(bundle.aggregates.len(), 1);
        assert_eq!(bundle.aggregates[0].source_evidence_ids.len(), 3);
        assert!(
            bundle
                .objects
                .iter()
                .all(|object| object.object_type == "windows.eprocess")
        );
        assert!(bundle.objects.iter().any(|object| {
            object.address_space == "kernel_virtual" && object.address == "0xffff800000001000"
        }));
        assert_eq!(
            bundle
                .objects
                .iter()
                .filter(|object| object.address_space == "physical")
                .count(),
            2
        );
        assert!(
            bundle
                .objects
                .iter()
                .all(|object| object.missing_ranges.len() == 1)
        );
    }

    #[test]
    fn registry_aggregates_link_real_hive_and_cell_locations() {
        let recent = serde_json::json!({
            "complete": true,
            "sources": [{
                "source": "registry.recentdocs",
                "user_sid": "S-1-5-21-88",
                "user_name": "testuser",
                "cmhive": "0xffff800000003000",
                "available": true,
                "complete": true
            }],
            "records": [{
                "source": "registry.recentdocs",
                "user_sid": "S-1-5-21-88",
                "registry_key": "RecentDocs",
                "registry_value": "0",
                "path": "C:\\\\示例表格.xlsx"
            }]
        });
        let bundle = extract_raw_objects("windows.recent-files", &source(), &recent).unwrap();
        assert_eq!(bundle.objects.len(), 1);
        assert_eq!(bundle.objects[0].object_type, "windows.registry.cmhive");
        assert_eq!(bundle.aggregates.len(), 1);
        assert_eq!(bundle.aggregates[0].source_evidence_ids.len(), 1);
        assert_eq!(
            bundle.objects[0]
                .validation
                .checks
                .get("cell_addresses_exposed"),
            Some(&Value::Bool(false))
        );

        let usb = serde_json::json!({
            "available": true,
            "complete": true,
            "registry_source_complete": true,
            "registry_system_cmhive": "0xffff800000004000",
            "records": [{
                "group_key": "serial:usb88",
                "serial": "usb88",
                "interfaces": [{
                    "registry_cell_index": 1056,
                    "enum_branch": "USBSTOR",
                    "registry_path": "ControlSet001\\\\Enum\\\\USBSTOR\\\\Disk\\\\usb88",
                    "instance_id": "usb88"
                }]
            }]
        });
        let bundle = extract_raw_objects("usb-history", &source(), &usb).unwrap();
        assert_eq!(bundle.objects.len(), 2);
        assert!(
            bundle
                .objects
                .iter()
                .any(|object| object.address_space == "registry_hive_cell")
        );
        assert_eq!(bundle.aggregates.len(), 1);
        assert_eq!(bundle.aggregates[0].source_evidence_ids.len(), 2);
    }

    #[test]
    fn browser_session_aggregates_link_memory_sources_not_session_snapshots() {
        let value = serde_json::json!({
            "complete": true,
            "cookies": [{
                "browser": "chrome",
                "profile": "Default",
                "source": "chromium_sqlite",
                "domain": "example.test",
                "path": "/",
                "name": "sid",
                "source_file": "C:\\\\Chrome\\\\Cookies",
                "file_object": "0xffff800000002000",
                "database_rowid": 7,
                "physical_addresses": [16384]
            }],
            "downloads": [{
                "url": "https://example.test/a.zip",
                "host": "example.test",
                "physical_addresses": [20480],
                "owners": [{"pid": 88, "process": "chrome.exe", "virtual_address": 24576}]
            }],
            "sessions": [{
                "kind": "profile",
                "browser": "chrome",
                "profile": "Default",
                "cookie_indices": [0],
                "download_indices": [0]
            }],
            "domain_relations": []
        });
        let bundle = extract_raw_objects("browser-session", &source(), &value).unwrap();
        let session = bundle
            .aggregates
            .iter()
            .find(|aggregate| aggregate.aggregate_type == "browser.session")
            .unwrap();
        assert_eq!(session.source_evidence_ids.len(), 4);
        assert!(
            bundle
                .objects
                .iter()
                .any(|object| object.object_type == "windows.file_object")
        );
        assert!(
            bundle
                .objects
                .iter()
                .all(|object| !object.object_type.contains("session"))
        );
    }

    #[test]
    fn process_string_links_verified_owner_and_physical_match() {
        let report = serde_json::json!({
            "available": true,
            "complete": true,
            "records": [{
                "pid": 4242,
                "process": "chrome.exe",
                "eprocess": "0xffff800000001000",
                "virtual_address": "0x000001aa00002000",
                "physical_address": "0x0000000000123000",
                "file_offset": 0x123000,
                "encoding": "utf16le",
                "match_length": 8,
                "context": "前⟦目标⟧后",
                "context_complete": true
            }]
        });
        let bundle = extract_raw_objects("windows.process-string", &source(), &report).unwrap();
        assert_eq!(bundle.objects.len(), 3);
        assert_eq!(bundle.aggregates.len(), 1);
        assert_eq!(bundle.aggregates[0].source_evidence_ids.len(), 3);
        assert!(bundle.objects.iter().any(|object| {
            object.object_type == "windows.eprocess"
                && object.address_space == "kernel_virtual"
                && object.validation.valid == Some(true)
        }));
        assert!(bundle.objects.iter().any(|object| {
            object.object_type == "windows.memory.virtual_string_alias"
                && object.address_space == "process_virtual_eprocess_0xffff800000001000"
                && object.validation.method == "process_virtual_literal_reread_v1"
        }));
        assert!(bundle.objects.iter().any(|object| {
            object.object_type == "windows.memory.string_match"
                && object.address_space == "physical"
                && object.validation.method == "physical_literal_bytes_matched_v1"
        }));
    }

    #[test]
    fn process_string_deduplicates_shared_physical_hits_but_keeps_each_owner_alias() {
        let report = serde_json::json!({
            "available": true,
            "complete": true,
            "records": [
                {
                    "pid": 100,
                    "process": "one.exe",
                    "eprocess": "0xffff800000001000",
                    "virtual_address": "0x0000010000002000",
                    "physical_address": "0x0000000000123000",
                    "encoding": "ascii",
                    "match_length": 7,
                    "context": "⟦StarMem⟧",
                    "context_complete": true
                },
                {
                    "pid": 200,
                    "process": "two.exe",
                    "eprocess": "0xffff800000002000",
                    "virtual_address": "0x0000020000003000",
                    "physical_address": "0x0000000000123000",
                    "encoding": "ascii",
                    "match_length": 7,
                    "context": "⟦StarMem⟧",
                    "context_complete": true
                }
            ]
        });
        let bundle = extract_raw_objects("windows.process-string", &source(), &report).unwrap();
        assert_eq!(
            bundle
                .objects
                .iter()
                .filter(|object| object.object_type == "windows.memory.string_match")
                .count(),
            1
        );
        assert_eq!(
            bundle
                .objects
                .iter()
                .filter(|object| object.object_type == "windows.memory.virtual_string_alias")
                .count(),
            2
        );
        assert_eq!(bundle.aggregates.len(), 2);
        assert!(
            bundle
                .aggregates
                .iter()
                .all(|aggregate| aggregate.source_evidence_ids.len() == 3)
        );
    }

    #[test]
    fn linux_adapters_only_emit_addressable_evidence() {
        let lsmod = serde_json::json!({
            "available": true,
            "complete": true,
            "missing_ranges": [],
            "modules": [{
                "module": "0xffffffffa0001000",
                "name": "evidence",
                "core_base": "0xffffffffa0002000"
            }]
        });
        let bundle = extract_raw_objects("linux.lsmod", &source(), &lsmod).unwrap();
        assert_eq!(bundle.objects.len(), 1);
        assert_eq!(bundle.objects[0].object_type, "linux.module");
        assert_eq!(bundle.aggregates[0].source_evidence_ids.len(), 1);

        let module_extract = serde_json::json!({
            "available": true,
            "complete": false,
            "module": {
                "module": "0xffffffffa0001000",
                "name": "evidence",
                "core_base": "0xffffffffa0002000"
            },
            "output": "evidence.ko.partial"
        });
        let bundle =
            extract_raw_objects("linux.module-extract", &source(), &module_extract).unwrap();
        assert_eq!(bundle.objects.len(), 1);
        assert_eq!(
            bundle.aggregates[0].aggregate_type,
            "linux.module-extract.output"
        );

        let mountinfo = serde_json::json!({
            "available": true,
            "complete": true,
            "namespace": "0xffff888000001000",
            "mounts": [{
                "namespace": "0xffff888000001000",
                "mount": "0xffff888000002000",
                "mount_id": 1,
                "mount_point": "/",
                "file_system": "ext4"
            }]
        });
        let bundle = extract_raw_objects("linux.mountinfo", &source(), &mountinfo).unwrap();
        assert_eq!(bundle.objects.len(), 2);
        assert_eq!(bundle.aggregates[0].source_evidence_ids.len(), 2);

        let kallsyms = serde_json::json!({
            "available": true,
            "complete": false,
            "symbols": [{
                "index": 1,
                "address": "0xffffffff81000000",
                "name": "_stext",
                "source": "core",
                "valid_kernel_address": true
            }]
        });
        let bundle = extract_raw_objects("linux.kallsyms", &source(), &kallsyms).unwrap();
        assert_eq!(
            bundle.objects[0].object_type,
            "linux.kallsyms.symbol_target"
        );
        assert_eq!(bundle.objects[0].validation.valid, Some(true));

        let modxview = serde_json::json!({
            "available": true,
            "complete": false,
            "records": [{
                "module": "0xffffffffa0003000",
                "name": "hidden",
                "in_modules_list": false,
                "in_module_kset": true,
                "in_semantic_scan": null,
                "suspicious": true
            }]
        });
        let bundle = extract_raw_objects("linux.modxview", &source(), &modxview).unwrap();
        assert_eq!(bundle.objects.len(), 1);
        assert_eq!(bundle.objects[0].validation.valid, Some(true));

        let syscall = serde_json::json!({
            "available": true,
            "complete": false,
            "table": "x64",
            "records": [{
                "index": 0,
                "entry_address": "0xffffffff82000000",
                "handler": "0xffffffff81000100",
                "classification": "kernel_text",
                "suspicious": false
            }]
        });
        let bundle = extract_raw_objects("linux.check-syscall", &source(), &syscall).unwrap();
        assert_eq!(bundle.objects[0].object_type, "linux.syscall_table_entry");

        let kmsg = serde_json::json!({
            "available": true,
            "complete": true,
            "records": [{"sequence": 1, "monotonic_ns": 2, "text": "boot"}]
        });
        let bundle = extract_raw_objects("linux.kmsg", &source(), &kmsg).unwrap();
        assert!(bundle.objects.is_empty());
        assert!(bundle.aggregates.is_empty());
    }

    #[test]
    fn jsonl_is_byte_deterministic_across_report_order() {
        let first_report = serde_json::json!({
            "events": [
                {"source": "mftscan", "path": "b", "physical_address": 8192},
                {"source": "mftscan", "path": "a", "physical_address": 4096}
            ]
        });
        let second_report = serde_json::json!({
            "events": [
                {"source": "mftscan", "path": "a", "physical_address": 4096},
                {"source": "mftscan", "path": "b", "physical_address": 8192}
            ]
        });
        let first = extract_raw_objects("windows.timeline", &source(), &first_report).unwrap();
        let second = extract_raw_objects("windows.timeline", &source(), &second_report).unwrap();
        assert_eq!(first, second);

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let first_path = std::env::temp_dir().join(format!(
            "starmem-raw-objects-a-{}-{nonce}.jsonl",
            std::process::id()
        ));
        let second_path = std::env::temp_dir().join(format!(
            "starmem-raw-objects-b-{}-{nonce}.jsonl",
            std::process::id()
        ));
        let first_summary = write_raw_objects_jsonl(&first_path, None, false, &first).unwrap();
        let second_summary = write_raw_objects_jsonl(&second_path, None, false, &second).unwrap();
        assert_eq!(
            fs::read(&first_path).unwrap(),
            fs::read(&second_path).unwrap()
        );
        assert_eq!(
            first_summary.references[0].hash,
            second_summary.references[0].hash
        );
        fs::remove_file(first_path).ok();
        fs::remove_file(second_path).ok();
    }
}
