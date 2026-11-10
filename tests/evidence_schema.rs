use std::collections::BTreeSet;

use serde_json::{Value, json};
use starmem::command_registry;
use starmem::evidence::{
    DigestReference, EVIDENCE_SCHEMA_VERSION, EngineIdentity, EvidenceEnvelope, EvidenceScope,
    RawEvidenceSummary, SourceIdentity,
};

fn assert_schema_shape(schema: &Value, document: &Value) {
    let object = document.as_object().expect("envelope must be an object");
    for field in schema["required"].as_array().unwrap() {
        let field = field.as_str().unwrap();
        assert!(object.contains_key(field), "missing schema field {field}");
    }
    assert!(document["available"].is_boolean());
    assert!(document["complete"].is_boolean());
    for field in ["warnings", "limits", "missing_ranges"] {
        assert!(document[field].is_array(), "{field} must be an array");
    }
    for field in [
        "engine_identity",
        "source_identity",
        "scope",
        "raw_evidence",
    ] {
        assert!(document[field].is_object(), "{field} must be an object");
    }
}

#[test]
fn checked_in_schema_matches_serialized_contract() {
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/evidence-envelope-v1.schema.json"))
            .expect("schema must be valid JSON");
    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        EVIDENCE_SCHEMA_VERSION
    );

    let envelope = EvidenceEnvelope::from_parts(
        "windows.pslist",
        EngineIdentity::new("0.2.0", "schema-test", 3),
        SourceIdentity {
            format: "raw".to_owned(),
            size: 0,
            mtime: None,
            sample_digest: DigestReference::new("sha256-starmem-sample-v1", "00"),
            symbol_identity: None,
            components: Vec::new(),
            physical_layout: None,
        },
        true,
        true,
        EvidenceScope::new("active_process_list"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        RawEvidenceSummary::default(),
        json!({"processes": []}),
    )
    .unwrap();
    let serialized = serde_json::to_value(envelope).unwrap();
    let actual = serialized
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, required);
    assert!(serialized["available"].is_boolean());
    assert!(serialized["complete"].is_boolean());
}

#[test]
fn schema_requires_every_contract_field() {
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/evidence-envelope-v1.schema.json")).unwrap();
    let required = schema["required"].as_array().unwrap();
    assert_eq!(required.len(), 12);
    assert!(schema["additionalProperties"] == Value::Bool(false));
}

#[test]
fn every_registered_leaf_has_a_schema_valid_boolean_status_envelope() {
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/evidence-envelope-v1.schema.json")).unwrap();
    let registry = command_registry::CommandRegistry::load_embedded().unwrap();
    for command in registry.command_ids() {
        let envelope = EvidenceEnvelope::from_parts(
            command,
            EngineIdentity::new("0.2.0", "all-leaves-schema-test", 3),
            SourceIdentity {
                format: "synthetic".to_owned(),
                size: 0,
                mtime: None,
                sample_digest: DigestReference::new("sha256", "00"),
                symbol_identity: None,
                components: Vec::new(),
                physical_layout: None,
            },
            false,
            false,
            EvidenceScope::new("declared_by_command_registry"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            RawEvidenceSummary::default(),
            json!({}),
        )
        .unwrap();
        let serialized = serde_json::to_value(envelope).unwrap();
        assert_schema_shape(&schema, &serialized);
    }
}
