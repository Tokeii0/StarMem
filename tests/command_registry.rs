#[allow(dead_code)]
#[path = "../src/command_registry.rs"]
mod command_registry;

use command_registry::{
    ArgumentValueType, CollectDisposition, CommandCategory, CommandRegistry,
    EMBEDDED_LEAF_COMMAND_COUNT, EquivalenceStatus, InputRole, MetadataStatus, OutputKind,
    RegistryError,
};
use std::collections::BTreeSet;

const LINUX_METADATA_COMMANDS: [&str; 8] = [
    "symbols.linux",
    "linux.lsmod",
    "linux.module-extract",
    "linux.mountinfo",
    "linux.kallsyms",
    "linux.kmsg",
    "linux.modxview",
    "linux.check-syscall",
];

#[test]
fn embedded_registry_covers_all_leaf_commands() {
    let registry = CommandRegistry::load_embedded().expect("embedded registry must validate");
    assert_eq!(registry.len(), EMBEDDED_LEAF_COMMAND_COUNT);
    assert_eq!(registry.len(), 179);
    assert!(!registry.is_empty());

    let ids = registry.command_ids().collect::<Vec<_>>();
    assert_eq!(
        ids.len(),
        ids.iter().copied().collect::<BTreeSet<_>>().len()
    );
    assert!(ids.contains(&"build-info"));
    assert!(ids.contains(&"symbols.id"));
    assert!(ids.contains(&"symbols.linux"));
    assert!(ids.contains(&"linux.lsmod"));
    assert!(ids.contains(&"linux.check-syscall"));
    assert!(ids.contains(&"windows.process-string"));
    assert!(ids.contains(&"windows.open-files"));
    assert!(ids.contains(&"mouse-history"));
    assert!(ids.contains(&"qqscan"));
    for name in [
        "bitlocker",
        "veracrypt",
        "sunlogin",
        "anydesk",
        "wps",
        "huorong",
        "ai-chat",
    ] {
        let contract = registry.by_id(name).expect("应用分析命令应可发现");
        assert!(contract.collect_parameterized);
        assert_eq!(contract.collect_disposition, CollectDisposition::Skipped);
    }
}

#[test]
fn qqscan_is_available_to_manual_hosts_but_skipped_by_collect() {
    let registry = CommandRegistry::load_embedded().unwrap();
    let contract = registry.by_id("qqscan").unwrap();
    assert!(contract.collect_parameterized);
    assert_eq!(contract.collect_disposition, CollectDisposition::Skipped);
    assert_eq!(contract.cli_path, ["qqscan"]);
    for name in ["pid", "limit", "anchor-limit", "process-space-limit"] {
        assert!(
            contract
                .arguments
                .items
                .iter()
                .any(|a| a.name == name && a.required == Some(false))
        );
    }
}

#[test]
fn symbolless_commands_have_no_symbol_inputs_and_are_manual_only() {
    let registry = CommandRegistry::load_embedded().unwrap();
    for name in [
        "symbolless.system-info",
        "symbolless.pslist",
        "symbolless.process-context",
        "symbolless.process-modules",
        "symbolless.filescan",
        "symbolless.dumpfile",
        "symbolless.registry",
    ] {
        let contract = registry.by_id(name).unwrap();
        assert!(contract.collect_parameterized);
        assert_eq!(contract.collect_disposition, CollectDisposition::Skipped);
        assert!(
            contract
                .input_roles
                .roles
                .iter()
                .all(|r| r.role != InputRole::Pdb && r.role != InputRole::SymbolStore)
        );
        assert!(
            contract
                .arguments
                .items
                .iter()
                .all(|a| !["pdb", "profile", "symbol-path", "cache"].contains(&a.name.as_str()))
        );
    }
}

#[test]
fn mouse_history_is_a_bounded_windows_command_without_a_volatility_equivalent() {
    let registry = CommandRegistry::load_embedded().unwrap();
    let contract = registry.by_id("mouse-history").unwrap();
    assert_eq!(contract.cli_path, ["mouse-history"]);
    assert_eq!(contract.equivalence.status, EquivalenceStatus::NoEquivalent);
    assert!(contract.arguments.items.iter().any(|a| a.name == "limit"));
    assert!(
        contract
            .input_roles
            .roles
            .iter()
            .any(|r| r.role == InputRole::MemoryImage && r.required == Some(true))
    );
}

#[test]
fn cli_paths_only_expand_the_documented_symbols_group() {
    let registry = CommandRegistry::load_embedded().unwrap();
    assert_eq!(
        registry.by_id("symbols.id").unwrap().cli_path,
        ["symbols", "id"]
    );
    assert_eq!(
        registry.by_id("symbols.linux").unwrap().cli_path,
        ["symbols", "linux"]
    );
    assert_eq!(
        registry.by_id("linux.info").unwrap().cli_path,
        ["linux.info"]
    );
    assert_eq!(
        registry.by_id("windows.open-files").unwrap().cli_path,
        ["windows.open-files"]
    );
    assert!(registry.by_id("does-not-exist").is_none());
}

#[test]
fn every_embedded_leaf_has_complete_known_metadata() {
    let registry = CommandRegistry::load_embedded().unwrap();
    for contract in registry.commands.values() {
        assert_eq!(
            contract.aliases.status,
            MetadataStatus::Known,
            "{}",
            contract.command_id
        );
        assert_eq!(
            contract.help.status,
            MetadataStatus::Known,
            "{}",
            contract.command_id
        );
        assert!(
            contract
                .help
                .value
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        );
        assert_eq!(
            contract.arguments.status,
            MetadataStatus::Known,
            "{}",
            contract.command_id
        );
        assert_ne!(
            contract.category,
            CommandCategory::Unknown,
            "{}",
            contract.command_id
        );
        assert_eq!(
            contract.input_roles.status,
            MetadataStatus::Known,
            "{}",
            contract.command_id
        );
        assert_eq!(
            contract.outputs.status,
            MetadataStatus::Known,
            "{}",
            contract.command_id
        );
        assert!(
            !contract.outputs.items.is_empty(),
            "{}",
            contract.command_id
        );
        assert_eq!(
            contract.derived_outputs.status,
            MetadataStatus::Known,
            "{}",
            contract.command_id
        );
        assert_eq!(
            contract.evidence_defaults.scope.status,
            MetadataStatus::Known,
            "{}",
            contract.command_id
        );
        assert_eq!(
            contract.evidence_defaults.adapter.status,
            MetadataStatus::Known,
            "{}",
            contract.command_id
        );
        assert_ne!(
            contract.collect_disposition,
            CollectDisposition::Unknown,
            "{}",
            contract.command_id
        );
        assert_eq!(contract.equivalence_id, contract.command_id);
    }
}

#[test]
fn linux_kernel_contracts_preserve_known_io_evidence_and_collect_metadata() {
    let registry = CommandRegistry::load_embedded().unwrap();
    for command_id in LINUX_METADATA_COMMANDS.into_iter().skip(1) {
        let contract = registry.by_id(command_id).unwrap();
        assert_eq!(contract.category, CommandCategory::Linux, "{command_id}");
        assert_eq!(
            contract.aliases.status,
            MetadataStatus::Known,
            "{command_id}"
        );
        assert_eq!(contract.aliases.values.len(), 1, "{command_id}");
        assert_eq!(contract.help.status, MetadataStatus::Known, "{command_id}");
        assert_eq!(
            contract.arguments.status,
            MetadataStatus::Known,
            "{command_id}"
        );
        assert_eq!(contract.arguments.items[0].name, "image", "{command_id}");
        assert_eq!(
            contract.arguments.items[0].value_type,
            ArgumentValueType::Path,
            "{command_id}"
        );
        assert_eq!(
            contract.arguments.items[0].required,
            Some(true),
            "{command_id}"
        );
        assert_eq!(
            contract.arguments.items[1].name, "system-map",
            "{command_id}"
        );
        assert_eq!(
            contract.arguments.items[1].value_type,
            ArgumentValueType::Path
        );
        assert_eq!(contract.arguments.items[1].required, Some(false));
        assert_eq!(contract.arguments.items[2].name, "cache", "{command_id}");
        assert_eq!(
            contract.arguments.items[3].name, "symbol-path",
            "{command_id}"
        );
        assert_eq!(contract.arguments.items[3].repeatable, Some(true));
        assert_eq!(contract.arguments.items[4].name, "dtb", "{command_id}");
        assert_eq!(
            contract.arguments.items[5].name, "kernel-slide",
            "{command_id}"
        );
        assert_eq!(
            contract.input_roles.status,
            MetadataStatus::Known,
            "{command_id}"
        );
        let image = contract
            .input_roles
            .roles
            .iter()
            .find(|role| role.role == InputRole::MemoryImage)
            .unwrap();
        assert_eq!(image.required, Some(true));
        assert!(
            contract
                .input_roles
                .roles
                .iter()
                .any(|role| role.role == InputRole::SymbolStore)
        );
        assert_eq!(
            contract.outputs.status,
            MetadataStatus::Known,
            "{command_id}"
        );
        assert_eq!(contract.outputs.items[0].kind, OutputKind::StructuredReport);
        assert_eq!(
            contract.evidence_defaults.adapter.value.as_deref(),
            Some("native-evidence-envelope-v1"),
            "{command_id}"
        );
        assert_eq!(
            contract.equivalence.platform,
            command_registry::CommandPlatform::Linux
        );
    }

    for command_id in [
        "linux.lsmod",
        "linux.mountinfo",
        "linux.kallsyms",
        "linux.kmsg",
        "linux.modxview",
        "linux.check-syscall",
    ] {
        assert_eq!(
            registry.by_id(command_id).unwrap().collect_disposition,
            CollectDisposition::Runnable,
            "{command_id}"
        );
    }

    let extract = registry.by_id("linux.module-extract").unwrap();
    assert_eq!(extract.collect_disposition, CollectDisposition::Skipped);
    assert!(extract.arguments.items.iter().any(|argument| {
        argument.name == "output"
            && argument.value_type == ArgumentValueType::OutputPath
            && argument.required == Some(true)
    }));
    assert!(extract.arguments.items.iter().any(|argument| {
        argument.name == "max-bytes"
            && argument.value_type == ArgumentValueType::Integer
            && argument.required == Some(true)
    }));
    assert!(extract.outputs.items.iter().any(|output| {
        output.name == "module_elf"
            && output.kind == OutputKind::File
            && output.required == Some(true)
    }));
    assert!(
        extract
            .derived_outputs
            .items
            .iter()
            .any(|output| output.name == "partial_module_elf")
    );
    assert!(
        extract
            .derived_outputs
            .items
            .iter()
            .any(|output| output.name == "recovery_manifest")
    );

    assert_eq!(
        registry.by_id("linux.lsmod").unwrap().equivalence.status,
        EquivalenceStatus::Exact
    );
    for command_id in [
        "linux.module-extract",
        "linux.mountinfo",
        "linux.kallsyms",
        "linux.kmsg",
        "linux.modxview",
        "linux.check-syscall",
    ] {
        assert_eq!(
            registry.by_id(command_id).unwrap().equivalence.status,
            EquivalenceStatus::Partial,
            "{command_id}"
        );
    }
    assert_eq!(
        registry
            .by_id("linux.kallsyms")
            .unwrap()
            .evidence_defaults
            .scope
            .value
            .as_deref(),
        Some("linux_core_and_module_kallsyms")
    );
}

#[test]
fn windows_process_string_declares_parameterized_process_memory_evidence() {
    let registry = CommandRegistry::load_embedded().unwrap();
    let contract = registry.by_id("windows.process-string").unwrap();
    assert_eq!(contract.cli_path, ["windows.process-string"]);
    assert_eq!(contract.aliases.values, ["process-string"]);
    assert_eq!(contract.category, CommandCategory::Process);
    assert_eq!(
        contract
            .arguments
            .items
            .iter()
            .map(|argument| argument.name.as_str())
            .collect::<Vec<_>>(),
        [
            "image",
            "text",
            "encoding",
            "profile",
            "pdb",
            "system-map",
            "cache",
            "symbol-path",
            "scan-hit-limit",
            "limit",
            "process-limit",
            "mapping-limit",
            "reverse-entry-limit",
            "reverse-alias-limit",
            "chunk-mib",
            "context-bytes",
        ]
    );
    let text = contract
        .arguments
        .items
        .iter()
        .find(|argument| argument.name == "text")
        .unwrap();
    assert_eq!(text.value_type, ArgumentValueType::Pattern);
    assert_eq!(text.required, Some(true));
    assert_eq!(
        contract
            .arguments
            .items
            .iter()
            .find(|argument| argument.name == "encoding")
            .unwrap()
            .value_type,
        ArgumentValueType::Choice
    );
    for argument_name in [
        "scan-hit-limit",
        "limit",
        "process-limit",
        "mapping-limit",
        "reverse-entry-limit",
        "reverse-alias-limit",
        "chunk-mib",
        "context-bytes",
    ] {
        assert_eq!(
            contract
                .arguments
                .items
                .iter()
                .find(|argument| argument.name == argument_name)
                .unwrap()
                .value_type,
            ArgumentValueType::Integer,
            "{argument_name}"
        );
    }
    assert_eq!(
        contract
            .input_roles
            .roles
            .iter()
            .map(|role| (&role.role, role.required))
            .collect::<Vec<_>>(),
        [
            (&InputRole::AuxiliaryFile, Some(false)),
            (&InputRole::MemoryImage, Some(true)),
            (&InputRole::Pdb, Some(false)),
            (&InputRole::SearchPattern, Some(true)),
            (&InputRole::SymbolStore, Some(false)),
        ]
    );
    assert_eq!(
        contract.evidence_defaults.scope.value.as_deref(),
        Some("windows_active_process_acquired_resident_literal_hits")
    );
    assert_eq!(contract.collect_disposition, CollectDisposition::Skipped);
    assert!(contract.collect_parameterized);
    assert_eq!(contract.equivalence.status, EquivalenceStatus::Composite);
}

#[test]
fn linux_symbol_contract_preserves_the_explicit_known_metadata() {
    let registry = CommandRegistry::load_embedded().unwrap();
    let contract = registry.by_id("symbols.linux").unwrap();
    assert_eq!(contract.help.status, MetadataStatus::Known);
    assert_eq!(contract.arguments.status, MetadataStatus::Known);
    assert_eq!(contract.arguments.items.len(), 10);
    assert_eq!(contract.arguments.items[0].name, "image");
    assert_eq!(contract.arguments.items[0].required, Some(true));
    let isf = contract
        .arguments
        .items
        .iter()
        .find(|argument| argument.name == "isf")
        .unwrap();
    assert_eq!(isf.required, Some(false));
    assert_eq!(contract.category, CommandCategory::Symbol);
    assert_eq!(contract.input_roles.status, MetadataStatus::Known);
    let image = contract
        .input_roles
        .roles
        .iter()
        .find(|role| role.role == InputRole::MemoryImage)
        .unwrap();
    assert_eq!(image.required, Some(true));
    let isf = contract
        .input_roles
        .roles
        .iter()
        .find(|role| role.role == InputRole::LinuxIsf)
        .unwrap();
    assert_eq!(isf.required, Some(false));
    assert_eq!(contract.outputs.items[0].kind, OutputKind::StructuredReport);
    assert_eq!(contract.outputs.items[0].required, Some(true));
    assert_eq!(contract.derived_outputs.items[0].name, "symbol_cache");
    assert_eq!(contract.derived_outputs.items[0].required, Some(false));
    assert_eq!(
        contract.evidence_defaults.scope.value.as_deref(),
        Some("symbol_candidates")
    );
    assert_eq!(
        contract.evidence_defaults.adapter.status,
        MetadataStatus::Known
    );
    assert_eq!(contract.collect_disposition, CollectDisposition::Skipped);
}

#[test]
fn equivalence_records_are_preserved_and_queryable() {
    let registry = CommandRegistry::load_embedded().unwrap();
    let pslist = registry.by_id("pslist").unwrap();
    assert_eq!(pslist.equivalence.status, EquivalenceStatus::Partial);
    assert_eq!(pslist.equivalence.set_key, ["pid", "name"]);
    assert!(
        pslist
            .equivalence
            .volatility3_plugins
            .contains(&"windows.pslist.PsList".to_owned())
    );
    assert_eq!(
        pslist.equivalence.external_tool.as_deref(),
        Some("Volatility 3 Framework 2.28.2")
    );

    let build_info = registry.by_id("build-info").unwrap();
    assert_eq!(
        build_info.equivalence.status,
        EquivalenceStatus::NoEquivalent
    );
    assert!(build_info.equivalence.adapter.as_deref().is_none());
    assert!(build_info.equivalence.external_tool.as_deref().is_none());
    assert!(
        build_info
            .equivalence
            .prerequisites
            .acquisition_format
            .is_empty()
    );
}

#[test]
fn validation_rejects_inconsistent_known_metadata_and_duplicate_cli_paths() {
    let mut registry = CommandRegistry::load_embedded().unwrap();
    let build_info = registry.commands.get_mut("build-info").unwrap();
    build_info.help.value = None;
    assert!(matches!(
        registry.validate(),
        Err(RegistryError::InvalidContract { field, .. }) if field == "help"
    ));

    let mut registry = CommandRegistry::load_embedded().unwrap();
    let duplicate_path = registry.by_id("pslist").unwrap().cli_path.clone();
    registry.commands.get_mut("psscan").unwrap().cli_path = duplicate_path;
    assert!(matches!(
        registry.validate(),
        Err(RegistryError::InvalidContract { field, .. }) if field == "cli_path"
    ));
}

#[test]
fn loader_rejects_duplicate_command_ids_before_map_insertion() {
    let record = r#"{
      "status":"no_equivalent",
      "platform":"cross",
      "volatility3_plugins":[],
      "adapter":null,
      "external_tool":null,
      "comparable_fields":[],
      "set_key":[],
      "normalizer":"identity-v1",
      "non_equivalent_fields":[{"field":"entire_result","reason":"test"}],
      "prerequisites":{"platform":["windows","linux"],"symbols":"none","acquisition_format":[]}
    }"#;
    let source = format!(
        r#"{{"schema_version":1,"commands":{{"duplicate":{record},"duplicate":{record}}}}}"#
    );
    assert!(matches!(
        CommandRegistry::from_equivalence_json(&source),
        Err(RegistryError::Json(message)) if message.contains("duplicate command ID duplicate")
    ));
}

#[test]
fn loader_rejects_a_missing_required_nullable_field() {
    let source = r#"{
      "schema_version": 1,
      "commands": {
        "incomplete": {
          "status": "no_equivalent",
          "platform": "cross",
          "volatility3_plugins": [],
          "external_tool": null,
          "comparable_fields": [],
          "set_key": [],
          "normalizer": "identity-v1",
          "non_equivalent_fields": [{"field": "entire_result", "reason": "test"}],
          "prerequisites": {"platform": ["windows", "linux"], "symbols": "none", "acquisition_format": []}
        }
      }
    }"#;
    let error = CommandRegistry::from_equivalence_json(source).unwrap_err();
    assert!(
        matches!(&error, RegistryError::Json(message) if message.contains("adapter")),
        "unexpected error: {error}"
    );
}

#[test]
fn embedded_source_join_rejects_manifest_equivalence_set_drift() {
    let mut manifest: serde_json::Value =
        serde_json::from_str(include_str!("../metadata/leaf-command-manifest.json")).unwrap();
    manifest["commands"]
        .as_object_mut()
        .unwrap()
        .remove("build-info");
    let error = CommandRegistry::from_json_sources(
        &serde_json::to_string(&manifest).unwrap(),
        include_str!("../benchmarks/command-equivalence.json"),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RegistryError::CommandSetMismatch {
            missing_from_manifest,
            missing_from_equivalence,
        } if missing_from_manifest == ["build-info"] && missing_from_equivalence.is_empty()
    ));
}

#[test]
fn validation_rejects_alias_collisions_and_parameterized_runners() {
    let mut registry = CommandRegistry::load_embedded().unwrap();
    registry
        .commands
        .get_mut("psscan")
        .unwrap()
        .aliases
        .values
        .push("pslist".to_owned());
    assert!(matches!(
        registry.validate(),
        Err(RegistryError::InvalidContract { field, .. }) if field == "aliases"
    ));

    let mut registry = CommandRegistry::load_embedded().unwrap();
    registry
        .commands
        .get_mut("pslist")
        .unwrap()
        .collect_parameterized = true;
    assert!(matches!(
        registry.validate(),
        Err(RegistryError::InvalidContract { field, .. }) if field == "collect_parameterized"
    ));
}

#[test]
fn serialized_registry_has_versioned_required_contract_fields() {
    let registry = CommandRegistry::load_embedded().unwrap();
    let value = serde_json::to_value(&registry).unwrap();
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["leaf_manifest_schema_version"], 1);
    assert_eq!(value["equivalence_schema_version"], 1);
    let contract = &value["commands"]["pslist"];
    for field in [
        "contract_version",
        "command_id",
        "cli_path",
        "aliases",
        "help",
        "arguments",
        "category",
        "input_roles",
        "outputs",
        "derived_outputs",
        "evidence_defaults",
        "collect_disposition",
        "collect_parameterized",
        "equivalence_id",
        "equivalence",
    ] {
        assert!(contract.get(field).is_some(), "missing {field}");
    }
}
