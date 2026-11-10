//! Versioned, read-only leaf-command contracts.
//!
//! `metadata/leaf-command-manifest.json` is the authoritative declaration of
//! CLI, I/O, Evidence and collection metadata.  The independent Volatility 3
//! equivalence table is joined by the declaration's stable `equivalence_id`;
//! loading fails closed when either document has a missing or extra leaf.

use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const COMMAND_REGISTRY_SCHEMA_VERSION: u32 = 2;
pub const LEAF_COMMAND_CONTRACT_VERSION: u32 = 2;
pub const LEAF_COMMAND_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const EMBEDDED_EQUIVALENCE_SCHEMA_VERSION: u32 = 1;
pub const EMBEDDED_LEAF_COMMAND_COUNT: usize = 155;

const EMBEDDED_EQUIVALENCE_JSON: &str = include_str!("../benchmarks/command-equivalence.json");
const EMBEDDED_LEAF_COMMAND_MANIFEST_JSON: &str =
    include_str!("../metadata/leaf-command-manifest.json");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataStatus {
    Known,
    Unknown,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextMetadata {
    pub status: MetadataStatus,
    pub value: Option<String>,
}

impl TextMetadata {
    fn known(value: impl Into<String>) -> Self {
        Self {
            status: MetadataStatus::Known,
            value: Some(value.into()),
        }
    }

    fn unknown() -> Self {
        Self {
            status: MetadataStatus::Unknown,
            value: None,
        }
    }

    fn validate(&self, field: &str) -> Result<(), String> {
        match (&self.status, &self.value) {
            (MetadataStatus::Known, Some(value)) if !value.trim().is_empty() => Ok(()),
            (MetadataStatus::Known, _) => Err(format!("{field} is known but has no value")),
            (MetadataStatus::Unknown | MetadataStatus::None, None) => Ok(()),
            (MetadataStatus::Unknown | MetadataStatus::None, Some(_)) => {
                Err(format!("{field} has a value without known status"))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringListMetadata {
    pub status: MetadataStatus,
    pub values: Vec<String>,
}

impl StringListMetadata {
    fn unknown() -> Self {
        Self {
            status: MetadataStatus::Unknown,
            values: Vec::new(),
        }
    }

    fn validate(&self, field: &str) -> Result<(), String> {
        if self.status != MetadataStatus::Known && !self.values.is_empty() {
            return Err(format!("{field} has values without known status"));
        }
        validate_non_empty_unique_strings(&self.values, field)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandCategory {
    Unknown,
    Acquisition,
    Browser,
    FileSystem,
    Kernel,
    Linux,
    Malware,
    Network,
    Process,
    Registry,
    Release,
    Symbol,
    Timeline,
    Windows,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentValueType {
    Unknown,
    Address,
    Boolean,
    Choice,
    Integer,
    OutputPath,
    Path,
    Pattern,
    String,
    Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgumentContract {
    pub name: String,
    pub value_type: ArgumentValueType,
    pub required: Option<bool>,
    pub repeatable: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgumentMetadata {
    pub status: MetadataStatus,
    pub items: Vec<ArgumentContract>,
}

impl ArgumentMetadata {
    fn unknown() -> Self {
        Self {
            status: MetadataStatus::Unknown,
            items: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.status != MetadataStatus::Known && !self.items.is_empty() {
            return Err("arguments have items without known status".to_owned());
        }
        let mut names = BTreeSet::new();
        for item in &self.items {
            if item.name.trim().is_empty() {
                return Err("argument name is empty".to_owned());
            }
            if !names.insert(item.name.as_str()) {
                return Err(format!("duplicate argument name {}", item.name));
            }
            if self.status == MetadataStatus::Known
                && (item.value_type == ArgumentValueType::Unknown
                    || item.required.is_none()
                    || item.repeatable.is_none())
            {
                return Err(format!(
                    "known argument {} has unknown type/required/repeatable metadata",
                    item.name
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputRole {
    Unknown,
    AuxiliaryFile,
    MemoryImage,
    LinuxIsf,
    OutputDirectory,
    Pdb,
    RegistryHive,
    SearchPattern,
    SymbolStore,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputRoleContract {
    pub role: InputRole,
    pub required: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputRoleMetadata {
    pub status: MetadataStatus,
    pub roles: Vec<InputRoleContract>,
}

impl InputRoleMetadata {
    fn unknown() -> Self {
        Self {
            status: MetadataStatus::Unknown,
            roles: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.status != MetadataStatus::Known && !self.roles.is_empty() {
            return Err("input roles exist without known status".to_owned());
        }
        let unique = self
            .roles
            .iter()
            .map(|contract| &contract.role)
            .collect::<BTreeSet<_>>();
        if unique.len() != self.roles.len() {
            return Err("input roles contain duplicates".to_owned());
        }
        if self.status == MetadataStatus::Known
            && self
                .roles
                .iter()
                .any(|contract| contract.role == InputRole::Unknown || contract.required.is_none())
        {
            return Err("known input role has unknown role/required metadata".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputKind {
    Unknown,
    Directory,
    File,
    StructuredReport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputContract {
    pub name: String,
    pub kind: OutputKind,
    pub media_type: Option<String>,
    pub required: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputMetadata {
    pub status: MetadataStatus,
    pub items: Vec<OutputContract>,
}

impl OutputMetadata {
    fn unknown() -> Self {
        Self {
            status: MetadataStatus::Unknown,
            items: Vec::new(),
        }
    }

    fn validate(&self, field: &str) -> Result<(), String> {
        if self.status != MetadataStatus::Known && !self.items.is_empty() {
            return Err(format!("{field} has items without known status"));
        }
        let mut names = BTreeSet::new();
        for item in &self.items {
            if item.name.trim().is_empty() {
                return Err(format!("{field} contains an empty output name"));
            }
            if !names.insert(item.name.as_str()) {
                return Err(format!("{field} contains duplicate output {}", item.name));
            }
            if self.status == MetadataStatus::Known
                && (item.kind == OutputKind::Unknown || item.required.is_none())
            {
                return Err(format!(
                    "{field} output {} has unknown kind/required metadata",
                    item.name
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceDefaults {
    pub scope: TextMetadata,
    pub adapter: TextMetadata,
}

impl EvidenceDefaults {
    fn unknown() -> Self {
        Self {
            scope: TextMetadata::unknown(),
            adapter: TextMetadata::unknown(),
        }
    }

    fn validate(&self) -> Result<(), String> {
        self.scope.validate("evidence_defaults.scope")?;
        self.adapter.validate("evidence_defaults.adapter")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectDisposition {
    Unknown,
    Runnable,
    Conditional,
    Skipped,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EquivalenceStatus {
    Exact,
    Partial,
    Composite,
    NoEquivalent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandPlatform {
    Cross,
    Windows,
    Linux,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NullableString(pub Option<String>);

impl NullableString {
    pub fn as_deref(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonEquivalentField {
    pub field: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalencePrerequisites {
    pub platform: Vec<PrerequisitePlatform>,
    pub symbols: String,
    pub acquisition_format: Vec<AcquisitionFormat>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrerequisitePlatform {
    Windows,
    Linux,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionFormat {
    Raw,
    CrashDump,
    VmwareVmem,
    VmwareSnapshot,
    Lime,
    ElfCore,
    XenElf64,
    AvmlV2,
    QevmV3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalenceRecord {
    pub status: EquivalenceStatus,
    pub platform: CommandPlatform,
    pub volatility3_plugins: Vec<String>,
    #[serde(deserialize_with = "deserialize_required_nullable_string")]
    pub adapter: NullableString,
    #[serde(deserialize_with = "deserialize_required_nullable_string")]
    pub external_tool: NullableString,
    pub comparable_fields: Vec<String>,
    pub set_key: Vec<String>,
    pub normalizer: String,
    pub non_equivalent_fields: Vec<NonEquivalentField>,
    pub prerequisites: EquivalencePrerequisites,
    #[serde(default)]
    pub notes: Option<String>,
}

fn deserialize_required_nullable_string<'de, D>(deserializer: D) -> Result<NullableString, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(NullableString)
}

impl EquivalenceRecord {
    fn validate(&self) -> Result<(), String> {
        validate_non_empty_unique_strings(&self.volatility3_plugins, "volatility3_plugins")?;
        validate_non_empty_unique_strings(&self.comparable_fields, "comparable_fields")?;
        validate_non_empty_unique_strings(&self.set_key, "set_key")?;
        validate_unique_values(&self.prerequisites.platform, "prerequisites.platform")?;
        validate_unique_values(
            &self.prerequisites.acquisition_format,
            "prerequisites.acquisition_format",
        )?;
        if self.prerequisites.platform.is_empty() {
            return Err("prerequisites.platform is empty".to_owned());
        }
        if self.normalizer.trim().is_empty() {
            return Err("normalizer is empty".to_owned());
        }
        if self.prerequisites.symbols.trim().is_empty() {
            return Err("prerequisites.symbols is empty".to_owned());
        }
        for difference in &self.non_equivalent_fields {
            if difference.field.trim().is_empty() || difference.reason.trim().is_empty() {
                return Err("non_equivalent_fields requires field and reason".to_owned());
            }
        }
        match self.status {
            EquivalenceStatus::NoEquivalent => {
                if !self.volatility3_plugins.is_empty()
                    || self.adapter.0.is_some()
                    || self.external_tool.0.is_some()
                {
                    return Err(
                        "no_equivalent requires empty plugins and null adapter/external_tool"
                            .to_owned(),
                    );
                }
                if self.non_equivalent_fields.is_empty() {
                    return Err("no_equivalent requires a documented reason".to_owned());
                }
            }
            EquivalenceStatus::Exact
            | EquivalenceStatus::Partial
            | EquivalenceStatus::Composite => {
                if self.volatility3_plugins.is_empty()
                    || self
                        .adapter
                        .as_deref()
                        .is_none_or(|value| value.trim().is_empty())
                    || self
                        .external_tool
                        .as_deref()
                        .is_none_or(|value| value.trim().is_empty())
                    || self.comparable_fields.is_empty()
                    || self.set_key.is_empty()
                {
                    return Err(
                        "mapped equivalence requires plugins, adapter, external tool, comparable fields, and set key"
                            .to_owned(),
                    );
                }
            }
        }
        for key in &self.set_key {
            if !self.comparable_fields.contains(key) {
                return Err(format!(
                    "set_key value {key} is absent from comparable_fields"
                ));
            }
        }
        let platform_matches = match self.platform {
            CommandPlatform::Windows => {
                self.prerequisites.platform == [PrerequisitePlatform::Windows]
            }
            CommandPlatform::Linux => self.prerequisites.platform == [PrerequisitePlatform::Linux],
            CommandPlatform::Cross => {
                self.prerequisites.platform
                    == [PrerequisitePlatform::Windows, PrerequisitePlatform::Linux]
            }
        };
        if !platform_matches {
            return Err("platform and prerequisites.platform disagree".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafCommandContract {
    pub contract_version: u32,
    pub command_id: String,
    pub cli_path: Vec<String>,
    pub aliases: StringListMetadata,
    pub help: TextMetadata,
    pub arguments: ArgumentMetadata,
    pub category: CommandCategory,
    pub input_roles: InputRoleMetadata,
    pub outputs: OutputMetadata,
    pub derived_outputs: OutputMetadata,
    pub evidence_defaults: EvidenceDefaults,
    pub collect_disposition: CollectDisposition,
    pub collect_parameterized: bool,
    pub equivalence_id: String,
    pub equivalence: EquivalenceRecord,
}

impl LeafCommandContract {
    fn from_equivalence(command_id: String, equivalence: EquivalenceRecord) -> Self {
        let cli_path = command_cli_path(&command_id);
        Self {
            contract_version: LEAF_COMMAND_CONTRACT_VERSION,
            equivalence_id: command_id.clone(),
            command_id,
            cli_path,
            aliases: StringListMetadata::unknown(),
            help: TextMetadata::unknown(),
            arguments: ArgumentMetadata::unknown(),
            category: CommandCategory::Unknown,
            input_roles: InputRoleMetadata::unknown(),
            outputs: OutputMetadata::unknown(),
            derived_outputs: OutputMetadata::unknown(),
            evidence_defaults: EvidenceDefaults::unknown(),
            collect_disposition: CollectDisposition::Unknown,
            collect_parameterized: false,
            equivalence,
        }
    }

    fn from_declaration(
        declaration: LeafCommandDeclaration,
        equivalence: EquivalenceRecord,
    ) -> Self {
        Self {
            contract_version: LEAF_COMMAND_CONTRACT_VERSION,
            command_id: declaration.command_id,
            cli_path: declaration.cli_path,
            aliases: StringListMetadata {
                status: MetadataStatus::Known,
                values: declaration.aliases,
            },
            help: TextMetadata::known(declaration.help),
            arguments: ArgumentMetadata {
                status: MetadataStatus::Known,
                items: declaration.arguments,
            },
            category: declaration.category,
            input_roles: InputRoleMetadata {
                status: MetadataStatus::Known,
                roles: declaration.input_roles,
            },
            outputs: OutputMetadata {
                status: MetadataStatus::Known,
                items: declaration.outputs,
            },
            derived_outputs: OutputMetadata {
                status: MetadataStatus::Known,
                items: declaration.derived_outputs,
            },
            evidence_defaults: EvidenceDefaults {
                scope: TextMetadata::known(declaration.evidence_defaults.scope),
                adapter: TextMetadata::known(declaration.evidence_defaults.adapter),
            },
            collect_disposition: declaration.collect_disposition,
            collect_parameterized: declaration.collect_parameterized,
            equivalence_id: declaration.equivalence_id,
            equivalence,
        }
    }

    fn validate(&self, map_key: &str) -> Result<(), RegistryError> {
        let invalid = |field: &str, reason: String| RegistryError::InvalidContract {
            command_id: self.command_id.clone(),
            field: field.to_owned(),
            reason,
        };
        if self.contract_version != LEAF_COMMAND_CONTRACT_VERSION {
            return Err(invalid(
                "contract_version",
                format!("expected {LEAF_COMMAND_CONTRACT_VERSION}"),
            ));
        }
        validate_command_id(&self.command_id).map_err(|reason| invalid("command_id", reason))?;
        if self.command_id != map_key {
            return Err(invalid("command_id", format!("map key is {map_key}")));
        }
        validate_command_id(&self.equivalence_id)
            .map_err(|reason| invalid("equivalence_id", reason))?;
        if self.equivalence_id != self.command_id {
            return Err(invalid(
                "equivalence_id",
                "must equal the command ID used by the equivalence table".to_owned(),
            ));
        }
        if self.cli_path.is_empty() || self.cli_path.iter().any(|part| part.trim().is_empty()) {
            return Err(invalid(
                "cli_path",
                "path contains an empty component".to_owned(),
            ));
        }
        self.aliases
            .validate("aliases")
            .map_err(|reason| invalid("aliases", reason))?;
        self.help
            .validate("help")
            .map_err(|reason| invalid("help", reason))?;
        self.arguments
            .validate()
            .map_err(|reason| invalid("arguments", reason))?;
        self.input_roles
            .validate()
            .map_err(|reason| invalid("input_roles", reason))?;
        self.outputs
            .validate("outputs")
            .map_err(|reason| invalid("outputs", reason))?;
        self.derived_outputs
            .validate("derived_outputs")
            .map_err(|reason| invalid("derived_outputs", reason))?;
        self.evidence_defaults
            .validate()
            .map_err(|reason| invalid("evidence_defaults", reason))?;
        self.equivalence
            .validate()
            .map_err(|reason| invalid("equivalence", reason))?;
        Ok(())
    }

    fn validate_complete_metadata(&self) -> Result<(), RegistryError> {
        let invalid = |field: &str, reason: &str| RegistryError::InvalidContract {
            command_id: self.command_id.clone(),
            field: field.to_owned(),
            reason: reason.to_owned(),
        };
        for (field, status) in [
            ("aliases", &self.aliases.status),
            ("help", &self.help.status),
            ("arguments", &self.arguments.status),
            ("input_roles", &self.input_roles.status),
            ("outputs", &self.outputs.status),
            ("derived_outputs", &self.derived_outputs.status),
            (
                "evidence_defaults.scope",
                &self.evidence_defaults.scope.status,
            ),
            (
                "evidence_defaults.adapter",
                &self.evidence_defaults.adapter.status,
            ),
        ] {
            if *status != MetadataStatus::Known {
                return Err(invalid(field, "embedded leaf metadata must be known"));
            }
        }
        if self.category == CommandCategory::Unknown {
            return Err(invalid("category", "embedded leaf category must be known"));
        }
        if matches!(self.collect_disposition, CollectDisposition::Unknown) {
            return Err(invalid(
                "collect_disposition",
                "embedded collect disposition must be explicit",
            ));
        }
        if self.outputs.items.is_empty() {
            return Err(invalid(
                "outputs",
                "embedded leaf must declare at least one output",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct LeafCommandManifest {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u32,
    #[serde(deserialize_with = "deserialize_unique_declarations")]
    commands: BTreeMap<String, LeafCommandDeclaration>,
}

#[derive(Debug, Deserialize)]
struct LeafCommandDeclaration {
    command_id: String,
    cli_path: Vec<String>,
    aliases: Vec<String>,
    help: String,
    arguments: Vec<ArgumentContract>,
    category: CommandCategory,
    input_roles: Vec<InputRoleContract>,
    outputs: Vec<OutputContract>,
    derived_outputs: Vec<OutputContract>,
    evidence_defaults: EvidenceDefaultsDeclaration,
    collect_disposition: CollectDisposition,
    collect_parameterized: bool,
    equivalence_id: String,
}

#[derive(Debug, Deserialize)]
struct EvidenceDefaultsDeclaration {
    scope: String,
    adapter: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRegistry {
    pub schema_version: u32,
    pub leaf_manifest_schema_version: u32,
    pub equivalence_schema_version: u32,
    pub source: String,
    pub commands: BTreeMap<String, LeafCommandContract>,
}

impl CommandRegistry {
    pub fn load_embedded() -> Result<Self, RegistryError> {
        let registry = Self::from_json_sources(
            EMBEDDED_LEAF_COMMAND_MANIFEST_JSON,
            EMBEDDED_EQUIVALENCE_JSON,
        )?;
        if registry.len() != EMBEDDED_LEAF_COMMAND_COUNT {
            return Err(RegistryError::UnexpectedEmbeddedCommandCount {
                expected: EMBEDDED_LEAF_COMMAND_COUNT,
                actual: registry.len(),
            });
        }
        Ok(registry)
    }

    pub fn from_json_sources(
        manifest_source: &str,
        equivalence_source: &str,
    ) -> Result<Self, RegistryError> {
        let manifest: LeafCommandManifest = serde_json::from_str(manifest_source)
            .map_err(|error| RegistryError::ManifestJson(error.to_string()))?;
        if manifest.schema_version != LEAF_COMMAND_MANIFEST_SCHEMA_VERSION {
            return Err(RegistryError::UnsupportedLeafManifestSchema {
                expected: LEAF_COMMAND_MANIFEST_SCHEMA_VERSION,
                actual: manifest.schema_version,
            });
        }
        if manifest.schema.trim().is_empty() {
            return Err(RegistryError::InvalidRegistry(
                "leaf manifest $schema is empty".to_owned(),
            ));
        }
        let mut table: EquivalenceTable = serde_json::from_str(equivalence_source)
            .map_err(|error| RegistryError::Json(error.to_string()))?;
        if table.schema_version != EMBEDDED_EQUIVALENCE_SCHEMA_VERSION {
            return Err(RegistryError::UnsupportedEquivalenceSchema {
                expected: EMBEDDED_EQUIVALENCE_SCHEMA_VERSION,
                actual: table.schema_version,
            });
        }
        let manifest_ids = manifest.commands.keys().cloned().collect::<BTreeSet<_>>();
        let equivalence_ids = table.commands.keys().cloned().collect::<BTreeSet<_>>();
        if manifest_ids != equivalence_ids {
            return Err(RegistryError::CommandSetMismatch {
                missing_from_manifest: equivalence_ids.difference(&manifest_ids).cloned().collect(),
                missing_from_equivalence: manifest_ids
                    .difference(&equivalence_ids)
                    .cloned()
                    .collect(),
            });
        }
        let mut commands = BTreeMap::new();
        for (map_key, declaration) in manifest.commands {
            if declaration.command_id != map_key {
                return Err(RegistryError::InvalidContract {
                    command_id: declaration.command_id,
                    field: "command_id".to_owned(),
                    reason: format!("manifest map key is {map_key}"),
                });
            }
            if declaration.equivalence_id != map_key {
                return Err(RegistryError::InvalidContract {
                    command_id: declaration.command_id,
                    field: "equivalence_id".to_owned(),
                    reason: format!("expected {map_key}"),
                });
            }
            let equivalence = table
                .commands
                .remove(&declaration.equivalence_id)
                .ok_or_else(|| RegistryError::InvalidContract {
                    command_id: declaration.command_id.clone(),
                    field: "equivalence_id".to_owned(),
                    reason: "does not resolve to an equivalence record".to_owned(),
                })?;
            commands.insert(
                map_key,
                LeafCommandContract::from_declaration(declaration, equivalence),
            );
        }
        let registry = Self {
            schema_version: COMMAND_REGISTRY_SCHEMA_VERSION,
            leaf_manifest_schema_version: manifest.schema_version,
            equivalence_schema_version: table.schema_version,
            source: "embedded-leaf-command-manifest-v1+command-equivalence-v1".to_owned(),
            commands,
        };
        registry.validate()?;
        for contract in registry.commands.values() {
            contract.validate_complete_metadata()?;
        }
        Ok(registry)
    }

    /// Compatibility loader for tools that only need to inspect an arbitrary
    /// equivalence document.  Since no leaf manifest is supplied, CLI/I-O
    /// metadata remains explicitly unknown and this path is never used for the
    /// embedded product registry.
    pub fn from_equivalence_json(source: &str) -> Result<Self, RegistryError> {
        let table: EquivalenceTable =
            serde_json::from_str(source).map_err(|error| RegistryError::Json(error.to_string()))?;
        if table.schema_version != EMBEDDED_EQUIVALENCE_SCHEMA_VERSION {
            return Err(RegistryError::UnsupportedEquivalenceSchema {
                expected: EMBEDDED_EQUIVALENCE_SCHEMA_VERSION,
                actual: table.schema_version,
            });
        }
        let commands = table
            .commands
            .into_iter()
            .map(|(command_id, equivalence)| {
                let contract =
                    LeafCommandContract::from_equivalence(command_id.clone(), equivalence);
                (command_id, contract)
            })
            .collect();
        let registry = Self {
            schema_version: COMMAND_REGISTRY_SCHEMA_VERSION,
            leaf_manifest_schema_version: 0,
            equivalence_schema_version: table.schema_version,
            source: "embedded-command-equivalence-v1".to_owned(),
            commands,
        };
        registry.validate()?;
        Ok(registry)
    }

    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.schema_version != COMMAND_REGISTRY_SCHEMA_VERSION {
            return Err(RegistryError::UnsupportedRegistrySchema {
                expected: COMMAND_REGISTRY_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        if self.commands.is_empty() {
            return Err(RegistryError::EmptyRegistry);
        }
        if self.source.trim().is_empty() {
            return Err(RegistryError::InvalidRegistry("source is empty".to_owned()));
        }
        let mut cli_paths = BTreeSet::new();
        let mut cli_names = BTreeMap::<String, String>::new();
        for (command_id, contract) in &self.commands {
            contract.validate(command_id)?;
            if contract.collect_parameterized
                && contract.collect_disposition != CollectDisposition::Skipped
            {
                return Err(RegistryError::InvalidContract {
                    command_id: command_id.clone(),
                    field: "collect_parameterized".to_owned(),
                    reason: "only explicitly skipped commands can require host parameters"
                        .to_owned(),
                });
            }
            let cli_path = contract.cli_path.join("\0");
            if !cli_paths.insert(cli_path) {
                return Err(RegistryError::InvalidContract {
                    command_id: command_id.clone(),
                    field: "cli_path".to_owned(),
                    reason: "duplicate CLI path".to_owned(),
                });
            }
            let parent = &contract.cli_path[..contract.cli_path.len() - 1];
            for name in contract
                .cli_path
                .last()
                .into_iter()
                .chain(contract.aliases.values.iter())
            {
                let qualified = parent
                    .iter()
                    .map(String::as_str)
                    .chain(std::iter::once(name.as_str()))
                    .collect::<Vec<_>>()
                    .join("\0");
                if let Some(previous) = cli_names.insert(qualified, command_id.clone())
                    && previous != *command_id
                {
                    return Err(RegistryError::InvalidContract {
                        command_id: command_id.clone(),
                        field: "aliases".to_owned(),
                        reason: format!("CLI name/alias collides with {previous}"),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn by_id(&self, command_id: &str) -> Option<&LeafCommandContract> {
        self.commands.get(command_id)
    }

    pub fn len(&self) -> usize {
        self.commands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    pub fn command_ids(&self) -> impl ExactSizeIterator<Item = &str> {
        self.commands.keys().map(String::as_str)
    }
}

#[derive(Debug, Deserialize)]
struct EquivalenceTable {
    schema_version: u32,
    #[serde(deserialize_with = "deserialize_unique_commands")]
    commands: BTreeMap<String, EquivalenceRecord>,
}

fn deserialize_unique_commands<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, EquivalenceRecord>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueCommandVisitor;

    impl<'de> Visitor<'de> for UniqueCommandVisitor {
        type Value = BTreeMap<String, EquivalenceRecord>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object with unique command IDs")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut commands = BTreeMap::new();
            while let Some((command_id, record)) =
                access.next_entry::<String, EquivalenceRecord>()?
            {
                if commands.insert(command_id.clone(), record).is_some() {
                    return Err(A::Error::custom(format!(
                        "duplicate command ID {command_id}"
                    )));
                }
            }
            Ok(commands)
        }
    }

    deserializer.deserialize_map(UniqueCommandVisitor)
}

fn deserialize_unique_declarations<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, LeafCommandDeclaration>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueDeclarationVisitor;

    impl<'de> Visitor<'de> for UniqueDeclarationVisitor {
        type Value = BTreeMap<String, LeafCommandDeclaration>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object with unique leaf-command declarations")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut commands = BTreeMap::new();
            while let Some((command_id, declaration)) =
                access.next_entry::<String, LeafCommandDeclaration>()?
            {
                if commands.insert(command_id.clone(), declaration).is_some() {
                    return Err(A::Error::custom(format!(
                        "duplicate leaf command ID {command_id}"
                    )));
                }
            }
            Ok(commands)
        }
    }

    deserializer.deserialize_map(UniqueDeclarationVisitor)
}

fn command_cli_path(command_id: &str) -> Vec<String> {
    if let Some(symbol_command) = command_id.strip_prefix("symbols.") {
        vec!["symbols".to_owned(), symbol_command.to_owned()]
    } else {
        vec![command_id.to_owned()]
    }
}

fn validate_command_id(command_id: &str) -> Result<(), String> {
    if command_id.is_empty() {
        return Err("command ID is empty".to_owned());
    }
    if !command_id.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    }) {
        return Err("command ID contains an unsupported character".to_owned());
    }
    Ok(())
}

fn validate_non_empty_unique_strings(values: &[String], field: &str) -> Result<(), String> {
    let mut unique = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(format!("{field} contains an empty value"));
        }
        if !unique.insert(value.as_str()) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}

fn validate_unique_values<T: Ord>(values: &[T], field: &str) -> Result<(), String> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(format!("{field} contains duplicate values"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    Json(String),
    ManifestJson(String),
    EmptyRegistry,
    InvalidRegistry(String),
    UnsupportedRegistrySchema {
        expected: u32,
        actual: u32,
    },
    UnsupportedEquivalenceSchema {
        expected: u32,
        actual: u32,
    },
    UnsupportedLeafManifestSchema {
        expected: u32,
        actual: u32,
    },
    CommandSetMismatch {
        missing_from_manifest: Vec<String>,
        missing_from_equivalence: Vec<String>,
    },
    UnexpectedEmbeddedCommandCount {
        expected: usize,
        actual: usize,
    },
    InvalidContract {
        command_id: String,
        field: String,
        reason: String,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "command registry JSON error: {error}"),
            Self::ManifestJson(error) => {
                write!(formatter, "leaf command manifest JSON error: {error}")
            }
            Self::EmptyRegistry => formatter.write_str("command registry is empty"),
            Self::InvalidRegistry(reason) => {
                write!(formatter, "invalid command registry: {reason}")
            }
            Self::UnsupportedRegistrySchema { expected, actual } => write!(
                formatter,
                "unsupported command registry schema {actual}; expected {expected}"
            ),
            Self::UnsupportedEquivalenceSchema { expected, actual } => write!(
                formatter,
                "unsupported command equivalence schema {actual}; expected {expected}"
            ),
            Self::UnsupportedLeafManifestSchema { expected, actual } => write!(
                formatter,
                "unsupported leaf command manifest schema {actual}; expected {expected}"
            ),
            Self::CommandSetMismatch {
                missing_from_manifest,
                missing_from_equivalence,
            } => write!(
                formatter,
                "leaf manifest/equivalence command sets differ; missing from manifest: {missing_from_manifest:?}; missing from equivalence: {missing_from_equivalence:?}"
            ),
            Self::UnexpectedEmbeddedCommandCount { expected, actual } => write!(
                formatter,
                "embedded command count is {actual}; expected {expected}"
            ),
            Self::InvalidContract {
                command_id,
                field,
                reason,
            } => write!(
                formatter,
                "invalid command contract {command_id}.{field}: {reason}"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}
