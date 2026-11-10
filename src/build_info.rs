use serde::Serialize;

/// 可复现发布与宿主集成所需的编译身份。
#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    pub version: &'static str,
    pub build_id: &'static str,
    pub git_commit: Option<&'static str>,
    pub dirty: Option<bool>,
    pub rust_target: &'static str,
    pub features: Vec<&'static str>,
    pub host_api_schema_version: u32,
    pub evidence_schema_version: u32,
    pub command_registry_schema_version: u32,
    pub leaf_command_manifest_schema_version: u32,
    pub integration_api_version: u32,
    pub sqlite_schema_version: i64,
    pub raw_object_schema_version: u32,
}

pub fn current_build_info() -> BuildInfo {
    BuildInfo {
        version: crate::VERSION,
        build_id: crate::BUILD_ID,
        git_commit: nonempty(option_env!("STARMEM_GIT_COMMIT")),
        dirty: match option_env!("STARMEM_GIT_DIRTY") {
            Some("true") => Some(true),
            Some("false") => Some(false),
            _ => None,
        },
        rust_target: env!("STARMEM_RUST_TARGET"),
        features: env!("STARMEM_FEATURES")
            .split(',')
            .filter(|feature| !feature.is_empty())
            .collect(),
        host_api_schema_version: crate::api::HOST_API_SCHEMA_VERSION,
        evidence_schema_version: crate::EVIDENCE_SCHEMA_VERSION,
        command_registry_schema_version: crate::command_registry::COMMAND_REGISTRY_SCHEMA_VERSION,
        leaf_command_manifest_schema_version:
            crate::command_registry::LEAF_COMMAND_MANIFEST_SCHEMA_VERSION,
        integration_api_version: crate::INTEGRATION_API_VERSION,
        sqlite_schema_version: crate::database::DATABASE_SCHEMA_VERSION,
        raw_object_schema_version: crate::RAW_OBJECT_SCHEMA_VERSION,
    }
}

fn nonempty(value: Option<&'static str>) -> Option<&'static str> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_all_public_contract_versions() {
        let info = current_build_info();
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.build_id.len(), 64);
        assert!(!info.rust_target.is_empty());
        assert_eq!(info.evidence_schema_version, 1);
        assert_eq!(info.host_api_schema_version, 1);
        assert_eq!(info.command_registry_schema_version, 2);
        assert_eq!(info.leaf_command_manifest_schema_version, 1);
        assert_eq!(info.integration_api_version, 5);
        assert!(info.sqlite_schema_version >= 3);
    }
}
