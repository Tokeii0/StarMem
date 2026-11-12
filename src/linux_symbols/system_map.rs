//! Complete a validated System.map with real types from an exact local ISF.
//! Addresses are never inferred from a similar release and types are never invented.
use super::*;
use crate::cancellation::CancellationToken;
use crate::linux_system_map::{LinuxSystemMap, PAGE_TABLE_SYMBOLS};

pub(crate) struct CompletedSystemMap {
    pub table: Arc<LinuxIsf>,
    pub source: PathBuf,
    pub source_sha256: String,
    pub addresses_verified: usize,
}

pub(crate) fn complete(
    image: &MemoryImage,
    store: &SymbolStore,
    map: &LinuxSystemMap,
    banner: &str,
    cancellation: &CancellationToken,
) -> Result<Option<CompletedSystemMap>> {
    cancellation.check_cancelled()?;
    // Use the existing exact-banner resolver, including its ambiguity rejection.
    // Local roots include previously downloaded/installed ISFs. This path does not
    // start a compiler or fetch an arbitrary kernel package based on a release name.
    let resolution = resolve_linux_isf(&store.without_linux_selection(), &[banner.to_owned()])?;
    cancellation.check_cancelled()?;
    let Some(source) = resolution.table else {
        return Ok(None);
    };
    let (bytes, digest) = read_linux_isf_json(source.path(), source.path())?;
    ensure!(
        digest == source.file_sha256(),
        "类型来源 ISF 在解析后已变化"
    );
    let mut document: serde_json::Value = serde_json::from_slice(&bytes)?;
    drop(bytes);
    let user_type_count = document["user_types"]
        .as_object()
        .map_or(0, serde_json::Map::len);
    let addresses_verified = merge_map(&mut document, &source, map, banner, cancellation)?;
    let generated = serde_json::to_vec(&document)?;
    ensure!(
        generated.len() as u64 <= MAX_ISF_BYTES,
        "生成的 Linux ISF 超过安全上限"
    );
    drop(document);
    let generated_sha256 = sha256_hex(&generated);
    // Keep derived tables outside automatic discovery: the source table and the
    // explicit map together select this immutable, versioned derivation.
    let root = store
        .writable_root()
        .join("linux-system-map-isf")
        .join("v1")
        .join(&map.identity.sha256)
        .join(&digest);
    let path = root.join("symbols.json");
    let provenance_path = root.join("provenance.json");
    let provenance = serde_json::json!({
        "schema_version": 1, "method": "exact_isf_types_with_verified_system_map",
        "banner": banner, "system_map_sha256": map.identity.sha256,
        "type_source_isf_sha256": digest, "isf_sha256": generated_sha256,
        "type_source_producer": source.producer(), "user_type_count": user_type_count,
        "addresses_verified": addresses_verified,
        "symbol_count": map.identity.symbol_count,
        "runtime_validation": "performed_by_each_analysis_session_before_use"
    });
    let mut policy = OutputPolicy::new(true);
    for input in image.sources() {
        policy.protect_file("memory_image_or_sidecar", &input.path);
    }
    policy.protect_file("system_map", &map.path);
    policy.protect_file("type_source_isf", source.path());
    policy.output(OutputTarget::file("generated_linux_isf", &path));
    policy.output(OutputTarget::file("linux_isf_provenance", &provenance_path));
    policy.preflight()?;
    cancellation.check_cancelled()?;
    if !load_linux_isf(&path).is_ok_and(|table| table.file_sha256() == generated_sha256) {
        policy.write_file_atomic_validated(
            &path,
            |output| {
                use std::io::Write;
                output.write_all(&generated)?;
                Ok(())
            },
            |staged| {
                cancellation.check_cancelled()?;
                let table = load_linux_isf_from_storage(staged, &path, legacy_features())?;
                ensure!(
                    table.file_sha256() == generated_sha256 && table.banner() == banner,
                    "生成的 Linux ISF 内容校验失败"
                );
                Ok(())
            },
        )?;
    }
    cancellation.check_cancelled()?;
    policy.write_bytes_atomic(&provenance_path, &serde_json::to_vec_pretty(&provenance)?)?;
    cancellation.check_cancelled()?;
    let table = load_linux_isf(&path)?;
    ensure!(
        table.file_sha256() == generated_sha256,
        "生成的 Linux ISF 在发布后已变化"
    );
    Ok(Some(CompletedSystemMap {
        table: Arc::new(table),
        source: source.path().to_owned(),
        source_sha256: digest,
        addresses_verified,
    }))
}

fn merge_map(
    document: &mut serde_json::Value,
    table: &LinuxIsf,
    map: &LinuxSystemMap,
    banner: &str,
    cancellation: &CancellationToken,
) -> Result<usize> {
    // complete() verified these bytes against the parsed table's SHA-256. Reuse
    // that compact table instead of duplicating the entire type document in RAM.
    ensure!(
        table.banner() == banner,
        "System.map 类型来源的完整 banner 与镜像不符"
    );
    let missing = table.requirement_gaps_for(&[LinuxSymbolFeature::Task].into_iter().collect());
    ensure!(
        missing.is_empty(),
        "System.map 类型来源缺少有效 task_struct：{missing:?}"
    );
    let symbols = document
        .get("symbols")
        .and_then(serde_json::Value::as_object)
        .context("ISF 缺少 symbols 对象")?;
    let address = |name: &str| symbols.get(name)?.get("address")?.as_u64();
    for name in ["linux_banner", "init_task", "_stext"] {
        ensure!(
            map.address(name) == address(name),
            "System.map 与类型来源的 {name} 地址不符"
        );
    }
    ensure!(
        PAGE_TABLE_SYMBOLS
            .iter()
            .any(|name| map.address(name).is_some() && map.address(name) == address(name)),
        "System.map 与类型来源没有一致的内核页表符号"
    );
    let mut merged = serde_json::Map::new();
    let mut verified = 0;
    for (index, (name, linked_address)) in map.symbols().enumerate() {
        if index % 1024 == 0 {
            cancellation.check_cancelled()?;
        }
        let value = if let Some(original) = symbols.get(name) {
            ensure!(
                address(name) == Some(linked_address),
                "System.map 与类型来源的 {name} 地址不符，拒绝混合不同内核构建"
            );
            verified += 1;
            original.clone()
        } else {
            serde_json::json!({"address": linked_address})
        };
        merged.insert(name.to_owned(), value);
    }
    document["symbols"] = serde_json::Value::Object(merged);
    // Preserve all real type definitions, enum values and banner bytes unchanged.
    document["metadata"]["linux"]["symbols"] = serde_json::json!([{
        "kind": "system-map", "name": "System.map",
        "hash_type": "sha256", "hash_value": map.identity.sha256
    }]);
    document["metadata"]["producer"] = serde_json::json!({
        "name": "StarMem System.map ISF completion", "version": env!("CARGO_PKG_VERSION")
    });
    Ok(verified)
}
