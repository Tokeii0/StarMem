//! File-backed registry evidence. No CMHIVE offsets, symbol store or temporary Hive exports.
use std::ops::Range;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{ProbeReport, files};
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::registry::{RegistryHive, RegistryReadGuard};
use crate::system::{credentials, registry as decoder};

const MAX_READ_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CELL_READS: u64 = 200_000;
const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;

pub struct RegistryOptions {
    pub address: u64,
    pub expected_physical: Option<u64>,
    pub source: String,
    pub action: String,
    pub system_address: Option<u64>,
    pub system_physical: Option<u64>,
    pub system_source: String,
    pub key: String,
    pub recurse: bool,
    pub limit: usize,
    pub max_bytes: u64,
}

impl RegistryOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(
                self.action.as_str(),
                "overview"
                    | "printkey"
                    | "hashdump"
                    | "lsadump"
                    | "cachedump"
                    | "userassist"
                    | "amcache"
            ),
            "未知注册表操作"
        );
        ensure!(
            matches!(self.source.as_str(), "cache" | "data")
                && matches!(self.system_source.as_str(), "cache" | "data"),
            "Hive 恢复来源必须是 cache 或 data"
        );
        ensure!(
            (1..=4096).contains(&self.limit),
            "注册表每组记录上限须为 1..4096"
        );
        ensure!(
            (8192..=64 * 1024 * 1024).contains(&self.max_bytes),
            "每个 Hive 读取上限须为 8192..67108864 字节"
        );
        ensure!(self.key.len() <= 4096, "注册表路径过长");
        let credentials = matches!(self.action.as_str(), "hashdump" | "lsadump" | "cachedump");
        ensure!(
            credentials == self.system_address.is_some(),
            "凭据操作必须显式指定 SYSTEM 文件对象；其他操作不接受 SYSTEM 配对"
        );
        ensure!(
            self.system_physical.is_none() || self.system_address.is_some(),
            "SYSTEM 物理地址缺少对应文件对象"
        );
        ensure!(
            self.action == "printkey" || (self.key.is_empty() && !self.recurse),
            "键路径与递归选项仅用于 printkey"
        );
        Ok(())
    }
}

struct RecoveredHive {
    hive: RegistryHive,
    name: String,
    evidence: Value,
}

fn path_parts(name: &str) -> (String, String) {
    let normalized = name.replace('/', "\\").to_lowercase();
    normalized
        .rsplit_once('\\')
        .map(|(parent, leaf)| (parent.to_owned(), leaf.to_owned()))
        .unwrap_or_else(|| (String::new(), normalized))
}

#[allow(clippy::too_many_arguments)]
fn recover(
    image: &MemoryImage,
    kernel: &ProbeReport,
    address: u64,
    expected_physical: Option<u64>,
    source: &str,
    max_bytes: u64,
    guard: &RegistryReadGuard,
    cancel: &CancellationToken,
) -> Result<RecoveredHive> {
    cancel.check_cancelled()?;
    let record = files::inspect_file(image, kernel, address)?;
    ensure!(
        expected_physical.is_none_or(|physical| physical == record.physical_address),
        "Hive FILE_OBJECT 的物理地址与扫描记录不一致"
    );
    let (plan, ranges): (Value, Vec<(u64, u64, u64)>) = if source == "cache" {
        let plan = files::plan_cache(image, kernel, &record, max_bytes, cancel)?;
        let ranges = plan
            .extents
            .iter()
            .map(|e| (e.file_offset, e.length, e.physical_address))
            .collect();
        (serde_json::to_value(plan)?, ranges)
    } else {
        let plan = files::sections::plan_section(image, kernel, &record, false, max_bytes, cancel)?;
        let ranges = plan
            .extents
            .iter()
            .map(|e| (e.file_offset, e.length, e.physical_address))
            .collect();
        (serde_json::to_value(plan)?, ranges)
    };
    let size = plan["logical_size"]
        .as_u64()
        .context("Hive 恢复计划缺少逻辑大小")?;
    ensure!(
        (8192..=max_bytes).contains(&size),
        "Hive 大小不在本次读取预算内"
    );
    let mut bytes = vec![0; size as usize];
    let mut recovered: Vec<Range<usize>> = Vec::new();
    let mut hash = Sha256::new();
    for (offset, length, physical) in ranges {
        let end = offset.checked_add(length).context("Hive 范围溢出")?;
        ensure!(
            length > 0
                && end <= size
                && recovered
                    .last()
                    .is_none_or(|last| last.end <= offset as usize),
            "Hive 恢复范围重叠或越界"
        );
        for (index, chunk) in bytes[offset as usize..end as usize]
            .chunks_mut(65536)
            .enumerate()
        {
            cancel.check_cancelled()?;
            image.read_physical(
                physical
                    .checked_add(index as u64 * 65536)
                    .context("Hive 物理地址溢出")?,
                chunk,
            )?;
            hash.update(&*chunk);
        }
        if let Some(last) = recovered.last_mut()
            && last.end == offset as usize
        {
            last.end = end as usize;
        } else {
            recovered.push(offset as usize..end as usize);
        }
    }
    ensure!(
        recovered
            .first()
            .is_some_and(|range| range.start == 0 && range.end >= 0x1020),
        "Hive 基块或首个 hbin 未完整恢复"
    );
    let stable = u32::from_le_bytes(bytes[0x28..0x2c].try_into()?) as u64;
    ensure!(
        stable >= 4096 && stable.is_multiple_of(4096) && stable + 4096 <= size,
        "Hive 稳定区声明大小无效或超出文件"
    );
    crate::windows::registry::validate_backing_base_block(&bytes[..4096], stable)
        .context("Hive 基块校验失败；当前不执行事务日志重放")?;
    let hive_size = (stable + 4096) as usize;
    bytes.truncate(hive_size);
    recovered.retain(|range| range.start < hive_size);
    for range in &mut recovered {
        range.end = range.end.min(hive_size);
    }
    let valid_bytes: usize = recovered.iter().map(|range| range.len()).sum();
    let evidence_ranges: Vec<_> = recovered
        .iter()
        .map(|range| json!({"offset":range.start,"length":range.len()}))
        .collect();
    let mut hive = RegistryHive::from_recovered_bytes(bytes, recovered)?;
    hive.set_read_guard(guard.clone());
    let root = hive.root()?;
    let evidence = json!({
        "file_object":address,"physical_address":record.physical_address,"device_object":record.device_object,"name":record.name,
        "source":source,"logical_size":size,"hive_bytes":hive_size,"recovered_hive_bytes":valid_bytes,
        "missing_hive_bytes":hive_size-valid_bytes,"acquisition_complete":valid_bytes==hive_size,
        "header_validated":true,"root_name":root.name,"active_hive_verified":false,
        "recovered_file_bytes_sha256":hex::encode(hash.finalize()),
        "hash_scope":"按文件偏移顺序拼接恢复计划中的实际字节；不含缺页补零，包含 Hive 声明范围外已恢复的文件尾部",
        "recovered_hive_ranges":evidence_ranges,"recovery_plan":plan,"source_label":"无符号推断"
    });
    Ok(RecoveredHive {
        hive,
        name: record.name,
        evidence,
    })
}

fn validate_pair(system: &RecoveredHive, target: &RecoveredHive, action: &str) -> Result<()> {
    let (system_parent, system_name) = path_parts(&system.name);
    let (target_parent, target_name) = path_parts(&target.name);
    let expected = if action == "hashdump" {
        "sam"
    } else {
        "security"
    };
    ensure!(
        system_name == "system" && target_name == expected,
        "此操作需要显式选择 SYSTEM 与 {expected} 文件对象"
    );
    ensure!(
        !system_parent.is_empty() && system_parent == target_parent,
        "SYSTEM 与目标 Hive 的文件目录不一致，拒绝自动配对"
    );
    ensure!(
        system.evidence["device_object"] == target.evidence["device_object"],
        "SYSTEM 与目标 Hive 不属于同一设备对象，拒绝按同名目录配对"
    );
    ensure!(
        system.evidence["file_object"] != target.evidence["file_object"],
        "SYSTEM 与目标 Hive 不能是同一对象"
    );
    Ok(())
}

pub(super) fn analyze(
    image: &MemoryImage,
    kernel: &ProbeReport,
    options: &RegistryOptions,
    cancel: &CancellationToken,
) -> Result<Value> {
    options.validate()?;
    let guard = RegistryReadGuard::new(cancel, MAX_CELL_READS, MAX_READ_BYTES);
    let target = recover(
        image,
        kernel,
        options.address,
        options.expected_physical,
        &options.source,
        options.max_bytes,
        &guard,
        cancel,
    )?;
    let source_file = target.name.clone();
    let mut sources = vec![target.evidence.clone()];
    let decoded = (|| -> Result<Value> {
        Ok(if let Some(address) = options.system_address {
            let system = recover(
                image,
                kernel,
                address,
                options.system_physical,
                &options.system_source,
                options.max_bytes,
                &guard,
                cancel,
            )?;
            validate_pair(&system, &target, &options.action)?;
            sources.push(system.evidence);
            match options.action.as_str() {
                "hashdump" => serde_json::to_value(credentials::hashdump_from_hives(
                    &system.hive,
                    &target.hive,
                    options.limit,
                )?)?,
                "lsadump" => serde_json::to_value(credentials::lsadump_from_hives(
                    &system.hive,
                    &target.hive,
                    options.limit,
                )?)?,
                "cachedump" => serde_json::to_value(credentials::cachedump_from_hives(
                    &system.hive,
                    &target.hive,
                    options.limit,
                )?)?,
                _ => anyhow::bail!("不支持的配对操作"),
            }
        } else if matches!(options.action.as_str(), "userassist" | "amcache") {
            let (_, leaf) = path_parts(&source_file);
            let expected = if options.action == "userassist" {
                "ntuser.dat"
            } else {
                "amcache.hve"
            };
            ensure!(
                leaf == expected,
                "{} 需要选择 {} 文件对象",
                options.action,
                expected
            );
            if options.action == "userassist" {
                serde_json::to_value(decoder::userassist_from_hive(
                    target.hive,
                    &source_file,
                    options.limit,
                ))?
            } else {
                serde_json::to_value(decoder::amcache_from_hive(
                    target.hive,
                    &source_file,
                    options.limit,
                ))?
            }
        } else if options.action == "printkey" {
            serde_json::to_value(decoder::print_registry_hive(
                target.hive,
                &source_file,
                &options.key,
                options.recurse,
                options.limit,
            ))?
        } else {
            let (_, leaf) = path_parts(&source_file);
            let kind = if leaf == "ntuser.dat" {
                "ntuser"
            } else {
                &leaf
            };
            let mut data = serde_json::to_value(decoder::analyze_registry_file(
                target.hive,
                kind,
                &source_file,
            )?)?;
            let object = data.as_object_mut().context("注册表摘要必须为对象")?;
            object.remove("hives");
            let scalar_keys: Vec<_> = object
                .iter()
                .filter(|(key, value)| {
                    !value.is_array() && *key != "available" && !key.ends_with("complete")
                })
                .map(|(key, _)| key.clone())
                .collect();
            let records: Vec<_> = scalar_keys
                .into_iter()
                .filter_map(|key| {
                    object
                        .remove(&key)
                        .filter(|value| !value.is_null())
                        .map(|value| json!({"field":key,"value":value}))
                })
                .collect();
            object.insert("records".into(), json!(records));
            data
        })
    })();
    // Existing artifact decoders use best-effort reads. A swallowed budget or cancellation
    // failure must never become an apparently successful empty report.
    guard.check()?;
    cancel.check_cancelled()?;
    let mut result = decoded?;
    let object = result.as_object_mut().context("注册表报告必须为对象")?;
    let decoder_complete = object.get("complete").cloned().unwrap_or(json!(false));
    object.insert("decoder_complete".into(), decoder_complete);
    object.insert("complete".into(), json!(false));
    object.insert("action".into(), json!(options.action));
    object.insert("source_file".into(), json!(source_file));
    object.insert("active_hive_verified".into(), json!(false));
    object.insert("hive_sources".into(), json!(sources));
    object.insert("pairing_basis".into(), json!(if options.system_address.is_some() { "显式选择对象、同一镜像、同一设备对象及相同文件目录；未证明来自同一写入时刻或活动 CMHIVE" } else { "单个显式选择的文件对象" }));
    object.insert("limits".into(), json!({"per_hive_bytes":options.max_bytes,"cell_reads":MAX_CELL_READS,"cumulative_read_bytes":MAX_READ_BYTES,"per_section_records":options.limit,"record_json_bytes":MAX_REPORT_BYTES}));
    let mut report_bytes = 0usize;
    let mut truncated = Vec::new();
    for (name, value) in object.iter_mut() {
        if matches!(
            name.as_str(),
            "hive_sources" | "warnings" | "usb_source_warnings"
        ) {
            continue;
        }
        let Some(rows) = value.as_array_mut() else {
            continue;
        };
        let mut retained = 0;
        for row in rows.iter_mut().take(options.limit) {
            cancel.check_cancelled()?;
            if let Some(row) = row.as_object_mut() {
                row.insert("hive_file_object".into(), json!(options.address));
                row.insert("system_file_object".into(), json!(options.system_address));
                row.insert("source_file".into(), json!(source_file));
                row.insert("source_label".into(), json!("无符号推断"));
            }
            let bytes = serde_json::to_vec(row)?.len();
            if report_bytes + bytes > MAX_REPORT_BYTES {
                break;
            }
            report_bytes += bytes;
            retained += 1;
        }
        if retained < rows.len() {
            rows.truncate(retained);
            truncated.push(name.clone());
        }
    }
    let warnings = object
        .entry("warnings")
        .or_insert(json!([]))
        .as_array_mut()
        .context("注册表告警必须为数组")?;
    warnings.push(json!("仅解析所选文件已恢复的稳定 Hive 字节；缺页不能补全，未核验活动 CMHIVE、易失性键、事务日志或内存压缩页。凭据配对不证明两个 Hive 同时有效。"));
    if !truncated.is_empty() {
        warnings.push(json!(
            "部分记录组达到本次条数或报告字节上限，请缩小键路径或单独读取"
        ));
    }
    object.insert("truncated_sections".into(), json!(truncated));
    Ok(result)
}

#[cfg(test)]
mod tests;
