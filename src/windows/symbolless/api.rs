//! Explicit symbol-free session; never opens an AnalysisSession or a symbol store.
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    ProbeReport, ProcessContextOptions, RegistryOptions, files, probe, probe_system,
    process_context, registry, system,
};
use super::{ProcessModulesOptions, process_modules};
use crate::cancellation::CancellationToken;
use crate::evidence::{SourceIdentity, source_identity_for_memory_image};
use crate::image::{ImageOpenOptions, MemoryImage};
use crate::output_policy::OutputPolicy;

pub struct SymbollessSession {
    image: MemoryImage,
    kernel: ProbeReport,
    identity: SourceIdentity,
}

pub struct RecoveryOptions {
    pub address: u64,
    pub expected_physical: Option<u64>,
    pub source: String,
    pub max_bytes: u64,
    pub output: PathBuf,
}

impl SymbollessSession {
    pub fn open_system_cancellable(
        path: &Path,
        options: ImageOpenOptions,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        cancel.check_cancelled()?;
        let image = MemoryImage::open_with_options(path, options)?;
        Self::from_image_mode(image, None, cancel)
    }

    pub fn open_cancellable(
        path: &Path,
        options: ImageOpenOptions,
        process_limit: usize,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        cancel.check_cancelled()?;
        let image = MemoryImage::open_with_options(path, options)?;
        Self::from_image(image, process_limit, cancel)
    }

    pub fn from_image(
        image: MemoryImage,
        process_limit: usize,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        Self::from_image_mode(image, Some(process_limit), cancel)
    }

    fn from_image_mode(
        image: MemoryImage,
        process_limit: Option<usize>,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        cancel.check_cancelled()?;
        let identity = source_identity_for_memory_image(image.path(), &image)?;
        let kernel = match process_limit {
            Some(limit) => probe(&image, limit, cancel)?,
            None => probe_system(&image, cancel)?,
        };
        let session = Self {
            image,
            kernel,
            identity,
        };
        session.verify_source(cancel)?;
        Ok(session)
    }

    pub fn image(&self) -> &MemoryImage {
        &self.image
    }

    fn verify_source(&self, cancel: &CancellationToken) -> Result<()> {
        cancel.check_cancelled()?;
        ensure!(
            self.identity == source_identity_for_memory_image(self.image.path(), &self.image)?,
            "无符号分析期间镜像或附加来源身份已改变"
        );
        cancel.check_cancelled()
    }

    fn report(&self, mut value: Value) -> Result<Value> {
        let object = value.as_object_mut().context("无符号报告必须为对象")?;
        object.insert("analysis_mode".into(), json!("symbolless"));
        object.insert("source_label".into(), json!("无符号推断"));
        object.insert("image_path".into(), json!(self.image.path()));
        object.insert("experimental".into(), json!(true));
        object.insert("external_debug_symbols_used".into(), json!(false));
        object.entry("available").or_insert(json!(true));
        object.insert(
            "source_identity".into(),
            serde_json::to_value(&self.identity)?,
        );
        object.insert("engine_build_id".into(), json!(crate::BUILD_ID));
        object.insert("capabilities".into(), json!({
            "system_information": {"status":"conditional", "reason":"读取目标导出和共享页；字段缺失、冲突及估算分别标记"},
            "process_list": {"status":if self.kernel.processes.is_empty() { "not_run" } else { "available" }, "exhaustive":false},
            "process_context": {"status":"conditional", "reason":"需要目标 PEB 访问函数、经校验的进程页表和原生 AMD64 用户映像；命令行和环境变量分别保留读取状态"},
            "process_modules": {"status":"conditional", "reason":"原生 AMD64 用户加载器双向链；逐进程标注缺页、截断及 PE 核验状态，不覆盖 VAD 或隐藏模块"},
            "filescan": {"status":"conditional", "reason":"需要可读的文件名称、设备对象及内核页表映射"},
            "cache_recovery": {"status":"conditional", "reason":"逐对象验证 File 类型、池分配、缓存归属和驻留页面"},
            "data_section_recovery": {"status":"conditional", "reason":"需要唯一子节布局及文件、段和控制区反向归属；仅恢复驻留 PTE"},
            "image_section_recovery": {"status":"conditional", "reason":"按子节文件偏移恢复驻留内容，不包含未映射的证书或覆盖数据"},
            "registry_files": {"status":"conditional", "reason":"显式选择 Hive 文件对象；只解析经校验的稳定数据，凭据另需同目录 SYSTEM；未核验活动注册表"},
            "automatic_fallback": {"status":"disabled"}
        }));
        for key in [
            "processes",
            "records",
            "environment",
            "extents",
            "process_sources",
        ] {
            if let Some(rows) = object.get_mut(key).and_then(Value::as_array_mut) {
                for row in rows.iter_mut().filter_map(Value::as_object_mut) {
                    row.insert("source_label".into(), json!("无符号推断"));
                }
            }
        }
        Ok(value)
    }

    pub fn processes(&self, cancel: &CancellationToken) -> Result<Value> {
        self.verify_source(cancel)?;
        ensure!(
            !self.kernel.processes.is_empty(),
            "系统信息会话未执行进程枚举，请使用 symbolless.pslist"
        );
        self.report(serde_json::to_value(&self.kernel)?)
    }

    pub fn system_info(&self, cancel: &CancellationToken) -> Result<Value> {
        self.verify_source(cancel)?;
        let result = system::analyze(&self.image, &self.kernel, cancel)?;
        self.verify_source(cancel)?;
        self.report(result)
    }

    pub fn process_context(
        &self,
        options: &ProcessContextOptions,
        cancel: &CancellationToken,
    ) -> Result<Value> {
        self.verify_source(cancel)?;
        let result = process_context::analyze(&self.image, &self.kernel, options, cancel)?;
        self.verify_source(cancel)?;
        self.report(result)
    }

    pub fn process_modules(
        &self,
        options: &ProcessModulesOptions,
        cancel: &CancellationToken,
    ) -> Result<Value> {
        options.validate()?;
        self.verify_source(cancel)?;
        let result = process_modules::analyze(&self.image, &self.kernel, options, cancel)?;
        self.verify_source(cancel)?;
        self.report(result)
    }

    pub fn registry(&self, options: &RegistryOptions, cancel: &CancellationToken) -> Result<Value> {
        options.validate()?;
        self.verify_source(cancel)?;
        let result = registry::analyze(&self.image, &self.kernel, options, cancel)?;
        self.verify_source(cancel)?;
        self.report(result)
    }

    pub fn files(
        &self,
        limit: usize,
        filter: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<Value> {
        let result = files::scan(&self.image, &self.kernel, limit, filter, cancel)?;
        self.verify_source(cancel)?;
        self.report(serde_json::to_value(result)?)
    }

    /// Publish a binary and its recovery sidecar using the shared output policy.
    /// The caller validates its request/image generation before each publication.
    /// New targets are required so a cancelled two-file publication can roll back
    /// only files owned by this call without removing earlier user evidence.
    pub fn recover_file(
        &self,
        options: &RecoveryOptions,
        cancel: &CancellationToken,
        before_publish: impl Fn() -> Result<()>,
    ) -> Result<Value> {
        ensure!(
            matches!(options.source.as_str(), "cache" | "data" | "image"),
            "无符号恢复来源必须是 cache、data 或 image"
        );
        self.verify_source(cancel)?;
        before_publish()?;
        let record = files::inspect_file(&self.image, &self.kernel, options.address)?;
        ensure!(
            options
                .expected_physical
                .is_none_or(|expected| expected == record.physical_address),
            "所选 FILE_OBJECT 的物理地址与扫描记录不一致"
        );
        let (plan, ranges) = if options.source == "cache" {
            let plan = files::plan_cache(
                &self.image,
                &self.kernel,
                &record,
                options.max_bytes,
                cancel,
            )?;
            let ranges: Vec<_> = plan
                .extents
                .iter()
                .map(|e| (e.file_offset, e.length, e.physical_address))
                .collect();
            (serde_json::to_value(plan)?, ranges)
        } else {
            let plan = files::sections::plan_section(
                &self.image,
                &self.kernel,
                &record,
                options.source == "image",
                options.max_bytes,
                cancel,
            )?;
            let ranges = plan
                .extents
                .iter()
                .map(|e| (e.file_offset, e.length, e.physical_address))
                .collect();
            (serde_json::to_value(plan)?, ranges)
        };
        let logical_size = plan["logical_size"]
            .as_u64()
            .context("恢复计划缺少逻辑大小")?;
        let output = if plan["complete"] == true {
            options.output.clone()
        } else {
            sibling(&options.output, ".partial")
        };
        let sidecar = sibling(&output, ".recovery.json");
        let mut policy = OutputPolicy::new(false);
        for source in self.image.sources() {
            policy.protect_file("image_or_sidecar", &source.path);
        }
        policy.output_file("requested_output", &options.output);
        if output != options.output {
            policy.output_file("partial_output", &output);
        }
        policy.output_file("recovery_sidecar", &sidecar);
        policy.preflight()?;
        let mut recovered_hash = String::new();
        let mut output_hash = String::new();
        let validate = || {
            self.verify_source(cancel)?;
            before_publish()
        };
        policy.write_file_atomic_validated(
            &output,
            |file| {
                recovered_hash =
                    files::write_ranges(&self.image, logical_size, &ranges, file, cancel)?;
                Ok(())
            },
            |staged| {
                output_hash = sha256(staged, cancel)?;
                validate()
            },
        )?;
        let mut sidecar_published = false;
        let publish = (|| {
            let value = self.report(json!({
                "complete": plan["complete"], "file_object":record.file_object, "name":record.name,
                "source":options.source, "output":output, "manifest":sidecar,
                "logical_size":logical_size, "recovered_bytes":plan["recovered_bytes"],
                "missing_bytes":plan["missing_bytes"], "extents":plan["extents"], "missing_ranges":plan["missing_ranges"],
                "output_sha256":output_hash, "recovered_bytes_sha256":recovered_hash,
                "warnings":plan["warnings"], "plan":plan,
            }))?;
            policy.write_file_atomic_validated(
                &sidecar,
                |file| {
                    serde_json::to_writer_pretty(file, &value)?;
                    Ok(())
                },
                |_| validate(),
            )?;
            sidecar_published = true;
            validate()?;
            Ok(value)
        })();
        if let Err(error) = publish {
            // Only outputs successfully created by this call are registered for
            // rollback. The ordinary publication policy continues to forbid replacement.
            let mut rollback = OutputPolicy::new(true);
            for source in self.image.sources() {
                rollback.protect_file("image_or_sidecar", &source.path);
            }
            rollback.output_file("created_binary", &output);
            if sidecar_published {
                rollback.output_file("created_manifest", &sidecar);
            }
            if sidecar_published {
                rollback
                    .remove_owned_file(&sidecar)
                    .context("取消发布后清理本次恢复说明失败")?;
            }
            rollback
                .remove_owned_file(&output)
                .context("取消发布后清理本次恢复文件失败")?;
            return Err(error);
        }
        publish
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn sha256(path: &Path, cancel: &CancellationToken) -> Result<String> {
    let mut input = File::open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        cancel.check_cancelled()?;
        let n = input.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
