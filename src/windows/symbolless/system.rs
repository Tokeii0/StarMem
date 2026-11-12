//! Bounded system metadata from the target PE and the public x64 shared-data ABI.
//! No registry reconstruction, host OS queries, PDBs or version-offset database.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{Value, json};

use super::{ProbeReport, export, pe_size, u32_at};
use crate::address::X64AddressSpace;
use crate::cancellation::CancellationToken;
use crate::image::{ImageFormat, MemoryImage};

const SHARED: u64 = 0xffff_f780_0000_0000;
const SHARED_SIZE: usize = 0x274;
const TICKS: u64 = 10_000_000;

#[derive(Serialize)]
pub struct SystemField {
    pub field: &'static str,
    pub label: &'static str,
    pub value: Value,
    pub raw_value: Value,
    pub evidence_status: &'static str,
    pub method: String,
    pub virtual_address: Option<u64>,
    pub physical_address: Option<u64>,
    pub note: String,
}

impl SystemField {
    fn new(field: &'static str, label: &'static str, value: Value, method: &str) -> Self {
        Self {
            field,
            label,
            evidence_status: if value.is_null() {
                "unavailable"
            } else {
                "observed"
            },
            raw_value: value.clone(),
            value,
            method: method.into(),
            virtual_address: None,
            physical_address: None,
            note: String::new(),
        }
    }

    fn at(mut self, space: &X64AddressSpace<'_>, address: u64) -> Self {
        self.virtual_address = Some(address);
        self.physical_address = space.translate(address).ok();
        self
    }

    fn note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }
}

fn root(bytes: &[u8]) -> Result<String> {
    let words: Vec<_> = bytes[0x30..0x238]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let end = words
        .iter()
        .position(|v| *v == 0)
        .context("系统目录副本缺少终止符")?;
    let value = String::from_utf16(&words[..end]).context("系统目录副本不是有效 UTF-16")?;
    let path = value.as_bytes();
    ensure!(
        path.len() > 3
            && path[0].is_ascii_alphabetic()
            && &path[1..3] == b":\\"
            && !value.chars().any(char::is_control),
        "系统目录副本不是绝对 Windows 路径"
    );
    Ok(value)
}

fn shared_data(space: &X64AddressSpace<'_>) -> Result<[u8; SHARED_SIZE]> {
    let mut bytes = [0; SHARED_SIZE];
    space
        .read_virtual(SHARED, &mut bytes)
        .context("共享数据页未完整驻留")?;
    ensure!(
        (5..=20).contains(&u32_at(&bytes, 0x26c)) && u32_at(&bytes, 0x270) <= 99,
        "共享页 NT 主/次版本不符合支持范围"
    );
    ensure!(
        bytes[0x268] == 1 && (1..=3).contains(&u32_at(&bytes, 0x264)),
        "共享页产品类型及有效标志不一致"
    );
    root(&bytes)?;
    Ok(bytes)
}

fn ksystem_time(bytes: &[u8], at: usize) -> Option<u64> {
    let high = u32_at(bytes, at + 4);
    (high == u32_at(bytes, at + 8)).then(|| ((high as u64) << 32) | u32_at(bytes, at) as u64)
}

fn timestamp(value: u64) -> Option<String> {
    if value == 0 {
        return None;
    }
    let seconds = i64::try_from(value / TICKS)
        .ok()?
        .checked_sub(11_644_473_600)?;
    let time = DateTime::<Utc>::from_timestamp(seconds, ((value % TICKS) * 100) as u32)?;
    (1601..=9999)
        .contains(&time.year())
        .then(|| time.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

pub(super) fn analyze(
    image: &MemoryImage,
    kernel: &ProbeReport,
    cancel: &CancellationToken,
) -> Result<Value> {
    cancel.check_cancelled()?;
    let space = X64AddressSpace::new(image, kernel.kernel_dtb)?;
    let mut records = Vec::new();
    let mut warnings = vec![
        "实验性 AMD64 系统信息：只解释已声明的共享页 ABI 和目标 PE 导出；不读取外部符号表。".to_owned(),
        "系统目录和产品类型是共享页副本；主机名、产品版本名称、补丁修订号及注册表信息尚未恢复。".to_owned(),
        "采集到的物理字节数不等于机器安装内存；启动时间由系统时间减中断时间估算，可能受校时和采集时间差影响。".to_owned(),
    ];
    let format = match image.format() {
        ImageFormat::Raw => "raw",
        ImageFormat::VmwareVmem { .. } => "vmware_vmem",
        ImageFormat::WindowsCrashDump64(_) => "windows_crash_dump64",
        ImageFormat::ExpertWitness { .. } => "ewf",
        ImageFormat::ElfPhysicalCore { .. } => "elf_core",
        ImageFormat::XenElf64(_) => "xen_elf64",
        ImageFormat::AvmlV2 { .. } => "avml_v2",
        ImageFormat::QevmV3 { .. } => "qevm_v3",
        ImageFormat::Lime { .. } => "lime",
    };
    for (field, label, value) in [
        ("image_format", "镜像格式", json!(format)),
        (
            "image_file_bytes",
            "镜像文件大小（字节）",
            json!(image.file_len()),
        ),
        (
            "image_logical_bytes",
            "镜像逻辑大小（字节）",
            json!(image.logical_len()),
        ),
        (
            "mapped_physical_bytes",
            "已映射物理内容（字节）",
            json!(image.mapped_bytes()),
        ),
        (
            "physical_span_count",
            "物理映射区间数",
            json!(image.spans().len()),
        ),
    ] {
        records.push(SystemField::new(
            field,
            label,
            value,
            "镜像容器与物理映射元数据",
        ));
    }
    records.push(
        SystemField::new(
            "architecture",
            "内核架构",
            json!("AMD64 / x86_64"),
            "目标内核 PE Machine=0x8664、PE32+ 与 x64 页表交叉校验",
        )
        .at(&space, kernel.kernel_base),
    );
    for (field, label, address) in [
        ("kernel_base", "内核基址", kernel.kernel_base),
        ("system_eprocess", "System 进程对象", kernel.system_eprocess),
    ] {
        records.push(
            SystemField::new(
                field,
                label,
                json!(format!("{address:#x}")),
                "目标导出、System PID/名称及页表关系校验",
            )
            .at(&space, address),
        );
    }
    records.push(
        SystemField::new(
            "kernel_dtb",
            "内核页表物理基址",
            json!(format!("{:#x}", kernel.kernel_dtb)),
            kernel.bootstrap_method,
        )
        .note("物理地址；不是镜像文件偏移"),
    );

    let shared = shared_data(&space);
    let shared_error = shared.as_ref().err().map(|e| format!("{e:#}"));
    if let Some(error) = &shared_error {
        warnings.push(error.clone());
    }
    let bytes = shared.as_ref().ok();
    let major = bytes.map(|b| u32_at(b, 0x26c));
    for (field, label, at, value) in [
        ("nt_major_version", "NT 主版本", 0x26c, json!(major)),
        (
            "nt_minor_version",
            "NT 次版本",
            0x270,
            json!(bytes.map(|b| u32_at(b, 0x270))),
        ),
        (
            "system_root_copy",
            "系统目录（共享页副本）",
            0x30,
            json!(bytes.and_then(|b| root(b).ok())),
        ),
        (
            "product_type_copy",
            "产品类型（共享页副本）",
            0x264,
            json!(bytes.map(|b| match u32_at(b, 0x264) {
                1 => "workstation",
                2 => "domain_controller",
                _ => "server",
            })),
        ),
    ] {
        records.push(
            SystemField::new(
                field,
                label,
                value,
                "KUSER_SHARED_DATA 固定 ABI；版本、产品标志与系统目录联合校验",
            )
            .at(&space, SHARED + at)
            .note(shared_error.clone().unwrap_or_default()),
        );
    }

    // NtBuildNumber at +0x260 was reserved on older NT; never interpret it there.
    let shared_build = bytes
        .filter(|_| major.is_some_and(|v| v >= 10))
        .map(|b| u32_at(b, 0x260))
        .filter(|v| (1000..=65_535).contains(v));
    let export_build = (|| -> Result<(u64, u32)> {
        let size = pe_size(&space, kernel.kernel_base)?;
        let address = export(
            image,
            kernel.kernel_dtb,
            kernel.kernel_base,
            size,
            "NtBuildNumber",
        )?;
        let mut raw = [0; 4];
        space.read_virtual(address, &mut raw)?;
        let value = u32::from_le_bytes(raw);
        ensure!(
            (1000..=65_535).contains(&(value & 0xffff)),
            "内核导出 Build 值无效"
        );
        Ok((address, value))
    })();
    let exported = export_build.as_ref().ok().map(|(_, raw)| raw & 0xffff);
    let conflict = matches!((shared_build, exported), (Some(a), Some(b)) if a != b);
    let build = if conflict {
        None
    } else {
        exported.or(shared_build)
    };
    let mut build_row = SystemField::new(
        "nt_build_number",
        "NT Build",
        json!(build),
        "目标 PE 导出 NtBuildNumber；NT >= 10 时与共享页 +0x260 交叉比对",
    );
    build_row.raw_value =
        json!({"export":export_build.as_ref().ok().map(|(_, raw)| *raw), "shared":shared_build});
    if let Ok((address, _)) = &export_build {
        build_row = build_row.at(&space, *address);
    } else if shared_build.is_some() {
        build_row = build_row.at(&space, SHARED + 0x260);
    }
    if conflict {
        build_row.evidence_status = "conflict";
        build_row.note = "内核导出与共享页 Build 冲突，保留原始值且不选定版本".into();
        warnings.push(build_row.note.clone());
    } else if let Err(error) = &export_build {
        build_row.note =
            format!("内核 Build 导出不可读：{error:#}；共享页 Build 只在 NT >= 10 时使用");
    }
    records.push(build_row);

    let clock_value = |offset| bytes.and_then(|b| ksystem_time(b, offset));
    let system_time = clock_value(0x14).filter(|v| timestamp(*v).is_some());
    let interrupt = clock_value(0x8).filter(|v| {
        *v < 100 * 366 * 86400 * TICKS && system_time.is_none_or(|system| *v <= system)
    });
    let bias = clock_value(0x20)
        .map(|v| v as i64)
        .filter(|v| v.unsigned_abs() <= 86400 * TICKS && *v % 600_000_000 == 0);
    for (field, label, offset, raw, value) in [
        (
            "system_time_utc",
            "镜像内系统时间（UTC）",
            0x14,
            json!(system_time),
            json!(system_time.and_then(timestamp)),
        ),
        (
            "uptime_seconds",
            "中断时钟运行时长（秒）",
            0x8,
            json!(interrupt),
            json!(interrupt.map(|v| v as f64 / TICKS as f64)),
        ),
        (
            "utc_offset_minutes",
            "当前 UTC 偏移（分钟）",
            0x20,
            json!(bias),
            json!(bias.map(|v| -v / 600_000_000)),
        ),
    ] {
        let mut row = SystemField::new(
            field,
            label,
            value,
            "KUSER_SHARED_DATA KSYSTEM_TIME；High1Time == High2Time，保留原始 100ns 值",
        )
        .at(&space, SHARED + offset);
        row.raw_value = json!({"value_100ns":raw, "ksystem_time_bytes":bytes.map(|b| hex::encode(&b[offset as usize..offset as usize + 12]))});
        row.note = if row.value.is_null() {
            shared_error
                .clone()
                .unwrap_or_else(|| "字段未通过一致性或取值范围校验；未补零、未使用宿主时间".into())
        } else if offset == 0x20 {
            "仅为采集时刻偏移，不能据此确定时区名称或历史夏令时规则".into()
        } else {
            String::new()
        };
        records.push(row);
    }
    let boot = system_time
        .zip(interrupt)
        .and_then(|(s, i)| s.checked_sub(i))
        .filter(|v| timestamp(*v).is_some());
    let mut boot_row = SystemField::new(
        "estimated_boot_time_utc",
        "估算启动时间（UTC）",
        json!(boot.and_then(timestamp)),
        "SystemTime - InterruptTime",
    )
    .at(&space, SHARED + 0x14)
    .note("估算值；不是读取 KeBootTime，可能受系统校时和非原子采集影响");
    boot_row.raw_value = json!(boot);
    if boot.is_some() {
        boot_row.evidence_status = "estimated";
    }
    records.push(boot_row);

    for (field, label, note) in [
        (
            "computer_name",
            "计算机名",
            "尚未接入无符号注册表或环境块恢复",
        ),
        (
            "product_name",
            "系统产品名称 / 版本",
            "未读取注册表，不由 Build 单独推定 Windows 客户端、Server 或 SKU",
        ),
        (
            "update_build_revision",
            "补丁修订号（UBR）",
            "需要可靠的注册表证据",
        ),
        (
            "installed_memory_bytes",
            "安装内存（字节）",
            "不能把镜像大小或已采集物理字节数当作机器安装内存",
        ),
    ] {
        records.push(SystemField::new(field, label, Value::Null, "未恢复").note(note));
    }
    let observed = records
        .iter()
        .filter(|r| r.evidence_status == "observed")
        .count();
    cancel.check_cancelled()?;
    Ok(json!({
        "method":"symbolless_x64_system_v1", "complete":false,
        "records":records, "observed_field_count":observed,
        "bootstrap_method":kernel.bootstrap_method, "kernel_base":kernel.kernel_base,
        "kernel_dtb":kernel.kernel_dtb, "system_eprocess":kernel.system_eprocess,
        "kernel_field_evidence":kernel.fields,
        "shared_data_address":SHARED, "shared_data_validated":shared.is_ok(),
        "process_enumeration_performed":!kernel.processes.is_empty(),
        "layout_priors":[
            "AMD64 KUSER_SHARED_DATA VA=0xfffff78000000000；固定读取 0x274 字节；不扫描物理内存中的相似字符串",
            "InterruptTime +0x8、SystemTime +0x14、TimeZoneBias +0x20、NtSystemRoot +0x30（260 个 UTF-16 字符）",
            "NtProductType +0x264、ProductTypeIsValid +0x268、NtMajorVersion +0x26c、NtMinorVersion +0x270；NtBuildNumber +0x260 仅 NT >= 10",
        ],
        "warnings":warnings,
    }))
}

#[cfg(test)]
mod tests;
