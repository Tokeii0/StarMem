//! Explicit-symbol macOS x86-64 analysis. Profile conversion reads data only;
//! no Python profile or recovered executable is executed. Currently the bootstrap
//! and ordinary (unpacked) vm_page queues cover OS X 10.8–10.11 layouts.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::cancellation::CancellationToken;
use crate::image::{MemoryImage, SourceLocation};
use crate::output_policy::{OutputPolicy, OutputTarget, append_path_suffix};
use crate::scan::scan_exact_cancellable;

const MASK: u64 = 0x000f_ffff_ffff_f000;
const KERNEL: u64 = 0xffff_ff80_0000_0000;

/// Content identity is also used by the host's parameterized report cache.
/// Replacing a profile at the same path must not reuse an earlier report.
pub fn profile_sha256(path: &Path) -> Result<String> {
    let mut input = File::open(path)
        .context("打开 macOS 符号文件失败")?
        .take(16 * 1024 * 1024 + 1);
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 8192];
    let mut total = 0;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count;
        ensure!(total <= 16 * 1024 * 1024, "macOS 符号 JSON 超过 16 MiB");
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[derive(Deserialize)]
struct Symbols {
    format: String,
    expected_banner: String,
    source: Value,
    symbols: BTreeMap<String, u64>,
    types: BTreeMap<String, (u64, BTreeMap<String, Value>)>,
}

impl Symbols {
    fn offset(&self, typ: &str, field: &str) -> Result<u64> {
        let (size, fields) = self
            .types
            .get(typ)
            .with_context(|| format!("macOS 符号缺少类型 {typ}"))?;
        let off = fields
            .get(field)
            .and_then(|v| v.get(0))
            .and_then(Value::as_u64)
            .with_context(|| format!("macOS 符号缺少字段 {typ}.{field}"))?;
        ensure!(off < *size, "字段 {typ}.{field} 越出结构大小");
        Ok(off)
    }

    fn symbol(&self, name: &str, slide: u64) -> Result<u64> {
        self.symbols
            .get(name)
            .context(format!("macOS 符号缺少 {name}"))?
            .checked_add(slide)
            .context("macOS 符号地址溢出")
    }
}

/// macOS does not use Windows transition PTEs. Only hardware-present entries
/// establish a translation here, including 2 MiB and 1 GiB leaves.
struct Reader<'a> {
    image: &'a MemoryImage,
    dtb: u64,
}

impl Reader<'_> {
    fn translate(&self, address: u64) -> Result<u64> {
        ensure!(
            address >> 48 == if address & (1 << 47) == 0 { 0 } else { 0xffff },
            "macOS 虚拟地址不是规范地址"
        );
        let mut table = self.dtb & MASK;
        for shift in [39, 30, 21, 12] {
            let entry = self
                .image
                .read_u64_physical(table + ((address >> shift) & 511) * 8)?;
            ensure!(
                entry & 1 != 0,
                "macOS 地址 {address:#x} 在层级 {shift} 缺少驻留页"
            );
            if shift != 39 && shift != 12 && entry & 128 != 0 {
                let mask = (1u64 << shift) - 1;
                return Ok((entry & MASK & !mask) | (address & mask));
            }
            table = entry & MASK;
        }
        Ok(table | (address & 4095))
    }

    fn read(&self, mut address: u64, mut out: &mut [u8]) -> Result<()> {
        while !out.is_empty() {
            let len = out.len().min((4096 - (address & 4095)) as usize);
            self.image
                .read_physical(self.translate(address)?, &mut out[..len])?;
            address = address
                .checked_add(len as u64)
                .context("macOS 读取地址溢出")?;
            out = &mut out[len..];
        }
        Ok(())
    }
    fn u64(&self, address: u64) -> Result<u64> {
        let mut b = [0; 8];
        self.read(address, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn u32(&self, address: u64) -> Result<u32> {
        let mut b = [0; 4];
        self.read(address, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn u16(&self, address: u64) -> Result<u16> {
        let mut b = [0; 2];
        self.read(address, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }
    fn text(&self, address: u64, limit: usize) -> Result<String> {
        ensure!(address != 0, "macOS 文本指针为零");
        let mut b = Vec::new();
        for index in 0..limit {
            let mut v = [0];
            self.read(address + index as u64, &mut v)?;
            if v[0] == 0 {
                return String::from_utf8(b).context("macOS 文本不是 UTF-8");
            }
            b.push(v[0]);
        }
        bail!("macOS 文本在 {limit} 字节范围内没有终止符")
    }
}

#[derive(Clone, Serialize)]
pub struct MacContext {
    pub banner: String,
    pub kernel_slide: u64,
    pub directory_table_base: u64,
    pub profile_sha256: String,
    pub profile_source: Value,
    pub validation: String,
}

pub struct MacSession {
    image: MemoryImage,
    symbols: Symbols,
    context: MacContext,
    profile_path: PathBuf,
}

#[derive(Serialize)]
pub struct MacReport {
    pub available: bool,
    pub complete: bool,
    pub scope: String,
    pub context: MacContext,
    pub records: Vec<Value>,
    pub warnings: Vec<String>,
    pub limit: usize,
    pub limit_reached: bool,
}

fn kernel_pointer(address: u64) -> Result<u64> {
    ensure!(
        address >= KERNEL && address & 7 == 0,
        "macOS 内核指针无效：{address:#x}"
    );
    Ok(address)
}

impl MacSession {
    pub fn open(
        image: MemoryImage,
        profile_path: &Path,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        cancel.check_cancelled()?;
        let mut bytes = Vec::new();
        File::open(profile_path)?
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "macOS 符号 JSON 超过 16 MiB"
        );
        let symbols: Symbols =
            serde_json::from_slice(&bytes).context("读取 macOS 符号 JSON 失败")?;
        ensure!(
            symbols.format == "starmem-macos-symbols-v1",
            "不支持的 macOS 符号格式"
        );
        ensure!(
            symbols
                .expected_banner
                .starts_with("Darwin Kernel Version ")
                && symbols.expected_banner.len() > 40,
            "macOS 符号须声明完整预期 Darwin banner"
        );
        let markers =
            scan_exact_cancellable(&image, b"Catfish \0\0", 128, 16 * 1024 * 1024, cancel)?;
        ensure!(
            !markers.truncated,
            "macOS 启动标记超过扫描上限，不能唯一定位"
        );
        let low = symbols
            .symbol("_lowGlo", 0)?
            .checked_sub(KERNEL)
            .context("_lowGlo 不在内核地址范围")?;
        let mut candidates = Vec::new();
        for hit in markers.hits {
            cancel.check_cancelled()?;
            let Some(slide) = hit.physical_address.checked_sub(low) else {
                continue;
            };
            if slide & 0x1f_ffff != 0 {
                continue;
            }
            let candidate = (|| -> Result<MacContext> {
                let boot = symbols
                    .symbol("_BootPML4", slide)?
                    .checked_sub(KERNEL)
                    .context("BootPML4 地址无效")?;
                let boot_reader = Reader {
                    image: &image,
                    dtb: boot,
                };
                let dtb = u64::from(boot_reader.u32(symbols.symbol("_IdlePML4", slide)?)?);
                ensure!(dtb != 0 && dtb & 4095 == 0, "IdlePML4 不是有效物理页表");
                let reader = Reader { image: &image, dtb };
                let banner = reader.text(symbols.symbol("_version", slide)?, 512)?;
                ensure!(
                    banner == symbols.expected_banner,
                    "macOS 运行时 banner 与显式符号不匹配"
                );
                let process = kernel_pointer(reader.u64(symbols.symbol("_allproc", slide)?)?)?;
                let task = kernel_pointer(reader.u64(process + symbols.offset("proc", "task")?)?)?;
                ensure!(
                    reader.u64(task + symbols.offset("task", "bsd_info")?)? == process,
                    "macOS proc/task 归属复验失败"
                );
                let pmap = kernel_pointer(reader.u64(symbols.symbol("_kernel_pmap", slide)?)?)?;
                ensure!(
                    reader.u64(pmap + symbols.offset("pmap", "pm_cr3")?)? & MASK == dtb,
                    "macOS 内核 pmap 与 IdlePML4 不匹配"
                );
                Ok(MacContext { banner, kernel_slide: slide, directory_table_base: dtb,
                    profile_sha256: format!("{:x}", Sha256::digest(&bytes)), profile_source: symbols.source.clone(),
                    validation: "完整 banner、启动页表、运行时符号地址、proc/task 双向归属和 kernel_pmap 已复验；未提供符号文件 UUID，不能声称 UUID 校验".into() })
            })();
            if let Ok(context) = candidate {
                candidates.push(context);
            }
        }
        ensure!(
            candidates.len() == 1,
            "macOS 启动上下文候选为 {}，需要匹配的显式符号",
            candidates.len()
        );
        Ok(Self {
            image,
            symbols,
            context: candidates.remove(0),
            profile_path: profile_path.into(),
        })
    }

    fn reader(&self) -> Reader<'_> {
        Reader {
            image: &self.image,
            dtb: self.context.directory_table_base,
        }
    }
    fn report(&self, scope: &str, limit: usize) -> MacReport {
        MacReport {
            available: true,
            complete: true,
            scope: scope.into(),
            context: self.context.clone(),
            records: Vec::new(),
            warnings: Vec::new(),
            limit,
            limit_reached: false,
        }
    }
    fn field(&self, base: u64, typ: &str, name: &str) -> Result<u64> {
        base.checked_add(self.symbols.offset(typ, name)?)
            .context("macOS 字段地址溢出")
    }

    pub fn analyze(
        &self,
        module: &str,
        name: Option<&str>,
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<MacReport> {
        ensure!(
            limit > 0 && limit <= 1_000_000,
            "macOS 结果上限须为 1–1000000"
        );
        let mut report = self.report(
            "活动对象链中的驻留证据；不含空闲对象扫描、交换区、压缩页或磁盘正文",
            limit,
        );
        let result = match module {
            "info" => {
                let r = self.reader();
                let hostname = self
                    .symbols
                    .symbol("_hostname", self.context.kernel_slide)
                    .and_then(|a| r.text(a, 256));
                report
                    .records
                    .push(json!({"banner":self.context.banner,"hostname":hostname.as_ref().ok()}));
                hostname.map(|_| ())
            }
            "processes" => self.processes(&mut report, cancel),
            "files" => self.files(&mut report, name, cancel),
            _ => bail!("不支持的 macOS 模块：{module}"),
        };
        if let Err(error) = result {
            if crate::cancellation::is_cancellation_error(&error) {
                return Err(error);
            }
            report.complete = false;
            report
                .warnings
                .push(format!("macOS 对象链读取不完整：{error:#}"));
        }
        Ok(report)
    }

    fn push(report: &mut MacReport, row: Value) -> bool {
        if report.records.len() == report.limit {
            report.complete = false;
            report.limit_reached = true;
            false
        } else {
            report.records.push(row);
            true
        }
    }

    fn processes(&self, report: &mut MacReport, cancel: &CancellationToken) -> Result<()> {
        let r = self.reader();
        let mut p = r.u64(self.symbols.symbol("_allproc", self.context.kernel_slide)?)?;
        let mut seen = HashSet::new();
        let mut prev_link = self.symbols.symbol("_allproc", self.context.kernel_slide)?;
        while p != 0 {
            cancel.check_cancelled()?;
            kernel_pointer(p)?;
            ensure!(seen.insert(p), "macOS 活动进程链出现循环");
            let link = self.field(p, "proc", "p_list")?;
            ensure!(
                r.u64(link + 8)? == prev_link,
                "macOS 进程 {p:#x} 链反向链接不匹配（预期 {prev_link:#x}，实际 {:#x}）",
                r.u64(link + 8)?
            );
            let task = kernel_pointer(r.u64(self.field(p, "proc", "task")?)?)?;
            ensure!(
                r.u64(self.field(task, "task", "bsd_info")?)? == p,
                "macOS 进程 task 归属不匹配"
            );
            let map = kernel_pointer(r.u64(self.field(task, "task", "map")?)?)?;
            let pmap = kernel_pointer(r.u64(self.field(map, "_vm_map", "pmap")?)?)?;
            let row = json!({"proc":p,"physical_address":r.translate(p)?,"pid":r.u32(self.field(p,"proc","p_pid")?)?,
                "ppid":r.u32(self.field(p,"proc","p_ppid")?)?,"name":r.text(self.field(p,"proc","p_comm")?,17)?,
                "task":task,"vm_map":map,"directory_table_base":r.u64(self.field(pmap,"pmap","pm_cr3")?)? & MASK});
            if !Self::push(report, row) {
                break;
            }
            prev_link = link;
            p = r.u64(link)?;
        }
        Ok(())
    }

    fn vnode_path(&self, mut vnode: u64) -> Result<String> {
        let r = self.reader();
        let mut seen = HashSet::new();
        let mut names = Vec::new();
        while vnode != 0 {
            kernel_pointer(vnode)?;
            ensure!(
                seen.insert(vnode) && seen.len() <= 256,
                "macOS vnode 路径链循环或超过 256 层"
            );
            let mount = r.u64(self.field(vnode, "vnode", "v_mount")?)?;
            let is_root = r.u32(self.field(vnode, "vnode", "v_flag")?)? & 1 != 0;
            // A filesystem root's v_name is the volume name, not a directory
            // component. The covered vnode supplies a mounted path component.
            if !is_root {
                let name = r.u64(self.field(vnode, "vnode", "v_name")?)?;
                if name != 0 {
                    let text = r.text(name, 1024)?;
                    if !text.is_empty() && text != "/" {
                        ensure!(!text.contains('/'), "vnode 名称含路径分隔符");
                        names.push(text);
                    }
                }
            }
            if is_root && mount != 0 {
                vnode = r.u64(self.field(mount, "mount", "mnt_vnodecovered")?)?;
            } else {
                vnode = r.u64(self.field(vnode, "vnode", "v_parent")?)?;
            }
        }
        names.reverse();
        Ok(format!("/{}", names.join("/")))
    }

    fn file_row(&self, vnode: u64) -> Result<Value> {
        kernel_pointer(vnode)?;
        let r = self.reader();
        let typ = r.u16(self.field(vnode, "vnode", "v_type")?)?;
        ensure!((1..=8).contains(&typ), "macOS vnode 类型无效");
        let path = self.vnode_path(vnode)?;
        let size = if typ == 1 {
            let ubc = r.u64(self.field(vnode, "vnode", "v_un")?)?;
            if ubc != 0 {
                Some(r.u64(self.field(kernel_pointer(ubc)?, "ubc_info", "ui_size")?)?)
            } else {
                None
            }
        } else {
            None
        };
        Ok(
            json!({"vnode":vnode,"physical_address":r.translate(vnode)?,"path":path,"vnode_type":typ,"logical_size":size}),
        )
    }

    fn files(
        &self,
        report: &mut MacReport,
        name: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let r = self.reader();
        let mut mount = r.u64(
            self.symbols
                .symbol("_mountlist", self.context.kernel_slide)?,
        )?;
        let mut mounts = HashSet::new();
        let mut vnodes = HashSet::new();
        while mount != 0 {
            cancel.check_cancelled()?;
            kernel_pointer(mount)?;
            ensure!(
                mounts.insert(mount) && mounts.len() <= 4096,
                "macOS 挂载链循环或超限"
            );
            let mut vnode = r.u64(self.field(mount, "mount", "mnt_vnodelist")?)?;
            while vnode != 0 {
                cancel.check_cancelled()?;
                kernel_pointer(vnode)?;
                ensure!(
                    vnodes.insert(vnode) && vnodes.len() <= 1_000_000,
                    "macOS vnode 链循环或超限"
                );
                ensure!(
                    r.u64(self.field(vnode, "vnode", "v_mount")?)? == mount,
                    "macOS vnode 挂载归属不匹配"
                );
                match self.file_row(vnode) {
                    Ok(row) => {
                        if name.is_none_or(|n| row["path"].as_str().is_some_and(|p| p.contains(n)))
                            && !Self::push(report, row)
                        {
                            return Ok(());
                        }
                    }
                    Err(error) => {
                        report.complete = false;
                        if report.warnings.len() < 128 {
                            report.warnings.push(format!("vnode {vnode:#x}：{error:#}"));
                        }
                    }
                }
                vnode = r.u64(self.field(vnode, "vnode", "v_mntvnodes")?)?;
            }
            mount = r.u64(self.field(mount, "mount", "mnt_list")?)?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct MacExtent {
    pub file_offset: u64,
    pub length: u64,
    pub physical_address: u64,
    pub source_location: Option<SourceLocation>,
}

#[derive(Serialize)]
pub struct MacRecovery {
    pub available: bool,
    pub complete: bool,
    pub scope: String,
    pub context: MacContext,
    pub vnode: u64,
    pub path: String,
    pub logical_size: u64,
    pub recovered_bytes: u64,
    pub output_path: PathBuf,
    pub recovery_manifest: PathBuf,
    pub sha256: Option<String>,
    pub extents: Vec<MacExtent>,
    pub missing_ranges: Vec<Value>,
    pub warnings: Vec<String>,
}

impl MacSession {
    pub fn recover(
        &self,
        vnode: u64,
        output: &Path,
        max_size: u64,
        cancel: &CancellationToken,
    ) -> Result<MacRecovery> {
        cancel.check_cancelled()?;
        let row = self.file_row(vnode)?;
        ensure!(row["vnode_type"] == 1, "仅能恢复普通 vnode 文件");
        let size = row["logical_size"]
            .as_u64()
            .context("vnode 缺少 UBC 文件大小")?;
        ensure!(
            size > 0 && size <= max_size,
            "macOS 文件大小为 {size}，超过范围或为空"
        );
        let r = self.reader();
        let ubc = kernel_pointer(r.u64(self.field(vnode, "vnode", "v_un")?)?)?;
        ensure!(
            r.u64(self.field(ubc, "ubc_info", "ui_vnode")?)? == vnode,
            "UBC vnode 反向归属不匹配"
        );
        let control = kernel_pointer(r.u64(self.field(ubc, "ubc_info", "ui_control")?)?)?;
        let object = kernel_pointer(r.u64(self.field(
            control,
            "memory_object_control",
            "moc_object",
        )?)?)?;
        ensure!(
            self.symbols
                .types
                .get("queue_entry")
                .is_some_and(|t| t.0 == 16),
            "暂不支持打包的 macOS vm_page 指针"
        );
        let head = self.field(object, "vm_object", "memq")?;
        let mut page = r.u64(head)?;
        let mut seen = HashSet::new();
        let mut pages = BTreeMap::new();
        let mut warnings = Vec::new();
        while page != head && page != 0 {
            cancel.check_cancelled()?;
            let result = (|| -> Result<u64> {
                kernel_pointer(page)?;
                ensure!(
                    seen.insert(page) && seen.len() <= 1_000_000,
                    "vm_page 队列循环或超过 1000000 页"
                );
                ensure!(
                    r.u64(self.field(page, "vm_page", "object")?)? == object,
                    "vm_page 文件对象归属不匹配"
                );
                let offset = r.u64(self.field(page, "vm_page", "offset")?)?;
                let pfn = r.u32(self.field(page, "vm_page", "phys_page")?)?;
                ensure!(offset & 4095 == 0, "vm_page 文件偏移未对齐");
                let flags = r.u32(page + self.symbols.offset("vm_page", "busy")?)?;
                ensure!(
                    flags & ((1 << 4) | (1 << 10) | (1 << 11) | (1 << 18) | (1 << 19) | (1 << 26))
                        == 0,
                    "vm_page 缺页、虚构、错误、加密或压缩状态不能视为文件正文"
                );
                if offset < size && pfn != 0 {
                    ensure!(
                        pages.insert(offset, u64::from(pfn) * 4096).is_none(),
                        "vm_page 文件偏移重复"
                    );
                }
                r.u64(self.field(page, "vm_page", "listq")?)
            })();
            match result {
                Ok(next) => page = next,
                Err(error) => {
                    warnings.push(format!("vm_page {page:#x}：{error:#}"));
                    break;
                }
            }
        }
        let mut extents = Vec::new();
        let mut missing = Vec::new();
        let mut cursor = 0;
        let mut recovered = 0;
        for (&offset, &physical) in &pages {
            if cursor < offset {
                missing.push(json!({"file_offset":cursor,"length":offset-cursor,"reason":"未恢复到驻留页面"}));
            }
            let length = 4096.min(size - offset);
            let mut b = vec![0; length as usize];
            if self.image.read_physical(physical, &mut b).is_ok() {
                recovered += length;
                extents.push(MacExtent {
                    file_offset: offset,
                    length,
                    physical_address: physical,
                    source_location: self.image.source_location(physical),
                });
            } else {
                missing.push(json!({"file_offset":offset,"length":length,"reason":"物理区间未采集或无法读取"}));
            }
            cursor = offset + length;
        }
        if cursor < size {
            missing.push(
                json!({"file_offset":cursor,"length":size-cursor,"reason":"未恢复到驻留页面"}),
            );
        }
        ensure!(recovered > 0, "macOS vnode 没有可读取的驻留文件页");
        let complete = recovered == size && missing.is_empty() && warnings.is_empty();
        let partial = append_path_suffix(output, ".partial");
        let actual = if complete { output } else { partial.as_path() };
        let manifest = append_path_suffix(actual, ".recovery.json");
        let mut policy = OutputPolicy::new(false);
        policy.protect_file("memory_image", self.image.path());
        policy.protect_file("profile", &self.profile_path);
        policy.output(OutputTarget::file("recovered_file", output).with_derived_path(&partial));
        policy.output(OutputTarget::file("recovery_manifest", &manifest));
        policy.preflight()?;
        let mut hash = Sha256::new();
        policy.write_file_atomic(actual, |file| {
            file.set_len(size)?;
            for extent in &extents {
                cancel.check_cancelled()?;
                let mut b = vec![0; extent.length as usize];
                self.image.read_physical(extent.physical_address, &mut b)?;
                file.seek(SeekFrom::Start(extent.file_offset))?;
                file.write_all(&b)?;
                if complete {
                    hash.update(&b);
                }
            }
            cancel.check_cancelled()?;
            Ok(())
        })?;
        let report = MacRecovery { available:true, complete, scope:"经 vnode/UBC/vm_object 归属复验的驻留文件页；缺页产物带 .partial，补零不计入恢复量或完整文件哈希".into(),
            context:self.context.clone(),vnode,path:row["path"].as_str().unwrap_or_default().into(),logical_size:size,recovered_bytes:recovered,
            output_path:actual.into(),recovery_manifest:manifest.clone(),sha256:complete.then(||format!("{:x}",hash.finalize())),extents,missing_ranges:missing,warnings };
        policy.write_file_atomic(&manifest, |file| {
            serde_json::to_writer_pretty(file, &report)?;
            Ok(())
        })?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn put(bytes: &mut [u8], address: usize, value: u64) {
        bytes[address..address + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture(missing_second: bool) -> (PathBuf, MacSession) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("starmem-macos-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let input = dir.join("memory.raw");
        let mut bytes = vec![0; 0x12000];
        put(&mut bytes, 0x1000 + 511 * 8, 0x2003);
        put(&mut bytes, 0x2000, 0x3003);
        put(&mut bytes, 0x3000, 0x4003);
        for index in 0..18 {
            put(&mut bytes, 0x4000 + index * 8, ((index as u64) * 4096) | 3);
        }
        let va = |pa: u64| KERNEL + pa;
        // vnode -> ubc -> control -> vm_object -> resident vm_page queue.
        bytes[0x6000..0x6002].copy_from_slice(&1u16.to_le_bytes());
        put(&mut bytes, 0x6008, va(0x6800));
        put(&mut bytes, 0x6020, va(0x7000));
        bytes[0x6800..0x6806].copy_from_slice(b"a.bin\0");
        put(&mut bytes, 0x7000, va(0x7100));
        put(&mut bytes, 0x7008, va(0x6000));
        put(&mut bytes, 0x7010, 5000);
        put(&mut bytes, 0x7100, va(0x7200));
        put(&mut bytes, 0x7200, va(0x7300));
        put(&mut bytes, 0x7300 + 16, 0);
        put(&mut bytes, 0x7300 + 24, va(0x7200));
        put(
            &mut bytes,
            0x7300,
            if missing_second {
                va(0x7200)
            } else {
                va(0x7400)
            },
        );
        put(&mut bytes, 0x7300 + 32, 8);
        put(&mut bytes, 0x7400, va(0x7200));
        put(&mut bytes, 0x7400 + 16, 4096);
        put(&mut bytes, 0x7400 + 24, va(0x7200));
        put(&mut bytes, 0x7400 + 32, 9);
        bytes[0x8000..0x9000].fill(b'A');
        bytes[0x9000..0xa000].fill(b'B');
        std::fs::write(&input, bytes).unwrap();
        let types = json!({
            "vnode":[48,{"v_type":[0],"v_name":[8],"v_parent":[16],"v_flag":[24],"v_un":[32],"v_mount":[40]}],
            "ubc_info":[24,{"ui_control":[0],"ui_vnode":[8],"ui_size":[16]}],
            "memory_object_control":[8,{"moc_object":[0]}],"vm_object":[16,{"memq":[0]}],
            "vm_page":[48,{"listq":[0],"offset":[16],"object":[24],"phys_page":[32],"busy":[40]}],"queue_entry":[16,{}]
        });
        let symbols = Symbols {
            format: "starmem-macos-symbols-v1".into(),
            expected_banner: String::new(),
            source: json!({}),
            symbols: BTreeMap::new(),
            types: serde_json::from_value(types).unwrap(),
        };
        let context = MacContext {
            banner: "fixture".into(),
            kernel_slide: 0,
            directory_table_base: 0x1000,
            profile_sha256: "fixture".into(),
            profile_source: json!({}),
            validation: "fixture".into(),
        };
        let profile = dir.join("profile.json");
        std::fs::write(&profile, b"{}").unwrap();
        let session = MacSession {
            image: MemoryImage::open(&input).unwrap(),
            symbols,
            context,
            profile_path: profile,
        };
        (dir, session)
    }

    #[test]
    fn mac_recovery_preserves_object_ownership_holes_and_hash_scope() {
        for partial in [false, true] {
            let (dir, session) = fixture(partial);
            let out = dir.join("recovered.bin");
            let report = session
                .recover(
                    KERNEL + 0x6000,
                    &out,
                    1024 * 1024,
                    &CancellationToken::new(),
                )
                .unwrap();
            assert_eq!(report.complete, !partial);
            assert_eq!(report.logical_size, 5000);
            assert_eq!(report.recovered_bytes, if partial { 4096 } else { 5000 });
            assert_eq!(report.sha256.is_none(), partial);
            assert_eq!(
                report.output_path.extension().unwrap(),
                if partial { "partial" } else { "bin" }
            );
            let recovered = std::fs::read(&report.output_path).unwrap();
            assert_eq!(&recovered[..4096], vec![b'A'; 4096]);
            assert_eq!(
                &recovered[4096..],
                vec![if partial { 0 } else { b'B' }; 904]
            );
            if partial {
                assert_eq!(report.missing_ranges[0]["length"], 904);
            } else {
                assert_eq!(
                    report.sha256.unwrap(),
                    format!("{:x}", Sha256::digest(&recovered))
                );
            }
            assert!(report.recovery_manifest.is_file());
            assert!(
                session
                    .recover(
                        KERNEL + 0x6000,
                        session.image.path(),
                        1024 * 1024,
                        &CancellationToken::new()
                    )
                    .is_err()
            );
            let cancelled = CancellationToken::new();
            cancelled.request_cancel();
            assert!(
                session
                    .recover(
                        KERNEL + 0x6000,
                        &dir.join("cancelled"),
                        1024 * 1024,
                        &cancelled
                    )
                    .is_err()
            );
            assert!(!dir.join("cancelled").exists());
            drop(session);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn mac_reader_rejects_windows_transition_and_noncanonical_addresses() {
        let (dir, session) = fixture(false);
        let reader = session.reader();
        assert!(reader.translate(0x0001_0000_0000_0000).is_err());
        assert_eq!(reader.translate(KERNEL + 0x6000).unwrap(), 0x6000);
        drop(session);
        let path = dir.join("memory.raw");
        let mut bytes = std::fs::read(&path).unwrap();
        put(&mut bytes, 0x4000 + 6 * 8, 0x6800);
        std::fs::write(&path, bytes).unwrap();
        let image = MemoryImage::open(&path).unwrap();
        assert!(
            Reader {
                image: &image,
                dtb: 0x1000
            }
            .translate(KERNEL + 0x6000)
            .is_err()
        );
        drop(image);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
