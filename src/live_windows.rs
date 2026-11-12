//! Narrow live observers: Windows processes, modules, network and DWM buffers.
//! The underlying AnalysisSession is private; offline-only plugins and file
//! evidence caches cannot be invoked through this API.

use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::address::X64AddressSpace;
use crate::cancellation::CancellationToken;
use crate::image::MemoryImage;
use crate::live::{LiveImageReader, LiveSource, VmwareLiveReader};
use crate::session::{AnalysisSession, SessionOptions};
use crate::symbols::codeview_from_virtual_pe;
use crate::windows::ProcessListReport;
use crate::windows::dwm_surfaces::{DwmSurfaceReport, recover_dwm_surfaces};

mod queries;
pub use queries::{LiveProcessDetails, LiveProcessIdentity};

#[derive(Debug, Serialize)]
pub struct LiveMemoryScreenObservation {
    pub source: LiveSource,
    pub started_unix_ms: u128,
    pub finished_unix_ms: u128,
    pub atomic_snapshot: bool,
    pub current_scanout_proven: bool,
    pub anchor: LiveWindowsAnchor,
    pub report: DwmSurfaceReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveWindowsAnchor {
    pub kernel_base: u64,
    pub directory_table_base: u64,
    pub pdb_guid: String,
    pub pdb_age: u32,
    /// Public symbol stripping can increment the PDB information-stream age;
    /// the DBI age, verified at connection, must match the PE CodeView age.
    pub pdb_information_age: u32,
    pub system_eprocess: u64,
    pub system_create_time: u64,
    pub boot_id: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct LiveObservation<T> {
    pub source: LiveSource,
    pub sequence: u64,
    pub started_unix_ms: u128,
    pub finished_unix_ms: u128,
    pub elapsed_micros: u128,
    pub atomic_snapshot: bool,
    pub anchor: LiveWindowsAnchor,
    pub report: T,
}

pub type LiveProcessObservation = LiveObservation<ProcessListReport>;

pub struct LiveWindowsSession {
    session: AnalysisSession,
    reader: Arc<LiveImageReader>,
    anchor: LiveWindowsAnchor,
    cancellation: CancellationToken,
    sequence: u64,
}

impl LiveWindowsSession {
    /// Initial exact-symbol resolution may scan guest RAM and download its PDB.
    /// Call inside the host's bounded analysis executor, not the UI thread.
    pub fn open(
        reader: VmwareLiveReader,
        mut options: SessionOptions,
        cancellation: CancellationToken,
    ) -> Result<Self> {
        options.allow_compatible_local_symbols = false;
        let explicit_pdb = options.pdb.clone();
        let reader = Arc::new(LiveImageReader::new(reader, cancellation.clone()));
        let image = MemoryImage::from_live_vmware(reader.clone())?;
        let session = AnalysisSession::from_image_cancellable(image, options, &cancellation)?;
        ensure!(
            !session.kernel().is_x86_pae(),
            "实时 Windows 观察目前支持 Windows x64"
        );
        let codeview = codeview_from_virtual_pe(
            session.image(),
            session.kernel().directory_table_base,
            session.kernel().kernel_base,
        )
        .context("实时内核没有可验证的 CodeView 标识")?;
        ensure!(
            codeview
                .guid
                .eq_ignore_ascii_case(&session.profile().pdb_guid),
            "实时内核 GUID {} 与类型布局 {} 不匹配",
            codeview.guid,
            session.profile().pdb_guid
        );
        let pdb_path = match explicit_pdb {
            Some(path) => path,
            None => session.symbol_store().resolve(&codeview)?,
        };
        let mut pdb = pdb::PDB::open(std::fs::File::open(&pdb_path)?)?;
        let pdb_dbi_age = pdb
            .debug_information()?
            .age()
            .context("精确内核 PDB 缺少 DBI age")?;
        ensure!(
            pdb_dbi_age == codeview.age,
            "内核 CodeView age {} 与 PDB DBI age {} 不匹配",
            codeview.age,
            pdb_dbi_age
        );
        let anchor = read_anchor(&session, pdb_dbi_age)?;
        Ok(Self {
            session,
            reader,
            anchor,
            cancellation,
            sequence: 0,
        })
    }

    pub fn source(&self) -> &LiveSource {
        self.reader.source()
    }

    pub fn stop(&self) -> Result<()> {
        self.reader.stop()
    }

    /// Recover real DWM pixel buffers from guest memory. No SVG window-layout
    /// substitute is generated. Finding a bitmap does not alone prove that it
    /// is the currently displayed scanout surface.
    pub fn recover_memory_frames(
        &mut self,
        output: &Path,
        max_dimension: u32,
    ) -> Result<LiveMemoryScreenObservation> {
        ensure!(
            (320..=8192).contains(&max_dimension),
            "实时图像边长上限必须为 320–8192"
        );
        self.cancellation.check_cancelled()?;
        ensure!(
            read_anchor(&self.session, self.anchor.pdb_age)? == self.anchor,
            "客户机内核或启动锚点已改变，请重新连接"
        );
        std::fs::create_dir(output).context("截图输出目录必须尚不存在")?;
        let started_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let result = (|| -> Result<LiveMemoryScreenObservation> {
            let report = recover_dwm_surfaces(
                self.session.image(),
                self.session.kernel(),
                self.session.profile(),
                self.session.symbol_store(),
                output,
                max_dimension,
                false,
                &self.cancellation,
            )?;
            self.cancellation.check_cancelled()?;
            ensure!(
                read_anchor(&self.session, self.anchor.pdb_age)? == self.anchor,
                "图像读取期间客户机启动锚点改变，不能将产物视为有效观察"
            );
            Ok(LiveMemoryScreenObservation {
                source: self.source().clone(),
                started_unix_ms,
                finished_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                atomic_snapshot: false,
                current_scanout_proven: false,
                anchor: self.anchor.clone(),
                report,
            })
        })();
        if let Err(error) = &result {
            let _ = self.stop();
            // Keep diagnostic artifacts, but never leave them looking like a
            // validated observation when cancellation/source changes abort it.
            let failure = serde_json::json!({
                "valid_observation": false,
                "source": self.source(),
                "started_unix_ms": started_unix_ms,
                "atomic_snapshot": false,
                "error": format!("{error:#}"),
            });
            let path = output.join("live-memory-screen.failed.json");
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| format!("{error:#}；另无法保存失败说明 {}", path.display()))?;
            serde_json::to_writer_pretty(file, &failure)
                .with_context(|| format!("{error:#}；另无法写入失败说明 {}", path.display()))?;
        }
        result
    }

    pub fn processes(&mut self, limit: usize) -> Result<LiveProcessObservation> {
        ensure!((1..=65_536).contains(&limit), "进程数量上限必须为 1–65536");
        self.observe(|session, cancellation| session.processes_cancellable(limit, cancellation))
    }

    fn observe<T>(
        &mut self,
        operation: impl FnOnce(&AnalysisSession, &CancellationToken) -> Result<T>,
    ) -> Result<LiveObservation<T>> {
        self.cancellation.check_cancelled()?;
        let started = Instant::now();
        let started_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let result = (|| -> Result<LiveObservation<T>> {
            ensure!(
                read_anchor(&self.session, self.anchor.pdb_age)? == self.anchor,
                "客户机内核或启动锚点已改变，请重新连接"
            );
            let report = operation(&self.session, &self.cancellation)?;
            ensure!(
                read_anchor(&self.session, self.anchor.pdb_age)? == self.anchor,
                "读取期间客户机启动锚点发生变化，本批作废"
            );
            self.cancellation.check_cancelled()?;
            self.sequence = self.sequence.checked_add(1).context("实时观察序号溢出")?;
            Ok(LiveObservation {
                source: self.reader.source().clone(),
                sequence: self.sequence,
                started_unix_ms,
                finished_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                elapsed_micros: started.elapsed().as_micros(),
                atomic_snapshot: false,
                anchor: self.anchor.clone(),
                report,
            })
        })();
        if result.is_err() {
            let _ = self.stop();
        }
        result
    }
}

fn read_anchor(session: &AnalysisSession, pdb_dbi_age: u32) -> Result<LiveWindowsAnchor> {
    let kernel = session.kernel();
    let profile = session.profile();
    let image = session.image();
    let space = X64AddressSpace::new(image, kernel.directory_table_base)?;
    let codeview = codeview_from_virtual_pe(image, kernel.directory_table_base, kernel.kernel_base)
        .context("实时内核没有可验证的 CodeView 标识")?;
    ensure!(
        codeview.guid.eq_ignore_ascii_case(&profile.pdb_guid) && codeview.age == pdb_dbi_age,
        "实时内核 PDB 与类型布局不匹配，不能使用兼容符号解释当前客户机"
    );
    let system_eprocess = space
        .read_u64(kernel.kernel_base + u64::from(profile.symbol_rva("PsInitialSystemProcess")?))?;
    ensure!(
        space.read_u64(system_eprocess + profile.field("UniqueProcessId")?.offset)? == 4,
        "系统进程锚点无效"
    );
    let system_create_time =
        space.read_u64(system_eprocess + profile.field("CreateTime")?.offset)?;
    ensure!(system_create_time > 0, "系统进程创建时间锚点不可用");
    let boot_id = profile
        .type_field("_KUSER_SHARED_DATA", "BootId")
        .ok()
        .map(|field| -> Result<u32> {
            let mut bytes = [0; 4];
            space.read_virtual(0xffff_f780_0000_0000 + field.offset, &mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        })
        .transpose()?;
    Ok(LiveWindowsAnchor {
        kernel_base: kernel.kernel_base,
        directory_table_base: kernel.directory_table_base,
        pdb_guid: codeview.guid,
        pdb_age: codeview.age,
        pdb_information_age: profile.pdb_age,
        system_eprocess,
        system_create_time,
        boot_id,
    })
}
