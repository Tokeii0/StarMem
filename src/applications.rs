//! Application evidence from verified Windows objects and resident file ranges.
//! Presence, configured state and successful use are deliberately separate claims.
mod ai;
mod bitlocker;
mod memory;
mod office;
mod remote;
mod storage;
mod text;
mod v8;
mod wal;

use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cancellation::{CancellationToken, is_cancellation_error};
use crate::session::AnalysisSession;
use crate::windows::files::{DumpSource, recover_file_bytes, scan_files_matching_cancellable};
use crate::windows::service_plugins::ServiceView;
use crate::windows_recent_files::{WindowsRecentFilesOptions, analyze_windows_recent_files};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationKind {
    Bitlocker,
    Veracrypt,
    Sunlogin,
    Anydesk,
    Wps,
    Huorong,
    Ai,
}

impl ApplicationKind {
    pub fn from_plugin(name: &str) -> Option<Self> {
        match name {
            "bitlocker" => Some(Self::Bitlocker),
            "veracrypt" => Some(Self::Veracrypt),
            "sunlogin" => Some(Self::Sunlogin),
            "anydesk" => Some(Self::Anydesk),
            "wps" => Some(Self::Wps),
            "huorong" => Some(Self::Huorong),
            "ai-chat" => Some(Self::Ai),
            _ => None,
        }
    }

    fn executable(self, name: &str) -> bool {
        let name = basename(name);
        let names: &[&str] = match self {
            Self::Bitlocker => &[
                "manage-bde.exe",
                "bitlockerwizard.exe",
                "bitlockerwizardelev.exe",
            ],
            Self::Veracrypt => &[
                "veracrypt.exe",
                "veracrypt format.exe",
                "veracryptformat.exe",
            ],
            Self::Sunlogin => &[
                "sunloginclient.exe",
                "sunloginclient",
                "sunloginservice.exe",
                "sunloginremote.exe",
                "awesun.exe",
                "awesun_guard.exe",
                "awesun_guard.e",
            ],
            Self::Anydesk => &["anydesk.exe"],
            Self::Wps => &[
                "wps.exe",
                "wpp.exe",
                "et.exe",
                "wpspdf.exe",
                "wpscloudsvr.exe",
                "wpscloudsvr.ex",
                "wpscenter.exe",
            ],
            Self::Huorong => &[
                "hipstray.exe",
                "hipsdaemon.exe",
                "hipsmain.exe",
                "wsctrl.exe",
            ],
            Self::Ai => return ai::process_app(&name).is_some(),
        };
        names.iter().any(|expected| {
            *expected == name
                || (13..=15).contains(&name.len())
                    && expected.len() > name.len()
                    && expected.starts_with(&name)
        })
    }

    fn driver(self, name: &str) -> bool {
        match self {
            Self::Bitlocker => matches!(basename(name).as_str(), "fvevol.sys" | "dumpfve.sys"),
            Self::Veracrypt => basename(name) == "veracrypt.sys",
            _ => false,
        }
    }

    fn service(self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        let names: &[&str] = match self {
            Self::Bitlocker => &["bdesvc", "fvevol"],
            Self::Veracrypt => &["veracrypt"],
            Self::Sunlogin => &["sunloginservice", "sunloginclient", "awesunservice"],
            Self::Anydesk => &["anydesk"],
            Self::Wps => &["wpscloudsvr"],
            Self::Huorong => &["hipsdaemon", "sysdiag"],
            Self::Ai => &[],
        };
        names.contains(&name.as_str())
    }

    fn execution_name(self, name: &str) -> bool {
        self.executable(name)
            || self == Self::Veracrypt && name.eq_ignore_ascii_case("IDRIX.VeraCrypt")
    }

    fn directory(self, path: &str) -> bool {
        let p = normalized(path);
        let parts: Vec<_> = p.split('\\').collect();
        match self {
            Self::Bitlocker => parts.contains(&"bitlocker"),
            Self::Veracrypt => parts.contains(&"veracrypt"),
            Self::Sunlogin => parts.iter().any(|p| {
                matches!(
                    *p,
                    "sunlogin" | "sunloginclient" | "sunloginenterprise" | "awesun"
                )
            }),
            Self::Anydesk => parts.contains(&"anydesk"),
            Self::Wps => {
                parts.contains(&"kingsoft")
                    && parts
                        .iter()
                        .any(|p| matches!(*p, "wps" | "wps office" | "office6"))
            }
            Self::Huorong => parts.contains(&"huorong") && parts.contains(&"sysdiag"),
            Self::Ai => ai::path_app(path).is_some(),
        }
    }

    fn file_kind(self, path: &str) -> Option<&'static str> {
        if matches!(self, Self::Huorong | Self::Ai) {
            return storage::file_kind(self, path);
        }
        let p = normalized(path);
        let name = basename(&p);
        if self.driver(&name) {
            return Some("driver_file");
        }
        if self.executable(&name) {
            return Some("program_file");
        }
        if self == Self::Bitlocker {
            if name.ends_with(".bek") {
                return Some("external_key_file_candidate");
            }
            if name.ends_with(".txt") && (name.contains("bitlocker") || name.contains("恢复密钥"))
            {
                return Some("recovery_key_file_candidate");
            }
        }
        if self == Self::Veracrypt && name.ends_with(".hc") {
            return Some("container_extension_candidate");
        }
        if !self.directory(path) {
            return None;
        }
        if name.ends_with(".db") || name.ends_with(".hive") {
            return Some("database_candidate");
        }
        if name.ends_with(".log") || name.ends_with(".trace") || name == "connection_trace.txt" {
            // Embedded Chromium LevelDB logs are binary storage, not remote session logs.
            if p.contains("\\leveldb\\") || p.contains("\\ebwebview\\") {
                return Some("database_candidate");
            }
            return Some("log_file");
        }
        if [".ini", ".conf", ".xml", ".json"]
            .iter()
            .any(|s| name.ends_with(s))
        {
            return Some("configuration_file");
        }
        None
    }
}

fn normalized(value: &str) -> String {
    value.replace('/', "\\").to_lowercase()
}
fn basename(value: &str) -> String {
    normalized(value)
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .to_owned()
}

fn is_office_document(path: &str) -> bool {
    let name = basename(path);
    [
        ".doc", ".docx", ".wps", ".xls", ".xlsx", ".et", ".ppt", ".pptx", ".wpp", ".pdf", ".ofd",
    ]
    .iter()
    .any(|extension| name.ends_with(extension))
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplicationOptions {
    pub limit: usize,
    /// Applies after application path filtering, not to unrelated FILE_OBJECTs.
    pub file_limit: usize,
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub pid: Option<u64>,
    pub skip_memory: bool,
    pub anchor_limit: usize,
    pub process_limit: usize,
}

impl Default for ApplicationOptions {
    fn default() -> Self {
        Self {
            limit: 4096,
            file_limit: 2048,
            max_files: 32,
            max_file_bytes: 4 * 1024 * 1024,
            pid: None,
            skip_memory: false,
            anchor_limit: 4096,
            process_limit: 64,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ApplicationRecord {
    pub artifact_kind: String,
    pub source: String,
    pub pid: Option<u64>,
    pub path: Option<String>,
    pub summary: String,
    pub evidence: Value,
    pub data: Value,
}

#[derive(Debug, Serialize)]
pub struct ApplicationSource {
    pub source: String,
    pub available: bool,
    pub complete: bool,
    pub examined: usize,
    pub warnings: Vec<String>,
    pub details: Value,
}

#[derive(Debug, Serialize)]
pub struct ApplicationReport {
    pub image: String,
    pub application: ApplicationKind,
    pub options: ApplicationOptions,
    pub records: Vec<ApplicationRecord>,
    pub sources: Vec<ApplicationSource>,
    pub available: bool,
    pub complete: bool,
    pub truncated: bool,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
    #[serde(skip)]
    record_bytes: usize,
}

impl ApplicationReport {
    fn source(
        &mut self,
        source: &str,
        available: bool,
        complete: bool,
        examined: usize,
        warnings: Vec<String>,
        details: Value,
    ) {
        self.available |= available;
        self.complete &= available && complete;
        for warning in &warnings {
            if self.warnings.len() < 128 {
                self.warnings.push(format!("{source}：{warning}"));
            }
        }
        self.sources.push(ApplicationSource {
            source: source.into(),
            available,
            complete,
            examined,
            warnings,
            details,
        });
    }
    fn failure(&mut self, source: &str, error: anyhow::Error) -> Result<()> {
        if is_cancellation_error(&error) {
            return Err(error);
        }
        self.source(
            source,
            false,
            false,
            0,
            vec![format!("{error:#}")],
            Value::Null,
        );
        Ok(())
    }
    fn push(&mut self, record: ApplicationRecord) {
        let bytes = serde_json::to_vec(&record).map_or(usize::MAX, |v| v.len());
        if self.records.len() < self.options.limit
            && bytes <= (32 * 1024 * 1024usize).saturating_sub(self.record_bytes)
        {
            self.record_bytes += bytes;
            self.records.push(record);
        } else if !self.truncated {
            self.truncated = true;
            self.complete = false;
            self.warnings.push(format!(
                "记录达到 {} 条或 32 MiB 报告预算；保留结果不完整",
                self.options.limit
            ));
        }
    }
}

pub fn analyze_application(
    session: &AnalysisSession,
    kind: ApplicationKind,
    options: &ApplicationOptions,
    token: &CancellationToken,
) -> Result<ApplicationReport> {
    token.check_cancelled()?;
    ensure!(
        !session.image().is_live(),
        "应用分析目前仅支持离线镜像，避免跨时刻归属混用"
    );
    ensure!((1..=16384).contains(&options.limit), "记录上限须为 1–16384");
    ensure!(
        (1..=16384).contains(&options.file_limit),
        "应用文件候选上限须为 1–16384"
    );
    ensure!(
        (1..=128).contains(&options.max_files),
        "内容读取文件数须为 1–128"
    );
    ensure!(
        (4096..=16 * 1024 * 1024).contains(&options.max_file_bytes),
        "单文件预算须为 4 KiB–16 MiB"
    );
    ensure!(
        (1..=16384).contains(&options.anchor_limit),
        "锚点上限须为 1–16384"
    );
    ensure!(
        (1..=64).contains(&options.process_limit),
        "进程上限须为 1–64"
    );
    let mut report = ApplicationReport {
        image: session.image().path().display().to_string(), application: kind, options: options.clone(),
        records: Vec::new(), sources: Vec::new(), available: false, complete: true, truncated: false, record_bytes: 0,
        warnings: session.warnings().to_vec(), limitations: vec![
            "进程名、驱动名和路径按明确规则识别，重命名程序可能漏检；路径与进程名不证明程序真实性。".into(),
            "文件对象与日志残留可能来自历史活动；零结果或未恢复不能证明从未使用。".into(),
            "文件缓存与进程驻留内容分别解析；内存映射不证明生成者。缺页、预算、加密及未支持格式均可能导致遗漏。".into(),
        ],
    };
    match kind {
        ApplicationKind::Bitlocker => report.limitations.push(
            "内核池中的 FVEK 候选经过布局与驻留校验，尚未通过磁盘卷解密验证；候选不等于恢复密码，也不证明某卷当前已解锁。".into()),
        ApplicationKind::Veracrypt => report.limitations.push(
            "加密组件、配置、容器名和挂载历史只代表线索，不能确认卷当前加密/解锁状态；未实现 VMK/FVEK 或 VeraCrypt 主密钥提取与卷头验证。".into()),
        ApplicationKind::Sunlogin | ApplicationKind::Anydesk => report.limitations.push(
            "远端地址可能是中继或服务端；连接请求、设备 ID、日志片段均不单独证明成功控制或操作者身份。".into()),
        ApplicationKind::Wps => report.limitations.push(
            "最近文件记录按注册表逐项时间解释；文件对象存在不证明由 WPS 打开，未关联的办公扩展名不归入 WPS。".into()),
        ApplicationKind::Huorong => report.limitations.push(
            "报毒目标 pathname 与触发进程 procname 分列；隔离/恢复动作不等于当前文件状态。WAL 仅使用连续校验且已提交的帧；同路径主库关联保留为重建依据。".into()),
        ApplicationKind::Ai => report.limitations.push(
            "支持已登记客户端的 JSON/JSONL、SQLite 及部分 V8 压缩指针堆布局。恢复正文保留原文与生成状态；请求、草稿、缓存或历史副本不单独证明已发送。缺页、未驻留历史、私有加密库及未支持的堆/LevelDB 格式仍可能遗漏。".into()),
    }
    match session.processes_cancellable(65_536, token) {
        Ok(processes) => {
            report.source(
                "pslist",
                true,
                processes.complete,
                processes.processes.len(),
                processes
                    .warnings
                    .iter()
                    .map(|w| w.message.clone())
                    .collect(),
                json!({"stop_reason":processes.stop_reason}),
            );
            for p in processes.processes {
                token.check_cancelled()?;
                if !kind.executable(&p.name)
                    && !p.details.image_path.as_deref().is_some_and(|v| {
                        if kind == ApplicationKind::Ai {
                            ai::path_app(v).is_some()
                        } else {
                            kind.executable(v) && kind.directory(v)
                        }
                    })
                {
                    continue;
                }
                report.push(ApplicationRecord { artifact_kind: "process".into(), source: "pslist".into(), pid: Some(p.pid),
                    path: p.details.image_path.clone(), summary: format!("{} (PID {})", p.name, p.pid),
                    evidence: json!({"eprocess":p.eprocess,"directory_table_base":p.details.directory_table_base,"create_time":p.details.create_time}),
                    data: json!({"name":p.name,"ppid":p.ppid,"state":p.details.state,"exit_time":p.details.exit_time,
                        "application":if kind == ApplicationKind::Ai { ai::path_app(p.details.image_path.as_deref().unwrap_or("")).or_else(||ai::process_app(&p.name)) } else { None }}) });
                if kind == ApplicationKind::Wps && p.details.state == "running" {
                    let source = format!("handles:{}:{:#x}", p.pid, p.eprocess);
                    match session.handles(p.pid, 65_536) {
                        Ok(handles) => {
                            report.source(&source, true, handles.complete, handles.records.len(), handles.warnings,
                                json!({"pid":p.pid,"eprocess":p.eprocess,"create_time":p.details.create_time}));
                            for h in handles.records.into_iter().filter(|h| {
                                h.object_type.eq_ignore_ascii_case("file")
                                    && h.name.as_deref().is_some_and(is_office_document)
                            }) {
                                token.check_cancelled()?;
                                report.push(ApplicationRecord {artifact_kind:"document_handle".into(),source:source.clone(),pid:Some(p.pid),path:h.name.clone(),
                                    summary:format!("{} 持有文档文件句柄；不代表已编辑或保存",p.name),
                                    evidence:json!({"eprocess":p.eprocess,"object":h.object,"handle":h.handle,"entry":h.entry}),data:serde_json::to_value(h)?});
                            }
                        }
                        Err(e) => report.failure(&source, e)?,
                    }
                }
            }
        }
        Err(e) => report.failure("pslist", e)?,
    }
    token.check_cancelled()?;
    if matches!(
        kind,
        ApplicationKind::Bitlocker | ApplicationKind::Veracrypt
    ) {
        match session.drivers(65_536) {
            Ok(drivers) => {
                report.source(
                    "drivers",
                    true,
                    drivers.complete,
                    drivers.records.len(),
                    drivers.warnings,
                    Value::Null,
                );
                for d in drivers.records.into_iter().filter(|d| kind.driver(&d.name)) {
                    report.push(ApplicationRecord {
                        artifact_kind: "loaded_driver".into(),
                        source: "drivers".into(),
                        pid: None,
                        path: Some(d.path.clone()),
                        summary: format!("已加载 {}；不据此判定卷加密状态", d.name),
                        evidence: json!({"entry":d.entry,"base":d.base}),
                        data: serde_json::to_value(d)?,
                    });
                }
            }
            Err(e) => report.failure("drivers", e)?,
        }
    } else {
        match session.network_cancellable(1_000_000, token) {
            Ok(network) => {
                report.source(
                    "netscan",
                    true,
                    network.complete,
                    network.records.len(),
                    network.warnings,
                    json!({"association":"使用端点报告原有属主名；不以 PID 合并到当前进程"}),
                );
                for n in network
                    .records
                    .into_iter()
                    .filter(|n| kind.executable(&n.process))
                {
                    report.push(ApplicationRecord { artifact_kind: "network_endpoint".into(), source: "netscan".into(), pid: Some(n.pid), path: None,
                        summary: format!("{} {}:{} → {}:{}", n.process, n.local_address, n.local_port, n.remote_address, n.remote_port.map_or("未知".into(), |p| p.to_string())),
                        evidence: json!({"physical_address":n.physical_address,"owner_resolution":n.owner_resolution}), data: serde_json::to_value(n)? });
                }
            }
            Err(e) => report.failure("netscan", e)?,
        }
    }
    token.check_cancelled()?;
    match session.services(ServiceView::List, 65_536, false) {
        Ok(services) => {
            report.source("svclist", true, services.complete, services.records.len(), services.warnings,
                json!({"association":"服务内存结构；保留布局名称及扫描/链表来源，不以 PID 绑定到当前进程"}));
            for s in services
                .records
                .into_iter()
                .filter(|s| kind.service(&s.name))
            {
                token.check_cancelled()?;
                report.push(ApplicationRecord {artifact_kind:"service".into(),source:"svclist".into(),pid:s.pid.map(u64::from),
                    path:s.binary_path_memory.clone(),summary:format!("{} · {}",s.name,s.state_name),
                    evidence:json!({"address":s.address,"found_by_scan":s.found_by_scan,"found_by_list":s.found_by_list,"adaptive_layout":s.adaptive_layout}),data:serde_json::to_value(s)?});
            }
        }
        Err(e) => report.failure("svclist", e)?,
    }
    token.check_cancelled()?;
    {
        match analyze_windows_recent_files(
            session,
            &WindowsRecentFilesOptions {
                include_wps: kind == ApplicationKind::Wps,
                include_recentdocs: kind != ApplicationKind::Wps,
                record_limit: 100_000,
                ..Default::default()
            },
            |_| {},
        ) {
            Ok(recent) => {
                report.source(
                    "recent_files",
                    !recent.sources.is_empty() && recent.sources.iter().any(|s| s.available),
                    recent.complete,
                    recent.matched_records,
                    recent.warnings,
                    serde_json::to_value(&recent.sources)?,
                );
                for r in recent.records {
                    token.check_cancelled()?;
                    if kind != ApplicationKind::Wps && kind.file_kind(&r.path).is_none() {
                        continue;
                    }
                    report.push(ApplicationRecord { artifact_kind: "recent_document".into(), source: r.source.clone(), pid: None,
                        path: Some(r.path.clone()), summary: format!("{} · {}", r.application.as_deref().unwrap_or("Explorer 最近文件"), r.timestamp_utc.as_deref().unwrap_or("仅 MRU 顺序，无逐项时间")),
                        evidence: json!({"hive":r.hive,"registry_key":r.registry_key,"registry_value":r.registry_value,"time_semantics":r.time_semantics}), data: serde_json::to_value(r)? });
                }
            }
            Err(e) => report.failure("recent_files", e)?,
        }
    }
    token.check_cancelled()?;
    match session.userassist(100_000) {
        Ok(history) => {
            report.source(
                "userassist",
                history.available,
                history.complete,
                history.records.len(),
                history.warnings,
                Value::Null,
            );
            for h in history
                .records
                .into_iter()
                .filter(|h| kind.execution_name(&h.decoded_name))
            {
                token.check_cancelled()?;
                report.push(ApplicationRecord {artifact_kind:"execution_history".into(),source:"userassist".into(),pid:None,
                    path:Some(h.decoded_name.clone()),summary:format!("UserAssist 最后执行：{}",h.last_execution.as_deref().unwrap_or("时间不可用")),
                    evidence:json!({"hive":h.hive,"guid":h.guid,"encoded_name":h.encoded_name,"last_execution_raw":h.last_execution_raw}),data:serde_json::to_value(h)?});
            }
        }
        Err(e) => report.failure("userassist", e)?,
    }
    // Prioritize typed evidence before general file metadata consumes the row budget.
    if matches!(kind, ApplicationKind::Huorong | ApplicationKind::Ai) {
        storage::analyze(session, kind, options, token, &mut report)?;
    }
    if !options.skip_memory {
        if kind == ApplicationKind::Bitlocker {
            bitlocker::analyze(session, options, token, &mut report)?;
        }
        memory::analyze(session, kind, options, token, &mut report)?;
    } else {
        report.source(
            "process_memory",
            false,
            false,
            0,
            vec!["本次参数跳过进程内存解析".into()],
            Value::Null,
        );
    }
    if !matches!(kind, ApplicationKind::Huorong | ApplicationKind::Ai) {
        analyze_files(session, kind, options, token, &mut report)?;
    }
    token.check_cancelled()?;
    Ok(report)
}

fn analyze_files(
    session: &AnalysisSession,
    kind: ApplicationKind,
    options: &ApplicationOptions,
    token: &CancellationToken,
    report: &mut ApplicationReport,
) -> Result<()> {
    let files = match scan_files_matching_cancellable(
        session.image(),
        session.kernel(),
        session.profile(),
        options.file_limit,
        &|p| kind.file_kind(p).is_some(),
        token,
    ) {
        Ok(files) => files,
        Err(e) => {
            report.failure("filescan", e)?;
            return Ok(());
        }
    };
    report.source(
        "filescan",
        true,
        files.complete,
        files.records.len(),
        files.warnings,
        json!({"path_filter_before_limit":true}),
    );
    // Stronger FILE_OBJECTs first; never merge objects merely because names match.
    let mut files = files.records;
    files.sort_by_key(|f| {
        (
            f.shared_cache_map == 0 && f.data_section_object == 0,
            f.file_object,
        )
    });
    let mut attempted = 0;
    for f in files {
        token.check_cancelled()?;
        let path = f.name.as_deref().unwrap_or("");
        let category = kind.file_kind(path).unwrap_or("file_candidate");
        let readable = matches!(
            category,
            "configuration_file" | "log_file" | "recovery_key_file_candidate"
        );
        let state = if !readable {
            "仅对象元数据；未解析内容"
        } else if attempted >= options.max_files {
            "内容未核对：已达文件数预算"
        } else {
            "内容核对状态见报告范围中的同对象来源"
        };
        report.push(ApplicationRecord { artifact_kind: category.into(), source: "filescan".into(), pid: None, path: f.name.clone(),
            summary: state.into(), evidence: json!({"file_object":f.file_object,"physical_address":f.physical_address,"object_type_verified":f.object_type_verified}), data: serde_json::to_value(&f)? });
        if !readable {
            continue;
        }
        if attempted >= options.max_files {
            if !report
                .warnings
                .iter()
                .any(|w| w.starts_with("文件内容核对达到"))
            {
                report.warnings.push(format!(
                    "文件内容核对达到 {} 个 FILE_OBJECT 上限，其余候选尚未核对",
                    options.max_files
                ));
                report.complete = false;
            }
            continue;
        }
        attempted += 1;
        for source in [DumpSource::Cache, DumpSource::Data] {
            token.check_cancelled()?;
            let source_id = format!("file:{:#x}:{source:?}", f.file_object);
            let present = match source {
                DumpSource::Cache => f.shared_cache_map != 0,
                _ => f.data_section_object != 0,
            };
            if !present {
                report.source(
                    &source_id,
                    false,
                    false,
                    0,
                    vec!["该 FILE_OBJECT 没有此内容映射".into()],
                    json!({"path":path,"file_object":f.file_object}),
                );
                continue;
            }
            let (dump, bytes) = match recover_file_bytes(
                session.image(),
                session.kernel(),
                session.profile(),
                f.file_object,
                source,
                options.max_file_bytes,
            ) {
                Ok(v) => v,
                Err(e) => {
                    report.failure(&source_id, e)?;
                    continue;
                }
            };
            token.check_cancelled()?;
            let parsed = text::parse_resident_lines(
                &bytes,
                &dump.extents,
                dump.logical_size,
                options.limit,
                token,
            )?;
            let mut warnings = dump.warnings.clone();
            if dump.recovered_bytes == 0 {
                warnings.push("未恢复任何有效字节".into());
            }
            if !parsed.complete {
                warnings.push(
                    "文本存在缺页边界、非支持编码、过长行或行数预算截断；仅保留可复核片段".into(),
                );
            }
            report.source(
                &source_id,
                dump.recovered_bytes > 0,
                dump.complete && parsed.complete,
                parsed.lines.len(),
                warnings,
                json!({"path":path,"file_object":f.file_object,"recovery":dump}),
            );
            for line in parsed.lines {
                token.check_cancelled()?;
                if line.complete {
                    let mut fields =
                        if matches!(kind, ApplicationKind::Sunlogin | ApplicationKind::Anydesk) {
                            remote::text(kind, &line.text)
                                .into_iter()
                                .map(|(_, _, a)| a)
                                .collect::<Vec<_>>()
                        } else if kind == ApplicationKind::Wps {
                            office::text(&line.text)
                                .into_iter()
                                .map(|(_, _, a)| a)
                                .collect()
                        } else {
                            vec![]
                        };
                    if let Ok(v) = serde_json::from_str::<Value>(&line.text) {
                        if matches!(kind, ApplicationKind::Sunlogin | ApplicationKind::Anydesk) {
                            fields.extend(remote::extract(kind, &v));
                        } else if kind == ApplicationKind::Wps {
                            fields.extend(office::extract(&v));
                        }
                    }
                    for a in fields {
                        report.push(ApplicationRecord{artifact_kind:a.kind.into(),source:source_id.clone(),pid:None,path:f.name.clone(),
                        summary:a.data.get("label").or_else(||a.data.get("document_path")).and_then(Value::as_str).unwrap_or(a.kind).chars().take(180).collect(),
                        evidence:json!({"file_object":f.file_object,"recovery_source":source,"file_offset":line.offset,"byte_length":line.byte_length,"encoding":line.encoding,"line_complete":true,"sha256":line.sha256,"json_pointer":a.pointer}),data:a.data});
                    }
                }
                let interpreted = text::interpret(kind, path, &line.text, line.complete);
                let artifact_kind = interpreted
                    .as_ref()
                    .map(|(k, _)| *k)
                    .unwrap_or("text_fragment");
                report.push(ApplicationRecord { artifact_kind: artifact_kind.into(), source: source_id.clone(), pid: None, path: f.name.clone(),
                    summary: line.text.chars().take(240).collect(), evidence: json!({"file_object":f.file_object,"recovery_source":source,
                        "file_offset":line.offset,"byte_length":line.byte_length,"encoding":line.encoding,"line_complete":line.complete,"sha256":line.sha256}),
                    data: json!({"text":line.text,"fields":interpreted.map(|(_,v)|v),"semantics":"驻留文件行；时间/设备号等为原文值，未推定成功会话或操作者"}) });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identities_are_component_scoped_and_include_awesun() {
        assert!(ApplicationKind::Sunlogin.executable("AweSun.exe"));
        assert!(
            ApplicationKind::Sunlogin
                .file_kind(r"\ProgramData\Oray\AweSun\sys_config.ini")
                .is_some()
        );
        assert!(
            ApplicationKind::Anydesk
                .file_kind(r"\AnyDesk\ad_custom\ad_custom_svc.trace")
                .is_some()
        );
        assert!(
            ApplicationKind::Anydesk
                .file_kind(r"\NotAnyDesk\connection_trace.txt")
                .is_none()
        );
        assert!(!ApplicationKind::Anydesk.executable("anydesk.exe.malware"));
        assert!(
            ApplicationKind::Wps
                .file_kind(r"\Users\a\report.docx")
                .is_none()
        );
        assert!(!ApplicationKind::Veracrypt.driver("truecrypt.sys"));
        assert!(ApplicationKind::Veracrypt.execution_name("IDRIX.VeraCrypt"));
        assert!(ApplicationKind::Sunlogin.executable("SunloginClient."));
        assert!(!ApplicationKind::Sunlogin.executable("SunloginHelper.exe"));
        assert!(is_office_document(r"C:\用户\报告.docx"));
        assert!(!is_office_document("report.docx.exe"));
    }
    #[test]
    fn partial_and_output_limits_survive_positive_evidence() {
        let mut r = ApplicationReport {
            image: "test".into(),
            application: ApplicationKind::Bitlocker,
            options: ApplicationOptions {
                limit: 1,
                ..Default::default()
            },
            records: vec![],
            sources: vec![],
            available: false,
            complete: true,
            truncated: false,
            warnings: vec![],
            limitations: vec![],
            record_bytes: 0,
        };
        r.source(
            "files",
            false,
            false,
            0,
            vec!["missing".into()],
            Value::Null,
        );
        r.source("drivers", true, true, 1, vec![], Value::Null);
        for _ in 0..2 {
            r.push(ApplicationRecord {
                artifact_kind: "loaded_driver".into(),
                source: "drivers".into(),
                pid: None,
                path: None,
                summary: "fvevol.sys".into(),
                evidence: Value::Null,
                data: Value::Null,
            });
        }
        assert!(r.available && r.truncated && !r.complete);
        assert_eq!(r.records.len(), 1);
        assert!(
            r.failure("cancel", crate::cancellation::CancellationError.into())
                .is_err()
        );
    }
}
