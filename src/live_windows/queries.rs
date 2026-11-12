use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::{LiveObservation, LiveWindowsSession};
use crate::address::X64AddressSpace;
use crate::session::AnalysisSession;
use crate::symbols::codeview_from_virtual_pe;
use crate::windows::ProcessRecord;
use crate::windows::netstat_plugins::NetstatReport;
use crate::windows::plugins::{DllRecord, PluginReport, list_process_dlls};

/// A guest PID alone is not an identity; retain this tuple from a live pslist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveProcessIdentity {
    pub source_session_id: String,
    pub pid: u64,
    pub eprocess: u64,
    pub create_time_raw: u64,
}

impl LiveProcessIdentity {
    pub fn from_record(source_session_id: &str, record: &ProcessRecord) -> Result<Self> {
        Ok(Self {
            source_session_id: source_session_id.to_owned(),
            pid: record.pid,
            eprocess: record.eprocess,
            create_time_raw: record
                .details
                .create_time_raw
                .context("进程缺少创建时间，不能绑定实时身份")?,
        })
    }

    fn matches(&self, record: &ProcessRecord) -> bool {
        self.pid == record.pid
            && self.eprocess == record.eprocess
            && Some(self.create_time_raw) == record.details.create_time_raw
    }
}

#[derive(Debug, Serialize)]
pub struct LiveProcessDetails {
    pub identity: LiveProcessIdentity,
    pub process: ProcessRecord,
    pub modules: PluginReport<DllRecord>,
    pub complete: bool,
    pub warnings: Vec<String>,
}

impl LiveWindowsSession {
    pub fn process_details(
        &mut self,
        identity: &LiveProcessIdentity,
        module_limit: usize,
    ) -> Result<LiveObservation<LiveProcessDetails>> {
        ensure!(
            (1..=4096).contains(&module_limit),
            "模块数量上限必须为 1–4096"
        );
        ensure!(
            identity.source_session_id == self.source().session_id,
            "进程属于其他实时会话，请重新选择"
        );
        self.observe(|session, cancellation| {
            let processes = session.processes_cancellable(65_536, cancellation)?;
            let process = processes
                .processes
                .into_iter()
                .find(|p| identity.matches(p))
                .context("所选进程身份已不可用，或进程链表读取不完整；请刷新列表后重新选择")?;
            verify_process_identity(session, identity)?;
            let modules = if process.details.exit_time_raw.is_some() {
                PluginReport {
                    records: Vec::new(),
                    complete: false,
                    warnings: vec!["进程已有退出时间，未读取其用户态模块".into()],
                }
            } else {
                list_process_dlls(
                    session.image(),
                    session.kernel(),
                    session.profile(),
                    &process,
                    module_limit,
                )?
            };
            verify_process_identity(session, identity)?;
            let mut warnings: Vec<_> = processes.warnings.into_iter().map(|w| w.message).collect();
            warnings.extend(modules.warnings.iter().cloned());
            if process.details.command_line.is_none() || process.details.image_path.is_none() {
                warnings.push("命令行或完整路径不可用，不能将缺失字段解释为空值".into());
            }
            Ok(LiveProcessDetails {
                identity: identity.clone(),
                complete: processes.complete && modules.complete && warnings.is_empty(),
                process,
                modules,
                warnings,
            })
        })
    }

    pub fn netstat(&mut self, limit: usize) -> Result<LiveObservation<NetstatReport>> {
        ensure!((1..=16_384).contains(&limit), "网络记录上限必须为 1–16384");
        self.observe(|session, cancellation| {
            cancellation.check_cancelled()?;
            let report = session.netstat(limit)?;
            let current = codeview_from_virtual_pe(
                session.image(),
                session.kernel().directory_table_base,
                report.tcpip_base,
            )
            .context("网络读取结束时无法核对 tcpip.sys")?;
            ensure!(
                current.pdb_name.eq_ignore_ascii_case("tcpip.pdb")
                    && current.symbol_key == report.tcpip_pdb_key,
                "网络读取期间 tcpip.sys 身份改变，本批作废"
            );
            cancellation.check_cancelled()?;
            Ok(report)
        })
    }
}

fn verify_process_identity(
    session: &AnalysisSession,
    identity: &LiveProcessIdentity,
) -> Result<()> {
    let space = X64AddressSpace::new(session.image(), session.kernel().directory_table_base)?;
    let profile = session.profile();
    let pid = space.read_u64(identity.eprocess + profile.field("UniqueProcessId")?.offset)?;
    let created = space.read_u64(identity.eprocess + profile.field("CreateTime")?.offset)?;
    ensure!(
        pid == identity.pid && created == identity.create_time_raw && created > 0,
        "读取期间所选进程身份改变，本批作废"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::ProcessDetails;

    #[test]
    fn process_identity_rejects_reused_pid_and_missing_creation_time() {
        let mut record = ProcessRecord {
            eprocess: 0xffff_8000_0000_1000,
            pid: 120,
            ppid: Some(4),
            name: "example.exe".into(),
            details: ProcessDetails::default(),
        };
        assert!(LiveProcessIdentity::from_record("live-1", &record).is_err());
        record.details.create_time_raw = Some(100);
        let identity = LiveProcessIdentity::from_record("live-1", &record).unwrap();
        assert!(identity.matches(&record));
        record.details.create_time_raw = Some(101);
        assert!(!identity.matches(&record));
        record.details.create_time_raw = Some(100);
        record.eprocess += 0x1000;
        assert!(!identity.matches(&record));
    }
}
