//! Bounded, read-only interaction evidence. Each adapter states its actual scope.
use crate::{
    cancellation::{CancellationToken, is_cancellation_error},
    session::AnalysisSession,
};
use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

mod browser;
mod formats;
mod gui;
mod shell;
mod storage;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum InteractionSource {
    Focus,
    Edit,
    ClipboardFiles,
    ClipboardHistory,
    Ime,
    BrowserTabs,
    Explorer,
    Notifications,
}

impl InteractionSource {
    pub const ALL: [Self; 8] = [
        Self::Focus,
        Self::Edit,
        Self::ClipboardFiles,
        Self::ClipboardHistory,
        Self::Ime,
        Self::BrowserTabs,
        Self::Explorer,
        Self::Notifications,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::Focus => "focus",
            Self::Edit => "edit",
            Self::ClipboardFiles => "clipboard_files",
            Self::ClipboardHistory => "clipboard_history",
            Self::Ime => "ime",
            Self::BrowserTabs => "browser_tabs",
            Self::Explorer => "explorer",
            Self::Notifications => "notifications",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InteractionOptions {
    pub sources: Vec<InteractionSource>,
    pub limit: usize,
    pub file_limit: usize,
    pub max_file_bytes: u64,
}
impl Default for InteractionOptions {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            limit: 4096,
            file_limit: 256,
            max_file_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct InteractionRecord {
    pub kind: String,
    pub evidence: Value,
    pub fields: Value,
}

#[derive(Debug, Serialize)]
pub struct InteractionCheck {
    pub scope: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct InteractionSection {
    pub status: String,
    pub complete: bool,
    pub records: Vec<InteractionRecord>,
    pub checks: Vec<InteractionCheck>,
    pub checks_truncated: bool,
    pub limitations: Vec<String>,
    #[serde(skip)]
    limit: usize,
}
impl InteractionSection {
    fn new(limit: usize) -> Self {
        Self {
            status: "not_observed".into(),
            complete: true,
            records: Vec::new(),
            checks: Vec::new(),
            checks_truncated: false,
            limitations: Vec::new(),
            limit,
        }
    }
    fn record(&mut self, kind: &str, evidence: Value, fields: Value) {
        if self.records.len() < self.limit {
            self.records.push(InteractionRecord {
                kind: kind.into(),
                evidence,
                fields,
            });
        } else if !self.checks.iter().any(|c| c.status == "limit_reached") {
            self.check("records", "limit_reached", "达到记录上限，结果不完整");
        }
    }
    fn check(&mut self, scope: impl Into<String>, status: &str, reason: impl Into<String>) {
        if !matches!(status, "checked" | "not_observed" | "not_applicable") {
            self.complete = false;
        }
        if self.checks.len() < 512 {
            self.checks.push(InteractionCheck {
                scope: scope.into(),
                status: status.into(),
                reason: reason.into(),
            });
        } else {
            self.checks_truncated = true;
            self.complete = false;
        }
    }
    fn finish(&mut self) {
        self.status = if self.complete {
            if self.records.is_empty() {
                "not_observed"
            } else {
                "recovered"
            }
        } else if !self.records.is_empty() {
            "partial"
        } else if self
            .checks
            .iter()
            .any(|c| c.status == "unavailable" || c.status == "missing_pages")
        {
            "unavailable"
        } else if self.checks.iter().any(|c| c.status == "unsupported") {
            "unsupported"
        } else {
            "incomplete"
        }
        .into();
    }
}

#[derive(Debug, Serialize)]
pub struct InteractionReport {
    pub image: String,
    pub sources: BTreeMap<String, InteractionSection>,
    pub complete: bool,
    pub atomic_snapshot: bool,
    pub warnings: Vec<String>,
}

pub fn analyze_windows_interaction(
    session: &AnalysisSession,
    options: &InteractionOptions,
    cancellation: &CancellationToken,
) -> Result<InteractionReport> {
    ensure!(!session.image().is_live(), "交互痕迹插件目前仅用于离线镜像");
    ensure!(
        !session.kernel().is_x86_pae(),
        "交互痕迹的对象适配目前支持 Windows x64；x86 PAE 尚未适配"
    );
    ensure!(
        (1..=65_536).contains(&options.limit),
        "记录上限必须为 1–65536"
    );
    ensure!(
        (1..=4096).contains(&options.file_limit),
        "文件候选上限必须为 1–4096"
    );
    ensure!(
        (4096..=256 * 1024 * 1024).contains(&options.max_file_bytes),
        "单文件预算必须为 4 KiB–256 MiB"
    );
    cancellation.check_cancelled()?;
    let enabled = |s| options.sources.is_empty() || options.sources.contains(&s);
    let mut sections: BTreeMap<_, _> = InteractionSource::ALL
        .into_iter()
        .filter(|s| enabled(*s))
        .map(|s| (s.name().to_owned(), InteractionSection::new(options.limit)))
        .collect();
    if [
        InteractionSource::Focus,
        InteractionSource::Edit,
        InteractionSource::Ime,
    ]
    .into_iter()
    .any(enabled)
    {
        let result = gui::analyze(session, options, cancellation, &mut sections);
        retain_source_error(result, &mut sections, &["focus", "edit", "ime"])?;
    }
    if enabled(InteractionSource::ClipboardFiles) {
        let result = shell::clipboard_files(
            session,
            options,
            cancellation,
            sections
                .get_mut("clipboard_files")
                .expect("enabled section"),
        );
        retain_source_error(result, &mut sections, &["clipboard_files"])?;
    }
    if enabled(InteractionSource::Explorer) {
        let result = shell::explorer(
            session,
            options,
            cancellation,
            sections.get_mut("explorer").expect("enabled section"),
        );
        retain_source_error(result, &mut sections, &["explorer"])?;
    }
    if [
        InteractionSource::ClipboardHistory,
        InteractionSource::BrowserTabs,
        InteractionSource::Notifications,
    ]
    .into_iter()
    .any(enabled)
    {
        let result = storage::analyze(session, options, cancellation, &mut sections);
        retain_source_error(
            result,
            &mut sections,
            &["clipboard_history", "browser_tabs", "notifications"],
        )?;
    }
    cancellation.check_cancelled()?;
    for section in sections.values_mut() {
        section.finish();
    }
    let complete = sections.values().all(|s| s.complete);
    Ok(InteractionReport {
        image: session.image().path().display().to_string(),
        sources: sections,
        complete,
        atomic_snapshot: false,
        warnings: vec![
            "报告包含不同保留时段的对象与驻留存储；不能据此推导完整操作历史或用户意图".into(),
        ],
    })
}

fn retain_source_error(
    result: Result<()>,
    sections: &mut BTreeMap<String, InteractionSection>,
    names: &[&str],
) -> Result<()> {
    if let Err(error) = result {
        if is_cancellation_error(&error) {
            return Err(error);
        }
        for name in names {
            if let Some(section) = sections.get_mut(*name) {
                section.check("source", "unavailable", format!("{error:#}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failures_and_limits_never_become_empty_success() {
        let mut s = InteractionSection::new(1);
        s.check("page", "missing_pages", "absent");
        s.finish();
        assert_eq!(s.status, "unavailable");
        s.record("x", Value::Null, Value::Null);
        s.record("y", Value::Null, Value::Null);
        s.finish();
        assert_eq!(s.status, "partial");
        assert_eq!(s.records.len(), 1);
        assert!(!s.complete);
    }
    #[test]
    fn source_failure_retains_other_evidence_but_cancellation_propagates() {
        let mut sections = BTreeMap::from([
            ("focus".into(), InteractionSection::new(10)),
            ("explorer".into(), InteractionSection::new(10)),
        ]);
        sections
            .get_mut("explorer")
            .unwrap()
            .record("mru", Value::Null, Value::Null);
        retain_source_error(
            Err(anyhow::anyhow!("missing page")),
            &mut sections,
            &["focus"],
        )
        .unwrap();
        for section in sections.values_mut() {
            section.finish();
        }
        assert_eq!(sections["focus"].status, "unavailable");
        assert_eq!(sections["explorer"].status, "recovered");
        let token = CancellationToken::new();
        token.request_cancel();
        assert!(is_cancellation_error(
            &retain_source_error(token.check_cancelled(), &mut sections, &["focus"]).unwrap_err()
        ));
    }
}
