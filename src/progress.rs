//! Optional process-wide progress reporting for long-running library scans.
//!
//! The analysis library only publishes structured progress events.  Terminal
//! rendering belongs to the CLI, so embedders and JSON/CSV users never receive
//! unsolicited output.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

static PROGRESS_OBSERVER: OnceLock<Arc<dyn ProgressObserver>> = OnceLock::new();
static NEXT_PROGRESS_ID: AtomicU64 = AtomicU64::new(1);

pub trait ProgressObserver: Send + Sync + 'static {
    fn started(&self, id: u64, label: &str, total: u64);
    fn advanced(&self, id: u64, current: u64, total: u64);
    fn finished(&self, id: u64, current: u64, total: u64, success: bool);
}

/// Installs the observer used by subsequent analysis operations.
///
/// Progress is process-wide and intentionally single-assignment so parallel
/// scans cannot race to replace an embedder's output policy.
pub fn install_progress_observer(observer: Arc<dyn ProgressObserver>) -> bool {
    PROGRESS_OBSERVER.set(observer).is_ok()
}

pub(crate) struct ProgressTask {
    id: u64,
    total: u64,
    current: AtomicU64,
    observer: Option<Arc<dyn ProgressObserver>>,
    finished: bool,
}

impl ProgressTask {
    pub(crate) fn advance(&self, amount: u64) {
        let Some(observer) = &self.observer else {
            return;
        };
        let current = self
            .current
            .fetch_add(amount, Ordering::Relaxed)
            .saturating_add(amount)
            .min(self.total);
        observer.advanced(self.id, current, self.total);
    }

    pub(crate) fn finish(mut self) {
        if let Some(observer) = &self.observer {
            observer.finished(
                self.id,
                self.current.load(Ordering::Relaxed).min(self.total),
                self.total,
                true,
            );
        }
        self.finished = true;
    }
}

impl Drop for ProgressTask {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Some(observer) = &self.observer {
            observer.finished(
                self.id,
                self.current.load(Ordering::Relaxed).min(self.total),
                self.total,
                false,
            );
        }
    }
}

pub(crate) fn start_progress(label: impl Into<String>, total: u64) -> ProgressTask {
    let observer = PROGRESS_OBSERVER.get().cloned();
    let id = NEXT_PROGRESS_ID.fetch_add(1, Ordering::Relaxed);
    if let Some(observer) = &observer {
        observer.started(id, &label.into(), total);
    }
    ProgressTask {
        id,
        total,
        current: AtomicU64::new(0),
        observer,
        finished: false,
    }
}
