use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

/// Stable error code included in the display form of [`CancellationError`].
///
/// GUI hosts may use [`is_cancellation_error`] when they receive an
/// `anyhow::Error` in-process. The code is also kept in the message so hosts
/// crossing an FFI/IPC boundary can distinguish cancellation from failure.
pub const CANCELLATION_ERROR_CODE: &str = "STARMEM_CANCELLED";

/// The typed error returned when a cooperative StarMem task is cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancellationError;

impl fmt::Display for CancellationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{CANCELLATION_ERROR_CODE}: StarMem task was cancelled"
        )
    }
}

impl Error for CancellationError {}

#[derive(Debug, Default)]
struct CancellationState {
    cancelled: AtomicBool,
}

/// Cloneable controller retained by a StarMem host for one logical task.
///
/// Call [`CancellationHandle::start`] immediately before dispatching a task,
/// pass the returned token to the cancellable StarMem API, and retain the
/// handle so another thread can call [`CancellationHandle::cancel`]. A handle
/// should not be shared by concurrently running logical tasks; create one
/// handle per task id instead.
#[derive(Debug, Clone, Default)]
pub struct CancellationHandle {
    state: Arc<CancellationState>,
}

impl CancellationHandle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets stale cancellation state and returns the token for a new run.
    ///
    /// The previous run using this handle must have already returned. Calling
    /// `start` while it is still running can clear its cancellation request.
    pub fn start(&self) -> CancellationToken {
        self.reset();
        self.token()
    }

    /// Returns a token sharing this handle's current cancellation state.
    pub fn token(&self) -> CancellationToken {
        CancellationToken {
            state: Arc::clone(&self.state),
        }
    }

    /// Requests cooperative cancellation. This operation is thread-safe and
    /// idempotent.
    pub fn cancel(&self) {
        self.state.cancelled.store(true, Ordering::Release);
    }

    /// Clears cancellation state before the next task starts.
    pub fn reset(&self) {
        self.state.cancelled.store(false, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }
}

/// Cloneable cancellation view passed into StarMem analysis functions.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    state: Arc<CancellationState>,
}

impl CancellationToken {
    /// Creates an independent token which is initially not cancelled.
    /// Existing non-cancellable APIs use one internally to preserve their
    /// behavior.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    /// Requests cancellation through a cloned token.
    ///
    /// This is primarily intended for host-side resource watchdogs. Normal
    /// UI cancellation should continue to use [`CancellationHandle`].
    pub fn request_cancel(&self) {
        self.state.cancelled.store(true, Ordering::Release);
    }

    /// Returns the typed cancellation error when cancellation was requested.
    pub fn check_cancelled(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(CancellationError.into())
        } else {
            Ok(())
        }
    }
}

/// Tests whether an `anyhow` error (including a context-wrapped error) was
/// caused by cooperative cancellation.
pub fn is_cancellation_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CancellationError>().is_some()
}

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use super::*;

    #[test]
    fn handle_can_cancel_and_restart_a_task() {
        let handle = CancellationHandle::new();
        let first = handle.start();
        assert!(!first.is_cancelled());

        handle.cancel();
        assert!(first.is_cancelled());
        let error = first.check_cancelled().unwrap_err();
        assert!(is_cancellation_error(&error));
        assert!(error.to_string().contains(CANCELLATION_ERROR_CODE));

        let second = handle.start();
        assert!(!second.is_cancelled());
        second.check_cancelled().unwrap();
    }

    #[test]
    fn cancellation_survives_anyhow_context() {
        let handle = CancellationHandle::new();
        let token = handle.start();
        handle.cancel();
        let error = token
            .check_cancelled()
            .context("host operation failed")
            .unwrap_err();
        assert!(is_cancellation_error(&error));
    }

    #[test]
    fn token_can_cancel_for_a_resource_watchdog() {
        let token = CancellationToken::new();
        let observer = token.clone();
        token.request_cancel();
        assert!(observer.is_cancelled());
        assert!(is_cancellation_error(
            &observer.check_cancelled().unwrap_err()
        ));
    }
}
