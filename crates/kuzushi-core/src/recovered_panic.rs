//! Panics a recovery boundary will catch, marked so a process panic hook can
//! tell them from the fatal kind.
//!
//! `std::panic::catch_unwind` does not keep the process panic hook from
//! running: the hook fires on the panicking thread *before* the unwind reaches
//! the boundary that recovers. Kuzushi's interactive shell installs a hook that
//! puts the operator's terminal back, so without this marker a panic a worker
//! was built to survive would still disable raw mode, leave the alternate
//! screen, and dump its message into the frame — under a shell that keeps
//! running and keeps drawing.
//!
//! Every in-process recovery boundary therefore runs its body through
//! [`catch`], which marks the thread for the body's duration. The marker is
//! thread-local, so a panic on any other thread is still read as fatal.
//!
//! A hook that suppresses its own output then holds the only account of the
//! failure — the panic's source location is reachable nowhere else — so it
//! [`record`]s what it saw and [`catch_disclosed`] hands that account to the
//! boundary, which owes the operator a reason and not just a refusal.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::panic::{catch_unwind, AssertUnwindSafe};

thread_local! {
    /// How many recovery boundaries this thread is inside. A counter rather
    /// than a flag, so leaving a nested boundary does not clear the outer one.
    static BOUNDARY_DEPTH: Cell<usize> = const { Cell::new(0) };
    /// What a process panic hook saw about the panic this thread is currently
    /// unwinding out of a boundary, kept until the boundary reads it.
    static RECORDED: RefCell<Option<RecoveredPanic>> = const { RefCell::new(None) };
}

/// What a recovery boundary can tell the operator about a panic it caught.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredPanic {
    message: String,
    location: Option<String>,
}

impl RecoveredPanic {
    /// The disclosure a caught payload alone supports: its message, and no
    /// location, because only a process panic hook is given one.
    pub fn from_payload(payload: &(dyn Any + Send)) -> Self {
        Self {
            message: payload_text(payload),
            location: None,
        }
    }

    /// The panic's own message, or a stand-in when its payload is not a string.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Where the panic was raised, when a hook recorded it.
    pub fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }
}

impl std::fmt::Display for RecoveredPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.location {
            Some(location) => write!(f, "panicked: {} at {location}", self.message),
            None => write!(f, "panicked: {}", self.message),
        }
    }
}

/// `true` while this thread is inside a [`catch`] body — that is, while a
/// panic raised here would be recovered rather than end the process.
///
/// Reads as `false` once the thread's local storage is gone, which only
/// happens during thread teardown. No boundary is live then, and reading a
/// panic as fatal is the disclosing answer.
pub fn in_boundary() -> bool {
    BOUNDARY_DEPTH
        .try_with(|depth| depth.get() > 0)
        .unwrap_or(false)
}

/// Run `body`, recovering from a panic inside it. The `Err` carries the panic
/// payload exactly as `std::panic::catch_unwind` does; the caller still owes
/// the operator a disclosure of the failure.
pub fn catch<T>(body: impl FnOnce() -> T) -> Result<T, Box<dyn Any + Send>> {
    let _boundary = Boundary::enter();
    catch_unwind(AssertUnwindSafe(body))
}

/// Run `body` as [`catch`] does, naming a recovered panic the way the operator
/// needs to read it: the hook's account when one was recorded for this
/// panic, the payload alone otherwise.
pub fn catch_disclosed<T>(body: impl FnOnce() -> T) -> Result<T, RecoveredPanic> {
    // An account a hook recorded for an earlier panic that no boundary read
    // must not be mistaken for this body's.
    let _stale = take_recorded();
    catch(body).map_err(|payload| disclose_caught(&*payload, take_recorded()))
}

/// The recorded account is only the last panic the hook saw on this thread —
/// a panic raised and caught while this one unwound, or a payload re-raised
/// with `resume_unwind`, which skips the hook, leaves an account of some other
/// panic. It is used only when it describes the caught payload; otherwise the
/// payload alone is disclosed, without a location borrowed from another panic.
fn disclose_caught(
    payload: &(dyn Any + Send),
    recorded: Option<RecoveredPanic>,
) -> RecoveredPanic {
    let caught = RecoveredPanic::from_payload(payload);
    match recorded {
        Some(account) if account.message == caught.message => account,
        _ => caught,
    }
}

/// Record what a process panic hook saw, for the boundary about to recover
/// this panic to disclose. A hook that leaves its message to the boundary owes
/// this call.
///
/// Ignored outside a boundary: that panic is fatal, and the hook discloses it
/// itself.
pub fn record(payload: &(dyn Any + Send), location: Option<String>) {
    if !in_boundary() {
        return;
    }
    let disclosure = RecoveredPanic {
        message: payload_text(payload),
        location,
    };
    let _ = RECORDED.try_with(|slot| slot.replace(Some(disclosure)));
}

/// Takes this thread's recorded account, leaving the slot empty so one account
/// is never read for two panics.
fn take_recorded() -> Option<RecoveredPanic> {
    RECORDED.try_with(RefCell::take).unwrap_or(None)
}

/// `std` puts a `&str` or a `String` in the payload of every `panic!`; any
/// other payload carries no readable message.
fn payload_text(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "non-string panic payload".to_string()
}

/// Marks the thread for as long as it is held, including while a panic unwinds
/// out of the boundary body — the hook has already run by then.
struct Boundary;

impl Boundary {
    fn enter() -> Self {
        adjust_depth(|depth| depth.saturating_add(1));
        Self
    }
}

impl Drop for Boundary {
    fn drop(&mut self) {
        adjust_depth(|depth| depth.saturating_sub(1));
    }
}

fn adjust_depth(next: impl FnOnce(usize) -> usize) {
    let _ = BOUNDARY_DEPTH.try_with(|depth| depth.set(next(depth.get())));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_boundary_is_live_outside_catch() {
        assert!(!in_boundary());
    }

    #[test]
    fn the_body_runs_inside_a_live_boundary() {
        let observed = catch(in_boundary).unwrap();

        assert!(observed, "the body must see its own boundary");
        assert!(!in_boundary(), "the boundary must not outlive the body");
    }

    #[test]
    fn a_recovered_panic_carries_its_payload_and_closes_its_boundary() {
        let payload = catch(|| panic!("probe")).unwrap_err();

        assert_eq!(payload.downcast_ref::<&str>(), Some(&"probe"));
        assert!(
            !in_boundary(),
            "unwinding out of the body must close the boundary"
        );
    }

    #[test]
    fn leaving_a_nested_boundary_keeps_the_outer_one_live() {
        let outer_still_live = catch(|| {
            let _ = catch(|| panic!("inner"));
            in_boundary()
        })
        .unwrap();

        assert!(outer_still_live);
        assert!(!in_boundary());
    }

    #[test]
    fn a_recovered_panic_without_a_hook_still_names_its_payload() {
        let disclosure = catch_disclosed(|| panic!("probe")).unwrap_err();

        assert_eq!(disclosure.message(), "probe");
        assert_eq!(disclosure.location(), None);
        assert_eq!(disclosure.to_string(), "panicked: probe");
    }

    #[test]
    fn a_hooks_account_is_preferred_over_the_payload() {
        let disclosure = catch_disclosed(|| {
            record(&"payload", Some("reader.rs:12".to_string()));
            panic!("payload")
        })
        .unwrap_err();

        assert_eq!(disclosure.message(), "payload");
        assert_eq!(disclosure.location(), Some("reader.rs:12"));
        assert_eq!(disclosure.to_string(), "panicked: payload at reader.rs:12");
    }

    #[test]
    fn an_account_of_another_panic_does_not_explain_the_caught_one() {
        let disclosure = catch_disclosed(|| {
            record(&"inner", Some("inner.rs:7".to_string()));
            panic!("outer")
        })
        .unwrap_err();

        assert_eq!(disclosure.message(), "outer");
        assert_eq!(disclosure.location(), None);
    }

    /// Panics while its owner unwinds, the way a cleanup step guarded by its
    /// own `catch` might — and records that inner panic as a hook would.
    struct PanickingCleanup;

    impl Drop for PanickingCleanup {
        fn drop(&mut self) {
            let _ = catch(|| {
                record(&"cleanup", Some("cleanup.rs:3".to_string()));
                std::panic::resume_unwind(Box::new("cleanup"))
            });
        }
    }

    #[test]
    fn a_panic_caught_during_unwind_does_not_lend_its_account_to_the_outer_one() {
        let disclosure = catch_disclosed(|| {
            let _cleanup = PanickingCleanup;
            record(&"outer", Some("outer.rs:1".to_string()));
            std::panic::resume_unwind(Box::new("outer"))
        })
        .unwrap_err();

        assert_eq!(disclosure.message(), "outer");
        assert_eq!(disclosure.location(), None);
    }

    #[test]
    fn an_unread_account_does_not_explain_the_next_panic() {
        catch(|| record(&"stale", Some("stale.rs:1".to_string()))).unwrap();

        let disclosure = catch_disclosed(|| panic!("fresh")).unwrap_err();

        assert_eq!(disclosure.message(), "fresh");
        assert_eq!(disclosure.location(), None);
    }

    #[test]
    fn an_account_recorded_outside_a_boundary_is_dropped() {
        record(&"fatal", Some("fatal.rs:1".to_string()));

        let disclosure = catch_disclosed(|| panic!("recovered")).unwrap_err();

        assert_eq!(disclosure.message(), "recovered");
    }

    #[test]
    fn a_non_string_payload_is_named_as_one() {
        let disclosure = catch_disclosed(|| std::panic::panic_any(7u8)).unwrap_err();

        assert_eq!(disclosure.message(), "non-string panic payload");
    }

    #[test]
    fn a_boundary_on_one_thread_does_not_mark_another() {
        let elsewhere = catch(|| {
            std::thread::spawn(in_boundary)
                .join()
                .expect("probe thread")
        })
        .unwrap();

        assert!(!elsewhere, "the marker must stay on the panicking thread");
    }
}
