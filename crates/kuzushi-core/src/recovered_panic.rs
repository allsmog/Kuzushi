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

use std::any::Any;
use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};

thread_local! {
    /// How many recovery boundaries this thread is inside. A counter rather
    /// than a flag, so leaving a nested boundary does not clear the outer one.
    static BOUNDARY_DEPTH: Cell<usize> = const { Cell::new(0) };
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
