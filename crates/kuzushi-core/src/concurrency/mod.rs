/// Stage priority bands. Set via [`with_priority`] before calling routed
/// agent functions. Higher variants preempt lower in the wait queue.

/// Run `fut` with `CURRENT_PRIORITY` scoped to `priority`.

/// Default per-model concurrency caps when not overridden by
/// `models.toml [concurrency]`. Numbers mirror RoboDuck's tested values
/// for production AIxCC traffic.

/// Per-model priority gate. One [`Semaphore`] per model, plus a fair
/// priority queue that hands out permits in priority-then-FIFO order.
///
/// Design: only the queue *head* may attempt `try_acquire_owned()` on the
/// underlying semaphore. Non-head waiters block on a per-waiter `Notify`
/// until they become head. When a permit is released, we wake the
/// current head. This sidesteps Tokio's internal FIFO inside `Semaphore`
/// — without this layer, `acquire_owned` futures would resolve in
/// arrival order regardless of priority.

/// Permit returned by [`ModelGate::acquire`]. Releases on drop and wakes
/// the next priority-queue head.
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_3;
mod new;
#[cfg(test)]
mod tests;

pub use items_1::current_priority;
pub use items_1::default_concurrency_for;
pub use items_1::with_priority;
pub use items_1::ModelGate;
pub use items_1::Priority;
pub use items_3::PriorityPermit;
