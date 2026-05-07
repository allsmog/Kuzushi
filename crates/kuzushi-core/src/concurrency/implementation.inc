use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

/// Stage priority bands. Set via [`with_priority`] before calling routed
/// agent functions. Higher variants preempt lower in the wait queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Interactive operator action — patcher, deep auditor.
    High,
    /// Default for triage and classifier-gate calls.
    Normal,
    /// Background full-mode-multi chunks; yields to everything else.
    Lowest,
}

impl Priority {
    fn band(self) -> usize {
        match self {
            Priority::High => 0,
            Priority::Normal => 1,
            Priority::Lowest => 2,
        }
    }
}

tokio::task_local! {
    /// Current task's priority. Falls back to `Normal` when not scoped.
    pub static CURRENT_PRIORITY: Priority;
}

pub fn current_priority() -> Priority {
    CURRENT_PRIORITY
        .try_with(|p| *p)
        .unwrap_or(Priority::Normal)
}

/// Run `fut` with `CURRENT_PRIORITY` scoped to `priority`.
pub async fn with_priority<F, T>(priority: Priority, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    CURRENT_PRIORITY.scope(priority, fut).await
}

/// Default per-model concurrency caps when not overridden by
/// `models.toml [concurrency]`. Numbers mirror RoboDuck's tested values
/// for production AIxCC traffic.
pub fn default_concurrency_for(model: &str) -> usize {
    let m = model.to_ascii_lowercase();
    if m.contains("haiku") {
        80
    } else if m.contains("sonnet") {
        80
    } else if m.contains("opus") {
        60
    } else if m.contains("gemini") {
        600
    } else if m.contains("o3") || m.contains("o1") {
        700
    } else if m.contains("o4") || m.contains("gpt-4.1") || m.contains("gpt-4o") {
        500
    } else {
        // Conservative default for unknown models.
        16
    }
}

/// Per-model priority gate. One [`Semaphore`] per model, plus a fair
/// priority queue that hands out permits in priority-then-FIFO order.
///
/// Design: only the queue *head* may attempt `try_acquire_owned()` on the
/// underlying semaphore. Non-head waiters block on a per-waiter `Notify`
/// until they become head. When a permit is released, we wake the
/// current head. This sidesteps Tokio's internal FIFO inside `Semaphore`
/// — without this layer, `acquire_owned` futures would resolve in
/// arrival order regardless of priority.
pub struct ModelGate {
    inner: Arc<ModelGateInner>,
}

struct ModelGateInner {
    semaphores: Mutex<BTreeMap<String, ModelSlot>>,
    overrides: Mutex<BTreeMap<String, usize>>,
}

#[derive(Clone)]
struct ModelSlot {
    sem: Arc<Semaphore>,
    queues: Arc<Mutex<[VecDeque<Arc<Notify>>; 3]>>,
    /// Notified whenever a permit is released back to the slot.
    permit_released: Arc<Notify>,
}

impl ModelGate {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ModelGateInner {
                semaphores: Mutex::new(BTreeMap::new()),
                overrides: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// Install a per-model cap from configuration. Re-calling with a new
    /// value replaces the existing semaphore — outstanding permits are
    /// honoured but new acquisitions go through the fresh semaphore.
    pub fn set_cap(&self, model: &str, cap: usize) {
        self.inner
            .overrides
            .lock()
            .expect("overrides poisoned")
            .insert(model.to_string(), cap.max(1));
        // Force re-creation on next acquire.
        self.inner
            .semaphores
            .lock()
            .expect("semaphores poisoned")
            .remove(model);
    }

    /// Configured cap for `model`, falling back to the default heuristic.
    pub fn cap_for(&self, model: &str) -> usize {
        if let Some(&cap) = self
            .inner
            .overrides
            .lock()
            .expect("overrides poisoned")
            .get(model)
        {
            return cap;
        }
        default_concurrency_for(model)
    }

    /// Acquire a permit for `model` at `priority`. The future resolves
    /// when the underlying semaphore has capacity AND no higher-priority
    /// waiter is queued ahead. Returns a [`PriorityPermit`] that releases
    /// on drop and wakes the next queue head.
    pub async fn acquire(&self, model: &str, priority: Priority) -> PriorityPermit {
        let slot = self.slot(model);
        let notify = Arc::new(Notify::new());

        {
            let mut queues = slot.queues.lock().expect("queues poisoned");
            queues[priority.band()].push_back(Arc::clone(&notify));
        }

        loop {
            // Are we head?
            let head = queue_head(&slot.queues.lock().expect("queues poisoned"));
            let is_head = head
                .as_ref()
                .map(|h| Arc::ptr_eq(h, &notify))
                .unwrap_or(false);

            if !is_head {
                notify.notified().await;
                continue;
            }

            // Head — try to acquire a permit immediately.
            match Arc::clone(&slot.sem).try_acquire_owned() {
                Ok(permit) => {
                    // Pop self and wake the next head (in case a permit is
                    // already free for them).
                    {
                        let mut queues = slot.queues.lock().expect("queues poisoned");
                        queues[priority.band()].pop_front();
                    }
                    self.notify_next_head(&slot);
                    return PriorityPermit {
                        permit: Some(permit),
                        slot,
                        gate: self.clone(),
                    };
                }
                Err(_) => {
                    // No capacity. Wait for a permit-release notification,
                    // then re-check head status (a higher-priority waiter
                    // may have arrived in the meantime).
                    slot.permit_released.notified().await;
                }
            }
        }
    }

    fn slot(&self, model: &str) -> ModelSlot {
        let mut semaphores = self.inner.semaphores.lock().expect("semaphores poisoned");
        if let Some(slot) = semaphores.get(model) {
            return slot.clone();
        }
        let cap = self.cap_for(model);
        let slot = ModelSlot {
            sem: Arc::new(Semaphore::new(cap)),
            queues: Arc::new(Mutex::new([
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
            ])),
            permit_released: Arc::new(Notify::new()),
        };
        let cloned = slot.clone();
        semaphores.insert(model.to_string(), slot);
        cloned
    }

    fn notify_next_head(&self, slot: &ModelSlot) {
        let queues = slot.queues.lock().expect("queues poisoned");
        if let Some(head) = queue_head(&queues) {
            head.notify_one();
        }
    }
}

/// Permit returned by [`ModelGate::acquire`]. Releases on drop and wakes
/// the next priority-queue head.
pub struct PriorityPermit {
    permit: Option<OwnedSemaphorePermit>,
    slot: ModelSlot,
    gate: ModelGate,
}

impl Drop for PriorityPermit {
    fn drop(&mut self) {
        // Release the semaphore before notifying waiters. If we notify first,
        // the queue head can wake, observe no capacity, and go back to sleep
        // with no later notification from the permit release.
        drop(self.permit.take());
        self.slot.permit_released.notify_waiters();
        self.gate.notify_next_head(&self.slot);
    }
}

impl Default for ModelGate {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ModelGate {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

fn queue_head(queues: &[VecDeque<Arc<Notify>>; 3]) -> Option<Arc<Notify>> {
    for q in queues {
        if let Some(front) = q.front() {
            return Some(Arc::clone(front));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cap_limits_in_flight_to_configured_value() {
        let gate = ModelGate::new();
        gate.set_cap("test:m", 2);

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let g = gate.clone();
            let in_flight = Arc::clone(&in_flight);
            let max_seen = Arc::clone(&max_seen);
            handles.push(tokio::spawn(async move {
                let _permit = g.acquire("test:m", Priority::Normal).await;
                let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(max_seen.load(Ordering::SeqCst) <= 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn high_priority_preempts_low_priority_in_queue() {
        let gate = ModelGate::new();
        gate.set_cap("test:m", 1);

        // Take the only permit so subsequent acquires queue.
        let _hold = gate.acquire("test:m", Priority::Normal).await;

        let order = Arc::new(Mutex::new(Vec::new()));

        let g1 = gate.clone();
        let order1 = Arc::clone(&order);
        let lo1 = tokio::spawn(async move {
            let _p = g1.acquire("test:m", Priority::Lowest).await;
            order1.lock().unwrap().push("lo1");
        });
        // Give lo1 time to enqueue.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let g2 = gate.clone();
        let order2 = Arc::clone(&order);
        let hi = tokio::spawn(async move {
            let _p = g2.acquire("test:m", Priority::High).await;
            order2.lock().unwrap().push("hi");
        });
        // Give hi time to enqueue.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Now release the held permit — hi should win even though lo1
        // queued first.
        drop(_hold);
        lo1.await.unwrap();
        hi.await.unwrap();

        let order = order.lock().unwrap();
        assert_eq!(order.as_slice(), &["hi", "lo1"]);
    }

    #[tokio::test]
    async fn priority_scope_propagates_via_task_local() {
        with_priority(Priority::Lowest, async {
            assert_eq!(current_priority(), Priority::Lowest);
            // Nested scope wins.
            with_priority(Priority::High, async {
                assert_eq!(current_priority(), Priority::High);
            })
            .await;
            assert_eq!(current_priority(), Priority::Lowest);
        })
        .await;
        // Outside any scope falls back to Normal.
        assert_eq!(current_priority(), Priority::Normal);
    }

    #[test]
    fn default_concurrency_table_matches_known_models() {
        assert_eq!(default_concurrency_for("anthropic:claude-haiku-4-5"), 80);
        assert_eq!(default_concurrency_for("anthropic:claude-opus-4-7"), 60);
        assert_eq!(default_concurrency_for("google:gemini-2.5-pro"), 600);
        assert_eq!(default_concurrency_for("openai:o3-2025-04-16"), 700);
        assert_eq!(default_concurrency_for("openai:gpt-4o"), 500);
        // Unknown model — conservative.
        assert_eq!(default_concurrency_for("anthropic:unknown-99"), 16);
    }

    #[test]
    fn set_cap_is_idempotent_and_persists_across_acquires() {
        let gate = ModelGate::new();
        gate.set_cap("test:m", 5);
        assert_eq!(gate.cap_for("test:m"), 5);
        gate.set_cap("test:m", 7);
        assert_eq!(gate.cap_for("test:m"), 7);
    }
}
