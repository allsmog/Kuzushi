use super::*;

pub struct PriorityPermit {
    pub(crate) permit: Option<OwnedSemaphorePermit>,
    pub(crate) slot: ModelSlot,
    pub(crate) gate: ModelGate,
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

/// RAII cleanup for a queued (but not-yet-serviced) [`ModelGate::acquire`]
/// waiter. If the acquiring future is dropped — cancelled, timed out, or
/// unwound — before it obtains a permit, this guard removes the waiter's
/// `Notify` from its band so it can never strand the queue head, then wakes
/// the next live head so forward progress resumes.
///
/// The guard is disarmed on the success path (once the waiter has popped
/// itself off the queue), so it never double-removes or double-notifies.
///
/// Invariant: a cancelled waiter must not leave a dangling `Arc<Notify>` at
/// the head of any band. If it did, `queue_head` would keep returning a
/// waiter that will never `try_acquire_owned()` again, and every subsequent
/// `notify_next_head` would wake a dead notify — a permanent stall.
pub(crate) struct QueueTicket {
    queues: Arc<Mutex<[VecDeque<Arc<Notify>>; 3]>>,
    permit_released: Arc<Notify>,
    notify: Arc<Notify>,
    band: usize,
    armed: bool,
}

impl QueueTicket {
    pub(crate) fn new(slot: &ModelSlot, notify: Arc<Notify>, band: usize) -> Self {
        Self {
            queues: Arc::clone(&slot.queues),
            permit_released: Arc::clone(&slot.permit_released),
            notify,
            band,
            armed: true,
        }
    }

    /// Stop the guard from touching the queue on drop. Call this only after
    /// the waiter has already removed itself (i.e. on the acquire path).
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for QueueTicket {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut queues = self.queues.lock().expect("queues poisoned");
        if let Some(index) = queues[self.band]
            .iter()
            .position(|waiter| Arc::ptr_eq(waiter, &self.notify))
        {
            queues[self.band].remove(index);
        }
        // Wake whatever is now the highest-priority head. A spurious wake is
        // safe: the acquire loop re-checks head identity and capacity.
        let next_head = queue_head(&queues);
        drop(queues);
        if let Some(head) = next_head {
            head.notify_one();
        }
        // The promoted head may currently be parked on `permit_released`
        // (it saw itself as head but had no capacity). Re-arm it so it
        // re-evaluates instead of sleeping until the next permit release.
        self.permit_released.notify_waiters();
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

pub(crate) fn queue_head(queues: &[VecDeque<Arc<Notify>>; 3]) -> Option<Arc<Notify>> {
    for q in queues {
        if let Some(front) = q.front() {
            return Some(Arc::clone(front));
        }
    }
    None
}
