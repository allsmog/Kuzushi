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
