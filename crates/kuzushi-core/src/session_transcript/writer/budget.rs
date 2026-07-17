use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct OutstandingEventBudget {
    limit: usize,
    count: AtomicUsize,
}

impl OutstandingEventBudget {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            count: AtomicUsize::new(0),
        }
    }

    pub(super) fn try_reserve(&self) -> bool {
        self.count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.limit).then_some(count + 1)
            })
            .is_ok()
    }

    pub(super) fn release(&self) {
        let previous = self.count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "session event budget underflow");
    }

    pub(super) fn pending(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }
}
