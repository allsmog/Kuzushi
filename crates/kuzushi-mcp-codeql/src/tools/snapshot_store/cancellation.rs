use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct SnapshotCancellation {
    cancelled: AtomicBool,
    changed: Notify,
}

impl SnapshotCancellation {
    pub(super) fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.changed.notify_waiters();
        }
    }

    pub(super) async fn cancelled(&self) {
        let changed = self.changed.notified();
        if self.is_cancelled() {
            return;
        }
        changed.await;
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}
