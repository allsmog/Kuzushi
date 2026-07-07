use super::*;
use std::fmt;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(crate) struct WorkerHandleRegistry {
    handles: Vec<TrackedWorkerHandle>,
}

impl WorkerHandleRegistry {
    pub(crate) fn register(
        &mut self,
        label: &'static str,
        generation: WorkerGeneration,
        handle: JoinHandle<()>,
    ) {
        self.handles.push(TrackedWorkerHandle {
            label,
            generation,
            handle,
            started_at: Instant::now(),
            watchdog: None,
        });
    }

    pub(crate) fn register_with_watchdog(
        &mut self,
        label: &'static str,
        generation: WorkerGeneration,
        handle: JoinHandle<()>,
        watchdog: Option<WorkerWatchdog>,
    ) {
        self.handles.push(TrackedWorkerHandle {
            label,
            generation,
            handle,
            started_at: Instant::now(),
            watchdog: watchdog.map(TrackedWorkerWatchdog::new),
        });
    }

    pub(crate) fn reap_finished(&mut self) -> Vec<FinishedWorkerHandle> {
        let mut finished = Vec::new();
        let mut active = Vec::with_capacity(self.handles.len());
        for tracked in self.handles.drain(..) {
            if tracked.handle.is_finished() {
                finished.push(tracked.join());
            } else {
                active.push(tracked);
            }
        }
        self.handles = active;
        finished
    }

    pub(crate) fn cancel_timed_out(&mut self, now: Instant) -> Vec<TimedOutWorkerHandle> {
        self.handles
            .iter_mut()
            .filter_map(|tracked| tracked.cancel_if_timed_out(now))
            .collect()
    }

    pub(crate) fn active_count(&self) -> usize {
        self.handles.len()
    }
}

impl Default for WorkerHandleRegistry {
    fn default() -> Self {
        Self {
            handles: Vec::new(),
        }
    }
}

impl fmt::Debug for WorkerHandleRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerHandleRegistry")
            .field("active_count", &self.active_count())
            .finish()
    }
}

struct TrackedWorkerHandle {
    label: &'static str,
    generation: WorkerGeneration,
    handle: JoinHandle<()>,
    started_at: Instant,
    watchdog: Option<TrackedWorkerWatchdog>,
}

impl TrackedWorkerHandle {
    fn join(self) -> FinishedWorkerHandle {
        FinishedWorkerHandle {
            label: self.label,
            generation: self.generation,
            panicked: self.handle.join().is_err(),
        }
    }

    fn cancel_if_timed_out(&mut self, now: Instant) -> Option<TimedOutWorkerHandle> {
        if self.handle.is_finished() {
            return None;
        }
        let watchdog = self.watchdog.as_mut()?;
        let elapsed = now.saturating_duration_since(self.started_at);
        watchdog.cancel_if_timed_out(self.label, self.generation, elapsed)
    }
}

pub(crate) struct WorkerWatchdog {
    cancel: ScanCancellation,
    timeout: Duration,
}

impl WorkerWatchdog {
    pub(crate) fn new(cancel: ScanCancellation, timeout: Duration) -> Self {
        Self { cancel, timeout }
    }
}

struct TrackedWorkerWatchdog {
    cancel: ScanCancellation,
    timeout: Duration,
    timeout_reported: bool,
}

impl TrackedWorkerWatchdog {
    fn new(watchdog: WorkerWatchdog) -> Self {
        Self {
            cancel: watchdog.cancel,
            timeout: watchdog.timeout,
            timeout_reported: false,
        }
    }

    fn cancel_if_timed_out(
        &mut self,
        label: &'static str,
        generation: WorkerGeneration,
        elapsed: Duration,
    ) -> Option<TimedOutWorkerHandle> {
        if self.timeout_reported || elapsed < self.timeout {
            return None;
        }
        self.timeout_reported = true;
        self.cancel.cancel();
        Some(TimedOutWorkerHandle {
            label,
            generation,
            elapsed,
            timeout: self.timeout,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FinishedWorkerHandle {
    pub(crate) label: &'static str,
    pub(crate) generation: WorkerGeneration,
    pub(crate) panicked: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TimedOutWorkerHandle {
    pub(crate) label: &'static str,
    pub(crate) generation: WorkerGeneration,
    pub(crate) elapsed: Duration,
    pub(crate) timeout: Duration,
}
