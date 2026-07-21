use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub(crate) const LIVE_TRACE_CHANNEL_CAPACITY: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkerGeneration(u64);

impl WorkerGeneration {
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) fn next(value: &mut u64) -> Self {
        *value = value.saturating_add(1);
        Self::new(*value)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LiveTraceBudget {
    pending: Arc<AtomicUsize>,
    dropped_live: Arc<AtomicUsize>,
}

impl LiveTraceBudget {
    pub(crate) fn new() -> Self {
        Self {
            pending: Arc::new(AtomicUsize::new(0)),
            dropped_live: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn try_reserve(&self) -> bool {
        let mut current = self.pending.load(Ordering::Relaxed);
        while current < LIVE_TRACE_CHANNEL_CAPACITY {
            match self.pending.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(next) => current = next,
            }
        }
        false
    }

    fn record_dropped_live_copy(&self) {
        self.dropped_live.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn release(&self) {
        let _ = self
            .pending
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |value| {
                value.checked_sub(1)
            });
    }

    pub(crate) fn take_dropped_live(&self) -> usize {
        self.dropped_live.swap(0, Ordering::AcqRel)
    }

    #[cfg(test)]
    pub(crate) fn reserve_for_test(&self) -> bool {
        self.try_reserve()
    }

    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn dropped_live(&self) -> usize {
        self.dropped_live.load(Ordering::Acquire)
    }
}

pub(crate) struct StampedTraceSink {
    inner: Arc<dyn kuzushi_core::TraceSink>,
    sink: JobEventSink,
    budget: LiveTraceBudget,
}

impl StampedTraceSink {
    pub(crate) fn new(
        inner: Arc<dyn kuzushi_core::TraceSink>,
        sink: JobEventSink,
        budget: LiveTraceBudget,
    ) -> Self {
        Self {
            inner,
            sink,
            budget,
        }
    }
}

impl kuzushi_core::TraceSink for StampedTraceSink {
    fn record(&self, step: &RunTraceStep) {
        self.inner.record(step);
        if !self.budget.try_reserve() {
            self.budget.record_dropped_live_copy();
            return;
        }
        if !self.sink.send(ShellEvent::Trace(step.clone())) {
            self.budget.release();
        }
    }

    fn run_artifact_location(&self) -> Option<(PathBuf, String)> {
        self.inner.run_artifact_location()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::TraceSink;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingTraceSink {
        steps: Mutex<Vec<RunTraceStep>>,
    }

    impl kuzushi_core::TraceSink for RecordingTraceSink {
        fn record(&self, step: &RunTraceStep) {
            self.steps.lock().unwrap().push(step.clone());
        }

        fn run_artifact_location(&self) -> Option<(PathBuf, String)> {
            None
        }
    }

    #[test]
    fn stamped_trace_sink_drops_only_live_ui_copy_when_channel_is_full() {
        let inner = Arc::new(RecordingTraceSink::default());
        let inner_sink: Arc<dyn kuzushi_core::TraceSink> = inner.clone();
        let mut hub = JobHub::default();
        let ticket = hub.start(JobKind::Run, "tool");
        let budget = LiveTraceBudget::new();
        for _ in 0..LIVE_TRACE_CHANNEL_CAPACITY {
            assert!(budget.try_reserve());
        }
        let sink = StampedTraceSink::new(inner_sink, ticket.sink(), budget.clone());

        sink.record(&RunTraceStep::new(1, "reasoning", "kept"));
        sink.record(&RunTraceStep::new(2, "reasoning", "dropped-live-copy"));

        assert_eq!(inner.steps.lock().unwrap().len(), 2);
        assert_eq!(budget.dropped_live(), 2);
        assert!(hub.drain(1).is_empty());
    }

    #[test]
    fn stamped_trace_sink_releases_budget_when_job_kind_rejects_event() {
        let inner = Arc::new(RecordingTraceSink::default());
        let inner_sink: Arc<dyn kuzushi_core::TraceSink> = inner.clone();
        let mut hub = JobHub::default();
        let ticket = hub.start(JobKind::Plan, "planner");
        let budget = LiveTraceBudget::new();
        let sink = StampedTraceSink::new(inner_sink, ticket.sink(), budget.clone());

        sink.record(&RunTraceStep::new(1, "reasoning", "gone"));

        assert_eq!(inner.steps.lock().unwrap().len(), 1);
        assert_eq!(budget.pending(), 0);
    }

    #[test]
    fn stamped_trace_sink_notifies_terminal_loop_after_live_trace_enqueue() {
        let inner_sink: Arc<dyn kuzushi_core::TraceSink> = Arc::new(RecordingTraceSink::default());
        let mut hub = JobHub::default();
        let (inbox, wake) = TerminalLoopInbox::channel_for_test();
        hub.set_wake(Some(wake));
        let ticket = hub.start(JobKind::Run, "tool");
        let sink = StampedTraceSink::new(inner_sink, ticket.sink(), LiveTraceBudget::new());

        sink.record(&RunTraceStep::new(1, "reasoning", "queued"));

        assert!(matches!(hub.drain(1).pop(), Some(ShellEvent::Trace(_))));
        assert!(matches!(
            inbox
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));
    }
}
