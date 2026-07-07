use super::*;
use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};

pub(super) const JOB_EVENT_CHANNEL_CAPACITY: usize = 4096;

#[derive(Debug)]
pub(super) struct StampedShellEvent {
    pub(super) kind: JobKind,
    pub(super) generation: WorkerGeneration,
    pub(super) event: ShellEvent,
}

#[derive(Debug)]
pub(crate) enum JobDrainResult {
    Event(ShellEvent),
    Stale,
    Empty,
}

#[derive(Debug)]
struct JobSlot {
    generation: WorkerGeneration,
    cancel: ScanCancellation,
    #[cfg(test)]
    label: String,
    #[cfg(test)]
    cancel_requested: bool,
}

#[derive(Debug)]
pub(crate) struct JobHub {
    tx: SyncSender<StampedShellEvent>,
    rx: Receiver<StampedShellEvent>,
    next_generation: u64,
    slots: BTreeMap<JobKind, JobSlot>,
    trace_budget: LiveTraceBudget,
    wake: Option<TerminalLoopWake>,
}

impl Default for JobHub {
    fn default() -> Self {
        let (tx, rx) = mpsc::sync_channel(JOB_EVENT_CHANNEL_CAPACITY);
        Self {
            tx,
            rx,
            next_generation: 0,
            slots: BTreeMap::new(),
            trace_budget: LiveTraceBudget::new(),
            wake: None,
        }
    }
}

impl JobHub {
    pub(crate) fn set_wake(&mut self, wake: Option<TerminalLoopWake>) {
        self.wake = wake;
    }

    pub(crate) fn start(&mut self, kind: JobKind, label: impl Into<String>) -> JobTicket {
        let generation = WorkerGeneration::next(&mut self.next_generation);
        let cancel = ScanCancellation::default();
        let label = label.into();
        self.slots.insert(
            kind,
            JobSlot {
                generation,
                cancel: cancel.clone(),
                #[cfg(test)]
                label: label.clone(),
                #[cfg(test)]
                cancel_requested: false,
            },
        );
        JobTicket::new(
            kind,
            generation,
            label,
            self.tx.clone(),
            cancel,
            self.wake.clone(),
        )
    }

    pub(crate) fn is_running(&self, kind: JobKind) -> bool {
        self.slots.contains_key(&kind)
    }

    #[cfg(test)]
    pub(crate) fn running_label(&self, kind: JobKind) -> Option<&str> {
        self.slots.get(&kind).map(|slot| slot.label.as_str())
    }

    #[cfg(test)]
    pub(crate) fn cancel_requested(&self, kind: JobKind) -> bool {
        self.slots
            .get(&kind)
            .is_some_and(|slot| slot.cancel_requested)
    }

    pub(crate) fn cancel(&mut self, kind: JobKind) -> bool {
        let Some(slot) = self.slots.get_mut(&kind) else {
            return false;
        };
        #[cfg(test)]
        {
            slot.cancel_requested = true;
        }
        slot.cancel.cancel();
        true
    }

    pub(crate) fn finish(&mut self, kind: JobKind) {
        self.slots.remove(&kind);
    }

    pub(crate) fn trace_budget(&self) -> LiveTraceBudget {
        self.trace_budget.clone()
    }

    #[cfg(test)]
    pub(crate) fn drain(&mut self, limit: usize) -> Vec<ShellEvent> {
        let mut events = Vec::with_capacity(limit);
        for _ in 0..limit {
            match self.drain_one() {
                JobDrainResult::Event(event) => events.push(event),
                JobDrainResult::Stale => {}
                JobDrainResult::Empty => break,
            }
        }
        events
    }

    pub(crate) fn drain_one(&mut self) -> JobDrainResult {
        let stamped = match self.rx.try_recv() {
            Ok(stamped) => stamped,
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return JobDrainResult::Empty,
        };
        self.release_trace_slot(&stamped.event);
        if self.is_current_generation(stamped.kind, stamped.generation) {
            JobDrainResult::Event(stamped.event)
        } else {
            JobDrainResult::Stale
        }
    }

    pub(crate) fn is_current_generation(
        &self,
        kind: JobKind,
        generation: WorkerGeneration,
    ) -> bool {
        self.slots
            .get(&kind)
            .is_some_and(|slot| slot.generation == generation)
    }

    fn release_trace_slot(&self, event: &ShellEvent) {
        if matches!(event, ShellEvent::Trace(_)) {
            self.trace_budget.release();
        }
    }
}
