use super::*;
use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::time::{Duration, Instant};

pub(super) const JOB_EVENT_CHANNEL_CAPACITY: usize = 4096;

/// Grace window between the watchdog's cooperative cancel and the synthetic
/// terminal failure that releases the slot of a worker that never polls its
/// cancellation token. The OS thread is left alone (killing it is unsafe);
/// only the logical job slot is released with an honest failure.
pub(crate) const WORKER_UNRESPONSIVE_GRACE: Duration = Duration::from_secs(30);

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
    label: String,
    /// When set, the watchdog's cooperative cancel went unanswered; once this
    /// deadline passes with no terminal event, the hub emits a synthetic
    /// failure to release the slot.
    unresponsive_deadline: Option<Instant>,
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
                label: label.clone(),
                unresponsive_deadline: None,
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

    /// Arm the unresponsive-worker escalation for a slot whose watchdog just
    /// requested a cooperative cancel. No-op if the slot changed generation or
    /// is already armed.
    pub(crate) fn schedule_unresponsive_escalation(
        &mut self,
        kind: JobKind,
        generation: WorkerGeneration,
        now: Instant,
    ) {
        let Some(slot) = self.slots.get_mut(&kind) else {
            return;
        };
        if slot.generation != generation || slot.unresponsive_deadline.is_some() {
            return;
        }
        slot.unresponsive_deadline = Some(now + WORKER_UNRESPONSIVE_GRACE);
    }

    /// Emit a synthetic terminal failure for every slot whose watchdog-cancel
    /// grace window has elapsed with no terminal event, so the slot is
    /// released and new work can start. Returns true if any failure was sent.
    pub(crate) fn fail_unresponsive_slots(&mut self, now: Instant) -> bool {
        let due: Vec<JobKind> = self
            .slots
            .iter()
            .filter(|(_, slot)| slot.unresponsive_deadline.is_some_and(|d| d <= now))
            .map(|(kind, _)| *kind)
            .collect();
        let mut failed_any = false;
        for kind in due {
            failed_any |= self.fail_unresponsive_slot(kind);
        }
        failed_any
    }

    fn fail_unresponsive_slot(&mut self, kind: JobKind) -> bool {
        let Some(slot) = self.slots.get_mut(&kind) else {
            return false;
        };
        let event = ShellEvent::failure(
            kind,
            &slot.label,
            "worker unresponsive: no terminal event after watchdog cancel; releasing job slot"
                .to_string(),
        );
        let stamped = StampedShellEvent {
            kind,
            generation: slot.generation,
            event,
        };
        if self.tx.try_send(stamped).is_err() {
            // Channel full: keep the deadline armed and retry next tick.
            return false;
        }
        slot.unresponsive_deadline = None;
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
