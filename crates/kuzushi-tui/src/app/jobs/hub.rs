use super::*;
use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::time::{Duration, Instant};

pub(super) const JOB_EVENT_CHANNEL_CAPACITY: usize = 4096;

/// Grace window between the watchdog's cooperative cancel and quarantine of a
/// worker that never polls its cancellation token. Rust cannot safely kill the
/// OS thread, so the logical slot remains owned until the worker really exits.
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
    /// When set, the watchdog's cooperative cancel went unanswered and the
    /// worker will be quarantined after the grace deadline.
    unresponsive_deadline: Option<Instant>,
    quarantined: bool,
}

#[derive(Debug)]
pub(crate) struct JobHub {
    tx: SyncSender<StampedShellEvent>,
    rx: Receiver<StampedShellEvent>,
    next_generation: u64,
    slots: BTreeMap<JobKind, JobSlot>,
    wake: Option<TerminalLoopWake>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JobStartConflict {
    pub(crate) kind: JobKind,
    pub(crate) label: String,
}

impl Default for JobHub {
    fn default() -> Self {
        let (tx, rx) = mpsc::sync_channel(JOB_EVENT_CHANNEL_CAPACITY);
        Self {
            tx,
            rx,
            next_generation: 0,
            slots: BTreeMap::new(),
            wake: None,
        }
    }
}

impl ShellApp {
    pub(crate) fn try_start_exclusive_job(
        &mut self,
        kind: JobKind,
        label: impl Into<String>,
    ) -> Option<JobTicket> {
        let label = label.into();
        match self.jobs_mut().try_start(kind, label.clone()) {
            Ok(ticket) => Some(ticket),
            Err(conflict) => {
                self.log(
                    "jobs",
                    format!(
                        "{label} blocked — {} ({:?}) still owns the background execution slot",
                        conflict.label, conflict.kind
                    ),
                );
                None
            }
        }
    }
}

impl JobHub {
    pub(crate) fn set_wake(&mut self, wake: Option<TerminalLoopWake>) {
        self.wake = wake;
    }

    pub(crate) fn try_start(
        &mut self,
        kind: JobKind,
        label: impl Into<String>,
    ) -> Result<JobTicket, JobStartConflict> {
        if let Some((active_kind, slot)) = self.slots.iter().next() {
            return Err(JobStartConflict {
                kind: *active_kind,
                label: slot.label.clone(),
            });
        }
        Ok(self.replace_slot(kind, label))
    }

    #[cfg(test)]
    pub(crate) fn start(&mut self, kind: JobKind, label: impl Into<String>) -> JobTicket {
        self.replace_slot(kind, label)
    }

    fn replace_slot(&mut self, kind: JobKind, label: impl Into<String>) -> JobTicket {
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
                quarantined: false,
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

    pub(crate) fn has_running_job(&self) -> bool {
        !self.slots.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn running_label(&self, kind: JobKind) -> Option<&str> {
        self.slots.get(&kind).map(|slot| slot.label.as_str())
    }

    /// Label of the one job that owns the execution slot. `try_start` refuses
    /// a second job, so there is at most one — which is what lets a stop
    /// request name what it is stopping, even when the job was launched from
    /// a view the operator has since left.
    pub(crate) fn live_job_label(&self) -> Option<&str> {
        self.slots.values().next().map(|slot| slot.label.as_str())
    }

    pub(crate) fn cancel_requested(&self, kind: JobKind) -> bool {
        self.slots
            .get(&kind)
            .is_some_and(|slot| slot.cancel.is_cancelled())
    }

    pub(crate) fn has_cancel_requested(&self) -> bool {
        self.slots.values().any(|slot| slot.cancel.is_cancelled())
    }

    #[cfg(test)]
    pub(crate) fn is_quarantined(&self, kind: JobKind) -> bool {
        self.slots.get(&kind).is_some_and(|slot| slot.quarantined)
    }

    pub(crate) fn has_quarantined_slot(&self) -> bool {
        self.slots.values().any(|slot| slot.quarantined)
    }

    pub(crate) fn cancel(&mut self, kind: JobKind) -> bool {
        let Some(slot) = self.slots.get_mut(&kind) else {
            return false;
        };
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

    /// Quarantine every slot whose watchdog-cancel grace window elapsed. The
    /// slot intentionally remains occupied: accepting new work while the OS
    /// thread is alive would permit overlapping workspace side effects.
    pub(crate) fn quarantine_unresponsive_slots(&mut self, now: Instant) -> bool {
        let mut quarantined = false;
        for slot in self.slots.values_mut().filter(|slot| {
            slot.unresponsive_deadline
                .is_some_and(|deadline| deadline <= now)
        }) {
            slot.unresponsive_deadline = None;
            slot.quarantined = true;
            quarantined = true;
        }
        quarantined
    }

    pub(crate) fn finish(&mut self, kind: JobKind) {
        self.slots.remove(&kind);
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
}
