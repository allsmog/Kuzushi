use super::hub::StampedShellEvent;
use super::*;
use std::any::Any;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::JoinHandle;

pub(crate) struct JobTicket {
    kind: JobKind,
    generation: WorkerGeneration,
    tx: SyncSender<StampedShellEvent>,
    label: String,
    pub(crate) cancel: ScanCancellation,
    wake: Option<TerminalLoopWake>,
    terminal_sent: Arc<AtomicBool>,
    guard: PanicGuard,
}

#[derive(Clone)]
pub(crate) struct JobEventSink {
    kind: JobKind,
    generation: WorkerGeneration,
    tx: SyncSender<StampedShellEvent>,
    wake: Option<TerminalLoopWake>,
    terminal_sent: Arc<AtomicBool>,
}

impl JobTicket {
    pub(super) fn new(
        kind: JobKind,
        generation: WorkerGeneration,
        label: String,
        tx: SyncSender<StampedShellEvent>,
        cancel: ScanCancellation,
        wake: Option<TerminalLoopWake>,
    ) -> Self {
        let terminal_sent = Arc::new(AtomicBool::new(false));
        let guard = PanicGuard::new(
            kind,
            generation,
            label.clone(),
            tx.clone(),
            wake.clone(),
            terminal_sent.clone(),
        );
        Self {
            kind,
            generation,
            tx,
            label,
            cancel,
            wake,
            terminal_sent,
            guard,
        }
    }

    #[cfg(test)]
    pub(crate) fn kind(&self) -> JobKind {
        self.kind
    }

    pub(crate) fn generation(&self) -> WorkerGeneration {
        self.generation
    }

    #[cfg(test)]
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn sink(&self) -> JobEventSink {
        JobEventSink {
            kind: self.kind,
            generation: self.generation,
            tx: self.tx.clone(),
            wake: self.wake.clone(),
            terminal_sent: self.terminal_sent.clone(),
        }
    }

    pub(crate) fn send(&self, event: ShellEvent) -> bool {
        self.sink().send(event)
    }

    pub(crate) fn fail(&self, error: String) -> bool {
        self.send(ShellEvent::failure(self.kind, &self.label, error))
    }

    fn terminal_sent(&self) -> bool {
        self.terminal_sent.load(Ordering::Acquire)
    }

    pub(crate) fn complete(mut self) {
        self.guard.disarm();
    }
}

impl JobEventSink {
    pub(crate) fn generation(&self) -> WorkerGeneration {
        self.generation
    }

    pub(crate) fn send(&self, event: ShellEvent) -> bool {
        if !event.is_operator_interaction() && event.kind() != self.kind {
            return false;
        }
        self.send_unchecked(event)
    }

    fn send_unchecked(&self, event: ShellEvent) -> bool {
        let terminal = event.is_terminal();
        let stamped = StampedShellEvent {
            kind: self.kind,
            generation: self.generation,
            event,
        };
        let reliable = terminal
            || matches!(
                &stamped.event,
                ShellEvent::OperatorQuestion(_)
                    | ShellEvent::OperatorQuestionCompleted(_)
                    | ShellEvent::CredentialQuestionRouted { .. }
            );
        let sent = if reliable {
            self.tx.send(stamped).is_ok()
        } else {
            self.tx.try_send(stamped).is_ok()
        };
        if sent {
            if terminal {
                self.terminal_sent.store(true, Ordering::Release);
            }
            notify_terminal_loop(&self.wake);
        }
        sent
    }
}

struct PanicGuard {
    kind: JobKind,
    generation: WorkerGeneration,
    label: String,
    tx: SyncSender<StampedShellEvent>,
    wake: Option<TerminalLoopWake>,
    terminal_sent: Arc<AtomicBool>,
    armed: bool,
}

impl PanicGuard {
    fn new(
        kind: JobKind,
        generation: WorkerGeneration,
        label: String,
        tx: SyncSender<StampedShellEvent>,
        wake: Option<TerminalLoopWake>,
        terminal_sent: Arc<AtomicBool>,
    ) -> Self {
        Self {
            kind,
            generation,
            label,
            tx,
            wake,
            terminal_sent,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PanicGuard {
    fn drop(&mut self) {
        if !self.armed || self.terminal_sent.load(Ordering::Acquire) {
            return;
        }
        let event = ShellEvent::failure(
            self.kind,
            &self.label,
            format!("{} worker ended without reporting completion", self.label),
        );
        let sent = self
            .tx
            .send(StampedShellEvent {
                kind: self.kind,
                generation: self.generation,
                event,
            })
            .is_ok();
        if sent {
            notify_terminal_loop(&self.wake);
        }
    }
}

pub(crate) fn spawn_job_worker<F>(
    worker_label: &'static str,
    ticket: JobTicket,
    body: F,
) -> JoinHandle<()>
where
    F: FnOnce(JobEventSink, ScanCancellation) + Send + 'static,
{
    std::thread::spawn(move || {
        let sink = ticket.sink();
        let cancel = ticket.cancel.clone();
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            body(sink, cancel);
        })) {
            if !ticket.terminal_sent() {
                ticket.fail(worker_panic_message(worker_label, payload));
            }
            ticket.complete();
        }
    })
}

fn worker_panic_message(worker_label: &str, payload: Box<dyn Any + Send>) -> String {
    format!(
        "{worker_label} worker panicked: {}",
        panic_payload_text(&*payload)
    )
}

fn panic_payload_text(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "non-string panic payload".to_string()
}

fn notify_terminal_loop(wake: &Option<TerminalLoopWake>) {
    if let Some(wake) = wake {
        wake.notify();
    }
}
