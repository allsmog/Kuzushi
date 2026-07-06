use super::*;
use std::any::Any;
use std::thread::JoinHandle;

pub(crate) fn spawn_panic_safe_worker<T, F, G>(
    worker_label: &'static str,
    tx: Sender<StampedEvent<T>>,
    generation: WorkerGeneration,
    wake: Option<TerminalLoopWake>,
    body: F,
    failure_event: G,
) -> JoinHandle<()>
where
    T: Send + 'static,
    F: FnOnce() + Send + 'static,
    G: FnOnce(String) -> T + Send + 'static,
{
    std::thread::spawn(move || {
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
            let event = failure_event(worker_panic_message(worker_label, payload));
            let _ = tx.send(StampedEvent::new(generation, event));
            notify_terminal_loop(&wake);
        }
    })
}

pub(crate) fn notify_terminal_loop(wake: &Option<TerminalLoopWake>) {
    if let Some(wake) = wake {
        wake.notify();
    }
}

pub(super) fn worker_panic_message(worker_label: &str, payload: Box<dyn Any + Send>) -> String {
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
