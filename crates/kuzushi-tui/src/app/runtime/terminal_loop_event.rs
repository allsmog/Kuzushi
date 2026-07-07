use super::*;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;

pub(crate) enum TerminalLoopEvent {
    Terminal(TermEvent),
    Wake,
}

pub(crate) struct TerminalLoopInbox {
    rx: Receiver<Result<TerminalLoopEvent, String>>,
}

#[derive(Clone, Debug)]
pub(crate) struct TerminalLoopWake {
    tx: Sender<Result<TerminalLoopEvent, String>>,
}

impl TerminalLoopWake {
    pub(crate) fn notify(&self) {
        let _ = self.tx.send(Ok(TerminalLoopEvent::Wake));
    }
}

impl TerminalLoopInbox {
    pub(crate) fn spawn_crossterm_reader() -> (Self, TerminalLoopWake) {
        let (tx, rx) = mpsc::channel();
        let wake = TerminalLoopWake { tx: tx.clone() };
        thread::spawn(move || loop {
            let event = event::read()
                .map(terminal_loop_event_from_crossterm)
                .map_err(|error| error.to_string());
            if tx.send(event).is_err() {
                break;
            }
        });
        (Self { rx }, wake)
    }

    #[cfg(test)]
    pub(crate) fn from_receiver(rx: Receiver<Result<TerminalLoopEvent, String>>) -> Self {
        Self { rx }
    }

    #[cfg(test)]
    pub(crate) fn channel_for_test() -> (Self, TerminalLoopWake) {
        let (tx, rx) = mpsc::channel();
        (Self { rx }, TerminalLoopWake { tx })
    }

    pub(crate) fn recv_timeout(&self, timeout: Duration) -> Result<Option<TerminalLoopEvent>> {
        match self.rx.recv_timeout(timeout) {
            Ok(Ok(event)) => Ok(Some(event)),
            Ok(Err(error)) => anyhow::bail!("terminal event reader failed: {error}"),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => anyhow::bail!("terminal event reader stopped"),
        }
    }
}

fn terminal_loop_event_from_crossterm(event: Event) -> TerminalLoopEvent {
    TermEvent::from_crossterm(event)
        .map(TerminalLoopEvent::Terminal)
        .unwrap_or(TerminalLoopEvent::Wake)
}

pub(crate) fn wait_for_terminal_loop_event(
    app: &mut ShellApp,
    inbox: &TerminalLoopInbox,
) -> Result<bool> {
    match inbox.recv_timeout(terminal_event_timeout(app))? {
        Some(TerminalLoopEvent::Terminal(event)) => {
            Ok(update_and_execute_effects(app, Msg::Term(event)))
        }
        Some(TerminalLoopEvent::Wake) | None => Ok(false),
    }
}
