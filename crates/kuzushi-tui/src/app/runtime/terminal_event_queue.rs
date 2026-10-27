use super::terminal_loop_event::TerminalLoopEvent;
use super::TermEvent;
use crossterm::event::MouseEventKind;
use std::collections::VecDeque;
use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub(super) type QueuedEvent = Result<TerminalLoopEvent, String>;
pub(super) const INPUT_EVENT_LIMIT: usize = 256;
pub(super) const INPUT_BYTE_LIMIT: usize = 4 * 1024 * 1024;
const PASTE_BYTE_LIMIT: usize = 1024 * 1024;

pub(super) enum TerminalEventReceiver {
    Bounded(std::sync::Arc<TerminalEventQueue>),
    #[cfg(test)]
    Scripted(std::sync::mpsc::Receiver<QueuedEvent>),
}

impl TerminalEventReceiver {
    pub(super) fn recv_timeout(&self, timeout: Duration) -> Result<QueuedEvent, RecvTimeoutError> {
        match self {
            Self::Bounded(queue) => queue.recv_timeout(timeout),
            #[cfg(test)]
            Self::Scripted(receiver) => receiver.recv_timeout(timeout),
        }
    }

    pub(super) fn try_recv(&self) -> Result<QueuedEvent, TryRecvError> {
        match self {
            Self::Bounded(queue) => queue.try_recv(),
            #[cfg(test)]
            Self::Scripted(receiver) => receiver.try_recv(),
        }
    }

    pub(super) fn close(&self) {
        match self {
            Self::Bounded(queue) => queue.close(),
            #[cfg(test)]
            Self::Scripted(_) => (),
        }
    }

    pub(super) fn stats(&self) -> InputQueueStats {
        match self {
            Self::Bounded(queue) => queue.stats(),
            #[cfg(test)]
            Self::Scripted(_) => InputQueueStats::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct InputQueueStats {
    pub queued: usize,
    pub bytes: usize,
    pub peak: usize,
    pub coalesced: u64,
    pub blocked: u64,
}

#[derive(Default)]
struct QueueState {
    events: VecDeque<QueuedEvent>,
    wake: bool,
    closed: bool,
    stats: InputQueueStats,
}

#[derive(Default)]
pub(super) struct TerminalEventQueue {
    state: Mutex<QueueState>,
    changed: Condvar,
}

impl std::fmt::Debug for TerminalEventQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalEventQueue")
            .field("stats", &self.stats())
            .finish()
    }
}

impl TerminalEventQueue {
    fn state(&self) -> MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(super) fn stats(&self) -> InputQueueStats {
        self.state().stats
    }

    pub(super) fn is_closed(&self) -> bool {
        self.state().closed
    }

    pub(super) fn close(&self) {
        self.state().closed = true;
        self.changed.notify_all();
    }

    /// Background notifications have one independent slot and never wait for
    /// terminal capacity: a consumer may itself be a notification producer.
    pub(super) fn notify(&self) -> bool {
        let mut state = self.state();
        if state.closed {
            return false;
        }
        state.wake = true;
        self.changed.notify_all();
        true
    }

    pub(super) fn send(&self, event: QueuedEvent) -> bool {
        if matches!(event, Ok(TerminalLoopEvent::Wake)) {
            return self.notify();
        }
        let mut event = bounded_event(event);
        let mut state = self.state();
        while !state.closed {
            event = match state.insert(event) {
                Ok(()) => {
                    self.changed.notify_all();
                    return true;
                }
                Err(event) => event,
            };
            state.stats.blocked = state.stats.blocked.saturating_add(1);
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
        false
    }

    pub(super) fn try_recv(&self) -> Result<QueuedEvent, TryRecvError> {
        let mut state = self.state();
        if let Some(event) = state.pop() {
            self.changed.notify_all();
            return Ok(event);
        }
        Err(if state.closed {
            TryRecvError::Disconnected
        } else {
            TryRecvError::Empty
        })
    }

    pub(super) fn recv_timeout(&self, timeout: Duration) -> Result<QueuedEvent, RecvTimeoutError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state();
        loop {
            if let Some(event) = state.pop() {
                self.changed.notify_all();
                return Ok(event);
            }
            require_waitable(&state, deadline)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            state = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|error| error.into_inner())
                .0;
        }
    }
}

fn require_waitable(state: &QueueState, deadline: Instant) -> Result<(), RecvTimeoutError> {
    if state.closed {
        return Err(RecvTimeoutError::Disconnected);
    }
    if Instant::now() >= deadline {
        return Err(RecvTimeoutError::Timeout);
    }
    Ok(())
}

impl QueueState {
    fn insert(&mut self, event: QueuedEvent) -> Result<(), QueuedEvent> {
        if let Some(prior) =
            coalescing_index(&self.events, &event).and_then(|index| self.events.remove(index))
        {
            self.stats.bytes -= event_bytes(&prior);
            self.stats.coalesced = self.stats.coalesced.saturating_add(1);
        }
        let bytes = event_bytes(&event);
        if self.events.len() >= INPUT_EVENT_LIMIT || self.stats.bytes + bytes > INPUT_BYTE_LIMIT {
            return Err(event);
        }
        self.stats.bytes += bytes;
        self.events.push_back(event);
        self.stats.queued = self.events.len();
        self.stats.peak = self.stats.peak.max(self.stats.queued);
        Ok(())
    }

    fn pop(&mut self) -> Option<QueuedEvent> {
        if std::mem::take(&mut self.wake) {
            return Some(Ok(TerminalLoopEvent::Wake));
        }
        let event = self.events.pop_front()?;
        self.stats.bytes -= event_bytes(&event);
        self.stats.queued = self.events.len();
        Some(event)
    }
}

/// Coalescing never crosses a key, paste, mouse action or diagnostic. The
/// latest replaceable state stays on the same side of every ordered action.
fn coalescing_index(events: &VecDeque<QueuedEvent>, event: &QueuedEvent) -> Option<usize> {
    let kind = replaceable_kind(event)?;
    events
        .iter()
        .enumerate()
        .rev()
        .take_while(|(_, prior)| replaceable_kind(prior).is_some())
        .find(|(_, prior)| replaceable_kind(prior) == Some(kind))
        .map(|(index, _)| index)
}

fn replaceable_kind(event: &QueuedEvent) -> Option<u8> {
    match event {
        Ok(TerminalLoopEvent::Terminal(TermEvent::Resize { .. })) => Some(0),
        Ok(TerminalLoopEvent::Terminal(TermEvent::Focus { .. })) => Some(1),
        Ok(TerminalLoopEvent::Terminal(TermEvent::Mouse(mouse)))
            if mouse.kind == MouseEventKind::Moved =>
        {
            Some(2)
        }
        _ => None,
    }
}

fn event_bytes(event: &QueuedEvent) -> usize {
    let payload = match event {
        Ok(TerminalLoopEvent::Terminal(TermEvent::Paste(text))) => text.capacity(),
        Ok(TerminalLoopEvent::InputRejected(message)) => message.capacity(),
        Err(error) => error.capacity(),
        _ => 0,
    };
    std::mem::size_of::<QueuedEvent>() + payload
}

fn bounded_event(event: QueuedEvent) -> QueuedEvent {
    match event {
        Ok(TerminalLoopEvent::Terminal(TermEvent::Paste(text))) => bounded_paste(text),
        Err(error) => Err(error.chars().take(512).collect()),
        event => event,
    }
}

fn bounded_paste(text: String) -> QueuedEvent {
    if text.len() > PASTE_BYTE_LIMIT {
        return Ok(TerminalLoopEvent::InputRejected(
            "paste exceeds the 1 MiB input limit; paste was not accepted".into(),
        ));
    }
    let compact = text.into_boxed_str().into_string();
    Ok(TerminalLoopEvent::Terminal(TermEvent::Paste(compact)))
}

#[cfg(test)]
#[path = "terminal_event_queue/tests.rs"]
mod tests;
