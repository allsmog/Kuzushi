use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

pub(crate) const TERMINAL_EVENT_BATCH_LIMIT: usize = 256;
pub(crate) const TERMINAL_EVENT_BATCH_TIME_SLICE: Duration = Duration::from_millis(2);
const MIN_BACKGROUND_WAKE_INTERVAL: Duration = Duration::from_millis(33);
const MAX_BACKGROUND_WAKE_BURST: u8 = 2;

#[derive(Debug, Default)]
struct WakeRateState {
    window_started: Option<Instant>,
    sends_in_window: u8,
}

impl WakeRateState {
    fn permits_send(&mut self, now: Instant) -> bool {
        if self.window_started.is_none_or(|started| {
            now.saturating_duration_since(started) >= MIN_BACKGROUND_WAKE_INTERVAL
        }) {
            self.window_started = Some(now);
            self.sends_in_window = 0;
        }
        if self.sends_in_window >= MAX_BACKGROUND_WAKE_BURST {
            return false;
        }
        self.sends_in_window += 1;
        true
    }
}

pub(crate) enum TerminalLoopEvent {
    Terminal(TermEvent),
    Wake,
}

pub(crate) struct TerminalLoopInbox {
    rx: Receiver<Result<TerminalLoopEvent, String>>,
    wake_pending: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
pub(crate) struct TerminalLoopWake {
    tx: Sender<Result<TerminalLoopEvent, String>>,
    pending: Arc<AtomicBool>,
    rate: Arc<Mutex<WakeRateState>>,
}

impl TerminalLoopWake {
    pub(crate) fn notify(&self) {
        self.notify_at(Instant::now());
    }

    fn notify_at(&self, now: Instant) {
        if self.pending.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut rate = self
            .rate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !rate.permits_send(now) {
            self.pending.store(false, Ordering::Release);
            return;
        }
        drop(rate);
        if self.tx.send(Ok(TerminalLoopEvent::Wake)).is_err() {
            self.pending.store(false, Ordering::Release);
        }
    }
}

impl TerminalLoopInbox {
    pub(crate) fn spawn_crossterm_reader() -> (Self, TerminalLoopWake) {
        let (tx, rx) = mpsc::channel();
        let wake_pending = Arc::new(AtomicBool::new(false));
        let rate = Arc::new(Mutex::new(WakeRateState::default()));
        let wake = TerminalLoopWake {
            tx: tx.clone(),
            pending: wake_pending.clone(),
            rate,
        };
        thread::spawn(move || loop {
            let event = event::read()
                .map(terminal_loop_event_from_crossterm)
                .map_err(|error| error.to_string());
            if tx.send(event).is_err() {
                break;
            }
        });
        (Self { rx, wake_pending }, wake)
    }

    #[cfg(test)]
    pub(crate) fn from_receiver(rx: Receiver<Result<TerminalLoopEvent, String>>) -> Self {
        Self {
            rx,
            wake_pending: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    pub(crate) fn channel_for_test() -> (Self, TerminalLoopWake) {
        let (tx, rx) = mpsc::channel();
        let wake_pending = Arc::new(AtomicBool::new(false));
        let rate = Arc::new(Mutex::new(WakeRateState::default()));
        let wake = TerminalLoopWake {
            tx,
            pending: wake_pending.clone(),
            rate,
        };
        (Self { rx, wake_pending }, wake)
    }

    pub(crate) fn recv_timeout(&self, timeout: Duration) -> Result<Option<TerminalLoopEvent>> {
        match self.rx.recv_timeout(timeout) {
            Ok(event) => self.resolve_received(event).map(Some),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => anyhow::bail!("terminal event reader stopped"),
        }
    }

    fn try_recv(&self) -> Result<Option<TerminalLoopEvent>> {
        match self.rx.try_recv() {
            Ok(event) => self.resolve_received(event).map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => anyhow::bail!("terminal event reader stopped"),
        }
    }

    fn resolve_received(
        &self,
        received: std::result::Result<TerminalLoopEvent, String>,
    ) -> Result<TerminalLoopEvent> {
        let event =
            received.map_err(|error| anyhow::anyhow!("terminal event reader failed: {error}"))?;
        if matches!(event, TerminalLoopEvent::Wake) {
            self.wake_pending.store(false, Ordering::Release);
        }
        Ok(event)
    }
}

fn terminal_loop_event_from_crossterm(event: Event) -> TerminalLoopEvent {
    TermEvent::from_crossterm(event)
        .map(TerminalLoopEvent::Terminal)
        .unwrap_or(TerminalLoopEvent::Wake)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct TerminalEventBatchOutcome {
    pub(crate) changed: bool,
    pub(crate) received_count: usize,
    pub(crate) terminal_event_count: usize,
    pub(crate) hit_batch_bound: bool,
    pub(crate) run_focus_transition_from: Option<ShellView>,
    quit_requested: bool,
}

#[cfg(test)]
pub(crate) fn wait_for_terminal_event_batch(
    app: &mut ShellApp,
    inbox: &TerminalLoopInbox,
) -> Result<bool> {
    let timeout = terminal_event_timeout(app);
    Ok(wait_for_terminal_event_batch_within(app, inbox, timeout)?.changed)
}

pub(crate) fn wait_for_terminal_event_batch_within(
    app: &mut ShellApp,
    inbox: &TerminalLoopInbox,
    timeout: Duration,
) -> Result<TerminalEventBatchOutcome> {
    wait_for_terminal_event_batch_with_limits(
        app,
        inbox,
        timeout,
        TERMINAL_EVENT_BATCH_LIMIT,
        TERMINAL_EVENT_BATCH_TIME_SLICE,
    )
}

pub(crate) fn wait_for_terminal_event_batch_with_limits(
    app: &mut ShellApp,
    inbox: &TerminalLoopInbox,
    timeout: Duration,
    event_limit: usize,
    time_slice: Duration,
) -> Result<TerminalEventBatchOutcome> {
    debug_assert!(event_limit > 0);
    let Some(first) = inbox.recv_timeout(timeout)? else {
        return Ok(TerminalEventBatchOutcome::default());
    };
    let started = Instant::now();
    let mut outcome = TerminalEventBatchOutcome::default();
    apply_terminal_loop_event(app, first, &mut outcome);
    while should_drain_another_event(&outcome, event_limit, started, time_slice) {
        let Some(event) = inbox.try_recv()? else {
            return Ok(outcome);
        };
        apply_terminal_loop_event(app, event, &mut outcome);
    }
    outcome.hit_batch_bound =
        outcome.run_focus_transition_from.is_none() && !outcome.quit_requested;
    Ok(outcome)
}

pub(crate) fn should_drain_another_event(
    outcome: &TerminalEventBatchOutcome,
    event_limit: usize,
    started: Instant,
    time_slice: Duration,
) -> bool {
    outcome.run_focus_transition_from.is_none()
        && !outcome.quit_requested
        && outcome.received_count < event_limit
        && started.elapsed() < time_slice
}

fn apply_terminal_loop_event(
    app: &mut ShellApp,
    event: TerminalLoopEvent,
    outcome: &mut TerminalEventBatchOutcome,
) {
    outcome.received_count += 1;
    let TerminalLoopEvent::Terminal(event) = event else {
        return;
    };
    let prior_view = app.shell_view();
    outcome.terminal_event_count += 1;
    outcome.changed |= update_and_execute_effects(app, Msg::Term(event));
    outcome.quit_requested = app.should_quit();
    if entered_running_activity(prior_view, app) {
        outcome.run_focus_transition_from = Some(prior_view);
    }
}

pub(crate) fn entered_running_activity(prior_view: ShellView, app: &ShellApp) -> bool {
    prior_view != ShellView::Activity
        && app.shell_view() == ShellView::Activity
        && app.has_running_work()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_wake_allows_one_immediate_tail_then_throttles() {
        let (input, wake) = TerminalLoopInbox::channel_for_test();
        let window = Instant::now();

        wake.notify_at(window);
        assert_wake_arrives_without_idle_poll(&input);
        wake.notify_at(window);
        assert_wake_arrives_without_idle_poll(&input);
        wake.notify_at(window);
        assert!(input.recv_timeout(Duration::ZERO).unwrap().is_none());

        wake.notify_at(window + MIN_BACKGROUND_WAKE_INTERVAL);
        assert_wake_arrives_without_idle_poll(&input);
    }

    fn assert_wake_arrives_without_idle_poll(input: &TerminalLoopInbox) {
        assert!(matches!(
            input.recv_timeout(Duration::from_millis(20)).unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));
    }
}
