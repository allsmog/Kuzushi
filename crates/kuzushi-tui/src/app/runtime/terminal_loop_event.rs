use super::terminal_event_queue::{TerminalEventQueue, TerminalEventReceiver};
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::mpsc::Receiver;
use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

pub(crate) const TERMINAL_EVENT_BATCH_LIMIT: usize = 256;
pub(crate) const TERMINAL_EVENT_BATCH_TIME_SLICE: Duration = Duration::from_millis(2);
const MIN_BACKGROUND_WAKE_INTERVAL: Duration = Duration::from_millis(33);
const MAX_BACKGROUND_WAKE_BURST: u8 = 2;

/// Paces background wakes to the frame cadence and remembers the hint it had
/// to suppress. A suppressed hint is not a dropped one: producers coalesce
/// into `deferred` while the inbox shortens its wait and delivers one paced
/// wake at the window boundary, so background work never has to wait out the
/// idle poll for a producer that already stopped notifying.
#[derive(Debug, Default)]
struct WakeRateState {
    window_started: Option<Instant>,
    sends_in_window: u8,
    deferred: bool,
}

impl WakeRateState {
    fn permits_send(&mut self, now: Instant) -> bool {
        self.roll_window(now);
        if self.sends_in_window >= MAX_BACKGROUND_WAKE_BURST {
            self.deferred = true;
            return false;
        }
        self.sends_in_window += 1;
        true
    }

    fn roll_window(&mut self, now: Instant) {
        if self.window_started.is_some_and(|started| {
            now.saturating_duration_since(started) < MIN_BACKGROUND_WAKE_INTERVAL
        }) {
            return;
        }
        self.window_started = Some(now);
        self.sends_in_window = 0;
        self.deferred = false;
    }

    /// How long a suppressed hint still owes the cadence, or `None` when no
    /// hint is waiting.
    fn deferred_wait(&self, now: Instant) -> Option<Duration> {
        let started = self.window_started.filter(|_| self.deferred)?;
        Some(MIN_BACKGROUND_WAKE_INTERVAL.saturating_sub(now.saturating_duration_since(started)))
    }

    fn take_deferred_if_due(&mut self, now: Instant) -> bool {
        if self.deferred_wait(now) != Some(Duration::ZERO) {
            return false;
        }
        self.window_started = Some(now);
        self.sends_in_window = 1;
        self.deferred = false;
        true
    }
}

pub(crate) enum TerminalLoopEvent {
    Terminal(TermEvent),
    Wake,
}

pub(crate) struct TerminalLoopInbox {
    rx: TerminalEventReceiver,
    reader: Option<thread::JoinHandle<()>>,
    pressure_reported: AtomicBool,
    wake_pending: Arc<AtomicBool>,
    rate: Arc<Mutex<WakeRateState>>,
}

#[derive(Clone, Debug)]
pub(crate) struct TerminalLoopWake {
    queue: Arc<TerminalEventQueue>,
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
        if !self.queue.notify() {
            self.pending.store(false, Ordering::Release);
        }
    }
}

impl TerminalLoopInbox {
    pub(crate) fn spawn_crossterm_reader() -> (Self, TerminalLoopWake) {
        let (mut inbox, wake) = Self::bounded_channel();
        let queue = wake.queue.clone();
        inbox.reader = Some(thread::spawn(move || read_terminal_events(queue)));
        (inbox, wake)
    }

    fn bounded_channel() -> (Self, TerminalLoopWake) {
        let queue = Arc::new(TerminalEventQueue::default());
        let wake_pending = Arc::new(AtomicBool::new(false));
        let rate = Arc::new(Mutex::new(WakeRateState::default()));
        let wake = TerminalLoopWake {
            queue: queue.clone(),
            pending: wake_pending.clone(),
            rate: rate.clone(),
        };
        (
            Self {
                rx: TerminalEventReceiver::Bounded(queue),
                reader: None,
                pressure_reported: AtomicBool::new(false),
                wake_pending,
                rate,
            },
            wake,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_receiver(rx: Receiver<Result<TerminalLoopEvent, String>>) -> Self {
        Self {
            rx: TerminalEventReceiver::Scripted(rx),
            reader: None,
            pressure_reported: AtomicBool::new(false),
            wake_pending: Arc::new(AtomicBool::new(false)),
            rate: Arc::new(Mutex::new(WakeRateState::default())),
        }
    }

    #[cfg(test)]
    pub(crate) fn channel_for_test() -> (Self, TerminalLoopWake) {
        Self::bounded_channel()
    }

    pub(crate) fn report_pressure(&self, app: &mut ShellApp) {
        let stats = self.rx.stats();
        if stats.blocked == 0 || self.pressure_reported.swap(true, Ordering::AcqRel) {
            return;
        }
        app.log("input", format!(
            "terminal input backpressure: {} queued / {} bytes, peak {}, {} state events coalesced; ordered input is preserved",
            stats.queued, stats.bytes, stats.peak, stats.coalesced
        ));
    }

    /// Waits the caller's full timeout, except that a suppressed background
    /// hint is delivered as one paced wake as soon as its cadence window
    /// closes. Waking early at the boundary must not shorten the caller's
    /// deadline, so an undue boundary resumes waiting for the remainder.
    pub(crate) fn recv_timeout(&self, timeout: Duration) -> Result<Option<TerminalLoopEvent>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(event) = self.recv_until_paced_boundary(deadline)? {
                return Ok(Some(event));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    fn recv_until_paced_boundary(&self, deadline: Instant) -> Result<Option<TerminalLoopEvent>> {
        match self.rx.recv_timeout(self.paced_timeout(deadline)) {
            Ok(event) => self.resolve_received(event).map(Some),
            Err(RecvTimeoutError::Timeout) => Ok(self.take_deferred_wake_if_due()),
            Err(RecvTimeoutError::Disconnected) => anyhow::bail!("terminal event reader stopped"),
        }
    }

    fn rate(&self) -> std::sync::MutexGuard<'_, WakeRateState> {
        self.rate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The next wait: time left on the caller's deadline, shortened to the
    /// cadence boundary when a suppressed hint is owed a wake.
    fn paced_timeout(&self, deadline: Instant) -> Duration {
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        self.rate()
            .deferred_wait(now)
            .map_or(remaining, |until_due| remaining.min(until_due))
    }

    /// Delivers the suppressed hint as one paced wake once its window closes.
    /// No producer has to notify again for the deferred work to run.
    fn take_deferred_wake_if_due(&self) -> Option<TerminalLoopEvent> {
        self.rate()
            .take_deferred_if_due(Instant::now())
            .then_some(TerminalLoopEvent::Wake)
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

impl Drop for TerminalLoopInbox {
    fn drop(&mut self) {
        self.rx.close();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn read_terminal_events(queue: Arc<TerminalEventQueue>) {
    while !queue.is_closed() {
        let event = match next_terminal_event() {
            Ok(Some(event)) => Ok(terminal_loop_event_from_crossterm(event)),
            Ok(None) => continue,
            Err(error) => Err(error.to_string()),
        };
        if !queue.send(event) {
            break;
        }
    }
}

fn next_terminal_event() -> io::Result<Option<Event>> {
    if !event::poll(Duration::from_millis(25))? {
        return Ok(None);
    }
    event::read().map(Some)
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

    #[test]
    fn wake_rate_defers_only_until_the_next_cadence_window() {
        let base = Instant::now();
        let mut rate = WakeRateState::default();

        assert!(rate.permits_send(base));
        assert!(rate.permits_send(base + Duration::from_millis(1)));
        assert!(!rate.permits_send(base + Duration::from_millis(2)));

        assert_eq!(
            rate.deferred_wait(base + Duration::from_millis(2)),
            Some(Duration::from_millis(31))
        );
        assert!(!rate.take_deferred_if_due(base + Duration::from_millis(32)));
        assert!(rate.take_deferred_if_due(base + MIN_BACKGROUND_WAKE_INTERVAL));

        // The paced wake opens the next window and spends one of its sends.
        assert_eq!(rate.sends_in_window, 1);
        assert_eq!(
            rate.deferred_wait(base + MIN_BACKGROUND_WAKE_INTERVAL),
            None
        );
    }

    #[test]
    fn suppressed_background_wake_is_delivered_without_a_producer_retry() {
        let (input, wake) = TerminalLoopInbox::channel_for_test();
        let window = Instant::now();

        wake.notify_at(window);
        assert_wake_arrives_without_idle_poll(&input);
        wake.notify_at(window);
        assert_wake_arrives_without_idle_poll(&input);

        // The third hint is paced away, but it is remembered. The inbox
        // shortens this otherwise-long wait to the cadence boundary and
        // delivers one wake even though no producer notifies again.
        wake.notify_at(window);
        let waited_from = Instant::now();
        assert!(matches!(
            input.recv_timeout(Duration::from_secs(5)).unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));
        assert!(
            waited_from.elapsed() < Duration::from_secs(1),
            "deferred wake waited out the caller timeout: {:?}",
            waited_from.elapsed()
        );
    }

    /// The pacing boundary shortens a long wait; it must never lengthen a
    /// short one. A zero/near-zero poll still reports "nothing yet" so the
    /// input-batch drain and the Run Focus visibility hold keep their own
    /// deadlines, and the hint survives that poll.
    #[test]
    fn a_deferred_wake_never_outlives_a_shorter_caller_timeout() {
        let (input, wake) = TerminalLoopInbox::channel_for_test();
        let window = Instant::now();
        for _ in 0..MAX_BACKGROUND_WAKE_BURST {
            wake.notify_at(window);
            assert_wake_arrives_without_idle_poll(&input);
        }
        wake.notify_at(window);

        assert!(input.recv_timeout(Duration::ZERO).unwrap().is_none());

        assert!(matches!(
            input.recv_timeout(Duration::from_secs(5)).unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));
    }

    fn assert_wake_arrives_without_idle_poll(input: &TerminalLoopInbox) {
        assert!(matches!(
            input.recv_timeout(Duration::from_millis(20)).unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));
    }
}
