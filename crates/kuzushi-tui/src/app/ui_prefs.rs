use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UiPrefs {
    auto_open_activity: bool,
    auto_open_viz: bool,
    last_operator_interaction: Option<Instant>,
    spinner_phase: u8,
    last_spinner_advance: Option<Instant>,
    force_full_redraw: bool,
    should_quit: bool,
    ctrl_c_armed_at: Option<Instant>,
    viewport: TerminalViewport,
}

impl UiPrefs {
    pub(crate) fn new(auto_open_activity: bool, auto_open_viz: bool) -> Self {
        Self {
            auto_open_activity,
            auto_open_viz,
            last_operator_interaction: None,
            spinner_phase: 0,
            last_spinner_advance: None,
            force_full_redraw: false,
            should_quit: false,
            ctrl_c_armed_at: None,
            viewport: TerminalViewport::default(),
        }
    }

    pub(crate) fn auto_open_activity(&self) -> bool {
        self.auto_open_activity
    }

    pub(crate) fn set_auto_open_activity(&mut self, enabled: bool) {
        self.auto_open_activity = enabled;
    }

    pub(crate) fn auto_open_viz(&self) -> bool {
        self.auto_open_viz
    }

    pub(crate) fn set_auto_open_viz(&mut self, enabled: bool) {
        self.auto_open_viz = enabled;
    }

    pub(crate) fn record_operator_interaction(&mut self, now: Instant) {
        self.last_operator_interaction = Some(now);
    }

    pub(crate) fn recent_operator_interaction(&self, grace: Duration) -> bool {
        self.last_operator_interaction
            .is_some_and(|at| at.elapsed() <= grace)
    }

    pub(crate) fn spinner_phase(&self) -> u8 {
        self.spinner_phase
    }

    #[cfg(test)]
    pub(crate) fn set_spinner_phase_for_test(&mut self, phase: u8) {
        self.spinner_phase = phase;
    }

    pub(crate) fn spinner_due(&self, now: Instant, frame: Duration) -> bool {
        self.last_spinner_advance
            .map(|prev| now.duration_since(prev) >= frame)
            .unwrap_or(true)
    }

    pub(crate) fn advance_spinner(&mut self, now: Instant) {
        self.spinner_phase = self.spinner_phase.wrapping_add(1);
        self.last_spinner_advance = Some(now);
    }

    pub(crate) fn reset_spinner(&mut self) -> bool {
        self.last_spinner_advance = None;
        if self.spinner_phase == 0 {
            return false;
        }
        self.spinner_phase = 0;
        true
    }

    #[cfg(test)]
    pub(crate) fn set_last_spinner_advance_for_test(&mut self, instant: Instant) {
        self.last_spinner_advance = Some(instant);
    }

    pub(crate) fn request_full_redraw(&mut self) {
        self.force_full_redraw = true;
    }

    #[cfg(test)]
    pub(crate) fn force_full_redraw(&self) -> bool {
        self.force_full_redraw
    }

    pub(crate) fn take_force_full_redraw(&mut self) -> bool {
        let requested = self.force_full_redraw;
        self.force_full_redraw = false;
        requested
    }

    pub(crate) fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub(crate) fn request_quit(&mut self) {
        self.should_quit = true;
    }

    pub(crate) fn ctrl_c_armed_at(&self) -> Option<Instant> {
        self.ctrl_c_armed_at
    }

    pub(crate) fn set_ctrl_c_armed_at(&mut self, armed_at: Option<Instant>) {
        self.ctrl_c_armed_at = armed_at;
    }

    pub(crate) fn viewport(&self) -> TerminalViewport {
        self.viewport
    }

    pub(crate) fn set_viewport(&mut self, viewport: TerminalViewport) {
        self.viewport = viewport;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalViewport {
    pub(crate) columns: u16,
    pub(crate) rows: u16,
}

impl TerminalViewport {
    pub(crate) fn new(columns: u16, rows: u16) -> Self {
        Self {
            columns: columns.max(1),
            rows: rows.max(1),
        }
    }
}

impl Default for TerminalViewport {
    fn default() -> Self {
        Self {
            columns: 160,
            rows: 40,
        }
    }
}
