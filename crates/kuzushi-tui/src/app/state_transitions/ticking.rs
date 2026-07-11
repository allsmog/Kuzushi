use super::*;

impl ShellApp {
    pub fn tick(&mut self) -> bool {
        self.tick_at(Instant::now())
    }

    pub(crate) fn tick_at(&mut self, now: Instant) -> bool {
        let mut changed = false;
        changed |= self.expire_ctrl_c_arm(now);
        changed |= self.expire_stale_advisory(AdvisoryKind::Throttle, now);
        changed |= self.expire_stale_advisory(AdvisoryKind::Notice, now);
        changed |= self.advance_spinner(now);
        changed |= self.advance_liveness_clock(now);
        changed |= self.advance_scene(now);
        changed
    }

    /// True while the security-viz gallery is on the animated 3D attack-surface
    /// page and not paused — drives both the faster redraw cadence and the
    /// per-tick camera advance.
    pub fn scene_animating(&self) -> bool {
        matches!(self.shell_view(), ShellView::Scene)
            && self.router.scene().page().is_animated()
            && !self.router.scene().paused()
            && !crate::theme::active_theme().reduced_motion
    }

    /// Spin the playground camera, paced by wall-clock so speed is independent
    /// of the redraw rate. No-op (and clears the baseline) when not animating.
    fn advance_scene(&mut self, now: Instant) -> bool {
        if !self.scene_animating() {
            self.router.scene_mut().clear_advance_baseline();
            return false;
        }
        let Some(prev) = self.router.scene().last_advance() else {
            self.router.scene_mut().set_advance_baseline(now);
            return true;
        };
        let elapsed = now.duration_since(prev);
        if elapsed < SCENE_FRAME {
            return false;
        }
        self.router
            .scene_mut()
            .advance_yaw(elapsed.as_secs_f32() * SCENE_SPIN_RATE, now);
        true
    }

    fn expire_ctrl_c_arm(&mut self, now: Instant) -> bool {
        let Some(armed_at) = self.ctrl_c_armed_at() else {
            return false;
        };
        if now.duration_since(armed_at) <= CTRL_C_ARM_WINDOW {
            return false;
        }
        self.set_ctrl_c_armed_at(None);
        true
    }

    fn expire_stale_advisory(&mut self, kind: AdvisoryKind, now: Instant) -> bool {
        let Some(since) = kind.since(self) else {
            return false;
        };
        if now.duration_since(since) <= kind.stale_after() {
            return false;
        }
        kind.clear(self);
        true
    }

    fn advance_spinner(&mut self, now: Instant) -> bool {
        if crate::theme::active_theme().reduced_motion {
            return self.reset_spinner();
        }
        if !self.has_running_work() {
            return self.reset_spinner();
        }
        if !self.ui().spinner_due(now, SPINNER_FRAME) {
            return false;
        }
        self.ui_mut().advance_spinner(now);
        true
    }

    fn advance_liveness_clock(&mut self, now: Instant) -> bool {
        if !self.has_running_work() {
            self.ui_mut().clear_liveness_redraw();
            return false;
        }
        self.ui_mut()
            .liveness_redraw_due(now, Duration::from_secs(1))
    }

    /// Clear the animation when work finishes so no frozen glyph lingers.
    fn reset_spinner(&mut self) -> bool {
        self.ui_mut().reset_spinner()
    }

    pub fn has_running_work(&self) -> bool {
        let scan_running = self.scan().is_some_and(|scan| scan.running);
        let tool_running = self.tool_is_running();
        let agent_running = self.agent_chat().is_some_and(|agent| agent.running);
        self.jobs().has_running_job()
            || scan_running
            || tool_running
            || agent_running
            || self.planner_running()
            || self.threat_worker_running()
    }

    pub fn spinner_glyph(&self) -> &'static str {
        const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        FRAMES[(self.ui().spinner_phase() as usize) % FRAMES.len()]
    }

    pub fn ctrl_c_armed(&self) -> bool {
        self.ctrl_c_armed_at()
            .map(|armed_at| Instant::now().duration_since(armed_at) <= CTRL_C_ARM_WINDOW)
            .unwrap_or(false)
    }

    pub fn set_throttle(&mut self, source: impl Into<String>, message: impl Into<String>) {
        let source = source.into();
        let message = message.into();
        self.log("throttle", format!("{source}: {message}"));
        self.advisory_mut().throttle = Some(ThrottleAdvisory {
            source,
            message,
            since: Instant::now(),
        });
    }

    pub fn clear_throttle(&mut self) {
        self.advisory_mut().throttle = None;
    }

    /// Surface a transient error banner (red) and keep the transcript record.
    pub fn set_error_notice(&mut self, source: impl Into<String>, message: impl Into<String>) {
        self.set_notice(NoticeSeverity::Error, source, message);
    }

    /// Surface a transient warning banner (amber) and keep the transcript record.
    pub fn set_warn_notice(&mut self, source: impl Into<String>, message: impl Into<String>) {
        self.set_notice(NoticeSeverity::Warn, source, message);
    }

    pub fn set_info_notice(&mut self, source: impl Into<String>, message: impl Into<String>) {
        self.set_notice(NoticeSeverity::Info, source, message);
    }

    /// Surface a transient completion banner (green) and keep the transcript
    /// record — how background work announces itself when the operator is
    /// on another view.
    pub fn set_success_notice(&mut self, source: impl Into<String>, message: impl Into<String>) {
        self.set_notice(NoticeSeverity::Success, source, message);
    }

    fn set_notice(
        &mut self,
        severity: NoticeSeverity,
        source: impl Into<String>,
        message: impl Into<String>,
    ) {
        let source = source.into();
        let message = message.into();
        let prefix = match severity {
            NoticeSeverity::Error => "error",
            NoticeSeverity::Warn | NoticeSeverity::Info | NoticeSeverity::Success => {
                source.as_str()
            }
        };
        self.log(prefix, message.clone());
        self.advisory_mut().notice = Some(Notice {
            source,
            message,
            severity,
            since: Instant::now(),
        });
    }

    pub fn clear_notice(&mut self) {
        self.advisory_mut().notice = None;
    }

    pub fn is_budget_halted(&self) -> bool {
        self.advisory().budget_halt.is_some()
    }

    pub fn record_cost(&mut self, cost_usd: f64) {
        self.session_mut().record_cost(cost_usd);
        self.maybe_trigger_budget_halt();
    }
}

/// The two transient banners that auto-expire in `tick`. Lets one helper
/// (`expire_stale_advisory`) drive both without duplicating the timer logic.
#[derive(Clone, Copy)]
enum AdvisoryKind {
    Throttle,
    Notice,
}

impl AdvisoryKind {
    fn since(self, app: &ShellApp) -> Option<Instant> {
        match self {
            AdvisoryKind::Throttle => app.advisory().throttle.as_ref().map(|t| t.since),
            AdvisoryKind::Notice => app.advisory().notice.as_ref().map(|n| n.since),
        }
    }

    fn stale_after(self) -> std::time::Duration {
        match self {
            AdvisoryKind::Throttle => THROTTLE_STALE_AFTER,
            AdvisoryKind::Notice => NOTICE_STALE_AFTER,
        }
    }

    fn clear(self, app: &mut ShellApp) {
        match self {
            AdvisoryKind::Throttle => app.advisory_mut().throttle = None,
            AdvisoryKind::Notice => app.advisory_mut().notice = None,
        }
    }
}
