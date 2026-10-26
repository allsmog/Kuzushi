use super::*;

impl ShellApp {
    pub fn tick(&mut self) -> bool {
        self.tick_at(Instant::now())
    }

    pub(crate) fn tick_at(&mut self, now: Instant) -> bool {
        let mut changed = false;
        changed |= self.expire_stale_advisory(AdvisoryKind::Throttle, now);
        changed |= self.expire_stale_advisory(AdvisoryKind::Notice, now);
        changed |= self.advance_spinner(now);
        changed |= self.advance_liveness_clock(now);
        changed |= self.advance_scene(now);
        changed |= self.reload_operator_keymap(now);
        changed |= self.drain_core_runtime_diagnostics();
        changed |= self.poll_campaign_completion();
        changed |= self.poll_relationship_write();
        changed |= self.poll_lesson_write();
        changed |= self.poll_source_review();
        changed |= self.poll_goal_review();
        changed
    }

    fn drain_core_runtime_diagnostics(&mut self) -> bool {
        let diagnostics = kuzushi_core::take_runtime_diagnostics();
        for diagnostic in &diagnostics {
            self.log_ephemeral(&diagnostic.source, &diagnostic.message);
        }
        !diagnostics.is_empty()
    }

    fn reload_operator_keymap(&mut self, now: Instant) -> bool {
        let Some(result) = self.ui_mut().poll_runtime_keymap(now) else {
            return false;
        };
        match result {
            Ok(reloaded) => {
                self.log_config_diagnostics(&reloaded.diagnostics);
                self.config_mut().operator.keybindings = reloaded.bindings;
                self.set_info_notice("keymap", "operator keybindings reloaded");
            }
            Err(error) => {
                self.set_error_notice("keymap", format!("operator keybindings unchanged: {error}"))
            }
        }
        true
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

    fn expire_stale_advisory(&mut self, kind: AdvisoryKind, now: Instant) -> bool {
        let Some(since) = kind.since(self) else {
            return false;
        };
        if kind.persists(self) {
            return false;
        }
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
        self.runtime_state.has_owned_dispatcher() || self.has_local_running_work()
    }

    pub(super) fn has_local_running_work(&self) -> bool {
        if self.runtime_state.source_review_worker.is_some()
            || self
                .runtime_state
                .goal_review_worker
                .as_ref()
                .is_some_and(|worker| worker.writing)
        {
            return true;
        }
        let scan_running = self.scan().is_some_and(|scan| scan.running);
        let tool_running = self.tool_is_running();
        let agent_running = self.agent_chat().is_some_and(|agent| agent.running);
        self.jobs().has_running_job()
            || self.runtime_state.relationship_write.is_some()
            || self.runtime_state.lesson_write.is_some()
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

    pub(crate) fn set_background_warn_notice(
        &mut self,
        source: impl Into<String>,
        message: impl Into<String>,
    ) {
        let source = source.into();
        let message = message.into();
        if self.advisory().foreground_notice_pending() {
            self.log(source, message);
            return;
        }
        self.set_warn_notice(source, message);
        let since = self.advisory().notice.as_ref().map(|notice| notice.since);
        self.advisory_mut().background_notice_since = since;
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
        self.advisory_mut().background_notice_since = None;
        self.advisory_mut().notice = Some(Notice {
            source,
            message,
            severity,
            since: Instant::now(),
        });
    }

    pub fn clear_notice(&mut self) {
        self.advisory_mut().notice = None;
        self.advisory_mut().background_notice_since = None;
    }

    pub fn is_budget_halted(&self) -> bool {
        self.advisory().budget_halt.is_some()
    }

    pub fn record_cost(&mut self, cost_usd: f64) {
        if let Err(error) = self.session_mut().record_cost(cost_usd) {
            self.report_cost_accounting_error(error);
            return;
        }
        self.maybe_trigger_budget_halt();
    }

    pub(crate) fn record_cost_report(&mut self, cost: kuzushi_core::runtime::RuntimeCostReport) {
        if let Err(error) = self.session_mut().record_cost_report(cost) {
            self.report_cost_accounting_error(error);
            return;
        }
        self.maybe_trigger_budget_halt();
    }

    pub(crate) fn begin_run_cost_tracking(&mut self, run_id: &str, runtime_backed: bool) {
        self.session_mut()
            .begin_run_cost_tracking(run_id, runtime_backed);
    }

    pub(crate) fn settle_run_cost_report(
        &mut self,
        run_id: &str,
        cost: kuzushi_core::runtime::RuntimeCostReport,
    ) {
        let report = match self.session_mut().settle_run_cost_report(run_id, cost) {
            Ok(report) => report,
            Err(error) => {
                self.report_cost_accounting_error(error);
                return;
            }
        };
        if let Some(activity) = self
            .activity_mut()
            .filter(|activity| activity.run_id == run_id)
        {
            activity.settle_runtime_cost(report);
        }
        self.maybe_trigger_budget_halt();
    }

    pub(crate) fn settle_active_run_cost_report(
        &mut self,
        cost: kuzushi_core::runtime::RuntimeCostReport,
    ) {
        let run_id = self.activity().map(|activity| activity.run_id.clone());
        if let Some(run_id) = run_id {
            self.begin_run_cost_tracking(&run_id, true);
            self.settle_run_cost_report(&run_id, cost);
        } else {
            self.record_cost_report(cost);
        }
    }

    pub(crate) fn report_cost_accounting_error(&mut self, error: impl std::fmt::Display) {
        let message = format!("runtime cost accounting failed closed: {error}");
        self.session_mut()
            .mark_cost_accounting_error(message.clone());
        self.set_error_notice("cost", message);
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

    fn persists(self, app: &ShellApp) -> bool {
        matches!(self, AdvisoryKind::Notice)
            && app
                .advisory()
                .notice
                .as_ref()
                .is_some_and(|notice| notice.source == "session")
            && app.session_persistence_is_degraded()
    }

    fn clear(self, app: &mut ShellApp) {
        match self {
            AdvisoryKind::Throttle => app.advisory_mut().throttle = None,
            AdvisoryKind::Notice => app.clear_notice(),
        }
    }
}
