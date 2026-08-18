use super::*;

impl ShellApp {
    pub(crate) fn request_exit_abort_effect(&mut self) {
        self.request_active_abort();
    }

    pub(crate) fn wait_for_abort_cleanup_effect(&mut self) {
        self.wait_briefly_for_abort_cleanup();
    }

    pub(crate) fn finish_shell_quit_effect(&mut self) {
        if !self.should_quit() {
            self.log("system", "exit requested; closing shell");
        }
        self.request_shell_quit();
    }

    pub(crate) fn request_active_abort(&mut self) -> bool {
        self.request_active_abort_with_reason(AbortReason::Operator)
    }

    pub(crate) fn request_active_abort_with_reason(&mut self, reason: AbortReason) -> bool {
        let had_running_work = self.has_running_work();
        let requested = self.request_domain_aborts(reason);
        self.cancel_active_tokens();
        if !had_running_work {
            return false;
        }
        self.log_unprojected_abort(requested);
        self.pause_planning_after_abort();
        self.mark_activity_canceling();
        self.drop_queued_steer_items_for_abort();
        self.flush_session_transcript();
        true
    }

    fn request_domain_aborts(&mut self, reason: AbortReason) -> bool {
        let mut requested = false;
        requested |= self.request_scan_abort_for(reason);
        requested |= self.request_tool_abort_for(reason);
        requested |= self.request_agent_abort();
        requested |= self.request_plan_abort();
        requested |= self.request_threat_abort();
        requested
    }

    fn log_unprojected_abort(&mut self, projected: bool) {
        if !projected {
            self.log(
                "system",
                "abort requested for active worker; waiting for cleanup",
            );
        }
    }

    fn pause_planning_after_abort(&mut self) {
        if !self.engagement.has_running_tool() && self.engagement.planning_queues_empty() {
            return;
        }
        self.engagement.pause_planning_queue();
        self.log(
            "planning",
            "planning queue paused after stop request; type `next` to review and resume",
        );
    }

    fn mark_activity_canceling(&mut self) {
        if let Some(session) = self.activity_mut() {
            session.mark_active_tasks_canceling();
        }
    }

    // A full-stop abort must not leave queued work behind: the canceled
    // worker's terminal event drains the steer queue (`advance_steer_queue` in
    // `apply_job_event`), so anything left here would launch as fresh work
    // seconds after the operator said "stop".
    fn drop_queued_steer_items_for_abort(&mut self) {
        let dropped = self.steer_queue_mut().drain_all();
        if dropped.is_empty() {
            return;
        }
        let summaries: Vec<&str> = dropped.iter().map(|cmd| cmd.summary.as_str()).collect();
        self.log(
            "queue",
            format!(
                "stop requested; dropped {} queued item(s): {} (re-queue after the abort if still wanted)",
                dropped.len(),
                summaries.join(", ")
            ),
        );
    }

    pub(crate) fn request_scan_abort(&mut self) -> bool {
        self.request_scan_abort_for(AbortReason::Operator)
    }

    fn request_scan_abort_for(&mut self, reason: AbortReason) -> bool {
        if !self.can_request_scan_abort() {
            return false;
        }

        self.apply_scan_abort_request(reason);
        true
    }

    fn apply_scan_abort_request(&mut self, reason: AbortReason) {
        self.cancel_run_job_or_scan_token();
        self.set_scan_abort_reason(Some(reason));
        self.mark_scan_abort_requested();
        self.announce_scan_abort_requested();
    }

    fn announce_scan_abort_requested(&mut self) {
        self.log(
            "scan",
            "abort requested; waiting for scanner subprocess to stop (not claiming it was killed)",
        );
        self.set_paused_activity(
            "sast:scan",
            "abort requested; waiting for scanner subprocess",
        );
    }

    fn can_request_scan_abort(&self) -> bool {
        self.scan()
            .is_some_and(|scan| scan.running && !scan.abort_requested)
    }

    fn cancel_run_job_or_scan_token(&mut self) {
        let cancel = self.scan_cancel_token().cloned();
        self.cancel_job_or_token(JobKind::Run, cancel);
    }

    fn mark_scan_abort_requested(&mut self) {
        if let Some(scan) = self.scan_mut() {
            scan.stage = "abort requested".to_string();
            scan.abort_requested = true;
        }
    }

    pub(crate) fn request_tool_abort(&mut self) -> bool {
        self.request_tool_abort_for(AbortReason::Operator)
    }

    fn request_tool_abort_for(&mut self, reason: AbortReason) -> bool {
        let Some(tool_name) = self.running_tool_name_owned() else {
            return false;
        };
        if self.tool_abort_requested() {
            return false;
        }
        self.cancel_run_job_or_tool_token();
        self.request_tool_abort_flag(reason);
        self.log(
            "tool",
            format!("{tool_name} cancel requested; waiting for the worker to stop"),
        );
        self.set_paused_activity(tool_name, "cancel requested; waiting for worker");
        true
    }

    fn cancel_run_job_or_tool_token(&mut self) {
        let cancel = self.tool_cancel_token().cloned();
        self.cancel_job_or_token(JobKind::Run, cancel);
    }

    pub(crate) fn request_agent_abort(&mut self) -> bool {
        let should_abort = self
            .agent_chat()
            .is_some_and(|agent| agent.running && !agent.abort_requested);
        if !should_abort {
            return false;
        }
        self.cancel_agent_job_or_token();
        if let Some(agent) = self.agent_chat_mut() {
            agent.abort_requested = true;
        }
        self.log(
            "agent",
            "abort requested; waiting for LangGraph to return (process kill not confirmed)",
        );
        self.set_paused_activity("agent", "abort requested; waiting for LangGraph");
        true
    }

    pub(crate) fn request_plan_abort(&mut self) -> bool {
        if !self.planner_running() || self.plan_abort_requested() {
            return false;
        }
        self.cancel_plan_job_or_token();
        self.set_plan_abort_requested(true);
        self.log(
            "plan",
            "abort requested; waiting for LangGraph planner to return (process kill not confirmed)",
        );
        self.set_paused_activity("plan", "abort requested; waiting for LangGraph planner");
        true
    }

    pub(crate) fn request_threat_abort(&mut self) -> bool {
        if !self.threat_worker_running() || self.threat_abort_requested() {
            return false;
        }
        self.cancel_threat_job_or_token();
        self.set_threat_abort_requested(true);
        self.log(
            "threats",
            "abort requested; waiting for LangGraph threat worker to return (process kill not confirmed)",
        );
        self.set_paused_activity(
            "threat model",
            "abort requested; waiting for LangGraph threat worker",
        );
        true
    }

    pub(super) fn reduce_quit_chord(&mut self) -> InputUpdate {
        if !self.has_running_work() {
            if crate::ui_view_models::has_volatile_session_state(self) {
                self.set_shell_view(ShellView::QuitConfirm);
                return InputUpdate::handled();
            }
            return InputUpdate::handled_with_effects(vec![ShellEffect::RequestShellQuit]);
        }
        if self.abort_request_pending() {
            self.log(
                "system",
                "abort already requested; waiting for cleanup (type `quit` to force exit)",
            );
            return InputUpdate::handled();
        }
        InputUpdate::handled_with_effects(vec![ShellEffect::CancelActiveJobs])
    }

    fn abort_request_pending(&self) -> bool {
        self.jobs().has_cancel_requested()
            || self.scan().is_some_and(|scan| scan.abort_requested)
            || self.tool_abort_requested()
            || self.agent_chat().is_some_and(|agent| agent.abort_requested)
            || self.plan_abort_requested()
            || self.threat_abort_requested()
    }

    fn cancel_active_tokens(&mut self) {
        self.cancel_run_job_or_scan_token();
        self.cancel_run_job_or_tool_token();
        self.cancel_agent_job_or_token();
        self.cancel_plan_job_or_token();
        self.cancel_threat_job_or_token();
    }

    fn cancel_agent_job_or_token(&mut self) {
        let cancel = self.agent_cancel_token().cloned();
        self.cancel_job_or_token(JobKind::Agent, cancel);
    }

    fn cancel_plan_job_or_token(&mut self) {
        let cancel = self.plan_cancel_token().cloned();
        self.cancel_job_or_token(JobKind::Plan, cancel);
    }

    fn cancel_threat_job_or_token(&mut self) {
        let cancel = self.threat_cancel_token().cloned();
        self.cancel_job_or_token(JobKind::Threat, cancel);
    }

    fn cancel_job_or_token(&mut self, kind: JobKind, cancel: Option<ScanCancellation>) {
        self.jobs_mut().cancel(kind);
        cancel_token(cancel.as_ref());
    }

    fn wait_briefly_for_abort_cleanup(&mut self) {
        if !self.has_worker_channels() {
            return;
        }
        let deadline = Instant::now() + Duration::from_millis(200);
        while self.has_running_work() && Instant::now() < deadline {
            apply_pending_background_events(self);
            std::thread::sleep(Duration::from_millis(25));
        }
        apply_pending_background_events(self);
    }

    fn has_worker_channels(&self) -> bool {
        self.jobs().is_running(JobKind::Run)
            || self.jobs().is_running(JobKind::Agent)
            || self.jobs().is_running(JobKind::Plan)
            || self.jobs().is_running(JobKind::Threat)
    }
}

fn cancel_token(cancel: Option<&ScanCancellation>) {
    if let Some(cancel) = cancel {
        cancel.cancel();
    }
}
