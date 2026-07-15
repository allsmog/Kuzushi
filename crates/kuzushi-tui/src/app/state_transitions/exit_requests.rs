use super::*;

impl ShellApp {
    pub(crate) fn request_exit_abort_effect(&mut self) {
        self.request_active_abort();
        self.cancel_active_tokens();
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
        let mut requested = false;
        requested |= self.request_scan_abort_for(reason);
        requested |= self.request_tool_abort_for(reason);
        requested |= self.request_agent_abort();
        requested |= self.request_plan_abort();
        requested |= self.request_threat_abort();
        if requested {
            if self.engagement.has_running_tool() || !self.engagement.planning_queues_empty() {
                self.engagement.pause_planning_queue();
                self.log(
                    "planning",
                    "planning queue paused after stop request; type `next` to review and resume",
                );
            }
            if let Some(session) = self.activity_mut() {
                session.mark_active_tasks_canceling();
            }
            // A full-stop abort must not leave queued work behind: the
            // canceled worker's terminal event drains the steer queue
            // (`advance_steer_queue` in `apply_job_event`), so anything left
            // here would launch as fresh work seconds after the operator said
            // "stop". Drop the queue on the same stage that cancels jobs and
            // tell the operator exactly what was dropped.
            self.drop_queued_steer_items_for_abort();
            self.flush_session_transcript();
        }
        requested
    }

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
        if self.has_abortable_work() {
            self.set_ctrl_c_armed_at(None);
            return InputUpdate::handled_with_effects(vec![ShellEffect::CancelActiveJobs]);
        }
        if self.exit_or_arm_while_work_is_running() {
            return InputUpdate::handled();
        }
        if self.armed_quit_chord_ready() {
            return InputUpdate::handled_with_effects(vec![ShellEffect::RequestShellQuit]);
        }
        self.arm_quit_chord();
        InputUpdate::handled()
    }

    fn has_abortable_work(&self) -> bool {
        self.can_request_scan_abort()
            || self.can_request_tool_abort()
            || self.can_request_agent_abort()
            || self.can_request_plan_abort()
            || self.can_request_threat_abort()
    }

    fn exit_or_arm_while_work_is_running(&mut self) -> bool {
        if !self.has_running_work() {
            return false;
        }
        if self.abort_request_pending() {
            self.log(
                "system",
                "abort already requested; waiting for cleanup (type `quit` to force exit)",
            );
            return true;
        }
        self.arm_quit_chord();
        true
    }

    fn abort_request_pending(&self) -> bool {
        self.scan().is_some_and(|scan| scan.abort_requested)
            || self.tool_abort_requested()
            || self.agent_chat().is_some_and(|agent| agent.abort_requested)
            || self.plan_abort_requested()
            || self.threat_abort_requested()
    }

    fn can_request_tool_abort(&self) -> bool {
        self.running_tool_name().is_some() && !self.tool_abort_requested()
    }

    fn can_request_agent_abort(&self) -> bool {
        self.agent_chat()
            .is_some_and(|agent| agent.running && !agent.abort_requested)
    }

    fn can_request_plan_abort(&self) -> bool {
        self.planner_running() && !self.plan_abort_requested()
    }

    fn can_request_threat_abort(&self) -> bool {
        self.threat_worker_running() && !self.threat_abort_requested()
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
        if self.jobs_mut().cancel(kind) {
            return;
        }
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

    fn armed_quit_chord_ready(&self) -> bool {
        self.ctrl_c_armed()
    }

    fn arm_quit_chord(&mut self) {
        self.set_ctrl_c_armed_at(Some(Instant::now()));
        self.log(
            "system",
            "press Ctrl+C again within 2s to exit (any other key cancels)",
        );
    }
}

fn cancel_token(cancel: Option<&ScanCancellation>) {
    if let Some(cancel) = cancel {
        cancel.cancel();
    }
}
