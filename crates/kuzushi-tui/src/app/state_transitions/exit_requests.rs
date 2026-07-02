use super::*;

impl ShellApp {
    pub(crate) fn request_exit(&mut self) {
        self.request_active_abort();
        self.cancel_active_tokens();
        self.wait_briefly_for_abort_cleanup();
        if !self.should_quit {
            self.log("system", "exit requested; closing shell");
        }
        self.should_quit = true;
    }

    pub(crate) fn request_active_abort(&mut self) -> bool {
        let mut requested = false;
        requested |= self.request_scan_abort();
        requested |= self.request_tool_abort();
        requested |= self.request_agent_abort();
        requested |= self.request_plan_abort();
        requested |= self.request_threat_abort();
        if requested {
            if let Some(session) = self.activity.as_mut() {
                session.mark_active_tasks_canceled();
            }
        }
        requested
    }

    pub(super) fn request_scan_abort(&mut self) -> bool {
        if !self.scan.as_ref().is_some_and(|scan| scan.running) {
            return false;
        }
        if self.scan.as_ref().is_some_and(|scan| scan.abort_requested) {
            return false;
        }

        if let Some(cancel) = &self.scan_cancel {
            cancel.cancel();
        }
        if let Some(scan) = &mut self.scan {
            scan.stage = "abort requested".to_string();
            scan.abort_requested = true;
        }
        self.log(
            "scan",
            "abort requested; waiting for scanner subprocess to stop (not claiming it was killed)",
        );
        self.set_paused_activity(
            "sast:scan",
            "abort requested; waiting for scanner subprocess",
        );
        true
    }

    pub(super) fn request_tool_abort(&mut self) -> bool {
        let Some(tool_name) = self.tool_running.clone() else {
            return false;
        };
        if self.tool_abort_requested {
            return false;
        }
        if let Some(cancel) = &self.tool_cancel {
            cancel.cancel();
        }
        self.tool_abort_requested = true;
        self.log(
            "tool",
            format!("{tool_name} cancel requested; waiting for the worker to stop"),
        );
        self.set_paused_activity(tool_name, "cancel requested; waiting for worker");
        true
    }

    pub(super) fn request_agent_abort(&mut self) -> bool {
        let Some(agent) = &mut self.agent_chat else {
            return false;
        };
        if !agent.running || agent.abort_requested {
            return false;
        }
        if let Some(cancel) = &self.agent_cancel {
            cancel.cancel();
        }
        agent.abort_requested = true;
        self.log(
            "agent",
            "abort requested; waiting for LangGraph to return (process kill not confirmed)",
        );
        self.set_paused_activity("agent", "abort requested; waiting for LangGraph");
        true
    }

    pub(super) fn request_plan_abort(&mut self) -> bool {
        if !self.planner_running || self.plan_abort_requested {
            return false;
        }
        if let Some(cancel) = &self.plan_cancel {
            cancel.cancel();
        }
        self.plan_abort_requested = true;
        self.log(
            "plan",
            "abort requested; waiting for LangGraph planner to return (process kill not confirmed)",
        );
        self.set_paused_activity("plan", "abort requested; waiting for LangGraph planner");
        true
    }

    pub(super) fn request_threat_abort(&mut self) -> bool {
        if !self.threat_worker_running || self.threat_abort_requested {
            return false;
        }
        if let Some(cancel) = &self.threat_cancel {
            cancel.cancel();
        }
        self.threat_abort_requested = true;
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

    pub(super) fn handle_quit_chord(&mut self) {
        if self.request_active_abort() {
            self.ctrl_c_armed_at = None;
            return;
        }
        if self.exit_or_arm_while_work_is_running() {
            return;
        }
        if self.consume_armed_quit_chord() {
            return;
        }
        self.arm_quit_chord();
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
        self.scan.as_ref().is_some_and(|scan| scan.abort_requested)
            || self.tool_abort_requested
            || self
                .agent_chat
                .as_ref()
                .is_some_and(|agent| agent.abort_requested)
            || self.plan_abort_requested
            || self.threat_abort_requested
    }

    fn cancel_active_tokens(&self) {
        cancel_token(self.scan_cancel.as_ref());
        cancel_token(self.tool_cancel.as_ref());
        cancel_token(self.agent_cancel.as_ref());
        cancel_token(self.plan_cancel.as_ref());
        cancel_token(self.threat_cancel.as_ref());
    }

    fn wait_briefly_for_abort_cleanup(&mut self) {
        if !self.has_worker_channels() {
            return;
        }
        let deadline = Instant::now() + Duration::from_millis(200);
        while self.has_running_work() && Instant::now() < deadline {
            self.drain_background_events();
            std::thread::sleep(Duration::from_millis(25));
        }
        self.drain_background_events();
    }

    fn has_worker_channels(&self) -> bool {
        self.scan_rx.is_some()
            || self.tool_rx.is_some()
            || self.agent_rx.is_some()
            || self.plan_rx.is_some()
            || self.threat_rx.is_some()
    }

    fn consume_armed_quit_chord(&mut self) -> bool {
        if !self.ctrl_c_armed() {
            return false;
        }
        self.should_quit = true;
        true
    }

    fn arm_quit_chord(&mut self) {
        self.ctrl_c_armed_at = Some(Instant::now());
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
