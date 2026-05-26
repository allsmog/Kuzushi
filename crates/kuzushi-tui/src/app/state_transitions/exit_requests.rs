use super::*;

impl ShellApp {
    pub(crate) fn request_exit(&mut self) {
        self.request_active_abort();
        if !self.should_quit {
            self.log("system", "exit requested; closing shell");
        }
        self.should_quit = true;
    }

    pub(super) fn request_active_abort(&mut self) -> bool {
        let mut requested = false;
        requested |= self.request_scan_abort();
        requested |= self.request_tool_abort();
        requested |= self.request_agent_abort();
        requested |= self.request_plan_abort();
        requested |= self.request_threat_abort();
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
        self.tool_abort_requested = true;
        self.log(
            "tool",
            format!("{tool_name} abort requested; waiting for the current filesystem step to finish (process kill not confirmed)"),
        );
        self.set_paused_activity(
            tool_name,
            "abort requested; waiting for current filesystem step",
        );
        true
    }

    pub(super) fn request_agent_abort(&mut self) -> bool {
        let Some(agent) = &mut self.agent_chat else {
            return false;
        };
        if !agent.running || agent.abort_requested {
            return false;
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
        let now = Instant::now();
        if let Some(armed_at) = self.ctrl_c_armed_at {
            if now.duration_since(armed_at) <= CTRL_C_ARM_WINDOW {
                self.should_quit = true;
                return;
            }
        }
        self.ctrl_c_armed_at = Some(now);
        self.log(
            "system",
            "press Ctrl+C again within 2s to exit (any other key cancels)",
        );
    }
}
