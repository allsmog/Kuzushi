use super::*;

impl ShellApp {
    pub fn drain_background_events(&mut self) -> bool {
        let mut changed = self.drain_scan_events();
        changed |= self.drain_tool_events();
        changed |= self.drain_agent_events();
        changed |= self.drain_plan_events();
        changed |= self.drain_threat_events();
        changed |= self.drain_trace_events();
        changed
    }

    pub(crate) fn drain_scan_events(&mut self) -> bool {
        let mut changed = false;
        let mut events = Vec::new();
        if let Some(rx) = &self.scan_rx {
            while let Ok(event) = rx.try_recv() {
                events.push(event);
            }
        }

        if !events.is_empty() {
            changed = true;
        }
        for event in events {
            self.apply_scan_event(event);
        }

        if self.scan.as_ref().is_some_and(|scan| !scan.running) {
            self.scan_rx = None;
            self.scan_cancel = None;
        }
        changed
    }

    pub(crate) fn drain_tool_events(&mut self) -> bool {
        let mut tool_events = Vec::new();
        if let Some(rx) = &self.tool_rx {
            while let Ok(event) = rx.try_recv() {
                tool_events.push(event);
            }
        }

        let changed = !tool_events.is_empty();
        for event in tool_events {
            self.apply_tool_event(event);
        }

        if self.tool_running.is_none() {
            self.tool_rx = None;
            self.tool_abort_requested = false;
        }
        changed
    }

    pub(crate) fn drain_agent_events(&mut self) -> bool {
        let mut agent_events = Vec::new();
        if let Some(rx) = &self.agent_rx {
            while let Ok(event) = rx.try_recv() {
                agent_events.push(event);
            }
        }

        let changed = !agent_events.is_empty();
        for event in agent_events {
            self.apply_agent_event(event);
        }

        if self.agent_chat.as_ref().is_some_and(|agent| !agent.running) {
            self.agent_rx = None;
        }
        changed
    }

    pub(crate) fn drain_plan_events(&mut self) -> bool {
        let mut plan_events = Vec::new();
        if let Some(rx) = &self.plan_rx {
            while let Ok(event) = rx.try_recv() {
                plan_events.push(event);
            }
        }
        let changed = !plan_events.is_empty();
        for event in plan_events {
            self.apply_plan_event(event);
        }
        if !self.planner_running {
            self.plan_rx = None;
        }
        changed
    }

    pub(crate) fn drain_threat_events(&mut self) -> bool {
        let mut threat_events = Vec::new();
        if let Some(rx) = &self.threat_rx {
            while let Ok(event) = rx.try_recv() {
                threat_events.push(event);
            }
        }
        let changed = !threat_events.is_empty();
        for event in threat_events {
            self.apply_threat_patch_event(event);
        }
        if !self.threat_worker_running {
            self.threat_rx = None;
        }
        changed
    }

    pub(crate) fn drain_trace_events(&mut self) -> bool {
        let mut steps = Vec::new();
        if let Some(rx) = &self.trace_rx {
            while let Ok(step) = rx.try_recv() {
                steps.push(step);
            }
        }
        let changed = !steps.is_empty();
        if changed {
            let session = self
                .activity
                .get_or_insert_with(|| ActivitySession::new(default_activity_run_id()));
            for step in steps {
                session.apply_step(step);
            }
        }
        // Tear down the receiver only when the producer is gone AND the
        // tool/scan that owned it has finished — otherwise a slow tick could
        // drop the channel mid-run. We check both `tool_running` and the
        // scan's running flag.
        let scan_running = self.scan.as_ref().is_some_and(|scan| scan.running);
        if !scan_running && self.tool_running.is_none() && steps_drained_recently_idle(self) {
            self.trace_rx = None;
        }
        changed
    }
}

fn default_activity_run_id() -> String {
    format!(
        "manual-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    )
}

fn steps_drained_recently_idle(_app: &ShellApp) -> bool {
    // Simple policy: keep the receiver around only while a run is active. If
    // we ever want to support detached late events we can extend this.
    true
}
