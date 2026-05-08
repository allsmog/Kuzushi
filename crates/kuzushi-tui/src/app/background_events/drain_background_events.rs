use super::*;

impl ShellApp {
    pub fn drain_background_events(&mut self) -> bool {
        let mut changed = self.drain_scan_events();
        changed |= self.drain_tool_events();
        changed |= self.drain_agent_events();
        changed |= self.drain_plan_events();
        changed |= self.drain_threat_events();
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

    #[cfg(test)]
    pub(crate) fn drain_next_agent_event_for_test(
        &mut self,
        timeout: Duration,
    ) -> std::result::Result<(), String> {
        let event = {
            let Some(rx) = self.agent_rx.as_ref() else {
                return Err(format!(
                    "agent worker channel missing; {}",
                    self.agent_chat_diagnostics_for_test()
                ));
            };
            match rx.recv_timeout(timeout) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "timed out after {timeout:?} waiting for agent worker event; {}",
                        self.agent_chat_diagnostics_for_test()
                    ));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "agent worker channel disconnected before reporting completion; {}",
                        self.agent_chat_diagnostics_for_test()
                    ));
                }
            }
        };

        self.apply_agent_event(event);
        if self.agent_chat.as_ref().is_some_and(|agent| !agent.running) {
            self.agent_rx = None;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn drain_next_tool_event_for_test(
        &mut self,
        timeout: Duration,
    ) -> std::result::Result<(), String> {
        let event = {
            let Some(rx) = self.tool_rx.as_ref() else {
                return Err(format!(
                    "tool worker channel missing; recent log: [{}]",
                    self.log
                        .iter()
                        .rev()
                        .take(5)
                        .map(|line| format!("{}: {}", line.prefix, line.body))
                        .collect::<Vec<_>>()
                        .join(" | ")
                ));
            };
            match rx.recv_timeout(timeout) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "timed out after {timeout:?} waiting for tool worker; running={:?}",
                        self.tool_running
                    ));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "tool worker channel disconnected before reporting completion; running={:?}",
                        self.tool_running
                    ));
                }
            }
        };

        self.apply_tool_event(event);
        if self.tool_running.is_none() {
            self.tool_rx = None;
            self.tool_abort_requested = false;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn agent_chat_diagnostics_for_test(&self) -> String {
        let agent_state = match &self.agent_chat {
            Some(agent) => format!(
                "AgentChat question={:?} running={} abort_requested={} answer={:?} error={:?}",
                agent.question, agent.running, agent.abort_requested, agent.answer, agent.error
            ),
            None => "AgentChat missing".to_string(),
        };
        let log_tail = self
            .log
            .iter()
            .rev()
            .take(5)
            .map(|line| format!("{}: {}", line.prefix, line.body))
            .collect::<Vec<_>>()
            .join(" | ");
        format!("{agent_state}; recent log: [{log_tail}]")
    }
}
