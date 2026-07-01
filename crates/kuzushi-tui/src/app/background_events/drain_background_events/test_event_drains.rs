use super::*;
use std::sync::mpsc;
use std::time::Duration;

impl ShellApp {
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
            self.agent_cancel = None;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn drain_next_tool_event_for_test(
        &mut self,
        timeout: Duration,
    ) -> std::result::Result<(), String> {
        let event = self.recv_next_tool_event_for_test(timeout)?;
        self.apply_tool_event(event);
        if self.tool_running.is_none() {
            self.tool_rx = None;
            self.tool_cancel = None;
            self.tool_abort_requested = false;
        }
        Ok(())
    }

    #[cfg(test)]
    fn recv_next_tool_event_for_test(
        &self,
        timeout: Duration,
    ) -> std::result::Result<ToolEvent, String> {
        let Some(rx) = self.tool_rx.as_ref() else {
            return Err(self.missing_tool_channel_diagnostics());
        };
        match rx.recv_timeout(timeout) {
            Ok(event) => Ok(event),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
                "timed out after {timeout:?} waiting for tool worker; running={:?}",
                self.tool_running
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(format!(
                "tool worker channel disconnected before reporting completion; running={:?}",
                self.tool_running
            )),
        }
    }

    #[cfg(test)]
    fn missing_tool_channel_diagnostics(&self) -> String {
        format!(
            "tool worker channel missing; recent log: [{}]",
            self.log
                .iter()
                .rev()
                .take(5)
                .map(|line| format!("{}: {}", line.prefix, line.body))
                .collect::<Vec<_>>()
                .join(" | ")
        )
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
