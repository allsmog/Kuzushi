use super::*;
use std::time::{Duration, Instant};

impl ShellApp {
    #[cfg(test)]
    pub(crate) fn drain_next_agent_event_for_test(
        &mut self,
        timeout: Duration,
    ) -> std::result::Result<(), String> {
        let deadline = Instant::now() + timeout;
        let mut drain_count = 0usize;
        let mut changed_count = 0usize;
        while Instant::now() < deadline {
            let agent_was_running = self.agent_chat().is_some_and(|agent| agent.running);
            let changed = self.drain_job_events();
            drain_count += 1;
            changed_count += usize::from(changed);
            let agent_stopped = self.agent_chat().is_some_and(|agent| !agent.running);
            if agent_was_running && agent_stopped {
                return Ok(());
            }
            if !changed {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Err(format!(
            "timed out after {timeout:?} waiting for job agent worker; job_running={}; drains={drain_count}; changed_drains={changed_count}; {}",
            self.jobs().is_running(JobKind::Agent),
            self.agent_chat_diagnostics_for_test(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn drain_next_tool_event_for_test(
        &mut self,
        timeout: Duration,
    ) -> std::result::Result<(), String> {
        let deadline = Instant::now() + timeout;
        let mut drain_count = 0usize;
        let mut changed_count = 0usize;
        while Instant::now() < deadline {
            let tool_was_running = self.tool_is_running();
            let changed = self.drain_job_events();
            drain_count += 1;
            changed_count += usize::from(changed);
            if tool_was_running && !self.tool_is_running() {
                return Ok(());
            }
            if !changed {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Err(format!(
            "timed out after {timeout:?} waiting for job tool worker; running={:?}; job_running={}; activity_events={}; drains={drain_count}; changed_drains={changed_count}; recent log: [{}]",
            self.running_tool_name(),
            self.jobs().is_running(JobKind::Run),
            self.activity().map(|activity| activity.events.len()).unwrap_or(0),
            self.log_lines()
                .iter()
                .rev()
                .take(6)
                .map(|line| format!("{}: {}", line.prefix, line.body))
                .collect::<Vec<_>>()
                .join(" | "),
        ))
    }

    #[cfg(test)]
    pub(crate) fn agent_chat_diagnostics_for_test(&self) -> String {
        let agent_state = match self.agent_chat() {
            Some(agent) => format!(
                "AgentChat question={:?} running={} abort_requested={} answer={:?} error={:?}",
                agent.question, agent.running, agent.abort_requested, agent.answer, agent.error
            ),
            None => "AgentChat missing".to_string(),
        };
        let log_tail = self
            .log_lines()
            .iter()
            .rev()
            .take(5)
            .map(|line| format!("{}: {}", line.prefix, line.body))
            .collect::<Vec<_>>()
            .join(" | ");
        format!("{agent_state}; recent log: [{log_tail}]")
    }
}
