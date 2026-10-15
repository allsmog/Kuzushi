use super::*;
use std::time::{Duration, Instant};

impl ShellApp {
    #[cfg(test)]
    pub(crate) fn drain_next_tool_event_for_test(
        &mut self,
        timeout: Duration,
    ) -> std::result::Result<(), String> {
        let deadline = Instant::now() + timeout;
        let awaited_tool = self.running_tool_name().map(str::to_string);
        let mut drain_count = 0usize;
        let mut changed_count = 0usize;
        while Instant::now() < deadline {
            let changed = self.drain_job_events();
            drain_count += 1;
            changed_count += usize::from(changed);
            let current_tool = self.running_tool_name();
            let next_tool_started =
                current_tool.is_some() && current_tool != awaited_tool.as_deref();
            let slot_settled = current_tool.is_none() && !self.jobs().is_running(JobKind::Run);
            if awaited_tool.is_some() && (next_tool_started || slot_settled) {
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
            self.activity().map(ActivitySession::event_count).unwrap_or(0),
            self.log_lines()
                .iter()
                .rev()
                .take(6)
                .map(|line| format!("{}: {}", line.prefix, line.body))
                .collect::<Vec<_>>()
                .join(" | "),
        ))
    }
}
