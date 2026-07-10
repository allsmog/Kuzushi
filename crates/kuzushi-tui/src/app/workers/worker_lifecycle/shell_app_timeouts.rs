use super::*;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

impl ShellApp {
    #[cfg(test)]
    pub(crate) fn register_worker_handle(
        &mut self,
        label: &'static str,
        generation: WorkerGeneration,
        handle: JoinHandle<()>,
    ) {
        self.runtime_state
            .worker_handles_mut()
            .register(label, generation, handle);
    }

    pub(crate) fn register_worker_handle_with_watchdog(
        &mut self,
        label: &'static str,
        generation: WorkerGeneration,
        handle: JoinHandle<()>,
        cancel: ScanCancellation,
    ) {
        let watchdog = self.worker_watchdog(cancel);
        self.runtime_state
            .worker_handles_mut()
            .register_with_watchdog(label, generation, handle, watchdog);
    }

    pub(crate) fn reap_worker_handles(&mut self) -> bool {
        let finished = self.runtime_state.worker_handles_mut().reap_finished();
        let changed = !finished.is_empty();
        let panicked = finished
            .into_iter()
            .filter(|worker| worker.panicked)
            .collect::<Vec<_>>();
        for worker in panicked {
            self.log(
                "error",
                format!(
                    "{} worker handle panicked after generation {:?}",
                    worker.label, worker.generation
                ),
            );
        }
        changed
    }

    pub(crate) fn cancel_timed_out_workers(&mut self) -> bool {
        let timed_out = self
            .runtime_state
            .worker_handles_mut()
            .cancel_timed_out(Instant::now());
        for worker in &timed_out {
            self.log_worker_timeout(worker);
            self.mark_worker_timeout_requested(worker);
        }
        let escalated = self.fail_unresponsive_workers();
        !timed_out.is_empty() || escalated
    }

    /// Escalation for non-cooperative workers: once the watchdog cancel's
    /// grace window elapses with no terminal event, emit a synthetic failure
    /// so the job slot is released and new work is accepted. The hung OS
    /// thread is not killed; only the logical slot is freed honestly.
    fn fail_unresponsive_workers(&mut self) -> bool {
        let escalated = self.jobs_mut().fail_unresponsive_slots(Instant::now());
        if escalated {
            self.log(
                "error",
                "worker unresponsive after watchdog cancel grace; releasing job slot with synthetic failure".to_string(),
            );
        }
        escalated
    }

    fn worker_watchdog(&self, cancel: ScanCancellation) -> Option<WorkerWatchdog> {
        self.config()
            .runtime
            .worker_watchdog_timeout_ms
            .map(Duration::from_millis)
            .map(|timeout| WorkerWatchdog::new(cancel, timeout))
    }

    fn log_worker_timeout(&mut self, worker: &TimedOutWorkerHandle) {
        self.log(
            "error",
            format!(
                "{} worker exceeded {}ms watchdog after {}ms; cancellation requested",
                worker.label,
                worker.timeout.as_millis(),
                worker.elapsed.as_millis()
            ),
        );
    }

    fn mark_worker_timeout_requested(&mut self, worker: &TimedOutWorkerHandle) {
        let Some(kind) = job_kind_for_worker(worker.label) else {
            return;
        };
        if !self.jobs().is_current_generation(kind, worker.generation) {
            return;
        }
        self.jobs_mut()
            .schedule_unresponsive_escalation(kind, worker.generation, Instant::now());
        match worker.label {
            "scan" => self.mark_scan_timeout(),
            "tool" => self.mark_tool_timeout(),
            "agent" => self.mark_agent_timeout(),
            "planner" => self.mark_plan_timeout(),
            "threat model" => self.mark_threat_timeout(),
            _ => {}
        }
    }

    fn mark_scan_timeout(&mut self) {
        self.set_scan_abort_reason(Some(AbortReason::Watchdog));
        if let Some(scan) = self.scan_mut() {
            scan.stage = "timeout reached; cancel requested".to_string();
            scan.abort_requested = true;
        }
        self.set_paused_activity("sast:scan", "timeout reached; cancel requested");
    }

    fn mark_tool_timeout(&mut self) {
        let Some(tool_name) = self.running_tool_name_owned() else {
            return;
        };
        self.request_tool_abort_flag(AbortReason::Watchdog);
        self.set_paused_activity(tool_name, "timeout reached; cancel requested");
    }

    fn mark_agent_timeout(&mut self) {
        if let Some(agent) = self.agent_chat_mut() {
            agent.abort_requested = true;
        }
        self.set_paused_activity("agent", "timeout reached; cancel requested");
    }

    fn mark_plan_timeout(&mut self) {
        self.set_plan_abort_requested(true);
        self.set_paused_activity("plan", "timeout reached; cancel requested");
    }

    fn mark_threat_timeout(&mut self) {
        self.set_threat_abort_requested(true);
        self.set_paused_activity("threat model", "timeout reached; cancel requested");
    }
}

fn job_kind_for_worker(label: &str) -> Option<JobKind> {
    match label {
        "scan" | "tool" => Some(JobKind::Run),
        "agent" => Some(JobKind::Agent),
        "planner" => Some(JobKind::Plan),
        "threat model" => Some(JobKind::Threat),
        _ => None,
    }
}
