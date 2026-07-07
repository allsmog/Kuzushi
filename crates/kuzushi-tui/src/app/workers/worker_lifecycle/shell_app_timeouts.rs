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
        self.worker_handles.register(label, generation, handle);
    }

    pub(crate) fn register_worker_handle_with_watchdog(
        &mut self,
        label: &'static str,
        generation: WorkerGeneration,
        handle: JoinHandle<()>,
        cancel: ScanCancellation,
    ) {
        let watchdog = self.worker_watchdog(cancel);
        self.worker_handles
            .register_with_watchdog(label, generation, handle, watchdog);
    }

    pub(crate) fn reap_worker_handles(&mut self) -> bool {
        let finished = self.worker_handles.reap_finished();
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
        let timed_out = self.worker_handles.cancel_timed_out(Instant::now());
        for worker in &timed_out {
            self.log_worker_timeout(worker);
            self.mark_worker_timeout_requested(worker);
        }
        !timed_out.is_empty()
    }

    fn worker_watchdog(&self, cancel: ScanCancellation) -> Option<WorkerWatchdog> {
        self.config
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
        match worker.label {
            "scan" => self.mark_scan_timeout(worker.generation),
            "tool" => self.mark_tool_timeout(worker.generation),
            "agent" => self.mark_agent_timeout(worker.generation),
            "planner" => self.mark_plan_timeout(worker.generation),
            "threat model" => self.mark_threat_timeout(worker.generation),
            _ => {}
        }
    }

    fn mark_scan_timeout(&mut self, generation: WorkerGeneration) {
        if self.scan_generation != Some(generation) {
            return;
        }
        if let Some(scan) = &mut self.scan {
            scan.stage = "timeout reached; cancel requested".to_string();
            scan.abort_requested = true;
        }
        self.set_paused_activity("sast:scan", "timeout reached; cancel requested");
    }

    fn mark_tool_timeout(&mut self, generation: WorkerGeneration) {
        if self.tool_generation != Some(generation) {
            return;
        }
        let Some(tool_name) = self.tool_running.clone() else {
            return;
        };
        self.tool_abort_requested = true;
        self.set_paused_activity(tool_name, "timeout reached; cancel requested");
    }

    fn mark_agent_timeout(&mut self, generation: WorkerGeneration) {
        if self.agent_generation != Some(generation) {
            return;
        }
        if let Some(agent) = &mut self.agent_chat {
            agent.abort_requested = true;
        }
        self.set_paused_activity("agent", "timeout reached; cancel requested");
    }

    fn mark_plan_timeout(&mut self, generation: WorkerGeneration) {
        if self.plan_generation != Some(generation) {
            return;
        }
        self.plan_abort_requested = true;
        self.set_paused_activity("plan", "timeout reached; cancel requested");
    }

    fn mark_threat_timeout(&mut self, generation: WorkerGeneration) {
        if self.threat_generation != Some(generation) {
            return;
        }
        self.threat_abort_requested = true;
        self.set_paused_activity("threat model", "timeout reached; cancel requested");
    }
}
