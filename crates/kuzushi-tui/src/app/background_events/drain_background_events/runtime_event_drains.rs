use super::*;
use std::time::{Duration, Instant};

const EVENT_DRAIN_LIMIT: usize = 256;
pub(super) const TRACE_DRAIN_LIMIT: usize = 512;
pub(super) const JOB_DRAIN_LIMIT: usize = EVENT_DRAIN_LIMIT + TRACE_DRAIN_LIMIT;
const JOB_DRAIN_TIME_SLICE: Duration = Duration::from_millis(3);
const MIN_JOB_DRAIN_EVENTS_BEFORE_TIME_CHECK: usize = 32;

impl ShellApp {
    pub fn drain_background_events(&mut self) -> bool {
        self.run_background_maintenance() | self.drain_job_events()
    }

    pub(crate) fn run_background_maintenance(&mut self) -> bool {
        self.reap_worker_handles() | self.cancel_timed_out_workers()
    }

    pub(crate) fn drain_job_events(&mut self) -> bool {
        let messages = self.drain_job_messages();
        update_many_and_execute_effects(self, messages)
    }

    pub(crate) fn drain_job_messages(&mut self) -> Vec<Msg> {
        let started_at = Instant::now();
        let mut inspected = 0;
        let mut messages = Vec::new();
        while inspected < JOB_DRAIN_LIMIT {
            match self.jobs_mut().drain_one() {
                JobDrainResult::Event(event) => {
                    messages.push(Msg::Job(event));
                }
                JobDrainResult::Stale => {}
                JobDrainResult::Empty => break,
            }
            inspected += 1;
            if inspected >= MIN_JOB_DRAIN_EVENTS_BEFORE_TIME_CHECK
                && started_at.elapsed() >= JOB_DRAIN_TIME_SLICE
            {
                break;
            }
        }
        messages
    }

    pub(crate) fn apply_job_event(&mut self, event: ShellEvent) -> Vec<ShellEffect> {
        let kind = event.kind();
        let finishes_slot = self.job_event_finishes_slot(&event);
        if finishes_slot {
            self.jobs_mut().finish(kind);
        }
        let mut effects = self.apply_current_job_event(event);
        if finishes_slot {
            self.clear_finished_job(kind);
            // Centralized steer-queue drain: every terminal job event (scan
            // success/failure, tool success/failure, agent/plan/threat finish)
            // flows through here, so the operator steer queue drains on ALL
            // completion paths — not just a successful background-tool finish.
            effects.extend(self.advance_steer_queue());
        }
        effects
    }

    fn apply_current_job_event(&mut self, event: ShellEvent) -> Vec<ShellEffect> {
        match event {
            ShellEvent::Trace(step) => {
                self.apply_trace_step(step);
                Vec::new()
            }
            ShellEvent::Scan(event) => self.apply_scan_event(event),
            ShellEvent::Tool(event) => self.apply_tool_event(event),
            ShellEvent::Agent(event) => self.apply_agent_event(event),
            ShellEvent::Plan(event) => {
                self.apply_plan_event(event);
                Vec::new()
            }
            ShellEvent::Threat(event) => {
                self.apply_threat_patch_event(event);
                Vec::new()
            }
        }
    }

    fn job_event_finishes_slot(&self, event: &ShellEvent) -> bool {
        match event {
            ShellEvent::Trace(_) | ShellEvent::Scan(ScanEvent::Stage(_)) => false,
            ShellEvent::Scan(ScanEvent::Finished { .. } | ScanEvent::Failed { .. }) => {
                !self.tool_is_running() && self.scan().is_some_and(|scan| scan.running)
            }
            ShellEvent::Tool(ToolEvent::Finished { .. } | ToolEvent::Failed { .. }) => {
                !self.scan().is_some_and(|scan| scan.running)
            }
            ShellEvent::Agent(_) | ShellEvent::Plan(_) | ShellEvent::Threat(_) => {
                event.is_terminal()
            }
        }
    }

    fn apply_trace_step(&mut self, step: RunTraceStep) {
        let session =
            self.activity_or_insert_with(|| ActivitySession::new(default_activity_run_id()));
        session.apply_step(step);
    }

    fn clear_finished_job(&mut self, kind: JobKind) {
        match kind {
            JobKind::Run => self.clear_finished_run_job(),
            JobKind::Agent => self.clear_finished_agent_job(),
            JobKind::Plan => self.clear_finished_plan_job(),
            JobKind::Threat => self.clear_finished_threat_job(),
        }
    }

    fn clear_finished_run_job(&mut self) {
        if self.scan().is_some_and(|scan| scan.running) || self.tool_is_running() {
            return;
        }
        self.set_scan_cancel(None);
        self.clear_finished_tool_run_slot();
    }

    fn clear_finished_agent_job(&mut self) {
        if self.agent_chat().is_some_and(|agent| agent.running) {
            return;
        }
        self.set_agent_cancel(None);
    }

    fn clear_finished_plan_job(&mut self) {
        if self.planner_running() {
            return;
        }
        self.set_plan_cancel(None);
    }

    fn clear_finished_threat_job(&mut self) {
        if self.threat_worker_running() {
            return;
        }
        self.set_threat_cancel(None);
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
