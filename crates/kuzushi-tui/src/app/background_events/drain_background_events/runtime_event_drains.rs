use super::event_collection::*;
use super::*;

const EVENT_DRAIN_LIMIT: usize = 256;
pub(super) const TRACE_DRAIN_LIMIT: usize = 512;
pub(super) const JOB_DRAIN_LIMIT: usize = EVENT_DRAIN_LIMIT + TRACE_DRAIN_LIMIT;

impl ShellApp {
    pub fn drain_background_events(&mut self) -> bool {
        let mut changed = self.reap_worker_handles();
        changed |= self.cancel_timed_out_workers();
        changed |= self.drain_job_events();
        changed |= self.drain_trace_events();
        changed |= self.drain_scan_events();
        changed |= self.drain_tool_events();
        changed |= self.drain_agent_events();
        changed |= self.drain_plan_events();
        changed |= self.drain_threat_events();
        changed
    }

    pub(crate) fn drain_job_events(&mut self) -> bool {
        let events = self.jobs.drain(JOB_DRAIN_LIMIT);
        let changed = !events.is_empty();
        for event in events {
            update(self, Msg::Job(event));
        }
        changed
    }

    pub(crate) fn apply_job_event(&mut self, event: ShellEvent) {
        let kind = event.kind();
        let finishes_slot = self.job_event_finishes_slot(&event);
        if finishes_slot {
            self.jobs.finish(kind);
        }
        match event {
            ShellEvent::Trace(step) => self.apply_trace_step(step),
            ShellEvent::Scan(event) => self.apply_scan_event(event),
            ShellEvent::Tool(event) => self.apply_tool_event(event),
            ShellEvent::Agent(event) => self.apply_agent_event(event),
            ShellEvent::Plan(event) => self.apply_plan_event(event),
            ShellEvent::Threat(event) => self.apply_threat_patch_event(event),
        }
        if finishes_slot {
            self.clear_finished_job(kind);
        }
    }

    fn job_event_finishes_slot(&self, event: &ShellEvent) -> bool {
        match event {
            ShellEvent::Trace(_) | ShellEvent::Scan(ScanEvent::Stage(_)) => false,
            ShellEvent::Scan(ScanEvent::Finished { .. } | ScanEvent::Failed { .. }) => {
                self.tool_running.is_none() && self.scan.as_ref().is_some_and(|scan| scan.running)
            }
            ShellEvent::Tool(ToolEvent::Finished { .. } | ToolEvent::Failed { .. }) => {
                !self.scan.as_ref().is_some_and(|scan| scan.running)
            }
            ShellEvent::Agent(_) | ShellEvent::Plan(_) | ShellEvent::Threat(_) => {
                event.is_terminal()
            }
        }
    }

    fn apply_trace_step(&mut self, step: RunTraceStep) {
        let session = self
            .activity
            .get_or_insert_with(|| ActivitySession::new(default_activity_run_id()));
        session.apply_step(step);
    }

    fn clear_finished_job(&mut self, kind: JobKind) {
        if kind == JobKind::Run {
            self.clear_finished_run_job();
        }
    }

    fn clear_finished_run_job(&mut self) {
        if self.scan.as_ref().is_some_and(|scan| scan.running) || self.tool_running.is_some() {
            return;
        }
        self.scan_generation = None;
        self.tool_generation = None;
        self.trace_generation = None;
        self.scan_cancel = None;
        self.tool_cancel = None;
        self.tool_abort_requested = false;
    }

    pub(crate) fn drain_scan_events(&mut self) -> bool {
        let (mut events, status) = collect_current_events(
            self.scan_rx.as_ref(),
            self.scan_generation,
            EVENT_DRAIN_LIMIT,
        );
        if disconnected_without_events(&events, status)
            && self.scan.as_ref().is_some_and(|scan| scan.running)
        {
            events.push(ScanEvent::Failed {
                error: disconnected_worker_message("scan"),
            });
        }
        let changed = !events.is_empty() || status == DrainStatus::Disconnected;
        self.drain_trace_before_terminal_events(&events);
        for event in events {
            self.apply_scan_event(event);
        }

        if can_clear_channel(status) && self.scan.as_ref().is_some_and(|scan| !scan.running) {
            self.scan_rx = None;
            self.scan_generation = None;
            self.scan_cancel = None;
        }
        changed
    }

    pub(crate) fn drain_tool_events(&mut self) -> bool {
        let (mut events, status) = collect_current_events(
            self.tool_rx.as_ref(),
            self.tool_generation,
            EVENT_DRAIN_LIMIT,
        );
        if disconnected_without_events(&events, status) {
            if let Some(tool_name) = self.tool_running.clone() {
                events.push(ToolEvent::Failed {
                    tool_name,
                    error: disconnected_worker_message("tool"),
                });
            }
        }
        let changed = !events.is_empty() || status == DrainStatus::Disconnected;
        self.drain_trace_before_terminal_events(&events);
        for event in events {
            self.apply_tool_event(event);
        }
        self.clear_finished_tool_channel(status);
        changed
    }

    fn clear_finished_tool_channel(&mut self, status: DrainStatus) {
        if can_clear_channel(status) && self.tool_running.is_none() {
            self.tool_rx = None;
            self.tool_generation = None;
            self.tool_cancel = None;
            self.tool_abort_requested = false;
        }
    }

    pub(crate) fn drain_agent_events(&mut self) -> bool {
        let (mut events, status) = collect_current_events(
            self.agent_rx.as_ref(),
            self.agent_generation,
            EVENT_DRAIN_LIMIT,
        );
        if disconnected_without_events(&events, status)
            && self.agent_chat.as_ref().is_some_and(|agent| agent.running)
        {
            events.push(AgentEvent::Failed {
                error: disconnected_worker_message("agent"),
                audit: disconnected_agent_audit(self),
            });
        }
        let changed = !events.is_empty() || status == DrainStatus::Disconnected;
        for event in events {
            self.apply_agent_event(event);
        }
        self.clear_finished_agent_channel(status);
        changed
    }

    fn clear_finished_agent_channel(&mut self, status: DrainStatus) {
        if can_clear_channel(status) && self.agent_chat.as_ref().is_some_and(|agent| !agent.running)
        {
            self.agent_rx = None;
            self.agent_generation = None;
            self.agent_cancel = None;
        }
    }

    pub(crate) fn drain_plan_events(&mut self) -> bool {
        let (mut events, status) = collect_current_events(
            self.plan_rx.as_ref(),
            self.plan_generation,
            EVENT_DRAIN_LIMIT,
        );
        if disconnected_without_events(&events, status) && self.planner_running {
            events.push(PlanEvent::Failed {
                error: disconnected_worker_message("planner"),
            });
        }
        let changed = !events.is_empty() || status == DrainStatus::Disconnected;
        for event in events {
            self.apply_plan_event(event);
        }
        self.clear_finished_plan_channel(status);
        changed
    }

    fn clear_finished_plan_channel(&mut self, status: DrainStatus) {
        if can_clear_channel(status) && !self.planner_running {
            self.plan_rx = None;
            self.plan_generation = None;
            self.plan_cancel = None;
        }
    }

    pub(crate) fn drain_threat_events(&mut self) -> bool {
        let (mut events, status) = collect_current_events(
            self.threat_rx.as_ref(),
            self.threat_generation,
            EVENT_DRAIN_LIMIT,
        );
        if disconnected_without_events(&events, status) && self.threat_worker_running {
            events.push(ThreatPatchEvent::Failed {
                error: disconnected_worker_message("threat model"),
            });
        }
        let changed = !events.is_empty() || status == DrainStatus::Disconnected;
        for event in events {
            self.apply_threat_patch_event(event);
        }
        self.clear_finished_threat_channel(status);
        changed
    }

    fn clear_finished_threat_channel(&mut self, status: DrainStatus) {
        if can_clear_channel(status) && !self.threat_worker_running {
            self.threat_rx = None;
            self.threat_generation = None;
            self.threat_cancel = None;
        }
    }

    pub(crate) fn drain_trace_events(&mut self) -> bool {
        let (steps, status) = collect_current_events(
            self.trace_rx.as_ref(),
            self.trace_generation,
            TRACE_DRAIN_LIMIT,
        );
        let changed = !steps.is_empty();
        if changed {
            let session = self
                .activity
                .get_or_insert_with(|| ActivitySession::new(default_activity_run_id()));
            for step in steps {
                session.apply_step(step);
            }
        }
        if status == DrainStatus::Disconnected
            || (can_clear_channel(status) && !self.has_running_work())
        {
            self.trace_rx = None;
            self.trace_generation = None;
        }
        changed || status == DrainStatus::Disconnected
    }

    fn drain_trace_before_terminal_events<T>(&mut self, events: &[T]) {
        if !events.is_empty() {
            self.drain_trace_events();
        }
    }
}
