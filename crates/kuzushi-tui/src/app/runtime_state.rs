use super::{
    AbortReason, JobHub, ProjectScopeDiscoveryResult, ProjectScopeDiscoveryRuntime,
    TerminalLoopWake, ToolRunState, WorkerHandleRegistry,
};
use kuzushi_core::ScanCancellation;
use std::path::PathBuf;

#[derive(Debug, Default)]
pub(crate) struct RuntimeState {
    worker_handles: WorkerHandleRegistry,
    loop_wake: Option<TerminalLoopWake>,
    scan_cancel: Option<ScanCancellation>,
    scan_abort_reason: Option<AbortReason>,
    agent_cancel: Option<ScanCancellation>,
    plan_cancel: Option<ScanCancellation>,
    threat_cancel: Option<ScanCancellation>,
    tool_run: ToolRunState,
    jobs: JobHub,
    project_scope_discovery: ProjectScopeDiscoveryRuntime,
}

impl RuntimeState {
    #[cfg(test)]
    pub(crate) fn worker_handles(&self) -> &WorkerHandleRegistry {
        &self.worker_handles
    }

    pub(crate) fn worker_handles_mut(&mut self) -> &mut WorkerHandleRegistry {
        &mut self.worker_handles
    }

    pub(crate) fn set_loop_wake(&mut self, wake: Option<TerminalLoopWake>) {
        self.loop_wake = wake;
    }

    pub(crate) fn start_project_scope_discovery(&mut self, root: PathBuf) {
        self.project_scope_discovery
            .start(root, self.loop_wake.clone());
    }

    pub(crate) fn drain_project_scope_discovery(&mut self) -> Vec<ProjectScopeDiscoveryResult> {
        self.project_scope_discovery.drain_current()
    }

    pub(crate) fn scan_cancel(&self) -> Option<&ScanCancellation> {
        self.scan_cancel.as_ref()
    }

    pub(crate) fn set_scan_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.scan_cancel = cancel;
    }

    pub(crate) fn scan_abort_reason(&self) -> Option<AbortReason> {
        self.scan_abort_reason
    }

    pub(crate) fn set_scan_abort_reason(&mut self, reason: Option<AbortReason>) {
        self.scan_abort_reason = reason;
    }

    pub(crate) fn agent_cancel(&self) -> Option<&ScanCancellation> {
        self.agent_cancel.as_ref()
    }

    pub(crate) fn set_agent_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.agent_cancel = cancel;
    }

    pub(crate) fn plan_cancel(&self) -> Option<&ScanCancellation> {
        self.plan_cancel.as_ref()
    }

    pub(crate) fn set_plan_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.plan_cancel = cancel;
    }

    pub(crate) fn threat_cancel(&self) -> Option<&ScanCancellation> {
        self.threat_cancel.as_ref()
    }

    pub(crate) fn set_threat_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.threat_cancel = cancel;
    }

    pub(crate) fn tool_run(&self) -> &ToolRunState {
        &self.tool_run
    }

    pub(crate) fn tool_run_mut(&mut self) -> &mut ToolRunState {
        &mut self.tool_run
    }

    pub(crate) fn jobs(&self) -> &JobHub {
        &self.jobs
    }

    pub(crate) fn jobs_mut(&mut self) -> &mut JobHub {
        &mut self.jobs
    }
}
