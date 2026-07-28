use super::{
    AbortReason, JobHub, ProjectScopeDiscoveryResult, ProjectScopeDiscoveryRuntime,
    StampedTargetCandidateFacts, TargetCandidateDiscoveryResult, TargetCandidateDiscoveryRuntime,
    TargetFactsRuntime, TerminalLoopWake, ToolRunState, ViewArtifactReader, ViewHydrationDrain,
    ViewHydrationKey, ViewHydrationRuntime, WorkerHandleRegistry,
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
    cleared_agent_run: Option<ClearedAgentRun>,
    plan_cancel: Option<ScanCancellation>,
    threat_cancel: Option<ScanCancellation>,
    tool_run: ToolRunState,
    jobs: JobHub,
    project_scope_discovery: ProjectScopeDiscoveryRuntime,
    target_candidate_discovery: TargetCandidateDiscoveryRuntime,
    active_target_facts: TargetFactsRuntime,
    view_hydration: ViewHydrationRuntime,
    /// Handle of the campaign dispatcher THIS shell launched. Held so the
    /// deck can reap it (no zombie) and so kill targets a verified-live pid
    /// instead of a possibly recycled one.
    dispatcher_child: Option<std::process::Child>,
}

#[derive(Debug, Clone)]
pub(crate) struct ClearedAgentRun {
    pub(crate) run_id: Option<String>,
    pub(crate) started_secs: u64,
    pub(crate) artifact_target: Option<PathBuf>,
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

    pub(crate) fn project_scope_discovery_running(&self) -> bool {
        self.project_scope_discovery.is_running()
    }

    pub(crate) fn schedule_view_hydration(
        &mut self,
        target: PathBuf,
        keys: Vec<ViewHydrationKey>,
    ) -> Vec<ViewHydrationKey> {
        self.view_hydration
            .schedule(target, keys, self.loop_wake.clone())
    }

    pub(crate) fn hydrate_view_blocking(
        &mut self,
        target: PathBuf,
        keys: Vec<ViewHydrationKey>,
    ) -> ViewHydrationDrain {
        self.view_hydration.hydrate_blocking(target, keys)
    }

    pub(crate) fn drain_view_hydration(&mut self) -> ViewHydrationDrain {
        self.view_hydration.drain_current()
    }

    pub(crate) fn invalidate_view_hydration(&mut self) {
        self.view_hydration.invalidate();
    }

    #[cfg(test)]
    pub(crate) fn set_view_artifact_reader(
        &mut self,
        reader: std::sync::Arc<dyn ViewArtifactReader>,
    ) {
        self.view_hydration.set_reader(reader);
    }

    #[cfg(test)]
    pub(crate) fn register_blocked_project_scope_discovery(
        &mut self,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        self.project_scope_discovery
            .register_blocked_handle(release);
    }

    pub(crate) fn start_target_candidate_discovery(&mut self, cwd: PathBuf) {
        self.target_candidate_discovery
            .start(cwd, self.loop_wake.clone());
    }

    pub(crate) fn drain_target_candidate_discovery(
        &mut self,
    ) -> Vec<TargetCandidateDiscoveryResult> {
        self.target_candidate_discovery.drain_current()
    }

    pub(crate) fn start_target_candidate_facts(&mut self, path: PathBuf) -> u64 {
        self.target_candidate_discovery
            .start_facts(path, self.loop_wake.clone())
    }

    pub(crate) fn drain_target_candidate_facts(&mut self) -> Vec<StampedTargetCandidateFacts> {
        self.target_candidate_discovery.drain_current_facts()
    }

    pub(crate) fn start_active_target_facts(&mut self, path: PathBuf) -> u64 {
        self.active_target_facts.start(path, self.loop_wake.clone())
    }

    pub(crate) fn drain_active_target_facts(&mut self) -> Vec<StampedTargetCandidateFacts> {
        self.active_target_facts.drain_current()
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

    pub(crate) fn remember_cleared_agent_run(&mut self, run: ClearedAgentRun) {
        self.cleared_agent_run = Some(run);
    }

    pub(crate) fn cleared_agent_run(&self) -> Option<&ClearedAgentRun> {
        self.cleared_agent_run.as_ref()
    }

    pub(crate) fn clear_cleared_agent_run(&mut self) {
        self.cleared_agent_run = None;
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

    pub(crate) fn set_dispatcher_child(&mut self, child: Option<std::process::Child>) {
        self.dispatcher_child = child;
    }

    pub(crate) fn take_dispatcher_child(&mut self) -> Option<std::process::Child> {
        self.dispatcher_child.take()
    }

    /// Reap the deck-launched dispatcher if it has exited. Returns true when
    /// a defunct dispatcher was just collected (callers then clear the pid).
    pub(crate) fn reap_exited_dispatcher(&mut self) -> bool {
        let exited = matches!(
            self.dispatcher_child
                .as_mut()
                .map(std::process::Child::try_wait),
            Some(Ok(Some(_)))
        );
        if exited {
            self.dispatcher_child = None;
        }
        exited
    }
}
