use super::{
    ActivitySession, AgentChatState, AgentChatView, ContextSnapshotView, ExploitChain,
    ExploitChainDetail, KnowledgeBaseView, LiveActivity, LogLine, LogState, PwnView, ReconSnapshot,
    ScanPanelState, ScanState, TaintFlowSnapshot, TaskDurationStore, WorkbenchCache, WorkspaceView,
};
use kuzushi_core::{
    findings::ReviewDecisionRecord,
    incremental_index::{coalesce_changes, plan_for_change, ReindexPlan, WorkspaceChange},
    AgenticSastReport, CarliniThreatHuntReport, Finding, ProgramScope, ScanProgress,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceStaleSummary {
    strongest_plan: ReindexPlan,
    pending_changes: Vec<WorkspaceChange>,
}

impl WorkspaceStaleSummary {
    pub(crate) fn from_changes(changes: &[WorkspaceChange]) -> Option<Self> {
        let pending_changes = coalesce_changes(changes.iter().cloned());
        let strongest_plan = pending_changes
            .iter()
            .map(plan_for_change)
            .max_by_key(|plan| reindex_plan_priority(*plan))?;
        Some(Self {
            strongest_plan,
            pending_changes,
        })
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.pending_changes.extend(other.pending_changes);
        self.pending_changes = coalesce_changes(std::mem::take(&mut self.pending_changes));
        if reindex_plan_priority(other.strongest_plan) > reindex_plan_priority(self.strongest_plan)
        {
            self.strongest_plan = other.strongest_plan;
        }
    }

    pub(crate) fn chip(&self) -> String {
        format!(
            "workspace:stale {}",
            reindex_plan_label(self.strongest_plan)
        )
    }

    pub(crate) fn change_count(&self) -> usize {
        self.pending_changes.len()
    }

    pub(crate) fn strongest_plan(&self) -> ReindexPlan {
        self.strongest_plan
    }

    pub(crate) fn pending_changes(&self) -> &[WorkspaceChange] {
        &self.pending_changes
    }
}

fn reindex_plan_priority(plan: ReindexPlan) -> u8 {
    match plan {
        ReindexPlan::MarkStaleOnly => 0,
        ReindexPlan::FileFacts => 1,
        ReindexPlan::FileFactsAndLocalAttackSurface => 2,
        ReindexPlan::DependencyIndex => 3,
        ReindexPlan::FullInventory => 4,
        ReindexPlan::FullDeterministicScan => 5,
        ReindexPlan::FullSnapshot => 6,
    }
}

fn reindex_plan_label(plan: ReindexPlan) -> &'static str {
    match plan {
        ReindexPlan::MarkStaleOnly => "prompts",
        ReindexPlan::FileFacts => "files",
        ReindexPlan::FileFactsAndLocalAttackSurface => "routes",
        ReindexPlan::DependencyIndex => "deps",
        ReindexPlan::FullInventory => "inventory",
        ReindexPlan::FullSnapshot => "snapshot",
        ReindexPlan::FullDeterministicScan => "rules",
    }
}

#[derive(Debug)]
pub struct DomainCache {
    context_view: ContextSnapshotView,
    workspace_view: WorkspaceView,
    kb_view: KnowledgeBaseView,
    log: LogState,
    pwn_view: PwnView,
    agent_chat: AgentChatState,
    scan: ScanState,
    task_durations: TaskDurationStore,
    workbench_cache: std::cell::RefCell<WorkbenchCache>,
    activity: Option<ActivitySession>,
    live_activity: Option<LiveActivity>,
    recon_snapshot: Option<ReconSnapshot>,
    carlini_snapshot: Option<CarliniThreatHuntReport>,
    agentic_sast_snapshot: Option<AgenticSastReport>,
    scan_progress: Option<ScanProgress>,
    chain_aliases: Vec<ExploitChain>,
    exploit_chains: Vec<ExploitChainDetail>,
    taint_flow: Option<TaintFlowSnapshot>,
    program_scope: Option<ProgramScope>,
    findings: Vec<Finding>,
    findings_total: usize,
    findings_read_watermark: Option<u64>,
    review_decisions: Vec<ReviewDecisionRecord>,
    workspace_stale: Option<WorkspaceStaleSummary>,
}

impl DomainCache {
    pub(crate) fn new(
        context_view: ContextSnapshotView,
        workspace_view: WorkspaceView,
        kb_view: KnowledgeBaseView,
        task_durations: TaskDurationStore,
    ) -> Self {
        Self {
            context_view,
            workspace_view,
            kb_view,
            log: LogState::default(),
            pwn_view: PwnView::default(),
            agent_chat: AgentChatState::default(),
            scan: ScanState::default(),
            task_durations,
            workbench_cache: std::cell::RefCell::new(WorkbenchCache::default()),
            activity: None,
            live_activity: None,
            recon_snapshot: None,
            carlini_snapshot: None,
            agentic_sast_snapshot: None,
            scan_progress: None,
            chain_aliases: Vec::new(),
            exploit_chains: Vec::new(),
            taint_flow: None,
            program_scope: None,
            findings: Vec::new(),
            findings_total: 0,
            findings_read_watermark: None,
            review_decisions: Vec::new(),
            workspace_stale: None,
        }
    }

    pub(crate) fn context_view(&self) -> &ContextSnapshotView {
        &self.context_view
    }

    #[cfg(test)]
    pub(crate) fn context_view_mut(&mut self) -> &mut ContextSnapshotView {
        &mut self.context_view
    }

    pub(crate) fn set_context_view(&mut self, context_view: ContextSnapshotView) {
        self.context_view = context_view;
    }

    pub(crate) fn workspace_view(&self) -> &WorkspaceView {
        &self.workspace_view
    }

    pub(crate) fn set_workspace_view(&mut self, workspace_view: WorkspaceView) {
        self.workspace_view = workspace_view;
    }

    pub(crate) fn kb_view(&self) -> &KnowledgeBaseView {
        &self.kb_view
    }

    #[cfg(test)]
    pub(crate) fn kb_view_mut(&mut self) -> &mut KnowledgeBaseView {
        &mut self.kb_view
    }

    pub(crate) fn set_kb_view(&mut self, kb_view: KnowledgeBaseView) {
        self.kb_view = kb_view;
    }

    pub(crate) fn push_log(&mut self, prefix: impl Into<String>, body: impl Into<String>) {
        self.log.push(prefix, body);
    }

    pub(crate) fn log_lines(&self) -> &[LogLine] {
        self.log.lines()
    }

    pub(crate) fn log_len(&self) -> usize {
        self.log.len()
    }

    pub(crate) fn clear_log(&mut self) {
        self.log.clear();
    }

    #[doc(hidden)]
    pub(crate) fn replace_log_for_test(&mut self, lines: Vec<LogLine>) {
        self.log.replace_for_test(lines);
    }

    #[doc(hidden)]
    pub(crate) fn log_lines_mut_for_test(&mut self) -> &mut [LogLine] {
        self.log.lines_mut_for_test()
    }

    pub(crate) fn pwn_view(&self) -> &PwnView {
        &self.pwn_view
    }

    pub(crate) fn pwn_view_mut(&mut self) -> &mut PwnView {
        &mut self.pwn_view
    }

    pub(crate) fn agent_chat(&self) -> Option<&AgentChatView> {
        self.agent_chat.current()
    }

    pub(crate) fn agent_chat_mut(&mut self) -> Option<&mut AgentChatView> {
        self.agent_chat.current_mut()
    }

    pub(crate) fn set_agent_chat(&mut self, agent: Option<AgentChatView>) {
        self.agent_chat.set(agent);
    }

    pub(crate) fn clear_agent_chat(&mut self) {
        self.agent_chat.clear();
    }

    pub(crate) fn agent_chat_or_default_mut(&mut self) -> &mut AgentChatView {
        self.agent_chat.get_or_insert_default()
    }

    pub(crate) fn scan(&self) -> Option<&ScanPanelState> {
        self.scan.current()
    }

    pub(crate) fn scan_mut(&mut self) -> Option<&mut ScanPanelState> {
        self.scan.current_mut()
    }

    pub(crate) fn set_scan(&mut self, scan: Option<ScanPanelState>) {
        self.scan.set(scan);
    }

    pub(crate) fn estimate_task_duration_secs(&self, task_id: &str) -> Option<u64> {
        self.task_durations.estimate_secs(task_id)
    }

    pub(crate) fn record_task_duration_secs(&mut self, task_id: &str, secs: u64) {
        self.task_durations.record_secs(task_id, secs);
    }

    pub(crate) fn workbench_cache(&self) -> &std::cell::RefCell<WorkbenchCache> {
        &self.workbench_cache
    }

    pub(crate) fn activity(&self) -> Option<&ActivitySession> {
        self.activity.as_ref()
    }

    pub(crate) fn activity_mut(&mut self) -> Option<&mut ActivitySession> {
        self.activity.as_mut()
    }

    pub(crate) fn activity_or_insert_with<F>(&mut self, create: F) -> &mut ActivitySession
    where
        F: FnOnce() -> ActivitySession,
    {
        self.activity.get_or_insert_with(create)
    }

    pub(crate) fn set_activity(&mut self, activity: Option<ActivitySession>) {
        self.activity = activity;
    }

    pub(crate) fn live_activity(&self) -> Option<&LiveActivity> {
        self.live_activity.as_ref()
    }

    pub(crate) fn set_live_activity(&mut self, activity: Option<LiveActivity>) {
        self.live_activity = activity;
    }

    pub(crate) fn recon_snapshot(&self) -> Option<&ReconSnapshot> {
        self.recon_snapshot.as_ref()
    }

    pub(crate) fn set_recon_snapshot(&mut self, snapshot: ReconSnapshot) {
        self.recon_snapshot = Some(snapshot);
    }

    pub(crate) fn carlini_snapshot(&self) -> Option<&CarliniThreatHuntReport> {
        self.carlini_snapshot.as_ref()
    }

    pub(crate) fn set_carlini_snapshot(&mut self, snapshot: CarliniThreatHuntReport) {
        self.carlini_snapshot = Some(snapshot);
    }

    pub(crate) fn agentic_sast_snapshot(&self) -> Option<&AgenticSastReport> {
        self.agentic_sast_snapshot.as_ref()
    }

    pub(crate) fn set_agentic_sast_snapshot(&mut self, snapshot: AgenticSastReport) {
        self.agentic_sast_snapshot = Some(snapshot);
    }

    pub(crate) fn scan_progress(&self) -> Option<&ScanProgress> {
        self.scan_progress.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn set_scan_progress(&mut self, progress: ScanProgress) {
        self.scan_progress = Some(progress);
    }

    pub(crate) fn exploit_chains(&self) -> &[ExploitChainDetail] {
        &self.exploit_chains
    }

    pub(crate) fn chain_aliases(&self) -> &[ExploitChain] {
        &self.chain_aliases
    }

    pub(crate) fn set_chain_aliases(&mut self, aliases: Vec<ExploitChain>) {
        self.chain_aliases = aliases;
    }

    pub(crate) fn has_exploit_chains(&self) -> bool {
        !self.exploit_chains.is_empty()
    }

    pub(crate) fn set_exploit_chains(&mut self, chains: Vec<ExploitChainDetail>) {
        self.exploit_chains = chains;
    }

    pub(crate) fn taint_flow(&self) -> Option<&TaintFlowSnapshot> {
        self.taint_flow.as_ref()
    }

    pub(crate) fn set_taint_flow(&mut self, flow: Option<TaintFlowSnapshot>) {
        self.taint_flow = flow;
    }

    pub(crate) fn program_scope(&self) -> Option<&ProgramScope> {
        self.program_scope.as_ref()
    }

    pub(crate) fn set_program_scope(&mut self, scope: Option<ProgramScope>) {
        self.program_scope = scope;
    }

    pub(crate) fn workspace_stale(&self) -> Option<&WorkspaceStaleSummary> {
        self.workspace_stale.as_ref()
    }

    pub(crate) fn apply_workspace_changes(&mut self, changes: &[WorkspaceChange]) {
        let Some(summary) = WorkspaceStaleSummary::from_changes(changes) else {
            return;
        };
        match &mut self.workspace_stale {
            Some(current) => current.merge(summary),
            None => self.workspace_stale = Some(summary),
        }
    }

    pub(crate) fn clear_workspace_stale(&mut self) {
        self.workspace_stale = None;
    }

    pub(crate) fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub(crate) fn findings_total_count(&self) -> usize {
        self.findings_total.max(self.findings.len())
    }

    pub(crate) fn findings_are_partial(&self) -> bool {
        self.findings_total_count() > self.findings.len()
    }

    pub(crate) fn findings_read_watermark(&self) -> Option<u64> {
        self.findings_read_watermark
    }

    pub(crate) fn findings_mut(&mut self) -> &mut Vec<Finding> {
        &mut self.findings
    }

    pub(crate) fn set_findings(&mut self, findings: Vec<Finding>) {
        self.findings_total = findings.len();
        self.findings = findings;
    }

    pub(crate) fn set_findings_total_count(&mut self, total: usize) {
        self.findings_total = total.max(self.findings.len());
    }

    pub(crate) fn set_findings_read_watermark(&mut self, read_watermark: Option<u64>) {
        self.findings_read_watermark = read_watermark;
    }

    pub(crate) fn review_decisions(&self) -> &[ReviewDecisionRecord] {
        &self.review_decisions
    }

    pub(crate) fn set_review_decisions(&mut self, decisions: Vec<ReviewDecisionRecord>) {
        self.review_decisions = decisions;
    }
}
