use super::{
    ActivitySession, AgentChatState, AgentChatView, ContextSnapshotView, ExploitChain,
    ExploitChainDetail, KnowledgeBaseView, LiveActivity, LogLine, LogState, PwnView, ReconSnapshot,
    ScanPanelState, ScanState, TaintFlowSnapshot, TaskDurationStore, TraceExpansionSnapshot,
    WorkbenchCache, WorkspaceView,
};
use kuzushi_core::{
    findings::{IdentityFoldPolicy, ReviewDecisionRecord},
    incremental_index::{coalesce_changes, plan_for_change, ReindexPlan, WorkspaceChange},
    workspace::ToolShelf,
    AgenticSastReport, CarliniThreatHuntReport, Finding, PatchLifecycleRecord, PatchLifecycleState,
    ProgramScope, ScanProgress, WorkspaceTarget,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceStaleSummary {
    strongest_plan: ReindexPlan,
    pending_changes: Vec<WorkspaceChange>,
}

/// A captured `worklist:rank` output bound to the engagement it was computed
/// for. The binding prevents two leaks: (1) rendering target A's rows after
/// switching to target B, and (2) a stale capture masking a fresh `context:build`
/// fold on the same target.
#[derive(Debug)]
struct WorklistSnapshot {
    /// The target root the capture was computed under.
    target: std::path::PathBuf,
    /// The attack-surface artifact hydration version at capture time. When the
    /// map is later rebuilt the live version diverges and the snapshot is
    /// treated as stale, so the fresh Read-safe fold wins.
    artifact_version: Option<u64>,
    /// The serialized `Worklist` `data` the tool emitted.
    data: serde_json::Value,
    /// A monotonic stamp bumped on every capture, so a render-path memo can key
    /// off snapshot identity in O(1) — without hashing or re-parsing the (large)
    /// worklist `data` per frame. A re-run at the same target/artifact version
    /// still yields a fresh stamp, invalidating the memo.
    generation: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FindingLedgerCounts {
    pub(crate) total: usize,
    pub(crate) reviewed: usize,
    pub(crate) confirmed: usize,
    pub(crate) proven: usize,
    /// Human proof deferrals bound to the current finding generations.
    pub(crate) proof_deferred: usize,
    pub(crate) proof_backed: usize,
    pub(crate) remediated: usize,
    pub(crate) remediation_projection_complete: bool,
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

    #[cfg(test)]
    pub(crate) fn change_count(&self) -> usize {
        self.pending_changes.len()
    }

    #[cfg(test)]
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
    taint_flows: Vec<TaintFlowSnapshot>,
    /// The last `worklist:rank` tool output (its serialized `Worklist` `data`),
    /// captured so the deck renders the tool's actual worklist — including the
    /// `deep`/systems `S` rows the Read-safe shell fold omits — instead of a
    /// fold that contradicts the run receipt. Held as raw JSON because the
    /// core `Worklist` is serialize-only (a `&'static str` field blocks
    /// `Deserialize`); the view model projects it. Keyed to the target root and
    /// attack-surface artifact version it was computed for, so it never renders
    /// under a different target and a fresh `context:build` supersedes it.
    worklist_snapshot: Option<WorklistSnapshot>,
    /// Monotonic counter for `worklist_snapshot` captures, so the render-path
    /// memo invalidates on every re-run without hashing the snapshot body.
    worklist_snapshot_generation: u64,
    trace_expansion: Option<TraceExpansionSnapshot>,
    program_scope: Option<ProgramScope>,
    findings: Vec<Finding>,
    finding_aliases: Vec<String>,
    identity_fold_policy: IdentityFoldPolicy,
    findings_revision: u64,
    findings_total: usize,
    findings_read_watermark: Option<u64>,
    findings_page: Option<kuzushi_core::findings::FindingPageMetadata>,
    findings_batch_id: Option<String>,
    review_decisions: Vec<ReviewDecisionRecord>,
    review_decisions_revision: u64,
    finding_ledger_counts: Option<FindingLedgerCounts>,
    review_source_applicabilities:
        BTreeMap<String, kuzushi_core::workspace::WorkspaceReviewSourceApplicability>,
    patch_lifecycles_by_reverify_run: BTreeMap<String, PatchLifecycleRecord>,
    workspace_stale: Option<WorkspaceStaleSummary>,
    returning_source_unverified: bool,
    /// Cached "YOUR TOOLS" shelf (favorites + recents). Loaded from disk on
    /// target wiring and favorite toggles — never read per frame.
    tool_shelf: ToolShelf,
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
            taint_flows: Vec::new(),
            worklist_snapshot: None,
            worklist_snapshot_generation: 0,
            trace_expansion: None,
            program_scope: None,
            findings: Vec::new(),
            finding_aliases: Vec::new(),
            identity_fold_policy: IdentityFoldPolicy::Legacy,
            findings_revision: 0,
            findings_total: 0,
            findings_read_watermark: None,
            findings_page: None,
            findings_batch_id: None,
            review_decisions: Vec::new(),
            review_decisions_revision: 0,
            finding_ledger_counts: None,
            review_source_applicabilities: BTreeMap::new(),
            patch_lifecycles_by_reverify_run: BTreeMap::new(),
            workspace_stale: None,
            returning_source_unverified: false,
            tool_shelf: ToolShelf::default(),
        }
    }

    /// Drop every projection whose meaning is rooted in the active target.
    /// The transcript and session-wide preferences survive; repository data
    /// never does. Call this before hydrating a newly activated workspace so a
    /// missing or unreadable artifact honestly renders empty rather than
    /// leaking the previous target's state.
    pub(crate) fn reset_for_target(&mut self, workspace: &WorkspaceTarget) {
        let root = workspace.root();
        self.context_view = empty_context_view(root);
        self.workspace_view = empty_workspace_view(workspace);
        self.kb_view = empty_knowledge_base_view();
        self.reset_target_runtime(root);
        self.clear_target_artifacts();
        self.clear_target_findings();
        self.workspace_stale = None;
        self.returning_source_unverified = false;
        self.tool_shelf = ToolShelf::default();
    }

    fn reset_target_runtime(&mut self, root: &std::path::Path) {
        self.pwn_view = PwnView::default();
        self.agent_chat = AgentChatState::default();
        self.scan = ScanState::default();
        self.task_durations = TaskDurationStore::load(Some(root));
        self.workbench_cache = std::cell::RefCell::new(WorkbenchCache::default());
        self.activity = None;
        self.live_activity = None;
        self.recon_snapshot = None;
        self.carlini_snapshot = None;
        self.agentic_sast_snapshot = None;
        self.scan_progress = None;
    }

    fn clear_target_artifacts(&mut self) {
        self.chain_aliases.clear();
        self.exploit_chains.clear();
        self.taint_flows.clear();
        self.worklist_snapshot = None;
        self.trace_expansion = None;
        self.program_scope = None;
    }

    fn clear_target_findings(&mut self) {
        self.findings.clear();
        self.finding_aliases.clear();
        self.identity_fold_policy = IdentityFoldPolicy::Legacy;
        self.bump_findings_revision();
        self.findings_total = 0;
        self.findings_read_watermark = None;
        self.findings_page = None;
        self.review_decisions.clear();
        self.bump_review_decisions_revision();
        self.finding_ledger_counts = None;
        self.review_source_applicabilities.clear();
        self.patch_lifecycles_by_reverify_run.clear();
    }

    pub(crate) fn tool_shelf(&self) -> &ToolShelf {
        &self.tool_shelf
    }

    pub(crate) fn set_tool_shelf(&mut self, shelf: ToolShelf) {
        self.tool_shelf = shelf;
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

    pub(crate) fn log_evicted(&self) -> usize {
        self.log.evicted()
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

    pub(super) fn agent_chat_state_mut(&mut self) -> &mut AgentChatState {
        &mut self.agent_chat
    }

    pub(crate) fn agent_chat_history(&self) -> &[AgentChatView] {
        self.agent_chat.history()
    }

    pub(crate) fn agent_chat_generation(&self) -> u64 {
        self.agent_chat.generation()
    }

    pub(crate) fn agent_chat_mut(&mut self) -> Option<&mut AgentChatView> {
        self.agent_chat.current_mut()
    }

    pub(crate) fn set_agent_chat(&mut self, agent: Option<AgentChatView>) {
        self.agent_chat.set(agent);
    }

    pub(crate) fn agent_artifact_target(&self) -> Option<&std::path::Path> {
        self.agent_chat.artifact_target()
    }

    pub(crate) fn set_agent_artifact_target(&mut self, target: Option<std::path::PathBuf>) {
        self.agent_chat.set_artifact_target(target);
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

    pub(crate) fn record_task_duration_secs(
        &mut self,
        task_id: &str,
        secs: u64,
    ) -> anyhow::Result<()> {
        self.task_durations.record_secs(task_id, secs)
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
        self.taint_flows.first()
    }

    pub(crate) fn set_taint_flows(&mut self, flows: Vec<TaintFlowSnapshot>) {
        self.taint_flows = flows;
    }

    /// The captured `worklist:rank` output for the *active engagement*: the raw
    /// JSON only when the capture's target root and attack-surface artifact
    /// version both match the caller's. A mismatch (different target, or a
    /// `context:build` that rebuilt the map) yields `None`, so the deck falls
    /// back to the Read-safe fold instead of rendering a foreign or stale
    /// worklist.
    pub(crate) fn has_worklist_snapshot_for(&self, target: &std::path::Path) -> bool {
        self.worklist_snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.target == target)
    }

    pub(crate) fn worklist_snapshot_for(
        &self,
        target: &std::path::Path,
        artifact_version: Option<u64>,
    ) -> Option<&serde_json::Value> {
        self.worklist_snapshot
            .as_ref()
            .filter(|snapshot| {
                snapshot.target == target && snapshot.artifact_version == artifact_version
            })
            .map(|snapshot| &snapshot.data)
    }

    /// The O(1) identity of the captured `worklist:rank` snapshot for the given
    /// engagement, or `None` when no snapshot matches. The render-path memo keys
    /// off this so the (large) snapshot body is projected only on a cache miss —
    /// never re-cloned and re-parsed per frame (C-4).
    pub(crate) fn worklist_snapshot_generation_for(
        &self,
        target: &std::path::Path,
        artifact_version: Option<u64>,
    ) -> Option<u64> {
        self.worklist_snapshot
            .as_ref()
            .filter(|snapshot| {
                snapshot.target == target && snapshot.artifact_version == artifact_version
            })
            .map(|snapshot| snapshot.generation)
    }

    /// Capture a `worklist:rank` output bound to the engagement it was computed
    /// for. Passing `None` for `data` clears any prior capture. Every capture
    /// bumps the monotonic generation so the render-path memo invalidates.
    pub(crate) fn set_worklist_snapshot(
        &mut self,
        target: std::path::PathBuf,
        artifact_version: Option<u64>,
        data: Option<serde_json::Value>,
    ) {
        self.worklist_snapshot_generation += 1;
        let generation = self.worklist_snapshot_generation;
        self.worklist_snapshot = data.map(|data| WorklistSnapshot {
            target,
            artifact_version,
            data,
            generation,
        });
    }

    /// Test-only: replace the captured snapshot's JSON body WITHOUT bumping its
    /// generation or changing its target/artifact-version identity. This lets a
    /// memoization test poison the source data behind a stable memo key so a
    /// pure cache hit returns the original projection, while a per-frame
    /// re-parse would surface the poisoned rows and fail the assertion. No-op
    /// when no snapshot is captured.
    #[cfg(test)]
    pub(crate) fn poison_worklist_snapshot_data_in_place(&mut self, data: serde_json::Value) {
        if let Some(snapshot) = self.worklist_snapshot.as_mut() {
            snapshot.data = data;
        }
    }

    /// The operator-requested trace expansion, keyed by finding fingerprint;
    /// another finding's snapshot never renders under the selected one.
    pub(crate) fn trace_expansion_for_finding(
        &self,
        fingerprint: &str,
    ) -> Option<&TraceExpansionSnapshot> {
        self.trace_expansion
            .as_ref()
            .filter(|snapshot| snapshot.finding_fingerprint == fingerprint)
    }

    /// Replace the complete outcome, including newly resolved empty note lists.
    pub(crate) fn set_trace_expansion(&mut self, snapshot: Option<TraceExpansionSnapshot>) {
        self.trace_expansion = snapshot;
    }

    pub(crate) fn taint_flow_for_finding(&self, finding: &Finding) -> Option<&TaintFlowSnapshot> {
        self.taint_flows.iter().find(|flow| {
            flow.finding_identity_id
                .as_deref()
                .zip(finding.identity_id.as_deref())
                .is_some_and(|(flow_id, finding_id)| flow_id == finding_id)
                || flow.finding_fingerprint.as_deref() == Some(finding.fingerprint.as_str())
        })
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

    pub(crate) fn returning_source_unverified(&self) -> bool {
        self.returning_source_unverified
    }

    pub(crate) fn set_returning_source_unverified(&mut self, unverified: bool) {
        self.returning_source_unverified = unverified;
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

    pub(crate) fn findings_page(&self) -> Option<&kuzushi_core::findings::FindingPageMetadata> {
        self.findings_page.as_ref()
    }

    pub(crate) fn set_findings_page(&mut self, page: kuzushi_core::findings::FindingPageMetadata) {
        self.findings_page = Some(page);
    }

    pub(crate) fn findings_batch_id(&self) -> Option<&str> {
        self.findings_batch_id.as_deref()
    }

    pub(crate) fn set_findings_batch_id(&mut self, id: Option<String>) {
        self.findings_batch_id = id;
    }

    pub(crate) fn findings_are_partial(&self) -> bool {
        self.findings_total_count() > self.findings.len()
    }

    pub(crate) fn findings_read_watermark(&self) -> Option<u64> {
        self.findings_read_watermark
    }

    pub(crate) fn findings_mut(&mut self) -> &mut Vec<Finding> {
        self.findings_page = None;
        self.bump_findings_revision();
        &mut self.findings
    }

    pub(crate) fn set_findings(&mut self, findings: Vec<Finding>) {
        self.findings_page = None;
        self.findings_total = findings.len();
        self.findings = findings;
        self.finding_aliases.clear();
        self.bump_findings_revision();
    }

    pub(crate) fn set_findings_projection(
        &mut self,
        findings: Vec<Finding>,
        aliases: Vec<String>,
        policy: IdentityFoldPolicy,
    ) {
        self.findings_batch_id = None;
        self.set_findings(findings);
        if aliases.len() == self.findings.len() {
            self.finding_aliases = aliases;
        }
        self.identity_fold_policy = policy;
    }

    pub(crate) fn finding_aliases(&self) -> &[String] {
        &self.finding_aliases
    }

    pub(crate) fn identity_fold_policy(&self) -> IdentityFoldPolicy {
        self.identity_fold_policy
    }

    pub(crate) fn findings_revision(&self) -> u64 {
        self.findings_revision
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
        self.bump_review_decisions_revision();
    }

    pub(crate) fn review_decisions_revision(&self) -> u64 {
        self.review_decisions_revision
    }

    pub(crate) fn finding_ledger_counts(&self) -> Option<FindingLedgerCounts> {
        self.finding_ledger_counts
    }

    pub(crate) fn set_finding_ledger_counts(&mut self, counts: FindingLedgerCounts) {
        self.finding_ledger_counts = Some(counts);
    }

    pub(crate) fn set_review_source_applicabilities(
        &mut self,
        values: BTreeMap<String, kuzushi_core::workspace::WorkspaceReviewSourceApplicability>,
    ) {
        self.review_source_applicabilities = values;
    }

    pub(crate) fn review_source_needs_reassessment(&self, finding: &Finding) -> bool {
        self.review_source_applicabilities
            .get(kuzushi_core::findings::finding_observation_identity(
                finding,
            ))
            .is_some_and(|value| value.needs_reassessment())
    }

    pub(crate) fn review_source_reassessment_count(&self) -> usize {
        self.review_source_applicabilities
            .values()
            .filter(|value| value.needs_reassessment())
            .count()
    }

    pub(crate) fn set_patch_lifecycle_records(&mut self, records: &[PatchLifecycleRecord]) {
        self.patch_lifecycles_by_reverify_run.clear();
        for record in records {
            let Some(run_id) = record.reverify_run_id.as_ref() else {
                continue;
            };
            self.patch_lifecycles_by_reverify_run
                .entry(run_id.clone())
                .or_insert_with(|| record.clone());
        }
    }

    pub(crate) fn matching_verified_reverify_run<'a>(
        &self,
        run_refs: &'a [String],
    ) -> Option<&'a str> {
        // `patch:reverify` writes its execution-context run id into the
        // application lifecycle. Phase attempt run refs have already crossed
        // descriptor/phase validation, so this exact intersection binds the
        // result to its durable application without consulting UI selection.
        run_refs.iter().find_map(|run_id| {
            self.patch_lifecycles_by_reverify_run
                .get(run_id)
                .is_some_and(PatchLifecycleRecord::is_empirically_verified)
                .then_some(run_id.as_str())
        })
    }

    fn bump_findings_revision(&mut self) {
        self.findings_revision = self.findings_revision.wrapping_add(1);
    }

    fn bump_review_decisions_revision(&mut self) {
        self.review_decisions_revision = self.review_decisions_revision.wrapping_add(1);
    }
}

fn empty_context_view(root: &std::path::Path) -> ContextSnapshotView {
    ContextSnapshotView {
        snapshot_path: Some(kuzushi_core::context_snapshot_path(root)),
        exists: false,
        freshness: None,
        status: "missing. Next: context build".to_string(),
        target: None,
        discovery: None,
        files_indexed: None,
        total_files: None,
        languages: Vec::new(),
        frameworks: Vec::new(),
        generated_slices: Vec::new(),
        stale_slices: Vec::new(),
        enrichment_claims: 0,
        enrichment_model: None,
        inspection: None,
    }
}

fn empty_workspace_view(workspace: &WorkspaceTarget) -> WorkspaceView {
    WorkspaceView {
        root: Some(workspace.root().to_path_buf()),
        state_dir: Some(workspace.state_dir()),
        findings_db: Some(workspace.findings_db_path()),
        findings_count: None,
        last_export: None,
        status: "workspace ready. Next: workspace status".to_string(),
    }
}

fn empty_knowledge_base_view() -> KnowledgeBaseView {
    KnowledgeBaseView {
        module_id: "context".to_string(),
        store_path: None,
        attachments: Vec::new(),
        artifacts: Vec::new(),
    }
}
