use super::*;

#[derive(Debug)]
pub struct ShellApp {
    pub input: String,
    pub cursor: usize,
    pub history_index: Option<usize>,
    pub history_draft: String,
    pub last_cleared_input: Option<String>,
    pub completion_cycle: Option<CompletionCycle>,
    pub log: Vec<LogLine>,
    pub target: Option<PathBuf>,
    pub focused_module: Option<String>,
    pub shell_view: ShellView,
    pub prev_shell_view: Option<ShellView>,
    pub catalog_expanded: bool,
    /// Index of the catalog row the operator's cursor is on.  `j`/`k`
    /// move the cursor; `Enter` runs `use <module>` for that row.  Per
    /// `design/mockups/catalog.jsx` the cursor is the bright `▌` on a
    /// `c-sel` background, set in `catalog_module_row`.
    pub catalog_cursor: usize,
    /// Patch staged for human approval — populated when a tool
    /// produces a `pending_patch` artefact.  See `ShellView::Patch`.
    pub pending_patch: Option<PendingPatch>,
    /// Session-scoped allowlist of `<tool> <target>` strings approved
    /// via `Y` (allow + remember).  `confirm_gate_for_tool` checks this
    /// before raising a fresh gate so re-runs don't re-prompt.
    pub confirm_allowlist: std::collections::BTreeSet<String>,
    /// Session-scoped denylist of `<tool> <target>` strings rejected
    /// via `N` (deny + add to denylist).  Re-runs are auto-refused.
    pub confirm_denylist: std::collections::BTreeSet<String>,
    pub config: V2Config,
    pub registry: ModuleRegistry,
    pub option_store: ToolOptionStore,
    pub command_history: Vec<String>,
    pub session_cost_usd: f64,
    pub last_tool_cost_usd: Option<f64>,
    pub selected_model_index: usize,
    pub context_view: ContextSnapshotView,
    pub workspace_view: WorkspaceView,
    pub kb_view: KnowledgeBaseView,
    pub agent_chat: Option<AgentChatView>,
    pub session_thinking_level: Option<String>,
    pub findings: Vec<Finding>,
    pub selected_finding: Option<Finding>,
    pub scan: Option<ScanPanelState>,
    pub should_quit: bool,
    pub ctrl_c_armed_at: Option<Instant>,
    pub session_budget_usd: Option<f64>,
    pub advisory: AdvisoryState,
    pub live_activity: Option<LiveActivity>,
    pub trusted_workflow_auto_accept: bool,
    pub pending_chain: Option<PrereqChain>,
    pub pending_prereq_prompt: Option<PendingPrereqPrompt>,
    pub pending_plan: Option<PlanProposal>,
    pub plan_cursor: usize,
    pub plan_skipped: BTreeSet<usize>,
    pub tune_cursor: usize,
    pub prompts_cursor: usize,
    pub actor_detail_filter: ActorDetailFilter,
    pub planner_running: bool,
    pub plan_abort_requested: bool,
    pub pending_threat_patch: Option<ThreatPatch>,
    pub threat_worker_running: bool,
    pub threat_abort_requested: bool,
    pub chains: Vec<ExploitChain>,
    pub story_return_view: Option<ShellView>,
    pub findings_cursor: usize,
    pub help_scroll: usize,
    pub tools_scroll: usize,
    pub modules_scroll: usize,
    pub history_scroll: usize,
    pub kb_scroll: usize,
    pub last_char_at: Option<Instant>,
    pub scroll_offset: u16,
    pub spinner_phase: u8,
    pub last_spinner_advance: Option<Instant>,
    pub force_full_redraw: bool,
    pub recon_snapshot: Option<ReconSnapshot>,
    pub carlini_snapshot: Option<CarliniThreatHuntReport>,
    pub agentic_sast_snapshot: Option<AgenticSastReport>,
    pub scan_progress: Option<ScanProgress>,
    pub(crate) scan_rx: Option<Receiver<ScanEvent>>,
    pub(crate) scan_cancel: Option<ScanCancellation>,
    pub(crate) tool_rx: Option<Receiver<ToolEvent>>,
    pub(crate) tool_running: Option<String>,
    pub(crate) tool_run_id: Option<String>,
    pub(crate) tool_abort_requested: bool,
    pub(crate) agent_rx: Option<Receiver<AgentEvent>>,
    pub(crate) plan_rx: Option<Receiver<PlanEvent>>,
    pub(crate) threat_rx: Option<Receiver<ThreatPatchEvent>>,
    /// Live trace step stream from the active tool/scan run. Populated when a
    /// `BroadcastSink` is attached at run start; drained each tick into
    /// `app.activity` so the Activity view can render the latest events.
    pub(crate) trace_rx: Option<Receiver<RunTraceStep>>,
    /// In-memory snapshot of DAG status + recent reasoning events feeding the
    /// Activity view. `Some` while a run is active or recently finished;
    /// reset by `R` in the Activity view.
    pub activity: Option<ActivitySession>,
    /// When true (default), the Activity view auto-opens at scan/tool start.
    /// Operators can opt out via `setg ui.auto_open_activity false` (parsed
    /// in `ShellApp::new`).
    pub auto_open_activity: bool,
}
