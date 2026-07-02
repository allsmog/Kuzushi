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
    /// Active nested project scope inside `target`, when the operator enters
    /// a submodule/vendored/dependency root from the picker.
    pub active_scope: Option<crate::app::TargetCandidateScope>,
    pub focused_module: Option<String>,
    pub shell_view: ShellView,
    pub prev_shell_view: Option<ShellView>,
    /// Bounded navigation history. Each view transition that isn't itself
    /// a back-navigation pushes the previous view here. `go_back` pops the
    /// most recent entry. Cap depth at NAV_HISTORY_DEPTH to keep memory
    /// bounded; older entries are discarded.
    pub nav_history: Vec<ShellView>,
    pub catalog_expanded: bool,
    /// Index of the catalog row the operator's cursor is on.  `j`/`k`
    /// move the cursor; `Enter` runs `use <module>` for that row.  Per
    /// `design/mockups/catalog.jsx` the cursor is the bright `▌` on a
    /// `c-sel` background, set in `catalog_module_row`.
    pub catalog_cursor: usize,
    /// Cursor into the component recommendation list. `Enter` runs the
    /// focused scoped scan; `p` promotes independent components to targets.
    pub recommend_cursor: usize,
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
    /// Active Ctrl+R reverse-history search, when the operator is searching.
    pub history_search: Option<HistorySearch>,
    pub session_cost_usd: f64,
    pub last_tool_cost_usd: Option<f64>,
    pub selected_model_index: usize,
    pub context_view: ContextSnapshotView,
    pub workspace_view: WorkspaceView,
    pub kb_view: KnowledgeBaseView,
    pub pwn_view: PwnView,
    pub auth_login: Option<AuthLoginView>,
    pub agent_chat: Option<AgentChatView>,
    pub session_thinking_level: Option<String>,
    pub findings: Vec<Finding>,
    pub selected_finding: Option<Finding>,
    /// Which Workbench pane (`Source`/`Center`/`Findings`/`Details`) currently has keyboard
    /// focus. `Tab` cycles it; `j`/`k` move within it. Defaults to `Findings`.
    pub workbench_focus: WorkbenchPane,
    /// Explicit cockpit page selected by the operator. `None` follows the
    /// workspace-derived journey phase so a fresh target opens on TERRAIN while
    /// a finding-bearing target opens on REVIEW.
    pub workbench_page: Option<WorkbenchPage>,
    /// Explicit content mode for the Workbench center pane. Focus changes should
    /// not replace the operator's selected center-deck page.
    pub workbench_center_mode: WorkbenchCenterMode,
    /// Pane-local scroll positions for non-list Workbench panes. The findings
    /// pane uses `findings_cursor` instead, so switching panes preserves the
    /// operator's reading position without confusing the list cursor.
    pub workbench_scroll: WorkbenchPaneScroll,
    pub(crate) workbench_cache: std::cell::RefCell<WorkbenchCache>,
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
    /// Command-palette (Ctrl+G) fuzzy query and cursor. Persisted on the app
    /// so typing/arrowing survives re-renders.
    pub palette_query: String,
    pub palette_cursor: usize,
    /// First-run model-picker cursor. Persisted on the app so `↑`/`↓`
    /// keep their position across re-renders.
    pub model_picker_cursor: usize,
    /// Auth-method picker cursor (0 = API key row, 1 = OAuth row).
    pub auth_picker_cursor: usize,
    /// Masked in-session API-key draft used only by the auth picker. It is
    /// never submitted as a command, logged, or persisted.
    pub auth_key_draft: String,
    /// Per-task duration history for ETA forecasting in the ambient
    /// progress chip. Loaded from `<target>/.kuzushi/task-durations.json`.
    pub(crate) task_durations: crate::app::TaskDurationStore,
    /// Launch-time target picker cursor (index into `target_candidates`).
    pub target_picker_cursor: usize,
    /// Candidates shown by the target picker; populated by
    /// `open_target_picker` from cwd + child repos/previous targets.
    pub target_candidates: Vec<crate::app::TargetCandidate>,
    /// Fuzzy file attach picker state. Paths are repo-relative and rooted at
    /// the active target so accepting a row can reuse `attach <path>`.
    pub file_picker_files: Vec<String>,
    pub file_picker_query: String,
    pub file_picker_cursor: usize,
    pub file_picker_truncated: bool,
    pub file_picker_return_view: Option<ShellView>,
    /// Planning-picker cursor (index into `planning_tasks`).
    pub planning_cursor: usize,
    /// Set of planning-task ids currently checked. Mirrors the
    /// `[x]` / `[ ]` state shown in the picker card.
    pub planning_selected: BTreeSet<PlanningTaskId>,
    /// Per-row state for the planning picker. Built when the picker
    /// opens and refreshed when artifacts change.
    pub planning_tasks: Vec<PlanningTaskRow>,
    /// Pending planning-run queue (topo-sorted). Drains one task at a
    /// time after Enter is pressed in the planning picker.
    pub planning_run_queue: std::collections::VecDeque<PlanningTaskId>,
    /// Name of the tool currently executing on behalf of the planning
    /// queue, used by `advance_planning_queue_after_tool` to know when
    /// to pop the next entry.
    pub planning_running_tool: Option<String>,
    /// The engagement phase the walker is currently in (組→崩→作→掛). `None`
    /// outside the phase-driven launch flow.
    pub workflow_phase: Option<crate::app::WorkflowPhase>,
    /// Detected target kind (source / apk / native binary), classified once at
    /// launch and reused to drive per-phase preselection.
    pub target_kind: Option<kuzushi_core::TargetKind>,
    /// Cached artifact tasks the operator explicitly marked for rebuild (`g`),
    /// overriding the reuse-by-default behavior for this run.
    pub planning_rebuild: BTreeSet<PlanningTaskId>,
    /// Which picker surface owns plain keys: the list, the selected step's
    /// options pane, or the shell command prompt.
    pub picker_focus: crate::app::PickerFocus,
    /// Cursor into the focused step's ToolDescriptor.options list.
    pub planning_option_cursor: usize,
    /// Run-scoped per-step input overlays from the planning picker. These are
    /// merged with stored options for this engagement only unless promoted.
    pub planning_option_overrides: crate::app::PlanningOptionOverrides,
    /// Inline editor draft for the selected planning option.
    pub planning_option_edit: Option<crate::app::PlanningOptionEdit>,
    /// Last validation/editing error shown in the planning options pane.
    pub planning_option_error: Option<String>,
    /// Tasks that failed in the current engagement, with their error text.
    /// Drives dependency-aware skipping and the end-of-run retry gate.
    pub planning_failed: Vec<crate::app::FailedPlanningTask>,
    pub planning_skipped_phases: BTreeSet<crate::app::WorkflowPhase>,
    /// Per-task input overrides applied on retry (e.g. a larger heap), consumed
    /// by the planning dispatcher and cleared once the retried task runs.
    pub planning_adjustments: BTreeMap<PlanningTaskId, crate::app::RetryAdjustment>,
    /// Tasks an explicit module-recommender run suggested for this engagement
    /// (mapped from the recommender's tool list). Merged into each phase's
    /// preselection.
    pub model_recommended_tasks: Option<BTreeSet<PlanningTaskId>>,
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
    pub help_filter: Option<String>,
    pub tools_scroll: usize,
    pub tools_filter: Option<String>,
    pub modules_scroll: usize,
    pub history_scroll: usize,
    pub kb_scroll: usize,
    /// Scroll offset in the `ShellView::Logs` (full-screen transcript) view.
    /// M1 §1.1 — operators page through the complete log buffer here instead
    /// of relying on the truncated embedded transcript strip.
    pub logs_scroll: usize,
    /// Last handled keyboard interaction. Viz auto-open uses this as a grace
    /// window so a finishing tool does not yank a recently navigated view.
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
    pub(crate) tool_cancel: Option<ScanCancellation>,
    /// Name of a background tool the shell dispatched for itself (the
    /// session-model recommender) rather than from an operator action. The
    /// Activity header and ambient chip label it "(background)" so it is never
    /// mistaken for the plan/tool the operator just confirmed. Cleared with
    /// `tool_running` when the tool's terminal event arrives.
    pub(crate) ambient_tool: Option<String>,
    pub(crate) tool_run_id: Option<String>,
    pub(crate) active_model_override: Option<String>,
    pub(crate) tool_abort_requested: bool,
    pub(crate) agent_rx: Option<Receiver<AgentEvent>>,
    pub(crate) agent_cancel: Option<ScanCancellation>,
    pub(crate) plan_rx: Option<Receiver<PlanEvent>>,
    pub(crate) plan_cancel: Option<ScanCancellation>,
    pub(crate) threat_rx: Option<Receiver<ThreatPatchEvent>>,
    pub(crate) threat_cancel: Option<ScanCancellation>,
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
    /// Which page of the security-viz gallery (`ShellView::Scene`) is showing.
    /// Cycled with `Tab` while the view is open.
    pub scene_page: crate::scene3d::VizPage,
    /// Yaw (radians) of the 3D attack-surface camera, advanced each tick while
    /// it auto-rotates; also nudged by `h`/`l`.
    pub scene_spin: f32,
    /// Pitch (radians) of the 3D attack-surface camera, nudged by `j`/`k`.
    pub scene_pitch: f32,
    /// When true the 3D attack-surface holds still (toggled with `space`/`p`).
    pub scene_paused: bool,
    /// Last spin advance, so rotation speed is wall-clock paced rather than
    /// tied to the redraw rate.
    pub last_scene_advance: Option<Instant>,
    /// When true (default), the relevant gallery page auto-opens when its
    /// artifact is generated (scan→Heatmap, threat-model→DFD, etc.). Opt out
    /// with `setg ui.auto_open_viz false`. Mirrors `auto_open_activity`.
    pub auto_open_viz: bool,
    /// Detailed exploit chains (with ordered steps) for the attack-tree page,
    /// cached from `exploit-chain:scan`. Parallel to the minimal `chains`.
    pub exploit_chains: Vec<ExploitChainDetail>,
    /// Latest source→sink taint flow for the attack-path page, cached from
    /// `taint-iris:hunt` structured output.
    pub taint_flow: Option<TaintFlowSnapshot>,
    /// Bug-bounty program scope loaded from `<target>/.kuzushi/scope.toml`
    /// when the target is set (M2 §2.1). Cached on the app so the footer
    /// chip and any in-shell validators don't hit disk every frame.
    /// `None` means no scope file is present.
    pub program_scope: Option<kuzushi_core::ProgramScope>,
}
