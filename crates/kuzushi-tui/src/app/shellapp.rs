use super::*;

#[derive(Debug)]
pub struct ShellApp {
    pub input: String,
    pub cursor: usize,
    pub history_index: Option<usize>,
    pub history_draft: String,
    pub last_cleared_input: Option<String>,
    pub completion_cycle: Option<CompletionCycle>,
    pub input_mode: InputMode,
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
    /// Route-local catalog state: expanded/collapsed mode plus row cursors for
    /// module browsing and component recommendations.
    pub catalog_route: CatalogRouteState,
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
    pub review_decisions: Vec<kuzushi_core::findings::ReviewDecisionRecord>,
    pub active_findings_filter: Option<String>,
    pub selected_finding: Option<Finding>,
    /// Cursor into the projected findings/review list. Workbench review,
    /// aliases, and detail selectors all read this as the selected finding row.
    pub findings_route: FindingsRouteState,
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
    /// pane uses `findings_route` instead, so switching panes preserves the
    /// operator's reading position without confusing the list cursor.
    pub workbench_scroll: WorkbenchPaneScroll,
    /// v3 review surface state: one cursor, one mode, and one denormalized
    /// committed frame. The broader shell still owns global runtime/session
    /// concerns; this state owns only Workbench review interaction.
    pub workbench_review: WorkbenchReviewState,
    /// Depth-stack review navigation (opt-in via `ui.workbench_depth_stack`).
    /// Owns depth/pane/tab/leg/drawer/scroll only; finding *selection* stays on
    /// `findings_route`, so DETAILS/legs always reflect the selected finding.
    pub workbench_nav: WorkbenchNav,
    /// When true, `ShellView::Workbench` Review renders the depth stack instead
    /// of the four-pane ring. Default off; `setg ui.workbench_depth_stack true`.
    pub workbench_depth_stack: bool,
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
    /// Command-palette (Ctrl+G) fuzzy query and cursor. Persisted on the app
    /// so typing/arrowing survives re-renders.
    pub palette_query: String,
    pub palette_cursor: usize,
    /// Route-local state for first-run model selection.
    pub model_picker_route: ModelPickerRouteState,
    /// Route-local state for auth method selection and in-session key draft.
    pub auth_picker_route: AuthPickerRouteState,
    /// Per-task duration history for ETA forecasting in the ambient
    /// progress chip. Loaded from `<target>/.kuzushi/task-durations.json`.
    pub(crate) task_durations: crate::app::TaskDurationStore,
    /// Route-local state for launch-time target selection.
    pub target_picker_route: TargetPickerRouteState,
    /// Fuzzy file attach picker route state. Paths are repo-relative and rooted
    /// at the active target so accepting a row can reuse `attach <path>`.
    pub file_picker_route: FilePickerRouteState,
    /// Route-local planning picker state: rows, cursor, checked tasks,
    /// rebuild flags, pane focus, and option editor/error state.
    pub planning_picker_route: PlanningPickerRouteState,
    /// Engagement-scoped planning runtime state: current phase, queued steps,
    /// failures/retries, target classification, and per-run option overlays.
    pub engagement: EngagementState,
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
    pub help_route: HelpRouteState,
    pub tools_route: ToolsRouteState,
    pub history_route: ScrollRouteState,
    pub kb_route: ScrollRouteState,
    pub modules_route: ScrollRouteState,
    pub logs_route: ScrollRouteState,
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
    pub(crate) next_worker_generation: u64,
    pub(crate) jobs: JobHub,
    pub(crate) worker_handles: WorkerHandleRegistry,
    pub(crate) loop_wake: Option<TerminalLoopWake>,
    pub(crate) scan_generation: Option<WorkerGeneration>,
    pub(crate) scan_rx: Option<Receiver<StampedEvent<ScanEvent>>>,
    pub(crate) scan_cancel: Option<ScanCancellation>,
    pub(crate) tool_generation: Option<WorkerGeneration>,
    pub(crate) tool_rx: Option<Receiver<StampedEvent<ToolEvent>>>,
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
    pub(crate) agent_generation: Option<WorkerGeneration>,
    pub(crate) agent_rx: Option<Receiver<StampedEvent<AgentEvent>>>,
    pub(crate) agent_cancel: Option<ScanCancellation>,
    pub(crate) plan_generation: Option<WorkerGeneration>,
    pub(crate) plan_rx: Option<Receiver<StampedEvent<PlanEvent>>>,
    pub(crate) plan_cancel: Option<ScanCancellation>,
    pub(crate) threat_generation: Option<WorkerGeneration>,
    pub(crate) threat_rx: Option<Receiver<StampedEvent<ThreatPatchEvent>>>,
    pub(crate) threat_cancel: Option<ScanCancellation>,
    pub(crate) trace_generation: Option<WorkerGeneration>,
    /// Live trace step stream from the active tool/scan run. Populated when a
    /// stamped live trace sink is attached at run start; drained each tick into
    /// `app.activity` so the Activity view can render the latest events.
    pub(crate) trace_rx: Option<Receiver<StampedEvent<RunTraceStep>>>,
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

impl ShellApp {
    pub(crate) fn next_worker_generation(&mut self) -> WorkerGeneration {
        WorkerGeneration::next(&mut self.next_worker_generation)
    }
}
