use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SastTaskRow {
    pub id: &'static str,
    pub scan_task: &'static str,
    pub cost: &'static str,
    pub notes: &'static str,
    pub toggleable: bool,
    pub selected: bool,
    pub state: &'static str,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeBaseView {
    pub module_id: String,
    pub store_path: Option<PathBuf>,
    pub attachments: Vec<AttachmentRecord>,
    pub artifacts: Vec<KnownArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSnapshotView {
    pub snapshot_path: Option<PathBuf>,
    pub exists: bool,
    pub status: String,
    pub target: Option<String>,
    pub discovery: Option<String>,
    pub files_indexed: Option<u64>,
    pub total_files: Option<u64>,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub generated_slices: Vec<String>,
    pub stale_slices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceView {
    pub root: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub findings_db: Option<PathBuf>,
    pub findings_count: Option<usize>,
    pub last_export: Option<PathBuf>,
    pub status: String,
}

#[derive(Debug, Clone, Default)]
pub struct ReconSnapshot {
    pub hosts: Vec<ReconHost>,
    pub services: Vec<ReconService>,
    pub notes: Vec<ReconNote>,
    pub last_tool: Option<String>,
    pub last_target: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PwnView {
    pub target: Option<PathBuf>,
    pub binary: Option<PathBuf>,
    pub state_path: Option<PathBuf>,
    pub profile_snapshot: Option<serde_json::Value>,
    pub reverse_snapshots: Vec<serde_json::Value>,
    pub auto_solve_snapshot: Option<serde_json::Value>,
    pub state_snapshot: Option<serde_json::Value>,
    pub candidates_snapshot: Option<serde_json::Value>,
    pub selected_panel: usize,
    pub selected_row: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthLoginView {
    pub provider: String,
    pub method: String,
    pub status: String,
    pub detail: String,
    pub store_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellView {
    Home,
    Catalog,
    Recommend,
    Module,
    ModuleRun,
    Findings,
    Finding,
    Tune,
    Threat(ThreatView),
    ThreatEditor,
    PromptsEditor,
    ActorDetail(usize),
    Runs,
    Replay(String),
    Trace(String),
    Help,
    Quickstart,
    Config,
    Tools,
    Options(OptionsView),
    SastTasks,
    Context,
    Workspace,
    KnowledgeBase,
    FailureHandoff,
    AgentChat,
    History,
    Story,
    /// `/auth` providers + model + spend surface.  See
    /// `design/mockups/auth.jsx`.
    Auth,
    /// `/cost` budget bars + by-tool spend.  See `design/mockups/cost.jsx`.
    Cost,
    /// `/patch <alias>` view — RATIONALE / DIFF / TESTS / GUARDRAIL
    /// per `design/mockups/patch.jsx`.  String is the finding alias
    /// the patch addresses.
    Patch(String),
    /// Dedicated pwn workflow dashboard backed by pwn:* tool results and
    /// `.kuzushi/pwn/<hash>/state.json`.
    Pwn,
    /// Live module-progress dashboard. Split pane: left shows DAG status
    /// (queued / active / done / failing per task), right shows a tagged
    /// reasoning feed `[module:verb]`. Session state lives on `app.activity`.
    Activity,
    /// First-run model picker. Lists the entries in `MODEL_CHOICES` and
    /// lets the operator pick one with ↑/↓/Enter. Esc falls through to
    /// `Catalog`. Opened only when `config.model.is_none()` at shell
    /// startup, or on demand via `/model-picker`.
    ModelPicker,
    /// Secondary picker shown after `ModelPicker` when the chosen
    /// provider supports both an API-key and an OAuth login path
    /// (anthropic, openai). The string is the provider id; this stays
    /// on the variant so the renderer + key handler stay stateless.
    AuthMethodPicker(String),
    /// Claude-Code-style multi-select that drives the eight planning
    /// tasks (context build, x-ray, threat-model variants, CPG, CodeQL
    /// DB, threat intel). State lives on `app.planning_*` fields.
    PlanningPicker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatView {
    Dfd,
    Stride,
    Stories,
    Scope,
    Summary,
}

#[derive(Debug, Clone)]
pub struct CompletionCycle {
    pub prefix: String,
    pub candidates: Vec<String>,
    pub index: usize,
}
