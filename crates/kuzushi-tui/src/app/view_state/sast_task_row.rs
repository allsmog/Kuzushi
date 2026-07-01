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
    /// Split-pane command center and the shell's default landing surface
    /// (Claude Design layout 1a). A multi-pane body —
    /// `[SOURCE tree | CENTER context | FINDINGS + DETAILS]` — under a
    /// `Kuzushi · Project · Target · LIVE · phase` top bar, with the shared
    /// prompt/keybind footer acting as its command bar. Folds the old standalone
    /// findings, finding-detail, and threat-DFD surfaces into one frame view.
    /// Pane focus lives on `app.workbench_focus`.
    Workbench,
    Tune,
    Threat(ThreatView),
    ThreatEditor,
    PromptsEditor,
    ActorDetail(usize),
    Runs,
    RunDiff {
        left: String,
        right: String,
    },
    Replay(String),
    Trace(String),
    Help,
    Quickstart,
    /// Full-screen scrollable transcript. M1 §1.1 — the embedded
    /// transcript at the bottom of every view only shows the last few
    /// lines; long recon output and Quickstart instructions scroll off
    /// before the operator can read them. `logs` switches into this view
    /// and `j`/`k`/`g`/`G`/`PgUp`/`PgDn` page through the buffer.
    Logs,
    Config,
    Tools,
    Options(OptionsView),
    SastTasks,
    Context,
    ProjectModel,
    StrategyQueue,
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
    /// Fuzzy command palette (Ctrl+G). Filters every `SHELL_COMMAND_SPECS`
    /// entry by `app.palette_query`; Enter loads the selected command's
    /// canonical head into the prompt (never auto-executes). State lives on
    /// `app.palette_query` / `app.palette_cursor`.
    CommandPalette,
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
    /// Launch-time target picker. Opens when an interactive shell starts
    /// with no `--target` (bare `kuzushi`), offering cwd + child repos /
    /// previous kuzushi targets so the front door lands in the same guided
    /// journey as `kuzushi shell --target .`. Explicit-target consent
    /// (PR #64) is preserved — the operator picks; nothing defaults.
    TargetPicker,
    /// Claude-Code-style multi-select that drives the eight planning
    /// tasks (context build, x-ray, threat-model variants, CPG, CodeQL
    /// DB, threat intel). State lives on `app.planning_*` fields.
    PlanningPicker,
    /// Security-visualization gallery, fed real Kuzushi data. One page is a 3D
    /// attack-surface terrain (half-block framebuffer); the rest are 2D diagrams
    /// (attack path, DFD, findings heatmap, exploit chain). Auto-opens to the
    /// relevant page when its artifact is generated (unless
    /// `KUZUSHI_AUTO_OPEN_VIZ=false`); page + 3D orientation live on
    /// `app.scene_*`. TTY-only for the 3D page — plain mode shows a summary.
    Scene(crate::scene3d::VizPage),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatView {
    Stride,
    Stories,
    Scope,
    Summary,
}

/// Which pane the operator's keyboard focus is on inside the Workbench command
/// center. `Tab` cycles `Source → Center → Findings → Details → Source`; `j`/`k`
/// move within the focused pane; `Enter` opens the cursored finding when
/// `Findings` is focused. Defaults to `Findings` — the list is the primary
/// interaction, and opening a finding moves focus to `Details` for reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkbenchPane {
    Source,
    Center,
    Findings,
    Details,
}

impl WorkbenchPane {
    /// Advance focus to the next pane in `Source → Center → Findings → Details` order.
    pub fn next(self) -> Self {
        match self {
            WorkbenchPane::Source => WorkbenchPane::Center,
            WorkbenchPane::Center => WorkbenchPane::Findings,
            WorkbenchPane::Findings => WorkbenchPane::Details,
            WorkbenchPane::Details => WorkbenchPane::Source,
        }
    }

    /// Move focus to the previous pane in `Source ← Center ← Findings ← Details` order.
    pub fn prev(self) -> Self {
        match self {
            WorkbenchPane::Source => WorkbenchPane::Details,
            WorkbenchPane::Center => WorkbenchPane::Source,
            WorkbenchPane::Findings => WorkbenchPane::Center,
            WorkbenchPane::Details => WorkbenchPane::Findings,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkbenchPaneScroll {
    pub source: u16,
    pub center: u16,
    pub details: u16,
}

impl WorkbenchPaneScroll {
    pub fn get(self, pane: WorkbenchPane) -> u16 {
        match pane {
            WorkbenchPane::Source => self.source,
            WorkbenchPane::Center => self.center,
            WorkbenchPane::Findings => 0,
            WorkbenchPane::Details => self.details,
        }
    }

    pub fn shift(&mut self, pane: WorkbenchPane, amount: i32) {
        let Some(scroll) = self.scroll_mut(pane) else {
            return;
        };
        *scroll = if amount.is_negative() {
            scroll.saturating_sub(amount.unsigned_abs().min(u16::MAX as u32) as u16)
        } else {
            scroll.saturating_add(amount.min(u16::MAX as i32) as u16)
        };
    }

    pub fn set(&mut self, pane: WorkbenchPane, value: u16) {
        if let Some(scroll) = self.scroll_mut(pane) {
            *scroll = value;
        }
    }

    fn scroll_mut(&mut self, pane: WorkbenchPane) -> Option<&mut u16> {
        match pane {
            WorkbenchPane::Source => Some(&mut self.source),
            WorkbenchPane::Center => Some(&mut self.center),
            WorkbenchPane::Findings => None,
            WorkbenchPane::Details => Some(&mut self.details),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompletionCycle {
    pub prefix: String,
    pub candidates: Vec<String>,
    pub index: usize,
}

/// Active Ctrl+R reverse-history search. `cursor` indexes into the live match
/// list (most-recent first) computed from `command_history`.
#[derive(Debug, Clone, Default)]
pub struct HistorySearch {
    pub query: String,
    pub cursor: usize,
}
