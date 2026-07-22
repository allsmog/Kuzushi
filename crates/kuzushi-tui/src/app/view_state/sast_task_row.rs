use super::*;
use crate::ui_view_models::PhaseSurfaceId;

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

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReconSnapshot {
    pub hosts: Vec<ReconHost>,
    pub services: Vec<ReconService>,
    pub notes: Vec<ReconNote>,
    pub last_tool: Option<String>,
    pub last_target: Option<String>,
}

impl ReconSnapshot {
    pub(crate) fn has_evidence(&self) -> bool {
        !self.hosts.is_empty() || !self.services.is_empty() || !self.notes.is_empty()
    }
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthLoginView {
    pub provider: String,
    pub method: String,
    pub status: String,
    pub detail: String,
    pub store_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptionView {
    BudgetHardStop,
    BudgetStop,
    NoBinary,
    NoModel,
    NoPlugin,
    NetworkDown,
    RateLimited,
}

// EnumIter (test-only) backs the renderer wiring registry test: every
// variant must reach a real screen instead of the unwired-view fallback.
#[cfg_attr(test, derive(strum::EnumIter))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellView {
    Home,
    Catalog,
    Recommend,
    Module,
    ModuleRun,
    /// Canonical phase-native cockpit for Map, Scan, Review, Prove, and Fix. The
    /// active page owns a screen composition of semantic surfaces while DFD,
    /// terrain, heatmap, attack tree, replay, chains, and trace open as
    /// contextual surfaces that restore this route exactly. Surface focus lives
    /// on `app.router.workbench().focus()`, keyed by `PhaseSurfaceId`.
    Workbench,
    /// Aggregate pre-engagement readiness surface. Target selection remains
    /// an explicit gate; once a target is active, Setup owns the Map plan,
    /// model/credential requirements, prompt posture, budget, and the single
    /// Start Map commit action.
    Setup,
    /// Dedicated workflow exit for exporting durable findings and remediation
    /// receipts without leaving the engagement cockpit.
    Report,
    Tune,
    Threat,
    ThreatEditor,
    PromptsEditor,
    ActorDetail,
    Runs,
    /// Background jobs registry — the operator control surface over the live
    /// run plus recent on-disk runs and queued steer items. Extends the Runs
    /// timeline with elapsed, current step, `-k` cancel, and pending rows.
    /// Shell-only, stateless like `Runs`.
    Jobs,
    RunDiff,
    Replay,
    Trace,
    /// Campaign deck — visual plan/launch surface over
    /// `.kuzushi/v3/campaigns/`: folds each plan with its dispatcher queue,
    /// supports per-job include/exclude and seasoned-prompt editing, and
    /// Launch spawns `kuzushi campaign run` as a detached subprocess so the
    /// shell never runs a campaign in-process.
    Campaign,
    /// Coverage matrix deck — read-only shards × threat-sources grid folded
    /// from every campaign plan/queue plus per-shard finding counts. Answers
    /// "where have we looked, what did we find, where is risk uncovered".
    Coverage,
    Help,
    Quickstart,
    /// Full-screen scrollable transcript. M1 §1.1 — the embedded
    /// transcript at the bottom of every view only shows the last few
    /// lines; long recon output and Quickstart instructions scroll off
    /// before the operator can read them. `logs` switches into this view
    /// and `j`/`k`/`g`/`G`/`PgUp`/`PgDn` page through the buffer.
    Logs,
    Config,
    /// Read-only application-policy summary. This is intentionally separate
    /// from model configuration so `permissions` never presents model choices
    /// as though they were authorization state.
    Permissions,
    Health,
    Tools,
    Options,
    SastTasks,
    Context,
    ProjectModel,
    StrategyQueue,
    Workspace,
    KnowledgeBase,
    FailureHandoff,
    History,
    Story,
    /// `/auth` providers + model + spend surface.  See
    /// `design/mockups/auth.jsx`.
    Auth,
    /// `/cost` budget bars + by-tool spend.  See `design/mockups/cost.jsx`.
    Cost,
    /// Launch splash / doctor-at-start surface. See
    /// `design/mockups/boot-splash.jsx`.
    BootSplash,
    /// Exit confirmation surface for dirty/in-flight sessions. See
    /// `design/mockups/quit-confirm.jsx`.
    QuitConfirm,
    /// Approval/refusal queue for runtime tool gates. See
    /// `design/mockups/confirm-dialog.jsx`.
    ConfirmDialog,
    /// Theme and accessibility preview surface. See
    /// `design/mockups/theme-picker.jsx`.
    ThemePicker,
    /// Printable keymap derived from command specs and active keybindings. See
    /// `design/mockups/keymap.jsx`.
    Keymap,
    /// Release-check/update status surface. See
    /// `design/mockups/update-available.jsx`.
    UpdateAvailable,
    /// Read-only recovery surfaces for common blocking states. See
    /// `design/mockups/err-no-model.jsx`, `err-no-binary.jsx`,
    /// `err-no-plugin.jsx`, `rate-limited.jsx`, `network-down.jsx`,
    /// `budget-stop.jsx`, and `budget-hard-stop.jsx`.
    Interruption,
    /// Patch review view — RATIONALE / DIFF / TESTS / GUARDRAIL.
    /// String is the finding alias the patch addresses.
    Patch,
    /// Dedicated pwn workflow dashboard backed by pwn:* tool results and
    /// `.kuzushi/pwn/<hash>/state.json`.
    Pwn,
    /// Live module-progress dashboard. Split pane: left shows DAG status
    /// (queued / active / done / failing per task), right shows a tagged
    /// reasoning feed `[module:verb]`. Session state lives in `DomainCache`.
    Activity,
    /// Fuzzy command palette (Ctrl+G). Filters every `SHELL_COMMAND_SPEC_GROUPS`
    /// entry by the command-palette route query; Enter loads the selected command's
    /// canonical head into the prompt (never auto-executes). State lives on
    /// `app.router.command_palette()`.
    CommandPalette,
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
    /// Target-rooted fuzzy file picker for `attach <path>`. It reuses the
    /// shell's line-rendered picker pattern: app-owned query/cursor state,
    /// no external event loop, and Enter dispatches through the existing
    /// attachment store.
    FilePicker,
    /// Security-visualization gallery, fed real Kuzushi data. One page is a 3D
    /// attack-surface terrain (half-block framebuffer); the rest are 2D diagrams
    /// (attack path, DFD, findings heatmap, exploit chain). Auto-opens to the
    /// relevant page when its artifact is generated (unless
    /// `KUZUSHI_AUTO_OPEN_VIZ=false`); page + 3D orientation live on
    /// `app.router.scene()`. TTY-only for the 3D page — plain mode shows a summary.
    Scene,
}

impl Default for ShellView {
    fn default() -> Self {
        Self::Catalog
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatView {
    Stride,
    Stories,
    Scope,
    Summary,
}

/// Durable operator screens for the five engagement phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkbenchPage {
    Map,
    Scan,
    Review,
    Prove,
    Fix,
}

impl WorkbenchPage {
    pub const SCAN_GRID_MIN_COLUMNS: u16 = 50;
    /// Shared chrome and the engagement header consume ten rows in the
    /// canonical Scan composition. Below `SCAN_GRID_MIN_BODY_ROWS` the
    /// renderer uses its one-pane summary, so keyboard focus must do the same.
    pub const SCAN_GRID_MIN_BODY_ROWS: u16 = 14;
    /// The phase body sits below the shared status/keybind/prompt chrome and
    /// the engagement header. Canonical 80x24 therefore has fewer than 20 body
    /// rows and renders the single combined Fix pane.
    pub const FIX_DIAGRAM_MIN_BODY_ROWS: u16 = 20;
    pub const ALL: [Self; 5] = [Self::Map, Self::Scan, Self::Review, Self::Prove, Self::Fix];

    pub fn from_phase(phase: WorkflowPhase) -> Self {
        match phase {
            WorkflowPhase::Map => Self::Map,
            WorkflowPhase::Scan => Self::Scan,
            WorkflowPhase::Review => Self::Review,
            WorkflowPhase::Prove => Self::Prove,
            WorkflowPhase::Fix => Self::Fix,
        }
    }

    pub fn phase(self) -> WorkflowPhase {
        match self {
            Self::Map => WorkflowPhase::Map,
            Self::Scan => WorkflowPhase::Scan,
            Self::Review => WorkflowPhase::Review,
            Self::Prove => WorkflowPhase::Prove,
            Self::Fix => WorkflowPhase::Fix,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Map => "MAP",
            Self::Scan => "SCAN",
            Self::Review => "REVIEW",
            Self::Prove => "PROVE",
            Self::Fix => "FIX",
        }
    }

    pub fn next(self) -> Self {
        let index = self.index();
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        let index = self.index();
        Self::ALL[(index + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    /// The surface focused when the operator lands on this page. Matches the
    /// first row each page's surface-spec builder emits, so the stored focus
    /// and the plan's `primary` fallback agree.
    pub fn primary_surface(self) -> PhaseSurfaceId {
        match self {
            Self::Map => PhaseSurfaceId::MapReadiness,
            Self::Scan => PhaseSurfaceId::ScanEngines,
            Self::Review => PhaseSurfaceId::ReviewQueue,
            Self::Prove => PhaseSurfaceId::ProveEvidence,
            Self::Fix => PhaseSurfaceId::FixRemediation,
        }
    }

    /// The finding-list-role surface — the default keyboard focus when no
    /// focus has been stored for this page.
    pub fn findings_surface(self) -> PhaseSurfaceId {
        match self {
            Self::Map => PhaseSurfaceId::MapHotModules,
            Self::Scan => PhaseSurfaceId::ScanDelta,
            Self::Review => PhaseSurfaceId::ReviewQueue,
            Self::Prove => PhaseSurfaceId::ProveLadder,
            Self::Fix => PhaseSurfaceId::FixRemediation,
        }
    }

    /// The reading-detail-role surface targeted when a finding or receipt is
    /// opened for reading.
    pub fn detail_surface(self) -> PhaseSurfaceId {
        match self {
            Self::Map => PhaseSurfaceId::MapDfd,
            Self::Scan => PhaseSurfaceId::ScanReceipt,
            Self::Review => PhaseSurfaceId::ReviewDetail,
            Self::Prove => PhaseSurfaceId::ProveReceipt,
            Self::Fix => PhaseSurfaceId::FixDfd,
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|page| *page == self).unwrap_or(0)
    }
}

/// Per-surface scroll offsets for the Workbench. Keyed by `PhaseSurfaceId`,
/// so an offset never leaks across pages the way the retired four-pane slots
/// shared scroll state between phases.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkbenchSurfaceScroll {
    offsets: std::collections::BTreeMap<PhaseSurfaceId, u16>,
}

impl WorkbenchSurfaceScroll {
    pub fn get(&self, surface: PhaseSurfaceId) -> u16 {
        self.offsets.get(&surface).copied().unwrap_or(0)
    }

    pub fn shift(&mut self, surface: PhaseSurfaceId, amount: i32) {
        let current = self.get(surface);
        let next = if amount.is_negative() {
            current.saturating_sub(amount.unsigned_abs().min(u16::MAX as u32) as u16)
        } else {
            current.saturating_add(amount.min(u16::MAX as i32) as u16)
        };
        self.set(surface, next);
    }

    pub fn set(&mut self, surface: PhaseSurfaceId, value: u16) {
        if value == 0 {
            self.offsets.remove(&surface);
        } else {
            self.offsets.insert(surface, value);
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

#[cfg(test)]
mod workbench_page_tests {
    use super::*;

    #[test]
    fn each_phase_names_its_role_surfaces() {
        assert_eq!(
            WorkbenchPage::Map.primary_surface(),
            PhaseSurfaceId::MapReadiness
        );
        assert_eq!(
            WorkbenchPage::Scan.primary_surface(),
            PhaseSurfaceId::ScanEngines
        );
        assert_eq!(
            WorkbenchPage::Review.primary_surface(),
            PhaseSurfaceId::ReviewQueue
        );
        assert_eq!(
            WorkbenchPage::Prove.primary_surface(),
            PhaseSurfaceId::ProveEvidence
        );
        assert_eq!(
            WorkbenchPage::Fix.primary_surface(),
            PhaseSurfaceId::FixRemediation
        );
        for page in WorkbenchPage::ALL {
            assert_eq!(page.primary_surface().page(), page);
            assert_eq!(page.findings_surface().page(), page);
            assert_eq!(page.detail_surface().page(), page);
        }
    }

    #[test]
    fn pages_cycle_map_scan_review_prove_fix() {
        assert_eq!(WorkbenchPage::Map.next(), WorkbenchPage::Scan);
        assert_eq!(WorkbenchPage::Scan.next(), WorkbenchPage::Review);
        assert_eq!(WorkbenchPage::Review.next(), WorkbenchPage::Prove);
        assert_eq!(WorkbenchPage::Prove.next(), WorkbenchPage::Fix);
        assert_eq!(WorkbenchPage::Fix.next(), WorkbenchPage::Map);
        assert_eq!(WorkbenchPage::Map.prev(), WorkbenchPage::Fix);
        for &phase in WorkflowPhase::ORDER {
            assert_eq!(WorkbenchPage::from_phase(phase).phase(), phase);
        }
    }

    #[test]
    fn surface_scroll_is_keyed_per_surface() {
        let mut scroll = WorkbenchSurfaceScroll::default();
        scroll.shift(PhaseSurfaceId::ReviewQueue, 3);
        scroll.shift(PhaseSurfaceId::FixRemediation, 5);
        assert_eq!(scroll.get(PhaseSurfaceId::ReviewQueue), 3);
        assert_eq!(scroll.get(PhaseSurfaceId::FixRemediation), 5);
        scroll.shift(PhaseSurfaceId::ReviewQueue, -10);
        assert_eq!(scroll.get(PhaseSurfaceId::ReviewQueue), 0);
        scroll.set(PhaseSurfaceId::MapDfd, 7);
        assert_eq!(scroll.get(PhaseSurfaceId::MapDfd), 7);
    }
}
