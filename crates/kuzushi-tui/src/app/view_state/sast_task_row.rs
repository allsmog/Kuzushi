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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellView {
    Home,
    Catalog,
    Recommend,
    Module,
    ModuleRun,
    /// Canonical phase-native cockpit for Map, Scan, Review, Prove, and Fix. The
    /// active page owns its semantic panes while DFD, terrain, heatmap, attack
    /// tree, replay, and trace open as contextual surfaces that restore this
    /// route exactly. Pane focus lives on `app.router.workbench().focus()`.
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
    AgentChat,
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
    pub const SCAN_GRID_MIN_BODY_ROWS: u16 = 14;
    /// Shared chrome and the engagement header consume ten rows in the
    /// canonical Scan composition. Below this viewport height the renderer
    /// uses its one-pane summary, so keyboard focus must do the same.
    #[cfg(test)]
    pub const SCAN_GRID_MIN_ROWS: u16 = Self::SCAN_GRID_MIN_BODY_ROWS + 10;
    #[cfg(test)]
    pub const FIX_GRID_MIN_COLUMNS: u16 = 80;
    pub const FIX_DIAGRAM_MIN_BODY_ROWS: u16 = 20;
    /// The phase body sits below the shared status/keybind/prompt chrome and
    /// the engagement header. Canonical 80x24 therefore has fewer than 20 body
    /// rows and renders the single combined Fix pane.
    #[cfg(test)]
    pub const FIX_GRID_MIN_ROWS: u16 = Self::FIX_DIAGRAM_MIN_BODY_ROWS + 10;
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

    /// Logical pane order for the phase-native cockpit.
    ///
    /// The renderer may stack these panes at compact widths, but their focus
    /// order stays stable so Tab never lands on content that is not visible on
    /// the active page.
    #[cfg(test)]
    pub fn pane_order(self) -> &'static [WorkbenchPane] {
        match self {
            Self::Map => &[
                WorkbenchPane::Source,
                WorkbenchPane::Center,
                WorkbenchPane::Findings,
                WorkbenchPane::Details,
            ],
            Self::Scan => &[
                WorkbenchPane::Source,
                WorkbenchPane::Center,
                WorkbenchPane::Findings,
                WorkbenchPane::Details,
            ],
            Self::Review => &[WorkbenchPane::Findings, WorkbenchPane::Details],
            Self::Prove => &[
                WorkbenchPane::Source,
                WorkbenchPane::Center,
                WorkbenchPane::Findings,
                WorkbenchPane::Details,
            ],
            Self::Fix => &[
                WorkbenchPane::Source,
                WorkbenchPane::Center,
                WorkbenchPane::Details,
                WorkbenchPane::Findings,
            ],
        }
    }

    #[cfg(test)]
    pub fn pane_order_for_viewport(self, columns: u16, rows: u16) -> &'static [WorkbenchPane] {
        if self == Self::Scan
            && (columns < Self::SCAN_GRID_MIN_COLUMNS || rows < Self::SCAN_GRID_MIN_ROWS)
        {
            return &[WorkbenchPane::Center];
        }
        if self == Self::Fix
            && (columns < Self::FIX_GRID_MIN_COLUMNS || rows < Self::FIX_GRID_MIN_ROWS)
        {
            return &[WorkbenchPane::Center];
        }
        self.pane_order()
    }

    /// Panes the active phase-native composition actually paints and can focus.
    #[cfg(test)]
    pub fn interactive_panes_for_viewport(
        self,
        columns: u16,
        rows: u16,
    ) -> &'static [WorkbenchPane] {
        self.pane_order_for_viewport(columns, rows)
    }

    pub fn primary_pane(self) -> WorkbenchPane {
        match self {
            Self::Review => WorkbenchPane::Findings,
            Self::Map => WorkbenchPane::Source,
            Self::Scan | Self::Prove => WorkbenchPane::Center,
            Self::Fix => WorkbenchPane::Findings,
        }
    }

    #[cfg(test)]
    pub fn next_pane_for_viewport(
        self,
        current: WorkbenchPane,
        reverse: bool,
        columns: u16,
        rows: u16,
    ) -> WorkbenchPane {
        self.next_pane_in(
            self.pane_order_for_viewport(columns, rows),
            current,
            reverse,
        )
    }

    #[cfg(test)]
    fn next_pane_in(
        self,
        panes: &[WorkbenchPane],
        current: WorkbenchPane,
        reverse: bool,
    ) -> WorkbenchPane {
        let Some(current_index) = panes.iter().position(|pane| *pane == current) else {
            return panes
                .first()
                .copied()
                .unwrap_or_else(|| self.primary_pane());
        };
        let next_index = if reverse {
            (current_index + panes.len() - 1) % panes.len()
        } else {
            (current_index + 1) % panes.len()
        };
        panes[next_index]
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|page| *page == self).unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkbenchPaneScroll {
    pub source: u16,
    pub center: u16,
    pub findings: u16,
    pub details: u16,
}

impl WorkbenchPaneScroll {
    pub fn get(self, pane: WorkbenchPane) -> u16 {
        match pane {
            WorkbenchPane::Source => self.source,
            WorkbenchPane::Center => self.center,
            WorkbenchPane::Findings => self.findings,
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
            WorkbenchPane::Findings => Some(&mut self.findings),
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

#[cfg(test)]
mod workbench_page_tests {
    use super::*;

    #[test]
    fn phase_pages_cycle_only_their_visible_panes() {
        assert_eq!(
            WorkbenchPage::Map.next_pane_for_viewport(WorkbenchPane::Center, false, 160, 40,),
            WorkbenchPane::Findings
        );
        assert_eq!(
            WorkbenchPage::Review.next_pane_for_viewport(WorkbenchPane::Findings, false, 160, 40,),
            WorkbenchPane::Details
        );
        assert_eq!(
            WorkbenchPage::Prove.next_pane_for_viewport(WorkbenchPane::Center, true, 160, 40,),
            WorkbenchPane::Source
        );
        assert_eq!(
            WorkbenchPage::Fix.next_pane_for_viewport(WorkbenchPane::Details, false, 160, 40,),
            WorkbenchPane::Findings
        );
        assert_eq!(
            WorkbenchPage::Fix.next_pane_for_viewport(WorkbenchPane::Details, false, 60, 20,),
            WorkbenchPane::Center,
            "compact Fix normalizes a stale hidden-pane focus"
        );
    }

    #[test]
    fn each_phase_names_its_primary_pane() {
        assert_eq!(WorkbenchPage::Map.primary_pane(), WorkbenchPane::Source);
        assert_eq!(WorkbenchPage::Scan.primary_pane(), WorkbenchPane::Center);
        assert_eq!(
            WorkbenchPage::Review.primary_pane(),
            WorkbenchPane::Findings
        );
        assert_eq!(WorkbenchPage::Prove.primary_pane(), WorkbenchPane::Center);
        assert_eq!(WorkbenchPage::Fix.primary_pane(), WorkbenchPane::Findings);
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
    fn narrow_scan_uses_one_truthful_combined_pane() {
        for viewport in [(40, 12), (60, 20)] {
            assert_eq!(
                WorkbenchPage::Scan.pane_order_for_viewport(viewport.0, viewport.1),
                &[WorkbenchPane::Center]
            );
            assert_eq!(
                WorkbenchPage::Scan.next_pane_for_viewport(
                    WorkbenchPane::Center,
                    false,
                    viewport.0,
                    viewport.1,
                ),
                WorkbenchPane::Center
            );
        }
        assert_eq!(
            WorkbenchPage::Scan.pane_order_for_viewport(80, 24),
            WorkbenchPage::Scan.pane_order()
        );
    }

    #[test]
    fn compact_fix_cycles_only_the_combined_center_pane() {
        for (columns, rows) in [(60, 20), (80, 24)] {
            assert_eq!(
                WorkbenchPage::Fix.next_pane_for_viewport(
                    WorkbenchPane::Center,
                    false,
                    columns,
                    rows,
                ),
                WorkbenchPane::Center
            );
            assert_eq!(
                WorkbenchPage::Fix.pane_order_for_viewport(columns, rows),
                &[WorkbenchPane::Center]
            );
        }
        assert_eq!(
            WorkbenchPage::Fix.next_pane_for_viewport(WorkbenchPane::Center, false, 120, 36,),
            WorkbenchPane::Details
        );
    }

    #[test]
    fn prove_and_fix_expose_every_rendered_reference_pane() {
        assert_eq!(
            WorkbenchPage::Prove.pane_order_for_viewport(120, 36),
            &[
                WorkbenchPane::Source,
                WorkbenchPane::Center,
                WorkbenchPane::Findings,
                WorkbenchPane::Details,
            ]
        );
        assert_eq!(
            WorkbenchPage::Fix.pane_order_for_viewport(120, 36),
            &[
                WorkbenchPane::Source,
                WorkbenchPane::Center,
                WorkbenchPane::Details,
                WorkbenchPane::Findings,
            ]
        );
    }

    #[test]
    fn contextual_visualizations_never_hide_phase_panes() {
        assert_eq!(
            WorkbenchPage::Prove.interactive_panes_for_viewport(150, 34),
            WorkbenchPage::Prove.pane_order()
        );
    }
}
