use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskAttachment {
    Screen,
    ThreatModel { whole_model: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskRequest {
    pub question: String,
    pub attachment: AskAttachment,
}

impl AskRequest {
    pub fn screen(question: impl Into<String>) -> Self {
        Self {
            question: question.into(),
            attachment: AskAttachment::Screen,
        }
    }

    pub fn threat_model(question: impl Into<String>, whole_model: bool) -> Self {
        Self {
            question: question.into(),
            attachment: AskAttachment::ThreatModel { whole_model },
        }
    }
}

impl AskAttachment {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Screen => "screen",
            Self::ThreatModel { whole_model: false } => "threat-model-scene",
            Self::ThreatModel { whole_model: true } => "threat-model-whole",
        }
    }

    pub(crate) fn whole_model(self) -> bool {
        matches!(self, Self::ThreatModel { whole_model: true })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellCommand {
    Home,
    Help(Option<String>),
    Back,
    Modules,
    Recommend,
    RecommendationReport,
    Tools(Option<String>),
    /// Toggle a tool as a favorite on the per-workspace shelf.
    FavoriteTool(String),
    /// Open the phase Workbench with the given workflow surface focused. The
    /// shell's default landing surface; `findings` and `open` also route here
    /// with the appropriate pane focus / selection.
    Workbench,
    Report,
    Scopes,
    Aim(Option<String>),
    Findings,
    FindingsFilter(String),
    Component(Option<String>),
    Open(String),
    /// Compatibility route for callers that constructed the former public
    /// `scan [target]` guided-workflow command directly. The shell parser no
    /// longer emits this variant.
    Scan(Option<PathBuf>),
    /// Execute `sast:scan` over files changed since a Git revision. Unlike
    /// `findings since`, this creates new scan evidence.
    ScanSince {
        reference: String,
        include_worktree: bool,
    },
    /// Open the dedicated nondeterministic scan-batch configurator. A named
    /// prior run may supply historical cost evidence; it is never inferred.
    ScanBatch {
        prior_run_id: Option<String>,
    },
    /// Open the guided Map → Scan workflow, optionally selecting a target
    /// first. Emitted by the public `full` and `pipeline` shell verbs.
    Full(Option<PathBuf>),
    /// Internal launch command. Chooses the initial terminal route without
    /// going through a public slash verb.
    LaunchStartView,
    /// Internal launch command for bare interactive shells without a target.
    LaunchTargetPicker,
    /// Compatibility route for the former non-interactive `scan [target]`
    /// behavior. Scripted plain input no longer emits it.
    ScriptedScan(Option<PathBuf>),
    Demo,
    Model(Option<String>),
    Auth,
    AuthLogin(Option<String>),
    Provider(Option<String>),
    Backend(Option<String>),
    Cost,
    Config,
    Health,
    Permissions,
    BootSplash,
    QuitConfirm,
    ThemePicker,
    Keymap,
    UpdateAvailable,
    Use(String),
    Tune,
    Threat(ThreatView),
    ThreatEditor,
    ThreatRegen,
    /// Ask about the current threat-model scene. Kept as a string payload for
    /// compatibility with callers that construct shell commands directly.
    ThreatAsk(String),
    ThreatAskWholeModel(String),
    ThreatApply,
    ThreatReject,
    /// Open the immutable-lineage picker backed by threat-model manifest
    /// heads. This is distinct from the legacy version ledger.
    ThreatModels,
    ThreatModelInspectDiff,
    ThreatModelActivate {
        model_id: String,
        revision_id: Option<String>,
    },
    ThreatModelRevisions(String),
    /// Compare two revisions or lineage heads (`tm_…`/`tmr_…` selectors).
    ThreatModelDiff {
        from: String,
        to: String,
    },
    ThreatModelRestore(String),
    ThreatVersions,
    ThreatVersionUse(i64),
    Prompts,
    Prompt(String),
    Actor(usize),
    ShowRuns,
    /// Open the background jobs registry (live + recent runs, queued steer
    /// items). `jobs`.
    ShowJobs,
    /// Cancel a running job (or dequeue a pending steer item) by run id.
    /// `jobs -k <id>`.
    CancelJob(String),
    /// Open the Campaign deck (all campaigns, or jump straight to one).
    /// `campaign [id]`.
    ShowCampaigns(Option<String>),
    /// Open one batch report and retain it as the Review scope.
    BatchResults(String),
    /// Leave batch-scoped Review and return to the workspace finding set.
    ClearBatchScope,
    ShowCoverage,
    ShowRelationships,
    ShowLessons,
    ShowFindingGroups,
    /// Queue a command to dispatch after the current run finishes. `queue
    /// <tool|verb>`.
    QueueCommand(String),
    /// Drop back to the Workbench while live work keeps running. `background`.
    Background,
    RunDiff {
        left: String,
        right: String,
    },
    ShowAliases(Option<String>),
    Since(String),
    Replay(String),
    Trace(String),
    Activity,
    FailureHandoff,
    Plan(String),
    /// Free-form prose submitted from a durable Workbench phase. The selected
    /// page is carried explicitly; it never mutates workflow reality.
    PhaseIntent {
        selected_phase: WorkflowPhase,
        text: String,
    },
    PlanApply,
    PlanDiscard,
    Quickstart,
    Onboarding,
    /// Continue the engagement: open the phase picker at the journey's
    /// current phase (derived from workspace state when no walker is live).
    Next,
    /// `next fresh` — explicit fresh-pass affordance: reset planner drafts
    /// and reopen the Map planner for this revision.
    NextFresh,
    /// Direct phase verb (`map`, `scan`, `review`, `prove`, `fix`). Opens the
    /// durable Workbench page once the engagement has completed or passed the
    /// phase; otherwise opens that phase's planner. Never changes
    /// workspace-derived `next` semantics.
    Phase(WorkflowPhase),
    /// Always open a specific phase planner, whatever the journey progress.
    /// Emitted by `plan <phase>` and `phase <phase>`.
    PhasePlanner(WorkflowPhase),
    /// Read (`None`) or set the operator autonomy posture — the always-visible
    /// authorization ceiling the dispatch gate enforces.
    Autonomy(Option<AutonomyPosture>),
    Logs,
    Target(Option<String>),
    TargetRevision(String),
    /// Ask about the current screen. Kept as a string payload for compatibility
    /// with callers that construct shell commands directly.
    Ask(String),
    AskWholeModel(String),
    /// Cancel only the active Ask, preserving a concurrently running scan.
    CancelAsk,
    Answers,
    Options {
        tool: Option<String>,
        filter: OptionsFilter,
    },
    SetOption {
        global: bool,
        name: String,
        value: String,
    },
    UnsetOption {
        global: bool,
        name: String,
    },
    Tasks,
    Task(SastTaskCommand),
    Context(ContextCommand),
    ProjectModel,
    Strategy(StrategyCommand),
    ReviewDecision(ReviewDecisionCommand),
    /// Explicit human deferral of empirical proof for one finding generation.
    ProofDeferral {
        reference: String,
        reason: String,
    },
    Patch(PatchCommand),
    Workspace(WorkspaceCommand),
    Pwn(PwnCommand),
    KnowledgeBase(Option<String>),
    FilePicker,
    Attach(String),
    Detach(String),
    Reparse(String),
    History,
    /// Show the durable transcript id, path, and writer health for this shell.
    SessionInfo,
    Clear,
    Load(Option<String>),
    Resume(Option<String>),
    Retry(Option<String>),
    Pause,
    Cancel,
    Story,
    /// Open the security-visualization gallery (risk heatmap, attack path,
    /// DFD, attack tree, 3D attack-surface terrain). Fed real Kuzushi data.
    Scene,
    /// Open the gallery focused on the risk-ranked file worklist page.
    Worklist,
    /// Toggle the context rail. Hiding persists (`ui.rail false`); showing
    /// restores the auto policy and force-opens for this session.
    Rail,
    RunTool {
        tool: Option<String>,
        input: Option<String>,
    },
    Quit,
    Empty,
    Unknown(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellCommandCategory {
    Navigation,
    RunScan,
    OptionsTasks,
    ContextKb,
    FindingsEvidence,
    AuthConfigModel,
    Session,
}

impl ShellCommandCategory {
    pub const ORDER: [ShellCommandCategory; 7] = [
        ShellCommandCategory::Navigation,
        ShellCommandCategory::RunScan,
        ShellCommandCategory::OptionsTasks,
        ShellCommandCategory::ContextKb,
        ShellCommandCategory::FindingsEvidence,
        ShellCommandCategory::AuthConfigModel,
        ShellCommandCategory::Session,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ShellCommandCategory::Navigation => "NAVIGATION",
            ShellCommandCategory::RunScan => "RUN / SCAN",
            ShellCommandCategory::OptionsTasks => "OPTIONS / TASKS",
            ShellCommandCategory::ContextKb => "CONTEXT / KB",
            ShellCommandCategory::FindingsEvidence => "FINDINGS / EVIDENCE",
            ShellCommandCategory::AuthConfigModel => "AUTH / CONFIG / MODEL",
            ShellCommandCategory::Session => "SESSION",
        }
    }
}
