use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellCommand {
    Home,
    Help(Option<String>),
    Back,
    Modules,
    Recommend,
    Tools(Option<String>),
    /// Open the Workbench command center with the given pane focused. The
    /// shell's default landing surface; `findings` and `open` also route here
    /// with the appropriate pane focus / selection.
    Workbench(WorkbenchPane),
    Aim(Option<String>),
    Findings,
    FindingsFilter(String),
    Component(Option<String>),
    Open(String),
    Scan(Option<PathBuf>),
    /// Internal launch command. Chooses the initial terminal route without
    /// going through a public slash verb.
    LaunchStartView,
    /// Internal launch command for bare interactive shells without a target.
    LaunchTargetPicker,
    /// Internal command for non-interactive scripted input. The public `scan`
    /// verb opens the guided workflow in the TUI; scripted plain mode starts
    /// the scan immediately and still routes through `Msg::Cmd`.
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
    ThreatAsk(String),
    ThreatApply,
    ThreatReject,
    Prompts,
    Prompt(String),
    Actor(usize),
    ShowRuns,
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
    PlanApply,
    PlanDiscard,
    Quickstart,
    Onboarding,
    /// Continue the engagement: open the phase picker at the journey's
    /// current phase (derived from workspace state when no walker is live).
    Next,
    /// Open a specific engagement phase picker without changing workspace-
    /// derived `next` semantics.
    Phase(WorkflowPhase),
    Logs,
    Target(Option<String>),
    TargetRevision(String),
    Ask(String),
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
    Patch(PatchCommand),
    Workspace(WorkspaceCommand),
    Pwn(PwnCommand),
    KnowledgeBase(Option<String>),
    FilePicker,
    Attach(String),
    Detach(String),
    Reparse(String),
    History,
    Clear,
    Load(Option<String>),
    Resume(Option<String>),
    Pause,
    Cancel,
    Story,
    /// Open the security-visualization gallery (risk heatmap, attack path,
    /// DFD, attack tree, 3D attack-surface terrain). Fed real Kuzushi data.
    Scene,
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
