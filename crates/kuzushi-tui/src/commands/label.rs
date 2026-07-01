use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellCommand {
    Home,
    Help,
    Back,
    Modules,
    Recommend,
    Tools,
    /// Open the Workbench command center with the given pane focused. The
    /// shell's default landing surface; `findings`/`open`/`threats dfd` also
    /// route here with the appropriate pane focus / selection.
    Workbench(WorkbenchPane),
    Findings,
    FindingsFilter(String),
    Open(String),
    Scan(Option<PathBuf>),
    Model(Option<String>),
    Auth,
    AuthLogin(Option<String>),
    Provider(Option<String>),
    Backend(Option<String>),
    Cost,
    Config,
    Permissions,
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
    Workspace(WorkspaceCommand),
    Pwn(PwnCommand),
    KnowledgeBase(Option<String>),
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
