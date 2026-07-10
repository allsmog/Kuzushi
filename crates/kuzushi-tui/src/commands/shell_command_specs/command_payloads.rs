use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SastTaskCommand {
    Block(String),
    Allow(String),
    Toggle(Option<String>),
    Mode(SastTaskModeCommand),
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextCommand {
    Show,
    Build,
    Status,
    Regen(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceCommand {
    Status,
    Reindex,
    ScopeInit,
    ExportFindings {
        output: PathBuf,
        format: Option<String>,
        completeness: Option<String>,
        allow_empty: bool,
    },
    Unsupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrategyCommand {
    Show,
    Approve(String),
    Reject(String),
    Fire,
    Correct {
        id: String,
        to_strategy: String,
        reason: Option<String>,
        scope: StrategyCorrectionCommandScope,
    },
    Unsupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchCommand {
    Apply,
    Reject,
    Regen { style: Option<String> },
    Unsupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewDecisionCommand {
    Record {
        verdict: String,
        reason: String,
    },
    Dismiss {
        reason: String,
        note: String,
    },
    Suppress {
        reference: String,
        reason: String,
        author: String,
        days: u64,
    },
    Unsupported(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyCorrectionCommandScope {
    Run,
    Workspace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PwnCommand {
    Show,
    Target(PathBuf),
    Profile,
    Reverse(Option<String>),
    Auto,
    State,
    Candidates(String),
    Unsupported(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SastTaskModeCommand {
    Auto,
    Manual,
    Toggle,
}
