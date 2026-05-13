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
    ExportFindings { output: PathBuf },
    Unsupported(String),
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
