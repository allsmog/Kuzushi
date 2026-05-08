use super::prelude::*;
use super::*;

pub(crate) const FEATURED_HELP_EXAMPLES: &[&str] = &[
    "scan .",
    "use semgrep",
    "run .",
    "findings",
    "open F-0001",
    "model 1",
];

pub fn shell_command_specs() -> impl Iterator<Item = &'static ShellCommandSpec> {
    SHELL_COMMAND_SPEC_GROUPS
        .iter()
        .flat_map(|specs| specs.iter())
}

pub fn shell_help_examples() -> Vec<&'static str> {
    FEATURED_HELP_EXAMPLES
        .iter()
        .copied()
        .filter(|example| shell_command_specs().any(|spec| spec.aliases.contains(example)))
        .collect()
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SastTaskModeCommand {
    Auto,
    Manual,
    Toggle,
}

pub fn parse_command(input: &str) -> ShellCommand {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return ShellCommand::Empty;
    }

    if trimmed == "?" {
        return ShellCommand::Help;
    }
    if let Some(question) = trimmed.strip_prefix('?') {
        let question = question.trim();
        if !question.is_empty() {
            return ShellCommand::Ask(question.to_string());
        }
    }

    let normalized = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let tokens = normalized.split_whitespace().collect::<Vec<_>>();
    let verb = tokens.first().copied().unwrap_or_default();
    let args = tokens.get(1..).unwrap_or_default();

    parse_static_command(verb)
        .or_else(|| parse_single_arg_command(verb, args, trimmed))
        .or_else(|| parse_joined_arg_command(verb, args, trimmed))
        .or_else(|| parse_nested_shell_command(verb, args, trimmed))
        .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string()))
}

pub(crate) fn parse_static_command(verb: &str) -> Option<ShellCommand> {
    let command = match verb {
        "help" | "h" | "?" => ShellCommand::Help,
        "back" | "b" => ShellCommand::Back,
        "modules" | "m" => ShellCommand::Modules,
        "tools" => ShellCommand::Tools,
        "cost" => ShellCommand::Cost,
        "config" => ShellCommand::Config,
        "permissions" => ShellCommand::Permissions,
        "tune" | "t" => ShellCommand::Tune,
        "prompts" => ShellCommand::Prompts,
        "tasks" => ShellCommand::Tasks,
        "runs" => ShellCommand::ShowRuns,
        "history" => ShellCommand::History,
        "clear" => ShellCommand::Clear,
        "pause" => ShellCommand::Pause,
        "story" => ShellCommand::Story,
        "yes" | "y" => ShellCommand::PlanApply,
        "no" | "n" => ShellCommand::PlanDiscard,
        "quickstart" => ShellCommand::Quickstart,
        "quit" | "exit" | "q" | "exitj" => ShellCommand::Quit,
        _ => return None,
    };
    Some(command)
}
