use super::*;

mod auth_config_model;
mod command_payloads;
mod context_kb;
mod findings_evidence;
mod navigation;
mod options_tasks;
mod run_scan;
mod session;

pub use command_payloads::{
    ContextCommand, PwnCommand, SastTaskCommand, SastTaskModeCommand, WorkspaceCommand,
};

pub(crate) const SHELL_COMMAND_SPEC_GROUPS: &[&[ShellCommandSpec]] = &[
    navigation::NAVIGATION_COMMANDS,
    run_scan::RUN_SCAN_COMMANDS,
    options_tasks::OPTIONS_TASK_COMMANDS,
    context_kb::CONTEXT_KB_COMMANDS,
    findings_evidence::FINDINGS_EVIDENCE_COMMANDS,
    auth_config_model::AUTH_CONFIG_MODEL_COMMANDS,
    session::SESSION_COMMANDS,
];

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

pub fn parse_command(input: &str) -> ShellCommand {
    let trimmed = input.trim();
    parse_prompt_command(trimmed).unwrap_or_else(|| parse_routed_command(trimmed))
}

fn parse_prompt_command(trimmed: &str) -> Option<ShellCommand> {
    if trimmed.is_empty() {
        return Some(ShellCommand::Empty);
    }
    let question = trimmed.strip_prefix('?')?.trim();
    Some(if question.is_empty() {
        ShellCommand::Help
    } else {
        ShellCommand::Ask(question.to_string())
    })
}

fn parse_routed_command(trimmed: &str) -> ShellCommand {
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
    parse_navigation_command(verb)
        .or_else(|| parse_catalog_command(verb))
        .or_else(|| parse_session_command(verb))
        .or_else(|| parse_plan_response_command(verb))
}

fn parse_navigation_command(verb: &str) -> Option<ShellCommand> {
    match verb {
        "" | "home" => Some(ShellCommand::Home),
        "help" | "h" | "?" => Some(ShellCommand::Help),
        "back" | "b" => Some(ShellCommand::Back),
        "quit" | "exit" | "q" | "exitj" => Some(ShellCommand::Quit),
        _ => None,
    }
}

fn parse_catalog_command(verb: &str) -> Option<ShellCommand> {
    match verb {
        "modules" | "m" => Some(ShellCommand::Modules),
        "recommend" | "rec" => Some(ShellCommand::Recommend),
        "tools" => Some(ShellCommand::Tools),
        "tune" | "t" => Some(ShellCommand::Tune),
        "prompts" => Some(ShellCommand::Prompts),
        "tasks" => Some(ShellCommand::Tasks),
        _ => None,
    }
}

fn parse_session_command(verb: &str) -> Option<ShellCommand> {
    match verb {
        "cost" => Some(ShellCommand::Cost),
        "config" => Some(ShellCommand::Config),
        "permissions" => Some(ShellCommand::Permissions),
        "runs" => Some(ShellCommand::ShowRuns),
        "history" => Some(ShellCommand::History),
        "clear" => Some(ShellCommand::Clear),
        "pause" => Some(ShellCommand::Pause),
        "story" => Some(ShellCommand::Story),
        "quickstart" => Some(ShellCommand::Quickstart),
        "onboarding" | "setup" | "plan-stage" | "planning" => Some(ShellCommand::Onboarding),
        "activity" | "progress" | "a" => Some(ShellCommand::Activity),
        "handoff" | "failure" | "failures" => Some(ShellCommand::FailureHandoff),
        _ => None,
    }
}

fn parse_plan_response_command(verb: &str) -> Option<ShellCommand> {
    match verb {
        "yes" | "y" => Some(ShellCommand::PlanApply),
        "no" | "n" => Some(ShellCommand::PlanDiscard),
        _ => None,
    }
}
