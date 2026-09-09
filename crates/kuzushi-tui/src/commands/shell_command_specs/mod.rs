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
    ContextCommand, PatchCommand, PwnCommand, ReviewDecisionCommand, SastTaskCommand,
    SastTaskModeCommand, StrategyCommand, StrategyCorrectionCommandScope, WorkspaceCommand,
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
    "demo",
    "next",
    "full .",
    "use semgrep",
    "run .",
    "findings",
    "open F-0001",
    "findings export report.sarif sarif",
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
        .filter(|example| {
            shell_command_specs()
                .any(|spec| spec.command == *example || spec.aliases.contains(example))
        })
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
        ShellCommand::Help(None)
    } else {
        parse_ask_command(
            &question.split_whitespace().collect::<Vec<_>>(),
            trimmed,
            false,
        )
    })
}

fn parse_routed_command(trimmed: &str) -> ShellCommand {
    let normalized = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let tokens = normalized.split_whitespace().collect::<Vec<_>>();
    let verb = tokens.first().copied().unwrap_or_default();
    let args = tokens.get(1..).unwrap_or_default();

    parse_help_command(verb, args)
        .or_else(|| parse_direct_phase_command(verb, args, trimmed))
        .or_else(|| parse_full_command(verb, args, trimmed))
        .or_else(|| parse_static_command(verb))
        .or_else(|| parse_single_arg_command(verb, args, trimmed))
        .or_else(|| parse_joined_arg_command(verb, args, trimmed))
        .or_else(|| parse_nested_shell_command(verb, args, trimmed))
        .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string()))
}

/// The five workflow names are zero-argument shortcuts for their exact phase
/// planners. `review` with arguments remains the human-decision command, while
/// `scan` with a target receives a dedicated migration error downstream.
const DIRECT_PHASE_COMMANDS: [(&str, WorkflowPhase); 10] = [
    ("map", WorkflowPhase::Map),
    ("ma", WorkflowPhase::Map),
    ("scan", WorkflowPhase::Scan),
    ("sc", WorkflowPhase::Scan),
    ("review", WorkflowPhase::Review),
    ("rv", WorkflowPhase::Review),
    ("prove", WorkflowPhase::Prove),
    ("pr", WorkflowPhase::Prove),
    ("fix", WorkflowPhase::Fix),
    ("fx", WorkflowPhase::Fix),
];

fn parse_direct_phase_command(verb: &str, args: &[&str], original: &str) -> Option<ShellCommand> {
    let phase = DIRECT_PHASE_COMMANDS
        .iter()
        .find_map(|(command, phase)| (*command == verb).then_some(*phase))?;
    if let Some(command) = parse_scan_since_command(verb, args) {
        return Some(command);
    }
    if args.is_empty() {
        return Some(ShellCommand::Phase(phase));
    }
    if matches!(verb, "review" | "rv") {
        return None;
    }
    Some(ShellCommand::Unknown(original.to_string()))
}

fn parse_scan_since_command(verb: &str, args: &[&str]) -> Option<ShellCommand> {
    if verb != "scan" {
        return None;
    }
    if let Some(command) = parse_scan_batch_command(args) {
        return Some(command);
    }
    let (reference, include_worktree) = match args {
        ["since", reference] => (*reference, false),
        ["since", reference, "--include-worktree"] => (*reference, true),
        _ => return None,
    };
    Some(ShellCommand::ScanSince {
        reference: reference.to_string(),
        include_worktree,
    })
}

fn parse_scan_batch_command(args: &[&str]) -> Option<ShellCommand> {
    match args {
        ["batch"] => Some(ShellCommand::ScanBatch { prior_run_id: None }),
        ["batch", "--prior-run", run_id] => Some(ShellCommand::ScanBatch {
            prior_run_id: Some((*run_id).to_string()),
        }),
        _ => None,
    }
}

fn parse_full_command(verb: &str, args: &[&str], original: &str) -> Option<ShellCommand> {
    if !matches!(verb, "full" | "pipeline") {
        return None;
    }
    Some(match args {
        [] => ShellCommand::Full(None),
        [target] => ShellCommand::Full(Some(PathBuf::from(target))),
        _ => ShellCommand::Unknown(original.to_string()),
    })
}

fn parse_help_command(verb: &str, args: &[&str]) -> Option<ShellCommand> {
    matches!(verb, "help" | "h" | "?").then(|| {
        let query = args
            .iter()
            .any(|arg| !arg.trim().is_empty())
            .then(|| args.join(" "));
        ShellCommand::Help(query)
    })
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
        "demo" => Some(ShellCommand::Demo),
        "help" | "h" | "?" => Some(ShellCommand::Help(None)),
        "back" | "b" => Some(ShellCommand::Back),
        "quit" | "exit" | "q" => Some(ShellCommand::Quit),
        "quit-confirm" => Some(ShellCommand::QuitConfirm),
        _ => None,
    }
}

fn parse_catalog_command(verb: &str) -> Option<ShellCommand> {
    match verb {
        "catalog" | "modules" | "m" => Some(ShellCommand::Modules),
        "recommend" | "rec" => Some(ShellCommand::Recommend),
        "tune" | "t" => Some(ShellCommand::Tune),
        "prompts" => Some(ShellCommand::Prompts),
        "tasks" => Some(ShellCommand::Tasks),
        "project" | "project-model" => Some(ShellCommand::ProjectModel),
        _ => None,
    }
}

fn parse_session_command(verb: &str) -> Option<ShellCommand> {
    match verb {
        "workbench" => Some(ShellCommand::Workbench),
        "report" => Some(ShellCommand::Report),
        "doctor" | "health" => Some(ShellCommand::Health),
        "cost" => Some(ShellCommand::Cost),
        "config" => Some(ShellCommand::Config),
        "permissions" => Some(ShellCommand::Permissions),
        "boot" | "boot-splash" => Some(ShellCommand::BootSplash),
        "theme" | "themes" => Some(ShellCommand::ThemePicker),
        "keys" | "keymap" => Some(ShellCommand::Keymap),
        "update" | "updates" | "changelog" => Some(ShellCommand::UpdateAvailable),
        "history" => Some(ShellCommand::History),
        "session" => Some(ShellCommand::SessionInfo),
        "clear" => Some(ShellCommand::Clear),
        "pause" => Some(ShellCommand::Pause),
        "cancel" | "c" | "stop" => Some(ShellCommand::Cancel),
        "story" => Some(ShellCommand::Story),
        "quickstart" => Some(ShellCommand::Quickstart),
        "setup" | "onboarding" | "planning" => Some(ShellCommand::Onboarding),
        "next" | "continue" => Some(ShellCommand::Next),
        "logs" | "log" | "transcript" => Some(ShellCommand::Logs),
        "answers" | "chat" => Some(ShellCommand::Answers),
        "background" | "bg" => Some(ShellCommand::Background),
        "activity" | "progress" | "a" => Some(ShellCommand::Activity),
        "scene" | "viz" => Some(ShellCommand::Scene),
        "worklist" => Some(ShellCommand::Worklist),
        "rail" | "sidebar" => Some(ShellCommand::Rail),
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
