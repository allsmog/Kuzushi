use super::prelude::*;
use super::*;

pub(crate) fn parse_single_arg_command(
    verb: &str,
    args: &[&str],
    original: &str,
) -> Option<ShellCommand> {
    let first = args.first().copied();
    let command = match verb {
        "open" => required_arg(first, original, ShellCommand::Open),
        "scan" => ShellCommand::Scan(first.map(PathBuf::from)),
        "provider" => ShellCommand::Provider(first.map(ToString::to_string)),
        "backend" => ShellCommand::Backend(first.map(ToString::to_string)),
        "use" => required_arg(first, original, ShellCommand::Use),
        "actor" => first
            .and_then(|value| value.parse::<usize>().ok())
            .map(ShellCommand::Actor)
            .unwrap_or_else(|| ShellCommand::Unknown(original.to_string())),
        "since" => required_arg(first, original, ShellCommand::Since),
        "replay" => required_arg(first, original, ShellCommand::Replay),
        "trace" => required_arg(first, original, ShellCommand::Trace),
        "target" => ShellCommand::Target(first.map(ToString::to_string)),
        "detach" => required_arg(first, original, ShellCommand::Detach),
        "reparse" => required_arg(first, original, ShellCommand::Reparse),
        "resume" => ShellCommand::Resume(first.map(ToString::to_string)),
        "kb" | "attachments" => ShellCommand::KnowledgeBase(first.map(ToString::to_string)),
        _ => return None,
    };
    Some(command)
}

pub(crate) fn required_arg(
    arg: Option<&str>,
    original: &str,
    build: impl FnOnce(String) -> ShellCommand,
) -> ShellCommand {
    arg.map(|value| build(value.to_string()))
        .unwrap_or_else(|| ShellCommand::Unknown(original.to_string()))
}

pub(crate) fn parse_joined_arg_command(
    verb: &str,
    args: &[&str],
    original: &str,
) -> Option<ShellCommand> {
    let rest = args.join(" ");
    let command = match verb {
        "model" => ShellCommand::Model((!rest.trim().is_empty()).then_some(rest)),
        "prompt" => empty_joined_arg(rest, ShellCommand::Prompts, ShellCommand::Prompt),
        "plan" => required_joined_arg(rest, original, ShellCommand::Plan),
        "ask" => required_joined_arg(rest, original, ShellCommand::Ask),
        "attach" => required_joined_arg(rest, original, ShellCommand::Attach),
        "load" => ShellCommand::Load((!rest.trim().is_empty()).then_some(rest)),
        _ => return None,
    };
    Some(command)
}

pub(crate) fn empty_joined_arg(
    rest: String,
    empty: ShellCommand,
    build: impl FnOnce(String) -> ShellCommand,
) -> ShellCommand {
    if rest.is_empty() {
        empty
    } else {
        build(rest)
    }
}

pub(crate) fn required_joined_arg(
    rest: String,
    original: &str,
    build: impl FnOnce(String) -> ShellCommand,
) -> ShellCommand {
    if rest.is_empty() {
        ShellCommand::Unknown(original.to_string())
    } else {
        build(rest)
    }
}

pub(crate) fn parse_nested_shell_command(
    verb: &str,
    args: &[&str],
    original: &str,
) -> Option<ShellCommand> {
    let command = match verb {
        "options" => options_command(args, OptionsFilter::Standard),
        "findings" | "f" => parse_findings_command(args),
        "auth" => parse_auth_command(args),
        "threats" => parse_threat_command(args),
        "show" => parse_show_command(args, original),
        "run" => parse_run_command(args.to_vec()),
        "set" => parse_set_command(false, args.to_vec()),
        "setg" => parse_set_command(true, args.to_vec()),
        "unset" => parse_unset_command(false, args.to_vec()),
        "unsetg" => parse_unset_command(true, args.to_vec()),
        "task" => parse_task_command(args.to_vec()),
        "context" => parse_context_command(args.to_vec()),
        "workspace" => parse_workspace_command(args.to_vec()),
        _ => return None,
    };
    Some(command)
}

pub(crate) fn options_command(args: &[&str], filter: OptionsFilter) -> ShellCommand {
    ShellCommand::Options {
        tool: args.first().map(|value| (*value).to_string()),
        filter,
    }
}

pub(crate) fn parse_findings_command(args: &[&str]) -> ShellCommand {
    match args.first().copied() {
        Some("export") => args
            .get(1)
            .map(|path| {
                ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                    output: PathBuf::from(path),
                })
            })
            .unwrap_or_else(|| ShellCommand::Unknown("findings export".to_string())),
        Some(other) => ShellCommand::Unknown(format!("findings {other}")),
        None => ShellCommand::Findings,
    }
}
