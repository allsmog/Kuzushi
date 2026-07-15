use super::*;

pub(crate) fn parse_single_arg_command(
    verb: &str,
    args: &[&str],
    original: &str,
) -> Option<ShellCommand> {
    let first = args.first().copied();
    let command = match verb {
        "open" | "use" | "since" | "replay" | "trace" | "detach" | "reparse" => {
            parse_required_single_arg_command(verb, first, original)
        }
        "scan" | "provider" | "backend" | "resume" | "kb" | "attachments" | "files"
        | "file-picker" | "component" => parse_optional_single_arg_command(verb, first),
        "target" => parse_target_command(args, original),
        "actor" => parse_actor_command(first, original),
        "phase" => parse_phase_command(first, original),
        "autonomy" | "posture" => parse_autonomy_command(first, original),
        _ => return None,
    };
    Some(command)
}

fn parse_required_single_arg_command(
    verb: &str,
    first: Option<&str>,
    original: &str,
) -> ShellCommand {
    match verb {
        "open" => required_arg(first, original, ShellCommand::Open),
        "scan" => ShellCommand::Scan(first.map(PathBuf::from)),
        "use" => required_arg(first, original, ShellCommand::Use),
        "since" => required_arg(first, original, ShellCommand::Since),
        "replay" => required_arg(first, original, ShellCommand::Replay),
        "trace" => required_arg(first, original, ShellCommand::Trace),
        "detach" => required_arg(first, original, ShellCommand::Detach),
        "reparse" => required_arg(first, original, ShellCommand::Reparse),
        _ => ShellCommand::Unknown(original.to_string()),
    }
}

fn parse_optional_single_arg_command(verb: &str, first: Option<&str>) -> ShellCommand {
    match verb {
        "scan" => ShellCommand::Scan(first.map(PathBuf::from)),
        "provider" => ShellCommand::Provider(first.map(ToString::to_string)),
        "backend" => ShellCommand::Backend(first.map(ToString::to_string)),
        "target" => ShellCommand::Target(first.map(ToString::to_string)),
        "resume" => ShellCommand::Resume(first.map(ToString::to_string)),
        "kb" | "attachments" => ShellCommand::KnowledgeBase(first.map(ToString::to_string)),
        "files" | "file-picker" => ShellCommand::FilePicker,
        "component" => ShellCommand::Component(first.map(ToString::to_string)),
        _ => ShellCommand::Unknown(verb.to_string()),
    }
}

fn parse_target_command(args: &[&str], original: &str) -> ShellCommand {
    match args {
        [] => ShellCommand::Target(None),
        ["rev" | "revision" | "sha", reference] => {
            ShellCommand::TargetRevision((*reference).to_string())
        }
        ["rev" | "revision" | "sha"] => ShellCommand::Unknown(original.to_string()),
        [path, ..] => ShellCommand::Target(Some((*path).to_string())),
    }
}

fn parse_actor_command(first: Option<&str>, original: &str) -> ShellCommand {
    first
        .and_then(|value| value.parse::<usize>().ok())
        .map(ShellCommand::Actor)
        .unwrap_or_else(|| ShellCommand::Unknown(original.to_string()))
}

fn parse_phase_command(first: Option<&str>, original: &str) -> ShellCommand {
    first
        .and_then(WorkflowPhase::parse)
        .map(ShellCommand::Phase)
        .unwrap_or_else(|| ShellCommand::Unknown(original.to_string()))
}

/// `autonomy` / `posture` with no argument reads the current rung;
/// `autonomy <recon|scan|review|prove|fix>` sets it. An unrecognized rung is an
/// explicit error, never a silent no-op.
fn parse_autonomy_command(first: Option<&str>, original: &str) -> ShellCommand {
    match first {
        None => ShellCommand::Autonomy(None),
        Some(raw) => AutonomyPosture::parse(raw)
            .map(|posture| ShellCommand::Autonomy(Some(posture)))
            .unwrap_or_else(|| ShellCommand::Unknown(original.to_string())),
    }
}

pub(crate) fn required_arg(
    arg: Option<&str>,
    original: &str,
    build: impl FnOnce(String) -> ShellCommand,
) -> ShellCommand {
    arg.map(|value| build(value.to_string()))
        .unwrap_or_else(|| ShellCommand::Unknown(original.to_string()))
}
