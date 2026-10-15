use super::*;

pub(crate) fn parse_joined_arg_command(
    verb: &str,
    args: &[&str],
    original: &str,
) -> Option<ShellCommand> {
    let rest = args.join(" ");
    let command = match verb {
        "model" | "mdl" => ShellCommand::Model((!rest.trim().is_empty()).then_some(rest)),
        "aim" => ShellCommand::Aim((!rest.trim().is_empty()).then_some(rest)),
        "tools" => ShellCommand::Tools(tools_query(&rest)),
        "find" => ShellCommand::Tools(tools_query(&rest)),
        "favorite" | "fav" => required_joined_arg(rest, original, ShellCommand::FavoriteTool),
        "prompt" => empty_joined_arg(rest, ShellCommand::Prompts, ShellCommand::Prompt),
        "plan" => parse_plan_command(args, rest, original),
        "ask" => return Some(parse_ask_command(args, original, false)),
        "attach" => empty_joined_arg(rest, ShellCommand::FilePicker, ShellCommand::Attach),
        "load" => ShellCommand::Load((!rest.trim().is_empty()).then_some(rest)),
        _ => return None,
    };
    Some(command)
}

/// `plan <phase>` opens that phase's planner explicitly; any other text is a
/// goal for the natural-language planner.
fn parse_plan_command(args: &[&str], rest: String, _original: &str) -> ShellCommand {
    let phase = match args {
        [word] => WorkflowPhase::parse(word),
        _ => None,
    };
    phase
        .map(ShellCommand::PhasePlanner)
        .unwrap_or_else(|| ShellCommand::Plan(rest))
}

/// Translate the `tools` argument into a `ToolQuery` string. A leading `--fav`
/// flag becomes the `fav:yes` query token so route state stays a single string.
pub(crate) fn tools_query(rest: &str) -> Option<String> {
    let trimmed = rest.trim();
    let query = match trimmed.strip_prefix("--fav") {
        Some(remainder) => format!("fav:yes {}", remainder.trim()).trim().to_string(),
        None => trimmed.to_string(),
    };
    (!query.is_empty()).then_some(query)
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
