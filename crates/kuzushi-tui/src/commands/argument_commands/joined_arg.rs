use super::*;

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
