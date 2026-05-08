use super::*;

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
