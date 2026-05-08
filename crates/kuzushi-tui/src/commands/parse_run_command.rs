use super::*;

pub(crate) fn parse_run_command(parts: Vec<&str>) -> ShellCommand {
    if parts.is_empty() {
        return ShellCommand::RunTool {
            tool: None,
            input: None,
        };
    }

    let first = parts[0];
    if first == "." {
        return ShellCommand::RunTool {
            tool: None,
            input: if parts.len() > 1 {
                Some(parts[1..].join(" "))
            } else {
                None
            },
        };
    }

    if first.starts_with('{') || first.starts_with('[') {
        return ShellCommand::RunTool {
            tool: None,
            input: Some(parts.join(" ")),
        };
    }

    ShellCommand::RunTool {
        tool: Some(first.to_string()),
        input: if parts.len() > 1 {
            Some(parts[1..].join(" "))
        } else {
            None
        },
    }
}
