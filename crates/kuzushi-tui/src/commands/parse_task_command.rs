use super::*;

pub(crate) fn parse_task_command(parts: Vec<&str>) -> ShellCommand {
    let Some(subcommand) = parts.first().copied() else {
        return ShellCommand::Unknown("task".to_string());
    };

    match subcommand {
        "block" | "deny" => parts
            .get(1)
            .map(|id| ShellCommand::Task(SastTaskCommand::Block((*id).to_string())))
            .unwrap_or_else(|| ShellCommand::Unknown("task block".to_string())),
        "allow" | "unblock" => parts
            .get(1)
            .map(|id| ShellCommand::Task(SastTaskCommand::Allow((*id).to_string())))
            .unwrap_or_else(|| ShellCommand::Unknown("task allow".to_string())),
        "toggle" => ShellCommand::Task(SastTaskCommand::Toggle(
            parts.get(1).map(|id| (*id).to_string()),
        )),
        "mode" => match parts.get(1).map(|mode| mode.to_ascii_lowercase()) {
            Some(mode) if mode == "auto" => {
                ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Auto))
            }
            Some(mode) if mode == "manual" => {
                ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Manual))
            }
            Some(mode) if mode == "toggle" => {
                ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Toggle))
            }
            _ => ShellCommand::Unknown("task mode".to_string()),
        },
        "reset" => ShellCommand::Task(SastTaskCommand::Reset),
        other => ShellCommand::Unknown(format!("task {other}")),
    }
}

pub(crate) fn parse_set_command(global: bool, parts: Vec<&str>) -> ShellCommand {
    if parts.is_empty() {
        return ShellCommand::Unknown(if global {
            "setg".to_string()
        } else {
            "set".to_string()
        });
    }

    let mut name = parts[0].to_string();
    let value = if let Some((lhs, rhs)) = parts[0].split_once('=') {
        name = lhs.to_string();
        let suffix = parts.get(1..).unwrap_or_default().join(" ");
        if suffix.is_empty() {
            rhs.to_string()
        } else {
            format!("{rhs} {suffix}")
        }
    } else if parts.len() >= 2 {
        parts[1..].join(" ")
    } else {
        String::new()
    };

    if name.trim().is_empty() || value.trim().is_empty() {
        return ShellCommand::Unknown(if global {
            "setg".to_string()
        } else {
            "set".to_string()
        });
    }

    ShellCommand::SetOption {
        global,
        name,
        value,
    }
}

pub(crate) fn parse_unset_command(global: bool, parts: Vec<&str>) -> ShellCommand {
    let Some(name) = parts.first().filter(|value| !value.trim().is_empty()) else {
        return ShellCommand::Unknown(if global {
            "unsetg".to_string()
        } else {
            "unset".to_string()
        });
    };

    ShellCommand::UnsetOption {
        global,
        name: (*name).to_string(),
    }
}
