use std::path::PathBuf;

use crate::app::ThreatView;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellCommand {
    Help,
    Back,
    Modules,
    Tools,
    Findings,
    Open(String),
    Scan(Option<PathBuf>),
    Model(Option<String>),
    Config,
    Use(String),
    Tune,
    Threat(ThreatView),
    ThreatEditor,
    Prompts,
    Prompt(String),
    Actor(usize),
    ShowRuns,
    ShowAliases(Option<String>),
    Since(String),
    Replay(String),
    Trace(String),
    Plan(String),
    RunTool {
        tool: Option<String>,
        input: Option<String>,
    },
    Quit,
    Empty,
    Unknown(String),
}

pub fn parse_command(input: &str) -> ShellCommand {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return ShellCommand::Empty;
    }

    let normalized = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let mut parts = normalized.split_whitespace();
    let verb = parts.next().unwrap_or_default();

    match verb {
        "help" | "h" | "?" => ShellCommand::Help,
        "back" => ShellCommand::Back,
        "modules" => ShellCommand::Modules,
        "tools" => ShellCommand::Tools,
        "findings" | "f" => ShellCommand::Findings,
        "open" => parts
            .next()
            .map(|id| ShellCommand::Open(id.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "scan" => ShellCommand::Scan(parts.next().map(PathBuf::from)),
        "model" => ShellCommand::Model(parts.next().map(ToString::to_string)),
        "config" => ShellCommand::Config,
        "use" => parts
            .next()
            .map(|id| ShellCommand::Use(id.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "tune" | "t" => ShellCommand::Tune,
        "threats" => match parts.next() {
            None | Some("summary") | Some("5") => ShellCommand::Threat(ThreatView::Summary),
            Some("dfd") | Some("1") => ShellCommand::Threat(ThreatView::Dfd),
            Some("stride") | Some("2") => ShellCommand::Threat(ThreatView::Stride),
            Some("stories") | Some("3") => ShellCommand::Threat(ThreatView::Stories),
            Some("scope") | Some("4") => ShellCommand::Threat(ThreatView::Scope),
            Some("edit") => ShellCommand::ThreatEditor,
            Some(other) => ShellCommand::Unknown(format!("/threats {other}")),
        },
        "prompts" => ShellCommand::Prompts,
        "prompt" => {
            let rest = parts.collect::<Vec<_>>().join(" ");
            if rest.is_empty() {
                ShellCommand::Prompts
            } else {
                ShellCommand::Prompt(rest)
            }
        }
        "actor" => parts
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .map(ShellCommand::Actor)
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "show" => match parts.next() {
            Some("runs") => ShellCommand::ShowRuns,
            Some("aliases") => ShellCommand::ShowAliases(parts.next().map(ToString::to_string)),
            Some("prompts") => ShellCommand::Prompts,
            Some(other) => ShellCommand::Unknown(format!("/show {other}")),
            None => ShellCommand::Unknown(trimmed.to_string()),
        },
        "since" => parts
            .next()
            .map(|reference| ShellCommand::Since(reference.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "replay" => parts
            .next()
            .map(|run_id| ShellCommand::Replay(run_id.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "trace" => parts
            .next()
            .map(|run_id| ShellCommand::Trace(run_id.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "plan" => {
            let rest = parts.collect::<Vec<_>>().join(" ");
            if rest.is_empty() {
                ShellCommand::Unknown(trimmed.to_string())
            } else {
                ShellCommand::Plan(rest)
            }
        }
        "run" => parse_run_command(parts.collect::<Vec<_>>()),
        "quit" | "exit" | "q" => ShellCommand::Quit,
        _ => ShellCommand::Unknown(trimmed.to_string()),
    }
}

fn parse_run_command(parts: Vec<&str>) -> ShellCommand {
    if parts.is_empty() {
        return ShellCommand::RunTool {
            tool: None,
            input: None,
        };
    }

    let first = parts[0];
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kept_commands() {
        assert_eq!(parse_command("/modules"), ShellCommand::Modules);
        assert_eq!(parse_command("/tools"), ShellCommand::Tools);
        assert_eq!(parse_command("/findings"), ShellCommand::Findings);
        assert_eq!(
            parse_command("/threats stride"),
            ShellCommand::Threat(ThreatView::Stride)
        );
        assert_eq!(parse_command("/prompts"), ShellCommand::Prompts);
        assert_eq!(
            parse_command("/open abc123"),
            ShellCommand::Open("abc123".to_string())
        );
        assert_eq!(
            parse_command("/scan ./repo"),
            ShellCommand::Scan(Some(PathBuf::from("./repo")))
        );
        assert_eq!(
            parse_command("/model openai:gpt-4.1"),
            ShellCommand::Model(Some("openai:gpt-4.1".to_string()))
        );
        assert_eq!(
            parse_command("/run dep-hygiene:check {\"target\":\".\"}"),
            ShellCommand::RunTool {
                tool: Some("dep-hygiene:check".to_string()),
                input: Some("{\"target\":\".\"}".to_string())
            }
        );
    }

    #[test]
    fn accepts_commands_without_slash_for_log_prompt() {
        assert_eq!(parse_command("help"), ShellCommand::Help);
        assert_eq!(parse_command("q"), ShellCommand::Quit);
    }
}
