use super::*;

pub(crate) fn parse_auth_command(args: &[&str]) -> ShellCommand {
    match args.first().copied() {
        None | Some("status") => ShellCommand::Auth,
        Some("login") => parse_auth_login_command(args),
        Some("openai") => ShellCommand::AuthLogin(Some("openai".to_string())),
        Some("anthropic") | Some("claude") => {
            ShellCommand::AuthLogin(Some("anthropic".to_string()))
        }
        Some("github-copilot") | Some("copilot") => {
            ShellCommand::AuthLogin(Some("github-copilot".to_string()))
        }
        Some(other) => ShellCommand::Unknown(format!("auth {other}")),
    }
}

fn parse_auth_login_command(args: &[&str]) -> ShellCommand {
    match args.get(1).copied() {
        Some("codex" | "openai-codex") => ShellCommand::Unknown(format!("auth login {}", args[1])),
        Some(_) => ShellCommand::AuthLogin(Some(args[1..].join(" "))),
        None => ShellCommand::AuthLogin(None),
    }
}

pub(crate) fn parse_threat_command(args: &[&str]) -> ShellCommand {
    match args.first().copied() {
        None | Some("summary") | Some("5") => ShellCommand::Threat(ThreatView::Summary),
        Some("dfd") | Some("1") => ShellCommand::Threat(ThreatView::Dfd),
        Some("stride") | Some("2") => ShellCommand::Threat(ThreatView::Stride),
        Some("stories") | Some("3") => ShellCommand::Threat(ThreatView::Stories),
        Some("scope") | Some("4") => ShellCommand::Threat(ThreatView::Scope),
        Some("edit") => ShellCommand::ThreatEditor,
        Some("regen") => ShellCommand::ThreatRegen,
        Some("apply") => ShellCommand::ThreatApply,
        Some("reject") | Some("discard") => ShellCommand::ThreatReject,
        Some("ask") => threat_ask_command(args),
        Some(other) => ShellCommand::Unknown(format!("/threats {other}")),
    }
}

pub(crate) fn threat_ask_command(args: &[&str]) -> ShellCommand {
    let rest = args.get(1..).unwrap_or_default().join(" ");
    if rest.trim().is_empty() {
        ShellCommand::Unknown("/threats ask".to_string())
    } else {
        ShellCommand::ThreatAsk(rest)
    }
}

pub(crate) fn parse_show_command(args: &[&str], original: &str) -> ShellCommand {
    match args.first().copied() {
        Some("modules") => ShellCommand::Modules,
        Some("tools") => ShellCommand::Tools,
        Some("runs") => ShellCommand::ShowRuns,
        Some("aliases") => ShellCommand::ShowAliases(args.get(1).map(|value| (*value).to_string())),
        Some("prompts") => ShellCommand::Prompts,
        Some("permissions") => ShellCommand::Permissions,
        Some("options") => options_command(&args[1..], OptionsFilter::Standard),
        Some("advanced") => options_command(&args[1..], OptionsFilter::Advanced),
        Some("missing") => options_command(&args[1..], OptionsFilter::Missing),
        Some(other) => ShellCommand::Unknown(format!("/show {other}")),
        None => ShellCommand::Unknown(original.to_string()),
    }
}

pub(crate) fn parse_context_command(parts: Vec<&str>) -> ShellCommand {
    match parts.first().copied() {
        None => ShellCommand::Context(ContextCommand::Show),
        Some("build") => ShellCommand::Context(ContextCommand::Build),
        Some("status") => ShellCommand::Context(ContextCommand::Status),
        Some("regen") => parts
            .get(1)
            .map(|slice| ShellCommand::Context(ContextCommand::Regen((*slice).to_string())))
            .unwrap_or_else(|| ShellCommand::Unknown("context regen".to_string())),
        Some(other) => ShellCommand::Unknown(format!("context {other}")),
    }
}

pub(crate) fn parse_workspace_command(parts: Vec<&str>) -> ShellCommand {
    match parts.first().copied() {
        None | Some("status") => ShellCommand::Workspace(WorkspaceCommand::Status),
        Some("export") => match parts.get(1).copied() {
            Some("findings") => parts
                .get(2)
                .map(|path| {
                    ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                        output: PathBuf::from(path),
                    })
                })
                .unwrap_or_else(|| ShellCommand::Unknown("workspace export findings".to_string())),
            Some(other) => ShellCommand::Workspace(WorkspaceCommand::Unsupported(format!(
                "workspace export {other}"
            ))),
            None => ShellCommand::Unknown("workspace export".to_string()),
        },
        Some("import") => ShellCommand::Workspace(WorkspaceCommand::Unsupported(
            "workspace import".to_string(),
        )),
        Some(other) => {
            ShellCommand::Workspace(WorkspaceCommand::Unsupported(format!("workspace {other}")))
        }
    }
}
