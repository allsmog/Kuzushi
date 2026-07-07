use super::*;

pub(crate) fn parse_auth_command(args: &[&str]) -> ShellCommand {
    match args.first().copied() {
        None | Some("status") => ShellCommand::Auth,
        Some("login") => parse_auth_login_command(args),
        Some("openai") => ShellCommand::AuthLogin(Some("openai".to_string())),
        Some("codex" | "openai-codex") => legacy_openai_oauth_selector_command(),
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
        Some("codex" | "openai-codex") => legacy_openai_oauth_selector_command(),
        Some(_) => ShellCommand::AuthLogin(Some(args[1..].join(" "))),
        None => ShellCommand::AuthLogin(None),
    }
}

fn legacy_openai_oauth_selector_command() -> ShellCommand {
    ShellCommand::Unknown("auth legacy-openai-oauth".to_string())
}

pub(crate) fn parse_threat_command(args: &[&str]) -> ShellCommand {
    match args.first().copied() {
        None | Some("summary") | Some("4") => ShellCommand::Threat(ThreatView::Summary),
        Some("stride") | Some("1") => ShellCommand::Threat(ThreatView::Stride),
        Some("stories") | Some("2") => ShellCommand::Threat(ThreatView::Stories),
        Some("scope") | Some("3") => ShellCommand::Threat(ThreatView::Scope),
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
        Some("tools") => ShellCommand::Tools(join_query(args.get(1..).unwrap_or_default())),
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

fn join_query(args: &[&str]) -> Option<String> {
    let query = args.join(" ");
    (!query.trim().is_empty()).then_some(query)
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
        Some("reindex" | "index") => ShellCommand::Workspace(WorkspaceCommand::Reindex),
        Some("export") => match parts.get(1).copied() {
            Some("findings") => parse_workspace_findings_export_args(
                parts.get(2..).unwrap_or_default(),
                "workspace export findings",
            ),
            Some(other) => ShellCommand::Workspace(WorkspaceCommand::Unsupported(format!(
                "workspace export {other}"
            ))),
            None => ShellCommand::Unknown("workspace export".to_string()),
        },
        Some("scope") => match parts.get(1).copied() {
            Some("init") => ShellCommand::Workspace(WorkspaceCommand::ScopeInit),
            Some(other) => ShellCommand::Workspace(WorkspaceCommand::Unsupported(format!(
                "workspace scope {other}"
            ))),
            None => ShellCommand::Workspace(WorkspaceCommand::Unsupported(
                "workspace scope".to_string(),
            )),
        },
        Some("import") => ShellCommand::Workspace(WorkspaceCommand::Unsupported(
            "workspace import".to_string(),
        )),
        Some(other) => {
            ShellCommand::Workspace(WorkspaceCommand::Unsupported(format!("workspace {other}")))
        }
    }
}

pub(crate) fn parse_workspace_findings_export_args(
    args: &[&str],
    missing_label: &str,
) -> ShellCommand {
    let Some((output, format, completeness, allow_empty)) = workspace_findings_export_args(args)
    else {
        return ShellCommand::Unknown(missing_label.to_string());
    };
    ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
        output,
        format,
        completeness,
        allow_empty,
    })
}

fn workspace_findings_export_args(
    args: &[&str],
) -> Option<(PathBuf, Option<String>, Option<String>, bool)> {
    let mut output: Option<PathBuf> = None;
    let mut format: Option<String> = None;
    let mut completeness: Option<String> = None;
    let mut allow_empty = false;
    let mut index = 0;
    while index < args.len() {
        let consumed = apply_workspace_export_arg(
            args,
            index,
            &mut output,
            &mut format,
            &mut completeness,
            &mut allow_empty,
        )?;
        index += consumed;
    }
    output.map(|output| (output, format, completeness, allow_empty))
}

fn apply_workspace_export_arg(
    args: &[&str],
    index: usize,
    output: &mut Option<PathBuf>,
    format: &mut Option<String>,
    completeness: &mut Option<String>,
    allow_empty: &mut bool,
) -> Option<usize> {
    let token = args.get(index).copied()?;
    if apply_allow_empty_export_arg(token, allow_empty) {
        return Some(1);
    }
    if let Some(consumed) = apply_completeness_style_export_arg(args, index, token, completeness) {
        return Some(consumed);
    }
    apply_format_style_export_arg(args, index, token, format)
        .or_else(|| apply_positional_export_arg(args, token, output, format))
}

fn apply_allow_empty_export_arg(token: &str, allow_empty: &mut bool) -> bool {
    match token {
        "--allow-empty" | "allow-empty" | "allowEmpty" | "allow_empty" => {
            *allow_empty = true;
            true
        }
        _ => explicit_allow_empty_value(token).is_some_and(|value| {
            *allow_empty = value;
            true
        }),
    }
}

fn explicit_allow_empty_value(token: &str) -> Option<bool> {
    token
        .strip_prefix("--allow-empty=")
        .or_else(|| token.strip_prefix("allowEmpty="))
        .or_else(|| token.strip_prefix("allow_empty="))
        .and_then(parse_bool_token)
}

fn parse_bool_token(value: &str) -> Option<bool> {
    match value {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn apply_completeness_style_export_arg(
    args: &[&str],
    index: usize,
    token: &str,
    completeness: &mut Option<String>,
) -> Option<usize> {
    if let Some(value) = explicit_completeness_value(token) {
        *completeness = Some(value.to_string());
        return Some(1);
    }
    if workspace_export_completeness_flag(token) {
        *completeness = Some(args.get(index + 1).map(|value| (*value).to_string())?);
        return Some(2);
    }
    None
}

fn explicit_completeness_value(token: &str) -> Option<&str> {
    token
        .strip_prefix("--completeness=")
        .or_else(|| token.strip_prefix("completeness="))
        .or_else(|| token.strip_prefix("--scope="))
        .or_else(|| token.strip_prefix("scope="))
        .filter(|value| !value.trim().is_empty())
}

fn workspace_export_completeness_flag(token: &str) -> bool {
    matches!(
        token,
        "--completeness" | "completeness" | "--scope" | "scope"
    )
}

fn apply_format_style_export_arg(
    args: &[&str],
    index: usize,
    token: &str,
    format: &mut Option<String>,
) -> Option<usize> {
    if apply_explicit_format_token(token, format) {
        return Some(1);
    }
    if workspace_export_format_flag(token) {
        *format = args.get(index + 1).map(|value| (*value).to_string());
        return Some(2);
    }
    None
}

fn apply_positional_export_arg(
    args: &[&str],
    token: &str,
    output: &mut Option<PathBuf>,
    format: &mut Option<String>,
) -> Option<usize> {
    if apply_leading_format_token(args, token, output, format) {
        return Some(1);
    }
    if apply_output_token(token, output) {
        return Some(1);
    }
    if apply_trailing_format_token(token, format) {
        return Some(1);
    }
    None
}

fn apply_explicit_format_token(token: &str, format: &mut Option<String>) -> bool {
    explicit_format_value(token).is_some_and(|value| {
        *format = Some(value.to_string());
        true
    })
}

fn workspace_export_format_flag(token: &str) -> bool {
    matches!(token, "--format" | "format")
}

fn apply_leading_format_token(
    args: &[&str],
    token: &str,
    output: &Option<PathBuf>,
    format: &mut Option<String>,
) -> bool {
    output.is_none() && args.len() > 1 && apply_format_token(token, format)
}

fn apply_output_token(token: &str, output: &mut Option<PathBuf>) -> bool {
    if output.is_some() {
        return false;
    }
    *output = Some(PathBuf::from(token));
    true
}

fn apply_trailing_format_token(token: &str, format: &mut Option<String>) -> bool {
    format.is_none() && apply_format_token(token, format)
}

fn apply_format_token(token: &str, format: &mut Option<String>) -> bool {
    if !workspace_export_format_token(token) {
        return false;
    }
    *format = Some(token.to_string());
    true
}

fn explicit_format_value(token: &str) -> Option<&str> {
    token
        .strip_prefix("format=")
        .or_else(|| token.strip_prefix("--format="))
        .filter(|value| !value.trim().is_empty())
}

fn workspace_export_format_token(token: &str) -> bool {
    kuzushi_core::WorkspaceExportFormat::from_input(token).is_ok()
}
