use super::prelude::*;
use super::*;

pub(super) fn resolve_model_selector(selector: &str) -> Option<&'static ModelChoice> {
    let key = selector.trim().to_ascii_lowercase().replace('_', "-");
    match key.as_str() {
        "1" | "gpt-5.5" | "5.5" | "openai:gpt-5.5" => MODEL_CHOICES.get(0),
        "2" | "gpt-5.5-mini" | "5.5-mini" | "mini" | "openai:gpt-5.5-mini" => MODEL_CHOICES.get(1),
        "3" | "codex:gpt-5.5" | "openai-codex:gpt-5.5" | "codex-5.5" => MODEL_CHOICES.get(2),
        "4" | "codex:gpt-5.5-mini" | "openai-codex:gpt-5.5-mini" | "codex-mini" => {
            MODEL_CHOICES.get(3)
        }
        "5" | "sonnet" | "claude-sonnet" | "claude-sonnet-4-6" | "anthropic:claude-sonnet-4-6" => {
            MODEL_CHOICES.get(4)
        }
        "6" | "opus" | "claude-opus" | "claude-opus-4-7" | "anthropic:claude-opus-4-7" => {
            MODEL_CHOICES.get(5)
        }
        _ => None,
    }
}

pub(crate) fn normalize_thinking_level(value: &str) -> Option<&'static str> {
    let normalized = value
        .trim()
        .to_ascii_lowercase()
        .replace(['_', '-', ' '], "");
    match normalized.as_str() {
        "low" => Some("low"),
        "medium" | "med" => Some("medium"),
        "high" => Some("high"),
        "xhigh" | "xtrahigh" | "extrahigh" => Some("xhigh"),
        _ => None,
    }
}

pub(super) fn pause_raw_mode_for_auth_login() -> bool {
    disable_raw_mode().is_ok()
}

pub(super) fn restore_raw_mode_after_auth_login(raw_mode_was_disabled: bool) {
    if raw_mode_was_disabled {
        let _ = enable_raw_mode();
    }
}

pub(super) fn spawn_auth_login_process(
    program: &str,
    args: &[String],
    provider: &str,
) -> io::Result<std::process::ExitStatus> {
    ProcessCommand::new(program)
        .args(args)
        .arg("--oauth-login")
        .arg(provider)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
}

pub(super) fn repaint_after_auth_login(force_full_redraw: &mut bool) {
    let mut stdout = io::stdout();
    let _ = execute!(stdout, Clear(ClearType::All), MoveTo(0, 0));
    *force_full_redraw = true;
}

pub(in crate::app) fn auth_login_status_message(
    provider: &str,
    status: io::Result<std::process::ExitStatus>,
) -> (&'static str, String) {
    match status {
        Ok(status) if status.success() => (
            "auth",
            format!(
                "{provider} OAuth stored at {}. Next: model {}",
                oauth_credentials_path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "~/.kuzushi/oauth-credentials.json".to_string()),
                if provider == "anthropic" { "5" } else { "3" }
            ),
        ),
        Ok(status) => (
            "error",
            format!("{provider} OAuth login exited with {status}. Next: auth status"),
        ),
        Err(error) => (
            "error",
            format!("could not start {provider} OAuth login: {error}. Next: auth status"),
        ),
    }
}

pub(super) fn normalize_auth_provider(provider: &str) -> std::result::Result<&'static str, String> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "" | "openai-codex" | "codex" => Ok("openai-codex"),
        "anthropic" | "claude" => Ok("anthropic"),
        other => Err(format!(
            "unsupported auth login provider {other:?}. Supported: openai-codex, anthropic. Next: auth login openai-codex"
        )),
    }
}

pub(super) fn oauth_credentials_path() -> Option<PathBuf> {
    env::var_os("HOME").map(|home| PathBuf::from(home).join(".kuzushi/oauth-credentials.json"))
}

pub(crate) fn oauth_provider_status(provider: &str) -> String {
    let Some(path) = oauth_credentials_path() else {
        return "missing".to_string();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return "missing".to_string();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return "unreadable".to_string();
    };
    let Some(entry) = json.get(provider) else {
        return "missing".to_string();
    };
    if entry
        .get("access")
        .and_then(serde_json::Value::as_str)
        .is_some()
        && entry
            .get("refresh")
            .and_then(serde_json::Value::as_str)
            .is_some()
    {
        "stored; value hidden".to_string()
    } else {
        "incomplete".to_string()
    }
}

pub(crate) fn thinking_level_from_input(input: &serde_json::Value) -> Option<String> {
    ["thinkingLevel", "reasoningEffort", "effort"]
        .iter()
        .find_map(|key| input.get(*key).and_then(serde_json::Value::as_str))
        .and_then(normalize_thinking_level)
        .map(ToString::to_string)
}

pub(crate) fn runtime_backend_label(config: &V2Config) -> &'static str {
    match config.runtime.kind {
        RuntimeKind::PiAgentCore => "pi-agent-core",
    }
}

pub(crate) fn bridge_command_status(config: &V2Config) -> &'static str {
    if config
        .runtime
        .agent_bridge_command
        .as_ref()
        .is_some_and(|command| !command.is_empty())
    {
        "configured"
    } else {
        "bundled/default"
    }
}
