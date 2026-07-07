use super::*;

pub(crate) fn pause_raw_mode_for_auth_login() -> bool {
    disable_raw_mode().is_ok()
}

pub(crate) fn restore_raw_mode_after_auth_login(raw_mode_was_disabled: bool) {
    if raw_mode_was_disabled {
        let _ = enable_raw_mode();
    }
}

pub(crate) fn spawn_auth_login_process(
    program: &str,
    args: &[String],
    provider: &str,
    method: &str,
) -> io::Result<std::process::ExitStatus> {
    let mut command = ProcessCommand::new(program);
    command
        .args(args)
        .arg("--oauth-login")
        .arg(auth_login_process_provider_arg(provider));
    if !method.is_empty() {
        command.arg(method);
    }
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
}

pub(crate) fn repaint_after_auth_login(ui: &mut crate::app::UiPrefs) {
    let mut stdout = io::stdout();
    let _ = execute!(stdout, Clear(ClearType::All), MoveTo(0, 0));
    ui.request_full_redraw();
}

pub(in crate::app) fn auth_login_status_message(
    provider: &str,
    method: &str,
    status: io::Result<std::process::ExitStatus>,
) -> (&'static str, String) {
    let display_provider = auth_provider_display_name(provider);
    let method_suffix = if method.is_empty() {
        String::new()
    } else {
        format!(" via {method}")
    };
    match status {
        Ok(status) if status.success() => (
            "auth",
            format!(
                "{display_provider} OAuth{method_suffix} stored at {}. Next: {}",
                oauth_credentials_path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(default_oauth_credentials_path_display),
                auth_login_next_step(provider),
            ),
        ),
        Ok(status) => (
            "error",
            format!("{display_provider} OAuth login exited with {status}. Next: auth status"),
        ),
        Err(error) => (
            "error",
            format!("could not start {display_provider} OAuth login: {error}. Next: auth status"),
        ),
    }
}

pub(in crate::app) fn auth_provider_display_name(provider: &str) -> &str {
    match provider {
        "openai-codex" => "openai",
        "github-copilot" => "github-copilot",
        _ => provider,
    }
}

pub(in crate::app) fn auth_login_process_provider_arg(provider: &str) -> &str {
    match provider {
        "openai-codex" => "openai",
        _ => provider,
    }
}

pub(crate) fn normalize_auth_provider(provider: &str) -> std::result::Result<&'static str, String> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "" | "openai" => Ok("openai-codex"),
        "anthropic" | "claude" => Ok("anthropic"),
        "github-copilot" | "copilot" => Ok("github-copilot"),
        other => Err(format!(
            "unsupported auth login provider {other:?}. Supported: openai, anthropic, github-copilot. Next: auth login openai browser"
        )),
    }
}

pub(crate) fn normalize_auth_method(
    provider: &str,
    method: Option<&str>,
) -> std::result::Result<&'static str, String> {
    let normalized = method.unwrap_or("").trim().to_ascii_lowercase();
    match (provider, normalized.as_str()) {
        ("openai-codex", "" | "browser") => Ok("browser"),
        ("openai-codex", "headless" | "device") => Ok("headless"),
        ("anthropic", "" | "browser") => Ok("browser"),
        ("github-copilot", "" | "device" | "headless") => Ok("device"),
        ("github-copilot", "browser") => Ok("device"),
        (_, other) => Err(format!(
            "unsupported auth login method {other:?} for {}. Next: auth login openai browser, auth login openai headless, auth login anthropic, or auth login github-copilot",
            auth_provider_display_name(provider)
        )),
    }
}

fn auth_login_next_step(provider: &str) -> String {
    crate::app::model_choices()
        .iter()
        .find(|choice| choice.provider == provider)
        .map(|choice| {
            let selector = crate::app::display_model_selector(choice.id);
            format!("model {} ({selector})", choice.index)
        })
        .unwrap_or_else(|| "auth status".to_string())
}
