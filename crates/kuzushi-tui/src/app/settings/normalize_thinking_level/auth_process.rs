use super::*;

pub(crate) fn spawn_auth_login_process(
    program: &str,
    args: &[String],
    provider: &str,
    method: &str,
) -> io::Result<std::process::ExitStatus> {
    let suspension = crate::app::ExternalTerminalSuspension::begin().map_err(terminal_io_error)?;
    let mut command = ProcessCommand::new(program);
    command
        .args(args)
        .arg("--oauth-login")
        .arg(auth_login_process_provider_arg(provider));
    if !method.is_empty() {
        command.arg(method);
    }
    let status = command
        .stdin(Stdio::inherit()) // terminal-output: suspended child
        .stdout(Stdio::inherit()) // terminal-output: suspended child
        .stderr(Stdio::inherit()) // terminal-output: suspended child
        .status();
    suspension.resume().map_err(terminal_io_error)?;
    status
}

fn terminal_io_error(error: anyhow::Error) -> io::Error {
    io::Error::other(error.to_string())
}

pub(crate) fn repaint_after_auth_login(ui: &mut crate::app::UiPrefs) {
    if crate::app::terminal_guard_active() {
        let mut stdout = io::stdout();
        let _ = execute!(stdout, Clear(ClearType::All), MoveTo(0, 0));
    }
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
            format!(
                "{display_provider} OAuth login exited with {status}. {}",
                auth_login_failure_next_step()
            ),
        ),
        Err(error) => (
            "error",
            format!(
                "could not start {display_provider} OAuth login: {error}. {}",
                auth_login_failure_next_step()
            ),
        ),
    }
}

fn auth_login_failure_next_step() -> &'static str {
    "Next: choose API key, retry OAuth, move to Offline demo and press Enter, or run auth status"
}

pub(in crate::app) fn auth_provider_display_name(provider: &str) -> &str {
    auth_provider_label(provider)
}

pub(in crate::app) fn auth_login_process_provider_arg(provider: &str) -> &str {
    AuthProvider::from_scene_provider(provider)
        .map(AuthProvider::login_command_name)
        .unwrap_or(provider)
}

pub(crate) fn normalize_auth_provider(provider: &str) -> std::result::Result<&'static str, String> {
    AuthProvider::from_login_command(provider).map(AuthProvider::oauth_model_provider)
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
