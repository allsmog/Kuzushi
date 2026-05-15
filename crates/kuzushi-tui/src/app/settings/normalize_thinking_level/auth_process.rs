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

pub(crate) fn repaint_after_auth_login(force_full_redraw: &mut bool) {
    let mut stdout = io::stdout();
    let _ = execute!(stdout, Clear(ClearType::All), MoveTo(0, 0));
    *force_full_redraw = true;
}

pub(in crate::app) fn auth_login_status_message(
    provider: &str,
    status: io::Result<std::process::ExitStatus>,
) -> (&'static str, String) {
    let display_provider = auth_provider_display_name(provider);
    match status {
        Ok(status) if status.success() => (
            "auth",
            format!(
                "{display_provider} OAuth stored at {}. Next: model {}",
                oauth_credentials_path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "~/.kuzushi/oauth-credentials.json".to_string()),
                if provider == "anthropic" { "5" } else { "3" }
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
        _ => provider,
    }
}

pub(crate) fn normalize_auth_provider(provider: &str) -> std::result::Result<&'static str, String> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "" | "openai" | "openai-codex" => Ok("openai-codex"),
        "anthropic" | "claude" => Ok("anthropic"),
        other => Err(format!(
            "unsupported auth login provider {other:?}. Supported: openai, anthropic. Next: auth login openai"
        )),
    }
}
