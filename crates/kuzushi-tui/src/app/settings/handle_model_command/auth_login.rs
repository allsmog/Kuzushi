use super::super::{
    auth_login_status_message, auth_provider_display_name, normalize_auth_method,
    normalize_auth_provider, oauth_credentials_path_display, pause_raw_mode_for_auth_login,
    repaint_after_auth_login, restore_raw_mode_after_auth_login, spawn_auth_login_process,
};
use super::*;

impl ShellApp {
    pub(crate) fn show_auth_status(&mut self) {
        // `/auth` now lands on the dedicated Auth surface
        // (`design/mockups/auth.jsx`) instead of the generic Config panel.
        self.shell_view = ShellView::Auth;
        let api_key_env = self.config.runtime.api_key_env.as_str();
        let env_status = if env::var_os(api_key_env).is_some() {
            "set"
        } else {
            "missing"
        };
        let anthropic_env = if env::var_os("ANTHROPIC_API_KEY").is_some() {
            "set"
        } else {
            "missing"
        };
        self.log(
            "auth",
            format!(
                "LangGraph auth: {api_key_env}={env_status}; ANTHROPIC_API_KEY={anthropic_env}; openai oauth {}; anthropic oauth {}; github-copilot oauth {}; secret values hidden. Next: auth login openai browser, auth login openai headless, auth login github-copilot",
                oauth_provider_status("openai-codex"),
                oauth_provider_status("anthropic"),
                oauth_provider_status("github-copilot")
            ),
        );
    }

    pub(crate) fn handle_auth_login_command(&mut self, provider: Option<String>) {
        self.shell_view = ShellView::Auth;
        let Some((provider, method)) = self.auth_login_provider_and_method(provider.as_deref())
        else {
            return;
        };
        self.auth_login = Some(AuthLoginView {
            provider: auth_provider_display_name(provider).to_string(),
            method: method.to_string(),
            status: "starting".to_string(),
            detail: auth_login_detail(provider, method).to_string(),
            store_path: oauth_credentials_path_display(),
        });
        self.log(
            "auth",
            format!(
                "starting {} OAuth login via {method}",
                auth_provider_display_name(provider),
            ),
        );

        let Some(command) = self.auth_login_bridge_command() else {
            return;
        };
        self.run_auth_login_process(provider, method, &command);
    }

    pub(crate) fn auth_login_provider_and_method(
        &mut self,
        input: Option<&str>,
    ) -> Option<(&'static str, &'static str)> {
        let mut parts = input.unwrap_or("openai").split_whitespace();
        let provider_input = parts.next().unwrap_or("openai");
        let method_input = parts.next();
        if let Some(extra) = parts.next() {
            self.log(
                "error",
                format!(
                    "unexpected auth login argument {extra:?}. Next: auth login openai browser"
                ),
            );
            return None;
        }
        let provider = match normalize_auth_provider(provider_input) {
            Ok(provider) => provider,
            Err(message) => {
                self.log("error", message);
                return None;
            }
        };
        match normalize_auth_method(provider, method_input) {
            Ok(method) => Some((provider, method)),
            Err(message) => {
                self.log("error", message);
                None
            }
        }
    }

    pub(crate) fn auth_login_bridge_command(&mut self) -> Option<Vec<String>> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let command = match LangGraphRuntime::from_config(&self.config, &cwd) {
            Ok(runtime) => runtime.command().to_vec(),
            Err(error) => {
                self.log("error", error.to_string());
                return None;
            }
        };
        self.non_empty_auth_login_bridge_command(command)
    }

    pub(crate) fn non_empty_auth_login_bridge_command(
        &mut self,
        command: Vec<String>,
    ) -> Option<Vec<String>> {
        if command.first().is_some() {
            return Some(command);
        }
        self.log("error", "LangGraph bridge command is empty");
        None
    }

    pub(crate) fn run_auth_login_process(
        &mut self,
        provider: &str,
        method: &str,
        command: &[String],
    ) {
        let Some(program) = command.first() else {
            self.log("error", "LangGraph bridge command is empty");
            return;
        };

        let raw_mode_was_disabled = pause_raw_mode_for_auth_login();
        if let Some(login) = &mut self.auth_login {
            login.status = "waiting".to_string();
        }
        let status = spawn_auth_login_process(program, &command[1..], provider, method);
        restore_raw_mode_after_auth_login(raw_mode_was_disabled);
        repaint_after_auth_login(&mut self.force_full_redraw);
        self.log_auth_login_status(provider, method, status);
    }

    pub(crate) fn log_auth_login_status(
        &mut self,
        provider: &str,
        method: &str,
        status: io::Result<std::process::ExitStatus>,
    ) {
        let success = status.as_ref().is_ok_and(std::process::ExitStatus::success);
        if let Some(login) = &mut self.auth_login {
            login.status = if success { "connected" } else { "failed" }.to_string();
            login.detail = if success {
                "credentials saved; values hidden".to_string()
            } else {
                "login did not complete; run auth status for details".to_string()
            };
        }
        let (prefix, message) = auth_login_status_message(provider, method, status);
        self.log(prefix, message);
    }
}

fn auth_login_detail(provider: &str, method: &str) -> &'static str {
    match (provider, method) {
        ("openai-codex", "headless") => "OpenAI device code flow",
        ("openai-codex", _) => "browser PKCE flow with localhost callback",
        ("anthropic", _) => "browser OAuth flow",
        ("github-copilot", _) => "GitHub device code flow",
        _ => "OAuth flow",
    }
}
