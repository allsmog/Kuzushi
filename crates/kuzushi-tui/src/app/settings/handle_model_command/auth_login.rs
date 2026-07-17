use super::super::{
    auth_login_status_message, auth_provider_display_name, normalize_auth_method,
    normalize_auth_provider, oauth_credentials_path_display, pause_raw_mode_for_auth_login,
    repaint_after_auth_login, restore_raw_mode_after_auth_login, spawn_auth_login_process,
};
use super::*;

impl ShellApp {
    pub(crate) fn reduce_auth_status(&mut self) -> Vec<ShellEffect> {
        if let Some(provider) = self
            .config()
            .model
            .as_deref()
            .and_then(|model| model.split(':').next())
            .map(str::to_string)
        {
            self.open_credential_entry(provider);
        } else {
            self.open_model_picker();
        }
        vec![ShellEffect::ShowAuthStatus(AuthStatusShow {
            api_key_env: self.config().runtime.api_key_env.clone(),
        })]
    }

    pub(crate) fn show_auth_status_effect(&mut self, show: AuthStatusShow) {
        let env_status = if env::var_os(&show.api_key_env).is_some() {
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
                "LangGraph auth: {}={env_status}; ANTHROPIC_API_KEY={anthropic_env}; openai oauth {}; anthropic oauth {}; github-copilot oauth {}; secret values hidden. Next: auth login openai browser, auth login openai headless, auth login github-copilot",
                show.api_key_env,
                oauth_provider_status("openai-codex"),
                oauth_provider_status("anthropic"),
                oauth_provider_status("github-copilot")
            ),
        );
    }

    pub(crate) fn reduce_auth_login_command(
        &mut self,
        provider: &Option<String>,
    ) -> Vec<ShellEffect> {
        self.reduce_auth_login(provider.as_deref(), false)
    }

    pub(crate) fn reduce_picker_auth_login(&mut self, provider: &str) -> Vec<ShellEffect> {
        let Some(provider) = AuthProvider::from_scene_provider(provider) else {
            self.log(
                "error",
                format!("unsupported onboarding auth provider {provider:?}"),
            );
            return Vec::new();
        };
        self.reduce_auth_login(Some(provider.login_command_name()), true)
    }

    fn reduce_auth_login(
        &mut self,
        provider: Option<&str>,
        continue_after_success: bool,
    ) -> Vec<ShellEffect> {
        self.set_shell_view(ShellView::Auth);
        let Some((provider, method)) = self.auth_login_provider_and_method(provider) else {
            return Vec::new();
        };
        self.router.auth_mut().set_login(AuthLoginView {
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
        vec![ShellEffect::AuthLogin(AuthLoginStart {
            provider: provider.to_string(),
            method: method.to_string(),
            continue_after_success,
        })]
    }

    pub(crate) fn start_auth_login_effect(&mut self, login: AuthLoginStart) -> Vec<ShellEffect> {
        let Some(command) = self.auth_login_bridge_command() else {
            return self.recover_from_missing_auth_login_bridge(&login.provider);
        };
        self.run_auth_login_process(&login.provider, &login.method, &command);
        if login.continue_after_success {
            return self.continue_after_picker_auth_login(&login.provider);
        }
        Vec::new()
    }

    /// `auth_login_bridge_command` already logged why the OAuth bridge is
    /// unavailable (missing binary, bad runtime config, …). Route back to
    /// the inline credential-entry step instead of stranding the operator on
    /// the read-only Auth view with no exit — the exact keyless dead-end
    /// this onboarding surface exists to remove.
    fn recover_from_missing_auth_login_bridge(&mut self, provider: &str) -> Vec<ShellEffect> {
        self.set_error_notice(
            "auth",
            "OAuth bridge unavailable — choose API key, retry OAuth after fixing the bridge, or move to Offline demo and press Enter",
        );
        self.open_credential_entry(provider.to_string());
        Vec::new()
    }

    fn continue_after_picker_auth_login(&mut self, provider: &str) -> Vec<ShellEffect> {
        if !auth_ready_for_provider(oauth_credential_provider_for_login(provider)) {
            // OAuth did not complete (operator cancelled the browser flow, or
            // it errored). Reopen the inline credential-entry step instead of
            // stranding them on the read-only Auth view — the reopen is
            // one-shot per Enter, and Esc always exits.
            self.report_incomplete_picker_oauth(provider);
            self.open_credential_entry(provider.to_string());
            return Vec::new();
        }
        let effects = self.select_oauth_model_for_provider(provider);
        self.transition_after_auth_ready();
        effects
    }

    fn report_incomplete_picker_oauth(&mut self, provider: &str) {
        let message = format!(
            "OAuth not completed for {} — choose API key, retry OAuth, or move to Offline demo and press Enter",
            auth_provider_label(provider)
        );
        let precise_failure_is_visible = self.advisory().notice.as_ref().is_some_and(|notice| {
            notice.source == "auth" && notice.severity == crate::app::NoticeSeverity::Error
        });
        if precise_failure_is_visible {
            self.log("onboarding", message);
        } else {
            self.set_error_notice("onboarding", message);
        }
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
        let command = match LangGraphRuntime::from_config(self.config(), &cwd) {
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
        if let Some(login) = self.router.auth_mut().login_mut() {
            login.status = "waiting".to_string();
        }
        let status = spawn_auth_login_process(program, &command[1..], provider, method);
        restore_raw_mode_after_auth_login(raw_mode_was_disabled);
        repaint_after_auth_login(self.ui_mut());
        self.log_auth_login_status(provider, method, status);
    }

    pub(crate) fn log_auth_login_status(
        &mut self,
        provider: &str,
        method: &str,
        status: io::Result<std::process::ExitStatus>,
    ) {
        let success = status.as_ref().is_ok_and(std::process::ExitStatus::success);
        if let Some(login) = self.router.auth_mut().login_mut() {
            login.status = if success { "connected" } else { "failed" }.to_string();
            login.detail = if success {
                "credentials saved; values hidden".to_string()
            } else {
                "login did not complete; run auth status for details".to_string()
            };
        }
        let (prefix, message) = auth_login_status_message(provider, method, status);
        if success {
            self.log(prefix, message);
        } else {
            self.set_error_notice("auth", message);
        }
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

fn oauth_credential_provider_for_login(provider: &str) -> &str {
    AuthProvider::from_scene_provider(provider)
        .map(AuthProvider::oauth_credential_key)
        .unwrap_or(provider)
}
