use super::super::{
    auth_login_status_message, auth_provider_display_name, incomplete_auth_login_message,
    normalize_auth_method, normalize_auth_provider, oauth_credentials_path_display,
    repaint_after_auth_login, spawn_auth_login_process,
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
        let env_status = if env_credential_is_ready(&show.api_key_env) {
            "set"
        } else {
            "missing"
        };
        let anthropic_env = if env_credential_is_ready("ANTHROPIC_API_KEY") {
            "set"
        } else {
            "missing"
        };
        self.log(
            "auth",
            format!(
                "LangGraph auth: {}={env_status}; ANTHROPIC_API_KEY={anthropic_env}; openai oauth {}; anthropic oauth {}; github-copilot oauth {}; secret values hidden. Next: auth login openai browser, auth login openai headless, auth login github-copilot",
                show.api_key_env,
                oauth_provider_status(self.config(), "openai-codex").label(),
                oauth_provider_status(self.config(), "anthropic").label(),
                oauth_provider_status(self.config(), "github-copilot").label()
            ),
        );
    }

    pub(crate) fn reduce_auth_login_command(
        &mut self,
        provider: &Option<String>,
    ) -> Vec<ShellEffect> {
        self.reduce_auth_login(provider.as_deref(), None)
    }

    pub(crate) fn reduce_picker_auth_login(&mut self, provider: &str) -> Vec<ShellEffect> {
        let scene_provider = provider;
        let Some(provider) = AuthProvider::from_scene_provider(scene_provider) else {
            self.log(
                "error",
                format!("unsupported onboarding auth provider {scene_provider:?}"),
            );
            return Vec::new();
        };
        let continuation = PickerAuthContinuation {
            credential_provider: scene_provider.to_string(),
            model_switch: oauth_model_switch_for_provider(scene_provider),
        };
        self.reduce_auth_login(Some(provider.login_command_name()), Some(continuation))
    }

    fn reduce_auth_login(
        &mut self,
        provider: Option<&str>,
        picker_continuation: Option<PickerAuthContinuation>,
    ) -> Vec<ShellEffect> {
        let Some((provider, method)) = self.auth_login_provider_and_method(provider) else {
            return Vec::new();
        };
        let origin = self.auth_login_origin();
        self.set_shell_view(ShellView::Auth);
        let store_path = oauth_credentials_path_display(self.config());
        self.router.auth_mut().set_login(AuthLoginView {
            provider: auth_provider_display_name(provider).to_string(),
            method: method.to_string(),
            status: "starting".to_string(),
            detail: auth_login_detail(provider, method).to_string(),
            store_path,
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
            picker_continuation,
            origin,
        })]
    }

    pub(crate) fn start_auth_login_effect(&mut self, login: AuthLoginStart) -> Vec<ShellEffect> {
        let recovery_provider = login
            .picker_continuation
            .as_ref()
            .map(|continuation| continuation.credential_provider.as_str())
            .unwrap_or(login.provider.as_str())
            .to_string();
        let Some(command) = self.auth_login_bridge_command() else {
            return self.recover_from_missing_auth_login_bridge(&recovery_provider);
        };
        let reconnect_required = self.pending_oauth_reconnect_required();
        let api_key_available = auth_picker_allows_api_key(&recovery_provider);
        let login_succeeded = self.run_auth_login_process(
            &login.provider,
            &login.method,
            &command,
            reconnect_required,
            api_key_available,
        );
        let Some(continuation) = login.picker_continuation else {
            self.restore_auth_login_origin(login.origin);
            return Vec::new();
        };
        self.continue_after_picker_auth_login(&login.provider, continuation, login_succeeded)
    }

    fn auth_login_origin(&self) -> AuthLoginOrigin {
        let view = self.shell_view();
        if contextual_surface_view(view) {
            return AuthLoginOrigin {
                view: self.router.overlay_origin().unwrap_or(view),
                input_mode: self
                    .router
                    .overlay_input_mode()
                    .unwrap_or(self.input_mode()),
            };
        }
        AuthLoginOrigin {
            view,
            input_mode: self.input_mode(),
        }
    }

    fn restore_auth_login_origin(&mut self, origin: AuthLoginOrigin) {
        self.set_shell_view(origin.view);
        self.set_input_mode(origin.input_mode);
        self.router
            .navigation_mut()
            .accept_back_transition(origin.view);
    }

    /// `auth_login_bridge_command` already logged why the OAuth bridge is
    /// unavailable (missing binary, bad runtime config, …). Route back to
    /// the inline credential-entry step instead of stranding the operator on
    /// the read-only Auth view with no exit — the exact keyless dead-end
    /// this onboarding surface exists to remove.
    fn recover_from_missing_auth_login_bridge(&mut self, provider: &str) -> Vec<ShellEffect> {
        let recovering_plan = self.engagement.pending_credential_continuation().is_some();
        let api_key_available = auth_picker_allows_api_key(provider);
        let message = match (recovering_plan, api_key_available) {
            (true, true) => "OAuth login unavailable · choose API key, retry OAuth after fixing authentication, or press Esc to return to the preserved Scan",
            (true, false) => "OAuth login unavailable · retry after fixing authentication, or press Esc to return to the preserved Scan",
            (false, true) => "OAuth login unavailable · choose API key, retry OAuth after fixing authentication, or move to Offline demo and press Enter",
            (false, false) => "OAuth login unavailable · retry OAuth after fixing authentication, or move to Offline demo and press Enter",
        };
        self.set_error_notice("auth", message);
        if recovering_plan {
            self.open_credential_recovery(provider.to_string());
        } else {
            self.open_credential_entry(provider.to_string());
        }
        Vec::new()
    }

    fn continue_after_picker_auth_login(
        &mut self,
        oauth_provider: &str,
        continuation: PickerAuthContinuation,
        login_succeeded: bool,
    ) -> Vec<ShellEffect> {
        let credential_provider = oauth_credential_provider_for_login(oauth_provider);
        if !login_succeeded || !oauth_credential_is_ready(self.config(), credential_provider) {
            // OAuth did not complete (operator cancelled the browser flow, or
            // it errored). Reopen the inline credential-entry step instead of
            // stranding them on the read-only Auth view — the reopen is
            // one-shot per Enter, and Esc always exits.
            self.report_incomplete_picker_oauth(&continuation.credential_provider);
            self.reopen_picker_after_auth_login(&continuation.credential_provider);
            return Vec::new();
        }
        let Some(mut model_effects) = self.apply_auth_model_switch(continuation.model_switch)
        else {
            self.reopen_picker_after_auth_login(&continuation.credential_provider);
            return Vec::new();
        };
        let mut effects = self.select_oauth_transport_effects(&continuation.credential_provider);
        effects.append(&mut model_effects);
        self.engagement.satisfy_pending_credential_requirement();
        effects.extend(self.transition_after_auth_ready());
        effects
    }

    fn reopen_picker_after_auth_login(&mut self, provider: &str) {
        if self.engagement.pending_credential_continuation().is_some() {
            self.open_credential_recovery(provider.to_string());
        } else {
            self.open_credential_entry(provider.to_string());
        }
    }

    pub(crate) fn apply_auth_model_switch(
        &mut self,
        selection: Option<AuthModelSwitch>,
    ) -> Option<Vec<ShellEffect>> {
        let Some(selection) = selection else {
            return Some(Vec::new());
        };
        if !self.pending_auth_switch_context_is_current() {
            self.set_error_notice(
                "planning",
                "The target or model changed while authentication was open; review the Scan before continuing.",
            );
            return None;
        }
        if self.pending_auth_switch_is_step_scoped() {
            return self.apply_step_auth_model_switch(&selection);
        }
        self.apply_global_auth_model_switch(selection)
    }

    fn apply_step_auth_model_switch(
        &mut self,
        selection: &AuthModelSwitch,
    ) -> Option<Vec<ShellEffect>> {
        if !self
            .engagement
            .retarget_pending_credential_model(&selection.model)
        {
            self.set_error_notice(
                "planning",
                "The paused step changed while authentication was open; review it before continuing.",
            );
            return None;
        }
        self.log(
            "model",
            format!(
                "paused step explicitly switched to {}; global model unchanged",
                display_model_selector(&selection.model)
            ),
        );
        Some(Vec::new())
    }

    fn apply_global_auth_model_switch(
        &mut self,
        selection: AuthModelSwitch,
    ) -> Option<Vec<ShellEffect>> {
        let has_pending = self.engagement.pending_credential_continuation().is_some();
        if has_pending
            && !self
                .engagement
                .retarget_pending_credential_model(&selection.model)
        {
            self.set_error_notice(
                "planning",
                "The preserved Scan changed while authentication was open; review it before continuing.",
            );
            return None;
        }
        let changed = self.config().model.as_deref() != Some(selection.model.as_str())
            || self.session_thinking_level() != Some(selection.thinking_level.as_str());
        self.config_mut().model = Some(selection.model.clone());
        self.set_session_thinking_level(Some(selection.thinking_level.clone()));
        self.log(
            "model",
            format!(
                "{} selected by the explicit OpenAI OAuth action (no fallback model)",
                display_model_selector(&selection.model)
            ),
        );
        Some(model_switch_persist_effects(&selection, changed))
    }

    pub(crate) fn pending_auth_switch_is_step_scoped(&self) -> bool {
        self.engagement
            .pending_credential_continuation()
            .is_some_and(|pending| {
                pending.model_binding == PendingCredentialModelBinding::DeferredStepInput
            })
    }

    fn pending_auth_switch_context_is_current(&self) -> bool {
        let Some(pending) = self.engagement.pending_credential_continuation() else {
            return true;
        };
        if self.target_owned().as_ref() != Some(&pending.target) {
            return false;
        }
        pending.model_binding != PendingCredentialModelBinding::Config
            || self.config().model.as_deref() == Some(pending.model.as_str())
    }

    pub(crate) fn pending_api_key_replacement_required(&self) -> bool {
        self.engagement
            .pending_credential_continuation()
            .is_some_and(|pending| {
                pending.credential_requirement == PendingCredentialRequirement::ReplaceApiKey
            })
    }

    pub(crate) fn pending_oauth_reconnect_required(&self) -> bool {
        self.engagement
            .pending_credential_continuation()
            .is_some_and(|pending| {
                pending.credential_requirement == PendingCredentialRequirement::ReconnectOauth
            })
    }

    fn report_incomplete_picker_oauth(&mut self, provider: &str) {
        let label = auth_provider_label(provider);
        let recovering_plan = self.engagement.pending_credential_continuation().is_some();
        let api_key_available = auth_picker_allows_api_key(provider);
        let next = match (recovering_plan, api_key_available) {
            (true, true) => {
                "choose API key, retry OAuth, or press Esc to return to the preserved Scan"
            }
            (true, false) => "retry OAuth, or press Esc to return to the preserved Scan",
            (false, true) => "choose API key, retry OAuth, or move to Offline demo and press Enter",
            (false, false) => "retry OAuth, or move to Offline demo and press Enter",
        };
        let message = format!("OAuth not completed for {label} · {next}");
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
        reconnect_required: bool,
        api_key_available: bool,
    ) -> bool {
        let Some(program) = command.first() else {
            self.log("error", "LangGraph bridge command is empty");
            return false;
        };

        if let Some(login) = self.router.auth_mut().login_mut() {
            login.status = "waiting".to_string();
        }
        let Some(credentials_path) = oauth_credentials_path(self.config()) else {
            self.set_error_notice(
                "auth",
                "could not resolve the configured OAuth credential path",
            );
            return false;
        };
        let previous_revision = reconnect_required
            .then(|| oauth_provider_revision(self.config(), provider))
            .flatten();
        let status =
            spawn_auth_login_process(program, &command[1..], provider, method, &credentials_path);
        let attempt = AuthLoginAttempt {
            credential_ready: oauth_credential_is_ready(self.config(), provider),
            credential_replaced: !reconnect_required
                || previous_revision != oauth_provider_revision(self.config(), provider),
            api_key_available,
            status,
        };
        let succeeded = attempt.completed();
        repaint_after_auth_login(self.ui_mut());
        self.log_auth_login_status(provider, method, attempt);
        succeeded
    }

    fn log_auth_login_status(&mut self, provider: &str, method: &str, attempt: AuthLoginAttempt) {
        let completed = attempt.completed();
        if let Some(login) = self.router.auth_mut().login_mut() {
            login.status = if completed { "connected" } else { "failed" }.to_string();
            login.detail = if completed {
                "credentials saved; values hidden".to_string()
            } else {
                "login did not complete; run auth status for details".to_string()
            };
        }
        let store_path = oauth_credentials_path_display(self.config());
        let recovering_plan = self.engagement.pending_credential_continuation().is_some();
        if let Some(reason) = attempt.successful_process_problem() {
            self.set_error_notice(
                "auth",
                incomplete_auth_login_message(
                    provider,
                    &store_path,
                    reason,
                    recovering_plan,
                    attempt.api_key_available,
                ),
            );
            return;
        }
        let (prefix, message) = auth_login_status_message(
            provider,
            method,
            attempt.status,
            &store_path,
            recovering_plan,
            attempt.api_key_available,
        );
        if completed {
            self.log(prefix, message);
        } else {
            self.set_error_notice("auth", message);
        }
    }
}

struct AuthLoginAttempt {
    status: io::Result<std::process::ExitStatus>,
    credential_ready: bool,
    credential_replaced: bool,
    api_key_available: bool,
}

impl AuthLoginAttempt {
    fn completed(&self) -> bool {
        self.status
            .as_ref()
            .is_ok_and(std::process::ExitStatus::success)
            && self.credential_ready
            && self.credential_replaced
    }

    fn successful_process_problem(&self) -> Option<&'static str> {
        let process_succeeded = self
            .status
            .as_ref()
            .is_ok_and(std::process::ExitStatus::success);
        match (
            process_succeeded,
            self.credential_ready,
            self.credential_replaced,
        ) {
            (true, false, _) => Some("finished without producing usable credentials"),
            (true, true, false) => Some("did not replace the rejected credential"),
            _ => None,
        }
    }
}

fn model_switch_persist_effects(selection: &AuthModelSwitch, changed: bool) -> Vec<ShellEffect> {
    changed
        .then(|| {
            global_model_selection_persist_effect(&selection.model, Some(&selection.thinking_level))
        })
        .into_iter()
        .collect()
}

fn auth_picker_allows_api_key(provider: &str) -> bool {
    auth_method_rows(provider)
        .iter()
        .any(|row| row.kind == AuthMethodRowKind::ApiKey)
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
