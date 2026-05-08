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
                "pi-agent-core auth: {api_key_env}={env_status}; ANTHROPIC_API_KEY={anthropic_env}; openai-codex oauth {}; anthropic oauth {}; secret values hidden. Next: auth login openai-codex or auth login anthropic",
                oauth_provider_status("openai-codex"),
                oauth_provider_status("anthropic")
            ),
        );
    }

    pub(crate) fn handle_auth_login_command(&mut self, provider: Option<String>) {
        self.shell_view = ShellView::Config;
        let Some(provider) = self.auth_login_provider(provider.as_deref()) else {
            return;
        };
        self.log("auth", format!("starting {provider} OAuth login"));

        let Some(command) = self.auth_login_bridge_command() else {
            return;
        };
        self.run_auth_login_process(provider, &command);
    }

    pub(crate) fn auth_login_provider(&mut self, provider: Option<&str>) -> Option<&'static str> {
        match normalize_auth_provider(provider.unwrap_or("openai-codex")) {
            Ok(provider) => Some(provider),
            Err(message) => {
                self.log("error", message);
                None
            }
        }
    }

    pub(crate) fn auth_login_bridge_command(&mut self) -> Option<Vec<String>> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let command = match PiAgentCoreRuntime::from_config(&self.config, &cwd) {
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
        self.log("error", "pi-agent-core bridge command is empty");
        None
    }

    pub(crate) fn run_auth_login_process(&mut self, provider: &str, command: &[String]) {
        let Some(program) = command.first() else {
            self.log("error", "pi-agent-core bridge command is empty");
            return;
        };

        let raw_mode_was_disabled = pause_raw_mode_for_auth_login();
        let status = spawn_auth_login_process(program, &command[1..], provider);
        restore_raw_mode_after_auth_login(raw_mode_was_disabled);
        repaint_after_auth_login(&mut self.force_full_redraw);
        self.log_auth_login_status(provider, status);
    }

    pub(crate) fn log_auth_login_status(
        &mut self,
        provider: &str,
        status: io::Result<std::process::ExitStatus>,
    ) {
        let (prefix, message) = auth_login_status_message(provider, status);
        self.log(prefix, message);
    }
}
