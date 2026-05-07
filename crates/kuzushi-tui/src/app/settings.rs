use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};

use crossterm::cursor::MoveTo;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use kuzushi_core::{OptionScope, OptionTarget, RuntimeKind, V2Config};
use kuzushi_openai::PiAgentCoreRuntime;

use super::{ShellApp, ShellView};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ModelChoice {
    pub index: usize,
    pub id: &'static str,
    pub label: &'static str,
    pub provider: &'static str,
    pub auth: &'static str,
    pub thinking_level: &'static str,
}

const MODEL_CHOICES: &[ModelChoice] = &[
    ModelChoice {
        index: 1,
        id: "openai:gpt-5.5",
        label: "GPT-5.5",
        provider: "openai",
        auth: "OPENAI_API_KEY",
        thinking_level: "xhigh",
    },
    ModelChoice {
        index: 2,
        id: "openai:gpt-5.5-mini",
        label: "GPT-5.5 mini",
        provider: "openai",
        auth: "OPENAI_API_KEY",
        thinking_level: "high",
    },
    ModelChoice {
        index: 3,
        id: "openai-codex:gpt-5.5",
        label: "Codex GPT-5.5",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "xhigh",
    },
    ModelChoice {
        index: 4,
        id: "openai-codex:gpt-5.5-mini",
        label: "Codex GPT-5.5 mini",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "high",
    },
    ModelChoice {
        index: 5,
        id: "anthropic:claude-sonnet-4-6",
        label: "Claude Sonnet 4.6",
        provider: "anthropic",
        auth: "ANTHROPIC_API_KEY or OAuth",
        thinking_level: "high",
    },
    ModelChoice {
        index: 6,
        id: "anthropic:claude-opus-4-7",
        label: "Claude Opus 4.7",
        provider: "anthropic",
        auth: "ANTHROPIC_API_KEY or OAuth",
        thinking_level: "xhigh",
    },
];

pub(crate) fn model_choices() -> &'static [ModelChoice] {
    MODEL_CHOICES
}

pub(super) fn preferred_model_choice_index(config: &V2Config) -> usize {
    preferred_model_choice_index_for_state(
        config.model.as_deref(),
        oauth_provider_status("openai-codex").starts_with("stored"),
        env::var_os("OPENAI_API_KEY").is_some(),
        env::var_os("ANTHROPIC_API_KEY").is_some()
            || oauth_provider_status("anthropic").starts_with("stored"),
    )
}

fn preferred_model_choice_index_for_state(
    configured_model: Option<&str>,
    codex_oauth_ready: bool,
    openai_key_ready: bool,
    anthropic_ready: bool,
) -> usize {
    if let Some(index) = configured_model.and_then(model_choice_index_by_id) {
        return index;
    }
    if let Some(index) = ready_provider_choice_index(codex_oauth_ready, "openai-codex") {
        return index;
    }
    if let Some(index) = ready_provider_choice_index(openai_key_ready, "openai") {
        return index;
    }
    if let Some(index) = ready_provider_choice_index(anthropic_ready, "anthropic") {
        return index;
    }
    0
}

fn model_choice_index_by_id(model: &str) -> Option<usize> {
    MODEL_CHOICES.iter().position(|choice| choice.id == model)
}

fn ready_provider_choice_index(ready: bool, provider: &str) -> Option<usize> {
    ready.then(|| {
        MODEL_CHOICES
            .iter()
            .position(|choice| choice.provider == provider)
    })?
}

impl ShellApp {
    pub(super) fn handle_model_command(&mut self, raw: Option<String>) {
        self.shell_view = ShellView::Config;
        let Some(raw) = raw
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            self.show_model_catalog();
            return;
        };

        let mut parts = raw.split_whitespace().collect::<Vec<_>>();
        if matches!(
            parts.first().copied(),
            Some("list") | Some("models") | Some("choices")
        ) {
            self.show_model_catalog();
            return;
        }

        let force_global = matches!(parts.first().copied(), Some("global") | Some("session"));
        let force_module = matches!(parts.first().copied(), Some("module"));
        if force_global || force_module {
            parts.remove(0);
        }

        let Some(selector) = parts.first().copied() else {
            self.show_model_catalog();
            return;
        };
        let explicit_effort = parts.get(1).copied();
        let (model, default_effort) = match resolve_model_selector(selector) {
            Some(choice) => (choice.id.to_string(), Some(choice.thinking_level)),
            None if selector.contains(':') => (selector.to_string(), None),
            None => {
                self.log(
                    "error",
                    format!(
                        "unknown model choice {selector:?}. Next: model, or model provider:model-id"
                    ),
                );
                return;
            }
        };
        if let Err(message) = validate_shell_model_id(&model) {
            self.log("error", message);
            return;
        }
        let thinking_level = match explicit_effort
            .or(default_effort)
            .map(normalize_thinking_level)
        {
            Some(Some(level)) => Some(level.to_string()),
            Some(None) => {
                self.log(
                    "error",
                    format!(
                        "unknown reasoning effort {:?}. Valid: low, medium, high, xhigh",
                        explicit_effort.unwrap_or_default()
                    ),
                );
                return;
            }
            None => None,
        };

        // Default behavior with no global model yet: set the global model
        // even if a module is focused. Otherwise `?question` traps the user
        // because the agent path reads `config.model`, not the per-module
        // option. Operators can still scope per-module explicitly with
        // `model module <choice>`.
        let scope_to_module = force_module
            || (!force_global && self.focused_module.is_some() && self.config.model.is_some());
        if scope_to_module {
            let Some(module_id) = self.focused_module.clone() else {
                self.log(
                    "error",
                    "model module requires a focused module. Next: use <module>, then model module <choice>",
                );
                return;
            };
            self.option_store.set_value(
                OptionScope::Session,
                OptionTarget::Module(module_id.clone()),
                "model",
                serde_json::json!(model.clone()),
            );
            if let Some(level) = &thinking_level {
                self.option_store.set_value(
                    OptionScope::Session,
                    OptionTarget::Module(module_id.clone()),
                    "effort",
                    serde_json::json!(level),
                );
            }
            self.log(
                "model",
                format!(
                    "module {module_id} uses {}{} via pi-agent-core (session only)",
                    model,
                    thinking_level
                        .as_deref()
                        .map(|level| format!(" / {level}"))
                        .unwrap_or_default()
                ),
            );
            return;
        }

        self.config.model = Some(model.clone());
        self.session_thinking_level = thinking_level.clone();
        self.sync_selected_model_index();
        self.log(
            "model",
            format!(
                "{model}{} via pi-agent-core (session only; no fallback model will be selected)",
                thinking_level
                    .as_deref()
                    .map(|level| format!(" / {level}"))
                    .unwrap_or_default()
            ),
        );
    }

    fn show_model_catalog(&mut self) {
        self.shell_view = ShellView::Config;
        self.sync_selected_model_index();
        let active = self
            .config
            .model
            .clone()
            .unwrap_or_else(|| "unconfigured".to_string());
        let effort = self.session_thinking_level.as_deref().unwrap_or("default");
        self.log(
            "model",
            format!("active {active} / {effort}. Select with: model <n> [low|medium|high|xhigh]"),
        );
        for choice in MODEL_CHOICES {
            self.log(
                "model",
                format!(
                    "{}. {}  {}  {}  auth {}",
                    choice.index, choice.id, choice.thinking_level, choice.label, choice.auth
                ),
            );
        }
        if self.focused_module.is_some() {
            let hint = if self.config.model.is_none() {
                "focused module detected, but no global model yet — model <n> sets the global model so `ask` works. Use `model module <n>` to scope per-module."
            } else {
                "focused module detected: model <n> sets this module; use `model global <n>` for global ask/defaults."
            };
            self.log("model", hint);
        }
    }

    pub(super) fn show_auth_status(&mut self) {
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

    pub(super) fn handle_auth_login_command(&mut self, provider: Option<String>) {
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

    fn auth_login_provider(&mut self, provider: Option<&str>) -> Option<&'static str> {
        match normalize_auth_provider(provider.unwrap_or("openai-codex")) {
            Ok(provider) => Some(provider),
            Err(message) => {
                self.log("error", message);
                None
            }
        }
    }

    fn auth_login_bridge_command(&mut self) -> Option<Vec<String>> {
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

    fn non_empty_auth_login_bridge_command(&mut self, command: Vec<String>) -> Option<Vec<String>> {
        if command.first().is_some() {
            return Some(command);
        }
        self.log("error", "pi-agent-core bridge command is empty");
        None
    }

    fn run_auth_login_process(&mut self, provider: &str, command: &[String]) {
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

    fn log_auth_login_status(
        &mut self,
        provider: &str,
        status: io::Result<std::process::ExitStatus>,
    ) {
        let (prefix, message) = auth_login_status_message(provider, status);
        self.log(prefix, message);
    }

    pub(super) fn handle_provider_command(&mut self, provider: Option<String>) {
        self.shell_view = ShellView::Config;
        if let Some(provider) = provider {
            let provider = provider.trim();
            if provider.is_empty() || provider.contains(':') {
                self.log(
                    "error",
                    "provider expects only the provider prefix. Next: model 1, model 5, or model provider:model-id",
                );
                return;
            }
            self.log(
                "provider",
                format!(
                    "{provider} requested. Rust uses pi-agent-core only; providers are selected through explicit model ids. Next: model {provider}:<model-id>"
                ),
            );
            return;
        }

        self.log(
            "provider",
            format!(
                "{} via pi-agent-core. Supported selectors: openai, openai-codex, anthropic. Next: model",
                self.provider_label()
            ),
        );
    }

    pub(super) fn handle_backend_command(&mut self, backend: Option<String>) {
        self.shell_view = ShellView::Config;
        if let Some(backend) = backend {
            let normalized = backend.trim().to_ascii_lowercase();
            if normalized == "pi-agent-core" || normalized == "pi_agent_core" {
                self.log("backend", "pi-agent-core already selected");
            } else {
                self.log(
                    "error",
                    format!(
                        "unsupported Rust backend {backend:?}. Supported: pi-agent-core. Next: backend pi-agent-core"
                    ),
                );
            }
            return;
        }

        self.log(
            "backend",
            format!(
                "{}; bridge {}",
                runtime_backend_label(&self.config),
                bridge_command_status(&self.config)
            ),
        );
    }

    pub(super) fn show_cost_status(&mut self) {
        // `/cost` lands on the dedicated Cost surface
        // (`design/mockups/cost.jsx`) — budget bars + by-tool spend.
        self.shell_view = ShellView::Cost;
        let message = if let Some(last) = self.last_tool_cost_usd {
            format!(
                "session estimate ${:.4}; last tool ${:.4}. Scanner-only work may report no LLM cost.",
                self.session_cost_usd, last
            )
        } else {
            "cost unavailable until a Rust tool reports costUsd; scanner-only work may report no LLM cost. Next: run <tool>"
                .to_string()
        };
        self.log("cost", message);
    }

    pub(crate) fn provider_label(&self) -> String {
        self.config
            .model
            .as_deref()
            .and_then(|model| model.split_once(':').map(|(provider, _)| provider))
            .filter(|provider| !provider.trim().is_empty())
            .unwrap_or("unconfigured")
            .to_string()
    }

    pub(super) fn sync_selected_model_index(&mut self) {
        self.selected_model_index = preferred_model_choice_index(&self.config);
    }

    pub(super) fn move_model_selection(&mut self, delta: isize) {
        let len = MODEL_CHOICES.len();
        if len == 0 {
            self.selected_model_index = 0;
            return;
        }
        let current = self.selected_model_index.min(len - 1) as isize;
        self.selected_model_index = (current + delta).rem_euclid(len as isize) as usize;
    }

    pub(super) fn select_current_model_choice(&mut self) {
        let Some(choice) = MODEL_CHOICES.get(self.selected_model_index) else {
            self.log("error", "no model choices are available");
            return;
        };
        self.config.model = Some(choice.id.to_string());
        self.session_thinking_level = Some(choice.thinking_level.to_string());
        self.shell_view = ShellView::Config;
        self.log(
            "model",
            format!(
                "{} / {} selected via onboarding (session only; no fallback model will be selected)",
                choice.id, choice.thinking_level
            ),
        );
    }
}

pub(super) fn parse_budget_env() -> Option<f64> {
    env::var("KUZUSHI_BUDGET_USD")
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
}

pub(crate) fn validate_shell_model_id(model: &str) -> std::result::Result<(), String> {
    if model.is_empty() {
        return Err("model cannot be empty. Next: model, or model provider:model-id".to_string());
    }
    let Some((provider, model_id)) = model.split_once(':') else {
        return Err(format!(
            "model must use provider:model syntax, got {model:?}. Next: model, or model openai:gpt-5.5"
        ));
    };
    if provider.trim().is_empty() || model_id.trim().is_empty() {
        return Err(format!(
            "model must include both provider and model id, got {model:?}. Next: model, or model openai:gpt-5.5"
        ));
    }
    Ok(())
}

fn resolve_model_selector(selector: &str) -> Option<&'static ModelChoice> {
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

fn pause_raw_mode_for_auth_login() -> bool {
    disable_raw_mode().is_ok()
}

fn restore_raw_mode_after_auth_login(raw_mode_was_disabled: bool) {
    if raw_mode_was_disabled {
        let _ = enable_raw_mode();
    }
}

fn spawn_auth_login_process(
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

fn repaint_after_auth_login(force_full_redraw: &mut bool) {
    let mut stdout = io::stdout();
    let _ = execute!(stdout, Clear(ClearType::All), MoveTo(0, 0));
    *force_full_redraw = true;
}

pub(super) fn auth_login_status_message(
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

fn normalize_auth_provider(provider: &str) -> std::result::Result<&'static str, String> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "" | "openai-codex" | "codex" => Ok("openai-codex"),
        "anthropic" | "claude" => Ok("anthropic"),
        other => Err(format!(
            "unsupported auth login provider {other:?}. Supported: openai-codex, anthropic. Next: auth login openai-codex"
        )),
    }
}

fn oauth_credentials_path() -> Option<PathBuf> {
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

pub(super) fn thinking_level_from_input(input: &serde_json::Value) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_model_choice_state_respects_configured_then_codex_openai_anthropic() {
        assert_eq!(
            preferred_model_choice_index_for_state(
                Some("anthropic:claude-opus-4-7"),
                true,
                true,
                true
            ),
            5
        );
        assert_eq!(
            preferred_model_choice_index_for_state(None, true, true, true),
            2
        );
        assert_eq!(
            preferred_model_choice_index_for_state(None, false, true, true),
            0
        );
        assert_eq!(
            preferred_model_choice_index_for_state(None, false, false, true),
            4
        );
        assert_eq!(
            preferred_model_choice_index_for_state(Some("unknown:model"), false, false, false),
            0
        );
    }
}
