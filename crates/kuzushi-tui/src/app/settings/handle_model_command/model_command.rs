use super::*;

impl ShellApp {
    pub(crate) fn handle_model_command(&mut self, raw: Option<String>) {
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
}
