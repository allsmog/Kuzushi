use super::*;

impl ShellApp {
    pub(super) fn model_command_scopes_to_module(&self, command: &ModelCommand) -> bool {
        if command.force_module {
            return true;
        }
        model_command_default_scopes_to_module(
            command.force_global,
            self.focused_module.is_some(),
            self.config.model.is_some(),
        )
    }

    pub(super) fn apply_module_model_command(
        &mut self,
        model: String,
        thinking_level: Option<String>,
    ) {
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
                "module {module_id} uses {}{} via LangGraph (session only)",
                model,
                thinking_level
                    .as_deref()
                    .map(|level| format!(" / {level}"))
                    .unwrap_or_default()
            ),
        );
    }

    pub(super) fn apply_global_model_command(
        &mut self,
        model: String,
        thinking_level: Option<String>,
    ) {
        self.config.model = Some(model.clone());
        self.session_thinking_level = thinking_level.clone();
        self.sync_selected_model_index();
        self.persist_global_model_choice(&model, thinking_level.as_deref());
        self.log(
            "model",
            format!(
                "{model}{} via LangGraph (no fallback model will be selected)",
                thinking_level
                    .as_deref()
                    .map(|level| format!(" / {level}"))
                    .unwrap_or_default()
            ),
        );
    }

    pub(crate) fn persist_global_model_choice(
        &mut self,
        model: &str,
        thinking_level: Option<&str>,
    ) {
        if !model_persistence_enabled_for_build() {
            return;
        }
        match kuzushi_core::config::persist_global_model_selection(model, thinking_level) {
            Ok(path) => self.log("model", format!("saved global model to {}", path.display())),
            Err(error) => self.log(
                "warn",
                format!("model active for this session, but could not save config: {error}"),
            ),
        }
    }
}

fn model_command_default_scopes_to_module(
    force_global: bool,
    has_focused_module: bool,
    has_global_model: bool,
) -> bool {
    (!force_global) & has_focused_module & has_global_model
}

#[cfg(not(test))]
fn model_persistence_enabled_for_build() -> bool {
    true
}

#[cfg(test)]
fn model_persistence_enabled_for_build() -> bool {
    std::env::var_os("KUZUSHI_TUI_TEST_PERSIST_MODEL").is_some()
}
