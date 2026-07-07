use super::*;

impl ShellApp {
    pub(super) fn model_command_scopes_to_module(&self, command: &ModelCommand) -> bool {
        if command.force_module {
            return true;
        }
        model_command_default_scopes_to_module(
            command.force_global,
            self.focused_module().is_some(),
            self.config().model.is_some(),
        )
    }

    pub(super) fn apply_module_model_command(
        &mut self,
        model: String,
        thinking_level: Option<String>,
    ) -> Vec<ShellEffect> {
        let Some(module_id) = self.focused_module_owned() else {
            self.log(
                "error",
                "model module requires a focused module. Next: use <module>, then model module <choice>",
            );
            return Vec::new();
        };
        self.option_store_mut().set_value(
            OptionScope::Session,
            OptionTarget::Module(module_id.clone()),
            "model",
            serde_json::json!(model.clone()),
        );
        if let Some(level) = &thinking_level {
            self.option_store_mut().set_value(
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
        Vec::new()
    }

    pub(super) fn apply_global_model_command(
        &mut self,
        model: String,
        thinking_level: Option<String>,
    ) -> Vec<ShellEffect> {
        self.config_mut().model = Some(model.clone());
        self.set_session_thinking_level(thinking_level.clone());
        self.sync_selected_model_index();
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
        vec![global_model_selection_persist_effect(
            &model,
            thinking_level.as_deref(),
        )]
    }

    pub(crate) fn persist_global_model_selection_effect(
        &mut self,
        selection: GlobalModelSelectionPersist,
    ) {
        if !model_persistence_enabled_for_build() {
            return;
        }
        match kuzushi_core::config::persist_global_model_selection(
            &selection.model,
            selection.thinking_level.as_deref(),
        ) {
            Ok(path) => self.log("model", format!("saved global model to {}", path.display())),
            Err(error) => self.log(
                "warn",
                format!("model active for this session, but could not save config: {error}"),
            ),
        }
    }
}

pub(crate) fn global_model_selection_persist_effect(
    model: &str,
    thinking_level: Option<&str>,
) -> ShellEffect {
    ShellEffect::PersistGlobalModelSelection(GlobalModelSelectionPersist {
        model: model.to_string(),
        thinking_level: thinking_level.map(ToString::to_string),
    })
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
