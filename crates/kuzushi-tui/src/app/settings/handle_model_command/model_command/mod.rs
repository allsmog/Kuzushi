use super::super::{normalize_thinking_level, resolve_model_selector};
use super::*;

mod application;
mod parsing;

pub(crate) use application::global_model_selection_persist_effect;

pub(super) struct ModelCommand {
    pub(super) force_global: bool,
    pub(super) force_module: bool,
    pub(super) selector: String,
    pub(super) explicit_effort: Option<String>,
}

impl ShellApp {
    pub(crate) fn reduce_model_command(&mut self, raw: &Option<String>) -> Vec<ShellEffect> {
        let Some(command) = parsing::parse_model_command(raw.clone()) else {
            self.open_model_picker();
            return Vec::new();
        };
        self.set_shell_view(ShellView::Config);
        let (model, thinking_level) = match parsing::resolve_model_command_selection(&command) {
            Ok(selection) => selection,
            Err(message) => {
                self.log("error", message);
                return Vec::new();
            }
        };
        if let Err(message) = validate_shell_model_id(&model) {
            self.log("error", message);
            return Vec::new();
        }

        if self.model_command_scopes_to_module(&command) {
            return self.apply_module_model_command(model, thinking_level);
        }

        self.apply_global_model_command(model, thinking_level)
    }
}
