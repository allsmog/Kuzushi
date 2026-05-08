use super::super::{normalize_thinking_level, resolve_model_selector};
use super::*;

mod application;
mod parsing;

pub(super) struct ModelCommand {
    pub(super) force_global: bool,
    pub(super) force_module: bool,
    pub(super) selector: String,
    pub(super) explicit_effort: Option<String>,
}

impl ShellApp {
    pub(crate) fn handle_model_command(&mut self, raw: Option<String>) {
        self.shell_view = ShellView::Config;
        let Some(command) = parsing::parse_model_command(raw) else {
            self.show_model_catalog();
            return;
        };
        let (model, thinking_level) = match parsing::resolve_model_command_selection(&command) {
            Ok(selection) => selection,
            Err(message) => {
                self.log("error", message);
                return;
            }
        };
        if let Err(message) = validate_shell_model_id(&model) {
            self.log("error", message);
            return;
        }

        if self.model_command_scopes_to_module(&command) {
            self.apply_module_model_command(model, thinking_level);
            return;
        }

        self.apply_global_model_command(model, thinking_level);
    }
}
