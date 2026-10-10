use super::*;

impl ShellApp {
    pub(crate) fn open_model_picker(&mut self) {
        let origin = self.config_model_picker_origin();
        let visible = visible_model_choices(self.config());
        let route = self.router.model_picker_mut();
        route.open(visible.first().map(|choice| choice.id));
        route.set_config_origin(origin);
        self.router.setup_mut().begin_editor(SetupEditor::Model);
        self.set_shell_view(ShellView::Setup);
        self.log(
            "model",
            "choose a model with ↑/↓/Enter; Esc keeps the current selection",
        );
    }

    fn config_model_picker_origin(&mut self) -> Option<ConfigModelPickerOrigin> {
        if self.shell_view() == ShellView::Config
            || (self.shell_view() == ShellView::Campaign
                && self
                    .context_generation()
                    .is_some_and(|generation| generation.allows_model_choice()))
        {
            self.sync_view_change();
            return Some(ConfigModelPickerOrigin {
                view: self.shell_view(),
                model: self.config().model.clone(),
                input_mode: self.input_mode(),
                scroll: self.router.default_scroll().offset(),
                navigation: self.router.navigation().clone(),
            });
        }
        if self.shell_view() != ShellView::Setup {
            return None;
        }
        if self.router.setup().editor() != Some(SetupEditor::Model) {
            return None;
        }
        self.router.model_picker().config_origin().cloned()
    }

    pub(crate) fn restore_model_picker_config_origin(&mut self) -> bool {
        if self.shell_view() != ShellView::Setup
            || self.router.setup().editor() != Some(SetupEditor::Model)
        {
            return false;
        }
        let Some(origin) = self.router.model_picker_mut().take_config_origin() else {
            return false;
        };
        self.router.setup_mut().finish_editor();
        self.set_shell_view(origin.view);
        self.set_input_mode(origin.input_mode);
        *self.router.navigation_mut() = origin.navigation;
        self.router.default_scroll_mut().set(origin.scroll);
        if origin.model != self.config().model {
            self.refresh_context_generation_model();
        }
        true
    }

    pub(crate) fn show_model_command_config(&mut self) {
        if !self.restore_model_picker_config_origin() {
            self.set_shell_view(ShellView::Config);
        }
    }
}

#[cfg(test)]
mod tests;
