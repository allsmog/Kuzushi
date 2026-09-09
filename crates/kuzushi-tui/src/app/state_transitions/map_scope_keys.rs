use super::*;
use crate::app::SetupEditor;

impl ShellApp {
    pub(crate) fn map_scope_picker_open(&self) -> bool {
        self.shell_view() == ShellView::Setup
            && self.router.setup().editor() == Some(SetupEditor::ThreatModel)
            && self.router.setup().map_run_config().scope().is_some()
    }

    pub(super) fn handle_map_scope_key(&mut self, key: KeyEvent) -> InputUpdate {
        if key.modifiers.is_empty() && key.code == KeyCode::Esc {
            self.router.setup_mut().map_run_config_mut().finish_scope();
            return InputUpdate::handled();
        }
        if key.modifiers.is_empty() && key.code == KeyCode::Enter {
            return self.commit_map_scope_selection();
        }
        let state = self.router.setup_mut().map_run_config_mut();
        state.clear_error();
        if let Some(picker) = state.scope_mut() {
            picker.handle_key(key);
        }
        InputUpdate::handled()
    }

    fn commit_map_scope_selection(&mut self) -> InputUpdate {
        if let Err(error) = self.select_map_scope() {
            self.set_map_run_config_result(Err(error));
        }
        InputUpdate::handled()
    }

    pub(super) fn capture_map_scope_paste(&mut self, text: &str) -> bool {
        if !self.map_scope_picker_open() {
            return false;
        }
        let state = self.router.setup_mut().map_run_config_mut();
        state.clear_error();
        if let Some(picker) = state.scope_mut() {
            picker.paste(text);
        }
        true
    }
}
