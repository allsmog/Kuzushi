use super::*;
use crate::app::{MapRunConfigRowId, SetupEditor};

impl ShellApp {
    pub(super) fn map_text_editor_owns_key(&self, key: KeyEvent) -> bool {
        if self.shell_view() != ShellView::Setup
            || self.router.setup().editor() != Some(SetupEditor::ThreatModel)
        {
            return false;
        }
        if key.modifiers == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('c' | 'd')) {
            return false;
        }
        self.router.setup().map_run_config().text().is_some() || self.map_scope_picker_open()
    }

    pub(super) fn handle_map_text_key(&mut self, key: KeyEvent) -> InputUpdate {
        let list = self.router.setup().map_run_config().text().unwrap();
        let document = list.row == MapRunConfigRowId::DesignDocs;
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('o') && document {
            self.open_map_document_picker();
            return InputUpdate::handled();
        }
        if list.field.is_some() {
            return self.handle_map_field_key(key, document);
        }
        self.handle_map_entry_list_key(key, document)
    }

    fn handle_map_field_key(&mut self, key: KeyEvent, document: bool) -> InputUpdate {
        if map_field_save_key(key, document) {
            return self.commit_map_run_text_input();
        }
        let state = self.router.setup_mut().map_run_config_mut();
        state.clear_error();
        let list = state.text_mut().unwrap();
        match key.code {
            KeyCode::Esc => list.field = None,
            KeyCode::Enter => list.field.as_mut().unwrap().insert("\n"),
            _ => {
                list.field.as_mut().unwrap().handle_key(key);
            }
        }
        InputUpdate::handled()
    }

    fn handle_map_entry_list_key(&mut self, key: KeyEvent, document: bool) -> InputUpdate {
        if !key.modifiers.is_empty() {
            return InputUpdate::handled();
        }
        if key.code == KeyCode::Delete {
            let result = self.remove_map_text_entry();
            self.set_map_run_config_result(result);
            return InputUpdate::handled();
        }
        if document && key.code == KeyCode::Char('f') {
            self.open_map_document_picker();
            return InputUpdate::handled();
        }
        self.update_map_entry_selection(key.code);
        InputUpdate::handled()
    }

    fn update_map_entry_selection(&mut self, code: KeyCode) {
        let state = self.router.setup_mut().map_run_config_mut();
        state.clear_error();
        let list = state.text_mut().unwrap();
        match code {
            KeyCode::Up => list.move_cursor(-1),
            KeyCode::Down => list.move_cursor(1),
            KeyCode::Enter => list.edit_selected(),
            KeyCode::Char('a') => list.add(),
            KeyCode::Esc => state.finish_edit(),
            _ => {}
        }
    }

    pub(super) fn capture_map_field_paste(&mut self, text: &str) -> bool {
        if self.shell_view() != ShellView::Setup
            || self.router.setup().editor() != Some(SetupEditor::ThreatModel)
        {
            return false;
        }
        let state = self.router.setup_mut().map_run_config_mut();
        let Some(list) = state.text_mut() else {
            return false;
        };
        if list.field.is_none() {
            list.add();
        }
        list.field.as_mut().unwrap().insert(text);
        state.clear_error();
        true
    }
}

fn map_field_save_key(key: KeyEvent, document: bool) -> bool {
    (key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('s'))
        || (document && key.modifiers.is_empty() && key.code == KeyCode::Enter)
}

#[cfg(test)]
mod tests;
