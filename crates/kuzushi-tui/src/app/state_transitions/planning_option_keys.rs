use super::*;

impl ShellApp {
    pub(crate) fn planning_option_editor_open(&self) -> bool {
        let planning_view = self.shell_view() == ShellView::PlanningPicker
            || (self.shell_view() == ShellView::Setup
                && self.router.setup().editor() == Some(SetupEditor::Plan));
        planning_view && self.engagement.planning_picker().option_edit().is_some()
    }

    pub(super) fn planning_option_editor_owns_key(&self, key: KeyEvent) -> bool {
        self.planning_option_editor_open() && !is_quit_chord(key)
    }

    pub(super) fn handle_planning_option_edit_key(&mut self, key: KeyEvent) -> bool {
        if !self.planning_option_editor_open() {
            return false;
        }
        if option_save_key(key) {
            self.commit_planning_option_edit();
        } else if key.code == KeyCode::Esc && key.modifiers.is_empty() {
            self.cancel_planning_option_edit();
        } else {
            self.edit_planning_option_key(key);
        }
        true
    }

    fn edit_planning_option_key(&mut self, key: KeyEvent) {
        if self.page_planning_option_error(key) {
            return;
        }
        let picker = self.engagement.planning_picker_mut();
        let Some(edit) = picker.option_edit_mut() else {
            return;
        };
        let before = edit.field.text().len();
        if key.code == KeyCode::Enter && key.modifiers == KeyModifiers::SHIFT {
            edit.field.insert("\n");
        } else {
            edit.field.handle_key(key);
        }
        if edit.field.text().len() != before {
            picker.clear_option_error();
        }
    }

    fn page_planning_option_error(&mut self, key: KeyEvent) -> bool {
        let direction = match (key.code, key.modifiers) {
            (KeyCode::PageUp, KeyModifiers::NONE) => -1,
            (KeyCode::PageDown, KeyModifiers::NONE) => 1,
            _ => return false,
        };
        let Some(scroll) = crate::renderer::planning_option_error_scroll(self, direction) else {
            return false;
        };
        if let Some(edit) = self.engagement.planning_picker_mut().option_edit_mut() {
            edit.error_scroll = scroll;
        }
        true
    }

    pub(super) fn insert_planning_option_text(&mut self, text: &str) {
        let picker = self.engagement.planning_picker_mut();
        if let Some(edit) = picker.option_edit_mut() {
            edit.field.insert(text);
            picker.clear_option_error();
        }
    }
}

fn option_save_key(key: KeyEvent) -> bool {
    (key.code == KeyCode::Enter && key.modifiers.is_empty())
        || (key.code == KeyCode::Char('s') && key.modifiers == KeyModifiers::CONTROL)
}

#[cfg(test)]
mod tests;
