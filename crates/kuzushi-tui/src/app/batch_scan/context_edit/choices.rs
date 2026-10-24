//! Choice navigation is local draft state. Only Enter changes the field value.
use super::*;
use crate::app::FieldEditor;
use crossterm::event::{KeyCode, KeyEvent};
use kuzushi_core::capabilities::threat_model::ContextEditConstraint;

impl ShellApp {
    pub(super) fn begin_context_field_edit(&mut self) {
        let draft = self.context_edit_draft_mut().unwrap();
        let entry = &mut draft.entries[draft.cursor];
        draft.notice = None;
        if let ContextEditConstraint::Choice(choices) = &entry.constraint {
            draft.choice_cursor = choices
                .iter()
                .position(|choice| choice.value == entry.text())
                .unwrap_or(0);
            draft.choice_details = false;
            draft.scroll = 0;
            draft.mode = ContextEditMode::Choosing;
            return;
        }
        entry.begin_edit();
        draft.mode = ContextEditMode::Writing;
    }

    pub(super) fn context_choice_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !key.modifiers.is_empty() {
            return InputUpdate::handled();
        }
        match key.code {
            KeyCode::Enter => self.choose_context_value(),
            KeyCode::Tab => self.toggle_context_choice_details(),
            _ => self.move_context_choice(key.code),
        }
        InputUpdate::handled()
    }

    fn choose_context_value(&mut self) {
        let draft = self.context_edit_draft_mut().unwrap();
        let entry = &mut draft.entries[draft.cursor];
        let ContextEditConstraint::Choice(choices) = &entry.constraint else {
            return;
        };
        let Some(choice) = choices.get(draft.choice_cursor) else {
            draft.notice =
                Some("No unambiguous component is available. The draft is unchanged.".into());
            return;
        };
        entry.editor = Some(FieldEditor::new(&choice.value));
        draft.mode = ContextEditMode::Fields;
        draft.notice = None;
        draft.scroll = 0;
    }

    fn toggle_context_choice_details(&mut self) {
        let draft = self.context_edit_draft_mut().unwrap();
        draft.choice_details = !draft.choice_details;
    }

    fn move_context_choice(&mut self, code: KeyCode) {
        if self.context_edit_draft().unwrap().choice_details {
            self.page_context_choice(code);
            return;
        }
        let page = crate::renderer::context_choice_page_rows(self);
        let draft = self.context_edit_draft_mut().unwrap();
        let entry = &draft.entries[draft.cursor];
        let ContextEditConstraint::Choice(choices) = &entry.constraint else {
            return;
        };
        let selected =
            super::navigation::cursor_after_key(code, draft.choice_cursor, choices.len(), page);
        if selected != draft.choice_cursor {
            draft.scroll = 0;
        }
        draft.choice_cursor = selected;
    }

    fn page_context_choice(&mut self, code: KeyCode) {
        let offset = crate::renderer::context_choice_offset_after_page(self, code);
        self.context_edit_draft_mut().unwrap().scroll = offset;
    }

    pub(super) fn finish_context_line(&mut self, key: KeyEvent) -> bool {
        let draft = self.context_edit_draft_mut().unwrap();
        if key.code != KeyCode::Enter || !key.modifiers.is_empty() {
            return false;
        }
        if draft.entries[draft.cursor].constraint != ContextEditConstraint::SingleLine {
            return false;
        }
        draft.mode = ContextEditMode::Fields;
        true
    }

    pub(super) fn refuse_context_line_break(&mut self, text: &str) -> bool {
        let draft = self.context_edit_draft_mut().unwrap();
        let single_line =
            draft.entries[draft.cursor].constraint == ContextEditConstraint::SingleLine;
        if single_line && text.chars().any(char::is_control) {
            draft.notice = Some("Use one line for this field. Your draft is unchanged.".into());
            return true;
        }
        false
    }
}
