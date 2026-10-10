use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::capabilities::threat_model::MAX_CONTEXT_EDIT_BYTES;

impl ShellApp {
    pub(crate) fn handle_context_edit_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let mode = self.context_edit_draft()?.mode;
        if let Some(update) = self.context_edit_primary_key(key, mode) {
            return Some(update);
        }
        Some(self.context_edit_mode_key(key, mode))
    }

    fn context_edit_primary_key(
        &mut self,
        key: KeyEvent,
        mode: ContextEditMode,
    ) -> Option<InputUpdate> {
        if key.code == KeyCode::Esc {
            self.context_edit_back(mode);
            return Some(InputUpdate::handled());
        }
        if key == KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)
            && mode != ContextEditMode::Saving
        {
            self.review_context_edits();
            return Some(InputUpdate::handled());
        }
        None
    }

    fn context_edit_back(&mut self, mode: ContextEditMode) {
        if matches!(mode, ContextEditMode::Fields | ContextEditMode::Saving) {
            self.close_context_editor();
            return;
        }
        let draft = self.context_edit_draft_mut().unwrap();
        draft.mode = ContextEditMode::Fields;
        draft.notice = None;
    }

    fn context_edit_mode_key(&mut self, key: KeyEvent, mode: ContextEditMode) -> InputUpdate {
        if mode == ContextEditMode::Writing {
            return self.context_text_key(key);
        }
        if mode == ContextEditMode::Saving {
            return InputUpdate::handled();
        }
        self.context_reading_key(key, mode)
    }

    fn context_reading_key(&mut self, key: KeyEvent, mode: ContextEditMode) -> InputUpdate {
        if !matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
            return InputUpdate::handled();
        }
        if mode == ContextEditMode::Discard {
            return self.context_discard_key(key.code);
        }
        if mode == ContextEditMode::Review {
            return self.context_review_key(key.code);
        }
        self.context_fields_key(key.code)
    }

    fn context_discard_key(&mut self, code: KeyCode) -> InputUpdate {
        if code == KeyCode::Enter {
            let key = self.context_edit_selection_key().unwrap();
            self.runtime_state.context_edit_drafts.remove(&key);
            self.close_context_editor();
        }
        InputUpdate::handled()
    }

    fn context_fields_key(&mut self, code: KeyCode) -> InputUpdate {
        if code == KeyCode::Char('g') {
            self.plan_selected_text_regeneration();
            return InputUpdate::handled();
        }
        if let Some(action) = field_action(code) {
            self.apply_context_field_action(action);
        } else {
            self.move_context_edit_field(code);
        }
        InputUpdate::handled()
    }

    fn apply_context_field_action(&mut self, action: FieldAction) {
        match action {
            FieldAction::Edit => {
                let draft = self.context_edit_draft_mut().unwrap();
                draft.entries[draft.cursor].begin_edit();
                draft.mode = ContextEditMode::Writing;
                draft.notice = None;
            }
            FieldAction::Review => self.review_context_edits(),
            FieldAction::Discard => {
                self.context_edit_draft_mut().unwrap().mode = ContextEditMode::Discard
            }
        }
    }

    fn move_context_edit_field(&mut self, code: KeyCode) {
        let draft = self.context_edit_draft_mut().unwrap();
        match code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                draft.cursor = draft.cursor.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                draft.cursor = (draft.cursor + 1).min(draft.entries.len() - 1)
            }
            _ => {}
        }
        draft.scroll = 0;
    }

    fn context_review_key(&mut self, code: KeyCode) -> InputUpdate {
        if code == KeyCode::Enter {
            return self.save_context_edits();
        }
        if code == KeyCode::Char('d') {
            self.context_edit_draft_mut().unwrap().mode = ContextEditMode::Discard;
        }
        self.page_context_edit_review(code);
        InputUpdate::handled()
    }

    fn page_context_edit_review(&mut self, code: KeyCode) {
        let rows = self.viewport().rows.saturating_sub(8).max(1) as usize;
        let draft = self.context_edit_draft_mut().unwrap();
        match code {
            KeyCode::PageUp => draft.scroll = draft.scroll.saturating_sub(rows),
            KeyCode::PageDown => draft.scroll = draft.scroll.saturating_add(rows),
            _ => {}
        }
    }

    fn context_text_key(&mut self, key: KeyEvent) -> InputUpdate {
        if let Some(text) = text_key_insert(key) {
            self.insert_context_text(&text);
        } else {
            let draft = self.context_edit_draft_mut().unwrap();
            draft.entries[draft.cursor]
                .editor
                .as_mut()
                .unwrap()
                .handle_key(key);
        }
        InputUpdate::handled()
    }

    fn insert_context_text(&mut self, text: &str) {
        let draft = self.context_edit_draft_mut().unwrap();
        let entry = &mut draft.entries[draft.cursor];
        let maximum = if entry.pointer.is_some() {
            MAX_CONTEXT_EDIT_BYTES
        } else {
            2048
        };
        if text.contains('\0') || entry.text().len() + text.len() > maximum {
            draft.notice = Some(format!(
                "Keep this field within {maximum} bytes; your draft is unchanged."
            ));
            return;
        }
        entry.editor.as_mut().unwrap().insert(text);
        draft.notice = None;
    }

    pub(crate) fn capture_context_edit_paste(&mut self, text: &str) -> bool {
        let Some(mode) = self.context_edit_draft().map(|draft| draft.mode) else {
            return false;
        };
        if mode == ContextEditMode::Writing {
            self.insert_context_text(text);
        } else {
            self.context_edit_draft_mut().unwrap().notice =
                Some("Enter a text field before pasting. Your draft is unchanged.".into());
        }
        true
    }
}

#[derive(Clone, Copy)]
enum FieldAction {
    Edit,
    Review,
    Discard,
}
fn field_action(code: KeyCode) -> Option<FieldAction> {
    [
        (KeyCode::Enter, FieldAction::Edit),
        (KeyCode::Char('r'), FieldAction::Review),
        (KeyCode::Char('d'), FieldAction::Discard),
    ]
    .into_iter()
    .find_map(|(key, action)| (key == code).then_some(action))
}

fn text_key_insert(key: KeyEvent) -> Option<String> {
    if !matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
        return None;
    }
    match key.code {
        KeyCode::Enter => Some("\n".into()),
        KeyCode::Char(ch) => Some(ch.to_string()),
        _ => None,
    }
}
