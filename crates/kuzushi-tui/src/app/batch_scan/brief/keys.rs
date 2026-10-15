use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::capabilities::campaign::MAX_BRIEF_TEXT_BYTES;

impl ShellApp {
    pub(crate) fn handle_brief_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let mode = self.brief_editor()?.mode;
        if key.code == KeyCode::Esc {
            self.brief_back(mode);
            return Some(InputUpdate::handled());
        }
        if key == KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL) {
            self.review_brief();
            return Some(InputUpdate::handled());
        }
        if mode == BriefMode::Writing {
            self.write_brief_key(key);
            return Some(InputUpdate::handled());
        }
        Some(self.brief_read_key(key.code, mode))
    }

    fn brief_back(&mut self, mode: BriefMode) {
        if matches!(mode, BriefMode::Writing | BriefMode::Review) {
            self.brief_editor_mut().unwrap().mode = BriefMode::Read;
        } else {
            self.close_brief();
        }
    }

    fn write_brief_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Enter {
            self.insert_brief_text("\n");
            return;
        }
        if let KeyCode::Char(ch) = key.code {
            if matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
                self.insert_brief_text(&ch.to_string());
                return;
            }
        }
        self.brief_editor_mut().unwrap().editor.handle_key(key);
    }

    fn brief_read_key(&mut self, code: KeyCode, mode: BriefMode) -> InputUpdate {
        if matches!(mode, BriefMode::Loading | BriefMode::Saving) {
            return InputUpdate::handled();
        }
        match code {
            KeyCode::Char('e') => self.brief_editor_mut().unwrap().mode = BriefMode::Writing,
            KeyCode::Enter if mode == BriefMode::Review => return self.save_reviewed_brief(),
            KeyCode::Char('a') if mode == BriefMode::Read => self.use_loaded_brief(),
            KeyCode::Char('r') => return self.refresh_brief(),
            code => self.scroll_brief(code),
        }
        InputUpdate::handled()
    }

    fn scroll_brief(&mut self, code: KeyCode) {
        let checkpoint = self.study_checkpoint_note();
        let notices = crate::ui_view_models::study_config::brief::notice_lines(
            self.brief_editor().unwrap(),
            checkpoint.as_deref(),
        )
        .len()
        .min(2) as u16;
        let page = self.viewport().rows.saturating_sub(4 + notices).max(1) as usize;
        let editor = self.brief_editor_mut().unwrap();
        match code {
            KeyCode::Up => editor.scroll = editor.scroll.saturating_sub(1),
            KeyCode::Down => editor.scroll = editor.scroll.saturating_add(1),
            KeyCode::PageUp => editor.scroll = editor.scroll.saturating_sub(page),
            KeyCode::PageDown => editor.scroll = editor.scroll.saturating_add(page),
            KeyCode::Home => editor.scroll = 0,
            _ => {}
        }
    }

    pub(crate) fn capture_brief_paste(&mut self, text: &str) -> bool {
        let Some(mode) = self.brief_editor().map(|editor| editor.mode) else {
            return false;
        };
        if mode == BriefMode::Writing {
            self.insert_brief_text(text);
        }
        self.checkpoint_study_choices();
        true
    }

    fn insert_brief_text(&mut self, text: &str) {
        let editor = self.brief_editor_mut().unwrap();
        if text.contains('\0')
            || editor.editor.text().len().saturating_add(text.len()) > MAX_BRIEF_TEXT_BYTES
        {
            editor.notice =
                Some("Keep the brief within 8192 bytes; your draft is unchanged.".into());
            return;
        }
        editor.editor.insert(text);
        editor.notice = None;
    }

    fn review_brief(&mut self) {
        let editor = self.brief_editor_mut().unwrap();
        if matches!(editor.mode, BriefMode::Loading | BriefMode::Saving) {
            return;
        }
        if editor.editor.text().trim().is_empty() {
            editor.notice = Some("Enter a goal and priorities before review.".into());
            return;
        }
        editor.mode = BriefMode::Review;
        editor.scroll = 0;
    }

    fn save_reviewed_brief(&mut self) -> InputUpdate {
        let study = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .investigation_id
            .clone();
        let editor = self.brief_editor_mut().unwrap();
        let revision = editor
            .loaded
            .as_ref()
            .map_or(0, |brief| brief.reference.revision);
        let input = json!({"mode":"save","expectedRevision":revision,"text":editor.editor.text()});
        editor.mode = BriefMode::Saving;
        editor.pending_study = Some(study);
        self.dispatch_brief(input)
    }

    fn refresh_brief(&mut self) -> InputUpdate {
        let editor = self.brief_editor_mut().unwrap();
        editor.preserve_text = true;
        editor.mode = BriefMode::Loading;
        self.dispatch_brief(json!({"mode":"read"}))
    }
}
