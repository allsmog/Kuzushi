use super::*;
use crate::app::state_transitions::InputUpdate;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl ShellApp {
    pub(crate) fn handle_source_review_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let mode = self.source_review_form()?.mode;
        if key.modifiers == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('c' | 'd')) {
            if self.runtime_state.source_review_worker.is_none() {
                return None;
            }
            self.close_source_review();
            return Some(InputUpdate::handled());
        }
        if key.code == KeyCode::Esc {
            self.source_review_back(mode);
        } else if mode == SourceReviewMode::Reason {
            self.source_review_reason_key(key);
        } else {
            self.source_review_reading_key(key, mode);
        }
        Some(InputUpdate::handled())
    }

    fn source_review_back(&mut self, mode: SourceReviewMode) {
        let next = match mode {
            SourceReviewMode::Reason => Some(SourceReviewMode::Verdict),
            SourceReviewMode::Verdict => Some(SourceReviewMode::Reading),
            SourceReviewMode::Confirm => Some(SourceReviewMode::Reason),
            _ => None,
        };
        if let Some(next) = next {
            let form = self.source_review_form_mut().unwrap();
            form.mode = next;
            if next == SourceReviewMode::Reading {
                form.scroll = form.reading_scroll;
            }
        } else {
            self.close_source_review();
        }
    }

    fn source_review_reading_key(&mut self, key: KeyEvent, mode: SourceReviewMode) {
        match mode {
            SourceReviewMode::Intro => self.source_review_intro_key(key.code),
            SourceReviewMode::Reading | SourceReviewMode::Saved => {
                self.source_review_code_key(key.code)
            }
            SourceReviewMode::Verdict => self.source_review_verdict_key(key.code),
            SourceReviewMode::Confirm => {
                if key.code == KeyCode::Enter {
                    self.spawn_source_review(true);
                } else {
                    self.page_source_review(key.code);
                }
            }
            _ => {}
        }
    }

    fn source_review_intro_key(&mut self, code: KeyCode) {
        if code == KeyCode::Enter {
            self.spawn_source_review(false);
        } else {
            self.page_source_review(code);
        }
    }

    fn source_review_code_key(&mut self, code: KeyCode) {
        if code == KeyCode::Tab {
            let form = self.source_review_form_mut().unwrap();
            form.show_source_receipt = !form.show_source_receipt;
            form.scroll = 0;
            return;
        }
        if code == KeyCode::Char('r') {
            let form = self.source_review_form_mut().unwrap();
            form.mode = SourceReviewMode::Intro;
            form.scroll = 0;
            return;
        }
        let rows = self.viewport().rows.saturating_sub(10).max(1) as usize;
        let form = self.source_review_form_mut().unwrap();
        match code {
            KeyCode::Enter if form.mode == SourceReviewMode::Reading => {
                form.reading_scroll = form.scroll;
                form.mode = SourceReviewMode::Verdict;
                form.scroll = 0;
            }
            KeyCode::PageDown => form.scroll = form.scroll.saturating_add(rows),
            KeyCode::PageUp => form.scroll = form.scroll.saturating_sub(rows),
            KeyCode::Down => form.scroll = form.scroll.saturating_add(1),
            KeyCode::Up => form.scroll = form.scroll.saturating_sub(1),
            _ => {}
        }
    }

    fn source_review_verdict_key(&mut self, code: KeyCode) {
        let form = self.source_review_form_mut().unwrap();
        match code {
            KeyCode::Down | KeyCode::Tab => {
                form.verdict = (form.verdict + 1) % SOURCE_VERDICTS.len()
            }
            KeyCode::Up | KeyCode::BackTab => {
                form.verdict = (form.verdict + SOURCE_VERDICTS.len() - 1) % SOURCE_VERDICTS.len()
            }
            KeyCode::Enter => form.mode = SourceReviewMode::Reason,
            _ => {}
        }
    }

    fn source_review_reason_key(&mut self, key: KeyEvent) {
        if key == KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL) {
            let form = self.source_review_form_mut().unwrap();
            if form.reason.text().trim().is_empty() {
                form.notice = Some("Add a reason before reviewing the decision.".into());
            } else {
                form.mode = SourceReviewMode::Confirm;
                form.notice = None;
                form.scroll = 0;
            }
            return;
        }
        let form = self.source_review_form_mut().unwrap();
        if key.code == KeyCode::Enter {
            form.reason.insert("\n");
        } else {
            form.reason.handle_key(key);
        }
        form.notice = None;
    }
}

impl ShellApp {
    fn page_source_review(&mut self, code: KeyCode) {
        let page = self.viewport().rows.saturating_sub(10).max(1) as usize;
        let form = self.source_review_form_mut().unwrap();
        match code {
            KeyCode::PageDown => form.scroll = form.scroll.saturating_add(page),
            KeyCode::PageUp => form.scroll = form.scroll.saturating_sub(page),
            KeyCode::Down => form.scroll = form.scroll.saturating_add(1),
            KeyCode::Up => form.scroll = form.scroll.saturating_sub(1),
            _ => {}
        }
    }
}
