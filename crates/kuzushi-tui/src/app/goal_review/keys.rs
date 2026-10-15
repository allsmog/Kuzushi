use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl ShellApp {
    pub(crate) fn handle_goal_review_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<state_transitions::InputUpdate> {
        self.goal_review()?;
        if key.modifiers == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('c' | 'd')) {
            return None;
        }
        if self.runtime_state.goal_review.show_history {
            self.goal_history_key(key.code);
        } else if self.runtime_state.goal_review.show_keys {
            self.goal_help_key(key.code);
        } else if self.runtime_state.goal_review.discarding {
            self.goal_discard_key(key.code);
        } else if self.runtime_state.goal_review.editing {
            self.goal_form_key(key);
        } else {
            self.goal_browse_key(key.code);
        }
        Some(state_transitions::InputUpdate::handled())
    }

    fn goal_history_key(&mut self, code: KeyCode) {
        if matches!(code, KeyCode::Esc | KeyCode::Char('h')) {
            self.runtime_state.goal_review.show_history = false;
            self.runtime_state.goal_review.scroll = 0;
        } else {
            self.scroll_goal_review(code);
        }
    }

    fn goal_help_key(&mut self, code: KeyCode) {
        if matches!(code, KeyCode::Esc | KeyCode::Char('?')) {
            self.runtime_state.goal_review.show_keys = false;
            self.runtime_state.goal_review.scroll = 0;
        } else {
            self.scroll_goal_review(code);
        }
    }

    fn goal_discard_key(&mut self, code: KeyCode) {
        let state = &mut self.runtime_state.goal_review;
        match code {
            KeyCode::Enter => {
                state.form = None;
                state.editing = false;
                state.discarding = false;
                state.notice = None;
            }
            KeyCode::Esc => state.discarding = false,
            _ => {}
        }
    }

    fn goal_browse_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => self.runtime_state.goal_review.visible = false,
            KeyCode::Char('h') => self.read_goal_history(),
            KeyCode::Char('?') => {
                self.runtime_state.goal_review.show_keys = true;
                self.runtime_state.goal_review.scroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_goal_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_goal_cursor(-1),
            KeyCode::Char('1') => self.begin_goal_assessment(GoalRelevance::Direct),
            KeyCode::Char('2') => self.begin_goal_assessment(GoalRelevance::Related),
            KeyCode::Char('3') => self.begin_goal_assessment(GoalRelevance::Outside),
            KeyCode::Char('4') => self.begin_goal_assessment(GoalRelevance::Uncertain),
            KeyCode::Char('u') => self.begin_goal_assessment(GoalRelevance::Cleared),
            KeyCode::Char('x') => {
                self.runtime_state.goal_review.discarding =
                    self.runtime_state.goal_review.form.is_some()
            }
            KeyCode::Char('d') => {
                self.runtime_state.goal_review.editing =
                    self.runtime_state.goal_review.form.is_some()
            }
            KeyCode::Char('b') => {
                self.runtime_state.goal_review.show_brief ^= true;
                self.runtime_state.goal_review.scroll = 0;
            }
            KeyCode::Char('i') => {
                self.runtime_state.goal_review.show_receipt ^= true;
                self.runtime_state.goal_review.scroll = 0;
            }
            KeyCode::Char('r') => self.read_goal_review(false),
            KeyCode::Char('R') => self.reset_goal_query(false, true),
            KeyCode::Char('f') => self.reset_goal_query(true, false),
            KeyCode::Char(']') => self.page_goal_review(true),
            KeyCode::Char('[') => self.page_goal_review(false),
            _ => self.scroll_goal_review(code),
        }
    }

    fn move_goal_cursor(&mut self, delta: isize) {
        let state = &mut self.runtime_state.goal_review;
        let Some(Ok(page)) = &state.page else {
            return;
        };
        let current = state
            .selected()
            .and_then(|row| {
                page.rows
                    .iter()
                    .position(|candidate| candidate.basis == row.basis)
            })
            .unwrap_or(state.cursor);
        state.cursor = current
            .saturating_add_signed(delta)
            .min(page.rows.len().saturating_sub(1));
        state.pinned = None;
        state.scroll = 0;
    }

    fn reset_goal_query(&mut self, filter: bool, newer_brief: bool) {
        if self.runtime_state.goal_review_worker.is_some() {
            return;
        }
        let state = &mut self.runtime_state.goal_review;
        if filter {
            state.filter = (state.filter + 1) % GOAL_FILTERS.len();
        }
        state.offset = 0;
        state.cursor = 0;
        state.pinned = None;
        state.scroll = 0;
        self.read_goal_review(newer_brief);
    }

    fn page_goal_review(&mut self, next: bool) {
        if self.runtime_state.goal_review_worker.is_some() {
            return;
        }
        let state = &mut self.runtime_state.goal_review;
        let Some(Ok(page)) = &state.page else {
            return;
        };
        if next && !page.has_more {
            return;
        }
        state.offset = if next {
            state.offset + 50
        } else {
            state.offset.saturating_sub(50)
        };
        state.cursor = 0;
        state.pinned = None;
        state.scroll = 0;
        self.read_goal_review(false);
    }

    fn goal_form_key(&mut self, key: KeyEvent) {
        if self.runtime_state.goal_review_worker.is_some() {
            return;
        }
        if key.code == KeyCode::Esc {
            self.back_goal_form();
            return;
        }
        let confirming = self
            .runtime_state
            .goal_review
            .form
            .as_ref()
            .is_some_and(|form| form.confirming);
        if confirming {
            self.goal_confirm_key(key.code);
        } else {
            self.goal_reason_key(key);
        }
    }

    fn back_goal_form(&mut self) {
        let state = &mut self.runtime_state.goal_review;
        let Some(form) = state.form.as_mut() else {
            return;
        };
        if form.confirming {
            form.confirming = false;
        } else {
            state.editing = false;
        }
    }

    fn goal_confirm_key(&mut self, code: KeyCode) {
        if code == KeyCode::Enter {
            self.save_goal_review();
        } else {
            self.scroll_goal_review(code);
        }
    }

    fn goal_reason_key(&mut self, key: KeyEvent) {
        if key == KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL) {
            self.review_goal_reason();
            return;
        }
        let Some(form) = self.runtime_state.goal_review.form.as_mut() else {
            return;
        };
        if key.code == KeyCode::Enter {
            form.reason.insert("\n");
        } else {
            form.reason.handle_key(key);
        }
    }

    fn review_goal_reason(&mut self) {
        let state = &mut self.runtime_state.goal_review;
        let Some(form) = state.form.as_mut() else {
            return;
        };
        if form.reason.text().trim().is_empty() || form.reason.text().len() > 4096 {
            state.notice = Some("Add a reason containing 1 to 4096 bytes.".into());
            return;
        }
        form.confirming = true;
        state.scroll = 0;
        state.notice = None;
    }

    fn scroll_goal_review(&mut self, code: KeyCode) {
        let page = self.viewport().rows.saturating_sub(8).max(1) as usize;
        let state = &mut self.runtime_state.goal_review;
        match code {
            KeyCode::PageDown => state.scroll = state.scroll.saturating_add(page),
            KeyCode::PageUp => state.scroll = state.scroll.saturating_sub(page),
            KeyCode::Home => state.scroll = 0,
            KeyCode::End => state.scroll = usize::MAX,
            _ => {}
        }
    }
}
