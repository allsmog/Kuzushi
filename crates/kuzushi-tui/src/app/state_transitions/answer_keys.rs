use super::text_input::chord_modified;
use super::*;
use crate::app::AnswerFocus;
use crate::ui_view_models::{
    answer_document, answer_scroll_start, answers_available, answers_layout, answers_own_input,
};

impl ShellApp {
    pub(crate) fn open_answers(&mut self) {
        if !answers_available(self) {
            self.set_info_notice(
                "answers",
                "Return to the workspace to read answers (workbench, then answers).",
            );
            return;
        }
        self.start_answer_recovery();
        self.router.answers_mut().open();
    }

    pub(super) fn handle_answer_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !answers_available(self) {
            return None;
        }
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('t') {
            self.toggle_answers();
            return Some(InputUpdate::handled());
        }
        if !answers_own_input(self) {
            return None;
        }
        self.reduce_focused_answer_key(key)
    }

    fn reduce_focused_answer_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if answer_yields_key(key) {
            return self.cancel_focused_ask(key);
        }
        Some(self.reduce_answer_input(key))
    }

    fn toggle_answers(&mut self) {
        if answers_own_input(self) {
            self.router.answers_mut().focus = AnswerFocus::Workspace;
        } else {
            self.open_answers();
        }
    }

    fn cancel_focused_ask(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if key.code != KeyCode::Char('c') || !self.agent_chat().is_some_and(|chat| chat.running) {
            return None;
        }
        Some(InputUpdate::handled_with_effects(vec![
            ShellEffect::CancelJob(JobKind::Agent),
        ]))
    }

    fn reduce_answer_input(&mut self, key: KeyEvent) -> InputUpdate {
        if self.router.answers().focus == AnswerFocus::Reply {
            return self.reduce_answer_reply(key);
        }
        if self.select_answer_history(key) || self.scroll_answer(key) {
            return InputUpdate::handled();
        }
        match key.code {
            KeyCode::Esc => self.router.answers_mut().close(),
            KeyCode::Enter => self.router.answers_mut().reply(),
            KeyCode::Char(_) if !chord_modified(key) => {
                self.router.answers_mut().reply();
                self.router.answers_mut().draft.handle_key(key);
            }
            _ => {}
        }
        InputUpdate::handled()
    }

    fn reduce_answer_reply(&mut self, key: KeyEvent) -> InputUpdate {
        if key.code == KeyCode::Enter && key.modifiers.is_empty() {
            return self.submit_answer_reply();
        }
        match (key.code, key.modifiers) {
            (KeyCode::Esc, KeyModifiers::NONE) => {
                self.router.answers_mut().focus = AnswerFocus::Reading
            }
            (KeyCode::Enter, KeyModifiers::SHIFT | KeyModifiers::ALT) => {
                self.router.answers_mut().draft.insert("\n")
            }
            (KeyCode::Char('s'), KeyModifiers::CONTROL) => return self.submit_answer_reply(),
            _ => {
                self.router.answers_mut().draft.handle_key(key);
            }
        }
        InputUpdate::handled()
    }

    fn submit_answer_reply(&mut self) -> InputUpdate {
        let question = self.router.answers().draft.text().to_string();
        let effects = self.reduce_ask_agent(&AskRequest::screen(question));
        InputUpdate::handled_with_effects(effects)
    }

    pub(super) fn capture_answer_paste(&mut self, text: &str) -> bool {
        if !answers_own_input(self) {
            return false;
        }
        self.router.answers_mut().reply();
        self.router.answers_mut().draft.insert(text);
        true
    }

    fn select_answer_history(&mut self, key: KeyEvent) -> bool {
        if key.modifiers != KeyModifiers::ALT {
            return false;
        }
        let delta = match key.code {
            KeyCode::Left => 1,
            KeyCode::Right => -1,
            _ => return false,
        };
        let count = self.agent_chat_history().len();
        self.router.answers_mut().select_history(delta, count);
        true
    }

    pub(super) fn scroll_answer(&mut self, key: KeyEvent) -> bool {
        if !key.modifiers.is_empty() {
            return false;
        }
        let viewport = self.viewport();
        let area = crate::renderer::primary_body_area(
            self,
            ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows),
        );
        let Some(pane) = answers_layout(self, area).answers else {
            return false;
        };
        let body = crate::renderer::answer_body_area(pane);
        let doc = answer_document(self, body.width as usize);
        let start = answer_scroll_start(self, &doc, body.height as usize);
        let page = usize::from(body.height).max(1);
        let Some(next) = answer_scroll_offset(key.code, start, page, doc.lines.len()) else {
            return false;
        };
        self.router.answers_mut().scroll = Some(next);
        true
    }
}

fn answer_yields_key(key: KeyEvent) -> bool {
    key.modifiers == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('c' | 'd' | 'g'))
}

fn answer_scroll_offset(key: KeyCode, start: usize, page: usize, count: usize) -> Option<usize> {
    let next = match key {
        KeyCode::Up => start.saturating_sub(1),
        KeyCode::Down => start.saturating_add(1),
        KeyCode::PageUp => start.saturating_sub(page),
        KeyCode::PageDown => start.saturating_add(page),
        KeyCode::Home => 0,
        KeyCode::End => count,
        _ => return None,
    };
    Some(next.min(count.saturating_sub(page)))
}

#[cfg(test)]
mod tests;
