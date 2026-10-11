//! Lesson review owns its inputs and returns background receipts without moving focus.
use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::findings::{
    FindingLesson, FindingLessonPage, LessonContent, LessonRef, LessonState,
};
use std::path::PathBuf;
mod state;
pub(crate) use state::{LessonForm, LessonFormAction, LessonWrite, LessonsRouteState};
mod context;
mod form;
mod write;

impl ShellApp {
    pub(crate) fn open_lessons(&mut self) {
        let target = self.target_owned();
        if self.router.lessons.target != target {
            self.router.lessons = LessonsRouteState {
                target,
                ..Default::default()
            };
        }
        self.router.lessons.finding_id = crate::ui_view_models::visible_finding_at_cursor(self)
            .and_then(|(_, finding)| finding.id);
        self.set_shell_view(ShellView::Lessons);
        self.set_input_mode(InputMode::Navigate);
    }

    pub(crate) fn lesson_page(&self) -> ViewDataState<Result<FindingLessonPage, String>> {
        let Some(target) = self.target_owned() else {
            return ViewDataState::NotRequested;
        };
        self.workbench_cache()
            .borrow()
            .lesson_pages
            .get(&(target, self.router.lessons.offset))
            .cloned()
            .map(ViewDataState::Ready)
            .unwrap_or(ViewDataState::Loading)
    }

    pub(crate) fn selected_lesson(&self) -> Option<FindingLesson> {
        let ViewDataState::Ready(Ok(page)) = self.lesson_page() else {
            return None;
        };
        page.rows.get(self.lesson_cursor(&page)?).cloned()
    }

    pub(crate) fn lesson_cursor(&self, page: &FindingLessonPage) -> Option<usize> {
        if let Some(id) = &self.router.lessons.pinned_id {
            return page.rows.iter().position(|row| &row.id == id);
        }
        (!page.rows.is_empty()).then(|| self.router.lessons.cursor.min(page.rows.len() - 1))
    }

    pub(crate) fn handle_lesson_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<state_transitions::InputUpdate> {
        if !self.lesson_surface_owns_key(key) {
            return None;
        }
        if let Some(update) = self.handle_lesson_modal_key(key) {
            return Some(update);
        }
        if self.input_mode() != InputMode::Navigate {
            return None;
        }
        self.handle_lesson_browse_key(key.code)
            .then(state_transitions::InputUpdate::handled)
    }

    fn lesson_surface_owns_key(&self, key: KeyEvent) -> bool {
        let interrupt =
            key.modifiers == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('c' | 'd'));
        self.shell_view() == ShellView::Lessons && !interrupt
    }

    fn handle_lesson_modal_key(&mut self, key: KeyEvent) -> Option<state_transitions::InputUpdate> {
        if self.router.lessons.form_visible {
            self.handle_lesson_form_key(key);
            return Some(state_transitions::InputUpdate::handled());
        }
        if self.router.lessons.context_selecting {
            self.handle_lesson_context_key(key);
            return Some(state_transitions::InputUpdate::handled());
        }
        None
    }

    fn handle_lesson_browse_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Esc => self.go_back(),
            KeyCode::Up | KeyCode::Char('k') => self.move_lesson(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_lesson(1),
            KeyCode::Char('n') => self.begin_lesson_draft(false),
            KeyCode::Char('e') => self.begin_lesson_draft(true),
            KeyCode::Char('d') => {
                self.router.lessons.form_visible = self.router.lessons.form.is_some()
            }
            KeyCode::Char('a') => self.begin_lesson_review(LessonState::Accepted),
            KeyCode::Char('r') => self.begin_lesson_review(LessonState::Rejected),
            KeyCode::Char('t') => self.begin_lesson_review(LessonState::Retired),
            KeyCode::Char(' ') => self.toggle_lesson_selection(),
            KeyCode::Char('u') => self.begin_lesson_context(),
            KeyCode::Char('g') => self.plan_lesson_generation(),
            KeyCode::Char('c') => self.router.lessons.selected.clear(),
            KeyCode::Char('R') => self.refresh_lessons(),
            KeyCode::Char(']') => self.change_lesson_page(true),
            KeyCode::Char('[') => self.change_lesson_page(false),
            _ => return false,
        }
        true
    }

    fn move_lesson(&mut self, delta: isize) {
        let ViewDataState::Ready(Ok(page)) = self.lesson_page() else {
            return;
        };
        let current = self.lesson_cursor(&page).unwrap_or_default();
        self.router.lessons.pinned_id = None;
        self.router.lessons.cursor = current
            .saturating_add_signed(delta)
            .min(page.rows.len().saturating_sub(1));
        self.router.default_scroll_mut().set(0);
    }

    fn change_lesson_page(&mut self, next: bool) {
        let ViewDataState::Ready(Ok(page)) = self.lesson_page() else {
            return;
        };
        if next && !page.has_more {
            return;
        }
        self.router.lessons.offset = if next {
            page.offset + 50
        } else {
            page.offset.saturating_sub(50)
        };
        self.router.lessons.cursor = 0;
        self.router.lessons.pinned_id = None;
        self.router.default_scroll_mut().set(0);
    }

    pub(super) fn refresh_lessons(&mut self) {
        self.workbench_cache().borrow_mut().lesson_pages.clear();
        self.router.lessons.notice = None;
    }
}

#[cfg(test)]
mod tests;
