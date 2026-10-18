use super::*;

impl ShellApp {
    pub(crate) fn lesson_reading_is_active(&self) -> bool {
        if self.shell_view() != ShellView::Lessons {
            return false;
        }
        if self.router.lessons.context_selecting {
            return self.router.lessons.context_confirm.is_some();
        }
        if self.router.lessons.form_visible {
            return self
                .router
                .lessons
                .form
                .as_ref()
                .is_some_and(|form| form.confirming);
        }
        true
    }

    pub(super) fn handle_lesson_reading_key(&mut self, key: KeyEvent) -> bool {
        if !key.modifiers.is_empty() || self.lesson_composer_owns_boundary(key.code) {
            return false;
        }
        let Some(scroll) = crate::renderer::lesson_reader_scroll(self) else {
            return false;
        };
        let current = self.router.default_scroll().offset().min(scroll.max_offset);
        let Some(offset) = reading_offset(current, scroll.max_offset, scroll.page_rows, key.code)
        else {
            return false;
        };
        self.router.default_scroll_mut().set(offset);
        true
    }

    fn lesson_composer_owns_boundary(&self, code: KeyCode) -> bool {
        self.input_mode() == InputMode::Prompt
            && !self.router.lessons.context_selecting
            && !self.router.lessons.form_visible
            && matches!(code, KeyCode::Home | KeyCode::End)
    }
}

fn reading_offset(current: u16, maximum: u16, page: u16, code: KeyCode) -> Option<u16> {
    match code {
        KeyCode::Home | KeyCode::End => Some(if code == KeyCode::Home { 0 } else { maximum }),
        KeyCode::PageUp | KeyCode::PageDown => Some(page_offset(
            current,
            maximum,
            page,
            code == KeyCode::PageDown,
        )),
        _ => None,
    }
}

fn page_offset(current: u16, maximum: u16, page: u16, forward: bool) -> u16 {
    if forward {
        current.saturating_add(page).min(maximum)
    } else {
        current.saturating_sub(page)
    }
}
