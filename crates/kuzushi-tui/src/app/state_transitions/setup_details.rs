//! Readiness inspection cannot edit, accept or execute a plan.
use super::*;

impl ShellApp {
    pub(super) fn handle_setup_details_key(&mut self, key: KeyEvent) -> InputUpdate {
        let Some(scroll) = crate::renderer::setup_detail_scroll(self) else {
            return InputUpdate::handled();
        };
        let position = self.router.setup().detail_scroll().min(scroll.max_offset);
        let next = match key.code {
            KeyCode::Esc | KeyCode::Tab => {
                self.router.setup_mut().finish_editor();
                return InputUpdate::handled();
            }
            KeyCode::Home => 0,
            KeyCode::End => scroll.max_offset,
            key => moved_setup_detail_position(key, position, scroll.page_rows),
        };
        self.router
            .setup_mut()
            .set_detail_scroll(next.min(scroll.max_offset));
        InputUpdate::handled()
    }

    pub(super) fn leave_setup_details_for_paste(&mut self) {
        if self.shell_view() == ShellView::Setup
            && self.router.setup().editor() == Some(SetupEditor::Details)
        {
            self.router.setup_mut().finish_editor();
        }
    }
}

fn moved_setup_detail_position(key: KeyCode, position: usize, page: usize) -> usize {
    match key {
        KeyCode::Up => position.saturating_sub(1),
        KeyCode::Down => position.saturating_add(1),
        KeyCode::PageUp => position.saturating_sub(page),
        KeyCode::PageDown => position.saturating_add(page),
        _ => position,
    }
}

#[cfg(test)]
mod tests;
