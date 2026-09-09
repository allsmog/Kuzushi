use super::*;
use crate::app::AnswerFocus;
use crate::ui_view_models::{answers_available, answers_layout, answers_visible};
use ratatui::layout::{Position, Rect};

impl ShellApp {
    pub(super) fn handle_answer_mouse(&mut self, mouse: MouseEvent) -> Option<InputUpdate> {
        if !answers_available(self) || !answers_visible(self) {
            return None;
        }
        let viewport = self.viewport();
        let full = Rect::new(0, 0, viewport.columns, viewport.rows);
        let area = crate::renderer::primary_body_area(self, full);
        let layout = answers_layout(self, area);
        let point = Position::new(mouse.column, mouse.row);
        if layout.answers.is_some_and(|pane| pane.contains(point)) {
            return Some(self.reduce_answer_mouse(mouse.kind));
        }
        if layout.workspace.contains(point) && changes_answer_focus(mouse.kind) {
            self.router.answers_mut().focus = AnswerFocus::Workspace;
        }
        None
    }

    fn reduce_answer_mouse(&mut self, kind: MouseEventKind) -> InputUpdate {
        if !changes_answer_focus(kind) {
            return InputUpdate::handled();
        }
        self.router.answers_mut().open();
        let code = match kind {
            MouseEventKind::ScrollUp => KeyCode::Up,
            MouseEventKind::ScrollDown => KeyCode::Down,
            _ => return InputUpdate::handled(),
        };
        self.scroll_answer(KeyEvent::new(code, KeyModifiers::NONE));
        InputUpdate::handled()
    }
}

fn changes_answer_focus(kind: MouseEventKind) -> bool {
    matches!(
        kind,
        MouseEventKind::Down(crossterm::event::MouseButton::Left)
            | MouseEventKind::ScrollUp
            | MouseEventKind::ScrollDown
    )
}
