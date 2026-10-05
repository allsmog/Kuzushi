use super::*;

impl ShellApp {
    pub(super) fn handle_confirm_mouse(&mut self, mouse: MouseEvent) -> Option<InputUpdate> {
        self.advisory().pending_confirm.as_ref()?;
        if self.shell_view() == ShellView::QuitConfirm {
            return None;
        }
        let key = match mouse.kind {
            MouseEventKind::ScrollUp => Some(KeyCode::Up),
            MouseEventKind::ScrollDown => Some(KeyCode::Down),
            _ => None,
        };
        if let Some(code) = key {
            self.handle_allowance_review_key(KeyEvent::new(code, KeyModifiers::NONE));
        }
        Some(InputUpdate::handled())
    }

    pub(super) fn handle_allowance_review_key(&mut self, key: KeyEvent) -> bool {
        if key.modifiers != KeyModifiers::NONE {
            return false;
        }
        let viewport = self.viewport();
        let Some(model) =
            crate::ui_view_models::allowance_review_model(self, viewport.columns, viewport.rows)
        else {
            return false;
        };
        let Some(next) = scroll_offset(key.code, &model) else {
            return false;
        };
        self.advisory_mut().confirm_scroll = next.min(model.max_offset);
        true
    }
}

fn scroll_offset(
    key: KeyCode,
    model: &crate::ui_view_models::AllowanceReviewModel,
) -> Option<usize> {
    let page = model.page_rows.max(1);
    let down = model.offset.saturating_add(1);
    let up = model.offset.saturating_sub(1);
    [
        (KeyCode::PageDown, model.offset.saturating_add(page)),
        (KeyCode::PageUp, model.offset.saturating_sub(page)),
        (KeyCode::Down, down),
        (KeyCode::Char('j'), down),
        (KeyCode::Up, up),
        (KeyCode::Char('k'), up),
        (KeyCode::Home, 0),
        (KeyCode::End, model.max_offset),
    ]
    .into_iter()
    .find_map(|(candidate, offset)| (candidate == key).then_some(offset))
}
