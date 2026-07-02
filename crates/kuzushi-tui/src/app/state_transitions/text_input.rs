use super::*;

impl ShellApp {
    pub(super) fn handle_text_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(ch) => self.insert_printable_key(ch),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Tab => self.apply_completion(),
            KeyCode::PageDown if self.input.is_empty() && key.modifiers.is_empty() => {
                self.page_down_current_view();
            }
            KeyCode::PageUp if self.input.is_empty() && key.modifiers.is_empty() => {
                self.page_up_current_view();
            }
            KeyCode::Enter => self.handle_enter_key(),
            KeyCode::Esc => return self.esc_clear_input_or_completion(),
            _ => return false,
        }
        true
    }

    pub(super) fn insert_printable_key(&mut self, ch: char) {
        self.insert_char_at_cursor(ch);
        self.last_char_at = Some(Instant::now());
    }

    pub(super) fn handle_enter_key(&mut self) {
        let raw = self.take_input();
        if self.submit_catalog_cursor_for_empty_enter(&raw) {
            return;
        }
        self.submit_line(&raw);
    }

    pub(super) fn submit_catalog_cursor_for_empty_enter(&mut self, raw: &str) -> bool {
        if !raw.is_empty()
            || !matches!(self.shell_view, ShellView::Catalog)
            || !self.catalog_expanded
        {
            return false;
        }
        let Some(id) = self.catalog_cursor_module_id() else {
            return false;
        };
        self.submit_line(&format!("use {id}"));
        true
    }

    pub(super) fn clear_conversation_preserving_input(&mut self) {
        let saved_input = std::mem::take(&mut self.input);
        let saved_cursor = self.cursor;
        self.clear_conversation();
        self.input = saved_input;
        self.cursor = saved_cursor.min(self.input.chars().count());
    }

    pub fn handle_paste(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let normalised: String = text
            .replace("\r\n", "\n")
            .chars()
            .filter(|ch| *ch != '\r')
            .collect();
        if self.capture_auth_key_paste(&normalised) {
            return;
        }
        // Multi-line pastes: keep the first line so the user can review and
        // submit explicitly, then warn about the dropped tail. Submitting
        // every \n-separated line as its own command is what bash/zsh do;
        // the kuzushi shell is a single-command-per-Enter prompt and
        // exposing the same behavior runs unintended commands (e.g. pasting
        // a snippet that begins with `rm`).
        if normalised.contains('\n') {
            let first_line = normalised.lines().next().unwrap_or("");
            let total = normalised.chars().count();
            let kept = first_line.chars().count();
            self.insert_str_at_cursor(first_line);
            let dropped_lines = normalised.lines().count().saturating_sub(1);
            self.set_warn_notice(
                "paste",
                format!(
                    "kept first line ({kept}/{total} chars); dropped {dropped_lines} more line(s). Submit, then paste the next part."
                ),
            );
            return;
        }
        self.insert_str_at_cursor(&normalised);
    }

    fn capture_auth_key_paste(&mut self, text: &str) -> bool {
        if !matches!(self.shell_view, ShellView::AuthMethodPicker(_))
            || self.auth_picker_cursor != 0
        {
            return false;
        }
        let key = text.lines().next().unwrap_or("").trim();
        if key.is_empty() {
            return true;
        }
        self.auth_key_draft.push_str(key);
        if text.contains('\n') {
            self.set_warn_notice(
                "paste",
                "kept first pasted line as API key draft; extra lines ignored",
            );
        }
        true
    }

    /// The wheel moves the FINDINGS cursor only when the Workbench has that
    /// pane focused and there are findings; everywhere else it scrolls lines.
    fn mouse_scrolls_findings(&self) -> bool {
        matches!(self.shell_view, ShellView::Workbench)
            && self.workbench_focus == crate::app::WorkbenchPane::Findings
            && !self.findings.is_empty()
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                self.handle_left_mouse_down(mouse.column, mouse.row);
            }
            MouseEventKind::ScrollUp => self.handle_mouse_scroll(-1),
            MouseEventKind::ScrollDown => self.handle_mouse_scroll(1),
            _ => {}
        }
    }

    fn handle_left_mouse_down(&mut self, column: u16, row: u16) {
        if let Some(pane) = self.workbench_pane_for_mouse(column, row) {
            self.workbench_focus = pane;
            return;
        }
        if let (Some(focus), Some(session)) = (
            self.activity_pane_for_mouse(column, row),
            self.activity.as_mut(),
        ) {
            session.pane_focus = focus;
        }
    }

    fn handle_mouse_scroll(&mut self, amount: i32) {
        if self.mouse_scrolls_findings() {
            self.move_findings_cursor(amount);
        } else if amount.is_negative() {
            self.scroll_up(1);
        } else {
            self.scroll_down(1);
        }
    }

    fn move_findings_cursor(&mut self, amount: i32) {
        if amount.is_negative() {
            self.findings_cursor = self.findings_cursor.saturating_sub(1);
        } else {
            self.findings_cursor =
                (self.findings_cursor + 1).min(self.findings.len().saturating_sub(1));
        }
    }

    fn workbench_pane_for_mouse(&self, column: u16, row: u16) -> Option<crate::app::WorkbenchPane> {
        if !matches!(self.shell_view, ShellView::Workbench) {
            return None;
        }
        let (width, height) = crossterm::terminal::size().unwrap_or((160, 40));
        workbench_pane_for_click(column, row, width, height)
    }

    fn activity_pane_for_mouse(&self, column: u16, row: u16) -> Option<crate::app::PaneFocus> {
        if !matches!(self.shell_view, ShellView::Activity) {
            return None;
        }
        let session = self.activity.as_ref()?;
        let (width, height) = crossterm::terminal::size().unwrap_or((160, 40));
        activity_pane_for_click(column, row, width, height, session.tasks.is_empty())
    }
}

fn workbench_pane_for_click(
    column: u16,
    row: u16,
    width: u16,
    height: u16,
) -> Option<crate::app::WorkbenchPane> {
    if width < 8 || height < 3 {
        return None;
    }
    Some(workbench_click_layout(width, height).pane_for_click(column, row, width, height))
}

const WORKBENCH_FOUR_COLUMN_MIN_WIDTH: u16 = 120;
const WORKBENCH_THREE_COLUMN_MIN_WIDTH: u16 = 100;
const WORKBENCH_STACKED_MIN_TERMINAL_HEIGHT: u16 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkbenchClickLayout {
    FourColumn,
    ThreeColumn,
    Stacked,
    ShortReview,
}

impl WorkbenchClickLayout {
    fn pane_for_click(
        self,
        column: u16,
        row: u16,
        width: u16,
        height: u16,
    ) -> crate::app::WorkbenchPane {
        match self {
            WorkbenchClickLayout::FourColumn => {
                four_column_workbench_pane_for_column(column, width)
            }
            WorkbenchClickLayout::ThreeColumn => {
                three_column_workbench_pane_for_column(column, width)
            }
            WorkbenchClickLayout::Stacked => stacked_workbench_pane_for_row(row, height),
            WorkbenchClickLayout::ShortReview => short_review_workbench_pane_for_row(row, height),
        }
    }
}

fn workbench_click_layout(width: u16, height: u16) -> WorkbenchClickLayout {
    match (
        width >= WORKBENCH_FOUR_COLUMN_MIN_WIDTH,
        width >= WORKBENCH_THREE_COLUMN_MIN_WIDTH,
        height >= WORKBENCH_STACKED_MIN_TERMINAL_HEIGHT,
    ) {
        (true, _, _) => WorkbenchClickLayout::FourColumn,
        (_, true, _) => WorkbenchClickLayout::ThreeColumn,
        (_, _, true) => WorkbenchClickLayout::Stacked,
        _ => WorkbenchClickLayout::ShortReview,
    }
}

fn four_column_workbench_pane_for_column(column: u16, width: u16) -> crate::app::WorkbenchPane {
    let source = (width * 14 / 100).clamp(18, 32);
    let findings = (width * 23 / 100).clamp(34, 56);
    let mut center = (width * 30 / 100).clamp(32, 76);
    let details_min = 44;
    let fixed = source + findings + center;
    if fixed + details_min > width {
        let reducible = center.saturating_sub(24);
        let needed = fixed + details_min - width;
        center = center.saturating_sub(needed.min(reducible));
    }
    if column < source {
        crate::app::WorkbenchPane::Source
    } else if column < source + center {
        crate::app::WorkbenchPane::Center
    } else if column < source + center + findings {
        crate::app::WorkbenchPane::Findings
    } else {
        crate::app::WorkbenchPane::Details
    }
}

fn three_column_workbench_pane_for_column(column: u16, width: u16) -> crate::app::WorkbenchPane {
    let center = (width * 34 / 100).clamp(32, 52);
    let findings = (width * 30 / 100).clamp(30, 44);
    if column < center {
        crate::app::WorkbenchPane::Center
    } else if column < center + findings {
        crate::app::WorkbenchPane::Findings
    } else {
        crate::app::WorkbenchPane::Details
    }
}

fn stacked_workbench_pane_for_row(row: u16, height: u16) -> crate::app::WorkbenchPane {
    match row.saturating_mul(4) / height.max(1) {
        0 => crate::app::WorkbenchPane::Source,
        1 => crate::app::WorkbenchPane::Center,
        2 => crate::app::WorkbenchPane::Findings,
        _ => crate::app::WorkbenchPane::Details,
    }
}

fn short_review_workbench_pane_for_row(row: u16, height: u16) -> crate::app::WorkbenchPane {
    if row < height / 2 {
        crate::app::WorkbenchPane::Findings
    } else {
        crate::app::WorkbenchPane::Details
    }
}

fn activity_pane_for_click(
    column: u16,
    row: u16,
    width: u16,
    height: u16,
    tasks_empty: bool,
) -> Option<crate::app::PaneFocus> {
    if width < 8 || height < 6 {
        return None;
    }
    let layout = crate::ui_view_models::activity_frame_layout();
    if !activity_body_contains_row(row, height, layout.header_rows, layout.footer_rows) {
        return None;
    }
    Some(activity_body_pane_for_column(
        column,
        width,
        layout.dag_percent,
        tasks_empty,
    ))
}

fn activity_body_contains_row(row: u16, height: u16, header_rows: u16, footer_rows: u16) -> bool {
    row >= header_rows && row < height.saturating_sub(footer_rows)
}

fn activity_body_pane_for_column(
    column: u16,
    width: u16,
    dag_percent: u16,
    tasks_empty: bool,
) -> crate::app::PaneFocus {
    if tasks_empty {
        return crate::app::PaneFocus::Right;
    }
    let task_width = (width * dag_percent / 100).max(1);
    if column < task_width {
        crate::app::PaneFocus::Left
    } else {
        crate::app::PaneFocus::Right
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_column_workbench_clicks_map_to_horizontal_panes() {
        assert_eq!(
            workbench_pane_for_click(2, 10, 120, 24),
            Some(crate::app::WorkbenchPane::Source)
        );
        assert_eq!(
            workbench_pane_for_click(20, 10, 120, 24),
            Some(crate::app::WorkbenchPane::Center)
        );
        assert_eq!(
            workbench_pane_for_click(50, 10, 120, 24),
            Some(crate::app::WorkbenchPane::Findings)
        );
        assert_eq!(
            workbench_pane_for_click(90, 10, 120, 24),
            Some(crate::app::WorkbenchPane::Details)
        );
    }

    #[test]
    fn three_column_workbench_clicks_skip_source() {
        assert_eq!(
            workbench_pane_for_click(2, 10, 110, 24),
            Some(crate::app::WorkbenchPane::Center)
        );
        assert_eq!(
            workbench_pane_for_click(45, 10, 110, 24),
            Some(crate::app::WorkbenchPane::Findings)
        );
        assert_eq!(
            workbench_pane_for_click(90, 10, 110, 24),
            Some(crate::app::WorkbenchPane::Details)
        );
    }

    #[test]
    fn narrow_tall_workbench_clicks_map_to_vertical_panes() {
        assert_eq!(
            workbench_pane_for_click(10, 2, 80, 30),
            Some(crate::app::WorkbenchPane::Source)
        );
        assert_eq!(
            workbench_pane_for_click(10, 10, 80, 30),
            Some(crate::app::WorkbenchPane::Center)
        );
        assert_eq!(
            workbench_pane_for_click(10, 18, 80, 30),
            Some(crate::app::WorkbenchPane::Findings)
        );
        assert_eq!(
            workbench_pane_for_click(10, 26, 80, 30),
            Some(crate::app::WorkbenchPane::Details)
        );
    }

    #[test]
    fn narrow_short_workbench_clicks_map_to_review_panes() {
        assert_eq!(
            workbench_pane_for_click(10, 8, 80, 24),
            Some(crate::app::WorkbenchPane::Findings)
        );
        assert_eq!(
            workbench_pane_for_click(10, 18, 80, 24),
            Some(crate::app::WorkbenchPane::Details)
        );
    }

    #[test]
    fn activity_clicks_map_to_visible_panes() {
        assert_eq!(
            activity_pane_for_click(4, 4, 120, 40, false),
            Some(crate::app::PaneFocus::Left)
        );
        assert_eq!(
            activity_pane_for_click(80, 4, 120, 40, false),
            Some(crate::app::PaneFocus::Right)
        );
        assert_eq!(
            activity_pane_for_click(4, 4, 120, 40, true),
            Some(crate::app::PaneFocus::Right)
        );
        assert_eq!(activity_pane_for_click(4, 1, 120, 40, false), None);
    }
}
