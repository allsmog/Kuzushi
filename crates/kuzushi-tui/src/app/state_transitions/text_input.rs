use super::*;

impl ShellApp {
    pub(super) fn handle_text_key(&mut self, key: KeyEvent) -> InputUpdate {
        match key.code {
            // Every chord this shell binds has already had its turn by now, so
            // a Ctrl/Alt-modified character here is an *unbound* chord — never
            // text the operator asked to type. Refuse it rather than letting
            // the bare letter land in the composer.
            KeyCode::Char(_) if chord_modified(key) => return InputUpdate::ignored(),
            KeyCode::Char(ch) => self.insert_printable_key(ch),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Tab if !self.ui().keymap_overrides_action("composer", "complete") => {
                self.apply_completion()
            }
            KeyCode::Tab => return InputUpdate::handled(),
            KeyCode::PageDown if self.input().is_empty() && key.modifiers.is_empty() => {
                self.page_down_current_view();
            }
            KeyCode::PageUp if self.input().is_empty() && key.modifiers.is_empty() => {
                self.page_up_current_view();
            }
            KeyCode::Enter => return self.handle_enter_key(),
            KeyCode::Esc => return InputUpdate::handled_if(self.esc_clear_input_or_completion()),
            _ => return InputUpdate::ignored(),
        }
        InputUpdate::handled()
    }

    pub(super) fn insert_printable_key(&mut self, ch: char) {
        let first_char_into_empty_composer = self.input().is_empty();
        self.insert_char_at_cursor(ch);
        self.ui_mut().record_operator_interaction(Instant::now());
        // First-session operators reliably press j/k expecting the list to
        // move and conclude the app hung when letters land in the composer
        // instead — say where the keys went, once per session.
        if first_char_into_empty_composer
            && self.shell_view() == ShellView::Workbench
            && self.ui_mut().take_typing_hint()
        {
            self.log(
                "keys",
                "typing goes to the command line — Esc (empty prompt) switches to list keys (j/k move, Enter opens)",
            );
        }
    }

    pub(super) fn handle_enter_key(&mut self) -> InputUpdate {
        let raw = self.take_input();
        let update = self.reduce_submitted_line(&raw);
        InputUpdate {
            handled: update.handled,
            effects: update.effects,
        }
    }

    pub(super) fn clear_conversation_preserving_input(&mut self) -> Vec<ShellEffect> {
        let snapshot = self.editor().snapshot_input();
        let effects = self.clear_conversation();
        self.editor_mut().restore_input_snapshot(snapshot);
        effects
    }

    pub(crate) fn reduce_paste(&mut self, text: &str) -> InputUpdate {
        if let Some(update) = self.paste_preflight(text) {
            return update;
        }
        let normalised = normalise_paste_text(text);
        if let Some(update) = self.capture_picker_editor_paste(&normalised) {
            return update;
        }
        if !self.prepare_picker_for_paste() {
            return InputUpdate::handled();
        }
        self.paste_before_prompt(&normalised)
            .unwrap_or_else(|| self.paste_into_prompt(&normalised))
    }

    fn paste_preflight(&self, text: &str) -> Option<InputUpdate> {
        if text.is_empty() {
            return Some(InputUpdate::ignored());
        }
        let confirmation = self.advisory().pending_confirm.is_some()
            || matches!(
                self.shell_view(),
                ShellView::QuitConfirm | ShellView::ConfirmDialog
            );
        confirmation.then(InputUpdate::handled)
    }

    fn prepare_picker_for_paste(&mut self) -> bool {
        if self.picker_surface_accepts_composer_input() {
            self.enter_picker_prompt_focus();
            return true;
        }
        if self.shell_view() == ShellView::FilePicker {
            return true;
        }
        if !self.is_picker_view() {
            return true;
        }
        self.picker_prompt_focused()
    }

    fn capture_picker_editor_paste(&mut self, text: &str) -> Option<InputUpdate> {
        if self.paste_operator_question_other(text) || self.capture_answer_paste(text) {
            return Some(InputUpdate::handled());
        }
        if self.capture_map_scope_paste(text) {
            return Some(InputUpdate::handled());
        }
        if self.capture_file_filter_paste(text) || self.capture_map_field_paste(text) {
            return Some(InputUpdate::handled());
        }
        self.capture_other_editor_paste(text)
    }

    fn capture_other_editor_paste(&mut self, text: &str) -> Option<InputUpdate> {
        if self.capture_report_path_paste(text) {
            return Some(InputUpdate::handled());
        }
        if self.capture_auth_key_paste(text) || self.capture_batch_number_paste(text) {
            return Some(InputUpdate::handled());
        }
        if self.capture_budget_paste(text) || self.capture_planning_option_paste(text) {
            return Some(InputUpdate::handled());
        }
        None
    }

    fn capture_file_filter_paste(&mut self, text: &str) -> bool {
        if self.shell_view() != ShellView::FilePicker {
            return false;
        }
        self.router.file_picker_mut().paste_query(text);
        true
    }

    fn capture_planning_option_paste(&mut self, text: &str) -> bool {
        if !self.planning_option_editor_open() {
            return false;
        }
        self.insert_planning_option_text(text);
        true
    }

    fn paste_before_prompt(&mut self, text: &str) -> Option<InputUpdate> {
        if self.paste_guided_scan_other(text) {
            return Some(InputUpdate::handled());
        }
        if self.paste_operator_question_other(text) {
            return Some(InputUpdate::handled());
        }
        (self.input_mode() == InputMode::Navigate).then(InputUpdate::ignored)
    }

    fn paste_into_prompt(&mut self, text: &str) -> InputUpdate {
        if let Some(update) = self.handle_routed_paste(text) {
            return update;
        }
        if self.handle_multiline_paste(text) {
            return InputUpdate::handled();
        }
        self.insert_str_at_cursor(text);
        InputUpdate::handled()
    }

    fn handle_routed_paste(&mut self, text: &str) -> Option<InputUpdate> {
        self.attachment_effects_from_paste(text)
            .map(InputUpdate::handled_with_effects)
    }

    fn handle_multiline_paste(&mut self, text: &str) -> bool {
        if !text.contains('\n') {
            return false;
        }
        let lines = text.split('\n').count();
        let chars = text.chars().count();
        let marker = self.editor_mut().insert_multiline_paste(text);
        self.set_warn_notice(
            "paste",
            format!(
                "stored all {lines} pasted lines ({chars} chars) as {marker}; keep the placeholder intact and press Enter once to submit"
            ),
        );
        true
    }

    fn capture_auth_key_paste(&mut self, text: &str) -> bool {
        if !matches!(self.shell_view(), ShellView::Setup)
            || self.router.setup().editor() != Some(crate::app::SetupEditor::Credentials)
            || self.picker_prompt_focused()
            || !self.router.auth_picker().is_api_key_row()
        {
            return false;
        }
        let key = text.lines().next().unwrap_or("").trim();
        if key.is_empty() {
            return true;
        }
        self.router.auth_picker_mut().push_key_str(key);
        self.clear_credential_notice();
        if text.contains('\n') {
            self.set_warn_notice(
                "paste",
                "kept first pasted line as API key draft; extra lines ignored",
            );
        }
        true
    }

    pub(crate) fn reduce_mouse(&mut self, mouse: MouseEvent) -> InputUpdate {
        if let Some(update) = self.handle_answer_mouse(mouse) {
            return update;
        }
        match mouse.kind {
            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                InputUpdate::handled_if(self.handle_left_mouse_down(mouse.column, mouse.row))
            }
            MouseEventKind::ScrollUp => self.handle_mouse_scroll(-1, mouse.column, mouse.row),
            MouseEventKind::ScrollDown => self.handle_mouse_scroll(1, mouse.column, mouse.row),
            _ => InputUpdate::ignored(),
        }
    }

    pub(crate) fn reduce_resize(&mut self, columns: u16, rows: u16) -> InputUpdate {
        self.set_viewport(TerminalViewport::new(columns, rows));
        InputUpdate::handled()
    }

    fn handle_left_mouse_down(&mut self, column: u16, row: u16) -> bool {
        if self.workbench_foreground_attention_is_active() {
            return self.shell_view() == ShellView::Workbench;
        }
        if let Some((surface, _)) = self.workbench_surface_for_mouse(column, row) {
            self.router.workbench_mut().set_focus(surface);
            return true;
        }
        if let (Some(focus), Some(_)) = (self.activity_pane_for_mouse(column, row), self.activity())
        {
            self.router.activity_mut().pane_focus = focus;
            return true;
        }
        false
    }

    fn handle_mouse_scroll(&mut self, amount: i32, column: u16, row: u16) -> InputUpdate {
        if self.workbench_foreground_attention_is_active() {
            return InputUpdate::handled();
        }
        if self.scroll_workbench_surface(amount, column, row) {
            return InputUpdate::handled();
        }
        if amount.is_negative() {
            self.scroll_up(1);
        } else {
            self.scroll_down(1);
        }
        InputUpdate::handled()
    }

    fn scroll_workbench_surface(&mut self, amount: i32, column: u16, row: u16) -> bool {
        let Some((slot, interaction)) = self.workbench_surface_for_mouse(column, row) else {
            return false;
        };
        match interaction {
            crate::ui_view_models::SurfaceInteraction::Selectable => {
                self.move_findings_cursor(amount)
            }
            crate::ui_view_models::SurfaceInteraction::Scrollable => {
                self.router.workbench_mut().scroll_mut().shift(slot, amount)
            }
            crate::ui_view_models::SurfaceInteraction::Static
            | crate::ui_view_models::SurfaceInteraction::Diagram => {}
        }
        true
    }

    fn workbench_foreground_attention_is_active(&self) -> bool {
        if self.shell_view() != ShellView::Workbench {
            return false;
        }
        if self.guided_scan_question_is_open() {
            return true;
        }
        self.phase_result_target_phase().is_some()
    }

    fn move_findings_cursor(&mut self, amount: i32) {
        let len = crate::ui_view_models::visible_findings_len(self);
        self.router
            .findings_mut()
            .step_direction(amount as isize, len);
        let detail = crate::ui_view_models::active_workbench_page(self).detail_surface();
        self.router.workbench_mut().scroll_mut().set(detail, 0);
    }

    fn workbench_surface_for_mouse(
        &self,
        column: u16,
        row: u16,
    ) -> Option<(
        crate::ui_view_models::PhaseSurfaceId,
        crate::ui_view_models::SurfaceInteraction,
    )> {
        let viewport = self.viewport();
        let plan = crate::renderer::workbench_phase_plan_for_app(
            self,
            ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows),
        )?;
        plan.hit_test(column, row)
            .map(|surface| (surface.id, surface.interaction))
    }

    fn activity_pane_for_mouse(&self, column: u16, row: u16) -> Option<crate::app::PaneFocus> {
        if !matches!(self.shell_view(), ShellView::Activity) {
            return None;
        }
        let session = self.activity()?;
        let viewport = self.viewport();
        let area = crate::renderer::workbench_primary_area(
            self,
            ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows),
        );
        if !area.contains(ratatui::layout::Position::new(column, row)) {
            return None;
        }
        let viewport = TerminalViewport::new(area.width, area.height);
        let crate::ui_view_models::ActivityViewModel::Active(model) =
            crate::ui_view_models::activity_view_model(self)
        else {
            return None;
        };
        let now = std::time::Instant::now();
        let heartbeat_rows = model.heartbeat_rows(viewport.columns, now).1.len();
        let frame_layout = model.frame_layout(viewport.columns, heartbeat_rows);
        let body_height = viewport
            .rows
            .saturating_sub(frame_layout.header_rows)
            .saturating_sub(frame_layout.footer_rows);
        activity_pane_for_click(
            column - area.x,
            row - area.y,
            viewport.columns,
            viewport.rows,
            session.tasks.is_empty(),
            self.router.activity().pane_focus,
            frame_layout,
            model.pane_layout(viewport.columns, body_height, now),
        )
    }
}

fn activity_pane_for_click(
    column: u16,
    row: u16,
    width: u16,
    height: u16,
    tasks_empty: bool,
    focused: crate::app::PaneFocus,
    frame_layout: crate::ui_view_models::ActivityFrameLayout,
    pane_layout: crate::ui_view_models::ActivityPaneLayout,
) -> Option<crate::app::PaneFocus> {
    let (_, body_row) = activity_click_body_position(
        row,
        width,
        height,
        frame_layout.header_rows,
        frame_layout.footer_rows,
    )?;
    if tasks_empty {
        return Some(crate::app::PaneFocus::Right);
    }
    Some(activity_pane_for_layout(
        column,
        body_row,
        focused,
        pane_layout,
    ))
}

fn activity_click_body_position(
    row: u16,
    width: u16,
    height: u16,
    header_rows: u16,
    footer_rows: u16,
) -> Option<(u16, u16)> {
    if width < 8 || height < 6 || !activity_body_contains_row(row, height, header_rows, footer_rows)
    {
        return None;
    }
    let body_height = height
        .saturating_sub(header_rows)
        .saturating_sub(footer_rows);
    Some((body_height, row.saturating_sub(header_rows)))
}

fn activity_pane_for_layout(
    column: u16,
    body_row: u16,
    focused: crate::app::PaneFocus,
    layout: crate::ui_view_models::ActivityPaneLayout,
) -> crate::app::PaneFocus {
    match layout {
        crate::ui_view_models::ActivityPaneLayout::SideBySide { task_width } => {
            pane_before_boundary(column, task_width)
        }
        crate::ui_view_models::ActivityPaneLayout::Stacked { task_height } => {
            pane_before_boundary(body_row, task_height)
        }
        crate::ui_view_models::ActivityPaneLayout::Focused => focused,
    }
}

fn pane_before_boundary(position: u16, boundary: u16) -> crate::app::PaneFocus {
    if position < boundary {
        crate::app::PaneFocus::Left
    } else {
        crate::app::PaneFocus::Right
    }
}

fn activity_body_contains_row(row: u16, height: u16, header_rows: u16, footer_rows: u16) -> bool {
    row >= header_rows && row < height.saturating_sub(footer_rows)
}

fn normalise_paste_text(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// True when the keystroke is a Ctrl/Alt chord rather than typed text. Mirrors
/// `picker_command_char`, so the composer and the picker prompt agree on what
/// counts as a character the operator meant to type.
pub(super) fn chord_modified(key: KeyEvent) -> bool {
    key.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

#[cfg(test)]
mod tests;
