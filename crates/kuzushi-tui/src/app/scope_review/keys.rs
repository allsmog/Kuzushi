use super::*;
use crate::app::state_transitions::is_quit_chord;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl ShellApp {
    pub(crate) fn handle_scope_review_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !self.scope_review_is_visible() {
            return None;
        }
        if is_quit_chord(key) {
            return None;
        }
        Some(self.reduce_scope_key(key))
    }

    fn reduce_scope_key(&mut self, key: KeyEvent) -> InputUpdate {
        if key.code == KeyCode::Esc {
            self.close_scope_subview();
            return InputUpdate::handled();
        }
        if self
            .scope_review()
            .is_some_and(|state| state.pending.is_some())
        {
            return InputUpdate::handled();
        }
        if let Some(update) = self.scope_editor_key(key) {
            return update;
        }
        self.reduce_scope_navigation(key)
    }

    fn scope_editor_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.scope_review()?.form.is_some() {
            return Some(self.scope_form_key(key));
        }
        self.scope_action_search_key(key)
    }

    fn reduce_scope_navigation(&mut self, key: KeyEvent) -> InputUpdate {
        if !matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
            return InputUpdate::handled();
        }
        if let Some(update) = self.scope_reading_key(key.code) {
            return update;
        }
        self.scope_choice_key(key.code)
            .or_else(|| self.scope_file_boundary_key(key.code))
            .unwrap_or_else(|| self.scope_list_key(key.code))
    }

    fn scope_file_boundary_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        let files = self.scope_review()?.files.as_ref()?;
        let offset = match code {
            KeyCode::Home => 0,
            KeyCode::End => files.page.total.saturating_sub(1) / 32 * 32,
            _ => return None,
        };
        Some(self.request_scope_files(offset))
    }

    fn scope_reading_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        if !matches!(code, KeyCode::PageUp | KeyCode::PageDown) {
            return None;
        }
        use crate::ui_view_models::{
            scope_review::{scope_detail_lines, scope_layout, scope_rows, scope_source_view},
            study_config::study_config_area,
        };
        let viewport = self.viewport();
        let state = self.scope_review()?;
        let area = scope_layout(
            study_config_area(viewport.columns, viewport.rows),
            scope_rows(state).0.len(),
        )
        .detail;
        let maximum =
            scope_detail_lines(state, &scope_source_view(self, state), area.width as usize)
                .len()
                .saturating_sub(area.height as usize);
        let current = state.scroll.min(maximum);
        let page = area.height.max(1) as usize;
        let offset = if code == KeyCode::PageUp {
            current.saturating_sub(page)
        } else {
            current.saturating_add(page).min(maximum)
        };
        self.router.scope_review_mut().as_mut().unwrap().scroll = offset;
        Some(InputUpdate::handled())
    }

    fn close_scope_subview(&mut self) {
        let state = self.router.scope_review_mut().as_mut().unwrap();
        if cancel_scope_editor(state) {
            return;
        }
        if state.accepting {
            state.accepting = false;
            return;
        }
        if state.files.take().is_some() {
            state.scroll = 0;
            return;
        }
        state.open = false;
    }

    fn scope_form_key(&mut self, key: KeyEvent) -> InputUpdate {
        if let Some(update) = self.scope_form_control(key.code) {
            return update;
        }
        let state = self.router.scope_review_mut().as_mut().unwrap();
        let form = state.form.as_mut().unwrap();
        match key.code {
            KeyCode::Tab => form.cursor = (form.cursor + 1) % form.fields.len(),
            KeyCode::BackTab => {
                form.cursor = (form.cursor + form.fields.len() - 1) % form.fields.len()
            }
            KeyCode::Enter if form.enter_submits() => return self.save_scope_form(),
            KeyCode::Enter => form.fields[form.cursor].1.insert("\n"),
            _ => {
                form.fields[form.cursor].1.handle_key(key);
            }
        }
        InputUpdate::handled()
    }

    fn scope_choice_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        let state = self.scope_review()?;
        if let Some(index) = state.menu {
            return Some(self.scope_menu_key(code, index));
        }
        if state.merge_target.is_some() {
            return Some(self.scope_merge_key(code));
        }
        if state.accepting {
            return Some(self.scope_acceptance_key(code));
        }
        None
    }

    fn scope_form_control(&mut self, code: KeyCode) -> Option<InputUpdate> {
        match code {
            KeyCode::F(2) => Some(self.save_scope_form()),
            KeyCode::F(3) => {
                self.toggle_scope_context();
                Some(InputUpdate::handled())
            }
            _ => None,
        }
    }

    fn toggle_scope_context(&mut self) {
        let state = self.router.scope_review_mut().as_mut().unwrap();
        let form = state.form.as_mut().unwrap();
        if form.kind != ScopeEditKind::AiPriorities {
            return;
        }
        form.omit_context = !form.omit_context;
        state.notice = Some(format!(
            "Architecture context: {}. F2 reviews model and allowance; nothing is sent yet.",
            if form.omit_context {
                "explicitly omitted"
            } else {
                "accepted Map revision, when available"
            }
        ));
    }

    fn scope_menu_key(&mut self, code: KeyCode, index: usize) -> InputUpdate {
        if code == KeyCode::Enter {
            return self.apply_scope_menu(index);
        }
        let state = self.router.scope_review_mut().as_mut().unwrap();
        move_index(state.menu.as_mut().unwrap(), code, SCOPE_ACTIONS.len());
        InputUpdate::handled()
    }

    fn scope_merge_key(&mut self, code: KeyCode) -> InputUpdate {
        if code == KeyCode::Enter {
            return self.complete_scope_merge();
        }
        let count = merge_destinations(self.scope_review().unwrap()).len();
        let state = self.router.scope_review_mut().as_mut().unwrap();
        move_index(state.merge_target.as_mut().unwrap(), code, count);
        InputUpdate::handled()
    }

    fn scope_acceptance_key(&mut self, code: KeyCode) -> InputUpdate {
        let state = self.router.scope_review_mut().as_mut().unwrap();
        if matches!(code, KeyCode::Enter | KeyCode::Char(' ')) {
            match state.acknowledgement_cursor {
                0 => state.acknowledgements.inventory_limitations ^= true,
                1 => state.acknowledgements.overlapping_discovery ^= true,
                2 => state.acknowledgements.exclusions ^= true,
                _ => return self.accept_scope_boundaries(),
            }
        } else {
            move_index(&mut state.acknowledgement_cursor, code, 4);
        }
        InputUpdate::handled()
    }

    fn scope_list_key(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::Enter if self.scope_review().is_some_and(|s| s.review.is_none()) => {
                return self.dispatch_scope_request(json!({"operation":"create"}))
            }
            KeyCode::Enter => self.router.scope_review_mut().as_mut().unwrap().menu = Some(0),
            KeyCode::Char('c') => {
                return self.dispatch_scope_request(json!({"operation":"create"}))
            }
            KeyCode::Char('a') => self.open_scope_acceptance(),
            KeyCode::Char('p') => return self.plan_selected_scope(),
            KeyCode::Char(' ') => return self.toggle_study_scope_selection(),
            KeyCode::Char('f') => return self.request_scope_files(0),
            KeyCode::Char('r') => return self.refresh_scope_head(),
            KeyCode::Char(']') => return self.turn_scope_file_page(false),
            KeyCode::Char('[') => return self.turn_scope_file_page(true),
            _ => self.move_scope_cursor(code),
        }
        InputUpdate::handled()
    }

    fn move_scope_cursor(&mut self, code: KeyCode) {
        let state = self.router.scope_review_mut().as_mut().unwrap();
        let before = state.cursor;
        let count = state.row_count();
        move_index(&mut state.cursor, code, count);
        if before != state.cursor {
            state.files = None;
            state.scroll = 0;
            state.notice = None;
        }
    }

    fn turn_scope_file_page(&mut self, previous: bool) -> InputUpdate {
        let Some(files) = self.scope_review().and_then(|s| s.files.as_ref()) else {
            return self.request_scope_files(0);
        };
        let offset = if previous {
            files.page.offset.saturating_sub(32)
        } else {
            (files.page.offset + 32).min(files.page.total.saturating_sub(1) / 32 * 32)
        };
        self.request_scope_files(offset)
    }

    fn refresh_scope_head(&mut self) -> InputUpdate {
        self.dispatch_scope_request(json!({"operation":"latest"}))
    }

    pub(crate) fn capture_scope_review_paste(&mut self, text: &str) -> bool {
        if !self.scope_review_is_visible() {
            return false;
        }
        let state = self.router.scope_review_mut().as_mut().unwrap();
        if state.pending.is_some() {
            return true;
        }
        insert_scope_paste(state, text);
        true
    }
}

fn insert_scope_paste(state: &mut ScopeReviewState, text: &str) {
    if state.menu.is_some() {
        state.paste_action_search(text);
    } else if let Some(form) = &mut state.form {
        form.fields[form.cursor].1.insert(text);
    }
}

fn move_index(index: &mut usize, code: KeyCode, count: usize) {
    match code {
        KeyCode::Up | KeyCode::Char('k') => *index = index.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => {
            *index = index.saturating_add(1).min(count.saturating_sub(1))
        }
        KeyCode::Home => *index = 0,
        KeyCode::End => *index = count.saturating_sub(1),
        _ => {}
    }
}

fn cancel_scope_editor(state: &mut ScopeReviewState) -> bool {
    if super::action_search::cancel_search(state) {
        return true;
    }
    if let Some(form) = state.form.take() {
        super::new_scope::retain_draft(state, form);
        return true;
    }
    if state.menu.take().is_some() {
        return true;
    }
    state.merge_target.take().is_some()
}
