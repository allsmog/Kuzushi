use super::*;
use crate::ui_view_models::context_history::history_catalog;

impl ShellApp {
    pub(super) fn reduce_context_history_key(&mut self, code: KeyCode) -> InputUpdate {
        if self.context_history().unwrap().request.is_some() {
            return self.handle_history_reader_key(code);
        }
        match code {
            KeyCode::Esc | KeyCode::Char('q') => self.leave_context_history(),
            KeyCode::Up | KeyCode::Char('k') => self.move_context_history(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_context_history(1),
            KeyCode::Home => self.move_context_history(isize::MIN),
            KeyCode::End => self.move_context_history(isize::MAX),
            _ => return self.handle_history_action(code),
        }
        InputUpdate::handled()
    }

    fn move_context_history(&mut self, amount: isize) {
        let catalog = history_catalog(self);
        if catalog.rows.is_empty() {
            return;
        }
        let current = catalog.selected_index(self.context_history()).unwrap_or(0);
        let index = current
            .saturating_add_signed(amount)
            .min(catalog.rows.len() - 1);
        let state = self.router.threat_mut().history_mut().unwrap();
        state.selected = Some(catalog.rows[index].reference.clone());
        state.selected_label = Some(catalog.rows[index].label.clone());
        state.error = None;
        state.scroll = 0;
        state.list_scroll = 0;
    }

    fn handle_history_action(&mut self, code: KeyCode) -> InputUpdate {
        let catalog = history_catalog(self);
        let Some(index) = catalog.selected_index(self.context_history()) else {
            self.history_notice(
                "The selected revision is unavailable. Choose an existing revision.",
            );
            return InputUpdate::handled();
        };
        let reference = catalog.rows[index].reference.clone();
        self.router.threat_mut().history_mut().unwrap().selected = Some(reference.clone());
        self.router
            .threat_mut()
            .history_mut()
            .unwrap()
            .selected_label = Some(catalog.rows[index].label.clone());
        match code {
            KeyCode::Enter => self.dispatch_history_request(ContextHistoryRequest::Read(reference)),
            KeyCode::Char('b') => self.pin_history_baseline(reference),
            KeyCode::Char('c') => self.compare_history_selection(reference),
            KeyCode::Char('a') => self.dispatch_history_write("threat-model:activate", reference),
            KeyCode::Char('r') => self.dispatch_history_write("threat-model:restore", reference),
            _ => {
                self.scroll_history_detail(code);
                InputUpdate::handled()
            }
        }
    }

    fn pin_history_baseline(&mut self, reference: ThreatModelRef) -> InputUpdate {
        let state = self.router.threat_mut().history_mut().unwrap();
        state.baseline = Some(reference);
        state.baseline_label = state.selected_label.clone();
        state.error = None;
        InputUpdate::handled()
    }

    fn compare_history_selection(&mut self, candidate: ThreatModelRef) -> InputUpdate {
        let Some(baseline) = self.context_history().unwrap().baseline.clone() else {
            self.history_notice("Choose a baseline with b, then select a revision and press c.");
            return InputUpdate::handled();
        };
        self.dispatch_history_request(ContextHistoryRequest::Compare {
            baseline,
            candidate,
        })
    }

    fn handle_history_reader_key(&mut self, code: KeyCode) -> InputUpdate {
        if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
            self.router
                .threat_mut()
                .history_mut()
                .unwrap()
                .back_to_list();
        } else if code == KeyCode::Tab {
            self.toggle_history_document();
        } else if code == KeyCode::Enter && self.context_history().unwrap().error.is_some() {
            let request = self.context_history().unwrap().request.clone().unwrap();
            return self.dispatch_history_request(request);
        } else {
            self.scroll_history_detail(code);
        }
        InputUpdate::handled()
    }

    fn toggle_history_document(&mut self) {
        let state = self.router.threat_mut().history_mut().unwrap();
        if !matches!(state.request, Some(ContextHistoryRequest::Read(_))) {
            return;
        }
        if state.document_raw {
            state.document_scroll = state.scroll;
            state.scroll = state.summary_scroll;
        } else {
            state.summary_scroll = state.scroll;
            state.scroll = state.document_scroll;
        }
        state.document_raw = !state.document_raw;
    }

    fn scroll_history_detail(&mut self, code: KeyCode) {
        let (page, max) = self.history_scroll_bounds();
        let state = self.router.threat_mut().history_mut().unwrap();
        state.scroll = state.scroll.min(max);
        match code {
            KeyCode::PageUp => state.scroll = state.scroll.saturating_sub(page),
            KeyCode::PageDown => state.scroll = state.scroll.saturating_add(page),
            KeyCode::Up | KeyCode::Char('k') => state.scroll = state.scroll.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => state.scroll = state.scroll.saturating_add(1),
            KeyCode::Home => state.scroll = 0,
            KeyCode::End => state.scroll = max,
            _ => {}
        }
        state.scroll = state.scroll.min(max);
        if state.request.is_none() {
            state.list_scroll = state.scroll;
        }
    }

    fn history_scroll_bounds(&self) -> (usize, usize) {
        use crate::ui_view_models::context_history::{history_detail_lines, history_layout};
        let state = self.context_history().unwrap();
        let viewport = self.viewport();
        let area = ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows);
        let layout = history_layout(area, state.request.is_some());
        let page = layout.detail.height.max(1) as usize;
        let lines =
            history_detail_lines(state, &history_catalog(self), layout.detail.width as usize);
        (page, lines.len().saturating_sub(page))
    }
}
