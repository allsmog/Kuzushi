use super::*;

impl ShellApp {
    pub fn log(&mut self, prefix: impl Into<String>, body: impl Into<String>) {
        self.log.push(LogLine::new(prefix, body));
        if self.log.len() > 500 {
            let overflow = self.log.len() - 500;
            self.log.drain(0..overflow);
        }
    }

    pub fn scroll_up(&mut self, amount: u16) {
        if matches!(self.shell_view, ShellView::Activity) {
            self.scroll_active_activity_pane(-(amount as isize));
            return;
        }
        if self.scroll_focused_workbench_pane(-(amount as i32)) {
            return;
        }
        if matches!(self.shell_view, ShellView::Logs) {
            self.logs_scroll = self.logs_scroll.saturating_sub(amount as usize);
            return;
        }
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: u16) {
        if matches!(self.shell_view, ShellView::Activity) {
            self.scroll_active_activity_pane(amount as isize);
            return;
        }
        if self.scroll_focused_workbench_pane(amount as i32) {
            return;
        }
        if matches!(self.shell_view, ShellView::Logs) {
            self.logs_scroll = self.logs_scroll.saturating_add(amount as usize);
            return;
        }
        self.scroll_offset = self.scroll_offset.saturating_add(amount);
    }

    pub fn scroll_to_top(&mut self) {
        if matches!(self.shell_view, ShellView::Activity) {
            self.activity.as_mut().map(focused_pane_to_top);
            return;
        }
        if self.set_focused_workbench_pane_scroll(0) {
            return;
        }
        if matches!(self.shell_view, ShellView::Logs) {
            self.logs_scroll = 0;
            return;
        }
        self.scroll_offset = 0;
    }

    pub fn scroll_to_bottom(&mut self) {
        if matches!(self.shell_view, ShellView::Activity) {
            self.focused_activity_pane_to_bottom();
            return;
        }
        if self.set_focused_workbench_pane_scroll(u16::MAX) {
            return;
        }
        if matches!(self.shell_view, ShellView::Logs) {
            self.logs_scroll = usize::MAX;
            return;
        }
        self.scroll_offset = u16::MAX;
    }

    /// j/k delta routed to whichever Activity-view pane currently has focus.
    /// Negative amount scrolls up, positive scrolls down. Pause is implied
    /// by manually scrolling the feed pane: once the operator scrolls up
    /// from the bottom, auto-tail is paused for that session.
    fn scroll_active_activity_pane(&mut self, amount: isize) {
        let deck_cursor_max = self.activity_deck_cursor_max();
        let Some(session) = self.activity.as_mut() else {
            return;
        };
        match session.effective_pane_focus() {
            PaneFocus::Left => session.shift_task_cursor(amount),
            PaneFocus::Right => {
                session.feed_auto_tail = false;
                session.deck_cursor = shift_clamped(session.deck_cursor, amount, deck_cursor_max);
            }
        }
    }

    fn focused_activity_pane_to_bottom(&mut self) {
        let deck_cursor_max = self.activity_deck_cursor_max();
        let Some(session) = self.activity.as_mut() else {
            return;
        };
        match session.effective_pane_focus() {
            PaneFocus::Left => session.move_task_cursor_to_bottom(),
            PaneFocus::Right => {
                session.deck_cursor = deck_cursor_max;
                session.feed_auto_tail = false;
            }
        }
    }

    fn activity_deck_cursor_max(&self) -> usize {
        let Some(session) = self.activity.as_ref() else {
            return 0;
        };
        match session.deck_page {
            ActivityDeckPage::Task => 0,
            ActivityDeckPage::Findings => self.findings.len().saturating_sub(1),
            ActivityDeckPage::AttackSurface => {
                crate::ui_view_models::risk_by_module(&self.findings)
                    .modules
                    .len()
                    .saturating_sub(1)
            }
            ActivityDeckPage::Dfd => {
                let model = crate::ui_view_models::dfd_model(self);
                let selectable = if model.flows.is_empty() {
                    model.nodes.len()
                } else {
                    model.flows.len()
                };
                selectable.saturating_sub(1)
            }
            ActivityDeckPage::Heatmap => crate::ui_view_models::findings_heatmap(&self.findings)
                .rows
                .len()
                .saturating_sub(1),
            ActivityDeckPage::AttackPath => crate::ui_view_models::taint_flow_path(self)
                .stages
                .len()
                .saturating_sub(1),
            ActivityDeckPage::ExploitChain => crate::ui_view_models::attack_tree(self)
                .chains
                .len()
                .saturating_sub(1),
        }
    }

    fn scroll_focused_workbench_pane(&mut self, amount: i32) -> bool {
        if !matches!(self.shell_view, ShellView::Workbench) {
            return false;
        }
        if matches!(self.workbench_focus, WorkbenchPane::Findings) {
            return false;
        }
        self.workbench_scroll.shift(self.workbench_focus, amount);
        true
    }

    fn set_focused_workbench_pane_scroll(&mut self, value: u16) -> bool {
        if !matches!(self.shell_view, ShellView::Workbench) {
            return false;
        }
        if matches!(self.workbench_focus, WorkbenchPane::Findings) {
            return false;
        }
        self.workbench_scroll.set(self.workbench_focus, value);
        true
    }

    pub(crate) fn sync_view_change(&mut self) -> bool {
        let current = Some(self.shell_view.clone());
        if self.prev_shell_view != current {
            self.scroll_offset = 0;
            self.last_cleared_input = None;
            if let Some(prev) = self.prev_shell_view.take() {
                self.push_nav_history(prev);
            }
            self.prev_shell_view = current;
            true
        } else {
            false
        }
    }

    pub(crate) fn push_nav_history(&mut self, view: ShellView) {
        const NAV_HISTORY_DEPTH: usize = 16;
        // Onboarding pickers are transient — `back` should never drop the user
        // back into a model/auth/planning picker they already dismissed.
        if matches!(
            view,
            ShellView::CommandPalette
                | ShellView::ModelPicker
                | ShellView::AuthMethodPicker(_)
                | ShellView::PlanningPicker
                | ShellView::TargetPicker
        ) {
            return;
        }
        if self.nav_history.last() == Some(&view) {
            return;
        }
        self.nav_history.push(view);
        if self.nav_history.len() > NAV_HISTORY_DEPTH {
            let excess = self.nav_history.len() - NAV_HISTORY_DEPTH;
            self.nav_history.drain(..excess);
        }
    }
}

fn focused_pane_to_top(session: &mut ActivitySession) {
    match session.effective_pane_focus() {
        PaneFocus::Left => session.move_task_cursor_to_top(),
        PaneFocus::Right => session.deck_cursor = 0,
    }
}

/// Apply a signed scroll delta and clamp the result to `[0, max]`, so a pane
/// can't be scrolled past its content into empty space.
fn shift_clamped(current: usize, amount: isize, max: usize) -> usize {
    let next = if amount.is_negative() {
        current.saturating_sub(amount.unsigned_abs())
    } else {
        current.saturating_add(amount as usize)
    };
    next.min(max)
}

#[cfg(test)]
mod shift_clamped_tests {
    use super::shift_clamped;

    #[test]
    fn cannot_scroll_past_content() {
        // Short content (max index 1): scrolling down hard stays clamped.
        assert_eq!(shift_clamped(0, 5, 1), 1);
        assert_eq!(shift_clamped(1, 3, 1), 1);
    }

    #[test]
    fn empty_content_never_scrolls() {
        assert_eq!(shift_clamped(0, 9, 0), 0);
    }

    #[test]
    fn scrolls_up_and_down_within_bounds() {
        assert_eq!(shift_clamped(3, 2, 10), 5);
        assert_eq!(shift_clamped(5, -2, 10), 3);
        assert_eq!(shift_clamped(1, -9, 10), 0);
    }
}
