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
        match self.scroll_target() {
            ScrollTarget::Activity => self.scroll_active_activity_pane(-(amount as isize)),
            ScrollTarget::WorkbenchPane => self
                .workbench_scroll
                .shift(self.workbench_focus, -(amount as i32)),
            ScrollTarget::Logs => {
                self.logs_scroll = self.logs_scroll.saturating_sub(amount as usize)
            }
            ScrollTarget::Default => self.scroll_offset = self.scroll_offset.saturating_sub(amount),
        }
    }

    pub fn scroll_down(&mut self, amount: u16) {
        match self.scroll_target() {
            ScrollTarget::Activity => self.scroll_active_activity_pane(amount as isize),
            ScrollTarget::WorkbenchPane => self
                .workbench_scroll
                .shift(self.workbench_focus, amount as i32),
            ScrollTarget::Logs => {
                self.logs_scroll = self.logs_scroll.saturating_add(amount as usize)
            }
            ScrollTarget::Default => self.scroll_offset = self.scroll_offset.saturating_add(amount),
        }
    }

    pub fn scroll_to_top(&mut self) {
        match self.scroll_target() {
            ScrollTarget::Activity => {
                self.activity.as_mut().map(focused_pane_to_top);
            }
            ScrollTarget::WorkbenchPane => self.workbench_scroll.set(self.workbench_focus, 0),
            ScrollTarget::Logs => self.logs_scroll = 0,
            ScrollTarget::Default => self.scroll_offset = 0,
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        match self.scroll_target() {
            ScrollTarget::Activity => self.focused_activity_pane_to_bottom(),
            ScrollTarget::WorkbenchPane => {
                self.workbench_scroll.set(self.workbench_focus, u16::MAX)
            }
            ScrollTarget::Logs => self.logs_scroll = usize::MAX,
            ScrollTarget::Default => self.scroll_offset = u16::MAX,
        }
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
            ActivityDeckPage::Findings => self.findings.len().saturating_sub(1),
            ActivityDeckPage::AttackSurface => {
                crate::ui_view_models::risk_by_module(&self.findings)
                    .modules
                    .len()
                    .saturating_sub(1)
            }
            ActivityDeckPage::Dfd => threat_dfd_selectable_count(self).saturating_sub(1),
            ActivityDeckPage::Heatmap => crate::ui_view_models::risk_by_module(&self.findings)
                .modules
                .len()
                .min(10)
                .saturating_sub(1),
            ActivityDeckPage::AttackPath => self
                .taint_flow
                .as_ref()
                .map(|flow| flow.stages.len().min(6))
                .unwrap_or_default()
                .saturating_sub(1),
            ActivityDeckPage::ExploitChain => self.exploit_chains.len().min(3).saturating_sub(1),
        }
    }

    fn scroll_target(&self) -> ScrollTarget {
        match self.shell_view {
            ShellView::Activity => ScrollTarget::Activity,
            ShellView::Workbench if self.workbench_focus != WorkbenchPane::Findings => {
                ScrollTarget::WorkbenchPane
            }
            ShellView::Logs => ScrollTarget::Logs,
            _ => ScrollTarget::Default,
        }
    }

    pub(crate) fn sync_view_change(&mut self) -> bool {
        let current = Some(self.shell_view.clone());
        if self.prev_shell_view != current {
            self.scroll_offset = 0;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScrollTarget {
    Activity,
    WorkbenchPane,
    Logs,
    Default,
}

fn focused_pane_to_top(session: &mut ActivitySession) {
    match session.effective_pane_focus() {
        PaneFocus::Left => session.move_task_cursor_to_top(),
        PaneFocus::Right => session.deck_cursor = 0,
    }
}

fn threat_dfd_selectable_count(app: &ShellApp) -> usize {
    let Some(doc) = crate::ui_view_models::threat_model_doc(app) else {
        return 0;
    };
    let flows = json_array_len(doc.pointer("/dfd/flows"));
    if flows > 0 {
        return flows;
    }
    json_array_len(doc.pointer("/dfd/nodes"))
}

fn json_array_len(value: Option<&serde_json::Value>) -> usize {
    value
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or_default()
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
