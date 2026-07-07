use super::*;

impl ShellApp {
    pub fn scroll_up(&mut self, amount: u16) {
        match self.scroll_target() {
            ScrollTarget::Activity => self.scroll_active_activity_pane(-(amount as isize)),
            ScrollTarget::WorkbenchPane => {
                let focus = self.router.workbench().focus();
                self.router
                    .workbench_mut()
                    .scroll_mut()
                    .shift(focus, -(amount as i32));
            }
            ScrollTarget::Logs => self.router.logs_mut().scroll_up(amount as usize),
            ScrollTarget::Default => self.router.default_scroll_mut().scroll_up(amount),
        }
    }

    pub fn scroll_down(&mut self, amount: u16) {
        match self.scroll_target() {
            ScrollTarget::Activity => self.scroll_active_activity_pane(amount as isize),
            ScrollTarget::WorkbenchPane => {
                let focus = self.router.workbench().focus();
                self.router
                    .workbench_mut()
                    .scroll_mut()
                    .shift(focus, amount as i32);
            }
            ScrollTarget::Logs => self.router.logs_mut().scroll_down(amount as usize),
            ScrollTarget::Default => self.router.default_scroll_mut().scroll_down(amount),
        }
    }

    pub fn scroll_to_top(&mut self) {
        match self.scroll_target() {
            ScrollTarget::Activity => {
                if let Some(session) = self.domain.activity() {
                    focused_pane_to_top(session, self.router.activity_mut());
                }
            }
            ScrollTarget::WorkbenchPane => {
                let focus = self.router.workbench().focus();
                self.router.workbench_mut().scroll_mut().set(focus, 0);
            }
            ScrollTarget::Logs => self.router.logs_mut().open(),
            ScrollTarget::Default => self.router.default_scroll_mut().reset(),
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        match self.scroll_target() {
            ScrollTarget::Activity => self.focused_activity_pane_to_bottom(),
            ScrollTarget::WorkbenchPane => {
                let focus = self.router.workbench().focus();
                self.router
                    .workbench_mut()
                    .scroll_mut()
                    .set(focus, u16::MAX);
            }
            ScrollTarget::Logs => self.router.logs_mut().set_scroll(usize::MAX),
            ScrollTarget::Default => self.router.default_scroll_mut().tail(),
        }
    }

    /// j/k delta routed to whichever Activity-view pane currently has focus.
    /// Negative amount scrolls up, positive scrolls down. Pause is implied
    /// by manually scrolling the feed pane: once the operator scrolls up
    /// from the bottom, auto-tail is paused for that session.
    fn scroll_active_activity_pane(&mut self, amount: isize) {
        let deck_cursor_max = self.activity_deck_cursor_max();
        let Some(session) = self.domain.activity() else {
            return;
        };
        let route = self.router.activity_mut();
        match route.effective_pane_focus(session) {
            PaneFocus::Left => route.shift_task_cursor(session, amount),
            PaneFocus::Right => {
                route.feed_auto_tail = false;
                route.deck_cursor = shift_clamped(route.deck_cursor, amount, deck_cursor_max);
            }
        }
    }

    fn focused_activity_pane_to_bottom(&mut self) {
        let deck_cursor_max = self.activity_deck_cursor_max();
        let Some(session) = self.domain.activity() else {
            return;
        };
        let route = self.router.activity_mut();
        match route.effective_pane_focus(session) {
            PaneFocus::Left => route.move_task_cursor_to_bottom(session),
            PaneFocus::Right => {
                route.deck_cursor = deck_cursor_max;
                route.feed_auto_tail = false;
            }
        }
    }

    fn activity_deck_cursor_max(&self) -> usize {
        if self.activity().is_none() {
            return 0;
        };
        match self.router.activity().deck_page {
            ActivityDeckPage::Findings => self.findings().len().saturating_sub(1),
            ActivityDeckPage::AttackSurface => crate::ui_view_models::cached_risk_by_module(self)
                .modules
                .len()
                .saturating_sub(1),
            ActivityDeckPage::Dfd => threat_dfd_selectable_count(self).saturating_sub(1),
            ActivityDeckPage::Heatmap => crate::ui_view_models::cached_risk_by_module(self)
                .modules
                .len()
                .min(10)
                .saturating_sub(1),
            ActivityDeckPage::AttackPath => self
                .domain()
                .taint_flow()
                .map(|flow| flow.stages.len().min(6))
                .unwrap_or_default()
                .saturating_sub(1),
            ActivityDeckPage::ExploitChain => self
                .domain()
                .exploit_chains()
                .len()
                .min(3)
                .saturating_sub(1),
        }
    }

    fn scroll_target(&self) -> ScrollTarget {
        match self.shell_view {
            ShellView::Activity => ScrollTarget::Activity,
            ShellView::Workbench if self.router.workbench().focus() != WorkbenchPane::Findings => {
                ScrollTarget::WorkbenchPane
            }
            ShellView::Logs => ScrollTarget::Logs,
            _ => ScrollTarget::Default,
        }
    }

    pub(crate) fn sync_view_change(&mut self) -> bool {
        let changed = self
            .router
            .navigation_mut()
            .sync_view_change(self.shell_view.clone());
        if changed {
            self.router.default_scroll_mut().reset();
        }
        changed
    }

    pub(crate) fn push_nav_history(&mut self, view: ShellView) {
        self.router.navigation_mut().push_history(view);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScrollTarget {
    Activity,
    WorkbenchPane,
    Logs,
    Default,
}

fn focused_pane_to_top(session: &ActivitySession, route: &mut ActivityRouteState) {
    match route.effective_pane_focus(session) {
        PaneFocus::Left => route.move_task_cursor_to_top(session),
        PaneFocus::Right => route.deck_cursor = 0,
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
