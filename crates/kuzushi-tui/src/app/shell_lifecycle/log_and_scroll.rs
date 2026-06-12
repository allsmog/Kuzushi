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
        if matches!(self.shell_view, ShellView::Logs) {
            self.logs_scroll = 0;
            return;
        }
        self.scroll_offset = 0;
    }

    pub fn scroll_to_bottom(&mut self) {
        if matches!(self.shell_view, ShellView::Activity) {
            self.activity.as_mut().map(focused_pane_to_bottom);
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
        let Some(session) = self.activity.as_mut() else {
            return;
        };
        match session.effective_pane_focus() {
            PaneFocus::Left => {
                // Clamp to the row count so a short DAG can't be scrolled into
                // empty space — there's nothing to reveal past the last task.
                let max = session.tasks.len().saturating_sub(1);
                session.task_scroll = shift_clamped(session.task_scroll, amount, max);
            }
            PaneFocus::Right => {
                // Manual feed scroll unpins live auto-tail so the operator
                // stays at the position they navigated to. `feed_auto_tail`
                // is reset by `G` (scroll-to-bottom). `paused` is decoupled
                // — toggling pause does not unpin the position.
                session.feed_auto_tail = false;
                let max = session.events.len().saturating_sub(1);
                session.feed_scroll = shift_clamped(session.feed_scroll, amount, max);
            }
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

    fn push_nav_history(&mut self, view: ShellView) {
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
        PaneFocus::Left => session.task_scroll = 0,
        PaneFocus::Right => session.feed_scroll = 0,
    }
}

fn focused_pane_to_bottom(session: &mut ActivitySession) {
    match session.effective_pane_focus() {
        PaneFocus::Left => session.task_scroll = usize::MAX,
        PaneFocus::Right => {
            session.feed_scroll = usize::MAX;
            // G on the feed pane unpins manual scroll so the operator
            // returns to live auto-tail.
            session.feed_auto_tail = true;
        }
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
