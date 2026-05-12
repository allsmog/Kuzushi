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
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: u16) {
        if matches!(self.shell_view, ShellView::Activity) {
            self.scroll_active_activity_pane(amount as isize);
            return;
        }
        self.scroll_offset = self.scroll_offset.saturating_add(amount);
    }

    pub fn scroll_to_top(&mut self) {
        if matches!(self.shell_view, ShellView::Activity) {
            if let Some(session) = self.activity.as_mut() {
                match session.pane_focus {
                    PaneFocus::Left => session.task_scroll = 0,
                    PaneFocus::Right => session.feed_scroll = 0,
                }
            }
            return;
        }
        self.scroll_offset = 0;
    }

    pub fn scroll_to_bottom(&mut self) {
        if matches!(self.shell_view, ShellView::Activity) {
            if let Some(session) = self.activity.as_mut() {
                match session.pane_focus {
                    PaneFocus::Left => session.task_scroll = usize::MAX,
                    PaneFocus::Right => {
                        session.feed_scroll = usize::MAX;
                        // G on the feed pane unpins manual scroll so the
                        // operator returns to live auto-tail.
                        session.feed_auto_tail = true;
                    }
                }
            }
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
        match session.pane_focus {
            PaneFocus::Left => {
                if amount.is_negative() {
                    session.task_scroll = session.task_scroll.saturating_sub(amount.unsigned_abs());
                } else {
                    session.task_scroll = session.task_scroll.saturating_add(amount as usize);
                }
            }
            PaneFocus::Right => {
                // Manual feed scroll unpins live auto-tail so the operator
                // stays at the position they navigated to. `feed_auto_tail`
                // is reset by `G` (scroll-to-bottom). `paused` is decoupled
                // — toggling pause does not unpin the position.
                session.feed_auto_tail = false;
                if amount.is_negative() {
                    session.feed_scroll = session.feed_scroll.saturating_sub(amount.unsigned_abs());
                } else {
                    session.feed_scroll = session.feed_scroll.saturating_add(amount as usize);
                }
            }
        }
    }

    pub(crate) fn sync_view_change(&mut self) -> bool {
        let current = Some(self.shell_view.clone());
        if self.prev_shell_view != current {
            self.scroll_offset = 0;
            self.prev_shell_view = current;
            true
        } else {
            false
        }
    }
}
