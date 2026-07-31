use super::*;

impl ShellApp {
    pub fn scroll_up(&mut self, amount: u16) {
        match self.scroll_target() {
            ScrollTarget::Activity => self.scroll_active_activity_pane(-(amount as isize)),
            ScrollTarget::WorkbenchSurface(focus) => {
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
            ScrollTarget::WorkbenchSurface(focus) => {
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
            ScrollTarget::WorkbenchSurface(focus) => {
                self.router.workbench_mut().scroll_mut().set(focus, 0);
            }
            ScrollTarget::Logs => self.router.logs_mut().open(),
            ScrollTarget::Default => self.router.default_scroll_mut().reset(),
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        match self.scroll_target() {
            ScrollTarget::Activity => self.focused_activity_pane_to_bottom(),
            ScrollTarget::WorkbenchSurface(focus) => {
                self.router
                    .workbench_mut()
                    .scroll_mut()
                    .set(focus, u16::MAX);
            }
            ScrollTarget::Logs => self.router.logs_mut().follow_tail(),
            ScrollTarget::Default => self.router.default_scroll_mut().tail(),
        }
    }

    /// j/k delta routed to whichever Activity-view pane currently has focus.
    /// Negative amount scrolls up, positive scrolls down. Pause is implied
    /// by manually scrolling the feed pane: once the operator scrolls up
    /// from the bottom, auto-tail is paused for that session.
    fn scroll_active_activity_pane(&mut self, amount: isize) {
        let Some(session) = self.domain.activity() else {
            return;
        };
        let route = self.router.activity_mut();
        match route.effective_pane_focus(session) {
            PaneFocus::Left => route.shift_task_cursor(session, amount),
            PaneFocus::Right => {
                route.feed_auto_tail = false;
                route.feed_scroll = shift_feed_from_tail(route.feed_scroll, amount);
            }
        }
    }

    fn focused_activity_pane_to_bottom(&mut self) {
        let Some(session) = self.domain.activity() else {
            return;
        };
        let route = self.router.activity_mut();
        match route.effective_pane_focus(session) {
            PaneFocus::Left => route.move_task_cursor_to_bottom(session),
            PaneFocus::Right => {
                route.feed_scroll = 0;
                route.feed_auto_tail = true;
            }
        }
    }

    fn scroll_target(&self) -> ScrollTarget {
        match self.shell_view() {
            ShellView::Activity => ScrollTarget::Activity,
            ShellView::Workbench => self
                .scrollable_workbench_surface()
                .map(ScrollTarget::WorkbenchSurface)
                .unwrap_or(ScrollTarget::Default),
            ShellView::Logs => ScrollTarget::Logs,
            _ => ScrollTarget::Default,
        }
    }

    fn scrollable_workbench_surface(&self) -> Option<crate::ui_view_models::PhaseSurfaceId> {
        let viewport = self.viewport();
        let plan = crate::renderer::workbench_phase_plan_for_app(
            self,
            ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows),
        )?;
        let surface = plan.surface(plan.effective_focus)?;
        (surface.interaction == crate::ui_view_models::SurfaceInteraction::Scrollable)
            .then_some(surface.id)
    }

    pub(crate) fn sync_view_change(&mut self) -> bool {
        let view = self.shell_view();
        let changed = self.router.navigation_mut().sync_view_change(view);
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
    WorkbenchSurface(crate::ui_view_models::PhaseSurfaceId),
    Logs,
    Default,
}

fn focused_pane_to_top(session: &ActivitySession, route: &mut ActivityRouteState) {
    match route.effective_pane_focus(session) {
        PaneFocus::Left => route.move_task_cursor_to_top(session),
        PaneFocus::Right => {
            route.feed_scroll = usize::MAX;
            route.feed_auto_tail = false;
        }
    }
}

/// Run Focus stores output scroll as distance above the live tail. This keeps
/// input handling independent of the renderer's current viewport height.
fn shift_feed_from_tail(current: usize, amount: isize) -> usize {
    if amount.is_negative() {
        current.saturating_add(amount.unsigned_abs())
    } else {
        current.saturating_sub(amount as usize)
    }
}

#[cfg(test)]
mod feed_scroll_tests {
    use super::shift_feed_from_tail;

    #[test]
    fn up_moves_away_from_the_tail_and_down_returns() {
        assert_eq!(shift_feed_from_tail(0, -5), 5);
        assert_eq!(shift_feed_from_tail(5, 3), 2);
    }

    #[test]
    fn down_never_moves_below_the_live_tail() {
        assert_eq!(shift_feed_from_tail(1, 9), 0);
    }
}
