use super::*;
use std::time::Instant;

const MINIMUM_RUN_FOCUS_VISIBILITY: Duration = Duration::from_millis(250);

#[derive(Debug, Default)]
pub(crate) struct RunFocusVisibilityHold {
    until: Option<Instant>,
}

impl RunFocusVisibilityHold {
    pub(crate) fn begin_after_transition(&mut self, prior: ShellView, app: &ShellApp) {
        if prior != ShellView::Activity
            && app.shell_view() == ShellView::Activity
            && app.has_running_work()
        {
            self.until = Some(Instant::now() + MINIMUM_RUN_FOCUS_VISIBILITY);
        }
    }

    pub(crate) fn intercept_input(
        &mut self,
        app: &mut ShellApp,
        inbox: &TerminalLoopInbox,
    ) -> Result<Option<bool>> {
        let Some(deadline) = self.until else {
            return Ok(None);
        };
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                self.until = None;
                return Ok(None);
            };
            match inbox.recv_timeout(remaining)? {
                Some(TerminalLoopEvent::Wake) => continue,
                Some(event) => {
                    self.until = None;
                    return Ok(Some(apply_visible_input(app, event)));
                }
                None => {
                    self.until = None;
                    return Ok(None);
                }
            }
        }
    }
}

fn apply_visible_input(app: &mut ShellApp, event: TerminalLoopEvent) -> bool {
    match event {
        TerminalLoopEvent::Terminal(event) => update_and_execute_effects(app, Msg::Term(event)),
        TerminalLoopEvent::InputRejected(message) => {
            app.set_warn_notice("input", message);
            true
        }
        TerminalLoopEvent::Wake => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paste_rejection_during_visibility_hold_keeps_the_shell_active() {
        let mut app = ShellApp::new(V2Config::default(), None);
        assert!(apply_visible_input(
            &mut app,
            TerminalLoopEvent::InputRejected("paste rejected".into())
        ));
        assert!(!app.should_quit());
    }

    #[test]
    fn foreground_run_transition_starts_a_visibility_hold() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_running_tool_for_test("context:build");
        app.set_shell_view(ShellView::Activity);
        let mut hold = RunFocusVisibilityHold::default();

        hold.begin_after_transition(ShellView::Setup, &app);

        assert!(hold.until.is_some());
    }

    #[test]
    fn existing_activity_view_does_not_restart_the_hold() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_running_tool_for_test("context:build");
        app.set_shell_view(ShellView::Activity);
        let mut hold = RunFocusVisibilityHold::default();

        hold.begin_after_transition(ShellView::Activity, &app);

        assert!(hold.until.is_none());
    }
}
