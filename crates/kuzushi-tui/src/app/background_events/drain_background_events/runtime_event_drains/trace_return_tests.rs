use super::*;

fn expansion_return(backgrounded: bool) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Prove));
    app.router.workbench_mut().toggle_trace_view();
    let mut session =
        ActivitySession::new("trace-completed").with_run_focus_origin(RunFocusOrigin {
            view: ShellView::Workbench,
            input_mode: InputMode::Prompt,
            auto_return: true,
        });
    session.run_focus_backgrounded = backgrounded;
    session.mark_run_focus_terminal_pending("completed");
    app.set_activity(Some(session));
    app.set_shell_view(ShellView::Activity);
    app.set_input_mode(InputMode::Prompt);
    app
}

#[test]
fn trace_return_restores_reader_controls_after_submitted_draft() {
    let mut app = expansion_return(false);
    assert!(app.finalize_run_focus_if_idle());
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(app.router.workbench().trace_view_open());
    assert_eq!(app.input_mode(), InputMode::Navigate);
    assert!(app.input().is_empty());
}

#[test]
fn trace_return_preserves_newer_draft_focus() {
    let mut app = expansion_return(false);
    app.set_input("new operator draft");
    assert!(app.finalize_run_focus_if_idle());
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(app.input(), "new operator draft");
    assert!(app.router.workbench().trace_view_open());
}

#[test]
fn background_trace_completion_keeps_current_focus() {
    let mut app = expansion_return(true);
    app.set_shell_view(ShellView::Home);
    app.set_input("unrelated draft");
    assert!(app.finalize_run_focus_if_idle());
    assert_eq!(app.shell_view(), ShellView::Home);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(app.input(), "unrelated draft");
}
