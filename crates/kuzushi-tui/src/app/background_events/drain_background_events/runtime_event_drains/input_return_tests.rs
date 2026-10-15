use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn returning_to(view: ShellView) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Scan));
    let mut session =
        ActivitySession::new("owned-input-return").with_run_focus_origin(RunFocusOrigin {
            view,
            input_mode: InputMode::Navigate,
            auto_return: true,
        });
    session.mark_run_focus_terminal_pending("partial");
    app.set_activity(Some(session));
    app.set_shell_view(ShellView::Activity);
    app.set_input_mode(InputMode::Prompt);
    app
}

#[test]
fn foreground_completion_keeps_newer_draft_cursor_and_printable_keys() {
    for origin in [
        ShellView::Home,
        ShellView::Logs,
        ShellView::Workbench,
        ShellView::Setup,
    ] {
        let mut app = returning_to(origin);
        app.set_input("inspect α ");
        app.move_cursor_left();
        let cursor = app.editor().cursor();

        assert!(app.finalize_run_focus_if_idle());
        assert_eq!(app.shell_view(), origin);
        assert_eq!(app.input_mode(), InputMode::Prompt, "{origin:?}");
        assert_eq!(app.editor().cursor(), cursor);
        let update = app.reduce_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert!(update.handled && update.effects.is_empty());
        assert_eq!(app.input(), "inspect αj ");
    }
}

#[test]
fn foreground_completion_retains_collapsed_multiline_paste_and_undo() {
    let mut app = returning_to(ShellView::Logs);
    app.set_input("inspect ");
    let update = app.reduce_paste("first α\nsecond β\n");
    assert!(update.handled && update.effects.is_empty());
    let visible = app.input().to_string();
    let expanded = app.editor().expanded_input();
    let cursor = app.editor().cursor();

    assert!(app.finalize_run_focus_if_idle());
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(app.input(), visible);
    assert_eq!(app.editor().expanded_input(), expanded);
    assert_eq!(app.editor().cursor(), cursor);
    assert!(app.editor_mut().restore_last_cleared_input());
    assert_eq!(app.input(), "inspect ");
}

#[test]
fn empty_completion_restores_navigation_without_a_new_command() {
    let mut app = returning_to(ShellView::Logs);
    assert!(app.finalize_run_focus_if_idle());
    assert_eq!(app.shell_view(), ShellView::Logs);
    assert_eq!(app.input_mode(), InputMode::Navigate);
    assert!(app.input().is_empty());
}

#[test]
fn background_completion_keeps_the_operators_new_view_and_draft() {
    let mut app = returning_to(ShellView::Logs);
    app.activity_mut().unwrap().run_focus_backgrounded = true;
    app.set_shell_view(ShellView::Home);
    app.set_input("held draft α");
    assert!(app.finalize_run_focus_if_idle());
    assert_eq!(app.shell_view(), ShellView::Home);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(app.input(), "held draft α");
}

#[test]
fn paused_review_choices_do_not_hold_foreground_completion_in_run_focus() {
    let mut app = returning_to(ShellView::Campaign);
    app.engagement
        .queue_plan(vec![PlanningTaskId::TriageFindings]);
    app.engagement.pause_planning_queue();
    app.set_input("held Review draft");
    app.set_cursor(4);
    assert!(app.finalize_run_focus_if_idle());
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!((app.input(), app.cursor()), ("held Review draft", 4));
    assert_eq!(
        app.engagement.pop_queued_task(),
        Some(PlanningTaskId::TriageFindings)
    );
    assert!(app.engagement.planning_paused());
}

#[test]
fn runnable_planning_continuation_still_holds_the_run_focus_sequence() {
    let mut app = returning_to(ShellView::Campaign);
    app.engagement
        .queue_plan(vec![PlanningTaskId::TriageFindings]);
    assert!(!app.finalize_run_focus_if_idle());
    assert_eq!(app.shell_view(), ShellView::Activity);
}

#[test]
fn background_completion_with_paused_choices_never_steals_focus() {
    let mut app = returning_to(ShellView::Campaign);
    app.engagement
        .queue_plan(vec![PlanningTaskId::TriageFindings]);
    app.engagement.pause_planning_queue();
    app.activity_mut().unwrap().run_focus_backgrounded = true;
    app.set_shell_view(ShellView::Report);
    app.set_input("newer draft");
    app.set_cursor(2);
    assert!(app.finalize_run_focus_if_idle());
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!((app.input(), app.cursor()), ("newer draft", 2));
}
