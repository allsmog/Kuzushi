use super::*;
use crate::app::{InputMode, ShellApp, ShellView};

fn open(router: &mut RouterState, view: ShellView, id: &str) {
    match view {
        ShellView::Replay => router.replay_mut().open(id),
        ShellView::Trace => router.trace_mut().open(id),
        _ => unreachable!(),
    }
    router.set_current(view);
}

#[test]
fn different_run_opens_at_the_outcome_and_same_run_retains_scroll() {
    for view in [ShellView::Replay, ShellView::Trace] {
        let mut router = RouterState::default();
        open(&mut router, view, "first");
        router.default_scroll_mut().set(12);
        open(&mut router, view, "first");
        assert_eq!(router.default_scroll().offset(), 12);
        open(&mut router, view, "second");
        assert_eq!(router.default_scroll().offset(), 0);
        router.default_scroll_mut().set(3);
        router.set_current(view);
        assert_eq!(router.default_scroll().offset(), 3);
    }
}

#[test]
fn pending_run_change_does_not_reset_another_view() {
    let mut router = RouterState::default();
    router.default_scroll_mut().set(17);
    router.replay_mut().open("new");
    router.set_current(ShellView::Report);
    assert_eq!(router.default_scroll().offset(), 17);
    router.set_current(ShellView::Replay);
    assert_eq!(router.default_scroll().offset(), 0);
}

#[test]
fn new_replay_preserves_draft_cursor_and_workflow_origin() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("retained\noperator draft");
    let cursor = app.cursor();
    app.open_replay_for_test("first");
    app.router.default_scroll_mut().set(15);
    app.open_replay_for_test("second");
    assert_eq!(app.router.default_scroll().offset(), 0);
    assert_eq!(app.router.overlay_origin(), Some(ShellView::Report));
    assert_eq!(app.router.overlay_input_mode(), Some(InputMode::Prompt));
    assert_eq!(app.input(), "retained\noperator draft");
    assert_eq!(app.cursor(), cursor);
}
