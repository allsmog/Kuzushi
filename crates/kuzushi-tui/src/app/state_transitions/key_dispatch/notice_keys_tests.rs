use super::*;

fn trace_reader() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Prove));
    app.router.workbench_mut().toggle_trace_view();
    app.set_input_mode(InputMode::Navigate);
    app
}

fn escape(app: &mut ShellApp) {
    let update = app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(update.handled);
    EffectRuntime::execute(app, update.effects);
}

#[test]
fn info_notice_does_not_capture_trace_back() {
    let mut app = trace_reader();
    app.set_info_notice("run", "completed");
    escape(&mut app);
    assert!(app.advisory().notice.is_none());
    assert!(!app.router.workbench().trace_view_open());
    assert_eq!(app.shell_view(), ShellView::Workbench);
}

#[test]
fn success_notice_does_not_capture_trace_back() {
    let mut app = trace_reader();
    app.set_success_notice("run", "completed");
    escape(&mut app);
    assert!(app.advisory().notice.is_none());
    assert!(!app.router.workbench().trace_view_open());
}

#[test]
fn warning_notice_dismissal_keeps_the_trace_open() {
    let mut app = trace_reader();
    app.set_warn_notice("run", "incomplete output");
    escape(&mut app);
    assert!(app.advisory().notice.is_none());
    assert!(app.router.workbench().trace_view_open());
}

#[test]
fn error_notice_dismissal_keeps_the_trace_open() {
    let mut app = trace_reader();
    app.set_error_notice("run", "could not save output");
    escape(&mut app);
    assert!(app.advisory().notice.is_none());
    assert!(app.router.workbench().trace_view_open());
}
