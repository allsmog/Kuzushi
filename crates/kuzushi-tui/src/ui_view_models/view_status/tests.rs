use super::*;
use kuzushi_core::V2Config;

#[test]
fn view_status_defaults_to_modules_catalog() {
    let app = ShellApp::new(V2Config::default(), None);

    assert_eq!(view_status_segment(&app), "catalog");
}

#[test]
fn view_status_uses_focused_module_for_module_views() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("semgrep".to_string()));

    app.set_shell_view(ShellView::Module);
    assert_eq!(view_status_segment(&app), "semgrep");

    app.set_shell_view(ShellView::ModuleRun);
    assert_eq!(view_status_segment(&app), "semgrep/run");
}

#[test]
fn view_status_reflects_actual_view_before_focused_module() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("semgrep".to_string()));

    app.set_shell_view(ShellView::Tools);
    assert_eq!(view_status_segment(&app), "tools");

    app.router.threat_mut().open(ThreatView::Stride);
    app.set_shell_view(ShellView::Threat);
    assert_eq!(view_status_segment(&app), "threats:stride");

    app.set_shell_view(ShellView::FailureHandoff);
    assert_eq!(view_status_segment(&app), "failure-handoff");
}
