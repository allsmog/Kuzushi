use super::*;
use kuzushi_core::V2Config;

#[test]
fn routing_mode_defaults_to_shell() {
    let app = ShellApp::new(V2Config::default(), None);

    assert_eq!(routing_mode(&app), RoutingMode::Shell);
    assert_eq!(routing_mode_segment(&app), "mode:shell");
}

#[test]
fn routing_mode_reports_module_for_focused_module() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.focused_module = Some("sast".to_string());

    assert_eq!(routing_mode(&app), RoutingMode::Module);
}

#[test]
fn routing_mode_prioritizes_run_over_plan_and_module() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.focused_module = Some("sast".to_string());
    app.planner_running = true;
    app.shell_view = ShellView::ModuleRun;

    assert_eq!(routing_mode(&app), RoutingMode::Run);
}

#[test]
fn routing_mode_prioritizes_agent_over_plan() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.planner_running = true;
    app.shell_view = ShellView::AgentChat;

    assert_eq!(routing_mode(&app), RoutingMode::Agent);
}

#[test]
fn uses_activity_frame_only_for_activity_view() {
    let mut app = ShellApp::new(V2Config::default(), None);
    assert!(!uses_activity_frame(&app));

    app.shell_view = ShellView::Activity;
    assert!(uses_activity_frame(&app));

    app.shell_view = ShellView::ModuleRun;
    assert!(!uses_activity_frame(&app));
}

#[test]
fn plain_render_mode_selects_specialized_plain_views() {
    let mut app = ShellApp::new(V2Config::default(), None);
    assert_eq!(plain_render_mode(&app), PlainRenderMode::LineBased);

    app.shell_view = ShellView::Help;
    assert_eq!(plain_render_mode(&app), PlainRenderMode::Help);

    app.shell_view = ShellView::Options(crate::OptionsView {
        tool_name: "sast:scan".to_string(),
        filter: crate::OptionsFilter::Standard,
    });
    assert!(matches!(
        plain_render_mode(&app),
        PlainRenderMode::Options(view) if view.tool_name == "sast:scan"
    ));
}
