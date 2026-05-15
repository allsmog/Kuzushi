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
