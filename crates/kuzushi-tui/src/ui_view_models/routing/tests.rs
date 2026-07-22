use super::*;
use kuzushi_core::V2Config;

#[test]
fn routing_mode_defaults_to_shell() {
    let app = ShellApp::new(V2Config::default(), None);

    assert_eq!(routing_mode(&app), RoutingMode::Shell);
    assert_eq!(routing_mode_segment(&app), "shell route");
}

#[test]
fn catalog_routing_ignores_stale_module_focus_but_module_view_reports_it() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("sast".to_string()));

    assert_eq!(routing_mode(&app), RoutingMode::Shell);
    app.set_shell_view(ShellView::Module);
    assert_eq!(routing_mode(&app), RoutingMode::Module);
}

#[test]
fn routing_mode_prioritizes_run_over_plan_and_module() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("sast".to_string()));
    app.set_planner_running(true);
    app.set_running_tool_for_test("triage:run");

    assert_eq!(routing_mode(&app), RoutingMode::Run);
}

#[test]
fn module_run_transcript_does_not_count_as_live_activity() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::ModuleRun);

    assert!(!has_run_activity(&app));
    assert_eq!(routing_mode(&app), RoutingMode::Shell);
}

#[test]
fn routing_mode_prioritizes_agent_over_plan() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_planner_running(true);
    app.set_agent_chat(Some(crate::app::AgentChatView {
        running: true,
        ..crate::app::AgentChatView::default()
    }));

    assert_eq!(routing_mode(&app), RoutingMode::Agent);
}

#[test]
fn uses_activity_frame_only_for_active_activity_view() {
    let mut app = ShellApp::new(V2Config::default(), None);
    assert!(!uses_activity_frame(&app));

    app.set_shell_view(ShellView::Activity);
    assert!(!uses_activity_frame(&app));
    app.set_activity(Some(crate::ActivitySession::new("run-active")));
    assert!(uses_activity_frame(&app));

    app.set_shell_view(ShellView::ModuleRun);
    assert!(!uses_activity_frame(&app));
}

#[test]
fn uses_scene_frame_reads_route_page() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router
        .scene_mut()
        .set_page(crate::scene3d::VizPage::AttackPath);
    app.set_shell_view(ShellView::Scene);

    assert!(!uses_scene_frame(&app));

    app.router
        .scene_mut()
        .set_page(crate::scene3d::VizPage::AttackSurface);

    assert!(uses_scene_frame(&app));
}

#[test]
fn plain_render_mode_selects_specialized_plain_views() {
    let mut app = ShellApp::new(V2Config::default(), None);
    assert_eq!(
        plain_render_mode(&app),
        PlainRenderMode::LineBased {
            include_context_strip: false
        }
    );

    app.set_shell_view(ShellView::Help);
    assert_eq!(plain_render_mode(&app), PlainRenderMode::Help);

    app.set_shell_view(ShellView::ProjectModel);
    assert_eq!(plain_render_mode(&app), PlainRenderMode::ProjectModel);

    app.set_shell_view(ShellView::StrategyQueue);
    assert_eq!(plain_render_mode(&app), PlainRenderMode::StrategyQueue);

    app.router.set_options(crate::OptionsView {
        tool_name: "sast:scan".to_string(),
        filter: crate::OptionsFilter::Standard,
    });
    app.set_shell_view(ShellView::Options);
    assert!(matches!(
        plain_render_mode(&app),
        PlainRenderMode::Options(view) if view.tool_name == "sast:scan"
    ));

    app.set_shell_view(ShellView::Workbench);
    assert_eq!(
        plain_render_mode(&app),
        PlainRenderMode::LineBased {
            include_context_strip: true
        }
    );

    app.open_model_picker();
    assert_eq!(
        plain_render_mode(&app),
        PlainRenderMode::LineBased {
            include_context_strip: false
        }
    );

    app.set_shell_view(ShellView::FilePicker);
    assert!(matches!(
        plain_render_mode(&app),
        PlainRenderMode::InteractiveOnly(model) if model.title == "FILE PICKER"
    ));
}
