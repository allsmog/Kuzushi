use super::*;
use crate::scene3d::VizPage;
use crate::ui_view_models::WORKBENCH_REPORT_COMMAND;
use crate::{ScanPanelState, ShellView};
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn unmapped_leaf_views_advertise_only_reachable_mode_actions() {
    for view in [
        ShellView::Auth,
        ShellView::Cost,
        ShellView::Patch,
        ShellView::FailureHandoff,
    ] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(view);
        let prompt = footer_keybindings(&app);
        assert!(
            prompt.contains(&bind("F2", "nav mode")),
            "{view:?}: {prompt:?}"
        );
        assert!(
            !prompt.contains(&bind("Esc", "back")),
            "{view:?}: {prompt:?}"
        );

        app.set_input_mode(crate::InputMode::Navigate);
        let navigate = footer_keybindings(&app);
        assert!(
            navigate.contains(&bind("Esc", "prompt")),
            "{view:?}: {navigate:?}"
        );
        assert!(
            !navigate.contains(&bind("Esc", "back")),
            "{view:?}: {navigate:?}"
        );
    }
}

#[test]
fn workbench_footer_separates_prompt_commands_from_navigation_keys() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    let prompt = footer_keybindings(&app);
    assert!(prompt.contains(&bind("Tab", "complete")));
    assert!(prompt.contains(&bind("F2", "nav mode")));
    assert!(prompt.contains(&bind("scan", "guided plan")));
    assert!(prompt.contains(&bind("run sast:scan {}", "rescan now")));
    assert!(prompt.contains(&bind("Ctrl+C", "exit")));
    assert!(!prompt.contains(&bind("n/N", "page")));
    assert!(!prompt.contains(&bind("1..4", "page")));
    assert!(!prompt.iter().any(|binding| binding.key == "Enter"));

    app.set_input_mode(crate::InputMode::Navigate);
    let navigate = footer_keybindings(&app);
    assert!(navigate.contains(&bind("Esc", "prompt")));
    assert!(navigate.contains(&bind("n/N", "page")));
    assert!(navigate.contains(&bind("1..4", "page")));
    assert!(!navigate.contains(&bind("scan", "guided plan")));
    assert!(!navigate.contains(&bind("run sast:scan {}", "rescan now")));
    assert!(!navigate.contains(&bind("Tab", "complete")));
}

#[test]
fn workbench_navigation_controls_follow_the_active_page_and_focus() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.set_input_mode(crate::InputMode::Navigate);
    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Terrain));
    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Center);
    assert!(!footer_keybindings(&app)
        .iter()
        .any(|binding| binding.key == "Tab"));
    assert!(app
        .view_keybindings()
        .iter()
        .all(|binding| binding.hint != "Tab" && binding.hint != "Enter"));

    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Details);
    let review = footer_keybindings(&app);
    for key in ["q", "v", "x", "c"] {
        assert!(
            review.iter().any(|binding| binding.key == key),
            "{review:?}"
        );
    }
}

#[test]
fn workbench_footer_advertises_export_when_findings_exist() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    *app.findings_mut() = vec![kuzushi_core::Finding::new_semgrep(
        "demo.rule",
        "src/app.rs",
        1,
        Some(1),
        kuzushi_core::Severity::High,
        "demo",
    )];

    let bindings = footer_keybindings(&app);

    assert!(bindings.contains(&bind(WORKBENCH_REPORT_COMMAND, "export report")));
}

#[test]
fn workbench_footer_only_advertises_enter_for_an_actionable_findings_pane() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.set_input_mode(crate::InputMode::Navigate);

    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Terrain));
    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Center);
    assert!(footer_keybindings(&app)
        .iter()
        .all(|binding| binding.key != "Enter"));

    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Coverage));
    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Findings);
    assert!(footer_keybindings(&app).contains(&bind("Enter", "review")));

    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Ship));
    assert!(footer_keybindings(&app).contains(&bind("Enter", "open")));
}

#[test]
fn footer_keybindings_include_shell_completion_prefix() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Home);

    let bindings = footer_keybindings(&app);

    assert_eq!(bindings[0], bind("Tab", "complete"));
    assert!(bindings.contains(&bind("modules", "browse")));
    assert!(bindings.contains(&bind("workbench", "command center")));
    assert!(!bindings.contains(&bind("n", "next phase")));
    assert!(bindings.contains(&bind("options sast:scan", "tune scan")));
    assert!(bindings.contains(&bind("Ctrl+C", "exit")));
}

#[test]
fn footer_keybindings_show_scan_abort_action_when_running() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_scan_panel(Some(scan_state(true, false)));

    let bindings = footer_keybindings(&app);

    assert_eq!(bindings[0], bind("Ctrl+C", "request abort"));
    assert!(bindings.contains(&bind("findings", "list")));
    assert!(bindings.contains(&bind("Tab", "complete")));
    assert!(bindings.contains(&bind("F2", "nav mode")));
}

#[test]
fn footer_keybindings_show_wait_cleanup_after_abort_request() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_scan_panel(Some(scan_state(true, true)));

    let bindings = footer_keybindings(&app);

    assert_eq!(bindings[0], bind("Ctrl+C", "wait cleanup"));
}

#[test]
fn footer_keybindings_deduplicate_view_bindings() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    *app.findings_mut() = vec![kuzushi_core::Finding::new_semgrep(
        "demo.rule",
        "src/app.rs",
        1,
        Some(1),
        kuzushi_core::Severity::High,
        "demo",
    )];

    app.set_input_mode(crate::InputMode::Navigate);
    let bindings = footer_keybindings(&app);

    assert_eq!(count_binding(&bindings, "j/k/↑/↓", "move"), 1);
    assert_eq!(count_binding(&bindings, "n/N", "page"), 1);
    assert_eq!(count_binding(&bindings, "scan", "guided plan"), 0);
}

#[test]
fn findings_navigation_precedes_secondary_workbench_controls() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.set_input_mode(crate::InputMode::Navigate);
    app.router
        .workbench_mut()
        .set_focus(crate::app::WorkbenchPane::Findings);

    let bindings = footer_keybindings(&app);
    let move_index = bindings
        .iter()
        .position(|binding| binding == &bind("j/k/↑/↓", "move"))
        .expect("movement binding");
    let page_index = bindings
        .iter()
        .position(|binding| binding.key == "1..4")
        .expect("phase page binding");

    assert!(move_index < page_index, "{bindings:?}");
}

#[test]
fn planning_picker_footer_separates_phase_navigation_skip_and_close() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::PlanningPicker);

    let bindings = footer_keybindings(&app);

    assert!(bindings.contains(&bind("KEYS", "j/k move")));
    assert!(bindings.contains(&bind("h/l ←/→", "phase")));
    assert!(bindings.contains(&bind("1-4", "jump phase")));
    assert!(bindings.contains(&bind("Tab/Shift+Tab/o", "focus pane")));
    assert!(bindings.contains(&bind("a/n", "all/none")));
    assert!(bindings.contains(&bind("s", "skip phase")));
    assert!(bindings.contains(&bind("Esc/q", "workbench")));
    assert!(bindings.contains(&bind("COMMAND", ": type")));
    assert!(!bindings.contains(&bind("Esc", "close")));
    assert!(!bindings.contains(&bind("workbench", "command center")));

    app.engagement
        .planning_picker_mut()
        .set_focus(crate::app::PickerFocus::OptionsPane);
    let bindings = footer_keybindings(&app);

    assert!(bindings.contains(&bind("KEYS", "j/k option")));
    assert!(bindings.contains(&bind("Tab/Shift+Tab/o", "steps")));
    assert!(bindings.contains(&bind("1-4", "phase")));
    assert!(bindings.contains(&bind("Esc/q", "steps")));
    assert!(bindings.contains(&bind("COMMAND", ": type")));
    assert!(!bindings.contains(&bind("workbench", "command center")));
}

#[test]
fn file_picker_footer_names_filter_and_attach_controls() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::FilePicker);

    let bindings = footer_keybindings(&app);

    assert!(bindings.contains(&bind("type", "filter")));
    assert!(bindings.contains(&bind("Enter", "attach")));
    assert!(bindings.contains(&bind("Esc", "close")));
    assert!(!bindings.contains(&bind(":", "type command")));
}

#[test]
fn navigate_mode_views_show_scroll_and_truthful_prompt_escape() {
    for view in [
        ShellView::Tools,
        ShellView::Config,
        ShellView::Permissions,
        ShellView::Runs,
        ShellView::History,
        ShellView::Context,
        ShellView::ProjectModel,
        ShellView::StrategyQueue,
        ShellView::Workspace,
        ShellView::KnowledgeBase,
        ShellView::AgentChat,
        ShellView::PromptsEditor,
    ] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(view);
        app.set_input_mode(crate::InputMode::Navigate);
        let bindings = footer_keybindings(&app);
        assert!(
            bindings.contains(&bind("j/k/g/G", "scroll")),
            "{view:?} footer should show scroll keys"
        );
        assert!(
            bindings.contains(&bind("Esc", "prompt")),
            "{view:?} footer should show Esc prompt"
        );
        assert_eq!(
            count_binding(&bindings, "Esc", "prompt"),
            1,
            "{view:?} should not duplicate the prompt hint"
        );
        assert!(!bindings.contains(&bind("Esc", "back")));
    }
}

#[test]
fn prompt_mode_help_keeps_non_editing_page_keys_discoverable() {
    for view in [ShellView::Help, ShellView::Quickstart] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(view);

        let bindings = footer_keybindings(&app);

        assert!(bindings.contains(&bind("PgUp/PgDn", "scroll")), "{view:?}");
        assert!(!bindings.contains(&bind("j/k/g/G", "scroll")), "{view:?}");
    }
}

#[test]
fn permission_policy_footer_separates_commands_from_scroll_keys() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Permissions);

    let prompt = footer_keybindings(&app);
    assert!(prompt.contains(&bind("doctor", "preflight")));
    assert!(prompt.contains(&bind("config", "model/runtime")));
    assert!(prompt.contains(&bind("runs", "execution evidence")));
    assert!(!prompt.contains(&bind("j/k/g/G", "scroll")));

    app.set_input_mode(crate::InputMode::Navigate);
    let navigate = footer_keybindings(&app);
    assert!(navigate.contains(&bind("j/k/g/G", "scroll")));
    assert!(navigate.contains(&bind("Esc", "prompt")));
    assert!(!navigate.contains(&bind("doctor", "preflight")));
}

#[test]
fn footers_do_not_relabel_back_as_home() {
    for view in [
        ShellView::Recommend,
        ShellView::Threat,
        ShellView::ModuleRun,
        ShellView::AgentChat,
    ] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(view);
        let bindings = footer_keybindings(&app);
        assert!(
            !bindings.contains(&bind("Esc", "home")),
            "{view:?} should not advertise Esc as home: {bindings:?}"
        );
    }
}

#[test]
fn scene_footer_advertises_3d_controls_only_on_3d_page() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.scene_mut().set_page(VizPage::Dfd);
    app.set_shell_view(ShellView::Scene);
    app.set_input_mode(crate::InputMode::Navigate);

    let dfd_bindings = footer_keybindings(&app);
    assert!(dfd_bindings.contains(&bind("j/k/g/G", "scroll")));
    assert!(dfd_bindings.contains(&bind("Tab", "next page")));
    assert!(dfd_bindings.contains(&bind("Shift+Tab", "prev page")));
    assert!(dfd_bindings.contains(&bind("q", "leave")));
    assert!(dfd_bindings.contains(&bind("Esc", "prompt")));
    assert!(!dfd_bindings.contains(&bind("h/l/j/k", "orbit 3D")));
    assert!(!dfd_bindings.contains(&bind("space/p", "pause")));
    assert!(!dfd_bindings.contains(&bind("r", "reset")));

    app.router.scene_mut().set_page(VizPage::AttackSurface);
    app.set_shell_view(ShellView::Scene);
    let terrain_bindings = footer_keybindings(&app);
    assert!(!terrain_bindings.contains(&bind("j/k/g/G", "scroll")));
    assert!(terrain_bindings.contains(&bind("h/l/j/k", "orbit 3D")));
    assert!(terrain_bindings.contains(&bind("space/p", "pause")));
    assert!(terrain_bindings.contains(&bind("r", "reset")));
}

fn scan_state(running: bool, abort_requested: bool) -> ScanPanelState {
    ScanPanelState {
        run_id: None,
        target: PathBuf::from("."),
        stage: "semgrep".to_string(),
        findings_count: 0,
        running,
        abort_requested,
        error: None,
    }
}

fn count_binding(bindings: &[FooterKeybinding], key: &'static str, label: &'static str) -> usize {
    let expected = FooterKeybinding { key, label };
    bindings
        .iter()
        .filter(|binding| **binding == expected)
        .count()
}
