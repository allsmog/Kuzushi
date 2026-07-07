use super::*;
use crate::scene3d::VizPage;
use crate::ui_view_models::WORKBENCH_REPORT_COMMAND;
use crate::{ScanPanelState, ShellView};
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn unmapped_leaf_views_advertise_the_exit_path() {
    // Auth/Cost/Patch/FailureHandoff fall through to the default footer —
    // which must lead with Esc so no view ever reads as a dead-end.
    for view in [
        ShellView::Auth,
        ShellView::Cost,
        ShellView::Patch,
        ShellView::FailureHandoff,
    ] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = view.clone();
        let bindings = footer_keybindings(&app);
        assert!(
            bindings.contains(&bind("Esc", "back")),
            "{view:?} must advertise Esc back: {bindings:?}"
        );
    }
}

#[test]
fn workbench_footer_advertises_esc_back_and_run_path() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Workbench;
    let bindings = footer_keybindings(&app);
    assert!(bindings.contains(&bind("Esc", "back")));
    assert!(!bindings.contains(&bind("cc", "workbench")));
    assert!(bindings.contains(&bind("n/N", "page")));
    assert!(bindings.contains(&bind("1..4", "page")));
    assert!(bindings.contains(&bind("scan", "run scan")));
    assert!(bindings.contains(&bind("Ctrl+C", "exit")));
    assert!(!bindings.contains(&bind(WORKBENCH_REPORT_COMMAND, "export report")));
}

#[test]
fn workbench_footer_advertises_export_when_findings_exist() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Workbench;
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
fn footer_keybindings_include_shell_completion_prefix() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Home;

    let bindings = footer_keybindings(&app);

    assert_eq!(bindings[0], bind("Tab", "complete"));
    assert!(bindings.contains(&bind("modules", "browse")));
    assert!(bindings.contains(&bind("workbench", "command center")));
    assert!(bindings.contains(&bind("n", "next phase")));
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
    assert!(!bindings.contains(&bind("Tab", "complete")));
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
    app.shell_view = ShellView::Workbench;
    *app.findings_mut() = vec![kuzushi_core::Finding::new_semgrep(
        "demo.rule",
        "src/app.rs",
        1,
        Some(1),
        kuzushi_core::Severity::High,
        "demo",
    )];

    let bindings = footer_keybindings(&app);

    assert_eq!(count_binding(&bindings, "j/k", "move"), 1);
    assert_eq!(count_binding(&bindings, "scan", "run scan"), 1);
    assert_eq!(count_binding(&bindings, "n/N", "page"), 1);
}

#[test]
fn planning_picker_footer_separates_phase_navigation_skip_and_close() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::PlanningPicker;

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
    app.shell_view = ShellView::FilePicker;

    let bindings = footer_keybindings(&app);

    assert!(bindings.contains(&bind("type", "filter")));
    assert!(bindings.contains(&bind("Enter", "attach")));
    assert!(bindings.contains(&bind("Esc", "close")));
    assert!(!bindings.contains(&bind(":", "type command")));
}

#[test]
fn previously_empty_views_now_show_scroll_and_back_in_footer() {
    for view in [
        ShellView::Tools,
        ShellView::History,
        ShellView::Context,
        ShellView::StrategyQueue,
        ShellView::KnowledgeBase,
        ShellView::AgentChat,
        ShellView::PromptsEditor,
    ] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = view.clone();
        let bindings = footer_keybindings(&app);
        assert!(
            bindings.contains(&bind("j/k/g/G", "scroll")),
            "{view:?} footer should show scroll keys"
        );
        assert!(
            bindings.contains(&bind("Esc", "back")),
            "{view:?} footer should show Esc back"
        );
        assert_eq!(
            count_binding(&bindings, "Esc", "back"),
            1,
            "{view:?} should not duplicate the back hint"
        );
    }
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
        app.shell_view = view.clone();
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
    app.shell_view = ShellView::Scene;

    let dfd_bindings = footer_keybindings(&app);
    assert!(dfd_bindings.contains(&bind("j/k/g/G", "scroll")));
    assert!(dfd_bindings.contains(&bind("Tab", "next page")));
    assert!(dfd_bindings.contains(&bind("Shift+Tab", "prev page")));
    assert!(dfd_bindings.contains(&bind("Esc/q", "leave")));
    assert!(!dfd_bindings.contains(&bind("h/l/j/k", "orbit 3D")));
    assert!(!dfd_bindings.contains(&bind("space/p", "pause")));
    assert!(!dfd_bindings.contains(&bind("r", "reset")));

    app.router.scene_mut().set_page(VizPage::AttackSurface);
    app.shell_view = ShellView::Scene;
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
